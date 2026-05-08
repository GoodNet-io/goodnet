/// @file   core/registry/connection.cpp
/// @brief  Implementation of the sharded connection registry.

#include "connection.hpp"

#include <memory>
#include <mutex>

namespace gn::core {

gn_conn_id_t ConnectionRegistry::alloc_id() noexcept {
    return next_id_.fetch_add(1, std::memory_order_relaxed);
}

ConnectionRegistry::Shard& ConnectionRegistry::shard_for(gn_conn_id_t id) noexcept {
    return shards_[id % kShardCount];
}

const ConnectionRegistry::Shard& ConnectionRegistry::shard_for(gn_conn_id_t id) const noexcept {
    return shards_[id % kShardCount];
}

gn_result_t ConnectionRegistry::insert_with_index(ConnectionRecord rec) noexcept {
    if (rec.id == GN_INVALID_ID) {
        return GN_ERR_INVALID_ENVELOPE;
    }

    /// `limits.md` §4a cap pre-check before locks: zero means
    /// "unlimited"; non-zero rejects when the live count is already
    /// at the cap.
    const std::uint32_t cap = max_connections_.load(std::memory_order_relaxed);
    if (cap != 0 &&
        live_count_.load(std::memory_order_relaxed) >= cap) {
        return GN_ERR_LIMIT_REACHED;
    }

    Shard& s = shard_for(rec.id);

    /// Lock all three mutexes in a fixed total order. `scoped_lock`
    /// picks an order that avoids deadlocks across concurrent
    /// inserters that share any subset of the locks.
    std::scoped_lock lock(s.mu, uri_mu_, pk_mu_);

    /// `conn_id` is kernel-allocated and never reused during runtime,
    /// so a duplicate id under the shard map is a structural bug — keep
    /// the rejection. URI and peer_pk indexes admit multiple conns per
    /// key (multipath, parallel transport, aggregation): kernel-level
    /// invariant is «one record per `conn_id`», not «one record per
    /// peer or URI». Strategy plugins that want single-active-per-peer
    /// discipline (sequential switch, channel upgrade) maintain their
    /// own `peer_pk → list-of-conns` map per `architecture/multi-path.ru.md`
    /// §«Идентичность connection поверх transport'а». Cross-session
    /// identity protection moved entirely to
    /// `attestation_dispatcher.peer_pin_map` per `attestation.md` §5
    /// step 7-8.
    if (s.records.contains(rec.id)) return GN_ERR_LIMIT_REACHED;

    /// Placeholder zero pk skips the index — many pre-handshake
    /// responders coexist on the kZeroPk; real peer key publishes
    /// through `update_remote_pk` post-handshake.
    static const PublicKey kZeroPk{};
    const bool has_peer_pk = (rec.remote_pk != kZeroPk);

    /// Re-check under the lock to close the race between the
    /// pre-lock load and a concurrent inserter that bumps the
    /// counter to the cap.
    if (cap != 0 &&
        live_count_.load(std::memory_order_relaxed) >= cap) {
        return GN_ERR_LIMIT_REACHED;
    }

    const gn_conn_id_t id    = rec.id;
    const std::string  uri   = rec.uri;
    const PublicKey    pk    = rec.remote_pk;

    s.records.emplace(id, std::make_shared<const ConnectionRecord>(std::move(rec)));
    s.counters.emplace(id, std::make_unique<AtomicCounters>());
    /// `insert_or_assign` so a multi-conn-to-same-URI registration
    /// last-writer-wins on the lookup index without rejecting the
    /// underlying record. Both records remain findable through
    /// `find_by_id`; `find_by_uri` returns the most recently
    /// registered.
    uri_index_.insert_or_assign(uri, id);
    if (has_peer_pk) pk_index_.insert_or_assign(pk, id);
    live_count_.fetch_add(1, std::memory_order_relaxed);

    return GN_OK;
}

void ConnectionRegistry::set_max_connections(std::uint32_t cap) noexcept {
    max_connections_.store(cap, std::memory_order_relaxed);
}

gn_result_t ConnectionRegistry::erase_with_index(gn_conn_id_t id) noexcept {
    if (id == GN_INVALID_ID) {
        return GN_ERR_INVALID_ENVELOPE;
    }

    Shard& s = shard_for(id);

    std::scoped_lock lock(s.mu, uri_mu_, pk_mu_);

    auto it = s.records.find(id);
    if (it == s.records.end()) {
        return GN_ERR_NOT_FOUND;
    }

    /// Copy index keys before dropping the record's shared_ptr so
    /// the references stay alive while the index erases run. Other
    /// readers that already hold a copy of the same shared_ptr
    /// keep observing the record until they release it.
    const std::string uri = it->second->uri;
    const PublicKey   pk  = it->second->remote_pk;

    /// Multi-conn-aware index erase: remove the entry only if it
    /// still points to **this** id. A different conn that registered
    /// the same URI / peer_pk later will have overwritten the index
    /// (last-writer-wins); erasing unconditionally would orphan that
    /// other conn's lookup.
    if (auto uri_it = uri_index_.find(uri);
        uri_it != uri_index_.end() && uri_it->second == id) {
        uri_index_.erase(uri_it);
    }
    if (auto pk_it = pk_index_.find(pk);
        pk_it != pk_index_.end() && pk_it->second == id) {
        pk_index_.erase(pk_it);
    }
    s.counters.erase(id);
    s.records.erase(it);
    live_count_.fetch_sub(1, std::memory_order_relaxed);
    return GN_OK;
}

std::optional<ConnectionRecord>
ConnectionRegistry::snapshot_and_erase(gn_conn_id_t id) noexcept {
    if (id == GN_INVALID_ID) return std::nullopt;
    Shard& s = shard_for(id);

    std::scoped_lock lock(s.mu, uri_mu_, pk_mu_);

    auto it = s.records.find(id);
    if (it == s.records.end()) return std::nullopt;

    /// `insert_with_index` always emplaces a counter slot beside the
    /// record under the same scoped_lock, so an existing record
    /// always has a live counter slot. Copy out a value-typed
    /// snapshot here — the caller wants ownership for one-shot
    /// event publishing, not a continuing reference to the
    /// shared_ptr.
    ConnectionRecord snapshot = *it->second;
    auto cit = s.counters.find(id);
    const auto& c = *cit->second;
    snapshot.bytes_in            = c.bytes_in.load(std::memory_order_relaxed);
    snapshot.bytes_out           = c.bytes_out.load(std::memory_order_relaxed);
    snapshot.frames_in           = c.frames_in.load(std::memory_order_relaxed);
    snapshot.frames_out          = c.frames_out.load(std::memory_order_relaxed);
    snapshot.pending_queue_bytes =
        c.pending_queue_bytes.load(std::memory_order_relaxed);
    snapshot.last_rtt_us         = c.last_rtt_us.load(std::memory_order_relaxed);

    /// `snapshot` owns a copy of `uri` and `remote_pk` after the
    /// dereference, so the index erases below are safe even after
    /// the shard erase drops the stored shared_ptr. Same multi-
    /// conn-aware guard as `erase_with_index` — only remove the
    /// index entry if it points at **this** id.
    if (auto uri_it = uri_index_.find(snapshot.uri);
        uri_it != uri_index_.end() && uri_it->second == id) {
        uri_index_.erase(uri_it);
    }
    if (auto pk_it = pk_index_.find(snapshot.remote_pk);
        pk_it != pk_index_.end() && pk_it->second == id) {
        pk_index_.erase(pk_it);
    }
    s.counters.erase(id);
    s.records.erase(it);
    live_count_.fetch_sub(1, std::memory_order_relaxed);
    return snapshot;
}

std::shared_ptr<const ConnectionRecord>
ConnectionRegistry::find_by_id(gn_conn_id_t id) const {
    if (id == GN_INVALID_ID) return nullptr;
    const Shard& s = shard_for(id);
    std::shared_lock lock(s.mu);
    auto it = s.records.find(id);
    if (it == s.records.end()) return nullptr;
    return it->second;
}

ConnectionRegistry::CounterSnapshot
ConnectionRegistry::read_counters(gn_conn_id_t id) const noexcept {
    CounterSnapshot out{};
    if (id == GN_INVALID_ID) return out;
    const Shard& s = shard_for(id);
    std::shared_lock lock(s.mu);
    auto it = s.counters.find(id);
    if (it == s.counters.end() || it->second == nullptr) return out;
    const auto& c = *it->second;
    out.bytes_in            = c.bytes_in.load(std::memory_order_relaxed);
    out.bytes_out           = c.bytes_out.load(std::memory_order_relaxed);
    out.frames_in           = c.frames_in.load(std::memory_order_relaxed);
    out.frames_out          = c.frames_out.load(std::memory_order_relaxed);
    out.pending_queue_bytes = c.pending_queue_bytes.load(std::memory_order_relaxed);
    out.last_rtt_us         = c.last_rtt_us.load(std::memory_order_relaxed);
    return out;
}

gn_result_t ConnectionRegistry::upgrade_trust(gn_conn_id_t id,
                                              gn_trust_class_t target,
                                              ConnectionRecord* out_record) noexcept {
    if (id == GN_INVALID_ID) return GN_ERR_NULL_ARG;
    Shard& s = shard_for(id);
    std::unique_lock lock(s.mu);
    auto it = s.records.find(id);
    if (it == s.records.end()) return GN_ERR_NOT_FOUND;
    if (!gn_trust_can_upgrade(it->second->trust, target)) {
        /// Helper from `sdk/trust.h` rejects: only `Untrusted → Peer`
        /// or identity transitions. The shard mutex serialises the
        /// read-decide-write so concurrent upgrades cannot race past
        /// the gate.
        return GN_ERR_LIMIT_REACHED;
    }
    /// Copy-on-write replace — readers holding the prior shared_ptr
    /// observe the old record until they drop their reference;
    /// readers post-store observe the new trust class.
    auto next = std::make_shared<ConnectionRecord>(*it->second);
    next->trust = target;
    if (out_record != nullptr) *out_record = *next;
    it->second = std::move(next);
    return GN_OK;
}

gn_result_t ConnectionRegistry::update_remote_pk(gn_conn_id_t id,
                                                 const PublicKey& new_pk) noexcept {
    if (id == GN_INVALID_ID) return GN_ERR_NULL_ARG;
    Shard& s = shard_for(id);
    /// Lock both shard and pk index in the canonical order so concurrent
    /// inserters / erasers / updaters cannot interleave.
    std::scoped_lock lock(s.mu, pk_mu_);

    auto it = s.records.find(id);
    if (it == s.records.end()) return GN_ERR_NOT_FOUND;

    const PublicKey old_pk = it->second->remote_pk;
    if (old_pk == new_pk) return GN_OK;  /// idempotent no-op

    /// Multi-conn-aware: a `new_pk` already mapping to a different
    /// conn is **valid** under the registry's multi-conn-per-peer
    /// model — both conns coexist, the index simply points at the
    /// most recently published one. Cross-session identity protection
    /// (impostor with different `device_pk` claiming an existing
    /// `peer_pk`) is enforced by
    /// `attestation_dispatcher.peer_pin_map` per `attestation.md`
    /// §5 step 7-8, not by this registry.
    static const PublicKey kZeroPk{};
    /// Old pk's index entry only points at `id` if no later conn
    /// overwrote it; touch it conditionally so we don't orphan a
    /// later conn's lookup.
    if (old_pk != kZeroPk) {
        if (auto pk_it = pk_index_.find(old_pk);
            pk_it != pk_index_.end() && pk_it->second == id) {
            pk_index_.erase(pk_it);
        }
    }
    pk_index_.insert_or_assign(new_pk, id);

    /// Copy-on-write replace mirrors `upgrade_trust`.
    auto next = std::make_shared<ConnectionRecord>(*it->second);
    next->remote_pk = new_pk;
    it->second = std::move(next);
    return GN_OK;
}

std::shared_ptr<const ConnectionRecord>
ConnectionRegistry::find_by_uri(std::string_view uri) const {
    gn_conn_id_t id = GN_INVALID_ID;
    {
        std::shared_lock lock(uri_mu_);
        auto it = uri_index_.find(std::string{uri});
        if (it == uri_index_.end()) return nullptr;
        id = it->second;
    }
    return find_by_id(id);
}

std::shared_ptr<const ConnectionRecord>
ConnectionRegistry::find_by_pk(const PublicKey& pk) const {
    gn_conn_id_t id = GN_INVALID_ID;
    {
        std::shared_lock lock(pk_mu_);
        auto it = pk_index_.find(pk);
        if (it == pk_index_.end()) return nullptr;
        id = it->second;
    }
    return find_by_id(id);
}

std::size_t ConnectionRegistry::size() const noexcept {
    std::size_t n = 0;
    for (const auto& s : shards_) {
        std::shared_lock lock(s.mu);
        n += s.records.size();
    }
    return n;
}

void ConnectionRegistry::for_each(
    const std::function<bool(const ConnectionRecord&,
                              const CounterSnapshot&)>& visitor) const {
    if (!visitor) return;
    for (const auto& s : shards_) {
        std::shared_lock lock(s.mu);
        for (const auto& [id, rec] : s.records) {
            CounterSnapshot snap{};
            auto cit = s.counters.find(id);
            if (cit != s.counters.end() && cit->second != nullptr) {
                const auto& c = *cit->second;
                snap.bytes_in            = c.bytes_in.load(std::memory_order_relaxed);
                snap.bytes_out           = c.bytes_out.load(std::memory_order_relaxed);
                snap.frames_in           = c.frames_in.load(std::memory_order_relaxed);
                snap.frames_out          = c.frames_out.load(std::memory_order_relaxed);
                snap.pending_queue_bytes = c.pending_queue_bytes.load(std::memory_order_relaxed);
                snap.last_rtt_us         = c.last_rtt_us.load(std::memory_order_relaxed);
            }
            if (!visitor(*rec, snap)) return;
        }
    }
}

void ConnectionRegistry::add_inbound(gn_conn_id_t id, std::uint64_t bytes,
                                      std::uint64_t frames) noexcept {
    if (id == GN_INVALID_ID) return;
    const Shard& s = shard_for(id);
    std::shared_lock lock(s.mu);
    auto it = s.counters.find(id);
    if (it == s.counters.end() || it->second == nullptr) return;
    it->second->bytes_in.fetch_add(bytes, std::memory_order_relaxed);
    it->second->frames_in.fetch_add(frames, std::memory_order_relaxed);
}

void ConnectionRegistry::add_outbound(gn_conn_id_t id, std::uint64_t bytes,
                                       std::uint64_t frames) noexcept {
    if (id == GN_INVALID_ID) return;
    const Shard& s = shard_for(id);
    std::shared_lock lock(s.mu);
    auto it = s.counters.find(id);
    if (it == s.counters.end() || it->second == nullptr) return;
    it->second->bytes_out.fetch_add(bytes, std::memory_order_relaxed);
    it->second->frames_out.fetch_add(frames, std::memory_order_relaxed);
}

void ConnectionRegistry::set_pending_bytes(gn_conn_id_t id,
                                            std::uint64_t bytes) noexcept {
    if (id == GN_INVALID_ID) return;
    const Shard& s = shard_for(id);
    std::shared_lock lock(s.mu);
    auto it = s.counters.find(id);
    if (it == s.counters.end() || it->second == nullptr) return;
    it->second->pending_queue_bytes.store(bytes, std::memory_order_relaxed);
}

gn_result_t ConnectionRegistry::pin_peer(
    const PublicKey& peer_pk,
    const PublicKey& device_pk,
    const PublicKey& user_pk,
    std::span<const std::uint8_t, GN_HASH_BYTES> handshake_hash) noexcept {
    std::unique_lock lock(pin_mu_);
    auto it = peer_pin_map_.find(peer_pk);
    if (it == peer_pin_map_.end()) {
        PeerPin pin;
        pin.device_pk = device_pk;
        pin.user_pk   = user_pk;
        std::memcpy(pin.handshake_hash.data(), handshake_hash.data(),
                    GN_HASH_BYTES);
        peer_pin_map_.emplace(peer_pk, pin);
        return GN_OK;
    }
    /// Pin already present. Equality with the proposed device_pk is
    /// idempotent success — refresh the user_pk and handshake_hash
    /// to the latest attestation's view. Mismatch on device_pk is
    /// rejected — the caller treats the result as an identity-change
    /// attempt and disconnects.
    if (it->second.device_pk != device_pk) {
        return GN_ERR_INVALID_ENVELOPE;
    }
    it->second.user_pk = user_pk;
    std::memcpy(it->second.handshake_hash.data(), handshake_hash.data(),
                GN_HASH_BYTES);
    return GN_OK;
}

gn_result_t ConnectionRegistry::apply_rotation(
    const PublicKey& peer_pk,
    const PublicKey& new_user_pk,
    std::uint64_t    new_counter) noexcept {
    std::unique_lock lock(pin_mu_);
    auto it = peer_pin_map_.find(peer_pk);
    if (it == peer_pin_map_.end()) return GN_ERR_NOT_FOUND;
    if (new_counter <= it->second.rotation_counter) {
        return GN_ERR_INVALID_ENVELOPE;
    }
    it->second.user_pk          = new_user_pk;
    it->second.rotation_counter = new_counter;
    return GN_OK;
}

std::optional<ConnectionRegistry::PeerPin>
ConnectionRegistry::get_pinned_peer(const PublicKey& peer_pk) const {
    std::shared_lock lock(pin_mu_);
    auto it = peer_pin_map_.find(peer_pk);
    if (it == peer_pin_map_.end()) return std::nullopt;
    return it->second;
}

std::optional<PublicKey>
ConnectionRegistry::get_pinned_device_pk(const PublicKey& peer_pk) const {
    std::shared_lock lock(pin_mu_);
    auto it = peer_pin_map_.find(peer_pk);
    if (it == peer_pin_map_.end()) return std::nullopt;
    return it->second.device_pk;
}

void ConnectionRegistry::clear_pinned_device_pk(
    const PublicKey& peer_pk) noexcept {
    std::unique_lock lock(pin_mu_);
    peer_pin_map_.erase(peer_pk);
}

std::size_t ConnectionRegistry::pin_count() const noexcept {
    std::shared_lock lock(pin_mu_);
    return peer_pin_map_.size();
}

} // namespace gn::core
