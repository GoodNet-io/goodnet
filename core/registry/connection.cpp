/// @file   core/registry/connection.cpp
/// @brief  Implementation of the sharded connection registry.

#include "connection.hpp"

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

    if (s.records.contains(rec.id))             return GN_ERR_LIMIT_REACHED;
    if (uri_index_.contains(rec.uri))           return GN_ERR_LIMIT_REACHED;
    if (pk_index_.contains(rec.remote_pk))      return GN_ERR_LIMIT_REACHED;

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

    s.records.emplace(id, std::move(rec));
    s.counters.emplace(id, std::make_unique<AtomicCounters>());
    uri_index_.emplace(uri, id);
    pk_index_.emplace(pk, id);
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

    /// Copy index keys before erasing the record itself; after the
    /// shard erase the references would dangle.
    const std::string uri = it->second.uri;
    const PublicKey   pk  = it->second.remote_pk;

    uri_index_.erase(uri);
    pk_index_.erase(pk);
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
    /// always has a live counter slot.
    ConnectionRecord snapshot = std::move(it->second);
    auto cit = s.counters.find(id);
    const auto& c = *cit->second;
    snapshot.bytes_in            = c.bytes_in.load(std::memory_order_relaxed);
    snapshot.bytes_out           = c.bytes_out.load(std::memory_order_relaxed);
    snapshot.frames_in           = c.frames_in.load(std::memory_order_relaxed);
    snapshot.frames_out          = c.frames_out.load(std::memory_order_relaxed);
    snapshot.pending_queue_bytes =
        c.pending_queue_bytes.load(std::memory_order_relaxed);
    snapshot.last_rtt_us         = c.last_rtt_us.load(std::memory_order_relaxed);

    /// `snapshot` owns a copy of `uri` and `remote_pk` after the move,
    /// so the index erases below are safe even after the shard erase.
    uri_index_.erase(snapshot.uri);
    pk_index_.erase(snapshot.remote_pk);
    s.counters.erase(id);
    s.records.erase(it);
    live_count_.fetch_sub(1, std::memory_order_relaxed);
    return snapshot;
}

std::optional<ConnectionRecord> ConnectionRegistry::find_by_id(gn_conn_id_t id) const {
    if (id == GN_INVALID_ID) return std::nullopt;
    const Shard& s = shard_for(id);
    std::shared_lock lock(s.mu);
    auto it = s.records.find(id);
    if (it == s.records.end()) return std::nullopt;
    ConnectionRecord snapshot = it->second;
    /// `merge_counters` reads the per-id atomics under the same
    /// shared lock so the snapshot reflects a consistent view.
    /// Atomic loads themselves do not need the lock; the lock
    /// guards the lookup of the counters slot.
    auto cit = s.counters.find(id);
    if (cit != s.counters.end() && cit->second != nullptr) {
        const auto& c = *cit->second;
        snapshot.bytes_in            = c.bytes_in.load(std::memory_order_relaxed);
        snapshot.bytes_out           = c.bytes_out.load(std::memory_order_relaxed);
        snapshot.frames_in           = c.frames_in.load(std::memory_order_relaxed);
        snapshot.frames_out          = c.frames_out.load(std::memory_order_relaxed);
        snapshot.pending_queue_bytes =
            c.pending_queue_bytes.load(std::memory_order_relaxed);
        snapshot.last_rtt_us         = c.last_rtt_us.load(std::memory_order_relaxed);
    }
    return snapshot;
}

gn_result_t ConnectionRegistry::upgrade_trust(gn_conn_id_t id,
                                              gn_trust_class_t target,
                                              ConnectionRecord* out_record) noexcept {
    if (id == GN_INVALID_ID) return GN_ERR_NULL_ARG;
    Shard& s = shard_for(id);
    std::unique_lock lock(s.mu);
    auto it = s.records.find(id);
    if (it == s.records.end()) return GN_ERR_NOT_FOUND;
    if (!gn_trust_can_upgrade(it->second.trust, target)) {
        /// Helper from `sdk/trust.h` rejects: only `Untrusted → Peer`
        /// or identity transitions. The shard mutex serialises the
        /// read-decide-write so concurrent upgrades cannot race past
        /// the gate.
        return GN_ERR_LIMIT_REACHED;
    }
    it->second.trust = target;
    if (out_record != nullptr) {
        *out_record = it->second;
    }
    return GN_OK;
}

std::optional<ConnectionRecord> ConnectionRegistry::find_by_uri(std::string_view uri) const {
    gn_conn_id_t id = GN_INVALID_ID;
    {
        std::shared_lock lock(uri_mu_);
        auto it = uri_index_.find(std::string{uri});
        if (it == uri_index_.end()) return std::nullopt;
        id = it->second;
    }
    return find_by_id(id);
}

std::optional<ConnectionRecord> ConnectionRegistry::find_by_pk(const PublicKey& pk) const {
    gn_conn_id_t id = GN_INVALID_ID;
    {
        std::shared_lock lock(pk_mu_);
        auto it = pk_index_.find(pk);
        if (it == pk_index_.end()) return std::nullopt;
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
    const std::function<bool(const ConnectionRecord&)>& visitor) const {
    if (!visitor) return;
    for (const auto& s : shards_) {
        std::shared_lock lock(s.mu);
        for (const auto& [_, rec] : s.records) {
            if (!visitor(rec)) return;
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

gn_result_t ConnectionRegistry::pin_device_pk(
    const PublicKey& peer_pk, const PublicKey& device_pk) noexcept {
    std::unique_lock lock(pin_mu_);
    auto it = peer_pin_map_.find(peer_pk);
    if (it == peer_pin_map_.end()) {
        peer_pin_map_.emplace(peer_pk, device_pk);
        return GN_OK;
    }
    /// Pin already present. Equality with the proposed device_pk is
    /// idempotent success. Mismatch is rejected — the caller treats
    /// the result as an identity-change attempt and disconnects.
    if (it->second == device_pk) return GN_OK;
    return GN_ERR_INVALID_ENVELOPE;
}

std::optional<PublicKey>
ConnectionRegistry::get_pinned_device_pk(const PublicKey& peer_pk) const {
    std::shared_lock lock(pin_mu_);
    auto it = peer_pin_map_.find(peer_pk);
    if (it == peer_pin_map_.end()) return std::nullopt;
    return it->second;
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
