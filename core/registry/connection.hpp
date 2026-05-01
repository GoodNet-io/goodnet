/// @file   core/registry/connection.hpp
/// @brief  Sharded connection registry with atomic insert-with-index.
///
/// Implements `docs/contracts/registry.md`. Three indexes (id, URI,
/// pk) are kept in lockstep through a single insert/erase operation.
/// Lookups by any of the three return a value-type snapshot of the
/// record so callers do not race with concurrent erase.

#pragma once

#include <array>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>

#include <sdk/cpp/types.hpp>
#include <sdk/endpoint.h>
#include <sdk/trust.h>
#include <sdk/types.h>

namespace gn::core {

/// Hash specialisation for PublicKey suitable for unordered_map. Public
/// keys are uniformly distributed; the leading machine-word bytes give
/// a sound hash without further mixing.
struct PublicKeyHash {
    [[nodiscard]] std::size_t operator()(const PublicKey& pk) const noexcept {
        std::size_t h = 0;
        std::memcpy(&h, pk.data(), sizeof(h));
        return h;
    }
};

/// Single connection record. Held inside a registry shard; copied out
/// of the shard for any caller that needs to outlive a single
/// shard-lock acquisition.
struct ConnectionRecord {
    gn_conn_id_t       id           = GN_INVALID_ID;
    PublicKey          remote_pk    {};
    std::string        uri;
    gn_trust_class_t   trust        = GN_TRUST_UNTRUSTED;
    gn_handshake_role_t role        = GN_ROLE_INITIATOR;
    std::string        link_scheme;

    /// Relay capability: when set, the protocol layer accepts inbound
    /// frames carrying EXPLICIT_SENDER / EXPLICIT_RECEIVER (relay or
    /// broadcast paths) per `gnet-protocol.md` §5. Default `false`
    /// implies the connection is a regular peer; the deframe layer
    /// rejects EXPLICIT_SENDER as a sender_pk-spoofing attempt.
    /// Operator-supplied through configuration / a future relay
    /// handler API; pre-RC the default-deny path applies everywhere.
    bool               allows_relay = false;

    /// Counters surfaced through `host_api->get_endpoint`.
    std::uint64_t bytes_in            = 0;
    std::uint64_t bytes_out           = 0;
    std::uint64_t frames_in           = 0;
    std::uint64_t frames_out          = 0;
    std::uint64_t pending_queue_bytes = 0;
    std::uint64_t last_rtt_us         = 0;
};

/// Connection registry with three indexes kept in lockstep.
///
/// Sharded by `id mod kShardCount`. The shard mutex, URI index mutex,
/// and pk index mutex are acquired in a fixed total order on every
/// mutation; `std::scoped_lock` does the ordering for us.
class ConnectionRegistry {
public:
    static constexpr std::size_t kShardCount = 16;

    ConnectionRegistry()                                     = default;
    ConnectionRegistry(const ConnectionRegistry&)            = delete;
    ConnectionRegistry& operator=(const ConnectionRegistry&) = delete;

    /// Allocate a fresh connection id. Never returns `GN_INVALID_ID`.
    /// Per `registry.md` §6, this is the only authoritative source of ids.
    [[nodiscard]] gn_conn_id_t alloc_id() noexcept;

    /// Insert @p rec under all three indexes atomically.
    ///
    /// Fails with `GN_ERR_LIMIT_REACHED` if any index already contains
    /// the proposed key OR the live record count already equals the
    /// `set_max_connections` cap (`limits.md` §4a). No partial state
    /// becomes visible on failure.
    [[nodiscard]] gn_result_t insert_with_index(ConnectionRecord rec) noexcept;

    /// Set the live-record cap (`gn_limits_t::max_connections`). A
    /// cap of zero disables the check; non-zero values reject inserts
    /// whose acceptance would push the live count above @p cap.
    void set_max_connections(std::uint32_t cap) noexcept;

    /// Remove the record with id @p id from all three indexes.
    [[nodiscard]] gn_result_t erase_with_index(gn_conn_id_t id) noexcept;

    /// Implements `registry.md` §4a atomic snapshot variant: returns
    /// the pre-erase record (per-connection counters folded in) and
    /// removes it from all three indexes under one critical section;
    /// `nullopt` when the id was not present.
    [[nodiscard]] std::optional<ConnectionRecord>
    snapshot_and_erase(gn_conn_id_t id) noexcept;

    /// Snapshot lookup by id.
    [[nodiscard]] std::optional<ConnectionRecord> find_by_id(gn_conn_id_t id) const;

    /// Promote a record's `trust` field through the policy gate from
    /// `sdk/trust.h`. Only `Untrusted → Peer` is a real transition;
    /// identity targets are a no-op success; every other combination
    /// returns `GN_ERR_LIMIT_REACHED` and leaves the record untouched.
    /// The contract is one-way — there is no `downgrade_trust` because
    /// security weakening is a closure event, not a registry mutation.
    ///
    /// When @p out_record is non-null and the upgrade succeeds, the
    /// post-upgrade record is captured under the same shard lock that
    /// commits the new trust class, so the caller observes a
    /// snapshot consistent with the trust value it just set.
    [[nodiscard]] gn_result_t upgrade_trust(gn_conn_id_t id,
                                             gn_trust_class_t target,
                                             ConnectionRecord* out_record = nullptr) noexcept;

    /// Update the record's `remote_pk` after a security session has
    /// completed its handshake and the peer's static public key is
    /// available (Noise `peer_static_pk`, TLS SPKI, etc).
    ///
    /// Drives `registry.md` §7a post-handshake peer-pk propagation:
    /// until this update fires the responder's `remote_pk` is
    /// whatever placeholder the link plugin passed at
    /// `notify_connect` (typically zeros), so the cross-session pin
    /// gate (§8a) keys on the placeholder and is structurally dead.
    ///
    /// Returns:
    /// - `GN_OK` on success or no-op (`remote_pk` already equals
    ///   @p new_pk, which is the initiator path).
    /// - `GN_ERR_NOT_FOUND` if no record carries id @p id.
    /// - `GN_ERR_LIMIT_REACHED` if @p new_pk is already mapped to a
    ///   different `conn_id` in the pk index — an identity-collision
    ///   attempt; the caller should tear down the connection.
    [[nodiscard]] gn_result_t update_remote_pk(gn_conn_id_t id,
                                                const PublicKey& new_pk) noexcept;

    /// Snapshot lookup by URI string.
    [[nodiscard]] std::optional<ConnectionRecord> find_by_uri(std::string_view uri) const;

    /// Snapshot lookup by remote public key.
    [[nodiscard]] std::optional<ConnectionRecord> find_by_pk(const PublicKey& pk) const;

    /// Number of records currently held.
    [[nodiscard]] std::size_t size() const noexcept;

    /// Iterate every record under per-shard read locks. The visitor
    /// returns `true` to continue, `false` to stop. The visitor must
    /// not call back into mutating methods on this registry —
    /// the shard locks are held for the duration. Per
    /// `conn-events.md` §4.
    void for_each(
        const std::function<bool(const ConnectionRecord&)>& visitor) const;

    /// Lock-free counter accessors — kernel thunks fold these into
    /// the inbound / outbound / backpressure paths so per-conn
    /// observability surfaces through `get_endpoint` without
    /// per-frame shard-lock contention. Each record owns an
    /// `AtomicCounters` block created on `insert_with_index` and
    /// erased with the record. Calls on a missing id are silent
    /// no-ops.
    void add_inbound(gn_conn_id_t id, std::uint64_t bytes,
                     std::uint64_t frames) noexcept;
    void add_outbound(gn_conn_id_t id, std::uint64_t bytes,
                      std::uint64_t frames) noexcept;
    void set_pending_bytes(gn_conn_id_t id,
                           std::uint64_t bytes) noexcept;

    /// Per-peer device-key pinning. A peer's `remote_pk` (mesh
    /// address) maps to a `device_pk` (the attestation cert's
    /// signing key) the first time the attestation dispatcher
    /// accepts an envelope from that peer. Subsequent attestations
    /// from the same peer must carry the same device_pk; a
    /// mismatch is an identity-change attempt and the dispatcher
    /// disconnects. The map outlives connection records so the
    /// pinning persists across reconnects.
    [[nodiscard]] gn_result_t pin_device_pk(const PublicKey& peer_pk,
                                             const PublicKey& device_pk) noexcept;
    [[nodiscard]] std::optional<PublicKey>
        get_pinned_device_pk(const PublicKey& peer_pk) const;
    void clear_pinned_device_pk(const PublicKey& peer_pk) noexcept;
    [[nodiscard]] std::size_t pin_count() const noexcept;

private:
    struct AtomicCounters {
        std::atomic<std::uint64_t> bytes_in{0};
        std::atomic<std::uint64_t> bytes_out{0};
        std::atomic<std::uint64_t> frames_in{0};
        std::atomic<std::uint64_t> frames_out{0};
        std::atomic<std::uint64_t> pending_queue_bytes{0};
        std::atomic<std::uint64_t> last_rtt_us{0};
    };

    struct Shard {
        mutable std::shared_mutex mu;
        std::unordered_map<gn_conn_id_t, ConnectionRecord> records;
        std::unordered_map<gn_conn_id_t,
                            std::unique_ptr<AtomicCounters>> counters;
    };

    /// Shard owning a given id.
    [[nodiscard]] Shard&       shard_for(gn_conn_id_t id) noexcept;
    [[nodiscard]] const Shard& shard_for(gn_conn_id_t id) const noexcept;

    std::array<Shard, kShardCount> shards_;

    mutable std::shared_mutex uri_mu_;
    std::unordered_map<std::string, gn_conn_id_t> uri_index_;

    mutable std::shared_mutex pk_mu_;
    std::unordered_map<PublicKey, gn_conn_id_t, PublicKeyHash> pk_index_;

    mutable std::shared_mutex pin_mu_;
    std::unordered_map<PublicKey, PublicKey, PublicKeyHash> peer_pin_map_;

    /// Monotonic id allocator. `GN_INVALID_ID == 0` is reserved, so
    /// the counter starts at 1.
    std::atomic<gn_conn_id_t> next_id_{1};

    /// Live record count + cap (`limits.md` §4a). `live_count_` is
    /// incremented on successful insert and decremented on any erase
    /// path. Zero `max_connections_` disables the cap check.
    std::atomic<std::uint32_t> live_count_{0};
    std::atomic<std::uint32_t> max_connections_{0};
};

} // namespace gn::core
