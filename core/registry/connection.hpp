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
    std::string        transport_scheme;

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
    /// the proposed key. No partial state becomes visible on failure.
    [[nodiscard]] gn_result_t insert_with_index(ConnectionRecord rec) noexcept;

    /// Remove the record with id @p id from all three indexes.
    [[nodiscard]] gn_result_t erase_with_index(gn_conn_id_t id) noexcept;

    /// Snapshot lookup by id.
    [[nodiscard]] std::optional<ConnectionRecord> find_by_id(gn_conn_id_t id) const;

    /// Promote a record's `trust` field through the policy gate from
    /// `sdk/trust.h`. Only `Untrusted → Peer` is a real transition;
    /// identity targets are a no-op success; every other combination
    /// returns `GN_ERR_LIMIT_REACHED` and leaves the record untouched.
    /// The contract is one-way — there is no `downgrade_trust` because
    /// security weakening is a closure event, not a registry mutation.
    [[nodiscard]] gn_result_t upgrade_trust(gn_conn_id_t id,
                                             gn_trust_class_t target) noexcept;

    /// Snapshot lookup by URI string.
    [[nodiscard]] std::optional<ConnectionRecord> find_by_uri(std::string_view uri) const;

    /// Snapshot lookup by remote public key.
    [[nodiscard]] std::optional<ConnectionRecord> find_by_pk(const PublicKey& pk) const;

    /// Number of records currently held; useful for tests.
    [[nodiscard]] std::size_t size() const noexcept;

private:
    struct Shard {
        mutable std::shared_mutex mu;
        std::unordered_map<gn_conn_id_t, ConnectionRecord> records;
    };

    /// Shard owning a given id.
    [[nodiscard]] Shard&       shard_for(gn_conn_id_t id) noexcept;
    [[nodiscard]] const Shard& shard_for(gn_conn_id_t id) const noexcept;

    std::array<Shard, kShardCount> shards_;

    mutable std::shared_mutex uri_mu_;
    std::unordered_map<std::string, gn_conn_id_t> uri_index_;

    mutable std::shared_mutex pk_mu_;
    std::unordered_map<PublicKey, gn_conn_id_t, PublicKeyHash> pk_index_;

    /// Monotonic id allocator. `GN_INVALID_ID == 0` is reserved, so
    /// the counter starts at 1.
    std::atomic<gn_conn_id_t> next_id_{1};
};

} // namespace gn::core
