/// @file   core/kernel/identity_set.hpp
/// @brief  Set of local node identities for multi-tenant routing.
///
/// A kernel may host more than one node identity in one process. The
/// router consults this set to decide whether an inbound envelope is
/// addressed to the local node or needs to be relayed (or dropped).

#pragma once

#include <cstddef>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <unordered_set>

#include <sdk/cpp/types.hpp>

#include <core/registry/connection.hpp>  // for PublicKeyHash

namespace gn::core {

/// Thread-safe set of local public keys.
///
/// Adds and removes are exclusive; contains is shared. The single-
/// identity case (vector of size 1) is the steady state for typical
/// deployments; multi-tenant kernels grow the set at boot.
class LocalIdentitySet {
public:
    LocalIdentitySet()                                   = default;
    LocalIdentitySet(const LocalIdentitySet&)            = delete;
    LocalIdentitySet& operator=(const LocalIdentitySet&) = delete;

    /// Insert @p pk. Idempotent: re-inserting a present pk is a no-op.
    void add(const PublicKey& pk) {
        std::unique_lock lock(mu_);
        set_.insert(pk);
    }

    /// Remove @p pk if present.
    void remove(const PublicKey& pk) {
        std::unique_lock lock(mu_);
        set_.erase(pk);
    }

    /// True if @p pk is one of the local node identities.
    [[nodiscard]] bool contains(const PublicKey& pk) const {
        std::shared_lock lock(mu_);
        return set_.contains(pk);
    }

    [[nodiscard]] std::size_t size() const {
        std::shared_lock lock(mu_);
        return set_.size();
    }

    /// Return any one identity from the set, or nullopt if empty.
    /// Used by the inbound-bytes thunk for the single-identity case;
    /// multi-tenant routing per `protocol-layer.md` §6 picks the right
    /// identity from the envelope's `receiver_pk` instead.
    [[nodiscard]] std::optional<PublicKey> any() const {
        std::shared_lock lock(mu_);
        if (set_.empty()) return std::nullopt;
        return *set_.begin();
    }

private:
    mutable std::shared_mutex                            mu_;
    std::unordered_set<PublicKey, PublicKeyHash>         set_;
};

} // namespace gn::core
