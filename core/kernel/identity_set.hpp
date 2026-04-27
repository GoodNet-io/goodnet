/// @file   core/kernel/identity_set.hpp
/// @brief  Set of local node identities for multi-tenant routing.
///
/// A kernel may host more than one node identity in one process. The
/// router consults this set to decide whether an inbound envelope is
/// addressed to the local node or needs to be relayed (or dropped).

#pragma once

#include <cstddef>
#include <mutex>
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

private:
    mutable std::shared_mutex                            mu_;
    std::unordered_set<PublicKey, PublicKeyHash>         set_;
};

} // namespace gn::core
