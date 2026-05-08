/// @file   core/registry/security.cpp

#include "security.hpp"

namespace gn::core {

gn_result_t SecurityRegistry::register_provider(
    std::string_view provider_id,
    const gn_security_provider_vtable_t* vtable,
    void* self,
    std::shared_ptr<void> lifetime_anchor) noexcept {

    if (provider_id.empty() || vtable == nullptr) return GN_ERR_NULL_ARG;

    /// `abi-evolution.md` §3a: defensive size-prefix check.
    if (vtable->api_size < sizeof(gn_security_provider_vtable_t)) {
        return GN_ERR_VERSION_MISMATCH;
    }

    auto fresh = std::make_shared<const SecurityEntry>(SecurityEntry{
        .provider_id     = std::string{provider_id},
        .vtable          = vtable,
        .self            = self,
        .lifetime_anchor = std::move(lifetime_anchor),
    });

    /// CAS from empty to fresh. A non-null incumbent means the
    /// slot is taken; reject without mutating it.
    std::shared_ptr<const SecurityEntry> empty;
    if (!entry_.compare_exchange_strong(empty, std::move(fresh),
                                         std::memory_order_acq_rel,
                                         std::memory_order_acquire)) {
        return GN_ERR_LIMIT_REACHED;
    }
    return GN_OK;
}

gn_result_t SecurityRegistry::unregister_provider(
    std::string_view provider_id) noexcept {

    auto cur = entry_.load(std::memory_order_acquire);
    if (!cur || cur->provider_id != provider_id) {
        return GN_ERR_NOT_FOUND;
    }
    /// Swap to empty atomically. A concurrent register would have
    /// observed the slot taken; a concurrent unregister observes
    /// the same `cur` and the CAS only succeeds for one of them.
    std::shared_ptr<const SecurityEntry> empty;
    if (!entry_.compare_exchange_strong(cur, std::move(empty),
                                         std::memory_order_acq_rel,
                                         std::memory_order_acquire)) {
        return GN_ERR_NOT_FOUND;
    }
    return GN_OK;
}

SecurityEntry SecurityRegistry::current() const {
    auto cur = entry_.load(std::memory_order_acquire);
    return cur ? *cur : SecurityEntry{};
}

bool SecurityRegistry::is_active() const noexcept {
    return static_cast<bool>(entry_.load(std::memory_order_acquire));
}

} // namespace gn::core
