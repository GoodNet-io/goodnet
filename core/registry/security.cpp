/// @file   core/registry/security.cpp

#include "security.hpp"

#include <mutex>

namespace gn::core {

gn_result_t SecurityRegistry::register_provider(
    std::string_view provider_id,
    const gn_security_provider_vtable_t* vtable,
    void* self,
    std::shared_ptr<void> lifetime_anchor) noexcept {

    if (provider_id.empty() || vtable == nullptr) return GN_ERR_NULL_ARG;

    std::unique_lock lock(mu_);
    if (active_) return GN_ERR_LIMIT_REACHED;

    entry_.provider_id     = provider_id;
    entry_.vtable          = vtable;
    entry_.self            = self;
    entry_.lifetime_anchor = std::move(lifetime_anchor);
    active_                = true;
    return GN_OK;
}

gn_result_t SecurityRegistry::unregister_provider(
    std::string_view provider_id) noexcept {

    std::unique_lock lock(mu_);
    if (!active_ || entry_.provider_id != provider_id) {
        return GN_ERR_UNKNOWN_RECEIVER;
    }
    entry_ = SecurityEntry{};
    active_ = false;
    return GN_OK;
}

SecurityEntry SecurityRegistry::current() const {
    std::shared_lock lock(mu_);
    return active_ ? entry_ : SecurityEntry{};
}

bool SecurityRegistry::is_active() const noexcept {
    std::shared_lock lock(mu_);
    return active_;
}

} // namespace gn::core
