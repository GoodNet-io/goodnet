/// @file   core/registry/security.hpp
/// @brief  Single active security provider holder.
///
/// Per `security-trust.md` §4 a node uses one default security
/// provider per trust class. v1 simplification: one provider total.
/// Multi-class policy lands when StackRegistry arrives.

#pragma once

#include <atomic>
#include <shared_mutex>
#include <string>
#include <string_view>

#include <sdk/security.h>
#include <sdk/types.h>

namespace gn::core {

struct SecurityEntry {
    std::string                          provider_id;
    const gn_security_provider_vtable_t* vtable = nullptr;
    void*                                self   = nullptr;
};

class SecurityRegistry {
public:
    SecurityRegistry()                                    = default;
    SecurityRegistry(const SecurityRegistry&)             = delete;
    SecurityRegistry& operator=(const SecurityRegistry&)  = delete;

    /// Install @p vtable as the kernel's active security provider.
    /// Returns `GN_ERR_LIMIT_REACHED` when one is already registered.
    [[nodiscard]] gn_result_t register_provider(std::string_view provider_id,
                                                const gn_security_provider_vtable_t* vtable,
                                                void* self) noexcept;

    /// Remove the provider matching @p provider_id.
    [[nodiscard]] gn_result_t unregister_provider(std::string_view provider_id) noexcept;

    /// Snapshot of the currently active provider, or nullopt.
    [[nodiscard]] SecurityEntry current() const;

    [[nodiscard]] bool is_active() const noexcept;

private:
    mutable std::shared_mutex mu_;
    SecurityEntry             entry_{};
    bool                      active_{false};
};

} // namespace gn::core
