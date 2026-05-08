/// @file   core/registry/security.hpp
/// @brief  Single active security provider holder.
///
/// Per `security-trust.md` §4 a node uses one default security
/// provider per trust class. v1 simplification: one provider total.
/// The backend is `std::atomic<std::shared_ptr<const SecurityEntry>>`
/// — a CAS-driven swap; the registry-shape mutex+bool that v0 used
/// was over-built for a single-slot holder. Multi-class policy lands
/// when StackRegistry arrives in v1.x.

#pragma once

#include <atomic>
#include <memory>
#include <string>
#include <string_view>

#include <sdk/security.h>
#include <sdk/types.h>

namespace gn::core {

struct SecurityEntry {
    std::string                          provider_id;
    const gn_security_provider_vtable_t* vtable = nullptr;
    void*                                self   = nullptr;

    /// Same shape as `HandlerEntry::lifetime_anchor`. The kernel
    /// snapshots `SecurityRegistry::current()` value-style; the
    /// returned anchor lives for the duration of the snapshot.
    std::shared_ptr<void>                lifetime_anchor;
};

class SecurityRegistry {
public:
    SecurityRegistry()                                    = default;
    SecurityRegistry(const SecurityRegistry&)             = delete;
    SecurityRegistry& operator=(const SecurityRegistry&)  = delete;

    /// Install @p vtable as the kernel's active security provider.
    /// Returns `GN_ERR_LIMIT_REACHED` when one is already registered.
    /// @p lifetime_anchor mirrors `HandlerRegistry::register_handler`.
    [[nodiscard]] gn_result_t register_provider(std::string_view provider_id,
                                                const gn_security_provider_vtable_t* vtable,
                                                void* self,
                                                std::shared_ptr<void> lifetime_anchor = {}) noexcept;

    /// Remove the provider matching @p provider_id.
    [[nodiscard]] gn_result_t unregister_provider(std::string_view provider_id) noexcept;

    /// Snapshot of the currently active provider, or a default-
    /// constructed entry when no provider is installed.
    [[nodiscard]] SecurityEntry current() const;

    [[nodiscard]] bool is_active() const noexcept;

private:
    std::atomic<std::shared_ptr<const SecurityEntry>> entry_{nullptr};
};

} // namespace gn::core
