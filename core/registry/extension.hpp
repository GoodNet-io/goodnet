/// @file   core/registry/extension.hpp
/// @brief  Named extension vtable lookup with semver gating.
///
/// Plugins publish typed vtables under stable names (`"gn.heartbeat"`
/// for the single-entry case, `"gn.transport.<scheme>"` for a
/// multi-entry family) so other plugins can call them without
/// linking. Kernel-side registry holds the (name, version, vtable)
/// triple; lookups verify a requested major/minor version is
/// compatible with the registered one.

#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include <sdk/types.h>

namespace gn::core {

/// One registered extension. Values are copied on lookup so the
/// caller does not race with concurrent unregister on the vtable
/// pointer; the producer is responsible for keeping the vtable
/// alive until `unregister_extension` returns.
struct ExtensionEntry {
    std::string           name;
    std::uint32_t         version = 0;
    const void*           vtable  = nullptr;

    /// Strong reference to the registering plugin's quiescence
    /// sentinel. `query_prefix` snapshots inherit it via value-copy.
    /// The C-ABI `query_extension_checked` path returns only the
    /// vtable pointer for back-compat; transport-composition consumers
    /// that want an anchor-bearing handle should reach for the C++
    /// `query_extension_with_anchor` overload.
    std::shared_ptr<void> lifetime_anchor;
};

class ExtensionRegistry {
public:
    ExtensionRegistry()                                    = default;
    ExtensionRegistry(const ExtensionRegistry&)            = delete;
    ExtensionRegistry& operator=(const ExtensionRegistry&) = delete;

    /// Register a vtable under @p name with @p version. Fails with
    /// `GN_ERR_LIMIT_REACHED` if @p name is already taken OR the live
    /// entry count already equals the `set_max_extensions` cap
    /// (`limits.md` §4a).
    /// @p lifetime_anchor mirrors `HandlerRegistry::register_handler`.
    [[nodiscard]] gn_result_t register_extension(std::string_view name,
                                                 std::uint32_t version,
                                                 const void* vtable,
                                                 std::shared_ptr<void> lifetime_anchor = {}) noexcept;

    /// Set the live-entry cap (`gn_limits_t::max_extensions`). A cap
    /// of zero disables the check; non-zero values reject registrations
    /// whose acceptance would push the live count above @p cap.
    void set_max_extensions(std::uint32_t cap) noexcept;

    /// Remove an extension by name.
    [[nodiscard]] gn_result_t unregister_extension(std::string_view name) noexcept;

    /// Look up @p name and verify the registered version is compatible
    /// with @p requested_version. Compatibility rule from
    /// `abi-evolution.md` §2: major must match exactly, registered
    /// minor must be >= requested minor. Returns the vtable pointer
    /// through @p out_vtable on success, NULL on miss or mismatch.
    [[nodiscard]] gn_result_t query_extension_checked(std::string_view name,
                                                      std::uint32_t requested_version,
                                                      const void** out_vtable) const noexcept;

    /// Return every entry whose name starts with @p prefix. Plugins
    /// that group their vtables under a shared dotted namespace
    /// enumerate the family through this entry without holding a
    /// separate index.
    [[nodiscard]] std::vector<ExtensionEntry>
    query_prefix(std::string_view prefix) const;

    [[nodiscard]] std::size_t size() const noexcept;

private:
    mutable std::shared_mutex                       mu_;
    std::unordered_map<std::string, ExtensionEntry> entries_;
    std::uint32_t                                   max_entries_ = 0;
};

} // namespace gn::core
