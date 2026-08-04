/// @file   core/kernel/service_resolver.hpp
/// @brief  Toposort plugin descriptors over the ext_requires graph.
///
/// Plugin descriptors carry `ext_requires` and `ext_provides` arrays
/// per `plugin-lifetime.en.md` §3 and the corresponding C ABI surface
/// in `sdk/plugin.h`. The kernel sorts the descriptors so providers
/// come before consumers, then runs the two-phase activation
/// (`init_all` then `register_all`) on the ordered set.
///
/// Errors detected:
///   - Duplicate provider: two plugins claim the same extension name.
///   - Unresolved requirement: a plugin requires an extension nobody
///     provides.
///   - Cycle: providers form a strongly-connected component.

#pragma once

#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <utility>

#include <sdk/plugin.h>
#include <vector>

#include <sdk/types.h>

namespace gn::core {

/// Descriptor a plugin contributes to the resolver. Names are
/// stable strings owned by the caller for the lifetime of the
/// resolve call.
struct ServiceDescriptor {
    std::string              plugin_name;
    std::vector<std::string> ext_requires;
    std::vector<std::string> ext_provides;
    gn_plugin_kind_t         kind{GN_PLUGIN_KIND_UNKNOWN};

    /// (protocol_id, msg_id) pairs this plugin injects into.
    /// msg_id == 0 is wildcard — the plugin may inject any msg_id
    /// into that protocol. Populated from gn_plugin_descriptor_t::inject_targets.
    std::vector<std::pair<std::string, std::uint32_t>> inject_targets = {};

    /// Config key prefixes this plugin is allowed to read via config_get().
    /// Empty means unrestricted. Populated from gn_plugin_descriptor_t::reads_config.
    std::vector<std::string> reads_config = {};

    /// Whether the plugin may call announce_rotation().
    bool may_rotate = false;

    /// Bitmask of gn_key_purpose_t values this plugin may pass to sign_local().
    /// Zero means unrestricted. Populated from gn_plugin_descriptor_t::sign_purposes.
    std::uint32_t sign_purposes = 0;

    /// (protocol_id, msg_id) pairs this plugin handles via register_vtable.
    /// msg_id == 0 is wildcard. Populated by the plugin manager from the
    /// vtable registration calls or the handler descriptor's protocol_id/msg_id.
    std::vector<std::pair<std::string, std::uint32_t>> inject_handles = {};
};

class ServiceResolver {
public:
    struct Error {
        gn_result_t code    = GN_OK;
        std::string message;
    };

    /// Sort @p input topologically over the ext-graph.
    ///
    /// Returns the ordered set on success.
    /// On any structural failure returns an `Error` with a
    /// human-readable description and the matching result code:
    ///   - `GN_ERR_LIMIT_REACHED` — duplicate provider for a name.
    ///   - `GN_ERR_NOT_FOUND` — required extension has no provider.
    ///   - `GN_ERR_INVALID_ENVELOPE` — graph contains a cycle.
    [[nodiscard]] static std::expected<std::vector<ServiceDescriptor>, Error>
    resolve(std::span<const ServiceDescriptor> input);
};

} // namespace gn::core
