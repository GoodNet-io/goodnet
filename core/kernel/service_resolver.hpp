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
    std::vector<std::pair<std::string, std::uint32_t>> inject_targets;

    /// (protocol_id, msg_id) pairs this plugin handles via register_vtable.
    /// msg_id == 0 is wildcard. Populated by the plugin manager from the
    /// vtable registration calls or the handler descriptor's protocol_id/msg_id.
    std::vector<std::pair<std::string, std::uint32_t>> inject_handles;
};

class ServiceResolver {
public:
    /// Sort @p input topologically over the ext-graph.
    ///
    /// Writes the ordered set into @p out_ordered on success.
    /// On any structural failure, @p out_diagnostic (if non-null)
    /// receives a human-readable description of the offending
    /// node.
    ///
    /// Return codes:
    ///   - `GN_OK` — sorted set written to @p out_ordered.
    ///   - `GN_ERR_LIMIT_REACHED` — duplicate provider for a name.
    ///   - `GN_ERR_NOT_FOUND` — required extension has no
    ///     provider.
    ///   - `GN_ERR_INVALID_ENVELOPE` — graph contains a cycle.
    [[nodiscard]] static gn_result_t resolve(
        std::span<const ServiceDescriptor> input,
        std::vector<ServiceDescriptor>& out_ordered,
        std::string* out_diagnostic = nullptr);
};

} // namespace gn::core
