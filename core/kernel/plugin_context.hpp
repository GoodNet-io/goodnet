/// @file   core/kernel/plugin_context.hpp
/// @brief  Per-plugin context the kernel hands through `host_api->host_ctx`.
///
/// Carries the plugin name (used for log prefixing) and a back-pointer
/// to the Kernel so host_api thunks can reach data-path components.
/// The struct lives kernel-side; plugins see only the opaque
/// `void* host_ctx` field on `host_api_t`.

#pragma once

#include <memory>
#include <string>

#include <sdk/plugin.h>

#include "plugin_anchor.hpp"

namespace gn::core {

class Kernel;

struct PluginContext {
    std::string             plugin_name;   ///< stable identifier; e.g. `"libgoodnet_tcp"`
    gn_plugin_kind_t        kind{GN_PLUGIN_KIND_UNKNOWN};
    Kernel*                 kernel{nullptr};

    /// Per-plugin liveness sentinel + cancellation gate. Registries
    /// copy the shared_ptr into every entry (and dispatch snapshots
    /// inherit the copy by value) so synchronous dispatch holds the
    /// plugin's `.text` mapped through every vtable call. Async
    /// callback sites pair the anchor with a `GateGuard` so the
    /// `in_flight` counter and the `shutdown_requested` flag form
    /// the explicit barrier the rollback path waits on before
    /// `dlclose` (see `plugin-lifetime.md` §4 and `plugin_anchor.hpp`).
    /// A null anchor means "no quiescence wait needed for entries
    /// from this context" — used by in-tree tests that exercise
    /// registries without a plugin manager.
    std::shared_ptr<PluginAnchor> plugin_anchor;
};

} // namespace gn::core
