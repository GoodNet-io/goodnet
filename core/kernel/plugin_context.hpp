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

namespace gn::core {

class Kernel;

struct PluginContext {
    std::string             plugin_name;   ///< stable identifier; e.g. `"libgoodnet_tcp"`
    gn_plugin_kind_t        kind{GN_PLUGIN_KIND_UNKNOWN};
    Kernel*                 kernel{nullptr};

    /// Strong reference-counted handle that proves the plugin's
    /// shared object is still mapped. Registry entries copy this
    /// anchor at register time; dispatch snapshots inherit the copy
    /// via value semantics. PluginManager observes the anchor through
    /// a weak_ptr during teardown — only after the weak observer
    /// reports expiry is `dlclose` safe to call (see
    /// `plugin-lifetime.md` §4 reference-counted ownership). Null
    /// anchor means "no quiescence wait needed for entries from this
    /// context" — used by in-tree tests that exercise registries
    /// without a plugin manager.
    std::shared_ptr<void>   plugin_anchor;
};

} // namespace gn::core
