/// @file   core/kernel/plugin_context.hpp
/// @brief  Per-plugin context the kernel hands through `host_api->host_ctx`.
///
/// Carries the plugin name (used for log prefixing) and a back-pointer
/// to the Kernel so host_api thunks can reach data-path components.
/// The struct lives kernel-side; plugins see only the opaque
/// `void* host_ctx` field on `host_api_t`.

#pragma once

#include <string>

#include <sdk/plugin.h>

namespace gn::core {

class Kernel;

struct PluginContext {
    std::string      plugin_name;   ///< stable identifier; e.g. `"libgoodnet_tcp"`
    gn_plugin_kind_t kind{GN_PLUGIN_KIND_UNKNOWN};
    Kernel*          kernel{nullptr};
};

} // namespace gn::core
