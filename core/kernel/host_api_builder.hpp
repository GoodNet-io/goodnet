/// @file   core/kernel/host_api_builder.hpp
/// @brief  Constructs `host_api_t` instances for plugins.
///
/// Thunks defined in the .cpp file cast `host_ctx` to `PluginContext*`
/// and reach into the kernel's data-path components per the slot
/// semantics in `docs/contracts/host-api.md` §2.

#pragma once

#include <sdk/host_api.h>

#include "plugin_context.hpp"

namespace gn::core {

/// Build a populated `host_api_t` whose function pointers route into
/// the kernel through @p ctx. The returned table is value-typed; the
/// caller stores it alongside the plugin and passes its address to
/// `gn_plugin_init`.
///
/// Currently implemented slots: `register_handler`, `unregister_handler`,
/// `limits`, `log`, `notify_connect`, `notify_inbound_bytes`,
/// `notify_disconnect`. Other slots are NULL — plugins guard with
/// `GN_API_HAS` per `abi-evolution.md` §3.
[[nodiscard]] host_api_t build_host_api(PluginContext& ctx);

} // namespace gn::core
