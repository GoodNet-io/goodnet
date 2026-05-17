/// @file   core/plugin/plugin_runtime.hpp
/// @brief  Polymorphic plugin-loader interface.
///
/// One implementation per linkage kind (dynamic / static / remote).
/// `PluginManager` looks up the right runtime by the manifest entry's
/// `kind` field and dispatches every lifecycle step through it.
///
/// State for each loaded plugin lives on the `PluginInstance` struct
/// the runtime fills in `load()`. The runtime itself is stateless
/// dispatch — adding a new linkage kind means implementing this
/// interface and registering an instance with `PluginManager`,
/// without touching any other lifecycle site.
///
/// The contract is kernel-internal. A future SDK slot
/// (`gn_core_register_runtime`) will admit external host-side
/// runtimes (Wasm, FFI-via-IPC) by adapting a C vtable into the
/// same interface — additive, non-breaking.

#pragma once

#include <memory>
#include <string>
#include <string_view>

#include <sdk/host_api.h>
#include <sdk/types.h>

namespace gn::core {

class PluginManifest;
struct PluginInstance;

class IPluginRuntime {
public:
    virtual ~IPluginRuntime() = default;

    /// Invoke `gn_plugin_init` (or the runtime's equivalent). The
    /// instance's `self` field is filled on success. The `api`
    /// pointer is the per-instance host_api table the runtime
    /// passes to the plugin's init entry — dynamic plugins reach
    /// `&inst.api` directly, remote workers carry the table over
    /// the wire.
    virtual gn_result_t init(PluginInstance& inst) = 0;

    /// Invoke `gn_plugin_register(self)` or the runtime's equivalent.
    virtual gn_result_t register_plugin(PluginInstance& inst) = 0;

    /// Invoke `gn_plugin_unregister(self)`. Best-effort: failures are
    /// surfaced to the caller but the rollback chain continues
    /// regardless. Returns GN_OK on every successful dispatch and
    /// the plugin's own status code when the entry returned an
    /// error.
    virtual void unregister(PluginInstance& inst) = 0;

    /// Invoke `gn_plugin_shutdown(self)`. Void return — same
    /// best-effort discipline as `unregister`.
    virtual void shutdown(PluginInstance& inst) = 0;

    /// Stable identifier; matches the manifest entry's `kind`
    /// string. The default "dynamic" / "static" / "remote" runtimes
    /// claim those three keys.
    [[nodiscard]] virtual std::string_view name() const noexcept = 0;
};

}  // namespace gn::core
