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

    /// Open the plugin and populate @p out. On failure @p out is
    /// untouched and @p diag carries the human-readable reason.
    /// The runtime is responsible for the kind-specific integrity
    /// check (digest verification for dlopen / fork-and-hash for
    /// remote / no-op for static-linked) before any plugin code
    /// runs.
    virtual gn_result_t load(
        const std::string& path,
        const PluginManifest& manifest,
        PluginInstance& out,
        std::string& diag) = 0;

    /// Invoke `gn_plugin_init(api, &self)` or the runtime's
    /// equivalent. The instance's `self` field is filled on success.
    virtual gn_result_t init(
        PluginInstance& inst,
        const host_api_t* api) = 0;

    /// Invoke `gn_plugin_register(self)` or the runtime's equivalent.
    virtual gn_result_t register_plugin(PluginInstance& inst) = 0;

    /// Invoke `gn_plugin_unregister(self)`. Best-effort: failures are
    /// logged but do not abort the rollback chain.
    virtual gn_result_t unregister(PluginInstance& inst) = 0;

    /// Invoke `gn_plugin_shutdown(self)`. Void return — same reason.
    virtual void shutdown(PluginInstance& inst) = 0;

    /// Tear down the load-time state — `dlclose` for dynamic, no-op
    /// for static, terminate-and-reap for remote.
    virtual void close(PluginInstance& inst) = 0;

    /// Stable identifier; matches the manifest entry's `kind`
    /// string. The default "dynamic" / "static" / "remote" runtimes
    /// claim those three keys.
    [[nodiscard]] virtual std::string_view name() const noexcept = 0;
};

}  // namespace gn::core
