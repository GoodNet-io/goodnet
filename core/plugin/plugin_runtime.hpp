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

class Kernel;
class PluginManifest;
struct PluginInstance;

/// Inputs the load step needs from the surrounding `PluginManager`.
/// The struct is built fresh on every `load()` call so runtimes do
/// not capture kernel state across instances.
struct PluginLoadContext {
    /// Kernel reference for PluginContext construction.
    Kernel*               kernel{nullptr};
    /// Operator integrity allowlist; empty in developer mode.
    const PluginManifest* manifest{nullptr};
    /// When true and `manifest` is empty, the load must fail with
    /// `GN_ERR_INTEGRITY_FAILED`. Operators flip this through
    /// `PluginManager::set_manifest_required`.
    bool                  manifest_required{false};
};

class IPluginRuntime {
public:
    virtual ~IPluginRuntime() = default;

    /// Open the plugin and populate @p out. On failure, @p out is
    /// left in an unusable state (no further methods are dispatched
    /// on it) and @p diag carries the human-readable reason. Each
    /// runtime owns its kind-specific load — `DynamicRuntime` runs
    /// the integrity + dlopen path, `RemoteRuntime` spawns a
    /// subprocess, `StaticRuntime` resolves `static://<name>` paths
    /// against the in-binary registry.
    virtual gn_result_t load(const std::string& path,
                              const PluginLoadContext& ctx,
                              PluginInstance& out,
                              std::string& diag) = 0;

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

    /// Release the kind-specific load state: `dlclose` for dynamic
    /// (only when @p drained, otherwise leak the handle to keep
    /// async callbacks safe per `plugin-lifetime.en.md` §4),
    /// `terminate` + `reset` for remote, no-op for static. The
    /// caller (`PluginManager::rollback`) runs the anchor-quiescence
    /// wait between `shutdown` and this entry; @p drained is the
    /// wait's outcome.
    virtual void close(PluginInstance& inst, bool drained) = 0;

    /// Stable identifier; matches the manifest entry's `kind`
    /// string. The default "dynamic" / "static" / "remote" runtimes
    /// claim those three keys.
    [[nodiscard]] virtual std::string_view name() const noexcept = 0;
};

}  // namespace gn::core
