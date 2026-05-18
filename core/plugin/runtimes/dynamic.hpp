/// @file   core/plugin/runtimes/dynamic.hpp
/// @brief  IPluginRuntime impl for the dlopen-backed linkage kind.
///
/// Resolves the per-symbol entry through `dlsym` against the
/// instance's `so_handle`. The load() and close() concerns (dlopen,
/// integrity verification, dlclose with quiescence) stay in
/// PluginManager for the moment; this runtime owns only the
/// init / register / unregister / shutdown dispatch.

#pragma once

#include <cstdint>

#include <core/plugin/plugin_runtime.hpp>

#include <sdk/host_api.h>
#include <sdk/plugin.h>
#include <sdk/types.h>

namespace gn::core {

using gn_plugin_sdk_version_fn = void (*)(std::uint32_t*, std::uint32_t*,
                                          std::uint32_t*);
using gn_plugin_init_fn        = gn_result_t (*)(const host_api_t*, void**);
using gn_plugin_register_fn    = gn_result_t (*)(void*);
using gn_plugin_unregister_fn  = gn_result_t (*)(void*);
using gn_plugin_shutdown_fn    = void (*)(void*);
using gn_plugin_descriptor_fn  = const gn_plugin_descriptor_t* (*)();

/// Function pointers resolved from the plugin's `.so` once at load
/// time and stored on the `PluginInstance` for the lifetime of the
/// load. Every `register` / `unregister` / `shutdown` dispatch reads
/// the cached pointer instead of calling `dlsym` again; the dispatch
/// is O(1) and on hot paths (test runs spawning many plugins) saves
/// the linker's per-symbol hash-table walk.
struct DynamicPluginSymbols {
    gn_plugin_sdk_version_fn  sdk_version{nullptr};
    gn_plugin_init_fn         init{nullptr};
    gn_plugin_register_fn     register_self{nullptr};
    gn_plugin_unregister_fn   unregister_self{nullptr};
    gn_plugin_shutdown_fn     shutdown{nullptr};
    /// Optional symbol; null when the plugin does not export one.
    gn_plugin_descriptor_fn   descriptor{nullptr};
};

class DynamicRuntime final : public IPluginRuntime {
public:
    gn_result_t load(const std::string& path,
                      const PluginLoadContext& ctx,
                      PluginInstance& out,
                      std::string& diag) override;

    gn_result_t init(PluginInstance& inst) override;
    gn_result_t register_plugin(PluginInstance& inst) override;
    void unregister(PluginInstance& inst) override;
    void shutdown(PluginInstance& inst) override;
    void close(PluginInstance& inst, bool drained) override;

    [[nodiscard]] std::string_view name() const noexcept override {
        return "dynamic";
    }

    /// Diagnostic counter — total `dlsym` calls this runtime has
    /// issued across every load it has serviced. Used by the dlsym
    /// cache regression test to assert that `register` /
    /// `unregister` / `shutdown` do not re-resolve symbols after
    /// `load`. Not exposed via any public surface and read-only
    /// for callers.
    [[nodiscard]] std::uint64_t dlsym_call_count() const noexcept {
        return dlsym_calls_;
    }

private:
    [[nodiscard]] gn_result_t resolve_symbols_(void* so,
                                                DynamicPluginSymbols& out,
                                                std::string& diagnostic);

    std::uint64_t dlsym_calls_{0};
};

}  // namespace gn::core
