/// @file   core/plugin/runtimes/dynamic.hpp
/// @brief  IPluginRuntime impl for the dlopen-backed linkage kind.
///
/// Resolves the per-symbol entry through `dlsym` against the
/// instance's `so_handle`. The load() and close() concerns (dlopen,
/// integrity verification, dlclose with quiescence) stay in
/// PluginManager for the moment; this runtime owns only the
/// init / register / unregister / shutdown dispatch.

#pragma once

#include <core/plugin/plugin_runtime.hpp>

namespace gn::core {

class DynamicRuntime final : public IPluginRuntime {
public:
    gn_result_t init(PluginInstance& inst) override;
    gn_result_t register_plugin(PluginInstance& inst) override;
    void unregister(PluginInstance& inst) override;
    void shutdown(PluginInstance& inst) override;
    void close(PluginInstance& inst, bool drained) override;

    [[nodiscard]] std::string_view name() const noexcept override {
        return "dynamic";
    }
};

}  // namespace gn::core
