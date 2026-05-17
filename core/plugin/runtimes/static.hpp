/// @file   core/plugin/runtimes/static.hpp
/// @brief  IPluginRuntime impl for the static-registry linkage kind.
///
/// Reads the entry function pointers directly from the
/// `gn_plugin_static_entry_t` the instance carries in
/// `static_entry`. The static path bypasses `dlopen` entirely —
/// every plugin's entry symbols are linked into the kernel binary
/// (suffix-renamed via the macros in `sdk/plugin.h`) and the
/// per-entry function pointers were resolved at link time.

#pragma once

#include <core/plugin/plugin_runtime.hpp>

namespace gn::core {

class StaticRuntime final : public IPluginRuntime {
public:
    gn_result_t init(PluginInstance& inst) override;
    gn_result_t register_plugin(PluginInstance& inst) override;
    void unregister(PluginInstance& inst) override;
    void shutdown(PluginInstance& inst) override;

    [[nodiscard]] std::string_view name() const noexcept override {
        return "static";
    }
};

}  // namespace gn::core
