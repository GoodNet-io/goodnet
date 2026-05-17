/// @file   core/plugin/runtimes/remote.hpp
/// @brief  IPluginRuntime impl for subprocess workers (RemoteHost).
///
/// Lifecycle invocations route through `inst.remote->call_*` and the
/// wire codec in `sdk/remote/wire.h` instead of `dlsym`. The
/// `RemoteHost` owns the child-process bookkeeping (named-pipe pair,
/// reader thread, child pid, GOODBYE / terminate sequencing); this
/// runtime is purely the lifecycle-method dispatcher.

#pragma once

#include <core/plugin/plugin_runtime.hpp>

namespace gn::core {

class RemoteRuntime final : public IPluginRuntime {
public:
    gn_result_t init(PluginInstance& inst) override;
    gn_result_t register_plugin(PluginInstance& inst) override;
    void unregister(PluginInstance& inst) override;
    void shutdown(PluginInstance& inst) override;

    [[nodiscard]] std::string_view name() const noexcept override {
        return "remote";
    }
};

}  // namespace gn::core
