/// @file   core/plugin/runtimes/remote.cpp
/// @brief  RemoteRuntime — RemoteHost-backed subprocess dispatch.

#include <core/plugin/runtimes/remote.hpp>

#include <cstdint>

#include <core/plugin/plugin_manager.hpp>
#include <core/plugin/remote_host.hpp>

namespace gn::core {

gn_result_t RemoteRuntime::init(PluginInstance& inst) {
    return inst.remote->call_init(&inst.self);
}

gn_result_t RemoteRuntime::register_plugin(PluginInstance& inst) {
    return inst.remote->call_register(
        reinterpret_cast<std::uintptr_t>(inst.self));
}

void RemoteRuntime::unregister(PluginInstance& inst) {
    /// `gn_result_t` discarded — the unregister path continues to
    /// teardown regardless of the worker's reported outcome.
    (void)inst.remote->call_unregister(
        reinterpret_cast<std::uintptr_t>(inst.self));
}

void RemoteRuntime::shutdown(PluginInstance& inst) {
    /// `call_shutdown` is void (no return code). The worker reaps
    /// its state and acks the PLUGIN_CALL but we do not branch on
    /// the reply.
    inst.remote->call_shutdown(
        reinterpret_cast<std::uintptr_t>(inst.self));
}

}  // namespace gn::core
