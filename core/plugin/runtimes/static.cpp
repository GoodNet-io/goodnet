/// @file   core/plugin/runtimes/static.cpp
/// @brief  StaticRuntime — gn_plugin_static_entry_t-backed dispatch.

#include <core/plugin/runtimes/static.hpp>

#include <core/kernel/safe_invoke.hpp>
#include <core/plugin/plugin_manager.hpp>

namespace gn::core {

gn_result_t StaticRuntime::init(PluginInstance& inst) {
    if (inst.static_entry == nullptr ||
        inst.static_entry->init == nullptr) {
        return GN_OK;
    }
    return inst.static_entry->init(&inst.api, &inst.self);
}

gn_result_t StaticRuntime::register_plugin(PluginInstance& inst) {
    if (inst.static_entry == nullptr ||
        inst.static_entry->reg == nullptr) {
        return GN_OK;
    }
    return inst.static_entry->reg(inst.self);
}

void StaticRuntime::unregister(PluginInstance& inst) {
    if (inst.static_entry == nullptr ||
        inst.static_entry->unreg == nullptr) {
        return;
    }
    /// Static-linkage path: dlsym would return null for the
    /// suffix-renamed entry, so we read the function pointer
    /// the registry already provides. Same noexcept guarantees
    /// apply across the C ABI as for the dlopen branch.
    (void)safe_call_result("plugin.gn_plugin_unregister",
                            inst.static_entry->unreg, inst.self);
}

void StaticRuntime::shutdown(PluginInstance& inst) {
    if (inst.static_entry == nullptr ||
        inst.static_entry->shutdown == nullptr) {
        return;
    }
    safe_call_void("plugin.gn_plugin_shutdown",
                    inst.static_entry->shutdown, inst.self);
}

void StaticRuntime::close(PluginInstance& /*inst*/, bool /*drained*/) {
    /// Static-linkage plugins are linked into the kernel binary
    /// itself — there is nothing to unload. `static_entry` is a
    /// borrowed pointer into a build-time array; clearing it
    /// would not change observable behaviour.
}

}  // namespace gn::core
