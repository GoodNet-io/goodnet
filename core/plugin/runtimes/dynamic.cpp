/// @file   core/plugin/runtimes/dynamic.cpp
/// @brief  DynamicRuntime — dlopen-backed lifecycle dispatch.

#include <core/plugin/runtimes/dynamic.hpp>

#include <dlfcn.h>

#include <string>

#include <core/kernel/safe_invoke.hpp>
#include <core/plugin/plugin_manager.hpp>

namespace gn::core {

namespace {

using gn_plugin_init_fn       = gn_result_t (*)(const host_api_t*, void**);
using gn_plugin_register_fn   = gn_result_t (*)(void*);
using gn_plugin_unregister_fn = gn_result_t (*)(void*);
using gn_plugin_shutdown_fn   = void (*)(void*);

}  // namespace

gn_result_t DynamicRuntime::init(PluginInstance& inst) {
    auto* fn = reinterpret_cast<gn_plugin_init_fn>(
        dlsym(inst.so_handle, "gn_plugin_init"));
    const auto tag =
        "plugin." + inst.descriptor.plugin_name + ".gn_plugin_init";
    return safe_call_result(tag.c_str(), fn, &inst.api, &inst.self);
}

gn_result_t DynamicRuntime::register_plugin(PluginInstance& inst) {
    auto* fn = reinterpret_cast<gn_plugin_register_fn>(
        dlsym(inst.so_handle, "gn_plugin_register"));
    return safe_call_result("plugin.gn_plugin_register", fn, inst.self);
}

void DynamicRuntime::unregister(PluginInstance& inst) {
    if (auto* fn = reinterpret_cast<gn_plugin_unregister_fn>(
            dlsym(inst.so_handle, "gn_plugin_unregister"))) {
        /// `gn_result_t` discarded — the unregister path continues
        /// to teardown regardless of the plugin's reported outcome;
        /// we only care that no exception escapes the C ABI
        /// boundary.
        (void)safe_call_result("plugin.gn_plugin_unregister",
                                fn, inst.self);
    }
}

void DynamicRuntime::shutdown(PluginInstance& inst) {
    if (auto* fn = reinterpret_cast<gn_plugin_shutdown_fn>(
            dlsym(inst.so_handle, "gn_plugin_shutdown"))) {
        safe_call_void("plugin.gn_plugin_shutdown", fn, inst.self);
    }
}

void DynamicRuntime::close(PluginInstance& inst, bool drained) {
    /// Only call `dlclose` when every kernel-side strong reference
    /// to the plugin's lifetime anchor has dropped — otherwise an
    /// in-flight callback that captured `self` would dereference
    /// a now-unmapped `.text` page. PluginManager logs and counts
    /// the leak in that path; here we just skip the unmap.
    if (drained && inst.so_handle != nullptr) {
        dlclose(inst.so_handle);
        inst.so_handle = nullptr;
    }
    /// The integrity fd pinned the inode for the duration of the
    /// dlopen call. Closing it now reclaims the fd number for
    /// future plugin loads — the kernel's TOCTOU guarantee was the
    /// dlopen point, not the fd's continued life.
    if (inst.integrity_fd >= 0) {
        ::close(inst.integrity_fd);
        inst.integrity_fd = -1;
    }
}

}  // namespace gn::core
