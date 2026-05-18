/// @file   core/plugin/runtimes/static.cpp
/// @brief  StaticRuntime — gn_plugin_static_entry_t-backed dispatch.

#include <core/plugin/runtimes/static.hpp>

#include <cstring>
#include <string_view>

#include <core/kernel/host_api_builder.hpp>
#include <core/kernel/plugin_anchor.hpp>
#include <core/kernel/plugin_context.hpp>
#include <core/kernel/safe_invoke.hpp>
#include <core/plugin/plugin_manager.hpp>
#include <core/plugin/static_registry.hpp>

#include <sdk/plugin.h>

namespace gn::core {

namespace {

constexpr std::string_view kStaticPrefix = "static://";

[[nodiscard]] const gn_plugin_static_entry_t* find_static_entry(
    std::string_view name) noexcept {
    for (const auto* e = &gn_plugin_static_registry[0];
         e->name != nullptr; ++e) {
        if (e->name == name) return e;
    }
    return nullptr;
}

}  // namespace

gn_result_t StaticRuntime::load(const std::string& path,
                                  const PluginLoadContext& ctx,
                                  PluginInstance& out,
                                  std::string& diag) {
    if (ctx.kernel == nullptr) {
        diag = "static runtime requires kernel context";
        return GN_ERR_NULL_ARG;
    }
    /// Static-linkage paths take the form `static://<entry-name>`;
    /// strip the prefix to find the registry entry pinned at build
    /// time. The walk is O(N) over the registry which is tiny in
    /// practice (every bundled plugin's entry name lives there).
    if (path.compare(0, kStaticPrefix.size(), kStaticPrefix) != 0) {
        diag = "static runtime: path must start with `static://`: ";
        diag += path;
        return GN_ERR_INVALID_ENVELOPE;
    }
    const std::string_view name{
        path.data() + kStaticPrefix.size(),
        path.size() - kStaticPrefix.size()};
    const auto* entry = find_static_entry(name);
    if (entry == nullptr) {
        diag = "static runtime: no registry entry for ";
        diag += name;
        return GN_ERR_NOT_FOUND;
    }

    /// Static plugins ship inside the kernel binary; their SDK
    /// version is forcibly identical to the host. Still call
    /// `sdk_version` if present so an out-of-tree static archive
    /// can catch a stale .a at the same point as the dlopen path
    /// catches a stale .so.
    if (entry->sdk_version) {
        uint32_t pmaj = 0, pmin = 0, ppatch = 0;
        entry->sdk_version(&pmaj, &pmin, &ppatch);
        if (pmaj != GN_SDK_VERSION_MAJOR) {
            diag = std::string("sdk-version mismatch: ") + entry->name;
            return GN_ERR_VERSION_MISMATCH;
        }
    }

    out.path = path;
    out.static_entry = entry;
    out.ctx = std::make_unique<PluginContext>();
    out.ctx->plugin_name = entry->name;
    out.ctx->kernel      = ctx.kernel;
    out.ctx->plugin_anchor = std::make_shared<PluginAnchor>();

    if (entry->descriptor) {
        if (const auto* d = entry->descriptor(); d != nullptr) {
            if (d->name) out.descriptor.plugin_name = d->name;
            out.ctx->kind = d->kind;
        }
    }
    if (out.descriptor.plugin_name.empty()) {
        out.descriptor.plugin_name = entry->name;
    }

    out.api      = build_host_api(*out.ctx);
    out.runtime  = this;
    out.self     = nullptr;
    out.registered = false;
    return GN_OK;
}

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
