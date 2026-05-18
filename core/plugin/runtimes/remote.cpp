/// @file   core/plugin/runtimes/remote.cpp
/// @brief  RemoteRuntime — RemoteHost-backed subprocess dispatch.

#include <core/plugin/runtimes/remote.hpp>

#include <cstdint>
#include <span>

#include <core/kernel/host_api_builder.hpp>
#include <core/kernel/plugin_anchor.hpp>
#include <core/kernel/plugin_context.hpp>
#include <core/plugin/plugin_manager.hpp>
#include <core/plugin/plugin_manifest.hpp>
#include <core/plugin/remote_host.hpp>

#include <sdk/handler.h>
#include <sdk/link.h>
#include <sdk/security.h>

namespace gn::core {

gn_result_t RemoteRuntime::load(const std::string& path,
                                  const PluginLoadContext& ctx,
                                  PluginInstance& out,
                                  std::string& diag) {
    if (ctx.kernel == nullptr || ctx.manifest == nullptr) {
        diag = "remote runtime requires kernel + manifest context";
        return GN_ERR_NULL_ARG;
    }

    /// Worker binary integrity: hash the file the same way the
    /// dlopen path hashes the .so. The kernel never executes an
    /// unverified worker, mirroring the dlopen rule that an
    /// unverified .so never reaches `RTLD_NOW`.
    std::string verify_diag;
    if (!ctx.manifest->verify(path, verify_diag)) {
        diag = "remote worker integrity check failed: ";
        diag += verify_diag;
        return GN_ERR_INTEGRITY_FAILED;
    }

    const ManifestEntry* manifest_entry = ctx.manifest->find(path);
    if (manifest_entry == nullptr) {
        diag = "remote manifest entry missing for ";
        diag += path;
        return GN_ERR_NOT_FOUND;
    }

    out.path = path;
    out.ctx = std::make_unique<PluginContext>();
    out.ctx->plugin_name = path;  // descriptor name overrides post-HELLO
    out.ctx->kernel      = ctx.kernel;
    out.ctx->plugin_anchor = std::make_shared<PluginAnchor>();
    out.api = build_host_api(*out.ctx);

    out.remote = std::make_unique<RemoteHost>();
    std::string spawn_diag;
    const auto rc = out.remote->spawn(path,
        std::span<const std::string>(
            manifest_entry->args.data(),
            manifest_entry->args.size()),
        *out.ctx, out.api, spawn_diag);
    if (rc != GN_OK) {
        diag = "remote spawn failed: ";
        diag += spawn_diag;
        out.remote.reset();
        out.ctx.reset();
        return rc;
    }

    if (const auto* d = out.remote->descriptor(); d != nullptr) {
        if (d->name) {
            out.descriptor.plugin_name = d->name;
            out.ctx->plugin_name       = d->name;
        }
        out.ctx->kind = d->kind;
    }
    if (out.descriptor.plugin_name.empty()) {
        out.descriptor.plugin_name = path;
    }

    out.runtime    = this;
    out.self       = nullptr;
    out.registered = false;
    return GN_OK;
}

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

void RemoteRuntime::close(PluginInstance& inst, bool /*drained*/) {
    /// `drained` does not gate the terminate path: the worker is a
    /// separate address space, so its `.text` cannot have async
    /// callbacks racing the kernel's `.text` after the GOODBYE. The
    /// `RemoteHost` destructor calls terminate() too, but doing it
    /// here explicitly keeps the dlclose-vs-terminate ordering
    /// symmetric with the dynamic-linkage close path above.
    if (inst.remote) {
        inst.remote->terminate();
        inst.remote.reset();
    }
}

}  // namespace gn::core
