/// @file   core/plugin/plugin_manager.cpp
/// @brief  Implementation of the dlopen + two-phase activation path.

#include "plugin_manager.hpp"

#include <dlfcn.h>

#include <cstring>
#include <utility>

#include <core/kernel/host_api_builder.hpp>
#include <core/kernel/kernel.hpp>
#include <core/util/log.hpp>

#include <sdk/plugin.h>

namespace gn::core {

namespace {

using gn_plugin_sdk_version_fn   = void  (*)(uint32_t*, uint32_t*, uint32_t*);
using gn_plugin_init_fn          = gn_result_t (*)(const host_api_t*, void**);
using gn_plugin_register_fn      = gn_result_t (*)(void*);
using gn_plugin_unregister_fn    = gn_result_t (*)(void*);
using gn_plugin_shutdown_fn      = void  (*)(void*);
using gn_plugin_descriptor_fn    = const gn_plugin_descriptor_t* (*)();

struct PluginSymbols {
    gn_plugin_sdk_version_fn  sdk_version;
    gn_plugin_init_fn         init;
    gn_plugin_register_fn     register_self;
    gn_plugin_unregister_fn   unregister_self;
    gn_plugin_shutdown_fn     shutdown;
    gn_plugin_descriptor_fn   descriptor;     // optional; may be null
};

[[nodiscard]] gn_result_t resolve_symbols(void* so, PluginSymbols& out,
                                          std::string& diagnostic) {
    out.sdk_version     = reinterpret_cast<gn_plugin_sdk_version_fn>(
                              dlsym(so, "gn_plugin_sdk_version"));
    out.init            = reinterpret_cast<gn_plugin_init_fn>(
                              dlsym(so, "gn_plugin_init"));
    out.register_self   = reinterpret_cast<gn_plugin_register_fn>(
                              dlsym(so, "gn_plugin_register"));
    out.unregister_self = reinterpret_cast<gn_plugin_unregister_fn>(
                              dlsym(so, "gn_plugin_unregister"));
    out.shutdown        = reinterpret_cast<gn_plugin_shutdown_fn>(
                              dlsym(so, "gn_plugin_shutdown"));
    out.descriptor      = reinterpret_cast<gn_plugin_descriptor_fn>(
                              dlsym(so, "gn_plugin_descriptor"));

    if (!out.sdk_version || !out.init || !out.register_self
        || !out.unregister_self || !out.shutdown) {
        diagnostic = "missing required gn_plugin_* entry symbol";
        return GN_ERR_VERSION_MISMATCH;
    }
    return GN_OK;
}

[[nodiscard]] bool sdk_version_compatible(const PluginSymbols& syms) noexcept {
    std::uint32_t major = 0, minor = 0, patch = 0;
    syms.sdk_version(&major, &minor, &patch);
    if (major != GN_SDK_VERSION_MAJOR) return false;
    return GN_SDK_VERSION_MINOR >= minor;
}

ServiceDescriptor descriptor_from_symbol(const PluginSymbols& syms,
                                         const std::string& path_fallback) {
    ServiceDescriptor sd;
    if (syms.descriptor != nullptr) {
        if (const auto* d = syms.descriptor()) {
            sd.plugin_name = d->name ? d->name : path_fallback;
            if (d->ext_requires) {
                for (const char* const* p = d->ext_requires; *p != nullptr; ++p) {
                    sd.ext_requires.emplace_back(*p);
                }
            }
            if (d->ext_provides) {
                for (const char* const* p = d->ext_provides; *p != nullptr; ++p) {
                    sd.ext_provides.emplace_back(*p);
                }
            }
            return sd;
        }
    }
    sd.plugin_name = path_fallback;
    return sd;
}

} // namespace

PluginManager::PluginManager(Kernel& kernel) noexcept : kernel_(kernel) {}

PluginManager::~PluginManager() { shutdown(); }

gn_result_t PluginManager::open_one(const std::string& path,
                                    PluginInstance& out,
                                    std::string& diag) {
    out.path = path;
    out.so_handle = ::dlopen(path.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (!out.so_handle) {
        diag = "dlopen failed for ";
        diag += path;
        diag += ": ";
        if (const char* err = ::dlerror()) diag += err;
        return GN_ERR_UNKNOWN_RECEIVER;
    }

    PluginSymbols syms{};
    auto rc = resolve_symbols(out.so_handle, syms, diag);
    if (rc != GN_OK) {
        ::dlclose(out.so_handle);
        out.so_handle = nullptr;
        return rc;
    }

    if (!sdk_version_compatible(syms)) {
        diag = "sdk-version mismatch in " + path;
        ::dlclose(out.so_handle);
        out.so_handle = nullptr;
        return GN_ERR_VERSION_MISMATCH;
    }

    out.descriptor = descriptor_from_symbol(syms, path);
    out.ctx.plugin_name = out.descriptor.plugin_name;
    out.ctx.kernel = &kernel_;
    out.api = build_host_api(out.ctx);
    out.self = nullptr;
    out.registered = false;
    return GN_OK;
}

gn_result_t PluginManager::load(std::span<const std::string> paths,
                                std::string* out_diagnostic) {
    if (active_) {
        if (out_diagnostic) *out_diagnostic = "PluginManager already active";
        return GN_ERR_LIMIT_REACHED;
    }

    auto note = [&](std::string_view m) {
        if (out_diagnostic) *out_diagnostic = m;
    };

    /// Phase 1-3: discover, dlopen, version-check.
    instances_.reserve(paths.size());
    std::vector<ServiceDescriptor> descriptors;
    descriptors.reserve(paths.size());
    for (const auto& p : paths) {
        PluginInstance inst{};
        std::string diag;
        const auto rc = open_one(p, inst, diag);
        if (rc != GN_OK) {
            note(diag);
            rollback();
            return rc;
        }
        descriptors.push_back(inst.descriptor);
        instances_.push_back(std::move(inst));
    }

    /// Resolve dependency order.
    std::vector<ServiceDescriptor> ordered;
    std::string diag;
    if (auto rc = ServiceResolver::resolve(descriptors, ordered, &diag);
        rc != GN_OK) {
        note(diag);
        rollback();
        return rc;
    }

    /// Reorder instances_ to match the resolver's output. The
    /// resolver returned descriptors by value; match them back to
    /// instance indices via plugin_name.
    std::vector<PluginInstance> reordered;
    reordered.reserve(instances_.size());
    for (const auto& d : ordered) {
        for (auto& inst : instances_) {
            if (inst.path.empty()) continue;
            if (inst.descriptor.plugin_name == d.plugin_name) {
                reordered.push_back(std::move(inst));
                inst.path.clear();
                break;
            }
        }
    }
    instances_ = std::move(reordered);

    /// Phase 4: init_all.
    for (auto& inst : instances_) {
        auto* init_fn = reinterpret_cast<gn_plugin_init_fn>(
            ::dlsym(inst.so_handle, "gn_plugin_init"));
        const auto rc = init_fn(&inst.api, &inst.self);
        if (rc != GN_OK) {
            note("gn_plugin_init failed for " + inst.descriptor.plugin_name);
            rollback();
            return rc;
        }
    }

    /// Phase 5: register_all.
    for (auto& inst : instances_) {
        auto* reg_fn = reinterpret_cast<gn_plugin_register_fn>(
            ::dlsym(inst.so_handle, "gn_plugin_register"));
        const auto rc = reg_fn(inst.self);
        if (rc != GN_OK) {
            note("gn_plugin_register failed for " + inst.descriptor.plugin_name);
            rollback();
            return rc;
        }
        inst.registered = true;
    }

    active_ = true;
    return GN_OK;
}

void PluginManager::rollback() {
    /// Mirror the activation path: unregister registered, shutdown
    /// inited, dlclose loaded — all in reverse order.
    for (auto it = instances_.rbegin(); it != instances_.rend(); ++it) {
        if (it->registered && it->so_handle) {
            if (auto* fn = reinterpret_cast<gn_plugin_unregister_fn>(
                    ::dlsym(it->so_handle, "gn_plugin_unregister"))) {
                fn(it->self);
            }
            it->registered = false;
        }
        if (it->self && it->so_handle) {
            if (auto* fn = reinterpret_cast<gn_plugin_shutdown_fn>(
                    ::dlsym(it->so_handle, "gn_plugin_shutdown"))) {
                fn(it->self);
            }
            it->self = nullptr;
        }
        if (it->so_handle) {
            ::dlclose(it->so_handle);
            it->so_handle = nullptr;
        }
    }
    instances_.clear();
    active_ = false;
}

void PluginManager::shutdown() {
    if (!active_ && instances_.empty()) return;
    rollback();
}

} // namespace gn::core
