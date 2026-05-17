/// @file   core/plugin/runtimes/dynamic.cpp
/// @brief  DynamicRuntime — dlopen-backed lifecycle dispatch.

#include <core/plugin/runtimes/dynamic.hpp>

#include <dlfcn.h>

#ifdef __linux__
#include <fcntl.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cerrno>
#if defined(SYS_openat2) && __has_include(<linux/openat2.h>)
#include <linux/openat2.h>
#define GOODNET_HAVE_OPENAT2 1
#endif
#endif

#include <string>

#include <core/kernel/host_api_builder.hpp>
#include <core/kernel/plugin_anchor.hpp>
#include <core/kernel/plugin_context.hpp>
#include <core/kernel/safe_invoke.hpp>
#include <core/plugin/plugin_manager.hpp>
#include <core/plugin/plugin_manifest.hpp>

#include <sdk/plugin.h>

namespace gn::core {

namespace {

using gn_plugin_sdk_version_fn = void (*)(uint32_t*, uint32_t*, uint32_t*);
using gn_plugin_init_fn        = gn_result_t (*)(const host_api_t*, void**);
using gn_plugin_register_fn    = gn_result_t (*)(void*);
using gn_plugin_unregister_fn  = gn_result_t (*)(void*);
using gn_plugin_shutdown_fn    = void (*)(void*);
using gn_plugin_descriptor_fn  = const gn_plugin_descriptor_t* (*)();

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
            sd.kind        = d->kind;
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

}  // namespace

gn_result_t DynamicRuntime::load(const std::string& path,
                                  const PluginLoadContext& ctx,
                                  PluginInstance& out,
                                  std::string& diag) {
    if (ctx.kernel == nullptr || ctx.manifest == nullptr) {
        diag = "dynamic runtime requires kernel + manifest context";
        return GN_ERR_NULL_ARG;
    }

    out.path = path;

    /// Production-mode trip-wire: when the manifest-required flag is
    /// set, an empty allowlist refuses every load. Operators flip
    /// the flag through `PluginManager::set_manifest_required(true)`
    /// on the bootstrap thread before `load`, paired with a populated
    /// manifest; the dev-mode flow leaves the flag clear and the
    /// empty allowlist passes through.
    if (ctx.manifest_required && ctx.manifest->empty()) {
        diag = "plugin integrity check failed: manifest required but empty: ";
        diag += path;
        return GN_ERR_INTEGRITY_FAILED;
    }

    /// Integrity check before dlopen. An empty manifest is the
    /// developer-mode path; production callers install a manifest
    /// at startup and the kernel refuses every plugin not in it.
    /// Per `plugin-manifest.en.md` the integrity check is the kernel's
    /// only defence between an attacker-controlled plugins directory
    /// and the kernel's own address space — running it before dlopen
    /// rather than after means a tampered binary never reaches
    /// `RTLD_NOW`-side initialisers.
#ifdef __linux__
    if (!ctx.manifest->empty()) {
        if (!ctx.manifest->contains(path)) {
            diag = "plugin integrity check failed: no manifest entry for path: ";
            diag += path;
            return GN_ERR_INTEGRITY_FAILED;
        }
        int fd = -1;
#ifdef GOODNET_HAVE_OPENAT2
        struct open_how how{};
        how.flags = static_cast<__u64>(O_RDONLY | O_CLOEXEC);
        how.resolve = RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS;
        fd = static_cast<int>(::syscall(
            SYS_openat2, AT_FDCWD, path.c_str(), &how, sizeof(how)));
        if (fd < 0 && errno == ENOSYS) {
            fd = ::open(path.c_str(),
                        O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        }
#else
        fd = ::open(path.c_str(),
                    O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
#endif
        if (fd < 0) {
            diag = "plugin integrity check failed: open: ";
            diag += path;
            return GN_ERR_INTEGRITY_FAILED;
        }
        const auto observed = PluginManifest::sha256_of_fd(fd);
        if (!observed) {
            ::close(fd);
            diag = "plugin integrity check failed: read: ";
            diag += path;
            return GN_ERR_INTEGRITY_FAILED;
        }
        std::string verify_diag;
        if (!ctx.manifest->verify_digest(path, *observed, verify_diag)) {
            ::close(fd);
            diag = "plugin integrity check failed: ";
            diag += verify_diag;
            return GN_ERR_INTEGRITY_FAILED;
        }
        char proc_path[64];
        (void)std::snprintf(proc_path, sizeof(proc_path),
                            "/proc/self/fd/%d", fd);
        out.so_handle = dlopen(proc_path, RTLD_NOW | RTLD_LOCAL);
        /// Keep the fd open across the rest of `load`. glibc's
        /// dlopen caches by path string; closing the fd here lets
        /// the kernel reuse fd N for the next plugin's open, the
        /// next `dlopen("/proc/self/fd/N")` then hits the cached
        /// handle from the first plugin and the second plugin's
        /// symbols never enter the address space.
        out.integrity_fd = fd;
        if (!out.so_handle) {
            ::close(fd);
            out.integrity_fd = -1;
            diag = "dlopen failed for ";
            diag += path;
            diag += ": ";
            if (const char* err = dlerror()) diag += err;
            return GN_ERR_NOT_FOUND;
        }
    } else {
        out.so_handle = dlopen(path.c_str(), RTLD_NOW | RTLD_LOCAL);
        if (!out.so_handle) {
            diag = "dlopen failed for ";
            diag += path;
            diag += ": ";
            if (const char* err = dlerror()) diag += err;
            return GN_ERR_NOT_FOUND;
        }
    }
#else
    if (!ctx.manifest->empty()) {
        std::string verify_diag;
        if (!ctx.manifest->verify(path, verify_diag)) {
            diag = "plugin integrity check failed: ";
            diag += verify_diag;
            return GN_ERR_INTEGRITY_FAILED;
        }
    }
    out.so_handle = dlopen(path.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (!out.so_handle) {
        diag = "dlopen failed for ";
        diag += path;
        diag += ": ";
        if (const char* err = dlerror()) diag += err;
        return GN_ERR_NOT_FOUND;
    }
#endif

    PluginSymbols syms{};
    auto rc = resolve_symbols(out.so_handle, syms, diag);
    if (rc != GN_OK) {
        dlclose(out.so_handle);
        out.so_handle = nullptr;
#ifdef __linux__
        if (out.integrity_fd >= 0) { ::close(out.integrity_fd); out.integrity_fd = -1; }
#endif
        return rc;
    }

    if (!sdk_version_compatible(syms)) {
        diag = "sdk-version mismatch in " + path;
        dlclose(out.so_handle);
        out.so_handle = nullptr;
#ifdef __linux__
        if (out.integrity_fd >= 0) { ::close(out.integrity_fd); out.integrity_fd = -1; }
#endif
        return GN_ERR_VERSION_MISMATCH;
    }

    out.descriptor = descriptor_from_symbol(syms, path);

    out.ctx = std::make_unique<PluginContext>();
    out.ctx->plugin_name = out.descriptor.plugin_name;
    out.ctx->kind        = out.descriptor.kind;
    out.ctx->kernel      = ctx.kernel;
    out.ctx->plugin_anchor = std::make_shared<PluginAnchor>();
    out.api  = build_host_api(*out.ctx);

    out.runtime    = this;
    out.self       = nullptr;
    out.registered = false;
    return GN_OK;
}

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
