/// @file   core/plugin/plugin_manager.cpp
/// @brief  Implementation of the dlopen + two-phase activation path.

#include "plugin_manager.hpp"

#include "dl_compat.hpp"

#ifdef __linux__
#include <fcntl.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <errno.h>
#if defined(SYS_openat2) && __has_include(<linux/openat2.h>)
#include <linux/openat2.h>
#define GOODNET_HAVE_OPENAT2 1
#endif
#endif

#include <chrono>
#include <cstring>
#include <thread>
#include <utility>

#include <core/kernel/host_api_builder.hpp>
#include <core/kernel/kernel.hpp>
#include <core/kernel/safe_invoke.hpp>
#include <core/plugin/remote_host.hpp>
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

} // namespace

PluginManager::PluginManager(Kernel& kernel) noexcept : kernel_(kernel) {}

PluginManager::~PluginManager() { shutdown(); }

gn_result_t PluginManager::open_one(const std::string& path,
                                    PluginInstance& out,
                                    std::string& diag) {
    out.path = path;

    /// Production-mode trip-wire: when the manifest-required flag is
    /// set, an empty allowlist refuses every load. Operators flip
    /// the flag through `set_manifest_required(true)` on the
    /// bootstrap thread before `load`, paired with a populated
    /// manifest; the dev-mode flow leaves the flag clear and the
    /// empty allowlist passes through.
    if (manifest_required_ && manifest_.empty()) {
        diag = "plugin integrity check failed: manifest required but empty: ";
        diag += path;
        return GN_ERR_INTEGRITY_FAILED;
    }

    /// Linkage selector: a manifest entry with `kind: "remote"`
    /// switches this path from dlopen to a subprocess worker over
    /// `sdk/remote/wire.h`. The dynamic-default branch below stays
    /// unchanged for every other entry.
    const ManifestEntry* manifest_entry =
        manifest_.empty() ? nullptr : manifest_.find(path);
    const bool is_remote =
        manifest_entry != nullptr &&
        manifest_entry->kind == ManifestKind::Remote;

    if (is_remote) {
        /// Worker binary integrity: hash the file the same way the
        /// dlopen path hashes the .so. The kernel never executes
        /// an unverified worker, mirroring the dlopen rule that an
        /// unverified .so never reaches `RTLD_NOW`.
        std::string verify_diag;
        if (!manifest_.verify(path, verify_diag)) {
            diag = "remote worker integrity check failed: ";
            diag += verify_diag;
            return GN_ERR_INTEGRITY_FAILED;
        }

        out.ctx = std::make_unique<PluginContext>();
        out.ctx->plugin_name = path;  // descriptor name overrides post-HELLO
        out.ctx->kernel      = &kernel_;
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

        out.self       = nullptr;
        out.registered = false;
        return GN_OK;
    }

    /// Integrity check before dlopen. An empty manifest is the
    /// developer-mode path; production callers install a manifest
    /// at startup and the kernel refuses every plugin not in it.
    /// Per `plugin-manifest.md` the integrity check is the kernel's
    /// only defence between an attacker-controlled plugins
    /// directory and the kernel's own address space — running it
    /// before dlopen rather than after means a tampered binary
    /// never reaches `RTLD_NOW`-side initialisers.
#ifdef __linux__
    if (!manifest_.empty()) {
        /// Cheap path-only check first — an unlisted plugin is
        /// rejected before paying the open + hash cost. Manifest
        /// membership is not a secret, so the timing differential
        /// here is OK.
        if (!manifest_.contains(path)) {
            diag = "plugin integrity check failed: no manifest entry for path: ";
            diag += path;
            return GN_ERR_INTEGRITY_FAILED;
        }
        /// `openat2(RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS)`
        /// (Linux 5.6+) refuses every symlink along the path, not
        /// only the leaf. A parent-directory swap that the older
        /// `O_NOFOLLOW` open could not see — `/var/lib/goodnet/` →
        /// attacker-symlink — fails here with `ELOOP`. Combined
        /// with `dlopen("/proc/self/fd/N")` it pins the kernel to
        /// a single inode across hash and load. The fallback for
        /// older kernels keeps `O_NOFOLLOW` (leaf-only) as the
        /// best-effort guard.
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
        if (!manifest_.verify_digest(path, *observed, verify_diag)) {
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
        /// symbols never enter the address space. The fd lives
        /// alongside `so_handle` and closes at plugin shutdown
        /// or `rollback`. This preserves the TOCTOU pin per
        /// plugin-manifest.md without breaking multi-plugin loads.
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
    if (!manifest_.empty()) {
        std::string verify_diag;
        if (!manifest_.verify(path, verify_diag)) {
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

    /// PluginContext lives on the heap so its address survives the
    /// reorder pass (instances_ is reordered after the resolver runs;
    /// a stack/inline ctx would relocate, invalidating every
    /// `host_api->host_ctx` pointer plugins captured in their own
    /// state).
    out.ctx = std::make_unique<PluginContext>();
    out.ctx->plugin_name = out.descriptor.plugin_name;
    out.ctx->kind        = out.descriptor.kind;
    out.ctx->kernel      = &kernel_;

    /// The lifetime anchor. The shared_ptr's reference count
    /// tracks `(this ctx) + (every registry entry the plugin
    /// installs) + (every dispatch snapshot in flight) + (every
    /// async callback currently in plugin code via GateGuard)`.
    /// `weak_ptr::expired()` is the drain-side observable; the
    /// embedded `shutdown_requested` flag is the cooperative-
    /// cancellation signal published to async callbacks and to the
    /// plugin itself through `is_shutdown_requested`.
    out.ctx->plugin_anchor = std::make_shared<PluginAnchor>();

    out.api  = build_host_api(*out.ctx);
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

    /// `limits.md` §4a: reject the whole load if it would push the
    /// loaded-plugin count above the cap. Zero means "unlimited".
    /// Read from `Kernel::limits()` rather than a local copy so
    /// `gn_limits_t::max_plugins` stays the single source of truth.
    const std::uint32_t max_plugins = kernel_.limits().max_plugins;
    if (max_plugins != 0 && paths.size() > max_plugins) {
        note("plugin count exceeds gn_limits_t::max_plugins");
        return GN_ERR_LIMIT_REACHED;
    }

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
                /// Mark the slot consumed *before* the move so the
                /// post-move access doesn't read a moved-from value.
                /// `inst.path.clear()` is the sentinel that drives
                /// the outer continue.
                inst.path.clear();
                reordered.push_back(std::move(inst));
                break;
            }
        }
    }
    instances_ = std::move(reordered);

    /// Phase 4: init_all.
    for (auto& inst : instances_) {
        gn_result_t rc = GN_OK;
        if (inst.remote) {
            /// Subprocess worker: the lifecycle entry-points cross
            /// the wire as PLUGIN_CALL frames. `self` becomes the
            /// worker-side opaque returned in the reply.
            rc = inst.remote->call_init(&inst.self);
        } else {
            auto* init_fn = reinterpret_cast<gn_plugin_init_fn>(
                dlsym(inst.so_handle, "gn_plugin_init"));
            const auto init_tag =
                "plugin." + inst.descriptor.plugin_name + ".gn_plugin_init";
            rc = safe_call_result(
                init_tag.c_str(),
                init_fn, &inst.api, &inst.self);
        }
        if (rc != GN_OK) {
            note("gn_plugin_init failed for " + inst.descriptor.plugin_name);
            rollback();
            return rc;
        }
        /// `gn_plugin_init` returned `GN_OK` but did not write a
        /// non-NULL `self`. Stateless plugins legitimately leave
        /// `self == NULL` (raw protocol, null security), so this is
        /// a soft warning rather than a hard failure — but every
        /// subsequent vtable call will dispatch with a NULL `self`
        /// argument, and a stateful plugin that forgot to assign
        /// `*self_out` would crash on the first slot invocation.
        /// The log line names the plugin so the operator can pick
        /// up the trail without digging through symbol tables.
        if (inst.self == nullptr) {
            SPDLOG_LOGGER_WARN(::gn::log::kernel().get(),
                "plugin '{}' returned GN_OK from gn_plugin_init but did "
                "not set *self_out; subsequent vtable calls will run "
                "with self == NULL — verify the plugin is stateless or "
                "fix the init entry",
                inst.descriptor.plugin_name);
        }
    }

    /// Phase 5: register_all.
    for (auto& inst : instances_) {
        gn_result_t rc = GN_OK;
        if (inst.remote) {
            rc = inst.remote->call_register(
                reinterpret_cast<std::uintptr_t>(inst.self));
        } else {
            auto* reg_fn = reinterpret_cast<gn_plugin_register_fn>(
                dlsym(inst.so_handle, "gn_plugin_register"));
            rc = safe_call_result(
                "plugin.gn_plugin_register",
                reg_fn, inst.self);
        }
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

bool PluginManager::drain_anchor(PluginInstance& inst,
                                  const std::weak_ptr<PluginAnchor>& watch) {
    /// Spin-wait with a short backoff. Most async callbacks complete
    /// in the microsecond range; the timeout exists to catch stuck
    /// workers that the plugin never told us about (a §9 violation).
    /// The interval grows from 100µs to 1ms so a fast quiescence
    /// pays no perceptible cost while a slow one yields the CPU.
    using clock = std::chrono::steady_clock;
    const auto deadline = clock::now() + quiescence_timeout_;
    auto interval = std::chrono::microseconds{100};
    while (true) {
        /// Lock the weak observer once per iteration. A null lock
        /// means every strong holder dropped — registries, snapshots,
        /// and gate guards — and `dlclose` is safe. Reading
        /// `in_flight` through the same locked strong ref avoids the
        /// race where a separate `expired()` check passes but the
        /// subsequent `lock()` for the warning log returns null and
        /// the operator sees `in_flight=0` even though leaked work
        /// just finished racing the deadline.
        auto strong = watch.lock();
        if (!strong) return true;

        if (clock::now() >= deadline) {
            const std::uint64_t in_flight = strong->in_flight.load(
                std::memory_order_acquire);
            ::gn::log::warn(
                "plugin '{}' did not quiesce within {}ms "
                "(in_flight={}); leaking dlclose handle to keep "
                "async callbacks safe",
                inst.descriptor.plugin_name,
                quiescence_timeout_.count(),
                in_flight);
            ++leaked_handles_;
            /// Persistent counter on the kernel's metrics surface
            /// (`metrics.md` §3). `leaked_handles_` resets at the
            /// start of every `rollback()` so the in-test API only
            /// reports the most recent rollback's count; the metric
            /// keeps the cumulative figure across the kernel's
            /// entire lifetime so an operator can graph leak rate
            /// alongside the matching log line.
            kernel_.metrics().increment("plugin.leak.dlclose_skipped");
            return false;
        }
        strong.reset();
        std::this_thread::sleep_for(interval);
        if (interval < std::chrono::milliseconds{1}) {
            interval *= 2;
        }
    }
}

void PluginManager::rollback() {
    leaked_handles_ = 0;

    /// Mirror the activation path: unregister registered, shutdown
    /// inited, drain anchors, dlclose loaded — all in reverse order.
    /// The drain step is the §4 quiescence gate: registry entries
    /// drop their anchor copy on `unregister`, the plugin's `self`
    /// is destroyed by `shutdown`, and the kernel-side strong refs
    /// drop right before the wait. Anything that survives is an
    /// in-flight dispatch snapshot — we wait for it to release the
    /// anchor before unmapping the .text section behind its vtable.
    for (auto it = instances_.rbegin(); it != instances_.rend(); ++it) {
        /// Publish `shutdown_requested = true` before any plugin
        /// entry runs in the rollback path. Async callbacks scheduled
        /// after this point refuse to enter plugin code through
        /// `GateGuard::acquire`; long-running plugin loops that poll
        /// `is_shutdown_requested` see the flag and exit cooperatively
        /// during `gn_plugin_unregister` / `gn_plugin_shutdown`
        /// (`plugin-lifetime.md` §8).
        if (it->ctx && it->ctx->plugin_anchor) {
            it->ctx->plugin_anchor->shutdown_requested.store(
                true, std::memory_order_release);
        }

        if (it->registered) {
            if (it->remote) {
                /// Remote-linkage path: `unregister` becomes a
                /// PLUGIN_CALL frame and the worker mirrors the
                /// in-process plugin's unregister entry-point. The
                /// `gn_result_t` is discarded same as the other
                /// branches — teardown continues regardless.
                (void)it->remote->call_unregister(
                    reinterpret_cast<std::uintptr_t>(it->self));
            } else if (it->so_handle) {
                if (auto* fn = reinterpret_cast<gn_plugin_unregister_fn>(
                        dlsym(it->so_handle, "gn_plugin_unregister"))) {
                    /// `gn_result_t` discarded — the unregister path
                    /// continues to teardown regardless of the
                    /// plugin's reported outcome; we only care that
                    /// no exception escapes the C ABI boundary.
                    (void)safe_call_result(
                        "plugin.gn_plugin_unregister",
                        fn, it->self);
                }
            } else if (it->static_entry && it->static_entry->unreg) {
                /// Static-linkage path: dlsym would return null for
                /// the suffix-renamed entry, so we read the function
                /// pointer the registry already provides. Same
                /// noexcept guarantees apply across the C ABI.
                (void)safe_call_result(
                    "plugin.gn_plugin_unregister",
                    it->static_entry->unreg, it->self);
            }
            it->registered = false;
        }

        /// Cancel still-pending timers / posted tasks for this anchor.
        /// Cancellation removes registry entries; in-flight callbacks
        /// that were already past `GateGuard::acquire` continue to
        /// run against the still-live plugin until they release the
        /// guard.
        if (it->ctx && it->ctx->plugin_anchor) {
            kernel_.timers().cancel_for_anchor(it->ctx->plugin_anchor);
        }

        /// Drain BEFORE `gn_plugin_shutdown`. Two-step: (1) demote the
        /// kernel-side strong references to weak observers — once
        /// every kernel-held strong drops, the only refs that keep
        /// `watch.lock()` alive are in-flight `GateGuard`s; (2) wait
        /// for those guards to release. After drain returns the
        /// plugin has zero callbacks running through its `.text`,
        /// every `user_data` derived from `self` is no longer being
        /// dereferenced, and `gn_plugin_shutdown` can free `self`
        /// without racing an active dispatch.
        ///
        /// Pre-fix order placed `drain_anchor` AFTER `gn_plugin_shutdown`,
        /// which meant `delete self` ran while a guard-holding callback
        /// was mid-call. The gate kept `.text` mapped — the call
        /// resolved — but the lambda's `user_data = &p->link->state`
        /// pointed at freed memory by the time the body ran. UAF
        /// observable under ASan on any timer-firing plugin in
        /// rollback.
        std::weak_ptr<PluginAnchor> watch;
        if (it->ctx) {
            watch = it->ctx->plugin_anchor;
            it->ctx->plugin_anchor.reset();
        }
        const bool drained = drain_anchor(*it, watch);

        if (it->self) {
            if (it->remote) {
                /// `call_shutdown` is void (no return code). The
                /// worker reaps state and acks the PLUGIN_CALL but
                /// we do not branch on its reply.
                it->remote->call_shutdown(
                    reinterpret_cast<std::uintptr_t>(it->self));
            } else if (it->so_handle) {
                if (auto* fn = reinterpret_cast<gn_plugin_shutdown_fn>(
                        dlsym(it->so_handle, "gn_plugin_shutdown"))) {
                    safe_call_void("plugin.gn_plugin_shutdown",
                        fn, it->self);
                }
            } else if (it->static_entry && it->static_entry->shutdown) {
                /// Static-linkage path — see the matching branch in
                /// the unregister step above. The static registry
                /// supplies the function pointer directly.
                safe_call_void("plugin.gn_plugin_shutdown",
                    it->static_entry->shutdown, it->self);
            }
            it->self = nullptr;
        }

        if (it->remote) {
            /// Remote-linkage final phase: send GOODBYE, join the
            /// reader thread, reap the worker process. The unique_ptr
            /// destructor would do this too, but running it
            /// explicitly here keeps the dlclose-vs-terminate
            /// ordering symmetric with the dlopen path.
            it->remote->terminate();
            it->remote.reset();
        }

        if (it->so_handle) {
            if (drained) {
                dlclose(it->so_handle);
            }
            it->so_handle = nullptr;
        }

        /// Close the integrity fd that pinned the inode through the
        /// dlopen call. It only stayed open so the kernel could not
        /// reuse the fd number for the next plugin's
        /// `dlopen("/proc/self/fd/N")` and hit a glibc cache line.
        /// After dlopen has the .so mapped, the fd has no further
        /// purpose.
#ifdef __linux__
        if (it->integrity_fd >= 0) {
            ::close(it->integrity_fd);
            it->integrity_fd = -1;
        }
#endif

        /// ctx is the last kernel-side owner of the heap allocation.
        /// Reset it after dlclose so any leftover `host_ctx` pointer
        /// the plugin captured points at freed memory rather than
        /// freed-and-reused memory; any UAF here surfaces as a clean
        /// ASan diagnostic instead of a silent corruption.
        it->ctx.reset();
    }
    instances_.clear();
    active_ = false;
}

void PluginManager::shutdown() {
    if (!active_ && instances_.empty()) return;
    rollback();
}

void PluginManager::set_manifest(PluginManifest manifest) noexcept {
    manifest_ = std::move(manifest);
}

void PluginManager::set_manifest_required(bool required) noexcept {
    manifest_required_ = required;
}

// ── Static-registry path ─────────────────────────────────────────────
//
// Activates every plugin baked into the kernel binary at link time.
// The registry array (`gn_plugin_static_registry[]`, declared in
// `core/plugin/static_registry.hpp`) is populated by either the
// generated `static_plugins.cpp` (under `-DGOODNET_STATIC_PLUGINS=ON`)
// or by the empty default TU. Either way the iteration here is
// safe — a dynamic build hits the sentinel on the first read and
// returns GN_OK after a no-op.

#include <core/plugin/static_registry.hpp>

gn_result_t PluginManager::load_static(std::string* out_diagnostic) {
    if (active_) {
        if (out_diagnostic) *out_diagnostic = "PluginManager already active";
        return GN_ERR_LIMIT_REACHED;
    }
    auto note = [&](std::string_view m) {
        if (out_diagnostic) *out_diagnostic = std::string(m);
    };

    /// Phase 1-3: gather every registry entry. We skip dlopen + symbol
    /// resolution + integrity verification entirely — every entry's
    /// addresses are already valid (the linker resolved them at build
    /// time) and the symbols' identity is implicit in the binary's
    /// own integrity check (the operator must verify the kernel itself
    /// rather than per-plugin .so files in this mode).
    for (const auto* e = &gn_plugin_static_registry[0];
         e->name != nullptr; ++e) {

        /// Static plugins ship inside the kernel binary; their SDK
        /// version is forcibly identical to the host. Still call
        /// `sdk_version` if present so a future build that ships
        /// an out-of-tree static archive can catch a stale .a at
        /// the same point as the dlopen path catches a stale .so.
        if (e->sdk_version) {
            uint32_t pmaj = 0, pmin = 0, ppatch = 0;
            e->sdk_version(&pmaj, &pmin, &ppatch);
            if (pmaj != GN_SDK_VERSION_MAJOR) {
                note(std::string("sdk-version mismatch: ") + e->name);
                rollback();
                return GN_ERR_VERSION_MISMATCH;
            }
        }

        PluginInstance inst{};
        inst.path = std::string("static://") + e->name;
        inst.static_entry = e;
        inst.ctx = std::make_unique<PluginContext>();
        inst.ctx->plugin_name = e->name;
        inst.ctx->kernel      = &kernel_;
        inst.ctx->plugin_anchor = std::make_shared<PluginAnchor>();

        if (e->descriptor) {
            if (const auto* d = e->descriptor(); d != nullptr) {
                if (d->name) inst.descriptor.plugin_name = d->name;
                inst.ctx->kind = d->kind;
            }
        }
        if (inst.descriptor.plugin_name.empty()) {
            inst.descriptor.plugin_name = e->name;
        }

        inst.api = build_host_api(*inst.ctx);

        instances_.push_back(std::move(inst));
    }

    /// Phase 4: init each plugin.
    for (std::size_t i = 0; i < instances_.size(); ++i) {
        auto& inst  = instances_[i];
        const auto* e = &gn_plugin_static_registry[i];
        if (!e->init) continue;
        const auto rc = e->init(&inst.api, &inst.self);
        if (rc != GN_OK) {
            note(std::string("gn_plugin_init failed: ") + e->name);
            rollback();
            return rc;
        }
    }

    /// Phase 5: register each plugin.
    for (std::size_t i = 0; i < instances_.size(); ++i) {
        auto& inst  = instances_[i];
        const auto* e = &gn_plugin_static_registry[i];
        if (!e->reg) continue;
        const auto rc = e->reg(inst.self);
        if (rc != GN_OK) {
            note(std::string("gn_plugin_register failed: ") + e->name);
            rollback();
            return rc;
        }
        inst.registered = true;
    }

    active_ = true;
    return GN_OK;
}

} // namespace gn::core
