/// @file   core/plugin/plugin_manager.cpp
/// @brief  Implementation of the dlopen + two-phase activation path.

#include "plugin_manager.hpp"

#include <dlfcn.h>

#ifdef __linux__
#include <fcntl.h>
#include <unistd.h>
#include <cstdio>
#endif

#include <chrono>
#include <cstring>
#include <thread>
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
        /// `O_NOFOLLOW` rejects a symlink at the leaf; combined
        /// with `dlopen("/proc/self/fd/N")` it pins the kernel
        /// to a single inode across hash and load. An attacker
        /// cannot swap the path between the two operations — the
        /// fd refers to the file the hash covered. Parent-directory
        /// symlink swaps remain in scope of the operator-controls
        /// assumption per `plugin-manifest.md` §7.
        const int fd = ::open(path.c_str(),
                              O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
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
        out.so_handle = ::dlopen(proc_path, RTLD_NOW | RTLD_LOCAL);
        ::close(fd);
        if (!out.so_handle) {
            diag = "dlopen failed for ";
            diag += path;
            diag += ": ";
            if (const char* err = ::dlerror()) diag += err;
            return GN_ERR_UNKNOWN_RECEIVER;
        }
    } else {
        out.so_handle = ::dlopen(path.c_str(), RTLD_NOW | RTLD_LOCAL);
        if (!out.so_handle) {
            diag = "dlopen failed for ";
            diag += path;
            diag += ": ";
            if (const char* err = ::dlerror()) diag += err;
            return GN_ERR_UNKNOWN_RECEIVER;
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

    out.so_handle = ::dlopen(path.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (!out.so_handle) {
        diag = "dlopen failed for ";
        diag += path;
        diag += ": ";
        if (const char* err = ::dlerror()) diag += err;
        return GN_ERR_UNKNOWN_RECEIVER;
    }
#endif

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

        if (it->registered && it->so_handle) {
            if (auto* fn = reinterpret_cast<gn_plugin_unregister_fn>(
                    ::dlsym(it->so_handle, "gn_plugin_unregister"))) {
                fn(it->self);
            }
            it->registered = false;
        }

        /// Cancel still-pending timers / posted tasks for this anchor
        /// **between** unregister and shutdown per `plugin-lifetime.md`
        /// §4 step 3. The plugin's `self` is still alive here, so any
        /// timer caught mid-flight finishes against a live plugin —
        /// after `gn_plugin_shutdown` returns, `self` is gone and a
        /// pending callback dereferencing `user_data = &self->state`
        /// would point at freed memory even though the gate keeps the
        /// `.text` mapped.
        if (it->ctx && it->ctx->plugin_anchor) {
            kernel_.timers().cancel_for_anchor(it->ctx->plugin_anchor);
        }

        if (it->self && it->so_handle) {
            if (auto* fn = reinterpret_cast<gn_plugin_shutdown_fn>(
                    ::dlsym(it->so_handle, "gn_plugin_shutdown"))) {
                fn(it->self);
            }
            it->self = nullptr;
        }

        if (it->so_handle) {
            /// Promote the kernel-side strong reference to a weak
            /// observer, then drop the ctx-held strong ref so only
            /// in-flight snapshots and not-yet-released gate guards
            /// remain.
            std::weak_ptr<PluginAnchor> watch;
            if (it->ctx) {
                watch = it->ctx->plugin_anchor;
                it->ctx->plugin_anchor.reset();
            }

            const bool drained = drain_anchor(*it, watch);
            if (drained) {
                ::dlclose(it->so_handle);
            }
            it->so_handle = nullptr;
        }

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

} // namespace gn::core
