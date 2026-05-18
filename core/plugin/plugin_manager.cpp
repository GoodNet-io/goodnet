/// @file   core/plugin/plugin_manager.cpp
/// @brief  Orchestrator for the plugin lifecycle. Kind-specific
///         load/init/register/unregister/shutdown/close logic lives
///         in `runtimes/<kind>.cpp`; this file is the dispatcher,
///         the service-resolver wiring, and the anchor-quiescence
///         wait that gates `dlclose`.

#include "plugin_manager.hpp"

#include <algorithm>
#include <cassert>
#include <chrono>
#include <thread>
#include <utility>

#include <core/kernel/kernel.hpp>
#include <core/plugin/remote_host.hpp>
#include <core/plugin/runtimes/dynamic.hpp>
#include <core/plugin/runtimes/remote.hpp>
#include <core/plugin/runtimes/static.hpp>
#include <core/plugin/static_registry.hpp>
#include <core/util/log.hpp>

#include <sdk/host_api.h>
#include <sdk/link.h>

namespace gn::core {

PluginManager::PluginManager(Kernel& kernel) noexcept : kernel_(kernel) {
    /// Populate the runtime registry with the three built-in
    /// linkage kinds. Hosts can add custom entries (Wasm, FFI) by
    /// calling `register_runtime` before `load`. The map outlives
    /// every PluginInstance — instances borrow these pointers
    /// through `PluginInstance::runtime`.
    runtimes_.emplace("dynamic", std::make_unique<DynamicRuntime>());
    runtimes_.emplace("static",  std::make_unique<StaticRuntime>());
    runtimes_.emplace("remote",  std::make_unique<RemoteRuntime>());
}

PluginManager::~PluginManager() { shutdown(); }

gn_result_t PluginManager::register_runtime(
    std::string kind, std::unique_ptr<IPluginRuntime> runtime) {
    if (runtime == nullptr || kind.empty()) return GN_ERR_NULL_ARG;
    auto [_, inserted] = runtimes_.emplace(std::move(kind),
                                             std::move(runtime));
    return inserted ? GN_OK : GN_ERR_LIMIT_REACHED;
}

IPluginRuntime* PluginManager::runtime_for(
    std::string_view kind) const noexcept {
    auto it = runtimes_.find(kind);
    return it == runtimes_.end() ? nullptr : it->second.get();
}

gn_result_t PluginManager::open_one(const std::string& path,
                                    PluginInstance& out,
                                    std::string& diag) {
    /// Pick the runtime by `path` shape (paths starting with
    /// `static://` go to the static-linkage runtime) or by the
    /// manifest entry's `kind` field for everything else. A future
    /// commit will admit a `kind` field on every manifest entry so
    /// path-shape inspection becomes optional.
    std::string_view kind = "dynamic";
    const ManifestEntry* me = nullptr;
    if (path.compare(0, 9, "static://") == 0) {
        kind = "static";
    } else if (!manifest_.empty()) {
        me = manifest_.find(path);
        if (me != nullptr && me->kind == ManifestKind::Remote) {
            kind = "remote";
        }
    }

    auto* runtime = runtime_for(kind);
    if (runtime == nullptr) {
        diag = "no plugin runtime registered for kind '";
        diag += kind;
        diag += "'";
        return GN_ERR_NOT_IMPLEMENTED;
    }

    PluginLoadContext ctx{
        .kernel = &kernel_,
        .manifest = &manifest_,
        .manifest_required = manifest_required_,
    };
    if (auto rc = runtime->load(path, ctx, out, diag); rc != GN_OK) {
        return rc;
    }
    /// Lift the per-plugin quiescence override out of the manifest
    /// entry so `drain_anchor` can consult it during rollback after
    /// `inst.path` has been cleared by the post-resolve reorder.
    /// Zero (the manifest default and the static-path default)
    /// keeps the global manager-wide value.
    if (me != nullptr) {
        out.quiescence_timeout_s = me->quiescence_timeout_s;
    }
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

    /// `limits.en.md` §4a: reject the whole load if it would push the
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
        const auto rc = init_one(inst);
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
        const auto rc = register_one(inst);
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

gn_result_t PluginManager::init_one(PluginInstance& inst) {
    if (inst.runtime == nullptr) return GN_ERR_INVALID_STATE;
    return inst.runtime->init(inst);
}

gn_result_t PluginManager::register_one(PluginInstance& inst) {
    if (inst.runtime == nullptr) return GN_ERR_INVALID_STATE;
    return inst.runtime->register_plugin(inst);
}

void PluginManager::unregister_one(PluginInstance& inst) {
    if (inst.runtime == nullptr) return;
    inst.runtime->unregister(inst);
}

void PluginManager::shutdown_one(PluginInstance& inst) {
    if (inst.runtime == nullptr) return;
    inst.runtime->shutdown(inst);
}

bool PluginManager::drain_anchor(PluginInstance& inst,
                                  const std::weak_ptr<PluginAnchor>& watch) {
    /// Spin-wait with a short backoff. Most async callbacks complete
    /// in the microsecond range; the timeout exists to catch stuck
    /// workers that the plugin never told us about (a §9 violation).
    /// The interval grows from 100µs to 1ms so a fast quiescence
    /// pays no perceptible cost while a slow one yields the CPU.
    ///
    /// The effective timeout is the manifest's per-plugin override
    /// when non-zero, else the manager-wide default. A long-running
    /// handler (large key derivation, slow disk flush) declares a
    /// higher value in its manifest entry so rollback waits long
    /// enough to drain its in-flight work rather than leaking the
    /// dlclose handle.
    using clock = std::chrono::steady_clock;
    const auto effective_timeout =
        inst.quiescence_timeout_s > 0
            ? std::chrono::milliseconds{
                  std::chrono::seconds{inst.quiescence_timeout_s}}
            : quiescence_timeout_;
    const auto deadline = clock::now() + effective_timeout;
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
                effective_timeout.count(),
                in_flight);
            ++leaked_handles_;
            /// Persistent counter on the kernel's metrics surface
            /// (`metrics.en.md` §3). `leaked_handles_` resets at the
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

void PluginManager::teardown_one(PluginInstance& inst) {
    /// Publish `shutdown_requested = true` before any plugin
    /// entry runs in the teardown path. Async callbacks scheduled
    /// after this point refuse to enter plugin code through
    /// `GateGuard::acquire`; long-running plugin loops that poll
    /// `is_shutdown_requested` see the flag and exit cooperatively
    /// during `gn_plugin_unregister` / `gn_plugin_shutdown`
    /// (`plugin-lifetime.en.md` §8).
    if (inst.ctx && inst.ctx->plugin_anchor) {
        inst.ctx->plugin_anchor->shutdown_requested.store(
            true, std::memory_order_release);
    }

    if (inst.registered) {
        unregister_one(inst);
        inst.registered = false;
    }

    /// Cancel still-pending timers / posted tasks for this anchor.
    /// Cancellation removes registry entries; in-flight callbacks
    /// that were already past `GateGuard::acquire` continue to
    /// run against the still-live plugin until they release the
    /// guard.
    if (inst.ctx && inst.ctx->plugin_anchor) {
        kernel_.timers().cancel_for_anchor(inst.ctx->plugin_anchor);
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
    /// Inverting this order — `gn_plugin_shutdown` before drain —
    /// would free `self` while a guard-holding callback was
    /// mid-call. The gate keeps `.text` mapped so the call
    /// resolves, but a lambda capturing `user_data = &p->link->state`
    /// would then dereference freed memory. The drain MUST run
    /// before `gn_plugin_shutdown` to keep the dereference safe.
    std::weak_ptr<PluginAnchor> watch;
    if (inst.ctx) {
        watch = inst.ctx->plugin_anchor;
        inst.ctx->plugin_anchor.reset();
    }
    const bool drained = drain_anchor(inst, watch);

    if (inst.self) {
        shutdown_one(inst);
        inst.self = nullptr;
    }

    /// Hand off the kind-specific load-state teardown to the
    /// runtime. Dynamic: dlclose if drained, plus the integrity
    /// fd. Remote: terminate + reset the RemoteHost. Static:
    /// nothing — entry symbols live in the kernel binary.
    if (inst.runtime != nullptr) {
        inst.runtime->close(inst, drained);
    }

    /// ctx is the last kernel-side owner of the heap allocation.
    /// Reset it after dlclose so any leftover `host_ctx` pointer
    /// the plugin captured points at freed memory rather than
    /// freed-and-reused memory; any UAF here surfaces as a clean
    /// ASan diagnostic instead of a silent corruption.
    inst.ctx.reset();
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
        teardown_one(*it);
    }
    instances_.clear();
    active_ = false;
}

gn_result_t PluginManager::unload(std::string_view name) {
    /// Find by descriptor's `plugin_name`. Matches the field the
    /// plugin sets in its `gn_plugin_descriptor` and the same key
    /// the resolver uses for dependency edges. An empty name has
    /// no chance of matching, so callers see `NOT_FOUND` instead
    /// of an accidental wildcard.
    if (name.empty()) return GN_ERR_NOT_FOUND;

    auto it = std::find_if(
        instances_.begin(), instances_.end(),
        [&](const PluginInstance& inst) {
            return inst.descriptor.plugin_name == name;
        });
    if (it == instances_.end()) return GN_ERR_NOT_FOUND;

    /// Reset the leak counter to match `rollback()` semantics — the
    /// per-call value reports "did this unload leak a handle?" and
    /// nothing more. Cumulative leaks live on the metrics surface.
    leaked_handles_ = 0;

    teardown_one(*it);
    instances_.erase(it);

    /// Walk the post-erase state to keep `active_` honest. The flag
    /// is the gate `load()` checks on entry; clearing it once every
    /// instance is gone lets a host re-prime the manager with a
    /// fresh `load()` after a sequence of `unload()` calls.
    if (instances_.empty()) {
        active_ = false;
    }
    return GN_OK;
}

void PluginManager::shutdown() {
    if (!active_ && instances_.empty()) return;
    rollback();
}

void PluginManager::set_manifest(PluginManifest manifest) noexcept {
    /// Manifest setters are bootstrap-only — the contract in the
    /// header (`plugin-manifest.en.md` §5 step 4) demands every
    /// setter run before `load`. Swapping the trust root mid-session
    /// would let a load admitted under the old hash list keep its
    /// instance live while a new arrival is checked against fresh
    /// expectations, and the per-plugin `quiescence_timeout_s`
    /// resolved at `open_one` would no longer match the manifest in
    /// effect. The assert turns the contract's "does not guard"
    /// note into a loud failure under an embedder bug.
    assert(!active_ && "manifest setters are bootstrap-only");
    manifest_ = std::move(manifest);
}

void PluginManager::set_manifest_required(bool required) noexcept {
    /// Bootstrap-only per the same reasoning as `set_manifest`.
    /// Flipping the required flag during an active session would
    /// not retroactively reject already-loaded plugins; the assert
    /// catches the misuse at the setter call rather than silently
    /// shipping a half-enforced policy.
    assert(!active_ && "manifest setters are bootstrap-only");
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
    /// Walk the registry to synthesize `static://<name>` paths and
    /// dispatch through the same `load()` entry the dynamic / remote
    /// paths take. The `static` runtime maps each synthesized path
    /// back to its registry entry; the rest of the lifecycle
    /// (resolver pass, init + register loops, rollback) is identical
    /// to a dlopen-driven load.
    std::vector<std::string> paths;
    for (const auto* e = &gn_plugin_static_registry[0];
         e->name != nullptr; ++e) {
        paths.emplace_back(std::string("static://") + e->name);
    }
    return load(paths, out_diagnostic);
}

} // namespace gn::core
