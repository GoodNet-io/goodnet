/// @file   core/plugin/plugin_manager.hpp
/// @brief  Loads plugin shared objects, version-checks, and orchestrates
///         the two-phase activation per `plugin-lifetime.md` §5.
///
/// Discovery happens via an explicit path list. Each plugin is
/// dlopened, version-checked against the kernel SDK triple, mapped
/// onto a stable `PluginContext` (heap-allocated so the address
/// handed to plugins through `host_api->host_ctx` survives
/// reordering), and run through the two-phase activation pipeline.
///
/// The reference-counted ownership invariant from
/// `plugin-lifetime.md` §4 is enforced here: every loaded plugin
/// owns a `std::shared_ptr<PluginAnchor>` lifetime anchor that
/// registry entries copy at registration time. The anchor carries
/// the `shutdown_requested` flag and the `in_flight` counter that
/// `GateGuard` maintains around every async callback. Unload waits
/// on a `weak_ptr` observation of the sentinel before `dlclose` to
/// prevent the classic "dispatch into a torn-down handler" UAF.
///
/// SHA-256 manifest verification and hot-reload land as additive
/// features once the dispatch generation-counter quiescence wait is
/// wired (per `plugin-lifetime.md` §6).

#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <sdk/host_api.h>
#include <sdk/types.h>

#include <core/kernel/plugin_context.hpp>
#include <core/kernel/service_resolver.hpp>
#include <core/plugin/plugin_manifest.hpp>
#include <core/plugin/static_registry.hpp>

namespace gn::core {

class Kernel;

/// One loaded plugin shared object plus its kernel-side state.
///
/// `ctx` is heap-allocated through `unique_ptr` so its address stays
/// stable across `instances_` reorders (the address is passed to the
/// plugin through `host_api->host_ctx` and captured in the plugin's
/// own state — moving it would invalidate every callback).
struct PluginInstance {
    std::string                       path;        ///< absolute .so path or `static://<name>` for the static-linkage path
    void*                             so_handle{nullptr};   ///< dlopen result; opaque to plugin
    int                               integrity_fd{-1};     ///< /proc/self/fd path source — kept open until shutdown so glibc dlopen does not reuse the path string across plugins
    std::unique_ptr<PluginContext>    ctx;         ///< handed via api->host_ctx
    host_api_t                        api{};       ///< per-plugin instance of the public table
    void*                             self{nullptr};        ///< returned from gn_plugin_init
    ServiceDescriptor                 descriptor;  ///< name + ext_requires/_provides
    bool                              registered{false};    ///< whether gn_plugin_register succeeded
    /// Non-null when the instance came from
    /// `gn_plugin_static_registry[]` instead of dlopen — the
    /// rollback path reads `unreg`/`shutdown` from here when
    /// `so_handle == nullptr`.
    const gn_plugin_static_entry_t*   static_entry{nullptr};
};

class PluginManager {
public:
    explicit PluginManager(Kernel& kernel) noexcept;
    ~PluginManager();

    PluginManager(const PluginManager&)            = delete;
    PluginManager& operator=(const PluginManager&) = delete;

    /// Load every shared object in @p paths, version-check each,
    /// build descriptors via the optional `gn_plugin_descriptor`
    /// symbol, run the ServiceResolver, then two-phase activate
    /// the ordered set per `plugin-lifetime.md` §5. Returns the
    /// first failing step's `gn_result_t` and triggers rollback so
    /// no half-state survives.
    ///
    /// @p out_diagnostic receives a human-readable description of
    /// any failing step.
    [[nodiscard]] gn_result_t load(std::span<const std::string> paths,
                                   std::string* out_diagnostic = nullptr);

    /// Activate every plugin from the static registry instead of
    /// `dlopen`. Used by `-DGOODNET_STATIC_PLUGINS=ON` builds where
    /// every plugin's entry symbols ship inside the kernel binary
    /// itself (suffix-renamed per the macros in `sdk/plugin.h`).
    /// Mirror semantics of `load()`: two-phase init → register with
    /// rollback on any failure. The registry array
    /// (`gn_plugin_static_registry[]`) is iterated until its
    /// sentinel `name == nullptr` is seen. Empty under a dynamic
    /// build — returns GN_OK after a no-op.
    [[nodiscard]] gn_result_t load_static(
        std::string* out_diagnostic = nullptr);

    /// Reverse the activation: unregister every plugin, then
    /// shutdown, then dlclose. Idempotent — second call no-ops.
    void shutdown();

    /// Number of currently-active plugins (post-init, pre-shutdown).
    [[nodiscard]] std::size_t size() const noexcept { return instances_.size(); }

    /// How long to wait for outstanding dispatch snapshots to drop
    /// their `lifetime_anchor` copies before falling back to the
    /// "log warn + leak the dlclose handle" path. The default of
    /// one second is chosen to be longer than any reasonable in-flight
    /// dispatch yet short enough that operator-driven shutdown does
    /// not stall. Callers may shorten or lengthen the wait when test
    /// fixtures need deterministic timing.
    void set_quiescence_timeout(std::chrono::milliseconds t) noexcept {
        quiescence_timeout_ = t;
    }
    [[nodiscard]] std::chrono::milliseconds quiescence_timeout() const noexcept {
        return quiescence_timeout_;
    }

    /// Number of plugins whose `dlclose` was skipped during the most
    /// recent rollback because the quiescence wait timed out. Counted
    /// here for tests; in production the warning lands in the log.
    [[nodiscard]] std::size_t leaked_handles() const noexcept {
        return leaked_handles_;
    }

    /// Install an integrity allowlist consulted before every
    /// `dlopen`. An empty manifest (the default) lets every plugin
    /// load — that is the developer-mode path for in-tree fixtures
    /// and the demo. A non-empty manifest puts the loader in
    /// production mode: every path must appear in the manifest with
    /// a matching SHA-256, or `load` fails with
    /// `GN_ERR_INTEGRITY_FAILED`. See `plugin-manifest.md`.
    void set_manifest(PluginManifest manifest) noexcept;

    [[nodiscard]] const PluginManifest& manifest() const noexcept {
        return manifest_;
    }

    /// Demand a non-empty manifest. With this flag set, `load` fails
    /// with `GN_ERR_INTEGRITY_FAILED` whenever the manifest is empty,
    /// even for in-tree paths the developer-mode flow would accept.
    /// Production deployments call this on the bootstrap thread
    /// before `load` and pair it with a populated manifest; dev
    /// fixtures leave the flag at its default `false`. See
    /// `plugin-manifest.md` §7. Both `set_manifest_required` and
    /// `set_manifest` are bootstrap-only — the manager does not
    /// guard against concurrent setter calls during an active
    /// session.
    void set_manifest_required(bool required) noexcept;

    [[nodiscard]] bool manifest_required() const noexcept {
        return manifest_required_;
    }

private:
    /// Build a ServiceDescriptor from the loaded plugin. Reads the
    /// optional `gn_plugin_descriptor` symbol; absence yields an
    /// empty descriptor (no provides, no requires) which still flows
    /// through the resolver as a leaf node.
    [[nodiscard]] gn_result_t open_one(const std::string& path,
                                       PluginInstance& out,
                                       std::string& out_diagnostic);

    /// Roll back from a partial init or register pass. Releases
    /// every still-live instance in reverse order, draining each
    /// plugin's lifetime_anchor weak_ptr between shutdown and dlclose
    /// per `plugin-lifetime.md` §4.
    void rollback();

    /// Drain a single plugin's lifetime anchor before its `dlclose`.
    /// Returns true on clean expiry, false on timeout (caller must
    /// then leak the dlclose handle to keep async callbacks safe).
    [[nodiscard]] bool drain_anchor(PluginInstance& inst,
                                    const std::weak_ptr<PluginAnchor>& watch);

    Kernel&                         kernel_;
    std::vector<PluginInstance>     instances_;
    bool                            active_{false};
    std::chrono::milliseconds       quiescence_timeout_{std::chrono::seconds{1}};
    std::size_t                     leaked_handles_{0};
    PluginManifest                  manifest_;
    bool                            manifest_required_{false};
};

} // namespace gn::core
