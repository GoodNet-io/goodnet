/// @file   core/plugin/plugin_manager.hpp
/// @brief  Loads plugin shared objects, version-checks, and orchestrates
///         the two-phase activation per `plugin-lifetime.md` §5.
///
/// Skeleton scope — covers the Linux dlopen path: discover via
/// explicit path list, resolve the five entry symbols, version
/// check against the kernel's SDK version, ServiceResolver toposort,
/// init_all → register_all, mirror in reverse on shutdown.
///
/// SHA-256 manifest verification and hot-reload land as additive
/// features once the dispatch generation-counter quiescence wait is
/// wired (per `plugin-lifetime.md` §6).

#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <sdk/host_api.h>
#include <sdk/types.h>

#include <core/kernel/plugin_context.hpp>
#include <core/kernel/service_resolver.hpp>

namespace gn::core {

class Kernel;

/// One loaded plugin shared object plus its kernel-side state.
struct PluginInstance {
    std::string             path;        ///< absolute .so path
    void*                   so_handle;   ///< dlopen result; opaque to plugin
    PluginContext           ctx;         ///< handed via api->host_ctx
    host_api_t              api;         ///< per-plugin instance of the public table
    void*                   self;        ///< returned from gn_plugin_init
    ServiceDescriptor       descriptor;  ///< name + ext_requires/_provides
    bool                    registered;  ///< whether gn_plugin_register succeeded
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

    /// Reverse the activation: unregister every plugin, then
    /// shutdown, then dlclose. Idempotent — second call no-ops.
    void shutdown();

    /// Number of currently-active plugins (post-init, pre-shutdown).
    [[nodiscard]] std::size_t size() const noexcept { return instances_.size(); }

private:
    /// Build a ServiceDescriptor from the loaded plugin. Reads the
    /// optional `gn_plugin_descriptor` symbol; absence yields an
    /// empty descriptor (no provides, no requires) which still flows
    /// through the resolver as a leaf node.
    [[nodiscard]] gn_result_t open_one(const std::string& path,
                                       PluginInstance& out,
                                       std::string& out_diagnostic);

    /// Roll back from a partial init or register pass. Releases
    /// every still-live instance in reverse order.
    void rollback();

    Kernel&                      kernel_;
    std::vector<PluginInstance>  instances_;
    bool                         active_{false};
};

} // namespace gn::core
