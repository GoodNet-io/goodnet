/// @file   apps/goodnet/subcommands/run.cpp
/// @brief  `goodnet run --config X --manifest Y --identity Z` —
///         production node entry point.
///
/// Loads NodeIdentity from disk, parses the kernel config + plugin
/// manifest, constructs a Kernel with the gnet protocol layer, hands
/// it to a PluginManager to dlopen the link / security / handler
/// plugins listed in the manifest, then sits on SIGTERM / SIGINT.
/// On signal: PluginManager.shutdown() drains in-flight async work
/// before the process exits.
///
/// gnet protocol is linked statically into the binary (it is the v1
/// canonical mesh-framing layer; an out-of-tree protocol layer would
/// override it through the kernel's `set_protocol_layer` from a host
/// program, not through the manifest). Operators with a custom
/// protocol layer build their own runner.

#include "../subcommands.hpp"

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <memory>
#include <sstream>
#include <string>
#include <thread>

#include <core/config/config.hpp>
#include <core/identity/node_identity.hpp>
#include <core/kernel/host_api_builder.hpp>
#include <core/kernel/kernel.hpp>
#include <core/kernel/plugin_context.hpp>
#include <core/plugin/plugin_manager.hpp>
#include <core/plugin/plugin_manifest.hpp>
#include <core/util/log.hpp>
#include <core/util/log_config.hpp>

#include <plugins/protocols/gnet/protocol.hpp>

namespace gn::apps::goodnet {

namespace {

/// Set on SIGTERM / SIGINT by the installed signal handler. The main
/// loop polls; on first set, the loop drops out and starts cleanup.
std::atomic<int> g_quit_signal{0};

extern "C" void run_signal_handler(int sig) {
    /// Set-once: a second signal during cleanup is a SIGKILL hint
    /// from systemd (TimeoutStopSec exceeded) — the kernel can't
    /// listen for it, but we don't overwrite the first sig number
    /// in case the operator wants to log which signal arrived first.
    int expected = 0;
    (void)g_quit_signal.compare_exchange_strong(expected, sig);
}

struct RunArgs {
    std::string config_path;
    std::string manifest_path;
    std::string identity_path;
};

[[nodiscard]] int parse_args(std::span<const std::string_view> args,
                              RunArgs& out) {
    for (std::size_t i = 0; i < args.size(); ++i) {
        const auto a = args[i];
        const auto need_val = [&](const char* flag) -> bool {
            if (i + 1 >= args.size()) {
                (void)std::fprintf(stderr,
                    "goodnet run: %s requires an argument\n", flag);
                return false;
            }
            return true;
        };
        if (a == "--config") {
            if (!need_val("--config")) return 2;
            out.config_path.assign(args[++i]);
        } else if (a == "--manifest") {
            if (!need_val("--manifest")) return 2;
            out.manifest_path.assign(args[++i]);
        } else if (a == "--identity") {
            if (!need_val("--identity")) return 2;
            out.identity_path.assign(args[++i]);
        } else {
            (void)std::fprintf(stderr,
                "goodnet run: unknown argument '%.*s'\n",
                static_cast<int>(a.size()), a.data());
            return 2;
        }
    }
    if (out.config_path.empty() ||
        out.manifest_path.empty() ||
        out.identity_path.empty()) {
        (void)std::fputs(
            "goodnet run: requires --config FILE --manifest FILE --identity FILE\n",
            stderr);
        return 2;
    }
    return 0;
}

[[nodiscard]] std::optional<std::string> read_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return std::nullopt;
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

}  // namespace

int cmd_run(std::span<const std::string_view> args) {
    RunArgs ra;
    if (const int rc = parse_args(args, ra); rc != 0) return rc;

    /// Identity first — the kernel's security pipeline needs it
    /// before any conn allocates a session, and a missing identity
    /// is a deploy-config error, not a runtime fault.
    auto identity = gn::core::identity::NodeIdentity::load_from_file(
        ra.identity_path);
    if (!identity) {
        (void)std::fprintf(stderr,
            "goodnet run: identity %s — %s\n",
            ra.identity_path.c_str(),
            identity.error().what.empty()
                ? "load failed"
                : identity.error().what.c_str());
        return 1;
    }

    /// Config: parse + validate. Same path as
    /// `goodnet config validate`, but here a failure exits the
    /// runner rather than reporting OK.
    gn::core::Config cfg;
    {
        std::string reason;
        if (cfg.load_file(ra.config_path, &reason) != GN_OK) {
            (void)std::fprintf(stderr,
                "goodnet run: config %s — %s\n",
                ra.config_path.c_str(), reason.c_str());
            return 1;
        }
    }

    /// Manifest: trust root for plugin loads. Read the file bytes,
    /// hand them to `PluginManifest::parse`. PluginManager is
    /// configured with `set_manifest_required=true` so an absent
    /// manifest entry refuses dlopen with `GN_ERR_INTEGRITY_FAILED`.
    gn::core::PluginManifest manifest;
    {
        const auto bytes = read_file(ra.manifest_path);
        if (!bytes) {
            (void)std::fprintf(stderr,
                "goodnet run: manifest %s — cannot open\n",
                ra.manifest_path.c_str());
            return 1;
        }
        std::string diag;
        if (gn::core::PluginManifest::parse(*bytes, manifest, diag) != GN_OK) {
            (void)std::fprintf(stderr,
                "goodnet run: manifest %s — %s\n",
                ra.manifest_path.c_str(), diag.c_str());
            return 1;
        }
    }

    /// Kernel up. Order:
    /// 1. Apply config-derived limits (protocol layer reads them on
    ///    every frame, so they must be in place before the layer
    ///    sees traffic).
    /// 2. Set the gnet protocol layer.
    /// 3. Install identity (security pipeline reads it on every
    ///    `notify_connect`).
    /// 4. apply_log_config — reroutes spdlog with the config's
    ///    format/level.
    using gn::core::Kernel;
    using gn::core::PluginContext;
    using gn::core::PluginManager;
    using gn::core::build_host_api;
    using gn::plugins::gnet::GnetProtocol;

    Kernel kernel;
    kernel.set_limits(cfg.limits());
    kernel.set_protocol_layer(std::make_shared<GnetProtocol>());
    kernel.identities().add(identity->device().public_key());
    kernel.set_node_identity(std::move(*identity));
    /// `Kernel::apply_log_config` is private (only `reload_config`
    /// calls it from inside the kernel); apply the same shape from
    /// the runner side via the public `gn::log::init_with` +
    /// `load_log_config(cfg)` helper.
    (void)gn::log::init_with(gn::core::util::load_log_config(cfg));

    /// Host context for the runner itself — no plugin anchor (the
    /// runner is not a loaded plugin), `kind = LINK` so the runner
    /// can hand `host_api` to embedded fixtures if one ever ships.
    /// Loaded plugins build their own contexts inside
    /// `PluginManager::load`.
    PluginContext host_ctx;
    host_ctx.plugin_name = "goodnet-runner";
    host_ctx.kernel      = &kernel;
    (void)build_host_api(host_ctx);  // initialises kernel-side state

    PluginManager plugins{kernel};
    plugins.set_manifest(std::move(manifest));
    plugins.set_manifest_required(true);

    /// Pull the manifest's path list into a flat `std::vector<std::string>`
    /// for `PluginManager::load`. The manager re-hashes each path as
    /// part of the integrity gate, so we don't pre-verify here.
    std::vector<std::string> plugin_paths;
    for (const auto& entry : plugins.manifest().entries()) {
        plugin_paths.emplace_back(entry.path);
    }
    {
        std::string diag;
        if (plugins.load(std::span<const std::string>(plugin_paths),
                          &diag) != GN_OK) {
            (void)std::fprintf(stderr,
                "goodnet run: plugin load failed — %s\n", diag.c_str());
            return 1;
        }
    }

    /// Signal handlers go in AFTER plugins load — until then a
    /// SIGTERM should kill the process immediately rather than walk
    /// a half-loaded shutdown path.
    /// `std::signal` returns the previous handler; we don't need it
    /// (no chained handler to restore on graceful exit since we
    /// intentionally drain on SIGTERM/SIGINT).
    (void)std::signal(SIGINT,  &run_signal_handler);
    (void)std::signal(SIGTERM, &run_signal_handler);

    (void)std::fprintf(stdout,
        "goodnet run: kernel up — %zu plugins loaded, awaiting signal\n",
        plugin_paths.size());

    /// Main loop: poll the quit flag every 100ms. Active work runs
    /// on plugin worker threads (asio io_context per transport,
    /// service executor per timer). The runner thread does nothing
    /// but wait — sleeping is correct; spinning would waste cycles.
    while (g_quit_signal.load() == 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    (void)std::fprintf(stdout,
        "goodnet run: signal %d received, draining plugins\n",
        g_quit_signal.load());

    /// Ordered teardown: PluginManager.shutdown() walks every loaded
    /// plugin's `gn_plugin_unregister` + `gn_plugin_shutdown` and
    /// waits on each anchor's weak_ptr to drop before `dlclose`.
    plugins.shutdown();

    (void)std::fprintf(stdout, "goodnet run: clean exit\n");
    return 0;
}

}  // namespace gn::apps::goodnet
