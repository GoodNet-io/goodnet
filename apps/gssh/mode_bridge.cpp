/// @file   apps/gssh/mode_bridge.cpp
/// @brief  Mode 2 — `ProxyCommand` bridge.
///
/// openssh launches this mode as a child process whenever the wrap
/// mode forwards a connection. The bridge owns a kernel handle for
/// the duration of the SSH session: it loads the operator identity,
/// dials the requested peer, waits for the Noise handshake to lift
/// the connection from `Untrusted` to `Peer`, then sits on a tight
/// stdin → kernel pipe with the kernel's inbound-handler trampoline
/// pumping bytes the other way (kernel → stdout).
///
/// Bytes flow:
///
/// @code
///                   stdin (openssh write)
///                      │
///                      ▼
///   ┌─────────────────────────────────────┐
///   │   read loop (this thread)           │
///   │   ::read(STDIN, buf, kBufBytes)     │
///   │   send(conn, kSshAppMsgId, buf)     │
///   └─────────────────────────────────────┘
///                      │
///                      ▼  (kernel send path)
///                 GoodNet conn
///                      ▲
///                      │  (kernel dispatch)
///   ┌─────────────────────────────────────┐
///   │   handler trampoline                │
///   │   ::write(STDOUT, payload, size)    │
///   └─────────────────────────────────────┘
///                      ▲
///                      │
///                stdout (openssh read)
/// @endcode
///
/// All logging strict to stderr — stdout is consumed verbatim by
/// openssh. A single fputs to stdout corrupts the SSH transport.

#include "modes.hpp"

#include "identity.hpp"
#include "peers.hpp"
#include "pipe.hpp"

#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <span>
#include <sstream>
#include <string>
#include <thread>
#include <unistd.h>
#include <vector>

#include <core/identity/node_identity.hpp>
#include <core/kernel/host_api_builder.hpp>
#include <core/kernel/kernel.hpp>
#include <core/kernel/plugin_context.hpp>
#include <core/plugin/plugin_manager.hpp>
#include <core/plugin/plugin_manifest.hpp>
#include <core/registry/extension.hpp>
#include <core/util/log.hpp>

#include <plugins/protocols/gnet/protocol.hpp>

#include <sdk/conn_events.h>
#include <sdk/extensions/link.h>
#include <sdk/handler.h>
#include <sdk/host_api.h>
#include <sdk/types.h>

namespace gn::apps::gssh {

namespace {

/// Plugin discovery: the bridge needs a link plugin (tcp / udp / ws /
/// ipc / tls) to dial the peer and a security plugin (noise) for the
/// handshake. The default search list mirrors the in-tree build
/// layout; production deployments install plugins under
/// `<prefix>/lib/` next to the binary.
[[nodiscard]] std::vector<std::string> default_plugin_paths() {
    namespace fs = std::filesystem;
    // Resolve relative to the executable so a portable install
    // (`<prefix>/bin/gssh` next to `<prefix>/lib/*.so`) works
    // without LD_LIBRARY_PATH gymnastics.
    std::error_code ec;
    auto exe = fs::read_symlink("/proc/self/exe", ec);
    fs::path bin_dir = ec ? fs::current_path() : exe.parent_path();
    fs::path prefix  = bin_dir.parent_path();

    std::vector<std::string> out;
    for (const auto* candidate : {
            "lib/libgoodnet_security_noise.so",
            "lib/libgoodnet_link_tcp.so",
            "plugins/libgoodnet_security_noise.so",
            "plugins/libgoodnet_link_tcp.so",
         }) {
        auto p = prefix / candidate;
        if (fs::exists(p, ec)) out.push_back(p.string());
    }
    return out;
}

/// Dispatch trampoline state. Owns the connection id the bridge
/// dialled and the stdout fd it writes to. The kernel hands every
/// inbound envelope into `handle_message` synchronously on the
/// dispatch thread.
struct BridgeHandler {
    gn_conn_id_t      target_conn = GN_INVALID_ID;
    int               stdout_fd   = STDOUT_FILENO;
    std::atomic<bool> stdout_broken{false};
};

/// One static msg-id list per process. The kernel queries this once
/// at registration; the storage outlives the registration so the
/// borrowed pointer the kernel keeps stays valid.
const std::uint32_t kBridgeMsgIds[] = {kSshAppMsgId};

const char* bridge_protocol_id(void*)             { return "gnet-v1"; }
void        bridge_supported_msg_ids(void*,
                                     const std::uint32_t** out_ids,
                                     std::size_t* out_count) {
    *out_ids   = kBridgeMsgIds;
    *out_count = sizeof(kBridgeMsgIds) / sizeof(kBridgeMsgIds[0]);
}

gn_propagation_t bridge_handle_message(void* self, const gn_message_t* env) {
    auto* h = static_cast<BridgeHandler*>(self);
    if (h == nullptr || env == nullptr) return GN_PROPAGATION_CONTINUE;
    if (env->conn_id != h->target_conn) return GN_PROPAGATION_CONTINUE;
    if (env->payload_size == 0) return GN_PROPAGATION_CONSUMED;

    const std::span<const std::uint8_t> bytes{env->payload, env->payload_size};
    if (write_all(h->stdout_fd, bytes) != 0) {
        h->stdout_broken.store(true, std::memory_order_release);
    }
    return GN_PROPAGATION_CONSUMED;
}

/// Build the static handler vtable once. Same shape as the
/// `bridges/cpp/handler.hpp` shared vtable; written here as plain
/// C ABI to keep the bridge's link surface minimal.
const gn_handler_vtable_t& bridge_handler_vtable() noexcept {
    static const gn_handler_vtable_t vt = []() {
        gn_handler_vtable_t v{};
        v.api_size          = sizeof(gn_handler_vtable_t);
        v.protocol_id       = &bridge_protocol_id;
        v.supported_msg_ids = &bridge_supported_msg_ids;
        v.handle_message    = &bridge_handle_message;
        return v;
    }();
    return vt;
}

/// Wrap plugin loading: the manager hashes each `.so`, refuses on
/// mismatch when a manifest is present, and walks the per-plugin
/// init/register sequence per `plugin-lifetime.md` §3. Empty list is
/// not an error here; the surrounding caller fails with a hint.
[[nodiscard]] gn_result_t load_bridge_plugins(gn::core::PluginManager& mgr) {
    auto paths = default_plugin_paths();
    if (paths.empty()) {
        (void)std::fputs(
            "gssh bridge: no plugins discovered next to the "
            "executable; bridge needs at least a link + security plugin\n",
            stderr);
        return GN_ERR_NOT_FOUND;
    }
    std::string diag;
    const auto rc = mgr.load(std::span<const std::string>(paths), &diag);
    if (rc != GN_OK) {
        (void)std::fprintf(stderr,
            "gssh bridge: plugin load failed — %s\n",
            diag.c_str());
    }
    return rc;
}

/// Connection-event subscriber state. Owned by the kernel for the
/// lifetime of the subscription; the destructor is invoked through
/// `ud_destroy` exactly once when the subscription drops.
struct ConnState {
    std::atomic<gn_conn_id_t>* dialed;
    std::atomic<bool>*         upgraded;
    std::atomic<bool>*         dropped;
};

void on_conn_event_cb(void* ud, const gn_conn_event_t* ev) {
    auto* s = static_cast<ConnState*>(ud);
    if (ev == nullptr || s == nullptr) return;
    switch (ev->kind) {
        case GN_CONN_EVENT_CONNECTED:
            s->dialed->store(ev->conn, std::memory_order_release);
            /// `TRUST_UPGRADED` only fires for the
            /// Untrusted → Peer transition driven by the
            /// attestation dispatcher; loopback / intra-node
            /// connections enter `notify_connect` already on a
            /// trust class above Untrusted, so the only signal
            /// the bridge ever sees is `CONNECTED` itself. Treat
            /// any non-Untrusted ready event as a green light to
            /// start piping.
            if (ev->trust != GN_TRUST_UNTRUSTED) {
                s->upgraded->store(true, std::memory_order_release);
            }
            break;
        case GN_CONN_EVENT_TRUST_UPGRADED:
            s->upgraded->store(true, std::memory_order_release);
            break;
        case GN_CONN_EVENT_DISCONNECTED:
            s->dropped->store(true, std::memory_order_release);
            break;
        default:
            break;
    }
}

void on_conn_event_destroy(void* ud) {
    delete static_cast<ConnState*>(ud);
}

}  // namespace

int run_bridge(std::string_view peer_pk_str, const Options& opts) {
    using gn::core::Kernel;
    using gn::core::PluginContext;
    using gn::core::PluginManager;
    using gn::core::build_host_api;
    using gn::plugins::gnet::GnetProtocol;

    // 1. Identity. Persistent operator keypair must be installed
    //    BEFORE the kernel's security pipeline sees a connection.
    Kernel kernel;
    kernel.set_protocol_layer(std::make_shared<GnetProtocol>());

    const std::string identity_path =
        opts.identity_path.empty() ? default_identity_path() : opts.identity_path;
    {
        std::string diag;
        if (const auto rc = install_identity_on_kernel(kernel, identity_path, diag);
            rc != GN_OK) {
            (void)std::fprintf(stderr,
                "gssh bridge: identity %s — %s\n",
                identity_path.c_str(), diag.c_str());
            if (rc == GN_ERR_NOT_FOUND) {
                (void)std::fprintf(stderr,
                    "gssh bridge: run 'goodnet identity gen --out %s'\n",
                    identity_path.c_str());
            }
            return 1;
        }
    }

    // 2. host_api host context for in-process use. The bridge's own
    //    handler registration goes through this surface.
    PluginContext host_ctx;
    host_ctx.plugin_name = "gssh-bridge";
    host_ctx.kernel      = &kernel;
    auto api             = build_host_api(host_ctx);

    // 3. Plugin loading. Without a noise plugin the bridge cannot
    //    complete a handshake; without a tcp / udp / ws / ipc plugin
    //    it cannot dial the peer in the first place.
    PluginManager plugins{kernel};
    if (const auto rc = load_bridge_plugins(plugins); rc != GN_OK) {
        return 1;
    }

    // 4. Resolve URI. `--uri` override wins; otherwise consult the
    //    catalogue.
    std::string uri;
    if (!opts.override_uri.empty()) {
        uri = opts.override_uri;
    } else {
        const std::string peers_path = default_peers_path();
        std::string diag;
        const auto peers = parse_peers(peers_path, diag);
        if (!diag.empty()) {
            (void)std::fprintf(stderr,
                "gssh bridge: %s — %s\n",
                peers_path.c_str(), diag.c_str());
        }
        auto found = resolve_peer_uri(peer_pk_str, peers);
        if (!found) {
            (void)std::fprintf(stderr,
                "gssh bridge: peer %.*s not in %s; add an "
                "entry or pass --uri\n",
                static_cast<int>(peer_pk_str.size()), peer_pk_str.data(),
                peers_path.c_str());
            return 1;
        }
        uri = std::move(*found);
    }

    // 5. Subscribe to connection events. Subscription must exist
    //    before `connect` so the CONNECTED event raised inside
    //    `connect`'s call stack does not fire on an empty subscriber
    //    list.
    std::atomic<gn_conn_id_t> dialed_conn{GN_INVALID_ID};
    std::atomic<bool>         trust_upgraded{false};
    std::atomic<bool>         disconnected{false};

    gn_subscription_id_t sub_id = GN_INVALID_SUBSCRIPTION_ID;
    {
        auto* state = new ConnState{&dialed_conn, &trust_upgraded, &disconnected};
        if (api.subscribe_conn_state(api.host_ctx,
                                     &on_conn_event_cb,
                                     state,
                                     &on_conn_event_destroy,
                                     &sub_id) != GN_OK) {
            delete state;
            (void)std::fputs(
                "gssh bridge: subscribe_conn_state failed\n", stderr);
            return 1;
        }
    }

    // 6. Kernel up. `advance_to(Running)` flips the FSM to the phase
    //    where inbound bytes flow through dispatch.
    (void)kernel.advance_to(gn::core::Phase::Running);

    // 7. Dial through the link's primary vtable. The L2 composition
    //    extension's `connect` slot returns GN_ERR_NOT_IMPLEMENTED
    //    by design (per `link.md` §8) — the actual dial path lives
    //    on the vtable the plugin registered into the kernel's link
    //    registry. Walk by scheme through `kernel.links()`.
    gn_conn_id_t conn_id = GN_INVALID_ID;
    {
        const auto scheme_end = uri.find("://");
        if (scheme_end == std::string::npos) {
            (void)std::fprintf(stderr,
                "gssh bridge: malformed URI '%s' "
                "(missing scheme://)\n",
                uri.c_str());
            return 1;
        }
        const std::string scheme = uri.substr(0, scheme_end);

        auto link_entry = kernel.links().find_by_scheme(scheme);
        if (!link_entry || !link_entry->vtable ||
            !link_entry->vtable->connect) {
            (void)std::fprintf(stderr,
                "gssh bridge: scheme '%s' has no registered link with "
                "a connect slot — check that the link plugin loaded\n",
                scheme.c_str());
            return 1;
        }
        /// The primary vtable's `connect` returns synchronously after
        /// dispatching the dial; the assigned `conn_id` arrives later
        /// via the `notify_connect` event the link plugin publishes
        /// once the kernel side accepts the connection. The
        /// `dialed_conn` atomic captured by the conn-state subscriber
        /// picks it up below.
        const auto rc = link_entry->vtable->connect(
            link_entry->self, uri.c_str());
        if (rc != GN_OK) {
            (void)std::fprintf(stderr,
                "gssh bridge: connect %s failed (rc=%d, %s)\n",
                uri.c_str(),
                static_cast<int>(rc),
                gn_strerror(rc));
            return 1;
        }
    }

    // 8. Trust-upgrade wait. The kernel publishes `CONNECTED` from
    //    `notify_connect` (link side) and `TRUST_UPGRADED` once the
    //    Noise handshake lifts the trust class. Until then the
    //    transport-phase send path is not yet open.
    const auto deadline = std::chrono::steady_clock::now() + kTrustTimeout;
    while (!trust_upgraded.load(std::memory_order_acquire) &&
           !disconnected.load(std::memory_order_acquire) &&
           std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds{20});
    }
    if (disconnected.load(std::memory_order_acquire)) {
        (void)std::fputs(
            "gssh bridge: peer disconnected before trust upgrade\n",
            stderr);
        return 1;
    }
    if (!trust_upgraded.load(std::memory_order_acquire)) {
        (void)std::fputs(
            "gssh bridge: trust upgrade timed out (15s)\n", stderr);
        return 1;
    }
    if (conn_id == GN_INVALID_ID) {
        // Fall back to the dialed_conn from the subscription if the
        // connect path returned `notify_connect`'s id through a
        // separate event (some link plugins land it asynchronously).
        conn_id = dialed_conn.load(std::memory_order_acquire);
    }
    if (conn_id == GN_INVALID_ID) {
        (void)std::fputs(
            "gssh bridge: no connection id observed\n", stderr);
        return 1;
    }

    // 9. Register the handler. The kernel routes inbound envelopes
    //    matching `kSshAppMsgId` through this trampoline.
    BridgeHandler h_state{};
    h_state.target_conn = conn_id;
    h_state.stdout_fd   = STDOUT_FILENO;

    gn_handler_id_t handler_id = GN_INVALID_HANDLER_ID;
    {
        gn_register_meta_t meta{};
        meta.api_size = sizeof(gn_register_meta_t);
        meta.name     = "gnet-v1";
        meta.msg_id   = kSshAppMsgId;
        meta.priority = 128;
        const auto rc = api.register_vtable(
            api.host_ctx, GN_REGISTER_HANDLER,
            &meta, &bridge_handler_vtable(), &h_state, &handler_id);
        if (rc != GN_OK) {
            (void)std::fputs(
                "gssh bridge: register_handler failed\n", stderr);
            return 1;
        }
    }

    // 10. stdin → kernel pump. Non-blocking so the loop polls the
    //     `disconnected` flag promptly and bails on peer drop. EOF on
    //     stdin is the operator's `^D` (or openssh closing the pipe
    //     on session end); we exit cleanly.
    if (make_fd_nonblocking(STDIN_FILENO) < 0) {
        (void)std::fprintf(stderr,
            "gssh bridge: fcntl(O_NONBLOCK) on stdin failed: %s\n",
            std::strerror(errno));
        (void)api.unregister_vtable(api.host_ctx, handler_id);
        return 1;
    }

    std::vector<std::uint8_t> buf(kPipeBufferBytes);
    while (!disconnected.load(std::memory_order_acquire) &&
           !h_state.stdout_broken.load(std::memory_order_acquire)) {
        const auto n = ::read(STDIN_FILENO, buf.data(), buf.size());
        if (n > 0) {
            const auto rc = api.send(api.host_ctx, conn_id, kSshAppMsgId,
                                      buf.data(), static_cast<std::size_t>(n));
            if (rc != GN_OK) {
                (void)std::fprintf(stderr,
                    "gssh bridge: send failed (rc=%d)\n",
                    static_cast<int>(rc));
                break;
            }
            continue;
        }
        if (n == 0) break;  // EOF on stdin
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            std::this_thread::sleep_for(std::chrono::milliseconds{1});
            continue;
        }
        (void)std::fprintf(stderr,
            "gssh bridge: stdin read error: %s\n",
            std::strerror(errno));
        break;
    }

    // 11. Tear down in the right order: handler first (the kernel
    //     stops dispatching past unregister), then plugin manager
    //     drains the live anchors, then kernel destructor releases
    //     registries.
    (void)api.unregister_vtable(api.host_ctx, handler_id);
    if (sub_id != GN_INVALID_SUBSCRIPTION_ID) {
        (void)api.unsubscribe(api.host_ctx, sub_id);
    }
    plugins.shutdown();
    return 0;
}

}  // namespace gn::apps::gssh
