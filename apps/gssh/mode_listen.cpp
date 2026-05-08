/// @file   apps/gssh/mode_listen.cpp
/// @brief  Mode 3 — server-side forwarder.
///
/// `gssh --listen` runs as a long-lived daemon: it brings up
/// a kernel that listens on a GoodNet URI (default
/// `tcp://0.0.0.0:9001`), waits for inbound peers to complete a
/// Noise handshake, and on each inbound connection opens a local
/// TCP socket to the target (default `localhost:22`). Bytes
/// forwarded both ways: `<-` peer → kernel → handler trampoline →
/// upstream; `->` upstream → reader thread → kernel send → peer.
///
/// One upstream TCP socket per inbound connection. The first inbound
/// envelope on `kSshAppMsgId` for a fresh conn id triggers the
/// upstream open; the per-conn `UpstreamTcp` instance owns a reader
/// thread that pumps the local socket's bytes back to the peer.
/// Disconnect is symmetric: a peer drop tears down the upstream;
/// an upstream EOF closes the kernel-side connection.
///
/// systemd integration: this mode is intended to run as a service
/// unit. The exit on SIGTERM/SIGINT is graceful — the kernel walks
/// PreShutdown → Shutdown, every live conn publishes DISCONNECTED,
/// upstream sockets close cleanly. A `Restart=on-failure` directive
/// in the unit file rerolls the daemon if it crashes.

#include "modes.hpp"

#include "identity.hpp"
#include "pipe.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <memory>
#include <mutex>
#include <netdb.h>
#include <netinet/in.h>
#include <span>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <unordered_map>
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

/// SIGTERM / SIGINT marker. The signal handler bumps it to a
/// non-zero value so the main loop falls out of its idle wait.
std::atomic<int> g_quit_signal{0};

extern "C" void listen_signal_handler(int sig) noexcept {
    int expected = 0;
    (void)g_quit_signal.compare_exchange_strong(expected, sig);
}

[[nodiscard]] std::vector<std::string> default_plugin_paths() {
    namespace fs = std::filesystem;
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

/// Resolve @p host : @p port through `getaddrinfo` and connect a
/// blocking TCP socket. Returns -1 on failure with errno set;
/// `host = "localhost"` is honoured by the resolver as 127.0.0.1
/// or ::1 depending on the system's `/etc/hosts`.
[[nodiscard]] int connect_tcp(const std::string& host, std::uint16_t port) {
    addrinfo hints{};
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    char port_buf[16];
    (void)std::snprintf(port_buf, sizeof(port_buf), "%u",
                        static_cast<unsigned>(port));

    addrinfo* res = nullptr;
    if (::getaddrinfo(host.c_str(), port_buf, &hints, &res) != 0 ||
        res == nullptr) {
        return -1;
    }

    int fd = -1;
    for (auto* p = res; p != nullptr; p = p->ai_next) {
        fd = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) continue;
        if (::connect(fd, p->ai_addr, p->ai_addrlen) == 0) break;
        ::close(fd);
        fd = -1;
    }
    ::freeaddrinfo(res);
    return fd;
}

/// Per-connection upstream TCP socket plus its reader thread. The
/// reader pumps bytes from the local socket into `host_api->send`;
/// the kernel-side handler trampoline pumps the other direction
/// directly into the socket fd via `write_all`.
class UpstreamTcp {
public:
    UpstreamTcp(host_api_t api, gn_conn_id_t conn,
                std::string host, std::uint16_t port)
        : api_(api),
          conn_(conn),
          host_(std::move(host)),
          port_(port) {}

    ~UpstreamTcp() { close(); }

    UpstreamTcp(const UpstreamTcp&)            = delete;
    UpstreamTcp& operator=(const UpstreamTcp&) = delete;

    /// Open the TCP socket and spawn the reader thread. Returns true
    /// on success, false on `connect_tcp` failure (errno set by the
    /// underlying call).
    [[nodiscard]] bool open() {
        fd_ = connect_tcp(host_, port_);
        if (fd_ < 0) return false;

        running_.store(true, std::memory_order_release);
        reader_ = std::thread([this] { reader_loop(); });
        return true;
    }

    /// Synchronously write @p bytes to the local socket. Called from
    /// the kernel's dispatch thread; blocks past partial writes.
    void write(std::span<const std::uint8_t> bytes) noexcept {
        if (fd_ < 0) return;
        if (write_all(fd_, bytes) != 0) {
            // Local socket dead — close down the upstream and let
            // the kernel-side disconnect propagate.
            close();
        }
    }

    /// Tear down the socket and join the reader thread. Idempotent.
    void close() noexcept {
        const int prev = fd_.exchange(-1);
        if (prev >= 0) ::close(prev);

        running_.store(false, std::memory_order_release);
        if (reader_.joinable() &&
            std::this_thread::get_id() != reader_.get_id()) {
            reader_.join();
        }
    }

private:
    void reader_loop() noexcept {
        std::vector<std::uint8_t> buf(kPipeBufferBytes);
        while (running_.load(std::memory_order_acquire)) {
            const int fd = fd_.load(std::memory_order_acquire);
            if (fd < 0) break;
            const auto n = ::read(fd, buf.data(), buf.size());
            if (n > 0) {
                (void)api_.send(api_.host_ctx, conn_, kSshAppMsgId,
                                 buf.data(), static_cast<std::size_t>(n));
                continue;
            }
            if (n == 0) break;  // upstream EOF
            if (errno == EINTR) continue;
            break;
        }
        // Upstream closed: tear down the kernel-side conn so the
        // peer sees DISCONNECTED.
        (void)api_.disconnect(api_.host_ctx, conn_);
        running_.store(false, std::memory_order_release);
    }

    host_api_t              api_;
    gn_conn_id_t            conn_;
    std::string             host_;
    std::uint16_t           port_;
    std::atomic<int>        fd_{-1};
    std::atomic<bool>       running_{false};
    std::thread             reader_;
};

/// One static msg-id list per process. The kernel keeps the borrowed
/// pointer alive past return; the storage outlives every
/// registration.
const std::uint32_t kListenMsgIds[] = {kSshAppMsgId};

const char* listen_protocol_id(void*)             { return "gnet-v1"; }
void        listen_supported_msg_ids(void*,
                                     const std::uint32_t** out_ids,
                                     std::size_t* out_count) {
    *out_ids   = kListenMsgIds;
    *out_count = sizeof(kListenMsgIds) / sizeof(kListenMsgIds[0]);
}

/// Per-process registry of live upstream sockets keyed on the
/// kernel's `gn_conn_id_t`. The handler trampoline + the
/// connection-event subscriber both reach into it.
struct SessionMap {
    std::mutex                                                    mu;
    std::unordered_map<gn_conn_id_t, std::unique_ptr<UpstreamTcp>> map;
};

struct ListenContext {
    SessionMap*    sessions;
    host_api_t     api;
    std::string    target_host;
    std::uint16_t  target_port;
};

gn_propagation_t listen_handle_message(void* self, const gn_message_t* env) {
    auto* ctx = static_cast<ListenContext*>(self);
    if (ctx == nullptr || env == nullptr) return GN_PROPAGATION_CONTINUE;

    UpstreamTcp* up = nullptr;
    {
        std::lock_guard lk(ctx->sessions->mu);
        if (auto it = ctx->sessions->map.find(env->conn_id);
            it != ctx->sessions->map.end()) {
            up = it->second.get();
        } else {
            // Lazy upstream open on the first inbound byte. The
            // remote side cannot send before its handshake completes
            // (the kernel rejects pre-transport sends), so the first
            // arriving envelope already implies the trust upgrade.
            auto fresh = std::make_unique<UpstreamTcp>(
                ctx->api, env->conn_id,
                ctx->target_host, ctx->target_port);
            if (!fresh->open()) {
                (void)std::fprintf(stderr,
                    "gssh listen: upstream %s:%u open failed: %s\n",
                    ctx->target_host.c_str(),
                    static_cast<unsigned>(ctx->target_port),
                    std::strerror(errno));
                (void)ctx->api.disconnect(ctx->api.host_ctx, env->conn_id);
                return GN_PROPAGATION_CONSUMED;
            }
            up = fresh.get();
            ctx->sessions->map.emplace(env->conn_id, std::move(fresh));
        }
    }

    if (env->payload_size > 0 && up != nullptr) {
        up->write(std::span<const std::uint8_t>(env->payload,
                                                  env->payload_size));
    }
    return GN_PROPAGATION_CONSUMED;
}

const gn_handler_vtable_t& listen_handler_vtable() noexcept {
    static const gn_handler_vtable_t vt = []() {
        gn_handler_vtable_t v{};
        v.api_size          = sizeof(gn_handler_vtable_t);
        v.protocol_id       = &listen_protocol_id;
        v.supported_msg_ids = &listen_supported_msg_ids;
        v.handle_message    = &listen_handle_message;
        return v;
    }();
    return vt;
}

void on_listen_conn_event(void* ud, const gn_conn_event_t* ev) {
    auto* sessions = static_cast<SessionMap*>(ud);
    if (ev == nullptr || sessions == nullptr) return;
    if (ev->kind != GN_CONN_EVENT_DISCONNECTED) return;

    std::unique_ptr<UpstreamTcp> dead;
    {
        std::lock_guard lk(sessions->mu);
        if (auto it = sessions->map.find(ev->conn);
            it != sessions->map.end()) {
            dead = std::move(it->second);
            sessions->map.erase(it);
        }
    }
    // `dead` destructor runs outside the lock so a slow upstream
    // teardown does not stall the kernel's dispatch thread.
}

void on_listen_conn_event_destroy(void*) {
    // The session map outlives the subscription — it lives in the
    // listen-mode stack frame. Nothing to free here.
}

[[nodiscard]] gn_result_t load_listen_plugins(gn::core::PluginManager& mgr) {
    auto paths = default_plugin_paths();
    if (paths.empty()) {
        (void)std::fputs(
            "gssh listen: no plugins discovered next to the "
            "executable; daemon needs at least a link + security plugin\n",
            stderr);
        return GN_ERR_NOT_FOUND;
    }
    std::string diag;
    const auto rc = mgr.load(std::span<const std::string>(paths), &diag);
    if (rc != GN_OK) {
        (void)std::fprintf(stderr,
            "gssh listen: plugin load failed — %s\n",
            diag.c_str());
    }
    return rc;
}

}  // namespace

int run_listen(const ListenOptions& opts) {
    using gn::core::Kernel;
    using gn::core::PluginContext;
    using gn::core::PluginManager;
    using gn::core::build_host_api;
    using gn::plugins::gnet::GnetProtocol;

    // 1. Identity. Persistent operator keypair before any peer
    //    handshake.
    Kernel kernel;
    {
        gn::core::protocol_layer_id_t proto_id =
            gn::core::kInvalidProtocolLayerId;
        (void)kernel.protocol_layers().register_layer(
            std::make_shared<GnetProtocol>(), &proto_id);
    }

    const std::string identity_path =
        opts.common.identity_path.empty()
            ? default_identity_path()
            : opts.common.identity_path;
    {
        std::string diag;
        if (const auto rc = install_identity_on_kernel(kernel, identity_path, diag);
            rc != GN_OK) {
            (void)std::fprintf(stderr,
                "gssh listen: identity %s — %s\n",
                identity_path.c_str(), diag.c_str());
            if (rc == GN_ERR_NOT_FOUND) {
                (void)std::fprintf(stderr,
                    "gssh listen: run 'goodnet identity gen --out %s'\n",
                    identity_path.c_str());
            }
            return 1;
        }
    }

    // 2. host_api host context for the listen-side handler.
    PluginContext host_ctx;
    host_ctx.plugin_name = "gssh-listen";
    host_ctx.kernel      = &kernel;
    auto api             = build_host_api(host_ctx);

    // 3. Load link + security plugins.
    PluginManager plugins{kernel};
    if (const auto rc = load_listen_plugins(plugins); rc != GN_OK) {
        return 1;
    }

    // 4. Per-conn upstream registry. Owned by this stack frame; the
    //    handler trampoline holds a borrowed pointer.
    SessionMap sessions;
    ListenContext lctx{
        .sessions    = &sessions,
        .api         = api,
        .target_host = opts.target_host,
        .target_port = opts.target_port,
    };

    // 5. Subscribe BEFORE listen so the very first inbound conn's
    //    DISCONNECTED is observed.
    gn_subscription_id_t sub_id = GN_INVALID_SUBSCRIPTION_ID;
    if (api.subscribe_conn_state(api.host_ctx,
                                 &on_listen_conn_event,
                                 &sessions,
                                 &on_listen_conn_event_destroy,
                                 &sub_id) != GN_OK) {
        (void)std::fputs(
            "gssh listen: subscribe_conn_state failed\n", stderr);
        return 1;
    }

    // 6. Register the inbound handler. Each envelope on `kSshAppMsgId`
    //    routes through `listen_handle_message`; the trampoline
    //    finds (or lazily opens) the per-conn upstream socket.
    gn_handler_id_t handler_id = GN_INVALID_HANDLER_ID;
    {
        gn_register_meta_t meta{};
        meta.api_size = sizeof(gn_register_meta_t);
        meta.name     = "gnet-v1";
        meta.msg_id   = kSshAppMsgId;
        meta.priority = 128;
        if (api.register_vtable(api.host_ctx, GN_REGISTER_HANDLER,
                                &meta, &listen_handler_vtable(), &lctx,
                                &handler_id) != GN_OK) {
            (void)std::fputs(
                "gssh listen: register_handler failed\n", stderr);
            (void)api.unsubscribe(api.host_ctx, sub_id);
            return 1;
        }
    }

    // 7. Bring the kernel to Running, then ask the link extension
    //    for its `listen` slot.
    (void)kernel.advance_to(gn::core::Phase::Running);

    {
        const auto& uri = opts.listen_uri;
        const auto scheme_end = uri.find("://");
        if (scheme_end == std::string::npos) {
            (void)std::fprintf(stderr,
                "gssh listen: malformed listen URI '%s' "
                "(missing scheme://)\n",
                uri.c_str());
            (void)api.unregister_vtable(api.host_ctx, handler_id);
            (void)api.unsubscribe(api.host_ctx, sub_id);
            return 1;
        }
        const std::string scheme = uri.substr(0, scheme_end);

        /// Listen lives on the link's primary vtable, not on the L2
        /// composition extension. The extension's `listen` slot is
        /// reserved for composer plugins and returns
        /// GN_ERR_NOT_IMPLEMENTED by design (per `link.md` §8). Walk
        /// the kernel's link registry by scheme to reach the actual
        /// vtable the loaded plugin registered.
        auto link_entry = kernel.links().find_by_scheme(scheme);
        if (!link_entry || !link_entry->vtable ||
            !link_entry->vtable->listen) {
            (void)std::fprintf(stderr,
                "gssh listen: scheme '%s' has no registered link with "
                "a listen slot — check that the link plugin loaded\n",
                scheme.c_str());
            (void)api.unregister_vtable(api.host_ctx, handler_id);
            (void)api.unsubscribe(api.host_ctx, sub_id);
            return 1;
        }
        const auto listen_rc = link_entry->vtable->listen(
            link_entry->self, uri.c_str());
        if (listen_rc != GN_OK) {
            (void)std::fprintf(stderr,
                "gssh listen: listen on %s failed (rc=%d, %s)\n",
                uri.c_str(),
                static_cast<int>(listen_rc),
                gn_strerror(listen_rc));
            (void)api.unregister_vtable(api.host_ctx, handler_id);
            (void)api.unsubscribe(api.host_ctx, sub_id);
            return 1;
        }
    }

    // 8. Install signal handlers AFTER the listen socket is up — a
    //    SIGTERM during plugin load should kill the process
    //    immediately rather than walk a half-loaded shutdown path.
    (void)std::signal(SIGINT,  &listen_signal_handler);
    (void)std::signal(SIGTERM, &listen_signal_handler);

    (void)std::fprintf(stderr,
        "gssh listen: ready on %s, forwarding to %s:%u\n",
        opts.listen_uri.c_str(),
        opts.target_host.c_str(),
        static_cast<unsigned>(opts.target_port));

    // 9. Idle loop. The kernel's dispatch and timer threads do all
    //    the work; this thread just waits for the quit signal.
    while (g_quit_signal.load(std::memory_order_acquire) == 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds{100});
    }

    (void)std::fprintf(stderr,
        "gssh listen: signal %d received, draining\n",
        g_quit_signal.load(std::memory_order_acquire));

    // 10. Tear down: unregister the handler so no further dispatch
    //     fires on a draining session map, drop every live upstream,
    //     drain plugins.
    (void)api.unregister_vtable(api.host_ctx, handler_id);
    (void)api.unsubscribe(api.host_ctx, sub_id);
    {
        std::lock_guard lk(sessions.mu);
        sessions.map.clear();  // dtor closes each upstream
    }
    plugins.shutdown();
    return 0;
}

}  // namespace gn::apps::gssh
