// SPDX-License-Identifier: Apache-2.0
/// @file   tests/integration/test_link_teardown_conformance.cpp
/// @brief  Cross-transport conformance for `link.md` §9 shutdown.
///
/// `link.md` §9 promises that every link plugin's `shutdown()`
/// fires `host_api->notify_disconnect` synchronously on the
/// caller's thread for every session that was published through
/// `notify_connect`. The four stream-class plugins (TCP, WS, IPC,
/// TLS) each carry an in-tree unit test pinning that invariant
/// against their own session model; this typed-fixture pins it
/// against a single shared shape so a future link plugin lands
/// against the same gate.
///
/// UDP is intentionally excluded: it is datagram-class with no
/// in-band close signal, and `tests/unit/plugins/links/test_udp.cpp::
/// UdpLink.ShutdownNotifiesAllPeers` already pins the same
/// release discipline against the per-peer registry. The
/// conformance suite stays focused on the four transports that
/// share the snapshot-and-notify implementation shape.

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <concepts>
#include <cstdio>
#include <filesystem>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <unistd.h>

#include <plugins/links/ipc/ipc.hpp>
#include <plugins/links/tcp/tcp.hpp>
#include <plugins/links/tls/tls.hpp>
#include <plugins/links/ws/ws.hpp>

#include <tests/support/test_self_signed_cert.hpp>

#include <sdk/host_api.h>
#include <sdk/trust.h>
#include <sdk/types.h>

namespace {

using namespace std::chrono_literals;

/// Host stub shared across every typed-fixture instantiation.
/// `main_tid` is set by the test before any async work starts; the
/// disconnect callback only increments `on_main_disconnects` when
/// the call lands on that thread, which lets the post-fix `link.md`
/// §9 invariant be checked without racing the worker thread.
struct ConformanceHost {
    std::mutex                  mu;
    std::vector<gn_conn_id_t>   connects;
    std::atomic<int>            disconnects{0};
    std::thread::id             main_tid{};
    std::atomic<int>            on_main_disconnects{0};
    std::atomic<gn_conn_id_t>   next_id{1};

    static gn_result_t s_notify_connect(void* host_ctx,
                                         const std::uint8_t* /*remote_pk*/,
                                         const char* /*uri*/,
                                         gn_trust_class_t /*trust*/,
                                         gn_handshake_role_t /*role*/,
                                         gn_conn_id_t* out_conn) {
        auto* h = static_cast<ConformanceHost*>(host_ctx);
        const auto id = h->next_id.fetch_add(1);
        {
            std::lock_guard lk(h->mu);
            h->connects.push_back(id);
        }
        *out_conn = id;
        return GN_OK;
    }

    static gn_result_t s_notify_inbound(void*, gn_conn_id_t,
                                         const std::uint8_t*, std::size_t) {
        return GN_OK;
    }

    static gn_result_t s_notify_disconnect(void* host_ctx, gn_conn_id_t,
                                            gn_result_t) {
        auto* h = static_cast<ConformanceHost*>(host_ctx);
        h->disconnects.fetch_add(1);
        if (h->main_tid != std::thread::id{} &&
            std::this_thread::get_id() == h->main_tid) {
            h->on_main_disconnects.fetch_add(1);
        }
        return GN_OK;
    }

    static gn_result_t s_kick(void*, gn_conn_id_t) { return GN_OK; }

    host_api_t make_api() {
        host_api_t api{};
        api.api_size              = sizeof(host_api_t);
        api.host_ctx              = this;
        api.notify_connect        = &s_notify_connect;
        api.notify_inbound_bytes  = &s_notify_inbound;
        api.notify_disconnect     = &s_notify_disconnect;
        api.kick_handshake        = &s_kick;
        return api;
    }
};

/// Compile-time interface gate: any type that wants to participate
/// in the conformance suite has to expose the four entry points the
/// fixture exercises. Catches a future plugin that drops `listen()`
/// or renames `shutdown()` at the type level rather than at link
/// time. `listen_port()` is intentionally excluded — IPC binds a
/// path, not a port — and consumed through the trait specialisation
/// below.
template <class T>
concept LinkPlugin = requires(T t, std::string_view uri,
                              const host_api_t* api) {
    { t.listen(uri) } -> std::same_as<gn_result_t>;
    { t.connect(uri) } -> std::same_as<gn_result_t>;
    { t.shutdown() } -> std::same_as<void>;
    { t.set_host_api(api) } -> std::same_as<void>;
};

/// Per-transport configuration. Specialise to teach the conformance
/// suite how to construct, listen, connect, and (when applicable)
/// wire credentials onto a pair of links.
template <class L>
struct LinkTraits;

template <>
struct LinkTraits<gn::link::tcp::TcpLink> {
    static constexpr const char* scheme = "tcp";
    static std::shared_ptr<gn::link::tcp::TcpLink> make() {
        return std::make_shared<gn::link::tcp::TcpLink>();
    }
    static std::string listen_uri() { return "tcp://127.0.0.1:0"; }
    static std::string connect_uri(std::uint16_t port) {
        return "tcp://127.0.0.1:" + std::to_string(port);
    }
    static bool wire_credentials(gn::link::tcp::TcpLink&,
                                  gn::link::tcp::TcpLink&) {
        return true;
    }
};

template <>
struct LinkTraits<gn::link::ws::WsLink> {
    static constexpr const char* scheme = "ws";
    static std::shared_ptr<gn::link::ws::WsLink> make() {
        return std::make_shared<gn::link::ws::WsLink>();
    }
    static std::string listen_uri() { return "ws://127.0.0.1:0/"; }
    static std::string connect_uri(std::uint16_t port) {
        return "ws://127.0.0.1:" + std::to_string(port) + "/";
    }
    static bool wire_credentials(gn::link::ws::WsLink&,
                                  gn::link::ws::WsLink&) {
        return true;
    }
};

template <>
struct LinkTraits<gn::link::ipc::IpcLink> {
    static constexpr const char* scheme = "ipc";
    /// Per-process, per-test socket path. `getpid()` keeps it
    /// unique against parallel ctest runs in the same checkout.
    static std::string socket_path() {
        char buf[128];
        (void)std::snprintf(buf, sizeof(buf),
            "/tmp/goodnet_conformance_%d_%ld.sock",
            ::getpid(),
            static_cast<long>(
                std::chrono::steady_clock::now()
                    .time_since_epoch().count()));
        return buf;
    }
    static std::string& shared_path() {
        static thread_local std::string path = socket_path();
        return path;
    }
    static std::shared_ptr<gn::link::ipc::IpcLink> make() {
        return std::make_shared<gn::link::ipc::IpcLink>();
    }
    static std::string listen_uri() {
        /// Refresh the path on every fixture instantiation so a
        /// repeat run never collides with a leftover socket inode.
        shared_path() = socket_path();
        std::filesystem::remove(shared_path());
        return "ipc://" + shared_path();
    }
    static std::string connect_uri(std::uint16_t /*port*/) {
        return "ipc://" + shared_path();
    }
    static bool wire_credentials(gn::link::ipc::IpcLink&,
                                  gn::link::ipc::IpcLink&) {
        return true;
    }
};

template <>
struct LinkTraits<gn::link::tls::TlsLink> {
    static constexpr const char* scheme = "tls";
    static std::shared_ptr<gn::link::tls::TlsLink> make() {
        return std::make_shared<gn::link::tls::TlsLink>();
    }
    static std::string listen_uri() { return "tls://127.0.0.1:0"; }
    static std::string connect_uri(std::uint16_t port) {
        return "tls://127.0.0.1:" + std::to_string(port);
    }
    /// Self-signed loopback cert; client opts out of peer-cert
    /// verification — same shape as the TLS unit test, matching the
    /// production "TLS as link encryption beneath Noise" path.
    static bool wire_credentials(gn::link::tls::TlsLink& server,
                                  gn::link::tls::TlsLink& client) {
        std::string cert, key;
        if (!gn::tests::support::generate_self_signed(cert, key)) {
            return false;
        }
        server.set_server_credentials(cert, key);
        client.set_verify_peer(false);
        return true;
    }
};

bool wait_for(auto&& predicate,
              std::chrono::milliseconds timeout = 5s) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (predicate()) return true;
        std::this_thread::sleep_for(5ms);
    }
    return predicate();
}

template <LinkPlugin L>
class LinkTeardownConformance : public ::testing::Test {};

using ConformedLinks = ::testing::Types<
    gn::link::tcp::TcpLink,
    gn::link::ws::WsLink,
    gn::link::ipc::IpcLink,
    gn::link::tls::TlsLink>;

/// `gtest` requires the `*_P` macros for typed parameter expansion;
/// the trailing class-name suffix in `TYPED_TEST_SUITE` is the
/// conventional "what is being parameterised" tag.
TYPED_TEST_SUITE(LinkTeardownConformance, ConformedLinks);

TYPED_TEST(LinkTeardownConformance, ShutdownReleasesEverySession) {
    using Link   = TypeParam;
    using Traits = LinkTraits<Link>;

    ConformanceHost host;
    host.main_tid = std::this_thread::get_id();
    auto api = host.make_api();

    auto server = Traits::make();
    auto client = Traits::make();
    server->set_host_api(&api);
    client->set_host_api(&api);
    ASSERT_TRUE(Traits::wire_credentials(*server, *client))
        << "scheme=" << Traits::scheme
        << ": credential setup failed before listen";

    ASSERT_EQ(server->listen(Traits::listen_uri()), GN_OK)
        << "scheme=" << Traits::scheme << ": listen rejected";
    /// IPC binds a path; the three TCP-backed plugins bind a
    /// kernel-allocated port that must surface non-zero before
    /// a client can dial. The trait helper builds the connect
    /// URI either way.
    std::uint16_t port = 0;
    if constexpr (requires { server->listen_port(); }) {
        port = server->listen_port();
        if (std::string_view{Traits::scheme} != "ipc") {
            ASSERT_GT(port, 0u)
                << "scheme=" << Traits::scheme
                << ": listen did not bind";
        }
    }

    ASSERT_EQ(client->connect(Traits::connect_uri(port)), GN_OK)
        << "scheme=" << Traits::scheme << ": connect rejected";

    ASSERT_TRUE(wait_for([&] {
        std::lock_guard lk(host.mu);
        return host.connects.size() >= 2;
    })) << "scheme=" << Traits::scheme
        << ": both notify_connect did not arrive within timeout";

    int connects = 0;
    {
        std::lock_guard lk(host.mu);
        connects = static_cast<int>(host.connects.size());
    }
    EXPECT_EQ(host.disconnects.load(), 0)
        << "scheme=" << Traits::scheme
        << ": disconnect fired before shutdown";
    EXPECT_EQ(host.on_main_disconnects.load(), 0);

    client->shutdown();
    server->shutdown();

    /// Caller-thread pin: pre-fix the worker thread sometimes
    /// won the race to an EOF-driven async notify before
    /// `ioc_.stop()` returned and sometimes did not — a count-
    /// only assert was flaky on a fast host. Post-fix the
    /// shutdown call walks the live snapshot and fires
    /// `notify_disconnect` itself, so the caller thread always
    /// sees one disconnect per `notify_connect` it observed.
    EXPECT_EQ(host.on_main_disconnects.load(), connects)
        << "scheme=" << Traits::scheme
        << ": shutdown() must fire notify_disconnect "
           "synchronously on the caller thread for every session "
           "published through notify_connect (link.md §9 step 3).";
}

}  // namespace
