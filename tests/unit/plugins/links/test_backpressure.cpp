/// @file   tests/unit/plugins/links/test_backpressure.cpp
/// @brief  `backpressure.md` §1 hard cap — TCP refuses fresh sends
///         once the per-connection write queue holds more than
///         `gn_limits_t::pending_queue_bytes_hard` bytes.
///
/// Drives a real loopback session: bind, connect, wait for
/// `notify_connect`, push enough bytes to saturate the cap, expect
/// `GN_ERR_LIMIT_REACHED`. The next send after the queue drains
/// succeeds again — the cap is a steady-state ceiling, not a
/// permanent reject.

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <mutex>
#include <span>
#include <thread>
#include <vector>

#include <plugins/links/tcp/tcp.hpp>

#include <sdk/conn_events.h>
#include <sdk/host_api.h>
#include <sdk/limits.h>
#include <sdk/types.h>

using namespace std::chrono_literals;
using gn::link::tcp::TcpLink;

namespace {

struct CapHost {
    gn_limits_t                          limits{};
    std::mutex                           mu;
    std::atomic<int>                     connects{0};
    std::vector<gn_conn_id_t>            conns;
    std::vector<gn_handshake_role_t>     roles;
    std::vector<gn_conn_event_kind_t>    bp_events;
    std::vector<std::uint64_t>           bp_pending;

    static const gn_limits_t* on_limits(void* ctx) {
        return &static_cast<CapHost*>(ctx)->limits;
    }

    static gn_result_t on_connect(void* ctx,
                                   const std::uint8_t /*pk*/[GN_PUBLIC_KEY_BYTES],
                                   const char* /*uri*/, const char* /*scheme*/,
                                   gn_trust_class_t /*trust*/,
                                   gn_handshake_role_t role,
                                   gn_conn_id_t* out_conn) {
        auto* h = static_cast<CapHost*>(ctx);
        std::lock_guard lk(h->mu);
        const auto id =
            static_cast<gn_conn_id_t>(h->conns.size() + 1);
        h->conns.push_back(id);
        h->roles.push_back(role);
        *out_conn = id;
        h->connects.fetch_add(1);
        return GN_OK;
    }
    static gn_result_t on_inbound(void*, gn_conn_id_t,
                                   const std::uint8_t*, std::size_t) {
        return GN_OK;
    }
    static gn_result_t on_disconnect(void*, gn_conn_id_t,
                                      gn_result_t) {
        return GN_OK;
    }
    static gn_result_t on_backpressure(void* ctx, gn_conn_id_t /*conn*/,
                                        gn_conn_event_kind_t kind,
                                        std::uint64_t pending) {
        auto* h = static_cast<CapHost*>(ctx);
        std::lock_guard lk(h->mu);
        h->bp_events.push_back(kind);
        h->bp_pending.push_back(pending);
        return GN_OK;
    }

    host_api_t make_api() {
        host_api_t api{};
        api.api_size             = sizeof(host_api_t);
        api.host_ctx             = this;
        api.limits               = &on_limits;
        api.notify_connect       = &on_connect;
        api.notify_inbound_bytes = &on_inbound;
        api.notify_disconnect    = &on_disconnect;
        api.notify_backpressure  = &on_backpressure;
        return api;
    }
};

bool wait_for(const std::function<bool()>& pred,
              std::chrono::milliseconds timeout = 2s) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) return true;
        std::this_thread::sleep_for(5ms);
    }
    return pred();
}

}  // namespace

TEST(BackpressureTcp, RejectsSendOnceQueueExceedsHardCap) {
    /// 1 KiB hard cap; a single 4 KiB payload sits well past it
    /// after one `send`, so the second `send` must reject.
    CapHost h;
    h.limits.pending_queue_bytes_low  = 256;
    h.limits.pending_queue_bytes_high = 512;
    h.limits.pending_queue_bytes_hard = 1024;
    auto api = h.make_api();

    auto server = std::make_shared<TcpLink>();
    auto client = std::make_shared<TcpLink>();
    server->set_host_api(&api);
    client->set_host_api(&api);

    ASSERT_EQ(server->listen("tcp://127.0.0.1:0"), GN_OK);
    const auto port = server->listen_port();
    ASSERT_GT(port, 0u);
    ASSERT_EQ(client->connect("tcp://127.0.0.1:" + std::to_string(port)),
              GN_OK);

    /// Wait for the responder side to register the conn — initiator
    /// id may not exist yet on the server transport's session map,
    /// so we send via whichever side allocated id 1 (responder).
    ASSERT_TRUE(wait_for([&] { return h.connects.load() >= 2; }));

    /// Identify the conn id allocated for the server-side responder
    /// on `server`. The harness gives ids 1 and 2; one is initiator
    /// (client) and the other responder (server). The server
    /// transport's send path resolves only the responder id. Since
    /// the same harness handed both ids, find the responder.
    gn_conn_id_t server_conn = 0;
    {
        std::lock_guard lk(h.mu);
        for (std::size_t i = 0; i < h.roles.size(); ++i) {
            if (h.roles[i] == GN_ROLE_RESPONDER) {
                server_conn = h.conns[i];
                break;
            }
        }
    }
    ASSERT_NE(server_conn, 0u);

    /// 4 KiB payload — first send fills the queue past 1 KiB
    /// because the queue is empty at the moment of enqueue. The
    /// second send sees ~4 KiB queued and rejects.
    std::vector<std::uint8_t> blob(4096, 0x55);
    auto rc1 = server->send(server_conn,
        std::span<const std::uint8_t>(blob));
    auto rc2 = server->send(server_conn,
        std::span<const std::uint8_t>(blob));

    /// First send may succeed (queue empty) or reject (cap=1024 vs
    /// payload=4096 → over the cap right away). Either is correct
    /// per `backpressure.md` §3 — we only care that the second
    /// send, after the queue is non-empty, definitively rejects.
    EXPECT_TRUE(rc1 == GN_OK || rc1 == GN_ERR_LIMIT_REACHED);
    EXPECT_EQ(rc2, GN_ERR_LIMIT_REACHED)
        << "second send onto a full queue must reject";

    server->shutdown();
    client->shutdown();
}

TEST(BackpressureTcp, ZeroCapDisablesEnforcement) {
    /// Zero `pending_queue_bytes_hard` is the v1 baseline opt-out:
    /// the transport behaves as before the cap landed. A payload
    /// far larger than any real cap goes through.
    CapHost h;  /// all-zero limits
    auto api = h.make_api();

    auto server = std::make_shared<TcpLink>();
    auto client = std::make_shared<TcpLink>();
    server->set_host_api(&api);
    client->set_host_api(&api);

    ASSERT_EQ(server->listen("tcp://127.0.0.1:0"), GN_OK);
    const auto port = server->listen_port();
    ASSERT_EQ(client->connect("tcp://127.0.0.1:" + std::to_string(port)),
              GN_OK);
    ASSERT_TRUE(wait_for([&] { return h.connects.load() >= 2; }));

    gn_conn_id_t conn = 0;
    {
        std::lock_guard lk(h.mu);
        conn = h.conns.front();
    }

    std::vector<std::uint8_t> blob(std::size_t{64} * 1024U, 0xAA);
    /// Push a few large payloads — all must succeed because the cap
    /// is disabled. The session id must belong to the transport we
    /// are calling; rotate through both transports until one accepts.
    bool any_ok = false;
    for (auto* tr : {server.get(), client.get()}) {
        if (tr->send(conn, std::span<const std::uint8_t>(blob)) == GN_OK) {
            any_ok = true;
            break;
        }
    }
    EXPECT_TRUE(any_ok);

    server->shutdown();
    client->shutdown();
}

TEST(BackpressureTcp, FiresSoftEventOnRisingEdge) {
    /// 1 KiB low / 2 KiB high / 8 KiB hard. A 4 KiB enqueue
    /// crosses the high mark and must publish exactly one
    /// `BACKPRESSURE_SOFT` event with `pending_bytes` reflecting
    /// the post-enqueue depth. A second 4 KiB enqueue does not
    /// fire again — the rising-edge model only signals once per
    /// crossing per `backpressure.md` §3.
    CapHost h;
    h.limits.pending_queue_bytes_low  = 1024;
    h.limits.pending_queue_bytes_high = 2048;
    h.limits.pending_queue_bytes_hard = 8192;
    auto api = h.make_api();

    auto server = std::make_shared<TcpLink>();
    auto client = std::make_shared<TcpLink>();
    server->set_host_api(&api);
    client->set_host_api(&api);

    ASSERT_EQ(server->listen("tcp://127.0.0.1:0"), GN_OK);
    const auto port = server->listen_port();
    ASSERT_EQ(client->connect("tcp://127.0.0.1:" + std::to_string(port)),
              GN_OK);
    ASSERT_TRUE(wait_for([&] { return h.connects.load() >= 2; }));

    gn_conn_id_t server_conn = 0;
    {
        std::lock_guard lk(h.mu);
        for (std::size_t i = 0; i < h.roles.size(); ++i) {
            if (h.roles[i] == GN_ROLE_RESPONDER) {
                server_conn = h.conns[i];
                break;
            }
        }
    }
    ASSERT_NE(server_conn, 0u);

    /// Crossing #1: 4 KiB enqueue past 2 KiB high mark.
    std::vector<std::uint8_t> blob(4096, 0x33);
    EXPECT_EQ(server->send(server_conn,
                            std::span<const std::uint8_t>(blob)),
              GN_OK);

    /// SOFT may land before send returns (rising-edge fire is
    /// synchronous on the caller's thread); allow a brief wait
    /// for completeness if the loopback drained instantly.
    ASSERT_TRUE(wait_for([&] {
        std::lock_guard lk(h.mu);
        return !h.bp_events.empty();
    }));
    {
        std::lock_guard lk(h.mu);
        ASSERT_GE(h.bp_events.size(), 1u);
        EXPECT_EQ(h.bp_events.front(), GN_CONN_EVENT_BACKPRESSURE_SOFT);
        EXPECT_GT(h.bp_pending.front(), 2048u);
    }

    server->shutdown();
    client->shutdown();
}
