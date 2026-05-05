// SPDX-License-Identifier: MIT
/// @file   plugins/links/ipc/tests/test_ipc.cpp
/// @brief  IpcLink — listen+connect on a per-PID socket path,
///         payload round-trip, socket-file cleanup on shutdown.

#include <gtest/gtest.h>

#include <plugins/links/ipc/ipc.hpp>

#include <sdk/host_api.h>
#include <sdk/trust.h>
#include <sdk/types.h>

#include <sys/stat.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <functional>
#include <mutex>
#include <span>
#include <string>
#include <thread>
#include <vector>

namespace {

using namespace std::chrono_literals;
using gn::link::ipc::IpcLink;

struct StubHost {
    std::atomic<int>                         connects{0};
    std::atomic<int>                         disconnects{0};
    std::atomic<int>                         inbound_calls{0};
    std::mutex                               mu;
    std::vector<gn_conn_id_t>                conns;
    std::vector<gn_handshake_role_t>         roles;
    std::vector<gn_trust_class_t>            trusts;
    std::vector<std::vector<std::uint8_t>>   inbound;
    std::vector<gn_conn_id_t>                inbound_owners;
    std::atomic<gn_conn_id_t>                next_id{1};

    /// Pinned caller thread for `link.md` §9 regression: shutdown
    /// must fire `notify_disconnect` on the caller's thread, not
    /// through an async strand-bound continuation (which would
    /// drop on `ioc_.stop()`). The pre-fix race in IPC sometimes
    /// wins on the worker thread before the io_context tears
    /// down, so a count-only check is flaky; the thread-id check
    /// is deterministic.
    std::thread::id                          main_tid{};
    std::atomic<int>                         on_main_disconnects{0};

    static gn_result_t on_connect(void* host_ctx,
                                   const std::uint8_t /*remote_pk*/[GN_PUBLIC_KEY_BYTES],
                                   const char* /*uri*/,
                                   gn_trust_class_t trust,
                                   gn_handshake_role_t role,
                                   gn_conn_id_t* out_conn) {
        auto* h = static_cast<StubHost*>(host_ctx);
        const auto id = h->next_id.fetch_add(1);
        {
            std::lock_guard lk(h->mu);
            h->conns.push_back(id);
            h->roles.push_back(role);
            h->trusts.push_back(trust);
        }
        *out_conn = id;
        h->connects.fetch_add(1);
        return GN_OK;
    }

    static gn_result_t on_inbound(void* host_ctx, gn_conn_id_t conn,
                                   const std::uint8_t* bytes, std::size_t size) {
        auto* h = static_cast<StubHost*>(host_ctx);
        std::lock_guard lk(h->mu);
        h->inbound.emplace_back(bytes, bytes + size);
        h->inbound_owners.push_back(conn);
        h->inbound_calls.fetch_add(1);
        return GN_OK;
    }

    static gn_result_t on_disconnect(void* host_ctx, gn_conn_id_t /*conn*/,
                                      gn_result_t /*reason*/) {
        auto* h = static_cast<StubHost*>(host_ctx);
        h->disconnects.fetch_add(1);
        if (h->main_tid != std::thread::id{} &&
            std::this_thread::get_id() == h->main_tid) {
            h->on_main_disconnects.fetch_add(1);
        }
        return GN_OK;
    }
};

host_api_t make_stub_api(StubHost& h) {
    host_api_t api{};
    api.api_size              = sizeof(host_api_t);
    api.host_ctx              = &h;
    api.notify_connect        = &StubHost::on_connect;
    api.notify_inbound_bytes  = &StubHost::on_inbound;
    api.notify_disconnect     = &StubHost::on_disconnect;
    return api;
}

void wait_for(const std::function<bool()>& pred,
              std::chrono::milliseconds timeout,
              const char* what) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) return;
        std::this_thread::sleep_for(5ms);
    }
    FAIL() << "timeout waiting for: " << what;
}

/// Per-test socket path. PID + test fixture pointer keeps it unique
/// across parallel ctest runs.
std::string make_socket_path() {
    char buf[128];
    (void)std::snprintf(buf, sizeof(buf),
                        "/tmp/goodnet_ipc_test_%d_%ld.sock",
                        ::getpid(),
                        static_cast<long>(std::chrono::steady_clock::now()
                                           .time_since_epoch().count()));
    return buf;
}

}  // namespace

// ── listen ───────────────────────────────────────────────────────────────

TEST(IpcLink, ListenCreatesSocketFile) {
    const auto path = make_socket_path();
    const auto uri  = "ipc://" + path;

    auto t = std::make_shared<IpcLink>();
    StubHost h;
    auto api = make_stub_api(h);
    t->set_host_api(&api);

    ASSERT_EQ(t->listen(uri), GN_OK);
    EXPECT_TRUE(std::filesystem::exists(path));

    struct ::stat st{};
    ASSERT_EQ(::stat(path.c_str(), &st), 0);
    EXPECT_TRUE(S_ISSOCK(st.st_mode));

    t->shutdown();
    /// shutdown unlinks the socket inode so the next listen on the
    /// same path is unblocked.
    EXPECT_FALSE(std::filesystem::exists(path));
}

TEST(IpcLink, ListenRejectsMalformedUri) {
    auto t = std::make_shared<IpcLink>();
    EXPECT_NE(t->listen("garbage"), GN_OK);
    EXPECT_NE(t->listen("tcp://127.0.0.1:9000"), GN_OK);  /// wrong scheme
}

TEST(IpcLink, ShutdownIsIdempotent) {
    auto t = std::make_shared<IpcLink>();
    t->shutdown();
    t->shutdown();
}

// ── full loopback round-trip ─────────────────────────────────────────────

TEST(IpcLink, LoopbackHandshakeAndPayloadRoundTrip) {
    const auto path = make_socket_path();
    const auto uri  = "ipc://" + path;

    StubHost h;
    auto api = make_stub_api(h);
    auto t = std::make_shared<IpcLink>();
    t->set_host_api(&api);

    ASSERT_EQ(t->listen(uri), GN_OK);
    ASSERT_EQ(t->connect(uri), GN_OK);

    wait_for([&] { return h.connects.load() == 2; }, 2s,
              "two notify_connect calls");

    /// Both sides report Loopback per `link.md` §3.
    {
        std::lock_guard lk(h.mu);
        ASSERT_EQ(h.trusts.size(), 2u);
        for (auto trust : h.trusts) EXPECT_EQ(trust, GN_TRUST_LOOPBACK);
    }

    gn_conn_id_t initiator = GN_INVALID_ID;
    gn_conn_id_t responder = GN_INVALID_ID;
    {
        std::lock_guard lk(h.mu);
        for (std::size_t i = 0; i < h.roles.size(); ++i) {
            if (h.roles[i] == GN_ROLE_INITIATOR) initiator = h.conns[i];
            if (h.roles[i] == GN_ROLE_RESPONDER) responder = h.conns[i];
        }
    }
    ASSERT_NE(initiator, GN_INVALID_ID);
    ASSERT_NE(responder, GN_INVALID_ID);

    /// 1 KiB payload — bigger than a single read buffer would coalesce
    /// in one shot, exercising the read loop.
    std::vector<std::uint8_t> payload(1024);
    for (std::size_t i = 0; i < payload.size(); ++i) {
        payload[i] = static_cast<std::uint8_t>(i & 0xFF);
    }
    ASSERT_EQ(t->send(initiator, std::span<const std::uint8_t>(payload)),
              GN_OK);

    wait_for([&] {
        std::lock_guard lk(h.mu);
        std::size_t total = 0;
        for (std::size_t i = 0; i < h.inbound_owners.size(); ++i) {
            if (h.inbound_owners[i] == responder)
                total += h.inbound[i].size();
        }
        return total == payload.size();
    }, 2s, "1 KiB payload arrived at responder");

    /// Reassemble the responder's view across whatever read chunks
    /// arrived; bytes must match the source verbatim.
    std::vector<std::uint8_t> received;
    {
        std::lock_guard lk(h.mu);
        for (std::size_t i = 0; i < h.inbound_owners.size(); ++i) {
            if (h.inbound_owners[i] == responder) {
                received.insert(received.end(),
                                 h.inbound[i].begin(), h.inbound[i].end());
            }
        }
    }
    EXPECT_EQ(received, payload);

    EXPECT_EQ(t->disconnect(initiator), GN_OK);
    wait_for([&] { return h.disconnects.load() >= 1; }, 2s, "disconnect notify");

    t->shutdown();
}

TEST(IpcLink, ShutdownFiresSynchronousNotifyDisconnect) {
    /// `link.md` §9 — shutdown releases every kernel-observable
    /// session before the io_context tear-down. Pre-fix, IPC closed
    /// the per-session sockets and let `ioc_.stop()` drop the read-
    /// completion path that fires `notify_disconnect`; the kernel-
    /// side `ConnectionRegistry` then kept live records past
    /// shutdown and held the security plugin's lifetime anchor.
    /// Carry-over of the TCP fix in commit bda18c6.
    const auto path = make_socket_path();
    const auto uri  = "ipc://" + path;

    StubHost h;
    h.main_tid = std::this_thread::get_id();
    auto api = make_stub_api(h);
    auto t = std::make_shared<IpcLink>();
    t->set_host_api(&api);

    ASSERT_EQ(t->listen(uri), GN_OK);
    ASSERT_EQ(t->connect(uri), GN_OK);

    /// Both sides need a valid `conn_id` before shutdown — the path
    /// only fires for sessions that completed `notify_connect`.
    wait_for([&] { return h.connects.load() == 2; }, 2s,
              "two notify_connect calls");
    ASSERT_EQ(h.disconnects.load(), 0);
    ASSERT_EQ(h.on_main_disconnects.load(), 0);

    t->shutdown();

    /// Pre-fix, `notify_disconnect` for live sessions fires from
    /// the worker thread when the `async_read_some` completion
    /// observes EOF (or, more often, gets dropped by `ioc_.stop()`
    /// — no notify at all). Post-fix, every session's
    /// `notify_disconnect` runs on the caller thread inside
    /// `shutdown()` itself. The thread-id pin is deterministic
    /// where a raw count is racy with worker-thread scheduling.
    EXPECT_EQ(h.on_main_disconnects.load(), 2)
        << "IpcLink::shutdown() must fire notify_disconnect "
           "synchronously on the caller thread for every live "
           "session before ioc_.stop() drops strand-bound "
           "continuations (link.md §9).";
}

TEST(IpcLink, ConnectRejectsNonExistentSocket) {
    StubHost h;
    auto api = make_stub_api(h);
    auto t = std::make_shared<IpcLink>();
    t->set_host_api(&api);

    /// Path that surely does not exist — the async connect will fail
    /// quietly; transport returns GN_OK from `connect()` (the call
    /// itself succeeds in posting the async op) but no notify_connect
    /// fires. This codifies the legacy "fire-and-forget" connect
    /// shape.
    EXPECT_EQ(t->connect("ipc:///tmp/this_path_never_existed_$$$.sock"),
              GN_OK);
    /// Give the io_context a moment to run and fail the connect.
    std::this_thread::sleep_for(50ms);
    EXPECT_EQ(h.connects.load(), 0);
    t->shutdown();
}
