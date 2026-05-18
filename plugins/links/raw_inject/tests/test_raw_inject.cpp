// SPDX-License-Identifier: Apache-2.0
/// @file   plugins/links/raw_inject/tests/test_raw_inject.cpp
/// @brief  Plugin-side unit tests: TCP listen, accept, inject pump,
///         outbound send, msg_id encoding modes.

#include <gtest/gtest.h>

#include <raw_inject.hpp>

#include <sdk/cpp/test/poll.hpp>
#include <sdk/cpp/test/stub_host.hpp>
#include <sdk/host_api.h>
#include <sdk/types.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <span>
#include <string>
#include <thread>
#include <vector>

namespace {

using namespace std::chrono_literals;
using gn::link::raw_inject::Config;
using gn::link::raw_inject::RawInjectLink;

/// Extension of the shared `LinkStub` that captures every `inject`
/// call so the tests can assert which msg_id / payload the plugin
/// pushed at the kernel.
struct InjectStub : ::gn::sdk::test::LinkStub {
    struct Record {
        gn_inject_layer_t        layer;
        gn_conn_id_t             source;
        std::uint32_t            msg_id;
        std::vector<std::uint8_t> payload;
    };

    mutable std::mutex      inject_mu;
    std::vector<Record>     injected;
    std::atomic<int>        inject_calls{0};

    static gn_result_t on_inject(void* host_ctx,
                                   gn_inject_layer_t layer,
                                   gn_conn_id_t source,
                                   std::uint32_t msg_id,
                                   const std::uint8_t* bytes,
                                   std::size_t size) {
        auto* h = static_cast<InjectStub*>(host_ctx);
        Record r;
        r.layer  = layer;
        r.source = source;
        r.msg_id = msg_id;
        r.payload.assign(bytes, bytes + size);
        {
            std::lock_guard lk(h->inject_mu);
            h->injected.push_back(std::move(r));
        }
        h->inject_calls.fetch_add(1);
        return GN_OK;
    }
};

[[nodiscard]] host_api_t make_api(InjectStub& h) noexcept {
    host_api_t api = ::gn::sdk::test::make_link_host_api(h);
    api.inject = &InjectStub::on_inject;
    return api;
}

[[nodiscard]] int connect_to(std::uint16_t port) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    EXPECT_GE(fd, 0);
    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(port);
    addr.sin_addr.s_addr = htonl(0x7F000001);  // 127.0.0.1
    const int rc = ::connect(fd, reinterpret_cast<sockaddr*>(&addr),
                              sizeof(addr));
    if (rc != 0) {
        ::close(fd);
        return -1;
    }
    return fd;
}

}  // namespace

// ── listen ───────────────────────────────────────────────────────────────

TEST(RawInjectLink, ListenBindsAndExposesPort) {
    auto t = std::make_shared<RawInjectLink>();
    InjectStub h;
    auto api = make_api(h);
    t->set_host_api(&api);

    ASSERT_EQ(t->listen("raw-inject://127.0.0.1:0"), GN_OK);
    EXPECT_GT(t->listen_port(), 0);
}

// ── accept + inject pump ────────────────────────────────────────────────

TEST(RawInjectLink, AcceptedConnectionPipesBytesThroughInject) {
    auto t = std::make_shared<RawInjectLink>();
    InjectStub h;
    auto api = make_api(h);
    t->set_host_api(&api);

    /// Default-msg-id mode: every inbound chunk injects under cfg.default_msg_id.
    Config cfg;
    cfg.default_msg_id = 0x10FF;
    cfg.encode_msg_id  = "config";
    t->set_config(cfg);

    ASSERT_EQ(t->listen("raw-inject://127.0.0.1:0"), GN_OK);
    const auto port = t->listen_port();

    const int fd = connect_to(port);
    ASSERT_GE(fd, 0);

    /// Wait for the accept side to publish a conn id.
    ASSERT_TRUE(::gn::sdk::test::wait_for(
        [&] { return h.connects.load() == 1; }, 2s));

    const char* msg = "hello";
    ASSERT_EQ(::write(fd, msg, 5), 5);

    ASSERT_TRUE(::gn::sdk::test::wait_for(
        [&] { return h.inject_calls.load() >= 1; }, 2s));

    {
        std::lock_guard lk(h.inject_mu);
        ASSERT_FALSE(h.injected.empty());
        const auto& r = h.injected.front();
        EXPECT_EQ(r.layer, GN_INJECT_LAYER_MESSAGE);
        EXPECT_EQ(r.msg_id, 0x10FFu);
        EXPECT_EQ(std::string(r.payload.begin(), r.payload.end()), "hello");
    }

    ::close(fd);
}

TEST(RawInjectLink, StreamMsgIdEncodingPeelsBigEndianPrefix) {
    auto t = std::make_shared<RawInjectLink>();
    InjectStub h;
    auto api = make_api(h);
    t->set_host_api(&api);

    Config cfg;
    cfg.encode_msg_id = "stream";
    t->set_config(cfg);

    ASSERT_EQ(t->listen("raw-inject://127.0.0.1:0"), GN_OK);
    const auto port = t->listen_port();
    const int fd = connect_to(port);
    ASSERT_GE(fd, 0);
    ASSERT_TRUE(::gn::sdk::test::wait_for(
        [&] { return h.connects.load() == 1; }, 2s));

    /// 0x00112233 big-endian + "abcd" payload.
    const std::uint8_t buf[] = {
        0x00, 0x11, 0x22, 0x33,
        'a', 'b', 'c', 'd' };
    ASSERT_EQ(::write(fd, buf, sizeof(buf)),
              static_cast<ssize_t>(sizeof(buf)));

    ASSERT_TRUE(::gn::sdk::test::wait_for(
        [&] { return h.inject_calls.load() >= 1; }, 2s));

    {
        std::lock_guard lk(h.inject_mu);
        ASSERT_FALSE(h.injected.empty());
        const auto& r = h.injected.front();
        EXPECT_EQ(r.msg_id, 0x00112233u);
        EXPECT_EQ(std::string(r.payload.begin(), r.payload.end()), "abcd");
    }

    ::close(fd);
}

// ── outbound send writes to the TCP socket ───────────────────────────────

TEST(RawInjectLink, SendWritesRawBytesToConnectedSocket) {
    auto t = std::make_shared<RawInjectLink>();
    InjectStub h;
    auto api = make_api(h);
    t->set_host_api(&api);

    ASSERT_EQ(t->listen("raw-inject://127.0.0.1:0"), GN_OK);
    const auto port = t->listen_port();

    const int fd = connect_to(port);
    ASSERT_GE(fd, 0);

    ASSERT_TRUE(::gn::sdk::test::wait_for(
        [&] { return h.connects.load() == 1; }, 2s));

    gn_conn_id_t conn = GN_INVALID_ID;
    {
        std::lock_guard lk(h.mu);
        ASSERT_EQ(h.conns.size(), 1u);
        conn = h.conns.front();
    }

    const std::uint8_t reply[] = {'w', 'o', 'r', 'l', 'd'};
    ASSERT_EQ(t->send(conn,
                       std::span<const std::uint8_t>(reply, sizeof(reply))),
              GN_OK);

    std::array<std::uint8_t, 16> rx{};
    const ssize_t n = ::read(fd, rx.data(), rx.size());
    ASSERT_EQ(n, 5);
    EXPECT_EQ(std::string(rx.data(), rx.data() + n), "world");

    ::close(fd);
}

// ── disconnect ──────────────────────────────────────────────────────────

TEST(RawInjectLink, DisconnectFiresNotifyDisconnect) {
    auto t = std::make_shared<RawInjectLink>();
    InjectStub h;
    auto api = make_api(h);
    t->set_host_api(&api);

    ASSERT_EQ(t->listen("raw-inject://127.0.0.1:0"), GN_OK);
    const auto port = t->listen_port();

    const int fd = connect_to(port);
    ASSERT_GE(fd, 0);
    ASSERT_TRUE(::gn::sdk::test::wait_for(
        [&] { return h.connects.load() == 1; }, 2s));

    ::close(fd);

    ASSERT_TRUE(::gn::sdk::test::wait_for(
        [&] { return h.disconnects.load() >= 1; }, 2s));
}

TEST(RawInjectLink, ConnectIsNotImplemented) {
    auto t = std::make_shared<RawInjectLink>();
    EXPECT_EQ(t->connect("raw-inject://127.0.0.1:1"),
              GN_ERR_NOT_IMPLEMENTED);
}

TEST(RawInjectLink, CapabilitiesAreStreamReliableOrdered) {
    const auto c = RawInjectLink::capabilities();
    EXPECT_TRUE(c.flags & GN_LINK_CAP_STREAM);
    EXPECT_TRUE(c.flags & GN_LINK_CAP_RELIABLE);
    EXPECT_TRUE(c.flags & GN_LINK_CAP_ORDERED);
}
