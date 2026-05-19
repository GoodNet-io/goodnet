// SPDX-License-Identifier: Apache-2.0
/// @file   plugins/links/raw_inject/tests/test_raw_inject.cpp
/// @brief  Plugin-side unit tests for the L2 composer.
///
/// raw_inject no longer owns a socket — every accept / read / write
/// goes through the `gn.link.tcp` carrier extension. These tests
/// install a synthetic `gn_link_api_t` vtable under the carrier's
/// extension name, drive the plugin's listen → accept → data →
/// inject flow by invoking the captured carrier callbacks directly,
/// and verify the inject + outbound paths through the stub
/// host_api.

#include <gtest/gtest.h>

#include <raw_inject.hpp>

#include <sdk/cpp/test/stub_host.hpp>
#include <sdk/extensions/link.h>
#include <sdk/host_api.h>
#include <sdk/types.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <span>
#include <string>
#include <vector>

namespace {

using gn::link::raw_inject::Config;
using gn::link::raw_inject::RawInjectLink;

// ─── Fake TCP carrier extension ──────────────────────────────────────────

struct FakeTcpCarrier {
    std::atomic<int>          listens{0};
    std::atomic<int>          sends{0};
    std::atomic<int>          closes{0};
    std::atomic<int>          data_subs{0};
    std::atomic<int>          data_unsubs{0};
    std::atomic<int>          accept_subs{0};
    std::atomic<int>          accept_unsubs{0};
    std::atomic<std::uint16_t> bound_port{0};

    mutable std::mutex                            mu;
    std::vector<std::vector<std::uint8_t>>        sent_payloads;
    std::vector<gn_conn_id_t>                     sent_conns;

    /// Captured carrier callbacks the test drives directly.
    gn_link_accept_cb_t accept_cb     = nullptr;
    void*               accept_user   = nullptr;
    gn_link_data_cb_t   data_cb       = nullptr;
    void*               data_user     = nullptr;
    gn_conn_id_t        data_conn     = GN_INVALID_ID;

    void deliver_accept(gn_conn_id_t conn, const char* peer_uri) {
        gn_link_accept_cb_t cb = nullptr;
        void* user = nullptr;
        {
            std::lock_guard lk(mu);
            cb = accept_cb;
            user = accept_user;
        }
        if (cb) cb(user, conn, peer_uri);
    }

    void deliver_data(gn_conn_id_t conn,
                       std::span<const std::uint8_t> bytes) {
        gn_link_data_cb_t cb = nullptr;
        void* user = nullptr;
        gn_conn_id_t expected = GN_INVALID_ID;
        {
            std::lock_guard lk(mu);
            cb = data_cb;
            user = data_user;
            expected = data_conn;
        }
        if (cb && expected == conn) {
            cb(user, conn, bytes.data(), bytes.size());
        }
    }

    static gn_result_t s_get_stats(void*, gn_link_stats_t*) { return GN_OK; }
    static gn_result_t s_get_caps(void*, gn_link_caps_t*)   { return GN_OK; }

    static gn_result_t s_send(void* ctx, gn_conn_id_t c,
                                const std::uint8_t* b, std::size_t n) {
        auto* f = static_cast<FakeTcpCarrier*>(ctx);
        std::lock_guard lk(f->mu);
        f->sent_payloads.emplace_back(b, b + n);
        f->sent_conns.push_back(c);
        f->sends.fetch_add(1);
        return GN_OK;
    }

    static gn_result_t s_send_batch(void*, gn_conn_id_t,
                                      const gn_byte_span_t*,
                                      std::size_t) {
        return GN_ERR_NOT_IMPLEMENTED;
    }

    static gn_result_t s_close(void* ctx, gn_conn_id_t, int) {
        static_cast<FakeTcpCarrier*>(ctx)->closes.fetch_add(1);
        return GN_OK;
    }

    static gn_result_t s_listen(void* ctx, const char* /*uri*/) {
        auto* f = static_cast<FakeTcpCarrier*>(ctx);
        f->listens.fetch_add(1);
        f->bound_port.store(45678);
        return GN_OK;
    }

    static gn_result_t s_connect(void*, const char*, gn_conn_id_t*) {
        return GN_ERR_NOT_IMPLEMENTED;
    }

    static gn_result_t s_subscribe_data(void* ctx, gn_conn_id_t c,
                                          gn_link_data_cb_t cb,
                                          void* user) {
        auto* f = static_cast<FakeTcpCarrier*>(ctx);
        std::lock_guard lk(f->mu);
        f->data_cb   = cb;
        f->data_user = user;
        f->data_conn = c;
        f->data_subs.fetch_add(1);
        return GN_OK;
    }

    static gn_result_t s_unsubscribe_data(void* ctx, gn_conn_id_t) {
        auto* f = static_cast<FakeTcpCarrier*>(ctx);
        std::lock_guard lk(f->mu);
        f->data_cb   = nullptr;
        f->data_user = nullptr;
        f->data_unsubs.fetch_add(1);
        return GN_OK;
    }

    static gn_result_t s_subscribe_accept(void* ctx,
                                            gn_link_accept_cb_t cb,
                                            void* user,
                                            gn_subscription_id_t* out) {
        auto* f = static_cast<FakeTcpCarrier*>(ctx);
        std::lock_guard lk(f->mu);
        f->accept_cb   = cb;
        f->accept_user = user;
        f->accept_subs.fetch_add(1);
        if (out) *out = 1;
        return GN_OK;
    }

    static gn_result_t s_unsubscribe_accept(void* ctx,
                                              gn_subscription_id_t) {
        auto* f = static_cast<FakeTcpCarrier*>(ctx);
        std::lock_guard lk(f->mu);
        f->accept_cb   = nullptr;
        f->accept_user = nullptr;
        f->accept_unsubs.fetch_add(1);
        return GN_OK;
    }

    static gn_result_t s_listen_port(void* ctx, std::uint16_t* out) {
        auto* f = static_cast<FakeTcpCarrier*>(ctx);
        if (out) *out = f->bound_port.load(std::memory_order_acquire);
        return GN_OK;
    }
};

[[nodiscard]] gn_link_api_t make_carrier_vtable(FakeTcpCarrier& f) {
    gn_link_api_t v{};
    v.api_size           = sizeof(v);
    v.get_stats          = &FakeTcpCarrier::s_get_stats;
    v.get_capabilities   = &FakeTcpCarrier::s_get_caps;
    v.send               = &FakeTcpCarrier::s_send;
    v.send_batch         = &FakeTcpCarrier::s_send_batch;
    v.close              = &FakeTcpCarrier::s_close;
    v.listen             = &FakeTcpCarrier::s_listen;
    v.connect            = &FakeTcpCarrier::s_connect;
    v.subscribe_data     = &FakeTcpCarrier::s_subscribe_data;
    v.unsubscribe_data   = &FakeTcpCarrier::s_unsubscribe_data;
    v.subscribe_accept   = &FakeTcpCarrier::s_subscribe_accept;
    v.unsubscribe_accept = &FakeTcpCarrier::s_unsubscribe_accept;
    v.composer_listen_port = &FakeTcpCarrier::s_listen_port;
    v.ctx                = &f;
    return v;
}

// ─── Host stub: notify_connect + inject + query_extension_checked ────────

struct Stub : ::gn::sdk::test::LinkStub {
    struct InjectRecord {
        gn_inject_layer_t        layer;
        gn_conn_id_t             source;
        std::uint32_t            msg_id;
        std::vector<std::uint8_t> payload;
    };

    mutable std::mutex      inject_mu;
    std::vector<InjectRecord> injected;
    std::atomic<int>        inject_calls{0};

    gn_link_api_t carrier_vt{};

    static gn_result_t on_inject(void* host_ctx,
                                   gn_inject_layer_t layer,
                                   gn_conn_id_t source,
                                   std::uint32_t msg_id,
                                   const std::uint8_t* bytes,
                                   std::size_t size) {
        auto* h = static_cast<Stub*>(host_ctx);
        InjectRecord r;
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

    static gn_result_t on_query_extension_checked(
        void* host_ctx, const char* name, std::uint32_t /*version*/,
        const void** out) {
        auto* h = static_cast<Stub*>(host_ctx);
        if (!out || !name) return GN_ERR_NULL_ARG;
        if (std::string_view(name) != "gn.link.tcp") {
            return GN_ERR_NOT_FOUND;
        }
        *out = &h->carrier_vt;
        return GN_OK;
    }
};

[[nodiscard]] host_api_t make_api(Stub& h, FakeTcpCarrier& carrier) noexcept {
    h.carrier_vt = make_carrier_vtable(carrier);
    host_api_t api = ::gn::sdk::test::make_link_host_api(h);
    api.inject                  = &Stub::on_inject;
    api.query_extension_checked = &Stub::on_query_extension_checked;
    return api;
}

}  // namespace

// ─── Listen wires the TCP carrier acceptor ─────────────────────────────

TEST(RawInjectLink, ListenSubscribesAcceptThenInvokesCarrierListen) {
    Stub h;
    FakeTcpCarrier carrier;
    auto api = make_api(h, carrier);
    auto link = std::make_shared<RawInjectLink>();
    link->set_host_api(&api);

    ASSERT_EQ(link->listen("raw-inject://127.0.0.1:0"), GN_OK);
    EXPECT_EQ(carrier.accept_subs.load(), 1);
    EXPECT_EQ(carrier.listens.load(),     1);
    EXPECT_EQ(link->listen_port(),        45678);
}

TEST(RawInjectLink, ListenFailsWithoutCarrierExtension) {
    Stub h;
    auto api = ::gn::sdk::test::make_link_host_api(h);
    auto link = std::make_shared<RawInjectLink>();
    /// `query_extension_checked` left null — the carrier query fails.
    link->set_host_api(&api);
    EXPECT_NE(link->listen("raw-inject://127.0.0.1:0"), GN_OK);
}

// ─── Accept + inject pump ─────────────────────────────────────────────

TEST(RawInjectLink, CarrierAcceptDispatchesNotifyConnect) {
    Stub h;
    FakeTcpCarrier carrier;
    auto api = make_api(h, carrier);
    auto link = std::make_shared<RawInjectLink>();
    link->set_host_api(&api);
    ASSERT_EQ(link->listen("raw-inject://127.0.0.1:0"), GN_OK);

    carrier.deliver_accept(0x1001, "tcp://127.0.0.1:55555");

    EXPECT_EQ(h.connects.load(), 1);
    {
        std::lock_guard lk(h.mu);
        ASSERT_EQ(h.trusts.size(), 1u);
        EXPECT_EQ(h.trusts.front(), GN_TRUST_ANONYMOUS_LOOPBACK);
        EXPECT_EQ(h.roles.front(),  GN_ROLE_RESPONDER);
    }
    EXPECT_EQ(carrier.data_subs.load(), 1);
}

TEST(RawInjectLink, CarrierDataDispatchesInjectWithDefaultMsgId) {
    Stub h;
    FakeTcpCarrier carrier;
    auto api = make_api(h, carrier);
    auto link = std::make_shared<RawInjectLink>();
    link->set_host_api(&api);

    Config cfg;
    cfg.default_msg_id = 0x10FF;
    cfg.encode_msg_id  = "config";
    link->set_config(cfg);

    ASSERT_EQ(link->listen("raw-inject://127.0.0.1:0"), GN_OK);
    carrier.deliver_accept(0x2001, "tcp://127.0.0.1:55556");

    const std::uint8_t payload[] = {'h', 'e', 'l', 'l', 'o'};
    carrier.deliver_data(0x2001,
        std::span<const std::uint8_t>(payload, sizeof(payload)));

    EXPECT_EQ(h.inject_calls.load(), 1);
    {
        std::lock_guard lk(h.inject_mu);
        ASSERT_EQ(h.injected.size(), 1u);
        const auto& r = h.injected.front();
        EXPECT_EQ(r.layer,  GN_INJECT_LAYER_MESSAGE);
        EXPECT_EQ(r.msg_id, 0x10FFu);
        EXPECT_EQ(std::string(r.payload.begin(), r.payload.end()), "hello");
    }
}

TEST(RawInjectLink, StreamMsgIdEncodingPeelsBigEndianPrefix) {
    Stub h;
    FakeTcpCarrier carrier;
    auto api = make_api(h, carrier);
    auto link = std::make_shared<RawInjectLink>();
    link->set_host_api(&api);

    Config cfg;
    cfg.encode_msg_id = "stream";
    link->set_config(cfg);

    ASSERT_EQ(link->listen("raw-inject://127.0.0.1:0"), GN_OK);
    carrier.deliver_accept(0x3001, "tcp://127.0.0.1:55557");

    const std::uint8_t buf[] = {
        0x00, 0x11, 0x22, 0x33,
        'a', 'b', 'c', 'd' };
    carrier.deliver_data(0x3001,
        std::span<const std::uint8_t>(buf, sizeof(buf)));

    EXPECT_EQ(h.inject_calls.load(), 1);
    {
        std::lock_guard lk(h.inject_mu);
        ASSERT_EQ(h.injected.size(), 1u);
        const auto& r = h.injected.front();
        EXPECT_EQ(r.msg_id, 0x00112233u);
        EXPECT_EQ(std::string(r.payload.begin(), r.payload.end()), "abcd");
    }
}

TEST(RawInjectLink, MaxPayloadOverflowDrops) {
    Stub h;
    FakeTcpCarrier carrier;
    auto api = make_api(h, carrier);
    auto link = std::make_shared<RawInjectLink>();
    link->set_host_api(&api);

    Config cfg;
    cfg.max_payload = 4;
    link->set_config(cfg);

    ASSERT_EQ(link->listen("raw-inject://127.0.0.1:0"), GN_OK);
    carrier.deliver_accept(0x4001, "tcp://127.0.0.1:55558");

    const std::uint8_t big[] = {1,2,3,4,5,6,7,8};
    carrier.deliver_data(0x4001,
        std::span<const std::uint8_t>(big, sizeof(big)));

    EXPECT_EQ(h.inject_calls.load(), 0);
}

// ─── Outbound: send forwards to the carrier ────────────────────────────

TEST(RawInjectLink, SendForwardsToCarrierSendOnKernelConnId) {
    Stub h;
    FakeTcpCarrier carrier;
    auto api = make_api(h, carrier);
    auto link = std::make_shared<RawInjectLink>();
    link->set_host_api(&api);

    ASSERT_EQ(link->listen("raw-inject://127.0.0.1:0"), GN_OK);
    carrier.deliver_accept(0x5001, "tcp://127.0.0.1:55559");

    gn_conn_id_t kernel_conn = GN_INVALID_ID;
    {
        std::lock_guard lk(h.mu);
        ASSERT_FALSE(h.conns.empty());
        kernel_conn = h.conns.front();
    }

    const std::uint8_t reply[] = {'w', 'o', 'r', 'l', 'd'};
    ASSERT_EQ(link->send(kernel_conn,
                          std::span<const std::uint8_t>(reply, sizeof(reply))),
              GN_OK);

    EXPECT_EQ(carrier.sends.load(), 1);
    {
        std::lock_guard lk(carrier.mu);
        ASSERT_EQ(carrier.sent_payloads.size(), 1u);
        EXPECT_EQ(carrier.sent_conns.front(), 0x5001u);
        EXPECT_EQ(std::string(carrier.sent_payloads.front().begin(),
                              carrier.sent_payloads.front().end()),
                  "world");
    }
}

TEST(RawInjectLink, SendUnknownConnReturnsNotFound) {
    Stub h;
    FakeTcpCarrier carrier;
    auto api = make_api(h, carrier);
    auto link = std::make_shared<RawInjectLink>();
    link->set_host_api(&api);

    ASSERT_EQ(link->listen("raw-inject://127.0.0.1:0"), GN_OK);
    const std::uint8_t reply[] = {1,2,3};
    EXPECT_EQ(link->send(0xDEAD,
                          std::span<const std::uint8_t>(reply, sizeof(reply))),
              GN_ERR_NOT_FOUND);
}

// ─── Disconnect ────────────────────────────────────────────────────────

TEST(RawInjectLink, DisconnectClosesCarrierConn) {
    Stub h;
    FakeTcpCarrier carrier;
    auto api = make_api(h, carrier);
    auto link = std::make_shared<RawInjectLink>();
    link->set_host_api(&api);

    ASSERT_EQ(link->listen("raw-inject://127.0.0.1:0"), GN_OK);
    carrier.deliver_accept(0x6001, "tcp://127.0.0.1:55560");

    gn_conn_id_t kernel_conn = GN_INVALID_ID;
    {
        std::lock_guard lk(h.mu);
        ASSERT_FALSE(h.conns.empty());
        kernel_conn = h.conns.front();
    }
    EXPECT_EQ(link->disconnect(kernel_conn), GN_OK);
    EXPECT_EQ(carrier.closes.load(), 1);
}

TEST(RawInjectLink, ConnectIsNotImplemented) {
    auto link = std::make_shared<RawInjectLink>();
    EXPECT_EQ(link->connect("raw-inject://127.0.0.1:1"),
              GN_ERR_NOT_IMPLEMENTED);
}

TEST(RawInjectLink, CapabilitiesAreStreamReliableOrdered) {
    const auto c = RawInjectLink::capabilities();
    EXPECT_TRUE(c.flags & GN_LINK_CAP_STREAM);
    EXPECT_TRUE(c.flags & GN_LINK_CAP_RELIABLE);
    EXPECT_TRUE(c.flags & GN_LINK_CAP_ORDERED);
}
