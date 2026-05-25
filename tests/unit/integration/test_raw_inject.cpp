/// @file   tests/unit/integration/test_raw_inject.cpp
/// @brief  End-to-end inject path for the L2-composer raw_inject.
///
/// The plugin no longer owns a socket — every accept / read / write
/// rides the `gn.link.tcp` extension. This test wires a synthetic
/// TCP-carrier extension into a real `Kernel`, registers raw_inject
/// against the kernel through `register_vtable`, registers a raw-v1
/// echo handler, then drives the inject path by invoking the
/// captured carrier accept + data callbacks directly. The success
/// criterion: an inbound payload round-trips through the kernel
/// router and out the carrier's send slot.

#include <atomic>
#include <cstring>
#include <memory>
#include <mutex>
#include <span>
#include <string_view>
#include <vector>

#include <gtest/gtest.h>

#include <core/kernel/host_api_builder.hpp>
#include <core/kernel/kernel.hpp>
#include <core/kernel/plugin_context.hpp>
#include <tests/util/protocol_setup.hpp>

#include <plugins/links/raw_inject/raw_inject.hpp>
#include <plugins/protocols/raw/raw.hpp>

#include <sdk/cpp/protocol_layer.hpp>
#include <sdk/extensions/link.h>
#include <sdk/handler.h>
#include <sdk/link.h>
#include <sdk/types.h>

namespace {

using namespace gn;
using namespace gn::core;
using gn::link::raw_inject::RawInjectLink;

class RawProtocolLayer final : public ::gn::IProtocolLayer {
public:
    RawProtocolLayer()
        : vtable_(::gn::protocol::raw::make_vtable()) {}

    [[nodiscard]] std::string_view protocol_id() const noexcept override {
        return "raw-v1";
    }

    [[nodiscard]] std::size_t max_payload_size() const noexcept override {
        return vtable_.max_payload_size
            ? vtable_.max_payload_size(nullptr) : 0;
    }

    [[nodiscard]] std::uint32_t allowed_trust_mask() const noexcept override {
        return vtable_.allowed_trust_mask
            ? vtable_.allowed_trust_mask(nullptr)
            : ::gn::IProtocolLayer::allowed_trust_mask();
    }

    ::gn::Result<::gn::DeframeResult> deframe(
        ::gn::ConnectionContext& /*ctx*/,
        std::span<const std::uint8_t> /*bytes*/) override {
        return ::gn::DeframeResult{};
    }

    ::gn::Result<std::vector<std::uint8_t>> frame(
        ::gn::ConnectionContext& ctx,
        const gn_message_t& msg) override {
        std::uint8_t* out_bytes = nullptr;
        std::size_t   out_size  = 0;
        void*         out_ud    = nullptr;
        void (*out_free)(void*, std::uint8_t*) = nullptr;
        const auto rc = vtable_.frame(
            nullptr, &ctx, &msg,
            &out_bytes, &out_size, &out_ud, &out_free);
        if (rc != GN_OK) {
            return std::unexpected{::gn::Error{rc, "raw frame failed"}};
        }
        std::vector<std::uint8_t> v(out_bytes, out_bytes + out_size);
        if (out_free) out_free(out_ud, out_bytes);
        return v;
    }

private:
    gn_protocol_layer_vtable_t vtable_;
};

/// Echo handler under raw-v1: every inbound message routes back to
/// the same conn via `host_api->send`.
struct EchoHandler {
    host_api_t*       api = nullptr;
    std::uint32_t     msg_id = 0;
    std::atomic<int>  calls{0};

    static gn_propagation_t handle(void* self, const gn_message_t* env) {
        auto* h = static_cast<EchoHandler*>(self);
        h->calls.fetch_add(1);
        if (h->api && h->api->send) {
            (void)h->api->send(h->api->host_ctx,
                                env->conn_id,
                                h->msg_id,
                                env->payload, env->payload_size);
        }
        return GN_PROPAGATION_CONSUMED;
    }
};

/// In-memory `gn.link.tcp` carrier — exposes the extension vtable
/// raw_inject queries through `LinkCarrier::query`. The test
/// invokes `deliver_accept` / `deliver_data` to drive the L2
/// pipeline.
struct FakeTcpCarrier {
    std::atomic<int>          listens{0};
    std::atomic<int>          sends{0};
    std::atomic<int>          closes{0};
    std::atomic<std::uint16_t> bound_port{0};

    mutable std::mutex                            mu;
    std::vector<std::vector<std::uint8_t>>        sent_payloads;
    std::vector<gn_conn_id_t>                     sent_conns;

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
    static gn_result_t s_listen(void* ctx, const char*) {
        auto* f = static_cast<FakeTcpCarrier*>(ctx);
        f->listens.fetch_add(1);
        f->bound_port.store(46000);
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
        return GN_OK;
    }
    static gn_result_t s_unsubscribe_data(void* ctx, gn_conn_id_t) {
        auto* f = static_cast<FakeTcpCarrier*>(ctx);
        std::lock_guard lk(f->mu);
        f->data_cb   = nullptr;
        f->data_user = nullptr;
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
        if (out) *out = 1;
        return GN_OK;
    }
    static gn_result_t s_unsubscribe_accept(void* ctx,
                                              gn_subscription_id_t) {
        auto* f = static_cast<FakeTcpCarrier*>(ctx);
        std::lock_guard lk(f->mu);
        f->accept_cb   = nullptr;
        f->accept_user = nullptr;
        return GN_OK;
    }
    static gn_result_t s_listen_port(void* ctx, std::uint16_t* out) {
        auto* f = static_cast<FakeTcpCarrier*>(ctx);
        if (out) *out = f->bound_port.load(std::memory_order_acquire);
        return GN_OK;
    }
};

[[nodiscard]] gn_link_api_t make_tcp_carrier_vtable(FakeTcpCarrier& f) {
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

/// raw_inject thunks bridging the C++ class to the kernel's
/// link-side C ABI. Same shape as the macro emits.
struct LinkThunks {
    static const char* scheme(void*) { return "raw-inject"; }
    static gn_result_t listen(void* self, const char* uri) {
        return static_cast<RawInjectLink*>(self)->listen(uri);
    }
    static gn_result_t connect(void* self, const char* uri) {
        return static_cast<RawInjectLink*>(self)->connect(uri);
    }
    static gn_result_t send(void* self, gn_conn_id_t conn,
                             const std::uint8_t* bytes, size_t size) {
        return static_cast<RawInjectLink*>(self)->send(
            conn, std::span<const std::uint8_t>(bytes, size));
    }
    static gn_result_t send_batch(void*, gn_conn_id_t,
                                    const gn_byte_span_t*, size_t) {
        return GN_ERR_NOT_IMPLEMENTED;
    }
    static gn_result_t disconnect(void* self, gn_conn_id_t conn) {
        return static_cast<RawInjectLink*>(self)->disconnect(conn);
    }
    static const char* extension_name(void*)   { return ""; }
    static const void* extension_vtable(void*) { return nullptr; }
    static void        destroy(void*)          {}

    static gn_link_vtable_t make_vtable() {
        gn_link_vtable_t v{};
        v.api_size         = sizeof(gn_link_vtable_t);
        v.scheme           = &scheme;
        v.listen           = &listen;
        v.connect          = &connect;
        v.send             = &send;
        v.send_batch       = &send_batch;
        v.disconnect       = &disconnect;
        v.extension_name   = &extension_name;
        v.extension_vtable = &extension_vtable;
        v.destroy          = &destroy;
        return v;
    }
};

}  // namespace

// ─── End-to-end inject round-trip via fake TCP carrier ──────────────────

TEST(RawInjectIntegration, LoopbackRoundTripsThroughCarrier) {
    Kernel kernel;
    auto raw_layer = std::make_shared<RawProtocolLayer>();
    ::gn::test::util::register_default_protocol(kernel, raw_layer);

    PluginContext plugin_ctx;
    plugin_ctx.plugin_name = "raw-inject-e2e";
    plugin_ctx.kernel      = &kernel;
    auto api = build_host_api(plugin_ctx);

    PublicKey local_pk;
    local_pk.fill(0x11);
    kernel.identities().add(local_pk);

    /// Plant a synthetic `gn.link.tcp` carrier so raw_inject's
    /// `LinkCarrier::query("tcp")` succeeds without dlopen.
    FakeTcpCarrier carrier;
    static auto carrier_vt = make_tcp_carrier_vtable(carrier);
    ASSERT_EQ(api.register_extension(api.host_ctx, "gn.link.tcp",
                                       GN_EXT_LINK_VERSION, &carrier_vt),
              GN_OK);

    EchoHandler echo;
    echo.api    = &api;
    echo.msg_id = 0x10FF;

    gn_handler_vtable_t h_vt{};
    h_vt.api_size       = sizeof(gn_handler_vtable_t);
    h_vt.handle_message = &EchoHandler::handle;

    gn_register_meta_t h_meta{};
    h_meta.api_size = sizeof(gn_register_meta_t);
    h_meta.name     = "raw-v1";
    h_meta.msg_id   = 0x10FF;
    h_meta.priority = 128;

    std::uint64_t hid = 0;
    ASSERT_EQ(api.register_vtable(api.host_ctx, GN_REGISTER_HANDLER,
                                   &h_meta, &h_vt, &echo, &hid),
              GN_OK);

    auto link = std::make_shared<RawInjectLink>();
    link->set_host_api(&api);

    gn::link::raw_inject::Config cfg;
    cfg.default_msg_id = 0x10FF;
    cfg.encode_msg_id  = "config";
    cfg.target_ns      = "raw-v1";
    link->set_config(cfg);

    static auto link_vt = LinkThunks::make_vtable();

    gn_register_meta_t link_meta{};
    link_meta.api_size    = sizeof(gn_register_meta_t);
    link_meta.name        = "raw-inject";
    link_meta.protocol_id = "raw-v1";

    std::uint64_t lid = 0;
    ASSERT_EQ(api.register_vtable(api.host_ctx, GN_REGISTER_LINK,
                                   &link_meta, &link_vt,
                                   link.get(), &lid),
              GN_OK);

    ASSERT_EQ(link->listen("raw-inject://127.0.0.1:0"), GN_OK);
    ASSERT_EQ(carrier.listens.load(), 1);

    /// Drive an accept + a payload through the captured carrier
    /// callbacks. The L2 plugin calls `notify_connect` with a
    /// deterministic pk derived from the peer URI under GN_TRUST_LOOPBACK.
    carrier.deliver_accept(0x7001, "tcp://127.0.0.1:55580");

    const std::uint8_t payload[] = {'h','e','l','l','o'};
    carrier.deliver_data(0x7001,
        std::span<const std::uint8_t>(payload, sizeof(payload)));

    EXPECT_EQ(echo.calls.load(), 1);
    EXPECT_EQ(carrier.sends.load(), 1);
    {
        std::lock_guard lk(carrier.mu);
        ASSERT_EQ(carrier.sent_payloads.size(), 1u);
        EXPECT_EQ(carrier.sent_conns.front(), 0x7001u);
        EXPECT_EQ(std::string(carrier.sent_payloads.front().begin(),
                              carrier.sent_payloads.front().end()),
                  "hello");
    }

    link->shutdown();
    (void)api.unregister_vtable(api.host_ctx, lid);
    (void)api.unregister_vtable(api.host_ctx, hid);
    (void)api.unregister_extension(api.host_ctx, "gn.link.tcp");
}
