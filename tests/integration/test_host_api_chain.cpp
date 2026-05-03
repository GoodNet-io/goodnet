/// @file   tests/integration/test_host_api_chain.cpp
/// @brief  Full kernel data path through the host_api boundary.
///
/// Mirrors `test_inbound_chain.cpp` but drives the kernel through the
/// same `host_api_t` a real plugin would receive. Covers
/// register_handler, notify_connect, notify_inbound_bytes, and
/// notify_disconnect; each must compose into the same dispatch
/// outcome that direct Router calls produced.

#include <atomic>
#include <cstring>
#include <memory>
#include <vector>

#include <gtest/gtest.h>

#include <core/kernel/connection_context.hpp>
#include <core/kernel/host_api_builder.hpp>
#include <core/kernel/kernel.hpp>
#include <core/kernel/plugin_context.hpp>

#include <plugins/protocols/gnet/protocol.hpp>

#include <sdk/handler.h>

namespace {

using namespace gn;
using namespace gn::core;
using namespace gn::plugins::gnet;

struct Capture {
    std::atomic<int> calls{0};
    PublicKey last_sender{};
    PublicKey last_receiver{};

    static gn_propagation_t handle(void* self, const gn_message_t* env) {
        auto* c = static_cast<Capture*>(self);
        std::memcpy(c->last_sender.data(),   env->sender_pk,   GN_PUBLIC_KEY_BYTES);
        std::memcpy(c->last_receiver.data(), env->receiver_pk, GN_PUBLIC_KEY_BYTES);
        c->calls.fetch_add(1);
        return GN_PROPAGATION_CONSUMED;
    }
};

/// One kernel + a populated host_api ready for integration scenarios.
struct KernelHarness {
    std::unique_ptr<Kernel>       kernel    = std::make_unique<Kernel>();
    std::shared_ptr<GnetProtocol> proto     = std::make_shared<GnetProtocol>();
    PluginContext                 plugin_ctx;
    host_api_t                    api{};

    KernelHarness(std::string plugin_name = "test") {
        kernel->set_protocol_layer(proto);
        plugin_ctx.plugin_name = std::move(plugin_name);
        plugin_ctx.kernel      = kernel.get();
        api = build_host_api(plugin_ctx);
    }
};

} // namespace

TEST(HostApiChain, RegisterHandlerThroughApi) {
    KernelHarness h;
    Capture cap;
    gn_handler_vtable_t vt{};
    vt.api_size       = sizeof(gn_handler_vtable_t);
    vt.handle_message = &Capture::handle;

    gn_handler_id_t hid = GN_INVALID_ID;
    gn_register_meta_t meta{};
    meta.api_size = sizeof(gn_register_meta_t);
    meta.name     = "gnet-v1";
    meta.msg_id   = 0x42;
    meta.priority = 128;
    ASSERT_EQ(h.api.register_vtable(h.api.host_ctx, GN_REGISTER_HANDLER,
                                     &meta, &vt, &cap, &hid),
              GN_OK);
    EXPECT_NE(hid, GN_INVALID_ID);
    EXPECT_EQ(h.kernel->handlers().size(), 1u);

    ASSERT_EQ(h.api.unregister_vtable(h.api.host_ctx, hid), GN_OK);
    EXPECT_EQ(h.kernel->handlers().size(), 0u);
}

TEST(HostApiChain, NotifyConnectThenDisconnect) {
    KernelHarness h;
    PublicKey peer_pk{};
    peer_pk[0] = 0xAA;

    gn_conn_id_t conn = GN_INVALID_ID;
    ASSERT_EQ(h.api.notify_connect(h.api.host_ctx,
                                   peer_pk.data(),
                                   "tcp://127.0.0.1:9000",
                                   GN_TRUST_PEER,
                                   GN_ROLE_INITIATOR,
                                   &conn),
              GN_OK);
    EXPECT_NE(conn, GN_INVALID_ID);
    EXPECT_EQ(h.kernel->connections().size(), 1u);

    ASSERT_EQ(h.api.notify_disconnect(h.api.host_ctx, conn, GN_OK), GN_OK);
    EXPECT_EQ(h.kernel->connections().size(), 0u);
}

TEST(HostApiChain, NotifyConnectControlByteUriRejected) {
    /// uri.md §5 #10 — a URI carrying CR / LF / space cannot reach
    /// the kernel registry index even on the `notify_connect` path
    /// that bypasses `parse_uri`. A downstream caller writing
    /// `rec.uri` into a wire frame (Host header, log line, request
    /// target) would otherwise smuggle a second HTTP request.
    KernelHarness h;
    PublicKey peer_pk{};
    peer_pk[0] = 0xAA;

    gn_conn_id_t conn = GN_INVALID_ID;
    EXPECT_EQ(h.api.notify_connect(h.api.host_ctx,
                                   peer_pk.data(),
                                   "ws://h:9/x HTTP/1.1\r\nEvil: 1\r\n\r\nGET /",
                                   GN_TRUST_PEER,
                                   GN_ROLE_INITIATOR,
                                   &conn),
              GN_ERR_INVALID_ENVELOPE);
    EXPECT_EQ(conn, GN_INVALID_ID);
    EXPECT_EQ(h.kernel->connections().size(), 0u);

    /// Plain whitespace is also rejected — leading space, embedded
    /// space, trailing tab. The registry index would otherwise hash
    /// these as legitimate distinct URIs.
    EXPECT_EQ(h.api.notify_connect(h.api.host_ctx,
                                   peer_pk.data(),
                                   " tcp://h:9000",
                                   GN_TRUST_PEER,
                                   GN_ROLE_INITIATOR,
                                   &conn),
              GN_ERR_INVALID_ENVELOPE);
    EXPECT_EQ(h.kernel->connections().size(), 0u);
}

TEST(HostApiChain, NotifyConnectMissingSchemePrefixRejected) {
    /// `host_api_t::notify_connect` derives the link scheme from the
    /// URI's `scheme://` prefix; the prefix doubles as the
    /// `LinkRegistry` key for the conn-id ownership gate
    /// (`security-trust.md` §6a). A URI without a scheme prefix has no
    /// route for ownership attribution — reject up front so a hostile
    /// caller cannot register an unattributable conn record.
    KernelHarness h;
    PublicKey peer_pk{};
    peer_pk[0] = 0x55;

    gn_conn_id_t conn = GN_INVALID_ID;
    EXPECT_EQ(h.api.notify_connect(h.api.host_ctx,
                                   peer_pk.data(),
                                   "127.0.0.1:9000",  // no scheme prefix
                                   GN_TRUST_PEER,
                                   GN_ROLE_INITIATOR,
                                   &conn),
              GN_ERR_INVALID_ENVELOPE);
    EXPECT_EQ(conn, GN_INVALID_ID);
    EXPECT_EQ(h.kernel->connections().size(), 0u);

    EXPECT_EQ(h.api.notify_connect(h.api.host_ctx,
                                   peer_pk.data(),
                                   "://just-the-separator",  // empty scheme
                                   GN_TRUST_PEER,
                                   GN_ROLE_INITIATOR,
                                   &conn),
              GN_ERR_INVALID_ENVELOPE);
    EXPECT_EQ(h.kernel->connections().size(), 0u);
}

TEST(HostApiChain, InboundBytesReachHandler) {
    KernelHarness alice("test-alice");
    KernelHarness bob("test-bob");

    /// Bob's local identity must match the receiver_pk Alice frames against.
    PublicKey alice_pk{};
    alice_pk[0] = 0x10;
    PublicKey bob_pk{};
    bob_pk[0] = 0x20;

    bob.kernel->identities().add(bob_pk);

    /// Bob registers a capturing handler through the host_api.
    Capture cap;
    gn_handler_vtable_t vt{};
    vt.api_size       = sizeof(gn_handler_vtable_t);
    vt.handle_message = &Capture::handle;
    gn_handler_id_t hid = GN_INVALID_ID;
    gn_register_meta_t meta{};
    meta.api_size = sizeof(gn_register_meta_t);
    meta.name     = "gnet-v1";
    meta.msg_id   = 0x77;
    meta.priority = 128;
    ASSERT_EQ(bob.api.register_vtable(bob.api.host_ctx, GN_REGISTER_HANDLER,
                                       &meta, &vt, &cap, &hid),
              GN_OK);

    /// Bob registers Alice as a known connection so the inbound
    /// pipeline can resolve sender_pk for direct frames.
    gn_conn_id_t conn = GN_INVALID_ID;
    ASSERT_EQ(bob.api.notify_connect(bob.api.host_ctx,
                                     alice_pk.data(),
                                     "tcp://127.0.0.1:9000",
                                     GN_TRUST_PEER,
                                     GN_ROLE_RESPONDER,
                                     &conn),
              GN_OK);

    /// Alice frames a relay-transit envelope (sender + receiver explicit
    /// on wire) so the test is independent of the inbound-context
    /// identity-source path; either way the handler must see the right
    /// envelope bytes.
    gn_message_t env{};
    std::memcpy(env.sender_pk,   alice_pk.data(), 32);
    std::memcpy(env.receiver_pk, bob_pk.data(),   32);
    env.msg_id = 0x77;
    const std::uint8_t payload[] = {0xDE, 0xAD};
    env.payload      = payload;
    env.payload_size = 2;

    /// Build a minimal alice-side context to frame against.
    gn_connection_context_t alice_ctx{};
    alice_ctx.local_pk  = alice_pk;
    alice_ctx.remote_pk = bob_pk;
    auto framed = alice.proto->frame(alice_ctx, env);
    ASSERT_TRUE(framed.has_value());

    /// Push the wire bytes into Bob through the host_api boundary.
    ASSERT_EQ(bob.api.notify_inbound_bytes(bob.api.host_ctx,
                                           conn,
                                           framed->data(), framed->size()),
              GN_OK);

    EXPECT_EQ(cap.calls.load(), 1);
    EXPECT_EQ(cap.last_sender,   alice_pk);
    EXPECT_EQ(cap.last_receiver, bob_pk);
}

TEST(HostApiChain, NotifyInboundUnknownConnRejected) {
    KernelHarness h;
    const std::uint8_t bytes[] = {0};
    EXPECT_EQ(h.api.notify_inbound_bytes(h.api.host_ctx,
                                         /* unknown */ 9999,
                                         bytes, 1),
              GN_ERR_NOT_FOUND);
}

TEST(HostApiChain, NotifyInboundOverFrameLimitRejected) {
    /// `thunk_notify_inbound_bytes` caps `size` against
    /// `limits.max_frame_bytes` before any state mutation. A
    /// misbehaving link plugin that posts an oversized buffer must
    /// surface `GN_ERR_PAYLOAD_TOO_LARGE` without driving the
    /// per-conn `bytes_in` counter or reaching the security
    /// session / protocol layer.
    KernelHarness h;
    /// Force a small frame cap to make the assertion deterministic.
    gn_limits_t lim{};
    lim.max_frame_bytes = 64;
    lim.max_payload_bytes = 64;
    h.kernel->set_limits(lim);

    /// Register a connection so the lookup at the front of the
    /// thunk does not return NOT_FOUND before reaching the size
    /// check. The peer pk is irrelevant; the size cap fires first.
    PublicKey peer_pk{}; peer_pk[0] = 0xFA;
    gn_conn_id_t conn = GN_INVALID_ID;
    ASSERT_EQ(h.api.notify_connect(h.api.host_ctx,
                                    peer_pk.data(),
                                    "tcp://127.0.0.1:9100",
                                    GN_TRUST_LOOPBACK,
                                    GN_ROLE_RESPONDER,
                                    &conn),
              GN_OK);

    /// 128-byte buffer exceeds the 64-byte cap; thunk rejects.
    std::vector<std::uint8_t> oversized(128, 0xAA);
    EXPECT_EQ(h.api.notify_inbound_bytes(h.api.host_ctx, conn,
                                          oversized.data(),
                                          oversized.size()),
              GN_ERR_PAYLOAD_TOO_LARGE);

    /// `bytes_in` counter must not have been incremented.
    auto endpoint = gn_endpoint_t{};
    ASSERT_EQ(h.api.get_endpoint(h.api.host_ctx, conn, &endpoint), GN_OK);
    EXPECT_EQ(endpoint.bytes_in, 0u)
        << "rejected oversized frame must not bump bytes_in counter";
}

TEST(HostApiChain, LimitsSlotReturnsKernelLimits) {
    KernelHarness h;
    gn_limits_t lim{};
    lim.max_connections = 1234;
    h.kernel->set_limits(lim);

    const gn_limits_t* got = h.api.limits(h.api.host_ctx);
    ASSERT_NE(got, nullptr);
    EXPECT_EQ(got->max_connections, 1234u);
}

TEST(HostApiChain, NotifyConnectRejectedFromHandlerKind) {
    /// Loader-side entries are reserved for transport plugins. A
    /// handler / security / protocol plugin attempting to call
    /// `notify_connect` is rejected with `GN_ERR_NOT_IMPLEMENTED`
    /// — phantom connection records would corrupt the registry.
    KernelHarness h;
    h.plugin_ctx.kind = GN_PLUGIN_KIND_HANDLER;

    std::uint8_t pk[GN_PUBLIC_KEY_BYTES] = {};
    pk[0] = 0xAA;
    gn_conn_id_t out = GN_INVALID_ID;
    EXPECT_EQ(h.api.notify_connect(h.api.host_ctx, pk,
                                    "tcp://1.2.3.4:9000",
                                    GN_TRUST_UNTRUSTED,
                                    GN_ROLE_INITIATOR, &out),
              GN_ERR_NOT_IMPLEMENTED);
    EXPECT_EQ(out, GN_INVALID_ID);
    EXPECT_EQ(h.kernel->connections().size(), 0u);
}

TEST(HostApiChain, NotifyDisconnectRejectedFromSecurityKind) {
    KernelHarness h;
    h.plugin_ctx.kind = GN_PLUGIN_KIND_SECURITY;
    EXPECT_EQ(h.api.notify_disconnect(h.api.host_ctx,
                                       /*conn*/ 7, GN_OK),
              GN_ERR_NOT_IMPLEMENTED);
}

TEST(HostApiChain, KickHandshakeRejectedFromProtocolKind) {
    KernelHarness h;
    h.plugin_ctx.kind = GN_PLUGIN_KIND_PROTOCOL;
    EXPECT_EQ(h.api.kick_handshake(h.api.host_ctx, /*conn*/ 7),
              GN_ERR_NOT_IMPLEMENTED);
}
