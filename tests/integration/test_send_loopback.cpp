/// @file   tests/integration/test_send_loopback.cpp
/// @brief  Full host_api round-trip through a paired in-memory transport.
///
/// Builds two kernels (Alice and Bob) and pairs a minimal loopback
/// transport between them: bytes pushed into one kernel's send slot
/// land in the other kernel's notify_inbound_bytes slot. Asserts the
/// receiver-side handler fires with the original payload.
///
/// Exercises every host_api slot wired so far end-to-end:
/// register_vtable(KIND), notify_connect, send,
/// notify_inbound_bytes (driven by the loopback peer), and the
/// downstream Router → IHandler dispatch.

#include <atomic>
#include <cstring>
#include <memory>
#include <vector>

#include <gtest/gtest.h>

#include <core/kernel/connection_context.hpp>
#include <core/kernel/host_api_builder.hpp>
#include <core/kernel/kernel.hpp>
#include <core/kernel/plugin_anchor.hpp>
#include <core/kernel/plugin_context.hpp>

#include <plugins/protocols/gnet/protocol.hpp>

#include <sdk/handler.h>
#include <sdk/link.h>
#include <sdk/types.h>

namespace {

using namespace gn;
using namespace gn::core;
using namespace gn::plugins::gnet;

/// Paired loopback transport. Each instance holds the peer kernel's
/// host_api and the connection id allocated on the peer side; bytes
/// pushed through `do_send` land in the peer's notify_inbound_bytes.
struct Loopback {
    host_api_t*  peer_api = nullptr;
    gn_conn_id_t peer_conn = GN_INVALID_ID;
    std::atomic<int> sends{0};

    static const char* do_scheme(void*) { return "loopback"; }

    static gn_result_t do_send(void* self,
                               gn_conn_id_t /*conn*/,
                               const std::uint8_t* bytes,
                               size_t size) {
        auto* l = static_cast<Loopback*>(self);
        l->sends.fetch_add(1);
        if (!l->peer_api || !l->peer_api->notify_inbound_bytes) {
            return GN_ERR_NOT_IMPLEMENTED;
        }
        return l->peer_api->notify_inbound_bytes(
            l->peer_api->host_ctx, l->peer_conn, bytes, size);
    }

    static gn_result_t do_listen(void*, const char*) { return GN_OK; }
    static gn_result_t do_connect(void*, const char*) { return GN_OK; }
    static gn_result_t do_send_batch(void*, gn_conn_id_t,
                                     const gn_byte_span_t*, size_t) {
        return GN_ERR_NOT_IMPLEMENTED;
    }
    static gn_result_t do_disconnect(void*, gn_conn_id_t) { return GN_OK; }
    static const char* do_extension_name(void*) { return ""; }
    static const void* do_extension_vtable(void*) { return nullptr; }
    static void        do_destroy(void*) {}

    static gn_link_vtable_t make_vtable() {
        gn_link_vtable_t v{};
        v.api_size           = sizeof(gn_link_vtable_t);
        v.scheme             = &do_scheme;
        v.listen             = &do_listen;
        v.connect            = &do_connect;
        v.send               = &do_send;
        v.send_batch         = &do_send_batch;
        v.disconnect         = &do_disconnect;
        v.extension_name     = &do_extension_name;
        v.extension_vtable   = &do_extension_vtable;
        v.destroy            = &do_destroy;
        return v;
    }
};

struct Capture {
    std::atomic<int> calls{0};
    std::vector<std::uint8_t> last_payload;
    std::uint32_t last_msg_id{0};

    static gn_propagation_t handle(void* self, const gn_message_t* env) {
        auto* c = static_cast<Capture*>(self);
        c->last_msg_id = env->msg_id;
        c->last_payload.assign(env->payload, env->payload + env->payload_size);
        c->calls.fetch_add(1);
        return GN_PROP_CONSUMED;
    }
};

/// One kernel + paired loopback transport + populated host_api.
struct Node {
    std::unique_ptr<Kernel>       kernel = std::make_unique<Kernel>();
    std::shared_ptr<GnetProtocol> proto  = std::make_shared<GnetProtocol>();
    PluginContext                 plugin_ctx;
    host_api_t                    api{};
    Loopback                      loop{};
    PublicKey                     pk{};

    Node(std::string name, std::uint8_t pk_seed) {
        kernel->set_protocol_layer(proto);
        plugin_ctx.plugin_name = std::move(name);
        plugin_ctx.kernel      = kernel.get();
        api = build_host_api(plugin_ctx);
        pk[0] = pk_seed;
        kernel->identities().add(pk);
    }
};

} // namespace

TEST(SendLoopback, RoundTripThroughHostApi) {
    Node alice("test-alice", 0xA1);
    Node bob  ("test-bob",   0xB2);

    /// Each side registers its loopback transport with its own kernel.
    static auto loopback_vt = Loopback::make_vtable();
    gn_link_id_t alice_t = GN_INVALID_ID;
    gn_link_id_t bob_t   = GN_INVALID_ID;
    ASSERT_EQ(alice.api.register_vtable(alice.api.host_ctx, GN_REGISTER_LINK,
        []{ static gn_register_meta_t mt{}; mt.api_size = sizeof(gn_register_meta_t); mt.name = "loopback"; return &mt; }(),
        &loopback_vt, &alice.loop, &alice_t), GN_OK);
    ASSERT_EQ(bob.api.register_vtable(bob.api.host_ctx, GN_REGISTER_LINK,
        []{ static gn_register_meta_t mt{}; mt.api_size = sizeof(gn_register_meta_t); mt.name = "loopback"; return &mt; }(),
        &loopback_vt, &bob.loop, &bob_t), GN_OK);

    /// Connections from each side's view: Alice has a connection to
    /// Bob through "loopback", Bob mirrors. Each side allocates its
    /// own conn_id; the loopbacks cross-wire those ids so payloads
    /// sent on Alice's conn arrive on Bob's conn.
    gn_conn_id_t alice_conn = GN_INVALID_ID;
    gn_conn_id_t bob_conn   = GN_INVALID_ID;
    ASSERT_EQ(alice.api.notify_connect(alice.api.host_ctx,
                                       bob.pk.data(),
                                       "loopback://bob",
                                       "loopback",
                                       GN_TRUST_PEER,
                                       GN_ROLE_INITIATOR,
                                       &alice_conn), GN_OK);
    ASSERT_EQ(bob.api.notify_connect(bob.api.host_ctx,
                                     alice.pk.data(),
                                     "loopback://alice",
                                     "loopback",
                                     GN_TRUST_PEER,
                                     GN_ROLE_RESPONDER,
                                     &bob_conn), GN_OK);

    alice.loop.peer_api  = &bob.api;
    alice.loop.peer_conn = bob_conn;
    bob.loop.peer_api    = &alice.api;
    bob.loop.peer_conn   = alice_conn;

    /// Bob registers a capturing handler.
    Capture cap;
    gn_handler_vtable_t vt{};
    vt.api_size       = sizeof(gn_handler_vtable_t);
    vt.handle_message = &Capture::handle;
    gn_handler_id_t hid = GN_INVALID_ID;
    ASSERT_EQ(bob.api.register_vtable(bob.api.host_ctx, GN_REGISTER_HANDLER,
        []{ static gn_register_meta_t mt{}; mt.api_size = sizeof(gn_register_meta_t); mt.name = "gnet-v1"; mt.msg_id = 0xCAFE; mt.priority = 128; return &mt; }(),
        &vt, &cap, &hid), GN_OK);

    /// Alice sends a message; the chain runs:
    ///   send → frame → loopback.send → bob.notify_inbound_bytes
    ///        → deframe → router → handler.handle_message
    const std::uint8_t payload[] = {0xDE, 0xAD, 0xBE, 0xEF};
    ASSERT_EQ(alice.api.send(alice.api.host_ctx,
                             alice_conn,
                             0xCAFE,
                             payload, sizeof(payload)), GN_OK);

    EXPECT_EQ(alice.loop.sends.load(), 1);
    EXPECT_EQ(cap.calls.load(), 1);
    EXPECT_EQ(cap.last_msg_id, 0xCAFEu);
    ASSERT_EQ(cap.last_payload.size(), 4u);
    EXPECT_EQ(cap.last_payload[0], 0xDE);
    EXPECT_EQ(cap.last_payload[3], 0xEF);
}

TEST(SendLoopback, SendUnknownConnectionRejected) {
    Node alice("test-alice", 0xA1);
    static auto loopback_vt = Loopback::make_vtable();
    gn_link_id_t alice_t = GN_INVALID_ID;
    ASSERT_EQ(alice.api.register_vtable(alice.api.host_ctx, GN_REGISTER_LINK,
        []{ static gn_register_meta_t mt{}; mt.api_size = sizeof(gn_register_meta_t); mt.name = "loopback"; return &mt; }(),
        &loopback_vt, &alice.loop, &alice_t), GN_OK);
    EXPECT_EQ(alice.api.send(alice.api.host_ctx,
                             /* unknown */ 9999,
                             0x1, nullptr, 0),
              GN_ERR_NOT_FOUND);
}

TEST(SendLoopback, DisconnectThroughTransport) {
    Node alice("test-alice", 0xA1);
    static auto loopback_vt = Loopback::make_vtable();
    gn_link_id_t alice_t = GN_INVALID_ID;
    ASSERT_EQ(alice.api.register_vtable(alice.api.host_ctx, GN_REGISTER_LINK,
        []{ static gn_register_meta_t mt{}; mt.api_size = sizeof(gn_register_meta_t); mt.name = "loopback"; return &mt; }(),
        &loopback_vt, &alice.loop, &alice_t), GN_OK);

    PublicKey peer_pk{};
    peer_pk[0] = 0xB2;
    gn_conn_id_t conn = GN_INVALID_ID;
    ASSERT_EQ(alice.api.notify_connect(alice.api.host_ctx,
                                       peer_pk.data(),
                                       "loopback://peer",
                                       "loopback",
                                       GN_TRUST_PEER,
                                       GN_ROLE_INITIATOR,
                                       &conn), GN_OK);

    /// disconnect routes through the transport vtable; loopback's
    /// stub disconnect returns GN_OK without notifying back.
    EXPECT_EQ(alice.api.disconnect(alice.api.host_ctx, conn), GN_OK);
}

TEST(SendLoopback, CrossPluginConnIdRejected) {
    /// security-trust.md §6a: only the link plugin that registered
    /// the scheme backing a connection may drive its host_api conn_id
    /// thunks. A second plugin attempting `notify_inbound_bytes` /
    /// `notify_disconnect` / `notify_link_event` / `kick_handshake`
    /// on a foreign connection sees `GN_ERR_NOT_FOUND` (the same
    /// shape as a missing conn id, so the existence of the foreign
    /// connection is not leaked through the error code).
    Node alice("test-alice", 0xA1);

    /// Alice the link plugin must carry a real anchor; the in-tree
    /// fixture default is null which the ownership check treats as
    /// permissive on purpose. Re-build the host_api after pinning
    /// the anchor so the link entry's `lifetime_anchor` matches.
    alice.plugin_ctx.plugin_anchor = std::make_shared<PluginAnchor>();
    alice.api = build_host_api(alice.plugin_ctx);

    static auto loopback_vt = Loopback::make_vtable();
    gn_link_id_t alice_t = GN_INVALID_ID;
    ASSERT_EQ(alice.api.register_vtable(alice.api.host_ctx, GN_REGISTER_LINK,
        []{ static gn_register_meta_t mt{}; mt.api_size = sizeof(gn_register_meta_t); mt.name = "loopback"; return &mt; }(),
        &loopback_vt, &alice.loop, &alice_t), GN_OK);

    PublicKey peer_pk{};
    peer_pk[0] = 0xC3;
    gn_conn_id_t conn = GN_INVALID_ID;
    ASSERT_EQ(alice.api.notify_connect(alice.api.host_ctx,
                                       peer_pk.data(),
                                       "loopback://peer",
                                       "loopback",
                                       GN_TRUST_PEER,
                                       GN_ROLE_INITIATOR,
                                       &conn), GN_OK);

    /// A second plugin (eve) shares the kernel but holds a fresh
    /// anchor that does not match the loopback link's.
    PluginContext eve_ctx;
    eve_ctx.plugin_name = "test-eve";
    eve_ctx.kernel = alice.kernel.get();
    eve_ctx.plugin_anchor = std::make_shared<PluginAnchor>();
    auto eve_api = build_host_api(eve_ctx);

    const std::uint8_t bytes[] = {0xDE, 0xAD};
    EXPECT_EQ(eve_api.notify_inbound_bytes(eve_api.host_ctx, conn,
                                           bytes, sizeof(bytes)),
              GN_ERR_NOT_FOUND);
    EXPECT_EQ(eve_api.notify_disconnect(eve_api.host_ctx, conn, GN_OK),
              GN_ERR_NOT_FOUND);
    EXPECT_EQ(eve_api.notify_backpressure(eve_api.host_ctx, conn,
                                          GN_CONN_EVENT_BACKPRESSURE_SOFT, 0),
              GN_ERR_NOT_FOUND);
    EXPECT_EQ(eve_api.kick_handshake(eve_api.host_ctx, conn),
              GN_OK);  /// no session bound — early return precedes the gate

    /// The connection record survives the foreign attempts.
    EXPECT_EQ(alice.kernel->connections().size(), 1u);

    /// Alice retains full access to her own connection.
    EXPECT_EQ(alice.api.notify_disconnect(alice.api.host_ctx, conn, GN_OK),
              GN_OK);
    EXPECT_EQ(alice.kernel->connections().size(), 0u);
}
