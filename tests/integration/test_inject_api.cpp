/// @file   tests/integration/test_inject_api.cpp
/// @brief  Bridge-tier injection paths per host-api.md §8 — driven
///         through the host_api thunks exactly as a plugin would.

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
    std::uint32_t    last_msg_id{};
    PublicKey        last_sender{};
    PublicKey        last_receiver{};
    gn_conn_id_t     last_conn_id{GN_INVALID_ID};
    std::uint32_t    last_api_size{0};
    std::vector<std::uint8_t> last_payload;

    static gn_propagation_t handle(void* self, const gn_message_t* env) {
        auto* c = static_cast<Capture*>(self);
        c->last_msg_id = env->msg_id;
        std::memcpy(c->last_sender.data(),   env->sender_pk,   GN_PUBLIC_KEY_BYTES);
        std::memcpy(c->last_receiver.data(), env->receiver_pk, GN_PUBLIC_KEY_BYTES);
        c->last_conn_id  = env->conn_id;
        c->last_api_size = env->api_size;
        c->last_payload.assign(env->payload, env->payload + env->payload_size);
        c->calls.fetch_add(1);
        return GN_PROPAGATION_CONSUMED;
    }
};

struct KernelHarness {
    std::unique_ptr<Kernel>       kernel = std::make_unique<Kernel>();
    std::shared_ptr<GnetProtocol> proto  = std::make_shared<GnetProtocol>();
    PluginContext                 plugin_ctx;
    host_api_t                    api{};

    KernelHarness() {
        kernel->set_protocol_layer(proto);
        plugin_ctx.plugin_name = "inject-test";
        plugin_ctx.kernel      = kernel.get();
        api = build_host_api(plugin_ctx);
    }

    /// Add a local identity so the kernel populates `receiver_pk` on
    /// injected envelopes.
    void install_local_identity(const PublicKey& pk) {
        kernel->identities().add(pk);
    }

    /// Register one connection that becomes the injection source.
    gn_conn_id_t make_source(const PublicKey& remote_pk,
                              gn_trust_class_t trust = GN_TRUST_PEER) {
        gn_conn_id_t id = GN_INVALID_ID;
        EXPECT_EQ(api.notify_connect(api.host_ctx,
                                      remote_pk.data(),
                                      "ipc:///tmp/test-bridge",
                                      "ipc",
                                      trust,
                                      GN_ROLE_RESPONDER,
                                      &id),
                  GN_OK);
        return id;
    }
};

}  // namespace

// ── inject (LAYER_MESSAGE) ───────────────────────────────────────────────

TEST(InjectExternal, HappyPathDispatchesEnvelope) {
    KernelHarness h;
    PublicKey local_pk; local_pk.fill(0xAA);
    PublicKey peer_pk;  peer_pk.fill(0xBB);
    h.install_local_identity(local_pk);

    Capture cap;
    gn_handler_vtable_t vt{};
    vt.api_size       = sizeof(gn_handler_vtable_t);
    vt.handle_message = &Capture::handle;
    gn_handler_id_t hid = GN_INVALID_ID;
    ASSERT_EQ(h.api.register_vtable(h.api.host_ctx, GN_REGISTER_HANDLER,
        []{ static gn_register_meta_t mt{}; mt.api_size = sizeof(gn_register_meta_t); mt.name = "gnet-v1"; mt.msg_id = 0x77; mt.priority = 128; return &mt; }(),
        &vt, &cap, &hid),
              GN_OK);

    const gn_conn_id_t src = h.make_source(peer_pk);
    const std::uint8_t payload[] = {1, 2, 3, 4};
    EXPECT_EQ(h.api.inject(h.api.host_ctx, GN_INJECT_LAYER_MESSAGE, src,
                                             /*msg_id*/ 0x77,
                                             payload, sizeof(payload)),
              GN_OK);

    EXPECT_EQ(cap.calls.load(), 1);
    EXPECT_EQ(cap.last_msg_id, 0x77u);
    EXPECT_EQ(cap.last_sender,   peer_pk);
    EXPECT_EQ(cap.last_receiver, local_pk);
    /// Per `host-api.md` §8: kernel stamps `env.conn_id = source` so
    /// conn-aware handlers (heartbeat RTT, future per-link gates) can
    /// route back through the bridge edge directly. Pre-fix this read
    /// zero (build_envelope zero-inits, no stamp site in thunk_inject).
    EXPECT_EQ(cap.last_conn_id, src);
    /// Kernel stamps `api_size = sizeof(gn_message_t)` at the same
    /// site so handlers compiled against later v1.x SDKs see the
    /// kernel-stamped fields through `GN_API_HAS`. Pre-fix this read
    /// zero (build_envelope zero-inits api_size).
    EXPECT_EQ(cap.last_api_size, sizeof(gn_message_t));
    EXPECT_EQ(cap.last_payload,
              std::vector<std::uint8_t>(payload, payload + sizeof(payload)));
}

TEST(InjectExternal, ReservedSystemMsgIdRejected) {
    /// `attestation.md §3` reserves msg_id 0x11 for the kernel-internal
    /// dispatcher. `notify_inbound_bytes` intercepts and routes to
    /// the dispatcher with the conn's own session; injected envelopes
    /// can't legitimately drive that path (the bridge IPC's session
    /// is not the originator-to-relay session attestation needs), so
    /// the thunk rejects up front. Mirrors the registration-side
    /// rejection at `is_reserved_system_msg_id`.
    KernelHarness h;
    PublicKey peer_pk; peer_pk.fill(0xF1);
    const gn_conn_id_t src = h.make_source(peer_pk);
    const std::uint8_t payload[] = {0};
    EXPECT_EQ(h.api.inject(h.api.host_ctx, GN_INJECT_LAYER_MESSAGE, src,
                            /*msg_id*/ 0x11,
                            payload, sizeof(payload)),
              GN_ERR_INVALID_ENVELOPE);
}

TEST(InjectExternal, UnknownSourceRejected) {
    KernelHarness h;
    const std::uint8_t payload[] = {0};
    EXPECT_EQ(h.api.inject(h.api.host_ctx, GN_INJECT_LAYER_MESSAGE,
                            /*source*/ 9999, 0x42,
                            payload, sizeof(payload)),
              GN_ERR_NOT_FOUND);
}

TEST(InjectExternal, ZeroMsgIdRejected) {
    KernelHarness h;
    PublicKey peer_pk; peer_pk.fill(0xCC);
    const gn_conn_id_t src = h.make_source(peer_pk);
    const std::uint8_t payload[] = {0};
    EXPECT_EQ(h.api.inject(h.api.host_ctx, GN_INJECT_LAYER_MESSAGE, src,
                                             /*msg_id*/ 0,
                                             payload, sizeof(payload)),
              GN_ERR_INVALID_ENVELOPE);
}

TEST(InjectExternal, NullPayloadWithSizeRejected) {
    KernelHarness h;
    PublicKey peer_pk; peer_pk.fill(0xDD);
    const gn_conn_id_t src = h.make_source(peer_pk);
    EXPECT_EQ(h.api.inject(h.api.host_ctx, GN_INJECT_LAYER_MESSAGE, src,
                                             /*msg_id*/ 0x10,
                                             /*payload*/ nullptr,
                                             /*size*/ 8),
              GN_ERR_NULL_ARG);
}

TEST(InjectExternal, EmptyPayloadAccepted) {
    KernelHarness h;
    PublicKey local_pk; local_pk.fill(0x11);
    PublicKey peer_pk;  peer_pk.fill(0x22);
    h.install_local_identity(local_pk);

    Capture cap;
    gn_handler_vtable_t vt{};
    vt.api_size       = sizeof(gn_handler_vtable_t);
    vt.handle_message = &Capture::handle;
    gn_handler_id_t hid = GN_INVALID_ID;
    ASSERT_EQ(h.api.register_vtable(h.api.host_ctx, GN_REGISTER_HANDLER,
        []{ static gn_register_meta_t mt{}; mt.api_size = sizeof(gn_register_meta_t); mt.name = "gnet-v1"; mt.msg_id = 0x55; mt.priority = 128; return &mt; }(),
        &vt, &cap, &hid),
              GN_OK);

    const gn_conn_id_t src = h.make_source(peer_pk);
    EXPECT_EQ(h.api.inject(h.api.host_ctx, GN_INJECT_LAYER_MESSAGE, src,
                                             /*msg_id*/ 0x55,
                                             /*payload*/ nullptr,
                                             /*size*/ 0),
              GN_OK);
    EXPECT_EQ(cap.calls.load(), 1);
    EXPECT_TRUE(cap.last_payload.empty());
}

TEST(InjectExternal, PayloadOverLimitRejected) {
    KernelHarness h;
    /// Set a small payload limit and verify the thunk enforces it.
    gn_limits_t limits{};
    limits.max_payload_bytes = 16;
    limits.max_frame_bytes   = 1024;
    h.kernel->set_limits(limits);

    PublicKey peer_pk; peer_pk.fill(0xEE);
    const gn_conn_id_t src = h.make_source(peer_pk);

    std::vector<std::uint8_t> big(32, 0xAB);
    EXPECT_EQ(h.api.inject(h.api.host_ctx, GN_INJECT_LAYER_MESSAGE, src,
                                             /*msg_id*/ 0x10,
                                             big.data(), big.size()),
              GN_ERR_PAYLOAD_TOO_LARGE);
}

// ── inject (LAYER_FRAME) ─────────────────────────────────────────────────

TEST(InjectFrame, RejectsUnknownSource) {
    KernelHarness h;
    const std::uint8_t buf[] = {0};
    EXPECT_EQ(h.api.inject(h.api.host_ctx, GN_INJECT_LAYER_FRAME, /*source*/ 4242, 0,
                                  buf, sizeof(buf)),
              GN_ERR_NOT_FOUND);
}

TEST(InjectFrame, MalformedFrameReturnsDeframerError) {
    KernelHarness h;
    PublicKey peer_pk; peer_pk.fill(0x33);
    const gn_conn_id_t src = h.make_source(peer_pk);

    /// A handful of arbitrary bytes that will not parse as a valid
    /// gnet header — the protocol layer rejects with its own code.
    const std::uint8_t junk[] = {0xDE, 0xAD, 0xBE, 0xEF};
    EXPECT_NE(h.api.inject(h.api.host_ctx, GN_INJECT_LAYER_FRAME, src, 0,
                                  junk, sizeof(junk)),
              GN_OK);
}

TEST(InjectFrame, EmptyBufferTreatedAsIncomplete) {
    KernelHarness h;
    PublicKey peer_pk; peer_pk.fill(0x44);
    const gn_conn_id_t src = h.make_source(peer_pk);

    /// Zero-byte input through `inject(LAYER_FRAME)`: the deframer reports
    /// incomplete; the thunk surfaces that verbatim.
    EXPECT_NE(h.api.inject(h.api.host_ctx, GN_INJECT_LAYER_FRAME, src, 0,
                                  /*frame*/ nullptr, /*size*/ 0),
              GN_OK);
}

TEST(InjectFrame, ReservedSystemMsgIdSkippedInDispatchLoop) {
    /// Inner frame carries msg_id 0x11 (attestation reserved). The
    /// inject thunk's per-envelope loop must skip these — bridge
    /// IPC's session is not the originator-to-relay session
    /// attestation needs, and routing them through the plugin chain
    /// would smuggle reserved msg_ids past `is_reserved_system_msg_id`
    /// (which gates registration). Pre-fix the loop called
    /// `route_one_envelope` and bumped `route.outcome.dropped_no_handler`
    /// (no plugin can register against 0x11). Post-fix nothing routes.
    KernelHarness h;
    PublicKey local_pk; local_pk.fill(0xA0);
    PublicKey peer_pk;  peer_pk.fill(0xB0);
    h.install_local_identity(local_pk);

    const gn_conn_id_t src = h.make_source(peer_pk);

    gn_message_t env{};
    std::memcpy(env.sender_pk,   local_pk.data(), 32);
    std::memcpy(env.receiver_pk, peer_pk.data(),  32);
    env.msg_id = 0x11;
    const std::uint8_t payload[] = {0xDE, 0xAD};
    env.payload      = payload;
    env.payload_size = 2;

    gn_connection_context_t fctx{};
    fctx.local_pk  = local_pk;
    fctx.remote_pk = peer_pk;
    auto framed = h.proto->frame(fctx, env);
    ASSERT_TRUE(framed.has_value());

    EXPECT_EQ(h.api.inject(h.api.host_ctx, GN_INJECT_LAYER_FRAME, src, 0,
                            framed->data(), framed->size()),
              GN_OK);

    EXPECT_EQ(h.kernel->metrics().value("route.outcome.dropped_no_handler"), 0u);
    EXPECT_EQ(h.kernel->metrics().value("route.outcome.dispatched_local"),   0u);
}

TEST(InjectFrame, StampsConnIdOnDispatchedEnvelopes) {
    KernelHarness h;
    PublicKey local_pk; local_pk.fill(0x55);
    PublicKey peer_pk;  peer_pk.fill(0x66);
    h.install_local_identity(local_pk);

    Capture cap;
    gn_handler_vtable_t vt{};
    vt.api_size       = sizeof(gn_handler_vtable_t);
    vt.handle_message = &Capture::handle;
    gn_handler_id_t hid = GN_INVALID_ID;
    ASSERT_EQ(h.api.register_vtable(h.api.host_ctx, GN_REGISTER_HANDLER,
        []{ static gn_register_meta_t mt{}; mt.api_size = sizeof(gn_register_meta_t); mt.name = "gnet-v1"; mt.msg_id = 0x99; mt.priority = 128; return &mt; }(),
        &vt, &cap, &hid),
              GN_OK);

    const gn_conn_id_t src = h.make_source(peer_pk);

    /// Build a direct frame (flags=0, no PK on wire) — sender =
    /// local_pk, receiver = peer_pk, framed against (local, peer)
    /// context. The conn record on the inject side carries
    /// remote_pk = peer_pk so the deframer reconstructs env with
    /// sender_pk = peer_pk (from ctx.remote_pk), receiver_pk =
    /// local_pk (from ctx.local_pk). No relay flag needed.
    gn_message_t env{};
    std::memcpy(env.sender_pk,   local_pk.data(), 32);
    std::memcpy(env.receiver_pk, peer_pk.data(),  32);
    env.msg_id = 0x99;
    const std::uint8_t payload[] = {0xCA, 0xFE};
    env.payload      = payload;
    env.payload_size = 2;

    gn_connection_context_t fctx{};
    fctx.local_pk  = local_pk;
    fctx.remote_pk = peer_pk;
    auto framed = h.proto->frame(fctx, env);
    ASSERT_TRUE(framed.has_value());

    EXPECT_EQ(h.api.inject(h.api.host_ctx, GN_INJECT_LAYER_FRAME, src, 0,
                            framed->data(), framed->size()),
              GN_OK);
    EXPECT_EQ(cap.calls.load(), 1);
    /// Per `host-api.md` §8: LAYER_FRAME stamps `env.conn_id = source`
    /// on every dispatched envelope, mirroring `notify_inbound_bytes`
    /// post-deframe. Pre-fix this read zero (no stamp site in the
    /// thunk's deframe loop).
    EXPECT_EQ(cap.last_conn_id, src);
    EXPECT_EQ(cap.last_api_size, sizeof(gn_message_t));
    EXPECT_EQ(cap.last_sender,   peer_pk);
    EXPECT_EQ(cap.last_receiver, local_pk);
}
