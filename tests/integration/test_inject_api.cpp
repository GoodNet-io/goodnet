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
    std::vector<std::uint8_t> last_payload;

    static gn_propagation_t handle(void* self, const gn_message_t* env) {
        auto* c = static_cast<Capture*>(self);
        c->last_msg_id = env->msg_id;
        std::memcpy(c->last_sender.data(),   env->sender_pk,   GN_PUBLIC_KEY_BYTES);
        std::memcpy(c->last_receiver.data(), env->receiver_pk, GN_PUBLIC_KEY_BYTES);
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

// ── inject (LAYER_MESSAGE) ────────────────────────────────────────

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
    EXPECT_EQ(cap.last_payload,
              std::vector<std::uint8_t>(payload, payload + sizeof(payload)));
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

// ── inject (LAYER_FRAME) ───────────────────────────────────────────────────

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
