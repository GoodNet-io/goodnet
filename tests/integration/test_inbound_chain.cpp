/// @file   tests/integration/test_inbound_chain.cpp
/// @brief  GnetProtocol → Router → IHandler full inbound chain.
///
/// Builds the minimum kernel-side composition that exercises every
/// piece of the data path together: a connection context, a
/// GnetProtocol that deframes bytes into envelopes, a HandlerRegistry
/// holding a registered IHandler, and a Router that dispatches the
/// envelopes through the handler chain. The test ends-to-end checks
/// that bytes arriving on the wire reach the handler's handle_message
/// with the right `gn_message_t` content.

#include <atomic>
#include <cstring>
#include <span>
#include <vector>

#include <gtest/gtest.h>

#include <core/kernel/connection_context.hpp>
#include <core/kernel/identity_set.hpp>
#include <core/kernel/router.hpp>
#include <core/registry/handler.hpp>

#include <plugins/protocols/gnet/protocol.hpp>

#include <sdk/handler.h>
#include <sdk/types.h>

namespace {

using namespace gn;
using namespace gn::core;
using namespace gn::plugins::gnet;

/// Minimal handler that records what it received. Atomic so a future
/// concurrent dispatch test does not need to retrofit synchronisation.
struct CaptureHandler {
    std::atomic<int>          calls{0};
    std::atomic<std::uint32_t> last_msg_id{0};
    std::vector<std::uint8_t>  last_payload;
    PublicKey                  last_sender{};
    PublicKey                  last_receiver{};

    static gn_propagation_t handle(void* self, const gn_message_t* env) {
        auto* h = static_cast<CaptureHandler*>(self);
        h->last_msg_id.store(env->msg_id);
        h->last_payload.assign(env->payload, env->payload + env->payload_size);
        std::memcpy(h->last_sender.data(),   env->sender_pk,   GN_PUBLIC_KEY_BYTES);
        std::memcpy(h->last_receiver.data(), env->receiver_pk, GN_PUBLIC_KEY_BYTES);
        h->calls.fetch_add(1);
        return GN_PROPAGATION_CONSUMED;
    }
};

/// Build a vtable that points at the static handle method above.
gn_handler_vtable_t make_vtable() {
    gn_handler_vtable_t vt{};
    vt.api_size       = sizeof(gn_handler_vtable_t);
    vt.handle_message = &CaptureHandler::handle;
    return vt;
}

/// Construct paired contexts where Alice and Bob each see the
/// connection from their own perspective.
struct PairedContexts {
    gn_connection_context_t alice;
    gn_connection_context_t bob;

    static PairedContexts make(std::uint8_t alice_seed, std::uint8_t bob_seed) {
        PairedContexts p{};
        p.alice.local_pk[0]  = alice_seed;
        p.alice.remote_pk[0] = bob_seed;
        p.alice.conn_id      = 1;

        p.bob.local_pk[0]  = bob_seed;
        p.bob.remote_pk[0] = alice_seed;
        p.bob.conn_id      = 1;
        return p;
    }
};

/// Drive the inbound chain: deframe `bytes` through `proto` against
/// `ctx`, then route each resulting envelope through `router`.
RouteOutcome run_inbound(GnetProtocol&            proto,
                         Router&                  router,
                         gn_connection_context_t& ctx,
                         std::span<const std::uint8_t> bytes) {
    auto deframed = proto.deframe(ctx, bytes);
    if (!deframed.has_value()) return RouteOutcome::Rejected;

    RouteOutcome final_outcome = RouteOutcome::DispatchedLocal;
    for (const auto& env : deframed->messages) {
        final_outcome = router.route_inbound(proto.protocol_id(), env);
    }
    return final_outcome;
}

} // namespace

// ── Direct: Alice frames, Bob deframes + routes to handler ─────────────────

TEST(InboundChain, DirectFrameReachesHandler) {
    auto ctxs = PairedContexts::make(0xA1, 0xB1);

    LocalIdentityRegistry ids;
    ids.add(ctxs.bob.local_pk);

    HandlerRegistry handlers;
    Router          router(ids, handlers);

    CaptureHandler cap;
    auto vt = make_vtable();
    gn_handler_id_t hid;
    ASSERT_EQ(handlers.register_handler("gnet-v1", 0x42, 128, &vt, &cap, &hid),
              GN_OK);

    GnetProtocol alice;
    GnetProtocol bob;

    gn_message_t env{};
    std::memcpy(env.sender_pk,   ctxs.alice.local_pk.data(),  32);
    std::memcpy(env.receiver_pk, ctxs.alice.remote_pk.data(), 32);
    env.msg_id = 0x42;
    const std::uint8_t payload[] = {0x10, 0x20, 0x30, 0x40};
    env.payload      = payload;
    env.payload_size = sizeof(payload);

    auto framed = alice.frame(ctxs.alice, env);
    ASSERT_TRUE(framed.has_value());

    auto outcome = run_inbound(bob, router, ctxs.bob, *framed);
    ASSERT_EQ(outcome, RouteOutcome::DispatchedLocal);

    EXPECT_EQ(cap.calls.load(), 1);
    EXPECT_EQ(cap.last_msg_id.load(), 0x42u);
    ASSERT_EQ(cap.last_payload.size(), 4u);
    EXPECT_EQ(cap.last_payload[0], 0x10);
    /// Bob sees sender = Alice (his remote).
    EXPECT_EQ(cap.last_sender,   ctxs.bob.remote_pk);
    /// Bob sees receiver = himself (his local).
    EXPECT_EQ(cap.last_receiver, ctxs.bob.local_pk);
}

// ── Broadcast: receiver_pk == ZERO, sender on wire ─────────────────────────

TEST(InboundChain, BroadcastFrameDispatches) {
    auto ctxs = PairedContexts::make(0xA2, 0xB2);
    /// Broadcast carries EXPLICIT_SENDER; receiving context must
    /// declare relay capability (`gnet-protocol.md` §5).
    ctxs.bob.allows_relay = true;

    LocalIdentityRegistry ids;
    ids.add(ctxs.bob.local_pk);

    HandlerRegistry handlers;
    Router          router(ids, handlers);

    CaptureHandler cap;
    auto vt = make_vtable();
    gn_handler_id_t hid;
    ASSERT_EQ(handlers.register_handler("gnet-v1", 0x99, 128, &vt, &cap, &hid),
              GN_OK);

    GnetProtocol alice;
    GnetProtocol bob;

    gn_message_t env{};
    std::memcpy(env.sender_pk, ctxs.alice.local_pk.data(), 32);
    /// receiver_pk left zero → broadcast.
    env.msg_id = 0x99;
    env.payload      = nullptr;
    env.payload_size = 0;

    auto framed = alice.frame(ctxs.alice, env);
    ASSERT_TRUE(framed.has_value());

    auto outcome = run_inbound(bob, router, ctxs.bob, *framed);
    ASSERT_EQ(outcome, RouteOutcome::DispatchedBroadcast);

    EXPECT_EQ(cap.calls.load(), 1);
    /// Sender from the wire (Alice).
    EXPECT_EQ(cap.last_sender, ctxs.bob.remote_pk);
    PublicKey zero{};
    EXPECT_EQ(cap.last_receiver, zero);
}

// ── Two frames in one buffer, both dispatched ──────────────────────────────

TEST(InboundChain, MultiFrameBufferRoutesEach) {
    auto ctxs = PairedContexts::make(0xA3, 0xB3);

    LocalIdentityRegistry ids;
    ids.add(ctxs.bob.local_pk);

    HandlerRegistry handlers;
    Router          router(ids, handlers);

    CaptureHandler cap;
    auto vt = make_vtable();
    gn_handler_id_t hid;
    ASSERT_EQ(handlers.register_handler("gnet-v1", 0x7, 128, &vt, &cap, &hid),
              GN_OK);

    GnetProtocol alice;
    GnetProtocol bob;

    gn_message_t env{};
    std::memcpy(env.sender_pk,   ctxs.alice.local_pk.data(),  32);
    std::memcpy(env.receiver_pk, ctxs.alice.remote_pk.data(), 32);
    env.msg_id = 0x7;
    const std::uint8_t payload[] = {0xAB};
    env.payload      = payload;
    env.payload_size = 1;

    auto f1 = alice.frame(ctxs.alice, env);
    auto f2 = alice.frame(ctxs.alice, env);
    ASSERT_TRUE(f1.has_value());
    ASSERT_TRUE(f2.has_value());

    std::vector<std::uint8_t> combined;
    combined.insert(combined.end(), f1->begin(), f1->end());
    combined.insert(combined.end(), f2->begin(), f2->end());

    /// Router returns the outcome of the LAST envelope; the test cares
    /// that both fired their handler, not which RouteOutcome surfaces.
    (void)run_inbound(bob, router, ctxs.bob, combined);
    EXPECT_EQ(cap.calls.load(), 2);
}

// ── Receiver not in identity set + no relay → DroppedUnknownReceiver ────────

TEST(InboundChain, UnknownReceiverDroppedWithoutRelay) {
    auto ctxs = PairedContexts::make(0xA4, 0xB4);

    /// IdentitySet does NOT include Bob's local pk, so the inbound
    /// envelope's receiver_pk does not match any local identity.
    LocalIdentityRegistry ids;
    HandlerRegistry  handlers;
    Router           router(ids, handlers);

    GnetProtocol alice;
    GnetProtocol bob;

    gn_message_t env{};
    std::memcpy(env.sender_pk,   ctxs.alice.local_pk.data(),  32);
    std::memcpy(env.receiver_pk, ctxs.alice.remote_pk.data(), 32);
    env.msg_id = 0xC0DE;
    env.payload      = nullptr;
    env.payload_size = 0;

    auto framed = alice.frame(ctxs.alice, env);
    ASSERT_TRUE(framed.has_value());

    auto outcome = run_inbound(bob, router, ctxs.bob, *framed);
    EXPECT_EQ(outcome, RouteOutcome::DroppedUnknownReceiver);
}
