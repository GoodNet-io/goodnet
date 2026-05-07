/// @file   plugins/protocols/gnet/tests/test_protocol.cpp
/// @brief  GoogleTest cases for `gn::plugins::gnet::GnetProtocol`.
///
/// Pins the IProtocolLayer envelope semantics from
/// `docs/contracts/protocol-layer.en.md` against the GNET wire-format from
/// `plugins/protocols/gnet/docs/wire-format.md`:
///
///   §3.1 / §5  — direct mode: no PK on wire, identity sourced from ctx
///   §3.2 / §5  — broadcast: sender on wire, receiver_pk == ZERO
///   §3.3 / §5  — relay-transit: both PKs on wire, end-to-end preserved
///   §4         — multi-frame, partial-frame, corrupt-frame parser states
///   §8         — `frame` rejection of malformed envelopes
///
/// Round-trip property tests live next to this file in
/// `test_protocol_property.cpp`.

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <string_view>
#include <vector>

#include <core/kernel/connection_context.hpp>
#include <plugins/protocols/gnet/protocol.hpp>
#include <plugins/protocols/gnet/wire.hpp>
#include <sdk/cpp/types.hpp>
#include <sdk/trust.h>
#include <sdk/types.h>

namespace gn::plugins::gnet {
namespace {

/* ── Test helpers ────────────────────────────────────────────────────────── */

/// Build a deterministic public key from a 64-bit seed; the first 8
/// bytes carry the seed, the rest are zero. The seed must be non-zero
/// to avoid the all-zero broadcast marker.
PublicKey make_pk(std::uint64_t seed) noexcept {
    PublicKey pk{};
    std::memcpy(pk.data(), &seed, sizeof(seed));
    return pk;
}

/// Pair of mirrored connection contexts: from Alice's view her local pk
/// is `alice_pk` and her remote is `bob_pk`; from Bob's view they swap.
/// This represents a single Noise tunnel observed by both endpoints.
struct MirroredContexts {
    PublicKey               alice_pk;
    PublicKey               bob_pk;
    gn_connection_context_t alice;  ///< Alice's view: local=Alice, remote=Bob
    gn_connection_context_t bob;    ///< Bob's view:   local=Bob,   remote=Alice
};

MirroredContexts make_mirrored_contexts(std::uint64_t alice_seed = 0xA11CE,
                                        std::uint64_t bob_seed   = 0xB0B) {
    MirroredContexts mc{};
    mc.alice_pk = make_pk(alice_seed);
    mc.bob_pk   = make_pk(bob_seed);

    mc.alice.local_pk  = mc.alice_pk;
    mc.alice.remote_pk = mc.bob_pk;
    mc.alice.conn_id   = 1;
    mc.alice.trust     = GN_TRUST_PEER;

    mc.bob.local_pk    = mc.bob_pk;
    mc.bob.remote_pk   = mc.alice_pk;
    mc.bob.conn_id     = 2;
    mc.bob.trust       = GN_TRUST_PEER;
    return mc;
}

/// Build an envelope with `payload` borrowed from the caller — payload
/// lifetime must outlive the call.
gn_message_t make_envelope(const PublicKey& sender,
                           const PublicKey& receiver,
                           std::uint32_t    msg_id,
                           std::span<const std::uint8_t> payload) {
    gn_message_t env{};
    std::memcpy(env.sender_pk,   sender.data(),   GN_PUBLIC_KEY_BYTES);
    std::memcpy(env.receiver_pk, receiver.data(), GN_PUBLIC_KEY_BYTES);
    env.msg_id       = msg_id;
    env.payload      = payload.data();
    env.payload_size = payload.size();
    return env;
}

/* ── protocol_id / max_payload_size ──────────────────────────────────────── */

TEST(GnetProtocolMetadata, ProtocolIdIsGnetV1) {
    GnetProtocol p;
    EXPECT_EQ(p.protocol_id(), std::string_view{"gnet-v1"});
}

TEST(GnetProtocolMetadata, MaxPayloadSizeMatchesContract) {
    /// 65536 (kMaxFrameBytes) − 14 (fixed header) − 64 (sender+receiver PK).
    GnetProtocol p;
    EXPECT_EQ(p.max_payload_size(),
              static_cast<std::size_t>(65536 - 14 - 64));
    EXPECT_EQ(p.max_payload_size(), 65458u);
}

/* ── Round-trip: direct mode ─────────────────────────────────────────────── */

TEST(GnetProtocolRoundTrip, DirectFrameNoPkOnWire) {
    /// Alice frames a message to Bob with sender=Alice, receiver=Bob.
    /// Wire size must be 14 + payload (no PK fields), and Bob's view
    /// reconstructs the envelope with sender=Bob.remote=Alice and
    /// receiver=Bob.local=Bob.
    auto mc = make_mirrored_contexts();
    GnetProtocol alice_proto, bob_proto;

    const std::array<std::uint8_t, 5> payload = {0xDE, 0xAD, 0xBE, 0xEF, 0x42};
    auto env = make_envelope(mc.alice_pk, mc.bob_pk, /*msg_id=*/0x1001, payload);

    auto framed = alice_proto.frame(mc.alice, env);
    ASSERT_TRUE(framed.has_value());
    EXPECT_EQ(framed->size(), wire::kFixedHeaderSize + payload.size());

    /// flags byte must be 0x00 — direct mode.
    EXPECT_EQ((*framed)[wire::kOffsetFlags], 0x00);

    auto deframed = bob_proto.deframe(mc.bob, *framed);
    ASSERT_TRUE(deframed.has_value());
    ASSERT_EQ(deframed->messages.size(), 1u);
    EXPECT_EQ(deframed->bytes_consumed, framed->size());

    const gn_message_t& got = deframed->messages[0];
    EXPECT_EQ(got.msg_id, 0x1001u);
    EXPECT_EQ(std::memcmp(got.sender_pk,   mc.alice_pk.data(), GN_PUBLIC_KEY_BYTES), 0);
    EXPECT_EQ(std::memcmp(got.receiver_pk, mc.bob_pk.data(),   GN_PUBLIC_KEY_BYTES), 0);
    ASSERT_EQ(got.payload_size, payload.size());
    EXPECT_EQ(std::memcmp(got.payload, payload.data(), payload.size()), 0);
}

TEST(GnetProtocolRoundTrip, DirectFrameWireBytesMatchPayload) {
    /// Direct mode: bytes after the 14-byte header are exactly the
    /// payload, with no intervening PK fields.
    auto mc = make_mirrored_contexts();
    GnetProtocol p;

    const std::array<std::uint8_t, 7> payload = {1, 2, 3, 4, 5, 6, 7};
    auto env = make_envelope(mc.alice_pk, mc.bob_pk, /*msg_id=*/9, payload);

    auto framed = p.frame(mc.alice, env);
    ASSERT_TRUE(framed.has_value());
    ASSERT_EQ(framed->size(), wire::kFixedHeaderSize + payload.size());

    for (std::size_t i = 0; i < payload.size(); ++i) {
        EXPECT_EQ((*framed)[wire::kFixedHeaderSize + i], payload[i])
            << "wire byte " << i;
    }
}

/* ── Round-trip: broadcast mode ──────────────────────────────────────────── */

TEST(GnetProtocolRoundTrip, BroadcastFrameSenderOnWireReceiverZero) {
    /// Alice broadcasts: receiver_pk = ZERO. Wire size must be
    /// 14 + 32 + payload. Bob's deframe surfaces sender=Alice (from
    /// wire) and receiver=ZERO. Broadcast carries `EXPLICIT_SENDER`,
    /// so the receiving context must declare `allows_relay` per
    /// `plugins/protocols/gnet/docs/wire-format.md` §5 — broadcast frames inherently come from
    /// a relay-shaped path.
    auto mc = make_mirrored_contexts();
    mc.bob.allows_relay = true;
    GnetProtocol alice_proto, bob_proto;

    const std::array<std::uint8_t, 4> payload = {0xCA, 0xFE, 0xBA, 0xBE};
    auto env = make_envelope(mc.alice_pk, kBroadcastPk, /*msg_id=*/77, payload);

    auto framed = alice_proto.frame(mc.alice, env);
    ASSERT_TRUE(framed.has_value());
    EXPECT_EQ(framed->size(),
              wire::kFixedHeaderSize + wire::kPublicKeySize + payload.size());
    EXPECT_EQ((*framed)[wire::kOffsetFlags],
              wire::kFlagExplicitSender | wire::kFlagBroadcast);

    auto deframed = bob_proto.deframe(mc.bob, *framed);
    ASSERT_TRUE(deframed.has_value());
    ASSERT_EQ(deframed->messages.size(), 1u);
    EXPECT_EQ(deframed->bytes_consumed, framed->size());

    const gn_message_t& got = deframed->messages[0];
    EXPECT_EQ(got.msg_id, 77u);
    EXPECT_EQ(std::memcmp(got.sender_pk, mc.alice_pk.data(), GN_PUBLIC_KEY_BYTES), 0);
    EXPECT_NE(gn_pk_is_zero(got.sender_pk), 1) << "sender must not be zero";
    EXPECT_EQ(gn_pk_is_zero(got.receiver_pk), 1)
        << "broadcast receiver_pk must be all-zero";
    ASSERT_EQ(got.payload_size, payload.size());
    EXPECT_EQ(std::memcmp(got.payload, payload.data(), payload.size()), 0);
}

/* ── Round-trip: relay-transit mode ──────────────────────────────────────── */

TEST(GnetProtocolRoundTrip, RelayTransitBothPksOnWire) {
    /// Alice forwards a message originated by ThirdParty to Bob.
    /// sender ≠ ctx.local → wire carries both PKs (78 + payload) and
    /// Bob's deframe preserves end-to-end identity.
    /// `allows_relay` declares that bob's connection trusts alice to
    /// inject foreign sender_pk values; without the flag the deframe
    /// would reject EXPLICIT_SENDER as a spoof attempt.
    auto mc = make_mirrored_contexts();
    mc.bob.allows_relay = true;
    GnetProtocol alice_proto, bob_proto;

    const PublicKey third_party = make_pk(0xC0FFEE);
    const std::array<std::uint8_t, 6> payload = {'r', 'e', 'l', 'a', 'y', '!'};
    auto env = make_envelope(third_party, mc.bob_pk,
                             /*msg_id=*/0xABCD, payload);

    auto framed = alice_proto.frame(mc.alice, env);
    ASSERT_TRUE(framed.has_value());
    EXPECT_EQ(framed->size(),
              wire::kFixedHeaderSize + 2 * wire::kPublicKeySize + payload.size());
    EXPECT_EQ((*framed)[wire::kOffsetFlags],
              wire::kFlagExplicitSender | wire::kFlagExplicitReceiver);

    auto deframed = bob_proto.deframe(mc.bob, *framed);
    ASSERT_TRUE(deframed.has_value());
    ASSERT_EQ(deframed->messages.size(), 1u);

    const gn_message_t& got = deframed->messages[0];
    EXPECT_EQ(got.msg_id, 0xABCDu);
    EXPECT_EQ(std::memcmp(got.sender_pk,   third_party.data(), GN_PUBLIC_KEY_BYTES), 0)
        << "relay-transit must preserve end-to-end sender";
    EXPECT_EQ(std::memcmp(got.receiver_pk, mc.bob_pk.data(),   GN_PUBLIC_KEY_BYTES), 0);
    ASSERT_EQ(got.payload_size, payload.size());
    EXPECT_EQ(std::memcmp(got.payload, payload.data(), payload.size()), 0);
}

TEST(GnetProtocolRoundTrip, RelayTransitForwardingPreservesEndToEnd) {
    /// A relay node holds an Alice↔Carol context but receives a frame
    /// originally framed for an Alice↔Bob path. Re-deframe through the
    /// transit-context must surface the original sender (ThirdParty)
    /// and receiver (Bob) untouched.
    auto edge_ab = make_mirrored_contexts(0xA11CE, 0xB0B);
    auto edge_ac = make_mirrored_contexts(0xA11CE, 0xCA401);  // Alice ↔ Carol
    edge_ac.bob.allows_relay = true;  /// transit context trusts the relay edge
    GnetProtocol alice_proto, transit_proto;

    const PublicKey origin = make_pk(0xDEADBEEF);
    const std::array<std::uint8_t, 3> payload = {'h', 'i', '!'};
    auto env = make_envelope(origin, edge_ab.bob_pk,
                             /*msg_id=*/0x10, payload);

    auto framed = alice_proto.frame(edge_ab.alice, env);
    ASSERT_TRUE(framed.has_value());

    /// Re-deframe through Carol's context — sender / receiver come
    /// from wire, so identity survives the swap.
    auto deframed = transit_proto.deframe(edge_ac.bob, *framed);
    ASSERT_TRUE(deframed.has_value());
    ASSERT_EQ(deframed->messages.size(), 1u);

    const gn_message_t& got = deframed->messages[0];
    EXPECT_EQ(got.msg_id, 0x10u);
    EXPECT_EQ(std::memcmp(got.sender_pk,   origin.data(),         GN_PUBLIC_KEY_BYTES), 0);
    EXPECT_EQ(std::memcmp(got.receiver_pk, edge_ab.bob_pk.data(), GN_PUBLIC_KEY_BYTES), 0);
}

TEST(GnetProtocolRoundTrip, ExplicitReceiverRejectedOnNonRelayContext) {
    /// Mirror gate to EXPLICIT_SENDER: a peer that has not been
    /// granted relay capability cannot redirect a frame to a
    /// wire-supplied `receiver_pk` either. The combination
    /// `EXPLICIT_RECEIVER` alone (without `EXPLICIT_SENDER`) is
    /// legal in the wire format (see `test_wire_property.cpp` §3.3
    /// generator), so the deframe gate is the choke point.
    ///
    /// The frame layout is hand-built so the test covers the
    /// EXPLICIT_RECEIVER-only path that `GnetProtocol::frame()`
    /// does not normally produce (`frame()` infers EXPLICIT_SENDER
    /// from the envelope's identity-mismatch heuristic).
    auto mc = make_mirrored_contexts();
    /// Default `allows_relay = false` — receiver is a regular peer.
    GnetProtocol bob_proto;

    const PublicKey foreign_receiver = make_pk(0xCC00FFEE);
    /// Hand-build the wire bytes: magic(4) + ver(1) + flags(1) +
    /// msg_id(4) + total_length(4) + receiver_pk(32) + payload(2).
    /// Total = 14 + 32 + 2 = 48 bytes.
    std::vector<std::uint8_t> frame_bytes;
    frame_bytes.reserve(48);
    /// Magic — ASCII "GNET".
    frame_bytes.insert(frame_bytes.end(),
                        wire::kMagic.begin(), wire::kMagic.end());
    frame_bytes.push_back(wire::kVersion);
    frame_bytes.push_back(wire::kFlagExplicitReceiver);
    /// msg_id (BE) = 5.
    constexpr std::array<std::uint8_t, 4> msg_id_be{0x00, 0x00, 0x00, 0x05};
    frame_bytes.insert(frame_bytes.end(),
                        msg_id_be.begin(), msg_id_be.end());
    /// total_length (BE) = 48.
    constexpr std::array<std::uint8_t, 4> total_be{0x00, 0x00, 0x00, 0x30};
    frame_bytes.insert(frame_bytes.end(),
                        total_be.begin(), total_be.end());
    /// receiver_pk — first 4 bytes from `foreign_receiver`, rest zero.
    frame_bytes.insert(frame_bytes.end(),
                        foreign_receiver.begin(), foreign_receiver.end());
    /// payload.
    frame_bytes.push_back(0xDE);
    frame_bytes.push_back(0xAD);

    auto deframed = bob_proto.deframe(mc.bob, frame_bytes);
    EXPECT_FALSE(deframed.has_value());
    if (!deframed.has_value()) {
        EXPECT_EQ(deframed.error().code, GN_ERR_INTEGRITY_FAILED);
    }

    /// Same wire bytes succeed once relay capability is granted.
    mc.bob.allows_relay = true;
    auto deframed2 = bob_proto.deframe(mc.bob, frame_bytes);
    ASSERT_TRUE(deframed2.has_value());
    ASSERT_EQ(deframed2->messages.size(), 1u);
    EXPECT_EQ(std::memcmp(deframed2->messages[0].receiver_pk,
                           foreign_receiver.data(), GN_PUBLIC_KEY_BYTES), 0);
}

TEST(GnetProtocolRoundTrip, ExplicitSenderRejectedOnNonRelayContext) {
    /// `plugins/protocols/gnet/docs/wire-format.md` §5: a peer that has not been granted relay
    /// capability must not be permitted to claim a sender_pk other
    /// than the connection's authenticated remote pk. Without the
    /// gate, every authenticated peer could spoof `sender_pk` on
    /// inbound frames and compromise handlers that authenticate
    /// by-sender.
    auto mc = make_mirrored_contexts();
    /// Default `allows_relay = false` — the receiver is a regular peer.
    GnetProtocol alice_proto, bob_proto;

    const std::array<std::uint8_t, 4> payload = {0x01, 0x02, 0x03, 0x04};
    /// Alice tries to frame a message claiming a third-party origin
    /// (relay-transit shape, EXPLICIT_SENDER on wire).
    const PublicKey foreign = make_pk(0xFA1CE);
    auto env = make_envelope(foreign, mc.bob_pk, /*msg_id=*/9, payload);

    auto framed = alice_proto.frame(mc.alice, env);
    ASSERT_TRUE(framed.has_value());
    /// Frame produces EXPLICIT_SENDER + EXPLICIT_RECEIVER as expected.
    EXPECT_EQ((*framed)[wire::kOffsetFlags],
              wire::kFlagExplicitSender | wire::kFlagExplicitReceiver);

    /// Bob's deframe rejects with INTEGRITY_FAILED — the gate fires
    /// before any envelope is yielded.
    auto deframed = bob_proto.deframe(mc.bob, *framed);
    EXPECT_FALSE(deframed.has_value());
    if (!deframed.has_value()) {
        EXPECT_EQ(deframed.error().code, GN_ERR_INTEGRITY_FAILED);
    }

    /// Same frame on a relay-capable context succeeds — same wire
    /// bytes, different policy.
    mc.bob.allows_relay = true;
    auto deframed2 = bob_proto.deframe(mc.bob, *framed);
    ASSERT_TRUE(deframed2.has_value());
    ASSERT_EQ(deframed2->messages.size(), 1u);
    EXPECT_EQ(std::memcmp(deframed2->messages[0].sender_pk,
                           foreign.data(), GN_PUBLIC_KEY_BYTES), 0);
}

/* ── Identity sourcing rules per protocol-layer §5 ───────────────────────── */

TEST(GnetProtocolIdentitySourcing, DirectInboundUsesContextRemoteAndLocal) {
    /// Direct mode inbound: sender_pk == ctx.remote, receiver_pk == ctx.local.
    auto mc = make_mirrored_contexts();
    GnetProtocol alice_proto, bob_proto;

    const std::array<std::uint8_t, 1> payload = {0x42};
    auto env = make_envelope(mc.alice_pk, mc.bob_pk, /*msg_id=*/3, payload);

    auto framed = alice_proto.frame(mc.alice, env);
    ASSERT_TRUE(framed.has_value());

    auto deframed = bob_proto.deframe(mc.bob, *framed);
    ASSERT_TRUE(deframed.has_value());
    ASSERT_EQ(deframed->messages.size(), 1u);

    const gn_message_t& got = deframed->messages[0];
    EXPECT_EQ(std::memcmp(got.sender_pk,   mc.bob.remote_pk.data(), GN_PUBLIC_KEY_BYTES), 0);
    EXPECT_EQ(std::memcmp(got.receiver_pk, mc.bob.local_pk.data(),  GN_PUBLIC_KEY_BYTES), 0);
}

TEST(GnetProtocolIdentitySourcing, DirectOutboundHasNoPkAfterHeader) {
    /// Direct mode outbound: the produced wire bytes after the 14-byte
    /// header must be the payload — no PK fields appended.
    auto mc = make_mirrored_contexts();
    GnetProtocol p;

    const std::array<std::uint8_t, 8> payload = {1, 2, 3, 4, 5, 6, 7, 8};
    auto env = make_envelope(mc.alice_pk, mc.bob_pk, /*msg_id=*/123, payload);

    auto framed = p.frame(mc.alice, env);
    ASSERT_TRUE(framed.has_value());
    ASSERT_EQ(framed->size(), wire::kFixedHeaderSize + payload.size());

    /// flags byte == 0x00 means no conditional PK fields.
    EXPECT_EQ((*framed)[wire::kOffsetFlags], 0x00);

    /// Verify wire bytes [14..14+8) are the payload bytes verbatim.
    for (std::size_t i = 0; i < payload.size(); ++i) {
        EXPECT_EQ((*framed)[wire::kFixedHeaderSize + i], payload[i]);
    }
}

/* ── frame rejection cases per protocol-layer §8 ─────────────────────────── */

TEST(GnetProtocolFrameRejection, ZeroMsgIdRejected) {
    auto mc = make_mirrored_contexts();
    GnetProtocol p;

    const std::array<std::uint8_t, 1> payload = {0x00};
    auto env = make_envelope(mc.alice_pk, mc.bob_pk, /*msg_id=*/0, payload);

    auto framed = p.frame(mc.alice, env);
    ASSERT_FALSE(framed.has_value());
    EXPECT_EQ(framed.error().code, GN_ERR_INVALID_ENVELOPE);
}

TEST(GnetProtocolFrameRejection, ZeroSenderPkRejected) {
    auto mc = make_mirrored_contexts();
    GnetProtocol p;

    const std::array<std::uint8_t, 1> payload = {0x00};
    auto env = make_envelope(kBroadcastPk, mc.bob_pk, /*msg_id=*/1, payload);

    auto framed = p.frame(mc.alice, env);
    ASSERT_FALSE(framed.has_value());
    EXPECT_EQ(framed.error().code, GN_ERR_INVALID_ENVELOPE);
}

TEST(GnetProtocolFrameRejection, PayloadTooLargeRejected) {
    auto mc = make_mirrored_contexts();
    GnetProtocol p;

    /// One byte past the documented ceiling.
    const std::size_t too_big = p.max_payload_size() + 1;
    std::vector<std::uint8_t> payload(too_big, 0x55);
    auto env = make_envelope(mc.alice_pk, mc.bob_pk, /*msg_id=*/1, payload);

    auto framed = p.frame(mc.alice, env);
    ASSERT_FALSE(framed.has_value());
    EXPECT_EQ(framed.error().code, GN_ERR_PAYLOAD_TOO_LARGE);
}

TEST(GnetProtocolFrameRejection, MaxPayloadSizeAccepted) {
    /// Exactly `max_payload_size()` is the boundary that must succeed.
    /// Sender ≠ ctx.local forces relay-transit so the framed buffer
    /// reaches the documented `kMaxFrameBytes` ceiling.
    auto mc = make_mirrored_contexts();
    GnetProtocol p;

    const PublicKey origin = make_pk(0xCAFE);
    std::vector<std::uint8_t> payload(p.max_payload_size(), 0xAA);
    auto env = make_envelope(origin, mc.bob_pk, /*msg_id=*/1, payload);

    auto framed = p.frame(mc.alice, env);
    ASSERT_TRUE(framed.has_value());
    EXPECT_EQ(framed->size(), wire::kMaxFrameBytes);
}

/* ── deframe robustness: multi-frame, partial, empty, corrupt ────────────── */

TEST(GnetProtocolDeframe, MultiFrameBufferYieldsAllMessages) {
    /// Concat three frames; deframe surfaces all three with
    /// `bytes_consumed` equal to the full buffer length.
    auto mc = make_mirrored_contexts();
    GnetProtocol alice_proto, bob_proto;

    const std::array<std::uint8_t, 3> p1 = {0x01, 0x02, 0x03};
    const std::array<std::uint8_t, 5> p2 = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE};
    const std::array<std::uint8_t, 1> p3 = {0xFF};

    auto f1 = alice_proto.frame(mc.alice, make_envelope(mc.alice_pk, mc.bob_pk, 1, p1));
    auto f2 = alice_proto.frame(mc.alice, make_envelope(mc.alice_pk, mc.bob_pk, 2, p2));
    auto f3 = alice_proto.frame(mc.alice, make_envelope(mc.alice_pk, mc.bob_pk, 3, p3));
    ASSERT_TRUE(f1.has_value());
    ASSERT_TRUE(f2.has_value());
    ASSERT_TRUE(f3.has_value());

    std::vector<std::uint8_t> stream;
    stream.insert(stream.end(), f1->begin(), f1->end());
    stream.insert(stream.end(), f2->begin(), f2->end());
    stream.insert(stream.end(), f3->begin(), f3->end());

    auto deframed = bob_proto.deframe(mc.bob, stream);
    ASSERT_TRUE(deframed.has_value());
    ASSERT_EQ(deframed->messages.size(), 3u);
    EXPECT_EQ(deframed->bytes_consumed, stream.size());

    EXPECT_EQ(deframed->messages[0].msg_id, 1u);
    EXPECT_EQ(deframed->messages[0].payload_size, p1.size());
    EXPECT_EQ(std::memcmp(deframed->messages[0].payload, p1.data(), p1.size()), 0);

    EXPECT_EQ(deframed->messages[1].msg_id, 2u);
    EXPECT_EQ(deframed->messages[1].payload_size, p2.size());
    EXPECT_EQ(std::memcmp(deframed->messages[1].payload, p2.data(), p2.size()), 0);

    EXPECT_EQ(deframed->messages[2].msg_id, 3u);
    EXPECT_EQ(deframed->messages[2].payload_size, p3.size());
    EXPECT_EQ(std::memcmp(deframed->messages[2].payload, p3.data(), p3.size()), 0);
}

TEST(GnetProtocolDeframe, PartialBodyAtTailReportsConsumedFullFramesOnly) {
    /// Two complete frames followed by a third whose header is
    /// complete but body is truncated mid-payload.
    auto mc = make_mirrored_contexts();
    GnetProtocol alice_proto, bob_proto;

    const std::array<std::uint8_t, 4> p1 = {1, 2, 3, 4};
    const std::array<std::uint8_t, 4> p2 = {5, 6, 7, 8};
    const std::array<std::uint8_t, 8> p3 = {0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 0x1, 0x2};

    auto f1 = alice_proto.frame(mc.alice, make_envelope(mc.alice_pk, mc.bob_pk, 1, p1));
    auto f2 = alice_proto.frame(mc.alice, make_envelope(mc.alice_pk, mc.bob_pk, 2, p2));
    auto f3 = alice_proto.frame(mc.alice, make_envelope(mc.alice_pk, mc.bob_pk, 3, p3));
    ASSERT_TRUE(f1.has_value());
    ASSERT_TRUE(f2.has_value());
    ASSERT_TRUE(f3.has_value());

    std::vector<std::uint8_t> stream;
    stream.insert(stream.end(), f1->begin(), f1->end());
    stream.insert(stream.end(), f2->begin(), f2->end());
    /// Third frame: keep the header (14 bytes) plus a few payload bytes
    /// shy of full body — body is incomplete.
    const std::size_t partial_third = wire::kFixedHeaderSize + 4;
    stream.insert(stream.end(), f3->begin(), f3->begin() + partial_third);

    auto deframed = bob_proto.deframe(mc.bob, stream);
    ASSERT_TRUE(deframed.has_value());
    ASSERT_EQ(deframed->messages.size(), 2u);
    EXPECT_EQ(deframed->bytes_consumed, f1->size() + f2->size());
}

TEST(GnetProtocolDeframe, PartialHeaderAtTailReportsConsumedFullFramesOnly) {
    /// One complete frame plus less than 14 trailing bytes — second
    /// frame's header itself is incomplete.
    auto mc = make_mirrored_contexts();
    GnetProtocol alice_proto, bob_proto;

    const std::array<std::uint8_t, 6> p1 = {1, 2, 3, 4, 5, 6};
    const std::array<std::uint8_t, 4> p2 = {0xA, 0xB, 0xC, 0xD};

    auto f1 = alice_proto.frame(mc.alice, make_envelope(mc.alice_pk, mc.bob_pk, 1, p1));
    auto f2 = alice_proto.frame(mc.alice, make_envelope(mc.alice_pk, mc.bob_pk, 2, p2));
    ASSERT_TRUE(f1.has_value());
    ASSERT_TRUE(f2.has_value());

    std::vector<std::uint8_t> stream;
    stream.insert(stream.end(), f1->begin(), f1->end());
    /// Append fewer than `kFixedHeaderSize` bytes from frame 2.
    const std::size_t partial_second = wire::kFixedHeaderSize - 1;
    stream.insert(stream.end(), f2->begin(), f2->begin() + partial_second);

    auto deframed = bob_proto.deframe(mc.bob, stream);
    ASSERT_TRUE(deframed.has_value());
    ASSERT_EQ(deframed->messages.size(), 1u);
    EXPECT_EQ(deframed->bytes_consumed, f1->size());
}

TEST(GnetProtocolDeframe, EmptyInputYieldsZeroConsumed) {
    auto mc = make_mirrored_contexts();
    GnetProtocol p;

    std::span<const std::uint8_t> empty;
    auto deframed = p.deframe(mc.bob, empty);
    ASSERT_TRUE(deframed.has_value());
    EXPECT_EQ(deframed->messages.size(), 0u);
    EXPECT_EQ(deframed->bytes_consumed, 0u);
}

TEST(GnetProtocolDeframe, CorruptMagicMidStreamReturnsError) {
    /// Frame 1 valid; frame 2 starts with corrupt magic. Per parser
    /// state machine §4, corruption produces `GN_ERR_DEFRAME_CORRUPT`.
    auto mc = make_mirrored_contexts();
    GnetProtocol alice_proto, bob_proto;

    const std::array<std::uint8_t, 4> p1 = {1, 2, 3, 4};
    const std::array<std::uint8_t, 4> p2 = {5, 6, 7, 8};

    auto f1 = alice_proto.frame(mc.alice, make_envelope(mc.alice_pk, mc.bob_pk, 1, p1));
    auto f2 = alice_proto.frame(mc.alice, make_envelope(mc.alice_pk, mc.bob_pk, 2, p2));
    ASSERT_TRUE(f1.has_value());
    ASSERT_TRUE(f2.has_value());

    std::vector<std::uint8_t> stream;
    stream.insert(stream.end(), f1->begin(), f1->end());
    stream.insert(stream.end(), f2->begin(), f2->end());
    /// Corrupt the magic of frame 2.
    stream[f1->size() + wire::kOffsetMagic + 0] = 0x00;

    auto deframed = bob_proto.deframe(mc.bob, stream);
    ASSERT_FALSE(deframed.has_value());
    EXPECT_EQ(deframed.error().code, GN_ERR_DEFRAME_CORRUPT);
}

}  // namespace
}  // namespace gn::plugins::gnet
