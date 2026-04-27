/// @file   tests/unit/protocols/gnet/test_protocol_property.cpp
/// @brief  RapidCheck property tests for `gn::plugins::gnet::GnetProtocol`.
///
/// Quantifies the round-trip contract of the IProtocolLayer envelope
/// through `frame` then `deframe` against the identity-sourcing rules
/// from `docs/contracts/protocol-layer.md` §5 and the wire-format from
/// `docs/contracts/gnet-protocol.md`:
///
///   ∀ legal envelope (msg_id != 0, sender_pk != ZERO, payload ≤ cap):
///       deframe(frame(env)) recovers msg_id, identity (per §5), payload
///
///   ∀ direct framing (sender == ctx.local, receiver == ctx.remote):
///       wire bytes after the 14-byte header are exactly the payload
///       (no PK fields appended).

#include <gtest/gtest.h>
#include <rapidcheck/gtest.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <vector>

#include <core/kernel/connection_context.hpp>
#include <plugins/protocols/gnet/protocol.hpp>
#include <plugins/protocols/gnet/wire.hpp>
#include <sdk/cpp/types.hpp>
#include <sdk/trust.h>
#include <sdk/types.h>

namespace gn::plugins::gnet {
namespace {

/* ── Generators ──────────────────────────────────────────────────────────── */

/// Generate a non-zero public key — at least one byte is forced > 0 so
/// the result never collides with the broadcast marker.
rc::Gen<PublicKey> nonzero_pk_gen() {
    return rc::gen::map(
        rc::gen::pair(rc::gen::inRange<std::size_t>(0, GN_PUBLIC_KEY_BYTES),
                      rc::gen::suchThat(rc::gen::arbitrary<std::uint8_t>(),
                                        [](std::uint8_t v) { return v != 0; })),
        [](const std::pair<std::size_t, std::uint8_t>& seed) {
            PublicKey pk{};
            /// First fill with low-entropy noise, then overwrite one byte
            /// to guarantee the result is non-zero.
            std::uint8_t fill = static_cast<std::uint8_t>(seed.first * 31u + seed.second);
            for (auto& b : pk) b = fill++;
            pk[seed.first] = seed.second;
            return pk;
        });
}

/// Cap on payload size matches the contract `max_payload_size()`.
inline constexpr std::size_t kMaxPayload =
    wire::kMaxFrameBytes - wire::kFixedHeaderSize - 2 * wire::kPublicKeySize;

/// Generate a payload of size ≤ `kMaxPayload` so framing never trips
/// `GN_ERR_PAYLOAD_TOO_LARGE`. Capped lower than the absolute max so
/// the test suite remains fast.
rc::Gen<std::vector<std::uint8_t>> payload_gen() {
    /// 1 KiB cap keeps the tests fast while still exercising the
    /// payload memcpy path. The boundary case `payload == max` is
    /// covered by the deterministic test in `test_protocol.cpp`.
    return rc::gen::mapcat(
        rc::gen::inRange<std::size_t>(0, 1025),
        [](std::size_t n) {
            return rc::gen::container<std::vector<std::uint8_t>>(
                n, rc::gen::arbitrary<std::uint8_t>());
        });
}

/* ── Helpers ─────────────────────────────────────────────────────────────── */

/// Build a pair of mirrored contexts: Alice.local == Bob.remote and
/// vice versa. Conn ids and trust class are non-relevant for protocol-
/// layer tests but populated so the contexts look realistic.
struct MirroredContexts {
    PublicKey               alice_pk;
    PublicKey               bob_pk;
    gn_connection_context_t alice;
    gn_connection_context_t bob;
};

MirroredContexts mirror(const PublicKey& alice_pk, const PublicKey& bob_pk) {
    MirroredContexts mc{};
    mc.alice_pk = alice_pk;
    mc.bob_pk   = bob_pk;
    mc.alice.local_pk  = alice_pk;
    mc.alice.remote_pk = bob_pk;
    mc.alice.conn_id   = 1;
    mc.alice.trust     = GN_TRUST_PEER;
    mc.bob.local_pk    = bob_pk;
    mc.bob.remote_pk   = alice_pk;
    mc.bob.conn_id     = 2;
    mc.bob.trust       = GN_TRUST_PEER;
    return mc;
}

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

/* ── Round-trip property: direct mode ────────────────────────────────────── */

RC_GTEST_PROP(GnetProtocolProperty,
              DirectRoundTripPreservesEnvelope,
              ()) {
    /// Arbitrary distinct (alice, bob) PKs and a direct frame from
    /// Alice to Bob; deframe through Bob's context recovers all fields.
    const PublicKey alice_pk = *nonzero_pk_gen();
    PublicKey bob_pk         = *nonzero_pk_gen();
    /// Force distinct PKs — relay-transit branch uses the equality
    /// check; we want the direct branch in this property.
    if (bob_pk == alice_pk) bob_pk[0] ^= 0xFF;

    const std::uint32_t msg_id =
        *rc::gen::suchThat(rc::gen::arbitrary<std::uint32_t>(),
                           [](std::uint32_t v) { return v != 0; });
    const auto payload = *payload_gen();

    auto mc = mirror(alice_pk, bob_pk);
    GnetProtocol alice_proto, bob_proto;

    auto env    = make_envelope(alice_pk, bob_pk, msg_id, payload);
    auto framed = alice_proto.frame(mc.alice, env);
    RC_ASSERT(framed.has_value());

    auto deframed = bob_proto.deframe(mc.bob, *framed);
    RC_ASSERT(deframed.has_value());
    RC_ASSERT(deframed->messages.size() == 1u);
    RC_ASSERT(deframed->bytes_consumed == framed->size());

    const gn_message_t& got = deframed->messages[0];
    RC_ASSERT(got.msg_id == msg_id);
    /// §5: sender = ctx.remote, receiver = ctx.local on direct inbound.
    RC_ASSERT(std::memcmp(got.sender_pk,   alice_pk.data(), GN_PUBLIC_KEY_BYTES) == 0);
    RC_ASSERT(std::memcmp(got.receiver_pk, bob_pk.data(),   GN_PUBLIC_KEY_BYTES) == 0);
    RC_ASSERT(got.payload_size == payload.size());
    /// memcmp demands non-null pointers regardless of count; an empty
    /// payload may come back with a null `payload` pointer. Skip the
    /// byte-compare when there are no bytes to compare.
    if (!payload.empty()) {
        RC_ASSERT(std::memcmp(got.payload, payload.data(),
                                payload.size()) == 0);
    }
}

/* ── Round-trip property: broadcast mode ─────────────────────────────────── */

RC_GTEST_PROP(GnetProtocolProperty,
              BroadcastRoundTripPreservesSenderReceiverZero,
              ()) {
    /// Broadcast: receiver_pk = ZERO, sender on wire — surfaced
    /// identity at the Bob side is sender=alice (from wire), receiver=ZERO.
    const PublicKey alice_pk = *nonzero_pk_gen();
    PublicKey bob_pk         = *nonzero_pk_gen();
    if (bob_pk == alice_pk) bob_pk[0] ^= 0xFF;

    const std::uint32_t msg_id =
        *rc::gen::suchThat(rc::gen::arbitrary<std::uint32_t>(),
                           [](std::uint32_t v) { return v != 0; });
    const auto payload = *payload_gen();

    auto mc = mirror(alice_pk, bob_pk);
    GnetProtocol alice_proto, bob_proto;

    auto env    = make_envelope(alice_pk, kBroadcastPk, msg_id, payload);
    auto framed = alice_proto.frame(mc.alice, env);
    RC_ASSERT(framed.has_value());

    auto deframed = bob_proto.deframe(mc.bob, *framed);
    RC_ASSERT(deframed.has_value());
    RC_ASSERT(deframed->messages.size() == 1u);

    const gn_message_t& got = deframed->messages[0];
    RC_ASSERT(got.msg_id == msg_id);
    RC_ASSERT(std::memcmp(got.sender_pk, alice_pk.data(), GN_PUBLIC_KEY_BYTES) == 0);
    RC_ASSERT(gn_pk_is_zero(got.receiver_pk) == 1);
    RC_ASSERT(got.payload_size == payload.size());
    /// memcmp demands non-null pointers regardless of count; an empty
    /// payload may come back with a null `payload` pointer. Skip the
    /// byte-compare when there are no bytes to compare.
    if (!payload.empty()) {
        RC_ASSERT(std::memcmp(got.payload, payload.data(),
                                payload.size()) == 0);
    }
}

/* ── Round-trip property: relay-transit mode ─────────────────────────────── */

RC_GTEST_PROP(GnetProtocolProperty,
              RelayTransitRoundTripPreservesEndToEnd,
              ()) {
    /// sender ≠ ctx.local: GnetProtocol picks relay-transit and writes
    /// both PKs on the wire. Inbound deframe yields end-to-end identity.
    const PublicKey alice_pk = *nonzero_pk_gen();
    PublicKey bob_pk         = *nonzero_pk_gen();
    PublicKey origin_pk      = *nonzero_pk_gen();
    /// Distinguish all three so the relay branch is entered (sender ≠
    /// ctx.local) and remains a non-broadcast path (receiver ≠ ZERO).
    if (bob_pk == alice_pk)        bob_pk[0]    ^= 0xFF;
    if (origin_pk == alice_pk)     origin_pk[1] ^= 0xAA;
    if (origin_pk == bob_pk)       origin_pk[2] ^= 0x55;

    const std::uint32_t msg_id =
        *rc::gen::suchThat(rc::gen::arbitrary<std::uint32_t>(),
                           [](std::uint32_t v) { return v != 0; });
    const auto payload = *payload_gen();

    auto mc = mirror(alice_pk, bob_pk);
    GnetProtocol alice_proto, bob_proto;

    auto env    = make_envelope(origin_pk, bob_pk, msg_id, payload);
    auto framed = alice_proto.frame(mc.alice, env);
    RC_ASSERT(framed.has_value());

    auto deframed = bob_proto.deframe(mc.bob, *framed);
    RC_ASSERT(deframed.has_value());
    RC_ASSERT(deframed->messages.size() == 1u);

    const gn_message_t& got = deframed->messages[0];
    RC_ASSERT(got.msg_id == msg_id);
    RC_ASSERT(std::memcmp(got.sender_pk,   origin_pk.data(), GN_PUBLIC_KEY_BYTES) == 0);
    RC_ASSERT(std::memcmp(got.receiver_pk, bob_pk.data(),    GN_PUBLIC_KEY_BYTES) == 0);
    RC_ASSERT(got.payload_size == payload.size());
    /// memcmp demands non-null pointers regardless of count; an empty
    /// payload may come back with a null `payload` pointer. Skip the
    /// byte-compare when there are no bytes to compare.
    if (!payload.empty()) {
        RC_ASSERT(std::memcmp(got.payload, payload.data(),
                                payload.size()) == 0);
    }
}

/* ── Wire shape: direct framing has no PK fields ─────────────────────────── */

RC_GTEST_PROP(GnetProtocolProperty,
              DirectFramingHasOnlyHeaderAndPayloadOnWire,
              ()) {
    /// Direct framing: bytes after the 14-byte header are exactly the
    /// payload (size = 14 + payload, flags byte == 0x00).
    const PublicKey alice_pk = *nonzero_pk_gen();
    PublicKey bob_pk         = *nonzero_pk_gen();
    if (bob_pk == alice_pk) bob_pk[0] ^= 0xFF;

    const std::uint32_t msg_id =
        *rc::gen::suchThat(rc::gen::arbitrary<std::uint32_t>(),
                           [](std::uint32_t v) { return v != 0; });
    const auto payload = *payload_gen();

    auto mc = mirror(alice_pk, bob_pk);
    GnetProtocol p;

    auto env    = make_envelope(alice_pk, bob_pk, msg_id, payload);
    auto framed = p.frame(mc.alice, env);
    RC_ASSERT(framed.has_value());

    /// Total size = 14 + payload — no conditional PK area present.
    RC_ASSERT(framed->size() == wire::kFixedHeaderSize + payload.size());
    RC_ASSERT((*framed)[wire::kOffsetFlags] == 0x00);

    /// And the post-header tail must be the payload byte-for-byte.
    for (std::size_t i = 0; i < payload.size(); ++i) {
        RC_ASSERT((*framed)[wire::kFixedHeaderSize + i] == payload[i]);
    }
}

}  // namespace
}  // namespace gn::plugins::gnet
