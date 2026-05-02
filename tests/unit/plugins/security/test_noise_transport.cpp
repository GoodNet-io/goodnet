// SPDX-License-Identifier: Apache-2.0
/// @file   tests/unit/plugins/security/test_noise_transport.cpp
/// @brief  Unit pin for `gn::noise::TransportState` — the post-Split
///         send/recv ciphers + rekey state machine.
///
/// `test_noise.cpp` covers the AEAD primitives and the interoperability
/// of TransportState through a real XX/IK handshake. The `e2e` test
/// runs the full TCP+Noise stack. Neither isolates the transport
/// state machine itself: send and recv nonces are independent;
/// `needs_rekey()` flips at the documented boundary; `rekey()` rotates
/// both keys atomically and resets both nonces; a failed decrypt
/// MUST NOT advance the recv counter (otherwise a single tampered
/// frame would desync the stream forever).
///
/// These cases hand-build `TransportState` from raw `CipherKey`s so
/// the state machine is exercised in isolation from the symmetric
/// state and the handshake DSL.

// clang-tidy treats `*opt` after `ASSERT_TRUE(opt.has_value())` as
// unchecked because the gtest flow is opaque to the analyser.
// NOLINTBEGIN(bugprone-unchecked-optional-access)

#include <gtest/gtest.h>

#include "cipher.hpp"
#include "transport.hpp"

#include <array>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace gn::noise {
namespace {

CipherKey deterministic_key(std::uint8_t marker) noexcept {
    CipherKey k{};
    for (std::size_t i = 0; i < k.size(); ++i) {
        k[i] = static_cast<std::uint8_t>(marker + i);
    }
    return k;
}

CipherState fresh_cipher(const CipherKey& k) {
    CipherState cs;
    cs.initialize_key(k);
    return cs;
}

/// Build a TransportState from two distinct keys: one for send, one
/// for recv. Production handshakes derive these from `Split()`; the
/// unit pin uses arbitrary 32-byte arrays so the state machine
/// runs without the symmetric/handshake stack underneath.
TransportState make_transport(std::uint8_t send_marker,
                                std::uint8_t recv_marker) {
    return TransportState(fresh_cipher(deterministic_key(send_marker)),
                          fresh_cipher(deterministic_key(recv_marker)));
}

std::vector<std::uint8_t> bytes_of(std::string_view s) {
    return {s.begin(), s.end()};
}

}  // namespace

TEST(NoiseTransport, RoundtripWithMatchingDirection) {
    /// `init` writes through `send_` (key A) and reads from `recv_`
    /// (key B); `resp` mirrors. The matching pair (init.send / resp.recv
    /// share the same key) is the only configuration that round-trips.
    auto init = make_transport(/*send_marker=*/0x10, /*recv_marker=*/0x20);
    auto resp = make_transport(/*send_marker=*/0x20, /*recv_marker=*/0x10);

    const auto plain = bytes_of("hello transport");
    const auto ct    = init.encrypt(plain);

    const auto pt = resp.decrypt(ct);
    ASSERT_TRUE(pt.has_value());
    EXPECT_EQ(*pt, plain);
}

TEST(NoiseTransport, SendAndRecvNoncesAreIndependent) {
    /// The two CipherStates carry independent counters. Encrypting
    /// MUST advance only `send_`; decrypting only `recv_`.
    auto init = make_transport(0x10, 0x20);
    auto resp = make_transport(0x20, 0x10);

    EXPECT_EQ(init.send_nonce(), 0u);
    EXPECT_EQ(init.recv_nonce(), 0u);

    const auto plain = bytes_of("ping");
    const auto ct1 = init.encrypt(plain);
    const auto ct2 = init.encrypt(plain);
    const auto ct3 = init.encrypt(plain);

    EXPECT_EQ(init.send_nonce(), 3u);
    EXPECT_EQ(init.recv_nonce(), 0u);

    /// Replay all three through `resp`'s recv side; only that nonce
    /// advances.
    EXPECT_TRUE(resp.decrypt(ct1).has_value());
    EXPECT_TRUE(resp.decrypt(ct2).has_value());
    EXPECT_TRUE(resp.decrypt(ct3).has_value());
    EXPECT_EQ(resp.send_nonce(), 0u);
    EXPECT_EQ(resp.recv_nonce(), 3u);
}

TEST(NoiseTransport, NeedsRekeyFalseBelowThresholdTrueAtOrAbove) {
    /// `needs_rekey()` MUST return `true` at the documented
    /// threshold (`REKEY_INTERVAL`, 2^60) and `false` at every value
    /// below it. The boundary is symmetric — either side hitting
    /// the threshold makes the predicate true.
    auto t = make_transport(0x40, 0x41);

    EXPECT_FALSE(t.needs_rekey());

    t.test_set_nonces(REKEY_INTERVAL - 1, 0);
    EXPECT_FALSE(t.needs_rekey());

    t.test_set_nonces(REKEY_INTERVAL, 0);
    EXPECT_TRUE(t.needs_rekey());

    t.test_set_nonces(0, REKEY_INTERVAL - 1);
    EXPECT_FALSE(t.needs_rekey());

    t.test_set_nonces(0, REKEY_INTERVAL);
    EXPECT_TRUE(t.needs_rekey());

    t.test_set_nonces(REKEY_INTERVAL + 7, REKEY_INTERVAL + 11);
    EXPECT_TRUE(t.needs_rekey());
}

TEST(NoiseTransport, RekeyResetsBothNoncesToZero) {
    /// `rekey()` rotates BOTH ciphers atomically and resets BOTH
    /// nonces. A regression that only resets one would leave a side
    /// at a non-zero counter under a fresh key, breaking interop on
    /// the next frame.
    auto t = make_transport(0x60, 0x61);
    t.test_set_nonces(123, 456);
    EXPECT_EQ(t.send_nonce(), 123u);
    EXPECT_EQ(t.recv_nonce(), 456u);

    t.rekey();

    EXPECT_EQ(t.send_nonce(), 0u);
    EXPECT_EQ(t.recv_nonce(), 0u);
}

TEST(NoiseTransport, RekeyChangesKeyPostSplit) {
    /// After `rekey()` the two sides MUST share the same new key on
    /// the matching direction; the ciphertext for the same plaintext
    /// at nonce 0 differs from the pre-rekey ciphertext at nonce 0
    /// (different keys).
    auto init = make_transport(0x10, 0x20);
    auto resp = make_transport(0x20, 0x10);
    const auto plain = bytes_of("rotation");

    /// Pre-rekey ciphertext at send nonce 0.
    const auto ct_pre = init.encrypt(plain);

    /// Both sides rekey on the matching boundary.
    init.rekey();
    resp.rekey();

    /// Post-rekey ciphertext at send nonce 0. Same plaintext, fresh
    /// key — `ct_post` MUST NOT equal `ct_pre`.
    const auto ct_post = init.encrypt(plain);
    EXPECT_NE(ct_pre, ct_post);

    /// Resp decrypts with the rotated key at recv nonce 0. The pre-
    /// rekey ciphertext is no longer accepted on the new key.
    EXPECT_FALSE(resp.decrypt(ct_pre).has_value());
    EXPECT_TRUE(resp.decrypt(ct_post).has_value());
}

TEST(NoiseTransport, FailedDecryptDoesNotAdvanceRecvNonce) {
    /// Per `cipher.hpp` `decrypt_with_ad` returns nullopt on AEAD
    /// failure and leaves the nonce at its current value. A
    /// regression that advanced the counter on every call —
    /// successful or not — would let a single tampered frame desync
    /// the stream forever.
    auto init = make_transport(0x10, 0x20);
    auto resp = make_transport(0x20, 0x10);

    const auto plain = bytes_of("payload");
    auto ct = init.encrypt(plain);

    /// Flip a body byte; Poly1305 rejects the frame.
    ASSERT_FALSE(ct.empty());
    ct[0] ^= static_cast<std::uint8_t>(0xFFu);

    EXPECT_EQ(resp.recv_nonce(), 0u);
    EXPECT_FALSE(resp.decrypt(ct).has_value());
    EXPECT_EQ(resp.recv_nonce(), 0u);

    /// A subsequent legal frame at the unchanged counter still
    /// decrypts. The single tampered packet did not desync the
    /// stream.
    const auto ct_ok = init.encrypt(plain);
    /// Init's send counter advanced past the tampered frame's
    /// nonce 0 to 1; resp's recv expects 0 so the OK frame fails
    /// against this construction. Reset init to test the recv
    /// fairness directly.
    auto init2 = make_transport(0x10, 0x20);
    auto resp2 = make_transport(0x20, 0x10);
    auto ct_a = init2.encrypt(plain);
    auto ct_a_tampered = ct_a;
    ct_a_tampered[0] ^= static_cast<std::uint8_t>(0xFFu);
    EXPECT_FALSE(resp2.decrypt(ct_a_tampered).has_value());
    EXPECT_EQ(resp2.recv_nonce(), 0u);
    EXPECT_TRUE(resp2.decrypt(ct_a).has_value());
    EXPECT_EQ(resp2.recv_nonce(), 1u);
}

TEST(NoiseTransport, MoveConstructTransfersStateAndIsUsable) {
    /// `TransportState` is movable. After move-construct the source
    /// is in a valid-but-unspecified state; the destination MUST
    /// carry the original ciphers and counters and remain usable.
    auto src = make_transport(0x70, 0x71);
    src.test_set_nonces(5, 6);

    TransportState dst(std::move(src));
    EXPECT_EQ(dst.send_nonce(), 5u);
    EXPECT_EQ(dst.recv_nonce(), 6u);

    /// `dst` can encrypt at its new home; counter advances on the
    /// destination.
    const auto ct = dst.encrypt(bytes_of("after-move"));
    EXPECT_EQ(dst.send_nonce(), 6u);
    EXPECT_FALSE(ct.empty());
}

// NOLINTEND(bugprone-unchecked-optional-access)

}  // namespace gn::noise
