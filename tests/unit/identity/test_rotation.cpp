/// @file   tests/unit/identity/test_rotation.cpp
/// @brief  RotationProof sign + verify roundtrip + negative cases.

#include <gtest/gtest.h>

#include <core/identity/rotation.hpp>

using namespace gn::core::identity;

namespace {

constexpr std::int64_t kValidFrom = 1700000000;

}  // namespace

// ── Sign + verify roundtrip ──────────────────────────────────────────────

TEST(Rotation, SignVerifyRoundtrip) {
    auto prev = KeyPair::generate();
    auto next = KeyPair::generate();
    ASSERT_TRUE(prev.has_value());
    ASSERT_TRUE(next.has_value());

    auto signed_proof = sign_rotation(*prev, next->public_key(),
                                       /*counter*/ 1,
                                       kValidFrom);
    ASSERT_TRUE(signed_proof.has_value());

    auto parsed = verify_rotation(
        std::span<const std::uint8_t>(*signed_proof),
        prev->public_key());
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->new_user_pk,        next->public_key());
    EXPECT_EQ(parsed->prev_user_pk,       prev->public_key());
    EXPECT_EQ(parsed->counter,            1u);
    EXPECT_EQ(parsed->valid_from_unix_ts, kValidFrom);
}

// ── Negative: wrong wire size ────────────────────────────────────────────

TEST(Rotation, RejectsWrongWireSize) {
    auto prev = KeyPair::generate();
    ASSERT_TRUE(prev.has_value());
    std::vector<std::uint8_t> short_buf(50, 0);
    auto r = verify_rotation(std::span<const std::uint8_t>(short_buf),
                              prev->public_key());
    EXPECT_FALSE(r.has_value());
}

// ── Negative: bad magic ─────────────────────────────────────────────────

TEST(Rotation, RejectsBadMagic) {
    auto prev = KeyPair::generate();
    auto next = KeyPair::generate();
    ASSERT_TRUE(prev.has_value());
    ASSERT_TRUE(next.has_value());

    auto wire = sign_rotation(*prev, next->public_key(), 1, kValidFrom);
    ASSERT_TRUE(wire.has_value());
    /// Corrupt the magic byte.
    (*wire)[0] = 0x00;
    auto r = verify_rotation(std::span<const std::uint8_t>(*wire),
                              prev->public_key());
    EXPECT_FALSE(r.has_value());
}

// ── Negative: bad version ───────────────────────────────────────────────

TEST(Rotation, RejectsBadVersion) {
    auto prev = KeyPair::generate();
    auto next = KeyPair::generate();
    ASSERT_TRUE(prev.has_value());
    ASSERT_TRUE(next.has_value());

    auto wire = sign_rotation(*prev, next->public_key(), 1, kValidFrom);
    ASSERT_TRUE(wire.has_value());
    /// Corrupt version (offset 4).
    (*wire)[4] = 0x99;
    auto r = verify_rotation(std::span<const std::uint8_t>(*wire),
                              prev->public_key());
    EXPECT_FALSE(r.has_value());
}

// ── Negative: prev_user_pk mismatch (anti-confusion) ────────────────────

TEST(Rotation, RejectsPrevUserPkMismatch) {
    auto prev_a = KeyPair::generate();
    auto prev_b = KeyPair::generate();
    auto next   = KeyPair::generate();
    ASSERT_TRUE(prev_a.has_value());
    ASSERT_TRUE(prev_b.has_value());
    ASSERT_TRUE(next.has_value());

    /// Caller expects `prev_b`, but the proof was signed by
    /// `prev_a` — refuse so a misrouted proof can't be applied.
    auto wire = sign_rotation(*prev_a, next->public_key(), 1, kValidFrom);
    ASSERT_TRUE(wire.has_value());
    auto r = verify_rotation(std::span<const std::uint8_t>(*wire),
                              prev_b->public_key());
    EXPECT_FALSE(r.has_value());
}

// ── Negative: tampered signature ────────────────────────────────────────

TEST(Rotation, RejectsTamperedSignature) {
    auto prev = KeyPair::generate();
    auto next = KeyPair::generate();
    ASSERT_TRUE(prev.has_value());
    ASSERT_TRUE(next.has_value());

    auto wire = sign_rotation(*prev, next->public_key(), 1, kValidFrom);
    ASSERT_TRUE(wire.has_value());
    /// Flip a bit in the signature region (offset 86..149).
    (*wire)[100] ^= 0x01;
    auto r = verify_rotation(std::span<const std::uint8_t>(*wire),
                              prev->public_key());
    EXPECT_FALSE(r.has_value());
}

// ── Negative: tampered counter (signature breaks) ──────────────────────

TEST(Rotation, RejectsTamperedCounter) {
    auto prev = KeyPair::generate();
    auto next = KeyPair::generate();
    ASSERT_TRUE(prev.has_value());
    ASSERT_TRUE(next.has_value());

    auto wire = sign_rotation(*prev, next->public_key(),
                                /*counter*/ 5, kValidFrom);
    ASSERT_TRUE(wire.has_value());
    /// Counter lives at offset 70..77.
    (*wire)[77] ^= 0xFF;
    auto r = verify_rotation(std::span<const std::uint8_t>(*wire),
                              prev->public_key());
    EXPECT_FALSE(r.has_value());
}
