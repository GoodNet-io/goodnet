/// @file   tests/unit/identity/test_identity.cpp
/// @brief  GoogleTest unit tests for `gn::core::identity`.
///
/// Covers the four pieces of the two-component identity model:
///   - `KeyPair` — Ed25519 generate / from_seed / sign / verify, move
///     semantics with secret wipe on destruction.
///   - `derive_address` — HKDF-SHA256 keyed on `device_pk` only
///     (device-stable; rotating user_pk must NOT change mesh
///     address). Apps build user-level graphs through
///     `host_api->get_peer_user_pk`, not by reading bits out of
///     the address.
///   - `Attestation` — user-signed device cert; round-trips via
///     `to_bytes` / `from_bytes`; verify rejects expired or
///     wrong-user inputs.
///   - `NodeIdentity::generate` — produced address equals
///     `derive_address(device.pk)`.

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <span>

#include <core/identity/attestation.hpp>
#include <core/identity/derive.hpp>
#include <core/identity/keypair.hpp>
#include <core/identity/node_identity.hpp>
#include <sdk/cpp/types.hpp>

namespace gn::core::identity {
namespace {

/// Fixed seed for deterministic tests.
constexpr std::array<std::uint8_t, kEd25519SeedBytes> kFixedSeed = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
};

/// Far-future epoch second so tests do not become flaky over time.
constexpr std::int64_t kFarFuture = 4'000'000'000;
constexpr std::int64_t kPast      = 1'000'000;

// ── KeyPair: generate / sign / verify ────────────────────────────────────

TEST(KeyPair_Generate, ProducesNonEmptyPublicKey) {
    auto kp = KeyPair::generate();
    ASSERT_TRUE(kp.has_value());
    /// At least one byte must differ — any all-zero pk would be
    /// the broadcast marker.
    bool nonzero = false;
    for (auto b : kp->public_key()) if (b) { nonzero = true; break; }
    EXPECT_TRUE(nonzero);
}

TEST(KeyPair_FromSeed, DeterministicForSameSeed) {
    auto kp1 = KeyPair::from_seed(std::span<const std::uint8_t,
                                              kEd25519SeedBytes>(kFixedSeed));
    auto kp2 = KeyPair::from_seed(std::span<const std::uint8_t,
                                              kEd25519SeedBytes>(kFixedSeed));
    ASSERT_TRUE(kp1.has_value());
    ASSERT_TRUE(kp2.has_value());
    EXPECT_EQ(kp1->public_key(), kp2->public_key());
}

TEST(KeyPair_FromSeed, DistinctSeedsYieldDistinctKeys) {
    std::array<std::uint8_t, kEd25519SeedBytes> alt_seed = kFixedSeed;
    alt_seed[0] ^= 0xFF;

    auto kp1 = KeyPair::from_seed(std::span<const std::uint8_t,
                                              kEd25519SeedBytes>(kFixedSeed));
    auto kp2 = KeyPair::from_seed(std::span<const std::uint8_t,
                                              kEd25519SeedBytes>(alt_seed));
    ASSERT_TRUE(kp1.has_value());
    ASSERT_TRUE(kp2.has_value());
    EXPECT_NE(kp1->public_key(), kp2->public_key());
}

TEST(KeyPair_Sign, VerifySucceedsForOwnSignature) {
    auto kp = KeyPair::generate();
    ASSERT_TRUE(kp.has_value());

    const std::uint8_t msg[] = "hello world";
    auto sig = kp->sign(std::span<const std::uint8_t>(msg, sizeof(msg) - 1));
    ASSERT_TRUE(sig.has_value());

    EXPECT_TRUE(KeyPair::verify(
        kp->public_key(),
        std::span<const std::uint8_t>(msg, sizeof(msg) - 1),
        std::span<const std::uint8_t, kEd25519SignatureBytes>(*sig)));
}

TEST(KeyPair_Sign, VerifyFailsForTamperedMessage) {
    auto kp = KeyPair::generate();
    ASSERT_TRUE(kp.has_value());

    std::uint8_t msg[] = "hello world";
    auto sig = kp->sign(std::span<const std::uint8_t>(msg, sizeof(msg) - 1));
    ASSERT_TRUE(sig.has_value());

    msg[0] ^= 0x01;  /// tamper
    EXPECT_FALSE(KeyPair::verify(
        kp->public_key(),
        std::span<const std::uint8_t>(msg, sizeof(msg) - 1),
        std::span<const std::uint8_t, kEd25519SignatureBytes>(*sig)));
}

TEST(KeyPair_Sign, VerifyFailsForWrongPublicKey) {
    auto kpA = KeyPair::generate();
    auto kpB = KeyPair::generate();
    ASSERT_TRUE(kpA.has_value());
    ASSERT_TRUE(kpB.has_value());

    const std::uint8_t msg[] = "msg";
    auto sigA = kpA->sign(std::span<const std::uint8_t>(msg, sizeof(msg) - 1));
    ASSERT_TRUE(sigA.has_value());

    EXPECT_FALSE(KeyPair::verify(
        kpB->public_key(),
        std::span<const std::uint8_t>(msg, sizeof(msg) - 1),
        std::span<const std::uint8_t, kEd25519SignatureBytes>(*sigA)));
}

TEST(KeyPair_Sign, EmptyMessageWorks) {
    auto kp = KeyPair::generate();
    ASSERT_TRUE(kp.has_value());

    auto sig = kp->sign(std::span<const std::uint8_t>{});
    ASSERT_TRUE(sig.has_value());
    EXPECT_TRUE(KeyPair::verify(
        kp->public_key(),
        std::span<const std::uint8_t>{},
        std::span<const std::uint8_t, kEd25519SignatureBytes>(*sig)));
}

TEST(KeyPair_Default, UninitialisedSignFails) {
    KeyPair kp;
    auto sig = kp.sign(std::span<const std::uint8_t>{});
    EXPECT_FALSE(sig.has_value());
    EXPECT_EQ(sig.error().code, GN_ERR_INVALID_ENVELOPE);
}

// ── KeyPair: move semantics ──────────────────────────────────────────────

TEST(KeyPair_Move, MoveConstructTransfersAndWipesSource) {
    auto kp = KeyPair::generate();
    ASSERT_TRUE(kp.has_value());
    const auto pk_before = kp->public_key();

    KeyPair moved(std::move(*kp));
    EXPECT_EQ(moved.public_key(), pk_before);

    /// The moved-from instance must be wiped: pk all zero, signing
    /// returns an error.
    ::gn::PublicKey zero{};
    EXPECT_EQ(kp->public_key(), zero);
    auto sig_attempt = kp->sign(std::span<const std::uint8_t>{});
    EXPECT_FALSE(sig_attempt.has_value());
}

TEST(KeyPair_Move, MoveAssignTransfersAndWipesSource) {
    auto kp1 = KeyPair::generate();
    auto kp2 = KeyPair::generate();
    ASSERT_TRUE(kp1.has_value());
    ASSERT_TRUE(kp2.has_value());

    const auto pk1_before = kp1->public_key();
    *kp2 = std::move(*kp1);
    EXPECT_EQ(kp2->public_key(), pk1_before);

    /// kp1 wiped after move.
    ::gn::PublicKey zero{};
    EXPECT_EQ(kp1->public_key(), zero);
}

TEST(KeyPair_Wipe, ExplicitWipeClearsPublicKey) {
    auto kp = KeyPair::generate();
    ASSERT_TRUE(kp.has_value());
    kp->wipe();
    ::gn::PublicKey zero{};
    EXPECT_EQ(kp->public_key(), zero);

    /// Post-wipe sign must fail.
    auto sig = kp->sign(std::span<const std::uint8_t>{});
    EXPECT_FALSE(sig.has_value());
}

// ── derive_address ───────────────────────────────────────────────────────

TEST(DeriveAddress, DeterministicForSameDevice) {
    auto d = KeyPair::generate();
    ASSERT_TRUE(d.has_value());

    auto a1 = derive_address(d->public_key());
    auto a2 = derive_address(d->public_key());
    EXPECT_EQ(a1, a2);
}

TEST(DeriveAddress, IndependentOfUserPk) {
    /// Decouple invariant: mesh_address depends on device_pk only,
    /// so rotating user_pk must NOT change a peer's mesh address.
    /// Apps building user-level connectivity graphs reach user_pk
    /// through `host_api->get_peer_user_pk` (a separate surface),
    /// not by reading bits out of the address. The API surface
    /// itself enforces this — `derive_address` no longer takes
    /// `user_pk`. This test exists as a regression marker so a
    /// future refactor that re-introduces a user-key parameter
    /// trips a fail; the invariant is checked by the type system.
    auto d = KeyPair::generate();
    ASSERT_TRUE(d.has_value());
    static_assert(
        std::is_invocable_r_v<::gn::PublicKey,
                              decltype(&derive_address),
                              const ::gn::PublicKey&>,
        "derive_address must take only device_pk after decouple");
    EXPECT_EQ(derive_address(d->public_key()),
              derive_address(d->public_key()));
}

TEST(DeriveAddress, DistinctDevicesProduceDistinctOutputs) {
    auto d1 = KeyPair::generate();
    auto d2 = KeyPair::generate();
    ASSERT_TRUE(d1.has_value());
    ASSERT_TRUE(d2.has_value());

    auto a1 = derive_address(d1->public_key());
    auto a2 = derive_address(d2->public_key());
    EXPECT_NE(a1, a2);
}

TEST(DeriveAddress, NonZeroOutputForNonZeroInput) {
    auto d = KeyPair::generate();
    ASSERT_TRUE(d.has_value());

    auto addr = derive_address(d->public_key());
    bool nonzero = false;
    for (auto b : addr) if (b) { nonzero = true; break; }
    EXPECT_TRUE(nonzero);
}

// ── Attestation: create / verify ─────────────────────────────────────────

TEST(Attestation_Create, FieldsPopulated) {
    auto user   = KeyPair::generate();
    auto device = KeyPair::generate();
    ASSERT_TRUE(user.has_value());
    ASSERT_TRUE(device.has_value());

    auto att = Attestation::create(*user, device->public_key(), kFarFuture);
    ASSERT_TRUE(att.has_value());

    EXPECT_EQ(att->user_pk,        user->public_key());
    EXPECT_EQ(att->device_pk,      device->public_key());
    EXPECT_EQ(att->expiry_unix_ts, kFarFuture);
    /// Signature was filled in.
    bool sig_nonzero = false;
    for (auto b : att->signature) if (b) { sig_nonzero = true; break; }
    EXPECT_TRUE(sig_nonzero);
}

TEST(Attestation_Verify, GoodAttestationVerifies) {
    auto user   = KeyPair::generate();
    auto device = KeyPair::generate();
    ASSERT_TRUE(user.has_value());
    ASSERT_TRUE(device.has_value());

    auto att = Attestation::create(*user, device->public_key(), kFarFuture);
    ASSERT_TRUE(att.has_value());
    EXPECT_TRUE(att->verify(user->public_key(), /*now*/ kPast));
}

TEST(Attestation_Verify, ExpiredRejected) {
    auto user   = KeyPair::generate();
    auto device = KeyPair::generate();
    ASSERT_TRUE(user.has_value());
    ASSERT_TRUE(device.has_value());

    /// Cert with expiry == 100, now == 200 → expired.
    auto att = Attestation::create(*user, device->public_key(), 100);
    ASSERT_TRUE(att.has_value());
    EXPECT_FALSE(att->verify(user->public_key(), /*now*/ 200));
}

TEST(Attestation_Verify, EqualToExpiryRejected) {
    /// Boundary: now == expiry must be rejected (the contract uses <=).
    auto user   = KeyPair::generate();
    auto device = KeyPair::generate();
    ASSERT_TRUE(user.has_value());
    ASSERT_TRUE(device.has_value());

    auto att = Attestation::create(*user, device->public_key(), 1000);
    ASSERT_TRUE(att.has_value());
    EXPECT_FALSE(att->verify(user->public_key(), /*now*/ 1000));
}

TEST(Attestation_Verify, ZeroExpiryActsAsNoExpiry) {
    /// `expiry_unix_ts == 0` is the «no expiry» sentinel — verify
    /// must skip the wall-clock gate and only fall back to the
    /// signature check. Without this, an identity generated by
    /// `goodnet identity gen` (no `--expiry` ⇒ default 0) cannot be
    /// loaded back through `NodeIdentity::load_from_file`.
    auto user   = KeyPair::generate();
    auto device = KeyPair::generate();
    ASSERT_TRUE(user.has_value());
    ASSERT_TRUE(device.has_value());

    auto att = Attestation::create(*user, device->public_key(), 0);
    ASSERT_TRUE(att.has_value());
    EXPECT_TRUE(att->verify(user->public_key(), /*now*/ 0));
    EXPECT_TRUE(att->verify(user->public_key(), /*now*/ kFarFuture));
}

TEST(Attestation_Verify, WrongUserRejected) {
    auto user_real  = KeyPair::generate();
    auto user_fake  = KeyPair::generate();
    auto device     = KeyPair::generate();
    ASSERT_TRUE(user_real.has_value());
    ASSERT_TRUE(user_fake.has_value());
    ASSERT_TRUE(device.has_value());

    auto att = Attestation::create(*user_real,
                                    device->public_key(),
                                    kFarFuture);
    ASSERT_TRUE(att.has_value());
    EXPECT_FALSE(att->verify(user_fake->public_key(), /*now*/ kPast));
}

TEST(Attestation_Verify, TamperedDevicePkRejected) {
    auto user   = KeyPair::generate();
    auto device = KeyPair::generate();
    ASSERT_TRUE(user.has_value());
    ASSERT_TRUE(device.has_value());

    auto att = Attestation::create(*user,
                                    device->public_key(),
                                    kFarFuture);
    ASSERT_TRUE(att.has_value());

    /// Tamper with device_pk after signature was computed.
    att->device_pk[0] ^= 0xFF;
    EXPECT_FALSE(att->verify(user->public_key(), /*now*/ kPast));
}

TEST(Attestation_Verify, TamperedExpiryRejected) {
    auto user   = KeyPair::generate();
    auto device = KeyPair::generate();
    ASSERT_TRUE(user.has_value());
    ASSERT_TRUE(device.has_value());

    auto att = Attestation::create(*user, device->public_key(), kFarFuture);
    ASSERT_TRUE(att.has_value());

    /// Tampering expiry shifts the canonical payload, signature mismatches.
    att->expiry_unix_ts = kFarFuture + 1;
    EXPECT_FALSE(att->verify(user->public_key(), /*now*/ kPast));
}

// ── Attestation: byte round-trip ─────────────────────────────────────────

TEST(Attestation_Bytes, RoundTripPreservesEverything) {
    auto user   = KeyPair::generate();
    auto device = KeyPair::generate();
    ASSERT_TRUE(user.has_value());
    ASSERT_TRUE(device.has_value());

    auto att = Attestation::create(*user, device->public_key(), kFarFuture);
    ASSERT_TRUE(att.has_value());

    auto bytes = att->to_bytes();
    EXPECT_EQ(bytes.size(), kAttestationBytes);

    auto parsed = Attestation::from_bytes(
        std::span<const std::uint8_t, kAttestationBytes>(bytes));
    ASSERT_TRUE(parsed.has_value());

    EXPECT_EQ(parsed->user_pk,        att->user_pk);
    EXPECT_EQ(parsed->device_pk,      att->device_pk);
    EXPECT_EQ(parsed->expiry_unix_ts, att->expiry_unix_ts);
    EXPECT_EQ(parsed->signature,      att->signature);

    /// And the parsed copy still verifies.
    EXPECT_TRUE(parsed->verify(user->public_key(), /*now*/ kPast));
}

TEST(Attestation_Bytes, ParsedNegativeExpiryPreserved) {
    /// Negative expiry round-trips through two's-complement bit
    /// pattern; the contract states `from_bytes` reinterprets the
    /// raw uint64 as a signed int64.
    auto user   = KeyPair::generate();
    auto device = KeyPair::generate();
    ASSERT_TRUE(user.has_value());
    ASSERT_TRUE(device.has_value());

    auto att = Attestation::create(*user, device->public_key(), -42);
    ASSERT_TRUE(att.has_value());
    auto bytes = att->to_bytes();
    auto parsed = Attestation::from_bytes(
        std::span<const std::uint8_t, kAttestationBytes>(bytes));
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->expiry_unix_ts, -42);
}

// ── NodeIdentity::generate ───────────────────────────────────────────────

TEST(NodeIdentity_Generate, AddressMatchesDeriveDevice) {
    auto node = NodeIdentity::generate(kFarFuture);
    ASSERT_TRUE(node.has_value());

    /// Address must equal derive_address(device_pk) — this is
    /// the consistency invariant the contract exposes after the
    /// user_pk decouple. user_pk travels through attestation,
    /// not through the mesh address.
    auto expected = derive_address(node->device().public_key());
    EXPECT_EQ(node->address(), expected);
}

TEST(NodeIdentity_Generate, AttestationVerifiesAgainstUser) {
    auto node = NodeIdentity::generate(kFarFuture);
    ASSERT_TRUE(node.has_value());

    EXPECT_TRUE(node->attestation().verify(node->user().public_key(),
                                            /*now*/ kPast));

    EXPECT_EQ(node->attestation().user_pk,   node->user().public_key());
    EXPECT_EQ(node->attestation().device_pk, node->device().public_key());
    EXPECT_EQ(node->attestation().expiry_unix_ts, kFarFuture);
}

TEST(NodeIdentity_Generate, EveryCallProducesDistinctIdentity) {
    auto a = NodeIdentity::generate(kFarFuture);
    auto b = NodeIdentity::generate(kFarFuture);
    ASSERT_TRUE(a.has_value());
    ASSERT_TRUE(b.has_value());
    EXPECT_NE(a->user().public_key(),   b->user().public_key());
    EXPECT_NE(a->device().public_key(), b->device().public_key());
    EXPECT_NE(a->address(),              b->address());
}

}  // namespace
}  // namespace gn::core::identity
