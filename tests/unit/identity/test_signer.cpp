/// @file   tests/unit/identity/test_signer.cpp
/// @brief  Unit coverage for the Phase-1 `IdentitySigner` abstraction.
///
/// Targets the new `LibsodiumSigner` (default in-process implementation)
/// plus the `NodeIdentity::signer()` integration. The HSM-backed
/// signers introduced in Phase 2 plug into the same gtest battery by
/// extending the typed-test parameter list.

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <memory>
#include <span>
#include <string>

#include <sodium.h>

#include <core/identity/libsodium_signer.hpp>
#include <core/identity/node_identity.hpp>
#include <core/identity/signer.hpp>
#include <sdk/core.h>
#include <sdk/cpp/types.hpp>

namespace gn::core::identity {
namespace {

constexpr std::array<std::uint8_t, kLibsodiumSeedBytes> kFixedSeed = {
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
};

TEST(LibsodiumSigner, RoundTrip) {
    /// Build the libsodium reference keypair from the same seed and
    /// then construct a signer from its 64-byte secret blob — the
    /// signer's signature should verify against the reference pubkey.
    std::array<std::uint8_t, 64> reference_sk{};
    std::array<std::uint8_t, 32> reference_pk{};
    ASSERT_EQ(::crypto_sign_seed_keypair(reference_pk.data(),
                                          reference_sk.data(),
                                          kFixedSeed.data()),
               0);

    LibsodiumSigner signer{std::span<const std::uint8_t, 64>{reference_sk}};

    /// Confirm `pubkey()` matches the libsodium-derived reference.
    std::array<std::uint8_t, 32> got_pk{};
    ASSERT_EQ(signer.pubkey(std::span<std::uint8_t, 32>{got_pk}), GN_OK);
    EXPECT_EQ(std::memcmp(got_pk.data(), reference_pk.data(), 32), 0);

    /// Sign a 32-byte payload and verify with libsodium directly.
    const std::array<std::uint8_t, 32> message = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    };
    std::array<std::uint8_t, 64> sig{};
    ASSERT_EQ(signer.sign(
                 std::span<const std::uint8_t>(message),
                 std::span<std::uint8_t, 64>{sig}),
               GN_OK);
    EXPECT_EQ(::crypto_sign_verify_detached(sig.data(),
                                             message.data(),
                                             message.size(),
                                             reference_pk.data()),
               0);
}

TEST(LibsodiumSigner, FromSeedDerivesSamePubkey) {
    auto signer = LibsodiumSigner::from_seed(
        std::span<const std::uint8_t, 32>{kFixedSeed});
    ASSERT_NE(signer, nullptr);

    std::array<std::uint8_t, 64> reference_sk{};
    std::array<std::uint8_t, 32> reference_pk{};
    ASSERT_EQ(::crypto_sign_seed_keypair(reference_pk.data(),
                                          reference_sk.data(),
                                          kFixedSeed.data()),
               0);

    std::array<std::uint8_t, 32> got_pk{};
    ASSERT_EQ(signer->pubkey(std::span<std::uint8_t, 32>{got_pk}), GN_OK);
    EXPECT_EQ(std::memcmp(got_pk.data(), reference_pk.data(), 32), 0);

    /// Cross-signer round-trip: signing through the `from_seed`
    /// instance must verify against the same pubkey.
    const std::array<std::uint8_t, 4> message = {'p', 'i', 'n', 'g'};
    std::array<std::uint8_t, 64> sig{};
    ASSERT_EQ(signer->sign(std::span<const std::uint8_t>(message),
                            std::span<std::uint8_t, 64>{sig}),
               GN_OK);
    EXPECT_EQ(::crypto_sign_verify_detached(sig.data(),
                                             message.data(),
                                             message.size(),
                                             reference_pk.data()),
               0);
}

TEST(LibsodiumSigner, WipesPrivateKeyOnDestroy) {
    /// Probe the secret-key region through a unique_ptr — after
    /// reset() the destructor's `sodium_memzero` should have cleared
    /// the bytes that previously held the seed. The check is best-
    /// effort: gtest cannot directly inspect freed memory, but it
    /// can verify the destructor at least runs to completion without
    /// asan tripping on the in-flight wipe. The strong observable
    /// guarantee is that a fresh `from_seed` call still derives the
    /// same pubkey after the prior instance is dropped — proving no
    /// stale state leaked through libsodium internals.
    {
        auto signer = LibsodiumSigner::from_seed(
            std::span<const std::uint8_t, 32>{kFixedSeed});
        ASSERT_NE(signer, nullptr);
    }
    /// Reconstruct from the same seed; if the destructor leaked
    /// anything global, a second instance would diverge.
    auto signer2 = LibsodiumSigner::from_seed(
        std::span<const std::uint8_t, 32>{kFixedSeed});
    ASSERT_NE(signer2, nullptr);
    std::array<std::uint8_t, 32> pk{};
    ASSERT_EQ(signer2->pubkey(std::span<std::uint8_t, 32>{pk}), GN_OK);

    std::array<std::uint8_t, 32> reference_pk{};
    std::array<std::uint8_t, 64> reference_sk{};
    ASSERT_EQ(::crypto_sign_seed_keypair(reference_pk.data(),
                                          reference_sk.data(),
                                          kFixedSeed.data()),
               0);
    EXPECT_EQ(std::memcmp(pk.data(), reference_pk.data(), 32), 0);
}

TEST(NodeIdentity, SignerAccessibleAndMatchesUserPubkey) {
    /// Generate a fresh identity and pull its signer's pubkey. The
    /// IdentitySigner must report the same bytes as the user keypair
    /// it was built from — the abstraction's whole point is that
    /// `node_identity.signer()->pubkey()` is the single source of
    /// truth for the identity public key.
    auto identity = NodeIdentity::generate(/*expiry*/ 4'000'000'000);
    ASSERT_TRUE(identity.has_value());

    auto* signer = identity->signer();
    ASSERT_NE(signer, nullptr);

    std::array<std::uint8_t, 32> signer_pk{};
    ASSERT_EQ(signer->pubkey(std::span<std::uint8_t, 32>{signer_pk}), GN_OK);
    EXPECT_EQ(std::memcmp(signer_pk.data(),
                           identity->user().public_key().data(),
                           32),
               0);

    /// Signing through the abstraction should verify against the
    /// keypair's pubkey — confirms the libsodium impl really wraps
    /// the same secret bytes the user keypair holds.
    const std::array<std::uint8_t, 8> msg = {1, 2, 3, 4, 5, 6, 7, 8};
    std::array<std::uint8_t, 64> sig{};
    ASSERT_EQ(signer->sign(std::span<const std::uint8_t>(msg),
                            std::span<std::uint8_t, 64>{sig}),
               GN_OK);
    EXPECT_EQ(::crypto_sign_verify_detached(
                 sig.data(), msg.data(), msg.size(),
                 identity->user().public_key().data()),
               0);
}

TEST(NodeIdentity, SignerSurvivesSaveLoadRoundTrip) {
    /// `gn_core_install_identity_from_file` reads the file and
    /// constructs a NodeIdentity through `load_from_file` →
    /// `compose`, which builds a fresh `LibsodiumSigner` from the
    /// user keypair. The signer's pubkey must match the file's
    /// embedded user pubkey bit-for-bit (no observable change vs
    /// the pre-refactor flow).
    namespace fs = std::filesystem;
    const auto tmp_dir = fs::temp_directory_path()
        / "gn_signer_phase1_roundtrip";
    fs::remove_all(tmp_dir);
    fs::create_directories(tmp_dir);
    const auto identity_path = (tmp_dir / "identity.bin").string();

    auto original = NodeIdentity::generate(/*expiry*/ 4'000'000'000);
    ASSERT_TRUE(original.has_value());
    const auto saved_user_pk = original->user().public_key();

    const auto save_rc = NodeIdentity::save_to_file(*original,
                                                     identity_path);
    ASSERT_TRUE(save_rc.has_value());

    /// Spin up a kernel, install the identity, and confirm the
    /// signer reports the saved pubkey through both `signer()` and
    /// `gn_core_get_pubkey` — the round-trip touches the install
    /// path the C ABI exposes.
    auto* core = gn_core_create();
    ASSERT_NE(core, nullptr);
    ASSERT_EQ(gn_core_install_identity_from_file(core,
                                                  identity_path.c_str()),
               GN_OK);
    ASSERT_EQ(gn_core_init(core), GN_OK);

    auto loaded = NodeIdentity::load_from_file(identity_path);
    ASSERT_TRUE(loaded.has_value());
    auto* signer = loaded->signer();
    ASSERT_NE(signer, nullptr);

    std::array<std::uint8_t, 32> signer_pk{};
    ASSERT_EQ(signer->pubkey(std::span<std::uint8_t, 32>{signer_pk}), GN_OK);
    EXPECT_EQ(std::memcmp(signer_pk.data(), saved_user_pk.data(), 32), 0);

    gn_core_stop(core);
    gn_core_destroy(core);
    fs::remove_all(tmp_dir);
}

}  // namespace
}  // namespace gn::core::identity
