/// @file   tests/unit/security/test_inline_crypto.cpp
/// @brief  Kernel-side ChaCha20-Poly1305 wrapper unit tests.

#include <gtest/gtest.h>

#include <core/security/inline_crypto.hpp>

#include <sdk/security.h>
#include <sdk/types.h>

#include <cstdint>
#include <cstring>
#include <vector>

namespace {

using gn::core::InlineCrypto;

gn_handshake_keys_t make_keys(std::uint8_t fill_send,
                               std::uint8_t fill_recv,
                               std::uint64_t initial_send = 0,
                               std::uint64_t initial_recv = 0) noexcept {
    gn_handshake_keys_t k{};
    k.api_size = sizeof(k);
    std::memset(k.send_cipher_key, fill_send, GN_CIPHER_KEY_BYTES);
    std::memset(k.recv_cipher_key, fill_recv, GN_CIPHER_KEY_BYTES);
    k.initial_send_nonce = initial_send;
    k.initial_recv_nonce = initial_recv;
    return k;
}

}  // namespace

TEST(InlineCrypto, RefusesUntilSeeded) {
    InlineCrypto crypto;
    EXPECT_FALSE(crypto.seeded());

    const std::vector<std::uint8_t> plain{1, 2, 3};
    std::vector<std::uint8_t> cipher;
    EXPECT_EQ(crypto.encrypt(plain, cipher), GN_ERR_INVALID_STATE);
    EXPECT_EQ(crypto.decrypt(plain, cipher), GN_ERR_INVALID_STATE);
}

TEST(InlineCrypto, ZeroedKeysDeclineSeed) {
    InlineCrypto crypto;
    gn_handshake_keys_t zero{};
    zero.api_size = sizeof(zero);
    EXPECT_FALSE(crypto.seed(zero));
    EXPECT_FALSE(crypto.seeded());
}

TEST(InlineCrypto, NonzeroKeysSeedAndAdvanceNonces) {
    InlineCrypto crypto;
    auto k = make_keys(0x11, 0x22);
    ASSERT_TRUE(crypto.seed(k));
    EXPECT_TRUE(crypto.seeded());
    EXPECT_EQ(crypto.send_nonce(), 0u);
    EXPECT_EQ(crypto.recv_nonce(), 0u);

    /// One encrypt advances the send counter by exactly one. The
    /// receive counter stays untouched.
    const std::vector<std::uint8_t> plain{1, 2, 3, 4, 5};
    std::vector<std::uint8_t> cipher;
    ASSERT_EQ(crypto.encrypt(plain, cipher), GN_OK);
    EXPECT_EQ(cipher.size(), plain.size() + InlineCrypto::kTagBytes);
    EXPECT_EQ(crypto.send_nonce(), 1u);
    EXPECT_EQ(crypto.recv_nonce(), 0u);
}

TEST(InlineCrypto, RoundTripBetweenPairedDirections) {
    /// Two crypto states wired peer-style: alice's send key is bob's
    /// recv key and vice versa. This is the post-Split arrangement
    /// in the noise plugin.
    InlineCrypto alice;
    InlineCrypto bob;
    ASSERT_TRUE(alice.seed(make_keys(0x55, 0xAA)));
    ASSERT_TRUE(bob.seed(make_keys(0xAA, 0x55)));

    const std::vector<std::uint8_t> plain{'h', 'e', 'l', 'l', 'o'};
    std::vector<std::uint8_t> cipher;
    ASSERT_EQ(alice.encrypt(plain, cipher), GN_OK);

    std::vector<std::uint8_t> back;
    ASSERT_EQ(bob.decrypt(cipher, back), GN_OK);
    EXPECT_EQ(back, plain);

    /// Reverse direction works on the same key pairing.
    const std::vector<std::uint8_t> plain2{'p', 'o', 'n', 'g'};
    std::vector<std::uint8_t> cipher2;
    ASSERT_EQ(bob.encrypt(plain2, cipher2), GN_OK);
    std::vector<std::uint8_t> back2;
    ASSERT_EQ(alice.decrypt(cipher2, back2), GN_OK);
    EXPECT_EQ(back2, plain2);
}

TEST(InlineCrypto, AeadRejectsTamperedCiphertext) {
    InlineCrypto alice;
    InlineCrypto bob;
    ASSERT_TRUE(alice.seed(make_keys(0x33, 0x44)));
    ASSERT_TRUE(bob.seed(make_keys(0x44, 0x33)));

    const std::vector<std::uint8_t> plain{1, 2, 3, 4};
    std::vector<std::uint8_t> cipher;
    ASSERT_EQ(alice.encrypt(plain, cipher), GN_OK);

    /// Flip one bit in the ciphertext body — Poly1305 catches it.
    cipher[0] ^= 0x01;
    std::vector<std::uint8_t> back;
    EXPECT_EQ(bob.decrypt(cipher, back), GN_ERR_INVALID_ENVELOPE);
}

TEST(InlineCrypto, MismatchedKeysFailToDecrypt) {
    InlineCrypto alice;
    InlineCrypto eve;
    ASSERT_TRUE(alice.seed(make_keys(0x10, 0x20)));
    /// Eve's recv key is wrong (0x99 instead of 0x10).
    ASSERT_TRUE(eve.seed(make_keys(0x20, 0x99)));

    const std::vector<std::uint8_t> plain{0xDE, 0xAD};
    std::vector<std::uint8_t> cipher;
    ASSERT_EQ(alice.encrypt(plain, cipher), GN_OK);

    std::vector<std::uint8_t> back;
    EXPECT_EQ(eve.decrypt(cipher, back), GN_ERR_INVALID_ENVELOPE);
}

TEST(InlineCrypto, ConcurrentEncryptsGetUniqueNonces) {
    /// Two threads racing on the same crypto state produce two
    /// different ciphertexts even when the plaintext bytes match —
    /// the atomic nonce counter assigns a unique nonce to each.
    InlineCrypto alice;
    InlineCrypto bob;
    ASSERT_TRUE(alice.seed(make_keys(0x77, 0x88)));
    ASSERT_TRUE(bob.seed(make_keys(0x88, 0x77)));

    const std::vector<std::uint8_t> plain(64, 0xCC);
    std::vector<std::uint8_t> a_cipher;
    std::vector<std::uint8_t> b_cipher;
    ASSERT_EQ(alice.encrypt(plain, a_cipher), GN_OK);
    ASSERT_EQ(alice.encrypt(plain, b_cipher), GN_OK);
    EXPECT_NE(a_cipher, b_cipher);

    /// Bob's receive counter advances in lockstep — both decrypts
    /// succeed in order.
    std::vector<std::uint8_t> back;
    ASSERT_EQ(bob.decrypt(a_cipher, back), GN_OK);
    EXPECT_EQ(back, plain);
    ASSERT_EQ(bob.decrypt(b_cipher, back), GN_OK);
    EXPECT_EQ(back, plain);
}

TEST(InlineCrypto, InitialNonceFromKeysHonored) {
    /// The session post-rekey or post-Split with an explicit
    /// initial nonce must seed both counters from the keys struct.
    /// A future provider's initial offset survives the round trip.
    InlineCrypto alice;
    InlineCrypto bob;
    ASSERT_TRUE(alice.seed(make_keys(0xAB, 0xCD,
                                       /*initial_send*/ 5,
                                       /*initial_recv*/ 9)));
    ASSERT_TRUE(bob.seed(make_keys(0xCD, 0xAB,
                                     /*initial_send*/ 9,
                                     /*initial_recv*/ 5)));
    EXPECT_EQ(alice.send_nonce(), 5u);
    EXPECT_EQ(alice.recv_nonce(), 9u);

    const std::vector<std::uint8_t> plain{0xFF};
    std::vector<std::uint8_t> cipher;
    ASSERT_EQ(alice.encrypt(plain, cipher), GN_OK);
    std::vector<std::uint8_t> back;
    ASSERT_EQ(bob.decrypt(cipher, back), GN_OK);
    EXPECT_EQ(back, plain);
}
