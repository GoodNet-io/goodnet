// SPDX-License-Identifier: Apache-2.0
/// @file   tests/unit/plugins/security/test_noise.cpp
/// @brief  Noise plugin — primitives (BLAKE2b, HMAC, HKDF, ChaCha20Poly1305)
///         and full XX / IK handshake round-trips.

// clang-tidy treats `*opt` after `ASSERT_TRUE(opt.has_value())` as
// unchecked because the GTest `ASSERT_*` flow-control is opaque to
// the analyser. The pattern is the standard gtest idiom; suppressing
// the check at the TU scope keeps the test bodies readable.
// NOLINTBEGIN(bugprone-unchecked-optional-access)

#include <gtest/gtest.h>

#include "cipher.hpp"
#include "handshake.hpp"
#include "hash.hpp"
#include "hkdf.hpp"
#include "hmac.hpp"
#include "symmetric.hpp"
#include "transport.hpp"

#include <array>
#include <cstdint>
#include <cstring>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace {

using namespace gn::noise;

std::vector<std::uint8_t> bytes_of(std::string_view s) {
    return std::vector<std::uint8_t>(s.begin(), s.end());
}

template <std::size_t N>
std::vector<std::uint8_t> from_hex(const char (&hex)[N]) {
    std::vector<std::uint8_t> out;
    out.reserve((N - 1) / 2);
    auto hex_nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (std::size_t i = 0; i + 1 < N - 1; i += 2) {
        const int hi = hex_nibble(hex[i]);
        const int lo = hex_nibble(hex[i + 1]);
        out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
    }
    return out;
}

} // namespace

// ── BLAKE2b: RFC 7693 Appendix A test vector ─────────────────────────────

TEST(NoiseHash, Blake2bRfc7693AbcVector) {
    // BLAKE2b-512("abc") per RFC 7693 Appendix A.
    constexpr std::string_view input = "abc";
    const auto expected = from_hex(
        "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
        "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923");

    const auto bytes = std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(input.data()), input.size());
    Digest d = blake2b(bytes);
    EXPECT_EQ(std::vector<std::uint8_t>(d.begin(), d.end()), expected);
}

TEST(NoiseHash, Blake2bEmptyInput) {
    const auto expected = from_hex(
        "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419"
        "d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce");
    Digest d = blake2b(std::span<const std::uint8_t>{});
    EXPECT_EQ(std::vector<std::uint8_t>(d.begin(), d.end()), expected);
}

TEST(NoiseHash, Blake2bConcatenationMatchesSequential) {
    const auto a = bytes_of("hello ");
    const auto b = bytes_of("world");
    std::vector<std::uint8_t> concat;
    concat.insert(concat.end(), a.begin(), a.end());
    concat.insert(concat.end(), b.begin(), b.end());

    auto d_combined = blake2b(a, b);
    auto d_concat   = blake2b(concat);
    EXPECT_EQ(std::vector<std::uint8_t>(d_combined.begin(), d_combined.end()),
              std::vector<std::uint8_t>(d_concat.begin(), d_concat.end()));
}

// ── HMAC-BLAKE2b ─────────────────────────────────────────────────────────

TEST(NoiseHmac, EmptyKeyDeterministic) {
    const auto key = bytes_of("");
    const auto msg = bytes_of("test message");
    auto a = hmac_blake2b(key, msg);
    auto b = hmac_blake2b(key, msg);
    EXPECT_EQ(std::vector<std::uint8_t>(a.begin(), a.end()),
              std::vector<std::uint8_t>(b.begin(), b.end()));
}

TEST(NoiseHmac, KeyChangeChangesOutput) {
    const auto key1 = bytes_of("key-one");
    const auto key2 = bytes_of("key-two");
    const auto msg  = bytes_of("same message");
    auto h1 = hmac_blake2b(key1, msg);
    auto h2 = hmac_blake2b(key2, msg);
    EXPECT_NE(std::vector<std::uint8_t>(h1.begin(), h1.end()),
              std::vector<std::uint8_t>(h2.begin(), h2.end()));
}

TEST(NoiseHmac, SplitInputMatchesSingle) {
    const auto key = bytes_of("hkdf-key");
    const auto a   = bytes_of("part-1");
    const auto b   = bytes_of("part-2");
    std::vector<std::uint8_t> joined;
    joined.insert(joined.end(), a.begin(), a.end());
    joined.insert(joined.end(), b.begin(), b.end());

    auto h_split = hmac_blake2b(key, a, b);
    auto h_full  = hmac_blake2b(key, joined);
    EXPECT_EQ(std::vector<std::uint8_t>(h_split.begin(), h_split.end()),
              std::vector<std::uint8_t>(h_full.begin(),  h_full.end()));
}

TEST(NoiseHmac, LongKeyHashedFirst) {
    // Key longer than BLOCKLEN must be hashed; the result must equal HMAC
    // with that hash as the key.
    std::vector<std::uint8_t> long_key(BLOCKLEN + 17, 0xAA);
    auto hashed_key = blake2b(long_key);

    const auto msg = bytes_of("policy: long key reduces to hash");
    auto h_long   = hmac_blake2b(long_key, msg);
    auto h_hashed = hmac_blake2b(
        std::span<const std::uint8_t>(hashed_key.data(), HASHLEN), msg);
    EXPECT_EQ(std::vector<std::uint8_t>(h_long.begin(),   h_long.end()),
              std::vector<std::uint8_t>(h_hashed.begin(), h_hashed.end()));
}

// ── HKDF ─────────────────────────────────────────────────────────────────

TEST(NoiseHkdf, OutputsAreDistinct) {
    const auto ck  = bytes_of("chaining-key-content");
    const auto ikm = bytes_of("input-key-material");
    auto pair = hkdf2(ck, ikm);
    EXPECT_NE(std::vector<std::uint8_t>(pair.output1.begin(), pair.output1.end()),
              std::vector<std::uint8_t>(pair.output2.begin(), pair.output2.end()));
}

TEST(NoiseHkdf, DeterministicForFixedInputs) {
    const auto ck  = bytes_of("ck");
    const auto ikm = bytes_of("ikm");
    auto p1 = hkdf2(ck, ikm);
    auto p2 = hkdf2(ck, ikm);
    EXPECT_EQ(std::vector<std::uint8_t>(p1.output1.begin(), p1.output1.end()),
              std::vector<std::uint8_t>(p2.output1.begin(), p2.output1.end()));
    EXPECT_EQ(std::vector<std::uint8_t>(p1.output2.begin(), p1.output2.end()),
              std::vector<std::uint8_t>(p2.output2.begin(), p2.output2.end()));
}

TEST(NoiseHkdf, ThreeOutputExtendsPair) {
    // The two-output and three-output forms share output1 and output2.
    const auto ck  = bytes_of("ck-shared");
    const auto ikm = bytes_of("ikm-shared");
    auto pair   = hkdf2(ck, ikm);
    auto triple = hkdf3(ck, ikm);
    EXPECT_EQ(std::vector<std::uint8_t>(pair.output1.begin(),   pair.output1.end()),
              std::vector<std::uint8_t>(triple.output1.begin(), triple.output1.end()));
    EXPECT_EQ(std::vector<std::uint8_t>(pair.output2.begin(),   pair.output2.end()),
              std::vector<std::uint8_t>(triple.output2.begin(), triple.output2.end()));
    EXPECT_NE(std::vector<std::uint8_t>(triple.output2.begin(), triple.output2.end()),
              std::vector<std::uint8_t>(triple.output3.begin(), triple.output3.end()));
}

// ── CipherState ──────────────────────────────────────────────────────────

TEST(NoiseCipher, NoKeyPassesThrough) {
    CipherState cs;
    EXPECT_FALSE(cs.has_key());
    const auto plain = bytes_of("plain bytes");
    auto enc = cs.encrypt_with_ad(std::span<const std::uint8_t>{}, plain);
    EXPECT_EQ(enc, plain);  // identity transform with no key
}

TEST(NoiseCipher, EncryptDecryptRoundTrip) {
    CipherKey k;
    k.fill(0x42);
    CipherState cs1, cs2;
    cs1.initialize_key(k);
    cs2.initialize_key(k);

    const auto ad    = bytes_of("aad-bytes");
    const auto plain = bytes_of("the secret message");
    auto enc = cs1.encrypt_with_ad(ad, plain);
    EXPECT_EQ(enc.size(), plain.size() + AEAD_TAG_BYTES);

    auto dec = cs2.decrypt_with_ad(ad, enc);
    ASSERT_TRUE(dec.has_value());
    EXPECT_EQ(*dec, plain);
}

TEST(NoiseCipher, NonceDivergenceFailsAuth) {
    CipherKey k;
    k.fill(0x11);
    CipherState cs1, cs2;
    cs1.initialize_key(k);
    cs2.initialize_key(k);

    const auto ad = std::span<const std::uint8_t>{};
    auto enc1 = cs1.encrypt_with_ad(ad, bytes_of("msg-1"));
    auto enc2 = cs1.encrypt_with_ad(ad, bytes_of("msg-2"));

    // cs2 reads msg-2 first — nonce mismatch fails AEAD.
    auto bad = cs2.decrypt_with_ad(ad, enc2);
    EXPECT_FALSE(bad.has_value());
    // cs2 nonce did not advance on failure; reading msg-1 still works.
    auto good = cs2.decrypt_with_ad(ad, enc1);
    ASSERT_TRUE(good.has_value());
    EXPECT_EQ(*good, bytes_of("msg-1"));
}

TEST(NoiseCipher, AdMismatchFailsAuth) {
    CipherKey k;
    k.fill(0x33);
    CipherState cs1, cs2;
    cs1.initialize_key(k);
    cs2.initialize_key(k);

    const auto ad_a = bytes_of("ad-a");
    const auto ad_b = bytes_of("ad-b");
    const auto plain = bytes_of("any payload");

    auto enc = cs1.encrypt_with_ad(ad_a, plain);
    auto bad = cs2.decrypt_with_ad(ad_b, enc);
    EXPECT_FALSE(bad.has_value());
}

TEST(NoiseCipherDeath, AbortsOnCounterAtMax) {
    /// Per Noise §5.1: incrementing the nonce counter past
    /// 2^64 - 1 must signal an error. The deterministic AEAD
    /// breaks catastrophically on nonce reuse — no recovery
    /// path exists in the wire protocol — so the cipher
    /// aborts before the next `crypto_aead_*` call.
    /// `test_set_nonce` is the in-tree test hatch on
    /// `cipher.hpp:63`; production code never reaches the
    /// 2^64 ceiling at any realistic message rate.
    GTEST_FLAG_SET(death_test_style, "threadsafe");
    CipherKey k;
    k.fill(0xAA);
    EXPECT_DEATH({
        CipherState cs;
        cs.initialize_key(k);
        cs.test_set_nonce(std::numeric_limits<std::uint64_t>::max());
        (void)cs.encrypt_with_ad(std::span<const std::uint8_t>{},
                                  bytes_of("never"));
    }, "");
    EXPECT_DEATH({
        CipherState cs;
        cs.initialize_key(k);
        cs.test_set_nonce(std::numeric_limits<std::uint64_t>::max());
        std::uint8_t ct[AEAD_TAG_BYTES] = {};
        (void)cs.decrypt_with_ad(std::span<const std::uint8_t>{},
                                  std::span<const std::uint8_t>(ct, sizeof(ct)));
    }, "");
}

TEST(NoiseCipher, RekeyChangesKey) {
    CipherKey k;
    k.fill(0x55);
    CipherState a, b;
    a.initialize_key(k);
    b.initialize_key(k);

    auto enc_pre = a.encrypt_with_ad(std::span<const std::uint8_t>{}, bytes_of("pre"));
    auto dec_pre = b.decrypt_with_ad(std::span<const std::uint8_t>{}, enc_pre);
    ASSERT_TRUE(dec_pre.has_value());

    a.rekey();
    b.rekey();

    auto enc_post = a.encrypt_with_ad(std::span<const std::uint8_t>{}, bytes_of("post"));
    auto dec_post = b.decrypt_with_ad(std::span<const std::uint8_t>{}, enc_post);
    ASSERT_TRUE(dec_post.has_value());
    EXPECT_EQ(*dec_post, bytes_of("post"));
}

// ── SymmetricState ───────────────────────────────────────────────────────

TEST(NoiseSymmetric, InitProducesShortNamePadded) {
    SymmetricState s;
    s.initialize("Noise_XX_25519_ChaChaPoly_BLAKE2b");
    Digest h = s.handshake_hash();
    // Name length 33 < HASHLEN=64, so first 33 bytes equal the name and the
    // remainder is zero.
    constexpr std::string_view name = "Noise_XX_25519_ChaChaPoly_BLAKE2b";
    EXPECT_EQ(std::memcmp(h.data(), name.data(), name.size()), 0);
    for (std::size_t i = name.size(); i < HASHLEN; ++i) EXPECT_EQ(h[i], 0);
}

TEST(NoiseSymmetric, MixHashChainsThroughInputs) {
    SymmetricState s;
    s.initialize("test-protocol");
    Digest h0 = s.handshake_hash();
    s.mix_hash(bytes_of("first"));
    Digest h1 = s.handshake_hash();
    s.mix_hash(bytes_of("second"));
    Digest h2 = s.handshake_hash();
    EXPECT_NE(std::vector<std::uint8_t>(h0.begin(), h0.end()),
              std::vector<std::uint8_t>(h1.begin(), h1.end()));
    EXPECT_NE(std::vector<std::uint8_t>(h1.begin(), h1.end()),
              std::vector<std::uint8_t>(h2.begin(), h2.end()));
}

TEST(NoiseSymmetric, MixKeyEnablesEncryption) {
    SymmetricState s;
    s.initialize("test-protocol");
    auto plain = bytes_of("payload");

    // Before MixKey, encrypt_and_hash returns plaintext (no cipher key).
    auto pre = s.encrypt_and_hash(plain);
    EXPECT_EQ(pre, plain);

    s.mix_key(bytes_of("ikm"));
    auto post = s.encrypt_and_hash(plain);
    // After MixKey, the cipher is keyed; ciphertext is plaintext + 16-byte tag.
    EXPECT_EQ(post.size(), plain.size() + AEAD_TAG_BYTES);
    EXPECT_NE(post, plain);
}

TEST(NoiseSymmetric, SplitProducesTwoIndependentCiphers) {
    SymmetricState s;
    s.initialize("split-test");
    s.mix_key(bytes_of("mix"));
    auto pair = s.split();
    EXPECT_TRUE(pair.first.has_key());
    EXPECT_TRUE(pair.second.has_key());

    auto enc1 = pair.first.encrypt_with_ad(std::span<const std::uint8_t>{}, bytes_of("a"));
    auto enc2 = pair.second.encrypt_with_ad(std::span<const std::uint8_t>{}, bytes_of("a"));
    EXPECT_NE(enc1, enc2);
}

// ── HandshakeState — XX round-trip ───────────────────────────────────────

namespace {

void run_xx_handshake(HandshakeState& initiator,
                       HandshakeState& responder) {
    // -> e
    auto m1 = initiator.write_message(std::span<const std::uint8_t>{});
    ASSERT_TRUE(m1.has_value());
    auto p1 = responder.read_message(*m1);
    ASSERT_TRUE(p1.has_value());
    EXPECT_TRUE(p1->empty());

    // <- e, ee, s, es
    auto m2 = responder.write_message(std::span<const std::uint8_t>{});
    ASSERT_TRUE(m2.has_value());
    auto p2 = initiator.read_message(*m2);
    ASSERT_TRUE(p2.has_value());
    EXPECT_TRUE(p2->empty());

    // -> s, se
    auto m3 = initiator.write_message(std::span<const std::uint8_t>{});
    ASSERT_TRUE(m3.has_value());
    auto p3 = responder.read_message(*m3);
    ASSERT_TRUE(p3.has_value());
    EXPECT_TRUE(p3->empty());

    EXPECT_TRUE(initiator.is_complete());
    EXPECT_TRUE(responder.is_complete());
}

} // namespace

TEST(NoiseHandshakeXX, FullRoundTripReachesMatchingHash) {
    Keypair init_static = generate_keypair();
    Keypair resp_static = generate_keypair();

    HandshakeState initiator(Pattern::XX, true,  init_static);
    HandshakeState responder(Pattern::XX, false, resp_static);

    run_xx_handshake(initiator, responder);

    Digest h_i = initiator.handshake_hash();
    Digest h_r = responder.handshake_hash();
    EXPECT_EQ(std::vector<std::uint8_t>(h_i.begin(), h_i.end()),
              std::vector<std::uint8_t>(h_r.begin(), h_r.end()));
}

TEST(NoiseHandshakeXX, PeerStaticKeysAreLearned) {
    Keypair init_static = generate_keypair();
    Keypair resp_static = generate_keypair();
    HandshakeState initiator(Pattern::XX, true,  init_static);
    HandshakeState responder(Pattern::XX, false, resp_static);
    run_xx_handshake(initiator, responder);

    // Initiator learns responder static during msg2.
    EXPECT_EQ(initiator.peer_static_public_key(), resp_static.pk);
    // Responder learns initiator static during msg3.
    EXPECT_EQ(responder.peer_static_public_key(), init_static.pk);
}

TEST(NoiseHandshakeXX, TransportCiphersInteroperate) {
    Keypair init_static = generate_keypair();
    Keypair resp_static = generate_keypair();
    HandshakeState initiator(Pattern::XX, true,  init_static);
    HandshakeState responder(Pattern::XX, false, resp_static);
    run_xx_handshake(initiator, responder);

    auto i_pair = initiator.split();
    auto r_pair = responder.split();

    TransportState init_t(std::move(i_pair.send), std::move(i_pair.recv));
    TransportState resp_t(std::move(r_pair.send), std::move(r_pair.recv));

    // Initiator → responder
    auto enc1 = init_t.encrypt(bytes_of("ping"));
    auto dec1 = resp_t.decrypt(enc1);
    ASSERT_TRUE(dec1.has_value());
    EXPECT_EQ(*dec1, bytes_of("ping"));

    // Responder → initiator
    auto enc2 = resp_t.encrypt(bytes_of("pong"));
    auto dec2 = init_t.decrypt(enc2);
    ASSERT_TRUE(dec2.has_value());
    EXPECT_EQ(*dec2, bytes_of("pong"));
}

TEST(NoiseHandshakeForwardSecrecy, SplitZeroisesStaticSecretXX) {
    /// `noise-handshake.md` §5 clause 4: Split clears the long-term
    /// static private key inside the handshake state. Before Split
    /// the buffer carries the supplied secret; after Split it is
    /// fully zero — the destructor sees an already-cleared buffer
    /// in the steady-state path.
    Keypair init_static = generate_keypair();
    Keypair resp_static = generate_keypair();
    HandshakeState initiator(Pattern::XX, true,  init_static);
    HandshakeState responder(Pattern::XX, false, resp_static);
    run_xx_handshake(initiator, responder);

    EXPECT_FALSE(initiator.static_secret_zeroised_for_test());
    EXPECT_FALSE(responder.static_secret_zeroised_for_test());

    [[maybe_unused]] auto i_pair = initiator.split();
    [[maybe_unused]] auto r_pair = responder.split();

    EXPECT_TRUE(initiator.static_secret_zeroised_for_test());
    EXPECT_TRUE(responder.static_secret_zeroised_for_test());
}

TEST(NoiseHandshakeForwardSecrecy, SplitZeroisesChainingKeyXX) {
    /// `noise-handshake.md` §5 clause 4: the symmetric chaining key
    /// has no remaining cryptographic purpose once Split has
    /// produced the transport ciphers. The buffer is cleared inside
    /// `SymmetricState::split()`; the handshake-state forwarder
    /// surfaces the observable.
    Keypair init_static = generate_keypair();
    Keypair resp_static = generate_keypair();
    HandshakeState initiator(Pattern::XX, true,  init_static);
    HandshakeState responder(Pattern::XX, false, resp_static);
    run_xx_handshake(initiator, responder);

    EXPECT_FALSE(initiator.chaining_key_zeroised_for_test());
    EXPECT_FALSE(responder.chaining_key_zeroised_for_test());

    [[maybe_unused]] auto i_pair = initiator.split();
    [[maybe_unused]] auto r_pair = responder.split();

    EXPECT_TRUE(initiator.chaining_key_zeroised_for_test());
    EXPECT_TRUE(responder.chaining_key_zeroised_for_test());
}

/// The next two tests intentionally probe the moved-from state to
/// pin the §5 clause 4 invariant: the moved-from source's secret
/// buffers are zero. The clang-tidy `bugprone-use-after-move` and
/// `clang-analyzer-cplusplus.Move` checks fire on the deliberate
/// reads — they are the test, not bugs.
// NOLINTBEGIN(bugprone-use-after-move,clang-analyzer-cplusplus.Move)

TEST(NoiseHandshakeForwardSecrecy, MoveConstructZeroisesSourceSecrets) {
    Keypair init_static = generate_keypair();
    HandshakeState orig(Pattern::XX, true, init_static);
    EXPECT_FALSE(orig.static_secret_zeroised_for_test());
    EXPECT_FALSE(orig.chaining_key_zeroised_for_test());

    HandshakeState moved(std::move(orig));
    /// Moved-into instance carries the secret; moved-from is wiped.
    EXPECT_FALSE(moved.static_secret_zeroised_for_test());
    EXPECT_FALSE(moved.chaining_key_zeroised_for_test());
    EXPECT_TRUE(orig.static_secret_zeroised_for_test());
    EXPECT_TRUE(orig.chaining_key_zeroised_for_test());
}

TEST(NoiseHandshakeForwardSecrecy, MoveAssignZeroisesSourceSecrets) {
    Keypair static_a = generate_keypair();
    Keypair static_b = generate_keypair();
    HandshakeState a(Pattern::XX, true, static_a);
    HandshakeState b(Pattern::XX, true, static_b);
    EXPECT_FALSE(a.static_secret_zeroised_for_test());
    EXPECT_FALSE(b.static_secret_zeroised_for_test());

    a = std::move(b);
    /// Destination now carries b's secret; source b is wiped.
    EXPECT_FALSE(a.static_secret_zeroised_for_test());
    EXPECT_FALSE(a.chaining_key_zeroised_for_test());
    EXPECT_TRUE(b.static_secret_zeroised_for_test());
    EXPECT_TRUE(b.chaining_key_zeroised_for_test());
}

// NOLINTEND(bugprone-use-after-move,clang-analyzer-cplusplus.Move)

TEST(NoiseTransportRekey, SymmetricThresholdRekeyKeepsInterop) {
    /// Auto-rekey trigger fires inside `noise_encrypt`/`noise_decrypt`
    /// once a CipherState reaches `REKEY_INTERVAL` (2^60). Both peers
    /// see the matching counter symmetrically — every encrypt by one
    /// side advances the peer's recv counter by one — so each side
    /// rekeys at the same point without coordination per
    /// `noise-handshake.md` §4. Pushing the counters to one short of
    /// the threshold and exchanging two frames runs the rekey path
    /// on both peers and asserts traffic continues to authenticate.
    Keypair init_static = generate_keypair();
    Keypair resp_static = generate_keypair();
    HandshakeState initiator(Pattern::XX, true,  init_static);
    HandshakeState responder(Pattern::XX, false, resp_static);
    run_xx_handshake(initiator, responder);

    auto i_pair = initiator.split();
    auto r_pair = responder.split();

    TransportState init_t(std::move(i_pair.send), std::move(i_pair.recv));
    TransportState resp_t(std::move(r_pair.send), std::move(r_pair.recv));

    init_t.test_set_nonces(REKEY_INTERVAL - 1, REKEY_INTERVAL - 1);
    resp_t.test_set_nonces(REKEY_INTERVAL - 1, REKEY_INTERVAL - 1);

    /// One encrypt+decrypt pair pushes both ciphers past the
    /// threshold; the next call observes `needs_rekey()` and runs
    /// the symmetric rekey on each side.
    auto e1 = init_t.encrypt(bytes_of("over-threshold"));
    if (init_t.needs_rekey()) init_t.rekey();
    auto d1 = resp_t.decrypt(e1);
    ASSERT_TRUE(d1.has_value());
    EXPECT_EQ(*d1, bytes_of("over-threshold"));
    if (resp_t.needs_rekey()) resp_t.rekey();

    /// Counters reset on both sides; subsequent traffic uses the
    /// fresh keys.
    EXPECT_EQ(init_t.send_nonce(), 0u);
    EXPECT_EQ(resp_t.recv_nonce(), 0u);

    auto e2 = resp_t.encrypt(bytes_of("post-rekey"));
    auto d2 = init_t.decrypt(e2);
    ASSERT_TRUE(d2.has_value());
    EXPECT_EQ(*d2, bytes_of("post-rekey"));
}

TEST(NoiseHandshakeXX, PayloadCarriedThroughEveryMessage) {
    Keypair init_static = generate_keypair();
    Keypair resp_static = generate_keypair();
    HandshakeState initiator(Pattern::XX, true,  init_static);
    HandshakeState responder(Pattern::XX, false, resp_static);

    const auto p1 = bytes_of("first-payload");
    auto m1 = initiator.write_message(p1);
    auto r1 = responder.read_message(*m1);
    ASSERT_TRUE(r1.has_value());
    EXPECT_EQ(*r1, p1);

    const auto p2 = bytes_of("second-payload");
    auto m2 = responder.write_message(p2);
    auto r2 = initiator.read_message(*m2);
    ASSERT_TRUE(r2.has_value());
    EXPECT_EQ(*r2, p2);

    const auto p3 = bytes_of("third-payload");
    auto m3 = initiator.write_message(p3);
    auto r3 = responder.read_message(*m3);
    ASSERT_TRUE(r3.has_value());
    EXPECT_EQ(*r3, p3);
}

// ── TransportState rekey ─────────────────────────────────────────────────

TEST(NoiseTransport, RekeyContinuesInteropAfterReset) {
    Keypair init_static = generate_keypair();
    Keypair resp_static = generate_keypair();
    HandshakeState initiator(Pattern::XX, true,  init_static);
    HandshakeState responder(Pattern::XX, false, resp_static);
    run_xx_handshake(initiator, responder);

    auto i_pair = initiator.split();
    auto r_pair = responder.split();
    TransportState init_t(std::move(i_pair.send), std::move(i_pair.recv));
    TransportState resp_t(std::move(r_pair.send), std::move(r_pair.recv));

    auto pre = init_t.encrypt(bytes_of("pre-rekey"));
    auto pre_dec = resp_t.decrypt(pre);
    ASSERT_TRUE(pre_dec.has_value());

    init_t.rekey();
    resp_t.rekey();

    EXPECT_EQ(init_t.send_nonce(), 0u);
    EXPECT_EQ(resp_t.recv_nonce(), 0u);

    auto post = init_t.encrypt(bytes_of("post-rekey"));
    auto post_dec = resp_t.decrypt(post);
    ASSERT_TRUE(post_dec.has_value());
    EXPECT_EQ(*post_dec, bytes_of("post-rekey"));
}

// NOLINTEND(bugprone-unchecked-optional-access)
