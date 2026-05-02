// SPDX-License-Identifier: Apache-2.0
/// @file   tests/unit/plugins/security/test_noise_cipher_property.cpp
/// @brief  RapidCheck property tests for the Noise CipherState
///         AEAD wrapper. Quantifies the encrypt/decrypt contract over
///         random keys, associated data, and plaintexts.
///
/// The deterministic cases in `test_noise.cpp` cover the happy path
/// with single-shot inputs. These properties exercise the full
/// (key × ad × plaintext) parameter space via RapidCheck so a
/// regression in the AEAD wrapper — wrong nonce encoding, key copy
/// vs move, broken tag handling — surfaces on a generated input
/// before it reaches a real handshake.

// clang-tidy treats `*opt` after `RC_ASSERT(opt.has_value())` as
// unchecked because the property-flow control is opaque to the
// analyser. The pattern is the standard rapidcheck idiom.
// NOLINTBEGIN(bugprone-unchecked-optional-access)

#include <gtest/gtest.h>
#include <rapidcheck/gtest.h>

#include "cipher.hpp"

#include <array>
#include <cstdint>
#include <span>
#include <vector>

namespace {

using gn::noise::AEAD_TAG_BYTES;
using gn::noise::CipherKey;
using gn::noise::CipherState;

/// Generator for a 32-byte symmetric key. Each byte is fully
/// arbitrary; rapidcheck shrinks toward zero on failure, which is
/// the safest default starting point for a key.
rc::Gen<CipherKey> key_gen() {
    return rc::gen::container<CipherKey>(rc::gen::arbitrary<std::uint8_t>());
}

/// Generator for arbitrary byte buffers up to a small cap. Crypto
/// failures usually surface with short inputs, and the property
/// budget is exhausted faster on multi-kilobyte buffers without
/// adding signal.
rc::Gen<std::vector<std::uint8_t>> bytes_gen(std::size_t cap) {
    return rc::gen::container<std::vector<std::uint8_t>>(
        *rc::gen::inRange<std::size_t>(0, cap + 1),
        rc::gen::arbitrary<std::uint8_t>());
}

CipherState fresh_cipher(const CipherKey& k) {
    CipherState cs;
    cs.initialize_key(k);
    return cs;
}

}  // namespace

/* ── Round-trip identity ─────────────────────────────────────────────────── */

RC_GTEST_PROP(NoiseCipherProperty,
              RoundtripWithRandomKeyAdPlaintext,
              ()) {
    const auto key       = *key_gen();
    const auto ad        = *bytes_gen(64);
    const auto plaintext = *bytes_gen(512);

    auto enc_cs = fresh_cipher(key);
    auto dec_cs = fresh_cipher(key);

    const auto ct = enc_cs.encrypt_with_ad(ad, plaintext);
    /// Tag adds exactly AEAD_TAG_BYTES on every key'd encrypt.
    RC_ASSERT(ct.size() == plaintext.size() + AEAD_TAG_BYTES);

    const auto pt_opt = dec_cs.decrypt_with_ad(ad, ct);
    RC_ASSERT(pt_opt.has_value());
    RC_ASSERT(*pt_opt == plaintext);
}

/* ── Empty plaintext is a legal AEAD input ──────────────────────────────── */

RC_GTEST_PROP(NoiseCipherProperty,
              EmptyPlaintextRoundtrips,
              ()) {
    const auto key = *key_gen();
    const auto ad  = *bytes_gen(64);

    auto enc_cs = fresh_cipher(key);
    auto dec_cs = fresh_cipher(key);

    const std::vector<std::uint8_t> empty{};
    const auto ct = enc_cs.encrypt_with_ad(ad, empty);
    /// Tag-only ciphertext for empty plaintext.
    RC_ASSERT(ct.size() == AEAD_TAG_BYTES);

    const auto pt_opt = dec_cs.decrypt_with_ad(ad, ct);
    RC_ASSERT(pt_opt.has_value());
    RC_ASSERT(pt_opt->empty());
}

/* ── Sequential nonces produce distinct ciphertexts ──────────────────────── */

RC_GTEST_PROP(NoiseCipherProperty,
              SequentialEncryptsOfSamePlaintextProduceDistinctCiphertexts,
              ()) {
    const auto key       = *key_gen();
    const auto ad        = *bytes_gen(64);
    const auto plaintext = *bytes_gen(256);

    /// A non-empty plaintext is needed for body distinctness; tag
    /// alone differs but the body comparison is the property.
    RC_PRE(!plaintext.empty());

    auto cs = fresh_cipher(key);
    const auto ct1 = cs.encrypt_with_ad(ad, plaintext);  /* nonce 0 */
    const auto ct2 = cs.encrypt_with_ad(ad, plaintext);  /* nonce 1 */

    RC_ASSERT(ct1 != ct2);
    RC_ASSERT(cs.nonce() == 2u);
}

/* ── Tampering rejection: ciphertext bit-flip ────────────────────────────── */

RC_GTEST_PROP(NoiseCipherProperty,
              BitFlipInCiphertextFailsAuth,
              ()) {
    const auto key       = *key_gen();
    const auto ad        = *bytes_gen(64);
    const auto plaintext = *bytes_gen(256);

    auto enc_cs = fresh_cipher(key);
    auto ct = enc_cs.encrypt_with_ad(ad, plaintext);
    RC_PRE(!ct.empty());  /// At least the tag is present.

    /// Flip one random bit in the ciphertext. Either the body byte
    /// fails Poly1305 verification or the tag itself does.
    const auto byte_idx = *rc::gen::inRange<std::size_t>(0, ct.size());
    const auto bit_idx  = *rc::gen::inRange<std::uint8_t>(0, 8);
    ct[byte_idx]        ^= static_cast<std::uint8_t>(1u << bit_idx);

    auto dec_cs = fresh_cipher(key);
    const auto pt_opt = dec_cs.decrypt_with_ad(ad, ct);
    RC_ASSERT(!pt_opt.has_value());
}

/* ── Tampering rejection: ad bit-flip ────────────────────────────────────── */

RC_GTEST_PROP(NoiseCipherProperty,
              BitFlipInAdFailsAuth,
              ()) {
    const auto key       = *key_gen();
    auto       ad        = *bytes_gen(64);
    const auto plaintext = *bytes_gen(256);

    /// AAD-empty AEAD never authenticates the AAD slot — the property
    /// only holds when the slot has at least one bit to flip.
    RC_PRE(!ad.empty());

    auto enc_cs = fresh_cipher(key);
    const auto ct = enc_cs.encrypt_with_ad(ad, plaintext);

    const auto byte_idx = *rc::gen::inRange<std::size_t>(0, ad.size());
    const auto bit_idx  = *rc::gen::inRange<std::uint8_t>(0, 8);
    ad[byte_idx]        ^= static_cast<std::uint8_t>(1u << bit_idx);

    auto dec_cs = fresh_cipher(key);
    const auto pt_opt = dec_cs.decrypt_with_ad(ad, ct);
    RC_ASSERT(!pt_opt.has_value());
}

/* ── Distinct keys produce distinct ciphertexts ──────────────────────────── */

RC_GTEST_PROP(NoiseCipherProperty,
              DistinctKeysProduceDistinctCiphertexts,
              ()) {
    const auto k1        = *key_gen();
    const auto k2        = *key_gen();
    const auto ad        = *bytes_gen(64);
    const auto plaintext = *bytes_gen(256);

    /// Skip the (probabilistically negligible) collision case — a
    /// 32-byte arbitrary collision means rapidcheck shrunk to two
    /// identical keys; that is not a property violation.
    RC_PRE(k1 != k2);
    RC_PRE(!plaintext.empty());

    auto cs1 = fresh_cipher(k1);
    auto cs2 = fresh_cipher(k2);

    const auto ct1 = cs1.encrypt_with_ad(ad, plaintext);
    const auto ct2 = cs2.encrypt_with_ad(ad, plaintext);

    RC_ASSERT(ct1 != ct2);
}

/* ── Cross-cipher decrypt: same key, fresh state, decrypts ───────────────── */

RC_GTEST_PROP(NoiseCipherProperty,
              FreshDecryptStateAtSameNonceSucceeds,
              ()) {
    const auto key       = *key_gen();
    const auto ad        = *bytes_gen(64);
    const auto plaintext = *bytes_gen(256);

    auto enc_cs = fresh_cipher(key);
    const auto ct = enc_cs.encrypt_with_ad(ad, plaintext);

    /// A second cipher instance, same key, never observed any bytes,
    /// must still decrypt because the nonce starts at zero on
    /// initialise. Catches a future regression where rekey state
    /// or some hidden counter leaks into fresh CipherStates.
    auto dec_cs = fresh_cipher(key);
    const auto pt_opt = dec_cs.decrypt_with_ad(ad, ct);
    RC_ASSERT(pt_opt.has_value());
    RC_ASSERT(*pt_opt == plaintext);
    RC_ASSERT(dec_cs.nonce() == 1u);
}

// NOLINTEND(bugprone-unchecked-optional-access)
