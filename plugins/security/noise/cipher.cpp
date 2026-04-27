// SPDX-License-Identifier: Apache-2.0
#include "cipher.hpp"

#include <sodium.h>

#include <cstring>

namespace gn::noise {
namespace {

/// Build the 12-byte ChaCha20-Poly1305 IETF nonce per Noise §5.1:
/// four zero bytes followed by @p counter in little-endian order.
void encode_nonce(std::uint64_t counter,
                  std::uint8_t out[AEAD_NONCE_BYTES]) noexcept {
    out[0] = out[1] = out[2] = out[3] = 0;
    for (int i = 0; i < 8; ++i) {
        out[4 + i] = static_cast<std::uint8_t>((counter >> (i * 8)) & 0xFFu);
    }
}

} // namespace

CipherState::CipherState(CipherState&& other) noexcept
    : k_(other.k_), n_(other.n_), has_key_(other.has_key_) {
    other.zeroize();
}

CipherState& CipherState::operator=(CipherState&& other) noexcept {
    if (this != &other) {
        zeroize();
        k_       = other.k_;
        n_       = other.n_;
        has_key_ = other.has_key_;
        other.zeroize();
    }
    return *this;
}

CipherState::~CipherState() {
    zeroize();
}

void CipherState::initialize_key(const CipherKey& k) noexcept {
    k_       = k;
    n_       = 0;
    has_key_ = true;
}

std::vector<std::uint8_t>
CipherState::encrypt_with_ad(std::span<const std::uint8_t> ad,
                              std::span<const std::uint8_t> plaintext) {
    if (!has_key_) {
        return std::vector<std::uint8_t>(plaintext.begin(), plaintext.end());
    }

    std::uint8_t nonce[AEAD_NONCE_BYTES];
    encode_nonce(n_, nonce);

    std::vector<std::uint8_t> out(plaintext.size() + AEAD_TAG_BYTES);
    unsigned long long out_len = 0;
    crypto_aead_chacha20poly1305_ietf_encrypt(
        out.data(), &out_len,
        plaintext.data(), plaintext.size(),
        ad.data(), ad.size(),
        nullptr,
        nonce, k_.data());
    out.resize(static_cast<std::size_t>(out_len));
    ++n_;
    return out;
}

std::optional<std::vector<std::uint8_t>>
CipherState::decrypt_with_ad(std::span<const std::uint8_t> ad,
                              std::span<const std::uint8_t> ciphertext) {
    if (!has_key_) {
        return std::vector<std::uint8_t>(ciphertext.begin(), ciphertext.end());
    }
    if (ciphertext.size() < AEAD_TAG_BYTES) {
        return std::nullopt;
    }

    std::uint8_t nonce[AEAD_NONCE_BYTES];
    encode_nonce(n_, nonce);

    std::vector<std::uint8_t> out(ciphertext.size() - AEAD_TAG_BYTES);
    unsigned long long out_len = 0;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            out.data(), &out_len,
            nullptr,
            ciphertext.data(), ciphertext.size(),
            ad.data(), ad.size(),
            nonce, k_.data()) != 0) {
        return std::nullopt;
    }
    out.resize(static_cast<std::size_t>(out_len));
    ++n_;
    return out;
}

void CipherState::rekey() noexcept {
    if (!has_key_) return;

    std::uint8_t nonce[AEAD_NONCE_BYTES];
    encode_nonce(0xFFFFFFFFFFFFFFFFULL, nonce);

    std::uint8_t zeros[CIPHER_KEY_BYTES] = {};
    std::uint8_t out[CIPHER_KEY_BYTES + AEAD_TAG_BYTES];
    unsigned long long out_len = 0;
    crypto_aead_chacha20poly1305_ietf_encrypt(
        out, &out_len,
        zeros, CIPHER_KEY_BYTES,
        nullptr, 0,
        nullptr,
        nonce, k_.data());

    std::memcpy(k_.data(), out, CIPHER_KEY_BYTES);
    sodium_memzero(out, sizeof(out));
}

void CipherState::zeroize() noexcept {
    sodium_memzero(k_.data(), CIPHER_KEY_BYTES);
    n_       = 0;
    has_key_ = false;
}

} // namespace gn::noise
