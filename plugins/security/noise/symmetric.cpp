// SPDX-License-Identifier: Apache-2.0
#include "symmetric.hpp"
#include "hkdf.hpp"

#include <sodium.h>

#include <cstring>

namespace gn::noise {

SymmetricState::~SymmetricState() {
    sodium_memzero(ck_.data(), HASHLEN);
    sodium_memzero(h_.data(),  HASHLEN);
}

void SymmetricState::initialize(std::string_view protocol_name) {
    if (protocol_name.size() <= HASHLEN) {
        h_.fill(0);
        std::memcpy(h_.data(), protocol_name.data(), protocol_name.size());
    } else {
        const auto* p = reinterpret_cast<const std::uint8_t*>(protocol_name.data());
        h_ = blake2b(std::span<const std::uint8_t>(p, protocol_name.size()));
    }
    ck_ = h_;
    cipher_ = CipherState{};
}

void SymmetricState::mix_key(std::span<const std::uint8_t> input_key_material) {
    HkdfPair out = hkdf2(std::span<const std::uint8_t>(ck_.data(), HASHLEN),
                          input_key_material);
    ck_ = out.output1;

    /// Per Noise spec §5.2 the cipher key is the first 32 bytes of
    /// HKDF output when HASHLEN > 32. With HASHLEN = 64 we always
    /// truncate.
    CipherKey ck_truncated;
    std::memcpy(ck_truncated.data(), out.output2.data(), CIPHER_KEY_BYTES);
    cipher_.initialize_key(ck_truncated);

    sodium_memzero(out.output2.data(), HASHLEN);
    sodium_memzero(ck_truncated.data(), CIPHER_KEY_BYTES);
}

void SymmetricState::mix_hash(std::span<const std::uint8_t> data) {
    h_ = blake2b(std::span<const std::uint8_t>(h_.data(), HASHLEN), data);
}

std::vector<std::uint8_t>
SymmetricState::encrypt_and_hash(std::span<const std::uint8_t> plaintext) {
    auto ciphertext = cipher_.encrypt_with_ad(
        std::span<const std::uint8_t>(h_.data(), HASHLEN), plaintext);
    mix_hash(std::span<const std::uint8_t>(ciphertext.data(), ciphertext.size()));
    return ciphertext;
}

std::optional<std::vector<std::uint8_t>>
SymmetricState::decrypt_and_hash(std::span<const std::uint8_t> ciphertext) {
    auto plaintext = cipher_.decrypt_with_ad(
        std::span<const std::uint8_t>(h_.data(), HASHLEN), ciphertext);
    if (!plaintext) return std::nullopt;
    mix_hash(ciphertext);
    return plaintext;
}

SymmetricState::SplitPair SymmetricState::split() {
    HkdfPair out = hkdf2(std::span<const std::uint8_t>(ck_.data(), HASHLEN),
                          std::span<const std::uint8_t>{});

    CipherKey k1, k2;
    std::memcpy(k1.data(), out.output1.data(), CIPHER_KEY_BYTES);
    std::memcpy(k2.data(), out.output2.data(), CIPHER_KEY_BYTES);

    SplitPair result;
    result.first.initialize_key(k1);
    result.second.initialize_key(k2);

    sodium_memzero(out.output1.data(), HASHLEN);
    sodium_memzero(out.output2.data(), HASHLEN);
    sodium_memzero(k1.data(), CIPHER_KEY_BYTES);
    sodium_memzero(k2.data(), CIPHER_KEY_BYTES);
    return result;
}

} // namespace gn::noise
