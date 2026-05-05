// SPDX-License-Identifier: Apache-2.0
/// @file   plugins/security/noise/symmetric.hpp
/// @brief  SymmetricState per Noise §5.2 — chaining key + handshake hash + cipher.

#pragma once

#include "cipher.hpp"
#include "hash.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace gn::noise {

class SymmetricState {
public:
    SymmetricState() = default;

    SymmetricState(const SymmetricState&)            = delete;
    SymmetricState& operator=(const SymmetricState&) = delete;
    SymmetricState(SymmetricState&&) noexcept;
    SymmetricState& operator=(SymmetricState&&) noexcept;
    ~SymmetricState();

    /// Initialise per Noise §5.2: if the protocol name fits in HASHLEN
    /// bytes, h = name padded with zeros to HASHLEN; otherwise
    /// h = HASH(name). ck = h. Cipher has no key.
    void initialize(std::string_view protocol_name);

    /// MixKey: (ck, temp_k) = HKDF(ck, ikm, 2); cipher.initialize_key(temp_k[0..32]).
    void mix_key(std::span<const std::uint8_t> input_key_material);

    /// MixHash: h = HASH(h || data).
    void mix_hash(std::span<const std::uint8_t> data);

    /// EncryptAndHash: ciphertext = cipher.encrypt(h, plaintext); MixHash(ciphertext).
    [[nodiscard]] std::vector<std::uint8_t>
    encrypt_and_hash(std::span<const std::uint8_t> plaintext);

    /// DecryptAndHash: plaintext = cipher.decrypt(h, ciphertext); MixHash(ciphertext).
    /// Returns nullopt on AEAD authentication failure; the hash is mixed
    /// only on success.
    [[nodiscard]] std::optional<std::vector<std::uint8_t>>
    decrypt_and_hash(std::span<const std::uint8_t> ciphertext);

    /// Split: (k1, k2) = HKDF(ck, "", 2). Returns two independent ciphers
    /// keyed with the first 32 bytes of each output.
    struct SplitPair {
        CipherState first;
        CipherState second;
    };
    [[nodiscard]] SplitPair split();

    /// Snapshot of the channel-binding hash. Returned by value so the
    /// internal state can be zeroised independently.
    [[nodiscard]] Digest handshake_hash() const noexcept { return h_; }

    /// Forward-secrecy observable: the chaining key buffer inside this
    /// state is fully zero. The regression suite that pins
    /// `plugins/security/noise/docs/handshake.md` §5 clause 4 consults this — production
    /// callers do not.
    [[nodiscard]] bool chaining_key_zeroised_for_test() const noexcept;

private:
    Digest      ck_{};   ///< chaining key
    Digest      h_{};    ///< handshake hash
    CipherState cipher_;
};

} // namespace gn::noise
