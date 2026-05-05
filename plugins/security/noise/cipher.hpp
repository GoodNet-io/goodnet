// SPDX-License-Identifier: Apache-2.0
/// @file   plugins/security/noise/cipher.hpp
/// @brief  CipherState — ChaCha20-Poly1305 IETF AEAD with Noise nonce encoding.
///
/// Per Noise §5.1 a CipherState carries a 32-byte key and a 64-bit
/// nonce counter. The 12-byte ChaCha20-Poly1305 IETF nonce is built as
/// 4 zero bytes followed by the 64-bit counter in little-endian order.

#pragma once

#include <array>
#include <cstdint>
#include <cstddef>
#include <optional>
#include <span>
#include <vector>

namespace gn::noise {

inline constexpr std::size_t CIPHER_KEY_BYTES = 32;
inline constexpr std::size_t AEAD_TAG_BYTES   = 16;
inline constexpr std::size_t AEAD_NONCE_BYTES = 12;

using CipherKey = std::array<std::uint8_t, CIPHER_KEY_BYTES>;

/// CipherState per Noise §5.1.
///
/// Owned by SymmetricState during the handshake and by TransportState
/// after Split. Single-strand access is the project invariant — a
/// connection's reads and writes are serialised on a Asio strand,
/// so no atomics are needed for the nonce counter.
class CipherState {
public:
    CipherState() = default;

    CipherState(const CipherState&)            = delete;
    CipherState& operator=(const CipherState&) = delete;
    CipherState(CipherState&&)                 noexcept;
    CipherState& operator=(CipherState&&)      noexcept;
    ~CipherState();

    /// Initialise the cipher with a 32-byte key. Nonce resets to zero.
    void initialize_key(const CipherKey& k) noexcept;

    [[nodiscard]] bool          has_key() const noexcept { return has_key_; }
    [[nodiscard]] std::uint64_t nonce()   const noexcept { return n_; }

    /// Reset the nonce counter to zero. Called by `TransportState::rekey`
    /// per `plugins/security/noise/docs/handshake.md` §4 — both sides reset on the same
    /// boundary so AES-GCM with a fresh key + zero nonce is independent
    /// of any earlier (key, nonce) pair. Restricted to the rekey path
    /// because arbitrary nonce assignment would let a caller force a
    /// (key, nonce) collision and leak keystream.
    void reset_nonce_to_zero() noexcept { n_ = 0; }

#ifdef GN_TEST_HOOKS
    /// Test-only seam: place the nonce counter at an arbitrary value
    /// so the rekey threshold path runs without burning 2^60 encrypt
    /// operations at suite time. Compiled out in production via the
    /// `GN_TEST_HOOKS` macro — surfacing nonce assignment in the
    /// shipped binary would let a misuse trip nonce reuse and hand
    /// the attacker a keystream collision.
    void test_set_nonce(std::uint64_t n) noexcept { n_ = n; }
#endif

    /// Encrypts @p plaintext with associated data @p ad. When the cipher
    /// has no key (pre-Split, or null suite) returns the plaintext
    /// unmodified — Noise §5.1 EncryptWithAd contract.
    [[nodiscard]] std::vector<std::uint8_t>
    encrypt_with_ad(std::span<const std::uint8_t> ad,
                    std::span<const std::uint8_t> plaintext);

    /// Decrypts @p ciphertext (must include the 16-byte tag at the tail).
    /// Returns nullopt on AEAD authentication failure; on success the
    /// nonce advances by one. With no key, returns @p ciphertext as-is.
    [[nodiscard]] std::optional<std::vector<std::uint8_t>>
    decrypt_with_ad(std::span<const std::uint8_t> ad,
                    std::span<const std::uint8_t> ciphertext);

    /// REKEY per Noise §4.2: new key = first 32 bytes of
    /// ENCRYPT(k, 2^64-1, ad="", plaintext=zeros[32]). Nonce is left
    /// untouched at this layer; the TransportState resets nonces on
    /// both ciphers atomically per `plugins/security/noise/docs/handshake.md` §4.
    void rekey() noexcept;

    /// Securely erase key material and reset state.
    void zeroize() noexcept;

private:
    CipherKey     k_{};
    std::uint64_t n_ = 0;
    bool          has_key_ = false;
};

} // namespace gn::noise
