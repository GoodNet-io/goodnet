// SPDX-License-Identifier: Apache-2.0
/// @file   plugins/security/noise/transport.hpp
/// @brief  TransportState — post-handshake send/recv ciphers with rekey.

#pragma once

#include "cipher.hpp"

#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace gn::noise {

inline constexpr std::uint64_t REKEY_INTERVAL = 1ULL << 60;

/// TransportState carries the two CipherStates produced by Split().
/// Per `plugins/security/noise/docs/handshake.md` §4 a `rekey()` call advances both ciphers
/// atomically and resets both nonces to zero.
class TransportState {
public:
    TransportState() = default;
    TransportState(CipherState send, CipherState recv) noexcept
        : send_(std::move(send)), recv_(std::move(recv)) {}

    TransportState(const TransportState&)            = delete;
    TransportState& operator=(const TransportState&) = delete;
    TransportState(TransportState&&)                 = default;
    TransportState& operator=(TransportState&&)      = default;

    /// Encrypt a transport-phase frame. Empty associated data per §7.
    [[nodiscard]] std::vector<std::uint8_t>
    encrypt(std::span<const std::uint8_t> plaintext) {
        return send_.encrypt_with_ad(std::span<const std::uint8_t>{}, plaintext);
    }

    /// Decrypt a transport-phase frame. Empty associated data per §7.
    [[nodiscard]] std::optional<std::vector<std::uint8_t>>
    decrypt(std::span<const std::uint8_t> ciphertext) {
        return recv_.decrypt_with_ad(std::span<const std::uint8_t>{}, ciphertext);
    }

    /// Atomic rekey: derive next keys on both ciphers and reset both
    /// nonces to zero per `plugins/security/noise/docs/handshake.md` §4. The peer is expected
    /// to invoke `rekey()` at the same point in its own counter so the
    /// two sides stay in sync.
    void rekey() noexcept {
        send_.rekey();
        recv_.rekey();
        send_.reset_nonce_to_zero();
        recv_.reset_nonce_to_zero();
    }

    [[nodiscard]] std::uint64_t send_nonce() const noexcept { return send_.nonce(); }
    [[nodiscard]] std::uint64_t recv_nonce() const noexcept { return recv_.nonce(); }

    /// True when either nonce has reached the rekey threshold.
    [[nodiscard]] bool needs_rekey() const noexcept {
        return send_.nonce() >= REKEY_INTERVAL || recv_.nonce() >= REKEY_INTERVAL;
    }

#ifdef GN_TEST_HOOKS
    /// Test-only seam: push both counters to a chosen value so the
    /// rekey threshold path runs without burning 2^60 encrypt
    /// operations at suite time. Compiled out in production via the
    /// `GN_TEST_HOOKS` macro so a shipped binary cannot be coaxed
    /// into nonce reuse → keystream collision → plaintext recovery.
    void test_set_nonces(std::uint64_t send_n,
                          std::uint64_t recv_n) noexcept {
        send_.test_set_nonce(send_n);
        recv_.test_set_nonce(recv_n);
    }
#endif

private:
    CipherState send_;
    CipherState recv_;
};

} // namespace gn::noise
