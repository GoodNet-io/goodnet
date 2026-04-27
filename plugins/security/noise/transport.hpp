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
/// Per `noise-handshake.md` §4 a `rekey()` call advances both ciphers
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
    /// nonces to zero per `noise-handshake.md` §4. The peer is expected
    /// to invoke `rekey()` at the same point in its own counter so the
    /// two sides stay in sync.
    void rekey() noexcept {
        send_.rekey();
        recv_.rekey();
        send_.set_nonce(0);
        recv_.set_nonce(0);
    }

    [[nodiscard]] std::uint64_t send_nonce() const noexcept { return send_.nonce(); }
    [[nodiscard]] std::uint64_t recv_nonce() const noexcept { return recv_.nonce(); }

    /// True when either nonce has reached the rekey threshold.
    [[nodiscard]] bool needs_rekey() const noexcept {
        return send_.nonce() >= REKEY_INTERVAL || recv_.nonce() >= REKEY_INTERVAL;
    }

private:
    CipherState send_;
    CipherState recv_;
};

} // namespace gn::noise
