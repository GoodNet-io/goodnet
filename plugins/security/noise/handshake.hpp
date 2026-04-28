// SPDX-License-Identifier: Apache-2.0
/// @file   plugins/security/noise/handshake.hpp
/// @brief  HandshakeState — XX and IK pattern progression on X25519.
///
/// Per `docs/contracts/noise-handshake.md`. The state machine is a step
/// counter advanced by `write_message` / `read_message` on the local
/// role. After the last pattern message, `is_complete()` returns true
/// and `split()` extracts the transport ciphers.

#pragma once

#include "cipher.hpp"
#include "symmetric.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace gn::noise {

inline constexpr std::size_t DH_PUBLIC_KEY_BYTES  = 32;
inline constexpr std::size_t DH_PRIVATE_KEY_BYTES = 32;
inline constexpr std::size_t DH_OUTPUT_BYTES      = 32;

using PublicKey  = std::array<std::uint8_t, DH_PUBLIC_KEY_BYTES>;
using PrivateKey = std::array<std::uint8_t, DH_PRIVATE_KEY_BYTES>;

struct Keypair {
    PublicKey  pk;
    PrivateKey sk;
};

/// Generate a fresh X25519 keypair using libsodium's CSPRNG.
[[nodiscard]] Keypair generate_keypair();

/// Pattern selector. The vtable picks the pattern at handshake_open time.
enum class Pattern : std::uint8_t {
    XX = 0,  ///< unknown peer, three-message mutual auth
    IK = 1,  ///< initiator knows responder pk, two-message
};

/// On-wire protocol-name strings — pinned by the contract.
[[nodiscard]] const char* protocol_name(Pattern p) noexcept;

class HandshakeState {
public:
    /// Construct a fresh handshake.
    ///
    /// @param remote_static_pk required for IK initiator; ignored otherwise.
    HandshakeState(Pattern pattern,
                    bool initiator,
                    const Keypair& static_keys,
                    std::optional<PublicKey> remote_static_pk = std::nullopt);

    HandshakeState(const HandshakeState&)            = delete;
    HandshakeState& operator=(const HandshakeState&) = delete;
    HandshakeState(HandshakeState&&)                 = default;
    HandshakeState& operator=(HandshakeState&&)      = default;
    ~HandshakeState();

    /// Produce the next handshake message. The payload may be empty.
    /// Returns the message bytes, or nullopt on internal failure
    /// (invalid DH, AEAD failure on encrypt — should never trigger).
    [[nodiscard]] std::optional<std::vector<std::uint8_t>>
    write_message(std::span<const std::uint8_t> payload);

    /// Consume an incoming handshake message. Returns the extracted
    /// payload (may be empty), or nullopt on AEAD authentication failure.
    [[nodiscard]] std::optional<std::vector<std::uint8_t>>
    read_message(std::span<const std::uint8_t> message);

    /// True once every pattern message has been processed.
    [[nodiscard]] bool is_complete() const noexcept;

    /// Number of pattern messages already processed (read or written).
    /// XX completes at 3, IK at 2. Plugins consult this to decide
    /// whose turn the next message belongs to.
    [[nodiscard]] int step() const noexcept { return step_; }

    /// Local role chosen at construction time.
    [[nodiscard]] bool initiator() const noexcept { return initiator_; }

    /// Channel-binding hash, available at any point during the handshake
    /// and frozen after Split.
    [[nodiscard]] Digest handshake_hash() const noexcept {
        return symmetric_.handshake_hash();
    }

    /// Peer static public key. For IK initiator this is the preshared
    /// value supplied at construction; for every other role it becomes
    /// valid after the pattern reveals it.
    [[nodiscard]] const PublicKey& peer_static_public_key() const noexcept {
        return rs_;
    }

    /// Convenience: returns true after `peer_static_public_key()` is
    /// authenticated by the pattern.
    [[nodiscard]] bool peer_static_known() const noexcept {
        return rs_known_;
    }

    /// Split into transport ciphers. Initiator gets {send, recv} mapped
    /// to the first/second HKDF outputs; responder gets the inverse.
    /// Pre: is_complete() == true.
    struct TransportPair {
        CipherState send;
        CipherState recv;
    };
    [[nodiscard]] TransportPair split();

private:
    Pattern        pattern_;
    bool           initiator_;
    int            step_ = 0;
    int            steps_total_;
    SymmetricState symmetric_;
    PrivateKey     s_sk_{};
    PublicKey      s_pk_{};
    PrivateKey     e_sk_{};
    PublicKey      e_pk_{};
    PublicKey      rs_{};
    PublicKey      re_{};
    bool           rs_known_ = false;
};

} // namespace gn::noise
