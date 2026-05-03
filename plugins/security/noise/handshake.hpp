// SPDX-License-Identifier: Apache-2.0
/// @file   plugins/security/noise/handshake.hpp
/// @brief  HandshakeState — Noise XX pattern progression on X25519.
///
/// Per `docs/contracts/noise-handshake.md`. The state machine is a step
/// counter advanced by `write_message` / `read_message` on the local
/// role. After the third pattern message, `is_complete()` returns true
/// and `split()` extracts the transport ciphers. The provider is
/// XX-only in v1; future patterns land in a sibling provider plugin
/// rather than as branches here.

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

/// Pattern selector. v1 ships the XX pattern only; the enum is kept
/// as a single-value bag so a v1.1 sibling provider can extend it
/// without an ABI break in the noise plugin's public surface.
enum class Pattern : std::uint8_t {
    XX = 0,  ///< unknown peer, three-message mutual auth
};

/// On-wire protocol-name strings — pinned by the contract.
[[nodiscard]] const char* protocol_name(Pattern p) noexcept;

class HandshakeState {
public:
    /// Construct a fresh XX handshake. The pattern parameter is
    /// passed verbatim through to `protocol_name()` and is required
    /// to be `Pattern::XX`; future patterns ship as a separate
    /// provider plugin per `noise-handshake.md` §1.
    HandshakeState(Pattern pattern,
                    bool initiator,
                    const Keypair& static_keys);

    HandshakeState(const HandshakeState&)            = delete;
    HandshakeState& operator=(const HandshakeState&) = delete;
    HandshakeState(HandshakeState&&) noexcept;
    HandshakeState& operator=(HandshakeState&&) noexcept;
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
    /// XX completes at 3. Plugins consult this to decide whose turn
    /// the next message belongs to.
    [[nodiscard]] int step() const noexcept { return step_; }

    /// Local role chosen at construction time.
    [[nodiscard]] bool initiator() const noexcept { return initiator_; }

    /// Channel-binding hash, available at any point during the handshake
    /// and frozen after Split.
    [[nodiscard]] Digest handshake_hash() const noexcept {
        return symmetric_.handshake_hash();
    }

    /// Peer static public key. Becomes valid after the pattern's
    /// encrypted-static message is consumed (XX message 2 on the
    /// initiator side, message 3 on the responder).
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

    /// Forward-secrecy observable: the long-term static private key
    /// buffer inside this handshake state is fully zero. Used by the
    /// regression suite that pins `noise-handshake.md` §5 clause 4 —
    /// production callers have no reason to consult this, the contract
    /// already states the handshake is unsafe to reuse after Split.
    [[nodiscard]] bool static_secret_zeroised_for_test() const noexcept;

    /// Forward-secrecy observable: the symmetric chaining key buffer
    /// embedded in this handshake state is fully zero. Same scope as
    /// `static_secret_zeroised_for_test()`.
    [[nodiscard]] bool chaining_key_zeroised_for_test() const noexcept;

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
