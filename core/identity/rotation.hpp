/// @file   core/identity/rotation.hpp
/// @brief  User-key rotation primitive: signed proof that the
///         holder of `prev_user_pk` authorised the move to
///         `new_user_pk`.
///
/// Wire format:
/// ```
///   0  4   magic   = "GNRX"
///   4  1   version = 0x01
///   5  1   flags   = reserved 0
///   6  32  new_user_pk
///   38 32  prev_user_pk
///   70 8   counter (BE64, monotonic — anti-replay)
///   78 8   valid_from_unix_ts (BE64, signed)
///   86 64  signature by prev_user_pk
///   ──
///   150 bytes total
/// ```
/// The signature covers SHA-256 of bytes 0..85 (everything except
/// the signature itself). Verification is canonical Ed25519 via
/// libsodium.
///
/// Counter is monotonic per `prev_user_pk`: a peer rejects a proof
/// whose counter does not strictly exceed the highest seen so far
/// for that user_pk, defeating replays of older valid proofs.
/// Persisting the counter alongside the key in the on-disk identity
/// file makes the gate restart-safe.

#pragma once

#include <array>
#include <cstdint>
#include <span>

#include <sdk/cpp/types.hpp>

#include "keypair.hpp"

namespace gn::core::identity {

inline constexpr std::array<std::uint8_t, 4> kRotationMagic{
    'G', 'N', 'R', 'X'};
inline constexpr std::uint8_t                kRotationVersion = 0x01;
inline constexpr std::size_t                 kRotationProofBytes = 150;
inline constexpr std::size_t                 kRotationProofSignedBytes = 86;
inline constexpr std::size_t                 kRotationProofSigOffset   = 86;

/// Parsed view of a `RotationProof`. All fields are big-endian on
/// the wire; this struct stores them in host order.
struct RotationProof {
    ::gn::PublicKey                 new_user_pk;
    ::gn::PublicKey                 prev_user_pk;
    std::uint64_t                   counter;
    std::int64_t                    valid_from_unix_ts;
    std::array<std::uint8_t, 64>    sig_by_prev{};
};

/// Sign a rotation proof with @p prev_user_kp and pack it onto the
/// 150-byte wire buffer. Returns `GN_OK` on success.
[[nodiscard]] ::gn::Result<std::array<std::uint8_t, kRotationProofBytes>>
sign_rotation(const KeyPair&                prev_user_kp,
              const ::gn::PublicKey&        new_user_pk,
              std::uint64_t                 counter,
              std::int64_t                  valid_from_unix_ts);

/// Parse + verify a 150-byte rotation proof. Checks magic,
/// version, flags, then the Ed25519 signature against the
/// supplied @p expected_prev_user_pk (which must match the
/// `prev_user_pk` field). Returns the parsed view on success;
/// `INTEGRITY_FAILED` on any structural / signature mismatch.
[[nodiscard]] ::gn::Result<RotationProof>
verify_rotation(std::span<const std::uint8_t>      wire,
                const ::gn::PublicKey&             expected_prev_user_pk);

} // namespace gn::core::identity
