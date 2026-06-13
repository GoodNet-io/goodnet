/// @file   core/identity/attestation.hpp
/// @brief  User-signed device attestation cert.
///
/// Proves that `user_pk` authorised `device_pk` to act under its
/// identity until `expiry_unix_ts`. Peers verify the cert during
/// security handshake before promoting the connection from
/// Untrusted to Peer (per `security-trust.en.md` §3).

#pragma once

#include <array>
#include <cstdint>
#include <span>

#include <sdk/cpp/types.hpp>

#include "keypair.hpp"
#include "signer.hpp"

namespace gn::core::identity {

/// Plain-data attestation. Serialised on the wire as
/// `user_pk || device_pk || expiry_be64 || signature` for a fixed
/// total of 32 + 32 + 8 + 64 = 136 bytes.
inline constexpr std::size_t kAttestationBytes = 136;

struct Attestation {
    ::gn::PublicKey                                   user_pk{};
    ::gn::PublicKey                                   device_pk{};
    std::int64_t                                      expiry_unix_ts{0};
    std::array<std::uint8_t, kEd25519SignatureBytes>  signature{};

    /// Build an attestation by signing `(user_pk || device_pk ||
    /// expiry_be64)` with @p user. Thin wrapper retained so test
    /// fixtures that hold a `KeyPair` directly keep compiling;
    /// internally it routes through the `IdentitySigner` overload
    /// below so the actual signing path is the Phase-1 abstraction.
    [[nodiscard]] static ::gn::Result<Attestation> create(
        const KeyPair&         user,
        const ::gn::PublicKey& device_pk,
        std::int64_t           expiry_unix_ts);

    /// Build an attestation by signing through @p user_signer (whose
    /// public key the caller passes as @p user_pk for the binding
    /// payload). Used by `NodeIdentity::compose` so the identity-key
    /// signing path is the same whether the signer is the in-process
    /// `LibsodiumSigner` or, in a later phase, an HSM-backed
    /// implementation that never exposes the seed.
    [[nodiscard]] static ::gn::Result<Attestation> create(
        IdentitySigner&        user_signer,
        const ::gn::PublicKey& user_pk,
        const ::gn::PublicKey& device_pk,
        std::int64_t           expiry_unix_ts);

    /// Returns true if the signature is valid for the embedded
    /// `(user_pk, device_pk, expiry)` triple, the cert has not
    /// expired against @p now_unix_ts, and the embedded user_pk
    /// matches @p expected_user.
    [[nodiscard]] bool verify(const ::gn::PublicKey& expected_user,
                              std::int64_t           now_unix_ts) const noexcept;

    /// Serialise to fixed-size 136-byte buffer.
    [[nodiscard]] std::array<std::uint8_t, kAttestationBytes>
    to_bytes() const noexcept;

    /// Parse from a 136-byte buffer. Returns nullopt on size mismatch.
    [[nodiscard]] static ::gn::Result<Attestation>
    from_bytes(std::span<const std::uint8_t, kAttestationBytes> bytes) noexcept;
};

} // namespace gn::core::identity
