/// @file   core/identity/signer.hpp
/// @brief  Thread-safe identity-key signer abstraction.
///
/// Phase 1 of the HSM-friendly identity refactor: every identity-key
/// signing call site in the kernel goes through `IdentitySigner`
/// instead of touching libsodium directly. `LibsodiumSigner`
/// (`core/identity/libsodium_signer.{hpp,cpp}`) is the default
/// in-process implementation that wraps the previous behavior; later
/// phases plug in HSM-backed signers (PKCS#11, TPM, Keychain,
/// WebAuthn) through the same interface — `NodeIdentity` only sees
/// the abstract type, so swapping the backing store is invisible to
/// every call site already migrated here.

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

#include <sdk/types.h>

namespace gn::core::identity {

/// Thread-safe identity-key signer. One instance per NodeIdentity;
/// kernel holds it through unique_ptr. Implementers MUST NOT leak
/// private key material — destructor wipes whatever in-process
/// storage exists.
class IdentitySigner {
public:
    virtual ~IdentitySigner() = default;

    /// Copy the Ed25519 public key into `out`. Cheap, can be called
    /// repeatedly. `out` must point to at least 32 bytes.
    virtual gn_result_t pubkey(std::span<std::uint8_t, 32> out) const = 0;

    /// Sign `message` (which is the already-prepared bytes — caller
    /// applies any required prefix or domain separation). Output is
    /// a 64-byte Ed25519 signature placed at `out_signature[0..64]`.
    /// Thread-safe: signing operations may be concurrent.
    virtual gn_result_t sign(
        std::span<const std::uint8_t> message,
        std::span<std::uint8_t, 64>   out_signature) = 0;
};

}  // namespace gn::core::identity
