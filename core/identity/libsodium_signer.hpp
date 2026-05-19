/// @file   core/identity/libsodium_signer.hpp
/// @brief  Default in-process `IdentitySigner` backed by libsodium.
///
/// Wraps the same `crypto_sign_detached` path the kernel used before
/// the Phase 1 refactor. The 64-byte libsodium Ed25519 secret-key
/// blob (32-byte seed prefix + 32-byte derived pubkey) lives inside
/// the instance and is wiped via `sodium_memzero` on destruction.
/// HSM-backed signers (PKCS#11, TPM, Keychain, WebAuthn) plug in
/// behind the same `IdentitySigner` interface in later phases and
/// keep the private bytes outside the process entirely.

#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <span>

#include "signer.hpp"

namespace gn::core::identity {

inline constexpr std::size_t kLibsodiumSecretKeyBytes = 64;
inline constexpr std::size_t kLibsodiumPublicKeyBytes = 32;
inline constexpr std::size_t kLibsodiumSeedBytes      = 32;

class LibsodiumSigner final : public IdentitySigner {
public:
    /// Construct from a 64-byte Ed25519 secret key (libsodium layout:
    /// 32 bytes seed + 32 bytes derived pubkey). Caller-owned input
    /// is consumed; destructor wipes the held copy.
    explicit LibsodiumSigner(
        std::span<const std::uint8_t, kLibsodiumSecretKeyBytes> secret_key);

    /// Construct from a 32-byte seed; libsodium derives the keypair.
    [[nodiscard]] static std::unique_ptr<LibsodiumSigner> from_seed(
        std::span<const std::uint8_t, kLibsodiumSeedBytes> seed);

    LibsodiumSigner(const LibsodiumSigner&)            = delete;
    LibsodiumSigner& operator=(const LibsodiumSigner&) = delete;
    LibsodiumSigner(LibsodiumSigner&&)                 = delete;
    LibsodiumSigner& operator=(LibsodiumSigner&&)      = delete;

    ~LibsodiumSigner() override;  // sodium_memzero on private_key_

    gn_result_t pubkey(std::span<std::uint8_t, 32> out) const override;
    gn_result_t sign(std::span<const std::uint8_t> message,
                     std::span<std::uint8_t, 64>   out_signature) override;

private:
    /// Default-construct an empty instance; the two named factories
    /// (`from_seed` + the public `(span)` ctor) populate the fields.
    LibsodiumSigner() noexcept;

    std::array<std::uint8_t, kLibsodiumSecretKeyBytes> private_key_{};
    std::array<std::uint8_t, kLibsodiumPublicKeyBytes> public_key_{};
};

}  // namespace gn::core::identity
