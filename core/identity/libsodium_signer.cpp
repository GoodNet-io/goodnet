/// @file   core/identity/libsodium_signer.cpp
/// @brief  Implementation of the libsodium-backed `IdentitySigner`.

#include "libsodium_signer.hpp"

#include <cstring>
#include <mutex>

#include <sodium.h>

namespace gn::core::identity {

namespace {

/// libsodium requires `sodium_init()` exactly once before any other
/// API call. Idempotent across threads via `std::call_once`. Mirrors
/// the gate `KeyPair` uses so signers constructed standalone (without
/// going through a `KeyPair` first) still see an initialised library.
void ensure_sodium_initialised() {
    static std::once_flag flag;
    std::call_once(flag, []() {
        if (::sodium_init() < 0) {
            std::abort();
        }
    });
}

}  // namespace

LibsodiumSigner::LibsodiumSigner() noexcept = default;

LibsodiumSigner::LibsodiumSigner(
    std::span<const std::uint8_t, kLibsodiumSecretKeyBytes> secret_key) {
    ensure_sodium_initialised();
    std::memcpy(private_key_.data(), secret_key.data(),
                kLibsodiumSecretKeyBytes);
    /// libsodium Ed25519 secret-key layout: bytes [32..64) are the
    /// derived public key. Cache it so `pubkey()` is a memcpy and
    /// callers can fetch it without touching the secret region.
    std::memcpy(public_key_.data(),
                private_key_.data() + kLibsodiumSeedBytes,
                kLibsodiumPublicKeyBytes);
}

std::unique_ptr<LibsodiumSigner> LibsodiumSigner::from_seed(
    std::span<const std::uint8_t, kLibsodiumSeedBytes> seed) {
    ensure_sodium_initialised();
    /// Default-construct + populate. Direct `new` because the private
    /// no-arg constructor is intentional — `from_seed` is the only
    /// path that derives the keypair via libsodium.
    std::unique_ptr<LibsodiumSigner> out{new LibsodiumSigner()};
    if (::crypto_sign_seed_keypair(out->public_key_.data(),
                                    out->private_key_.data(),
                                    seed.data()) != 0) {
        return nullptr;
    }
    return out;
}

LibsodiumSigner::~LibsodiumSigner() {
    /// Wipe the secret-key region; the public-key cache is harmless
    /// but zeroing it too keeps the destructor cheap and uniform.
    ::sodium_memzero(private_key_.data(), private_key_.size());
    public_key_.fill(0);
}

gn_result_t LibsodiumSigner::pubkey(std::span<std::uint8_t, 32> out) const {
    std::memcpy(out.data(), public_key_.data(), kLibsodiumPublicKeyBytes);
    return GN_OK;
}

gn_result_t LibsodiumSigner::sign(
    std::span<const std::uint8_t> message,
    std::span<std::uint8_t, 64>   out_signature) {
    unsigned long long sig_len = 0;
    if (::crypto_sign_detached(out_signature.data(), &sig_len,
                                message.data(), message.size(),
                                private_key_.data()) != 0) {
        return GN_ERR_OUT_OF_MEMORY;
    }
    return GN_OK;
}

}  // namespace gn::core::identity
