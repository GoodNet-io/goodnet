/// @file   core/identity/keypair.cpp
/// @brief  Implementation of Ed25519 KeyPair via libsodium.

#include "keypair.hpp"

#include <cstring>
#include <mutex>

#include <sodium.h>

namespace gn::core::identity {

namespace {

/// libsodium requires `sodium_init()` exactly once before any other
/// API call. Idempotent across threads via std::call_once.
void ensure_sodium_initialised() {
    static std::once_flag flag;
    std::call_once(flag, []() {
        if (::sodium_init() < 0) {
            /// libsodium init failed — the host has no working
            /// CSPRNG. There is no graceful recovery; abort early
            /// so the surrounding code never proceeds with weak keys.
            std::abort();
        }
    });
}

} // namespace

KeyPair::KeyPair() noexcept = default;

KeyPair::~KeyPair() { wipe(); }

KeyPair::KeyPair(KeyPair&& other) noexcept
    : pk_(other.pk_), sk_(other.sk_), present_(other.present_) {
    other.wipe();
}

KeyPair& KeyPair::operator=(KeyPair&& other) noexcept {
    if (this != &other) {
        wipe();
        pk_ = other.pk_;
        sk_ = other.sk_;
        present_ = other.present_;
        other.wipe();
    }
    return *this;
}

void KeyPair::wipe() noexcept {
    ::sodium_memzero(sk_.data(), sk_.size());
    pk_.fill(0);
    present_ = false;
}

::gn::Result<KeyPair> KeyPair::clone() const {
    if (!present_) {
        return std::unexpected(::gn::Error{
            GN_ERR_INVALID_STATE, "clone: keypair not initialised"});
    }
    /// Re-seed from the stored seed prefix. Produces an
    /// independently-owned KeyPair instance whose destructor
    /// wipes its own secret.
    return from_seed(std::span<const std::uint8_t, kEd25519SeedBytes>(
        sk_.data(), kEd25519SeedBytes));
}

::gn::Result<KeyPair> KeyPair::generate() {
    ensure_sodium_initialised();
    KeyPair kp;
    if (::crypto_sign_keypair(kp.pk_.data(), kp.sk_.data()) != 0) {
        return std::unexpected(::gn::Error{
            GN_ERR_OUT_OF_MEMORY, "crypto_sign_keypair failed"});
    }
    kp.present_ = true;
    return kp;
}

::gn::Result<KeyPair> KeyPair::from_seed(
    std::span<const std::uint8_t, kEd25519SeedBytes> seed) {
    ensure_sodium_initialised();
    KeyPair kp;
    if (::crypto_sign_seed_keypair(kp.pk_.data(), kp.sk_.data(),
                                    seed.data()) != 0) {
        return std::unexpected(::gn::Error{
            GN_ERR_INVALID_ENVELOPE, "crypto_sign_seed_keypair failed"});
    }
    kp.present_ = true;
    return kp;
}

::gn::Result<std::array<std::uint8_t, kEd25519SignatureBytes>>
KeyPair::sign(std::span<const std::uint8_t> message) const {
    if (!present_) {
        return std::unexpected(::gn::Error{
            GN_ERR_INVALID_ENVELOPE, "keypair not initialised"});
    }
    std::array<std::uint8_t, kEd25519SignatureBytes> sig{};
    unsigned long long sig_len = 0;
    if (::crypto_sign_detached(sig.data(), &sig_len,
                                message.data(), message.size(),
                                sk_.data()) != 0) {
        return std::unexpected(::gn::Error{
            GN_ERR_OUT_OF_MEMORY, "crypto_sign_detached failed"});
    }
    return sig;
}

bool KeyPair::verify(const ::gn::PublicKey& public_key,
                     std::span<const std::uint8_t> message,
                     std::span<const std::uint8_t, kEd25519SignatureBytes> signature) noexcept {
    ensure_sodium_initialised();
    return ::crypto_sign_verify_detached(signature.data(),
                                          message.data(), message.size(),
                                          public_key.data()) == 0;
}

} // namespace gn::core::identity
