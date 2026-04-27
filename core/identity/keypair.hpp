/// @file   core/identity/keypair.hpp
/// @brief  Ed25519 keypair value type for user / device identities.
///
/// Both halves of the two-component identity (user_keypair plus
/// device_keypair) use Ed25519. The library treats them
/// symmetrically — semantic distinction lives in how the keypair
/// is stored (long-term portable vs hardware-bound) and how it is
/// used (signing attestations vs signing handshakes).

#pragma once

#include <array>
#include <cstdint>
#include <span>

#include <sdk/cpp/types.hpp>
#include <sdk/types.h>

namespace gn::core::identity {

/// libsodium Ed25519 secret-key layout: 32-byte seed prefix + 32-byte
/// public key suffix = 64 bytes total. Always kept opaque to plugins.
inline constexpr std::size_t kEd25519SecretKeyBytes = GN_PRIVATE_KEY_BYTES;
inline constexpr std::size_t kEd25519PublicKeyBytes = GN_PUBLIC_KEY_BYTES;
inline constexpr std::size_t kEd25519SeedBytes      = 32;
inline constexpr std::size_t kEd25519SignatureBytes = 64;

/// Owning Ed25519 keypair. Move-only; secret bytes are wiped on
/// destruction so a leaked instance does not leave key material in
/// freed memory.
class KeyPair {
public:
    KeyPair() noexcept;
    ~KeyPair();

    KeyPair(const KeyPair&)            = delete;
    KeyPair& operator=(const KeyPair&) = delete;

    KeyPair(KeyPair&& other) noexcept;
    KeyPair& operator=(KeyPair&& other) noexcept;

    /// Generate a fresh random keypair. libsodium's CSPRNG seeds
    /// the secret; the public key is derived from it.
    [[nodiscard]] static ::gn::Result<KeyPair> generate();

    /// Reproduce a keypair from a 32-byte seed. Useful for restoring
    /// a long-term user identity from a backup phrase or sealed file.
    [[nodiscard]] static ::gn::Result<KeyPair>
    from_seed(std::span<const std::uint8_t, kEd25519SeedBytes> seed);

    /// Read-only access to the public key. The pk view stays
    /// valid for the lifetime of the KeyPair.
    [[nodiscard]] const ::gn::PublicKey& public_key() const noexcept { return pk_; }

    /// Signs @p message with the secret key. Returns the 64-byte
    /// detached signature on success.
    [[nodiscard]] ::gn::Result<std::array<std::uint8_t, kEd25519SignatureBytes>>
    sign(std::span<const std::uint8_t> message) const;

    /// Static verification — does not need a KeyPair instance.
    /// Returns true iff @p signature is valid for @p message under
    /// @p public_key.
    [[nodiscard]] static bool verify(
        const ::gn::PublicKey& public_key,
        std::span<const std::uint8_t> message,
        std::span<const std::uint8_t, kEd25519SignatureBytes> signature) noexcept;

    /// Wipe the secret key in place. Call before serialising the
    /// pair to disk — secret stays only as long as needed.
    void wipe() noexcept;

private:
    ::gn::PublicKey                                  pk_{};
    std::array<std::uint8_t, kEd25519SecretKeyBytes> sk_{};
    bool                                             present_{false};
};

} // namespace gn::core::identity
