/// @file   core/identity/derive.cpp
/// @brief  HKDF-SHA256 address derivation implementation.

#include "derive.hpp"

#include <array>
#include <cstring>

#include <sodium.h>

#include "keypair.hpp"

namespace gn::core::identity {

::gn::PublicKey derive_address(
    const ::gn::PublicKey& user_pk,
    const ::gn::PublicKey& device_pk) noexcept {

    /// Concatenate user_pk || device_pk as the HKDF input keying
    /// material. Order matters — swapping yields a distinct address.
    std::array<std::uint8_t, 64> ikm{};
    std::memcpy(ikm.data(),                user_pk.data(),   GN_PUBLIC_KEY_BYTES);
    std::memcpy(ikm.data() + GN_PUBLIC_KEY_BYTES,
                device_pk.data(), GN_PUBLIC_KEY_BYTES);

    /// HKDF-SHA256 extract+expand into a 32-byte address. libsodium
    /// exposes both halves separately; we collapse them into a
    /// single derive with empty info string.
    std::array<std::uint8_t, crypto_kdf_hkdf_sha256_KEYBYTES> prk{};
    ::crypto_kdf_hkdf_sha256_extract(
        prk.data(),
        reinterpret_cast<const unsigned char*>(kAddressDeriveSalt),
        sizeof(kAddressDeriveSalt) - 1,
        ikm.data(), ikm.size());

    ::gn::PublicKey out{};
    ::crypto_kdf_hkdf_sha256_expand(
        out.data(), out.size(),
        /* info */ nullptr, 0,
        prk.data());

    /// Wipe the intermediate PRK; the IKM is just public keys, no
    /// secret leakage.
    ::sodium_memzero(prk.data(), prk.size());
    return out;
}

} // namespace gn::core::identity
