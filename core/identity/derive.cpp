/// @file   core/identity/derive.cpp
/// @brief  HKDF-SHA256 device-address derivation implementation.

#include "derive.hpp"

#include <array>

#include <sodium.h>

#include "keypair.hpp"

namespace gn::core::identity {

::gn::PublicKey derive_address(
    const ::gn::PublicKey& device_pk) noexcept {

    /// HKDF-SHA256 extract+expand keyed on `device_pk` only. The
    /// user_pk used to mix into the IKM in v1; rotating user_pk
    /// then renamed every live conn out from under the application,
    /// breaking long-term graph state. Decouple keeps mesh-address
    /// device-stable and routes user identity through attestation
    /// + `host_api->get_peer_user_pk` instead.
    std::array<std::uint8_t, crypto_kdf_hkdf_sha256_KEYBYTES> prk{};
    ::crypto_kdf_hkdf_sha256_extract(
        prk.data(),
        reinterpret_cast<const unsigned char*>(kAddressDeriveSalt),
        sizeof(kAddressDeriveSalt) - 1,
        device_pk.data(), GN_PUBLIC_KEY_BYTES);

    ::gn::PublicKey out{};
    ::crypto_kdf_hkdf_sha256_expand(
        out.data(), out.size(),
        /* info */ nullptr, 0,
        prk.data());

    /// Wipe the intermediate PRK. IKM is a public key — no secret
    /// leakage to wipe — but the PRK is full HKDF state.
    ::sodium_memzero(prk.data(), prk.size());
    return out;
}

} // namespace gn::core::identity
