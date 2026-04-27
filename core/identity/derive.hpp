/// @file   core/identity/derive.hpp
/// @brief  HKDF-SHA256 address derivation from (user_pk, device_pk).
///
/// Per the two-key model: the on-wire 32-byte `gn_pk_t` is derived
/// from the user-key public half concatenated with the device-key
/// public half. Plugins still see only 32 bytes; all attestation /
/// rotation logic stays kernel-side.

#pragma once

#include <span>

#include <sdk/cpp/types.hpp>

namespace gn::core::identity {

/// Salt that scopes HKDF output to the GoodNet v1 addressing scheme.
/// A future v2 variant changes this constant rather than the input
/// material so old peers cannot mistake derivations.
inline constexpr char kAddressDeriveSalt[] = "goodnet/v1/address";

/// Derive the 32-byte mesh address from the user public key plus
/// the device public key. The function is pure: same input pair
/// always yields the same address; different pairs (under SHA-256
/// collision resistance) produce different addresses.
[[nodiscard]] ::gn::PublicKey derive_address(
    const ::gn::PublicKey& user_pk,
    const ::gn::PublicKey& device_pk) noexcept;

} // namespace gn::core::identity
