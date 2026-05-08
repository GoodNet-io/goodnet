/// @file   core/identity/derive.hpp
/// @brief  HKDF-SHA256 mesh-address derivation from device public key.
///
/// The mesh address is **device-stable**: rotating `user_pk` does
/// not change a peer's mesh address. Plugins build user-level
/// connectivity graphs through `host_api->get_peer_user_pk(conn)`
/// (a separate API surface) rather than by reading bits out of the
/// address. See `docs/contracts/identity.en.md` §2 for the design
/// rationale and §3 for how user_pk now travels — through
/// attestation rather than the address.

#pragma once

#include <span>

#include <sdk/cpp/types.hpp>

namespace gn::core::identity {

/// Salt that scopes HKDF output to the GoodNet v1 device-address
/// derivation. The salt deliberately differs from the legacy
/// `goodnet/v1/address` so a v1-derived address (which mixed in
/// `user_pk`) never collides with a v1-decouple address from the
/// same device — peers reject the mismatch via attestation pin.
inline constexpr char kAddressDeriveSalt[] = "goodnet/v1/device-address";

/// Derive the 32-byte mesh address from the device public key.
/// Pure function: same `device_pk` always yields the same address;
/// different `device_pk` values produce different addresses under
/// SHA-256 collision resistance. Independent of `user_pk` so user
/// rotation preserves live mesh addresses.
[[nodiscard]] ::gn::PublicKey derive_address(
    const ::gn::PublicKey& device_pk) noexcept;

} // namespace gn::core::identity
