// SPDX-License-Identifier: Apache-2.0
/// @file   plugins/security/noise/hmac.hpp
/// @brief  HMAC-BLAKE2b per RFC 2104 — used by Noise HKDF (§4.3).
///
/// BLAKE2 has a built-in keyed mode, but RFC 2104 HMAC is what the
/// Noise spec mandates for HKDF. Building HMAC explicitly preserves
/// canonical test-vector compatibility — keyed-BLAKE2b and HMAC-BLAKE2b
/// produce different MACs.

#pragma once

#include "hash.hpp"

#include <span>

namespace gn::noise {

/// HMAC-BLAKE2b(key, message). Output length is HASHLEN.
[[nodiscard]] Digest hmac_blake2b(std::span<const std::uint8_t> key,
                                   std::span<const std::uint8_t> message);

/// HMAC-BLAKE2b(key, a || b). Concatenates inputs without an intermediate
/// allocation — used by HKDF where one of the inputs is a single byte.
[[nodiscard]] Digest hmac_blake2b(std::span<const std::uint8_t> key,
                                   std::span<const std::uint8_t> a,
                                   std::span<const std::uint8_t> b);

} // namespace gn::noise
