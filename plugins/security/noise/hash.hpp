// SPDX-License-Identifier: Apache-2.0
/// @file   plugins/security/noise/hash.hpp
/// @brief  BLAKE2b primitive used by the Noise plugin.
///
/// Per `docs/contracts/noise-handshake.md` §2 the canonical hash for
/// `Noise_*_25519_ChaChaPoly_BLAKE2b` is BLAKE2b with `HASHLEN = 64`.
/// Implemented through libsodium's `crypto_generichash_blake2b_*`.

#pragma once

#include <array>
#include <cstdint>
#include <cstddef>
#include <span>

namespace gn::noise {

inline constexpr std::size_t HASHLEN  = 64;   ///< BLAKE2b digest length
inline constexpr std::size_t BLOCKLEN = 128;  ///< BLAKE2b internal block size

using Digest = std::array<std::uint8_t, HASHLEN>;

/// Compute BLAKE2b-512 over a single contiguous range.
[[nodiscard]] Digest blake2b(std::span<const std::uint8_t> data);

/// Compute BLAKE2b-512 over the concatenation of two ranges without
/// allocating an intermediate buffer.
[[nodiscard]] Digest blake2b(std::span<const std::uint8_t> a,
                              std::span<const std::uint8_t> b);

} // namespace gn::noise
