// SPDX-License-Identifier: Apache-2.0
/// @file   plugins/security/noise/hkdf.hpp
/// @brief  Noise HKDF per spec §4.3, parameterised on HMAC-BLAKE2b.
///
/// The Noise framework defines its own HKDF that returns up to three
/// HASHLEN-sized outputs through repeated HMAC. The first input
/// (chaining_key) acts as the HMAC salt, the second (input_key_material)
/// as the HMAC message — argument order matters.

#pragma once

#include "hash.hpp"

#include <span>

namespace gn::noise {

/// Two-output HKDF: returns (output1, output2).
struct HkdfPair {
    Digest output1;
    Digest output2;
};

/// Three-output HKDF: returns (output1, output2, output3). Used only by
/// MixKeyAndHash (PSK patterns). Provided for completeness.
struct HkdfTriple {
    Digest output1;
    Digest output2;
    Digest output3;
};

[[nodiscard]] HkdfPair hkdf2(std::span<const std::uint8_t> chaining_key,
                              std::span<const std::uint8_t> input_key_material);

[[nodiscard]] HkdfTriple hkdf3(std::span<const std::uint8_t> chaining_key,
                                std::span<const std::uint8_t> input_key_material);

} // namespace gn::noise
