// SPDX-License-Identifier: Apache-2.0
#include "hkdf.hpp"
#include "hmac.hpp"

#include <sodium.h>

namespace gn::noise {

HkdfPair hkdf2(std::span<const std::uint8_t> chaining_key,
                std::span<const std::uint8_t> input_key_material) {
    Digest temp_key = hmac_blake2b(chaining_key, input_key_material);

    const std::uint8_t one = 0x01;
    Digest output1 = hmac_blake2b(temp_key,
                                   std::span<const std::uint8_t>(&one, 1));

    const std::uint8_t two = 0x02;
    Digest output2 = hmac_blake2b(temp_key,
                                   std::span<const std::uint8_t>(output1.data(), HASHLEN),
                                   std::span<const std::uint8_t>(&two, 1));

    sodium_memzero(temp_key.data(), HASHLEN);
    return {output1, output2};
}

HkdfTriple hkdf3(std::span<const std::uint8_t> chaining_key,
                  std::span<const std::uint8_t> input_key_material) {
    Digest temp_key = hmac_blake2b(chaining_key, input_key_material);

    const std::uint8_t one = 0x01;
    Digest output1 = hmac_blake2b(temp_key,
                                   std::span<const std::uint8_t>(&one, 1));

    const std::uint8_t two = 0x02;
    Digest output2 = hmac_blake2b(temp_key,
                                   std::span<const std::uint8_t>(output1.data(), HASHLEN),
                                   std::span<const std::uint8_t>(&two, 1));

    const std::uint8_t three = 0x03;
    Digest output3 = hmac_blake2b(temp_key,
                                   std::span<const std::uint8_t>(output2.data(), HASHLEN),
                                   std::span<const std::uint8_t>(&three, 1));

    sodium_memzero(temp_key.data(), HASHLEN);
    return {output1, output2, output3};
}

} // namespace gn::noise
