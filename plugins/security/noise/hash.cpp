// SPDX-License-Identifier: Apache-2.0
#include "hash.hpp"

#include <sodium.h>

namespace gn::noise {

Digest blake2b(std::span<const std::uint8_t> data) {
    Digest out;
    crypto_generichash_blake2b(out.data(), out.size(),
                                data.data(), data.size(),
                                nullptr, 0);
    return out;
}

Digest blake2b(std::span<const std::uint8_t> a,
               std::span<const std::uint8_t> b) {
    Digest out;
    crypto_generichash_blake2b_state state;
    crypto_generichash_blake2b_init(&state, nullptr, 0, HASHLEN);
    crypto_generichash_blake2b_update(&state, a.data(), a.size());
    crypto_generichash_blake2b_update(&state, b.data(), b.size());
    crypto_generichash_blake2b_final(&state, out.data(), HASHLEN);
    return out;
}

} // namespace gn::noise
