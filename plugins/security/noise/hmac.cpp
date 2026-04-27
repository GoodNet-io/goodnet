// SPDX-License-Identifier: Apache-2.0
#include "hmac.hpp"

#include <sodium.h>

#include <array>
#include <cstring>

namespace gn::noise {
namespace {

using KeyBlock = std::array<std::uint8_t, BLOCKLEN>;

/// Prepare the HMAC key block: pad to BLOCKLEN, hashing first if longer.
KeyBlock prepare_key(std::span<const std::uint8_t> key) {
    KeyBlock out;
    out.fill(0);
    if (key.size() <= BLOCKLEN) {
        std::memcpy(out.data(), key.data(), key.size());
    } else {
        Digest h = blake2b(key);
        std::memcpy(out.data(), h.data(), HASHLEN);
        sodium_memzero(h.data(), HASHLEN);
    }
    return out;
}

/// In-place XOR every byte of a key block with the constant @p c.
void xor_const(KeyBlock& blk, std::uint8_t c) {
    for (auto& b : blk) b ^= c;
}

} // namespace

Digest hmac_blake2b(std::span<const std::uint8_t> key,
                    std::span<const std::uint8_t> message) {
    KeyBlock k = prepare_key(key);

    KeyBlock ipad = k; xor_const(ipad, 0x36);
    KeyBlock opad = k; xor_const(opad, 0x5c);

    Digest inner = blake2b(std::span<const std::uint8_t>(ipad.data(), BLOCKLEN),
                            message);
    Digest outer = blake2b(std::span<const std::uint8_t>(opad.data(), BLOCKLEN),
                            std::span<const std::uint8_t>(inner.data(), HASHLEN));

    sodium_memzero(k.data(),    BLOCKLEN);
    sodium_memzero(ipad.data(), BLOCKLEN);
    sodium_memzero(opad.data(), BLOCKLEN);
    sodium_memzero(inner.data(), HASHLEN);
    return outer;
}

Digest hmac_blake2b(std::span<const std::uint8_t> key,
                    std::span<const std::uint8_t> a,
                    std::span<const std::uint8_t> b) {
    KeyBlock k = prepare_key(key);

    KeyBlock ipad = k; xor_const(ipad, 0x36);
    KeyBlock opad = k; xor_const(opad, 0x5c);

    Digest inner;
    {
        crypto_generichash_blake2b_state st;
        crypto_generichash_blake2b_init(&st, nullptr, 0, HASHLEN);
        crypto_generichash_blake2b_update(&st, ipad.data(), BLOCKLEN);
        crypto_generichash_blake2b_update(&st, a.data(), a.size());
        crypto_generichash_blake2b_update(&st, b.data(), b.size());
        crypto_generichash_blake2b_final(&st, inner.data(), HASHLEN);
    }
    Digest outer = blake2b(std::span<const std::uint8_t>(opad.data(), BLOCKLEN),
                            std::span<const std::uint8_t>(inner.data(), HASHLEN));

    sodium_memzero(k.data(),    BLOCKLEN);
    sodium_memzero(ipad.data(), BLOCKLEN);
    sodium_memzero(opad.data(), BLOCKLEN);
    sodium_memzero(inner.data(), HASHLEN);
    return outer;
}

} // namespace gn::noise
