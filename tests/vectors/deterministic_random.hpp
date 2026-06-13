// SPDX-License-Identifier: Apache-2.0
/// @file   tests/vectors/deterministic_random.hpp
/// @brief  Install a deterministic libsodium PRNG so the noise
///         plugin's `randombytes_buf` call (used to mint ephemerals
///         inside HandshakeState::write_message) emits a reproducible
///         byte stream.
///
/// The replacement implements `randombytes_implementation` on top of
/// ChaCha20 keyed by a 32-byte seed; counter increments per 64-byte
/// block. Calling `install_deterministic_random(seed)` swaps the
/// global libsodium PRNG to this stream and resets the counter — any
/// subsequent `randombytes_buf` call (from this TU or from the noise
/// plugin objects we link against) consumes the next bytes of the
/// stream.
///
/// This header lives ONLY under tests/vectors/ and is never compiled
/// into the shipped kernel binary. The shipped code path uses the
/// libsodium default `sysrandom` / `/dev/urandom` implementation.

#pragma once

#include <sodium.h>

#include <array>
#include <cstdint>
#include <cstring>

namespace gn::vectors {

/// Internal counter the deterministic PRNG advances. Lives in BSS so
/// the helper is header-only; `install_deterministic_random` resets
/// it on every call.
inline std::uint64_t&        det_counter() noexcept {
    static std::uint64_t c = 0;
    return c;
}
inline std::array<std::uint8_t, 32>& det_seed() noexcept {
    static std::array<std::uint8_t, 32> s{};
    return s;
}

namespace detail {

inline const char* det_impl_name() { return "goodnet-test-vectors-chacha20"; }

inline std::uint32_t det_impl_random() {
    std::uint8_t buf[4];
    // Reuse the buf path so a single source of truth controls the bytes.
    std::uint8_t nonce[crypto_stream_chacha20_NONCEBYTES] = {0};
    // Encode counter as little-endian 8 bytes into the start of the nonce.
    auto& c = det_counter();
    for (int i = 0; i < 8; ++i) {
        nonce[i] = static_cast<std::uint8_t>((c >> (i * 8)) & 0xFFu);
    }
    ++c;
    // chacha20 stream produces 64 bytes per nonce; we only need 4 here.
    std::uint8_t block[64];
    crypto_stream_chacha20(block, sizeof(block), nonce, det_seed().data());
    std::memcpy(buf, block, 4);
    std::uint32_t out =
        static_cast<std::uint32_t>(buf[0])
      | (static_cast<std::uint32_t>(buf[1]) << 8)
      | (static_cast<std::uint32_t>(buf[2]) << 16)
      | (static_cast<std::uint32_t>(buf[3]) << 24);
    return out;
}

inline void det_impl_buf(void* buf, std::size_t size) {
    std::uint8_t* p = static_cast<std::uint8_t*>(buf);
    auto& c = det_counter();
    while (size > 0) {
        std::uint8_t nonce[crypto_stream_chacha20_NONCEBYTES] = {0};
        for (int i = 0; i < 8; ++i) {
            nonce[i] = static_cast<std::uint8_t>((c >> (i * 8)) & 0xFFu);
        }
        ++c;
        std::uint8_t block[64];
        crypto_stream_chacha20(block, sizeof(block), nonce, det_seed().data());
        std::size_t take = size < sizeof(block) ? size : sizeof(block);
        std::memcpy(p, block, take);
        p    += take;
        size -= take;
    }
}

inline int det_impl_close() { return 0; }
inline const char* det_impl_implementation_name() { return det_impl_name(); }

}  // namespace detail

/// Install the deterministic PRNG. Resets the internal counter and
/// copies the 32-byte seed into the chacha20 key slot. Idempotent
/// when called with the same seed; calling with a different seed
/// resets the stream.
inline void install_deterministic_random(const std::array<std::uint8_t, 32>& seed) {
    static randombytes_implementation impl = {
        /* implementation_name */ &detail::det_impl_implementation_name,
        /* random              */ &detail::det_impl_random,
        /* stir                */ nullptr,
        /* uniform             */ nullptr,
        /* buf                 */ &detail::det_impl_buf,
        /* close               */ &detail::det_impl_close,
    };
    det_seed()    = seed;
    det_counter() = 0;
    randombytes_set_implementation(&impl);
}

/// 32-byte seed of the canonical XX vector. Pinned so generator and
/// consumer derive the same ephemeral keys.
inline constexpr std::array<std::uint8_t, 32> kCanonicalEphemeralSeed = {
    0x6e, 0x6f, 0x69, 0x73, 0x65, 0x2d, 0x78, 0x78,
    0x2d, 0x65, 0x70, 0x68, 0x65, 0x6d, 0x65, 0x72,
    0x61, 0x6c, 0x2d, 0x73, 0x65, 0x65, 0x64, 0x21,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
};

}  // namespace gn::vectors
