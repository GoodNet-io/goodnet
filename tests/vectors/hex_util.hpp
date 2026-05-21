// SPDX-License-Identifier: Apache-2.0
/// @file   tests/vectors/hex_util.hpp
/// @brief  Header-only hex encode / decode helpers used by the
///         cross-implementation test vector generator and consumer.
///         No dependency on the kernel; cross-language consumers
///         implement an equivalent pair in their own runtime.

#pragma once

#include <cstdint>
#include <cstddef>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace gn::vectors {

inline std::string hex_encode(std::span<const std::uint8_t> bytes) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string out;
    out.resize(bytes.size() * 2);
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        out[2 * i]     = digits[(bytes[i] >> 4) & 0x0F];
        out[2 * i + 1] = digits[bytes[i] & 0x0F];
    }
    return out;
}

inline std::vector<std::uint8_t> hex_decode(std::string_view hex) {
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    std::vector<std::uint8_t> out;
    out.reserve(hex.size() / 2);
    for (std::size_t i = 0; i + 1 < hex.size(); i += 2) {
        const int hi = nibble(hex[i]);
        const int lo = nibble(hex[i + 1]);
        out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
    }
    return out;
}

}  // namespace gn::vectors
