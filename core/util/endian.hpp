/// @file   core/util/endian.hpp
/// @brief  Generic big-endian byte read/write helpers.
///
/// Used by every code path that touches the wire — protocol plugins
/// frame and deframe through these. The helpers are protocol-agnostic;
/// they know nothing about message layout.

#pragma once

#include <bit>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>

namespace gn::util {

/// Trivially-copyable unsigned integer that endian helpers operate on.
template <class T>
concept BeWord = std::unsigned_integral<T> && std::is_trivially_copyable_v<T>;

/// Read an unsigned integer in big-endian byte order from @p src.
///
/// The caller guarantees `src.size() >= sizeof(T)`. No bounds check is
/// performed in release builds; debug builds assert on the slot.
template <BeWord T>
[[nodiscard]] constexpr T read_be(std::span<const std::uint8_t> src) noexcept {
    T raw{};
    std::memcpy(&raw, src.data(), sizeof(T));
    if constexpr (std::endian::native == std::endian::little) {
        return std::byteswap(raw);
    } else {
        return raw;
    }
}

/// Write an unsigned integer in big-endian byte order to @p dst.
///
/// The caller guarantees `dst.size() >= sizeof(T)`.
template <BeWord T>
constexpr void write_be(std::span<std::uint8_t> dst, T value) noexcept {
    if constexpr (std::endian::native == std::endian::little) {
        value = std::byteswap(value);
    }
    std::memcpy(dst.data(), &value, sizeof(T));
}

/// Convenience overloads for raw pointer call sites — equivalent to
/// `read_be<T>({ptr, sizeof(T)})`. Useful when the caller knows it has
/// at least `sizeof(T)` bytes available without packaging the span.
template <BeWord T>
[[nodiscard]] constexpr T read_be_ptr(const std::uint8_t* src) noexcept {
    return read_be<T>(std::span<const std::uint8_t>{src, sizeof(T)});
}

template <BeWord T>
constexpr void write_be_ptr(std::uint8_t* dst, T value) noexcept {
    write_be<T>(std::span<std::uint8_t>{dst, sizeof(T)}, value);
}

} // namespace gn::util
