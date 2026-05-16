/// @file   sdk/cpp/endian.hpp
/// @brief  Big- and little-endian byte read/write helpers.
///
/// Every wire-touching code path goes through this header — protocol
/// plugins frame and deframe, the security layer reads counter words,
/// the kernel codec lifts CBOR ints. The helpers are protocol-agnostic;
/// they know nothing about message layout.

#pragma once

#include <bit>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <type_traits>

namespace gn::endian {

/// Trivially-copyable unsigned integer the helpers operate on.
template <class T>
concept Word = std::unsigned_integral<T> && std::is_trivially_copyable_v<T>;

namespace detail {

template <Word T>
[[nodiscard]] constexpr T load(const std::uint8_t* src) noexcept {
    T raw{};
    std::memcpy(&raw, src, sizeof(T));
    return raw;
}

template <Word T>
constexpr void store(std::uint8_t* dst, T value) noexcept {
    std::memcpy(dst, &value, sizeof(T));
}

} // namespace detail

/* ── Big-endian ─────────────────────────────────────────────────────────── */

/// Read an unsigned integer in big-endian byte order from @p src.
/// Caller guarantees `src.size() >= sizeof(T)`.
template <Word T>
[[nodiscard]] constexpr T read_be(std::span<const std::uint8_t> src) noexcept {
    const T raw = detail::load<T>(src.data());
    if constexpr (std::endian::native == std::endian::little) {
        return std::byteswap(raw);
    } else {
        return raw;
    }
}

/// Write an unsigned integer in big-endian byte order to @p dst.
/// Caller guarantees `dst.size() >= sizeof(T)`.
template <Word T>
constexpr void write_be(std::span<std::uint8_t> dst, T value) noexcept {
    if constexpr (std::endian::native == std::endian::little) {
        value = std::byteswap(value);
    }
    detail::store(dst.data(), value);
}

/// Raw-pointer variant — equivalent to `read_be<T>({ptr, sizeof(T)})`.
template <Word T>
[[nodiscard]] constexpr T read_be_ptr(const std::uint8_t* src) noexcept {
    return read_be<T>(std::span<const std::uint8_t>{src, sizeof(T)});
}

template <Word T>
constexpr void write_be_ptr(std::uint8_t* dst, T value) noexcept {
    write_be<T>(std::span<std::uint8_t>{dst, sizeof(T)}, value);
}

/* ── Little-endian ──────────────────────────────────────────────────────── */

/// Read an unsigned integer in little-endian byte order from @p src.
/// Caller guarantees `src.size() >= sizeof(T)`.
template <Word T>
[[nodiscard]] constexpr T read_le(std::span<const std::uint8_t> src) noexcept {
    const T raw = detail::load<T>(src.data());
    if constexpr (std::endian::native == std::endian::big) {
        return std::byteswap(raw);
    } else {
        return raw;
    }
}

/// Write an unsigned integer in little-endian byte order to @p dst.
/// Caller guarantees `dst.size() >= sizeof(T)`.
template <Word T>
constexpr void write_le(std::span<std::uint8_t> dst, T value) noexcept {
    if constexpr (std::endian::native == std::endian::big) {
        value = std::byteswap(value);
    }
    detail::store(dst.data(), value);
}

/// Raw-pointer variants.
template <Word T>
[[nodiscard]] constexpr T read_le_ptr(const std::uint8_t* src) noexcept {
    return read_le<T>(std::span<const std::uint8_t>{src, sizeof(T)});
}

template <Word T>
constexpr void write_le_ptr(std::uint8_t* dst, T value) noexcept {
    write_le<T>(std::span<std::uint8_t>{dst, sizeof(T)}, value);
}

} // namespace gn::endian
