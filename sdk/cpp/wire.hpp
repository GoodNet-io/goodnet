// SPDX-License-Identifier: MIT
/// @file   sdk/cpp/wire.hpp
/// @brief  Per-payload wire-format concept for typed extension messages.
///
/// Pre-v1 plugins translated between in-memory payload structs and
/// the wire by hand — each handler exposed its own free
/// `serialize` / `parse` pair, the kernel had no way to verify that
/// every typed payload spoke the same shape, and a future TLV /
/// capability-bitmap evolution would have had to re-touch every
/// site. `gn::wire::WireSchema<T>` is the contract a typed wire
/// payload satisfies; one place to require the shape, one
/// `static_assert` per implementer.
///
/// A schema is a stateless type — never instantiated. It exposes:
///
/// - `using value_type = …;` — the in-memory representation
/// - `static constexpr std::uint32_t msg_id` — protocol-layer routing key
/// - `static constexpr std::size_t   size`   — fixed wire-frame length
/// - `static std::array<std::uint8_t, size> serialize(const value_type&)`
/// - `static std::optional<value_type> parse(std::span<const std::uint8_t>)`
///
/// `serialize` writes a buffer of exactly `size` bytes; `parse`
/// returns `nullopt` when the input length is wrong or the bytes
/// cannot be decoded into a valid `value_type`. Both functions
/// must be `noexcept` so wire-path callers are not surprised by
/// allocator failure on a schema's behalf.

#pragma once

#include <array>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <type_traits>

namespace gn::wire {

/// Concept satisfied by a stateless per-payload schema.
template <class T>
concept WireSchema = requires {
    typename T::value_type;
    { T::msg_id } -> std::convertible_to<std::uint32_t>;
    { T::size   } -> std::convertible_to<std::size_t>;
    requires std::is_invocable_v<
        decltype(&T::serialize),
        const typename T::value_type&>;
    requires std::is_invocable_r_v<
        std::optional<typename T::value_type>,
        decltype(&T::parse),
        std::span<const std::uint8_t>>;
};

}  // namespace gn::wire
