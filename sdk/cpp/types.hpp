/**
 * @file   sdk/cpp/types.hpp
 * @brief  C++ wrappers for the fundamental SDK types.
 *
 * Mirrors of the @c gn_* C ABI structures using value-semantic helpers.
 * Plugins written in C++ pull this header instead of `sdk/types.h`.
 */
#pragma once

#include <array>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>

#include <sdk/types.h>

namespace gn {

/**
 * @brief Strongly-typed error wrapping a @ref gn_result_t code and message.
 */
struct Error {
    gn_result_t code{GN_ERR_NOT_IMPLEMENTED};
    std::string what;
};

/// Result-or-error alias used across the SDK. Mirrors `Result<T>` in legacy code.
template<class T>
using Result = std::expected<T, Error>;

/// Owning value-type alias for an Ed25519 public key.
using PublicKey = std::array<std::uint8_t, GN_PUBLIC_KEY_BYTES>;

/// All-zero public key, treated as the broadcast marker.
inline constexpr PublicKey kBroadcastPk{};

/// Returns true if @p pk is the all-zero broadcast marker.
[[nodiscard]] inline bool is_broadcast(const PublicKey& pk) noexcept {
    std::uint8_t acc = 0;
    for (auto b : pk) acc |= b;
    return acc == 0;
}

/**
 * @brief Read-only view over a @ref gn_message_t.
 *
 * Constructible from the C envelope without copying. Provides span-based
 * accessors for the public-key fields and payload, keeping the borrowed
 * lifetime explicit at the call site.
 */
class MessageView {
public:
    constexpr explicit MessageView(const gn_message_t& m) noexcept : m_(m) {}

    [[nodiscard]] std::span<const std::uint8_t, GN_PUBLIC_KEY_BYTES>
    sender_pk() const noexcept {
        return std::span<const std::uint8_t, GN_PUBLIC_KEY_BYTES>(m_.sender_pk);
    }

    [[nodiscard]] std::span<const std::uint8_t, GN_PUBLIC_KEY_BYTES>
    receiver_pk() const noexcept {
        return std::span<const std::uint8_t, GN_PUBLIC_KEY_BYTES>(m_.receiver_pk);
    }

    [[nodiscard]] std::uint32_t msg_id() const noexcept { return m_.msg_id; }

    [[nodiscard]] std::span<const std::uint8_t> payload() const noexcept {
        return {m_.payload, m_.payload_size};
    }

    [[nodiscard]] bool is_broadcast() const noexcept {
        return gn_pk_is_zero(m_.receiver_pk) != 0;
    }

    [[nodiscard]] const gn_message_t& raw() const noexcept { return m_; }

private:
    const gn_message_t& m_;
};

} // namespace gn
