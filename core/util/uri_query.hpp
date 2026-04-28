/// @file   core/util/uri_query.hpp
/// @brief  libsodium-dependent helpers atop `sdk/cpp/uri.hpp`.
///
/// The base parser is libsodium-free so transport plugins can include
/// it without pulling crypto headers. Helpers that need hex decoding
/// (the `?peer=<64-hex>` query parameter for IK-initiator preset keys)
/// live here so the dependency stays one level removed.

#pragma once

#include <sdk/cpp/uri.hpp>

#include <sodium/utils.h>

#include <array>
#include <cstdint>
#include <optional>
#include <string_view>

namespace gn::util {

/// Strip the query string (everything from the first `?` onward).
/// Thin wrapper for call sites that want the canonical-key form
/// without round-tripping through `parse_uri`.
[[nodiscard]] inline std::string_view
uri_strip_query(std::string_view uri) noexcept {
    const auto q = uri.find('?');
    return (q == std::string_view::npos) ? uri : uri.substr(0, q);
}

/// Decode the `?peer=<hex>` query parameter into a 32-byte X25519
/// public key per `docs/contracts/uri.md` §6 reserved keys. Returns
/// nullopt when the URI is malformed, the parameter is missing, or
/// the hex payload is not exactly 64 characters.
[[nodiscard]] inline std::optional<std::array<std::uint8_t, 32>>
parse_peer_param(std::string_view uri) {
    const auto parts = ::gn::parse_uri(uri);
    if (!parts) return std::nullopt;

    const auto hex = ::gn::uri_query_value(parts->query, "peer");
    if (hex.size() != 64) return std::nullopt;

    std::array<std::uint8_t, 32> out{};
    std::size_t bin_len = 0;
    if (::sodium_hex2bin(out.data(), out.size(),
                          hex.data(), hex.size(),
                          nullptr, &bin_len, nullptr) != 0
        || bin_len != 32)
    {
        return std::nullopt;
    }
    return out;
}

}  // namespace gn::util
