// SPDX-License-Identifier: MIT
/// @file   sdk/cpp/uri.hpp
/// @brief  Header-only URI parser per `docs/contracts/uri.md`.
///
/// One parser shared by every transport plugin and the kernel
/// connection registry's URI index. Without it, "tcp://1.2.3.4:80"
/// can substring-match "1.2.3.4:8080" and routing hits the wrong
/// peer. The parser is pure string work — no DNS, no URL decoding.
/// Header-only, no libsodium so transports can include it directly.
/// Hex decoding for `?peer=<hex>` lives in `core/util/uri_query.hpp`.

#pragma once

#include <charconv>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace gn {

/// Parsed connection URI per uri.md §3.
struct UriParts {
    std::string      scheme;   ///< "tcp" / "udp" / "ws" / "ipc" / …; empty if omitted
    std::string      host;     ///< IP literal / hostname (host:port); mirrors `path` (path-style)
    std::uint16_t    port = 0; ///< Parsed port; 0 only on path-style URIs
    std::string      path;     ///< Filesystem path / abstract name (`ipc://`); empty for host:port
    std::string_view query;    ///< Raw "k=v&k=v" view, empty when no `?`

    /// Returns true iff the URI carries a filesystem path or abstract
    /// name in place of `host:port` (currently `ipc://`).
    [[nodiscard]] bool is_path_style() const noexcept {
        return port == 0 && !path.empty();
    }

    /// `host:port` / `[v6]:port` form suitable for an HTTP `Host:`
    /// header (RFC 7230 §5.4). Empty for path-style URIs (`ipc://`).
    [[nodiscard]] std::string host_authority() const {
        if (is_path_style()) return {};
        std::string s;
        s.reserve(host.size() + 8);
        const bool is_v6 = host.find(':') != std::string::npos;
        if (is_v6) s += '[';
        s += host;
        if (is_v6) s += ']';
        s += ':';
        s += std::to_string(port);
        return s;
    }

    /// Canonical "scheme://host:port" / "scheme://path" form for use
    /// as a registry key. Strips the query so lookups stay stable
    /// regardless of per-call metadata, and re-brackets IPv6 literals
    /// so the unbracketed-fallback (uri.md §5.1) round-trips to the
    /// strict form.
    [[nodiscard]] std::string canonical() const {
        std::string s;
        s.reserve(scheme.size() + 3 + host.size() + path.size() + 7);
        if (!scheme.empty()) {
            s += scheme;
            s += "://";
        }
        if (is_path_style()) {
            s += path;
        } else {
            s += host_authority();
        }
        return s;
    }
};

/// True iff @p uri carries any byte ≤ `0x20` or == `0x7F`.
///
/// A URI carrying CR/LF/NUL/space splits cleanly into a smuggled HTTP
/// request line / header pair when the transport later concatenates
/// it into a wire frame, so every entry point that lets a URI cross
/// into the kernel runs this check (`parse_uri` below; the kernel's
/// `notify_connect` thunk for raw URIs that bypass the grammar).
/// RFC 3986 already forbids these bytes inside a URI without
/// percent-encoding, so rejection is strictly correct, not just
/// defensive (uri.md §5 #10).
[[nodiscard]] inline bool uri_has_control_bytes(std::string_view uri) noexcept {
    for (const char ch : uri) {
        const auto byte = static_cast<unsigned char>(ch);
        if (byte <= 0x20 || byte == 0x7F) {
            return true;
        }
    }
    return false;
}

/// Parse a connection URI. Returns `nullopt` on every failure mode in
/// `docs/contracts/uri.md` §5; never throws, never writes through a
/// partial result.
[[nodiscard]] inline std::optional<UriParts>
parse_uri(std::string_view uri) {
    UriParts out;

    if (uri_has_control_bytes(uri)) return std::nullopt;

    /// Split the query first so the scheme/host/port logic never sees
    /// query characters in its slice.
    if (auto q = uri.find('?'); q != std::string_view::npos) {
        out.query = uri.substr(q + 1);
        uri = uri.substr(0, q);
    }

    /// Optional `scheme://` prefix.
    if (auto sep = uri.find("://"); sep != std::string_view::npos) {
        out.scheme.assign(uri.substr(0, sep));
        uri = uri.substr(sep + 3);
    }

    if (uri.empty()) return std::nullopt;

    /// Path-style schemes carry a path / abstract name where host:port
    /// would normally sit. Detected by scheme so a stray missing port
    /// on a host:port URI still fails fast.
    if (out.scheme == "ipc") {
        out.path.assign(uri);
        out.host = out.path;  // back-compat: host mirrors path
        return out;
    }

    /// Bracketed IPv6 — `[v6]:port`. RFC 3986 requires brackets to
    /// disambiguate the embedded `::` from the host:port `:`.
    std::string_view::size_type colon = std::string_view::npos;
    if (uri.front() == '[') {
        const auto rb = uri.find(']');
        if (rb == std::string_view::npos) return std::nullopt;  // unclosed
        out.host.assign(uri.substr(1, rb - 1));
        if (rb + 1 < uri.size() && uri[rb + 1] == ':') {
            colon = rb + 1;
        } else {
            return std::nullopt;  // bracket without :port
        }
    } else {
        /// Unbracketed: split on the rightmost `:` so single-colon
        /// host:port works regardless of any `:` inside an unbracketed
        /// v6 literal (uri.md §5.1 fallback canonicalises into bracket
        /// form).
        colon = uri.rfind(':');
        if (colon == std::string_view::npos) return std::nullopt;
        out.host.assign(uri.substr(0, colon));
    }

    const auto port_sv = uri.substr(colon + 1);
    if (out.host.empty() || port_sv.empty()) return std::nullopt;

    std::uint16_t port = 0;
    const auto [ptr, ec] = std::from_chars(
        port_sv.data(), port_sv.data() + port_sv.size(), port);
    /// Strict: reject trailing garbage. Port 0 is syntactically
    /// valid — `listen` uses it for ephemeral-port allocation; the
    /// `connect` side rejects it at the application layer
    /// (uri.md §5).
    if (ec != std::errc{} ||
        ptr != port_sv.data() + port_sv.size())
    {
        return std::nullopt;
    }

    out.port = port;
    return out;
}

/// Look up the value of a named query parameter without allocating.
/// Returns an empty view when the key is absent or the query has no
/// `=` separator on the relevant pair.
[[nodiscard]] inline std::string_view
uri_query_value(std::string_view query, std::string_view key) noexcept {
    while (!query.empty()) {
        const auto amp = query.find('&');
        const auto pair = (amp == std::string_view::npos)
                              ? query
                              : query.substr(0, amp);
        if (const auto eq = pair.find('=');
            eq != std::string_view::npos)
        {
            const auto k = pair.substr(0, eq);
            const auto v = pair.substr(eq + 1);
            if (k == key) return v;
        }
        if (amp == std::string_view::npos) break;
        query = query.substr(amp + 1);
    }
    return {};
}

}  // namespace gn
