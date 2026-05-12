// SPDX-License-Identifier: Apache-2.0
/// @file   sdk/cpp/connect.hpp
/// @brief  Scheme-dispatch sugar over `gn.link.<scheme>` extensions.
///
/// Closes the DX gap documented in the 2026-05-12 audit: apps that
/// want to `connect("wss://host:443")` should not have to:
///   1. Parse the scheme manually
///   2. Build the extension name `"gn.link.wss"` (or `ws`, or `tcp`)
///   3. Call `host_api->query_extension_checked` + cast vtables
///   4. Call `vt->connect(...)` and remember the conn id
///   5. Wrap the result in an RAII handle
///
/// All of that becomes:
/// @code
/// auto conn = gn::sdk::connect_to(host_api, "wss://host:443");
/// if (!conn) return GN_ERR_NOT_FOUND;
/// conn->send(payload);
/// @endcode
///
/// **Static (Tier 1)** — `connect_to` is synchronous. The underlying
/// carrier handshake (TCP ACK, TLS, etc.) is async but most plugins
/// queue sends until the wire is up, so the caller can issue
/// `send()` immediately. A future Tier-2 `connect_async(uri,
/// on_ready, on_error)` waits for a real "transport-ready" signal
/// once `host_api->get_conn_phase` lands.

#pragma once

#include <cstddef>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

#include <sdk/cpp/connection.hpp>
#include <sdk/cpp/link_carrier.hpp>
#include <sdk/host_api.h>
#include <sdk/types.h>

namespace gn::sdk {

/// Result bundle that owns BOTH the carrier and the conn handle.
/// Carrier lifetime ≥ conn lifetime — if the carrier moves, the
/// conn's back-pointer would dangle, so we co-locate them inside
/// the same object and only expose move semantics on the bundle.
class ConnectedSession {
public:
    ConnectedSession(LinkCarrier carrier, gn_conn_id_t conn)
        : carrier_(std::make_unique<LinkCarrier>(std::move(carrier))),
          conn_(*carrier_, conn) {}

    ConnectedSession(ConnectedSession&&) noexcept            = default;
    ConnectedSession& operator=(ConnectedSession&&) noexcept = default;
    ConnectedSession(const ConnectedSession&)                = delete;
    ConnectedSession& operator=(const ConnectedSession&)     = delete;

    [[nodiscard]] Connection&       conn()       noexcept { return conn_; }
    [[nodiscard]] const Connection& conn() const noexcept { return conn_; }

    [[nodiscard]] LinkCarrier&       carrier()       noexcept { return *carrier_; }
    [[nodiscard]] const LinkCarrier& carrier() const noexcept { return *carrier_; }

    /// Pass-through send / on_data for the common case where caller
    /// doesn't need explicit access to the inner Connection.
    [[nodiscard]] gn_result_t send(std::span<const std::uint8_t> b) {
        return conn_.send(b);
    }
    [[nodiscard]] gn_result_t on_data(Connection::DataFn cb) {
        return conn_.on_data(std::move(cb));
    }
    [[nodiscard]] gn_conn_id_t id() const noexcept { return conn_.id(); }
    [[nodiscard]] bool valid() const noexcept { return conn_.valid(); }

private:
    /// `unique_ptr` so move'ing the session doesn't relocate the
    /// carrier — Connection's back-pointer stays valid through
    /// move chains (e.g. returning out of a factory function).
    std::unique_ptr<LinkCarrier> carrier_;
    Connection                   conn_;
};

namespace detail {

/// Extract the scheme prefix from @p uri ("wss://host:443" → "wss").
/// Returns empty when no `://` separator is present.
[[nodiscard]] inline std::string_view parse_scheme(
    std::string_view uri) noexcept {
    const auto pos = uri.find("://");
    if (pos == std::string_view::npos) return {};
    return uri.substr(0, pos);
}

}  // namespace detail

/// Synchronous URI-driven connect. Parses the scheme, queries the
/// matching `gn.link.<scheme>` extension, calls `connect`, wraps
/// the result in a `ConnectedSession`.
///
/// Returns `nullopt` on:
///   * empty / malformed URI
///   * no plugin registered under `gn.link.<scheme>`
///   * underlying `connect` failure (use `connect_to_err` if you
///     need the failure code surfaced)
[[nodiscard]] inline std::optional<ConnectedSession>
connect_to(const host_api_t* api, std::string_view uri) {
    if (!api) return std::nullopt;
    const auto scheme = detail::parse_scheme(uri);
    if (scheme.empty()) return std::nullopt;

    auto carrier_opt = LinkCarrier::query(api, scheme);
    if (!carrier_opt) return std::nullopt;

    gn_conn_id_t conn = GN_INVALID_ID;
    const gn_result_t rc = carrier_opt->connect(uri, &conn);
    if (rc != GN_OK || conn == GN_INVALID_ID) {
        return std::nullopt;
    }
    return ConnectedSession(std::move(*carrier_opt), conn);
}

/// Same as `connect_to` but surfaces the underlying `gn_result_t`
/// through an out-parameter. Use this when an app needs to
/// distinguish "scheme not found" from "DNS failed" from "TCP RST".
[[nodiscard]] inline std::optional<ConnectedSession>
connect_to_err(const host_api_t* api,
                std::string_view uri,
                gn_result_t* out_err) {
    if (out_err) *out_err = GN_OK;
    if (!api) {
        if (out_err) *out_err = GN_ERR_NULL_ARG;
        return std::nullopt;
    }
    const auto scheme = detail::parse_scheme(uri);
    if (scheme.empty()) {
        if (out_err) *out_err = GN_ERR_INVALID_ENVELOPE;
        return std::nullopt;
    }

    auto carrier_opt = LinkCarrier::query(api, scheme);
    if (!carrier_opt) {
        if (out_err) *out_err = GN_ERR_NOT_FOUND;
        return std::nullopt;
    }

    gn_conn_id_t conn = GN_INVALID_ID;
    const gn_result_t rc = carrier_opt->connect(uri, &conn);
    if (rc != GN_OK || conn == GN_INVALID_ID) {
        if (out_err) *out_err = (rc != GN_OK) ? rc : GN_ERR_INVALID_STATE;
        return std::nullopt;
    }
    return ConnectedSession(std::move(*carrier_opt), conn);
}

/// Peer-pk-level outbound send. Wraps `host_api->send_to`, the
/// kernel-side dispatcher landed in Slice 9-KERNEL: walks live
/// conns to @p peer_pk, asks the active `gn.strategy.*` extension
/// to pick one, dispatches through `host_api->send`. Returns the
/// kernel's `gn_result_t` verbatim.
///
/// One-call replacement for the old "find_conn_by_pk + send"
/// boilerplate every handler had to write.
[[nodiscard]] inline gn_result_t
send_to(const host_api_t* api,
         const std::uint8_t peer_pk[GN_PUBLIC_KEY_BYTES],
         std::uint32_t msg_id,
         std::span<const std::uint8_t> payload) noexcept {
    if (!api || !api->send_to || !peer_pk) return GN_ERR_NULL_ARG;
    return api->send_to(api->host_ctx, peer_pk, msg_id,
                         payload.data(), payload.size());
}

/// Listen variant: same scheme dispatch, returns the carrier
/// (caller installs `on_accept` themselves — listeners produce
/// many conns, not one, so wrapping in `ConnectedSession` would
/// not fit).
[[nodiscard]] inline std::optional<LinkCarrier>
listen_to(const host_api_t* api, std::string_view uri) {
    if (!api) return std::nullopt;
    const auto scheme = detail::parse_scheme(uri);
    if (scheme.empty()) return std::nullopt;
    auto carrier_opt = LinkCarrier::query(api, scheme);
    if (!carrier_opt) return std::nullopt;
    if (carrier_opt->listen(uri) != GN_OK) return std::nullopt;
    return carrier_opt;
}

}  // namespace gn::sdk
