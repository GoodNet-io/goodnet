// SPDX-License-Identifier: MIT
/// @file   sdk/cpp/dns.hpp
/// @brief  Header-only synchronous DNS resolver per `dns.md` §2.
///
/// `resolve_uri_host` rewrites a `<scheme>://<host>:<port>[/path][?query]`
/// URI so the host segment is an IP literal. Transports call this
/// once per outbound `connect` to keep the orchestrator's cached
/// peer-pk stash and the registry URI index keyed on the same
/// canonical form. IP-literal hosts and `ipc://` path-style URIs
/// short-circuit — the helper rewrites only when an actual lookup is
/// needed.

#pragma once

#include <cstddef>
#include <expected>
#include <string>
#include <string_view>
#include <system_error>

#include <asio/io_context.hpp>
#include <asio/ip/address.hpp>
#include <asio/ip/tcp.hpp>

namespace gn::sdk {

/// Reason a `resolve_uri_host` call could not produce a literal-host
/// URI. The `message` field carries the asio error string for the
/// `ResolveFailed` case so the caller can surface it through logs.
struct ResolveError {
    enum class Kind {
        UnparseableUri,
        ResolveFailed,
    };
    Kind        kind;
    std::string message;
};

/// Rewrite the host segment of @p uri to an IP literal. See
/// `dns.md` §2 for the full input matrix.
[[nodiscard]] inline std::expected<std::string, ResolveError>
resolve_uri_host(asio::io_context& ioc, std::string_view uri) {
    if (uri.empty()) {
        return std::unexpected(ResolveError{
            ResolveError::Kind::UnparseableUri, std::string{uri}});
    }

    /// Locate the start of the authority — the substring after
    /// `<scheme>://`. URIs without `://` are passed through; the
    /// caller's transport-specific parser handles them on its own.
    const auto scheme_sep = uri.find("://");
    if (scheme_sep == std::string_view::npos) {
        return std::string{uri};
    }
    const std::size_t auth_start = scheme_sep + 3;
    if (auth_start >= uri.size()) {
        return std::unexpected(ResolveError{
            ResolveError::Kind::UnparseableUri, std::string{uri}});
    }

    /// Path-style schemes (`ipc://...`) carry a filesystem path in
    /// place of host:port. Detect by scheme name and short-circuit.
    const std::string_view scheme = uri.substr(0, scheme_sep);
    if (scheme == "ipc") {
        return std::string{uri};
    }

    /// Authority ends at the first `/` (path) or `?` (query) past
    /// `://`, whichever comes first; otherwise the rest of the URI.
    const auto path_pos  = uri.find('/', auth_start);
    const auto query_pos = uri.find('?', auth_start);
    const auto auth_end  = std::min(path_pos, query_pos);
    const std::string_view authority =
        auth_end == std::string_view::npos
            ? uri.substr(auth_start)
            : uri.substr(auth_start, auth_end - auth_start);

    if (authority.empty()) {
        return std::unexpected(ResolveError{
            ResolveError::Kind::UnparseableUri, std::string{uri}});
    }

    /// Extract the host substring out of the authority. Bracketed
    /// IPv6 keeps its brackets; unbracketed forms split on the last
    /// `:` so `host:port` and `[v6]:port` both work.
    std::size_t host_off_in_uri = 0;
    std::size_t host_len        = 0;
    bool        host_is_v6_literal = false;
    if (authority.front() == '[') {
        const auto rb = authority.find(']');
        if (rb == std::string_view::npos) {
            return std::unexpected(ResolveError{
                ResolveError::Kind::UnparseableUri, std::string{uri}});
        }
        /// Skip the `[`; length covers the literal alone.
        host_off_in_uri    = auth_start + 1;
        host_len           = rb - 1;
        host_is_v6_literal = true;
    } else {
        const auto colon = authority.rfind(':');
        host_off_in_uri = auth_start;
        host_len        = (colon == std::string_view::npos) ? authority.size()
                                                            : colon;
    }

    if (host_len == 0) {
        return std::unexpected(ResolveError{
            ResolveError::Kind::UnparseableUri, std::string{uri}});
    }

    const std::string_view host = uri.substr(host_off_in_uri, host_len);

    /// IP literal? The helper is a no-op — return the original URI
    /// unchanged so trailing path / query bytes survive verbatim.
    {
        std::error_code ec;
        (void)asio::ip::make_address(host, ec);
        if (!ec) {
            return std::string{uri};
        }
    }

    /// IPv6 literals never reach the resolver path — `make_address`
    /// already accepted them above. A bracketed authority that fell
    /// through is malformed (resolver would treat the literal as a
    /// hostname).
    if (host_is_v6_literal) {
        return std::unexpected(ResolveError{
            ResolveError::Kind::UnparseableUri, std::string{uri}});
    }

    /// Hostname → IP literal. Synchronous resolve on the caller's
    /// thread; hostname-bearing connects are sparse compared to per-
    /// frame work, so the blocking shape is correct.
    asio::ip::tcp::resolver resolver(ioc);
    std::error_code         ec;
    auto results = resolver.resolve(host, "", ec);
    if (ec) {
        return std::unexpected(ResolveError{
            ResolveError::Kind::ResolveFailed, ec.message()});
    }
    if (results.empty()) {
        return std::unexpected(ResolveError{
            ResolveError::Kind::ResolveFailed, "empty resolver result"});
    }

    const auto address = results.begin()->endpoint().address();
    std::string literal = address.to_string();

    /// Splice the literal back in; v6 results need brackets so the
    /// downstream `host:port` split keeps working.
    std::string out;
    out.reserve(uri.size() + literal.size());
    out.append(uri.substr(0, host_off_in_uri));
    if (address.is_v6()) {
        out.push_back('[');
        out.append(literal);
        out.push_back(']');
    } else {
        out.append(literal);
    }
    out.append(uri.substr(host_off_in_uri + host_len));
    return out;
}

}  // namespace gn::sdk
