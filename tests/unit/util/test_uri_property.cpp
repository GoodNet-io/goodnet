// SPDX-License-Identifier: MIT
/// @file   tests/unit/util/test_uri_property.cpp
/// @brief  Round-trip property — canonicalisation is idempotent across
///         every recognised URI form.

#include <gtest/gtest.h>
#include <rapidcheck/gtest.h>

#include <sdk/cpp/uri.hpp>

#include <cstdint>
#include <string>

namespace {

/// Generator: well-formed scheme strings ("tcp" / "udp" / "ws" / "mqtt").
rc::Gen<std::string> gen_scheme() {
    return rc::gen::element<std::string>("tcp", "udp", "ws", "mqtt");
}

/// Generator: IPv4 dotted quad (literal host).
rc::Gen<std::string> gen_v4() {
    return rc::gen::map(
        rc::gen::tuple(rc::gen::inRange(0, 256),
                        rc::gen::inRange(0, 256),
                        rc::gen::inRange(0, 256),
                        rc::gen::inRange(0, 256)),
        [](auto t) {
            const auto [a, b, c, d] = t;
            return std::to_string(a) + "." + std::to_string(b) + "." +
                   std::to_string(c) + "." + std::to_string(d);
        });
}

/// Generator: ports in [1, 65535].
rc::Gen<std::uint16_t> gen_port() {
    return rc::gen::map(rc::gen::inRange(1, 65536),
                        [](int p) { return static_cast<std::uint16_t>(p); });
}

/// Build a `scheme://host:port` URI from generators.
rc::Gen<std::string> gen_v4_uri() {
    return rc::gen::map(
        rc::gen::tuple(gen_scheme(), gen_v4(), gen_port()),
        [](auto t) {
            const auto& [s, h, p] = t;
            return s + "://" + h + ":" + std::to_string(p);
        });
}

}  // namespace

// ── round-trip identity ─────────────────────────────────────────────

RC_GTEST_PROP(UriProperty, V4UriCanonicalRoundTrip, ()) {
    const auto uri = *gen_v4_uri();
    const auto first = ::gn::parse_uri(uri);
    RC_ASSERT(first.has_value());

    /// canonical() output parses back to a UriParts that produces the
    /// same canonical string — the operation is idempotent.
    const auto canon = first->canonical();
    const auto second = ::gn::parse_uri(canon);
    RC_ASSERT(second.has_value());
    RC_ASSERT(second->canonical() == canon);
    RC_ASSERT(first->scheme == second->scheme);
    RC_ASSERT(first->host   == second->host);
    RC_ASSERT(first->port   == second->port);
}

RC_GTEST_PROP(UriProperty, V4UriQueryDoesNotChangeCanonical, ()) {
    const auto uri = *gen_v4_uri();
    const auto suffix = *rc::gen::element<std::string>(
        "", "?peer=abc", "?x=1&y=2", "?a=&b=", "?single");

    const auto plain = ::gn::parse_uri(uri);
    const auto with_q = ::gn::parse_uri(uri + suffix);
    RC_ASSERT(plain.has_value());
    RC_ASSERT(with_q.has_value());
    /// uri.md §4: canonical() drops the query.
    RC_ASSERT(plain->canonical() == with_q->canonical());
}

RC_GTEST_PROP(UriProperty, IpcPathRoundTrip, ()) {
    /// Path bodies use URI-safe characters (no `?` so the query split
    /// stays clean). Any non-empty body is valid for ipc://.
    const auto path = *rc::gen::nonEmpty(
        rc::gen::container<std::string>(
            rc::gen::element('a','b','c','d','/','-','_','.','1','2','3')));
    const auto uri = "ipc://" + path;
    const auto parts = ::gn::parse_uri(uri);
    RC_ASSERT(parts.has_value());
    RC_ASSERT(parts->is_path_style());
    RC_ASSERT(parts->path == path);
    RC_ASSERT(parts->canonical() == uri);
}

RC_GTEST_PROP(UriProperty, MalformedPortRejected, ()) {
    /// Port segment carrying any non-digit terminal character must
    /// fail the strict `from_chars` check.
    const auto host = *gen_v4();
    const auto port = *gen_port();
    const auto trailing = *rc::gen::element<std::string>("x", "abc", "9z", "-");
    const auto uri = "tcp://" + host + ":" + std::to_string(port) + trailing;
    RC_ASSERT(!::gn::parse_uri(uri).has_value());
}
