// SPDX-License-Identifier: MIT
/// @file   tests/unit/util/test_uri.cpp
/// @brief  parse_uri + UriParts — every recognised form and every
///         failure mode from `docs/contracts/uri.md`.

#include <gtest/gtest.h>

#include <sdk/cpp/uri.hpp>
#include <core/util/uri_query.hpp>

#include <array>
#include <cstdint>
#include <string>

namespace {

/// Every test below pre-checks `r.has_value()` via gtest's `ASSERT_TRUE`
/// before dereferencing through `r->...`. clang-tidy's data-flow can't
/// see the abort, so the whole anonymous namespace is silenced. Same
/// pattern as `tests/unit/plugins/security/test_noise.cpp`.
// NOLINTBEGIN(bugprone-unchecked-optional-access)

// ── §2 recognised forms ──────────────────────────────────────────────────

TEST(ParseUri, SchemeHostPort) {
    auto r = ::gn::parse_uri("tcp://127.0.0.1:9000");
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(r->scheme, "tcp");
    EXPECT_EQ(r->host, "127.0.0.1");
    EXPECT_EQ(r->port, 9000);
    EXPECT_TRUE(r->query.empty());
    EXPECT_FALSE(r->is_path_style());
    EXPECT_EQ(r->canonical(), "tcp://127.0.0.1:9000");
}

TEST(ParseUri, SchemeHostPortQuery) {
    auto r = ::gn::parse_uri("mqtt://broker:1883?peer=abc&x=1");
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(r->scheme, "mqtt");
    EXPECT_EQ(r->host, "broker");
    EXPECT_EQ(r->port, 1883);
    EXPECT_EQ(r->query, "peer=abc&x=1");
    EXPECT_EQ(r->canonical(), "mqtt://broker:1883");
}

TEST(ParseUri, HostPortNoScheme) {
    auto r = ::gn::parse_uri("127.0.0.1:19800");
    ASSERT_TRUE(r.has_value());
    EXPECT_TRUE(r->scheme.empty());
    EXPECT_EQ(r->host, "127.0.0.1");
    EXPECT_EQ(r->port, 19800);
    EXPECT_EQ(r->canonical(), "127.0.0.1:19800");
}

TEST(ParseUri, IpcPathStyle) {
    auto r = ::gn::parse_uri("ipc:///run/goodnet.sock");
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(r->scheme, "ipc");
    EXPECT_EQ(r->path, "/run/goodnet.sock");
    EXPECT_EQ(r->host, "/run/goodnet.sock");  /// host mirrors path
    EXPECT_EQ(r->port, 0);
    EXPECT_TRUE(r->is_path_style());
    EXPECT_EQ(r->canonical(), "ipc:///run/goodnet.sock");
}

TEST(ParseUri, IpcAbstractName) {
    auto r = ::gn::parse_uri("ipc://my-bus");
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(r->path, "my-bus");
    EXPECT_TRUE(r->is_path_style());
    EXPECT_EQ(r->canonical(), "ipc://my-bus");
}

TEST(ParseUri, IpcWithQuery) {
    auto r = ::gn::parse_uri("ipc:///tmp/sock?peer=abc");
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(r->path, "/tmp/sock");
    EXPECT_EQ(r->query, "peer=abc");
    EXPECT_EQ(r->canonical(), "ipc:///tmp/sock");
}

// ── §5 failure modes ─────────────────────────────────────────────────────

TEST(ParseUri, EmptyInput) {
    EXPECT_FALSE(::gn::parse_uri("").has_value());
    EXPECT_FALSE(::gn::parse_uri("tcp://").has_value());
    EXPECT_FALSE(::gn::parse_uri("?peer=abc").has_value());
}

TEST(ParseUri, MissingPort) {
    EXPECT_FALSE(::gn::parse_uri("tcp://127.0.0.1").has_value());
    EXPECT_FALSE(::gn::parse_uri("host").has_value());
    EXPECT_FALSE(::gn::parse_uri("host:").has_value());
}

TEST(ParseUri, ZeroPortAccepted) {
    /// uri.md §5 — port 0 is syntactically valid for the parser;
    /// `listen()` uses it for OS-allocated ephemeral ports.
    auto r = ::gn::parse_uri("tcp://127.0.0.1:0");
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(r->port, 0);
}

TEST(ParseUri, RejectsTrailingGarbage) {
    EXPECT_FALSE(::gn::parse_uri("tcp://h:9000x").has_value());
    EXPECT_FALSE(::gn::parse_uri("tcp://h:xyz").has_value());
}

TEST(ParseUri, QueryStripsBeforeStrictPortCheck) {
    auto r = ::gn::parse_uri("tcp://127.0.0.1:9000?peer=abcxxx&trash=yes");
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(r->port, 9000);
    EXPECT_EQ(r->query, "peer=abcxxx&trash=yes");
}

TEST(ParseUri, MaxPort) {
    auto r = ::gn::parse_uri("tcp://h:65535");
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(r->port, 65535);
}

TEST(ParseUri, PortOverflowRejected) {
    EXPECT_FALSE(::gn::parse_uri("tcp://h:65536").has_value());
    EXPECT_FALSE(::gn::parse_uri("tcp://h:99999").has_value());
}

TEST(ParseUri, UnclosedBracketRejected) {
    EXPECT_FALSE(::gn::parse_uri("tcp://[::1:9000").has_value());
}

TEST(ParseUri, BracketWithoutPortRejected) {
    EXPECT_FALSE(::gn::parse_uri("tcp://[::1]").has_value());
    EXPECT_FALSE(::gn::parse_uri("tcp://[::1]9000").has_value());
}

TEST(ParseUri, ControlBytesRejected) {
    /// uri.md §5 #10 — any byte ≤ 0x20 or == 0x7F anywhere in the
    /// input is rejected before parsing. CRLF in particular would
    /// otherwise let a URI carry a smuggled HTTP request line when
    /// the transport concatenates the URI into a wire frame
    /// (`ws://h:9/x HTTP/1.1\r\nEvil: 1\r\n\r\nGET /` smuggles a
    /// second request through a naive serialiser).
    using namespace std::string_view_literals;
    EXPECT_FALSE(::gn::parse_uri("ws://h:9/x HTTP/1.1\r\nEvil: 1\r\n\r\nGET /"sv).has_value());
    EXPECT_FALSE(::gn::parse_uri("tcp://h:9000\r\n"sv).has_value());
    EXPECT_FALSE(::gn::parse_uri("tcp://h:9000\n"sv).has_value());
    EXPECT_FALSE(::gn::parse_uri("tcp://h:9000\t"sv).has_value());
    EXPECT_FALSE(::gn::parse_uri("tcp://h:\09000"sv).has_value());
    EXPECT_FALSE(::gn::parse_uri("tcp://h:9000 "sv).has_value());
    EXPECT_FALSE(::gn::parse_uri(" tcp://h:9000"sv).has_value());
    EXPECT_FALSE(::gn::parse_uri("tcp://host with space:9000"sv).has_value());
    EXPECT_FALSE(::gn::parse_uri("tcp://h:9000\x7F"sv).has_value());
    /// query slice is not exempt — CRLF in `?peer=...` would still
    /// reach the kernel's URI index and any caller reading the raw
    /// `query` view downstream.
    EXPECT_FALSE(::gn::parse_uri("tcp://h:9000?peer=abc\r\nEvil: 1"sv).has_value());
}

// ── §4 canonical form ────────────────────────────────────────────────────

TEST(ParseUri, CanonicalIgnoresQuery) {
    auto a = ::gn::parse_uri("tcp://1.2.3.4:80");
    auto b = ::gn::parse_uri("tcp://1.2.3.4:80?peer=deadbeef");
    ASSERT_TRUE(a.has_value());
    ASSERT_TRUE(b.has_value());
    EXPECT_EQ(a->canonical(), b->canonical());
}

TEST(ParseUri, CanonicalDistinguishesPort) {
    auto a = ::gn::parse_uri("tcp://1.2.3.4:80");
    auto b = ::gn::parse_uri("tcp://1.2.3.4:8080");
    ASSERT_TRUE(a.has_value());
    ASSERT_TRUE(b.has_value());
    EXPECT_NE(a->canonical(), b->canonical());
}

// ── IPv6 ─────────────────────────────────────────────────────────────────

TEST(ParseUri, BracketedIpv6Loopback) {
    auto r = ::gn::parse_uri("tcp://[::1]:9000");
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(r->host, "::1");          /// brackets stripped from host
    EXPECT_EQ(r->port, 9000);
    EXPECT_EQ(r->canonical(), "tcp://[::1]:9000");  /// re-bracketed
}

TEST(ParseUri, BracketedIpv6Wildcard) {
    auto r = ::gn::parse_uri("udp://[::]:5000");
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(r->host, "::");
    EXPECT_EQ(r->port, 5000);
}

TEST(ParseUri, BracketedIpv6Full) {
    auto r = ::gn::parse_uri("tcp://[2001:db8::1]:443");
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(r->host, "2001:db8::1");
    EXPECT_EQ(r->port, 443);
    EXPECT_EQ(r->canonical(), "tcp://[2001:db8::1]:443");
}

TEST(ParseUri, BracketedIpv6V4Mapped) {
    auto r = ::gn::parse_uri("tcp://[::ffff:127.0.0.1]:9000");
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(r->host, "::ffff:127.0.0.1");
    EXPECT_EQ(r->port, 9000);
}

TEST(ParseUri, BareBracketedIpv6) {
    auto r = ::gn::parse_uri("[::1]:9000");
    ASSERT_TRUE(r.has_value());
    EXPECT_TRUE(r->scheme.empty());
    EXPECT_EQ(r->host, "::1");
    EXPECT_EQ(r->port, 9000);
    EXPECT_EQ(r->canonical(), "[::1]:9000");
}

TEST(ParseUri, HostAuthorityBracketsV6) {
    /// `host_authority()` is the IP-literal form RFC 7230 §5.4 wants
    /// in an HTTP `Host:` header: brackets on IPv6, bare for IPv4 /
    /// hostnames, empty on path-style URIs.
    auto v4 = ::gn::parse_uri("tcp://1.2.3.4:80");
    ASSERT_TRUE(v4.has_value());
    EXPECT_EQ(v4->host_authority(), "1.2.3.4:80");

    auto v6 = ::gn::parse_uri("ws://[::1]:9000");
    ASSERT_TRUE(v6.has_value());
    EXPECT_EQ(v6->host_authority(), "[::1]:9000");

    auto host = ::gn::parse_uri("https://example.com:443");
    ASSERT_TRUE(host.has_value());
    EXPECT_EQ(host->host_authority(), "example.com:443");

    auto ipc = ::gn::parse_uri("ipc:///run/sock");
    ASSERT_TRUE(ipc.has_value());
    EXPECT_TRUE(ipc->host_authority().empty());
}

TEST(ParseUri, BracketedIpv6WithQuery) {
    auto r = ::gn::parse_uri("tcp://[::1]:9000?peer=abc");
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(r->host, "::1");
    EXPECT_EQ(r->query, "peer=abc");
}

TEST(ParseUri, UnbracketedIpv6FallbackCanonicalisesToBrackets) {
    /// uri.md §5.1: rightmost-`:` split rescues the legacy unbracketed
    /// form, but canonical() always re-brackets so future call sites
    /// only see the strict shape.
    auto r = ::gn::parse_uri("tcp://::1:9000");
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(r->host, "::1");
    EXPECT_EQ(r->port, 9000);
    EXPECT_EQ(r->canonical(), "tcp://[::1]:9000");
}

// ── query helpers ────────────────────────────────────────────────────────

TEST(UriQuery, ValueLookup) {
    auto r = ::gn::parse_uri("tcp://h:9?peer=abc&foo=42");
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(::gn::uri_query_value(r->query, "peer"), "abc");
    EXPECT_EQ(::gn::uri_query_value(r->query, "foo"),  "42");
    EXPECT_EQ(::gn::uri_query_value(r->query, "bar"),  "");
}

TEST(UriQuery, StripQuery) {
    EXPECT_EQ(::gn::util::uri_strip_query("tcp://h:9?peer=abc"), "tcp://h:9");
    EXPECT_EQ(::gn::util::uri_strip_query("tcp://h:9"), "tcp://h:9");
    EXPECT_EQ(::gn::util::uri_strip_query("?only-query"), "");
}

TEST(UriQuery, ParsePeerParamHexDecode) {
    /// 64-hex string decodes to 32 bytes; mismatched length / invalid
    /// hex returns nullopt.
    constexpr const char* kUri =
        "tcp://h:9?peer=0123456789abcdef0123456789abcdef"
                       "0123456789abcdef0123456789abcdef";
    auto pk = ::gn::util::parse_peer_param(kUri);
    ASSERT_TRUE(pk.has_value());
    EXPECT_EQ((*pk)[0], 0x01);
    EXPECT_EQ((*pk)[31], 0xef);

    /// Wrong length.
    EXPECT_FALSE(::gn::util::parse_peer_param("tcp://h:9?peer=deadbeef").has_value());
    /// Non-hex characters.
    EXPECT_FALSE(::gn::util::parse_peer_param(
        "tcp://h:9?peer=zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
                       "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz").has_value());
    /// Missing `peer` key.
    EXPECT_FALSE(::gn::util::parse_peer_param("tcp://h:9?other=42").has_value());
    /// Malformed URI.
    EXPECT_FALSE(::gn::util::parse_peer_param("garbage").has_value());
}

// NOLINTEND(bugprone-unchecked-optional-access)

}  // namespace
