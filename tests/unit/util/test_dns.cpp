/// @file   tests/unit/util/test_dns.cpp
/// @brief  `gn::sdk::resolve_uri_host` per `dns.md` §2.
///
/// Hostname resolution itself is delegated to asio + libc; the cases
/// here pin the rewrite rules: IP literals pass through, path-style
/// URIs pass through, unparseable input is rejected, query strings
/// survive the rewrite. Hostname → literal goes through `localhost`,
/// which every CI image resolves locally without network access.

#include <gtest/gtest.h>

#include <sdk/cpp/dns.hpp>
#include <sdk/cpp/uri.hpp>

#include <asio/io_context.hpp>

#include <string>

namespace {

asio::io_context& shared_ioc() {
    static asio::io_context ioc;
    return ioc;
}

}  // namespace

TEST(ResolveUriHost, IpLiteralPassesThroughUnchanged) {
    auto& ioc = shared_ioc();
    auto out = gn::sdk::resolve_uri_host(ioc, "tcp://127.0.0.1:9000");
    ASSERT_TRUE(out.has_value());
    EXPECT_EQ(*out, "tcp://127.0.0.1:9000");
}

TEST(ResolveUriHost, Ipv6LiteralPassesThroughUnchanged) {
    auto& ioc = shared_ioc();
    auto out = gn::sdk::resolve_uri_host(ioc, "tcp://[::1]:9000");
    ASSERT_TRUE(out.has_value());
    EXPECT_EQ(*out, "tcp://[::1]:9000");
}

TEST(ResolveUriHost, PathStyleUriPassesThrough) {
    auto& ioc = shared_ioc();
    auto out = gn::sdk::resolve_uri_host(ioc, "ipc:///run/goodnet.sock");
    ASSERT_TRUE(out.has_value());
    EXPECT_EQ(*out, "ipc:///run/goodnet.sock");
}

TEST(ResolveUriHost, UnparseableUriReportsError) {
    auto& ioc = shared_ioc();
    auto out = gn::sdk::resolve_uri_host(ioc, "");
    ASSERT_FALSE(out.has_value());
    EXPECT_EQ(out.error().kind, gn::sdk::ResolveError::Kind::UnparseableUri);
}

TEST(ResolveUriHost, QueryStringSurvivesRewrite) {
    auto& ioc = shared_ioc();
    /// IP literal path: query passes through canonicalisation.
    auto out = gn::sdk::resolve_uri_host(
        ioc, "tcp://127.0.0.1:9000?peer=abcd");
    ASSERT_TRUE(out.has_value());
    EXPECT_EQ(*out, "tcp://127.0.0.1:9000?peer=abcd");
}

TEST(ResolveUriHost, LocalhostResolvesToLoopbackLiteral) {
    /// The OS resolver returns either 127.0.0.1 or ::1 for "localhost"
    /// depending on /etc/hosts and address family preference. Either
    /// is acceptable as long as the result is an IP literal that the
    /// asio parser round-trips.
    auto& ioc = shared_ioc();
    auto out = gn::sdk::resolve_uri_host(ioc, "tcp://localhost:9000");
    ASSERT_TRUE(out.has_value()) << "localhost should resolve on every "
                                     "supported platform";
    /// The returned URI has the form tcp://<literal>:9000 — a fresh
    /// parse succeeds and the host slot is now a literal address.
    auto parts = gn::parse_uri(*out);
    ASSERT_TRUE(parts.has_value());
    if (parts.has_value()) {
        const auto& got = *parts;
        EXPECT_EQ(got.scheme, "tcp");
        EXPECT_EQ(got.port, 9000);

        std::error_code ec;
        auto addr = asio::ip::make_address(got.host, ec);
        EXPECT_FALSE(ec) << "host '" << got.host << "' is not an IP literal";
        EXPECT_TRUE(addr.is_loopback())
            << "localhost should map to a loopback address";
    }
}

TEST(ResolveUriHost, NonResolvableHostnameReportsError) {
    /// `*.invalid` is reserved by RFC 2606 so every conforming
    /// resolver returns NXDOMAIN. Surface that as `ResolveFailed`,
    /// not a silent passthrough.
    auto& ioc = shared_ioc();
    auto out = gn::sdk::resolve_uri_host(
        ioc, "tcp://nonexistent.invalid:443");
    ASSERT_FALSE(out.has_value());
    EXPECT_EQ(out.error().kind, gn::sdk::ResolveError::Kind::ResolveFailed);
    EXPECT_FALSE(out.error().message.empty());
}

TEST(ResolveUriHost, RejectsUserinfoBeforeHost) {
    /// `user:pass@host` would otherwise leak credentials to the
    /// system resolver. Rejected before the lookup.
    auto& ioc = shared_ioc();
    auto out = gn::sdk::resolve_uri_host(
        ioc, "tcp://user:pass@example.com:443");
    ASSERT_FALSE(out.has_value());
    EXPECT_EQ(out.error().kind,
              gn::sdk::ResolveError::Kind::UnparseableUri);
}

TEST(ResolveUriHost, RejectsHostnameWithSpaces) {
    /// LDH alphabet excludes spaces; a URI containing a space in
    /// the host slot is malformed.
    auto& ioc = shared_ioc();
    auto out = gn::sdk::resolve_uri_host(
        ioc, "tcp://bad host:443");
    ASSERT_FALSE(out.has_value());
    EXPECT_EQ(out.error().kind,
              gn::sdk::ResolveError::Kind::UnparseableUri);
}
