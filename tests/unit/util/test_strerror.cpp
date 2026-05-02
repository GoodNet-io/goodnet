// SPDX-License-Identifier: MIT
/// @file   tests/unit/util/test_strerror.cpp
/// @brief  `gn_strerror` covers every enumerator of `gn_result_t` and
///         falls through to a sentinel for unknown values.
///
/// The mapping ships in `sdk/types.h` as `static inline` so plugins
/// linked against only the SDK pick it up without depending on
/// `goodnet_kernel`. This test pins:
///   * every enumerator returns a non-NULL, non-empty, non-sentinel
///     string (catching a future enum addition that forgets the
///     branch in the switch);
///   * unknown values surface the `"unknown gn_result_t"` sentinel
///     so log call sites can rely on a non-NULL return;
///   * a few representative codes carry the expected substring so a
///     wholesale rewording fails the test instead of silently
///     drifting an operator-facing message.

#include <gtest/gtest.h>

#include <array>
#include <cstring>
#include <string_view>

#include <sdk/types.h>

namespace {

constexpr std::string_view kUnknownSentinel = "unknown gn_result_t";

/// Every enumerator declared in `gn_result_t`. Adding a new code
/// without extending this array — and without a matching case in
/// `gn_strerror` — surfaces as a test failure instead of silently
/// returning the sentinel in production.
constexpr std::array<gn_result_t, 16> kAllCodes = {
    GN_OK,
    GN_ERR_NULL_ARG,
    GN_ERR_OUT_OF_MEMORY,
    GN_ERR_INVALID_ENVELOPE,
    GN_ERR_UNKNOWN_RECEIVER,
    GN_ERR_PAYLOAD_TOO_LARGE,
    GN_ERR_DEFRAME_INCOMPLETE,
    GN_ERR_DEFRAME_CORRUPT,
    GN_ERR_NOT_IMPLEMENTED,
    GN_ERR_VERSION_MISMATCH,
    GN_ERR_LIMIT_REACHED,
    GN_ERR_INVALID_STATE,
    GN_ERR_INTEGRITY_FAILED,
    GN_ERR_INTERNAL,
    GN_ERR_NOT_FOUND,
    GN_ERR_OUT_OF_RANGE,
};

}  // namespace

TEST(GnStrerror, EveryEnumeratorMapsToNonSentinel) {
    for (const auto code : kAllCodes) {
        const char* msg = gn_strerror(code);
        ASSERT_NE(msg, nullptr) << "code=" << static_cast<int>(code);
        EXPECT_GT(std::strlen(msg), 0u) << "code=" << static_cast<int>(code);
        EXPECT_NE(std::string_view{msg}, kUnknownSentinel)
            << "code=" << static_cast<int>(code) << " fell through to sentinel";
    }
}

TEST(GnStrerror, UnknownValueReturnsSentinel) {
    /// A value safely outside the enumerated range. Plugins built
    /// against an older SDK may receive a code from a newer kernel
    /// that they do not recognise; the sentinel keeps log call sites
    /// safe rather than degrading to NULL. The cast is intentional —
    /// we exercise the unknown-value branch.
    // NOLINTNEXTLINE(clang-analyzer-optin.core.EnumCastOutOfRange)
    const auto bogus = static_cast<gn_result_t>(-9999);
    const char* msg = gn_strerror(bogus);
    ASSERT_NE(msg, nullptr);
    EXPECT_EQ(std::string_view{msg}, kUnknownSentinel);
}

TEST(GnStrerror, OkIsExactlyOk) {
    EXPECT_EQ(std::string_view{gn_strerror(GN_OK)}, "ok");
}

TEST(GnStrerror, RepresentativeCodesCarryExpectedKeyword) {
    /// A loose substring check rather than a full-string pin: the
    /// wording is allowed to evolve, but the load-bearing keyword
    /// (the one operators grep for) MUST stay.
    struct Probe {
        gn_result_t      code;
        std::string_view keyword;
    };
    constexpr std::array<Probe, 5> probes = {{
        {GN_ERR_NULL_ARG,         "null"},
        {GN_ERR_OUT_OF_MEMORY,    "memory"},
        {GN_ERR_INVALID_ENVELOPE, "envelope"},
        {GN_ERR_NOT_FOUND,        "not found"},
        {GN_ERR_INTEGRITY_FAILED, "integrity"},
    }};

    for (const auto& p : probes) {
        const std::string_view msg = gn_strerror(p.code);
        EXPECT_NE(msg.find(p.keyword), std::string_view::npos)
            << "code=" << static_cast<int>(p.code)
            << " expected keyword=\"" << p.keyword << "\" got=\"" << msg << "\"";
    }
}

TEST(GnStrerror, ReturnedStringsAreLiteralsBeyondCallReturn) {
    /// The pointer must be valid past the call return; calling twice
    /// returns identical addresses since the strings are literals
    /// embedded in the binary.
    const char* a = gn_strerror(GN_OK);
    const char* b = gn_strerror(GN_OK);
    EXPECT_EQ(a, b);
}
