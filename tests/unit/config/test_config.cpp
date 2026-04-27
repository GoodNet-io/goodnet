/// @file   tests/unit/config/test_config.cpp
/// @brief  GoogleTest unit tests for `gn::core::Config`.
///
/// Pins the contract from `docs/contracts/limits.md` §3 (cross-field
/// invariants on `gn_limits_t`) plus the dotted-path lookup surface
/// described in `host-api.md` §2 (config slots): JSON load is atomic;
/// parse failure preserves prior state; `validate` rejects every
/// invariant violation; lookups distinguish missing-key from
/// type-mismatch.

#include <gtest/gtest.h>

#include <cstdint>
#include <string>

#include <core/config/config.hpp>
#include <sdk/limits.h>
#include <sdk/types.h>

namespace gn::core {
namespace {

// ─── load_json: success / failure modes ─────────────────────────────

TEST(Config_LoadJson, EmptyDocumentLeavesDefaults) {
    Config c;
    /// Empty object — no overrides — defaults stand.
    ASSERT_EQ(c.load_json("{}"), GN_OK);
    EXPECT_EQ(c.limits().max_connections,
              GN_LIMITS_DEFAULT_MAX_CONNECTIONS);
    EXPECT_EQ(c.limits().max_relay_ttl,
              GN_LIMITS_DEFAULT_MAX_RELAY_TTL);
}

TEST(Config_LoadJson, OverridesLimitsFields) {
    Config c;
    const char* doc = R"({
        "limits": {
            "max_connections": 2048,
            "max_outbound_connections": 512,
            "max_relay_ttl": 3
        }
    })";
    ASSERT_EQ(c.load_json(doc), GN_OK);
    EXPECT_EQ(c.limits().max_connections, 2048u);
    EXPECT_EQ(c.limits().max_outbound_connections, 512u);
    EXPECT_EQ(c.limits().max_relay_ttl, 3u);
    /// Untouched fields keep defaults.
    EXPECT_EQ(c.limits().max_frame_bytes,
              GN_LIMITS_DEFAULT_MAX_FRAME_BYTES);
}

TEST(Config_LoadJson, MalformedJsonReturnsInvalidEnvelope) {
    Config c;
    EXPECT_EQ(c.load_json("{not json"), GN_ERR_INVALID_ENVELOPE);
}

TEST(Config_LoadJson, NonObjectRootRejected) {
    Config c;
    EXPECT_EQ(c.load_json("[1,2,3]"), GN_ERR_INVALID_ENVELOPE);
    EXPECT_EQ(c.load_json("\"string\""), GN_ERR_INVALID_ENVELOPE);
    EXPECT_EQ(c.load_json("42"), GN_ERR_INVALID_ENVELOPE);
}

TEST(Config_LoadJson, ParseFailurePreservesPriorState) {
    Config c;
    /// First, install a known-good state.
    const char* good = R"({"limits": {"max_connections": 999}, "alpha": "first"})";
    ASSERT_EQ(c.load_json(good), GN_OK);
    EXPECT_EQ(c.limits().max_connections, 999u);
    std::string s;
    ASSERT_EQ(c.get_string("alpha", s), GN_OK);
    EXPECT_EQ(s, "first");

    /// Now feed a syntactically bad doc — must NOT clobber state.
    EXPECT_EQ(c.load_json("[broken"), GN_ERR_INVALID_ENVELOPE);
    EXPECT_EQ(c.limits().max_connections, 999u);
    s.clear();
    ASSERT_EQ(c.get_string("alpha", s), GN_OK);
    EXPECT_EQ(s, "first");

    /// And a non-object root — same guarantee.
    EXPECT_EQ(c.load_json("[]"), GN_ERR_INVALID_ENVELOPE);
    EXPECT_EQ(c.limits().max_connections, 999u);
}

// ─── validate: cross-field invariants from limits.md §3 ─────────────

TEST(Config_Validate, DefaultsPass) {
    Config c;
    std::string reason;
    EXPECT_EQ(c.validate(&reason), GN_OK);
    EXPECT_TRUE(reason.empty());
}

TEST(Config_Validate, OutboundExceedsTotalRejected) {
    Config c;
    const char* doc = R"({"limits": {
        "max_connections": 100,
        "max_outbound_connections": 200
    }})";
    ASSERT_EQ(c.load_json(doc), GN_OK);
    std::string reason;
    EXPECT_EQ(c.validate(&reason), GN_ERR_LIMIT_REACHED);
    EXPECT_FALSE(reason.empty());
    EXPECT_NE(reason.find("max_outbound_connections"), std::string::npos);
}

TEST(Config_Validate, WatermarkInversionRejected) {
    /// low must be strictly less than high.
    Config c;
    const char* doc = R"({"limits": {
        "pending_queue_bytes_low":  4096,
        "pending_queue_bytes_high": 1024,
        "pending_queue_bytes_hard": 8192
    }})";
    ASSERT_EQ(c.load_json(doc), GN_OK);
    std::string reason;
    EXPECT_EQ(c.validate(&reason), GN_ERR_LIMIT_REACHED);
    EXPECT_NE(reason.find("pending_queue_bytes_low"), std::string::npos);
}

TEST(Config_Validate, HardCapBelowSoftCapRejected) {
    Config c;
    const char* doc = R"({"limits": {
        "pending_queue_bytes_low":  1024,
        "pending_queue_bytes_high": 8192,
        "pending_queue_bytes_hard": 4096
    }})";
    ASSERT_EQ(c.load_json(doc), GN_OK);
    std::string reason;
    EXPECT_EQ(c.validate(&reason), GN_ERR_LIMIT_REACHED);
    EXPECT_NE(reason.find("pending_queue_bytes_high"), std::string::npos);
}

TEST(Config_Validate, RelayTtlZeroRejected) {
    Config c;
    const char* doc = R"({"limits": {"max_relay_ttl": 0}})";
    ASSERT_EQ(c.load_json(doc), GN_OK);
    std::string reason;
    EXPECT_EQ(c.validate(&reason), GN_ERR_LIMIT_REACHED);
    EXPECT_NE(reason.find("max_relay_ttl"), std::string::npos);
}

TEST(Config_Validate, RelayTtlAboveCeilRejected) {
    Config c;
    const char* doc = R"({"limits": {"max_relay_ttl": 9}})";
    ASSERT_EQ(c.load_json(doc), GN_OK);
    std::string reason;
    EXPECT_EQ(c.validate(&reason), GN_ERR_LIMIT_REACHED);
    EXPECT_NE(reason.find("max_relay_ttl"), std::string::npos);
}

TEST(Config_Validate, RelayTtlAtCeilAccepted) {
    Config c;
    const char* doc = R"({"limits": {"max_relay_ttl": 8}})";
    ASSERT_EQ(c.load_json(doc), GN_OK);
    EXPECT_EQ(c.validate(), GN_OK);
}

TEST(Config_Validate, StorageValueExceedsPayloadRejected) {
    Config c;
    /// Set storage > payload to trip the §3 invariant.
    const char* doc = R"({"limits": {
        "max_payload_bytes": 1024,
        "max_storage_value_bytes": 8192
    }})";
    ASSERT_EQ(c.load_json(doc), GN_OK);
    std::string reason;
    EXPECT_EQ(c.validate(&reason), GN_ERR_LIMIT_REACHED);
    EXPECT_NE(reason.find("max_storage_value_bytes"), std::string::npos);
}

TEST(Config_Validate, NullReasonAccepted) {
    /// `validate` must tolerate a nullptr `out_reason` even when
    /// reporting a violation.
    Config c;
    const char* doc = R"({"limits": {"max_relay_ttl": 0}})";
    ASSERT_EQ(c.load_json(doc), GN_OK);
    EXPECT_EQ(c.validate(nullptr), GN_ERR_LIMIT_REACHED);
}

// ─── get_string ─────────────────────────────────────────────────────

TEST(Config_GetString, TopLevelKey) {
    Config c;
    const char* doc = R"({"hello": "world"})";
    ASSERT_EQ(c.load_json(doc), GN_OK);
    std::string out;
    EXPECT_EQ(c.get_string("hello", out), GN_OK);
    EXPECT_EQ(out, "world");
}

TEST(Config_GetString, DottedPath) {
    Config c;
    const char* doc = R"({
        "stacks": { "test": { "transport": "tcp" } }
    })";
    ASSERT_EQ(c.load_json(doc), GN_OK);
    std::string out;
    EXPECT_EQ(c.get_string("stacks.test.transport", out), GN_OK);
    EXPECT_EQ(out, "tcp");
}

TEST(Config_GetString, MissingKeyReturnsUnknownReceiver) {
    Config c;
    ASSERT_EQ(c.load_json("{}"), GN_OK);
    std::string out;
    EXPECT_EQ(c.get_string("absent", out), GN_ERR_UNKNOWN_RECEIVER);
}

TEST(Config_GetString, MissingMidSegmentReturnsUnknownReceiver) {
    Config c;
    const char* doc = R"({"a": {"b": "ok"}})";
    ASSERT_EQ(c.load_json(doc), GN_OK);
    std::string out;
    EXPECT_EQ(c.get_string("a.missing.b", out),
              GN_ERR_UNKNOWN_RECEIVER);
}

TEST(Config_GetString, TypeMismatchReturnsInvalidEnvelope) {
    Config c;
    const char* doc = R"({"k": 42})";
    ASSERT_EQ(c.load_json(doc), GN_OK);
    std::string out;
    EXPECT_EQ(c.get_string("k", out), GN_ERR_INVALID_ENVELOPE);
}

TEST(Config_GetString, NestedTypeMismatchReturnsInvalidEnvelope) {
    Config c;
    const char* doc = R"({"a": {"b": [1,2,3]}})";
    ASSERT_EQ(c.load_json(doc), GN_OK);
    std::string out;
    EXPECT_EQ(c.get_string("a.b", out), GN_ERR_INVALID_ENVELOPE);
}

TEST(Config_GetString, DescendingIntoNonObjectMisses) {
    Config c;
    const char* doc = R"({"k": "value"})";
    ASSERT_EQ(c.load_json(doc), GN_OK);
    std::string out;
    /// Tries to descend into a string node — fails.
    EXPECT_EQ(c.get_string("k.nested", out), GN_ERR_UNKNOWN_RECEIVER);
}

// ─── get_int64 ──────────────────────────────────────────────────────

TEST(Config_GetInt64, TopLevelKey) {
    Config c;
    const char* doc = R"({"answer": 42})";
    ASSERT_EQ(c.load_json(doc), GN_OK);
    std::int64_t out = 0;
    EXPECT_EQ(c.get_int64("answer", out), GN_OK);
    EXPECT_EQ(out, 42);
}

TEST(Config_GetInt64, NegativeValue) {
    Config c;
    const char* doc = R"({"v": -7})";
    ASSERT_EQ(c.load_json(doc), GN_OK);
    std::int64_t out = 0;
    EXPECT_EQ(c.get_int64("v", out), GN_OK);
    EXPECT_EQ(out, -7);
}

TEST(Config_GetInt64, DottedPath) {
    Config c;
    const char* doc = R"({"limits": {"max_connections": 4096}})";
    ASSERT_EQ(c.load_json(doc), GN_OK);
    std::int64_t out = 0;
    EXPECT_EQ(c.get_int64("limits.max_connections", out), GN_OK);
    EXPECT_EQ(out, 4096);
}

TEST(Config_GetInt64, MissingKey) {
    Config c;
    std::int64_t out = 123;
    EXPECT_EQ(c.get_int64("absent", out), GN_ERR_UNKNOWN_RECEIVER);
}

TEST(Config_GetInt64, TypeMismatchString) {
    Config c;
    const char* doc = R"({"k": "abc"})";
    ASSERT_EQ(c.load_json(doc), GN_OK);
    std::int64_t out = 0;
    EXPECT_EQ(c.get_int64("k", out), GN_ERR_INVALID_ENVELOPE);
}

TEST(Config_GetInt64, TypeMismatchFloat) {
    Config c;
    const char* doc = R"({"k": 3.14})";
    ASSERT_EQ(c.load_json(doc), GN_OK);
    std::int64_t out = 0;
    EXPECT_EQ(c.get_int64("k", out), GN_ERR_INVALID_ENVELOPE);
}

TEST(Config_GetInt64, EmptySegmentRejected) {
    Config c;
    ASSERT_EQ(c.load_json(R"({"k": 1})"), GN_OK);
    std::int64_t out = 0;
    EXPECT_EQ(c.get_int64("", out), GN_ERR_UNKNOWN_RECEIVER);
    EXPECT_EQ(c.get_int64(".", out), GN_ERR_UNKNOWN_RECEIVER);
    EXPECT_EQ(c.get_int64("k.", out), GN_ERR_UNKNOWN_RECEIVER);
}

}  // namespace
}  // namespace gn::core
