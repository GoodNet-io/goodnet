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
    /// First, install a known-good state. The new state lowers
    /// `max_connections` and `max_outbound_connections` together so
    /// the auto-validate path inside `load_json` does not reject
    /// the install on the cross-field invariant.
    const char* good = R"({"limits": {
        "max_connections": 999,
        "max_outbound_connections": 256
    }, "alpha": "first"})";
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

TEST(Config_LoadJson, ValidationFailurePreservesPriorState) {
    /// `load_json` runs `validate_limits` on the parsed limits before
    /// installing them; an invariant violation rolls the kernel
    /// state back to the prior load. This is the principal
    /// behaviour change versus the legacy split (`load_json`
    /// accepts → caller invokes `validate`): the kernel never
    /// executes against an invariant-violating limits set.
    Config c;
    const char* good = R"({"limits": {
        "max_connections": 1024,
        "max_outbound_connections": 256
    }, "marker": "ok"})";
    ASSERT_EQ(c.load_json(good), GN_OK);
    EXPECT_EQ(c.limits().max_connections, 1024u);

    /// Push a config that violates an invariant.
    const char* bad = R"({"limits": {
        "max_connections": 100,
        "max_outbound_connections": 200
    }, "marker": "tampered"})";
    EXPECT_EQ(c.load_json(bad), GN_ERR_LIMIT_REACHED);

    /// Prior state survives.
    EXPECT_EQ(c.limits().max_connections, 1024u);
    std::string s;
    ASSERT_EQ(c.get_string("marker", s), GN_OK);
    EXPECT_EQ(s, "ok");
}

// ─── validate: cross-field invariants from limits.md §3 ─────────────

TEST(Config_Validate, DefaultsPass) {
    Config c;
    std::string reason;
    EXPECT_EQ(c.validate(&reason), GN_OK);
    EXPECT_TRUE(reason.empty());
}

TEST(Config_Validate, OutboundExceedsTotalRejectedAtLoad) {
    /// `load_json` auto-validates; an invariant-violating doc fails
    /// the load directly with `GN_ERR_LIMIT_REACHED`. The legacy
    /// "load succeeds, validate fails later" path is gone — the
    /// kernel never accepts a config it would reject.
    Config c;
    const char* doc = R"({"limits": {
        "max_connections": 100,
        "max_outbound_connections": 200
    }})";
    EXPECT_EQ(c.load_json(doc), GN_ERR_LIMIT_REACHED);
}

TEST(Config_Validate, WatermarkInversionRejectedAtLoad) {
    Config c;
    const char* doc = R"({"limits": {
        "pending_queue_bytes_low":  4096,
        "pending_queue_bytes_high": 1024,
        "pending_queue_bytes_hard": 8192
    }})";
    EXPECT_EQ(c.load_json(doc), GN_ERR_LIMIT_REACHED);
}

TEST(Config_Validate, HardCapBelowSoftCapRejectedAtLoad) {
    Config c;
    const char* doc = R"({"limits": {
        "pending_queue_bytes_low":  1024,
        "pending_queue_bytes_high": 8192,
        "pending_queue_bytes_hard": 4096
    }})";
    EXPECT_EQ(c.load_json(doc), GN_ERR_LIMIT_REACHED);
}

TEST(Config_Validate, RelayTtlZeroRejectedAtLoad) {
    Config c;
    const char* doc = R"({"limits": {"max_relay_ttl": 0}})";
    EXPECT_EQ(c.load_json(doc), GN_ERR_LIMIT_REACHED);
}

TEST(Config_Validate, RelayTtlAboveCeilRejectedAtLoad) {
    Config c;
    const char* doc = R"({"limits": {"max_relay_ttl": 9}})";
    EXPECT_EQ(c.load_json(doc), GN_ERR_LIMIT_REACHED);
}

TEST(Config_Validate, RelayTtlAtCeilAccepted) {
    Config c;
    const char* doc = R"({"limits": {"max_relay_ttl": 8}})";
    ASSERT_EQ(c.load_json(doc), GN_OK);
    EXPECT_EQ(c.validate(), GN_OK);
}

TEST(Config_Validate, StorageValueExceedsPayloadRejectedAtLoad) {
    /// `max_payload_bytes` lowered to 1024 also trips the
    /// `max_payload_bytes + 14 > max_frame_bytes` invariant unless
    /// frame size shrinks alongside it; we override both so the
    /// rejection isolates on the storage / payload comparison.
    Config c;
    const char* doc = R"({"limits": {
        "max_payload_bytes": 1024,
        "max_frame_bytes":   1100,
        "max_storage_value_bytes": 8192
    }})";
    EXPECT_EQ(c.load_json(doc), GN_ERR_LIMIT_REACHED);
}

TEST(Config_Validate, ValidateStandaloneStillUsable) {
    /// The public `validate` remains usable for paths that re-check
    /// after a manual mutation — e.g. a future hot-reload signal
    /// might let an operator inspect the live limits without going
    /// through `load_json` again.
    Config c;
    EXPECT_EQ(c.validate(nullptr), GN_OK)
        << "default-constructed Config must satisfy every invariant";
}

TEST(Config_Validate, InjectRateBurstUnderHalfRateRejectedAtLoad) {
    /// New invariant: a token bucket whose burst is below half the
    /// refill rate cannot absorb a momentary spike — the burst
    /// must give the legitimate caller at least 0.5s of headroom.
    Config c;
    const char* doc = R"({"limits": {
        "inject_rate_per_source": 100,
        "inject_rate_burst": 30
    }})";
    EXPECT_EQ(c.load_json(doc), GN_ERR_LIMIT_REACHED);
}

TEST(Config_Validate, InjectRateZeroRateAcceptedAnyBurst) {
    /// A zero refill rate is a valid "drain only" choice that the
    /// integration tests use to make a tight, non-refilling bucket.
    /// The burst-vs-rate guard short-circuits in that case.
    Config c;
    const char* doc = R"({"limits": {
        "inject_rate_per_source": 0,
        "inject_rate_burst": 1
    }})";
    EXPECT_EQ(c.load_json(doc), GN_OK);
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
