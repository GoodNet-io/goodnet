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
#include <filesystem>
#include <fstream>
#include <string>

#include <core/config/config.hpp>
#include <sdk/limits.h>
#include <sdk/types.h>

namespace gn::core {
namespace {

// ── load_json: success / failure modes ───────────────────────────────────

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

// ── validate: cross-field invariants from limits.md §3 ───────────────────

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

// ── get_string ───────────────────────────────────────────────────────────

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

TEST(Config_GetString, MissingKeyReturnsNotFound) {
    Config c;
    ASSERT_EQ(c.load_json("{}"), GN_OK);
    std::string out;
    EXPECT_EQ(c.get_string("absent", out), GN_ERR_NOT_FOUND);
}

TEST(Config_GetString, MissingMidSegmentReturnsNotFound) {
    Config c;
    const char* doc = R"({"a": {"b": "ok"}})";
    ASSERT_EQ(c.load_json(doc), GN_OK);
    std::string out;
    EXPECT_EQ(c.get_string("a.missing.b", out),
              GN_ERR_NOT_FOUND);
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
    EXPECT_EQ(c.get_string("k.nested", out), GN_ERR_NOT_FOUND);
}

// ── get_int64 ────────────────────────────────────────────────────────────

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
    EXPECT_EQ(c.get_int64("absent", out), GN_ERR_NOT_FOUND);
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
    EXPECT_EQ(c.get_int64("", out), GN_ERR_NOT_FOUND);
    EXPECT_EQ(c.get_int64(".", out), GN_ERR_NOT_FOUND);
    EXPECT_EQ(c.get_int64("k.", out), GN_ERR_NOT_FOUND);
}

// ── get_bool ─────────────────────────────────────────────────────────────

TEST(Config_GetBool, ReadsTrueAndFalse) {
    Config c;
    ASSERT_EQ(c.load_json(R"({"on": true, "off": false})"), GN_OK);
    bool v = false;
    EXPECT_EQ(c.get_bool("on", v), GN_OK);
    EXPECT_TRUE(v);
    EXPECT_EQ(c.get_bool("off", v), GN_OK);
    EXPECT_FALSE(v);
}

TEST(Config_GetBool, IntegerNotABool) {
    /// JSON distinguishes `1` from `true`; the typed slot rejects
    /// the integer rather than coerce. Plugins that want C-style
    /// "0/1 means false/true" pick `get_int64` instead.
    Config c;
    ASSERT_EQ(c.load_json(R"({"v": 1})"), GN_OK);
    bool v = false;
    EXPECT_EQ(c.get_bool("v", v), GN_ERR_INVALID_ENVELOPE);
}

TEST(Config_GetBool, MissingReturnsNotFound) {
    Config c;
    bool v = false;
    EXPECT_EQ(c.get_bool("absent", v), GN_ERR_NOT_FOUND);
}

// ── get_double ───────────────────────────────────────────────────────────

TEST(Config_GetDouble, FloatLiteral) {
    Config c;
    ASSERT_EQ(c.load_json(R"({"k": 3.14})"), GN_OK);
    double v = 0.0;
    EXPECT_EQ(c.get_double("k", v), GN_OK);
    EXPECT_DOUBLE_EQ(v, 3.14);
}

TEST(Config_GetDouble, IntegerLiteralAccepted) {
    /// Operators reach the same knob whether they write `1` or
    /// `1.0`; the typed slot widens the integer to double rather
    /// than rejecting on type mismatch.
    Config c;
    ASSERT_EQ(c.load_json(R"({"k": 5})"), GN_OK);
    double v = 0.0;
    EXPECT_EQ(c.get_double("k", v), GN_OK);
    EXPECT_DOUBLE_EQ(v, 5.0);
}

TEST(Config_GetDouble, StringRejected) {
    Config c;
    ASSERT_EQ(c.load_json(R"({"k": "1.5"})"), GN_OK);
    double v = 0.0;
    EXPECT_EQ(c.get_double("k", v), GN_ERR_INVALID_ENVELOPE);
}

// ── get_array_* ──────────────────────────────────────────────────────────

TEST(Config_GetArray, SizeOfFlatArray) {
    Config c;
    ASSERT_EQ(c.load_json(R"({"peers": ["a", "b", "c"]})"), GN_OK);
    std::size_t n = 0;
    EXPECT_EQ(c.get_array_size("peers", n), GN_OK);
    EXPECT_EQ(n, 3u);
}

TEST(Config_GetArray, SizeOnNonArrayRejected) {
    Config c;
    ASSERT_EQ(c.load_json(R"({"k": "scalar"})"), GN_OK);
    std::size_t n = 0;
    EXPECT_EQ(c.get_array_size("k", n), GN_ERR_INVALID_ENVELOPE);
}

TEST(Config_GetArray, StringByIndex) {
    Config c;
    ASSERT_EQ(c.load_json(R"({"peers": ["alpha", "beta", "gamma"]})"),
              GN_OK);
    std::string out;
    EXPECT_EQ(c.get_array_string("peers", 0, out), GN_OK);
    EXPECT_EQ(out, "alpha");
    EXPECT_EQ(c.get_array_string("peers", 2, out), GN_OK);
    EXPECT_EQ(out, "gamma");
}

TEST(Config_GetArray, OutOfBoundsReturnsOutOfRange) {
    Config c;
    ASSERT_EQ(c.load_json(R"({"peers": ["a", "b"]})"), GN_OK);
    std::string out;
    EXPECT_EQ(c.get_array_string("peers", 5, out),
              GN_ERR_OUT_OF_RANGE);
}

TEST(Config_GetArray, ElementTypeMismatch) {
    Config c;
    ASSERT_EQ(c.load_json(R"({"mixed": [1, "two", 3]})"), GN_OK);
    std::string s;
    EXPECT_EQ(c.get_array_string("mixed", 0, s),
              GN_ERR_INVALID_ENVELOPE);
    EXPECT_EQ(c.get_array_string("mixed", 1, s), GN_OK);
    EXPECT_EQ(s, "two");

    std::int64_t i = 0;
    EXPECT_EQ(c.get_array_int64("mixed", 0, i), GN_OK);
    EXPECT_EQ(i, 1);
    EXPECT_EQ(c.get_array_int64("mixed", 1, i),
              GN_ERR_INVALID_ENVELOPE);
}

TEST(Config_GetArray, IntegerArray) {
    /// Typical use-case: `dht.bootstrap_nodes` ports or
    /// `tuning.profile_thresholds` numeric config.
    Config c;
    ASSERT_EQ(c.load_json(R"({"ports": [9000, 9001, 9002]})"), GN_OK);
    std::int64_t v = 0;
    EXPECT_EQ(c.get_array_int64("ports", 1, v), GN_OK);
    EXPECT_EQ(v, 9001);
}

// ── merge_json (layered config) ──────────────────────────────────────────

TEST(Config_Merge, OverlayKeepsBaseFields) {
    /// Layered config pattern: defaults → site override. Fields
    /// the overlay does not mention survive from the base.
    Config c;
    ASSERT_EQ(c.load_json(R"({"limits": {
        "max_connections": 4096,
        "max_outbound_connections": 1024,
        "max_timers": 4096
    }, "marker": "base"})"), GN_OK);

    ASSERT_EQ(c.merge_json(R"({"marker": "site"})"), GN_OK);

    /// `marker` came from the overlay; limits survived intact.
    std::string s;
    EXPECT_EQ(c.get_string("marker", s), GN_OK);
    EXPECT_EQ(s, "site");
    EXPECT_EQ(c.limits().max_connections, 4096u);
    EXPECT_EQ(c.limits().max_timers,      4096u);
}

TEST(Config_Merge, NestedObjectFieldsMergeFieldByField) {
    /// `limits` object exists in both — RFC 7396 deep-merge means
    /// only the overlay's named fields replace; the base's other
    /// fields stay.
    Config c;
    ASSERT_EQ(c.load_json(R"({"limits": {
        "max_connections": 4096,
        "max_outbound_connections": 1024,
        "max_timers": 2048
    }})"), GN_OK);

    ASSERT_EQ(c.merge_json(R"({"limits": {"max_timers": 256}})"),
              GN_OK);

    EXPECT_EQ(c.limits().max_connections,        4096u);
    EXPECT_EQ(c.limits().max_outbound_connections, 1024u);
    EXPECT_EQ(c.limits().max_timers,              256u);
}

TEST(Config_Merge, OverlayReplacesArrays) {
    /// Arrays replace wholesale per RFC 7396 — operators that
    /// want to extend an array re-write the full list at the
    /// merge site.
    Config c;
    ASSERT_EQ(c.load_json(R"({"peers": ["a", "b", "c"]})"), GN_OK);
    ASSERT_EQ(c.merge_json(R"({"peers": ["x"]})"), GN_OK);

    std::size_t n = 0;
    EXPECT_EQ(c.get_array_size("peers", n), GN_OK);
    EXPECT_EQ(n, 1u);
    std::string s;
    EXPECT_EQ(c.get_array_string("peers", 0, s), GN_OK);
    EXPECT_EQ(s, "x");
}

TEST(Config_Merge, ProfileSwitchSnapsUnsetLimitsToNewBaseline) {
    /// `config.md` §3a — merging an overlay that names a different
    /// `profile` re-evaluates every limits.* field that the
    /// overlay does not pin against the new baseline. The caller
    /// who only meant to override `max_timers` ends up with the
    /// embedded profile's connection cap because the baseline
    /// flipped under the overlay.
    Config c;
    ASSERT_EQ(c.load_json(R"({"profile": "server"})"), GN_OK);
    /// Server baseline ships `max_connections = 4096`.
    ASSERT_EQ(c.limits().max_connections, 4096u);

    ASSERT_EQ(c.merge_json(
        R"({"profile": "embedded", "limits": {"max_timers": 128}})"),
        GN_OK);

    /// `max_connections` was unset in the overlay; profile flip
    /// snaps it to the embedded baseline (64). The pinned
    /// `max_timers` stays at 128 even though embedded would have
    /// defaulted to 256.
    EXPECT_EQ(c.limits().max_connections, 64u);
    EXPECT_EQ(c.limits().max_timers, 128u);
}

TEST(Config_Merge, OverlayWithoutProfileKeepsPriorBaseline) {
    /// Same §3a — an overlay that omits `profile` keeps the
    /// active baseline so unset limits stay where the prior
    /// `load_json` placed them. This is the intended workflow
    /// for nudging a single field without surprise.
    Config c;
    ASSERT_EQ(c.load_json(R"({"profile": "embedded"})"), GN_OK);
    ASSERT_EQ(c.limits().max_connections, 64u);

    ASSERT_EQ(c.merge_json(R"({"limits": {"max_timers": 128}})"), GN_OK);
    EXPECT_EQ(c.limits().max_connections, 64u);
    EXPECT_EQ(c.limits().max_timers, 128u);
}

TEST(Config_Merge, MalformedOverlayPreservesPriorState) {
    Config c;
    ASSERT_EQ(c.load_json(R"({"marker": "base"})"), GN_OK);
    EXPECT_EQ(c.merge_json("[bad json"), GN_ERR_INVALID_ENVELOPE);

    std::string s;
    EXPECT_EQ(c.get_string("marker", s), GN_OK);
    EXPECT_EQ(s, "base");
}

TEST(Config_Merge, OverlayThatViolatesInvariantRollsBack) {
    /// Auto-validate covers merge too. An overlay that lowers
    /// `max_connections` below `max_outbound_connections` rolls
    /// the kernel state back to the prior successful load.
    Config c;
    ASSERT_EQ(c.load_json(R"({"limits": {
        "max_connections": 1024,
        "max_outbound_connections": 256
    }, "marker": "ok"})"), GN_OK);

    EXPECT_EQ(c.merge_json(R"({"limits": {"max_connections": 100}})"),
              GN_ERR_LIMIT_REACHED);

    /// Prior state intact.
    EXPECT_EQ(c.limits().max_connections, 1024u);
    std::string s;
    EXPECT_EQ(c.get_string("marker", s), GN_OK);
    EXPECT_EQ(s, "ok");
}

TEST(Config_Merge, ChainedMergesYieldExpectedFinalState) {
    /// Three-layer pattern from docs §1: defaults → site → deploy.
    Config c;
    ASSERT_EQ(c.load_json(R"({"limits": {
        "max_connections": 4096,
        "max_outbound_connections": 1024,
        "max_timers": 2048
    }})"), GN_OK);

    ASSERT_EQ(c.merge_json(R"({"limits": {"max_timers": 1024}})"),
              GN_OK);
    ASSERT_EQ(c.merge_json(R"({"limits": {"max_outbound_connections": 256}})"),
              GN_OK);

    EXPECT_EQ(c.limits().max_connections,         4096u);
    EXPECT_EQ(c.limits().max_outbound_connections, 256u);  // deploy
    EXPECT_EQ(c.limits().max_timers,              1024u);  // site
}

// ── profiles ─────────────────────────────────────────────────────────────

TEST(Config_Profile, NameParserAcceptsKnown) {
    EXPECT_EQ(Config::parse_profile_name("server"),
              Config::Profile::Server);
    EXPECT_EQ(Config::parse_profile_name("embedded"),
              Config::Profile::Embedded);
    EXPECT_EQ(Config::parse_profile_name("desktop"),
              Config::Profile::Desktop);
}

TEST(Config_Profile, NameParserFallsBackToServer) {
    /// Unknown names fall back to canonical defaults. An operator
    /// who typoed their profile sees the safe-default values, not
    /// a tighter set that would drop traffic.
    EXPECT_EQ(Config::parse_profile_name(""),
              Config::Profile::Server);
    EXPECT_EQ(Config::parse_profile_name("typo"),
              Config::Profile::Server);
    EXPECT_EQ(Config::parse_profile_name("SERVER"),
              Config::Profile::Server);  // strict lowercase match
}

TEST(Config_Profile, ServerDefaultsMatchHistorical) {
    const auto L = Config::profile_defaults(Config::Profile::Server);
    EXPECT_EQ(L.max_connections,          GN_LIMITS_DEFAULT_MAX_CONNECTIONS);
    EXPECT_EQ(L.max_outbound_connections,
              GN_LIMITS_DEFAULT_MAX_OUTBOUND_CONNECTIONS);
    EXPECT_EQ(L.max_timers,               GN_LIMITS_DEFAULT_MAX_TIMERS);
    EXPECT_EQ(L.max_frame_bytes,          GN_LIMITS_DEFAULT_MAX_FRAME_BYTES);
}

TEST(Config_Profile, EmbeddedShrinksEveryDimension) {
    const auto S = Config::profile_defaults(Config::Profile::Server);
    const auto E = Config::profile_defaults(Config::Profile::Embedded);
    EXPECT_LT(E.max_connections,          S.max_connections);
    EXPECT_LT(E.max_outbound_connections, S.max_outbound_connections);
    EXPECT_LT(E.max_timers,               S.max_timers);
    EXPECT_LT(E.max_frame_bytes,          S.max_frame_bytes);
    EXPECT_LT(E.max_plugins,              S.max_plugins);
    EXPECT_LT(E.inject_rate_per_source,   S.inject_rate_per_source);
}

TEST(Config_Profile, DesktopBetweenEmbeddedAndServer) {
    const auto S = Config::profile_defaults(Config::Profile::Server);
    const auto E = Config::profile_defaults(Config::Profile::Embedded);
    const auto D = Config::profile_defaults(Config::Profile::Desktop);
    EXPECT_GT(D.max_connections, E.max_connections);
    EXPECT_LT(D.max_connections, S.max_connections);
    EXPECT_GT(D.max_timers,      E.max_timers);
    EXPECT_LT(D.max_timers,      S.max_timers);
}

TEST(Config_Profile, JsonSelectsProfile) {
    Config c;
    ASSERT_EQ(c.load_json(R"({"profile": "embedded"})"), GN_OK);
    EXPECT_EQ(c.limits().max_connections, 64u)
        << "embedded baseline must surface even with no `limits` block";
}

TEST(Config_Profile, LimitsBlockOverridesProfile) {
    /// `profile` selects the baseline; `limits` overrides individual
    /// fields on top. An operator writing both wants the baseline's
    /// shape with surgical exceptions.
    Config c;
    const char* doc = R"({
        "profile": "embedded",
        "limits": {
            "max_connections": 32
        }
    })";
    ASSERT_EQ(c.load_json(doc), GN_OK);
    EXPECT_EQ(c.limits().max_connections, 32u)
        << "limits override must beat profile baseline";
    /// Untouched fields keep the embedded baseline (not server).
    EXPECT_EQ(c.limits().max_timers, 256u)
        << "embedded baseline must surface for non-overridden fields";
}

TEST(Config_Profile, MissingProfileFieldUsesServerBaseline) {
    /// No `profile` key — historical behaviour: server defaults.
    /// Lower outbound alongside total to satisfy the invariant.
    Config c;
    const char* doc = R"({"limits": {
        "max_connections": 999,
        "max_outbound_connections": 256
    }})";
    ASSERT_EQ(c.load_json(doc), GN_OK);
    EXPECT_EQ(c.limits().max_connections, 999u);
    /// Untouched field reflects server baseline (4096-default).
    EXPECT_EQ(c.limits().max_timers,
              GN_LIMITS_DEFAULT_MAX_TIMERS);
}

// ── dump round-trip ──────────────────────────────────────────────────────

TEST(Config_Dump, EmptyConfigYieldsEmptyObject) {
    Config c;
    EXPECT_EQ(c.dump(), "{}");
}

TEST(Config_Dump, RoundTripPreservesValues) {
    Config c;
    const char* doc = R"({"hello":"world","limits":{"max_connections":2048,"max_outbound_connections":512}})";
    ASSERT_EQ(c.load_json(doc), GN_OK);

    /// dump (compact) → re-load — every observable value carries through.
    Config c2;
    ASSERT_EQ(c2.load_json(c.dump()), GN_OK);
    EXPECT_EQ(c2.limits().max_connections, 2048u);
    EXPECT_EQ(c2.limits().max_outbound_connections, 512u);

    std::string s;
    EXPECT_EQ(c2.get_string("hello", s), GN_OK);
    EXPECT_EQ(s, "world");
}

TEST(Config_Dump, IndentEmitsPrettyOutput) {
    Config c;
    ASSERT_EQ(c.load_json(R"({"a":1,"b":[1,2]})"), GN_OK);
    /// Compact never has newlines; indent=2 always does on a
    /// non-trivial structure.
    EXPECT_EQ(c.dump(-1).find('\n'), std::string::npos);
    EXPECT_NE(c.dump(2).find('\n'), std::string::npos);
}

TEST(Config_Dump, ReflectsLatestLoadAfterReload) {
    Config c;
    ASSERT_EQ(c.load_json(R"({"marker":"first"})"), GN_OK);
    EXPECT_NE(c.dump().find("first"), std::string::npos);

    ASSERT_EQ(c.load_json(R"({"marker":"second"})"), GN_OK);
    EXPECT_EQ(c.dump().find("first"), std::string::npos);
    EXPECT_NE(c.dump().find("second"), std::string::npos);
}

// ── JSON5-style comments ─────────────────────────────────────────────────

TEST(Config_LoadJson, AcceptsLineComments) {
    /// Operators annotate config files routinely; a strict parser
    /// turns the convenience into hostility. Both `//` and `/* */`
    /// styles are stripped at parse-time.
    Config c;
    const char* doc = R"(
        {
            // top-level annotation
            "limits": {
                "max_connections": 4096   // matches default explicitly
            }
        }
    )";
    EXPECT_EQ(c.load_json(doc), GN_OK);
    EXPECT_EQ(c.limits().max_connections, 4096u);
}

TEST(Config_LoadJson, AcceptsBlockComments) {
    Config c;
    const char* doc = R"(
        {
            /* multi-line
               annotation */
            "marker": "ok"
        }
    )";
    ASSERT_EQ(c.load_json(doc), GN_OK);
    std::string s;
    EXPECT_EQ(c.get_string("marker", s), GN_OK);
    EXPECT_EQ(s, "ok");
}

// ── load_file ────────────────────────────────────────────────────────────

TEST(Config_LoadFile, ReadsExistingFile) {
    /// Write a temp file with a known config; load it through the
    /// convenience entry; verify limits round-trip from disk to
    /// the parsed `gn_limits_t`.
    namespace fs = std::filesystem;
    const auto path = fs::temp_directory_path() / "gn_config_load_file.json";
    {
        std::ofstream out(path);
        out << R"({
            "limits": {
                "max_connections": 8192,
                "max_outbound_connections": 1024
            }
        })";
    }

    Config c;
    EXPECT_EQ(c.load_file(path.string()), GN_OK);
    EXPECT_EQ(c.limits().max_connections, 8192u);
    fs::remove(path);
}

TEST(Config_LoadFile, MissingFileReportsNotFound) {
    Config c;
    EXPECT_EQ(c.load_file("/nonexistent/missing-config.json"),
              GN_ERR_NOT_FOUND);
}

TEST(Config_LoadFile, MalformedFilePreservesPriorState) {
    /// Same atomicity guarantee as `load_json`: a malformed file
    /// leaves the previous good state intact.
    namespace fs = std::filesystem;

    Config c;
    ASSERT_EQ(c.load_json(R"({"marker": "first"})"), GN_OK);

    const auto path = fs::temp_directory_path() / "gn_config_bad.json";
    {
        std::ofstream out(path);
        out << "{not json";
    }

    EXPECT_EQ(c.load_file(path.string()), GN_ERR_INVALID_ENVELOPE);
    std::string s;
    EXPECT_EQ(c.get_string("marker", s), GN_OK);
    EXPECT_EQ(s, "first");
    fs::remove(path);
}

}  // namespace
}  // namespace gn::core
