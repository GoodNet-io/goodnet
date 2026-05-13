/// @file   tests/unit/plugin/test_wire_codec_fuzz.cpp
/// @brief  Property-based fuzz over the CBOR subset implemented in
///         `core/plugin/wire_codec.{hpp,cpp}`.
///
/// Two invariant families:
///   1. Random byte sequences MUST NOT crash any decoder. Malformed
///      input either returns `GN_ERR_OUT_OF_RANGE` or consumes some
///      prefix and stops — never UB.
///   2. Encoded values round-trip cleanly back through the matching
///      decoder for every shape we encode in production (u64 / i64
///      / bytes / text / array header / map header / bool / null).
///
/// The first family is the safety guarantee that wire-fed CBOR from
/// an untrusted remote worker (subprocess plugin host) can't take
/// the kernel down. rapidcheck supplies the inputs; the test asserts
/// "no signal raised, decoder returns one of the documented codes".

#include <cstdint>
#include <limits>
#include <span>
#include <string>
#include <vector>

#include <gtest/gtest.h>
#include <rapidcheck/gtest.h>

#include <core/plugin/wire_codec.hpp>

using gn::core::wire::Reader;
namespace wire = gn::core::wire;

namespace {

Reader make_reader(const std::vector<std::uint8_t>& buf) {
    return Reader{std::span<const std::uint8_t>(buf.data(), buf.size()), 0};
}

}  // namespace

// ── Family 1: random bytes never crash any decoder ─────────────────

RC_GTEST_PROP(WireCodecFuzz, DecodeU64NeverCrashes,
              (const std::vector<std::uint8_t>& bytes)) {
    auto r = make_reader(bytes);
    std::uint64_t v = 0;
    const auto rc = wire::decode_u64(r, v);
    RC_ASSERT(rc == GN_OK || rc == GN_ERR_OUT_OF_RANGE);
}

RC_GTEST_PROP(WireCodecFuzz, DecodeI64NeverCrashes,
              (const std::vector<std::uint8_t>& bytes)) {
    auto r = make_reader(bytes);
    std::int64_t v = 0;
    const auto rc = wire::decode_i64(r, v);
    RC_ASSERT(rc == GN_OK || rc == GN_ERR_OUT_OF_RANGE);
}

RC_GTEST_PROP(WireCodecFuzz, DecodeBytesNeverCrashes,
              (const std::vector<std::uint8_t>& bytes)) {
    auto r = make_reader(bytes);
    std::span<const std::uint8_t> out;
    const auto rc = wire::decode_bytes(r, out);
    RC_ASSERT(rc == GN_OK || rc == GN_ERR_OUT_OF_RANGE);
    if (rc == GN_OK) {
        RC_ASSERT(out.size() <= bytes.size());
    }
}

RC_GTEST_PROP(WireCodecFuzz, DecodeTextNeverCrashes,
              (const std::vector<std::uint8_t>& bytes)) {
    auto r = make_reader(bytes);
    std::string_view out;
    const auto rc = wire::decode_text(r, out);
    RC_ASSERT(rc == GN_OK || rc == GN_ERR_OUT_OF_RANGE);
    if (rc == GN_OK) {
        RC_ASSERT(out.size() <= bytes.size());
    }
}

RC_GTEST_PROP(WireCodecFuzz, DecodeArrayHeaderNeverCrashes,
              (const std::vector<std::uint8_t>& bytes)) {
    auto r = make_reader(bytes);
    std::size_t n = 0;
    const auto rc = wire::decode_array_header(r, n);
    RC_ASSERT(rc == GN_OK || rc == GN_ERR_OUT_OF_RANGE);
}

RC_GTEST_PROP(WireCodecFuzz, DecodeMapHeaderNeverCrashes,
              (const std::vector<std::uint8_t>& bytes)) {
    auto r = make_reader(bytes);
    std::size_t n = 0;
    const auto rc = wire::decode_map_header(r, n);
    RC_ASSERT(rc == GN_OK || rc == GN_ERR_OUT_OF_RANGE);
}

RC_GTEST_PROP(WireCodecFuzz, DecodeBoolNeverCrashes,
              (const std::vector<std::uint8_t>& bytes)) {
    auto r = make_reader(bytes);
    bool v = false;
    const auto rc = wire::decode_bool(r, v);
    RC_ASSERT(rc == GN_OK || rc == GN_ERR_OUT_OF_RANGE);
}

RC_GTEST_PROP(WireCodecFuzz, DecodeNullNeverCrashes,
              (const std::vector<std::uint8_t>& bytes)) {
    auto r = make_reader(bytes);
    const auto rc = wire::decode_null(r);
    RC_ASSERT(rc == GN_OK || rc == GN_ERR_OUT_OF_RANGE);
}

RC_GTEST_PROP(WireCodecFuzz, PeekMajorNeverCrashes,
              (const std::vector<std::uint8_t>& bytes)) {
    auto r = make_reader(bytes);
    std::uint8_t major = 0xFF;
    const auto rc = wire::peek_major_type(r, major);
    RC_ASSERT(rc == GN_OK || rc == GN_ERR_OUT_OF_RANGE);
    if (rc == GN_OK) {
        RC_ASSERT(major <= 7);
    }
}

// ── Family 2: encode → decode round-trips ──────────────────────────

RC_GTEST_PROP(WireCodecFuzz, U64RoundTrip, (std::uint64_t v)) {
    std::vector<std::uint8_t> buf;
    wire::encode_u64(buf, v);
    auto r = make_reader(buf);
    std::uint64_t got = 0;
    RC_ASSERT(wire::decode_u64(r, got) == GN_OK);
    RC_ASSERT(got == v);
}

RC_GTEST_PROP(WireCodecFuzz, I64RoundTrip, (std::int64_t v)) {
    std::vector<std::uint8_t> buf;
    wire::encode_i64(buf, v);
    auto r = make_reader(buf);
    std::int64_t got = 0;
    RC_ASSERT(wire::decode_i64(r, got) == GN_OK);
    RC_ASSERT(got == v);
}

RC_GTEST_PROP(WireCodecFuzz, BytesRoundTrip,
              (const std::vector<std::uint8_t>& payload)) {
    std::vector<std::uint8_t> buf;
    wire::encode_bytes(buf, std::span<const std::uint8_t>(
        payload.data(), payload.size()));
    auto r = make_reader(buf);
    std::span<const std::uint8_t> got;
    RC_ASSERT(wire::decode_bytes(r, got) == GN_OK);
    RC_ASSERT(got.size() == payload.size());
    for (std::size_t i = 0; i < payload.size(); ++i) {
        RC_ASSERT(got[i] == payload[i]);
    }
}

RC_GTEST_PROP(WireCodecFuzz, TextRoundTrip, (const std::string& s)) {
    std::vector<std::uint8_t> buf;
    wire::encode_text(buf, s);
    auto r = make_reader(buf);
    std::string_view got;
    RC_ASSERT(wire::decode_text(r, got) == GN_OK);
    RC_ASSERT(got == s);
}

RC_GTEST_PROP(WireCodecFuzz, ArrayHeaderRoundTrip, (std::uint32_t n)) {
    std::vector<std::uint8_t> buf;
    wire::encode_array_header(buf, n);
    auto r = make_reader(buf);
    std::size_t got = 0;
    RC_ASSERT(wire::decode_array_header(r, got) == GN_OK);
    RC_ASSERT(got == n);
}

RC_GTEST_PROP(WireCodecFuzz, MapHeaderRoundTrip, (std::uint32_t n)) {
    std::vector<std::uint8_t> buf;
    wire::encode_map_header(buf, n);
    auto r = make_reader(buf);
    std::size_t got = 0;
    RC_ASSERT(wire::decode_map_header(r, got) == GN_OK);
    RC_ASSERT(got == n);
}

RC_GTEST_PROP(WireCodecFuzz, BoolRoundTrip, (bool v)) {
    std::vector<std::uint8_t> buf;
    wire::encode_bool(buf, v);
    auto r = make_reader(buf);
    bool got = !v;
    RC_ASSERT(wire::decode_bool(r, got) == GN_OK);
    RC_ASSERT(got == v);
}

// ── Family 3: structural — encoded shapes never over-consume ───────

RC_GTEST_PROP(WireCodecFuzz, EncodedSizeAdvancesReader,
              (std::uint64_t v)) {
    std::vector<std::uint8_t> buf;
    wire::encode_u64(buf, v);
    auto r = make_reader(buf);
    std::uint64_t got = 0;
    RC_ASSERT(wire::decode_u64(r, got) == GN_OK);
    RC_ASSERT(r.pos == buf.size());
}

RC_GTEST_PROP(WireCodecFuzz, RandomPrefixDoesntOverflow,
              (const std::vector<std::uint8_t>& bytes,
               std::uint8_t op_tag)) {
    auto r = make_reader(bytes);
    /// Pick a decoder via the op tag; whichever fires must leave
    /// `r.pos <= bytes.size()` on either success or failure. The
    /// return code is intentionally discarded — we exercise the
    /// fail-soft contract, not the success path.
    switch (op_tag & 7u) {
        case 0u: { std::uint64_t v;  (void)wire::decode_u64(r, v); break; }
        case 1u: { std::int64_t  v;  (void)wire::decode_i64(r, v); break; }
        case 2u: {
            std::span<const std::uint8_t> v;
            (void)wire::decode_bytes(r, v);
            break;
        }
        case 3u: {
            std::string_view v;
            (void)wire::decode_text(r, v);
            break;
        }
        case 4u: { std::size_t n; (void)wire::decode_array_header(r, n); break; }
        case 5u: { std::size_t n; (void)wire::decode_map_header(r, n);   break; }
        case 6u: { bool v;        (void)wire::decode_bool(r, v);          break; }
        case 7u: {                (void)wire::decode_null(r);             break; }
        default: break;
    }
    RC_ASSERT(r.pos <= bytes.size());
}
