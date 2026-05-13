/// @file   tests/unit/plugin/test_wire_codec.cpp
/// @brief  Round-trip the CBOR subset implemented in
///         `core/plugin/wire_codec.cpp` against every boundary the
///         encoder switches initial-byte width on.

#include <cstdint>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <gtest/gtest.h>

#include <core/plugin/wire_codec.hpp>

using gn::core::wire::Reader;
namespace wire = gn::core::wire;

namespace {

Reader make_reader(const std::vector<std::uint8_t>& buf) {
    return Reader{std::span<const std::uint8_t>(buf.data(), buf.size()), 0};
}

}  // namespace

TEST(WireCodecU64, ImmediateRange) {
    for (std::uint64_t v : {0ULL, 1ULL, 22ULL, 23ULL}) {
        std::vector<std::uint8_t> buf;
        wire::encode_u64(buf, v);
        ASSERT_EQ(buf.size(), 1u) << "value " << v << " must fit in one byte";
        auto r = make_reader(buf);
        std::uint64_t got = 0;
        ASSERT_EQ(wire::decode_u64(r, got), GN_OK);
        EXPECT_EQ(got, v);
        EXPECT_EQ(r.pos, buf.size());
    }
}

TEST(WireCodecU64, WidthBoundaries) {
    const std::uint64_t cases[] = {
        24, 255,
        256, 65535,
        65536, 4294967295ULL,
        4294967296ULL, std::numeric_limits<std::uint64_t>::max(),
    };
    const std::size_t expected_size[] = {2, 2, 3, 3, 5, 5, 9, 9};
    std::size_t idx = 0;
    for (std::uint64_t v : cases) {
        std::vector<std::uint8_t> buf;
        wire::encode_u64(buf, v);
        EXPECT_EQ(buf.size(), expected_size[idx])
            << "value " << v << " encoded width";
        auto r = make_reader(buf);
        std::uint64_t got = 0;
        ASSERT_EQ(wire::decode_u64(r, got), GN_OK) << "value " << v;
        EXPECT_EQ(got, v);
        EXPECT_EQ(r.pos, buf.size());
        ++idx;
    }
}

TEST(WireCodecI64, NegativeRoundTrip) {
    const std::int64_t cases[] = {
        -1, -24, -25, -100,
        -255, -256, -65535, -65536,
        std::numeric_limits<std::int64_t>::min() + 1,
        std::numeric_limits<std::int64_t>::min(),
    };
    for (std::int64_t v : cases) {
        std::vector<std::uint8_t> buf;
        wire::encode_i64(buf, v);
        auto r = make_reader(buf);
        std::int64_t got = 0;
        ASSERT_EQ(wire::decode_i64(r, got), GN_OK) << "value " << v;
        EXPECT_EQ(got, v);
        EXPECT_EQ(r.pos, buf.size());
    }
}

TEST(WireCodecI64, PositiveRoundTripThroughDecodeI64) {
    const std::int64_t positives[] = {
        0, 1, 23, 24, 1000,
        std::numeric_limits<std::int64_t>::max(),
    };
    for (std::int64_t v : positives) {
        std::vector<std::uint8_t> buf;
        wire::encode_i64(buf, v);
        auto r = make_reader(buf);
        std::int64_t got = 0;
        ASSERT_EQ(wire::decode_i64(r, got), GN_OK) << "value " << v;
        EXPECT_EQ(got, v);
    }
}

TEST(WireCodecBytes, EmptyAndShortAndLong) {
    for (std::size_t len : std::initializer_list<std::size_t>{
             0, 1, 23, 24, 255, 256, 65535, 65536, 100000}) {
        std::vector<std::uint8_t> payload(len, 0);
        for (std::size_t i = 0; i < len; ++i) {
            payload[i] = static_cast<std::uint8_t>((i * 31 + 7) & 0xFF);
        }
        std::vector<std::uint8_t> buf;
        wire::encode_bytes(buf,
            std::span<const std::uint8_t>(payload.data(), payload.size()));
        auto r = make_reader(buf);
        std::span<const std::uint8_t> got{};
        ASSERT_EQ(wire::decode_bytes(r, got), GN_OK) << "len " << len;
        ASSERT_EQ(got.size(), len);
        for (std::size_t i = 0; i < len; ++i) {
            EXPECT_EQ(got[i], payload[i]) << "byte " << i << " of len " << len;
        }
        EXPECT_EQ(r.pos, buf.size());
    }
}

TEST(WireCodecText, AsciiAndUtf8) {
    const std::vector<std::string_view> cases = {
        "", "x", "hello",
        "twenty-three characters", "twenty-four characters!",
        "А вот и кириллица",          // multi-byte UTF-8
        std::string_view("\x00\x01\x02 mixed", 9)};
    for (auto v : cases) {
        std::vector<std::uint8_t> buf;
        wire::encode_text(buf, v);
        auto r = make_reader(buf);
        std::string_view got{};
        ASSERT_EQ(wire::decode_text(r, got), GN_OK) << "value '" << v << "'";
        EXPECT_EQ(got, v);
    }
}

TEST(WireCodecArray, HeaderRoundTrip) {
    for (std::size_t n : std::initializer_list<std::size_t>{
             0, 1, 23, 24, 255, 65536}) {
        std::vector<std::uint8_t> buf;
        wire::encode_array_header(buf, n);
        auto r = make_reader(buf);
        std::size_t got = 0;
        ASSERT_EQ(wire::decode_array_header(r, got), GN_OK);
        EXPECT_EQ(got, n);
    }
}

TEST(WireCodecMap, MixedKeyTypes) {
    std::vector<std::uint8_t> buf;
    wire::encode_map_header(buf, 3);
    wire::encode_text(buf, "code");
    wire::encode_i64(buf, -14);
    wire::encode_text(buf, "name");
    wire::encode_text(buf, "remote_echo");
    wire::encode_u64(buf, 42);
    wire::encode_bool(buf, true);

    auto r = make_reader(buf);
    std::size_t n = 0;
    ASSERT_EQ(wire::decode_map_header(r, n), GN_OK);
    ASSERT_EQ(n, 3u);

    std::string_view key{};
    std::int64_t code = 0;
    ASSERT_EQ(wire::decode_text(r, key), GN_OK);
    EXPECT_EQ(key, "code");
    ASSERT_EQ(wire::decode_i64(r, code), GN_OK);
    EXPECT_EQ(code, -14);

    std::string_view name{};
    ASSERT_EQ(wire::decode_text(r, key), GN_OK);
    EXPECT_EQ(key, "name");
    ASSERT_EQ(wire::decode_text(r, name), GN_OK);
    EXPECT_EQ(name, "remote_echo");

    std::uint64_t num_key = 0;
    bool flag = false;
    ASSERT_EQ(wire::decode_u64(r, num_key), GN_OK);
    EXPECT_EQ(num_key, 42u);
    ASSERT_EQ(wire::decode_bool(r, flag), GN_OK);
    EXPECT_TRUE(flag);

    EXPECT_EQ(r.pos, buf.size());
}

TEST(WireCodecSimple, BoolAndNull) {
    std::vector<std::uint8_t> buf;
    wire::encode_bool(buf, true);
    wire::encode_bool(buf, false);
    wire::encode_null(buf);
    auto r = make_reader(buf);
    bool b = false;
    ASSERT_EQ(wire::decode_bool(r, b), GN_OK); EXPECT_TRUE(b);
    ASSERT_EQ(wire::decode_bool(r, b), GN_OK); EXPECT_FALSE(b);
    ASSERT_EQ(wire::decode_null(r), GN_OK);
    EXPECT_EQ(r.pos, buf.size());
}

TEST(WireCodecPeek, MajorType) {
    std::vector<std::uint8_t> buf;
    wire::encode_u64(buf, 5);
    wire::encode_text(buf, "x");
    auto r = make_reader(buf);
    std::uint8_t major = 0xFF;
    ASSERT_EQ(wire::peek_major_type(r, major), GN_OK);
    EXPECT_EQ(major, 0u);  // major 0 = unsigned int
    std::uint64_t got = 0;
    ASSERT_EQ(wire::decode_u64(r, got), GN_OK);
    ASSERT_EQ(wire::peek_major_type(r, major), GN_OK);
    EXPECT_EQ(major, 3u);  // major 3 = text string
}

TEST(WireCodecDecodeErrors, EmptyBufferIsRange) {
    std::vector<std::uint8_t> empty;
    auto r = make_reader(empty);
    std::uint64_t v = 0;
    EXPECT_EQ(wire::decode_u64(r, v), GN_ERR_OUT_OF_RANGE);
}

TEST(WireCodecDecodeErrors, MajorMismatch) {
    std::vector<std::uint8_t> buf;
    wire::encode_text(buf, "not a number");
    auto r = make_reader(buf);
    std::uint64_t v = 0;
    EXPECT_EQ(wire::decode_u64(r, v), GN_ERR_OUT_OF_RANGE);
}

TEST(WireCodecDecodeErrors, TruncatedBytestring) {
    // Build a bytestring header claiming 10 bytes but only supply 3.
    std::vector<std::uint8_t> buf = {0x4A /* major 2, 10 bytes */,
                                      0x01, 0x02, 0x03};
    auto r = make_reader(buf);
    std::span<const std::uint8_t> got{};
    EXPECT_EQ(wire::decode_bytes(r, got), GN_ERR_OUT_OF_RANGE);
}
