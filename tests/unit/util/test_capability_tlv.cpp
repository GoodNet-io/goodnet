/// @file   tests/unit/util/test_capability_tlv.cpp
/// @brief  TLV encode / parse round-trip per `capability-tlv.md`.

#include <gtest/gtest.h>

#include <sdk/cpp/capability_tlv.hpp>

#include <cstdint>
#include <vector>

using gn::sdk::TlvError;
using gn::sdk::TlvRecord;
using gn::sdk::encode_tlv;
using gn::sdk::parse_tlv;

TEST(CapabilityTlv, EmptyBlobParsesToEmptyVector) {
    auto out = parse_tlv({});
    ASSERT_TRUE(out.has_value());
    EXPECT_TRUE(out->empty());
}

TEST(CapabilityTlv, EmptyRecordsEncodeToEmptyBlob) {
    std::vector<TlvRecord> records;
    auto out = encode_tlv(records);
    ASSERT_TRUE(out.has_value());
    EXPECT_TRUE(out->empty());
}

TEST(CapabilityTlv, SingleRecordRoundTrip) {
    std::vector<TlvRecord> records;
    records.push_back({0x0100, {0xde, 0xad, 0xbe, 0xef}});

    auto encoded = encode_tlv(records);
    ASSERT_TRUE(encoded.has_value());
    if (encoded.has_value()) {
        const auto& blob = *encoded;
        ASSERT_EQ(blob.size(), 4u + 4u);
        /// type 0x0100 big-endian, length 0x0004 big-endian, value bytes.
        EXPECT_EQ(blob[0], 0x01);
        EXPECT_EQ(blob[1], 0x00);
        EXPECT_EQ(blob[2], 0x00);
        EXPECT_EQ(blob[3], 0x04);

        auto parsed = parse_tlv(blob);
        ASSERT_TRUE(parsed.has_value());
        if (parsed.has_value()) {
            ASSERT_EQ(parsed->size(), 1u);
            EXPECT_EQ((*parsed)[0].type, 0x0100u);
            EXPECT_EQ((*parsed)[0].value, records[0].value);
        }
    }
}

TEST(CapabilityTlv, MultipleRecordsPreserveOrder) {
    std::vector<TlvRecord> records;
    records.push_back({0x0001, {0xaa}});
    records.push_back({0x0002, {0xbb, 0xcc}});
    records.push_back({0x0003, {}});  /// empty value
    records.push_back({0xffff, {0x11, 0x22, 0x33}});

    auto encoded = encode_tlv(records);
    ASSERT_TRUE(encoded.has_value());
    if (encoded.has_value()) {
        auto parsed = parse_tlv(*encoded);
        ASSERT_TRUE(parsed.has_value());
        if (parsed.has_value()) {
            ASSERT_EQ(parsed->size(), 4u);
            EXPECT_EQ((*parsed)[0].type, 0x0001u);
            EXPECT_EQ((*parsed)[1].type, 0x0002u);
            EXPECT_EQ((*parsed)[2].type, 0x0003u);
            EXPECT_TRUE((*parsed)[2].value.empty());
            EXPECT_EQ((*parsed)[3].type, 0xffffu);
            EXPECT_EQ((*parsed)[3].value.size(), 3u);
        }
    }
}

TEST(CapabilityTlv, EncodeRejectsOversizedValue) {
    std::vector<TlvRecord> records;
    records.push_back({0x1000, std::vector<std::uint8_t>(0x10000)});

    auto out = encode_tlv(records);
    ASSERT_FALSE(out.has_value());
    EXPECT_EQ(out.error().kind, TlvError::Kind::ValueTooLarge);
}

TEST(CapabilityTlv, ParseRejectsTruncatedHeader) {
    /// Three bytes — not enough for a 4-byte header.
    std::vector<std::uint8_t> blob{0x00, 0x01, 0x00};
    auto out = parse_tlv(blob);
    ASSERT_FALSE(out.has_value());
    EXPECT_EQ(out.error().kind, TlvError::Kind::Truncated);
    EXPECT_EQ(out.error().offset, 0u);
}

TEST(CapabilityTlv, ParseRejectsTruncatedValue) {
    /// Header says length=10 but only 4 bytes follow.
    std::vector<std::uint8_t> blob{
        0x00, 0x01, 0x00, 0x0a, 0xaa, 0xbb, 0xcc, 0xdd};
    auto out = parse_tlv(blob);
    ASSERT_FALSE(out.has_value());
    EXPECT_EQ(out.error().kind, TlvError::Kind::Truncated);
    EXPECT_EQ(out.error().offset, 0u);
}

TEST(CapabilityTlv, UnknownTypeIsAccepted) {
    /// An unknown type with a known length parses successfully —
    /// peer compatibility comes from receivers tolerating unknowns.
    std::vector<TlvRecord> records;
    records.push_back({/*reserved-experimental*/ 0x8042, {0x01, 0x02}});
    auto encoded = encode_tlv(records);
    ASSERT_TRUE(encoded.has_value());
    if (encoded.has_value()) {
        auto parsed = parse_tlv(*encoded);
        ASSERT_TRUE(parsed.has_value());
        if (parsed.has_value()) {
            ASSERT_EQ(parsed->size(), 1u);
            EXPECT_EQ((*parsed)[0].type, 0x8042u);
        }
    }
}
