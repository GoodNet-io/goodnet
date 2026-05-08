/// @file   plugins/protocols/gnet/tests/test_wire.cpp
/// @brief  Deterministic GoogleTest cases for the GNET v1 wire layer.
///
/// Pins the byte-level behaviour from `plugins/protocols/gnet/docs/wire-format.md`:
///   §2.1  fixed 14-byte header at the documented offsets,
///   §2.2  conditional pk fields gated by `EXPLICIT_*` flags,
///   §2.3  reserved bits and BROADCAST/EXPLICIT_RECEIVER conflict rules,
///   §3    the three encoding modes (direct / broadcast / relay-transit),
///   §4    parser-state-machine error codes
///         (`GN_ERR_DEFRAME_INCOMPLETE`, `GN_ERR_DEFRAME_CORRUPT`).
///
/// Property-style invariants over the encode/decode round-trip live next
/// to this file in `test_wire_property.cpp`.

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <span>
#include <vector>

#include <plugins/protocols/gnet/wire.hpp>
#include <sdk/types.h>

namespace gn::plugins::gnet::wire {
namespace {

/* ── Constants ───────────────────────────────────────────────────────────── */

TEST(GnetWireConstants, MagicSpellsGNET) {
    EXPECT_EQ(kMagic[0], static_cast<std::uint8_t>('G'));
    EXPECT_EQ(kMagic[1], static_cast<std::uint8_t>('N'));
    EXPECT_EQ(kMagic[2], static_cast<std::uint8_t>('E'));
    EXPECT_EQ(kMagic[3], static_cast<std::uint8_t>('T'));
    EXPECT_EQ(kMagic[0], 0x47);
    EXPECT_EQ(kMagic[1], 0x4E);
    EXPECT_EQ(kMagic[2], 0x45);
    EXPECT_EQ(kMagic[3], 0x54);
}

TEST(GnetWireConstants, VersionIsOne) {
    EXPECT_EQ(kVersion, 0x01);
}

TEST(GnetWireConstants, FixedHeaderSizeIs14) {
    EXPECT_EQ(kFixedHeaderSize, 14u);
}

TEST(GnetWireConstants, PublicKeySizeIs32) {
    EXPECT_EQ(kPublicKeySize, 32u);
}

TEST(GnetWireConstants, FieldOffsetsMatchContract) {
    EXPECT_EQ(kOffsetMagic,   0u);
    EXPECT_EQ(kOffsetVersion, 4u);
    EXPECT_EQ(kOffsetFlags,   5u);
    EXPECT_EQ(kOffsetMsgId,   6u);
    EXPECT_EQ(kOffsetLength, 10u);
}

TEST(GnetWireConstants, ReservedBitsCoverHighFive) {
    /// Bits 3..7 (0xF8) are MUST-be-zero in v1; bits 0..2 are the live flags.
    EXPECT_EQ(kReservedBitsMask, 0xF8);
    EXPECT_EQ(kFlagExplicitSender   | kFlagExplicitReceiver | kFlagBroadcast,
              static_cast<std::uint8_t>(~kReservedBitsMask));
}

/* ── conditional_pk_size ─────────────────────────────────────────────────── */

TEST(GnetWireConditionalPkSize, NoFlagsZero) {
    EXPECT_EQ(conditional_pk_size(0x00), 0u);
}

TEST(GnetWireConditionalPkSize, ExplicitSenderOnly) {
    EXPECT_EQ(conditional_pk_size(kFlagExplicitSender), 32u);
}

TEST(GnetWireConditionalPkSize, ExplicitReceiverOnly) {
    EXPECT_EQ(conditional_pk_size(kFlagExplicitReceiver), 32u);
}

TEST(GnetWireConditionalPkSize, BothExplicitFlags) {
    const std::uint8_t both = kFlagExplicitSender | kFlagExplicitReceiver;
    EXPECT_EQ(conditional_pk_size(both), 64u);
}

TEST(GnetWireConditionalPkSize, BroadcastFlagAlone) {
    /// `kFlagBroadcast` does NOT contribute to conditional-pk area;
    /// only the two `EXPLICIT_*` bits do.
    EXPECT_EQ(conditional_pk_size(kFlagBroadcast), 0u);
}

/* ── compute_frame_size ──────────────────────────────────────────────────── */

TEST(GnetWireComputeFrameSize, DirectMode) {
    EXPECT_EQ(compute_frame_size(0x00, 0u),     14u);
    EXPECT_EQ(compute_frame_size(0x00, 100u),  114u);
}

TEST(GnetWireComputeFrameSize, BroadcastMode) {
    /// 14 header + 32 sender_pk + payload — broadcast flag does NOT
    /// add to conditional area but EXPLICIT_SENDER does.
    const std::uint8_t flags = kFlagExplicitSender | kFlagBroadcast;
    EXPECT_EQ(compute_frame_size(flags, 0u),    46u);
    EXPECT_EQ(compute_frame_size(flags, 200u), 246u);
}

TEST(GnetWireComputeFrameSize, RelayTransitMode) {
    /// 14 header + 32 sender_pk + 32 receiver_pk + payload.
    const std::uint8_t flags = kFlagExplicitSender | kFlagExplicitReceiver;
    EXPECT_EQ(compute_frame_size(flags, 0u),     78u);
    EXPECT_EQ(compute_frame_size(flags, 100u),  178u);
}

/* ── encode_header / parse_header round-trip ─────────────────────────────── */

TEST(GnetWireEncodeHeader, WritesFieldsAtCorrectOffsets) {
    std::array<std::uint8_t, kFixedHeaderSize> buf{};
    constexpr std::uint32_t msg_id = 0x12345678;
    constexpr std::uint32_t length = 0x000000A0;
    constexpr std::uint8_t  flags  = 0x05;

    encode_header(buf, flags, msg_id, length);

    /// Magic at offset 0..3.
    EXPECT_EQ(buf[0], 0x47);
    EXPECT_EQ(buf[1], 0x4E);
    EXPECT_EQ(buf[2], 0x45);
    EXPECT_EQ(buf[3], 0x54);

    /// Version at offset 4.
    EXPECT_EQ(buf[4], kVersion);

    /// Flags at offset 5.
    EXPECT_EQ(buf[5], flags);

    /// msg_id big-endian at offset 6..9.
    EXPECT_EQ(buf[6], 0x12);
    EXPECT_EQ(buf[7], 0x34);
    EXPECT_EQ(buf[8], 0x56);
    EXPECT_EQ(buf[9], 0x78);

    /// length big-endian at offset 10..13.
    EXPECT_EQ(buf[10], 0x00);
    EXPECT_EQ(buf[11], 0x00);
    EXPECT_EQ(buf[12], 0x00);
    EXPECT_EQ(buf[13], 0xA0);
}

TEST(GnetWireRoundTrip, DirectModeFlagsZero) {
    std::array<std::uint8_t, kFixedHeaderSize> buf{};
    const std::uint32_t msg_id = 42;
    const std::uint32_t length = kFixedHeaderSize + 10;  // 14 hdr + 10 payload
    encode_header(buf, 0x00, msg_id, length);

    ParsedHeader out{};
    ASSERT_EQ(parse_header(buf, out), GN_OK);
    EXPECT_EQ(out.flags, 0x00);
    EXPECT_EQ(out.msg_id, msg_id);
    EXPECT_EQ(out.total_length, length);
    EXPECT_EQ(out.header_size, kFixedHeaderSize);
    EXPECT_FALSE(out.has_explicit_sender());
    EXPECT_FALSE(out.has_explicit_receiver());
    EXPECT_FALSE(out.is_broadcast());
}

TEST(GnetWireRoundTrip, BroadcastMode) {
    std::array<std::uint8_t, kFixedHeaderSize> buf{};
    const std::uint8_t  flags  = kFlagExplicitSender | kFlagBroadcast;
    const std::uint32_t msg_id = 0xDEADBEEF;
    const std::uint32_t length = static_cast<std::uint32_t>(kFixedHeaderSize + 32 + 5);
    encode_header(buf, flags, msg_id, length);

    ParsedHeader out{};
    ASSERT_EQ(parse_header(buf, out), GN_OK);
    EXPECT_EQ(out.flags, flags);
    EXPECT_EQ(out.msg_id, msg_id);
    EXPECT_EQ(out.total_length, length);
    EXPECT_EQ(out.header_size, kFixedHeaderSize + 32);
    EXPECT_TRUE(out.has_explicit_sender());
    EXPECT_FALSE(out.has_explicit_receiver());
    EXPECT_TRUE(out.is_broadcast());
}

TEST(GnetWireRoundTrip, RelayTransitMode) {
    std::array<std::uint8_t, kFixedHeaderSize> buf{};
    const std::uint8_t  flags  = kFlagExplicitSender | kFlagExplicitReceiver;
    const std::uint32_t msg_id = 1;
    const std::uint32_t length = static_cast<std::uint32_t>(kFixedHeaderSize + 64);  // header + 2 PK + 0 payload
    encode_header(buf, flags, msg_id, length);

    ParsedHeader out{};
    ASSERT_EQ(parse_header(buf, out), GN_OK);
    EXPECT_EQ(out.flags, flags);
    EXPECT_EQ(out.msg_id, msg_id);
    EXPECT_EQ(out.total_length, length);
    EXPECT_EQ(out.header_size, kFixedHeaderSize + 64);
    EXPECT_TRUE(out.has_explicit_sender());
    EXPECT_TRUE(out.has_explicit_receiver());
    EXPECT_FALSE(out.is_broadcast());
}

/* ── parse_header rejection cases ────────────────────────────────────────── */

/// Build a syntactically valid header for `flags`, then return it as a
/// fresh buffer the caller can mutate.
std::array<std::uint8_t, kFixedHeaderSize>
make_valid_header(std::uint8_t flags, std::uint32_t msg_id, std::uint32_t length) {
    std::array<std::uint8_t, kFixedHeaderSize> buf{};
    encode_header(buf, flags, msg_id, length);
    return buf;
}

TEST(GnetWireParseRejection, BadMagicByte0) {
    auto buf = make_valid_header(0, 1, kFixedHeaderSize);
    buf[0] = 0x00;  /// 'G' → 0x00
    ParsedHeader out{};
    EXPECT_EQ(parse_header(buf, out), GN_ERR_DEFRAME_CORRUPT);
}

TEST(GnetWireParseRejection, BadMagicByte3) {
    auto buf = make_valid_header(0, 1, kFixedHeaderSize);
    buf[3] = 0xFF;  /// 'T' → 0xFF
    ParsedHeader out{};
    EXPECT_EQ(parse_header(buf, out), GN_ERR_DEFRAME_CORRUPT);
}

TEST(GnetWireParseRejection, WrongVersion) {
    auto buf = make_valid_header(0, 1, kFixedHeaderSize);
    buf[kOffsetVersion] = 0x02;
    ParsedHeader out{};
    EXPECT_EQ(parse_header(buf, out), GN_ERR_DEFRAME_CORRUPT);
}

TEST(GnetWireParseRejection, ZeroVersion) {
    auto buf = make_valid_header(0, 1, kFixedHeaderSize);
    buf[kOffsetVersion] = 0x00;
    ParsedHeader out{};
    EXPECT_EQ(parse_header(buf, out), GN_ERR_DEFRAME_CORRUPT);
}

TEST(GnetWireForwardCompat, ReservedBit3Masked) {
    /// Reserved bits are forward-compat — v1.1+ flags land in
    /// them. v1 must mask the unknown bit off and continue
    /// parsing rather than drop the connection.
    auto buf = make_valid_header(0, 1, kFixedHeaderSize);
    buf[kOffsetFlags] = 0x08;  /// bit 3 reserved
    ParsedHeader out{};
    EXPECT_EQ(parse_header(buf, out), GN_OK);
    EXPECT_EQ(out.flags & 0x08, 0u)
        << "reserved bit must be masked off in the parsed flags";
}

TEST(GnetWireForwardCompat, ReservedBit7Masked) {
    auto buf = make_valid_header(0, 1, kFixedHeaderSize);
    buf[kOffsetFlags] = 0x80;  /// bit 7 reserved
    ParsedHeader out{};
    EXPECT_EQ(parse_header(buf, out), GN_OK);
    EXPECT_EQ(out.flags & 0x80, 0u);
}

TEST(GnetWireForwardCompat, AnyReservedBitMasked) {
    /// Walk every bit in the reserved-bits mask in isolation;
    /// each must round-trip parse as `GN_OK` with the bit
    /// masked off in `out.flags`.
    for (std::uint8_t bit = 3; bit < 8; ++bit) {
        auto buf = make_valid_header(0, 1, kFixedHeaderSize);
        buf[kOffsetFlags] = static_cast<std::uint8_t>(1u << bit);
        ParsedHeader out{};
        EXPECT_EQ(parse_header(buf, out), GN_OK)
            << "reserved bit " << static_cast<int>(bit)
            << " must parse cleanly (forward-compat)";
        EXPECT_EQ(out.flags & static_cast<std::uint8_t>(1u << bit), 0u)
            << "reserved bit " << static_cast<int>(bit)
            << " must be masked off in `out.flags`";
    }
}

TEST(GnetWireParseRejection, BroadcastWithoutExplicitSender) {
    /// BROADCAST without EXPLICIT_SENDER violates §2.3 and §3.2.
    auto buf = make_valid_header(kFlagBroadcast, 1, kFixedHeaderSize);
    ParsedHeader out{};
    EXPECT_EQ(parse_header(buf, out), GN_ERR_DEFRAME_CORRUPT);
}

TEST(GnetWireParseRejection, BroadcastWithExplicitReceiver) {
    /// BROADCAST with EXPLICIT_RECEIVER is illegal per §2.3 (receiver
    /// is implicit ZERO under broadcast).
    const std::uint8_t flags =
        kFlagExplicitSender | kFlagExplicitReceiver | kFlagBroadcast;
    /// Length must accomodate header + 64 bytes of conditional pk to make
    /// sure this case is rejected on the flag conflict, not on the size check.
    const std::uint32_t length = kFixedHeaderSize + 64;
    auto buf = make_valid_header(flags, 1, length);
    ParsedHeader out{};
    EXPECT_EQ(parse_header(buf, out), GN_ERR_DEFRAME_CORRUPT);
}

TEST(GnetWireParseRejection, LengthSmallerThanHeader) {
    /// Direct mode header_size = 14; declaring length=13 is impossible.
    auto buf = make_valid_header(0, 1, kFixedHeaderSize - 1);
    ParsedHeader out{};
    EXPECT_EQ(parse_header(buf, out), GN_ERR_DEFRAME_CORRUPT);
}

TEST(GnetWireParseRejection, LengthSmallerThanHeaderRelayTransit) {
    /// Relay-transit header_size = 78; declaring length=20 is impossible
    /// even though it covers the fixed 14-byte header.
    const std::uint8_t flags = kFlagExplicitSender | kFlagExplicitReceiver;
    auto buf = make_valid_header(flags, 1, 20);
    ParsedHeader out{};
    EXPECT_EQ(parse_header(buf, out), GN_ERR_DEFRAME_CORRUPT);
}

TEST(GnetWireParseRejection, LengthExceedsMaxFrameBytes) {
    /// Frame length past the v1 wire ceiling is a hostile-peer
    /// signal — distinct from generic corruption so the operator
    /// metric (`drop.frame_too_large`) names the suspicion.
    auto buf = make_valid_header(0, 1, static_cast<std::uint32_t>(kMaxFrameBytes + 1));
    ParsedHeader out{};
    EXPECT_EQ(parse_header(buf, out), GN_ERR_FRAME_TOO_LARGE);
}

TEST(GnetWireParseRejection, LengthAtMaxFrameBytesAccepted) {
    /// Exactly `kMaxFrameBytes` is the largest legal value.
    auto buf = make_valid_header(0, 1, static_cast<std::uint32_t>(kMaxFrameBytes));
    ParsedHeader out{};
    EXPECT_EQ(parse_header(buf, out), GN_OK);
    EXPECT_EQ(out.total_length, kMaxFrameBytes);
}

TEST(GnetWireParseIncomplete, EmptyBuffer) {
    std::span<const std::uint8_t> empty;
    ParsedHeader out{};
    EXPECT_EQ(parse_header(empty, out), GN_ERR_DEFRAME_INCOMPLETE);
}

TEST(GnetWireParseIncomplete, ShorterThanFixedHeader) {
    auto full = make_valid_header(0, 1, kFixedHeaderSize);
    for (std::size_t n = 0; n < kFixedHeaderSize; ++n) {
        std::span<const std::uint8_t> partial(full.data(), n);
        ParsedHeader out{};
        EXPECT_EQ(parse_header(partial, out), GN_ERR_DEFRAME_INCOMPLETE)
            << "n=" << n;
    }
}

TEST(GnetWireParseIncomplete, ExactlyFourteenBytesAccepted) {
    /// Boundary: exactly the fixed-header size is enough to parse.
    auto buf = make_valid_header(0, 1, kFixedHeaderSize);
    ParsedHeader out{};
    EXPECT_EQ(parse_header(buf, out), GN_OK);
}

}  // namespace
}  // namespace gn::plugins::gnet::wire
