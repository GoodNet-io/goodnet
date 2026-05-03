/// @file   tests/unit/protocols/gnet/test_wire_property.cpp
/// @brief  RapidCheck property tests for the GNET v1 wire layer.
///
/// Quantifies the encode/decode contract from
/// `docs/contracts/gnet-protocol.md`:
///
///   ∀ legal `(flags, msg_id, payload_size)`:
///       parse_header(encode_header(...)) === input              (round-trip)
///
///   ∀ buffer ≥ 14 bytes that begins with a syntactically legal header:
///       parse_header succeeds                                    (acceptance)
///
///   ∀ buffer that starts with a mutated `magic` byte:
///       parse_header → GN_ERR_DEFRAME_CORRUPT                    (rejection)
///
///   ∀ version != 0x01:
///       parse_header → GN_ERR_DEFRAME_CORRUPT                    (version)
///
/// These complement the deterministic cases in `test_wire.cpp`.

#include <gtest/gtest.h>
#include <rapidcheck/gtest.h>

#include <array>
#include <cstdint>
#include <vector>

#include <plugins/protocols/gnet/wire.hpp>
#include <sdk/types.h>

namespace gn::plugins::gnet::wire {
namespace {

/* ── Generators ──────────────────────────────────────────────────────────── */

/// Generate one of the four legal v1 flag combinations:
///   0x00              direct
///   EXPLICIT_SENDER
///   EXPLICIT_RECEIVER
///   EXPLICIT_SENDER | EXPLICIT_RECEIVER       (relay-transit)
///   EXPLICIT_SENDER | BROADCAST               (broadcast)
///
/// The `EXPLICIT_RECEIVER` only case is a legal flag combination on its
/// own — the contract only forbids broadcast+receiver and broadcast
/// without sender, so we keep it in the set.
rc::Gen<std::uint8_t> legal_flags_gen() {
    return rc::gen::element<std::uint8_t>(
        0x00,
        kFlagExplicitSender,
        kFlagExplicitReceiver,
        static_cast<std::uint8_t>(kFlagExplicitSender | kFlagExplicitReceiver),
        static_cast<std::uint8_t>(kFlagExplicitSender | kFlagBroadcast));
}

/// Generate a payload size that, given `flags`, keeps the total frame
/// size within `kMaxFrameBytes`.
rc::Gen<std::size_t> payload_size_gen(std::uint8_t flags) {
    const std::size_t cap =
        kMaxFrameBytes - kFixedHeaderSize - conditional_pk_size(flags);
    return rc::gen::inRange<std::size_t>(0, cap + 1);
}

/* ── Round-trip property ─────────────────────────────────────────────────── */

RC_GTEST_PROP(GnetWireProperty,
              EncodeParseRoundTrip,
              ()) {
    const std::uint8_t  flags        = *legal_flags_gen();
    const std::uint32_t msg_id       = *rc::gen::arbitrary<std::uint32_t>();
    const std::size_t   payload_size = *payload_size_gen(flags);
    const std::uint32_t length =
        static_cast<std::uint32_t>(compute_frame_size(flags, payload_size));

    std::array<std::uint8_t, kFixedHeaderSize> buf{};
    encode_header(buf, flags, msg_id, length);

    ParsedHeader out{};
    RC_ASSERT(parse_header(buf, out) == GN_OK);
    RC_ASSERT(out.flags        == flags);
    RC_ASSERT(out.msg_id       == msg_id);
    RC_ASSERT(out.total_length == length);
    RC_ASSERT(out.header_size  == kFixedHeaderSize + conditional_pk_size(flags));
}

/* ── Acceptance: any prefix-correct ≥14-byte buffer parses ───────────────── */

RC_GTEST_PROP(GnetWireProperty,
              ValidPrefixedBufferParses,
              ()) {
    const std::uint8_t  flags        = *legal_flags_gen();
    const std::uint32_t msg_id       = *rc::gen::arbitrary<std::uint32_t>();
    const std::size_t   payload_size = *payload_size_gen(flags);
    const std::uint32_t length =
        static_cast<std::uint32_t>(compute_frame_size(flags, payload_size));

    /// Build a buffer of `length` bytes; only the first 14 are header-
    /// shaped, the rest is garbage from the generator. parse_header is
    /// only required to look at the header.
    std::vector<std::uint8_t> buf(length, 0);
    encode_header(std::span<std::uint8_t>{buf.data(), kFixedHeaderSize},
                  flags, msg_id, length);

    /// Fill the rest with arbitrary content — must not affect header parse.
    if (length > kFixedHeaderSize) {
        const auto tail = *rc::gen::container<std::vector<std::uint8_t>>(
            length - kFixedHeaderSize, rc::gen::arbitrary<std::uint8_t>());
        for (std::size_t i = 0; i < tail.size(); ++i) {
            buf[kFixedHeaderSize + i] = tail[i];
        }
    }

    ParsedHeader out{};
    RC_ASSERT(parse_header(buf, out) == GN_OK);
    RC_ASSERT(out.flags        == flags);
    RC_ASSERT(out.msg_id       == msg_id);
    RC_ASSERT(out.total_length == length);
}

/* ── Rejection: magic mutation ───────────────────────────────────────────── */

RC_GTEST_PROP(GnetWireProperty,
              MagicMutationRejected,
              ()) {
    const std::size_t   pos      = *rc::gen::inRange<std::size_t>(0, kMagic.size());
    /// Pick a byte value that is NOT the original magic byte at `pos`.
    const std::uint8_t  mutation = *rc::gen::distinctFrom(kMagic[pos]);

    std::array<std::uint8_t, kFixedHeaderSize> buf{};
    encode_header(buf, /*flags=*/0x00, /*msg_id=*/1,
                  /*total_length=*/static_cast<std::uint32_t>(kFixedHeaderSize));
    buf[pos] = mutation;

    ParsedHeader out{};
    RC_ASSERT(parse_header(buf, out) == GN_ERR_DEFRAME_CORRUPT);
}

/* ── Rejection: any version != 0x01 ──────────────────────────────────────── */

RC_GTEST_PROP(GnetWireProperty,
              WrongVersionRejected,
              ()) {
    const std::uint8_t bad_ver = *rc::gen::distinctFrom(kVersion);

    std::array<std::uint8_t, kFixedHeaderSize> buf{};
    encode_header(buf, /*flags=*/0x00, /*msg_id=*/1,
                  /*total_length=*/static_cast<std::uint32_t>(kFixedHeaderSize));
    buf[kOffsetVersion] = bad_ver;

    ParsedHeader out{};
    RC_ASSERT(parse_header(buf, out) == GN_ERR_DEFRAME_CORRUPT);
}

/* ── Forward-compat: any reserved bit set is masked, not rejected ─────── */

RC_GTEST_PROP(GnetWireProperty,
              ReservedBitSetMasked,
              ()) {
    /// Pick a non-zero pattern that lives entirely inside the reserved
    /// bits 3..7 — these are forward-compat slots: a v1 reader masks
    /// them off and continues parsing rather than dropping the
    /// connection. v1.1 flags land here without breaking v1 peers.
    /// Restrict the pattern to ONLY reserved bits — a generated
    /// value with low bits set could trip the broadcast / explicit
    /// validation downstream and falsely look like a rejection of
    /// the reserved-bit branch.
    const std::uint8_t reserved =
        *rc::gen::suchThat(rc::gen::arbitrary<std::uint8_t>(),
                           [](std::uint8_t v) {
                               return (v & kReservedBitsMask) != 0;
                           }) & kReservedBitsMask;

    std::array<std::uint8_t, kFixedHeaderSize> buf{};
    encode_header(buf, reserved, /*msg_id=*/1,
                  /*total_length=*/static_cast<std::uint32_t>(
                      kFixedHeaderSize + conditional_pk_size(reserved)));

    ParsedHeader out{};
    RC_ASSERT(parse_header(buf, out) == GN_OK);
    RC_ASSERT((out.flags & kReservedBitsMask) == 0);
}

}  // namespace
}  // namespace gn::plugins::gnet::wire
