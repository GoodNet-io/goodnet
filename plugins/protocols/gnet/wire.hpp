/// @file   plugins/protocols/gnet/wire.hpp
/// @brief  Byte-level encoding and decoding for the GNET v1 wire format.
///
/// Implements the layout from `plugins/protocols/gnet/docs/wire-format.md` §2.
/// Pure byte operations — no `ConnectionContext`, no envelope. The
/// surrounding `protocol.hpp` ties wire bytes to the kernel envelope.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include <sdk/types.h>

namespace gn::plugins::gnet::wire {

/// Fixed magic bytes — ASCII "GNET".
inline constexpr std::array<std::uint8_t, 4> kMagic = {0x47, 0x4E, 0x45, 0x54};

/// Wire-format version. A receiver built for `0x01` rejects frames
/// declaring any other value.
inline constexpr std::uint8_t kVersion = 0x01;

/// Fixed header size, bytes — magic(4) + ver(1) + flags(1) + msg_id(4) + length(4).
inline constexpr std::size_t kFixedHeaderSize = 14;

/// Public-key field size in bytes. Matches `GN_PUBLIC_KEY_BYTES`.
inline constexpr std::size_t kPublicKeySize = 32;

/// Maximum permitted frame size on the wire, including header + any
/// conditional pk fields + payload. Matches the default
/// `gn_limits_t::max_frame_bytes`.
inline constexpr std::size_t kMaxFrameBytes = 65536;

/* ── Flag bits ───────────────────────────────────────────────────────────── */

inline constexpr std::uint8_t kFlagExplicitSender   = 0x01;  ///< sender_pk on wire
inline constexpr std::uint8_t kFlagExplicitReceiver = 0x02;  ///< receiver_pk on wire
inline constexpr std::uint8_t kFlagBroadcast        = 0x04;  ///< receiver implicit ZERO
inline constexpr std::uint8_t kReservedBitsMask     = 0xF8;  ///< bits 3-7, must be zero in v1

/* ── Field offsets within the fixed header ──────────────────────────────── */

inline constexpr std::size_t kOffsetMagic    = 0;
inline constexpr std::size_t kOffsetVersion  = 4;
inline constexpr std::size_t kOffsetFlags    = 5;
inline constexpr std::size_t kOffsetMsgId    = 6;
inline constexpr std::size_t kOffsetLength   = 10;

/* ── Parsed-header structure ─────────────────────────────────────────────── */

/// Result of parsing the fixed header plus any conditional pk fields.
///
/// `total_length` is taken verbatim from the wire `length` field; it
/// covers fixed-header + conditional pks + payload. The caller subtracts
/// `header_size` to obtain the payload byte count.
struct ParsedHeader {
    std::uint8_t  flags;            ///< raw flags byte
    std::uint32_t msg_id;           ///< host byte order after parse
    std::uint32_t total_length;     ///< total frame size on wire
    std::size_t   header_size;      ///< 14 + 32*popcount(EXPLICIT_*)

    /// Convenience predicates derived from `flags`.
    [[nodiscard]] bool has_explicit_sender()   const noexcept { return (flags & kFlagExplicitSender)   != 0; }
    [[nodiscard]] bool has_explicit_receiver() const noexcept { return (flags & kFlagExplicitReceiver) != 0; }
    [[nodiscard]] bool is_broadcast()          const noexcept { return (flags & kFlagBroadcast)        != 0; }
};

/* ── Header parse / encode ───────────────────────────────────────────────── */

/// Parse the fixed header from @p bytes.
///
/// @return
///   - `GN_OK` on success; @p out populated.
///   - `GN_ERR_DEFRAME_INCOMPLETE` if `bytes.size() < kFixedHeaderSize`.
///   - `GN_ERR_DEFRAME_CORRUPT` on bad magic, wrong version, reserved
///     bits set, broadcast/receiver flag conflict, or impossible
///     `total_length` (smaller than `header_size`, or larger than
///     `kMaxFrameBytes`).
[[nodiscard]] gn_result_t parse_header(std::span<const std::uint8_t> bytes,
                                       ParsedHeader& out) noexcept;

/// Encode the 14-byte fixed header into @p dst.
///
/// Caller guarantees `dst.size() >= kFixedHeaderSize`. Conditional pk
/// fields (if requested by @p flags) are NOT written here — the caller
/// places them in `dst[kFixedHeaderSize ...]` per the layout.
void encode_header(std::span<std::uint8_t> dst,
                   std::uint8_t  flags,
                   std::uint32_t msg_id,
                   std::uint32_t total_length) noexcept;

/// Compute the byte count for a frame given flags and payload size.
///
/// @return `kFixedHeaderSize + 32 * count(EXPLICIT_* set in flags) + payload_size`.
[[nodiscard]] std::size_t compute_frame_size(std::uint8_t flags,
                                             std::size_t  payload_size) noexcept;

/// Compute the conditional-pk-area size from the flag byte.
[[nodiscard]] constexpr std::size_t conditional_pk_size(std::uint8_t flags) noexcept {
    std::size_t n = 0;
    if (flags & kFlagExplicitSender)   ++n;
    if (flags & kFlagExplicitReceiver) ++n;
    return n * kPublicKeySize;
}

} // namespace gn::plugins::gnet::wire
