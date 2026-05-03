/// @file   plugins/protocols/gnet/wire.cpp
/// @brief  Implementation of the GNET v1 byte-level encoder / decoder.

#include "wire.hpp"

#include <core/util/endian.hpp>

namespace gn::plugins::gnet::wire {

gn_result_t parse_header(std::span<const std::uint8_t> bytes,
                         ParsedHeader& out) noexcept {
    if (bytes.size() < kFixedHeaderSize) {
        return GN_ERR_DEFRAME_INCOMPLETE;
    }

    /// Magic check — first four bytes must spell "GNET".
    for (std::size_t i = 0; i < kMagic.size(); ++i) {
        if (bytes[kOffsetMagic + i] != kMagic[i]) {
            return GN_ERR_DEFRAME_CORRUPT;
        }
    }

    /// Version check — kernel built for v1 rejects anything else;
    /// version negotiation belongs to a higher layer.
    if (bytes[kOffsetVersion] != kVersion) {
        return GN_ERR_DEFRAME_CORRUPT;
    }

    const std::uint8_t raw_flags = bytes[kOffsetFlags];

    /// Reserved bits are forward-compatible slots — v1.1+ flags
    /// land in them. Mask the unknown bits off so a frame from a
    /// v1.1 sender survives parsing on a v1 reader instead of
    /// dropping the connection. The deframe path stays
    /// strict on the bits it understands; the rest are
    /// invisible. Operator surface stays in `metrics.md` once the
    /// v1.1 spec lands a per-flag counter.
    const std::uint8_t flags = raw_flags & ~kReservedBitsMask;

    /// Broadcast frames must declare EXPLICIT_SENDER and must NOT
    /// declare EXPLICIT_RECEIVER — receiver is implicit ZERO.
    if (flags & kFlagBroadcast) {
        if ((flags & kFlagExplicitSender) == 0) {
            return GN_ERR_DEFRAME_CORRUPT;
        }
        if ((flags & kFlagExplicitReceiver) != 0) {
            return GN_ERR_DEFRAME_CORRUPT;
        }
    }

    const std::uint32_t msg_id =
        gn::util::read_be<std::uint32_t>(bytes.subspan(kOffsetMsgId, 4));
    const std::uint32_t length =
        gn::util::read_be<std::uint32_t>(bytes.subspan(kOffsetLength, 4));

    const std::size_t cond_pk = conditional_pk_size(flags);
    const std::size_t header  = kFixedHeaderSize + cond_pk;

    /// Length field must cover at least the header itself and must
    /// not exceed the global wire ceiling.
    if (length < header) {
        return GN_ERR_DEFRAME_CORRUPT;
    }
    if (length > kMaxFrameBytes) {
        /// Distinct from generic deframe corruption: a length field
        /// past the v1 wire ceiling is a hostile-peer signal
        /// (`drop.frame_too_large` metric), not a magic-mismatch /
        /// version-drift signal (`drop.deframe_corrupt`). Operators
        /// distinguishing the two diagnose intent without strace.
        return GN_ERR_FRAME_TOO_LARGE;
    }

    out.flags        = flags;
    out.msg_id       = msg_id;
    out.total_length = length;
    out.header_size  = header;
    return GN_OK;
}

void encode_header(std::span<std::uint8_t> dst,
                   std::uint8_t  flags,
                   std::uint32_t msg_id,
                   std::uint32_t total_length) noexcept {
    /// Magic.
    for (std::size_t i = 0; i < kMagic.size(); ++i) {
        dst[kOffsetMagic + i] = kMagic[i];
    }
    dst[kOffsetVersion] = kVersion;
    dst[kOffsetFlags]   = flags;
    gn::util::write_be<std::uint32_t>(dst.subspan(kOffsetMsgId,  4), msg_id);
    gn::util::write_be<std::uint32_t>(dst.subspan(kOffsetLength, 4), total_length);
}

std::size_t compute_frame_size(std::uint8_t flags, std::size_t payload_size) noexcept {
    return kFixedHeaderSize + conditional_pk_size(flags) + payload_size;
}

} // namespace gn::plugins::gnet::wire
