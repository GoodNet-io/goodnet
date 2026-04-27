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

    const std::uint8_t flags = bytes[kOffsetFlags];

    /// Reserved bits must be zero in v1.
    if ((flags & kReservedBitsMask) != 0) {
        return GN_ERR_DEFRAME_CORRUPT;
    }

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
        return GN_ERR_DEFRAME_CORRUPT;
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
