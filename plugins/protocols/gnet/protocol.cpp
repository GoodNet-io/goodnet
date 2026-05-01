/// @file   plugins/protocols/gnet/protocol.cpp
/// @brief  Implementation of GnetProtocol.

#include "protocol.hpp"
#include "wire.hpp"

#include <sodium.h>

#include <cstring>

#include <sdk/connection.h>

namespace gn::plugins::gnet {

namespace {

/// Compare a 32-byte public key buffer against the all-zero pattern.
/// Mirror of `gn_pk_is_zero` from `sdk/types.h`, kept inline so the
/// implementation does not depend on cross-TU inlining of the C helper.
[[nodiscard]] bool pk_buffer_is_zero(const std::uint8_t* pk) noexcept {
    std::uint8_t acc = 0;
    for (std::size_t i = 0; i < GN_PUBLIC_KEY_BYTES; ++i) acc |= pk[i];
    return acc == 0;
}

[[nodiscard]] bool pk_buffer_eq(const std::uint8_t* a, const std::uint8_t* b) noexcept {
    /// Constant-time compare so the framed-vs-relay-transit branch
    /// downstream (header overhead 14 vs 78 bytes) does not become a
    /// length oracle on the per-byte equality of either public key.
    return sodium_memcmp(a, b, GN_PUBLIC_KEY_BYTES) == 0;
}

} // namespace

std::string_view GnetProtocol::protocol_id() const noexcept {
    return kProtocolId;
}

std::size_t GnetProtocol::max_payload_size() const noexcept {
    /// Wire ceiling minus worst-case header: fixed 14 bytes plus both
    /// optional public-key fields = 14 + 64 = 78 bytes overhead.
    return wire::kMaxFrameBytes - wire::kFixedHeaderSize - 2 * wire::kPublicKeySize;
}

::gn::Result<::gn::DeframeResult> GnetProtocol::deframe(
    ::gn::ConnectionContext& ctx,
    std::span<const std::uint8_t> bytes) {

    deframe_buffer_.clear();
    std::size_t cursor = 0;

    while (cursor < bytes.size()) {
        wire::ParsedHeader hdr;
        const auto rc = wire::parse_header(bytes.subspan(cursor), hdr);

        if (rc == GN_ERR_DEFRAME_INCOMPLETE) {
            /// Header itself not fully buffered; keep what we have and
            /// retry with more bytes on the next call.
            break;
        }
        if (rc != GN_OK) {
            return std::unexpected(::gn::Error{rc, "GNET header parse failed"});
        }

        if (cursor + hdr.total_length > bytes.size()) {
            /// Header parsed but full body not yet buffered.
            break;
        }

        const std::uint8_t* frame_start = bytes.data() + cursor;
        std::size_t pk_offset = wire::kFixedHeaderSize;

        gn_message_t env{};
        env.msg_id = hdr.msg_id;

        /// sender_pk — wire-explicit when EXPLICIT_SENDER set,
        /// otherwise the peer pk from the connection context.
        ///
        /// Relay capability gate: a peer that lacks
        /// `ctx.allows_relay` must not be allowed to claim a sender_pk
        /// other than its own. Without the gate, every authenticated
        /// peer could spoof `sender_pk` on any inbound frame and
        /// compromise handlers that authenticate by sender_pk.
        /// `gnet-protocol.md` §5 pins the contract — only relay-capable
        /// connections are permitted to carry EXPLICIT_SENDER /
        /// EXPLICIT_RECEIVER flags.
        if (hdr.has_explicit_sender()) {
            if (gn_ctx_allows_relay(&ctx) == 0) {
                return std::unexpected(::gn::Error{
                    GN_ERR_INTEGRITY_FAILED,
                    "GNET deframe rejected EXPLICIT_SENDER on a "
                    "non-relay connection (sender_pk spoofing gate)"});
            }
            std::memcpy(env.sender_pk, frame_start + pk_offset,
                        wire::kPublicKeySize);
            pk_offset += wire::kPublicKeySize;
        } else {
            const std::uint8_t* remote = gn_ctx_remote_pk(&ctx);
            if (remote == nullptr) {
                return std::unexpected(::gn::Error{
                    GN_ERR_NULL_ARG,
                    "GNET deframe needs ctx.remote for direct frame"});
            }
            std::memcpy(env.sender_pk, remote, wire::kPublicKeySize);
        }

        /// receiver_pk — wire-explicit when EXPLICIT_RECEIVER set,
        /// ZERO when BROADCAST flag set, otherwise the local node pk.
        ///
        /// Same relay-capability gate (`gnet-protocol.md` §5):
        /// EXPLICIT_RECEIVER lets the peer redirect a frame to a
        /// wire-supplied receiver_pk. On a non-relay connection that
        /// is a direct routing-mismatch attack — the peer claims to
        /// be sending to identity X, the kernel dispatches to X's
        /// handlers, but the frame arrived through a connection
        /// authenticated as Y. Reject up front.
        if (hdr.has_explicit_receiver()) {
            if (gn_ctx_allows_relay(&ctx) == 0) {
                return std::unexpected(::gn::Error{
                    GN_ERR_INTEGRITY_FAILED,
                    "GNET deframe rejected EXPLICIT_RECEIVER on a "
                    "non-relay connection (receiver_pk redirect gate)"});
            }
            std::memcpy(env.receiver_pk, frame_start + pk_offset,
                        wire::kPublicKeySize);
        } else if (hdr.is_broadcast()) {
            /// receiver_pk stays zero-initialised.
        } else {
            const std::uint8_t* local = gn_ctx_local_pk(&ctx);
            if (local == nullptr) {
                return std::unexpected(::gn::Error{
                    GN_ERR_NULL_ARG,
                    "GNET deframe needs ctx.local for direct frame"});
            }
            std::memcpy(env.receiver_pk, local, wire::kPublicKeySize);
        }

        /// Payload borrows from the input buffer for one dispatch cycle.
        env.payload      = frame_start + hdr.header_size;
        env.payload_size = hdr.total_length - hdr.header_size;

        deframe_buffer_.push_back(env);
        cursor += hdr.total_length;
    }

    return ::gn::DeframeResult{
        .messages       = std::span<const gn_message_t>(deframe_buffer_),
        .bytes_consumed = cursor};
}

::gn::Result<std::vector<std::uint8_t>> GnetProtocol::frame(
    ::gn::ConnectionContext& ctx,
    const gn_message_t& msg) {

    /// Envelope validation per protocol-layer §2.
    if (msg.msg_id == 0) {
        return std::unexpected(::gn::Error{
            GN_ERR_INVALID_ENVELOPE, "msg_id must be non-zero"});
    }
    if (pk_buffer_is_zero(msg.sender_pk)) {
        return std::unexpected(::gn::Error{
            GN_ERR_INVALID_ENVELOPE, "sender_pk must be non-zero"});
    }
    if (msg.payload_size > max_payload_size()) {
        return std::unexpected(::gn::Error{
            GN_ERR_PAYLOAD_TOO_LARGE, "payload exceeds max_payload_size"});
    }

    /// Decide flags and which pk fields go on the wire.
    std::uint8_t flags = 0;
    const bool receiver_zero = pk_buffer_is_zero(msg.receiver_pk);

    if (receiver_zero) {
        /// Broadcast — sender on wire so transit nodes preserve identity.
        flags = wire::kFlagBroadcast | wire::kFlagExplicitSender;
    } else {
        const std::uint8_t* local  = gn_ctx_local_pk(&ctx);
        const std::uint8_t* remote = gn_ctx_remote_pk(&ctx);
        if (local == nullptr || remote == nullptr) {
            return std::unexpected(::gn::Error{
                GN_ERR_NULL_ARG, "GNET frame needs ctx.local and ctx.remote"});
        }

        const bool sender_is_local    = pk_buffer_eq(msg.sender_pk,   local);
        const bool receiver_is_remote = pk_buffer_eq(msg.receiver_pk, remote);

        if (sender_is_local && receiver_is_remote) {
            /// Direct — Noise carries identity; no PK on wire.
            flags = 0;
        } else {
            /// Relay-transit — preserve end-to-end identity on wire.
            flags = wire::kFlagExplicitSender | wire::kFlagExplicitReceiver;
        }
    }

    const std::size_t total = wire::compute_frame_size(flags, msg.payload_size);
    std::vector<std::uint8_t> buf(total);

    wire::encode_header(std::span<std::uint8_t>(buf.data(), wire::kFixedHeaderSize),
                        flags, msg.msg_id, static_cast<std::uint32_t>(total));

    std::size_t offset = wire::kFixedHeaderSize;
    if (flags & wire::kFlagExplicitSender) {
        std::memcpy(buf.data() + offset, msg.sender_pk, wire::kPublicKeySize);
        offset += wire::kPublicKeySize;
    }
    if (flags & wire::kFlagExplicitReceiver) {
        std::memcpy(buf.data() + offset, msg.receiver_pk, wire::kPublicKeySize);
        offset += wire::kPublicKeySize;
    }

    if (msg.payload_size > 0 && msg.payload != nullptr) {
        std::memcpy(buf.data() + offset, msg.payload, msg.payload_size);
    }

    return buf;
}

} // namespace gn::plugins::gnet
