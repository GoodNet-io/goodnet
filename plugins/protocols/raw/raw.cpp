// SPDX-License-Identifier: MIT
#include "raw.hpp"

#include <cstdint>
#include <cstdlib>
#include <cstring>

namespace gn::protocol::raw {
namespace {

constexpr std::size_t kMaxPayloadBytes = 1U << 20;  // 1 MiB cap

const char* protocol_id_thunk(void* /*self*/) noexcept {
    return kProtocolId;
}

/// Free function matching `gn_protocol_layer_vtable_t::frame`'s
/// `out_free` signature. The kernel calls this once it has
/// finished pushing the framed bytes through the security layer.
void free_buffer(std::uint8_t* p) noexcept {
    std::free(p);
}

gn_result_t deframe_thunk(void* /*self*/,
                          gn_connection_context_t* ctx,
                          const std::uint8_t* bytes,
                          std::size_t bytes_size,
                          gn_deframe_result_t* out) noexcept {
    if (!ctx || !out) return GN_ERR_NULL_ARG;
    if (!bytes && bytes_size > 0) return GN_ERR_NULL_ARG;
    if (bytes_size == 0) return GN_ERR_DEFRAME_INCOMPLETE;
    if (bytes_size > kMaxPayloadBytes) return GN_ERR_PAYLOAD_TOO_LARGE;

    /// Trust gate — `raw` is for opaque-passthrough scenarios where
    /// the wire's authenticity is established outside the kernel
    /// (loopback, intra-process, simulation, replay). Refuse on any
    /// trust class where unauthenticated bytes would be a security
    /// hole.
    const auto trust = gn_ctx_trust(ctx);
    if (trust != GN_TRUST_LOOPBACK && trust != GN_TRUST_INTRA_NODE) {
        return GN_ERR_INVALID_ENVELOPE;
    }

    /// One envelope per call; payload borrows the input buffer.
    /// `messages` is owned by `self` storage — but `raw` is
    /// stateless so we use a thread-local cache. The kernel
    /// dispatches synchronously inside one connection's strand,
    /// so the thread-local lifetime matches the contract: result
    /// is valid until the next deframe on the same thread.
    static thread_local gn_message_t scratch{};
    scratch = gn_message_t{};
    scratch.msg_id       = 1;  /// raw uses a fixed routing key
    scratch.payload      = bytes;
    scratch.payload_size = bytes_size;

    if (const std::uint8_t* local = gn_ctx_local_pk(ctx); local) {
        std::memcpy(scratch.receiver_pk, local, GN_PUBLIC_KEY_BYTES);
    }
    if (const std::uint8_t* remote = gn_ctx_remote_pk(ctx); remote) {
        std::memcpy(scratch.sender_pk, remote, GN_PUBLIC_KEY_BYTES);
    }

    out->messages       = &scratch;
    out->count          = 1;
    out->bytes_consumed = bytes_size;
    return GN_OK;
}

gn_result_t frame_thunk(void* /*self*/,
                        gn_connection_context_t* /*ctx*/,
                        const gn_message_t* msg,
                        std::uint8_t** out_bytes,
                        std::size_t* out_size,
                        void (**out_free)(std::uint8_t*)) noexcept {
    if (!msg || !out_bytes || !out_size || !out_free) {
        return GN_ERR_NULL_ARG;
    }
    if (!msg->payload && msg->payload_size > 0) return GN_ERR_NULL_ARG;
    if (msg->payload_size > kMaxPayloadBytes) return GN_ERR_PAYLOAD_TOO_LARGE;

    /// `raw` writes the payload verbatim. Allocate a copy so the
    /// kernel can hold the buffer past the synchronous return; the
    /// matching free function disposes of it after the security
    /// layer consumes the bytes.
    auto* buf = static_cast<std::uint8_t*>(
        std::malloc(msg->payload_size > 0 ? msg->payload_size : 1));
    if (!buf) return GN_ERR_OUT_OF_MEMORY;
    if (msg->payload_size > 0) {
        std::memcpy(buf, msg->payload, msg->payload_size);
    }

    *out_bytes = buf;
    *out_size  = msg->payload_size;
    *out_free  = &free_buffer;
    return GN_OK;
}

std::size_t max_payload_size_thunk(void* /*self*/) noexcept {
    return kMaxPayloadBytes;
}

void destroy_thunk(void* /*self*/) noexcept {
    /// Nothing to release — `raw` is stateless.
}

std::uint32_t allowed_trust_mask_thunk(void* /*self*/) noexcept {
    /// Same gate as `deframe_thunk` enforces inline. Two layers in
    /// case the kernel ever consults the vtable mask before a
    /// deframe call (a future dlopen'd-protocol path), and the
    /// inline check stays defence-in-depth for direct invocations.
    return (1u << GN_TRUST_LOOPBACK) | (1u << GN_TRUST_INTRA_NODE);
}

}  // namespace

gn_protocol_layer_vtable_t make_vtable() noexcept {
    gn_protocol_layer_vtable_t v{};
    v.api_size           = sizeof(gn_protocol_layer_vtable_t);
    v.protocol_id        = &protocol_id_thunk;
    v.deframe            = &deframe_thunk;
    v.frame              = &frame_thunk;
    v.max_payload_size   = &max_payload_size_thunk;
    v.destroy            = &destroy_thunk;
    v.allowed_trust_mask = &allowed_trust_mask_thunk;
    return v;
}

}  // namespace gn::protocol::raw
