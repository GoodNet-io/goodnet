// SPDX-License-Identifier: MIT
/// @file   plugins/protocols/raw/tests/test_raw.cpp
/// @brief  Raw protocol — opaque-payload frame/deframe + trust gate.

#include <gtest/gtest.h>

#include <plugins/protocols/raw/raw.hpp>

#include <core/kernel/connection_context.hpp>

#include <sdk/connection.h>
#include <sdk/protocol.h>
#include <sdk/trust.h>
#include <sdk/types.h>

#include <cstdint>
#include <cstring>
#include <vector>

namespace {

/// Build a real `gn_connection_context_s` (kernel-side struct) so
/// the protocol-layer accessors (`gn_ctx_local_pk` etc.) resolve
/// against the kernel's own implementation. Tests link against
/// `goodnet_kernel` which provides the `extern "C"` thunks.
gn_connection_context_t make_ctx(gn_trust_class_t trust,
                                  std::uint8_t local_marker,
                                  std::uint8_t remote_marker) {
    gn_connection_context_t ctx{};
    ctx.local_pk[0]  = local_marker;
    ctx.remote_pk[0] = remote_marker;
    ctx.conn_id      = 7;
    ctx.trust        = trust;
    return ctx;
}

}  // namespace

TEST(RawProtocol, ProtocolIdIsStable) {
    auto vt = gn::protocol::raw::make_vtable();
    ASSERT_NE(vt.protocol_id, nullptr);
    EXPECT_STREQ(vt.protocol_id(nullptr), "raw-v1");
}

TEST(RawProtocol, FrameWritesPayloadVerbatim) {
    auto vt   = gn::protocol::raw::make_vtable();
    auto ctx  = make_ctx(GN_TRUST_LOOPBACK, 0x11, 0x22);
    const std::uint8_t payload[] = {0x01, 0x02, 0x03, 0x04};

    gn_message_t msg{};
    msg.msg_id       = 1;
    msg.payload      = payload;
    msg.payload_size = sizeof(payload);

    std::uint8_t* out_bytes = nullptr;
    std::size_t   out_size  = 0;
    void* out_user_data = nullptr; void (*out_free)(void*, std::uint8_t*) = nullptr;
    ASSERT_EQ(vt.frame(nullptr, &ctx, &msg,
                        &out_bytes, &out_size, &out_user_data, &out_free),
              GN_OK);
    ASSERT_NE(out_bytes, nullptr);
    ASSERT_EQ(out_size, sizeof(payload));
    EXPECT_EQ(std::memcmp(out_bytes, payload, sizeof(payload)), 0);

    out_free(out_user_data, out_bytes);
}

TEST(RawProtocol, DeframeReproducesPayload) {
    auto vt  = gn::protocol::raw::make_vtable();
    auto ctx = make_ctx(GN_TRUST_LOOPBACK, 0xAA, 0xBB);
    const std::uint8_t wire[] = {0xDE, 0xAD, 0xBE, 0xEF};

    gn_deframe_result_t res{};
    ASSERT_EQ(vt.deframe(nullptr, &ctx, wire, sizeof(wire), &res), GN_OK);
    ASSERT_EQ(res.count, 1u);
    ASSERT_NE(res.messages, nullptr);
    EXPECT_EQ(res.messages[0].payload_size, sizeof(wire));
    EXPECT_EQ(std::memcmp(res.messages[0].payload, wire, sizeof(wire)), 0);
    EXPECT_EQ(res.bytes_consumed, sizeof(wire));

    /// Sender / receiver come from the context.
    EXPECT_EQ(res.messages[0].sender_pk[0],   0xBB);
    EXPECT_EQ(res.messages[0].receiver_pk[0], 0xAA);
}

TEST(RawProtocol, DeframeWorksOnIntraNode) {
    auto vt  = gn::protocol::raw::make_vtable();
    auto ctx = make_ctx(GN_TRUST_INTRA_NODE, 0x01, 0x02);
    const std::uint8_t wire[] = {0xFF};
    gn_deframe_result_t res{};
    /// `IntraNode` is the second trust class permitted for `raw`
    /// per security-trust.md §4.
    EXPECT_EQ(vt.deframe(nullptr, &ctx, wire, sizeof(wire), &res), GN_OK);
}

TEST(RawProtocol, DeframeRefusesUntrusted) {
    auto vt  = gn::protocol::raw::make_vtable();
    auto ctx = make_ctx(GN_TRUST_UNTRUSTED, 0x00, 0x00);
    const std::uint8_t bytes[] = {0x01};
    gn_deframe_result_t res{};
    /// Per security-trust.md §4 raw is permitted only on
    /// LOOPBACK / INTRA_NODE; deframe on UNTRUSTED returns the
    /// invariant-violation code so the kernel drops the frame.
    EXPECT_EQ(vt.deframe(nullptr, &ctx, bytes, sizeof(bytes), &res),
              GN_ERR_INVALID_ENVELOPE);
}

TEST(RawProtocol, DeframeRefusesPeer) {
    auto vt  = gn::protocol::raw::make_vtable();
    auto ctx = make_ctx(GN_TRUST_PEER, 0x00, 0x00);
    const std::uint8_t bytes[] = {0x01};
    gn_deframe_result_t res{};
    /// Even authenticated peers go through the proper protocol
    /// layer (gnet-v1) — `raw` is opaque-passthrough only.
    EXPECT_EQ(vt.deframe(nullptr, &ctx, bytes, sizeof(bytes), &res),
              GN_ERR_INVALID_ENVELOPE);
}

TEST(RawProtocol, DeframeRefusesEmpty) {
    auto vt  = gn::protocol::raw::make_vtable();
    auto ctx = make_ctx(GN_TRUST_LOOPBACK, 0x00, 0x00);
    gn_deframe_result_t res{};
    EXPECT_EQ(vt.deframe(nullptr, &ctx, nullptr, 0, &res),
              GN_ERR_DEFRAME_INCOMPLETE);
}

TEST(RawProtocol, FrameRejectsOversized) {
    auto vt  = gn::protocol::raw::make_vtable();
    auto ctx = make_ctx(GN_TRUST_LOOPBACK, 0x00, 0x00);
    const std::uint8_t junk = 0;
    gn_message_t msg{};
    msg.payload      = &junk;
    msg.payload_size = (1U << 25);  /// 32 MiB > kMaxPayloadBytes

    std::uint8_t* out_bytes = nullptr;
    std::size_t   out_size  = 0;
    void* out_user_data = nullptr; void (*out_free)(void*, std::uint8_t*) = nullptr;
    EXPECT_EQ(vt.frame(nullptr, &ctx, &msg,
                        &out_bytes, &out_size, &out_user_data, &out_free),
              GN_ERR_PAYLOAD_TOO_LARGE);
    EXPECT_EQ(out_bytes, nullptr);
}

TEST(RawProtocol, MaxPayloadAdvertised) {
    auto vt = gn::protocol::raw::make_vtable();
    EXPECT_GT(vt.max_payload_size(nullptr), 0u);
}

TEST(RawProtocol, RoundTripFrameDeframe) {
    auto vt  = gn::protocol::raw::make_vtable();
    auto ctx = make_ctx(GN_TRUST_LOOPBACK, 0xAB, 0xCD);

    const std::uint8_t payload[] = {0x10, 0x20, 0x30, 0x40, 0x50};
    gn_message_t msg{};
    msg.payload      = payload;
    msg.payload_size = sizeof(payload);

    std::uint8_t* out_bytes = nullptr;
    std::size_t   out_size  = 0;
    void* out_user_data = nullptr; void (*out_free)(void*, std::uint8_t*) = nullptr;
    ASSERT_EQ(vt.frame(nullptr, &ctx, &msg,
                        &out_bytes, &out_size, &out_user_data, &out_free),
              GN_OK);

    gn_deframe_result_t res{};
    ASSERT_EQ(vt.deframe(nullptr, &ctx, out_bytes, out_size, &res), GN_OK);
    ASSERT_EQ(res.count, 1u);
    EXPECT_EQ(res.messages[0].payload_size, sizeof(payload));
    EXPECT_EQ(std::memcmp(res.messages[0].payload, payload, sizeof(payload)), 0);

    out_free(out_user_data, out_bytes);
}
