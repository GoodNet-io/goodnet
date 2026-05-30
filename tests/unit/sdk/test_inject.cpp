// SPDX-License-Identifier: Apache-2.0
/// @file   tests/unit/sdk/test_inject.cpp
/// @brief  Input-guard tests for sdk/cpp/inject.hpp wrappers.
///
/// Exercises the three guards that fire *before* the kernel is reached:
///   1. null api pointer / null inject slot → GN_ERR_NOT_IMPLEMENTED
///   2. empty target_ns              → GN_ERR_INVALID_ENVELOPE
///   3. empty frame span (frame path) → GN_ERR_NULL_ARG
///
/// No kernel is instantiated here; the inject slot is either null or a
/// stub that must not be reached for the guard cases.

#include <gtest/gtest.h>

#include <cstdint>
#include <span>

#include <sdk/cpp/inject.hpp>
#include <sdk/host_api.h>
#include <sdk/types.h>

namespace {

/// Stub inject that must not be reached for the guard cases.
gn_result_t unreachable_inject(void*, gn_inject_layer_t, gn_conn_id_t,
                                const char*, uint32_t,
                                const uint8_t*, size_t) noexcept {
    ADD_FAILURE() << "inject slot reached — guard did not fire";
    return GN_ERR_INTERNAL;
}

/// Minimal host_api_t with inject wired to unreachable_inject.
host_api_t stub_api() noexcept {
    host_api_t a{};
    a.api_size = sizeof(a);
    a.inject   = &unreachable_inject;
    return a;
}

constexpr gn_conn_id_t kDummyConn = 1;
const std::uint8_t kPayload[1]    = {0x42};
const std::uint8_t kFrame[4]      = {0x01, 0x02, 0x03, 0x04};

}  // namespace

// ── inject_message guards ────────────────────────────────────────────────

TEST(InjectSdkGuards, Message_NullApi_ReturnsNotImplemented) {
    EXPECT_EQ(gn::sdk::inject_message(nullptr, kDummyConn, "gnet-v1",
                                       0x42, {kPayload, 1}),
              GN_ERR_NOT_IMPLEMENTED);
}

TEST(InjectSdkGuards, Message_NullInjectSlot_ReturnsNotImplemented) {
    host_api_t a{};
    a.api_size = sizeof(a);
    // a.inject left null
    EXPECT_EQ(gn::sdk::inject_message(&a, kDummyConn, "gnet-v1",
                                       0x42, {kPayload, 1}),
              GN_ERR_NOT_IMPLEMENTED);
}

TEST(InjectSdkGuards, Message_EmptyNamespace_ReturnsInvalidEnvelope) {
    auto a = stub_api();
    EXPECT_EQ(gn::sdk::inject_message(&a, kDummyConn, "",
                                       0x42, {kPayload, 1}),
              GN_ERR_INVALID_ENVELOPE);
}

// ── inject_frame guards ──────────────────────────────────────────────────

TEST(InjectSdkGuards, Frame_NullApi_ReturnsNotImplemented) {
    EXPECT_EQ(gn::sdk::inject_frame(nullptr, kDummyConn, "gnet-v1",
                                     {kFrame, 4}),
              GN_ERR_NOT_IMPLEMENTED);
}

TEST(InjectSdkGuards, Frame_NullInjectSlot_ReturnsNotImplemented) {
    host_api_t a{};
    a.api_size = sizeof(a);
    EXPECT_EQ(gn::sdk::inject_frame(&a, kDummyConn, "gnet-v1",
                                     {kFrame, 4}),
              GN_ERR_NOT_IMPLEMENTED);
}

TEST(InjectSdkGuards, Frame_EmptyNamespace_ReturnsInvalidEnvelope) {
    auto a = stub_api();
    EXPECT_EQ(gn::sdk::inject_frame(&a, kDummyConn, "", {kFrame, 4}),
              GN_ERR_INVALID_ENVELOPE);
}

TEST(InjectSdkGuards, Frame_EmptySpan_ReturnsNullArg) {
    auto a = stub_api();
    EXPECT_EQ(gn::sdk::inject_frame(&a, kDummyConn, "gnet-v1",
                                     std::span<const std::uint8_t>{}),
              GN_ERR_NULL_ARG);
}
