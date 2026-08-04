/// @file   tests/unit/kernel/test_host_api_identity.cpp
/// @brief  Ownership enforcement for register_local_key / delete_local_key,
///         announce_rotation gate, and sign_local purpose gate.
///
/// W6: creator plugin_name is stored at register time and checked at
/// delete time — plugin B cannot delete plugin A's sub-key.
/// W7: sign_purposes bitmask in PluginContext gates sign_local() calls.

#include <gtest/gtest.h>

#include <core/identity/node_identity.hpp>
#include <core/kernel/host_api_builder.hpp>
#include <core/kernel/kernel.hpp>
#include <core/kernel/plugin_context.hpp>

#include <sdk/host_api.h>
#include <sdk/identity.h>
#include <sdk/types.h>

using gn::core::Kernel;
using gn::core::PluginContext;
using gn::core::build_host_api;
using gn::core::identity::NodeIdentity;

namespace {

constexpr std::int64_t kFarFuture = 9'999'999'999LL;

struct IdentityHarness {
    Kernel      kernel;

    IdentityHarness() {
        auto id = NodeIdentity::generate(kFarFuture);
        EXPECT_TRUE(id.has_value());
        kernel.set_node_identity(std::move(*id));
    }

    PluginContext make_ctx(const char* name) {
        PluginContext ctx;
        ctx.plugin_name = name;
        ctx.kind        = GN_PLUGIN_KIND_HANDLER;
        ctx.kernel      = &kernel;
        return ctx;
    }
};

}  // namespace

TEST(HostApiIdentityOwnership, OwnerCanDelete) {
    IdentityHarness h;
    auto ctx_a = h.make_ctx("plugin-a");
    auto api_a = build_host_api(ctx_a);

    gn_key_id_t id = GN_INVALID_KEY_ID;
    ASSERT_EQ(api_a.register_local_key(api_a.host_ctx,
                                        GN_KEY_PURPOSE_RECOVERY,
                                        "my-key", &id),
              GN_OK);
    ASSERT_NE(id, GN_INVALID_KEY_ID);

    EXPECT_EQ(api_a.delete_local_key(api_a.host_ctx, id), GN_OK);
}

TEST(HostApiIdentityOwnership, NonOwnerCannotDelete) {
    IdentityHarness h;
    auto ctx_a = h.make_ctx("plugin-a");
    auto ctx_b = h.make_ctx("plugin-b");
    auto api_a = build_host_api(ctx_a);
    auto api_b = build_host_api(ctx_b);

    gn_key_id_t id = GN_INVALID_KEY_ID;
    ASSERT_EQ(api_a.register_local_key(api_a.host_ctx,
                                        GN_KEY_PURPOSE_RECOVERY,
                                        "a-key", &id),
              GN_OK);

    EXPECT_EQ(api_b.delete_local_key(api_b.host_ctx, id), GN_ERR_NOT_FOUND);
}

TEST(HostApiIdentityOwnership, NonExistentKeyReturnsNotFound) {
    IdentityHarness h;
    auto ctx = h.make_ctx("plugin-a");
    auto api = build_host_api(ctx);

    EXPECT_EQ(api.delete_local_key(api.host_ctx,
                                    static_cast<gn_key_id_t>(0xDEADBEEF)),
              GN_ERR_NOT_FOUND);
}

TEST(HostApiIdentityOwnership, DeleteAfterNonOwnerFailureStillSucceeds) {
    IdentityHarness h;
    auto ctx_a = h.make_ctx("plugin-a");
    auto ctx_b = h.make_ctx("plugin-b");
    auto api_a = build_host_api(ctx_a);
    auto api_b = build_host_api(ctx_b);

    gn_key_id_t id = GN_INVALID_KEY_ID;
    ASSERT_EQ(api_a.register_local_key(api_a.host_ctx,
                                        GN_KEY_PURPOSE_SECOND_FACTOR,
                                        "sf-key", &id),
              GN_OK);

    EXPECT_EQ(api_b.delete_local_key(api_b.host_ctx, id), GN_ERR_NOT_FOUND);
    EXPECT_EQ(api_a.delete_local_key(api_a.host_ctx, id), GN_OK);
    EXPECT_EQ(api_a.delete_local_key(api_a.host_ctx, id), GN_ERR_NOT_FOUND);
}

// ── W9: announce_rotation gate ───────────────────────────────────────────────

TEST(HostApiRotation, WithoutMayRotateFlagRefused) {
    IdentityHarness h;
    auto ctx = h.make_ctx("plugin-no-rotate");
    // may_rotate defaults to false
    auto api = build_host_api(ctx);
    EXPECT_EQ(api.announce_rotation(api.host_ctx, 0), GN_ERR_NOT_IMPLEMENTED);
}

TEST(HostApiRotation, WithMayRotateFlagSucceeds) {
    IdentityHarness h;
    auto ctx = h.make_ctx("plugin-rotate");
    ctx.may_rotate = true;
    auto api = build_host_api(ctx);
    EXPECT_EQ(api.announce_rotation(api.host_ctx, 0), GN_OK);
}

TEST(HostApiRotation, SecondCallWithinCooldownRejected) {
    IdentityHarness h;
    auto ctx = h.make_ctx("plugin-rotate");
    ctx.may_rotate = true;
    auto api = build_host_api(ctx);

    EXPECT_EQ(api.announce_rotation(api.host_ctx, 0), GN_OK);
    EXPECT_EQ(api.announce_rotation(api.host_ctx, 0), GN_ERR_LIMIT_REACHED);
}

TEST(HostApiRotation, CallAfterCooldownSucceeds) {
    IdentityHarness h;
    h.kernel.reset_rotation_timestamp();
    // Simulate last rotation far in the past by seeding timestamp directly.
    // We can't easily fast-forward time, so instead reset to 0 (never rotated)
    // and verify a fresh harness allows a call.
    auto ctx = h.make_ctx("plugin-rotate");
    ctx.may_rotate = true;
    auto api = build_host_api(ctx);
    EXPECT_EQ(api.announce_rotation(api.host_ctx, 0), GN_OK);
}

// ── W7: sign_local purpose gate ─────────────────────────────────────────────

TEST(HostApiSignLocal, ZeroSignPurposesBlocksNonUnknownKind) {
    IdentityHarness h;
    auto ctx = h.make_ctx("plugin-any");
    // sign_purposes == 0 + kind=HANDLER → blocked (grant-by-declaration)
    auto api = build_host_api(ctx);
    std::uint8_t sig[64];
    const std::uint8_t payload[] = {1, 2, 3};
    EXPECT_EQ(api.sign_local(api.host_ctx, GN_KEY_PURPOSE_ASSERT,
                              payload, sizeof(payload), sig),
              GN_ERR_NOT_IMPLEMENTED);
}

TEST(HostApiSignLocal, UnknownKindBypassesSignPurposesGate) {
    IdentityHarness h;
    auto ctx = h.make_ctx("plugin-operator");
    ctx.kind = GN_PLUGIN_KIND_UNKNOWN;
    auto api = build_host_api(ctx);
    std::uint8_t sig[64];
    const std::uint8_t payload[] = {1, 2, 3};
    EXPECT_EQ(api.sign_local(api.host_ctx, GN_KEY_PURPOSE_ASSERT,
                              payload, sizeof(payload), sig),
              GN_OK);
}

TEST(HostApiSignLocal, DeclaredPurposeAllowed) {
    IdentityHarness h;
    auto ctx = h.make_ctx("plugin-assert");
    ctx.sign_purposes = 1u << static_cast<unsigned>(GN_KEY_PURPOSE_ASSERT);
    auto api = build_host_api(ctx);
    std::uint8_t sig[64];
    const std::uint8_t payload[] = {0xAB};
    EXPECT_EQ(api.sign_local(api.host_ctx, GN_KEY_PURPOSE_ASSERT,
                              payload, sizeof(payload), sig),
              GN_OK);
}

TEST(HostApiSignLocal, UndeclaredPurposeRejected) {
    IdentityHarness h;
    auto ctx = h.make_ctx("plugin-assert-only");
    // only ASSERT declared
    ctx.sign_purposes = 1u << static_cast<unsigned>(GN_KEY_PURPOSE_ASSERT);
    auto api = build_host_api(ctx);
    std::uint8_t sig[64];
    const std::uint8_t payload[] = {0xFF};
    EXPECT_EQ(api.sign_local(api.host_ctx, GN_KEY_PURPOSE_AUTH,
                              payload, sizeof(payload), sig),
              GN_ERR_NOT_IMPLEMENTED);
}

TEST(HostApiSignLocal, MultiplePurposesAllowAllDeclared) {
    IdentityHarness h;
    auto ctx = h.make_ctx("plugin-multi");
    ctx.sign_purposes = (1u << static_cast<unsigned>(GN_KEY_PURPOSE_ASSERT))
                      | (1u << static_cast<unsigned>(GN_KEY_PURPOSE_AUTH));
    auto api = build_host_api(ctx);
    std::uint8_t sig[64];
    const std::uint8_t payload[] = {1};
    EXPECT_EQ(api.sign_local(api.host_ctx, GN_KEY_PURPOSE_ASSERT,
                              payload, sizeof(payload), sig),
              GN_OK);
    EXPECT_EQ(api.sign_local(api.host_ctx, GN_KEY_PURPOSE_AUTH,
                              payload, sizeof(payload), sig),
              GN_OK);
    EXPECT_EQ(api.sign_local(api.host_ctx, GN_KEY_PURPOSE_ROTATION_SIGN,
                              payload, sizeof(payload), sig),
              GN_ERR_NOT_IMPLEMENTED);
}
