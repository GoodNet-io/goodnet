/// @file   tests/integration/test_config_reload.cpp
/// @brief  Hot reload pipeline: Kernel::reload_config →
///         on_config_reload signal → plugin re-reads via
///         host_api->subscribe(GN_SUBSCRIBE_CONFIG_RELOAD).
///
/// Pins `config.md` §2 (reload lifecycle) end-to-end through the
/// host_api thunks: a kernel-level reload triggers each subscribed
/// plugin's callback, which observes the new state via
/// `config_get_*` and applies the updated knobs to its own
/// running state.

#include <gtest/gtest.h>

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>

#include <core/kernel/host_api_builder.hpp>
#include <core/kernel/kernel.hpp>
#include <core/kernel/plugin_context.hpp>

#include <sdk/host_api.h>
#include <sdk/types.h>

using gn::core::Kernel;
using gn::core::PluginAnchor;
using gn::core::PluginContext;
using gn::core::build_host_api;

namespace {

PluginContext make_ctx(Kernel& k) {
    PluginContext ctx;
    ctx.kernel        = &k;
    ctx.kind          = GN_PLUGIN_KIND_HANDLER;
    ctx.plugin_name   = "reload-fixture";
    ctx.plugin_anchor = std::make_shared<PluginAnchor>();
    return ctx;
}

}  // namespace

// ── reload_config end-to-end ─────────────────────────────────────────────

TEST(ConfigReload, ReloadFiresSubscriberCallback) {
    Kernel k;
    auto ctx = make_ctx(k);
    auto api = build_host_api(ctx);

    std::atomic<int> calls{0};
    gn_subscription_id_t token = GN_INVALID_SUBSCRIPTION_ID;
    ASSERT_EQ(api.subscribe(
                api.host_ctx,
                GN_SUBSCRIBE_CONFIG_RELOAD,
                +[](void* ud, const void* /*payload*/, std::size_t /*size*/) {
                    static_cast<std::atomic<int>*>(ud)->fetch_add(1);
                },
                &calls,
                /*ud_destroy*/ nullptr,
                &token),
              GN_OK);
    EXPECT_NE(token, GN_INVALID_SUBSCRIPTION_ID);

    /// Reload must fire the subscribed callback exactly once.
    ASSERT_EQ(k.reload_config(R"({"marker":"first"})"), GN_OK);
    EXPECT_EQ(calls.load(), 1);

    /// Second reload — second fire.
    ASSERT_EQ(k.reload_config(R"({"marker":"second"})"), GN_OK);
    EXPECT_EQ(calls.load(), 2);
}

TEST(ConfigReload, FailedReloadDoesNotFire) {
    /// A reload that fails parse must not fire the signal —
    /// subscribers see a consistent "every fire corresponds to a
    /// successful state change" contract.
    Kernel k;
    auto ctx = make_ctx(k);
    auto api = build_host_api(ctx);

    std::atomic<int> calls{0};
    gn_subscription_id_t token = GN_INVALID_SUBSCRIPTION_ID;
    ASSERT_EQ(api.subscribe(
                api.host_ctx,
                GN_SUBSCRIBE_CONFIG_RELOAD,
                +[](void* ud, const void* /*payload*/, std::size_t /*size*/) {
                    static_cast<std::atomic<int>*>(ud)->fetch_add(1);
                },
                &calls,
                /*ud_destroy*/ nullptr,
                &token),
              GN_OK);

    EXPECT_EQ(k.reload_config("[bad json"), GN_ERR_INVALID_ENVELOPE);
    EXPECT_EQ(calls.load(), 0);
}

TEST(ConfigReload, FailedValidationDoesNotFire) {
    Kernel k;
    auto ctx = make_ctx(k);
    auto api = build_host_api(ctx);

    std::atomic<int> calls{0};
    gn_subscription_id_t token = GN_INVALID_SUBSCRIPTION_ID;
    ASSERT_EQ(api.subscribe(
                api.host_ctx,
                GN_SUBSCRIBE_CONFIG_RELOAD,
                +[](void* ud, const void* /*payload*/, std::size_t /*size*/) {
                    static_cast<std::atomic<int>*>(ud)->fetch_add(1);
                },
                &calls,
                /*ud_destroy*/ nullptr,
                &token),
              GN_OK);

    /// Invariant violation: max_outbound > max_total.
    const char* bad = R"({"limits": {
        "max_connections": 100,
        "max_outbound_connections": 200
    }})";
    EXPECT_EQ(k.reload_config(bad), GN_ERR_LIMIT_REACHED);
    EXPECT_EQ(calls.load(), 0);
}

TEST(ConfigReload, UnsubscribeStopsCallbacks) {
    Kernel k;
    auto ctx = make_ctx(k);
    auto api = build_host_api(ctx);

    std::atomic<int> calls{0};
    gn_subscription_id_t token = GN_INVALID_SUBSCRIPTION_ID;
    ASSERT_EQ(api.subscribe(
                api.host_ctx,
                GN_SUBSCRIBE_CONFIG_RELOAD,
                +[](void* ud, const void* /*payload*/, std::size_t /*size*/) {
                    static_cast<std::atomic<int>*>(ud)->fetch_add(1);
                },
                &calls,
                /*ud_destroy*/ nullptr,
                &token),
              GN_OK);

    ASSERT_EQ(k.reload_config(R"({"a":1})"), GN_OK);
    EXPECT_EQ(calls.load(), 1);

    EXPECT_EQ(api.unsubscribe(api.host_ctx, token),
              GN_OK);
    /// Idempotent: unsubscribing a second time is success.
    EXPECT_EQ(api.unsubscribe(api.host_ctx, token),
              GN_OK);

    ASSERT_EQ(k.reload_config(R"({"a":2})"), GN_OK);
    EXPECT_EQ(calls.load(), 1)
        << "unsubscribed callback must not fire";
}

TEST(ConfigReload, MergeReloadAlsoFires) {
    /// Both reload entries — wholesale and merge — fire the same
    /// signal so subscribers do not have to discriminate.
    Kernel k;
    auto ctx = make_ctx(k);
    auto api = build_host_api(ctx);

    std::atomic<int> calls{0};
    gn_subscription_id_t token = GN_INVALID_SUBSCRIPTION_ID;
    ASSERT_EQ(api.subscribe(
                api.host_ctx,
                GN_SUBSCRIBE_CONFIG_RELOAD,
                +[](void* ud, const void* /*payload*/, std::size_t /*size*/) {
                    static_cast<std::atomic<int>*>(ud)->fetch_add(1);
                },
                &calls,
                /*ud_destroy*/ nullptr,
                &token),
              GN_OK);

    ASSERT_EQ(k.reload_config(R"({"limits":{
        "max_connections": 1024,
        "max_outbound_connections": 256
    }})"), GN_OK);
    EXPECT_EQ(calls.load(), 1);

    ASSERT_EQ(k.reload_config_merge(
                R"({"limits": {"max_outbound_connections": 128}})"),
              GN_OK);
    EXPECT_EQ(calls.load(), 2);
    EXPECT_EQ(k.limits().max_outbound_connections, 128u);
}

TEST(ConfigReload, ReloadPropagatesLimitsIntoRegistries) {
    /// `Kernel::reload_config` calls `set_limits` on the new
    /// gn_limits_t after firing the subscriber callbacks. Verify
    /// kernel-owned registries see the propagation.
    Kernel k;
    EXPECT_EQ(k.limits().max_timers,
              GN_LIMITS_DEFAULT_MAX_TIMERS);

    ASSERT_EQ(k.reload_config(R"({"limits":{"max_timers":256}})"),
              GN_OK);
    EXPECT_EQ(k.limits().max_timers, 256u);
}
