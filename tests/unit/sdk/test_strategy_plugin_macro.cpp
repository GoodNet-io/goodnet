/// @file   tests/unit/sdk/test_strategy_plugin_macro.cpp
/// @brief  Coverage for `sdk/extensions/strategy.h` + `sdk/cpp/
///         strategy_plugin.hpp` (Слайс 9-SDK foundation).
///
/// The `GN_STRATEGY_PLUGIN` macro expands at file scope, emitting
/// `gn_plugin_*` extern "C" symbols that would clash with any other
/// translation unit in this gtest binary. Following the
/// `test_dsl_helpers.cpp` convention, the macro itself is NOT
/// invoked here — its real-world coverage comes from the future
/// `plugins/strategies/float_send_rtt` plugin (Слайс 9-RTT).
///
/// What this file DOES cover:
///   1. C ABI shape — `gn_strategy_api_t` and helpers compile as C++.
///   2. SFINAE traits in `gn::sdk::detail` — required vs optional
///      method detection across two synthetic strategy class shapes.
///   3. Vtable dispatch — register a hand-built `gn_strategy_api_t`
///      via `host_api->register_extension`, query through
///      `query_extension_checked`, invoke `pick_conn` /
///      `on_path_event` slots end-to-end.
///   4. Auto-stub for missing optional `on_path_event` — strategies
///      that omit it still satisfy the vtable contract through the
///      macro-generated thunk (covered indirectly: the SFINAE
///      `if constexpr` returns GN_OK when the method is absent).

#include <gtest/gtest.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>

#include <core/kernel/host_api_builder.hpp>
#include <core/kernel/kernel.hpp>
#include <core/kernel/plugin_context.hpp>

#include <sdk/cpp/strategy_plugin.hpp>
#include <sdk/extensions/strategy.h>
#include <sdk/host_api.h>
#include <sdk/types.h>

using gn::core::Kernel;
using gn::core::PluginContext;
using gn::core::build_host_api;

namespace {

PluginContext make_ctx(Kernel& k) {
    PluginContext ctx;
    ctx.kernel        = &k;
    ctx.kind          = GN_PLUGIN_KIND_STRATEGY;
    ctx.plugin_name   = "test-strategy";
    ctx.plugin_anchor = std::make_shared<gn::core::PluginAnchor>();
    return ctx;
}

/// Synthetic strategy class that implements every optional hook —
/// drives the maximum SFINAE coverage path.
struct FullStrategy {
    explicit FullStrategy(const host_api_t*) {}

    static constexpr const char* extension_name() noexcept {
        return "gn.strategy.full-test";
    }
    static constexpr std::uint32_t extension_version() noexcept {
        return 0x00010000U;
    }

    gn_result_t pick_conn(const std::uint8_t*,
                           const gn_path_sample_t* candidates,
                           std::size_t count,
                           gn_conn_id_t* out) {
        if (!candidates || count == 0 || !out) return GN_ERR_NULL_ARG;
        *out = candidates[0].conn;
        return GN_OK;
    }

    gn_result_t on_path_event(const std::uint8_t*,
                                gn_path_event_t,
                                const gn_path_sample_t*) {
        return GN_OK;
    }

    void on_init() {}
    void on_shutdown() {}
};

/// Synthetic strategy class with the minimum required surface —
/// drives the SFINAE "method absent" branch.
struct MinimalStrategy {
    explicit MinimalStrategy(const host_api_t*) {}

    static constexpr const char* extension_name() noexcept {
        return "gn.strategy.minimal-test";
    }
    static constexpr std::uint32_t extension_version() noexcept {
        return 0x00010000U;
    }

    gn_result_t pick_conn(const std::uint8_t*,
                           const gn_path_sample_t*,
                           std::size_t,
                           gn_conn_id_t*) {
        return GN_OK;
    }
};

}  // namespace

// ─── Compile-time invariants ──────────────────────────────────────

/// The required-symbol probe must accept both shapes; the optional-
/// hook probe distinguishes between them. `if constexpr` consumes
/// these directly at macro expansion time — exercising them here as
/// `static_assert` proves the trait predicates work outside the
/// macro context too.
static_assert(::gn::sdk::detail::strategy_has_required_v<FullStrategy>,
               "FullStrategy must satisfy strategy_has_required_v");
static_assert(::gn::sdk::detail::strategy_has_required_v<MinimalStrategy>,
               "MinimalStrategy must satisfy strategy_has_required_v");

/// `pick_conn_dispatch` must compile for both shapes — `MinimalStrategy`
/// lacks `on_path_event`, but pick_conn is unconditional.
TEST(StrategyMacro, DispatchHelpersCompileForBothShapes) {
    FullStrategy full(nullptr);
    MinimalStrategy minimal(nullptr);

    std::uint8_t pk[GN_PUBLIC_KEY_BYTES] = {1};
    gn_path_sample_t one{};
    one.conn   = 0x1234;
    one.rtt_us = 100;
    gn_conn_id_t out = GN_INVALID_ID;

    EXPECT_EQ(::gn::sdk::detail::pick_conn_dispatch(full, pk, &one, 1, &out),
              GN_OK);
    EXPECT_EQ(out, 0x1234u);

    out = GN_INVALID_ID;
    EXPECT_EQ(::gn::sdk::detail::pick_conn_dispatch(minimal, pk, &one, 1, &out),
              GN_OK);

    /// `on_path_event_dispatch` returns GN_OK when the class lacks the
    /// method — the macro-generated thunk relies on this so the vtable
    /// slot stays callable regardless of class shape.
    EXPECT_EQ(::gn::sdk::detail::on_path_event_dispatch(
                  minimal, pk, GN_PATH_EVENT_RTT_UPDATE, &one),
              GN_OK);
    EXPECT_EQ(::gn::sdk::detail::on_path_event_dispatch(
                  full, pk, GN_PATH_EVENT_CONN_UP, &one),
              GN_OK);
}

TEST(StrategyMacro, PickConnNullArgsAreRejected) {
    FullStrategy s(nullptr);
    std::uint8_t pk[GN_PUBLIC_KEY_BYTES] = {2};
    gn_path_sample_t cand{};
    gn_conn_id_t out = GN_INVALID_ID;

    EXPECT_EQ(::gn::sdk::detail::pick_conn_dispatch(s, nullptr, &cand, 1, &out),
              GN_ERR_NULL_ARG);
    EXPECT_EQ(::gn::sdk::detail::pick_conn_dispatch(s, pk, nullptr, 1, &out),
              GN_ERR_NULL_ARG);
    EXPECT_EQ(::gn::sdk::detail::pick_conn_dispatch(s, pk, &cand, 0, &out),
              GN_ERR_NULL_ARG);
    EXPECT_EQ(::gn::sdk::detail::pick_conn_dispatch(s, pk, &cand, 1, nullptr),
              GN_ERR_NULL_ARG);
}

// ─── End-to-end extension registration ────────────────────────────

namespace {

struct StrategyCallCounters {
    std::atomic<int>          pick_calls{0};
    std::atomic<int>          event_calls{0};
    std::atomic<gn_conn_id_t> last_pick{GN_INVALID_ID};
    std::atomic<int>          last_event_kind{-1};
};

gn_result_t fake_pick_conn(
    void* ctx, const std::uint8_t*,
    const gn_path_sample_t* candidates,
    std::size_t count, gn_conn_id_t* out) {
    auto* c = static_cast<StrategyCallCounters*>(ctx);
    c->pick_calls.fetch_add(1, std::memory_order_relaxed);
    if (!candidates || count == 0 || !out) return GN_ERR_NULL_ARG;
    *out = candidates[count - 1].conn;
    c->last_pick.store(*out, std::memory_order_relaxed);
    return GN_OK;
}

gn_result_t fake_on_path_event(
    void* ctx, const std::uint8_t*,
    gn_path_event_t ev, const gn_path_sample_t*) {
    auto* c = static_cast<StrategyCallCounters*>(ctx);
    c->event_calls.fetch_add(1, std::memory_order_relaxed);
    c->last_event_kind.store(static_cast<int>(ev), std::memory_order_relaxed);
    return GN_OK;
}

}  // namespace

TEST(StrategyExtension, RegisterQueryDispatchRoundtrip) {
    Kernel k;
    auto ctx = make_ctx(k);
    auto api = build_host_api(ctx);

    StrategyCallCounters fake;
    gn_strategy_api_t vt{};
    vt.api_size      = sizeof(vt);
    vt.pick_conn     = &fake_pick_conn;
    vt.on_path_event = &fake_on_path_event;
    vt.ctx           = &fake;

    /// Register under a per-test unique name so concurrent test
    /// translation units cannot collide.
    constexpr const char* kName = "gn.strategy.roundtrip-test";
    ASSERT_EQ(api.register_extension(&ctx, kName,
                                       GN_EXT_STRATEGY_VERSION, &vt),
              GN_OK);

    /// Query through the size-checked path. The minimum acceptable
    /// `api_size` matches the producer's snapshot exactly — older
    /// consumers asking for a smaller struct still get the same
    /// pointer because the kernel's check is "registered >= requested".
    const void* out = nullptr;
    ASSERT_EQ(api.query_extension_checked(
                  &ctx, kName, GN_EXT_STRATEGY_VERSION, &out),
              GN_OK);
    ASSERT_NE(out, nullptr);
    const auto* queried = static_cast<const gn_strategy_api_t*>(out);
    EXPECT_GE(queried->api_size, sizeof(gn_strategy_api_t));
    EXPECT_EQ(queried->ctx, &fake);

    /// Dispatch `pick_conn` through the queried vtable.
    std::uint8_t pk[GN_PUBLIC_KEY_BYTES] = {0xAB};
    gn_path_sample_t pool[2]{};
    pool[0].conn   = 0xC0DE0001;
    pool[0].rtt_us = 500;
    pool[1].conn   = 0xC0DE0002;
    pool[1].rtt_us = 200;
    gn_conn_id_t chosen = GN_INVALID_ID;
    ASSERT_EQ(queried->pick_conn(queried->ctx, pk, pool, 2, &chosen), GN_OK);
    EXPECT_EQ(chosen, 0xC0DE0002u);
    EXPECT_EQ(fake.pick_calls.load(), 1);
    EXPECT_EQ(fake.last_pick.load(), 0xC0DE0002u);

    /// And `on_path_event` — null sample is permitted for CONN_DOWN
    /// per the contract.
    ASSERT_EQ(queried->on_path_event(queried->ctx, pk,
                                       GN_PATH_EVENT_CONN_DOWN, nullptr),
              GN_OK);
    EXPECT_EQ(fake.event_calls.load(), 1);
    EXPECT_EQ(fake.last_event_kind.load(),
              static_cast<int>(GN_PATH_EVENT_CONN_DOWN));

    (void)api.unregister_extension(&ctx, kName);

    /// Post-unregister: query must report "not found" so the kernel
    /// dispatch path can fall back to plain priority-ordering.
    out = nullptr;
    EXPECT_NE(api.query_extension_checked(
                  &ctx, kName, GN_EXT_STRATEGY_VERSION, &out),
              GN_OK);
}

TEST(StrategyExtension, ApiSizeFirstInvariantHolds) {
    /// `GN_VTABLE_API_SIZE_FIRST` in the strategy header expands to a
    /// static_assert that puts `api_size` at byte offset zero —
    /// mandatory so older consumers can read the size prefix without
    /// knowing the rest of the struct layout. The static_assert fires
    /// at header inclusion time; this test simply confirms the runtime
    /// invariant matches the compile-time one.
    EXPECT_EQ(offsetof(gn_strategy_api_t, api_size), 0u);
    EXPECT_GE(sizeof(gn_strategy_api_t),
              sizeof(std::uint32_t) + 3 * sizeof(void*));
}
