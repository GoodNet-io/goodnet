/// @file   tests/unit/kernel/test_plugin_anchor.cpp
/// @brief  PluginAnchor + GateGuard cooperative-cancellation
///         semantics per `plugin-lifetime.md` §4 and §8.
///
/// Pins:
///   * GateGuard refuses on a stale anchor;
///   * GateGuard refuses once `shutdown_requested` was published;
///   * `in_flight` counts engaged guards and decays on release;
///   * the host_api `is_shutdown_requested` slot mirrors the flag;
///   * a timer scheduled before shutdown but fired after has its
///     callback dropped — counter stays at 0.

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <memory>
#include <thread>

#include <core/kernel/host_api_builder.hpp>
#include <core/kernel/kernel.hpp>
#include <core/kernel/plugin_anchor.hpp>
#include <core/kernel/plugin_context.hpp>
#include <core/kernel/timer_registry.hpp>

#include <sdk/host_api.h>
#include <sdk/plugin.h>
#include <sdk/types.h>

using namespace gn::core;

namespace {

bool wait_for(auto&& predicate,
              std::chrono::milliseconds timeout = std::chrono::seconds{2}) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (predicate()) return true;
        std::this_thread::sleep_for(std::chrono::microseconds{100});
    }
    return predicate();
}

}  // namespace

// ── GateGuard semantics ──────────────────────────────────────────────────

TEST(PluginAnchor, GateRefusesExpiredAnchor) {
    auto anchor = std::make_shared<PluginAnchor>();
    auto weak   = std::weak_ptr<PluginAnchor>(anchor);
    anchor.reset();

    auto guard = GateGuard::acquire(weak);
    EXPECT_FALSE(guard.has_value())
        << "expired anchor must yield nullopt";
}

TEST(PluginAnchor, GateRefusesAfterShutdownPublished) {
    auto anchor = std::make_shared<PluginAnchor>();
    anchor->shutdown_requested.store(true, std::memory_order_release);

    auto guard = GateGuard::acquire(std::weak_ptr<PluginAnchor>(anchor));
    EXPECT_FALSE(guard.has_value())
        << "shutdown_requested must refuse new acquisitions";
    EXPECT_EQ(anchor->in_flight.load(), 0u)
        << "refused acquire must not leak the in_flight increment";
}

TEST(PluginAnchor, EngagedGuardIncrementsInFlight) {
    auto anchor = std::make_shared<PluginAnchor>();

    {
        auto g = GateGuard::acquire(std::weak_ptr<PluginAnchor>(anchor));
        ASSERT_TRUE(g.has_value());
        EXPECT_EQ(anchor->in_flight.load(), 1u);

        {
            auto h = GateGuard::acquire(std::weak_ptr<PluginAnchor>(anchor));
            ASSERT_TRUE(h.has_value());
            EXPECT_EQ(anchor->in_flight.load(), 2u)
                << "concurrent guards stack";
        }
        EXPECT_EQ(anchor->in_flight.load(), 1u)
            << "inner release drops to one";
    }
    EXPECT_EQ(anchor->in_flight.load(), 0u)
        << "all guards released";
}

TEST(PluginAnchor, GuardMoveDoesNotDoubleRelease) {
    auto anchor = std::make_shared<PluginAnchor>();
    {
        auto g = GateGuard::acquire(std::weak_ptr<PluginAnchor>(anchor));
        ASSERT_TRUE(g.has_value());
        ASSERT_EQ(anchor->in_flight.load(), 1u);

        if (g.has_value()) {
            /// Move out of the optional; the source is now disengaged.
            GateGuard moved = std::move(*g);
            EXPECT_EQ(anchor->in_flight.load(), 1u)
                << "move transfers ownership; counter unchanged";
        }
    }
    EXPECT_EQ(anchor->in_flight.load(), 0u)
        << "exactly one release happens at the moved-to scope exit";
}

// ── host_api `is_shutdown_requested` thunk ───────────────────────────────

TEST(PluginAnchor, IsShutdownRequestedReflectsFlag) {
    Kernel k;
    PluginContext ctx;
    ctx.kernel        = &k;
    ctx.kind          = GN_PLUGIN_KIND_HANDLER;
    ctx.plugin_name   = "anchor-fixture";
    ctx.plugin_anchor = std::make_shared<PluginAnchor>();

    auto api = build_host_api(ctx);
    ASSERT_NE(api.is_shutdown_requested, nullptr)
        << "slot must be wired in build_host_api";

    EXPECT_EQ(api.is_shutdown_requested(&ctx), 0)
        << "fresh anchor reports no shutdown";

    ctx.plugin_anchor->shutdown_requested.store(true,
        std::memory_order_release);
    EXPECT_NE(api.is_shutdown_requested(&ctx), 0)
        << "published flag is observable through the slot";
}

TEST(PluginAnchor, IsShutdownRequestedSafeWithoutAnchor) {
    Kernel k;
    PluginContext ctx;
    ctx.kernel      = &k;
    ctx.kind        = GN_PLUGIN_KIND_HANDLER;
    ctx.plugin_name = "no-anchor";
    /// In-tree fixture convention: no anchor at all.

    auto api = build_host_api(ctx);
    EXPECT_EQ(api.is_shutdown_requested(&ctx), 0)
        << "missing anchor reports no shutdown — slot must not crash";
}

// ── Timer dispatch refused after shutdown_requested ──────────────────────

TEST(PluginAnchor, TimerCallbackDroppedAfterShutdownPublished) {
    TimerRegistry r;
    auto anchor = std::make_shared<PluginAnchor>();

    std::atomic<int> hits{0};
    gn_timer_id_t id = GN_INVALID_TIMER_ID;
    ASSERT_EQ(r.set_timer(20, [](void* p) {
        static_cast<std::atomic<int>*>(p)->fetch_add(1);
    }, &hits, anchor, &id), GN_OK);

    /// Publish shutdown before the timer fires. The anchor is still
    /// alive (we hold the strong ref), so the gate's weak.lock()
    /// succeeds — but the flag check refuses, dropping the dispatch.
    anchor->shutdown_requested.store(true, std::memory_order_release);

    std::this_thread::sleep_for(std::chrono::milliseconds{60});
    EXPECT_EQ(hits.load(), 0)
        << "shutdown_requested must drop the dispatch even with live anchor";
    EXPECT_EQ(anchor->in_flight.load(), 0u)
        << "refused dispatch must not bump in_flight";
}

TEST(PluginAnchor, TimerHoldsInFlightForDurationOfDispatch) {
    TimerRegistry r;
    auto anchor = std::make_shared<PluginAnchor>();

    struct Probe {
        std::atomic<std::uint64_t>* in_flight;
        std::atomic<std::uint64_t>  observed{0};
    } probe{&anchor->in_flight, {}};

    gn_timer_id_t id = GN_INVALID_TIMER_ID;
    ASSERT_EQ(r.set_timer(5, [](void* p) {
        auto* x = static_cast<Probe*>(p);
        x->observed.store(x->in_flight->load(),
                          std::memory_order_relaxed);
    }, &probe, anchor, &id), GN_OK);

    EXPECT_TRUE(wait_for([&] {
        return probe.observed.load(std::memory_order_relaxed) == 1u;
    }))
        << "in_flight must read 1 from inside the dispatched callback";
    /// Counter drops back after the dispatch returns.
    EXPECT_EQ(anchor->in_flight.load(), 0u);
}

// ── §10 latch persistence ────────────────────────────────────────────────

TEST(PluginAnchor, IsShutdownRequestedLatchesAcrossRepeatedCalls) {
    Kernel k;
    PluginContext ctx;
    ctx.kernel        = &k;
    ctx.kind          = GN_PLUGIN_KIND_HANDLER;
    ctx.plugin_name   = "latch";
    ctx.plugin_anchor = std::make_shared<PluginAnchor>();

    auto api = build_host_api(ctx);
    EXPECT_EQ(api.is_shutdown_requested(&ctx), 0);

    ctx.plugin_anchor->shutdown_requested.store(true,
        std::memory_order_release);

    /// `host-api.md` §10: once set, every subsequent call returns
    /// non-zero through the rest of the plugin's lifetime.
    for (int i = 0; i < 16; ++i) {
        EXPECT_NE(api.is_shutdown_requested(&ctx), 0)
            << "latch must hold across repeated reads (i=" << i << ')';
    }
}

// ── Happy path: gate released before deadline, no timeout ────────────────

TEST(PluginAnchor, GateReleaseBeforeDeadlineLetsObserverExpire) {
    auto anchor = std::make_shared<PluginAnchor>();
    auto watch  = std::weak_ptr<PluginAnchor>(anchor);

    auto guard = GateGuard::acquire(watch);
    ASSERT_TRUE(guard.has_value());
    EXPECT_EQ(anchor->in_flight.load(), 1u);
    EXPECT_FALSE(watch.expired())
        << "guard's strong ref keeps the observer alive";

    /// Release the guard, then drop the only other strong ref.
    /// `weak_ptr::expired()` must flip true — the drain spin would
    /// observe quiescence on the next iteration without timing out.
    guard.reset();
    EXPECT_EQ(anchor->in_flight.load(), 0u);
    anchor.reset();
    EXPECT_TRUE(watch.expired())
        << "all strong refs released; drain would exit cleanly";
}

// ── Multi-thread refuse after publish ────────────────────────────────────

TEST(PluginAnchor, ConcurrentAcquireAfterPublishAllRefused) {
    auto anchor = std::make_shared<PluginAnchor>();
    anchor->shutdown_requested.store(true, std::memory_order_release);

    constexpr int kThreads = 8;
    constexpr int kPerThread = 256;
    std::atomic<int> refused{0};
    std::atomic<int> acquired{0};

    std::vector<std::thread> workers;
    workers.reserve(kThreads);
    for (int i = 0; i < kThreads; ++i) {
        workers.emplace_back([&] {
            auto weak = std::weak_ptr<PluginAnchor>(anchor);
            for (int j = 0; j < kPerThread; ++j) {
                auto g = GateGuard::acquire(weak);
                if (g) {
                    acquired.fetch_add(1, std::memory_order_relaxed);
                } else {
                    refused.fetch_add(1, std::memory_order_relaxed);
                }
            }
        });
    }
    for (auto& w : workers) w.join();

    EXPECT_EQ(acquired.load(), 0)
        << "every acquire after publish must refuse";
    EXPECT_EQ(refused.load(), kThreads * kPerThread);
    EXPECT_EQ(anchor->in_flight.load(), 0u)
        << "no leaked in_flight increments from refused acquires";
}
