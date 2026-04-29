/// @file   tests/unit/kernel/test_metrics_registry.cpp
/// @brief  Pin the kernel's named-counter store invariants per
///         `metrics.md`: increment is monotonic, iterate visits
///         every counter once, name lookup is heterogenous,
///         RouteOutcome/drop_reason names are stable.

#include <gtest/gtest.h>

#include <atomic>
#include <cstdint>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include <core/kernel/metrics_registry.hpp>
#include <core/kernel/router.hpp>

#include <sdk/types.h>

namespace gn::core {
namespace {

// ─── Basic increment / read ────────────────────────────────────────

TEST(MetricsRegistry, IncrementCreatesAndIncrements) {
    MetricsRegistry m;
    EXPECT_EQ(m.value("plugin.heartbeat.ticks"), 0u);

    m.increment("plugin.heartbeat.ticks");
    m.increment("plugin.heartbeat.ticks");
    m.increment("plugin.heartbeat.ticks");
    EXPECT_EQ(m.value("plugin.heartbeat.ticks"), 3u);
}

TEST(MetricsRegistry, ReadOfMissingCounterReturnsZero) {
    MetricsRegistry m;
    EXPECT_EQ(m.value("never.touched.counter"), 0u);
}

TEST(MetricsRegistry, EachCounterHoldsIndependentValue) {
    MetricsRegistry m;
    m.increment("a");
    m.increment("b");
    m.increment("b");
    m.increment("c");
    m.increment("c");
    m.increment("c");

    EXPECT_EQ(m.value("a"), 1u);
    EXPECT_EQ(m.value("b"), 2u);
    EXPECT_EQ(m.value("c"), 3u);
}

// ─── Iteration ─────────────────────────────────────────────────────

TEST(MetricsRegistry, ForEachVisitsEveryCounterOnce) {
    MetricsRegistry m;
    m.increment("alpha");
    m.increment("alpha");
    m.increment("beta");

    std::unordered_map<std::string, std::uint64_t> seen;
    m.for_each([&](std::string_view name, std::uint64_t v) {
        seen[std::string(name)] = v;
    });

    EXPECT_EQ(seen.size(), 2u);
    EXPECT_EQ(seen["alpha"], 2u);
    EXPECT_EQ(seen["beta"], 1u);
}

TEST(MetricsRegistry, IterateStopsEarlyOnNonZeroVisitor) {
    MetricsRegistry m;
    for (int i = 0; i < 5; ++i) {
        m.increment("c" + std::to_string(i));
    }

    int seen = 0;
    const auto visited = m.iterate(
        [](void* ud, const char*, std::uint64_t) -> std::int32_t {
            auto* counter = static_cast<int*>(ud);
            ++(*counter);
            return *counter >= 2 ? 1 : 0;  // stop after the second
        },
        &seen);
    EXPECT_EQ(seen, 2);
    EXPECT_EQ(visited, 2u);
}

TEST(MetricsRegistry, IterateNullVisitorIsNoOp) {
    MetricsRegistry m;
    m.increment("ignored");
    EXPECT_EQ(m.iterate(nullptr, nullptr), 0u);
    /// Counter is still readable; iterate's no-op did not corrupt
    /// the store.
    EXPECT_EQ(m.value("ignored"), 1u);
}

// ─── Built-in enums ────────────────────────────────────────────────

TEST(MetricsRegistry, RouteOutcomeNameIsStable) {
    MetricsRegistry m;
    m.increment_route_outcome(RouteOutcome::DispatchedLocal);
    m.increment_route_outcome(RouteOutcome::DispatchedLocal);
    m.increment_route_outcome(RouteOutcome::Rejected);

    EXPECT_EQ(m.value("route.outcome.dispatched_local"), 2u);
    EXPECT_EQ(m.value("route.outcome.rejected"), 1u);
    EXPECT_EQ(m.value("route.outcome.dispatched_broadcast"), 0u);
}

TEST(MetricsRegistry, DropReasonNameIsStable) {
    MetricsRegistry m;
    m.increment_drop_reason(GN_DROP_FRAME_TOO_LARGE);
    m.increment_drop_reason(GN_DROP_RATE_LIMITED);
    m.increment_drop_reason(GN_DROP_RATE_LIMITED);

    EXPECT_EQ(m.value("drop.frame_too_large"), 1u);
    EXPECT_EQ(m.value("drop.rate_limited"), 2u);
}

// ─── Concurrency ───────────────────────────────────────────────────

TEST(MetricsRegistry, ConcurrentIncrementsTallyExactly) {
    MetricsRegistry m;
    constexpr int kThreads = 8;
    constexpr int kPerThread = 10'000;

    std::vector<std::thread> workers;
    workers.reserve(kThreads);
    for (int t = 0; t < kThreads; ++t) {
        workers.emplace_back([&] {
            for (int i = 0; i < kPerThread; ++i) {
                m.increment("hot.counter");
            }
        });
    }
    for (auto& w : workers) w.join();
    EXPECT_EQ(m.value("hot.counter"),
              static_cast<std::uint64_t>(kThreads) * kPerThread);
}

}  // namespace
}  // namespace gn::core
