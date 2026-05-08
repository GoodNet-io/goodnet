/// @file   tests/integration/test_metrics_thunks.cpp
/// @brief  `host_api->emit_counter` + `iterate_counters` slot wiring.
///
/// Drives the metrics surface through the public host_api the same
/// way a plugin would: emit a counter, then iterate to read it
/// back. Pins the contract from `metrics.md` end-to-end through
/// `build_host_api` rather than against the in-process
/// `MetricsRegistry` directly.

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <unordered_map>

#include <core/kernel/host_api_builder.hpp>
#include <core/kernel/kernel.hpp>
#include <core/kernel/plugin_context.hpp>

#include <sdk/host_api.h>
#include <sdk/limits.h>
#include <sdk/metrics.h>
#include <sdk/types.h>

using gn::core::Kernel;
using gn::core::PluginAnchor;
using gn::core::PluginContext;
using gn::core::build_host_api;

namespace {

struct Bag {
    std::unordered_map<std::string, std::uint64_t> seen;
};

/// Visitor that collects every `(name, value)` pair into the bag.
/// Returns 0 to keep iteration going.
std::int32_t collect(void* ud, const char* name, std::uint64_t value) {
    auto* b = static_cast<Bag*>(ud);
    b->seen[std::string(name)] = value;
    return 0;
}

PluginContext make_ctx(Kernel& k) {
    PluginContext ctx;
    ctx.kernel        = &k;
    ctx.kind          = GN_PLUGIN_KIND_HANDLER;
    ctx.plugin_name   = "metrics-fixture";
    ctx.plugin_anchor = std::make_shared<PluginAnchor>();
    return ctx;
}

}  // namespace

TEST(HostApiMetrics, EmitCounterIncrementsThroughThunk) {
    Kernel k;
    auto ctx = make_ctx(k);
    auto api = build_host_api(ctx);

    ASSERT_NE(api.emit_counter, nullptr);
    ASSERT_NE(api.iterate_counters, nullptr);

    api.emit_counter(api.host_ctx, "plugin.test.events");
    api.emit_counter(api.host_ctx, "plugin.test.events");
    api.emit_counter(api.host_ctx, "plugin.test.errors");

    Bag bag;
    const auto visited = api.iterate_counters(
        api.host_ctx, &collect, &bag);
    /// `metrics.cardinality_rejected` is pre-created (Wave 9.1)
    /// and surfaces in iteration even when zero — the exporter
    /// always sees `=0` rather than missing-on-healthy. Drop it
    /// before counting the test's own contribution.
    bag.seen.erase("metrics.cardinality_rejected");
    EXPECT_EQ(visited, 3u)
        << "iterate sees the test's two counters + the pre-created "
           "cardinality_rejected sentinel";
    EXPECT_EQ(bag.seen.size(), 2u);
    EXPECT_EQ(bag.seen["plugin.test.events"], 2u);
    EXPECT_EQ(bag.seen["plugin.test.errors"], 1u);
}

TEST(HostApiMetrics, NullNameIsDroppedSilently) {
    Kernel k;
    auto ctx = make_ctx(k);
    auto api = build_host_api(ctx);

    api.emit_counter(api.host_ctx, nullptr);  // must not crash

    Bag bag;
    const auto visited = api.iterate_counters(
        api.host_ctx, &collect, &bag);
    /// `metrics.cardinality_rejected` is pre-created — visited
    /// reports 1, not 0.
    bag.seen.erase("metrics.cardinality_rejected");
    EXPECT_EQ(visited, 1u);
    EXPECT_TRUE(bag.seen.empty());
}

TEST(HostApiMetrics, FrameTooLargeBumpsDropCounter) {
    /// `notify_inbound_bytes` rejects frames above `max_frame_bytes`
    /// per `host-api.md`. Per `metrics.md` §3 the rejection is paired
    /// with both a counter increment (`drop.frame_too_large`) and a
    /// structured warn line carrying `(conn, observed, configured)`.
    /// This test covers the counter half so dashboards see the rate.
    Kernel k;
    PluginContext ctx;
    ctx.kernel        = &k;
    ctx.kind          = GN_PLUGIN_KIND_LINK;
    ctx.plugin_name   = "frame-cap-fixture";
    ctx.plugin_anchor = std::make_shared<PluginAnchor>();

    /// A tight cap so the test sends a tiny over-cap buffer instead
    /// of allocating megabytes.
    gn_limits_t limits{};
    limits.max_frame_bytes = 64;
    k.set_limits(limits);

    auto api = build_host_api(ctx);

    const std::array<std::uint8_t, 128> big{};
    EXPECT_EQ(
        api.notify_inbound_bytes(api.host_ctx, /*conn=*/1,
                                  big.data(), big.size()),
        GN_ERR_PAYLOAD_TOO_LARGE);

    EXPECT_EQ(k.metrics().value("drop.frame_too_large"), 1u);
}

TEST(HostApiMetrics, IteratorVisitorMaySignalEarlyExit) {
    Kernel k;
    auto ctx = make_ctx(k);
    auto api = build_host_api(ctx);

    for (int i = 0; i < 5; ++i) {
        const auto name = "p" + std::to_string(i);
        api.emit_counter(api.host_ctx, name.c_str());
    }

    int count = 0;
    const auto visited = api.iterate_counters(
        api.host_ctx,
        +[](void* ud, const char*, std::uint64_t) -> std::int32_t {
            auto* c = static_cast<int*>(ud);
            ++(*c);
            return *c == 3 ? 1 : 0;
        },
        &count);
    EXPECT_EQ(count, 3);
    EXPECT_EQ(visited, 3u);
}
