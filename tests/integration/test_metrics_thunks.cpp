/// @file   tests/integration/test_metrics_thunks.cpp
/// @brief  `host_api->emit_counter` + `iterate_counters` slot wiring.
///
/// Drives the metrics surface through the public host_api the same
/// way a plugin would: emit a counter, then iterate to read it
/// back. Pins the contract from `metrics.md` end-to-end through
/// `build_host_api` rather than against the in-process
/// `MetricsRegistry` directly.

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <unordered_map>

#include <core/kernel/host_api_builder.hpp>
#include <core/kernel/kernel.hpp>
#include <core/kernel/plugin_context.hpp>

#include <sdk/host_api.h>
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
    EXPECT_EQ(visited, 2u);
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
    EXPECT_EQ(visited, 0u);
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
