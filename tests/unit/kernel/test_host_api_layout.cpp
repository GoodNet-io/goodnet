/// @file   tests/unit/kernel/test_host_api_layout.cpp
/// @brief  Runtime pin: every `host_api_t` slot the kernel hands a
///         plugin is populated and the `api_size` self-report matches
///         the producer-side `sizeof`.
///
/// `tests/abi/test_layout.c` pins offsets and the total `sizeof` at
/// compile time. That catches header-side reshuffles but does not
/// catch the symmetric failure mode: a refactor that adds a new slot
/// to `host_api.h`, updates the offsets, but forgets to wire it up
/// inside `host_api_builder.cpp`. The plugin would receive a NULL
/// function pointer and crash on first call.
///
/// This test file builds a real `host_api_t` through `build_host_api`
/// and walks every slot the contract requires. A new slot added
/// without wiring fails here loudly instead of in production.

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string_view>

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

/// Build a host_api against a fresh kernel + plugin context. The
/// plugin kind is `HANDLER` so the builder takes the unrestricted
/// path; security-only or link-only contexts gate a few slots
/// behind kind checks the layout pin should not exercise.
host_api_t fresh_api(Kernel& k, PluginContext& ctx) {
    ctx.kernel        = &k;
    ctx.kind          = GN_PLUGIN_KIND_HANDLER;
    ctx.plugin_name   = "host-api-layout-fixture";
    ctx.plugin_anchor = std::make_shared<PluginAnchor>();
    return build_host_api(ctx);
}

}  // namespace

TEST(HostApiLayout, ApiSizeMatchesProducerSizeof) {
    /// `api_size` is the size-prefix every consumer reads to gate
    /// `GN_API_HAS` checks. A drift between this field and the real
    /// `sizeof(host_api_t)` would silently mask out tail slots a
    /// plugin compiled against the same SDK should still see.
    Kernel k;
    PluginContext ctx;
    auto api = fresh_api(k, ctx);
    EXPECT_EQ(api.api_size, sizeof(host_api_t));
}

TEST(HostApiLayout, HostCtxPopulated) {
    Kernel k;
    PluginContext ctx;
    auto api = fresh_api(k, ctx);
    EXPECT_NE(api.host_ctx, nullptr);
}

TEST(HostApiLayout, EveryFunctionPointerSlotPopulated) {
    /// Walk every slot the contract requires. A new slot landing in
    /// `sdk/host_api.h` without a matching write in
    /// `host_api_builder.cpp` surfaces here as a NULL pointer.
    Kernel k;
    PluginContext ctx;
    auto api = fresh_api(k, ctx);

    EXPECT_NE(api.send,                     nullptr) << "send";
    EXPECT_NE(api.disconnect,               nullptr) << "disconnect";
    EXPECT_NE(api.register_vtable,          nullptr) << "register_vtable";
    EXPECT_NE(api.unregister_vtable,        nullptr) << "unregister_vtable";
    EXPECT_NE(api.find_conn_by_pk,          nullptr) << "find_conn_by_pk";
    EXPECT_NE(api.get_endpoint,             nullptr) << "get_endpoint";
    EXPECT_NE(api.query_extension_checked,  nullptr) << "query_extension_checked";
    EXPECT_NE(api.register_extension,       nullptr) << "register_extension";
    EXPECT_NE(api.unregister_extension,     nullptr) << "unregister_extension";
    EXPECT_NE(api.config_get,               nullptr) << "config_get";
    EXPECT_NE(api.limits,                   nullptr) << "limits";
    EXPECT_NE(api.notify_connect,           nullptr) << "notify_connect";
    EXPECT_NE(api.notify_disconnect,        nullptr) << "notify_disconnect";
    EXPECT_NE(api.notify_inbound_bytes,     nullptr) << "notify_inbound_bytes";
    EXPECT_NE(api.kick_handshake,           nullptr) << "kick_handshake";
    EXPECT_NE(api.register_security,        nullptr) << "register_security";
    EXPECT_NE(api.unregister_security,      nullptr) << "unregister_security";
    EXPECT_NE(api.subscribe,                nullptr) << "subscribe";
    EXPECT_NE(api.unsubscribe,              nullptr) << "unsubscribe";
    EXPECT_NE(api.set_timer,                nullptr) << "set_timer";
    EXPECT_NE(api.cancel_timer,             nullptr) << "cancel_timer";
    EXPECT_NE(api.inject,                   nullptr) << "inject";
    EXPECT_NE(api.for_each_connection,      nullptr) << "for_each_connection";
    EXPECT_NE(api.notify_backpressure,      nullptr) << "notify_backpressure";
    EXPECT_NE(api.emit_counter,             nullptr) << "emit_counter";
    EXPECT_NE(api.iterate_counters,         nullptr) << "iterate_counters";
    EXPECT_NE(api.is_shutdown_requested,    nullptr) << "is_shutdown_requested";
}

TEST(HostApiLayout, LogVtablePopulated) {
    /// `host_api_t::log` is a sub-struct, not a function pointer
    /// slot. Both of its entries must be wired before any plugin
    /// uses them — the kernel routes through `should_log` first
    /// to short-circuit hot-path formatting.
    Kernel k;
    PluginContext ctx;
    auto api = fresh_api(k, ctx);

    EXPECT_GE(api.log.api_size, sizeof(api.log)) << "log.api_size";
    EXPECT_NE(api.log.should_log, nullptr)        << "log.should_log";
    EXPECT_NE(api.log.emit,       nullptr)        << "log.emit";
}

TEST(HostApiLayout, ReservedTailZeroed) {
    /// `_reserved` slots MUST be zero in the produced table per
    /// `abi-evolution.md` §4. A non-zero slot would mean the builder
    /// wrote past the contract's named tail; a future SDK that
    /// promotes a reserved slot to a real entry would inherit
    /// garbage.
    Kernel k;
    PluginContext ctx;
    auto api = fresh_api(k, ctx);

    for (std::size_t i = 0; i < std::size(api._reserved); ++i) {
        EXPECT_EQ(api._reserved[i], nullptr)
            << "_reserved[" << i << "] not zero";
    }
}

TEST(HostApiLayout, IndependentBuildsProduceIdenticalShape) {
    /// Two builds against two distinct kernels must report the same
    /// `api_size`. Catches a TU-local `#ifdef` drift that would
    /// silently produce different table sizes for different plugins
    /// loaded into the same kernel.
    Kernel k1, k2;
    PluginContext c1, c2;
    auto a1 = fresh_api(k1, c1);
    auto a2 = fresh_api(k2, c2);
    EXPECT_EQ(a1.api_size, a2.api_size);
}
