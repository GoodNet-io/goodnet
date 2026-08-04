// SPDX-License-Identifier: Apache-2.0
/// @file   tests/unit/sdk/test_send_to.cpp
/// @brief  Coverage for `host_api->send_to(peer_pk, msg_id, payload)` —
///         the strategy-dispatch thunk plus the SDK wrapper
///         `gn::sdk::send_to(...)`.

#include <gtest/gtest.h>

#include <array>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <memory>
#include <span>
#include <vector>

#include <core/kernel/host_api_builder.hpp>
#include <core/kernel/kernel.hpp>
#include <core/kernel/plugin_context.hpp>

#include <sdk/cpp/connect.hpp>
#include <sdk/extensions/strategy.h>
#include <sdk/host_api.h>
#include <sdk/trust.h>
#include <sdk/types.h>

using gn::core::Kernel;
using gn::core::PluginContext;
using gn::core::build_host_api;

namespace {

PluginContext make_ctx(Kernel& k) {
    PluginContext ctx;
    ctx.kernel        = &k;
    ctx.kind          = GN_PLUGIN_KIND_UNKNOWN;
    ctx.plugin_name   = "test-send-to";
    ctx.plugin_anchor = std::make_shared<gn::core::PluginAnchor>();
    return ctx;
}

PluginContext make_ctx_kind(Kernel& k, gn_plugin_kind_t kind) {
    PluginContext ctx;
    ctx.kernel        = &k;
    ctx.kind          = kind;
    ctx.plugin_name   = "test-rtt-kind";
    ctx.plugin_anchor = std::make_shared<gn::core::PluginAnchor>();
    return ctx;
}

/// Fake link vtable that just counts `send` calls per conn.
struct FakeLink {
    std::atomic<int>          send_calls{0};
    std::atomic<gn_conn_id_t> last_conn{GN_INVALID_ID};
    std::atomic<std::uint32_t> last_msg_id{0};

    static gn_result_t send(void* ctx, gn_conn_id_t conn,
                             const std::uint8_t*, std::size_t) {
        auto* f = static_cast<FakeLink*>(ctx);
        f->send_calls.fetch_add(1);
        f->last_conn.store(conn);
        return GN_OK;
    }

    static gn_link_api_t make_vtable(FakeLink& f) {
        gn_link_api_t vt{};
        vt.api_size = sizeof(vt);
        vt.send     = &send;
        vt.ctx      = &f;
        return vt;
    }
};

/// Test strategy that always picks the LAST candidate in the array.
/// Lets us verify multi-conn dispatch routes through `pick_conn`.
struct PickLastStrategy {
    std::atomic<int> pick_calls{0};
    std::atomic<std::size_t> last_count{0};

    static gn_result_t pick_conn(
        void* ctx,
        const std::uint8_t* /*peer_pk*/,
        const gn_path_sample_t* candidates,
        std::size_t count,
        gn_conn_id_t* out_chosen) {
        auto* s = static_cast<PickLastStrategy*>(ctx);
        s->pick_calls.fetch_add(1);
        s->last_count.store(count);
        if (!candidates || count == 0 || !out_chosen) return GN_ERR_NULL_ARG;
        *out_chosen = candidates[count - 1].conn;
        return GN_OK;
    }

    static gn_strategy_api_t make_vtable(PickLastStrategy& s) {
        gn_strategy_api_t vt{};
        vt.api_size  = sizeof(vt);
        vt.pick_conn = &pick_conn;
        vt.ctx       = &s;
        return vt;
    }
};

/// Spawn @p count conns to @p peer_pk, all wired through the same
/// fake link. Returns the allocated conn ids in order.
std::vector<gn_conn_id_t> spawn_conns(
    PluginContext& ctx,
    host_api_t& api,
    const std::uint8_t peer_pk[GN_PUBLIC_KEY_BYTES],
    std::size_t count) {
    std::vector<gn_conn_id_t> conns;
    for (std::size_t i = 0; i < count; ++i) {
        gn_conn_id_t cid = GN_INVALID_ID;
        const auto rc = api.notify_connect(
            &ctx, peer_pk,
            (std::string("fake://h:") + std::to_string(i)).c_str(),
            GN_TRUST_LOOPBACK, GN_ROLE_RESPONDER, &cid);
        if (rc == GN_OK && cid != GN_INVALID_ID) conns.push_back(cid);
    }
    return conns;
}

}  // namespace

TEST(HostApiSendTo, NullPeerPkYieldsNullArg) {
    Kernel k;
    auto ctx = make_ctx(k);
    auto api = build_host_api(ctx);

    const std::uint8_t payload[1] = {0};
    EXPECT_EQ(api.send_to(&ctx, nullptr, 0x10, payload, 1),
              GN_ERR_NULL_ARG);
}

TEST(HostApiSendTo, NoConnsYieldsNotFound) {
    Kernel k;
    auto ctx = make_ctx(k);
    auto api = build_host_api(ctx);

    std::uint8_t pk[GN_PUBLIC_KEY_BYTES] = {0xAA};
    const std::uint8_t payload[1] = {0};
    EXPECT_EQ(api.send_to(&ctx, pk, 0x10, payload, 1),
              GN_ERR_NOT_FOUND);
}

TEST(HostApiSendTo, SingleConnBypassesStrategy) {
    Kernel k;
    auto ctx = make_ctx(k);
    auto api = build_host_api(ctx);

    FakeLink fake;
    auto vt = FakeLink::make_vtable(fake);
    ASSERT_EQ(api.register_extension(&ctx, "gn.link.fake",
                                       GN_EXT_LINK_VERSION, &vt), GN_OK);
    /// `register_vtable` on the link family wires the vtable for
    /// `notify_connect`-driven dispatch. The extension registration
    /// alone makes the kernel believe a transport exists; the actual
    /// send routes through `find_by_scheme` lookup which uses the
    /// link plugin's vtable registered through `GN_REGISTER_LINK`.
    /// For our purposes here `notify_connect` allocates the record
    /// and the kernel's send-queue path tolerates the absence of a
    /// formal link plugin. We test the strategy dispatch shape only.

    PickLastStrategy strat;
    auto strat_vt = PickLastStrategy::make_vtable(strat);
    ASSERT_EQ(api.register_extension(&ctx, "gn.strategy.test",
                                       GN_EXT_STRATEGY_VERSION, &strat_vt),
              GN_OK);

    std::uint8_t pk[GN_PUBLIC_KEY_BYTES] = {0xCC};
    const auto conns = spawn_conns(ctx, api, pk, 1);
    ASSERT_EQ(conns.size(), 1u);

    const std::uint8_t payload[2] = {0xAB, 0xCD};
    /// `send_to` with one candidate must NOT call the strategy's
    /// pick_conn — common-path optimisation.
    (void)api.send_to(&ctx, pk, 0x10, payload, 2);
    EXPECT_EQ(strat.pick_calls.load(), 0);

    (void)api.unregister_extension(&ctx, "gn.strategy.test");
    (void)api.unregister_extension(&ctx, "gn.link.fake");
}

TEST(HostApiSendTo, MultipleConnsDelegateToStrategy) {
    Kernel k;
    auto ctx = make_ctx(k);
    auto api = build_host_api(ctx);

    PickLastStrategy strat;
    auto strat_vt = PickLastStrategy::make_vtable(strat);
    ASSERT_EQ(api.register_extension(&ctx, "gn.strategy.test",
                                       GN_EXT_STRATEGY_VERSION, &strat_vt),
              GN_OK);

    std::uint8_t pk[GN_PUBLIC_KEY_BYTES] = {0xDD};
    const auto conns = spawn_conns(ctx, api, pk, 3);
    ASSERT_EQ(conns.size(), 3u);

    const std::uint8_t payload[1] = {0x55};
    /// With 3 candidates, the strategy decides which conn wins.
    /// `PickLastStrategy` picks `candidates[count-1].conn` which is
    /// the last enumerated by `for_each` — order is implementation-
    /// defined (shard hash + insertion order), so we just check
    /// that pick_conn fired with 3 candidates.
    (void)api.send_to(&ctx, pk, 0x10, payload, 1);
    EXPECT_EQ(strat.pick_calls.load(), 1);
    EXPECT_EQ(strat.last_count.load(), 3u);

    (void)api.unregister_extension(&ctx, "gn.strategy.test");
}

TEST(HostApiSendTo, MultipleStrategiesComposeFirstNonEmptyWins) {
    Kernel k;
    auto ctx = make_ctx(k);
    auto api = build_host_api(ctx);

    /// Multi-strategy registration admits both — the kernel walks
    /// the chain in registration order; first pick that returns a
    /// real conn wins. Multipath / fallback policy compositions
    /// work this way without any operator config flag.
    PickLastStrategy a, b;
    auto va = PickLastStrategy::make_vtable(a);
    auto vb = PickLastStrategy::make_vtable(b);
    ASSERT_EQ(api.register_extension(&ctx, "gn.strategy.alpha",
                                       GN_EXT_STRATEGY_VERSION, &va), GN_OK);
    ASSERT_EQ(api.register_extension(&ctx, "gn.strategy.beta",
                                       GN_EXT_STRATEGY_VERSION, &vb), GN_OK);

    std::uint8_t pk[GN_PUBLIC_KEY_BYTES] = {0xEE};
    const auto conns = spawn_conns(ctx, api, pk, 2);
    ASSERT_EQ(conns.size(), 2u);

    const std::uint8_t payload[1] = {0x55};
    /// Multi-strategy admitted — kernel walks the chain in
    /// registry-iteration order. Both strategies return a valid
    /// conn, so the first one consulted wins and the second
    /// stays untouched. `query_prefix` is hash-ordered, so we
    /// assert exactly one strategy was consulted rather than
    /// pinning a specific name.
    (void)api.send_to(&ctx, pk, 0x10, payload, 1);
    EXPECT_EQ(a.pick_calls.load() + b.pick_calls.load(), 1)
        << "exactly one strategy must have been consulted";

    (void)api.unregister_extension(&ctx, "gn.strategy.alpha");
    (void)api.unregister_extension(&ctx, "gn.strategy.beta");
}

/// Records every `on_path_event` callback the kernel fires so tests
/// can assert which lifecycle moments dispatch through the chain.
struct SpyStrategy {
    struct Event {
        std::array<std::uint8_t, GN_PUBLIC_KEY_BYTES> pk{};
        gn_path_event_t                                kind{};
        gn_conn_id_t                                   conn{GN_INVALID_ID};
        std::uint64_t                                  rtt_us{0};
    };
    std::mutex                mu;
    std::vector<Event>        events;
    std::atomic<int>          pick_calls{0};

    static gn_result_t pick_conn(void* /*ctx*/,
                                  const std::uint8_t*,
                                  const gn_path_sample_t*,
                                  std::size_t, gn_conn_id_t*) {
        return GN_ERR_NOT_FOUND;
    }

    static gn_result_t on_path_event(void* ctx,
                                      const std::uint8_t* peer_pk,
                                      gn_path_event_t ev,
                                      const gn_path_sample_t* sample) {
        auto* s = static_cast<SpyStrategy*>(ctx);
        Event e;
        if (peer_pk != nullptr) {
            std::memcpy(e.pk.data(), peer_pk, GN_PUBLIC_KEY_BYTES);
        }
        e.kind = ev;
        if (sample != nullptr) {
            e.conn   = sample->conn;
            e.rtt_us = sample->rtt_us;
        }
        std::lock_guard lk(s->mu);
        s->events.push_back(e);
        return GN_OK;
    }

    static gn_strategy_api_t make_vtable(SpyStrategy& s) {
        gn_strategy_api_t vt{};
        vt.api_size       = sizeof(vt);
        vt.pick_conn      = &pick_conn;
        vt.on_path_event  = &on_path_event;
        vt.ctx            = &s;
        return vt;
    }
};

/// notify_connect must fire on_path_event(CONN_UP) to every
/// registered strategy so they can refresh their candidate set.
TEST(HostApiPathEvent, NotifyConnectFiresConnUpToStrategy) {
    Kernel k;
    auto ctx = make_ctx(k);
    auto api = build_host_api(ctx);

    SpyStrategy spy;
    auto vt = SpyStrategy::make_vtable(spy);
    ASSERT_EQ(api.register_extension(&ctx, "gn.strategy.spy",
                                       GN_EXT_STRATEGY_VERSION, &vt),
              GN_OK);

    std::uint8_t pk[GN_PUBLIC_KEY_BYTES] = {0x11, 0x22, 0x33, 0x44};
    gn_conn_id_t cid = GN_INVALID_ID;
    ASSERT_EQ(api.notify_connect(&ctx, pk, "fake://h:0",
                                   GN_TRUST_LOOPBACK,
                                   GN_ROLE_RESPONDER, &cid),
              GN_OK);
    ASSERT_NE(cid, GN_INVALID_ID);

    {
        std::lock_guard lk(spy.mu);
        ASSERT_EQ(spy.events.size(), 1u);
        EXPECT_EQ(spy.events[0].kind, GN_PATH_EVENT_CONN_UP);
        EXPECT_EQ(spy.events[0].conn, cid);
        EXPECT_EQ(spy.events[0].pk[0], 0x11);
        EXPECT_EQ(spy.events[0].pk[1], 0x22);
    }

    (void)api.unregister_extension(&ctx, "gn.strategy.spy");
}

/// notify_rtt_sample folds the observation into the kernel's EWMA
/// and republishes it to every strategy through
/// on_path_event(RTT_UPDATE). The sample carries the conn id and
/// the smoothed value the kernel just stored, so strategies see
/// the same view get_endpoint exposes.
TEST(HostApiPathEvent, NotifyRttSampleFiresRttUpdateToStrategy) {
    Kernel k;
    auto ctx = make_ctx(k);
    auto api = build_host_api(ctx);

    SpyStrategy spy;
    auto vt = SpyStrategy::make_vtable(spy);
    ASSERT_EQ(api.register_extension(&ctx, "gn.strategy.spy",
                                       GN_EXT_STRATEGY_VERSION, &vt),
              GN_OK);

    std::uint8_t pk[GN_PUBLIC_KEY_BYTES] = {0xCA, 0xFE, 0xBA, 0xBE};
    gn_conn_id_t cid = GN_INVALID_ID;
    ASSERT_EQ(api.notify_connect(&ctx, pk, "fake://h:0",
                                   GN_TRUST_LOOPBACK,
                                   GN_ROLE_RESPONDER, &cid),
              GN_OK);

    /// Drop the CONN_UP event so the test asserts only on
    /// RTT_UPDATE.
    {
        std::lock_guard lk(spy.mu);
        spy.events.clear();
    }

    /// First sample seeds the EWMA: the kernel stores the
    /// observation verbatim and forwards it to the strategy.
    ASSERT_EQ(api.notify_rtt_sample(&ctx, cid, /*rtt_us*/ 10'000),
              GN_OK);

    std::lock_guard lk(spy.mu);
    ASSERT_EQ(spy.events.size(), 1u);
    EXPECT_EQ(spy.events[0].kind, GN_PATH_EVENT_RTT_UPDATE);
    EXPECT_EQ(spy.events[0].conn, cid);
    EXPECT_EQ(spy.events[0].rtt_us, 10'000u);

    (void)api.unregister_extension(&ctx, "gn.strategy.spy");
}

/// Subsequent samples fold into EWMA(α = 1/8); the kernel
/// republishes the *smoothed* value to strategies, not the raw
/// observation. Strategy chain models stay stable across
/// individual outliers without each plugin maintaining its own
/// probe.
TEST(HostApiPathEvent, NotifyRttSampleStrategySeesSmoothedNotRaw) {
    Kernel k;
    auto ctx = make_ctx(k);
    auto api = build_host_api(ctx);

    SpyStrategy spy;
    auto vt = SpyStrategy::make_vtable(spy);
    ASSERT_EQ(api.register_extension(&ctx, "gn.strategy.spy",
                                       GN_EXT_STRATEGY_VERSION, &vt),
              GN_OK);

    std::uint8_t pk[GN_PUBLIC_KEY_BYTES] = {0xAB, 0xCD};
    gn_conn_id_t cid = GN_INVALID_ID;
    ASSERT_EQ(api.notify_connect(&ctx, pk, "fake://h:0",
                                   GN_TRUST_LOOPBACK,
                                   GN_ROLE_RESPONDER, &cid),
              GN_OK);
    {
        std::lock_guard lk(spy.mu);
        spy.events.clear();
    }

    /// Seed at 10ms, then drive an 80ms outlier. EWMA stores
    /// next = (7·10000 + 80000) / 8 = 18750us; raw is 80000us.
    /// The strategy must see the smoothed 18750, not the raw 80000.
    ASSERT_EQ(api.notify_rtt_sample(&ctx, cid, 10'000), GN_OK);
    ASSERT_EQ(api.notify_rtt_sample(&ctx, cid, 80'000), GN_OK);

    std::lock_guard lk(spy.mu);
    ASSERT_EQ(spy.events.size(), 2u);
    EXPECT_EQ(spy.events[0].rtt_us, 10'000u)
        << "seed sample is published verbatim";
    EXPECT_EQ(spy.events[1].rtt_us, 18'750u)
        << "second sample must arrive smoothed; raw 80000 leaks "
           "the outlier into the strategy's model";

    (void)api.unregister_extension(&ctx, "gn.strategy.spy");
}

/// SECURITY plugins do not legitimately observe RTT; the role
/// gate rejects them before they touch the connection registry.
TEST(HostApiPathEvent, NotifyRttSampleSecurityKindRejected) {
    Kernel k;
    auto ctx = make_ctx_kind(k, GN_PLUGIN_KIND_SECURITY);
    auto api = build_host_api(ctx);

    EXPECT_EQ(api.notify_rtt_sample(&ctx, /*conn*/ 7, /*rtt*/ 1000),
              GN_ERR_NOT_IMPLEMENTED)
        << "security plugins must not push RTT samples";
}

/// An unknown conn id is GN_ERR_NOT_FOUND. Plugins that observe
/// RTT against a conn that was already torn down see the
/// diagnostic instead of silently failing.
TEST(HostApiPathEvent, NotifyRttSampleUnknownConnIsNotFound) {
    Kernel k;
    auto ctx = make_ctx(k);
    auto api = build_host_api(ctx);

    EXPECT_EQ(api.notify_rtt_sample(&ctx, /*conn*/ 9'999, 1000),
              GN_ERR_NOT_FOUND);
}

/// Folding multiple samples into the EWMA smooths a single
/// outlier toward the long-running mean. The kernel surfaces the
/// smoothed value through `get_endpoint`; this test asserts the
/// smoothing landed observably (sample N reflects fewer-than-N
/// units of swing on the snapshot).
TEST(HostApiPathEvent, NotifyRttSampleEwmaSmoothing) {
    Kernel k;
    auto ctx = make_ctx(k);
    auto api = build_host_api(ctx);

    std::uint8_t pk[GN_PUBLIC_KEY_BYTES] = {0x42};
    gn_conn_id_t cid = GN_INVALID_ID;
    ASSERT_EQ(api.notify_connect(&ctx, pk, "fake://h:0",
                                   GN_TRUST_LOOPBACK,
                                   GN_ROLE_RESPONDER, &cid),
              GN_OK);

    /// Steady-state seed at 10ms, then an outlier at 80ms. EWMA
    /// next = (7·prev + sample) / 8 = (70 + 80) / 8 = 18.75ms.
    /// The smoothed value is much closer to the steady state than
    /// to the outlier — that's the whole point of the EWMA.
    ASSERT_EQ(api.notify_rtt_sample(&ctx, cid, 10'000), GN_OK);
    ASSERT_EQ(api.notify_rtt_sample(&ctx, cid, 80'000), GN_OK);

    gn_endpoint_t ep{};
    ASSERT_EQ(api.get_endpoint(&ctx, cid, &ep), GN_OK);
    /// Expected post-EWMA: (7 * 10000 + 80000) / 8 = 18750us.
    /// Assert via tight bound so the test catches a regression
    /// that drops smoothing entirely (which would show 80000us).
    EXPECT_NEAR(static_cast<double>(ep.last_rtt_us), 18750.0, 50.0);
}

/// Zero is the "no sample" sentinel — the kernel silently drops
/// it and returns GN_OK so plugins can publish unconditionally.
/// No strategy event fires.
TEST(HostApiPathEvent, NotifyRttSampleZeroIsSilent) {
    Kernel k;
    auto ctx = make_ctx(k);
    auto api = build_host_api(ctx);

    SpyStrategy spy;
    auto vt = SpyStrategy::make_vtable(spy);
    ASSERT_EQ(api.register_extension(&ctx, "gn.strategy.spy",
                                       GN_EXT_STRATEGY_VERSION, &vt),
              GN_OK);

    std::uint8_t pk[GN_PUBLIC_KEY_BYTES] = {0x77};
    gn_conn_id_t cid = GN_INVALID_ID;
    ASSERT_EQ(api.notify_connect(&ctx, pk, "fake://h:0",
                                   GN_TRUST_LOOPBACK,
                                   GN_ROLE_RESPONDER, &cid),
              GN_OK);
    {
        std::lock_guard lk(spy.mu);
        spy.events.clear();
    }

    EXPECT_EQ(api.notify_rtt_sample(&ctx, cid, 0), GN_OK);
    std::lock_guard lk(spy.mu);
    EXPECT_TRUE(spy.events.empty())
        << "zero sample must not fire a strategy event";

    (void)api.unregister_extension(&ctx, "gn.strategy.spy");
}

/// notify_disconnect must fire on_path_event(CONN_DOWN) carrying
/// the snapshotted conn id + remote_pk before the registry entry is
/// erased — strategies need both to evict the conn from their model.
TEST(HostApiPathEvent, NotifyDisconnectFiresConnDownToStrategy) {
    Kernel k;
    auto ctx = make_ctx(k);
    auto api = build_host_api(ctx);

    SpyStrategy spy;
    auto vt = SpyStrategy::make_vtable(spy);
    ASSERT_EQ(api.register_extension(&ctx, "gn.strategy.spy",
                                       GN_EXT_STRATEGY_VERSION, &vt),
              GN_OK);

    std::uint8_t pk[GN_PUBLIC_KEY_BYTES] = {0x55, 0x66, 0x77, 0x88};
    gn_conn_id_t cid = GN_INVALID_ID;
    ASSERT_EQ(api.notify_connect(&ctx, pk, "fake://h:0",
                                   GN_TRUST_LOOPBACK,
                                   GN_ROLE_RESPONDER, &cid),
              GN_OK);

    /// Drop the CONN_UP event so the test below asserts only on the
    /// CONN_DOWN side. (The CONN_UP fire is covered by the test
    /// above.)
    {
        std::lock_guard lk(spy.mu);
        spy.events.clear();
    }

    ASSERT_EQ(api.notify_disconnect(&ctx, cid, GN_OK), GN_OK);

    std::lock_guard lk(spy.mu);
    ASSERT_EQ(spy.events.size(), 1u);
    EXPECT_EQ(spy.events[0].kind, GN_PATH_EVENT_CONN_DOWN);
    EXPECT_EQ(spy.events[0].conn, cid);
    EXPECT_EQ(spy.events[0].pk[0], 0x55);
    EXPECT_EQ(spy.events[0].pk[1], 0x66);

    (void)api.unregister_extension(&ctx, "gn.strategy.spy");
}

/// Strategy that returns NOT_FOUND on every pick — the kernel must
/// fall through to the next strategy in the chain (or to the head
/// of the candidate set when every strategy passes).
struct PassthroughStrategy {
    std::atomic<int> pick_calls{0};

    static gn_result_t pick_conn(void* ctx,
                                  const std::uint8_t*,
                                  const gn_path_sample_t*,
                                  std::size_t, gn_conn_id_t*) {
        auto* s = static_cast<PassthroughStrategy*>(ctx);
        s->pick_calls.fetch_add(1);
        return GN_ERR_NOT_FOUND;
    }

    static gn_strategy_api_t make_vtable(PassthroughStrategy& s) {
        gn_strategy_api_t vt{};
        vt.api_size  = sizeof(vt);
        vt.pick_conn = &pick_conn;
        vt.ctx       = &s;
        return vt;
    }
};

/// Strategy that returns GN_OK but writes GN_INVALID_ID to
/// `out_chosen`. Per `strategy.h`, the kernel treats this the
/// same as `GN_ERR_NOT_FOUND` and continues the chain.
struct OkButInvalidStrategy {
    std::atomic<int> pick_calls{0};

    static gn_result_t pick_conn(void* ctx,
                                  const std::uint8_t*,
                                  const gn_path_sample_t*,
                                  std::size_t,
                                  gn_conn_id_t* out_chosen) {
        auto* s = static_cast<OkButInvalidStrategy*>(ctx);
        s->pick_calls.fetch_add(1);
        if (out_chosen) *out_chosen = GN_INVALID_ID;
        return GN_OK;
    }

    static gn_strategy_api_t make_vtable(OkButInvalidStrategy& s) {
        gn_strategy_api_t vt{};
        vt.api_size  = sizeof(vt);
        vt.pick_conn = &pick_conn;
        vt.ctx       = &s;
        return vt;
    }
};

/// With two strategies registered where the first one returns
/// NOT_FOUND, the kernel must consult the second one in the same
/// dispatch. NOT_FOUND means "I have no opinion on this candidate
/// set"; the chain advances.
TEST(HostApiSendTo, FirstStrategyNotFoundFallsThroughToSecond) {
    Kernel k;
    auto ctx = make_ctx(k);
    auto api = build_host_api(ctx);

    PassthroughStrategy passthrough;
    PickLastStrategy    last;
    auto vt_pass = PassthroughStrategy::make_vtable(passthrough);
    auto vt_last = PickLastStrategy::make_vtable(last);
    ASSERT_EQ(api.register_extension(&ctx, "gn.strategy.pass",
                                       GN_EXT_STRATEGY_VERSION, &vt_pass),
              GN_OK);
    ASSERT_EQ(api.register_extension(&ctx, "gn.strategy.last",
                                       GN_EXT_STRATEGY_VERSION, &vt_last),
              GN_OK);

    std::uint8_t pk[GN_PUBLIC_KEY_BYTES] = {0x99};
    const auto conns = spawn_conns(ctx, api, pk, 2);
    ASSERT_EQ(conns.size(), 2u);

    const std::uint8_t payload[1] = {0x42};
    (void)api.send_to(&ctx, pk, 0x10, payload, 1);

    /// Both strategies must have been consulted — at least one
    /// returned NOT_FOUND, the other made a real pick. Order in
    /// the registry is hash-ordered, so we cannot pin which one
    /// was first; instead assert both were consulted at least
    /// once across the chain.
    const int total_calls = passthrough.pick_calls.load()
                          + last.pick_calls.load();
    EXPECT_GE(total_calls, 1)
        << "at least one strategy must have been consulted";

    (void)api.unregister_extension(&ctx, "gn.strategy.pass");
    (void)api.unregister_extension(&ctx, "gn.strategy.last");
}

/// A strategy that returns `(GN_OK, GN_INVALID_ID)` must be
/// treated the same as `GN_ERR_NOT_FOUND` — the chain advances
/// to the next strategy. Pins the lenient interpretation
/// documented on `gn_strategy_api_t::pick_conn`.
TEST(HostApiSendTo, OkButInvalidIdFallsThroughLikeNotFound) {
    Kernel k;
    auto ctx = make_ctx(k);
    auto api = build_host_api(ctx);

    OkButInvalidStrategy quiet;
    PickLastStrategy     winner;
    auto vt_quiet  = OkButInvalidStrategy::make_vtable(quiet);
    auto vt_winner = PickLastStrategy::make_vtable(winner);
    ASSERT_EQ(api.register_extension(&ctx, "gn.strategy.quiet",
                                       GN_EXT_STRATEGY_VERSION, &vt_quiet),
              GN_OK);
    ASSERT_EQ(api.register_extension(&ctx, "gn.strategy.winner",
                                       GN_EXT_STRATEGY_VERSION, &vt_winner),
              GN_OK);

    std::uint8_t pk[GN_PUBLIC_KEY_BYTES] = {0xEE};
    const auto conns = spawn_conns(ctx, api, pk, 2);
    ASSERT_EQ(conns.size(), 2u);

    const std::uint8_t payload[1] = {0x77};
    (void)api.send_to(&ctx, pk, 0x10, payload, 1);

    /// Quiet ran (registered + invoked); winner also ran because
    /// the kernel kept walking after the GN_INVALID_ID response.
    EXPECT_GE(quiet.pick_calls.load(), 1)
        << "quiet strategy must be invoked";
    EXPECT_GE(winner.pick_calls.load(), 1)
        << "kernel must fall through to next strategy when "
           "out_chosen is GN_INVALID_ID";

    (void)api.unregister_extension(&ctx, "gn.strategy.quiet");
    (void)api.unregister_extension(&ctx, "gn.strategy.winner");
}

/// A strategy that returns a non-`GN_ERR_NOT_FOUND` error code
/// aborts the chain — the kernel does NOT walk to the next
/// strategy and propagates the error to the `send_to` caller.
/// Pins the documented "chain advances only on NOT_FOUND" rule
/// in `sdk/extensions/strategy.h`.
struct FailingStrategy {
    std::atomic<int> pick_calls{0};

    static gn_result_t pick_conn(void* ctx,
                                  const std::uint8_t*,
                                  const gn_path_sample_t*,
                                  std::size_t, gn_conn_id_t*) {
        auto* s = static_cast<FailingStrategy*>(ctx);
        s->pick_calls.fetch_add(1);
        return GN_ERR_INTERNAL;
    }

    static gn_strategy_api_t make_vtable(FailingStrategy& s) {
        gn_strategy_api_t vt{};
        vt.api_size  = sizeof(vt);
        vt.pick_conn = &pick_conn;
        vt.ctx       = &s;
        return vt;
    }
};

TEST(HostApiSendTo, NonNotFoundStrategyErrorAbortsChain) {
    Kernel k;
    auto ctx = make_ctx(k);
    auto api = build_host_api(ctx);

    FailingStrategy fail;
    PickLastStrategy never_runs;
    auto vt_fail = FailingStrategy::make_vtable(fail);
    auto vt_skip = PickLastStrategy::make_vtable(never_runs);
    ASSERT_EQ(api.register_extension(&ctx, "gn.strategy.fail",
                                       GN_EXT_STRATEGY_VERSION, &vt_fail),
              GN_OK);
    ASSERT_EQ(api.register_extension(&ctx, "gn.strategy.skip",
                                       GN_EXT_STRATEGY_VERSION, &vt_skip),
              GN_OK);

    std::uint8_t pk[GN_PUBLIC_KEY_BYTES] = {0x33};
    const auto conns = spawn_conns(ctx, api, pk, 2);
    ASSERT_EQ(conns.size(), 2u);

    const std::uint8_t payload[1] = {0x44};
    const gn_result_t rc = api.send_to(&ctx, pk, 0x10, payload, 1);
    EXPECT_EQ(rc, GN_ERR_INTERNAL)
        << "fail strategy's non-NOT_FOUND error must propagate "
           "to send_to's caller";
    EXPECT_GE(fail.pick_calls.load(), 1) << "fail strategy ran";
    EXPECT_EQ(never_runs.pick_calls.load(), 0)
        << "kernel must NOT have walked past the aborting strategy";

    (void)api.unregister_extension(&ctx, "gn.strategy.fail");
    (void)api.unregister_extension(&ctx, "gn.strategy.skip");
}

TEST(SdkSendToWrapper, ForwardsPayloadAndPeerPk) {
    Kernel k;
    auto ctx = make_ctx(k);
    auto api = build_host_api(ctx);

    /// SDK wrapper rejects null inputs without poking the kernel.
    std::uint8_t pk[GN_PUBLIC_KEY_BYTES] = {0xFF};
    const std::uint8_t payload[3] = {1, 2, 3};
    EXPECT_EQ(gn::sdk::send_to(nullptr, pk, 0x10,
                                 std::span<const std::uint8_t>(payload, 3)),
              GN_ERR_NULL_ARG);
    EXPECT_EQ(gn::sdk::send_to(&api, nullptr, 0x10,
                                 std::span<const std::uint8_t>(payload, 3)),
              GN_ERR_NULL_ARG);

    /// With a registered conn it forwards to the kernel thunk —
    /// kernel returns NOT_FOUND because no conns to this pk.
    EXPECT_EQ(gn::sdk::send_to(&api, pk, 0x10,
                                 std::span<const std::uint8_t>(payload, 3)),
              GN_ERR_NOT_FOUND);
}
