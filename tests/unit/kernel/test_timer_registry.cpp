/// @file   tests/unit/kernel/test_timer_registry.cpp
/// @brief  TimerRegistry: schedule, cancel, anchor-gated dispatch,
///         fire-and-forget set_timer(0, ...), quota enforcement.

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <memory>
#include <thread>

#include <core/kernel/timer_registry.hpp>

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

} // namespace

// ─── set_timer / cancel_timer basics ────────────────────────────

TEST(TimerRegistry_Schedule, FiresAfterDelay) {
    TimerRegistry r;

    std::atomic<int> hits{0};
    gn_timer_id_t id = GN_INVALID_TIMER_ID;
    ASSERT_EQ(r.set_timer(5, [](void* p) {
        static_cast<std::atomic<int>*>(p)->fetch_add(1);
    }, &hits, /*anchor=*/{}, &id), GN_OK);
    EXPECT_NE(id, GN_INVALID_TIMER_ID);

    EXPECT_TRUE(wait_for([&] { return hits.load() == 1; }));
    EXPECT_EQ(r.active_timers(), 0u)
        << "self-cleanup must remove the entry on fire";
}

TEST(TimerRegistry_Schedule, CancelStopsDispatch) {
    TimerRegistry r;

    std::atomic<int> hits{0};
    gn_timer_id_t id = GN_INVALID_TIMER_ID;
    /// Long enough that cancel arrives before fire.
    ASSERT_EQ(r.set_timer(500, [](void* p) {
        static_cast<std::atomic<int>*>(p)->fetch_add(1);
    }, &hits, /*anchor=*/{}, &id), GN_OK);

    EXPECT_EQ(r.cancel_timer(id), GN_OK);
    EXPECT_EQ(r.active_timers(), 0u);

    /// Wait beyond the original delay; must not fire.
    std::this_thread::sleep_for(std::chrono::milliseconds{50});
    EXPECT_EQ(hits.load(), 0);
}

TEST(TimerRegistry_Schedule, CancelTwiceIsOk) {
    TimerRegistry r;
    gn_timer_id_t id = GN_INVALID_TIMER_ID;
    ASSERT_EQ(r.set_timer(500, [](void*) {}, nullptr, {}, &id), GN_OK);
    EXPECT_EQ(r.cancel_timer(id), GN_OK);
    EXPECT_EQ(r.cancel_timer(id), GN_OK)  // idempotent per timer.md §7
        << "second cancel of same id must report success";
    EXPECT_EQ(r.cancel_timer(GN_INVALID_TIMER_ID), GN_ERR_NULL_ARG);
}

TEST(TimerRegistry_Schedule, RejectsNullCallback) {
    /// `fn == nullptr` is the only NULL_ARG path on `set_timer`;
    /// `out_id == nullptr` is the legal fire-and-forget shape per
    /// `timer.md` §2 / `host-api.md` §9.
    TimerRegistry r;
    gn_timer_id_t id = GN_INVALID_TIMER_ID;
    EXPECT_EQ(r.set_timer(10, nullptr, nullptr, {}, &id),
              GN_ERR_NULL_ARG);
    EXPECT_EQ(id, GN_INVALID_TIMER_ID);
    EXPECT_EQ(r.set_timer(10, nullptr, nullptr, {}, nullptr),
              GN_ERR_NULL_ARG);
}

// ─── anchor-gated dispatch (plugin lifetime) ────────────────────

TEST(TimerRegistry_Anchor, ExpiredAnchorDropsCallback) {
    TimerRegistry r;
    auto anchor = std::make_shared<PluginAnchor>();

    std::atomic<int> hits{0};
    gn_timer_id_t id = GN_INVALID_TIMER_ID;
    ASSERT_EQ(r.set_timer(20, [](void* p) {
        static_cast<std::atomic<int>*>(p)->fetch_add(1);
    }, &hits, anchor, &id), GN_OK);

    /// Drop the anchor before the timer fires; the dispatcher must
    /// observe the expiry and skip the callback silently.
    anchor.reset();

    std::this_thread::sleep_for(std::chrono::milliseconds{60});
    EXPECT_EQ(hits.load(), 0)
        << "anchor expired before fire; callback must be dropped";
}

TEST(TimerRegistry_Anchor, LiveAnchorDispatches) {
    TimerRegistry r;
    auto anchor = std::make_shared<PluginAnchor>();

    std::atomic<int> hits{0};
    gn_timer_id_t id = GN_INVALID_TIMER_ID;
    ASSERT_EQ(r.set_timer(5, [](void* p) {
        static_cast<std::atomic<int>*>(p)->fetch_add(1);
    }, &hits, anchor, &id), GN_OK);

    EXPECT_TRUE(wait_for([&] { return hits.load() == 1; }));
}

TEST(TimerRegistry_Anchor, CancelForAnchorRemovesMatchingTimers) {
    TimerRegistry r;
    auto a = std::make_shared<PluginAnchor>();
    auto b = std::make_shared<PluginAnchor>();

    gn_timer_id_t id1 = GN_INVALID_TIMER_ID;
    gn_timer_id_t id2 = GN_INVALID_TIMER_ID;
    gn_timer_id_t id3 = GN_INVALID_TIMER_ID;
    ASSERT_EQ(r.set_timer(5'000, [](void*) {}, nullptr, a, &id1), GN_OK);
    ASSERT_EQ(r.set_timer(5'000, [](void*) {}, nullptr, a, &id2), GN_OK);
    ASSERT_EQ(r.set_timer(5'000, [](void*) {}, nullptr, b, &id3), GN_OK);
    EXPECT_EQ(r.active_timers(), 3u);

    r.cancel_for_anchor(a);
    EXPECT_EQ(r.active_timers(), 1u);
    EXPECT_EQ(r.cancel_timer(id3), GN_OK);
}

// ─── fire-and-forget set_timer(0, ...) ─────────────────────────────────────────

TEST(TimerRegistry_SetTimer, AcceptsNullOutIdForFireAndForget) {
    /// `host-api.md` §9 / `timer.md` §2 / `conn-events.md` §3.5
    /// promise that fire-and-forget callers pass `out_id = NULL`.
    /// Pre-fix the kernel rejected with NULL_ARG and the second
    /// call dereferenced *out_id, segfaulting under ASan.
    TimerRegistry r;
    std::atomic<int> hits{0};
    EXPECT_EQ(r.set_timer(/*delay_ms*/ 0,
                           [](void* p) {
                               static_cast<std::atomic<int>*>(p)->fetch_add(1);
                           },
                           &hits,
                           /*anchor=*/{},
                           /*out_id=*/nullptr),
              GN_OK);
    EXPECT_TRUE(wait_for([&] { return hits.load() == 1; }));
}

TEST(TimerRegistry_Post, RunsOnServiceExecutor) {
    TimerRegistry r;
    std::atomic<int> hits{0};
    EXPECT_EQ(r.post([](void* p) {
        static_cast<std::atomic<int>*>(p)->fetch_add(1);
    }, &hits, /*anchor=*/{}), GN_OK);
    EXPECT_TRUE(wait_for([&] { return hits.load() == 1; }));
}

TEST(TimerRegistry_Post, AnchorExpiredSkips) {
    TimerRegistry r;
    auto anchor = std::make_shared<PluginAnchor>();
    std::atomic<int> hits{0};

    /// Drop anchor before posting so the queued task observes
    /// expired weak observer.
    auto weak_only = std::weak_ptr<PluginAnchor>(anchor);
    /// Re-create anchor strong only inside post call (move-by-copy).
    EXPECT_EQ(r.post([](void* p) {
        static_cast<std::atomic<int>*>(p)->fetch_add(1);
    }, &hits, anchor), GN_OK);
    anchor.reset();

    /// The post lambda holds a weak observer; by the time the
    /// service executor picks it up the anchor may already be gone.
    /// We give the executor a moment, then assert at-most-one fire
    /// (the race resolves either way; what matters is no UAF).
    std::this_thread::sleep_for(std::chrono::milliseconds{20});
    EXPECT_LE(hits.load(), 1);
}

// ─── quota enforcement ──────────────────────────────────────────

TEST(TimerRegistry_Quota, RejectsPastMaxTimers) {
    TimerRegistry r;
    r.set_max_timers(2);

    gn_timer_id_t a = GN_INVALID_TIMER_ID;
    gn_timer_id_t b = GN_INVALID_TIMER_ID;
    gn_timer_id_t c = GN_INVALID_TIMER_ID;
    EXPECT_EQ(r.set_timer(5'000, [](void*) {}, nullptr, {}, &a), GN_OK);
    EXPECT_EQ(r.set_timer(5'000, [](void*) {}, nullptr, {}, &b), GN_OK);
    EXPECT_EQ(r.set_timer(5'000, [](void*) {}, nullptr, {}, &c),
              GN_ERR_LIMIT_REACHED);
    EXPECT_EQ(c, GN_INVALID_TIMER_ID);
}

TEST(TimerRegistry_Quota, ZeroPendingCapMeansUnlimited) {
    /// `limits.md` §4 — a cap left at the `set_*` default of zero
    /// is treated as unlimited. Mirrors the `set_timer` per-plugin
    /// behaviour exercised by `ZeroPerPluginCapMeansUnlimited`.
    /// The flip cap=1 → 0 makes the test fail on the pre-fix path
    /// where `cur >= cap` rejected at zero unconditionally.
    TimerRegistry r;
    r.set_max_pending_tasks(1);
    EXPECT_EQ(r.post([](void*) {}, nullptr, {}), GN_OK);
    /// Cap == 1 with one admit already in flight — second post is
    /// the LIMIT_REACHED case, exercising the non-zero-cap path.
    EXPECT_EQ(r.post([](void*) {}, nullptr, {}), GN_ERR_LIMIT_REACHED);

    /// Switch to "unlimited" — every subsequent admit must
    /// succeed even though the live counter is already at the
    /// previous cap. A pre-fix run rejects every call with
    /// `cur >= 0` true.
    r.set_max_pending_tasks(0);
    for (int i = 0; i < 32; ++i) {
        EXPECT_EQ(r.post([](void*) {}, nullptr, {}), GN_OK);
    }
    r.shutdown();
}

TEST(TimerRegistry_Quota, ZeroMaxTimersCapMeansUnlimited) {
    /// Same `limits.md` §4 rule for the global `max_timers` cap
    /// in `set_timer`. Flip from cap=2 → 0 demonstrates the
    /// transition: the third admit at cap=2 is rejected, then
    /// cap=0 admits the same call. Pre-fix code rejected at
    /// cap=0 with `timers_.size() >= 0` always true.
    TimerRegistry r;
    r.set_max_timers(2);

    gn_timer_id_t id = GN_INVALID_TIMER_ID;
    EXPECT_EQ(r.set_timer(60'000, [](void*) {}, nullptr, {}, &id), GN_OK);
    EXPECT_EQ(r.set_timer(60'000, [](void*) {}, nullptr, {}, &id), GN_OK);
    EXPECT_EQ(r.set_timer(60'000, [](void*) {}, nullptr, {}, &id),
              GN_ERR_LIMIT_REACHED);

    r.set_max_timers(0);
    for (int i = 0; i < 32; ++i) {
        EXPECT_EQ(r.set_timer(60'000, [](void*) {}, nullptr, {}, &id), GN_OK);
    }
    r.shutdown();
}

TEST(TimerRegistry_Quota, SetTimerCapHoldsUnderConcurrentAdmits) {
    /// `set_timer`'s global cap admit-then-emplace previously
    /// released the mutex between the size check and the
    /// `timers_.emplace` — concurrent admits could each observe
    /// `size() < cap` and both push past it. Holding the lock
    /// from check through emplace collapses the window. Stress
    /// test asserts the count never exceeds the cap regardless of
    /// thread interleaving.
    TimerRegistry r;
    r.set_max_timers(8);

    constexpr int kThreads = 16;
    constexpr int kSetsPerThread = 32;
    std::atomic<int> accepted{0};
    std::atomic<int> rejected{0};
    std::vector<std::thread> workers;
    workers.reserve(kThreads);
    for (int t = 0; t < kThreads; ++t) {
        workers.emplace_back([&] {
            for (int i = 0; i < kSetsPerThread; ++i) {
                gn_timer_id_t id = GN_INVALID_TIMER_ID;
                /// 60-second delay ensures none of the timers fire
                /// during the stress; the entries stay in the map
                /// for the duration of the assertion.
                const auto rc = r.set_timer(60'000, [](void*) {},
                                             nullptr, {}, &id);
                if (rc == GN_OK) accepted.fetch_add(1);
                else if (rc == GN_ERR_LIMIT_REACHED) rejected.fetch_add(1);
            }
        });
    }
    for (auto& w : workers) w.join();
    /// Map size never exceeds the cap; the surplus admits all
    /// route to LIMIT_REACHED.
    EXPECT_LE(accepted.load(), 8);
    EXPECT_GT(rejected.load(), 0);
    EXPECT_EQ(accepted.load() + rejected.load(), kThreads * kSetsPerThread);
    r.shutdown();
}

TEST(TimerRegistry_Quota, PostCapHoldsUnderConcurrentAdmits) {
    /// CAS-loop admit on `post()` must keep two concurrent
    /// admit threads under the cap even when both observe a
    /// sub-cap value before either publishes its increment.
    /// Without the loop the loser's `fetch_add` would push the
    /// counter over the ceiling and the per-plugin pending pool
    /// would silently overflow.
    TimerRegistry r;
    r.set_max_pending_tasks(8);

    constexpr int kThreads = 16;
    constexpr int kPosts   = 64;
    std::atomic<int> accepted{0};
    std::atomic<int> rejected{0};
    std::vector<std::thread> workers;
    workers.reserve(kThreads);
    for (int t = 0; t < kThreads; ++t) {
        workers.emplace_back([&] {
            for (int i = 0; i < kPosts; ++i) {
                const auto rc = r.post([](void*) {}, nullptr, {});
                if (rc == GN_OK) accepted.fetch_add(1);
                else if (rc == GN_ERR_LIMIT_REACHED) rejected.fetch_add(1);
            }
        });
    }
    for (auto& w : workers) w.join();
    /// Wait for the asio worker to drain the queue so the
    /// pending counter reads back to zero. The cap holds in
    /// flight; the post-execution refund matches.
    r.shutdown();
    EXPECT_GT(accepted.load(), 0);
    EXPECT_GT(rejected.load(), 0);
    EXPECT_EQ(accepted.load() + rejected.load(), kThreads * kPosts);
}

// ─── per-plugin sub-quota (limits.md §4a) ──────────────────────

TEST(TimerRegistry_Quota, PerPluginQuotaIsolatesSiblings) {
    /// Plugin A's anchor exhausts its per-plugin budget; plugin B
    /// must keep its full budget untouched. The historical "global
    /// cap only" path would let A's spam starve B.
    TimerRegistry r;
    r.set_max_timers_per_plugin(2);
    /// Generous global cap so the per-plugin check is what fires.
    r.set_max_timers(64);

    auto anchor_a = std::make_shared<PluginAnchor>();
    auto anchor_b = std::make_shared<PluginAnchor>();

    gn_timer_id_t id = GN_INVALID_TIMER_ID;
    EXPECT_EQ(r.set_timer(5'000, [](void*) {}, nullptr, anchor_a, &id), GN_OK);
    EXPECT_EQ(r.set_timer(5'000, [](void*) {}, nullptr, anchor_a, &id), GN_OK);
    /// A's third admit must hit the per-plugin cap.
    EXPECT_EQ(r.set_timer(5'000, [](void*) {}, nullptr, anchor_a, &id),
              GN_ERR_LIMIT_REACHED);
    EXPECT_EQ(anchor_a->active_timers.load(), 2u);

    /// B's first two admits succeed — the cap is per-anchor.
    EXPECT_EQ(r.set_timer(5'000, [](void*) {}, nullptr, anchor_b, &id), GN_OK);
    EXPECT_EQ(r.set_timer(5'000, [](void*) {}, nullptr, anchor_b, &id), GN_OK);
    EXPECT_EQ(anchor_b->active_timers.load(), 2u);
}

TEST(TimerRegistry_Quota, CancelRefundsPerPluginBudget) {
    /// Cancelling a pending timer must credit the plugin's slot
    /// back so a long-running plugin that cycles its timer pool
    /// does not slowly starve itself.
    TimerRegistry r;
    r.set_max_timers_per_plugin(2);
    r.set_max_timers(64);

    auto anchor = std::make_shared<PluginAnchor>();

    gn_timer_id_t a = GN_INVALID_TIMER_ID;
    gn_timer_id_t b = GN_INVALID_TIMER_ID;
    ASSERT_EQ(r.set_timer(60'000, [](void*) {}, nullptr, anchor, &a), GN_OK);
    ASSERT_EQ(r.set_timer(60'000, [](void*) {}, nullptr, anchor, &b), GN_OK);

    /// At quota now; cancel one and let the lambda's refund settle.
    ASSERT_EQ(r.cancel_timer(a), GN_OK);
    EXPECT_TRUE(wait_for(
        [&] { return anchor->active_timers.load() == 1u; }))
        << "cancel must refund within the test timeout; observed "
        << anchor->active_timers.load();

    /// Budget restored — a fresh admit succeeds.
    gn_timer_id_t c = GN_INVALID_TIMER_ID;
    EXPECT_EQ(r.set_timer(60'000, [](void*) {}, nullptr, anchor, &c), GN_OK);
    ASSERT_EQ(r.cancel_timer(b), GN_OK);
    ASSERT_EQ(r.cancel_timer(c), GN_OK);
}

TEST(TimerRegistry_Quota, ZeroPerPluginCapMeansUnlimited) {
    /// `set_max_timers_per_plugin(0)` is the historical default —
    /// no per-plugin gating, only the global cap.
    TimerRegistry r;
    r.set_max_timers_per_plugin(0);
    r.set_max_timers(64);

    auto anchor = std::make_shared<PluginAnchor>();

    gn_timer_id_t id = GN_INVALID_TIMER_ID;
    /// Schedule more than any plausible per-plugin cap; the global
    /// cap is what stops the run.
    for (int i = 0; i < 10; ++i) {
        ASSERT_EQ(r.set_timer(60'000, [](void*) {}, nullptr,
                              anchor, &id), GN_OK)
            << "with cap == 0 the per-plugin check must short-circuit";
    }
    EXPECT_EQ(anchor->active_timers.load(), 10u);
}

// ─── shutdown ───────────────────────────────────────────────────

TEST(TimerRegistry_Shutdown, IdempotentAndCancelsPending) {
    auto r = std::make_unique<TimerRegistry>();
    std::atomic<int> hits{0};
    gn_timer_id_t id = GN_INVALID_TIMER_ID;
    ASSERT_EQ(r->set_timer(500, [](void* p) {
        static_cast<std::atomic<int>*>(p)->fetch_add(1);
    }, &hits, {}, &id), GN_OK);

    r->shutdown();
    r->shutdown();  // second call must no-op

    /// After shutdown the pending timer must not fire.
    std::this_thread::sleep_for(std::chrono::milliseconds{50});
    EXPECT_EQ(hits.load(), 0);
}
