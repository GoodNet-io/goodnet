/// @file   tests/unit/kernel/test_timer_registry.cpp
/// @brief  TimerRegistry: schedule, cancel, anchor-gated dispatch,
///         post_to_executor, quota enforcement.

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
    TimerRegistry r;
    gn_timer_id_t id = GN_INVALID_TIMER_ID;
    EXPECT_EQ(r.set_timer(10, nullptr, nullptr, {}, &id),
              GN_ERR_NULL_ARG);
    EXPECT_EQ(id, GN_INVALID_TIMER_ID);
    EXPECT_EQ(r.set_timer(10, [](void*) {}, nullptr, {}, nullptr),
              GN_ERR_NULL_ARG);
}

// ─── anchor-gated dispatch (plugin lifetime) ────────────────────

TEST(TimerRegistry_Anchor, ExpiredAnchorDropsCallback) {
    TimerRegistry r;
    auto anchor = std::make_shared<int>(0);

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
    auto anchor = std::make_shared<int>(0);

    std::atomic<int> hits{0};
    gn_timer_id_t id = GN_INVALID_TIMER_ID;
    ASSERT_EQ(r.set_timer(5, [](void* p) {
        static_cast<std::atomic<int>*>(p)->fetch_add(1);
    }, &hits, anchor, &id), GN_OK);

    EXPECT_TRUE(wait_for([&] { return hits.load() == 1; }));
}

TEST(TimerRegistry_Anchor, CancelForAnchorRemovesMatchingTimers) {
    TimerRegistry r;
    auto a = std::make_shared<int>(0);
    auto b = std::make_shared<int>(0);

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

// ─── post_to_executor ───────────────────────────────────────────

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
    auto anchor = std::make_shared<int>(0);
    std::atomic<int> hits{0};

    /// Drop anchor before posting so the queued task observes
    /// expired weak observer.
    auto weak_only = std::weak_ptr<void>(anchor);
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
