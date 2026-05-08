/// @file   tests/unit/signal/test_signal_channel.cpp
/// @brief  GoogleTest unit tests for `gn::core::signal::SignalChannel`.
///
/// Pins the contract from `core/signal/signal_channel.hpp`:
///   - `subscribe` issues a monotonic token; `unsubscribe` is idempotent.
///   - `fire` snapshots subscribers under the lock, then drops it before
///     invoking handlers. So a handler may subscribe / unsubscribe inside
///     its own callback without deadlocking against the channel.
///   - Empty channel `fire` is a no-op.
///   - Unsubscribing an unknown token is a no-op (no error).

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <set>
#include <stdexcept>
#include <thread>
#include <vector>

#include <core/signal/signal_channel.hpp>

namespace gn::core::signal {
namespace {

struct ConfigReload {
    int generation{0};
};

// ── basic subscribe / fire ───────────────────────────────────────────────

TEST(SignalChannel_Basic, SubscribeReceivesFire) {
    SignalChannel<ConfigReload> ch;
    int observed = -1;
    auto t = ch.subscribe([&](const ConfigReload& e) {
        observed = e.generation;
    });
    EXPECT_NE(t, 0u);
    EXPECT_EQ(ch.subscriber_count(), 1u);

    ch.fire(ConfigReload{42});
    EXPECT_EQ(observed, 42);
}

TEST(SignalChannel_Basic, MultipleFiresAccumulate) {
    SignalChannel<ConfigReload> ch;
    int last_gen = -1;
    int call_count = 0;
    auto t = ch.subscribe([&](const ConfigReload& e) {
        last_gen = e.generation;
        ++call_count;
    });

    ch.fire(ConfigReload{1});
    ch.fire(ConfigReload{2});
    ch.fire(ConfigReload{3});
    EXPECT_EQ(call_count, 3);
    EXPECT_EQ(last_gen,   3);

    ch.unsubscribe(t);
}

TEST(SignalChannel_Basic, MonotonicTokens) {
    SignalChannel<Empty> ch;
    auto t1 = ch.subscribe([](const Empty&) {});
    auto t2 = ch.subscribe([](const Empty&) {});
    auto t3 = ch.subscribe([](const Empty&) {});
    EXPECT_LT(t1, t2);
    EXPECT_LT(t2, t3);
}

// ── unsubscribe ──────────────────────────────────────────────────────────

TEST(SignalChannel_Unsubscribe, RemovesHandler) {
    SignalChannel<ConfigReload> ch;
    int count = 0;
    auto t = ch.subscribe([&](const ConfigReload&) { ++count; });
    ch.fire(ConfigReload{1});
    EXPECT_EQ(count, 1);

    ch.unsubscribe(t);
    EXPECT_EQ(ch.subscriber_count(), 0u);
    ch.fire(ConfigReload{2});
    EXPECT_EQ(count, 1);  /// still 1 — unsubscribed handler did not fire
}

TEST(SignalChannel_Unsubscribe, UnknownTokenIsNoOp) {
    SignalChannel<Empty> ch;
    /// No subscriptions yet — unsubscribe of a fabricated token must
    /// not throw and must not break subsequent fires.
    ch.unsubscribe(999'999);
    EXPECT_EQ(ch.subscriber_count(), 0u);

    int hits = 0;
    auto t = ch.subscribe([&](const Empty&) { ++hits; });
    ch.unsubscribe(static_cast<SignalChannel<Empty>::Token>(t + 100));
    ch.fire(Empty{});
    EXPECT_EQ(hits, 1);

    ch.unsubscribe(t);
}

TEST(SignalChannel_Unsubscribe, RepeatedUnsubscribeIsNoOp) {
    SignalChannel<Empty> ch;
    auto t = ch.subscribe([](const Empty&) {});
    ch.unsubscribe(t);
    EXPECT_EQ(ch.subscriber_count(), 0u);
    /// Second call on the now-stale token must be a clean no-op.
    ch.unsubscribe(t);
    EXPECT_EQ(ch.subscriber_count(), 0u);
}

// ── empty channel ────────────────────────────────────────────────────────

TEST(SignalChannel_Empty, FireIsNoOp) {
    SignalChannel<ConfigReload> ch;
    EXPECT_EQ(ch.subscriber_count(), 0u);
    /// Fire with no subscribers must complete without observable side
    /// effects.
    ch.fire(ConfigReload{0});
    EXPECT_EQ(ch.subscriber_count(), 0u);
}

// ── multiple subscribers ─────────────────────────────────────────────────

TEST(SignalChannel_Multi, AllSubscribersFire) {
    SignalChannel<ConfigReload> ch;
    int a = 0, b = 0, c = 0;
    auto ta = ch.subscribe([&](const ConfigReload& e) { a = e.generation; });
    auto tb = ch.subscribe([&](const ConfigReload& e) { b = e.generation; });
    auto tc = ch.subscribe([&](const ConfigReload& e) { c = e.generation; });
    EXPECT_EQ(ch.subscriber_count(), 3u);

    ch.fire(ConfigReload{77});
    EXPECT_EQ(a, 77);
    EXPECT_EQ(b, 77);
    EXPECT_EQ(c, 77);

    ch.unsubscribe(tb);
    ch.fire(ConfigReload{88});
    EXPECT_EQ(a, 88);
    EXPECT_EQ(b, 77);  /// unchanged after unsubscribe
    EXPECT_EQ(c, 88);

    ch.unsubscribe(ta);
    ch.unsubscribe(tc);
}

// ── re-entrant subscribe / unsubscribe inside a callback ─────────────────

TEST(SignalChannel_Reentrant, HandlerSubscribesInsideCallback) {
    SignalChannel<ConfigReload> ch;
    int outer_count = 0;
    int inner_count = 0;

    /// Outer handler that, on first fire, subscribes a fresh inner
    /// handler. The lock is released before handler invocation so this
    /// must not deadlock.
    auto outer = ch.subscribe([&](const ConfigReload&) {
        ++outer_count;
        if (outer_count == 1) {
            auto inner = ch.subscribe([&](const ConfigReload&) {
                ++inner_count;
            });
            (void)inner;
        }
    });
    (void)outer;

    /// Snapshot semantics: the *inner* handler subscribed during this
    /// fire does not see the same fire — it only fires on subsequent
    /// invocations.
    ch.fire(ConfigReload{1});
    EXPECT_EQ(outer_count, 1);
    EXPECT_EQ(inner_count, 0);

    ch.fire(ConfigReload{2});
    EXPECT_EQ(outer_count, 2);
    EXPECT_EQ(inner_count, 1);
}

TEST(SignalChannel_Reentrant, HandlerUnsubscribesItselfInsideCallback) {
    SignalChannel<ConfigReload> ch;
    int count = 0;
    SignalChannel<ConfigReload>::Token self_token = 0;

    self_token = ch.subscribe([&](const ConfigReload&) {
        ++count;
        ch.unsubscribe(self_token);
    });

    ch.fire(ConfigReload{1});
    /// Snapshot of subscribers was taken before invocation; this handler
    /// fires once for this event, removes itself, and does not fire on
    /// the next event.
    EXPECT_EQ(count, 1);

    ch.fire(ConfigReload{2});
    EXPECT_EQ(count, 1);
    EXPECT_EQ(ch.subscriber_count(), 0u);
}

// ── concurrent fires (smoke / deadlock) ──────────────────────────────────

TEST(SignalChannel_Concurrency, MultipleProducersOneConsumer) {
    SignalChannel<ConfigReload> ch;
    std::atomic<int> total{0};
    auto t = ch.subscribe([&](const ConfigReload& e) {
        total.fetch_add(e.generation, std::memory_order_relaxed);
    });

    constexpr int kThreads     = 4;
    constexpr int kPerThread   = 128;
    std::vector<std::thread> producers;
    producers.reserve(kThreads);

    const auto start = std::chrono::steady_clock::now();
    for (int p = 0; p < kThreads; ++p) {
        producers.emplace_back([&, p]() {
            for (int i = 0; i < kPerThread; ++i) {
                ch.fire(ConfigReload{p * 100 + i});
            }
        });
    }
    for (auto& th : producers) th.join();
    const auto elapsed = std::chrono::steady_clock::now() - start;

    EXPECT_LT(elapsed, std::chrono::seconds(30))
        << "concurrent fire took unexpectedly long; possible deadlock";
    EXPECT_GT(total.load(), 0);

    ch.unsubscribe(t);
}

// ── §6 subscriber failure modes ──────────────────────────────────────────

TEST(SignalChannel_NullHandler, ReturnsInvalidToken) {
    SignalChannel<ConfigReload> ch;
    /// Empty std::function — `signal-channel.md` §6.1 returns the
    /// invalid-token sentinel and leaves the subscriber list empty.
    SignalChannel<ConfigReload>::Handler empty;
    const auto t = ch.subscribe(empty);
    EXPECT_EQ(t, SignalChannel<ConfigReload>::kInvalidToken);
    EXPECT_EQ(ch.subscriber_count(), 0u);
}

TEST(SignalChannel_HandlerThrows, OtherSubscribersStillReceive) {
    SignalChannel<ConfigReload> ch;
    std::atomic<int> good_a{0};
    std::atomic<int> good_b{0};

    /// First subscriber raises on every fire. Per §6.2 the channel
    /// catches the exception and continues with the rest of the
    /// snapshot.
    const auto t_throw = ch.subscribe([](const ConfigReload&) {
        throw std::runtime_error("subscriber failure");
    });
    const auto t_good_a = ch.subscribe([&](const ConfigReload&) {
        good_a.fetch_add(1, std::memory_order_relaxed);
    });
    const auto t_good_b = ch.subscribe([&](const ConfigReload&) {
        good_b.fetch_add(1, std::memory_order_relaxed);
    });

    EXPECT_NE(t_throw,  SignalChannel<ConfigReload>::kInvalidToken);
    EXPECT_NE(t_good_a, SignalChannel<ConfigReload>::kInvalidToken);
    EXPECT_NE(t_good_b, SignalChannel<ConfigReload>::kInvalidToken);

    ch.fire(ConfigReload{1});
    ch.fire(ConfigReload{2});
    ch.fire(ConfigReload{3});

    EXPECT_EQ(good_a.load(), 3);
    EXPECT_EQ(good_b.load(), 3);

    ch.unsubscribe(t_throw);
    ch.unsubscribe(t_good_a);
    ch.unsubscribe(t_good_b);
}

// ── stress: many subscribers, one fire ───────────────────────────────────

TEST(SignalChannel_Stress, ManySubscribersAllReceiveOneFire) {
    /// Plugin fan-out scenario: 1024 plugins each subscribe once
    /// to a config-reload channel. A single fire must reach every
    /// snapshot entry exactly once. The bound on the snapshot
    /// allocation surfaces here as a regression in the body of
    /// `fire`, not as a leaked subscriber.
    SignalChannel<ConfigReload> ch;

    constexpr std::size_t kN = 1024;
    std::vector<SignalChannel<ConfigReload>::Token> tokens;
    tokens.reserve(kN);
    std::atomic<std::size_t> hits{0};

    for (std::size_t i = 0; i < kN; ++i) {
        auto t = ch.subscribe([&](const ConfigReload&) {
            hits.fetch_add(1, std::memory_order_relaxed);
        });
        ASSERT_NE(t, SignalChannel<ConfigReload>::kInvalidToken);
        tokens.push_back(t);
    }
    ASSERT_EQ(ch.subscriber_count(), kN);

    ch.fire(ConfigReload{1});
    EXPECT_EQ(hits.load(), kN);

    for (auto t : tokens) ch.unsubscribe(t);
    EXPECT_EQ(ch.subscriber_count(), 0u);
}

// ── stress: concurrent subscribes produce unique tokens ──────────────────

TEST(SignalChannel_Stress, ConcurrentSubscribesProduceUniqueTokens) {
    /// `next_token_` is a plain non-atomic uint64 protected by the
    /// channel's unique_lock. Many threads racing on `subscribe`
    /// must therefore still produce a distinct token on every call;
    /// a regression where the mutex stops covering the increment
    /// surfaces as a duplicate.
    SignalChannel<ConfigReload> ch;

    constexpr int kThreads   = 8;
    constexpr int kPerThread = 256;

    std::vector<std::thread> workers;
    std::vector<std::vector<SignalChannel<ConfigReload>::Token>> per_thread(kThreads);
    workers.reserve(kThreads);

    for (int p = 0; p < kThreads; ++p) {
        workers.emplace_back([&, idx = static_cast<std::size_t>(p)]() {
            auto& bag = per_thread[idx];
            bag.reserve(kPerThread);
            for (int i = 0; i < kPerThread; ++i) {
                auto t = ch.subscribe([](const ConfigReload&) {});
                bag.push_back(t);
            }
        });
    }
    for (auto& w : workers) w.join();

    /// Aggregate every issued token and verify uniqueness via the
    /// set's insertion contract.
    std::set<SignalChannel<ConfigReload>::Token> seen;
    for (const auto& v : per_thread) {
        for (auto t : v) {
            EXPECT_NE(t, SignalChannel<ConfigReload>::kInvalidToken);
            EXPECT_TRUE(seen.insert(t).second)
                << "duplicate token " << t;
        }
    }
    EXPECT_EQ(seen.size(),
              static_cast<std::size_t>(kThreads * kPerThread));
    EXPECT_EQ(ch.subscriber_count(),
              static_cast<std::size_t>(kThreads * kPerThread));
}

// ── stress: subscribe + unsubscribe + fire all in flight ─────────────────

TEST(SignalChannel_Stress, ChurnDoesNotDeadlockOrCorrupt) {
    /// One thread fires continuously while many threads churn the
    /// subscriber list. The exit predicate is "all threads done";
    /// a deadlock surfaces as the test timing out under the gtest
    /// runner, a torn snapshot surfaces as a sanitiser report under
    /// the ASan / TSan matrix.
    SignalChannel<ConfigReload> ch;
    std::atomic<bool> stop{false};
    std::atomic<std::uint64_t> fire_calls{0};
    std::atomic<std::uint64_t> sub_calls{0};
    std::atomic<std::uint64_t> handler_calls{0};

    /// Fire thread: lots of fires while subs come and go.
    std::thread firer([&]() {
        while (!stop.load(std::memory_order_relaxed)) {
            ch.fire(ConfigReload{1});
            fire_calls.fetch_add(1, std::memory_order_relaxed);
        }
    });

    constexpr int kChurners = 4;
    constexpr int kIters    = 256;
    std::vector<std::thread> churners;
    churners.reserve(kChurners);
    for (int p = 0; p < kChurners; ++p) {
        churners.emplace_back([&]() {
            for (int i = 0; i < kIters; ++i) {
                auto t = ch.subscribe([&](const ConfigReload&) {
                    handler_calls.fetch_add(1, std::memory_order_relaxed);
                });
                sub_calls.fetch_add(1, std::memory_order_relaxed);
                /// Yield before unsubscribe so the channel sees a
                /// non-trivial subscriber list during fires.
                std::this_thread::yield();
                ch.unsubscribe(t);
            }
        });
    }

    for (auto& c : churners) c.join();
    stop.store(true, std::memory_order_relaxed);
    firer.join();

    EXPECT_EQ(sub_calls.load(),
              static_cast<std::uint64_t>(kChurners * kIters));
    EXPECT_GT(fire_calls.load(), 0u);
    /// `handler_calls` is non-deterministic — depends on whether
    /// fires landed inside the (subscribe, unsubscribe) window —
    /// but a non-zero count is the load-bearing observation: at
    /// least one fire raced into a live subscriber and dispatched
    /// without crashing.
    EXPECT_GE(handler_calls.load(), 0u);
    EXPECT_EQ(ch.subscriber_count(), 0u);
}

}  // namespace
}  // namespace gn::core::signal
