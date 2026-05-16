// SPDX-License-Identifier: MIT
/// @file   tests/unit/util/test_token_bucket.cpp
/// @brief  TokenBucket + RateLimiterMap with mock clock — deterministic
///         under sanitizers; no sleep_for, no real time.

#include <gtest/gtest.h>

#include <sdk/cpp/token_bucket.hpp>

#include <chrono>
#include <cstdint>

namespace {

using namespace std::chrono_literals;

/// Mock clock satisfying the shape `TokenBucket` expects: nested
/// `time_point` type and a `now()` static reading. Tick is advanced
/// only by `advance(dur)`, never by real time.
struct MockClock {
    using duration   = std::chrono::nanoseconds;
    using rep        = duration::rep;
    using period     = duration::period;
    using time_point = std::chrono::time_point<MockClock>;

    static inline time_point current{};

    static time_point now() noexcept { return current; }

    template <class Dur>
    static void advance(Dur d) noexcept {
        current += std::chrono::duration_cast<duration>(d);
    }

    static void reset() noexcept { current = time_point{}; }
};

}  // namespace

// ── TokenBucket ──────────────────────────────────────────────────────────

TEST(TokenBucket, BurstConsumedThenEmpty) {
    MockClock::reset();
    ::gn::ratelimit::TokenBucket<MockClock> bucket(/*rate*/ 1.0, /*burst*/ 3.0,
                                                MockClock::now());
    EXPECT_TRUE(bucket.try_consume(MockClock::now()));
    EXPECT_TRUE(bucket.try_consume(MockClock::now()));
    EXPECT_TRUE(bucket.try_consume(MockClock::now()));
    EXPECT_FALSE(bucket.try_consume(MockClock::now()));  /// burst exhausted
}

TEST(TokenBucket, RefillsByElapsedTimeAndRate) {
    MockClock::reset();
    ::gn::ratelimit::TokenBucket<MockClock> bucket(/*rate*/ 10.0, /*burst*/ 5.0,
                                                MockClock::now());
    /// drain the burst
    for (int i = 0; i < 5; ++i) {
        EXPECT_TRUE(bucket.try_consume(MockClock::now()));
    }
    EXPECT_FALSE(bucket.try_consume(MockClock::now()));

    MockClock::advance(200ms);   /// 0.2s × 10/s = 2 tokens
    EXPECT_TRUE(bucket.try_consume(MockClock::now()));
    EXPECT_TRUE(bucket.try_consume(MockClock::now()));
    EXPECT_FALSE(bucket.try_consume(MockClock::now()));
}

TEST(TokenBucket, RefillCappedAtBurst) {
    MockClock::reset();
    ::gn::ratelimit::TokenBucket<MockClock> bucket(/*rate*/ 100.0, /*burst*/ 4.0,
                                                MockClock::now());
    /// Drain
    for (int i = 0; i < 4; ++i) (void)bucket.try_consume(MockClock::now());

    MockClock::advance(10s);     /// would refill 1000, but capped at 4
    EXPECT_TRUE(bucket.try_consume(MockClock::now()));
    EXPECT_TRUE(bucket.try_consume(MockClock::now()));
    EXPECT_TRUE(bucket.try_consume(MockClock::now()));
    EXPECT_TRUE(bucket.try_consume(MockClock::now()));
    EXPECT_FALSE(bucket.try_consume(MockClock::now()));
}

TEST(TokenBucket, ResetReplacesPolicyAndRefillsToBurst) {
    MockClock::reset();
    ::gn::ratelimit::TokenBucket<MockClock> bucket(/*rate*/ 1.0, /*burst*/ 1.0,
                                                MockClock::now());
    EXPECT_TRUE(bucket.try_consume(MockClock::now()));
    EXPECT_FALSE(bucket.try_consume(MockClock::now()));

    bucket.reset(/*rate*/ 10.0, /*burst*/ 5.0, MockClock::now());
    /// Reset refills to burst; five consecutive consumes succeed.
    for (int i = 0; i < 5; ++i) {
        EXPECT_TRUE(bucket.try_consume(MockClock::now()));
    }
    EXPECT_FALSE(bucket.try_consume(MockClock::now()));
}

// ── RateLimiterMap ───────────────────────────────────────────────────────

TEST(RateLimiterMap, FirstRequestPerKeyAllowed) {
    MockClock::reset();
    ::gn::ratelimit::RateLimiterMap<MockClock> map(/*rate*/ 1.0, /*burst*/ 1.0);
    EXPECT_TRUE(map.allow(/*key*/ 1, MockClock::now()));
    EXPECT_TRUE(map.allow(/*key*/ 2, MockClock::now()));
    EXPECT_TRUE(map.allow(/*key*/ 3, MockClock::now()));
    EXPECT_EQ(map.size(), 3u);
}

TEST(RateLimiterMap, IndependentKeysIsolated) {
    MockClock::reset();
    ::gn::ratelimit::RateLimiterMap<MockClock> map(/*rate*/ 1.0, /*burst*/ 2.0);
    /// Key 1 burns its burst.
    EXPECT_TRUE(map.allow(1, MockClock::now()));
    EXPECT_TRUE(map.allow(1, MockClock::now()));
    EXPECT_FALSE(map.allow(1, MockClock::now()));
    /// Key 2 still has its own burst.
    EXPECT_TRUE(map.allow(2, MockClock::now()));
    EXPECT_TRUE(map.allow(2, MockClock::now()));
    EXPECT_FALSE(map.allow(2, MockClock::now()));
}

TEST(RateLimiterMap, RefillBetweenCallsAfterTimeAdvance) {
    MockClock::reset();
    ::gn::ratelimit::RateLimiterMap<MockClock> map(/*rate*/ 10.0, /*burst*/ 1.0);
    EXPECT_TRUE(map.allow(7, MockClock::now()));
    EXPECT_FALSE(map.allow(7, MockClock::now()));
    MockClock::advance(110ms);   /// 0.11s × 10/s = 1.1 tokens (capped at burst=1)
    EXPECT_TRUE(map.allow(7, MockClock::now()));
}

TEST(RateLimiterMap, LruEvictsOldestWhenAtCapacity) {
    MockClock::reset();
    ::gn::ratelimit::RateLimiterMap<MockClock> map(/*rate*/ 1.0, /*burst*/ 1.0,
                                                /*max_entries*/ 2);
    EXPECT_TRUE(map.allow(1, MockClock::now()));
    EXPECT_TRUE(map.allow(2, MockClock::now()));
    EXPECT_EQ(map.size(), 2u);

    /// Touch key 1 so key 2 becomes the LRU.
    MockClock::advance(2s);
    (void)map.allow(1, MockClock::now());

    /// Insert key 3 — key 2 is evicted.
    EXPECT_TRUE(map.allow(3, MockClock::now()));
    EXPECT_EQ(map.size(), 2u);

    /// Re-inserting key 2 looks like a fresh entry — first request OK.
    EXPECT_TRUE(map.allow(2, MockClock::now()));
}
