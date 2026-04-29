/// @file   core/util/token_bucket.hpp
/// @brief  Token-bucket rate limiter with explicit clock injection.
///
/// Per `docs/contracts/clock.md`, every time-dependent component
/// accepts its time source as an explicit input. The bucket is
/// templated on `Clock` so production code uses
/// `std::chrono::steady_clock` and tests use a deterministic mock
/// without `sleep_for` racing the sanitizer's slowdown.
///
/// `TokenBucket<Clock>` itself carries no mutex — concurrent callers
/// serialise externally (the `RateLimiterMap` below holds the only
/// mutex; per-key buckets live inside its lock). Keeping the bucket
/// move-able lets the map store entries by value.

#pragma once

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <list>
#include <mutex>
#include <unordered_map>

namespace gn::util {

/// @tparam Clock  monotonic clock providing `time_point` and `now()`
///                with ticks convertible to `std::chrono::duration<double>`.
template <class Clock = std::chrono::steady_clock>
class TokenBucket {
public:
    using time_point = typename Clock::time_point;

    constexpr TokenBucket() noexcept = default;

    /// Construct a bucket that holds @p burst tokens, refills at
    /// @p rate tokens per second, and treats @p start as the most
    /// recent refill timestamp.
    TokenBucket(double rate, double burst, time_point start) noexcept
        : rate_(rate), burst_(burst), tokens_(burst), last_(start) {}

    /// Try to consume one token at @p now. Refills the bucket from
    /// the elapsed interval since the last call, then deducts one
    /// token if the bucket is non-empty. Returns true on consumption,
    /// false on empty.
    [[nodiscard]] bool try_consume(time_point now) noexcept {
        refill(now);
        if (tokens_ >= 1.0) {
            tokens_ -= 1.0;
            return true;
        }
        return false;
    }

    /// Reset the bucket to a fresh @p rate and @p burst with @p start
    /// as the new last-refill timestamp. Useful when the limiter's
    /// policy changes at runtime (config reload).
    void reset(double rate, double burst, time_point start) noexcept {
        rate_   = rate;
        burst_  = burst;
        tokens_ = burst;
        last_   = start;
    }

    [[nodiscard]] double rate()   const noexcept { return rate_; }
    [[nodiscard]] double burst()  const noexcept { return burst_; }
    [[nodiscard]] double tokens() const noexcept { return tokens_; }

private:
    void refill(time_point now) noexcept {
        const auto elapsed =
            std::chrono::duration<double>(now - last_).count();
        if (elapsed > 0.0) {
            tokens_ = std::min(burst_, tokens_ + elapsed * rate_);
            last_   = now;
        }
    }

    double     rate_   = 0.0;
    double     burst_  = 0.0;
    double     tokens_ = 0.0;
    time_point last_{};
};

/// Per-key token bucket map with LRU eviction. One mutex protects the
/// map and every nested bucket.
///
/// @tparam Clock  same shape as `TokenBucket<Clock>::Clock`.
template <class Clock = std::chrono::steady_clock>
class RateLimiterMap {
public:
    using time_point = typename Clock::time_point;

    explicit RateLimiterMap(double rate, double burst,
                             std::size_t max_entries = 4096) noexcept
        : rate_(rate), burst_(burst), max_entries_(max_entries) {}

    /// Allow one request keyed on @p key at @p now. Lazily creates a
    /// bucket on the first hit; evicts the least-recently-used entry
    /// when the map reaches `max_entries`. Returns true on consumption.
    [[nodiscard]] bool allow(std::uint64_t key, time_point now) {
        std::lock_guard<std::mutex> lk(mu_);

        if (auto it = map_.find(key); it != map_.end()) {
            lru_.splice(lru_.begin(), lru_, it->second.lru_it);
            return it->second.bucket.try_consume(now);
        }

        if (map_.size() >= max_entries_) {
            const auto oldest = lru_.back();
            lru_.pop_back();
            map_.erase(oldest);
        }

        lru_.push_front(key);
        Entry e{TokenBucket<Clock>(rate_, burst_, now), lru_.begin()};
        /// First request always allowed; debit one token on insert.
        (void)e.bucket.try_consume(now);
        map_.emplace(key, std::move(e));
        return true;
    }

    /// Convenience overload that reads `Clock::now()` directly. Use
    /// in production paths; tests should pass time explicitly.
    [[nodiscard]] bool allow(std::uint64_t key) {
        return allow(key, Clock::now());
    }

    /// Replace the active @p rate and @p burst, drop every existing
    /// per-key bucket, and clear the LRU. Subsequent `allow` calls
    /// observe the new policy from a fresh state. Mirrors
    /// `TokenBucket::reset` at map scope; the kernel reuses this when
    /// reload-time policy changes invalidate the prior buckets and
    /// tests use it to install a deterministic, tight bucket.
    void reset(double rate, double burst) noexcept {
        std::lock_guard<std::mutex> lk(mu_);
        rate_  = rate;
        burst_ = burst;
        map_.clear();
        lru_.clear();
    }

    [[nodiscard]] std::size_t size() const {
        std::lock_guard<std::mutex> lk(mu_);
        return map_.size();
    }

private:
    struct Entry {
        TokenBucket<Clock>                  bucket;
        typename std::list<std::uint64_t>::iterator lru_it;
    };

    mutable std::mutex                                  mu_;
    double                                              rate_;
    double                                              burst_;
    std::size_t                                         max_entries_;
    std::list<std::uint64_t>                            lru_;
    std::unordered_map<std::uint64_t, Entry>            map_;
};

}  // namespace gn::util
