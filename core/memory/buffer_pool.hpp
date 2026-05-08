/// @file   core/memory/buffer_pool.hpp
/// @brief  Thread-local bucketed buffer pool — no mutex on the hot
///         path, recycles `std::vector<uint8_t>` across allocations.
///
/// `acquire(n)` pops a buffer from the thread-local free list (or
/// allocates a fresh one). `release(buf)` returns it for reuse. Free
/// lists are bucketed by `ceil(log2(capacity))`: a request for 800
/// bytes lands on the 1024-byte bucket, 5000 → 8192, and so on. Both
/// ends are O(1) amortised; thread-local storage avoids cross-thread
/// contention on the send/receive path.

#pragma once

#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace gn::core {

/// @brief Thread-local bucketed buffer pool.
class BufferPool {
    /// `log2(16 MiB) + 1` — anything larger goes straight to the heap.
    static constexpr std::size_t kNumBuckets = 25;

    struct ThreadCache {
        std::array<std::vector<std::vector<std::uint8_t>>, kNumBuckets> buckets{};
        std::size_t total_count = 0;
    };

    static ThreadCache& cache() {
        thread_local ThreadCache tc;
        return tc;
    }

    static std::size_t bucket_for(std::size_t cap) noexcept {
        if (cap <= 1) return 0;
        // `bit_width(cap - 1) == ceil(log2(cap))` for `cap >= 2`.
        return static_cast<std::size_t>(std::bit_width(cap - 1));
    }

    /// Configurable limits — set once at startup, read from any thread.
    static inline std::size_t max_free_per_thread_ = 128;
    static inline std::size_t max_buffer_retain_   = std::size_t{64} * 1024;

public:
    /// Configure pool limits. Call once before any acquire/release.
    static void configure(std::size_t max_buffers, std::size_t max_buf_size) {
        max_free_per_thread_ = max_buffers;
        max_buffer_retain_   = max_buf_size;
    }

    /// Acquire a buffer of at least @p size bytes. Reuses a pooled
    /// buffer when one is available in the matching size bucket.
    static std::vector<std::uint8_t> acquire(std::size_t size) {
        const auto idx = bucket_for(size);
        if (idx < kNumBuckets) {
            auto& bucket = cache().buckets[idx];
            if (!bucket.empty()) {
                auto buf = std::move(bucket.back());
                bucket.pop_back();
                --cache().total_count;
                buf.resize(size);
                return buf;
            }
        }
        return std::vector<std::uint8_t>(size);
    }

    /// Release a buffer back to the pool. Drops it on the floor when
    /// the per-thread cap is hit or the buffer is larger than the
    /// configured retention ceiling.
    static void release(std::vector<std::uint8_t> buf) {
        if (buf.capacity() > max_buffer_retain_) return;
        if (cache().total_count >= max_free_per_thread_) return;
        const auto idx = bucket_for(buf.capacity());
        if (idx >= kNumBuckets) return;
        buf.clear();
        cache().buckets[idx].push_back(std::move(buf));
        ++cache().total_count;
    }
};

} // namespace gn::core
