/// @file   core/registry/spsc_ring.hpp
/// @brief  Lock-free SPSC ring + MPSC adapter (producer spinlock).
///
/// Per `docs/contracts/backpressure.en.md` §2 the kernel must accept
/// `host_api->send` from any plugin thread without blocking on a per-
/// connection mutex. The SPSC variant runs free-of-lock through
/// relaxed/acquire/release atomics; the MPSC adapter wraps it with a
/// producer spinlock so concurrent senders coordinate without ever
/// stalling the consumer (`SendQueueManager` drainer).
///
/// Capacity is a template parameter defaulting to `kSendRingCapacity`,
/// a build-time constant. The slots live inline (`std::array`) so the
/// modulo mask is a `constexpr AND` and the consumer drains without
/// an indirection through the heap.

#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <type_traits>
#include <vector>

namespace gn::core {

/// Per-priority slot count in every send-side ring. Profile knobs are
/// out of scope for v1; the desktop default lives here and operators
/// pick a different value through a recompile when they need it.
inline constexpr std::size_t kSendRingCapacity = 2048;

/// @brief Lock-free SPSC ring buffer.
///
/// Power-of-2 capacity, one slot reserved to distinguish full from
/// empty so usable capacity is `N - 1`. Producer calls `try_push`;
/// consumer calls `try_pop` / `drain`. No mutex, no CAS — only
/// relaxed/acquire/release atomics.
template <typename T, std::size_t N = kSendRingCapacity>
class SpscRing {
    static_assert(N > 1 && (N & (N - 1)) == 0,
                  "SpscRing capacity must be a power of 2");
    static constexpr std::size_t kMask = N - 1;

public:
    SpscRing() = default;

    SpscRing(const SpscRing&)            = delete;
    SpscRing& operator=(const SpscRing&) = delete;

    /// Producer: enqueue one item. Returns false when the ring is full.
    bool try_push(T&& item) noexcept(std::is_nothrow_move_assignable_v<T>) {
        const std::size_t head = head_.load(std::memory_order_relaxed);
        const std::size_t next = (head + 1) & kMask;
        if (next == tail_.load(std::memory_order_acquire)) return false;
        buf_[head] = std::move(item);
        head_.store(next, std::memory_order_release);
        return true;
    }

    /// Consumer: dequeue one item. Returns false when the ring is empty.
    bool try_pop(T& out) noexcept(std::is_nothrow_move_assignable_v<T>) {
        const std::size_t tail = tail_.load(std::memory_order_relaxed);
        if (tail == head_.load(std::memory_order_acquire)) return false;
        out = std::move(buf_[tail]);
        tail_.store((tail + 1) & kMask, std::memory_order_release);
        return true;
    }

    /// Consumer: drain up to @p max items into @p out. Returns count drained.
    std::size_t drain(std::vector<T>& out, std::size_t max) {
        const std::size_t tail = tail_.load(std::memory_order_relaxed);
        const std::size_t head = head_.load(std::memory_order_acquire);
        if (tail == head) return 0;

        const std::size_t avail = (head - tail) & kMask;
        const std::size_t n     = (max < avail) ? max : avail;

        out.reserve(out.size() + n);
        std::size_t pos = tail;
        for (std::size_t i = 0; i < n; ++i) {
            out.push_back(std::move(buf_[pos]));
            pos = (pos + 1) & kMask;
        }
        tail_.store(pos, std::memory_order_release);
        return n;
    }

    [[nodiscard]] std::size_t size_approx() const noexcept {
        const std::size_t head = head_.load(std::memory_order_relaxed);
        const std::size_t tail = tail_.load(std::memory_order_relaxed);
        return (head - tail) & kMask;
    }

    [[nodiscard]] bool empty() const noexcept {
        return head_.load(std::memory_order_relaxed) ==
               tail_.load(std::memory_order_relaxed);
    }

    static constexpr std::size_t capacity() noexcept { return N - 1; }

private:
    alignas(64) std::atomic<std::size_t> head_{0};
    alignas(64) std::atomic<std::size_t> tail_{0};
    alignas(64) std::array<T, N>         buf_{};
};

/// @brief MPSC adapter — producers coordinate via a spinlock, the
///        single consumer drains lock-free.
///
/// Per `docs/impl/cpp/concurrency.md` the spinlock acquires only on
/// the push path. The drain path holds no lock, so the consumer never
/// contends with a producer; the spinlock is only ever observed when
/// two producers race to enqueue on the same connection.
template <typename T, std::size_t N = kSendRingCapacity>
class MpscRing {
public:
    MpscRing() = default;

    MpscRing(const MpscRing&)            = delete;
    MpscRing& operator=(const MpscRing&) = delete;

    /// Thread-safe push (multiple producers).
    bool try_push(T&& item) noexcept(std::is_nothrow_move_assignable_v<T>) {
        lock();
        const bool ok = ring_.try_push(std::move(item));
        unlock();
        return ok;
    }

    /// Single-consumer drain — no lock needed.
    std::size_t drain(std::vector<T>& out, std::size_t max) {
        return ring_.drain(out, max);
    }

    /// Single-consumer pop — no lock needed.
    bool try_pop(T& out) noexcept(std::is_nothrow_move_assignable_v<T>) {
        return ring_.try_pop(out);
    }

    [[nodiscard]] std::size_t size_approx() const noexcept { return ring_.size_approx(); }
    [[nodiscard]] bool empty() const noexcept { return ring_.empty(); }
    static constexpr std::size_t capacity() noexcept { return SpscRing<T, N>::capacity(); }

private:
    void lock() noexcept {
        while (flag_.test_and_set(std::memory_order_acquire))
            flag_.wait(true, std::memory_order_relaxed);
    }
    void unlock() noexcept {
        flag_.clear(std::memory_order_release);
        flag_.notify_one();
    }

    SpscRing<T, N>   ring_;
    std::atomic_flag flag_ = ATOMIC_FLAG_INIT;
};

} // namespace gn::core
