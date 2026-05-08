/// @file   core/crypto/crypto_worker_pool.hpp
/// @brief  Worker thread pool for parallel cryptographic batches.
///
/// Per `docs/contracts/backpressure.en.md` §3 the kernel drains a
/// per-connection ring of plaintext frames once `drain_scheduled`
/// is claimed; on a session that exposes a fast path, the encrypt
/// step runs at drain time so K parallel jobs amortise across
/// workers instead of serialising on the producer thread.
///
/// The pool is **algorithm-agnostic**: each `Job` carries the
/// callback that runs on the worker, plus a small set of
/// convenience fields suited to AEAD shapes (key / nonce / plain
/// / out). Sites that need a different shape — hashing, key
/// derivation, signature verification — repurpose `user_ctx` and
/// stamp their own callback. The pool itself never inspects the
/// fields; it just calls `job.fn(job)` and counts the latch down.
///
/// Each `run_batch` push-es N jobs guarded by a per-call
/// `std::latch`; workers pop `WorkItem{Job*, latch*}` from a
/// shared `std::deque` under mutex+cv. No state crosses batches
/// — the pool is reentrant for concurrent callers.

#pragma once

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <latch>
#include <mutex>
#include <span>
#include <thread>
#include <vector>

namespace gn::core {

/// @brief Worker thread pool for parallel cryptographic batches.
class CryptoWorkerPool {
public:
    struct Job;

    /// Worker callback. Reads / writes whatever fields of `job`
    /// the algorithm needs; stores the result length (or success
    /// flag) into `result_len`. `noexcept` because exceptions
    /// across the worker would orphan the latch.
    using JobFn = void (*)(Job& job) noexcept;

    /// One unit of work. The pool calls `fn(job)` on whichever
    /// worker pops the item; nothing else inspects the fields.
    struct Job {
        JobFn                          fn         = nullptr;
        /// Convenience slots for AEAD-shaped ops (ChaCha20-Poly1305,
        /// AES-GCM, future). Hashing / KDF / signature jobs
        /// repurpose `user_ctx` for their own state.
        const std::uint8_t*            key        = nullptr;
        std::uint64_t                  nonce      = 0;
        std::span<const std::uint8_t>  plain;
        std::span<std::uint8_t>        out;
        std::size_t                    result_len = 0;
        void*                          user_ctx   = nullptr;
    };

    /// Create a pool with N worker threads. `0` resolves to
    /// `max(1, hardware_concurrency()/2)` — half the cores
    /// leaves headroom for link plugin worker pools and the
    /// kernel-side drain caller.
    explicit CryptoWorkerPool(unsigned thread_count = 0);
    ~CryptoWorkerPool();

    CryptoWorkerPool(const CryptoWorkerPool&)            = delete;
    CryptoWorkerPool& operator=(const CryptoWorkerPool&) = delete;

    /// Run every job in @p jobs in parallel. Blocks until each
    /// `job.fn(job)` has returned. Single-job batches and empty
    /// pools fall through to a serial loop on the caller thread
    /// to skip the latch / cv handshake overhead. Safe to call
    /// from multiple threads concurrently.
    void run_batch(std::span<Job> jobs);

    [[nodiscard]] unsigned thread_count() const noexcept {
        return static_cast<unsigned>(workers_.size());
    }

private:
    struct WorkItem {
        Job*        job  = nullptr;
        std::latch* done = nullptr;
    };

    void worker_loop();

    std::vector<std::thread> workers_;
    std::atomic<bool>        stop_{false};

    std::mutex              queue_mu_;
    std::condition_variable queue_cv_;
    std::deque<WorkItem>    work_queue_;
};

} // namespace gn::core
