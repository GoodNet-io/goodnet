/// @file   core/crypto/crypto_worker_pool.cpp

#include "crypto_worker_pool.hpp"

#include <algorithm>

namespace gn::core {

CryptoWorkerPool::CryptoWorkerPool(unsigned thread_count) {
    if (thread_count == 0) {
        thread_count = std::max(1u, std::thread::hardware_concurrency() / 2);
    }
    workers_.reserve(thread_count);
    for (unsigned i = 0; i < thread_count; ++i) {
        workers_.emplace_back([this] { worker_loop(); });
    }
}

CryptoWorkerPool::~CryptoWorkerPool() {
    stop_.store(true, std::memory_order_release);
    queue_cv_.notify_all();
    for (auto& w : workers_) {
        if (w.joinable()) w.join();
    }

    /// Workers exit on `stop_` without finishing the queue, so a
    /// thread still blocked inside `run_batch`'s `done.wait()`
    /// would hang forever. Drain any leftover items here, count
    /// them down, so callers either see their (now-stale) outputs
    /// or unblock cleanly. The pool is being destroyed — the data
    /// will not actually be sent — but a graceful wakeup beats a
    /// permanent stall in shutdown / test teardown paths.
    std::lock_guard lk(queue_mu_);
    for (auto& item : work_queue_) {
        if (item.done != nullptr) item.done->count_down();
    }
    work_queue_.clear();
}

void CryptoWorkerPool::run_batch(std::span<Job> jobs) {
    if (jobs.empty()) return;

    /// Single job or empty pool — run inline on the caller thread.
    /// The latch + cv handshake overhead would dominate the
    /// micro-cost of a single ChaCha pass; serial is faster.
    if (jobs.size() == 1 || workers_.empty()) {
        for (auto& j : jobs) {
            if (j.fn != nullptr) j.fn(j);
        }
        return;
    }

    std::latch done(static_cast<std::ptrdiff_t>(jobs.size()));
    {
        std::lock_guard lk(queue_mu_);
        for (auto& j : jobs) {
            work_queue_.push_back({&j, &done});
        }
    }
    queue_cv_.notify_all();
    done.wait();
}

void CryptoWorkerPool::worker_loop() {
    while (!stop_.load(std::memory_order_acquire)) {
        WorkItem item{};
        {
            std::unique_lock lk(queue_mu_);
            queue_cv_.wait(lk, [this] {
                return stop_.load(std::memory_order_acquire) ||
                       !work_queue_.empty();
            });
            if (stop_.load(std::memory_order_acquire)) return;
            if (!work_queue_.empty()) {
                item = work_queue_.front();
                work_queue_.pop_front();
            }
        }
        if (item.job != nullptr && item.job->fn != nullptr) {
            item.job->fn(*item.job);
        }
        if (item.done != nullptr) item.done->count_down();
    }
}

} // namespace gn::core
