/// @file   core/kernel/timer_registry.cpp
/// @brief  Implementation of the kernel service executor.

#include "timer_registry.hpp"

#include <asio/post.hpp>

#include <utility>

namespace gn::core {

TimerRegistry::TimerRegistry()
    : ioc_(),
      work_(asio::make_work_guard(ioc_)) {
    worker_ = std::thread([this] { ioc_.run(); });
}

TimerRegistry::~TimerRegistry() {
    /// `shutdown()` joins the worker; bad_executor or thread-join
    /// failure surfaces as `system_error` in practice. The dtor
    /// stays noexcept by counting the swallowed exception so the
    /// post-mortem at least sees how many shutdowns went wrong.
    try {
        shutdown();
    } catch (const std::exception&) {
        shutdown_throws_.fetch_add(1, std::memory_order_relaxed);
    }
}

void TimerRegistry::set_max_timers(std::uint32_t v) noexcept {
    max_timers_.store(v, std::memory_order_relaxed);
}
void TimerRegistry::set_max_pending_tasks(std::uint32_t v) noexcept {
    max_pending_tasks_.store(v, std::memory_order_relaxed);
}

std::size_t TimerRegistry::active_timers() const noexcept {
    std::lock_guard lk(mu_);
    return timers_.size();
}

std::size_t TimerRegistry::pending_tasks() const noexcept {
    return pending_tasks_.load(std::memory_order_relaxed);
}

gn_result_t TimerRegistry::set_timer(std::uint32_t  delay_ms,
                                       gn_task_fn_t   fn,
                                       void*          user_data,
                                       const std::shared_ptr<void>& anchor,
                                       gn_timer_id_t* out_id) noexcept {
    if (fn == nullptr || out_id == nullptr) return GN_ERR_NULL_ARG;
    if (shutdown_.load(std::memory_order_acquire)) {
        return GN_ERR_INVALID_STATE;
    }

    try {
        {
            std::lock_guard lk(mu_);
            if (timers_.size() >=
                max_timers_.load(std::memory_order_relaxed)) {
                return GN_ERR_LIMIT_REACHED;
            }
        }

        const auto id = next_id_.fetch_add(1, std::memory_order_relaxed);
        auto timer = std::make_shared<asio::steady_timer>(
            ioc_, std::chrono::milliseconds{delay_ms});

        TimerEntry entry;
        entry.timer      = timer;
        entry.anchor     = anchor;
        entry.fn         = fn;
        entry.user_data  = user_data;
        entry.anchor_set = static_cast<bool>(anchor);

        {
            std::lock_guard lk(mu_);
            timers_.emplace(id, std::move(entry));
        }

        timer->async_wait([this, id, fn, user_data,
                           anchor_weak = std::weak_ptr<void>(anchor),
                           anchor_set = static_cast<bool>(anchor)](
            const std::error_code& ec) {
            TimerEntry consumed;
            bool found = false;
            {
                std::lock_guard lk(mu_);
                auto it = timers_.find(id);
                if (it != timers_.end()) {
                    consumed = std::move(it->second);
                    timers_.erase(it);
                    found = true;
                }
            }
            if (!found) return;          // cancelled before fire
            if (ec)     return;          // operation_aborted, etc.

            /// Lifetime gate: drop the dispatch when the calling
            /// plugin's quiescence sentinel has expired. Anchor-less
            /// timers (in-tree fixtures) skip the gate.
            if (anchor_set && anchor_weak.expired()) return;
            fn(user_data);
        });

        *out_id = id;
        return GN_OK;
    } catch (const std::bad_alloc&) {
        return GN_ERR_OUT_OF_MEMORY;
    } catch (const std::exception&) {
        return GN_ERR_NULL_ARG;
    }
}

gn_result_t TimerRegistry::cancel_timer(gn_timer_id_t id) noexcept {
    if (id == GN_INVALID_TIMER_ID) return GN_ERR_NULL_ARG;
    try {
        std::shared_ptr<asio::steady_timer> doomed;
        {
            std::lock_guard lk(mu_);
            auto it = timers_.find(id);
            if (it == timers_.end()) return GN_OK;  // idempotent
            doomed = std::move(it->second.timer);
            timers_.erase(it);
        }
        /// `cancel()` on a steady_timer queues the wait callback
        /// with `operation_aborted`; the lambda above sees
        /// `found == false` because the entry is already erased.
        if (doomed->cancel() > 0) {}
        return GN_OK;
    } catch (const std::exception&) {
        return GN_ERR_NULL_ARG;
    }
}

gn_result_t TimerRegistry::post(gn_task_fn_t                 fn,
                                 void*                        user_data,
                                 const std::shared_ptr<void>& anchor) noexcept {
    if (fn == nullptr) return GN_ERR_NULL_ARG;
    if (shutdown_.load(std::memory_order_acquire)) {
        return GN_ERR_INVALID_STATE;
    }
    if (pending_tasks_.load(std::memory_order_relaxed) >=
        max_pending_tasks_.load(std::memory_order_relaxed)) {
        return GN_ERR_LIMIT_REACHED;
    }

    try {
        pending_tasks_.fetch_add(1, std::memory_order_relaxed);
        asio::post(ioc_,
            [this, fn, user_data,
             anchor_weak = std::weak_ptr<void>(anchor),
             anchor_set = static_cast<bool>(anchor)] {
                pending_tasks_.fetch_sub(1, std::memory_order_relaxed);
                if (anchor_set && anchor_weak.expired()) return;
                fn(user_data);
            });
        return GN_OK;
    } catch (const std::bad_alloc&) {
        pending_tasks_.fetch_sub(1, std::memory_order_relaxed);
        return GN_ERR_OUT_OF_MEMORY;
    } catch (const std::exception&) {
        pending_tasks_.fetch_sub(1, std::memory_order_relaxed);
        return GN_ERR_NULL_ARG;
    }
}

void TimerRegistry::cancel_for_anchor(
    const std::shared_ptr<void>& anchor) noexcept {
    if (!anchor) return;
    try {
        std::vector<std::shared_ptr<asio::steady_timer>> doomed;
        {
            std::lock_guard lk(mu_);
            for (auto it = timers_.begin(); it != timers_.end(); ) {
                auto locked = it->second.anchor.lock();
                if (locked.get() == anchor.get()) {
                    doomed.push_back(std::move(it->second.timer));
                    it = timers_.erase(it);
                } else {
                    ++it;
                }
            }
        }
        /// Cancel outside the lock so the wait callback's lock
        /// acquisition cannot self-deadlock.
        for (auto& t : doomed) {
            if (t->cancel() > 0) {}
        }
    } catch (const std::exception&) {
        /// Best-effort: the lifetime gate inside async_wait still
        /// drops the dispatch on expiry even if matching here
        /// failed. Counted so callers can surface the rare event.
        shutdown_throws_.fetch_add(1, std::memory_order_relaxed);
    }
}

void TimerRegistry::shutdown() {
    if (shutdown_.exchange(true, std::memory_order_acq_rel)) return;
    {
        std::lock_guard lk(mu_);
        for (auto& [_, entry] : timers_) {
            if (entry.timer && entry.timer->cancel() > 0) {}
        }
        timers_.clear();
    }
    work_.reset();
    ioc_.stop();
    if (worker_.joinable()) worker_.join();
}

} // namespace gn::core
