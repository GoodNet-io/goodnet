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
void TimerRegistry::set_max_timers_per_plugin(std::uint32_t v) noexcept {
    max_timers_per_plugin_.store(v, std::memory_order_relaxed);
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
                                       const std::shared_ptr<PluginAnchor>& anchor,
                                       gn_timer_id_t* out_id) noexcept {
    if (fn == nullptr || out_id == nullptr) return GN_ERR_NULL_ARG;
    if (shutdown_.load(std::memory_order_acquire)) {
        return GN_ERR_INVALID_STATE;
    }

    try {
        /// Per-plugin sub-quota (`limits.md` §4a /
        /// `max_timers_per_plugin`). The counter is always
        /// maintained when an anchor is supplied — the cap is
        /// consulted at admit time, but the fetch_sub at the head
        /// of every fire / cancel callback expects a fetch_add to
        /// pair with regardless of whether the cap was zero at
        /// admission. That keeps the count consistent if the
        /// operator raises the cap mid-flight from zero to a
        /// non-zero value, and lets diagnostics surface the live
        /// per-plugin timer pressure even before a cap is set.
        ///
        /// The compare-and-exchange loop guards against two
        /// concurrent admits both squeaking past the cap; the cap
        /// of zero is rendered as "no upper bound" via the
        /// `max == 0 || cur < max` predicate.
        if (anchor) {
            const std::uint32_t per_plugin_cap =
                max_timers_per_plugin_.load(std::memory_order_relaxed);
            std::uint32_t cur =
                anchor->active_timers.load(std::memory_order_relaxed);
            while (true) {
                if (per_plugin_cap != 0 && cur >= per_plugin_cap) {
                    return GN_ERR_LIMIT_REACHED;
                }
                if (anchor->active_timers.compare_exchange_weak(
                        cur, cur + 1,
                        std::memory_order_acq_rel,
                        std::memory_order_relaxed)) {
                    break;
                }
            }
        }

        gn_timer_id_t id = GN_INVALID_TIMER_ID;
        std::shared_ptr<asio::steady_timer> timer;
        {
            /// Hold `mu_` from the global-cap check through the
            /// `emplace`. `limits.md` §4 — a cap of zero disables
            /// enforcement. The pre-fix path released the lock
            /// between the size check and the emplace; two admits
            /// racing through that window could both observe
            /// `size() < cap` and both push, leaving the registry
            /// at `cap + 1`. Holding the lock collapses the window
            /// at the cost of constructing the asio timer and the
            /// entry under the mutex — both are short and bounded
            /// (one heap allocation, no syscalls).
            std::lock_guard lk(mu_);
            const std::uint32_t cap =
                max_timers_.load(std::memory_order_relaxed);
            if (cap != 0 && timers_.size() >= cap) {
                if (anchor) {
                    anchor->active_timers.fetch_sub(
                        1, std::memory_order_acq_rel);
                }
                return GN_ERR_LIMIT_REACHED;
            }
            id = next_id_.fetch_add(1, std::memory_order_relaxed);
            timer = std::make_shared<asio::steady_timer>(
                ioc_, std::chrono::milliseconds{delay_ms});
            TimerEntry entry;
            entry.timer     = timer;
            entry.anchor    = anchor;
            entry.fn        = fn;
            entry.user_data = user_data;
            timers_.emplace(id, std::move(entry));
        }

        timer->async_wait([this, id, fn, user_data,
                           anchor_weak = std::weak_ptr<PluginAnchor>(anchor),
                           anchor_set = static_cast<bool>(anchor)](
            const std::error_code& ec) {
            /// Refund the per-plugin timer quota at the head of the
            /// callback so every dispatch path — natural fire,
            /// cancel-before-fire, anchor-expired drop — credits
            /// the slot back. Without this the cancel path would
            /// leak the increment and the plugin would slowly
            /// exhaust its budget.
            if (anchor_set) {
                if (auto strong = anchor_weak.lock()) {
                    strong->active_timers.fetch_sub(
                        1, std::memory_order_acq_rel);
                }
            }

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

            /// Cancellation gate: open a `GateGuard` for the
            /// duration of the dispatch. Acquire fails if the
            /// anchor expired or the rollback path already published
            /// `shutdown_requested = true`; the guard's destructor
            /// drops the in-flight counter and wakes the drain CV
            /// on the last release. Anchor-less timers (in-tree
            /// fixtures) skip the gate.
            if (anchor_set) {
                auto guard = GateGuard::acquire(anchor_weak);
                if (!guard) return;
                fn(user_data);
            } else {
                fn(user_data);
            }
        });

        *out_id = id;
        return GN_OK;
    } catch (const std::bad_alloc&) {
        if (anchor) {
            anchor->active_timers.fetch_sub(1, std::memory_order_acq_rel);
        }
        return GN_ERR_OUT_OF_MEMORY;
    } catch (const std::exception&) {
        if (anchor) {
            anchor->active_timers.fetch_sub(1, std::memory_order_acq_rel);
        }
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
                                 const std::shared_ptr<PluginAnchor>& anchor) noexcept {
    if (fn == nullptr) return GN_ERR_NULL_ARG;
    if (shutdown_.load(std::memory_order_acquire)) {
        return GN_ERR_INVALID_STATE;
    }
    /// Compare-and-exchange admission: read the current pending
    /// count, reject when it would step over the cap, otherwise
    /// publish the increment. Two concurrent admits cannot both
    /// observe a sub-cap value and both pass the check — the
    /// loser's CAS sees an updated `cur` and re-evaluates against
    /// the cap. A cap of zero disables enforcement per
    /// `limits.md` §4. Mirrors the `set_timer` per-plugin
    /// admission loop.
    {
        std::uint32_t cur = pending_tasks_.load(std::memory_order_relaxed);
        while (true) {
            const std::uint32_t cap =
                max_pending_tasks_.load(std::memory_order_relaxed);
            if (cap != 0 && cur >= cap) {
                return GN_ERR_LIMIT_REACHED;
            }
            if (pending_tasks_.compare_exchange_weak(
                    cur, cur + 1,
                    std::memory_order_acq_rel,
                    std::memory_order_relaxed)) {
                break;
            }
        }
    }

    try {
        asio::post(ioc_,
            [this, fn, user_data,
             anchor_weak = std::weak_ptr<PluginAnchor>(anchor),
             anchor_set = static_cast<bool>(anchor)] {
                pending_tasks_.fetch_sub(1, std::memory_order_relaxed);
                /// See `set_timer` for the cancellation-gate
                /// rationale — the GateGuard's `in_flight` bump
                /// blocks `drain_anchor` from running `dlclose`
                /// while the dispatch is still in plugin code.
                if (anchor_set) {
                    auto guard = GateGuard::acquire(anchor_weak);
                    if (!guard) return;
                    fn(user_data);
                } else {
                    fn(user_data);
                }
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
    const std::shared_ptr<PluginAnchor>& anchor) noexcept {
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
