/// @file   core/kernel/timer_registry.cpp
/// @brief  Implementation of the kernel service executor.

#include "timer_registry.hpp"

#include <stdexec/execution.hpp>
#include <exec/timed_thread_scheduler.hpp>
#include <exec/start_detached.hpp>
namespace exec = experimental::execution;

#include <utility>

#include "safe_invoke.hpp"

namespace gn::core {

TimerRegistry::TimerRegistry()
    : ctx_()
{
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
    /// `out_id == nullptr` is the fire-and-forget shape: the
    /// caller drops the cancel handle and trusts the kernel to
    /// run the work without holding a reference. `fn == nullptr`
    /// is the only hard NULL_ARG path.
    if (fn == nullptr) return GN_ERR_NULL_ARG;
    if (shutdown_.load(std::memory_order_acquire)) {
        return GN_ERR_INVALID_STATE;
    }

    try {
        /// Per-plugin sub-quota (`limits.en.md` §4a /
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
        {
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
            TimerEntry entry;
            entry.anchor    = anchor;
            entry.fn        = fn;
            entry.user_data = user_data;
            timers_.emplace(id, std::move(entry));
        }

        exec::start_detached(
            exec::schedule_after(ctx_.get_scheduler(),
                                 std::chrono::milliseconds{delay_ms})
            | stdexec::then([this, id, fn, user_data,
                             anchor_weak = std::weak_ptr<PluginAnchor>(anchor),
                             anchor_set  = static_cast<bool>(anchor)]() noexcept {
                if (anchor_set) {
                    if (auto s = anchor_weak.lock()) {
                        s->active_timers.fetch_sub(1, std::memory_order_acq_rel);
                    }
                }
                {
                    std::lock_guard lk(mu_);
                    auto it = timers_.find(id);
                    if (it == timers_.end()) return; // cancelled
                    timers_.erase(it);
                }
                if (anchor_set) {
                    auto guard = GateGuard::acquire(anchor_weak);
                    if (!guard) return;
                    safe_call_void("timer.callback", fn, user_data);
                } else {
                    safe_call_void("timer.callback", fn, user_data);
                }
            })
            | stdexec::upon_stopped([]() noexcept {}) // absorb set_stopped when ctx_ shuts down
        );

        if (out_id != nullptr) *out_id = id;
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
        std::weak_ptr<PluginAnchor> anchor_weak;
        bool had_anchor = false;
        {
            std::lock_guard lk(mu_);
            auto it = timers_.find(id);
            if (it == timers_.end()) return GN_OK;
            anchor_weak = it->second.anchor;
            had_anchor  = !anchor_weak.expired();
            timers_.erase(it);
        }
        if (had_anchor) {
            if (auto s = anchor_weak.lock()) {
                s->active_timers.fetch_sub(1, std::memory_order_acq_rel);
            }
        }
        // The pending schedule_after will fire later and see the id absent
        // from timers_, so it skips the callback cleanly.
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
    /// `limits.en.md` §4. Mirrors the `set_timer` per-plugin
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
        exec::start_detached(
            stdexec::schedule(ctx_.get_scheduler())
            | stdexec::then([this, fn, user_data,
                             anchor_weak = std::weak_ptr<PluginAnchor>(anchor),
                             anchor_set  = static_cast<bool>(anchor)]() noexcept {
                pending_tasks_.fetch_sub(1, std::memory_order_relaxed);
                if (anchor_set) {
                    auto guard = GateGuard::acquire(anchor_weak);
                    if (!guard) return;
                    safe_call_void("executor.task", fn, user_data);
                } else {
                    safe_call_void("executor.task", fn, user_data);
                }
            })
            | stdexec::upon_stopped([]() noexcept {})
        );
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
        {
            std::lock_guard lk(mu_);
            for (auto it = timers_.begin(); it != timers_.end(); ) {
                auto locked = it->second.anchor.lock();
                if (locked.get() == anchor.get()) {
                    it = timers_.erase(it);
                } else {
                    ++it;
                }
            }
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
        timers_.clear();
    }
    // timed_thread_context dtor requests stop and joins its thread.
    // Pending schedule_after operations complete with set_stopped;
    // start_detached sinks those silently — no extra work needed.
}

} // namespace gn::core
