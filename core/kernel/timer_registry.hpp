/// @file   core/kernel/timer_registry.hpp
/// @brief  Kernel-owned service executor — backs the `set_timer`,
///         `cancel_timer`, and `post_to_executor` host_api slots
///         per `docs/contracts/timer.md`.
///
/// The registry owns one `asio::io_context` and the worker thread
/// that drives it. The thread serialises every task and timer
/// callback so plugins observe the single-thread guarantee from
/// `timer.md` §3 without depending on any transport's executor.
///
/// Lifetime safety mirrors `plugin-lifetime.md` §4: each scheduled
/// entry stores a `std::weak_ptr<void>` of the calling plugin's
/// quiescence sentinel. Before invoking the user callback the
/// dispatcher upgrades the observer; failure to upgrade is a
/// silent drop, so a callback whose plugin has already unloaded
/// never dereferences unmapped memory.

#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <thread>
#include <unordered_map>

#include <asio/executor_work_guard.hpp>
#include <asio/io_context.hpp>
#include <asio/steady_timer.hpp>

#include <sdk/types.h>

namespace gn::core {

/// Thread-safe per-kernel timer + task scheduler.
class TimerRegistry {
public:
    TimerRegistry();
    ~TimerRegistry();

    TimerRegistry(const TimerRegistry&)            = delete;
    TimerRegistry& operator=(const TimerRegistry&) = delete;

    /// Schedule a one-shot callback after @p delay_ms milliseconds.
    /// @p anchor is the calling plugin's quiescence sentinel
    /// (`PluginContext::plugin_anchor`); a null anchor disables
    /// the lifetime gate, which is the in-tree-test convention.
    /// @return `GN_OK` and `*out_id` on success;
    ///         `GN_ERR_NULL_ARG` on null `fn` / `out_id`;
    ///         `GN_ERR_LIMIT_REACHED` on quota exhaustion.
    [[nodiscard]] gn_result_t set_timer(std::uint32_t  delay_ms,
                                         gn_task_fn_t   fn,
                                         void*          user_data,
                                         const std::shared_ptr<void>& anchor,
                                         gn_timer_id_t* out_id) noexcept;

    /// Cancel a pending timer. Returns `GN_OK` whether the timer
    /// was alive or already fired/cancelled (idempotent per
    /// `timer.md` §7). `GN_ERR_NULL_ARG` for `GN_INVALID_TIMER_ID`.
    [[nodiscard]] gn_result_t cancel_timer(gn_timer_id_t id) noexcept;

    /// Post a task to the service executor. Same lifetime rules as
    /// `set_timer`: anchor is observed weakly and a dropped plugin
    /// silently skips the dispatch.
    [[nodiscard]] gn_result_t post(gn_task_fn_t fn,
                                    void*        user_data,
                                    const std::shared_ptr<void>& anchor) noexcept;

    /// Cap on simultaneously-pending timers + queued tasks.
    /// Defaults match `gn_limits_t::max_timers` /
    /// `max_pending_tasks` (`limits.md`); the kernel updates them
    /// after `set_limits`.
    void set_max_timers(std::uint32_t v) noexcept;
    void set_max_pending_tasks(std::uint32_t v) noexcept;

    /// Cancel every still-pending timer whose anchor refers to the
    /// same control block as @p anchor. Used by `PluginManager`
    /// during rollback so a quiescing plugin's drain loop is not
    /// extended by stale timers.
    void cancel_for_anchor(const std::shared_ptr<void>& anchor) noexcept;

    [[nodiscard]] std::size_t active_timers() const noexcept;
    [[nodiscard]] std::size_t pending_tasks() const noexcept;

    /// Stop the worker thread. Idempotent. Called from the
    /// destructor; can be called explicitly when the kernel
    /// transitions through `Shutdown`.
    void shutdown();

private:
    struct TimerEntry {
        std::shared_ptr<asio::steady_timer> timer;
        std::weak_ptr<void>                 anchor;
        gn_task_fn_t                        fn          = nullptr;
        void*                               user_data   = nullptr;
        bool                                anchor_set  = false;
    };

    asio::io_context                                          ioc_;
    asio::executor_work_guard<asio::io_context::executor_type> work_;
    std::thread                                               worker_;
    std::atomic<bool>                                         shutdown_{false};

    mutable std::mutex                                  mu_;
    std::unordered_map<gn_timer_id_t, TimerEntry>       timers_;
    std::atomic<gn_timer_id_t>                          next_id_{1};
    std::atomic<std::uint32_t>                          max_timers_{4096};
    std::atomic<std::uint32_t>                          max_pending_tasks_{4096};
    std::atomic<std::uint32_t>                          pending_tasks_{0};
    std::atomic<std::uint32_t>                          shutdown_throws_{0};
};

} // namespace gn::core
