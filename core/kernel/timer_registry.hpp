/// @file   core/kernel/timer_registry.hpp
/// @brief  Kernel-owned service executor — backs the `set_timer`
///         and `cancel_timer` host_api slots per
///         `docs/contracts/timer.md`. Fire-and-forget work uses
///         `set_timer(delay_ms = 0, …, out_id = NULL)`.
///
/// The registry owns one `asio::io_context` and the worker thread
/// that drives it. The thread serialises every task and timer
/// callback so plugins observe the single-thread guarantee from
/// `timer.md` §3 without depending on any transport's executor.
///
/// Lifetime safety mirrors `plugin-lifetime.md` §4: each scheduled
/// entry stores a `std::weak_ptr<PluginAnchor>` of the calling
/// plugin. Before invoking the user callback the dispatcher opens a
/// `GateGuard`; the guard refuses if the anchor expired or the
/// plugin's rollback path already published `shutdown_requested =
/// true`, and otherwise increments the anchor's in-flight counter
/// for the duration of the dispatch. The drain side waits on the
/// counter before `dlclose`, so a callback whose plugin already
/// unloaded never dereferences unmapped memory.

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

#include "plugin_anchor.hpp"

namespace gn::core {

/// Thread-safe per-kernel timer + task scheduler.
class TimerRegistry {
public:
    TimerRegistry();
    ~TimerRegistry();

    TimerRegistry(const TimerRegistry&)            = delete;
    TimerRegistry& operator=(const TimerRegistry&) = delete;

    /// Schedule a one-shot callback after @p delay_ms milliseconds.
    /// @p anchor is the calling plugin's lifetime anchor
    /// (`PluginContext::plugin_anchor`); a null anchor disables
    /// the lifetime gate, which is the in-tree-test convention.
    /// @p out_id is optional — pass `nullptr` for fire-and-forget
    /// work that does not need a cancel handle.
    /// @return `GN_OK` (and `*out_id` written when `out_id != nullptr`);
    ///         `GN_ERR_NULL_ARG` on null `fn`;
    ///         `GN_ERR_LIMIT_REACHED` on quota exhaustion.
    [[nodiscard]] gn_result_t set_timer(std::uint32_t  delay_ms,
                                         gn_task_fn_t   fn,
                                         void*          user_data,
                                         const std::shared_ptr<PluginAnchor>& anchor,
                                         gn_timer_id_t* out_id) noexcept;

    /// Cancel a pending timer. Returns `GN_OK` whether the timer
    /// was alive or already fired/cancelled (idempotent per
    /// `timer.md` §7). `GN_ERR_NULL_ARG` for `GN_INVALID_TIMER_ID`.
    [[nodiscard]] gn_result_t cancel_timer(gn_timer_id_t id) noexcept;

    /// Post a task to the service executor. Same lifetime rules as
    /// `set_timer`: anchor is observed weakly and a dropped plugin
    /// silently skips the dispatch. Equivalent to
    /// `set_timer(delay_ms = 0, fn, user_data, anchor, out_id = nullptr)`;
    /// remains as a kernel-internal helper for kernel components
    /// that schedule serialised work outside the host_api surface.
    [[nodiscard]] gn_result_t post(gn_task_fn_t fn,
                                    void*        user_data,
                                    const std::shared_ptr<PluginAnchor>& anchor) noexcept;

    /// Cap on simultaneously-pending timers + queued tasks.
    /// Defaults match `gn_limits_t::max_timers` /
    /// `max_pending_tasks` (`limits.md`); the kernel updates them
    /// after `set_limits`.
    void set_max_timers(std::uint32_t v) noexcept;
    void set_max_pending_tasks(std::uint32_t v) noexcept;

    /// Per-plugin cap on simultaneously-pending timers. `0` (the
    /// default) keeps the historical "global cap only" behaviour;
    /// any non-zero value adds an extra check at `set_timer`
    /// admission time that compares the calling plugin's anchor
    /// `active_timers` count against the cap. Mirrors
    /// `gn_limits_t::max_timers_per_plugin`.
    void set_max_timers_per_plugin(std::uint32_t v) noexcept;

    /// Cancel every still-pending timer whose anchor refers to the
    /// same control block as @p anchor. Used by `PluginManager`
    /// during rollback so a quiescing plugin's drain loop is not
    /// extended by stale timers.
    void cancel_for_anchor(const std::shared_ptr<PluginAnchor>& anchor) noexcept;

    [[nodiscard]] std::size_t active_timers() const noexcept;
    [[nodiscard]] std::size_t pending_tasks() const noexcept;

    /// Stop the worker thread. Idempotent. Called from the
    /// destructor; can be called explicitly when the kernel
    /// transitions through `Shutdown`.
    void shutdown();

private:
    struct TimerEntry {
        std::shared_ptr<asio::steady_timer> timer;
        std::weak_ptr<PluginAnchor>         anchor;
        gn_task_fn_t                        fn          = nullptr;
        void*                               user_data   = nullptr;
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
    std::atomic<std::uint32_t>                          max_timers_per_plugin_{0};
    std::atomic<std::uint32_t>                          pending_tasks_{0};
    std::atomic<std::uint32_t>                          shutdown_throws_{0};
};

} // namespace gn::core
