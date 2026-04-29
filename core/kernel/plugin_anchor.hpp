/// @file   core/kernel/plugin_anchor.hpp
/// @brief  Per-plugin liveness sentinel + cooperative-cancellation
///         flag (`plugin-lifetime.md` §4 / §8).
///
/// Every loaded plugin owns one heap-allocated `PluginAnchor`. The
/// `shared_ptr<PluginAnchor>` it sits inside threads through three
/// orthogonal use-sites:
///
///   * **Liveness** — registries (handler / transport / security /
///     extension) copy the shared_ptr into every entry; dispatch
///     snapshots inherit the copy by value. Synchronous dispatch
///     (router → handler vtable) is protected by the snapshot's
///     strong reference, the same way it has always been.
///
///   * **Async-callback gate** — async callback sites (timer fire,
///     posted task, signal-channel subscriber) open the dispatch
///     with `GateGuard::acquire`. The guard locks the weak observer
///     into a strong reference for the duration of the dispatch
///     (so `weak_ptr::expired()` cannot become true while the
///     callback is still in plugin code) **and** refuses if the
///     rollback path already published `shutdown_requested = true`
///     — callbacks scheduled before rollback but fired after are
///     dropped without entering plugin code.
///
///   * **Cooperative shutdown** — plugins poll
///     `host_api->is_shutdown_requested()` from inside long-running
///     async work. The flag flips on entry to the rollback path, so
///     a plugin that observes it can finish its loop early instead
///     of riding into the drain timeout (`plugin-lifetime.md` §8).
///
/// `in_flight` is maintained for diagnostics: the count is logged
/// alongside the drain-timeout warning so an operator can tell how
/// many async callbacks failed to drain on a misbehaving plugin.

#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <optional>
#include <utility>

namespace gn::core {

struct PluginAnchor {
    /// Number of async callbacks currently inside the plugin's
    /// `.text`. Maintained by `GateGuard` (`++` on acquire, `--` on
    /// destructor). Read by the drain path on timeout to surface the
    /// leak count to the operator.
    std::atomic<std::uint64_t> in_flight{0};

    /// Set true the moment `PluginManager::rollback` enters the per-
    /// plugin teardown path. Async callbacks observing the flag
    /// through `GateGuard::acquire` refuse to enter plugin code;
    /// long-running plugin loops observing the flag through
    /// `host_api->is_shutdown_requested` exit cooperatively.
    std::atomic<bool>          shutdown_requested{false};

    /// Per-plugin active-timer count for quota enforcement. The
    /// kernel's `TimerRegistry` increments at `set_timer` admission
    /// time and decrements at the head of every fire / cancel
    /// callback. With `gn_limits_t::max_timers_per_plugin` set to a
    /// non-zero value the registry refuses an admit that would push
    /// the counter past the cap, so a misbehaving plugin cannot
    /// exhaust the kernel's global timer budget on its sibling
    /// plugins' behalf.
    std::atomic<std::uint32_t> active_timers{0};
};

/// RAII gate held for the duration of an async callback's dispatch
/// into plugin code.
///
/// `acquire` upgrades a weak observer to a strong reference and
/// rejects acquisitions made after `shutdown_requested` was set.
/// While the guard lives, `weak_ptr<PluginAnchor>::expired()` cannot
/// become true on this anchor — that is the property the drain spin
/// relies on to know no callback is in plugin code.
///
/// Movable, non-copyable: the strong reference must be released
/// exactly once, when the dispatch is complete.
class [[nodiscard]] GateGuard {
public:
    /// @return engaged guard if the anchor is still live and shutdown
    ///         has not yet been requested; `std::nullopt` otherwise.
    [[nodiscard]] static std::optional<GateGuard>
    acquire(const std::weak_ptr<PluginAnchor>& weak) noexcept {
        auto strong = weak.lock();
        if (!strong) {
            return std::nullopt;
        }
        if (strong->shutdown_requested.load(std::memory_order_acquire)) {
            return std::nullopt;
        }
        strong->in_flight.fetch_add(1, std::memory_order_acq_rel);
        return GateGuard{std::move(strong)};
    }

    GateGuard(GateGuard&& other) noexcept
        : anchor_(std::exchange(other.anchor_, nullptr)) {}

    GateGuard& operator=(GateGuard&& other) noexcept {
        if (this != &other) {
            release();
            anchor_ = std::exchange(other.anchor_, nullptr);
        }
        return *this;
    }

    GateGuard(const GateGuard&)            = delete;
    GateGuard& operator=(const GateGuard&) = delete;

    ~GateGuard() { release(); }

private:
    explicit GateGuard(std::shared_ptr<PluginAnchor> a) noexcept
        : anchor_(std::move(a)) {}

    void release() noexcept {
        if (!anchor_) return;
        anchor_->in_flight.fetch_sub(1, std::memory_order_acq_rel);
        anchor_.reset();
    }

    std::shared_ptr<PluginAnchor> anchor_;
};

}  // namespace gn::core
