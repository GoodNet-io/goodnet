/// @file   core/kernel/kernel.cpp
/// @brief  Implementation of the kernel FSM orchestrator.

#include "kernel.hpp"

#include <core/util/log.hpp>
#include <core/util/log_config.hpp>

#include <algorithm>
#include <cstdint>
#include <string>

namespace gn::core {

Kernel::Kernel() noexcept {
    /// `limits_` is zero-initialised by the field declaration's
    /// `{}`, but the kernel's running state should default to the
    /// canonical limits the Config holder uses. An embedding that
    /// never calls `set_limits` (or never loads a config) thereby
    /// runs against a sensible baseline rather than zero ceilings
    /// that would reject every operation.
    limits_ = config_.limits();

    /// The logger shape is owned by the operator: either through the
    /// lazy `gn::log::kernel()` default (build-aware level + console
    /// pattern) or through an explicit `gn::log::init_with(...)` set
    /// up before construction. The first `reload_config()` call
    /// re-applies the shape from the loaded `log.*` keys; the ctor
    /// itself stays out of the way so a host that already configured
    /// the logger does not get its sink list rebuilt out from under
    /// it. The single INFO marker below tells an operator with the
    /// console floor at info that the kernel reached construction.
    GN_LOG_INFO("kernel constructed "
                "(max_connections={}, max_extensions={})",
                limits_.max_connections, limits_.max_extensions);
}

/// Joins the timer executor before the default member sequence
/// runs, so no in-flight callback reaches kernel state during
/// destruction.
Kernel::~Kernel() {
    timers_.shutdown();
}

void Kernel::set_protocol_layer(std::shared_ptr<::gn::IProtocolLayer> layer) noexcept {
    protocol_layer_.store(std::move(layer), std::memory_order_release);
}

std::shared_ptr<::gn::IProtocolLayer> Kernel::protocol_layer() const noexcept {
    return protocol_layer_.load(std::memory_order_acquire);
}

void Kernel::set_limits(const gn_limits_t& limits) noexcept {
    limits_ = limits;
    if (limits_.max_timers != 0) {
        timers_.set_max_timers(limits_.max_timers);
    }
    if (limits_.max_pending_tasks != 0) {
        timers_.set_max_pending_tasks(limits_.max_pending_tasks);
    }
    /// Zero leaves the per-plugin cap at the registry default of
    /// "off"; non-zero installs the cap as a sub-quota under the
    /// global `max_timers`.
    timers_.set_max_timers_per_plugin(limits_.max_timers_per_plugin);

    /// Reconfigure the inject-path rate limiter live. A zero
    /// `inject_rate_per_source` keeps the bucket at the kernel's
    /// startup defaults — operators that omit the section get the
    /// historical 100/50/4096 shape unchanged. A non-zero value
    /// drops every existing per-pk bucket and rebuilds with the
    /// new (rate, burst, lru cap) triple, so an operator pushing
    /// updated limits sees the new ceiling on the next admit
    /// without a kernel restart.
    if (limits_.inject_rate_per_source != 0) {
        inject_rate_limiter_.reconfigure(
            static_cast<double>(limits_.inject_rate_per_source),
            static_cast<double>(limits_.inject_rate_burst),
            static_cast<std::size_t>(limits_.inject_rate_lru_cap));
    }
    /// `limits.md` §4 — wire every cap that lives on a kernel-owned
    /// registry so a single `gn_limits_t` is the source of truth.
    /// `PluginManager` is not kernel-owned; it reads `kernel.limits()`
    /// directly when applying `max_plugins` inside `load`.
    if (limits_.max_connections != 0) {
        connections_.set_max_connections(limits_.max_connections);
    }
    if (limits_.max_extensions != 0) {
        extensions_.set_max_extensions(limits_.max_extensions);
    }
    if (limits_.max_handlers_per_msg_id != 0) {
        handlers_.set_max_chain_length(limits_.max_handlers_per_msg_id);
    }
    if (limits_.max_counter_names != 0) {
        metrics_.set_max_counter_names(limits_.max_counter_names);
    }
    if (limits_.max_subscriptions != 0) {
        const std::size_t cap = limits_.max_subscriptions;
        on_conn_event_.set_max_subscribers(cap);
        on_config_reload_.set_max_subscribers(cap);
    }
}

gn_result_t Kernel::reload_config(std::string_view text) {
    /// Atomic-from-the-outside: load_json is itself
    /// rollback-on-failure, so a parse / invariant error leaves
    /// the live config and limits unchanged. Only on success do
    /// we propagate the new limits into kernel-owned registries
    /// and notify subscribers.
    std::string diagnostic;
    if (auto rc = config_.load_json(text, &diagnostic); rc != GN_OK) {
        SPDLOG_LOGGER_WARN(::gn::log::kernel().get(),
            "kernel.reload_config: rejected config — {}", diagnostic);
        return rc;
    }
    set_limits(config_.limits());
    apply_log_config();
    on_config_reload_.fire(signal::Empty{});
    return GN_OK;
}

gn_result_t Kernel::reload_config_merge(std::string_view overlay) {
    std::string diagnostic;
    if (auto rc = config_.merge_json(overlay, &diagnostic); rc != GN_OK) {
        SPDLOG_LOGGER_WARN(::gn::log::kernel().get(),
            "kernel.reload_config_merge: rejected overlay — {}", diagnostic);
        return rc;
    }
    set_limits(config_.limits());
    apply_log_config();
    on_config_reload_.fire(signal::Empty{});
    return GN_OK;
}

void Kernel::apply_log_config() noexcept {
    (void)gn::log::init_with(gn::core::util::load_log_config(config_));
}

void Kernel::set_node_identity(identity::NodeIdentity ident) {
    auto shared = std::make_shared<const identity::NodeIdentity>(std::move(ident));
    node_identity_.store(std::move(shared), std::memory_order_release);
}

std::shared_ptr<const identity::NodeIdentity>
Kernel::node_identity() const noexcept {
    return node_identity_.load(std::memory_order_acquire);
}

Phase Kernel::current_phase() const noexcept {
    return state_.load(std::memory_order_acquire);
}

bool Kernel::advance_to(Phase next) {
    Phase prev = state_.load(std::memory_order_acquire);

    if (!is_forward_transition(prev, next)) {
        return false;
    }
    if (prev == next) {
        return true;                          // idempotent, no notify
    }

    /// Commit by atomic exchange. The exchange semantics also act as
    /// a single-writer guard: a concurrent caller that loses the race
    /// observes the winner's `next` value and returns without firing
    /// duplicate notifications.
    Phase observed = state_.exchange(next, std::memory_order_acq_rel);
    if (observed != prev) {
        /// Someone else moved the phase between our load and exchange.
        /// Roll back and let the winner own the notification.
        state_.store(observed, std::memory_order_release);
        return false;
    }

    fire(prev, next);
    return true;
}

void Kernel::stop() {
    bool expected = false;
    if (!stop_requested_.compare_exchange_strong(
            expected, true,
            std::memory_order_acq_rel, std::memory_order_acquire)) {
        return;
    }

    /// Walk forward to PreShutdown then Shutdown. Each step uses
    /// advance_to so observers see commit-then-notify. Failures
    /// (already past those phases) are harmless — the casts to void
    /// are explicit about not consuming the [[nodiscard]] result.
    (void)advance_to(Phase::PreShutdown);
    (void)advance_to(Phase::Shutdown);
}

void Kernel::subscribe(std::weak_ptr<IPhaseObserver> observer) {
    if (observer.expired()) return;
    std::scoped_lock lock(observers_mu_);
    observers_.push_back(std::move(observer));
}

std::size_t Kernel::observer_count() const {
    std::scoped_lock lock(observers_mu_);
    /// Returns the live count; expired weak-pointers do not contribute.
    std::size_t alive = 0;
    for (const auto& w : observers_) {
        if (!w.expired()) ++alive;
    }
    return alive;
}

void Kernel::fire(Phase prev, Phase next) {
    /// Take a snapshot under the mutex, drop the lock before invoking
    /// callbacks. Observers may subscribe / unsubscribe during their
    /// own callback without deadlocking against ourselves.
    std::vector<std::weak_ptr<IPhaseObserver>> snapshot;
    {
        std::scoped_lock lock(observers_mu_);
        snapshot = observers_;
        /// Prune expired observers in place; cheap on the same pass.
        std::erase_if(observers_,
            [](const std::weak_ptr<IPhaseObserver>& w) { return w.expired(); });
    }

    for (auto& weak : snapshot) {
        if (auto obs = weak.lock()) {
            obs->on_phase_change(prev, next);
        }
    }
}

} // namespace gn::core
