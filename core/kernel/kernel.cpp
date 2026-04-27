/// @file   core/kernel/kernel.cpp
/// @brief  Implementation of the kernel FSM orchestrator.

#include "kernel.hpp"

#include <algorithm>

namespace gn::core {

Kernel::Kernel() noexcept = default;
Kernel::~Kernel() = default;

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
