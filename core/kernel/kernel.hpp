/// @file   core/kernel/kernel.hpp
/// @brief  Kernel FSM orchestrator.
///
/// Owns the lifecycle phase, the phase-change observer set, and the
/// `stop()` entry point. The actual plugin loading, registry
/// construction, and dispatch live in surrounding components — the
/// kernel is the conductor that walks them through phases in order
/// and notifies subscribers after every successful transition.
///
/// Implements `docs/contracts/fsm-events.md`: commit-then-notify on
/// every transition, compare-and-exchange on idempotent operations,
/// weak-observer subscription so plugins that forget to unsubscribe
/// do not leak.

#pragma once

#include <atomic>
#include <cstddef>
#include <memory>
#include <mutex>
#include <vector>

#include "phase.hpp"

namespace gn::core {

/// Subscriber to phase transitions. Implementations should be cheap;
/// the callback runs synchronously on the transitioning thread.
class IPhaseObserver {
public:
    virtual ~IPhaseObserver() = default;
    virtual void on_phase_change(Phase prev, Phase next) noexcept = 0;
};

/// Kernel lifecycle controller.
///
/// Ownership: a single `Kernel` instance per process. The class is
/// thread-safe; `advance_to` and `stop` may be called from any thread.
class Kernel {
public:
    Kernel() noexcept;
    ~Kernel();

    Kernel(const Kernel&)            = delete;
    Kernel& operator=(const Kernel&) = delete;

    /// Current phase. Atomic, observable from any thread.
    [[nodiscard]] Phase current_phase() const noexcept;

    /// Walk the FSM forward to @p next.
    ///
    /// Permitted transitions are: stay in the same phase (no-op, no
    /// observer notification) or advance to the next ordinal phase.
    /// Skipping or reversing returns `false` without mutating state.
    ///
    /// On a successful forward transition the public phase field is
    /// written first, then observers fire — commit-before-notify.
    [[nodiscard]] bool advance_to(Phase next);

    /// Idempotent shutdown trigger. Concurrent callers race through a
    /// compare-and-exchange; exactly one wins and walks the FSM
    /// through `PreShutdown → Shutdown`. Subsequent callers return
    /// without effect. The transition to `Unload` is left to the
    /// surrounding loader.
    void stop();

    /// Subscribe @p observer for phase-change callbacks.
    ///
    /// Held weakly: an observer that drops its last shared reference
    /// expires from the set automatically at the next fire. Safe for
    /// plugins to forget unsubscribe before shutdown.
    void subscribe(std::weak_ptr<IPhaseObserver> observer);

    /// Number of currently live observers; useful for tests.
    [[nodiscard]] std::size_t observer_count() const;

private:
    void                      fire(Phase prev, Phase next);

    std::atomic<Phase>        state_{Phase::Load};
    std::atomic<bool>         stop_requested_{false};

    mutable std::mutex                            observers_mu_;
    std::vector<std::weak_ptr<IPhaseObserver>>    observers_;
};

} // namespace gn::core
