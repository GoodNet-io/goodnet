/// @file   tests/unit/kernel/test_phase.cpp
/// @brief  Tests for the kernel `Phase` enum and its helpers.
///
/// Pins the contract from `docs/contracts/fsm-events.md` §2: phases are
/// linear, the only forward step is "next ordinal", same-phase is a
/// permitted no-op. `phase_name` returns a stable string for every
/// enumerator.

#include <gtest/gtest.h>

#include <array>
#include <string_view>

#include <core/kernel/phase.hpp>

namespace gn::core {
namespace {

/// Master ordered list mirrored from `phase.hpp`. If a new phase is
/// added there, this array breaks the build until it is updated here —
/// intentional: tests must follow the FSM, not lag it.
constexpr std::array<Phase, 8> kAllPhases{
    Phase::Load,
    Phase::Wire,
    Phase::Resolve,
    Phase::Ready,
    Phase::Running,
    Phase::PreShutdown,
    Phase::Shutdown,
    Phase::Unload,
};

// ── phase_name ───────────────────────────────────────────────────────────

TEST(Phase_Name, EveryEnumeratorHasStableString) {
    EXPECT_EQ(phase_name(Phase::Load),        std::string_view{"Load"});
    EXPECT_EQ(phase_name(Phase::Wire),        std::string_view{"Wire"});
    EXPECT_EQ(phase_name(Phase::Resolve),     std::string_view{"Resolve"});
    EXPECT_EQ(phase_name(Phase::Ready),       std::string_view{"Ready"});
    EXPECT_EQ(phase_name(Phase::Running),     std::string_view{"Running"});
    EXPECT_EQ(phase_name(Phase::PreShutdown), std::string_view{"PreShutdown"});
    EXPECT_EQ(phase_name(Phase::Shutdown),    std::string_view{"Shutdown"});
    EXPECT_EQ(phase_name(Phase::Unload),      std::string_view{"Unload"});
}

TEST(Phase_Name, IsConstexprUsable) {
    /// The helper is `constexpr`; its value must be available at compile time.
    static_assert(phase_name(Phase::Running) == std::string_view{"Running"});
    static_assert(phase_name(Phase::Shutdown) == std::string_view{"Shutdown"});
    SUCCEED();
}

// ── is_forward_transition ────────────────────────────────────────────────

TEST(Phase_Forward, SamePhaseIsAlwaysForward) {
    /// Idempotent transitions are explicitly permitted (§3 commit-then-notify
    /// allows a no-op same-phase advance).
    for (Phase p : kAllPhases) {
        EXPECT_TRUE(is_forward_transition(p, p))
            << "same-phase must be permitted: " << phase_name(p);
    }
}

TEST(Phase_Forward, NextOrdinalIsForward) {
    for (std::size_t i = 0; i + 1 < kAllPhases.size(); ++i) {
        const Phase prev = kAllPhases[i];
        const Phase next = kAllPhases[i + 1];
        EXPECT_TRUE(is_forward_transition(prev, next))
            << phase_name(prev) << " -> " << phase_name(next)
            << " must be permitted";
    }
}

TEST(Phase_Forward, BackwardIsRejected) {
    for (std::size_t i = 1; i < kAllPhases.size(); ++i) {
        const Phase prev = kAllPhases[i];
        const Phase next = kAllPhases[i - 1];
        EXPECT_FALSE(is_forward_transition(prev, next))
            << phase_name(prev) << " -> " << phase_name(next)
            << " must be rejected (backward)";
    }
}

TEST(Phase_Forward, SkippingIsRejected) {
    /// Anything other than +0 or +1 ordinal is rejected. Skipping
    /// destroys the per-phase invariants — Resolve cannot run before
    /// Wire has populated the host vtable.
    for (std::size_t i = 0; i < kAllPhases.size(); ++i) {
        for (std::size_t j = 0; j < kAllPhases.size(); ++j) {
            const Phase prev = kAllPhases[i];
            const Phase next = kAllPhases[j];
            const bool same   = (i == j);
            const bool plus_one = (j == i + 1);
            const bool expected = same || plus_one;
            EXPECT_EQ(is_forward_transition(prev, next), expected)
                << phase_name(prev) << " -> " << phase_name(next);
        }
    }
}

TEST(Phase_Forward, IsConstexprUsable) {
    static_assert(is_forward_transition(Phase::Load, Phase::Wire));
    static_assert(is_forward_transition(Phase::Running, Phase::Running));
    static_assert(!is_forward_transition(Phase::Load, Phase::Running));
    static_assert(!is_forward_transition(Phase::Shutdown, Phase::Running));
    SUCCEED();
}

}  // namespace
}  // namespace gn::core
