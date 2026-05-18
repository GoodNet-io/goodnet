/// @file   core/kernel/phase.hpp
/// @brief  Kernel lifecycle phases.
///
/// Mirrors the diagram in `docs/contracts/fsm-events.en.md` §2 plus the
/// plugin lifecycle phases in `plugin-lifetime.en.md` §2. Phases are
/// linear; backward transitions are forbidden.

#pragma once

#include <array>
#include <cstddef>
#include <string_view>

namespace gn::core {

enum class Phase {
    Load        = 0,  ///< plugin shared objects mapped, version-checked
    Wire        = 1,  ///< host_api fully populated
    Resolve     = 2,  ///< service-graph toposort
    Ready       = 3,  ///< plugins past init_all, registry tables empty but live
    Running     = 4,  ///< plugins past register_all, dispatch open
    PreShutdown = 5,  ///< new connections refused, in-flight dispatches drained
    Shutdown    = 6,  ///< transports disconnected, handlers torn down
    Unload      = 7   ///< shared objects unmapped
};

/// Forward-only ordering: a `next` reachable from `prev` is the very
/// next phase value. Transitions skipping a phase are rejected.
[[nodiscard]] constexpr bool is_forward_transition(Phase prev, Phase next) noexcept {
    if (prev == next) return true;       // idempotent
    return static_cast<int>(next) == static_cast<int>(prev) + 1;
}

namespace detail {

inline constexpr std::size_t kPhaseCount = 8;

inline constexpr std::array<std::string_view, kPhaseCount> kPhaseNames = {
    "Load", "Wire", "Resolve", "Ready",
    "Running", "PreShutdown", "Shutdown", "Unload",
};

static_assert(static_cast<std::size_t>(Phase::Unload) + 1 == kPhaseCount,
              "kPhaseNames must stay aligned with the Phase enum.");

}  // namespace detail

[[nodiscard]] constexpr std::string_view phase_name(Phase p) noexcept {
    const auto idx = static_cast<std::size_t>(p);
    return idx < detail::kPhaseNames.size() ? detail::kPhaseNames[idx] : "?";
}

} // namespace gn::core
