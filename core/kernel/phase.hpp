/// @file   core/kernel/phase.hpp
/// @brief  Kernel lifecycle phases.
///
/// Mirrors the diagram in `docs/contracts/fsm-events.md` §2 plus the
/// plugin lifecycle phases in `plugin-lifetime.md` §2. Phases are
/// linear; backward transitions are forbidden.

#pragma once

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

[[nodiscard]] constexpr std::string_view phase_name(Phase p) noexcept {
    switch (p) {
        case Phase::Load:        return "Load";
        case Phase::Wire:        return "Wire";
        case Phase::Resolve:     return "Resolve";
        case Phase::Ready:       return "Ready";
        case Phase::Running:     return "Running";
        case Phase::PreShutdown: return "PreShutdown";
        case Phase::Shutdown:    return "Shutdown";
        case Phase::Unload:      return "Unload";
    }
    return "?";
}

} // namespace gn::core
