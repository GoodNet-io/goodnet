/// @file   core/kernel/plugin_context.hpp
/// @brief  Per-plugin context the kernel hands through `host_api->host_ctx`.
///
/// Carries the plugin name (used for log prefixing) and a back-pointer
/// to the Kernel so host_api thunks can reach data-path components.
/// The struct lives kernel-side; plugins see only the opaque
/// `void* host_ctx` field on `host_api_t`.

#pragma once

#include <memory>
#include <string>

#include <sdk/plugin.h>

#include "plugin_anchor.hpp"

namespace gn::core {

class Kernel;

struct PluginContext {
    /// Liveness canary. Every host_api thunk in
    /// `host_api_builder.cpp` reads this field via `ctx_live`
    /// before any other field; a mismatch means the context has
    /// already been destroyed (the plugin retained `host_api`
    /// past its own `dlclose`) and the thunk drops the call
    /// instead of dereferencing `pc->plugin_name` /
    /// `pc->kernel` / `pc->plugin_anchor` into reused memory.
    /// The destructor stamps `kMagicDead`. The check is a soft
    /// fast-fail — if the heap slab is reused between teardown
    /// and the next thunk call the magic read aliases unrelated
    /// bytes and the heuristic fails open. True UAF detection
    /// remains sanitisers' job; this guard catches the common
    /// case where the slot is still in the freed state.
    static constexpr std::uint64_t kMagicLive = 0xC0DE600DC0DE600DULL;
    static constexpr std::uint64_t kMagicDead = 0xDEAD600DDEAD600DULL;
    std::uint64_t           magic{kMagicLive};

    std::string             plugin_name;   ///< stable identifier; e.g. `"libgoodnet_tcp"`
    gn_plugin_kind_t        kind{GN_PLUGIN_KIND_UNKNOWN};
    Kernel*                 kernel{nullptr};

    /// Per-plugin liveness sentinel + cancellation gate. Registries
    /// copy the shared_ptr into every entry (and dispatch snapshots
    /// inherit the copy by value) so synchronous dispatch holds the
    /// plugin's `.text` mapped through every vtable call. Async
    /// callback sites pair the anchor with a `GateGuard` so the
    /// `in_flight` counter and the `shutdown_requested` flag form
    /// the explicit barrier the rollback path waits on before
    /// `dlclose` (see `plugin-lifetime.md` §4 and `plugin_anchor.hpp`).
    /// A null anchor means "no quiescence wait needed for entries
    /// from this context" — used by in-tree tests that exercise
    /// registries without a plugin manager.
    std::shared_ptr<PluginAnchor> plugin_anchor;

    PluginContext() = default;
    /// Stamp the canary on destruction so a thunk that arrives
    /// here through a stale `host_ctx` reads `kMagicDead` and
    /// drops the call. Move-from leaves the source destructor
    /// to fire the stamp at scope-exit; the destination keeps
    /// `kMagicLive` from the field-wise move.
    ~PluginContext() noexcept { magic = kMagicDead; }
};

} // namespace gn::core
