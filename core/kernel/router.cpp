/// @file   core/kernel/router.cpp
/// @brief  Implementation of the inbound envelope router.

#include "router.hpp"

#include <cstring>

namespace gn::core {

namespace {

/// Local helper mirroring `gn_pk_is_zero` so the router does not
/// depend on the C inline being inlined across compilation units.
[[nodiscard]] bool pk_is_zero(const std::uint8_t (&pk)[GN_PUBLIC_KEY_BYTES]) noexcept {
    std::uint8_t acc = 0;
    for (std::size_t i = 0; i < GN_PUBLIC_KEY_BYTES; ++i) acc |= pk[i];
    return acc == 0;
}

} // namespace

Router::Router(LocalIdentitySet& identities, HandlerRegistry& handlers) noexcept
    : identities_(identities), handlers_(handlers) {}

bool Router::relay_available() const noexcept {
    return relay_available_.load(std::memory_order_acquire);
}

void Router::set_relay_available(bool v) noexcept {
    relay_available_.store(v, std::memory_order_release);
}

RouteOutcome Router::route_inbound(std::string_view    protocol_id,
                                   const gn_message_t& env) const {
    /// Sender identity must be present.
    if (pk_is_zero(env.sender_pk))            return RouteOutcome::DroppedZeroSender;
    if (env.msg_id == 0)                      return RouteOutcome::DroppedInvalidMsgId;

    /// Broadcast is recognised by an all-zero receiver.
    if (pk_is_zero(env.receiver_pk)) {
        const auto rc = dispatch_chain(protocol_id, env);
        if (rc == RouteOutcome::DroppedNoHandler) {
            return rc;
        }
        return rc == RouteOutcome::Rejected ? rc : RouteOutcome::DispatchedBroadcast;
    }

    /// Direct receiver — does it match a local identity?
    PublicKey receiver{};
    std::memcpy(receiver.data(), env.receiver_pk, GN_PUBLIC_KEY_BYTES);

    if (identities_.contains(receiver)) {
        const auto rc = dispatch_chain(protocol_id, env);
        if (rc == RouteOutcome::DroppedNoHandler) return rc;
        return rc == RouteOutcome::Rejected ? rc : RouteOutcome::DispatchedLocal;
    }

    /// Foreign receiver — only relay can handle it.
    if (relay_available()) {
        return RouteOutcome::DeferredRelay;
    }
    return RouteOutcome::DroppedUnknownReceiver;
}

RouteOutcome Router::dispatch_chain(std::string_view    protocol_id,
                                    const gn_message_t& env) const {
    /// Atomic snapshot — chain + the generation counter the registry
    /// observed inside the lookup's shared lock. The dispatcher
    /// keeps the recorded generation in scope so a future hot-reload
    /// path can compare against the live counter for stale-chain
    /// observability without a second lookup. Per
    /// `handler-registration.md` §6 the generation bumps on every
    /// register / unregister; an exporter plugin can surface the
    /// gap between recorded and live counters as a "dispatch on
    /// stale chain" rate.
    auto snap = handlers_.lookup_with_generation(protocol_id, env.msg_id);
    if (snap.chain.empty()) {
        return RouteOutcome::DroppedNoHandler;
    }

    /// Walk the chain in priority order. `on_result` fires after every
    /// `handle_message` regardless of return; `Consumed` stops the
    /// chain; `Reject` propagates upward. The snapshot's
    /// `lifetime_anchor` strong refs keep every entry's vtable valid
    /// for the entire walk even if the registry mutates concurrently
    /// — no UAF, only a possibly-stale dispatch on entries the new
    /// generation no longer wants to see.
    RouteOutcome outcome = RouteOutcome::DispatchedLocal;

    for (const auto& entry : snap.chain) {
        const gn_propagation_t r =
            entry.vtable->handle_message(entry.self, &env);

        if (entry.vtable->on_result != nullptr) {
            entry.vtable->on_result(entry.self, &env, r);
        }

        if (r == GN_PROP_REJECT) {
            outcome = RouteOutcome::Rejected;
            break;
        }
        if (r == GN_PROP_CONSUMED) {
            break;
        }
        /// GN_PROP_CONTINUE: fall through to the next entry.
    }

    return outcome;
}

} // namespace gn::core
