/// @file   core/kernel/router.hpp
/// @brief  Inbound envelope router.
///
/// Implements the routing rules from
/// `docs/contracts/protocol-layer.en.md` §6:
///
/// ```
/// on inbound envelope:
///     if receiver_pk == ZERO:
///         dispatch_broadcast(msg_id, envelope)
///     elif receiver_pk in local_identities:
///         dispatch_local(receiver_pk, msg_id, envelope)
///     else:
///         relay_or_drop(envelope)
/// ```
///
/// Per `docs/contracts/handler-registration.en.md` §3 and §6, the router
/// materialises the dispatch chain once, walks it in priority order,
/// invokes `handle_message` and `on_result` on every step, and stops
/// on `Consumed`. `Reject` propagates up so the connection can be
/// closed by the surrounding layer.

#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <string_view>

#include <sdk/handler.h>
#include <sdk/trust.h>
#include <sdk/types.h>

#include <core/kernel/identity_set.hpp>
#include <core/registry/handler.hpp>

namespace gn::core {

/// Classify a connection's scope as "loopback" for the purposes of
/// the `GN_TRUST_ANONYMOUS_LOOPBACK` zero-sender relaxation gate.
/// `ipc://` is always loopback; `tcp://`, `udp://`, `tls://`,
/// `quic://`, `ws://`, `wss://`, `raw-inject://` are loopback iff
/// their host parses to 127.0.0.0/8, ::1, or one of the
/// `127.0.0.1` / `localhost` literal forms.
/// Any other scheme defaults to `false` — the conservative answer.
[[nodiscard]] bool is_loopback_scope(std::string_view scheme,
                                      std::string_view uri) noexcept;

/// Outcome of routing one inbound envelope.
///
/// Distinct values let the kernel surface metric counters and react
/// appropriately at the call site (e.g. close connection on `Rejected`).
enum class RouteOutcome {
    DispatchedLocal,        ///< handed to a local-identity handler chain
    DispatchedBroadcast,    ///< handed to broadcast subscribers (receiver_pk == ZERO)
    DeferredRelay,          ///< receiver not local; relay extension owns it
    DroppedZeroSender,      ///< envelope.sender_pk == ZERO, malformed input
    DroppedInvalidMsgId,    ///< envelope.msg_id == 0
    DroppedUnknownReceiver, ///< no local-identity match and no relay loaded
    DroppedNoHandler,       ///< chain for (protocol_id, msg_id) is empty
    Rejected                ///< a handler returned `GN_PROPAGATION_REJECT`
};

/// Stateless dispatch helper bound to the kernel's identity set and
/// handler registry.
class Router {
public:
    /// Connection metadata the router consults for the zero-sender
    /// relaxation gate (`GN_TRUST_ANONYMOUS_LOOPBACK` + loopback scope).
    /// `lookup` returns `false` when the conn id is unknown — callers
    /// then fall back to the default `DroppedZeroSender` path.
    struct ConnInfo {
        gn_trust_class_t trust          = GN_TRUST_UNTRUSTED;
        bool             is_loopback    = false;
    };
#ifdef __cpp_lib_move_only_function
    using ConnLookup = std::move_only_function<bool(gn_conn_id_t, ConnInfo&)>;
#else
    using ConnLookup = std::function<bool(gn_conn_id_t, ConnInfo&)>;
#endif

    Router(LocalIdentityRegistry& identities,
           HandlerRegistry&  handlers) noexcept;

    Router(const Router&)            = delete;
    Router& operator=(const Router&) = delete;

    /// Route one inbound envelope produced by `IProtocolLayer::deframe`.
    ///
    /// @param protocol_id  the active protocol layer's id; used to
    ///                     scope the handler lookup namespace.
    /// @param env          @borrowed for the duration of the call.
    [[nodiscard]] RouteOutcome route_inbound(std::string_view  protocol_id,
                                             const gn_message_t& env) const;

    /// Returns `true` once a relay extension has been loaded. Used by
    /// the dispatcher to decide between `DroppedUnknownReceiver` and
    /// `DeferredRelay` for envelopes addressed elsewhere.
    [[nodiscard]] bool relay_available() const noexcept;
    void               set_relay_available(bool v) noexcept;

    /// Install the connection-metadata lookup. Called once at kernel
    /// startup. When unset (test fixtures) the router falls back to
    /// the legacy reject-zero-sender behaviour.
    void set_conn_lookup(ConnLookup fn);

private:
    [[nodiscard]] RouteOutcome dispatch_chain(std::string_view    protocol_id,
                                              const gn_message_t& env) const;

    [[nodiscard]] bool accept_zero_sender(const gn_message_t& env) const;

    LocalIdentityRegistry&     identities_;
    HandlerRegistry&      handlers_;
    mutable std::atomic<bool> relay_available_{false};
    mutable ConnLookup        conn_lookup_;
};

} // namespace gn::core
