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

#include <sdk/cpp/protocol_layer.hpp>
#include <sdk/limits.h>

#include "attestation_dispatcher.hpp"
#include "conn_event.hpp"
#include "identity_set.hpp"
#include "metrics_registry.hpp"
#include "phase.hpp"
#include "router.hpp"
#include "timer_registry.hpp"

#include <core/identity/node_identity.hpp>
#include <core/security/session.hpp>
#include <core/util/token_bucket.hpp>

#include <core/config/config.hpp>
#include <core/registry/connection.hpp>
#include <core/registry/extension.hpp>
#include <core/registry/handler.hpp>
#include <core/registry/security.hpp>
#include <core/registry/transport.hpp>
#include <core/signal/signal_channel.hpp>

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

    /* ── Data-path components (owned by the kernel) ────────────────── */

    [[nodiscard]] LocalIdentitySet&    identities()  noexcept { return identities_; }
    [[nodiscard]] HandlerRegistry&     handlers()    noexcept { return handlers_; }
    [[nodiscard]] ConnectionRegistry&  connections() noexcept { return connections_; }
    [[nodiscard]] TransportRegistry&   transports()  noexcept { return transports_; }
    [[nodiscard]] SecurityRegistry&    security()    noexcept { return security_; }
    [[nodiscard]] Sessions&            sessions()    noexcept { return sessions_; }
    [[nodiscard]] ExtensionRegistry&   extensions()  noexcept { return extensions_; }
    [[nodiscard]] Router&              router()      noexcept { return router_; }
    [[nodiscard]] TimerRegistry&       timers()      noexcept { return timers_; }
    [[nodiscard]] signal::SignalChannel<ConnEvent>& on_conn_event() noexcept {
        return on_conn_event_;
    }
    [[nodiscard]] util::RateLimiterMap<>& inject_rate_limiter() noexcept {
        return inject_rate_limiter_;
    }
    [[nodiscard]] AttestationDispatcher& attestation_dispatcher() noexcept {
        return attestation_dispatcher_;
    }
    [[nodiscard]] MetricsRegistry& metrics() noexcept { return metrics_; }
    [[nodiscard]] const MetricsRegistry& metrics() const noexcept {
        return metrics_;
    }

    /// Mandatory mesh-framing layer per `protocol-layer.md` §4.
    /// Set once before `Wire` phase; cannot be replaced afterwards.
    /// Read returns a shared snapshot so the caller holds a strong
    /// reference for the duration of its `frame`/`deframe` call —
    /// concurrent `set_protocol_layer` cannot pull the layer out
    /// from under an in-flight dispatch.
    void set_protocol_layer(std::shared_ptr<::gn::IProtocolLayer> layer) noexcept;
    [[nodiscard]] std::shared_ptr<::gn::IProtocolLayer> protocol_layer() const noexcept;

    /// Read-only resource bounds per `limits.md` §2. Loaded once at
    /// startup; subsequent reload requires kernel restart.
    void set_limits(const gn_limits_t& limits) noexcept;
    [[nodiscard]] const gn_limits_t& limits() const noexcept { return limits_; }

    /// Kernel-owned Config instance per `host-api.md` §2
    /// (`config_get_*`). Plugins reach it through the host_api thunks.
    [[nodiscard]] Config& config() noexcept { return config_; }
    [[nodiscard]] const Config& config() const noexcept { return config_; }

    /// Install the kernel's `NodeIdentity` for the security pipeline.
    /// Must be called before reaching `Wire` phase so the security
    /// session has the local Ed25519 keypair available at handshake
    /// time. The kernel takes ownership; the wrapped instance is
    /// destroyed (and its secrets zeroised through the keypair's
    /// `wipe()` path) when the last shared reference goes away.
    /// Throws `std::bad_alloc` if the wrapping `make_shared`
    /// allocation fails — startup-time only call site, fatal if it
    /// hits.
    void set_node_identity(identity::NodeIdentity identity);

    [[nodiscard]] bool has_node_identity() const noexcept {
        return node_identity() != nullptr;
    }

    /// Read-only access to the installed node identity. Returns a
    /// null shared_ptr when none has been set. The shared snapshot
    /// keeps the identity alive for the duration of the caller's
    /// scope — concurrent `set_node_identity` cannot pull secrets
    /// out from under an in-flight handshake.
    [[nodiscard]] std::shared_ptr<const identity::NodeIdentity>
        node_identity() const noexcept;

private:
    void                      fire(Phase prev, Phase next);

    std::atomic<Phase>        state_{Phase::Load};
    std::atomic<bool>         stop_requested_{false};

    mutable std::mutex                            observers_mu_;
    std::vector<std::weak_ptr<IPhaseObserver>>    observers_;

    /// Data-path components live for the kernel's lifetime. Order of
    /// declaration matches construction order — Router depends on
    /// identities_ and handlers_, so they precede it.
    LocalIdentitySet     identities_;
    HandlerRegistry      handlers_;
    ConnectionRegistry   connections_;
    TransportRegistry    transports_;
    SecurityRegistry     security_;
    Sessions             sessions_;
    ExtensionRegistry    extensions_;
    Router               router_{identities_, handlers_};
    TimerRegistry        timers_;

    /// Atomic-shared so concurrent `set_protocol_layer` and reads
    /// from thunk paths do not race. The strong ref returned by
    /// `protocol_layer()` extends the layer's lifetime past any
    /// concurrent replacement.
    std::atomic<std::shared_ptr<::gn::IProtocolLayer>> protocol_layer_;
    gn_limits_t                           limits_{};
    Config                                config_;

    signal::SignalChannel<ConnEvent>      on_conn_event_;

    /// Atomic-shared like `protocol_layer_`: secrets stay alive for
    /// the caller's snapshot scope across concurrent identity install.
    std::atomic<std::shared_ptr<const identity::NodeIdentity>> node_identity_;

    /// Per-source rate limiter for `host_api->inject_*` per
    /// `host-api.md` §8: 100 msg/s, burst 50, LRU cap 4096 sources.
    util::RateLimiterMap<>                inject_rate_limiter_{
        100.0, 50.0, 4096};

    /// Kernel-internal attestation flow per `attestation.md`. Owns
    /// per-connection `our_sent` / `their_received_valid` flags and
    /// fires the `Untrusted → Peer` upgrade once both halves of the
    /// mutual exchange complete.
    AttestationDispatcher                 attestation_dispatcher_;

    /// Named-counter store the kernel maintains for built-in
    /// observability targets (`route.outcome.*`, `drop.*`,
    /// per-plugin counters). Plugins extend the surface through
    /// `host_api->emit_counter`; an exporter plugin reads through
    /// `iterate_counters`. Per `metrics.md`.
    MetricsRegistry                       metrics_;
};

} // namespace gn::core
