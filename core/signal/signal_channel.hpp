/// @file   core/signal/signal_channel.hpp
/// @brief  Typed publish/subscribe channel for non-FSM kernel events.
///
/// FSM phase changes go through `Kernel::subscribe` per
/// `fsm-events.md` §7. Other event families — config reload, plugin
/// loaded / unloaded, connection state changes — flow through one
/// `SignalChannel<Event>` per event type.
///
/// Subscribers register a handler and receive a token they hand back
/// on unsubscribe. Snapshots taken under the channel's shared lock
/// fire without holding it so a handler may subscribe or unsubscribe
/// against the same channel inside its own callback without
/// deadlocking. Token issuance is monotonic and does not wrap inside
/// realistic lifetimes.

#pragma once

#include <cstdint>
#include <exception>
#include <functional>
#include <mutex>
#include <shared_mutex>
#include <utility>
#include <vector>

namespace gn::core::signal {

template <class Event>
class SignalChannel {
public:
    using Handler = std::function<void(const Event&)>;
    using Token   = std::uint64_t;

    /// Sentinel returned from `subscribe` when the handler is empty;
    /// matches `GN_INVALID_SUBSCRIPTION_ID` in `conn-events.md` §3.
    static constexpr Token kInvalidToken = 0;

    SignalChannel()                                = default;
    SignalChannel(const SignalChannel&)            = delete;
    SignalChannel& operator=(const SignalChannel&) = delete;

    /// Register @p handler. Returns a token the caller hands back to
    /// `unsubscribe`. An empty `std::function` (default-constructed
    /// or wrapping a NULL C function pointer) returns `kInvalidToken`
    /// per `signal-channel.md` §6.1; the subscriber list is unchanged.
    /// A subscribe past the live-cap (`set_max_subscribers`) also
    /// returns `kInvalidToken`; the host_api thunks surface that to
    /// callers as `GN_ERR_LIMIT_REACHED` per `conn-events.md` §6.
    [[nodiscard]] Token subscribe(Handler handler) {
        if (!handler) return kInvalidToken;
        std::unique_lock lock(mu_);
        const std::size_t cap = max_subscribers_;
        if (cap != 0 && subs_.size() >= cap) return kInvalidToken;
        Token t = next_token_++;
        subs_.push_back(Sub{t, std::move(handler)});
        return t;
    }

    /// Set the live-subscriber cap. Zero disables the check.
    /// Plain store under the mutex so a concurrent `subscribe`
    /// either sees the new cap or completes against the old one;
    /// in either case the cap holds eventually because the live
    /// list is protected by the same mutex.
    void set_max_subscribers(std::size_t cap) {
        std::unique_lock lock(mu_);
        max_subscribers_ = cap;
    }

    /// Remove the subscription. Idempotent — calling on an already-
    /// removed token is a no-op.
    void unsubscribe(Token token) {
        std::unique_lock lock(mu_);
        std::erase_if(subs_, [token](const Sub& s) { return s.token == token; });
    }

    /// Fire @p event to every current subscriber. Snapshot under the
    /// lock, drop the lock, then invoke handlers — so handlers may
    /// subscribe or unsubscribe inside their own callback without
    /// deadlocking against the channel. A handler that raises is
    /// caught per `signal-channel.md` §6.2: the exception is
    /// discarded and remaining snapshot subscribers still receive
    /// the event.
    void fire(const Event& event) {
        std::vector<Handler> snapshot;
        {
            std::shared_lock lock(mu_);
            snapshot.reserve(subs_.size());
            for (const auto& s : subs_) snapshot.push_back(s.handler);
        }
        for (auto& h : snapshot) {
            try {
                h(event);
            } catch (...) {  // NOLINT(bugprone-empty-catch)
                /// Per `signal-channel.md` §6.2: drop the exception so
                /// one bad subscriber cannot starve the rest. Plugin
                /// authors catch internally before returning across the
                /// C ABI boundary; `std::current_exception` is avoided
                /// so `fire` stays no-throw even under memory pressure.
            }
        }
    }

    /// Number of currently subscribed handlers. Useful for tests.
    [[nodiscard]] std::size_t subscriber_count() const {
        std::shared_lock lock(mu_);
        return subs_.size();
    }

private:
    struct Sub {
        Token   token;
        Handler handler;
    };

    mutable std::shared_mutex mu_;
    std::vector<Sub>          subs_;
    Token                     next_token_{1};
    std::size_t               max_subscribers_{0};
};

/// Empty event type — used as the payload for parameterless signals
/// like config_reload where the topic itself carries all the meaning.
struct Empty {};

} // namespace gn::core::signal
