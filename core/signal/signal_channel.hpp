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

    SignalChannel()                                = default;
    SignalChannel(const SignalChannel&)            = delete;
    SignalChannel& operator=(const SignalChannel&) = delete;

    /// Register @p handler. Returns a token the caller hands back to
    /// `unsubscribe`.
    [[nodiscard]] Token subscribe(Handler handler) {
        std::unique_lock lock(mu_);
        Token t = next_token_++;
        subs_.push_back(Sub{t, std::move(handler)});
        return t;
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
    /// deadlocking against the channel.
    void fire(const Event& event) {
        std::vector<Handler> snapshot;
        {
            std::shared_lock lock(mu_);
            snapshot.reserve(subs_.size());
            for (const auto& s : subs_) snapshot.push_back(s.handler);
        }
        for (auto& h : snapshot) h(event);
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
};

/// Empty event type — used as the payload for parameterless signals
/// like config_reload where the topic itself carries all the meaning.
struct Empty {};

} // namespace gn::core::signal
