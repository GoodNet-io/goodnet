// SPDX-License-Identifier: Apache-2.0
/// @file   sdk/cpp/per_conn_map.hpp
/// @brief  Per-connection state map with auto-cleanup on DISCONNECTED.
///
/// Every handler/link plugin with peer-specific state (heartbeat,
/// relay, float-send-rtt, ...) hand-rolls the same pattern:
///   1. `unordered_map<gn_conn_id_t, shared_ptr<State>>` + mutex
///   2. `ensure_peer` / `find_peer` helpers
///   3. `subscribe_conn_state` with a callback that erases on
///      `GN_CONN_EVENT_DISCONNECTED`
///
/// `gn::sdk::PerConnMap<State>` packages it into one type with
/// auto-cleanup safety: the conn-state subscription is owned by the
/// map, and the internal storage is held via a `shared_ptr<Impl>` so
/// an in-flight DISCONNECTED callback finishes safely even if the
/// map gets destroyed mid-callback.
///
/// @code
/// struct PeerState { Pings pings; LastSeen last_seen; };
/// gn::sdk::PerConnMap<PeerState> peers_(host_api);
///
/// auto state = peers_.ensure(conn);  // get-or-create
/// state->last_seen = now();
/// @endcode

#pragma once

#include <functional>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <utility>

#include <sdk/conn_events.h>
#include <sdk/cpp/subscription.hpp>
#include <sdk/host_api.h>
#include <sdk/types.h>

namespace gn::sdk {

template <class State>
class PerConnMap {
public:
    using DisconnectHandler = std::function<void(gn_conn_id_t)>;

    /// Subscribes to `conn_state` immediately. Pass a custom @p
    /// on_disconnect if the default `erase` semantics aren't right
    /// (e.g., you want to schedule a delayed teardown instead).
    explicit PerConnMap(const host_api_t* api,
                        DisconnectHandler on_disconnect = {})
        : impl_(std::make_shared<Impl>()) {
        impl_->on_disconnect = std::move(on_disconnect);
        std::weak_ptr<Impl> weak = impl_;
        sub_ = Subscription::on_conn_state(api,
            [weak](const gn_conn_event_t& ev) {
                if (ev.kind != GN_CONN_EVENT_DISCONNECTED) return;
                auto self = weak.lock();
                if (!self) return;
                DisconnectHandler hook;
                {
                    std::lock_guard lk(self->mu);
                    self->m.erase(ev.conn);
                    hook = self->on_disconnect;
                }
                if (hook) hook(ev.conn);
            });
    }

    PerConnMap(const PerConnMap&)            = delete;
    PerConnMap& operator=(const PerConnMap&) = delete;
    PerConnMap(PerConnMap&&) noexcept            = default;
    PerConnMap& operator=(PerConnMap&&) noexcept = default;
    ~PerConnMap()                                = default;

    /// Get-or-construct per-conn state. Default-constructed unless
    /// @p args is non-empty.
    template <class... Args>
    [[nodiscard]] std::shared_ptr<State> ensure(gn_conn_id_t conn,
                                                  Args&&... args) {
        std::lock_guard lk(impl_->mu);
        auto& slot = impl_->m[conn];
        if (!slot) {
            slot = std::make_shared<State>(std::forward<Args>(args)...);
        }
        return slot;
    }

    /// Return the state for @p conn, or `nullptr` if absent.
    [[nodiscard]] std::shared_ptr<State> find(gn_conn_id_t conn) const {
        std::lock_guard lk(impl_->mu);
        auto it = impl_->m.find(conn);
        return it == impl_->m.end() ? nullptr : it->second;
    }

    void erase(gn_conn_id_t conn) {
        std::lock_guard lk(impl_->mu);
        impl_->m.erase(conn);
    }

    [[nodiscard]] std::size_t size() const noexcept {
        std::lock_guard lk(impl_->mu);
        return impl_->m.size();
    }

    /// Override the DISCONNECTED hook installed at construction.
    /// The hook runs after the entry is erased; pass `{}` to disable.
    void set_disconnect_handler(DisconnectHandler hook) {
        std::lock_guard lk(impl_->mu);
        impl_->on_disconnect = std::move(hook);
    }

    /// Iterate over every (conn, state) pair under the internal
    /// lock. The visitor must not call other `PerConnMap` methods on
    /// the same instance (would deadlock).
    template <class Visitor>
    void for_each(Visitor&& v) const {
        std::lock_guard lk(impl_->mu);
        for (const auto& [conn, state] : impl_->m) {
            v(conn, state);
        }
    }

private:
    struct Impl {
        mutable std::mutex mu;
        std::unordered_map<gn_conn_id_t, std::shared_ptr<State>> m;
        DisconnectHandler on_disconnect;
    };

    std::shared_ptr<Impl> impl_;
    Subscription          sub_;
};

} // namespace gn::sdk
