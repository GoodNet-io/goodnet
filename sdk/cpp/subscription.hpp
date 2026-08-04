// SPDX-License-Identifier: Apache-2.0
/// @file   sdk/cpp/subscription.hpp
/// @brief  RAII wrapper around `host_api_t` subscribe slots.
///
/// Each handler/link plugin that subscribes to a kernel event
/// channel (`conn_state`, `config_reload`, `capability_blob`) ends up
/// hand-writing the same 3-line pattern: declare a
/// `gn_subscription_id_t` field, call `subscribe_*` in init, call
/// `unsubscribe` in dtor. The pattern leaks under exceptions and
/// makes destructor ordering subtle.
///
/// `gn::sdk::Subscription` is a move-only handle that pairs a
/// subscription token with the `host_api_t*` that issued it; the
/// dtor calls `api->unsubscribe(token)`. The lambda captures get
/// owned by the handle, so they outlive the subscription
/// regardless of caller scope.
///
/// @code
/// auto sub = gn::sdk::Subscription::on_conn_state(
///     api,
///     [this](const gn_conn_event_t& ev) { handle(ev); });
/// // ...sub lives as a class member; dtor auto-unsubscribes.
/// @endcode

#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <utility>

#include <sdk/conn_events.h>
#include <sdk/cpp/contract.hpp>
#include <sdk/host_api.h>
#include <sdk/identity.h>
#include <sdk/types.h>

namespace gn::sdk {

class Subscription {
public:
    /// Bundle of the 5 flat parameters the kernel passes to a
    /// `gn_capability_blob_cb_t` invocation. Lets the lambda accept
    /// one argument instead of five.
    struct CapabilityBlob {
        gn_conn_id_t                 from_conn;
        std::span<const std::uint8_t> bytes;
        std::int64_t                 expires_unix_ts;
    };

    using ConnStateFn        = std::move_only_function<void(const gn_conn_event_t&)>;
    using ConfigReloadFn     = std::move_only_function<void()>;
    using TopologyReloadFn   = std::move_only_function<void(const gn_topology_s* prev,
                                                             const gn_topology_s* next)>;
    using CapabilityBlobFn   = std::move_only_function<void(const CapabilityBlob&)>;

    Subscription() noexcept = default;

    Subscription(const Subscription&)            = delete;
    Subscription& operator=(const Subscription&) = delete;

    Subscription(Subscription&& o) noexcept { steal(std::move(o)); }
    Subscription& operator=(Subscription&& o) noexcept {
        if (this != &o) {
            release();
            steal(std::move(o));
        }
        return *this;
    }
    ~Subscription() noexcept { release(); }

    [[nodiscard]] bool valid() const noexcept {
        return api_ != nullptr && id_ != GN_INVALID_SUBSCRIPTION_ID;
    }
    [[nodiscard]] gn_subscription_id_t id() const noexcept { return id_; }

    /// Subscribe to `GN_SUBSCRIBE_CONN_STATE`. Returns a null handle
    /// (`valid() == false`) if @p api is null, the subscribe slot is
    /// unset, or the kernel rejected the registration.
    [[nodiscard]] static Subscription
    on_conn_state(const host_api_t* api, ConnStateFn fn)
    {
        if (!api) return {};
        return subscribe_impl<ConnStateFn>(api, std::move(fn),
                                           api->subscribe_conn_state,
                                           &conn_state_thunk);
    }

    /// Subscribe to `GN_SUBSCRIBE_CONFIG_RELOAD`. Same null-handle
    /// semantics as `on_conn_state`.
    [[nodiscard]] static Subscription
    on_config_reload(const host_api_t* api, ConfigReloadFn fn)
    {
        if (!api) return {};
        return subscribe_impl<ConfigReloadFn>(api, std::move(fn),
                                              api->subscribe_config_reload,
                                              &config_reload_thunk);
    }

    /// Subscribe to `GN_SUBSCRIBE_TOPOLOGY_RELOAD`. `prev` is null on
    /// the first reload. Both pointers are borrowed for the callback
    /// duration. Same null-handle semantics as `on_conn_state`.
    [[nodiscard]] static Subscription
    on_topology_reload(const host_api_t* api, TopologyReloadFn fn)
    {
        if (!api) return {};
        if (!GN_API_HAS(host_api_t, api, subscribe_topology_reload) ||
            !api->subscribe_topology_reload) return {};
        return subscribe_impl<TopologyReloadFn>(api, std::move(fn),
                                                api->subscribe_topology_reload,
                                                &topology_reload_thunk);
    }

    /// Event-typed conn-state subscribers — sugar over
    /// `on_conn_state` that pre-filters by `kind` so the lambda
    /// signature only carries fields relevant to that event. Wraps
    /// the `match (ev.kind) { ... }` boilerplate plugins write today.
    using ConnectedFn     = std::move_only_function<void(gn_conn_id_t,
                                                          const gn_conn_event_t&)>;
    using DisconnectedFn  = std::move_only_function<void(gn_conn_id_t)>;
    using TrustUpgradedFn = std::move_only_function<void(gn_conn_id_t,
                                                          gn_trust_class_t)>;
    using BackpressureFn  = std::move_only_function<void(gn_conn_id_t, bool soft)>;

    /// Fires only on `GN_CONN_EVENT_CONNECTED`. Lambda receives the
    /// new conn id and the full event (for trust class, role, etc.).
    [[nodiscard]] static Subscription
    on_connected(const host_api_t* api, ConnectedFn fn) {
        if (!fn) return {};
        return on_conn_state(api,
            [cb = std::move(fn)](const gn_conn_event_t& ev) mutable {
                if (ev.kind == GN_CONN_EVENT_CONNECTED) cb(ev.conn, ev);
            });
    }

    /// Fires only on `GN_CONN_EVENT_DISCONNECTED`. Lambda receives
    /// just the conn id — the rest of the event is irrelevant on a
    /// closed conn.
    [[nodiscard]] static Subscription
    on_disconnected(const host_api_t* api, DisconnectedFn fn) {
        if (!fn) return {};
        return on_conn_state(api,
            [cb = std::move(fn)](const gn_conn_event_t& ev) mutable {
                if (ev.kind == GN_CONN_EVENT_DISCONNECTED) cb(ev.conn);
            });
    }

    /// Fires only on `GN_CONN_EVENT_TRUST_UPGRADED`. Lambda receives
    /// the conn id and the new trust class.
    [[nodiscard]] static Subscription
    on_trust_upgraded(const host_api_t* api, TrustUpgradedFn fn) {
        if (!fn) return {};
        return on_conn_state(api,
            [cb = std::move(fn)](const gn_conn_event_t& ev) mutable {
                if (ev.kind == GN_CONN_EVENT_TRUST_UPGRADED) {
                    cb(ev.conn, ev.trust);
                }
            });
    }

    /// Fires on both `GN_CONN_EVENT_BACKPRESSURE_SOFT` (soft=true)
    /// and `GN_CONN_EVENT_BACKPRESSURE_CLEAR` (soft=false). One
    /// subscription covers both half-events — pair them in the
    /// caller's state machine.
    [[nodiscard]] static Subscription
    on_backpressure(const host_api_t* api, BackpressureFn fn) {
        if (!fn) return {};
        return on_conn_state(api,
            [cb = std::move(fn)](const gn_conn_event_t& ev) mutable {
                if (ev.kind == GN_CONN_EVENT_BACKPRESSURE_SOFT) {
                    cb(ev.conn, /*soft=*/true);
                } else if (ev.kind == GN_CONN_EVENT_BACKPRESSURE_CLEAR) {
                    cb(ev.conn, /*soft=*/false);
                }
            });
    }

    /// Subscribe to `subscribe_capability_blob`. Returns a null
    /// handle if the slot is unset (the kernel build dropped the
    /// blob bus) or the kernel rejected the registration.
    [[nodiscard]] static Subscription
    on_capability_blob(const host_api_t* api, CapabilityBlobFn fn)
    {
        if (!api) return {};
        return subscribe_impl<CapabilityBlobFn>(api, std::move(fn),
                                                api->subscribe_capability_blob,
                                                &capability_blob_thunk);
    }

private:
    Subscription(const host_api_t* api, gn_subscription_id_t id) noexcept
        : api_(api), id_(id) {}

    void steal(Subscription&& o) noexcept {
        api_ = o.api_;
        id_  = o.id_;
        o.api_ = nullptr;
        o.id_  = GN_INVALID_SUBSCRIPTION_ID;
    }

    void release() noexcept {
        if (!valid()) return;
        if (api_ && api_->unsubscribe) {
            (void)api_->unsubscribe(api_->host_ctx, id_);
        }
        api_ = nullptr;
        id_  = GN_INVALID_SUBSCRIPTION_ID;
    }

    /// Generic subscribe helper. Allocates @p fn on the heap, calls
    /// @p slot with the typed thunk and destroy, returns a valid
    /// Subscription on success. Frees @p fn and returns invalid on
    /// any failure. Both slot-null and fn-falsy cases short-circuit.
    template <typename FnType, typename SlotFn, typename ThunkFn>
    [[nodiscard]] static Subscription subscribe_impl(
        const host_api_t* api, FnType fn, SlotFn slot, ThunkFn thunk)
    {
        if (!slot || !fn) return {};
        auto* holder = new FnType(std::move(fn));
        gn_subscription_id_t id = GN_INVALID_SUBSCRIPTION_ID;
        const gn_result_t rc = slot(api->host_ctx, thunk, holder,
                                     &destroy_holder<FnType>, &id);
        if (rc != GN_OK || id == GN_INVALID_SUBSCRIPTION_ID) {
            destroy_holder<FnType>(holder);
            return {};
        }
        return Subscription(api, id);
    }

    template <typename T>
    static void destroy_holder(void* p) noexcept {
        delete static_cast<T*>(p);
    }

    static void conn_state_thunk(void* user,
                                  const gn_conn_event_t* ev) noexcept {
        if (!user || !ev) return;
        try { (*static_cast<ConnStateFn*>(user))(*ev); } catch (...) {}  // NOLINT(bugprone-empty-catch)
    }

    static void config_reload_thunk(void* user) noexcept {
        if (!user) return;
        try { (*static_cast<ConfigReloadFn*>(user))(); } catch (...) {}  // NOLINT(bugprone-empty-catch)
    }

    static void topology_reload_thunk(void* user,
                                       const struct gn_topology_s* prev,
                                       const struct gn_topology_s* next) noexcept {
        if (!user) return;
        try { (*static_cast<TopologyReloadFn*>(user))(prev, next); } catch (...) {}  // NOLINT(bugprone-empty-catch)
    }

    static void capability_blob_thunk(void* user,
                                       gn_conn_id_t from_conn,
                                       const std::uint8_t* blob,
                                       std::size_t size,
                                       std::int64_t expires) noexcept {
        if (!user) return;
        CapabilityBlob b{from_conn,
                          std::span<const std::uint8_t>(blob, size),
                          expires};
        try { (*static_cast<CapabilityBlobFn*>(user))(b); } catch (...) {}  // NOLINT(bugprone-empty-catch)
    }

    const host_api_t*    api_ = nullptr;
    gn_subscription_id_t id_  = GN_INVALID_SUBSCRIPTION_ID;
};

} // namespace gn::sdk
