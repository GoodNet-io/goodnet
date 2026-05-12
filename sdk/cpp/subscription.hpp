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

    using ConnStateFn      = std::function<void(const gn_conn_event_t&)>;
    using ConfigReloadFn   = std::function<void()>;
    using CapabilityBlobFn = std::function<void(const CapabilityBlob&)>;

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
    on_conn_state(const host_api_t* api, ConnStateFn fn) {
        if (!api || !api->subscribe_conn_state || !fn) return {};
        auto holder = new ConnStateFn(std::move(fn));
        gn_subscription_id_t id = GN_INVALID_SUBSCRIPTION_ID;
        const gn_result_t rc = api->subscribe_conn_state(
            api->host_ctx,
            &conn_state_thunk, holder, &destroy_conn_state, &id);
        if (rc != GN_OK || id == GN_INVALID_SUBSCRIPTION_ID) {
            delete holder;
            return {};
        }
        return Subscription(api, id);
    }

    /// Subscribe to `GN_SUBSCRIBE_CONFIG_RELOAD`. Same null-handle
    /// semantics as `on_conn_state`.
    [[nodiscard]] static Subscription
    on_config_reload(const host_api_t* api, ConfigReloadFn fn) {
        if (!api || !api->subscribe_config_reload || !fn) return {};
        auto holder = new ConfigReloadFn(std::move(fn));
        gn_subscription_id_t id = GN_INVALID_SUBSCRIPTION_ID;
        const gn_result_t rc = api->subscribe_config_reload(
            api->host_ctx,
            &config_reload_thunk, holder, &destroy_config_reload, &id);
        if (rc != GN_OK || id == GN_INVALID_SUBSCRIPTION_ID) {
            delete holder;
            return {};
        }
        return Subscription(api, id);
    }

    /// Event-typed conn-state subscribers — sugar over
    /// `on_conn_state` that pre-filters by `kind` so the lambda
    /// signature only carries fields relevant to that event. Wraps
    /// the `match (ev.kind) { ... }` boilerplate plugins write today.
    using ConnectedFn = std::function<void(gn_conn_id_t,
                                            const gn_conn_event_t&)>;
    using DisconnectedFn = std::function<void(gn_conn_id_t)>;
    using TrustUpgradedFn = std::function<void(gn_conn_id_t,
                                                 gn_trust_class_t)>;
    using BackpressureFn  = std::function<void(gn_conn_id_t, bool soft)>;

    /// Fires only on `GN_CONN_EVENT_CONNECTED`. Lambda receives the
    /// new conn id and the full event (for trust class, role, etc.).
    [[nodiscard]] static Subscription
    on_connected(const host_api_t* api, ConnectedFn fn) {
        if (!fn) return {};
        return on_conn_state(api,
            [cb = std::move(fn)](const gn_conn_event_t& ev) {
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
            [cb = std::move(fn)](const gn_conn_event_t& ev) {
                if (ev.kind == GN_CONN_EVENT_DISCONNECTED) cb(ev.conn);
            });
    }

    /// Fires only on `GN_CONN_EVENT_TRUST_UPGRADED`. Lambda receives
    /// the conn id and the new trust class.
    [[nodiscard]] static Subscription
    on_trust_upgraded(const host_api_t* api, TrustUpgradedFn fn) {
        if (!fn) return {};
        return on_conn_state(api,
            [cb = std::move(fn)](const gn_conn_event_t& ev) {
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
            [cb = std::move(fn)](const gn_conn_event_t& ev) {
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
    on_capability_blob(const host_api_t* api, CapabilityBlobFn fn) {
        if (!api || !api->subscribe_capability_blob || !fn) return {};
        auto holder = new CapabilityBlobFn(std::move(fn));
        gn_subscription_id_t id = GN_INVALID_SUBSCRIPTION_ID;
        const gn_result_t rc = api->subscribe_capability_blob(
            api->host_ctx,
            &capability_blob_thunk, holder, &destroy_capability_blob, &id);
        if (rc != GN_OK || id == GN_INVALID_SUBSCRIPTION_ID) {
            delete holder;
            return {};
        }
        return Subscription(api, id);
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

    static void conn_state_thunk(void* user,
                                  const gn_conn_event_t* ev) noexcept {
        if (!user || !ev) return;
        try { (*static_cast<ConnStateFn*>(user))(*ev); } catch (...) {  // NOLINT(bugprone-empty-catch)
            // Kernel callback boundary is noexcept across the C ABI.
        }
    }
    static void destroy_conn_state(void* user) noexcept {
        delete static_cast<ConnStateFn*>(user);
    }

    static void config_reload_thunk(void* user) noexcept {
        if (!user) return;
        try { (*static_cast<ConfigReloadFn*>(user))(); } catch (...) {  // NOLINT(bugprone-empty-catch)
            // Kernel callback boundary is noexcept across the C ABI.
        }
    }
    static void destroy_config_reload(void* user) noexcept {
        delete static_cast<ConfigReloadFn*>(user);
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
        try { (*static_cast<CapabilityBlobFn*>(user))(b); } catch (...) {  // NOLINT(bugprone-empty-catch)
            // Kernel callback boundary is noexcept across the C ABI.
        }
    }
    static void destroy_capability_blob(void* user) noexcept {
        delete static_cast<CapabilityBlobFn*>(user);
    }

    const host_api_t*    api_ = nullptr;
    gn_subscription_id_t id_  = GN_INVALID_SUBSCRIPTION_ID;
};

} // namespace gn::sdk
