/// @file   core/kernel/host_api_builder.cpp
/// @brief  Implementation of `build_host_api`.

#include "host_api_builder.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <core/util/log.hpp>

#include "connection_context.hpp"
#include "kernel.hpp"
#include "safe_invoke.hpp"
#include "system_handler_ids.hpp"

namespace gn::core {

namespace {

/// Liveness check for the `PluginContext*` every host_api thunk
/// reaches through `host_ctx`. The kernel stamps `kMagicDead` in
/// `~PluginContext`; a plugin that retained the `host_api`
/// pointer past its own teardown lands in a thunk with a freed
/// context whose magic field reads as the poison value (or, if
/// the slab was reused, as unrelated bytes). The thunk returns
/// before dereferencing any other field. See
/// `plugin_context.hpp` for the soft-guard caveats — sanitisers
/// remain the source of truth for true UAF detection.
[[nodiscard]] inline bool ctx_live(PluginContext* pc) noexcept {
    return pc != nullptr && pc->magic == PluginContext::kMagicLive;
}

/// Build a `gn_message_t` from the four pieces every assembly site
/// always has: the two public keys, the msg id, and the borrowed
/// payload span. Pre-helper this was a 7-line memcpy ritual at
/// every site (thunk_send, thunk_inject_external_message); the
/// helper centralises the layout so a future field addition lands
/// in one place. `payload` is `@borrowed` for the kernel call;
/// the helper does not copy.
[[nodiscard]] gn_message_t build_envelope(
    const PublicKey&   sender_pk,
    const PublicKey&   receiver_pk,
    std::uint32_t      msg_id,
    const std::uint8_t* payload,
    std::size_t        payload_size) noexcept
{
    gn_message_t env{};
    env.msg_id       = msg_id;
    env.payload      = payload;
    env.payload_size = payload_size;
    std::memcpy(env.sender_pk,   sender_pk.data(),   GN_PUBLIC_KEY_BYTES);
    std::memcpy(env.receiver_pk, receiver_pk.data(), GN_PUBLIC_KEY_BYTES);
    return env;
}

/// Loader-side host-API entries — `notify_connect` /
/// `notify_inbound_bytes` / `notify_disconnect` / `kick_handshake`
/// — are reserved for transport plugins. A handler / security /
/// protocol plugin attempting to call them must be rejected up
/// front: a misbehaving handler that allocated phantom connection
/// records would corrupt the registry. The descriptor's `kind`
/// field declares the plugin's role; `Unknown` is permissive for
/// legacy descriptors that predate the field.
[[nodiscard]] bool transport_role(const PluginContext* pc) noexcept {
    if (pc == nullptr) return false;
    return pc->kind == GN_PLUGIN_KIND_LINK ||
           pc->kind == GN_PLUGIN_KIND_UNKNOWN;
}

/// Stable name per `RouteOutcome` value for diagnostic logs.
[[nodiscard]] const char* route_outcome_str(RouteOutcome o) noexcept {
    switch (o) {
        case RouteOutcome::DispatchedLocal:        return "dispatched-local";
        case RouteOutcome::DispatchedBroadcast:    return "dispatched-broadcast";
        case RouteOutcome::DeferredRelay:          return "deferred-relay";
        case RouteOutcome::DroppedZeroSender:      return "drop-zero-sender";
        case RouteOutcome::DroppedInvalidMsgId:    return "drop-invalid-msg-id";
        case RouteOutcome::DroppedUnknownReceiver: return "drop-unknown-receiver";
        case RouteOutcome::DroppedNoHandler:       return "drop-no-handler";
        case RouteOutcome::Rejected:               return "rejected";
    }
    return "unknown";
}

/// Surface the router's verdict — the result was previously dropped
/// `(void)`-cast at every dispatch site, so a handler returning
/// `Rejected` or a malformed envelope hitting `DroppedZeroSender`
/// produced no kernel-side trace. Per `fsm-events.md`, every
/// callback return is consumed; here we consume by logging **and**
/// by bumping the corresponding `route.outcome.*` counter so an
/// out-of-tree exporter plugin can scrape envelope-loss totals
/// (`metrics.md` §4). Reject is a handler-policy signal — kernel
/// does not auto-disconnect on it, but the operator now sees the
/// rate alongside every other drop reason on the same surface.
void route_one_envelope(Kernel& kernel,
                        std::string_view protocol_id,
                        const gn_message_t& env) {
    const auto outcome = kernel.router().route_inbound(protocol_id, env);
    kernel.metrics().increment_route_outcome(outcome);
    switch (outcome) {
        case RouteOutcome::DispatchedLocal:
        case RouteOutcome::DispatchedBroadcast:
        case RouteOutcome::DeferredRelay:
            return;
        case RouteOutcome::Rejected:
        case RouteOutcome::DroppedZeroSender:
        case RouteOutcome::DroppedInvalidMsgId:
            ::gn::log::warn("router: drop outcome={} msg_id={}",
                            route_outcome_str(outcome), env.msg_id);
            return;
        case RouteOutcome::DroppedUnknownReceiver:
        case RouteOutcome::DroppedNoHandler:
            ::gn::log::debug("router: drop outcome={} msg_id={}",
                             route_outcome_str(outcome), env.msg_id);
            return;
    }
}

/* ── Slot thunks. Each casts host_ctx → PluginContext* and dispatches. ── */

gn_result_t thunk_send(void* host_ctx,
                       gn_conn_id_t conn,
                       uint32_t msg_id,
                       const uint8_t* payload,
                       size_t payload_size) {
    if (!host_ctx) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;

    auto rec = pc->kernel->connections().find_by_id(conn);
    if (!rec) return GN_ERR_NOT_FOUND;

    auto trans = pc->kernel->links().find_by_scheme(rec->transport_scheme);
    if (!trans || !trans->vtable || !trans->vtable->send) {
        return GN_ERR_NOT_IMPLEMENTED;
    }

    auto layer = pc->kernel->protocol_layer();
    if (!layer) return GN_ERR_NOT_IMPLEMENTED;

    /// Outbound envelope: this node is the sender, `rec` is the
    /// receiver. `identities().any()` returns the kernel's local
    /// identity public key; absent it the envelope's `sender_pk`
    /// stays zero and the protocol layer emits the broadcast form.
    const PublicKey local_pk =
        pc->kernel->identities().any().value_or(PublicKey{});
    gn_message_t env = build_envelope(
        local_pk, rec->remote_pk, msg_id, payload, payload_size);

    gn_connection_context_t ctx{};
    ctx.conn_id   = conn;
    ctx.trust     = rec->trust;
    ctx.remote_pk = rec->remote_pk;
    if (auto local = pc->kernel->identities().any(); local) {
        ctx.local_pk = *local;
    }

    auto framed = layer->frame(ctx, env);
    if (!framed) return framed.error().code;

    /// Encrypt the framed envelope through the connection's security
    /// session when one is bound and has reached the transport phase.
    /// While the session is in Handshake the framed plaintext is
    /// buffered on the session's pending queue and drained once the
    /// transport keys come up (`backpressure.md` §8). The no-session
    /// path (loopback / null-security per `security-trust.md` §4)
    /// sends the framed bytes verbatim.
    auto session = pc->kernel->sessions().find(conn);
    if (session != nullptr) {
        if (session->phase() == SecurityPhase::Handshake) {
            const auto cap = pc->kernel->limits().pending_handshake_bytes;
            return session->enqueue_pending(std::move(*framed),
                                             static_cast<std::uint64_t>(cap));
        }
        if (session->phase() == SecurityPhase::Transport) {
            std::vector<std::uint8_t> cipher;
            const gn_result_t rc = session->encrypt_transport(*framed, cipher);
            if (rc != GN_OK) return rc;
            const auto send_rc = safe_call_result("transport.send",
                trans->vtable->send, trans->self, conn,
                cipher.data(), cipher.size());
            if (send_rc == GN_OK) {
                pc->kernel->connections().add_outbound(
                    conn, cipher.size(), 1);
            }
            return send_rc;
        }
    }

    const auto send_rc = safe_call_result("transport.send",
        trans->vtable->send, trans->self, conn,
        framed->data(), framed->size());
    if (send_rc == GN_OK) {
        pc->kernel->connections().add_outbound(
            conn, framed->size(), 1);
    }
    return send_rc;
}

gn_result_t thunk_find_conn_by_pk(void* host_ctx,
                                   const std::uint8_t pk[GN_PUBLIC_KEY_BYTES],
                                   gn_conn_id_t* out_conn) {
    if (!host_ctx || !pk || !out_conn) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;

    PublicKey key{};
    std::memcpy(key.data(), pk, GN_PUBLIC_KEY_BYTES);
    auto rec = pc->kernel->connections().find_by_pk(key);
    if (!rec) return GN_ERR_NOT_FOUND;
    *out_conn = rec->id;
    return GN_OK;
}

gn_result_t thunk_get_endpoint(void* host_ctx, gn_conn_id_t conn,
                                gn_endpoint_t* out) {
    if (!host_ctx || !out) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;

    auto rec = pc->kernel->connections().find_by_id(conn);
    if (!rec) return GN_ERR_NOT_FOUND;

    std::memset(out, 0, sizeof(*out));
    out->conn_id = rec->id;
    std::memcpy(out->remote_pk, rec->remote_pk.data(), GN_PUBLIC_KEY_BYTES);
    out->trust = rec->trust;

    const std::size_t uri_n =
        std::min(rec->uri.size(), static_cast<std::size_t>(GN_ENDPOINT_URI_MAX - 1));
    std::memcpy(out->uri, rec->uri.data(), uri_n);
    out->uri[uri_n] = '\0';

    const std::size_t scheme_n =
        std::min(rec->transport_scheme.size(), sizeof(out->transport_scheme) - 1);
    std::memcpy(out->transport_scheme, rec->transport_scheme.data(), scheme_n);
    out->transport_scheme[scheme_n] = '\0';

    out->bytes_in            = rec->bytes_in;
    out->bytes_out           = rec->bytes_out;
    out->frames_in           = rec->frames_in;
    out->frames_out          = rec->frames_out;
    out->pending_queue_bytes = rec->pending_queue_bytes;
    out->last_rtt_us         = rec->last_rtt_us;
    return GN_OK;
}

gn_result_t thunk_register_security(void* host_ctx,
                                     const char* provider_id,
                                     const gn_security_provider_vtable_t* vtable,
                                     void* security_self) {
    if (!host_ctx || !provider_id || !vtable) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;
    return pc->kernel->security().register_provider(
        provider_id, vtable, security_self, pc->plugin_anchor);
}

gn_result_t thunk_unregister_security(void* host_ctx, const char* provider_id) {
    if (!host_ctx || !provider_id) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;
    return pc->kernel->security().unregister_provider(provider_id);
}

gn_result_t thunk_disconnect(void* host_ctx, gn_conn_id_t conn) {
    if (!host_ctx) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;
    auto rec = pc->kernel->connections().find_by_id(conn);
    if (!rec) return GN_ERR_NOT_FOUND;
    auto trans = pc->kernel->links().find_by_scheme(rec->transport_scheme);
    if (!trans || !trans->vtable || !trans->vtable->disconnect) {
        return GN_ERR_NOT_IMPLEMENTED;
    }
    return safe_call_result("transport.disconnect",
        trans->vtable->disconnect, trans->self, conn);
}

gn_result_t thunk_query_extension_checked(void* host_ctx,
                                          const char* name,
                                          uint32_t version,
                                          const void** out_vtable) {
    if (!host_ctx) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;
    return pc->kernel->extensions().query_extension_checked(
        name, version, out_vtable);
}

gn_result_t thunk_register_extension(void* host_ctx,
                                     const char* name,
                                     uint32_t version,
                                     const void* vtable) {
    if (!host_ctx) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;
    return pc->kernel->extensions().register_extension(
        name, version, vtable, pc->plugin_anchor);
}

gn_result_t thunk_unregister_extension(void* host_ctx, const char* name) {
    if (!host_ctx || !name) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;
    return pc->kernel->extensions().unregister_extension(name);
}

gn_result_t thunk_set_timer(void* host_ctx,
                             std::uint32_t delay_ms,
                             gn_task_fn_t fn,
                             void* user_data,
                             gn_timer_id_t* out_id) {
    if (!host_ctx) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;
    return pc->kernel->timers().set_timer(
        delay_ms, fn, user_data, pc->plugin_anchor, out_id);
}

gn_result_t thunk_cancel_timer(void* host_ctx, gn_timer_id_t id) {
    if (!host_ctx) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;
    return pc->kernel->timers().cancel_timer(id);
}

gn_result_t thunk_post_to_executor(void* host_ctx,
                                    gn_task_fn_t fn,
                                    void* user_data) {
    if (!host_ctx) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;
    return pc->kernel->timers().post(fn, user_data, pc->plugin_anchor);
}

gn_result_t thunk_subscribe_conn_state(void* host_ctx,
                                        gn_conn_event_cb_t cb,
                                        void* user_data,
                                        gn_subscription_id_t* out_id) {
    if (!host_ctx || !cb || !out_id) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;
    auto anchor_weak = std::weak_ptr<PluginAnchor>(pc->plugin_anchor);
    const bool anchor_set = static_cast<bool>(pc->plugin_anchor);
    auto token = pc->kernel->on_conn_event().subscribe(
        [cb, user_data, anchor_weak, anchor_set](const ConnEvent& ev) {
            /// Open a `GateGuard` for the dispatch so
            /// `PluginManager::drain_anchor` cannot run `dlclose`
            /// while the callback is still in the plugin's `.text`.
            /// The guard refuses if rollback already published
            /// `shutdown_requested = true`, dropping the dispatch.
            std::optional<GateGuard> guard;
            if (anchor_set) {
                guard = GateGuard::acquire(anchor_weak);
                if (!guard) return;
            }
            gn_conn_event_t e{};
            e.api_size      = sizeof(gn_conn_event_t);
            e.kind          = ev.kind;
            e.conn          = ev.conn;
            e.trust         = ev.trust;
            e.pending_bytes = ev.pending_bytes;
            std::memcpy(e.remote_pk, ev.remote_pk.data(),
                        GN_PUBLIC_KEY_BYTES);
            safe_call_void("conn_state.subscriber",
                cb, user_data, &e);
        });
    *out_id = static_cast<gn_subscription_id_t>(token);
    return GN_OK;
}

gn_result_t thunk_subscribe_config_reload(void* host_ctx,
                                           void (*cb)(void* user_data),
                                           void* user_data,
                                           uint64_t* out_id) {
    if (!host_ctx || !cb || !out_id) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;
    auto anchor_weak = std::weak_ptr<PluginAnchor>(pc->plugin_anchor);
    const bool anchor_set = static_cast<bool>(pc->plugin_anchor);
    auto token = pc->kernel->on_config_reload().subscribe(
        [cb, user_data, anchor_weak, anchor_set](const signal::Empty&) {
            /// Same lifetime gate as `subscribe_conn_state`: refuse
            /// the dispatch if the plugin's anchor expired or
            /// rollback published `shutdown_requested`. A plugin
            /// being unloaded must not see one last reload event
            /// after its `gn_plugin_shutdown` returned.
            if (anchor_set) {
                auto guard = GateGuard::acquire(anchor_weak);
                if (!guard) return;
                safe_call_void("config_reload.subscriber",
                    cb, user_data);
            } else {
                safe_call_void("config_reload.subscriber",
                    cb, user_data);
            }
        });
    *out_id = static_cast<std::uint64_t>(token);
    return GN_OK;
}

gn_result_t thunk_unsubscribe_config_reload(void* host_ctx,
                                              uint64_t id) {
    if (!host_ctx) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;
    pc->kernel->on_config_reload().unsubscribe(
        static_cast<signal::SignalChannel<signal::Empty>::Token>(id));
    return GN_OK;
}

int32_t thunk_is_shutdown_requested(void* host_ctx) {
    if (!host_ctx) return 0;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    /// A poisoned context surfaces as `shutdown_requested = 1`
    /// per `host-api.md` §10's cooperative-cancellation invariant
    /// — a long-running plugin loop that finds itself reading a
    /// dead context is by definition past its teardown point and
    /// should bail rather than proceed against stale state.
    if (!ctx_live(pc)) [[unlikely]] return 1;
    if (!pc->plugin_anchor) return 0;
    return pc->plugin_anchor->shutdown_requested.load(
        std::memory_order_acquire) ? 1 : 0;
}

void thunk_emit_counter(void* host_ctx, const char* name) {
    if (!host_ctx || !name) return;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return;
    pc->kernel->metrics().increment(name);
}

std::uint64_t thunk_iterate_counters(void* host_ctx,
                                      gn_counter_visitor_t visitor,
                                      void* user_data) {
    if (!host_ctx || !visitor) return 0;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return 0;
    return pc->kernel->metrics().iterate(visitor, user_data);
}

gn_result_t thunk_unsubscribe_conn_state(void* host_ctx,
                                          gn_subscription_id_t id) {
    if (!host_ctx) return GN_ERR_NULL_ARG;
    if (id == GN_INVALID_SUBSCRIPTION_ID) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;
    pc->kernel->on_conn_event().unsubscribe(
        static_cast<signal::SignalChannel<ConnEvent>::Token>(id));
    return GN_OK;
}

gn_result_t thunk_for_each_connection(void* host_ctx,
                                       gn_conn_visitor_t visitor,
                                       void* user_data) {
    if (!host_ctx || !visitor) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;
    pc->kernel->connections().for_each(
        [visitor, user_data](const ConnectionRecord& rec) -> bool {
            const auto rc_opt = safe_call_value<int>(
                "for_each_connection.visitor",
                visitor, user_data,
                rec.id, rec.trust,
                rec.remote_pk.data(), rec.uri.c_str());
            /// A throwing visitor stops the walk just as a non-zero
            /// return would; we conservatively treat the throw as
            /// "stop visiting" rather than continue.
            return rc_opt.value_or(1) == 0;
        });
    return GN_OK;
}

gn_result_t thunk_notify_backpressure(void* host_ctx,
                                       gn_conn_id_t conn,
                                       gn_conn_event_kind_t kind,
                                       std::uint64_t pending_bytes) {
    if (!host_ctx) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;
    /// Only transport-kind plugins own write queues, so only they
    /// can produce truthful backpressure signals. Other plugin
    /// kinds attempting to publish here are misconfigured.
    if (!transport_role(pc)) return GN_ERR_NOT_IMPLEMENTED;
    if (kind != GN_CONN_EVENT_BACKPRESSURE_SOFT &&
        kind != GN_CONN_EVENT_BACKPRESSURE_CLEAR) {
        return GN_ERR_INVALID_ENVELOPE;
    }

    ConnEvent ev{};
    ev.kind          = kind;
    ev.conn          = conn;
    ev.pending_bytes = pending_bytes;
    /// Snapshot trust + pk from the registry so subscribers get
    /// the same payload shape as the lifecycle events.
    if (auto rec = pc->kernel->connections().find_by_id(conn)) {
        ev.trust     = rec->trust;
        ev.remote_pk = rec->remote_pk;
    }
    /// Persist the queue depth on the record so `get_endpoint`
    /// surfaces the same value that just hit subscribers.
    pc->kernel->connections().set_pending_bytes(conn, pending_bytes);
    pc->kernel->on_conn_event().fire(ev);
    return GN_OK;
}

gn_result_t thunk_register_link(void* host_ctx,
                                     const char* scheme,
                                     const gn_link_vtable_t* vtable,
                                     void* transport_self,
                                     gn_link_id_t* out_id) {
    if (!host_ctx) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;
    return pc->kernel->links().register_link(
        scheme, vtable, transport_self, out_id, pc->plugin_anchor);
}

gn_result_t thunk_unregister_link(void* host_ctx, gn_link_id_t id) {
    if (!host_ctx) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;
    return pc->kernel->links().unregister_link(id);
}

gn_result_t thunk_register_handler(void* host_ctx,
                                   const char* protocol_id,
                                   uint32_t msg_id,
                                   uint8_t priority,
                                   const gn_handler_vtable_t* vtable,
                                   void* handler_self,
                                   gn_handler_id_t* out_id) {
    if (!host_ctx || !protocol_id || !vtable || !out_id) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;
    return pc->kernel->handlers().register_handler(
        protocol_id, msg_id, priority, vtable, handler_self, out_id,
        pc->plugin_anchor);
}

gn_result_t thunk_unregister_handler(void* host_ctx, gn_handler_id_t id) {
    if (!host_ctx) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;
    return pc->kernel->handlers().unregister_handler(id);
}

const gn_limits_t* thunk_limits(void* host_ctx) {
    if (!host_ctx) return nullptr;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return nullptr;
    return &pc->kernel->limits();
}

gn_result_t thunk_config_get_string(void* host_ctx,
                                    const char* key,
                                    char** out_str,
                                    void (**out_free)(char*)) {
    if (!host_ctx || !key || !out_str || !out_free) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;

    std::string buf;
    const auto rc = pc->kernel->config().get_string(key, buf);
    if (rc != GN_OK) return rc;

    /// Plain malloc'd C string the caller frees through *out_free.
    auto* heap = static_cast<char*>(std::malloc(buf.size() + 1));
    if (!heap) return GN_ERR_OUT_OF_MEMORY;
    std::memcpy(heap, buf.data(), buf.size());
    heap[buf.size()] = '\0';

    *out_str  = heap;
    *out_free = +[](char* p) { std::free(p); };
    return GN_OK;
}

gn_result_t thunk_config_get_int64(void* host_ctx,
                                   const char* key,
                                   int64_t* out_value) {
    if (!host_ctx || !key || !out_value) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;
    std::int64_t v = 0;
    const auto rc = pc->kernel->config().get_int64(key, v);
    if (rc != GN_OK) return rc;
    *out_value = v;
    return GN_OK;
}

gn_result_t thunk_config_get_bool(void* host_ctx,
                                   const char* key,
                                   int32_t* out_value) {
    if (!host_ctx || !key || !out_value) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;
    bool v = false;
    const auto rc = pc->kernel->config().get_bool(key, v);
    if (rc != GN_OK) return rc;
    *out_value = v ? 1 : 0;
    return GN_OK;
}

gn_result_t thunk_config_get_double(void* host_ctx,
                                     const char* key,
                                     double* out_value) {
    if (!host_ctx || !key || !out_value) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;
    return pc->kernel->config().get_double(key, *out_value);
}

gn_result_t thunk_config_get_array_size(void* host_ctx,
                                         const char* key,
                                         size_t* out_size) {
    if (!host_ctx || !key || !out_size) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;
    std::size_t v = 0;
    const auto rc = pc->kernel->config().get_array_size(key, v);
    if (rc != GN_OK) return rc;
    *out_size = v;
    return GN_OK;
}

gn_result_t thunk_config_get_array_string(void* host_ctx,
                                           const char* key,
                                           size_t index,
                                           char** out_str,
                                           void (**out_free)(char*)) {
    if (!host_ctx || !key || !out_str || !out_free) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;

    std::string buf;
    const auto rc = pc->kernel->config().get_array_string(key, index, buf);
    if (rc != GN_OK) return rc;

    auto* heap = static_cast<char*>(std::malloc(buf.size() + 1));
    if (!heap) return GN_ERR_OUT_OF_MEMORY;
    std::memcpy(heap, buf.data(), buf.size());
    heap[buf.size()] = '\0';

    *out_str  = heap;
    *out_free = +[](char* p) { std::free(p); };
    return GN_OK;
}

gn_result_t thunk_config_get_array_int64(void* host_ctx,
                                          const char* key,
                                          size_t index,
                                          int64_t* out_value) {
    if (!host_ctx || !key || !out_value) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;
    std::int64_t v = 0;
    const auto rc = pc->kernel->config().get_array_int64(key, index, v);
    if (rc != GN_OK) return rc;
    *out_value = v;
    return GN_OK;
}

[[nodiscard]] ::spdlog::level::level_enum
map_log_level(gn_log_level_t level) noexcept {
    switch (level) {
        case GN_LOG_TRACE: return ::spdlog::level::trace;
        case GN_LOG_DEBUG: return ::spdlog::level::debug;
        case GN_LOG_INFO:  return ::spdlog::level::info;
        case GN_LOG_WARN:  return ::spdlog::level::warn;
        case GN_LOG_ERROR: return ::spdlog::level::err;
        case GN_LOG_FATAL: return ::spdlog::level::critical;
    }
    return ::spdlog::level::off;
}

int32_t thunk_log_should_log(void* host_ctx, gn_log_level_t level) {
    if (!host_ctx) return 0;
    if (!ctx_live(static_cast<PluginContext*>(host_ctx))) [[unlikely]] return 0;
    const auto sp_lvl = map_log_level(level);
    if (sp_lvl == ::spdlog::level::off) return 0;
    return ::gn::log::kernel()->should_log(sp_lvl) ? 1 : 0;
}

void thunk_log_emit(void* host_ctx, gn_log_level_t level,
                     const char* file, int32_t line, const char* msg) {
    if (!host_ctx || !msg) return;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return;

    const auto sp_lvl = map_log_level(level);
    if (sp_lvl == ::spdlog::level::off) return;
    if (!::gn::log::kernel()->should_log(sp_lvl)) return;

    /// `msg` reaches spdlog as a literal `{}` argument. The kernel
    /// never invokes vsnprintf on plugin bytes — format-string
    /// attack against the kernel address space is closed.
    const ::spdlog::source_loc loc{file ? file : "", line, ""};
    if (pc->plugin_name.empty()) {
        ::gn::log::kernel()->log(loc, sp_lvl, "{}", msg);
    } else {
        ::gn::log::kernel()->log(loc, sp_lvl,
                                "[{}] {}", pc->plugin_name, msg);
    }
}

/// Send handshake-phase bytes raw via the transport vtable, bypassing
/// the security and protocol layers. The bytes are produced by the
/// security provider and already carry their own AEAD framing.
gn_result_t send_raw_via_transport(PluginContext* pc,
                                    gn_conn_id_t conn,
                                    std::string_view scheme,
                                    std::span<const std::uint8_t> bytes) {
    if (bytes.empty()) return GN_OK;
    auto trans = pc->kernel->links().find_by_scheme(scheme);
    if (!trans || !trans->vtable || !trans->vtable->send) {
        return GN_ERR_NOT_IMPLEMENTED;
    }
    return safe_call_result("transport.send",
        trans->vtable->send, trans->self, conn,
        bytes.data(), bytes.size());
}

/// Kernel-side teardown for a connection that the kernel itself
/// closes (no plugin-driven `notify_disconnect` upstream). Drops
/// the security session, atomic snapshot+erases the registry
/// record, clears the attestation per-conn state, and publishes a
/// single `GN_CONN_EVENT_DISCONNECTED` carrying the captured
/// snapshot's trust class and `remote_pk`. Idempotent on already-
/// erased ids.
void publish_kernel_disconnect(PluginContext* pc, gn_conn_id_t conn) {
    pc->kernel->sessions().destroy(conn);
    auto snapshot = pc->kernel->connections().snapshot_and_erase(conn);
    pc->kernel->attestation_dispatcher().on_disconnect(conn);
    if (!snapshot) return;
    ConnEvent ev{};
    ev.kind      = GN_CONN_EVENT_DISCONNECTED;
    ev.conn      = conn;
    ev.trust     = snapshot->trust;
    ev.remote_pk = snapshot->remote_pk;
    pc->kernel->on_conn_event().fire(ev);
}

/// Drain the session's pending-handshake queue once it has reached
/// the Transport phase.
///
/// A transport vtable that disappears between `enqueue_pending` and
/// drain would otherwise strand the bytes inside the session
/// without a visible signal. The kernel publishes
/// `GN_CONN_EVENT_DISCONNECTED` for the connection, atomic-erases
/// the registry record, and tears the session down so the producer
/// observes one loss event instead of silent buffering.
///
/// Per-frame failures (encrypt error or transport hard-cap rejection)
/// disconnect the connection through the transport plugin's
/// `disconnect` slot; the plugin's own `notify_disconnect` chain
/// publishes the event. The producer already received `GN_OK` from
/// `enqueue_pending`; once the AEAD nonce advances on the first
/// successful encrypt, partial completion is unrecoverable. Per
/// `backpressure.md` §8.
void drain_handshake_pending(PluginContext* pc,
                              gn_conn_id_t conn,
                              SecuritySession& session,
                              std::string_view transport_scheme) {
    auto trans = pc->kernel->links().find_by_scheme(transport_scheme);
    if (!trans || !trans->vtable || !trans->vtable->send) {
        publish_kernel_disconnect(pc, conn);
        return;
    }

    auto pending = session.take_pending();
    if (pending.empty()) return;

    for (auto& plaintext : pending) {
        std::vector<std::uint8_t> cipher;
        if (session.encrypt_transport(plaintext, cipher) != GN_OK) {
            if (trans->vtable->disconnect) {
                (void)safe_call_result("transport.disconnect",
                    trans->vtable->disconnect, trans->self, conn);
            }
            return;
        }
        const auto rc = safe_call_result("transport.send",
            trans->vtable->send, trans->self, conn,
            cipher.data(), cipher.size());
        if (rc == GN_OK) {
            pc->kernel->connections().add_outbound(conn, cipher.size(), 1);
            continue;
        }
        if (trans->vtable->disconnect) {
            (void)safe_call_result("transport.disconnect",
                trans->vtable->disconnect, trans->self, conn);
        }
        return;
    }
}

/// True iff @p pk has at least one non-zero byte; the kernel uses
/// all-zero as the "unknown peer" sentinel on inbound connections.
bool pk_is_known(const std::uint8_t pk[GN_PUBLIC_KEY_BYTES]) noexcept {
    for (std::size_t i = 0; i < GN_PUBLIC_KEY_BYTES; ++i) {
        if (pk[i] != 0) return true;
    }
    return false;
}

/// 64-bit key for the per-source rate limiter on `inject_*` thunks.
/// Ed25519 public keys are uniformly distributed, so the leading
/// eight bytes give a sound hash without further mixing — collision
/// rate is 1 in 2^64. Using `remote_pk` rather than `gn_conn_id_t`
/// keeps the bucket attached to the originating peer identity, so a
/// bridge plugin that disconnects and re-opens the connection does
/// not skip the rate limit by acquiring a fresh `conn_id`.
[[nodiscard]] std::uint64_t inject_rate_key(const PublicKey& pk) noexcept {
    std::uint64_t key = 0;
    std::memcpy(&key, pk.data(), sizeof(key));
    return key;
}

gn_result_t thunk_notify_connect(void* host_ctx,
                                 const uint8_t remote_pk[GN_PUBLIC_KEY_BYTES],
                                 const char* uri,
                                 const char* scheme,
                                 gn_trust_class_t trust,
                                 gn_handshake_role_t role,
                                 gn_conn_id_t* out_conn) {
    if (!host_ctx || !remote_pk || !uri || !scheme || !out_conn) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;
    if (!transport_role(pc)) return GN_ERR_NOT_IMPLEMENTED;

    /// Protocol-layer trust gate per `security-trust.md` §4: the
    /// active layer declares which trust classes it may deframe;
    /// reject the connection up front if the declared `trust` is
    /// not in the layer's mask. The security-provider gate fires
    /// later inside `Sessions::create` against the security mask.
    if (auto layer = pc->kernel->protocol_layer(); layer != nullptr) {
        const std::uint32_t mask = layer->allowed_trust_mask();
        const std::uint32_t bit  = 1u << static_cast<unsigned>(trust);
        if ((mask & bit) == 0u) return GN_ERR_INVALID_ENVELOPE;
    }

    ConnectionRecord rec;
    const gn_conn_id_t new_id = pc->kernel->connections().alloc_id();
    rec.id = new_id;
    rec.uri = uri;
    rec.transport_scheme = scheme;
    rec.trust = trust;
    rec.role  = role;
    std::memcpy(rec.remote_pk.data(), remote_pk, GN_PUBLIC_KEY_BYTES);

    const gn_result_t rc =
        pc->kernel->connections().insert_with_index(std::move(rec));
    if (rc != GN_OK) return rc;

    *out_conn = new_id;

    {
        ConnEvent ev{};
        ev.kind  = GN_CONN_EVENT_CONNECTED;
        ev.conn  = new_id;
        ev.trust = trust;
        std::memcpy(ev.remote_pk.data(), remote_pk, GN_PUBLIC_KEY_BYTES);
        pc->kernel->on_conn_event().fire(ev);
    }

    /// Spin up a security session if a provider is registered and the
    /// kernel carries a NodeIdentity. Trust classes that bypass
    /// encryption (Loopback / IntraNode with explicit opt-in per
    /// security-trust.md §4) take the no-session path and fall through
    /// to the bare protocol layer.
    auto& sec = pc->kernel->security();
    auto ident = pc->kernel->node_identity();
    if (sec.is_active() && ident != nullptr) {
        const auto entry = sec.current();
        const auto& device = ident->device();
        std::span<const std::uint8_t> rs_span;
        if (pk_is_known(remote_pk)) {
            rs_span = std::span<const std::uint8_t>(remote_pk, GN_PUBLIC_KEY_BYTES);
        }

        gn_result_t session_rc = GN_OK;
        (void)pc->kernel->sessions().create(
            new_id,
            entry,
            trust,
            role,
            device.secret_key_view(),
            std::span<const std::uint8_t, GN_PUBLIC_KEY_BYTES>(device.public_key()),
            rs_span,
            session_rc);
        if (session_rc != GN_OK) {
            (void)pc->kernel->connections().erase_with_index(new_id);
            return session_rc;
        }
        /// Initiator's first wire message is deferred to a separate
        /// `kick_handshake` call so the transport has a window to
        /// register its socket under `new_id` before bytes ride out.
    }

    return GN_OK;
}

gn_result_t thunk_kick_handshake(void* host_ctx, gn_conn_id_t conn) {
    if (!host_ctx) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;
    if (!transport_role(pc)) return GN_ERR_NOT_IMPLEMENTED;

    auto session = pc->kernel->sessions().find(conn);
    if (!session) return GN_OK;  /// no security on this conn
    if (session->phase() != SecurityPhase::Handshake) return GN_OK;

    auto rec = pc->kernel->connections().find_by_id(conn);
    if (!rec) return GN_ERR_NOT_FOUND;

    std::vector<std::uint8_t> first;
    const gn_result_t adv_rc = session->advance_handshake({}, first);
    if (adv_rc != GN_OK) return adv_rc;

    if (!first.empty()) {
        (void)send_raw_via_transport(pc, conn, rec->transport_scheme, first);
    }

    /// IK-style patterns can complete the handshake on the initiator's
    /// first message. If `advance_handshake` already moved the session
    /// to Transport, hand off to the kernel-internal attestation
    /// dispatcher per `attestation.md` §4: the dispatcher sends the
    /// local attestation payload over the secured channel; the trust
    /// upgrade `Untrusted → Peer` fires only after the peer's
    /// attestation has verified back. Loopback / IntraNode sessions
    /// take the dispatcher's no-op path (see `attestation.md` §4).
    if (session->phase() == SecurityPhase::Transport) {
        pc->kernel->attestation_dispatcher().send_self(*pc->kernel,
                                                        conn, *session);
        drain_handshake_pending(pc, conn, *session, rec->transport_scheme);
    }
    return GN_OK;
}

gn_result_t thunk_notify_inbound_bytes(void* host_ctx,
                                       gn_conn_id_t conn,
                                       const uint8_t* bytes,
                                       size_t size) {
    if (!host_ctx || (!bytes && size > 0)) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;
    if (!transport_role(pc)) return GN_ERR_NOT_IMPLEMENTED;

    /// Look up the connection record to populate the per-call context.
    auto rec = pc->kernel->connections().find_by_id(conn);
    if (!rec) return GN_ERR_NOT_FOUND;

    /// Account inbound traffic on the per-conn record; this counts
    /// every transport-delivered byte regardless of whether the
    /// payload is handshake noise, encrypted application data, or
    /// plaintext for null-security stacks. One frame per call site.
    pc->kernel->connections().add_inbound(conn, size, 1);

    /// Route through the security session when one is bound to this
    /// connection. Handshake-phase bytes drive `advance_handshake`;
    /// transport-phase bytes are decrypted before reaching the
    /// protocol layer. Connections without a session (loopback +
    /// null-security stacks per security-trust.md §4) skip both
    /// branches and fall through to the bare protocol layer.
    auto session = pc->kernel->sessions().find(conn);
    std::vector<std::uint8_t> plaintext;
    std::span<const std::uint8_t> wire_bytes{bytes, size};

    if (session != nullptr) {
        if (session->phase() == SecurityPhase::Handshake) {
            std::vector<std::uint8_t> reply;
            const gn_result_t rc = session->advance_handshake(wire_bytes, reply);
            if (rc != GN_OK) return rc;
            if (!reply.empty()) {
                (void)send_raw_via_transport(pc, conn, rec->transport_scheme, reply);
            }
            /// `advance_handshake` may have moved the session to
            /// Transport on this byte run. Hand off to the kernel-
            /// internal attestation dispatcher per `attestation.md`
            /// §4: the trust upgrade fires only after the mutual
            /// exchange completes. Loopback / IntraNode sessions
            /// take the dispatcher's no-op path.
            if (session->phase() == SecurityPhase::Transport) {
                pc->kernel->attestation_dispatcher().send_self(
                    *pc->kernel, conn, *session);
                drain_handshake_pending(pc, conn, *session,
                                         rec->transport_scheme);
            }
            /// Handshake bytes never carry application payload — the
            /// protocol layer is not consulted until Transport phase.
            return GN_OK;
        }
        if (session->phase() == SecurityPhase::Transport) {
            const gn_result_t rc = session->decrypt_transport(wire_bytes, plaintext);
            if (rc != GN_OK) return rc;
            wire_bytes = std::span<const std::uint8_t>(plaintext);
        }
    }

    gn_connection_context_t ctx{};
    ctx.conn_id   = conn;
    ctx.trust     = rec->trust;
    ctx.remote_pk = rec->remote_pk;
    if (auto local = pc->kernel->identities().any(); local) {
        ctx.local_pk = *local;
    }

    auto layer = pc->kernel->protocol_layer();
    if (layer == nullptr) return GN_ERR_NOT_IMPLEMENTED;

    auto deframed = layer->deframe(ctx, wire_bytes);
    if (!deframed.has_value()) return deframed.error().code;

    for (const auto& env : deframed->messages) {
        /// Reserved system msg_ids are intercepted before the
        /// regular dispatch chain. `0x11` (attestation) per
        /// `attestation.md` §3 routes to the kernel-internal
        /// dispatcher; the envelope never reaches plugin
        /// handlers regardless of any registration.
        if (env.msg_id == kAttestationMsgId) {
            std::shared_ptr<SecuritySession> session_for_inbound =
                pc->kernel->sessions().find(conn);
            if (session_for_inbound != nullptr) {
                std::span<const std::uint8_t> payload_span{
                    env.payload, env.payload_size};
                (void)pc->kernel->attestation_dispatcher().on_inbound(
                    *pc->kernel, conn, *session_for_inbound,
                    payload_span);
            }
            continue;
        }
        route_one_envelope(*pc->kernel, layer->protocol_id(), env);
    }
    return GN_OK;
}

gn_result_t thunk_inject_external_message(void* host_ctx,
                                           gn_conn_id_t source,
                                           std::uint32_t msg_id,
                                           const std::uint8_t* payload,
                                           std::size_t payload_size) {
    if (!host_ctx) return GN_ERR_NULL_ARG;
    if (!payload && payload_size > 0) return GN_ERR_NULL_ARG;
    if (msg_id == 0) return GN_ERR_INVALID_ENVELOPE;

    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;

    auto rec = pc->kernel->connections().find_by_id(source);
    if (!rec) return GN_ERR_NOT_FOUND;

    const auto& limits = pc->kernel->limits();
    if (limits.max_payload_bytes != 0 &&
        payload_size > limits.max_payload_bytes) {
        return GN_ERR_PAYLOAD_TOO_LARGE;
    }

    if (!pc->kernel->inject_rate_limiter().allow(
            inject_rate_key(rec->remote_pk))) {
        return GN_ERR_LIMIT_REACHED;
    }

    auto layer = pc->kernel->protocol_layer();
    if (layer == nullptr) return GN_ERR_NOT_IMPLEMENTED;

    /// Inbound bridge envelope: source connection's remote pk is
    /// the sender (the bridge re-publishes a foreign-system payload
    /// under that identity); this node's local pk is the receiver.
    const PublicKey local_pk =
        pc->kernel->identities().any().value_or(PublicKey{});
    gn_message_t env = build_envelope(
        rec->remote_pk, local_pk, msg_id, payload, payload_size);

    route_one_envelope(*pc->kernel, layer->protocol_id(), env);
    return GN_OK;
}

gn_result_t thunk_inject_frame(void* host_ctx,
                                gn_conn_id_t source,
                                const std::uint8_t* frame,
                                std::size_t frame_size) {
    if (!host_ctx) return GN_ERR_NULL_ARG;
    if (!frame || frame_size == 0) return GN_ERR_NULL_ARG;

    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;

    auto rec = pc->kernel->connections().find_by_id(source);
    if (!rec) return GN_ERR_NOT_FOUND;

    const auto& limits = pc->kernel->limits();
    if (limits.max_frame_bytes != 0 &&
        frame_size > limits.max_frame_bytes) {
        return GN_ERR_PAYLOAD_TOO_LARGE;
    }

    if (!pc->kernel->inject_rate_limiter().allow(
            inject_rate_key(rec->remote_pk))) {
        return GN_ERR_LIMIT_REACHED;
    }

    auto layer = pc->kernel->protocol_layer();
    if (layer == nullptr) return GN_ERR_NOT_IMPLEMENTED;

    gn_connection_context_t ctx{};
    ctx.conn_id   = source;
    ctx.trust     = rec->trust;
    ctx.remote_pk = rec->remote_pk;
    if (auto local = pc->kernel->identities().any(); local) {
        ctx.local_pk = *local;
    }

    auto deframed = layer->deframe(
        ctx, std::span<const std::uint8_t>{frame, frame_size});
    if (!deframed.has_value()) return deframed.error().code;

    /// inject_frame expects a complete frame; partial input or empty
    /// envelope set is a malformed call per host-api.md §8.
    if (deframed->messages.empty() || deframed->bytes_consumed == 0) {
        return GN_ERR_DEFRAME_INCOMPLETE;
    }

    for (const auto& env : deframed->messages) {
        route_one_envelope(*pc->kernel, layer->protocol_id(), env);
    }
    return GN_OK;
}

gn_result_t thunk_notify_disconnect(void* host_ctx,
                                    gn_conn_id_t conn,
                                    gn_result_t /*reason*/) {
    if (!host_ctx) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;
    if (!transport_role(pc)) return GN_ERR_NOT_IMPLEMENTED;

    /// Implements `conn-events.md` §2a: drop the security session,
    /// then atomic snapshot+erase from `registry.md` §4a, then publish
    /// DISCONNECTED only on a real removal; on no-op return
    /// `GN_ERR_NOT_FOUND` without publishing.
    pc->kernel->sessions().destroy(conn);
    auto snapshot = pc->kernel->connections().snapshot_and_erase(conn);

    /// Drop kernel-internal per-connection state before publishing
    /// the event. A subscriber that re-uses the numeric id (after
    /// kernel id reuse) on a fresh connection should not inherit
    /// stale attestation flags per `attestation.md` §7.
    pc->kernel->attestation_dispatcher().on_disconnect(conn);

    if (!snapshot) {
        return GN_ERR_NOT_FOUND;
    }

    ConnEvent ev{};
    ev.kind      = GN_CONN_EVENT_DISCONNECTED;
    ev.conn      = conn;
    ev.trust     = snapshot->trust;
    ev.remote_pk = snapshot->remote_pk;
    pc->kernel->on_conn_event().fire(ev);
    return GN_OK;
}

} // namespace

host_api_t build_host_api(PluginContext& ctx) {
    host_api_t a{};
    a.api_size = sizeof(host_api_t);
    a.host_ctx = &ctx;

    a.send                  = &thunk_send;
    a.disconnect            = &thunk_disconnect;

    a.register_handler      = &thunk_register_handler;
    a.unregister_handler    = &thunk_unregister_handler;

    a.register_link    = &thunk_register_link;
    a.unregister_link  = &thunk_unregister_link;

    a.query_extension_checked = &thunk_query_extension_checked;
    a.register_extension      = &thunk_register_extension;
    a.unregister_extension    = &thunk_unregister_extension;

    a.set_timer               = &thunk_set_timer;
    a.cancel_timer            = &thunk_cancel_timer;
    a.post_to_executor        = &thunk_post_to_executor;

    a.subscribe_conn_state    = &thunk_subscribe_conn_state;
    a.unsubscribe_conn_state  = &thunk_unsubscribe_conn_state;
    a.for_each_connection     = &thunk_for_each_connection;
    a.notify_backpressure     = &thunk_notify_backpressure;

    a.limits                = &thunk_limits;

    a.log.api_size          = sizeof(gn_log_api_t);
    a.log.should_log        = &thunk_log_should_log;
    a.log.emit              = &thunk_log_emit;

    a.config_get_string     = &thunk_config_get_string;
    a.config_get_int64      = &thunk_config_get_int64;
    a.config_get_bool       = &thunk_config_get_bool;
    a.config_get_double     = &thunk_config_get_double;
    a.config_get_array_size = &thunk_config_get_array_size;
    a.config_get_array_string = &thunk_config_get_array_string;
    a.config_get_array_int64 = &thunk_config_get_array_int64;

    a.notify_connect        = &thunk_notify_connect;
    a.notify_inbound_bytes  = &thunk_notify_inbound_bytes;
    a.notify_disconnect     = &thunk_notify_disconnect;

    a.register_security     = &thunk_register_security;
    a.unregister_security   = &thunk_unregister_security;

    a.find_conn_by_pk       = &thunk_find_conn_by_pk;
    a.get_endpoint          = &thunk_get_endpoint;

    a.inject_external_message = &thunk_inject_external_message;
    a.inject_frame            = &thunk_inject_frame;
    a.kick_handshake          = &thunk_kick_handshake;

    a.is_shutdown_requested   = &thunk_is_shutdown_requested;

    a.subscribe_config_reload   = &thunk_subscribe_config_reload;
    a.unsubscribe_config_reload = &thunk_unsubscribe_config_reload;

    a.emit_counter            = &thunk_emit_counter;
    a.iterate_counters        = &thunk_iterate_counters;

    /// Other slots remain NULL; plugins guard with GN_API_HAS.
    return a;
}

} // namespace gn::core
