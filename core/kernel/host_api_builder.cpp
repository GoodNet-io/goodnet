/// @file   core/kernel/host_api_builder.cpp
/// @brief  Implementation of `build_host_api`.

#include "host_api_builder.hpp"

#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <core/util/log.hpp>

#include "connection_context.hpp"
#include "kernel.hpp"

namespace gn::core {

namespace {

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
    return pc->kind == GN_PLUGIN_KIND_TRANSPORT ||
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
/// callback return is consumed; here we consume by logging. Reject
/// is a handler-policy signal — kernel does not auto-disconnect on
/// it (that decision belongs to a future policy layer), but the
/// operator now sees it.
void route_one_envelope(Kernel& kernel,
                        std::string_view protocol_id,
                        const gn_message_t& env) {
    const auto outcome = kernel.router().route_inbound(protocol_id, env);
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

    auto rec = pc->kernel->connections().find_by_id(conn);
    if (!rec) return GN_ERR_UNKNOWN_RECEIVER;

    auto trans = pc->kernel->transports().find_by_scheme(rec->transport_scheme);
    if (!trans || !trans->vtable || !trans->vtable->send) {
        return GN_ERR_NOT_IMPLEMENTED;
    }

    auto* layer = pc->kernel->protocol_layer();
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
    /// During the handshake phase application data is rejected; the
    /// no-session path (loopback / null-security per security-trust.md
    /// §4) sends the framed bytes verbatim.
    auto session = pc->kernel->sessions().find(conn);
    if (session != nullptr) {
        if (session->phase() == SecurityPhase::Handshake) {
            return GN_ERR_INVALID_ENVELOPE;
        }
        if (session->phase() == SecurityPhase::Transport) {
            std::vector<std::uint8_t> cipher;
            const gn_result_t rc = session->encrypt_transport(*framed, cipher);
            if (rc != GN_OK) return rc;
            return trans->vtable->send(trans->self, conn,
                                        cipher.data(), cipher.size());
        }
    }

    return trans->vtable->send(trans->self, conn,
                               framed->data(), framed->size());
}

gn_result_t thunk_find_conn_by_pk(void* host_ctx,
                                   const std::uint8_t pk[GN_PUBLIC_KEY_BYTES],
                                   gn_conn_id_t* out_conn) {
    if (!host_ctx || !pk || !out_conn) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);

    PublicKey key{};
    std::memcpy(key.data(), pk, GN_PUBLIC_KEY_BYTES);
    auto rec = pc->kernel->connections().find_by_pk(key);
    if (!rec) return GN_ERR_UNKNOWN_RECEIVER;
    *out_conn = rec->id;
    return GN_OK;
}

gn_result_t thunk_get_endpoint(void* host_ctx, gn_conn_id_t conn,
                                gn_endpoint_t* out) {
    if (!host_ctx || !out) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);

    auto rec = pc->kernel->connections().find_by_id(conn);
    if (!rec) return GN_ERR_UNKNOWN_RECEIVER;

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
    return pc->kernel->security().register_provider(
        provider_id, vtable, security_self, pc->plugin_anchor);
}

gn_result_t thunk_unregister_security(void* host_ctx, const char* provider_id) {
    if (!host_ctx || !provider_id) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    return pc->kernel->security().unregister_provider(provider_id);
}

gn_result_t thunk_disconnect(void* host_ctx, gn_conn_id_t conn) {
    if (!host_ctx) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    auto rec = pc->kernel->connections().find_by_id(conn);
    if (!rec) return GN_ERR_UNKNOWN_RECEIVER;
    auto trans = pc->kernel->transports().find_by_scheme(rec->transport_scheme);
    if (!trans || !trans->vtable || !trans->vtable->disconnect) {
        return GN_ERR_NOT_IMPLEMENTED;
    }
    return trans->vtable->disconnect(trans->self, conn);
}

gn_result_t thunk_query_extension_checked(void* host_ctx,
                                          const char* name,
                                          uint32_t version,
                                          const void** out_vtable) {
    if (!host_ctx) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    return pc->kernel->extensions().query_extension_checked(
        name, version, out_vtable);
}

gn_result_t thunk_register_extension(void* host_ctx,
                                     const char* name,
                                     uint32_t version,
                                     const void* vtable) {
    if (!host_ctx) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    return pc->kernel->extensions().register_extension(
        name, version, vtable, pc->plugin_anchor);
}

gn_result_t thunk_register_transport(void* host_ctx,
                                     const char* scheme,
                                     const gn_transport_vtable_t* vtable,
                                     void* transport_self,
                                     gn_transport_id_t* out_id) {
    if (!host_ctx) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    return pc->kernel->transports().register_transport(
        scheme, vtable, transport_self, out_id, pc->plugin_anchor);
}

gn_result_t thunk_unregister_transport(void* host_ctx, gn_transport_id_t id) {
    if (!host_ctx) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    return pc->kernel->transports().unregister_transport(id);
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
    return pc->kernel->handlers().register_handler(
        protocol_id, msg_id, priority, vtable, handler_self, out_id,
        pc->plugin_anchor);
}

gn_result_t thunk_unregister_handler(void* host_ctx, gn_handler_id_t id) {
    if (!host_ctx) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    return pc->kernel->handlers().unregister_handler(id);
}

const gn_limits_t* thunk_limits(void* host_ctx) {
    if (!host_ctx) return nullptr;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    return &pc->kernel->limits();
}

gn_result_t thunk_config_get_string(void* host_ctx,
                                    const char* key,
                                    char** out_str,
                                    void (**out_free)(char*)) {
    if (!host_ctx || !key || !out_str || !out_free) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);

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
    std::int64_t v = 0;
    const auto rc = pc->kernel->config().get_int64(key, v);
    if (rc != GN_OK) return rc;
    *out_value = v;
    return GN_OK;
}

void thunk_log(void* host_ctx, gn_log_level_t level, const char* fmt, ...) {
    if (!host_ctx || !fmt) return;
    auto* pc = static_cast<PluginContext*>(host_ctx);

    /// Map the C ABI level to spdlog's enum.
    auto sp_lvl = ::spdlog::level::info;
    switch (level) {
        case GN_LOG_TRACE: sp_lvl = ::spdlog::level::trace;    break;
        case GN_LOG_DEBUG: sp_lvl = ::spdlog::level::debug;    break;
        case GN_LOG_INFO:  sp_lvl = ::spdlog::level::info;     break;
        case GN_LOG_WARN:  sp_lvl = ::spdlog::level::warn;     break;
        case GN_LOG_ERROR: sp_lvl = ::spdlog::level::err;      break;
        case GN_LOG_FATAL: sp_lvl = ::spdlog::level::critical; break;
    }
    if (!::gn::log::kernel().should_log(sp_lvl)) return;

    /// Render varargs into a stack buffer; truncate beyond 4 KiB so the
    /// hot path stays allocation-free.
    char buf[4096];
    va_list ap;
    va_start(ap, fmt);
    (void)std::vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    ::gn::log::kernel().log(sp_lvl, "[{}] {}", pc->plugin_name, buf);
}

/// Send handshake-phase bytes raw via the transport vtable, bypassing
/// the security and protocol layers. The bytes are produced by the
/// security provider and already carry their own AEAD framing.
gn_result_t send_raw_via_transport(PluginContext* pc,
                                    gn_conn_id_t conn,
                                    std::string_view scheme,
                                    std::span<const std::uint8_t> bytes) {
    if (bytes.empty()) return GN_OK;
    auto trans = pc->kernel->transports().find_by_scheme(scheme);
    if (!trans || !trans->vtable || !trans->vtable->send) {
        return GN_ERR_NOT_IMPLEMENTED;
    }
    return trans->vtable->send(trans->self, conn, bytes.data(), bytes.size());
}

/// True iff @p pk has at least one non-zero byte; the kernel uses
/// all-zero as the "unknown peer" sentinel on inbound connections.
bool pk_is_known(const std::uint8_t pk[GN_PUBLIC_KEY_BYTES]) noexcept {
    for (std::size_t i = 0; i < GN_PUBLIC_KEY_BYTES; ++i) {
        if (pk[i] != 0) return true;
    }
    return false;
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
    if (!transport_role(pc)) return GN_ERR_NOT_IMPLEMENTED;

    /// Protocol-layer trust gate per `security-trust.md` §4: the
    /// active layer declares which trust classes it may deframe;
    /// reject the connection up front if the declared `trust` is
    /// not in the layer's mask. The security-provider gate fires
    /// later inside `Sessions::create` against the security mask.
    if (auto* layer = pc->kernel->protocol_layer(); layer != nullptr) {
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

    /// Spin up a security session if a provider is registered and the
    /// kernel carries a NodeIdentity. Trust classes that bypass
    /// encryption (Loopback / IntraNode with explicit opt-in per
    /// security-trust.md §4) take the no-session path and fall through
    /// to the bare protocol layer.
    auto& sec = pc->kernel->security();
    const auto* ident = pc->kernel->node_identity();
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
            entry.vtable,
            entry.self,
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
    if (!transport_role(pc)) return GN_ERR_NOT_IMPLEMENTED;

    auto session = pc->kernel->sessions().find(conn);
    if (!session) return GN_OK;  /// no security on this conn
    if (session->phase() != SecurityPhase::Handshake) return GN_OK;

    auto rec = pc->kernel->connections().find_by_id(conn);
    if (!rec) return GN_ERR_UNKNOWN_RECEIVER;

    std::vector<std::uint8_t> first;
    const gn_result_t adv_rc = session->advance_handshake({}, first);
    if (adv_rc != GN_OK) return adv_rc;

    if (!first.empty()) {
        (void)send_raw_via_transport(pc, conn, rec->transport_scheme, first);
    }

    /// IK-style patterns can complete the handshake on the initiator's
    /// first message. If `advance_handshake` already moved the session
    /// to Transport, gate-promote `Untrusted → Peer` per
    /// `security-trust.md` §3. Loopback / Peer connections take the
    /// helper's no-op path; `LIMIT_REACHED` from the gate is the
    /// "policy says no" return and is not propagated — the connection
    /// is still functional, just at its declared trust class.
    if (session->phase() == SecurityPhase::Transport) {
        (void)pc->kernel->connections().upgrade_trust(conn, GN_TRUST_PEER);
    }
    return GN_OK;
}

gn_result_t thunk_notify_inbound_bytes(void* host_ctx,
                                       gn_conn_id_t conn,
                                       const uint8_t* bytes,
                                       size_t size) {
    if (!host_ctx || (!bytes && size > 0)) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!transport_role(pc)) return GN_ERR_NOT_IMPLEMENTED;

    /// Look up the connection record to populate the per-call context.
    auto rec = pc->kernel->connections().find_by_id(conn);
    if (!rec) return GN_ERR_UNKNOWN_RECEIVER;

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
            /// Transport on this byte run. Gate-promote `Untrusted →
            /// Peer` per `security-trust.md` §3; the helper rejects
            /// any other transition with `LIMIT_REACHED`, which we
            /// silently absorb — the connection continues at its
            /// declared trust class.
            if (session->phase() == SecurityPhase::Transport) {
                (void)pc->kernel->connections().upgrade_trust(
                    conn, GN_TRUST_PEER);
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

    auto* layer = pc->kernel->protocol_layer();
    if (layer == nullptr) return GN_ERR_NOT_IMPLEMENTED;

    auto deframed = layer->deframe(ctx, wire_bytes);
    if (!deframed.has_value()) return deframed.error().code;

    for (const auto& env : deframed->messages) {
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

    auto rec = pc->kernel->connections().find_by_id(source);
    if (!rec) return GN_ERR_UNKNOWN_RECEIVER;

    const auto& limits = pc->kernel->limits();
    if (limits.max_payload_bytes != 0 &&
        payload_size > limits.max_payload_bytes) {
        return GN_ERR_PAYLOAD_TOO_LARGE;
    }

    if (!pc->kernel->inject_rate_limiter().allow(
            static_cast<std::uint64_t>(source))) {
        return GN_ERR_LIMIT_REACHED;
    }

    auto* layer = pc->kernel->protocol_layer();
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

    auto rec = pc->kernel->connections().find_by_id(source);
    if (!rec) return GN_ERR_UNKNOWN_RECEIVER;

    const auto& limits = pc->kernel->limits();
    if (limits.max_frame_bytes != 0 &&
        frame_size > limits.max_frame_bytes) {
        return GN_ERR_PAYLOAD_TOO_LARGE;
    }

    if (!pc->kernel->inject_rate_limiter().allow(
            static_cast<std::uint64_t>(source))) {
        return GN_ERR_LIMIT_REACHED;
    }

    auto* layer = pc->kernel->protocol_layer();
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
    if (!transport_role(pc)) return GN_ERR_NOT_IMPLEMENTED;
    pc->kernel->sessions().destroy(conn);
    return pc->kernel->connections().erase_with_index(conn);
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

    a.register_transport    = &thunk_register_transport;
    a.unregister_transport  = &thunk_unregister_transport;

    a.query_extension_checked = &thunk_query_extension_checked;
    a.register_extension      = &thunk_register_extension;

    a.limits                = &thunk_limits;
    a.log                   = &thunk_log;

    a.config_get_string     = &thunk_config_get_string;
    a.config_get_int64      = &thunk_config_get_int64;

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

    /// Other slots remain NULL; plugins guard with GN_API_HAS.
    return a;
}

} // namespace gn::core
