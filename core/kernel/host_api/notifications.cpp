/// @file   core/kernel/host_api/notifications.cpp
/// @brief  Connection lifecycle notifications + bridge inject —
///         notify_connect, kick_handshake, notify_inbound_bytes,
///         notify_disconnect, inject. The heavy paths in the
///         kernel host_api surface.

#include "../host_api_internal.hpp"

#include <cstring>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <core/identity/node_identity.hpp>
#include <core/identity/rotation.hpp>
#include <core/registry/protocol_layer.hpp>
#include <core/util/log.hpp>
#include <sdk/cpp/uri.hpp>
#include <sdk/endpoint.h>
#include <sdk/identity.h>

#include "../connection_context.hpp"
#include "../safe_invoke.hpp"
#include "../system_handler_ids.hpp"

namespace gn::core::host_api_thunks {

using namespace host_api_internal;

gn_result_t notify_connect(void* host_ctx,
                            const uint8_t remote_pk[GN_PUBLIC_KEY_BYTES],
                            const char* uri,
                            gn_trust_class_t trust,
                            gn_handshake_role_t role,
                            gn_conn_id_t* out_conn) {
    if (!host_ctx || !remote_pk || !uri || !out_conn) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;
    if (!link_role(pc)) return GN_ERR_NOT_IMPLEMENTED;

    if (::strnlen(uri, GN_ENDPOINT_URI_MAX) >= GN_ENDPOINT_URI_MAX) {
        return GN_ERR_INVALID_ENVELOPE;
    }
    if (gn::uri_has_control_bytes(uri)) return GN_ERR_INVALID_ENVELOPE;

    const std::string_view uri_view(uri);
    const auto sep = uri_view.find("://");
    if (sep == std::string_view::npos || sep == 0) {
        return GN_ERR_INVALID_ENVELOPE;
    }
    const std::string_view scheme_view = uri_view.substr(0, sep);
    if (!gn::is_valid_scheme(scheme_view)) {
        return GN_ERR_INVALID_ENVELOPE;
    }
    const std::string scheme(scheme_view);

    if (pc->plugin_anchor) {
        if (const auto link = pc->kernel->links().find_by_scheme(scheme);
            link && link->lifetime_anchor &&
            link->lifetime_anchor != pc->plugin_anchor) {
            return GN_ERR_NOT_FOUND;
        }
    }

    std::string declared_protocol_id;
    if (const auto link = pc->kernel->links().find_by_scheme(scheme);
        link.has_value() && !link->protocol_id.empty()) {
        declared_protocol_id = link->protocol_id;
    } else {
        declared_protocol_id = std::string{::gn::core::kDefaultProtocolId};
    }

    if (auto layer = pc->kernel->protocol_layers().find_by_protocol_id(
            declared_protocol_id);
        layer != nullptr) {
        const std::uint32_t mask = layer->allowed_trust_mask();
        const std::uint32_t bit  = 1u << static_cast<unsigned>(trust);
        if ((mask & bit) == 0u) {
            pc->kernel->metrics().increment("drop.trust_class_mismatch");
            return GN_ERR_INVALID_ENVELOPE;
        }
    }

    ConnectionRecord rec;
    const gn_conn_id_t new_id = pc->kernel->connections().alloc_id();
    rec.id = new_id;
    rec.uri = uri;
    rec.scheme = scheme;
    rec.trust = trust;
    rec.role  = role;
    rec.protocol_id = std::move(declared_protocol_id);
    std::memcpy(rec.remote_pk.data(), remote_pk, GN_PUBLIC_KEY_BYTES);

    const gn_result_t rc =
        pc->kernel->connections().insert_with_index(std::move(rec));
    if (rc != GN_OK) return rc;

    pc->kernel->send_queues().create(new_id);

    *out_conn = new_id;

    {
        ConnEvent ev{};
        ev.kind  = GN_CONN_EVENT_CONNECTED;
        ev.conn  = new_id;
        ev.trust = trust;
        std::memcpy(ev.remote_pk.data(), remote_pk, GN_PUBLIC_KEY_BYTES);
        pc->kernel->on_conn_event().fire(ev);
    }

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
        const auto& limits   = pc->kernel->limits();
        const auto recv_cap  = limits.max_frame_bytes != 0
            ? PerConnQueue::kDefaultDrainBatch
                * static_cast<std::size_t>(limits.max_frame_bytes)
                + ::gn::core::kFramePrefixBytes
            : 0;
        (void)pc->kernel->sessions().create(
            new_id,
            entry,
            trust,
            role,
            device.secret_key_view(),
            std::span<const std::uint8_t, GN_PUBLIC_KEY_BYTES>(device.public_key()),
            rs_span,
            session_rc,
            recv_cap);
        if (session_rc != GN_OK) {
            if (session_rc == GN_ERR_INVALID_ENVELOPE) {
                pc->kernel->metrics().increment("drop.trust_class_mismatch");
            }
            (void)pc->kernel->connections().erase_with_index(new_id);
            pc->kernel->send_queues().erase(new_id);
            return session_rc;
        }
    }

    return GN_OK;
}

gn_result_t kick_handshake(void* host_ctx, gn_conn_id_t conn) {
    if (!host_ctx) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;
    if (!link_role(pc)) return GN_ERR_NOT_IMPLEMENTED;

    auto session = pc->kernel->sessions().find(conn);
    if (!session) return GN_OK;
    if (session->phase() != SecurityPhase::Handshake) return GN_OK;

    auto rec = pc->kernel->connections().find_by_id(conn);
    if (!rec) return GN_ERR_NOT_FOUND;
    if (!conn_owned_by_caller(pc, *rec)) return GN_ERR_NOT_FOUND;

    std::vector<std::uint8_t> first;
    const gn_result_t adv_rc = session->advance_handshake({}, first);
    if (adv_rc != GN_OK) return adv_rc;

    if (!first.empty()) {
        (void)send_raw_via_link(pc, conn, rec->scheme, first);
    }

    if (session->phase() == SecurityPhase::Transport) {
        if (const gn_result_t prc =
                propagate_peer_pk_after_handshake(pc, conn, *session);
            prc != GN_OK) {
            kernel_initiated_disconnect(pc, conn);
            return prc;
        }
        pc->kernel->attestation_dispatcher().send_self(*pc->kernel,
                                                        conn, *session);
        drain_handshake_pending(pc, conn, *session, rec->scheme);
    }
    return GN_OK;
}

gn_result_t notify_inbound_bytes(void* host_ctx,
                                  gn_conn_id_t conn,
                                  const uint8_t* bytes,
                                  size_t size) {
    if (!host_ctx || (!bytes && size > 0)) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;
    if (!link_role(pc)) return GN_ERR_NOT_IMPLEMENTED;

    const auto& limits = pc->kernel->limits();
    if (limits.max_frame_bytes != 0 && size > limits.max_frame_bytes) {
        pc->kernel->metrics().increment_drop_reason(GN_DROP_FRAME_TOO_LARGE);
        ::gn::log::warn(
            "host_api.notify_inbound_bytes: frame above cap — "
            "conn={} observed={} configured_max={}",
            static_cast<std::uint64_t>(conn),
            size,
            limits.max_frame_bytes);
        return GN_ERR_PAYLOAD_TOO_LARGE;
    }

    auto rec = pc->kernel->connections().find_by_id(conn);
    if (!rec) return GN_ERR_NOT_FOUND;
    if (!conn_owned_by_caller(pc, *rec)) return GN_ERR_NOT_FOUND;

    pc->kernel->connections().add_inbound(conn, size, 1);

    auto session = pc->kernel->sessions().find(conn);
    std::span<const std::uint8_t> wire_bytes{bytes, size};

    std::vector<std::vector<std::uint8_t>> plaintexts;

    if (session != nullptr) {
        if (session->phase() == SecurityPhase::Handshake) {
            std::vector<std::uint8_t> reply;
            const gn_result_t rc = session->advance_handshake(wire_bytes, reply);
            if (rc != GN_OK) return rc;
            if (!reply.empty()) {
                (void)send_raw_via_link(pc, conn, rec->scheme, reply);
            }
            if (session->phase() == SecurityPhase::Transport) {
                if (const gn_result_t prc =
                        propagate_peer_pk_after_handshake(pc, conn, *session);
                    prc != GN_OK) {
                    kernel_initiated_disconnect(pc, conn);
                    return prc;
                }
                pc->kernel->attestation_dispatcher().send_self(
                    *pc->kernel, conn, *session);
                drain_handshake_pending(pc, conn, *session,
                                         rec->scheme);
            }
            return GN_OK;
        }
        if (session->phase() == SecurityPhase::Transport) {
            const gn_result_t rc = session->decrypt_transport_stream(
                wire_bytes, plaintexts);
            if (rc != GN_OK) return rc;
            if (plaintexts.empty()) return GN_OK;
        }
    } else {
        plaintexts.emplace_back(wire_bytes.begin(), wire_bytes.end());
    }

    gn_connection_context_t ctx{};
    ctx.conn_id   = conn;
    ctx.trust     = rec->trust;
    ctx.remote_pk    = rec->remote_pk;
    ctx.allows_relay = rec->allows_relay;
    if (auto local = pc->kernel->identities().any(); local) {
        ctx.local_pk = *local;
    }

    auto layer = pc->kernel->protocol_layers().find_by_protocol_id(
        rec->protocol_id);
    if (layer == nullptr) return GN_ERR_NOT_IMPLEMENTED;

    for (const auto& pt : plaintexts) {
        auto deframed = layer->deframe(
            ctx, std::span<const std::uint8_t>(pt));
        if (!deframed.has_value()) {
            const auto err = deframed.error().code;
            const char* drop_metric =
                (err == GN_ERR_FRAME_TOO_LARGE) ? "drop.frame_too_large"
              : (err == GN_ERR_DEFRAME_CORRUPT) ? "drop.deframe_corrupt"
                                                 : nullptr;
            if (drop_metric != nullptr) {
                pc->kernel->metrics().increment(drop_metric);
            }
            return err;
        }

        for (const auto& env : deframed->messages) {
            gn_message_t stamped = env;
            stamped.api_size     = sizeof(gn_message_t);
            stamped.conn_id      = conn;

            if (stamped.msg_id == kAttestationMsgId) {
                std::shared_ptr<SecuritySession> session_for_inbound =
                    pc->kernel->sessions().find(conn);
                if (session_for_inbound != nullptr) {
                    std::span<const std::uint8_t> payload_span{
                        stamped.payload, stamped.payload_size};
                    (void)pc->kernel->attestation_dispatcher().on_inbound(
                        *pc->kernel, conn, *session_for_inbound,
                        payload_span);
                }
                continue;
            }
            if (stamped.msg_id == kIdentityRotationMsgId) {
                auto pin = pc->kernel->connections().get_pinned_peer(
                    rec->remote_pk);
                if (!pin) continue;
                auto verified = identity::verify_rotation(
                    std::span<const std::uint8_t>(
                        stamped.payload, stamped.payload_size),
                    pin->user_pk);
                if (!verified) {
                    pc->kernel->metrics().increment(
                        "drop.rotation_bad_proof");
                    continue;
                }
                if (pc->kernel->connections().apply_rotation(
                        rec->remote_pk, verified->new_user_pk,
                        verified->counter) != GN_OK) {
                    pc->kernel->metrics().increment(
                        "drop.rotation_replay");
                    continue;
                }
                ConnEvent ev{};
                ev.kind      = GN_CONN_EVENT_IDENTITY_ROTATED;
                ev.conn      = conn;
                ev.trust     = rec->trust;
                ev.remote_pk = rec->remote_pk;
                ev._reserved[0] =
                    const_cast<void*>(static_cast<const void*>(
                        verified->prev_user_pk.data()));
                ev._reserved[1] =
                    const_cast<void*>(static_cast<const void*>(
                        verified->new_user_pk.data()));
                ev._reserved[2] =
                    const_cast<void*>(static_cast<const void*>(
                        &verified->counter));
                pc->kernel->on_conn_event().fire(ev);
                continue;
            }
            if (stamped.msg_id == kCapabilityBlobMsgId) {
                pc->kernel->capability_blob_bus().on_inbound(
                    conn, stamped.payload, stamped.payload_size);
                continue;
            }
            route_one_envelope(*pc->kernel, layer->protocol_id(), stamped);
        }
    }
    return GN_OK;
}

gn_result_t inject(void* host_ctx,
                    gn_inject_layer_t layer_kind,
                    gn_conn_id_t source,
                    std::uint32_t msg_id,
                    const std::uint8_t* bytes,
                    std::size_t size) {
    if (!host_ctx) return GN_ERR_NULL_ARG;

    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;

    auto rec = pc->kernel->connections().find_by_id(source);
    if (!rec) return GN_ERR_NOT_FOUND;

    auto layer = pc->kernel->protocol_layers().find_by_protocol_id(
        rec->protocol_id);
    if (layer == nullptr) return GN_ERR_NOT_IMPLEMENTED;

    const auto& limits = pc->kernel->limits();

    switch (layer_kind) {
    case GN_INJECT_LAYER_MESSAGE:
        if (!bytes && size > 0) return GN_ERR_NULL_ARG;
        if (msg_id == 0)        return GN_ERR_INVALID_ENVELOPE;
        if (is_reserved_system_msg_id(msg_id))
            return GN_ERR_INVALID_ENVELOPE;
        if (is_identity_range_msg_id(msg_id))
            return GN_ERR_INVALID_ENVELOPE;
        if (limits.max_payload_bytes != 0 &&
            size > limits.max_payload_bytes) {
            pc->kernel->metrics().increment_drop_reason(
                GN_DROP_PAYLOAD_TOO_LARGE);
            ::gn::log::warn(
                "host_api.inject(MESSAGE): payload above cap — "
                "source={} observed={} configured_max={}",
                static_cast<std::uint64_t>(source),
                size,
                limits.max_payload_bytes);
            return GN_ERR_PAYLOAD_TOO_LARGE;
        }
        break;

    case GN_INJECT_LAYER_FRAME:
        if (!bytes || size == 0) return GN_ERR_NULL_ARG;
        if (limits.max_frame_bytes != 0 &&
            size > limits.max_frame_bytes) {
            pc->kernel->metrics().increment_drop_reason(
                GN_DROP_FRAME_TOO_LARGE);
            ::gn::log::warn(
                "host_api.inject(FRAME): frame above cap — "
                "source={} observed={} configured_max={}",
                static_cast<std::uint64_t>(source),
                size,
                limits.max_frame_bytes);
            return GN_ERR_PAYLOAD_TOO_LARGE;
        }
        break;

    default:
        return GN_ERR_INVALID_ENVELOPE;
    }

    if (!pc->kernel->inject_rate_limiter().allow(
            inject_rate_key(rec->remote_pk))) {
        pc->kernel->metrics().increment_drop_reason(GN_DROP_RATE_LIMITED);
        ::gn::log::warn(
            "host_api.inject: rate-limited — source={} "
            "remote_pk_prefix={:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            static_cast<std::uint64_t>(source),
            rec->remote_pk[0], rec->remote_pk[1],
            rec->remote_pk[2], rec->remote_pk[3],
            rec->remote_pk[4], rec->remote_pk[5],
            rec->remote_pk[6], rec->remote_pk[7]);
        return GN_ERR_LIMIT_REACHED;
    }

    if (layer_kind == GN_INJECT_LAYER_MESSAGE) {
        const PublicKey local_pk =
            pc->kernel->identities().any().value_or(PublicKey{});
        gn_message_t env = build_envelope(
            rec->remote_pk, local_pk, msg_id, bytes, size);

        env.api_size = sizeof(gn_message_t);
        env.conn_id  = source;

        route_one_envelope(*pc->kernel, layer->protocol_id(), env);
        return GN_OK;
    }

    gn_connection_context_t ctx{};
    ctx.conn_id   = source;
    ctx.trust     = rec->trust;
    ctx.remote_pk    = rec->remote_pk;
    ctx.allows_relay = rec->allows_relay;
    if (auto local = pc->kernel->identities().any(); local) {
        ctx.local_pk = *local;
    }

    auto deframed = layer->deframe(
        ctx, std::span<const std::uint8_t>{bytes, size});
    if (!deframed.has_value()) return deframed.error().code;

    if (deframed->messages.empty() || deframed->bytes_consumed == 0) {
        return GN_ERR_DEFRAME_INCOMPLETE;
    }

    for (const auto& env : deframed->messages) {
        if (is_reserved_system_msg_id(env.msg_id)) {
            continue;
        }
        gn_message_t stamped  = env;
        stamped.api_size      = sizeof(gn_message_t);
        stamped.conn_id       = source;
        route_one_envelope(*pc->kernel, layer->protocol_id(), stamped);
    }
    return GN_OK;
}

gn_result_t notify_disconnect(void* host_ctx,
                               gn_conn_id_t conn,
                               gn_result_t /*reason*/) {
    if (!host_ctx) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;
    if (!link_role(pc)) return GN_ERR_NOT_IMPLEMENTED;

    if (auto rec = pc->kernel->connections().find_by_id(conn);
        rec && !conn_owned_by_caller(pc, *rec)) {
        return GN_ERR_NOT_FOUND;
    }

    pc->kernel->sessions().destroy(conn);
    auto snapshot = pc->kernel->connections().snapshot_and_erase(conn);
    pc->kernel->send_queues().erase(conn);

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

}  // namespace gn::core::host_api_thunks
