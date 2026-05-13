/// @file   core/kernel/host_api/messaging.cpp
/// @brief  Messaging slots — `send`, `send_to`, `disconnect`.

#include "../host_api_internal.hpp"

#include <cstring>

#include <core/registry/protocol_layer.hpp>
#include <sdk/extensions/strategy.h>

#include "../connection_context.hpp"
#include "../safe_invoke.hpp"

namespace gn::core::host_api_thunks {

using namespace host_api_internal;

gn_result_t send(void* host_ctx,
                  gn_conn_id_t conn,
                  uint32_t msg_id,
                  const uint8_t* payload,
                  size_t payload_size) {
    if (!host_ctx) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;

    auto rec = pc->kernel->connections().find_by_id(conn);
    if (!rec) return GN_ERR_NOT_FOUND;

    auto trans = pc->kernel->links().find_by_scheme(rec->scheme);
    if (!trans || !trans->vtable || !trans->vtable->send) {
        return GN_ERR_NOT_IMPLEMENTED;
    }

    auto layer = pc->kernel->protocol_layers().find_by_protocol_id(
        rec->protocol_id);
    if (!layer) return GN_ERR_NOT_IMPLEMENTED;

    const PublicKey local_pk =
        pc->kernel->identities().any().value_or(PublicKey{});
    gn_message_t env = build_envelope(
        local_pk, rec->remote_pk, msg_id, payload, payload_size);

    gn_connection_context_t ctx{};
    ctx.conn_id   = conn;
    ctx.trust     = rec->trust;
    ctx.remote_pk    = rec->remote_pk;
    ctx.allows_relay = rec->allows_relay;
    if (auto local = pc->kernel->identities().any(); local) {
        ctx.local_pk = *local;
    }

    auto framed = layer->frame(ctx, env);
    if (!framed) return framed.error().code;

    /// Handshake-phase frames buffer on the session's own pending
    /// queue, not the kernel send queue, because their order is tied
    /// to the AEAD nonce sequence the session will commit only on
    /// the upgrade to Transport.
    auto session = pc->kernel->sessions().find(conn);
    if (session != nullptr && session->phase() == SecurityPhase::Handshake) {
        const auto cap = pc->kernel->limits().pending_handshake_bytes;
        return session->enqueue_pending(std::move(*framed),
                                         static_cast<std::uint64_t>(cap));
    }

    auto queue = pc->kernel->send_queues().find(conn);
    if (queue == nullptr) {
        /// No queue — test scaffolding that bypassed `notify_connect`.
        std::vector<std::uint8_t> wire;
        if (session != nullptr && session->phase() == SecurityPhase::Transport) {
            const gn_result_t rc = session->encrypt_transport(*framed, wire);
            if (rc != GN_OK) return rc;
        } else {
            wire = std::move(*framed);
        }
        const auto send_rc = safe_call_result("link.send",
            trans->vtable->send, trans->self, conn,
            wire.data(), wire.size());
        if (send_rc == GN_OK) {
            pc->kernel->connections().add_outbound(
                conn, wire.size(), 1);
        }
        return send_rc;
    }

    if (session != nullptr && session->fast_crypto_active()) {
        if (!queue->try_push_plain(std::move(*framed), SendPriority::Low)) {
            bool kicked = false;
            if (queue->drain_scheduled.compare_exchange_strong(
                    kicked, true, std::memory_order_acq_rel)) {
                drain_send_queue(pc, *trans, conn, *queue, session);
            }
            return GN_ERR_LIMIT_REACHED;
        }
    } else {
        std::vector<std::uint8_t> wire;
        if (session != nullptr && session->phase() == SecurityPhase::Transport) {
            const gn_result_t rc = session->encrypt_transport(*framed, wire);
            if (rc != GN_OK) return rc;
        } else {
            wire = std::move(*framed);
        }
        if (!queue->try_push(std::move(wire), SendPriority::Low)) {
            bool kicked = false;
            if (queue->drain_scheduled.compare_exchange_strong(
                    kicked, true, std::memory_order_acq_rel)) {
                drain_send_queue(pc, *trans, conn, *queue, session);
            }
            return GN_ERR_LIMIT_REACHED;
        }
    }

    bool expected = false;
    if (queue->drain_scheduled.compare_exchange_strong(
            expected, true, std::memory_order_acq_rel)) {
        drain_send_queue(pc, *trans, conn, *queue, session);
    }
    return GN_OK;
}

gn_result_t send_to(void* host_ctx,
                     const uint8_t peer_pk[GN_PUBLIC_KEY_BYTES],
                     uint32_t msg_id,
                     const uint8_t* payload,
                     size_t payload_size) {
    if (!host_ctx || !peer_pk) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;

    PublicKey target;
    std::memcpy(target.data(), peer_pk, GN_PUBLIC_KEY_BYTES);

    std::vector<gn_path_sample_t> candidates;
    pc->kernel->connections().for_each(
        [&target, &candidates](
            const ConnectionRecord& rec,
            const ConnectionRegistry::CounterSnapshot& snap)
            -> bool {
            if (rec.remote_pk != target) return true;
            gn_path_sample_t s{};
            s.conn          = rec.id;
            s.rtt_us        = snap.last_rtt_us;
            s.loss_pct_x100 = 0;
            s.caps          = 0;
            candidates.push_back(s);
            return true;
        });

    if (candidates.empty()) return GN_ERR_NOT_FOUND;

    if (candidates.size() == 1) {
        return send(host_ctx, candidates[0].conn,
                     msg_id, payload, payload_size);
    }

    auto strategies =
        pc->kernel->extensions().query_prefix("gn.strategy.");
    if (strategies.empty()) {
        return send(host_ctx, candidates[0].conn,
                     msg_id, payload, payload_size);
    }
    if (strategies.size() > 1) {
        return GN_ERR_LIMIT_REACHED;
    }

    const auto& entry = strategies.front();
    const auto* api =
        static_cast<const gn_strategy_api_t*>(entry.vtable);
    if (!api || !api->pick_conn ||
        api->api_size < sizeof(gn_strategy_api_t)) {
        return GN_ERR_NOT_IMPLEMENTED;
    }

    gn_conn_id_t chosen = GN_INVALID_ID;
    const gn_result_t rc = api->pick_conn(
        api->ctx, peer_pk,
        candidates.data(), candidates.size(),
        &chosen);
    if (rc != GN_OK) return rc;
    if (chosen == GN_INVALID_ID) return GN_ERR_NOT_FOUND;

    return send(host_ctx, chosen, msg_id, payload, payload_size);
}

gn_result_t disconnect(void* host_ctx, gn_conn_id_t conn) {
    if (!host_ctx) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;
    auto rec = pc->kernel->connections().find_by_id(conn);
    if (!rec) return GN_ERR_NOT_FOUND;
    auto trans = pc->kernel->links().find_by_scheme(rec->scheme);
    if (!trans || !trans->vtable || !trans->vtable->disconnect) {
        return GN_ERR_NOT_IMPLEMENTED;
    }
    return safe_call_result("link.disconnect",
        trans->vtable->disconnect, trans->self, conn);
}

}  // namespace gn::core::host_api_thunks
