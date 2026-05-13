/// @file   core/kernel/host_api/internal.cpp
/// @brief  Cross-cutting helpers used by more than one `host_api/*.cpp`
///         translation unit. Declarations live in
///         `core/kernel/host_api_internal.hpp`.

#include "../host_api_internal.hpp"

#include <cstring>

#include <core/util/log.hpp>

#include "../connection_context.hpp"
#include "../safe_invoke.hpp"

namespace gn::core::host_api_internal {

gn_message_t build_envelope(const PublicKey&    sender_pk,
                            const PublicKey&    receiver_pk,
                            std::uint32_t       msg_id,
                            const std::uint8_t* payload,
                            std::size_t         payload_size) noexcept {
    gn_message_t env{};
    env.msg_id       = msg_id;
    env.payload      = payload;
    env.payload_size = payload_size;
    std::memcpy(env.sender_pk,   sender_pk.data(),   GN_PUBLIC_KEY_BYTES);
    std::memcpy(env.receiver_pk, receiver_pk.data(), GN_PUBLIC_KEY_BYTES);
    return env;
}

gn_result_t propagate_peer_pk_after_handshake(const PluginContext*   pc,
                                              gn_conn_id_t           conn,
                                              const SecuritySession& session) {
    if (pc == nullptr || pc->kernel == nullptr) return GN_OK;
    if (session.phase() != SecurityPhase::Transport) return GN_OK;
    const auto& keys = session.transport_keys();
    PublicKey peer_pk{};
    std::memcpy(peer_pk.data(), keys.peer_static_pk, GN_PUBLIC_KEY_BYTES);
    static const PublicKey kZeroPk{};
    if (peer_pk == kZeroPk) return GN_OK;
    const gn_result_t rc = pc->kernel->connections().update_remote_pk(conn, peer_pk);
    if (rc == GN_ERR_LIMIT_REACHED) return GN_ERR_INTEGRITY_FAILED;
    return rc;
}

void kernel_initiated_disconnect(const PluginContext* pc,
                                 gn_conn_id_t conn) {
    if (pc == nullptr || pc->kernel == nullptr) return;
    pc->kernel->sessions().destroy(conn);
    pc->kernel->attestation_dispatcher().on_disconnect(conn);
    auto snapshot = pc->kernel->connections().snapshot_and_erase(conn);
    pc->kernel->send_queues().erase(conn);
    if (snapshot) {
        ConnEvent ev{};
        ev.kind      = GN_CONN_EVENT_DISCONNECTED;
        ev.conn      = conn;
        ev.trust     = snapshot->trust;
        ev.remote_pk = snapshot->remote_pk;
        pc->kernel->on_conn_event().fire(ev);
    }
}

bool conn_owned_by_caller(const PluginContext* pc,
                          const ConnectionRecord& rec) {
    if (pc == nullptr || pc->kernel == nullptr) return false;
    if (!pc->plugin_anchor) return true;
    auto link = pc->kernel->links().find_by_scheme(rec.scheme);
    if (!link) return true;
    if (!link->lifetime_anchor) return true;
    return link->lifetime_anchor == pc->plugin_anchor;
}

namespace {

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

}  // namespace

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

gn_result_t send_link_batch(PluginContext*                                pc,
                            const LinkEntry&                              trans,
                            gn_conn_id_t                                  conn,
                            std::span<const std::vector<std::uint8_t>>    batch,
                            std::size_t&                                  out_accepted) noexcept {
    out_accepted = 0;
    if (batch.empty()) return GN_OK;

    std::vector<gn_byte_span_t> spans;
    spans.reserve(batch.size());
    std::size_t total_bytes = 0;
    for (const auto& frame : batch) {
        spans.push_back({frame.data(), frame.size()});
        total_bytes += frame.size();
    }

    gn_result_t batch_rc = GN_ERR_NOT_IMPLEMENTED;
    if (trans.vtable->send_batch != nullptr) {
        batch_rc = safe_call_result("link.send_batch",
            trans.vtable->send_batch, trans.self, conn,
            spans.data(), spans.size());
    }
    if (batch_rc == GN_ERR_NOT_IMPLEMENTED) {
        batch_rc = GN_OK;
        for (const auto& frame : batch) {
            const auto rc = safe_call_result("link.send",
                trans.vtable->send, trans.self, conn,
                frame.data(), frame.size());
            if (rc == GN_OK) {
                ++out_accepted;
                continue;
            }
            if (rc == GN_ERR_LIMIT_REACHED) {
                batch_rc = GN_ERR_LIMIT_REACHED;
                break;
            }
            ++out_accepted;
        }
        std::size_t accepted_bytes = 0;
        for (std::size_t i = 0; i < out_accepted; ++i) {
            accepted_bytes += batch[i].size();
        }
        if (out_accepted > 0) {
            pc->kernel->connections().add_outbound(
                conn, accepted_bytes, out_accepted);
        }
        return batch_rc;
    }
    if (batch_rc == GN_OK) {
        out_accepted = batch.size();
        pc->kernel->connections().add_outbound(
            conn, total_bytes, batch.size());
    }
    return batch_rc;
}

void drain_send_queue(PluginContext*                            pc,
                      const LinkEntry&                          trans,
                      gn_conn_id_t                              conn,
                      PerConnQueue&                             queue,
                      const std::shared_ptr<SecuritySession>&   session) noexcept {
    while (true) {
        if (!queue.stalled_wire_batch.empty()) {
            std::size_t accepted = 0;
            const gn_result_t rc = send_link_batch(
                pc, trans, conn, queue.stalled_wire_batch, accepted);
            if (rc == GN_OK) {
                std::size_t cleared = 0;
                for (const auto& f : queue.stalled_wire_batch) {
                    cleared += f.size();
                }
                queue.pending_bytes.fetch_sub(
                    cleared, std::memory_order_acq_rel);
                queue.stalled_wire_batch.clear();
            } else {
                if (accepted > 0 && accepted < queue.stalled_wire_batch.size()) {
                    std::size_t cleared = 0;
                    for (std::size_t i = 0; i < accepted; ++i) {
                        cleared += queue.stalled_wire_batch[i].size();
                    }
                    queue.pending_bytes.fetch_sub(
                        cleared, std::memory_order_acq_rel);
                    queue.stalled_wire_batch.erase(
                        queue.stalled_wire_batch.begin(),
                        queue.stalled_wire_batch.begin()
                            + static_cast<std::ptrdiff_t>(accepted));
                }
                queue.drain_scheduled.store(
                    false, std::memory_order_release);
                return;
            }
        }

        if (session != nullptr && session->fast_crypto_active() &&
            queue.has_plain()) {
            auto plain_batch = queue.drain_plain_batch();
            if (!plain_batch.empty()) {
                std::vector<std::vector<std::uint8_t>> wire_batch;
                const gn_result_t rc = session->encrypt_batch_transport(
                    pc->kernel->crypto_pool(), plain_batch, wire_batch);
                if (rc != GN_OK) continue;
                std::size_t accepted = 0;
                const gn_result_t link_rc = send_link_batch(
                    pc, trans, conn, wire_batch, accepted);
                if (link_rc == GN_ERR_LIMIT_REACHED) {
                    if (accepted > 0) {
                        wire_batch.erase(
                            wire_batch.begin(),
                            wire_batch.begin()
                                + static_cast<std::ptrdiff_t>(accepted));
                    }
                    std::size_t parked = 0;
                    for (const auto& f : wire_batch) {
                        parked += f.size();
                    }
                    queue.pending_bytes.fetch_add(
                        parked, std::memory_order_acq_rel);
                    queue.stalled_wire_batch = std::move(wire_batch);
                    queue.drain_scheduled.store(
                        false, std::memory_order_release);
                    return;
                }
                continue;
            }
        }

        auto cipher_batch = queue.drain_batch();
        if (!cipher_batch.empty()) {
            std::size_t accepted = 0;
            const gn_result_t rc = send_link_batch(
                pc, trans, conn, cipher_batch, accepted);
            if (rc == GN_ERR_LIMIT_REACHED) {
                if (accepted > 0) {
                    cipher_batch.erase(
                        cipher_batch.begin(),
                        cipher_batch.begin()
                            + static_cast<std::ptrdiff_t>(accepted));
                }
                std::size_t parked = 0;
                for (const auto& f : cipher_batch) {
                    parked += f.size();
                }
                queue.pending_bytes.fetch_add(
                    parked, std::memory_order_acq_rel);
                queue.stalled_wire_batch = std::move(cipher_batch);
                queue.drain_scheduled.store(
                    false, std::memory_order_release);
                return;
            }
            continue;
        }

        queue.drain_scheduled.store(false, std::memory_order_release);
        if (!queue.has_frames() && !queue.has_plain() &&
            queue.stalled_wire_batch.empty()) {
            return;
        }
        bool exp = false;
        if (!queue.drain_scheduled.compare_exchange_strong(
                exp, true, std::memory_order_acq_rel)) {
            return;
        }
    }
}

gn_result_t send_raw_via_link(PluginContext* pc,
                              gn_conn_id_t conn,
                              std::string_view scheme,
                              std::span<const std::uint8_t> bytes) {
    if (bytes.empty()) return GN_OK;
    auto trans = pc->kernel->links().find_by_scheme(scheme);
    if (!trans || !trans->vtable || !trans->vtable->send) {
        return GN_ERR_NOT_IMPLEMENTED;
    }
    return safe_call_result("link.send",
        trans->vtable->send, trans->self, conn,
        bytes.data(), bytes.size());
}

void publish_kernel_disconnect(PluginContext* pc, gn_conn_id_t conn) {
    pc->kernel->sessions().destroy(conn);
    auto snapshot = pc->kernel->connections().snapshot_and_erase(conn);
    pc->kernel->send_queues().erase(conn);
    pc->kernel->attestation_dispatcher().on_disconnect(conn);
    if (!snapshot) return;
    ConnEvent ev{};
    ev.kind      = GN_CONN_EVENT_DISCONNECTED;
    ev.conn      = conn;
    ev.trust     = snapshot->trust;
    ev.remote_pk = snapshot->remote_pk;
    pc->kernel->on_conn_event().fire(ev);
}

void drain_handshake_pending(PluginContext* pc,
                              gn_conn_id_t conn,
                              SecuritySession& session,
                              std::string_view link_scheme) {
    auto trans = pc->kernel->links().find_by_scheme(link_scheme);
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
                (void)safe_call_result("link.disconnect",
                    trans->vtable->disconnect, trans->self, conn);
            }
            return;
        }
        const auto rc = safe_call_result("link.send",
            trans->vtable->send, trans->self, conn,
            cipher.data(), cipher.size());
        if (rc == GN_OK) {
            pc->kernel->connections().add_outbound(conn, cipher.size(), 1);
            continue;
        }
        if (trans->vtable->disconnect) {
            (void)safe_call_result("link.disconnect",
                trans->vtable->disconnect, trans->self, conn);
        }
        return;
    }
}

bool pk_is_known(const std::uint8_t pk[GN_PUBLIC_KEY_BYTES]) noexcept {
    for (std::size_t i = 0; i < GN_PUBLIC_KEY_BYTES; ++i) {
        if (pk[i] != 0) return true;
    }
    return false;
}

std::uint64_t inject_rate_key(const PublicKey& pk) noexcept {
    std::uint64_t key = 0;
    std::memcpy(&key, pk.data(), sizeof(key));
    return key;
}

}  // namespace gn::core::host_api_internal
