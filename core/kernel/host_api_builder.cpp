/// @file   core/kernel/host_api_builder.cpp
/// @brief  Implementation of `build_host_api`.

#include "host_api_builder.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>

#include <core/identity/node_identity.hpp>
#include <core/identity/rotation.hpp>
#include <core/registry/protocol_layer.hpp>
#include <core/util/log.hpp>
#include <sdk/cpp/uri.hpp>
#include <sdk/endpoint.h>
#include <sdk/extensions/strategy.h>
#include <sdk/identity.h>

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
/// every site (thunk_send, thunk_inject for LAYER_MESSAGE); the
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
[[nodiscard]] bool link_role(const PluginContext* pc) noexcept {
    if (pc == nullptr) return false;
    return pc->kind == GN_PLUGIN_KIND_LINK ||
           pc->kind == GN_PLUGIN_KIND_UNKNOWN;
}

/// Verify the calling link plugin owns the connection it is acting on.
///
/// A link plugin is permitted to drive `notify_inbound_bytes`,
/// `notify_disconnect`, `notify_link_event`, and `kick_handshake` only
/// for connections backed by a scheme it itself registered. Without
/// this gate any loaded link plugin could spoof inbound bytes on a
/// peer transport's connection id (security-trust.md §6a).
///
/// The match is by plugin anchor identity: the connection record
/// carries a `link_scheme`, and the link registry maps scheme →
/// `LinkEntry::lifetime_anchor`. The caller's anchor lives on
/// `pc->plugin_anchor`. Equal anchors → same plugin.
///
/// In-tree fixtures construct kernels and call host_api thunks
/// without ever loading a plugin shared object; in that case both
/// anchors are null and the check is permissive. The loader-driven
/// path always produces non-null anchors.
/// Propagate the security session's `peer_static_pk` into the
/// connection record's `remote_pk` once the handshake has completed.
///
/// Without this update the responder side of the cross-session pin
/// gate (`registry.md` §7a + §8a) is dead code: the link plugin
/// passes a placeholder `remote_pk` (typically zeros) at
/// `notify_connect`, so the attestation dispatcher's
/// `pin_device_pk` map keys on the placeholder rather than the
/// authenticated peer key. After this propagation the pin map
/// keys on the peer's real Noise static, and any reconnect under
/// a different device key trips the gate as designed.
///
/// The propagation also fires harmlessly on the initiator path
/// (where `remote_pk` already matches `peer_static_pk` from the
/// IK / cached preset) — the registry update is a no-op in that
/// case.
///
/// Returns:
/// - `GN_OK` on success / no-op (initiator path) / pre-handshake
///   placeholder still set (null security provider).
/// - `GN_ERR_INTEGRITY_FAILED` when the registry rejects the new
///   pk because it already maps to a different `conn_id`. The
///   caller MUST tear the connection down — accepting the post-
///   handshake state with an unauthenticated `remote_pk` would
///   leave the cross-session pin gate keyed on the placeholder.
[[nodiscard]] gn_result_t
propagate_peer_pk_after_handshake(const PluginContext* pc,
                                  gn_conn_id_t conn,
                                  const SecuritySession& session) {
    if (pc == nullptr || pc->kernel == nullptr) return GN_OK;
    /// Re-verify Transport phase under the call: a concurrent
    /// `SessionRegistry::destroy` could have flipped the session into
    /// Closed between the caller's `phase()` check and ours, in
    /// which case `transport_keys()` may carry zeroed bytes from
    /// the destructor's wipe.
    if (session.phase() != SecurityPhase::Transport) return GN_OK;
    const auto& keys = session.transport_keys();
    PublicKey peer_pk{};
    std::memcpy(peer_pk.data(), keys.peer_static_pk, GN_PUBLIC_KEY_BYTES);
    static const PublicKey kZeroPk{};
    if (peer_pk == kZeroPk) return GN_OK;  /// null provider / pre-handshake
    const gn_result_t rc = pc->kernel->connections().update_remote_pk(conn, peer_pk);
    if (rc == GN_ERR_LIMIT_REACHED) {
        /// `peer_static_pk` collides with another live connection's
        /// `remote_pk`. Either a duplicate-peer race (two responders
        /// from the same identity at the same time) or an identity-
        /// collision attempt — both leave the pin gate compromised
        /// if the kernel keeps the connection alive.
        return GN_ERR_INTEGRITY_FAILED;
    }
    return rc;  /// GN_OK or, very rarely, NOT_FOUND — propagate.
}

/// Tear down a connection from inside a kernel thunk after a
/// security-level failure (peer pk collision, integrity check). The
/// session is destroyed so the link plugin's next read on the conn
/// hits no decrypted payload, and the registry record + URI/pk
/// indexes are erased so subsequent host_api thunks see
/// `GN_ERR_NOT_FOUND`. A `GN_CONN_EVENT_DISCONNECTED` is published
/// so subscribers see the teardown the same way as an explicit
/// `notify_disconnect`. The reason code is conveyed back to the
/// link plugin through the calling thunk's return value.
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

[[nodiscard]] bool conn_owned_by_caller(const PluginContext* pc,
                                        const ConnectionRecord& rec) {
    if (pc == nullptr || pc->kernel == nullptr) return false;
    if (!pc->plugin_anchor) return true;  // in-tree fixture
    auto link = pc->kernel->links().find_by_scheme(rec.scheme);
    if (!link) return true;  // scheme already torn down — let downstream NOT_FOUND fire
    if (!link->lifetime_anchor) return true;  // anchorless link entry — fixture
    return link->lifetime_anchor == pc->plugin_anchor;
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

/// Hand a batch of wire-frame buffers to the link plugin and report
/// the outcome. `send_batch` is optional per `link.md` §4: a link
/// declares it `nullptr` *or* returns `GN_ERR_NOT_IMPLEMENTED` to
/// opt out, and the kernel falls through to the scalar `send` slot
/// one frame at a time.
///
/// Returns `GN_OK` when the link accepted the batch (or every frame
/// of the scalar fallback). Returns `GN_ERR_LIMIT_REACHED` when the
/// link signalled hard-cap rejection — drainer parks **only the
/// rejected suffix** (per `out_accepted`) as stalled and retries on
/// the next claim with the **same wire bytes**, preserving the AEAD
/// nonce sequence the receiver expects.
///
/// `out_accepted` reports how many leading frames the link accepted
/// before any rejection. It equals `batch.size()` on full success
/// and is the index of the first rejected frame on
/// `GN_ERR_LIMIT_REACHED`. The vtable batch path is all-or-nothing
/// per `link.md §3` ("one logical write"), so `out_accepted` is
/// either 0 (LIMIT_REACHED) or `batch.size()` (OK) on that path; the
/// scalar fallback below honours the contract by reporting the
/// genuine partial accept count so the drainer never re-sends the
/// already-accepted prefix — duplicate wire bytes under fresh recv
/// nonces would otherwise break the AEAD MAC and tear the link down.
[[nodiscard]] gn_result_t send_link_batch(
    PluginContext*                                pc,
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
        /// Scalar fallback for vtables that opt out of batch.
        /// Tracks accepted count so the caller (drainer) can park
        /// only the unsent suffix; without this the partial prefix
        /// already on the wire would replay on retry under fresh
        /// recv nonces and break the AEAD MAC.
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
            /// Other failure (transport tear-down, etc.) — bytes
            /// gone, link plugin owns retry / disconnect policy.
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

/// Drain a connection's send queue — claim has already been won via
/// the `PerConnQueue::drain_scheduled` CAS. Two ring pairs feed the
/// drainer per `docs/contracts/backpressure.en.md` §3:
///
/// 1. **Plaintext rings** (`frames_plain_high/low`) — populated when
///    the session has fast-crypto seeded. Drainer reserves K send
///    nonces atomically through `SecuritySession::encrypt_batch_transport`,
///    runs K parallel jobs through `CryptoWorkerPool`, then ships
///    the wire-framed ciphertext through `link->send_batch`.
/// 2. **Ciphertext rings** (`frames_high/low`) — populated when the
///    session has no fast-crypto seeded (loopback, null security,
///    vtable-only providers). Drainer hands the bytes verbatim to
///    the link.
///
/// Plaintext is drained first so a session that just upgraded to
/// fast-crypto does not strand any wire bytes left over from the
/// vtable-encrypt phase. The drainer re-loops while either ring
/// has frames; per `link.md` §4 single-writer is preserved by the
/// drain CAS.
///
/// Send failures from the link are dropped silently here: the kernel
/// queue has already counted the bytes through `pending_bytes` and the
/// link plugin owns retry / disconnect policy on hard caps. Future
/// improvement: re-push on `GN_ERR_LIMIT_REACHED` from the link.
void drain_send_queue(PluginContext*                            pc,
                      const LinkEntry&                          trans,
                      gn_conn_id_t                              conn,
                      PerConnQueue&                             queue,
                      const std::shared_ptr<SecuritySession>&   session) noexcept {
    while (true) {
        /// Stalled batch retry — wire frames the link rejected on
        /// a previous claim. The drainer reattempts the **same
        /// bytes** (already AEAD-encrypted with their reserved
        /// nonces) so the receiver's nonce sequence stays gap-free.
        /// `pending_bytes` carries those bytes in its accounting
        /// while stalled (added back below on stall, subtracted
        /// here on successful flush) so producers continue to
        /// observe backpressure through `try_push`.
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
                /// Fall through — try draining new frames.
            } else {
                /// Link still rejecting; halt. Compact the parked
                /// batch to drop the prefix the link DID accept
                /// before it returned `LIMIT_REACHED`. Without the
                /// compaction the next claim retries the already-
                /// sent prefix, the receiver's recv nonce has
                /// advanced past those frames, AEAD MAC fails, and
                /// the link's `host_api_failures_` threshold tears
                /// the conn down. Producer's next push claims
                /// drain again to retry the suffix.
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

        /// Plaintext path — only when the session has fast crypto
        /// active. A drained plain batch is encrypted in parallel
        /// through `CryptoWorkerPool` before it goes to the link.
        if (session != nullptr && session->fast_crypto_active() &&
            queue.has_plain()) {
            auto plain_batch = queue.drain_plain_batch();
            if (!plain_batch.empty()) {
                std::vector<std::vector<std::uint8_t>> wire_batch;
                const gn_result_t rc = session->encrypt_batch_transport(
                    pc->kernel->crypto_pool(), plain_batch, wire_batch);
                if (rc != GN_OK) {
                    /// Oversized cipher / session torn down between
                    /// push and drain — bytes dropped, producer
                    /// learns through `add_outbound` not advancing.
                    continue;
                }
                std::size_t accepted = 0;
                const gn_result_t link_rc = send_link_batch(
                    pc, trans, conn, wire_batch, accepted);
                if (link_rc == GN_ERR_LIMIT_REACHED) {
                    /// Park as stalled — same wire bytes (with
                    /// reserved nonces) retried on next claim.
                    /// Drop the accepted prefix so the parked
                    /// remainder doesn't replay frames already on
                    /// the wire under fresh recv nonces. Re-credit
                    /// `pending_bytes` for the parked suffix so
                    /// producers see backpressure while it's held.
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

        /// Ciphertext path — bytes are wire-ready already.
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

        /// Both rings empty + no stalled batch — clear flag and
        /// re-check for a pusher that slipped a frame in between
        /// drain-empty and the flag clear.
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

    auto trans = pc->kernel->links().find_by_scheme(rec->scheme);
    if (!trans || !trans->vtable || !trans->vtable->send) {
        return GN_ERR_NOT_IMPLEMENTED;
    }

    auto layer = pc->kernel->protocol_layers().find_by_protocol_id(
        rec->protocol_id);
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

    /// Decide which ring to push onto. When the session has the
    /// fast crypto path active, the framed plaintext goes onto the
    /// plaintext rings — the drainer reserves K send nonces and
    /// runs K parallel encrypt jobs through `CryptoWorkerPool`,
    /// amortising the AEAD pass across cores. Otherwise (loopback,
    /// null security, vtable-only providers) the synchronous path
    /// stays — encrypt now, push wire bytes onto the ciphertext
    /// rings.
    auto queue = pc->kernel->send_queues().find(conn);
    if (queue == nullptr) {
        /// No queue — test scaffolding that bypassed `notify_connect`.
        /// Fall through to the synchronous send so those tests still
        /// pass; the path encrypts inline if a session exists.
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
        /// Push framed plaintext — drainer encrypts in batch.
        if (!queue->try_push_plain(std::move(*framed), SendPriority::Low)) {
            /// Kernel queue full (often because a stalled wire
            /// batch is still parked from a prior link rejection).
            /// Producer back-off path doesn't naturally pump the
            /// drain — claim drain CAS here so the stalled batch
            /// gets retried even when no new bytes can land.
            bool kicked = false;
            if (queue->drain_scheduled.compare_exchange_strong(
                    kicked, true, std::memory_order_acq_rel)) {
                drain_send_queue(pc, *trans, conn, *queue, session);
            }
            return GN_ERR_LIMIT_REACHED;
        }
    } else {
        /// Encrypt synchronously (vtable fallback or no session).
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
    /// When CAS lost — another caller is already draining and our
    /// frame goes out as part of their next batch.
    return GN_OK;
}

/* ── Peer-pk-level send (DX Tier 3 / Slice 9-KERNEL) ──────────────
 *
 * Walks the connection registry collecting every live conn that
 * targets @p peer_pk, asks the registered `gn.strategy.*` extension
 * to pick one, and dispatches through `thunk_send`. When no strategy
 * is registered OR exactly one conn matches, falls through to the
 * single candidate directly — strategies are an optional plugin
 * family, not a kernel hard dependency.
 */
gn_result_t thunk_send_to(void* host_ctx,
                          const uint8_t peer_pk[GN_PUBLIC_KEY_BYTES],
                          uint32_t msg_id,
                          const uint8_t* payload,
                          size_t payload_size) {
    if (!host_ctx || !peer_pk) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;

    /// Collect every live conn that targets this peer.
    /// `for_each` holds shard locks for the visitor's duration —
    /// the visitor MUST NOT call `find_by_*` or `read_counters`
    /// (registry.md §4 lock-recursion ban); the visitor gets the
    /// `CounterSnapshot` alongside the record exactly for this case.
    PublicKey target;
    std::memcpy(target.data(), peer_pk, GN_PUBLIC_KEY_BYTES);

    std::vector<gn_path_sample_t> candidates;
    pc->kernel->connections().for_each(
        [&target, &candidates](
            const ConnectionRecord& rec,
            const ConnectionRegistry::CounterSnapshot& snap)
            -> bool {
            if (rec.remote_pk != target) return true;  // continue
            gn_path_sample_t s{};
            s.conn          = rec.id;
            s.rtt_us        = snap.last_rtt_us;
            s.loss_pct_x100 = 0;   // not yet exposed by kernel
            s.caps          = 0;   // future: link cap snapshot
            candidates.push_back(s);
            return true;
        });

    if (candidates.empty()) return GN_ERR_NOT_FOUND;

    /// Single candidate — bypass strategy lookup entirely. Common
    /// path: most peers have exactly one transport.
    if (candidates.size() == 1) {
        return thunk_send(host_ctx, candidates[0].conn,
                           msg_id, payload, payload_size);
    }

    /// Multi-conn: look up the registered strategy. Convention is
    /// exactly one active strategy per node; ambiguous registration
    /// returns `GN_ERR_LIMIT_REACHED` so the operator notices.
    auto strategies =
        pc->kernel->extensions().query_prefix("gn.strategy.");
    if (strategies.empty()) {
        /// No strategy registered — fall back to first candidate.
        /// Plugin tests for `send_to` without a strategy still work.
        return thunk_send(host_ctx, candidates[0].conn,
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

    return thunk_send(host_ctx, chosen, msg_id, payload, payload_size);
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
        std::min(rec->scheme.size(), sizeof(out->scheme) - 1);
    std::memcpy(out->scheme, rec->scheme.data(), scheme_n);
    out->scheme[scheme_n] = '\0';

    /// Counters live on the per-id `AtomicCounters` block, not on
    /// the shared record — `find_by_id` returns a `shared_ptr` ref
    /// bump on the hot path so its bytes_in/out fields stay zero.
    /// `read_counters` loads the live atomic values.
    const auto counters = pc->kernel->connections().read_counters(conn);
    out->bytes_in            = counters.bytes_in;
    out->bytes_out           = counters.bytes_out;
    out->frames_in           = counters.frames_in;
    out->frames_out          = counters.frames_out;
    out->pending_queue_bytes = counters.pending_queue_bytes;
    out->last_rtt_us         = counters.last_rtt_us;
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
    auto trans = pc->kernel->links().find_by_scheme(rec->scheme);
    if (!trans || !trans->vtable || !trans->vtable->disconnect) {
        return GN_ERR_NOT_IMPLEMENTED;
    }
    return safe_call_result("link.disconnect",
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

/// Subscription ids carry a 4-bit channel tag in the top bits so
/// `unsubscribe(id)` can route to the right SignalChannel without
/// the caller naming the channel a second time. 60-bit token space
/// (~1.15e18) is structurally non-exhaustible across realistic
/// process lifetimes.
constexpr std::uint64_t kSubChannelShift = 60;
constexpr std::uint64_t kSubChannelMask  =
    static_cast<std::uint64_t>(0xF) << kSubChannelShift;
constexpr std::uint64_t kSubTokenMask    =
    (std::uint64_t{1} << kSubChannelShift) - 1;

/// Channel tag for capability_blob subscriptions. Sits past the
/// public `GN_SUBSCRIBE_*` enum values in the 4-bit field;
/// kernel-internal — plugins never read the tag, they pass the
/// id back through `unsubscribe`.
constexpr std::uint64_t kCapabilityBlobChannel = 2;

[[nodiscard]] constexpr std::uint64_t pack_subscription_id(
    gn_subscribe_channel_t channel, std::uint64_t token) noexcept {
    return (static_cast<std::uint64_t>(channel) << kSubChannelShift) |
           (token & kSubTokenMask);
}

[[nodiscard]] constexpr std::uint64_t token_of_id(std::uint64_t id) noexcept {
    return id & kSubTokenMask;
}

/// RAII guard fires `ud_destroy(user_data)` exactly once when the
/// subscription's lambda is destroyed — either through
/// `unsubscribe()` or when the kernel observes the plugin anchor
/// expire and tears the subscription down. Captured by
/// `shared_ptr` into the channel lambda so the last reference
/// drops the moment the channel removes the subscription, and
/// the guard's dtor calls `ud_destroy` exactly once.
struct UserDataGuard {
    void* user_data = nullptr;
    void (*ud_destroy)(void*) = nullptr;
    UserDataGuard(void* ud, void (*d)(void*)) noexcept
        : user_data(ud), ud_destroy(d) {}
    UserDataGuard(const UserDataGuard&)            = delete;
    UserDataGuard& operator=(const UserDataGuard&) = delete;
    ~UserDataGuard() {
        if (ud_destroy) ud_destroy(user_data);
    }
};

gn_result_t thunk_subscribe_conn_state(void* host_ctx,
                                        gn_conn_state_cb_t cb,
                                        void* user_data,
                                        void (*ud_destroy)(void*),
                                        gn_subscription_id_t* out_id) {
    if (!host_ctx || !cb || !out_id) return GN_ERR_NULL_ARG;

    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;

    auto anchor_weak = std::weak_ptr<PluginAnchor>(pc->plugin_anchor);
    const bool anchor_set = static_cast<bool>(pc->plugin_anchor);
    auto ud_guard = std::make_shared<UserDataGuard>(user_data, ud_destroy);

    auto token = pc->kernel->on_conn_event().subscribe(
        [cb, ud_guard, anchor_weak, anchor_set](const ConnEvent& ev) {
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
            safe_call_void("subscriber.conn_state",
                cb, ud_guard->user_data, &e);
        });
    if (token == signal::SignalChannel<ConnEvent>::kInvalidToken) {
        return GN_ERR_LIMIT_REACHED;
    }
    *out_id = pack_subscription_id(GN_SUBSCRIBE_CONN_STATE,
                                    static_cast<std::uint64_t>(token));
    return GN_OK;
}

gn_result_t thunk_subscribe_config_reload(void* host_ctx,
                                           gn_config_reload_cb_t cb,
                                           void* user_data,
                                           void (*ud_destroy)(void*),
                                           gn_subscription_id_t* out_id) {
    if (!host_ctx || !cb || !out_id) return GN_ERR_NULL_ARG;

    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;

    auto anchor_weak = std::weak_ptr<PluginAnchor>(pc->plugin_anchor);
    const bool anchor_set = static_cast<bool>(pc->plugin_anchor);
    auto ud_guard = std::make_shared<UserDataGuard>(user_data, ud_destroy);

    auto token = pc->kernel->on_config_reload().subscribe(
        [cb, ud_guard, anchor_weak, anchor_set](const signal::Empty&) {
            if (anchor_set) {
                auto guard = GateGuard::acquire(anchor_weak);
                if (!guard) return;
            }
            safe_call_void("subscriber.config_reload",
                cb, ud_guard->user_data);
        });
    if (token == signal::SignalChannel<signal::Empty>::kInvalidToken) {
        return GN_ERR_LIMIT_REACHED;
    }
    *out_id = pack_subscription_id(GN_SUBSCRIBE_CONFIG_RELOAD,
                                    static_cast<std::uint64_t>(token));
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

/* ── Identity primitives ───────────────────────────────────────────── */

gn_result_t thunk_register_local_key(void* host_ctx,
                                      gn_key_purpose_t purpose,
                                      const char* label,
                                      gn_key_id_t* out_id) {
    if (!host_ctx || !out_id) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;
    *out_id = GN_INVALID_KEY_ID;

    auto current = pc->kernel->node_identity();
    if (!current) return GN_ERR_INVALID_STATE;

    auto cloned = current->clone();
    if (!cloned) return cloned.error().code;

    auto kp = identity::KeyPair::generate();
    if (!kp) return kp.error().code;

    const std::int64_t now = static_cast<std::int64_t>(std::time(nullptr));
    const std::string_view label_sv = (label != nullptr) ? label : "";
    const auto id = cloned->sub_keys().insert(purpose, std::move(*kp),
                                               label_sv, now);
    *out_id = id;

    pc->kernel->set_node_identity(std::move(*cloned));
    return GN_OK;
}

gn_result_t thunk_delete_local_key(void* host_ctx, gn_key_id_t id) {
    if (!host_ctx) return GN_ERR_NULL_ARG;
    if (id == GN_INVALID_KEY_ID) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;

    auto current = pc->kernel->node_identity();
    if (!current) return GN_ERR_INVALID_STATE;

    auto cloned = current->clone();
    if (!cloned) return cloned.error().code;

    if (!cloned->sub_keys().erase(id)) return GN_ERR_NOT_FOUND;
    pc->kernel->set_node_identity(std::move(*cloned));
    return GN_OK;
}

gn_result_t thunk_list_local_keys(void* host_ctx,
                                   gn_key_descriptor_t* out_array,
                                   std::size_t array_cap,
                                   std::size_t* out_count) {
    if (!host_ctx || !out_count) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;

    auto current = pc->kernel->node_identity();
    if (!current) {
        *out_count = 0;
        return GN_ERR_INVALID_STATE;
    }
    current->sub_keys().snapshot(out_array, array_cap, out_count);
    return GN_OK;
}

gn_result_t thunk_sign_local(void* host_ctx,
                              gn_key_purpose_t purpose,
                              const std::uint8_t* payload,
                              std::size_t size,
                              std::uint8_t out_sig[64]) {
    if (!host_ctx || !out_sig) return GN_ERR_NULL_ARG;
    if (!payload && size > 0) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;

    auto current = pc->kernel->node_identity();
    if (!current) return GN_ERR_INVALID_STATE;

    /// Built-in keys answer first: user_pk for ASSERT /
    /// ROTATION_SIGN, device_pk for AUTH / KEY_AGREEMENT. Other
    /// purposes route through the sub-key registry.
    const identity::KeyPair* kp = nullptr;
    switch (purpose) {
    case GN_KEY_PURPOSE_ASSERT:
    case GN_KEY_PURPOSE_ROTATION_SIGN:
        kp = &current->user();
        break;
    case GN_KEY_PURPOSE_AUTH:
    case GN_KEY_PURPOSE_KEY_AGREEMENT:
        kp = &current->device();
        break;
    default:
        kp = current->sub_keys().find_first_of_purpose(purpose);
        break;
    }
    if (!kp) return GN_ERR_NOT_FOUND;

    auto sig = kp->sign(std::span<const std::uint8_t>(payload, size));
    if (!sig) return sig.error().code;
    std::memcpy(out_sig, sig->data(), 64);
    return GN_OK;
}

gn_result_t thunk_sign_local_by_id(void* host_ctx,
                                    gn_key_id_t id,
                                    const std::uint8_t* payload,
                                    std::size_t size,
                                    std::uint8_t out_sig[64]) {
    if (!host_ctx || !out_sig) return GN_ERR_NULL_ARG;
    if (id == GN_INVALID_KEY_ID) return GN_ERR_NULL_ARG;
    if (!payload && size > 0) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;

    auto current = pc->kernel->node_identity();
    if (!current) return GN_ERR_INVALID_STATE;

    const auto* kp = current->sub_keys().find_by_id(id);
    if (!kp) return GN_ERR_NOT_FOUND;

    auto sig = kp->sign(std::span<const std::uint8_t>(payload, size));
    if (!sig) return sig.error().code;
    std::memcpy(out_sig, sig->data(), 64);
    return GN_OK;
}

gn_result_t thunk_get_peer_user_pk(void* host_ctx,
                                    gn_conn_id_t conn,
                                    std::uint8_t out_pk[GN_PUBLIC_KEY_BYTES]) {
    if (!host_ctx || !out_pk) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;

    auto rec = pc->kernel->connections().find_by_id(conn);
    if (!rec) return GN_ERR_NOT_FOUND;

    auto pin = pc->kernel->connections().get_pinned_peer(rec->remote_pk);
    if (!pin) return GN_ERR_INVALID_STATE;
    std::memcpy(out_pk, pin->user_pk.data(), GN_PUBLIC_KEY_BYTES);
    return GN_OK;
}

gn_result_t thunk_get_peer_device_pk(void* host_ctx,
                                      gn_conn_id_t conn,
                                      std::uint8_t out_pk[GN_PUBLIC_KEY_BYTES]) {
    if (!host_ctx || !out_pk) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;

    auto rec = pc->kernel->connections().find_by_id(conn);
    if (!rec) return GN_ERR_NOT_FOUND;

    auto pin = pc->kernel->connections().get_pinned_peer(rec->remote_pk);
    if (!pin) return GN_ERR_INVALID_STATE;
    std::memcpy(out_pk, pin->device_pk.data(), GN_PUBLIC_KEY_BYTES);
    return GN_OK;
}

gn_result_t thunk_get_handshake_hash(void* host_ctx,
                                      gn_conn_id_t conn,
                                      std::uint8_t out_hash[GN_HASH_BYTES]) {
    if (!host_ctx || !out_hash) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;

    auto rec = pc->kernel->connections().find_by_id(conn);
    if (!rec) return GN_ERR_NOT_FOUND;

    auto pin = pc->kernel->connections().get_pinned_peer(rec->remote_pk);
    if (!pin) return GN_ERR_INVALID_STATE;
    std::memcpy(out_hash, pin->handshake_hash.data(), GN_HASH_BYTES);
    return GN_OK;
}

/* ── Identity rotation announce ────────────────────────────────── */

gn_result_t thunk_announce_rotation(void* host_ctx,
                                     std::int64_t valid_from_unix_ts) {
    if (!host_ctx) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;

    auto current = pc->kernel->node_identity();
    if (!current) return GN_ERR_INVALID_STATE;

    /// Generate a fresh user keypair for the new identity. A
    /// caller-supplied recovery key path lands as a follow-up; the
    /// minimal slot mints a new keypair every announce.
    auto new_user_kp = identity::KeyPair::generate();
    if (!new_user_kp) return new_user_kp.error().code;

    /// Clone the current identity and bump its rotation counter.
    /// The clone is the candidate that will replace the kernel's
    /// active NodeIdentity once we have signed the proof.
    auto cloned = current->clone();
    if (!cloned) return cloned.error().code;
    const auto next_counter = cloned->bump_rotation_counter();

    /// Sign the proof with the **old** user keypair. The old
    /// public key is what every peer currently has pinned; the
    /// new one inherits trust through the signed continuity.
    auto proof = identity::sign_rotation(
        current->user(), new_user_kp->public_key(),
        next_counter, valid_from_unix_ts);
    if (!proof) return proof.error().code;

    /// Record the rotation in the cloned identity's history,
    /// then swap the user keypair. Old keys live on through the
    /// history entries in case future verifiers need to chase
    /// the chain.
    identity::RotationEntry entry{};
    entry.prev_user_pk        = current->user().public_key();
    entry.next_user_pk        = new_user_kp->public_key();
    entry.counter             = next_counter;
    entry.valid_from_unix_ts  = valid_from_unix_ts;
    std::memcpy(entry.sig_by_prev.data(),
                proof->data() + identity::kRotationProofSigOffset,
                64);
    cloned->push_rotation_history(entry);

    /// Build a fresh NodeIdentity rooted on `new_user_kp` while
    /// inheriting cloned's sub-keys, history, counter, and
    /// reusing the device keypair. This keeps the device-derived
    /// mesh address unchanged — the live transport survives.
    auto device_kp = cloned->device().clone();
    if (!device_kp) return device_kp.error().code;
    auto rotated = identity::NodeIdentity::compose(
        std::move(*new_user_kp), std::move(*device_kp),
        cloned->attestation().expiry_unix_ts);
    if (!rotated) return rotated.error().code;
    /// Carry over sub-keys, rotation history (incl. new entry),
    /// counter from cloned.
    auto& dst_subs = rotated->sub_keys().entries_mut();
    for (auto& e : cloned->sub_keys().entries_mut()) {
        dst_subs.push_back(std::move(e));
    }
    while (rotated->rotation_counter() < next_counter) {
        rotated->bump_rotation_counter();
    }
    for (const auto& h : cloned->rotation_history()) {
        rotated->push_rotation_history(h);
    }

    /// Swap in the new identity. From this point on, signing with
    /// `GN_KEY_PURPOSE_ROTATION_SIGN` uses the new private key.
    pc->kernel->set_node_identity(std::move(*rotated));

    /// Send the proof to every live conn at trust >= Peer. The
    /// receiver-side intercepts msg_id 0x12 in
    /// `notify_inbound_bytes` and routes through the rotation
    /// handler.
    auto live_conns = std::vector<gn_conn_id_t>{};
    pc->kernel->connections().for_each(
        [&live_conns](const ConnectionRecord& rec,
                       const ConnectionRegistry::CounterSnapshot&) -> bool {
            if (rec.trust >= GN_TRUST_PEER) {
                live_conns.push_back(rec.id);
            }
            return false;  // continue
        });
    for (const auto conn : live_conns) {
        (void)thunk_send(host_ctx, conn, kIdentityRotationMsgId,
                         proof->data(), proof->size());
    }
    return GN_OK;
}

/* ── Capability TLV transport ──────────────────────────────────── */

gn_result_t thunk_present_capability_blob(void* host_ctx,
                                           gn_conn_id_t conn,
                                           const std::uint8_t* blob,
                                           std::size_t size,
                                           std::int64_t expires_unix_ts) {
    if (!host_ctx) return GN_ERR_NULL_ARG;
    if (!blob && size > 0) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;

    /// Hard cap from operator config. Default 16 KiB; 0 disables.
    const auto& limits = pc->kernel->limits();
    if (limits.max_capability_blob_bytes != 0
        && size > limits.max_capability_blob_bytes) {
        pc->kernel->metrics().increment("drop.capability_blob_too_large");
        return GN_ERR_PAYLOAD_TOO_LARGE;
    }

    /// Compose the wire payload: 8-byte BE expiry prefix + blob.
    std::vector<std::uint8_t> wire(8 + size);
    const auto u = static_cast<std::uint64_t>(expires_unix_ts);
    wire[0] = static_cast<std::uint8_t>((u >> 56) & 0xFFu);
    wire[1] = static_cast<std::uint8_t>((u >> 48) & 0xFFu);
    wire[2] = static_cast<std::uint8_t>((u >> 40) & 0xFFu);
    wire[3] = static_cast<std::uint8_t>((u >> 32) & 0xFFu);
    wire[4] = static_cast<std::uint8_t>((u >> 24) & 0xFFu);
    wire[5] = static_cast<std::uint8_t>((u >> 16) & 0xFFu);
    wire[6] = static_cast<std::uint8_t>((u >>  8) & 0xFFu);
    wire[7] = static_cast<std::uint8_t>( u        & 0xFFu);
    if (size > 0) std::memcpy(wire.data() + 8, blob, size);

    /// Route through the regular send path so backpressure and AEAD
    /// invariants apply identically to plugin-driven sends.
    return thunk_send(host_ctx, conn, kCapabilityBlobMsgId,
                      wire.data(), wire.size());
}

gn_result_t thunk_subscribe_capability_blob(void* host_ctx,
                                             gn_capability_blob_cb_t cb,
                                             void* user_data,
                                             void (*ud_destroy)(void*),
                                             gn_subscription_id_t* out_id) {
    if (!host_ctx || !cb || !out_id) return GN_ERR_NULL_ARG;
    *out_id = GN_INVALID_SUBSCRIPTION_ID;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;

    const auto bus_id = pc->kernel->capability_blob_bus().subscribe(
        cb, user_data, ud_destroy);
    if (bus_id == GN_INVALID_SUBSCRIPTION_ID) return GN_ERR_NULL_ARG;
    /// Encode the channel tag in the top 4 bits so `unsubscribe`
    /// routes back to the bus without naming the kind a second
    /// time.
    *out_id = (kCapabilityBlobChannel << kSubChannelShift)
              | (bus_id & kSubTokenMask);
    return GN_OK;
}

gn_result_t thunk_unsubscribe(void* host_ctx,
                               gn_subscription_id_t id) {
    if (!host_ctx) return GN_ERR_NULL_ARG;
    if (id == GN_INVALID_SUBSCRIPTION_ID) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;

    const auto raw_channel =
        (id & kSubChannelMask) >> kSubChannelShift;
    const auto token = token_of_id(id);

    switch (raw_channel) {
    case GN_SUBSCRIBE_CONN_STATE:
        pc->kernel->on_conn_event().unsubscribe(
            static_cast<signal::SignalChannel<ConnEvent>::Token>(token));
        return GN_OK;
    case GN_SUBSCRIBE_CONFIG_RELOAD:
        pc->kernel->on_config_reload().unsubscribe(
            static_cast<signal::SignalChannel<signal::Empty>::Token>(token));
        return GN_OK;
    case kCapabilityBlobChannel:
        return pc->kernel->capability_blob_bus().unsubscribe(token)
                   ? GN_OK
                   : GN_ERR_NOT_FOUND;
    default:
        return GN_ERR_NOT_FOUND;
    }
}

gn_result_t thunk_for_each_connection(void* host_ctx,
                                       gn_conn_visitor_t visitor,
                                       void* user_data) {
    if (!host_ctx || !visitor) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;
    pc->kernel->connections().for_each(
        [visitor, user_data](const ConnectionRecord& rec,
                              const ConnectionRegistry::CounterSnapshot& /*counters*/) -> bool {
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
    if (!link_role(pc)) return GN_ERR_NOT_IMPLEMENTED;
    if (kind != GN_CONN_EVENT_BACKPRESSURE_SOFT &&
        kind != GN_CONN_EVENT_BACKPRESSURE_CLEAR) {
        return GN_ERR_INVALID_ENVELOPE;
    }

    /// Ownership gate (security-trust.md §6a): backpressure signals
    /// describe a transport's own write queue, so only the owning link
    /// plugin may publish them. A foreign plugin spoofing SOFT/CLEAR
    /// would freeze or unfreeze a peer's senders.
    auto rec_for_check = pc->kernel->connections().find_by_id(conn);
    if (rec_for_check && !conn_owned_by_caller(pc, *rec_for_check)) {
        return GN_ERR_NOT_FOUND;
    }

    ConnEvent ev{};
    ev.kind          = kind;
    ev.conn          = conn;
    ev.pending_bytes = pending_bytes;
    /// Snapshot trust + pk from the registry so subscribers get
    /// the same payload shape as the lifecycle events.
    if (rec_for_check) {
        ev.trust     = rec_for_check->trust;
        ev.remote_pk = rec_for_check->remote_pk;
    }
    /// Persist the queue depth on the record so `get_endpoint`
    /// surfaces the same value that just hit subscribers.
    pc->kernel->connections().set_pending_bytes(conn, pending_bytes);
    pc->kernel->on_conn_event().fire(ev);
    return GN_OK;
}

/// Register-id tagging mirrors `subscribe`/`unsubscribe` (`thunk_subscribe`):
/// 4-bit kind tag in the top bits, 60-bit registry-internal token below.
constexpr std::uint64_t kRegisterChannelShift = 60;
constexpr std::uint64_t kRegisterChannelMask  =
    static_cast<std::uint64_t>(0xF) << kRegisterChannelShift;
constexpr std::uint64_t kRegisterTokenMask    =
    (std::uint64_t{1} << kRegisterChannelShift) - 1;

[[nodiscard]] constexpr std::uint64_t pack_register_id(
    gn_register_kind_t kind, std::uint64_t token) noexcept {
    return (static_cast<std::uint64_t>(kind) << kRegisterChannelShift) |
           (token & kRegisterTokenMask);
}

[[nodiscard]] constexpr gn_register_kind_t kind_of_register_id(
    std::uint64_t id) noexcept {
    return static_cast<gn_register_kind_t>(
        (id & kRegisterChannelMask) >> kRegisterChannelShift);
}

[[nodiscard]] constexpr std::uint64_t token_of_register_id(
    std::uint64_t id) noexcept {
    return id & kRegisterTokenMask;
}

gn_result_t thunk_register_vtable(void* host_ctx,
                                   gn_register_kind_t kind,
                                   const gn_register_meta_t* meta,
                                   const void* vtable,
                                   void* self,
                                   std::uint64_t* out_id) {
    if (!host_ctx) return GN_ERR_NULL_ARG;

    /// Reject unknown enum values before any per-arg validation —
    /// matches the convention from `thunk_subscribe` and
    /// `thunk_config_get`.
    switch (kind) {
    case GN_REGISTER_HANDLER:
    case GN_REGISTER_LINK:
        break;
    default:
        return GN_ERR_INVALID_ENVELOPE;
    }

    if (!meta || !meta->name || !vtable || !out_id) {
        return GN_ERR_NULL_ARG;
    }
    if (meta->api_size < sizeof(gn_register_meta_t)) {
        return GN_ERR_VERSION_MISMATCH;
    }

    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;

    switch (kind) {
    case GN_REGISTER_HANDLER: {
        gn_handler_id_t inner = GN_INVALID_ID;
        const std::string_view declared_namespace =
            meta->namespace_id != nullptr
                ? std::string_view{meta->namespace_id}
                : std::string_view{};
        const auto rc = pc->kernel->handlers().register_handler(
            declared_namespace,
            meta->name, meta->msg_id, meta->priority,
            static_cast<const gn_handler_vtable_t*>(vtable),
            self, &inner, pc->plugin_anchor, pc->plugin_name);
        if (rc != GN_OK) return rc;
        *out_id = pack_register_id(GN_REGISTER_HANDLER,
                                    static_cast<std::uint64_t>(inner));
        return GN_OK;
    }
    case GN_REGISTER_LINK: {
        gn_link_id_t inner = GN_INVALID_ID;
        const std::string_view declared_protocol_id =
            meta->protocol_id != nullptr
                ? std::string_view{meta->protocol_id}
                : std::string_view{};
        const auto rc = pc->kernel->links().register_link(
            meta->name,
            declared_protocol_id,
            static_cast<const gn_link_vtable_t*>(vtable),
            self, &inner, pc->plugin_anchor);
        if (rc != GN_OK) return rc;
        *out_id = pack_register_id(GN_REGISTER_LINK,
                                    static_cast<std::uint64_t>(inner));
        return GN_OK;
    }
    }
    return GN_ERR_INVALID_ENVELOPE;
}

gn_result_t thunk_unregister_vtable(void* host_ctx, std::uint64_t id) {
    if (!host_ctx) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;

    const auto kind  = kind_of_register_id(id);
    const auto token = token_of_register_id(id);

    switch (kind) {
    case GN_REGISTER_HANDLER:
        return pc->kernel->handlers().unregister_handler(
            static_cast<gn_handler_id_t>(token));
    case GN_REGISTER_LINK:
        return pc->kernel->links().unregister_link(
            static_cast<gn_link_id_t>(token));
    }
    return GN_ERR_NOT_FOUND;
}

const gn_limits_t* thunk_limits(void* host_ctx) {
    if (!host_ctx) return nullptr;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return nullptr;
    return &pc->kernel->limits();
}

gn_result_t thunk_config_get(void* host_ctx,
                              const char* key,
                              gn_config_value_type_t type,
                              std::size_t index,
                              void* out_value,
                              void** out_user_data,
                              void (**out_free)(void*, void*)) {
    if (!host_ctx || !key || !out_value) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;

    /// Reject unknown enum values before any per-type validation —
    /// the failure-mode table promises `INVALID_ENVELOPE` for them
    /// regardless of the index / out_free shape.
    switch (type) {
    case GN_CONFIG_VALUE_INT64:
    case GN_CONFIG_VALUE_BOOL:
    case GN_CONFIG_VALUE_DOUBLE:
    case GN_CONFIG_VALUE_STRING:
    case GN_CONFIG_VALUE_ARRAY_SIZE:
        break;
    default:
        return GN_ERR_INVALID_ENVELOPE;
    }

    /// `out_free` and `out_user_data` are meaningful only for STRING
    /// reads. Anything else must pass NULL on both — otherwise the
    /// plugin author confused the shape and would observe an
    /// undefined free callback after a non-STRING read.
    const bool is_string =
        (type == GN_CONFIG_VALUE_STRING);
    if (is_string && (!out_free || !out_user_data))  return GN_ERR_NULL_ARG;
    if (!is_string && (out_free || out_user_data))   return GN_ERR_NULL_ARG;

    /// Index sentinel rules: scalar / ARRAY_SIZE require
    /// GN_CONFIG_NO_INDEX; INT64 and STRING accept either form
    /// (sentinel = scalar lookup, real index = array element).
    const bool is_array_size =
        (type == GN_CONFIG_VALUE_ARRAY_SIZE);
    const bool is_indexable =
        (type == GN_CONFIG_VALUE_INT64) ||
        (type == GN_CONFIG_VALUE_STRING);
    if (is_array_size && index != GN_CONFIG_NO_INDEX) {
        return GN_ERR_OUT_OF_RANGE;
    }
    if (!is_indexable && !is_array_size && index != GN_CONFIG_NO_INDEX) {
        return GN_ERR_OUT_OF_RANGE;
    }

    auto& cfg = pc->kernel->config();

    switch (type) {
    case GN_CONFIG_VALUE_INT64: {
        std::int64_t v = 0;
        const auto rc = (index == GN_CONFIG_NO_INDEX)
            ? cfg.get_int64(key, v)
            : cfg.get_array_int64(key, index, v);
        if (rc != GN_OK) return rc;
        *static_cast<std::int64_t*>(out_value) = v;
        return GN_OK;
    }
    case GN_CONFIG_VALUE_BOOL: {
        bool v = false;
        const auto rc = cfg.get_bool(key, v);
        if (rc != GN_OK) return rc;
        *static_cast<std::int32_t*>(out_value) = v ? 1 : 0;
        return GN_OK;
    }
    case GN_CONFIG_VALUE_DOUBLE: {
        return cfg.get_double(key, *static_cast<double*>(out_value));
    }
    case GN_CONFIG_VALUE_STRING: {
        std::string buf;
        const auto rc = (index == GN_CONFIG_NO_INDEX)
            ? cfg.get_string(key, buf)
            : cfg.get_array_string(key, index, buf);
        if (rc != GN_OK) return rc;

        /// Plain malloc'd C string the caller frees through
        /// (*out_free)(*out_user_data, *out_value). The kernel-side
        /// destructor is stateless, so `out_user_data` stays NULL.
        auto* heap = static_cast<char*>(std::malloc(buf.size() + 1));
        if (!heap) return GN_ERR_OUT_OF_MEMORY;
        std::memcpy(heap, buf.data(), buf.size());
        heap[buf.size()] = '\0';

        *static_cast<char**>(out_value) = heap;
        *out_user_data = nullptr;
        *out_free = +[](void* /*user_data*/, void* p) { std::free(p); };
        return GN_OK;
    }
    case GN_CONFIG_VALUE_ARRAY_SIZE: {
        std::size_t v = 0;
        const auto rc = cfg.get_array_size(key, v);
        if (rc != GN_OK) return rc;
        *static_cast<std::size_t*>(out_value) = v;
        return GN_OK;
    }
    }
    return GN_ERR_INVALID_ENVELOPE;
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
                                 gn_trust_class_t trust,
                                 gn_handshake_role_t role,
                                 gn_conn_id_t* out_conn) {
    if (!host_ctx || !remote_pk || !uri || !out_conn) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;
    if (!link_role(pc)) return GN_ERR_NOT_IMPLEMENTED;

    /// URI length cap. `gn_endpoint_t::uri` is a fixed-size buffer of
    /// `GN_ENDPOINT_URI_MAX` bytes (`sdk/endpoint.h`); a URI longer
    /// than that gets silently truncated when `get_endpoint` copies
    /// `rec.uri` out, so two distinct longer URIs collapse to the
    /// same endpoint after truncation. An out-of-tree bridge passing
    /// a multi-megabyte URI would also bloat the kernel's URI index
    /// (`ConnectionRegistry::uri_index_`) without a compensating cap.
    /// `strnlen` rather than `strlen` to bound the scan itself.
    if (::strnlen(uri, GN_ENDPOINT_URI_MAX) >= GN_ENDPOINT_URI_MAX) {
        return GN_ERR_INVALID_ENVELOPE;
    }

    /// URI control-byte gate (uri.md §5 #10). The kernel writes `uri`
    /// straight into `ConnectionRecord::uri` and the registry's URI
    /// index without re-parsing through `parse_uri`, so a hostile
    /// link plugin (or any out-of-tree bridge that produces URIs from
    /// peer-controlled bytes) could slip CRLF / NUL / space through
    /// here even after the `parse_uri` fix on every other entry. A
    /// downstream caller concatenating `rec.uri` into a wire frame
    /// (Host header, request-target, log line) would smuggle a second
    /// HTTP request. Reject up front.
    if (gn::uri_has_control_bytes(uri)) return GN_ERR_INVALID_ENVELOPE;

    /// Derive the link scheme from the URI prefix. The link plugin
    /// owns the scheme-as-registry-key contract; pulling it from the
    /// URI removes a redundant explicit parameter and makes any
    /// scheme-vs-URI inconsistency unforgeable. URI without a
    /// `scheme://` prefix is rejected — link registry would have no
    /// way to attribute the conn for the ownership gate
    /// (`security-trust.md` §6a) and downstream `notify_disconnect`
    /// + `notify_inbound_bytes` would race a missing record.
    const std::string_view uri_view(uri);
    const auto sep = uri_view.find("://");
    if (sep == std::string_view::npos || sep == 0) {
        return GN_ERR_INVALID_ENVELOPE;
    }
    const std::string_view scheme_view = uri_view.substr(0, sep);
    /// RFC 3986 ABNF on the derived scheme — closes the gap above
    /// `uri_has_control_bytes` (which only catches 0x00-0x20 + 0x7F).
    /// Without this gate, a non-ASCII scheme prefix would store
    /// garbage in `ConnectionRecord::scheme`, never match any
    /// `LinkRegistry::find_by_scheme` lookup, and `get_endpoint`
    /// would silently truncate the bytes into a fixed-size buffer.
    if (!gn::is_valid_scheme(scheme_view)) {
        return GN_ERR_INVALID_ENVELOPE;
    }
    const std::string scheme(scheme_view);

    /// Caller-anchor gate per `security-trust.md` §6a, ingress side.
    /// A link plugin may only announce conns whose derived scheme it
    /// owns in `LinkRegistry`. Without this gate a TCP plugin could
    /// call `notify_connect("ws://...")` and stash an orphan record
    /// indexed under `ws` that the WS plugin cannot serve — the WS
    /// vtable would receive `send`/`disconnect` for a conn id it
    /// doesn't know. Match the egress gate shape from
    /// `conn_owned_by_caller`: only reject on a registered-scheme
    /// anchor mismatch; an unregistered scheme stays permissive so
    /// in-tree fixtures (which set `plugin_anchor` without
    /// registering a link) and unregister-races don't break.
    if (pc->plugin_anchor) {
        if (const auto link = pc->kernel->links().find_by_scheme(scheme);
            link && link->lifetime_anchor &&
            link->lifetime_anchor != pc->plugin_anchor) {
            return GN_ERR_NOT_FOUND;
        }
    }

    /// Resolve the protocol layer this connection routes through.
    /// Empty scheme entries (in-tree fixtures that bypass
    /// `register_link`) get the kernel default `gnet-v1` so the
    /// dispatch sites resolve consistently.
    std::string declared_protocol_id;
    if (const auto link = pc->kernel->links().find_by_scheme(scheme);
        link.has_value() && !link->protocol_id.empty()) {
        declared_protocol_id = link->protocol_id;
    } else {
        declared_protocol_id = std::string{::gn::core::kDefaultProtocolId};
    }

    /// Protocol-layer trust gate per `security-trust.md` §4: the
    /// link's declared layer states which trust classes it may
    /// deframe; reject up front if the declared `trust` is not in
    /// the layer's mask. The security-provider gate fires later
    /// inside `SessionRegistry::create` against the security mask.
    /// The reject increments the operator metric so a spike in
    /// unauthorized trust classes is visible without strace.
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
        /// Per-session inbound buffer cap. Sized to absorb a full
        /// drain batch from the peer's send-side
        /// `CryptoWorkerPool` (`PerConnQueue::kDefaultDrainBatch`
        /// frames × `max_frame_bytes` + headroom). With Phase 5
        /// deferred encrypt the peer can dump up to
        /// `drain_batch_size` frames into one wire `send_batch`;
        /// receiver buffer must accept the burst before the
        /// session decrypts and dispatches frames out, otherwise
        /// `decrypt_transport_stream` returns `LIMIT_REACHED` to
        /// `notify_inbound_bytes` and the link plugin's
        /// `host_api_failures_` counter trips a disconnect after
        /// 16 consecutive non-OK returns. Per `backpressure.md`
        /// §9 — a zero or unset `max_frame_bytes` falls back to
        /// the wire-format ceiling inside `SecuritySession::open`.
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
            /// Mirror the protocol-layer mask gate above: a security-mask
            /// rejection bumps the same `drop.trust_class_mismatch`
            /// counter the operator watches at the protocol-side
            /// boundary. `INVALID_ENVELOPE` from `SessionRegistry::create`
            /// is the only documented mismatch outcome (per
            /// `security-trust.md` §4); other failures stay outside this
            /// counter.
            if (session_rc == GN_ERR_INVALID_ENVELOPE) {
                pc->kernel->metrics().increment("drop.trust_class_mismatch");
            }
            (void)pc->kernel->connections().erase_with_index(new_id);
            pc->kernel->send_queues().erase(new_id);
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
    if (!link_role(pc)) return GN_ERR_NOT_IMPLEMENTED;

    auto session = pc->kernel->sessions().find(conn);
    if (!session) return GN_OK;  /// no security on this conn
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

    /// IK-style patterns can complete the handshake on the initiator's
    /// first message. If `advance_handshake` already moved the session
    /// to Transport, hand off to the kernel-internal attestation
    /// dispatcher per `attestation.md` §4: the dispatcher sends the
    /// local attestation payload over the secured channel; the trust
    /// upgrade `Untrusted → Peer` fires only after the peer's
    /// attestation has verified back. Loopback / IntraNode sessions
    /// take the dispatcher's no-op path (see `attestation.md` §4).
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

gn_result_t thunk_notify_inbound_bytes(void* host_ctx,
                                       gn_conn_id_t conn,
                                       const uint8_t* bytes,
                                       size_t size) {
    if (!host_ctx || (!bytes && size > 0)) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;
    if (!link_role(pc)) return GN_ERR_NOT_IMPLEMENTED;

    /// Cap the per-call byte count against `limits.max_frame_bytes`
    /// before any state mutation. A misbehaving link plugin that
    /// passes `size = SIZE_MAX` would otherwise drive the per-conn
    /// `bytes_in` counter into wraparound and force downstream
    /// vector reservations to overflow. The cap is configured by
    /// the operator through `limits.md` §2; a zero value means
    /// "no cap" and skips the check, matching the rest of the
    /// `gn_limits_t` family.
    const auto& limits = pc->kernel->limits();
    if (limits.max_frame_bytes != 0 && size > limits.max_frame_bytes) {
        /// Drop site: bump the named counter and emit a structured
        /// warn carrying the `(conn, observed, configured)` triple
        /// per `metrics.md` §3 so the operator can move from the
        /// counter rate on a dashboard to the offending connection
        /// without a second tool.
        pc->kernel->metrics().increment_drop_reason(GN_DROP_FRAME_TOO_LARGE);
        ::gn::log::warn(
            "host_api.notify_inbound_bytes: frame above cap — "
            "conn={} observed={} configured_max={}",
            static_cast<std::uint64_t>(conn),
            size,
            limits.max_frame_bytes);
        return GN_ERR_PAYLOAD_TOO_LARGE;
    }

    /// Look up the connection record to populate the per-call context.
    auto rec = pc->kernel->connections().find_by_id(conn);
    if (!rec) return GN_ERR_NOT_FOUND;

    /// Ownership gate (security-trust.md §6a): only the link plugin
    /// that registered the scheme backing this connection may deliver
    /// inbound bytes for it. Without the gate any loaded link plugin
    /// could spoof inbound bytes on a peer transport's connection id.
    /// Failure surfaces as `GN_ERR_NOT_FOUND` to avoid revealing the
    /// existence of connections owned by other plugins.
    if (!conn_owned_by_caller(pc, *rec)) return GN_ERR_NOT_FOUND;

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
    std::span<const std::uint8_t> wire_bytes{bytes, size};

    /// Frames the protocol layer should deframe + dispatch. Filled by
    /// the security branch (one entry per decrypted frame on
    /// stream-class transports) or by the no-session fall-through
    /// path (one entry that aliases `wire_bytes`).
    std::vector<std::vector<std::uint8_t>> plaintexts;

    if (session != nullptr) {
        if (session->phase() == SecurityPhase::Handshake) {
            std::vector<std::uint8_t> reply;
            const gn_result_t rc = session->advance_handshake(wire_bytes, reply);
            if (rc != GN_OK) return rc;
            if (!reply.empty()) {
                (void)send_raw_via_link(pc, conn, rec->scheme, reply);
            }
            /// `advance_handshake` may have moved the session to
            /// Transport on this byte run. Hand off to the kernel-
            /// internal attestation dispatcher per `attestation.md`
            /// §4: the trust upgrade fires only after the mutual
            /// exchange completes. Loopback / IntraNode sessions
            /// take the dispatcher's no-op path.
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
            /// Handshake bytes never carry application payload — the
            /// protocol layer is not consulted until Transport phase.
            return GN_OK;
        }
        if (session->phase() == SecurityPhase::Transport) {
            /// Stream-class transports deliver any chunk size; the
            /// session buffers partial bytes per `backpressure.md`
            /// §9 and emits one plaintext per complete security
            /// frame. Calls with no complete frame return GN_OK
            /// with an empty `plaintexts` — the loop below skips and
            /// the link plugin re-feeds with the next chunk.
            const gn_result_t rc = session->decrypt_transport_stream(
                wire_bytes, plaintexts);
            if (rc != GN_OK) return rc;
            if (plaintexts.empty()) return GN_OK;
        }
    } else {
        /// No session — loopback / null-security stack per
        /// `security-trust.md` §4. Bytes pass through to the
        /// protocol layer verbatim as a single "frame".
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

    /// Loop over every plaintext the security session emitted, run
    /// the protocol-layer deframer on each, then dispatch each
    /// envelope. A plaintext may carry multiple GNET envelopes if
    /// a sender batches; deframe handles that locally.
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
            /// Stamp ABI metadata + receiving connection id onto every
            /// envelope before dispatch. `api_size = sizeof(gn_message_t)`
            /// advertises the full v1 layout so size-prefix-gated reads
            /// from handlers compiled against later v1.x SDKs see the
            /// kernel-stamped fields. `conn_id` names the inbound edge —
            /// handlers consult `env.conn_id` instead of resolving
            /// `sender_pk` through `find_conn_by_pk`, which is wrong on
            /// relay paths where `sender_pk` is the originating peer
            /// (set via EXPLICIT_SENDER) but the receiving connection
            /// belongs to the relay. Per `gn_message_t::conn_id`
            /// documentation in `sdk/types.h`.
            gn_message_t stamped = env;
            stamped.api_size     = sizeof(gn_message_t);
            stamped.conn_id      = conn;

            /// Reserved system msg_ids are intercepted before the
            /// regular dispatch chain. `0x11` (attestation) per
            /// `attestation.md` §3 routes to the kernel-internal
            /// dispatcher; the envelope never reaches plugin
            /// handlers regardless of any registration.
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
            /// Identity rotation announce (`identity.en.md` §7).
            /// Verify the 150-byte proof against the user_pk we
            /// already pinned for this peer; on success advance
            /// the pin and fire `IDENTITY_ROTATED` so apps that
            /// build connectivity graphs by user_pk update edges
            /// without disconnecting the live transport.
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
                /// Heap-stable pointers for the conn-event
                /// callback. The signal channel runs the callback
                /// synchronously on the publishing thread, so
                /// stack lifetime is enough — but we put the
                /// pointers in `_reserved[0..2]` and the
                /// subscribers borrow for the call duration.
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
            /// Capability blob (`identity.en.md` §8) — kernel-side
            /// distribution. Inbound bytes carry a 8-byte
            /// `expires_unix_ts` BE prefix followed by the blob
            /// payload; the kernel hands the slice to every
            /// subscriber registered via `subscribe_capability_blob`.
            /// Plugins still drive sender-side via
            /// `present_capability_blob` (kernel composes the prefix
            /// + sends through the standard send path).
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

gn_result_t thunk_inject(void* host_ctx,
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

    /// Validate args + size + layer-specific invariants BEFORE
    /// consuming a token. A rejected call must not debit the
    /// per-source bucket; otherwise a bystander plugin's misuse
    /// becomes a DoS against legitimate inject traffic from the same
    /// source.
    switch (layer_kind) {
    case GN_INJECT_LAYER_MESSAGE:
        if (!bytes && size > 0) return GN_ERR_NULL_ARG;
        if (msg_id == 0)        return GN_ERR_INVALID_ENVELOPE;
        /// Reserved kernel-internal msg_ids (`attestation.md` §3 etc.)
        /// must not enter the handler chain through the bridge path.
        /// `notify_inbound_bytes` intercepts them and routes to the
        /// owning subsystem with the conn's own session; that
        /// session is the wrong context for an injected envelope —
        /// the bridge IPC's session cannot legitimately complete the
        /// originator-to-relay attestation binding. Reject up front;
        /// handler-registration.md §2a names the same set as
        /// unregisterable for symmetric reasons.
        if (is_reserved_system_msg_id(msg_id))
            return GN_ERR_INVALID_ENVELOPE;
        /// Identity-range msg ids carry user-level identity payloads
        /// (rotation announces, capability blobs, 2FA challenges).
        /// Bridge-style inject would let one plugin synthesise such
        /// an event on another plugin's connection — the cross-plugin
        /// trust boundary every identity proof relies on. Reject
        /// alongside the hard-reserved set; legitimate identity
        /// traffic flows through `host_api->send` (which keeps the
        /// originating plugin's anchor) or the dedicated
        /// `present_capability_blob` slot.
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
        /// Rate-limit drop carries the per-pk bucket key (first 8
        /// bytes of remote_pk). The limiter is keyed on the full
        /// pk; the truncated identifier here is just enough for an
        /// operator to correlate against the conn's
        /// remote_pk in connection logs.
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
        /// Inbound bridge envelope: source connection's remote pk is
        /// the sender (the bridge re-publishes a foreign-system
        /// payload under that identity); this node's local pk is the
        /// receiver.
        const PublicKey local_pk =
            pc->kernel->identities().any().value_or(PublicKey{});
        gn_message_t env = build_envelope(
            rec->remote_pk, local_pk, msg_id, bytes, size);

        /// Stamp ABI metadata + bridge edge. `api_size` advertises the
        /// full v1 layout so handlers gating field reads through
        /// `GN_API_HAS` see every slot (the gate would otherwise
        /// reject `conn_id` reads against `api_size == 0`). `conn_id`
        /// names the bridge-source conn so handlers can subscribe /
        /// respond / disconnect on the foreign-protocol carrier
        /// without resolving `sender_pk` through `find_conn_by_pk`
        /// (which is wrong when the bridge re-publishes under its
        /// own identity). Per `host-api.md §8` and
        /// `gn_message_t::conn_id` doc.
        env.api_size = sizeof(gn_message_t);
        env.conn_id  = source;

        route_one_envelope(*pc->kernel, layer->protocol_id(), env);
        return GN_OK;
    }

    /// LAYER_FRAME path.
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

    /// FRAME inject expects a complete frame; partial input or
    /// empty envelope set is a malformed call per host-api.md §8.
    if (deframed->messages.empty() || deframed->bytes_consumed == 0) {
        return GN_ERR_DEFRAME_INCOMPLETE;
    }

    /// Stamp the bridge edge on every dispatched envelope, mirroring
    /// the `notify_inbound_bytes` post-deframe loop. The deframer
    /// returns `span<const gn_message_t>` (envelope bytes are owned
    /// by an upstream buffer); copy-then-stamp so the borrowed
    /// payload pointers ride through unchanged. Reserved
    /// kernel-internal msg_ids never reach the handler chain — the
    /// inject source's session is not the originator-to-relay
    /// session attestation needs, so even routing the envelope to
    /// the kernel-internal dispatcher would fail the binding check.
    /// Drop them here so a relay-style bridge cannot smuggle a
    /// reserved msg_id into a plugin chain.
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

gn_result_t thunk_notify_disconnect(void* host_ctx,
                                    gn_conn_id_t conn,
                                    gn_result_t /*reason*/) {
    if (!host_ctx) return GN_ERR_NULL_ARG;
    auto* pc = static_cast<PluginContext*>(host_ctx);
    if (!ctx_live(pc)) [[unlikely]] return GN_ERR_INVALID_STATE;
    if (!link_role(pc)) return GN_ERR_NOT_IMPLEMENTED;

    /// Ownership gate (security-trust.md §6a): a link plugin must own
    /// the conn before it may tear it down. Snapshot the record first
    /// — without erasing — so the ownership check runs against current
    /// state; only then commit the destructive snapshot+erase. The
    /// pre-check is permissive when the conn is already gone (let
    /// the snapshot_and_erase return NOT_FOUND on its own).
    if (auto rec = pc->kernel->connections().find_by_id(conn);
        rec && !conn_owned_by_caller(pc, *rec)) {
        return GN_ERR_NOT_FOUND;
    }

    /// Implements `conn-events.md` §2a: drop the security session,
    /// then atomic snapshot+erase from `registry.md` §4a, then publish
    /// DISCONNECTED only on a real removal; on no-op return
    /// `GN_ERR_NOT_FOUND` without publishing.
    pc->kernel->sessions().destroy(conn);
    auto snapshot = pc->kernel->connections().snapshot_and_erase(conn);
    pc->kernel->send_queues().erase(conn);

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

    a.register_vtable       = &thunk_register_vtable;
    a.unregister_vtable     = &thunk_unregister_vtable;

    a.query_extension_checked = &thunk_query_extension_checked;
    a.register_extension      = &thunk_register_extension;
    a.unregister_extension    = &thunk_unregister_extension;

    a.set_timer               = &thunk_set_timer;
    a.cancel_timer            = &thunk_cancel_timer;

    a.subscribe_conn_state    = &thunk_subscribe_conn_state;
    a.subscribe_config_reload = &thunk_subscribe_config_reload;
    a.unsubscribe             = &thunk_unsubscribe;
    a.for_each_connection     = &thunk_for_each_connection;
    a.notify_backpressure     = &thunk_notify_backpressure;

    a.limits                = &thunk_limits;

    a.log.api_size          = sizeof(gn_log_api_t);
    a.log.should_log        = &thunk_log_should_log;
    a.log.emit              = &thunk_log_emit;

    a.config_get            = &thunk_config_get;

    a.notify_connect        = &thunk_notify_connect;
    a.notify_inbound_bytes  = &thunk_notify_inbound_bytes;
    a.notify_disconnect     = &thunk_notify_disconnect;

    a.register_security     = &thunk_register_security;
    a.unregister_security   = &thunk_unregister_security;

    a.find_conn_by_pk       = &thunk_find_conn_by_pk;
    a.get_endpoint          = &thunk_get_endpoint;

    a.inject                  = &thunk_inject;
    a.kick_handshake          = &thunk_kick_handshake;

    a.is_shutdown_requested   = &thunk_is_shutdown_requested;

    a.emit_counter            = &thunk_emit_counter;
    a.iterate_counters        = &thunk_iterate_counters;

    a.register_local_key      = &thunk_register_local_key;
    a.delete_local_key        = &thunk_delete_local_key;
    a.list_local_keys         = &thunk_list_local_keys;
    a.sign_local              = &thunk_sign_local;
    a.sign_local_by_id        = &thunk_sign_local_by_id;

    a.get_peer_user_pk        = &thunk_get_peer_user_pk;
    a.get_peer_device_pk      = &thunk_get_peer_device_pk;
    a.get_handshake_hash      = &thunk_get_handshake_hash;

    a.present_capability_blob   = &thunk_present_capability_blob;
    a.subscribe_capability_blob = &thunk_subscribe_capability_blob;

    a.announce_rotation         = &thunk_announce_rotation;

    a.send_to                   = &thunk_send_to;

    /// Other slots remain NULL; plugins guard with GN_API_HAS.
    return a;
}

} // namespace gn::core
