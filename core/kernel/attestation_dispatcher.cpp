/// @file   core/kernel/attestation_dispatcher.cpp
/// @brief  Implementation of `AttestationDispatcher`.

#include "attestation_dispatcher.hpp"

#include <sodium.h>

#include <cstring>
#include <ctime>
#include <utility>

#include <core/identity/node_identity.hpp>
#include <core/security/session.hpp>
#include <core/util/log.hpp>

#include "connection_context.hpp"
#include "kernel.hpp"
#include "safe_invoke.hpp"

namespace gn::core {

namespace {

constexpr std::size_t kCertOffset      = 0;
constexpr std::size_t kCertSize        = identity::kAttestationBytes;       // 136
constexpr std::size_t kBindingOffset   = kCertOffset + kCertSize;           // 136
constexpr std::size_t kBindingSize     = GN_HASH_BYTES;                     //  32
constexpr std::size_t kSignatureOffset = kBindingOffset + kBindingSize;     // 168
constexpr std::size_t kSignatureSize   = identity::kEd25519SignatureBytes;  //  64

static_assert(
    kSignatureOffset + kSignatureSize == AttestationDispatcher::kPayloadBytes,
    "attestation payload layout drift — see attestation.md §2");

[[nodiscard]] std::int64_t default_now_unix_seconds() noexcept {
    return static_cast<std::int64_t>(std::time(nullptr));
}

/// Drop the connection on a per-step verification failure per
/// `attestation.md` §8: destroy session, snapshot+erase the
/// registry record, publish one DISCONNECTED event with the
/// captured payload.
[[nodiscard]] const char* drop_reason_label(gn_drop_reason_t reason) noexcept {
    switch (reason) {
    case GN_DROP_ATTESTATION_BAD_SIZE:           return "attestation.bad_size";
    case GN_DROP_ATTESTATION_REPLAY:             return "attestation.replay";
    case GN_DROP_ATTESTATION_PARSE_FAILED:       return "attestation.parse_failed";
    case GN_DROP_ATTESTATION_BAD_SIGNATURE:      return "attestation.bad_signature";
    case GN_DROP_ATTESTATION_EXPIRED_OR_INVALID: return "attestation.expired_or_invalid";
    case GN_DROP_ATTESTATION_IDENTITY_CHANGE:    return "attestation.identity_change";
    default:                                     return "attestation.unknown";
    }
}

void disconnect_on_consumer_failure(Kernel&          kernel,
                                     gn_conn_id_t    conn,
                                     gn_drop_reason_t reason) noexcept {
    /// Snapshot first so the warn line and the DISCONNECTED event
    /// carry the same `(remote_pk, trust)` view of the registry.
    auto removed = kernel.connections().snapshot_and_erase(conn);
    kernel.send_queues().erase(conn);

    /// Per `metrics.md` §3 every drop site bumps both the named
    /// counter and a structured log. Counter without log leaves
    /// operators with a count and no `which conn?` follow-up;
    /// log without counter hides the rate from the dashboard.
    kernel.metrics().increment_drop_reason(reason);

    if (removed.has_value()) {
        ::gn::log::warn(
            "attestation: consumer step failed — conn={} reason={} "
            "remote_pk={:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            static_cast<std::uint64_t>(conn),
            drop_reason_label(reason),
            removed->remote_pk[0], removed->remote_pk[1],
            removed->remote_pk[2], removed->remote_pk[3],
            removed->remote_pk[4], removed->remote_pk[5],
            removed->remote_pk[6], removed->remote_pk[7]);
    } else {
        ::gn::log::warn(
            "attestation: consumer step failed — conn={} reason={} (registry miss)",
            static_cast<std::uint64_t>(conn),
            drop_reason_label(reason));
    }

    kernel.sessions().destroy(conn);
    if (removed.has_value()) {
        ConnEvent ev{};
        ev.kind      = GN_CONN_EVENT_DISCONNECTED;
        ev.conn      = conn;
        ev.trust     = removed->trust;
        ev.remote_pk = removed->remote_pk;
        kernel.on_conn_event().fire(ev);
    }
}

} // namespace

AttestationDispatcher::AttestationDispatcher()
    : clock_(&default_now_unix_seconds) {}

void AttestationDispatcher::set_clock(NowSec clock) noexcept {
    std::lock_guard lock(mu_);
    clock_ = clock ? std::move(clock) : NowSec{&default_now_unix_seconds};
}

::gn::Result<std::vector<std::uint8_t>>
AttestationDispatcher::compose_payload(
    const identity::NodeIdentity& identity,
    std::span<const std::uint8_t, GN_HASH_BYTES> binding) noexcept try
{
    std::vector<std::uint8_t> payload(kPayloadBytes);

    /// Step 1: serialise the local attestation cert.
    const auto cert_bytes = identity.attestation().to_bytes();
    std::memcpy(payload.data() + kCertOffset, cert_bytes.data(), kCertSize);

    /// Step 2: copy the binding (handshake_hash) verbatim.
    std::memcpy(payload.data() + kBindingOffset, binding.data(), kBindingSize);

    /// Step 3: sign cert||binding with the local device key.
    /// Sign over the same byte range that the consumer will verify.
    std::span<const std::uint8_t> to_sign{
        payload.data(), kCertSize + kBindingSize};
    auto sig = identity.device().sign(to_sign);
    if (!sig.has_value()) {
        return std::unexpected(sig.error());
    }
    std::memcpy(payload.data() + kSignatureOffset, sig->data(), kSignatureSize);
    return payload;
} catch (...) {
    return std::unexpected(::gn::Error{.code = GN_ERR_OUT_OF_MEMORY, .what = {}});
}

AttestationDispatcher::Outcome
AttestationDispatcher::verify_payload(
    std::span<const std::uint8_t>                payload,
    std::span<const std::uint8_t, GN_HASH_BYTES> binding,
    std::int64_t                                 now_unix_seconds,
    ::gn::PublicKey&                             out_user_pk,
    ::gn::PublicKey&                             out_device_pk) noexcept
{
    /// Step 1: size check.
    if (payload.size() != kPayloadBytes) return Outcome::BadSize;

    /// Step 2: layout split — purely arithmetic, no allocation.
    const auto cert_span = payload.first<kCertSize>();
    const auto recv_binding = payload.subspan<kBindingOffset, kBindingSize>();
    const auto sig_span     = payload.subspan<kSignatureOffset, kSignatureSize>();

    /// Step 3: binding match. Constant-time compare so a peer that
    /// runs the channel-binding probe through repeated handshakes
    /// learns nothing from per-byte timing.
    if (sodium_memcmp(recv_binding.data(), binding.data(), kBindingSize) != 0) {
        return Outcome::BindingMismatch;
    }

    /// Step 4: cert parse.
    auto parsed = identity::Attestation::from_bytes(cert_span);
    if (!parsed.has_value()) return Outcome::ParseFailed;

    /// Step 5: signature verify.
    /// The signed range is cert||binding (the first 168 bytes).
    std::span<const std::uint8_t> signed_range{payload.data(),
                                                kCertSize + kBindingSize};
    if (!identity::KeyPair::verify(parsed->device_pk, signed_range, sig_span)) {
        return Outcome::BadSignature;
    }

    /// Step 6: cert verify (signature self-check + non-expired).
    if (!parsed->verify(parsed->user_pk, now_unix_seconds)) {
        return Outcome::ExpiredOrInvalidCert;
    }

    out_user_pk   = parsed->user_pk;
    out_device_pk = parsed->device_pk;
    return Outcome::Ok;
}

void AttestationDispatcher::send_self(Kernel&          kernel,
                                       gn_conn_id_t     conn,
                                       SecuritySession& session) noexcept try
{
    /// Producer step per `attestation.md` §4. Loopback / IntraNode
    /// connections skip the exchange — their trust class is final
    /// at notify_connect.
    auto rec = kernel.connections().find_by_id(conn);
    if (!rec) return;
    if (rec->trust != GN_TRUST_UNTRUSTED) return;

    auto identity = kernel.node_identity();
    if (identity == nullptr) return;

    std::span<const std::uint8_t, GN_HASH_BYTES> binding{
        session.transport_keys().handshake_hash, GN_HASH_BYTES};

    auto payload = compose_payload(*identity, binding);
    if (!payload.has_value()) {
        ::gn::log::warn("attestation: producer compose failed — conn={}",
                        static_cast<std::uint64_t>(conn));
        return;
    }

    /// Build envelope: sender = local mesh address, receiver =
    /// remote pk learned through the security handshake.
    gn_message_t env{};
    env.msg_id       = kAttestationMsgId;
    env.payload      = payload->data();
    env.payload_size = payload->size();
    std::memcpy(env.sender_pk,   identity->address().data(),
                GN_PUBLIC_KEY_BYTES);
    std::memcpy(env.receiver_pk, rec->remote_pk.data(),
                GN_PUBLIC_KEY_BYTES);

    auto layer = kernel.protocol_layer();
    if (layer == nullptr) return;

    gn_connection_context_t ctx{};
    ctx.conn_id = conn;
    ctx.trust   = rec->trust;
    ctx.remote_pk = rec->remote_pk;
    ctx.local_pk  = identity->address();

    auto framed = layer->frame(ctx, env);
    if (!framed.has_value()) {
        ::gn::log::warn("attestation: producer frame failed — conn={}",
                        static_cast<std::uint64_t>(conn));
        return;
    }

    std::vector<std::uint8_t> cipher;
    if (session.encrypt_transport(*framed, cipher) != GN_OK) {
        ::gn::log::warn("attestation: producer encrypt failed — conn={}",
                        static_cast<std::uint64_t>(conn));
        return;
    }

    auto trans = kernel.links().find_by_scheme(rec->scheme);
    if (!trans || !trans->vtable || !trans->vtable->send) return;

    const gn_result_t rc = safe_call_result("link.send",
        trans->vtable->send, trans->self, conn,
        cipher.data(), cipher.size());
    if (rc != GN_OK) {
        ::gn::log::warn("attestation: producer transport send failed — "
                        "conn={} rc={}",
                        static_cast<std::uint64_t>(conn),
                        static_cast<int>(rc));
        return;
    }

    kernel.connections().add_outbound(conn, cipher.size(), 1);

    {
        std::lock_guard lock(mu_);
        states_[conn].our_sent = true;
    }
    try_complete_upgrade(kernel, conn);
} catch (...) {
    ::gn::log::warn("attestation: producer raised exception — conn={}",
                    static_cast<std::uint64_t>(conn));
}

int AttestationDispatcher::on_inbound(Kernel&                       kernel,
                                       gn_conn_id_t                  conn,
                                       SecuritySession&              session,
                                       std::span<const std::uint8_t> payload) noexcept try
{
    std::span<const std::uint8_t, GN_HASH_BYTES> binding{
        session.transport_keys().handshake_hash, GN_HASH_BYTES};

    NowSec clock_copy;
    {
        std::lock_guard lock(mu_);
        clock_copy = clock_;
    }
    const std::int64_t now = clock_copy ? clock_copy() : default_now_unix_seconds();

    ::gn::PublicKey user_pk{};
    ::gn::PublicKey device_pk{};
    const Outcome outcome = verify_payload(payload, binding, now,
                                            user_pk, device_pk);

    auto disconnect = [&](gn_drop_reason_t reason) {
        disconnect_on_consumer_failure(kernel, conn, reason);
    };

    switch (outcome) {
    case Outcome::BadSize:
        disconnect(GN_DROP_ATTESTATION_BAD_SIZE);
        return static_cast<int>(outcome);
    case Outcome::BindingMismatch:
        disconnect(GN_DROP_ATTESTATION_REPLAY);
        return static_cast<int>(outcome);
    case Outcome::ParseFailed:
        disconnect(GN_DROP_ATTESTATION_PARSE_FAILED);
        return static_cast<int>(outcome);
    case Outcome::BadSignature:
        disconnect(GN_DROP_ATTESTATION_BAD_SIGNATURE);
        return static_cast<int>(outcome);
    case Outcome::ExpiredOrInvalidCert:
        disconnect(GN_DROP_ATTESTATION_EXPIRED_OR_INVALID);
        return static_cast<int>(outcome);
    case Outcome::Ok:
    case Outcome::IdentityChange:
        /// verify_payload itself does not flag identity-change —
        /// that step lives below against the per-conn pinned key.
        /// Both fall through to the post-verify steps.
        break;
    }

    /// Step 7a: cross-session identity stability. The connection
    /// registry stores a `peer_pk → device_pk` map that survives
    /// disconnect; a peer that returns with a different device_pk
    /// is an identity-change attempt across sessions and is
    /// rejected before per-conn state has a chance to record the
    /// new value. `peer_pk` zero (responder-side pre-Noise) skips
    /// the check — the pinning is keyed on the post-handshake
    /// mesh address, not the placeholder.
    if (auto conn_rec = kernel.connections().find_by_id(conn);
        conn_rec != nullptr) {
        const auto& peer_pk = conn_rec->remote_pk;
        if (gn_pk_is_zero(peer_pk.data()) == 0) {
            auto existing =
                kernel.connections().get_pinned_device_pk(peer_pk);
            if (existing.has_value()
                && sodium_memcmp(existing->data(), device_pk.data(),
                                  GN_PUBLIC_KEY_BYTES) != 0) {
                disconnect_on_consumer_failure(kernel, conn,
                    GN_DROP_ATTESTATION_IDENTITY_CHANGE);
                return static_cast<int>(Outcome::IdentityChange);
            }
            /// `pin_peer` returns non-GN_OK when a concurrent
            /// caller already wrote a different device_pk for
            /// this peer; treat the rejection identically to the
            /// mismatch path so a write race cannot smuggle past
            /// the cross-session gate. On idempotent success
            /// (same device_pk) the call refreshes user_pk and
            /// handshake_hash to the latest attestation's view —
            /// host_api consumers reach those bytes through
            /// `get_peer_user_pk` / `get_handshake_hash`.
            if (kernel.connections().pin_peer(
                    peer_pk, device_pk, user_pk,
                    binding) != GN_OK) {
                disconnect_on_consumer_failure(kernel, conn,
                    GN_DROP_ATTESTATION_IDENTITY_CHANGE);
                return static_cast<int>(Outcome::IdentityChange);
            }
        }
    }

    /// Step 7b: per-session identity stability. The dispatcher's
    /// per-conn state records the device_pk on first acceptance so
    /// a duplicate attestation on the same session is detected
    /// even when the registry-side pin matches.
    bool identity_changed = false;
    {
        std::lock_guard lock(mu_);
        State& state = states_[conn];
        if (state.their_received_valid) {
            const ::gn::PublicKey& pinned = state.pinned_device_pk;
            if (sodium_memcmp(pinned.data(), device_pk.data(),
                              GN_PUBLIC_KEY_BYTES) != 0) {
                /// Identity-change attempt — flag for disconnect
                /// outside the lock so the registry critical
                /// section runs without holding the dispatcher's
                /// mutex.
                identity_changed = true;
            } else {
                /// Same device_pk, duplicate attestation — drop
                /// the envelope but do not disconnect (per
                /// `attestation.md` §9 live re-attestation note).
                return static_cast<int>(Outcome::IdentityChange);
            }
        } else {
            state.their_received_valid = true;
            state.pinned_device_pk     = device_pk;
        }
    }

    if (identity_changed) {
        disconnect_on_consumer_failure(kernel, conn,
                                        GN_DROP_ATTESTATION_IDENTITY_CHANGE);
        return static_cast<int>(Outcome::IdentityChange);
    }

    try_complete_upgrade(kernel, conn);
    return static_cast<int>(Outcome::Ok);
} catch (...) {
    ::gn::log::warn("attestation: consumer raised exception — conn={}",
                    static_cast<std::uint64_t>(conn));
    return static_cast<int>(Outcome::ParseFailed);
}

void AttestationDispatcher::on_disconnect(gn_conn_id_t conn) noexcept {
    std::lock_guard lock(mu_);
    states_.erase(conn);
}

bool AttestationDispatcher::our_sent(gn_conn_id_t conn) const noexcept {
    std::lock_guard lock(mu_);
    auto it = states_.find(conn);
    return it != states_.end() && it->second.our_sent;
}

bool AttestationDispatcher::their_received_valid(gn_conn_id_t conn) const noexcept {
    std::lock_guard lock(mu_);
    auto it = states_.find(conn);
    return it != states_.end() && it->second.their_received_valid;
}

void AttestationDispatcher::test_seed_and_complete(
    Kernel&                kernel,
    gn_conn_id_t           conn,
    bool                   our_sent_flag,
    bool                   their_received_valid_flag,
    const ::gn::PublicKey& pinned_device_pk) noexcept
{
    {
        std::lock_guard lock(mu_);
        State& state = states_[conn];
        state.our_sent             = our_sent_flag;
        state.their_received_valid = their_received_valid_flag;
        state.pinned_device_pk     = pinned_device_pk;
    }
    try_complete_upgrade(kernel, conn);
}

void AttestationDispatcher::try_complete_upgrade(Kernel&      kernel,
                                                  gn_conn_id_t conn) noexcept
{
    bool ready = false;
    {
        std::lock_guard lock(mu_);
        auto it = states_.find(conn);
        if (it == states_.end()) return;
        ready = it->second.our_sent && it->second.their_received_valid;
    }
    if (!ready) return;

    /// Promote `Untrusted → Peer`. The gate refuses any other
    /// transition; on `LIMIT_REACHED` (already-promoted, or a
    /// trust class for which the gate does not allow the move)
    /// the dispatcher silently drops — the connection stays at
    /// its declared trust class, which is the contract for
    /// Loopback/IntraNode anyway.
    ///
    /// The gate enforces the "exactly once" guarantee from
    /// `attestation.md` §6: a concurrent caller that races
    /// through the lock above reaches `upgrade_trust` second
    /// and observes `GN_ERR_LIMIT_REACHED` (the gate refuses
    /// `Peer → Peer`); only the first winner emits the event.
    ///
    /// `out_record` captures the post-upgrade snapshot under the
    /// same shard mutex that commits the new trust class, so the
    /// `remote_pk` carried in the event is consistent with the
    /// trust value the gate just set.
    ConnectionRecord upgraded{};
    if (kernel.connections().upgrade_trust(conn, GN_TRUST_PEER,
                                            &upgraded) != GN_OK) {
        return;
    }

    ConnEvent ev{};
    ev.kind  = GN_CONN_EVENT_TRUST_UPGRADED;
    ev.conn  = conn;
    ev.trust = GN_TRUST_PEER;
    ev.remote_pk = upgraded.remote_pk;
    kernel.on_conn_event().fire(ev);
}

} // namespace gn::core
