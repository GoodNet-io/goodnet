/// @file   core/security/session.cpp
/// @brief  Per-connection security session — handshake/transport phase
///         machine binding `IProtocolLayer` to the registered provider.

#include "session.hpp"

#include <cstring>
#include <utility>

#include <core/kernel/safe_invoke.hpp>

namespace gn::core {

// ── SecuritySession ──────────────────────────────────────────────────────

SecuritySession::~SecuritySession() {
    close();
}

void SecuritySession::close() noexcept {
    /// Symmetric pair to `open()`: handshake_close fires whenever the
    /// session is in any phase other than `Closed`, including the
    /// `state == nullptr` case (some providers carry no per-conn
    /// state). Default-constructed sessions stay in `Closed` and so
    /// skip the call.
    if (vtable_ &&
        phase_.load(std::memory_order_acquire) != SecurityPhase::Closed &&
        vtable_->handshake_close)
    {
        safe_call_void("security.handshake_close",
            vtable_->handshake_close, provider_self_, state_);
    }
    state_ = nullptr;
    phase_.store(SecurityPhase::Closed, std::memory_order_release);
    /// Drop any plaintext that never made it through the handshake.
    /// `Transport` already drained the queue via `take_pending`; this
    /// path covers a session that closed mid-handshake.
    {
        std::lock_guard lock(pending_mu_);
        pending_.clear();
    }
    pending_bytes_.store(0, std::memory_order_release);
    /// Drop the inbound partial-frame buffer per `backpressure.md`
    /// §9 "Drop on close". A connection closing with bytes mid-frame
    /// loses those bytes; the producer observes the loss through
    /// `GN_CONN_EVENT_DISCONNECTED`.
    {
        std::lock_guard lock(recv_mu_);
        recv_buffer_.clear();
        recv_buffer_.shrink_to_fit();
    }
    /// Keys remain available to callers that need the channel-binding
    /// hash after close; they are zeroised by the provider's
    /// handshake_close per `plugins/security/noise/docs/handshake.md` §5, but the SDK copy
    /// in `keys_` belongs to this struct's storage.
}

gn_result_t SecuritySession::open(
    const SecurityEntry& entry,
    gn_conn_id_t conn,
    gn_trust_class_t trust,
    gn_handshake_role_t role,
    std::span<const std::uint8_t, GN_PRIVATE_KEY_BYTES> local_static_sk,
    std::span<const std::uint8_t, GN_PUBLIC_KEY_BYTES>  local_static_pk,
    std::span<const std::uint8_t> remote_static_pk_or_empty) {
    if (!entry.vtable || !entry.vtable->handshake_open) return GN_ERR_NULL_ARG;

    vtable_           = entry.vtable;
    provider_self_    = entry.self;
    security_anchor_  = entry.lifetime_anchor;
    conn_id_          = conn;

    const std::uint8_t* remote_pk_ptr = nullptr;
    if (!remote_static_pk_or_empty.empty()) {
        if (remote_static_pk_or_empty.size() != GN_PUBLIC_KEY_BYTES) {
            return GN_ERR_NULL_ARG;
        }
        remote_pk_ptr = remote_static_pk_or_empty.data();
    }

    void* state = nullptr;
    const gn_result_t rc = safe_call_result(
        "security.handshake_open",
        vtable_->handshake_open,
        provider_self_, conn, trust, role,
        local_static_sk.data(), local_static_pk.data(),
        remote_pk_ptr, &state);
    if (rc != GN_OK) {
        phase_.store(SecurityPhase::Closed, std::memory_order_release);
        return rc;
    }
    state_ = state;
    phase_.store(SecurityPhase::Handshake, std::memory_order_release);
    return GN_OK;
}

gn_result_t SecuritySession::advance_handshake(
    std::span<const std::uint8_t> incoming,
    std::vector<std::uint8_t>& out_msg) {
    if (phase_.load(std::memory_order_acquire) != SecurityPhase::Handshake)
        return GN_ERR_INVALID_ENVELOPE;
    if (!vtable_ || !vtable_->handshake_step) return GN_ERR_NOT_IMPLEMENTED;

    gn_secure_buffer_t step_out{};
    const gn_result_t rc = safe_call_result(
        "security.handshake_step",
        vtable_->handshake_step,
        provider_self_, state_,
        incoming.data(), incoming.size(),
        &step_out);
    if (rc != GN_OK) return rc;

    /// Copy plugin-allocated bytes into the caller's vector and free
    /// the source via the provider's @ref gn_secure_buffer_t::free_fn.
    if (step_out.bytes && step_out.size > 0) {
        out_msg.assign(step_out.bytes, step_out.bytes + step_out.size);
    } else {
        out_msg.clear();
    }
    if (step_out.free_fn && step_out.bytes) {
        safe_call_void("security.handshake_step.free_fn",
            step_out.free_fn, step_out.free_user_data, step_out.bytes);
    }

    /// Check completion. Provider returns nonzero when the handshake
    /// has reached the transport phase.
    if (vtable_->handshake_complete) {
        const auto complete_opt = safe_call_value<int>(
            "security.handshake_complete",
            vtable_->handshake_complete, provider_self_, state_);
        if (complete_opt.value_or(0) != 0) {
            if (vtable_->export_transport_keys) {
                keys_.api_size = sizeof(keys_);
                const gn_result_t er = safe_call_result(
                    "security.export_transport_keys",
                    vtable_->export_transport_keys,
                    provider_self_, state_, &keys_);
                if (er != GN_OK) return er;
                /// Seed the inline-crypto fast path with the keys
                /// the provider just exported. A provider that opts
                /// out of inline crypto (null security) hands back
                /// a zeroed struct and `seed` returns false; the
                /// session falls back to the vtable encrypt/decrypt
                /// for that connection's lifetime.
                (void)inline_crypto_.seed(keys_);
            }
            phase_.store(SecurityPhase::Transport, std::memory_order_release);
        }
    }
    return GN_OK;
}

gn_result_t SecuritySession::encrypt_transport(
    std::span<const std::uint8_t> plaintext,
    std::vector<std::uint8_t>& out_cipher) {
    if (phase_.load(std::memory_order_acquire) != SecurityPhase::Transport)
        return GN_ERR_INVALID_ENVELOPE;

    /// Encrypt into a scratch buffer first; the wire bytes get the
    /// 2-byte big-endian length prefix prepended afterwards so the
    /// frame on the wire is `[u16 BE len][cipher+tag]` per
    /// `plugins/security/noise/docs/handshake.md` §7.
    std::vector<std::uint8_t> cipher;

    if (inline_crypto_.seeded()) {
        const gn_result_t rc = inline_crypto_.encrypt(plaintext, cipher);
        if (rc != GN_OK) return rc;
    } else {
        if (!vtable_ || !vtable_->encrypt) return GN_ERR_NOT_IMPLEMENTED;
        gn_secure_buffer_t enc_out{};
        const gn_result_t rc = safe_call_result(
            "security.encrypt",
            vtable_->encrypt,
            provider_self_, state_,
            plaintext.data(), plaintext.size(),
            &enc_out);
        if (rc != GN_OK) return rc;
        if (enc_out.bytes && enc_out.size > 0) {
            cipher.assign(enc_out.bytes, enc_out.bytes + enc_out.size);
        }
        if (enc_out.free_fn && enc_out.bytes) {
            safe_call_void("security.encrypt.free_fn",
                enc_out.free_fn, enc_out.free_user_data, enc_out.bytes);
        }
    }

    /// Bound the per-frame ciphertext length at the wire-side u16
    /// ceiling. Producers oversized past `max_frame_bytes` are
    /// already rejected on send by `gn_limits_t::max_frame_bytes`
    /// (`thunk_send` chain) and on inbound by
    /// `thunk_notify_inbound_bytes`; the cap here guards against an
    /// uncoordinated provider whose AEAD overhead pushes the wire
    /// frame past 65535 bytes.
    if (cipher.size() > kFrameCipherMaxBytes) {
        return GN_ERR_PAYLOAD_TOO_LARGE;
    }

    out_cipher.resize(kFramePrefixBytes + cipher.size());
    const std::uint16_t len_be = static_cast<std::uint16_t>(cipher.size());
    out_cipher[0] = static_cast<std::uint8_t>((len_be >> 8) & 0xFF);
    out_cipher[1] = static_cast<std::uint8_t>(len_be        & 0xFF);
    std::memcpy(out_cipher.data() + kFramePrefixBytes,
                cipher.data(), cipher.size());
    return GN_OK;
}

gn_result_t SecuritySession::enqueue_pending(
    std::vector<std::uint8_t>&& bytes,
    std::uint64_t hard_cap_bytes) {
    /// Phase check + cap check + push happen under the mutex so
    /// `take_pending` cannot observe a stale `Handshake` while a
    /// concurrent `advance_handshake` has already moved the session
    /// to `Transport`. Without the unified critical section a
    /// post-transition push would leave bytes in `pending_` that the
    /// kernel never drains — the producer would have received `GN_OK`
    /// for bytes that never reach the wire.
    const auto incoming = static_cast<std::uint64_t>(bytes.size());
    std::lock_guard lock(pending_mu_);
    if (phase_.load(std::memory_order_acquire) != SecurityPhase::Handshake) {
        return GN_ERR_INVALID_STATE;
    }
    if (hard_cap_bytes > 0 &&
        pending_bytes_.load(std::memory_order_relaxed) + incoming
            > hard_cap_bytes) {
        return GN_ERR_LIMIT_REACHED;
    }
    pending_bytes_.fetch_add(incoming, std::memory_order_relaxed);
    pending_.push_back(std::move(bytes));
    return GN_OK;
}

std::vector<std::vector<std::uint8_t>> SecuritySession::take_pending() {
    std::vector<std::vector<std::uint8_t>> out;
    std::lock_guard lock(pending_mu_);
    out.swap(pending_);
    /// Counter reset stays inside the lock so a concurrent
    /// `enqueue_pending` (already serialised through the same mutex)
    /// observes the zeroed counter before its own
    /// `pending_bytes_.fetch_add` runs.
    pending_bytes_.store(0, std::memory_order_relaxed);
    return out;
}

gn_result_t SecuritySession::decrypt_transport(
    std::span<const std::uint8_t> ciphertext,
    std::vector<std::uint8_t>& out_plaintext) {
    if (phase_.load(std::memory_order_acquire) != SecurityPhase::Transport)
        return GN_ERR_INVALID_ENVELOPE;

    if (inline_crypto_.seeded()) {
        return inline_crypto_.decrypt(ciphertext, out_plaintext);
    }

    if (!vtable_ || !vtable_->decrypt) return GN_ERR_NOT_IMPLEMENTED;
    gn_secure_buffer_t dec_out{};
    const gn_result_t rc = safe_call_result(
        "security.decrypt",
        vtable_->decrypt,
        provider_self_, state_,
        ciphertext.data(), ciphertext.size(),
        &dec_out);
    if (rc != GN_OK) return rc;

    if (dec_out.bytes && dec_out.size > 0) {
        out_plaintext.assign(dec_out.bytes, dec_out.bytes + dec_out.size);
    } else {
        out_plaintext.clear();
    }
    if (dec_out.free_fn && dec_out.bytes) {
        safe_call_void("security.decrypt.free_fn",
            dec_out.free_fn, dec_out.free_user_data, dec_out.bytes);
    }
    return GN_OK;
}

gn_result_t SecuritySession::decrypt_transport_stream(
    std::span<const std::uint8_t> wire_bytes,
    std::vector<std::vector<std::uint8_t>>& out_plaintexts) {
    if (phase_.load(std::memory_order_acquire) != SecurityPhase::Transport)
        return GN_ERR_INVALID_ENVELOPE;

    std::lock_guard lock(recv_mu_);

    /// Reject growth past the cap before mutating the buffer so a
    /// peer feeding garbage that never resolves to a frame boundary
    /// (adversarial or broken) can't grow the kernel's per-conn
    /// memory unboundedly. The link plugin's failure threshold
    /// (`link.md` §3) catches the tear-down — defence-in-depth with
    /// the per-call cap here.
    if (recv_buffer_.size() + wire_bytes.size() > kRecvBufferCapBytes) {
        return GN_ERR_LIMIT_REACHED;
    }
    recv_buffer_.insert(recv_buffer_.end(),
                         wire_bytes.begin(), wire_bytes.end());

    /// Drain every complete frame at the buffer head. A frame is
    /// `[u16 BE len][len bytes of cipher+tag]`; partial bytes
    /// remain at the head for the next call. The loop returns OK
    /// even when no complete frame surfaced this call — that is
    /// the legitimate "need more bytes" path on every chunk that
    /// straddles a boundary.
    ///
    /// Per-frame failure (malformed length, oversized frame, AEAD
    /// authentication fail) erases every byte consumed so far —
    /// including the bad frame — before returning. Without the
    /// erase the next `notify_inbound_bytes` would re-decrypt the
    /// same OK-frames already moved into `out_plaintexts`, double-
    /// dispatching them to the handler, and re-hit the bad frame
    /// every call until the link plugin's failure threshold tears
    /// the conn down. The drain-on-error invariant keeps
    /// `recv_buffer_` aligned to "no consumed bytes ever live past
    /// a return".
    std::size_t cursor = 0;
    auto erase_consumed = [&] {
        if (cursor > 0) {
            using diff_t = std::vector<std::uint8_t>::difference_type;
            recv_buffer_.erase(recv_buffer_.begin(),
                                recv_buffer_.begin()
                                    + static_cast<diff_t>(cursor));
            cursor = 0;
        }
    };

    while (cursor + kFramePrefixBytes <= recv_buffer_.size()) {
        const std::uint16_t len = static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(recv_buffer_[cursor]) << 8) |
            static_cast<std::uint16_t>(recv_buffer_[cursor + 1]));
        if (len == 0) {
            /// A zero-length frame is malformed: the AEAD always
            /// produces a 16-byte tag, so a payload-free frame
            /// would still occupy 16 wire bytes.
            cursor += kFramePrefixBytes;
            erase_consumed();
            return GN_ERR_INVALID_ENVELOPE;
        }
        if (len > kFrameCipherMaxBytes) {
            /// u16 caps at 65535 — covered above by the type — so
            /// this branch is defensive.
            cursor += kFramePrefixBytes;
            erase_consumed();
            return GN_ERR_FRAME_TOO_LARGE;
        }
        const std::size_t total = kFramePrefixBytes + len;
        if (cursor + total > recv_buffer_.size()) break;  // partial body

        std::span<const std::uint8_t> cipher{
            recv_buffer_.data() + cursor + kFramePrefixBytes, len};

        std::vector<std::uint8_t> plaintext;
        gn_result_t rc;
        if (inline_crypto_.seeded()) {
            rc = inline_crypto_.decrypt(cipher, plaintext);
        } else if (vtable_ && vtable_->decrypt) {
            gn_secure_buffer_t dec_out{};
            rc = safe_call_result(
                "security.decrypt",
                vtable_->decrypt,
                provider_self_, state_,
                cipher.data(), cipher.size(),
                &dec_out);
            if (rc == GN_OK) {
                if (dec_out.bytes && dec_out.size > 0) {
                    plaintext.assign(dec_out.bytes,
                                      dec_out.bytes + dec_out.size);
                }
                if (dec_out.free_fn && dec_out.bytes) {
                    safe_call_void("security.decrypt.free_fn",
                        dec_out.free_fn, dec_out.free_user_data,
                        dec_out.bytes);
                }
            }
        } else {
            erase_consumed();
            return GN_ERR_NOT_IMPLEMENTED;
        }
        if (rc != GN_OK) {
            cursor += total;       // drop the bad frame too
            erase_consumed();
            return rc;
        }

        out_plaintexts.push_back(std::move(plaintext));
        cursor += total;
    }

    erase_consumed();
    return GN_OK;
}

// ── SessionRegistry ──────────────────────────────────────────────────────

std::shared_ptr<SecuritySession> SessionRegistry::create(
    gn_conn_id_t conn,
    const SecurityEntry& entry,
    gn_trust_class_t trust,
    gn_handshake_role_t role,
    std::span<const std::uint8_t, GN_PRIVATE_KEY_BYTES> local_static_sk,
    std::span<const std::uint8_t, GN_PUBLIC_KEY_BYTES>  local_static_pk,
    std::span<const std::uint8_t> remote_static_pk_or_empty,
    gn_result_t& out_result) {
    /// Stack-policy gate per `security-trust.md` §4: the provider
    /// declares which trust classes it may serve through
    /// `allowed_trust_mask`; the kernel rejects any mismatch before
    /// the handshake state is allocated. Refusing here keeps the
    /// upstream pipeline from leaking a half-initialised session
    /// into the registry on a misconfigured stack.
    if (entry.vtable && entry.vtable->allowed_trust_mask) {
        const auto mask_opt = safe_call_value<std::uint32_t>(
            "security.allowed_trust_mask",
            entry.vtable->allowed_trust_mask, entry.self);
        /// A throwing trust-mask slot collapses the gate to "deny"
        /// — we cannot trust a provider that crashes to enumerate
        /// its admitted classes correctly.
        const std::uint32_t mask = mask_opt.value_or(0u);
        const std::uint32_t bit  = 1u << static_cast<unsigned>(trust);
        if ((mask & bit) == 0u) {
            /// `out_result = INVALID_ENVELOPE` is the same code the
            /// protocol-layer gate in `host_api_builder.cpp:1068`
            /// returns; the caller maps both gates onto the
            /// `drop.trust_class_mismatch` metric so an operator
            /// watching the counter sees a uniform rate regardless
            /// of which gate fired. Per `security-trust.md` §4 + §9.
            out_result = GN_ERR_INVALID_ENVELOPE;
            return nullptr;
        }
    }

    /// Reserve the slot under exclusive lock, then run the
    /// provider's `handshake_open` outside the lock. Two callers
    /// racing on the same `conn` see at most one slot reservation;
    /// the loser receives `GN_ERR_LIMIT_REACHED` before any
    /// provider state is allocated, so the provider never observes
    /// a duplicate `handshake_open(conn, ...)` for one id.
    auto session = std::make_shared<SecuritySession>();
    {
        std::unique_lock lock(mu_);
        if (map_.count(conn) != 0) {
            out_result = GN_ERR_LIMIT_REACHED;
            return nullptr;
        }
        map_.emplace(conn, session);
    }

    out_result = session->open(entry, conn, trust, role,
                                local_static_sk, local_static_pk,
                                remote_static_pk_or_empty);
    if (out_result != GN_OK) {
        std::unique_lock lock(mu_);
        map_.erase(conn);
        return nullptr;
    }
    return session;
}

std::shared_ptr<SecuritySession> SessionRegistry::find(
    gn_conn_id_t conn) const noexcept
{
    std::shared_lock lock(mu_);
    auto it = map_.find(conn);
    return (it == map_.end()) ? std::shared_ptr<SecuritySession>{} : it->second;
}

void SessionRegistry::destroy(gn_conn_id_t conn) {
    std::shared_ptr<SecuritySession> session;
    {
        std::unique_lock lock(mu_);
        auto it = map_.find(conn);
        if (it == map_.end()) return;
        session = std::move(it->second);
        map_.erase(it);
    }
    /// `session` drops here; if other handles exist (in-flight
    /// `phase()` / `encrypt_transport()`), the destructor waits for
    /// them to release before running `handshake_close`.
}

std::size_t SessionRegistry::size() const {
    std::shared_lock lock(mu_);
    return map_.size();
}

} // namespace gn::core
