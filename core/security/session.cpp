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
    /// Drop the inbound partial-frame buffer per `backpressure.en.md`
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
    std::span<const std::uint8_t> remote_static_pk_or_empty,
    std::size_t recv_buffer_cap_bytes) {
    if (!entry.vtable || !entry.vtable->handshake_open) return GN_ERR_NULL_ARG;

    vtable_           = entry.vtable;
    provider_self_    = entry.self;
    security_anchor_  = entry.lifetime_anchor;
    conn_id_          = conn;
    recv_buffer_cap_bytes_ = recv_buffer_cap_bytes != 0
        ? recv_buffer_cap_bytes
        : kRecvBufferCapDefaultBytes;

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

void SecuritySession::set_datagram_mode() noexcept {
    datagram_mode_ = true;
    inline_crypto_.enable_datagram_mode();
}

gn_result_t SecuritySession::encrypt_transport(
    std::span<const std::uint8_t> plaintext,
    std::vector<std::uint8_t>& out_cipher) {
    if (phase_.load(std::memory_order_acquire) != SecurityPhase::Transport)
        return GN_ERR_INVALID_ENVELOPE;

    /// Datagram mode: InlineCrypto produces `[u64 LE nonce][cipher+tag]`;
    /// no stream length prefix. Vtable fallback is unsupported for datagram
    /// (null security runs only on ordered loopback links).
    if (datagram_mode_ && inline_crypto_.seeded()) {
        return inline_crypto_.encrypt(plaintext, out_cipher);
    }

    /// Stream mode: encrypt into a scratch buffer, then prepend the
    /// 2-byte big-endian length prefix so the frame on the wire is
    /// `[u16 BE len][cipher+tag]` per `plugins/security/noise/docs/handshake.md` §7.
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
    /// (the `send` chain in `core/kernel/host_api/messaging.cpp`)
    /// and on inbound by `notify_inbound_bytes` in
    /// `core/kernel/host_api/notifications.cpp`; the cap here
    /// guards against an uncoordinated provider whose AEAD
    /// overhead pushes the wire frame past 65535 bytes.
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

bool SecuritySession::fast_crypto_active() const noexcept {
    return phase_.load(std::memory_order_acquire) == SecurityPhase::Transport &&
           inline_crypto_.seeded();
}

gn_result_t SecuritySession::encrypt_batch_transport(
    CryptoWorkerPool&                                pool,
    std::span<const std::vector<std::uint8_t>>       plaintexts,
    std::vector<std::vector<std::uint8_t>>&          out_wire_frames) {
    if (!fast_crypto_active()) return GN_ERR_INVALID_STATE;
    out_wire_frames.clear();
    if (plaintexts.empty()) return GN_OK;

    /// Cipher size for ChaCha20-Poly1305 IETF is exactly
    /// `plain.size() + kTagBytes` (16). Bound-check every frame
    /// against the wire-side u16 ceiling **before** consuming any
    /// nonces — partial nonce consumption on a bad batch would
    /// strand the receiver out of step with the sender.
    for (const auto& plain : plaintexts) {
        const std::size_t cipher_size = plain.size() + InlineCrypto::kTagBytes;
        if (cipher_size > kFrameCipherMaxBytes) {
            return GN_ERR_PAYLOAD_TOO_LARGE;
        }
    }

    const std::size_t k = plaintexts.size();
    const std::uint64_t nonce_base = inline_crypto_.reserve_send_nonces(k);

    out_wire_frames.resize(k);
    std::vector<CryptoWorkerPool::Job> jobs;
    jobs.reserve(k);
    for (std::size_t i = 0; i < k; ++i) {
        const auto& plain = plaintexts[i];
        const std::size_t cipher_size = plain.size() + InlineCrypto::kTagBytes;
        out_wire_frames[i].resize(kFramePrefixBytes + cipher_size);

        /// Write the 2-byte BE length prefix up front — cipher
        /// size is fixed by AEAD overhead, so the prefix is known
        /// before the worker runs. The pool fills the cipher
        /// portion in place.
        const std::uint16_t len_be = static_cast<std::uint16_t>(cipher_size);
        out_wire_frames[i][0] = static_cast<std::uint8_t>((len_be >> 8) & 0xFF);
        out_wire_frames[i][1] = static_cast<std::uint8_t>(len_be        & 0xFF);

        std::span<std::uint8_t> cipher_slot{
            out_wire_frames[i].data() + kFramePrefixBytes,
            cipher_size};
        jobs.push_back(inline_crypto_.make_encrypt_job(
            plain, nonce_base + i, cipher_slot));
    }

    pool.run_batch(jobs);
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

#ifdef GOODNET_BENCH_SHOWCASE
gn_result_t SecuritySession::_test_clear_inline_crypto() {
    /// The compile-time gate (`-DGOODNET_BENCH_SHOWCASE=ON`) is the
    /// only thing standing between production code and the inline
    /// AEAD wipe. Default builds drop this entire translation unit
    /// region, so a release kernel has no symbol to call. Inside
    /// the bench build, the only runtime guard is the session phase
    /// — a session that never finished handshake stays in
    /// `Closed`/`Handshake`, and clearing inline crypto on it would
    /// race the next encrypt cycle.
    if (phase_.load(std::memory_order_acquire) != SecurityPhase::Transport) {
        return GN_ERR_INVALID_STATE;
    }
    inline_crypto_.clear_for_test();
    return GN_OK;
}
#endif  // GOODNET_BENCH_SHOWCASE

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

gn_result_t SecuritySession::decrypt_batch_transport(
    CryptoWorkerPool&                              pool,
    std::span<const std::span<const std::uint8_t>> ciphertexts,
    std::vector<std::vector<std::uint8_t>>&        out_plaintexts) {
    if (!fast_crypto_active()) return GN_ERR_INVALID_STATE;
    out_plaintexts.clear();
    if (ciphertexts.empty()) return GN_OK;

    for (const auto& cipher : ciphertexts) {
        if (cipher.size() < InlineCrypto::kTagBytes) {
            return GN_ERR_INVALID_ENVELOPE;
        }
    }

    const std::size_t k = ciphertexts.size();
    const std::uint64_t nonce_base = inline_crypto_.reserve_recv_nonces(k);

    out_plaintexts.resize(k);
    std::vector<CryptoWorkerPool::Job> jobs;
    jobs.reserve(k);
    for (std::size_t i = 0; i < k; ++i) {
        const auto& cipher = ciphertexts[i];
        const std::size_t plain_size = cipher.size() - InlineCrypto::kTagBytes;
        out_plaintexts[i] = take_plaintext_buffer();
        out_plaintexts[i].resize(plain_size);
        std::span<std::uint8_t> plain_slot{
            out_plaintexts[i].data(), plain_size};
        jobs.push_back(inline_crypto_.make_decrypt_job(
            cipher, nonce_base + i, plain_slot));
    }

    pool.run_batch(jobs);

    for (std::size_t i = 0; i < k; ++i) {
        if (jobs[i].result_len == static_cast<std::size_t>(-1)) {
            out_plaintexts.clear();
            return GN_ERR_INVALID_ENVELOPE;
        }
        out_plaintexts[i].resize(jobs[i].result_len);
    }
    return GN_OK;
}

std::vector<std::uint8_t>
SecuritySession::take_plaintext_buffer() noexcept {
    if (recycled_plaintext_pool_.empty()) return {};
    std::vector<std::uint8_t> buf = std::move(recycled_plaintext_pool_.back());
    recycled_plaintext_pool_.pop_back();
    buf.clear();
    return buf;
}

void SecuritySession::release_plaintext_buffer(
    std::vector<std::uint8_t>&& buf) noexcept {
    if (recycled_plaintext_pool_.size() >= kRecycledPlaintextPoolMax) return;
    buf.clear();
    recycled_plaintext_pool_.push_back(std::move(buf));
}

void SecuritySession::recycle_plaintext_buffers(
    std::vector<std::vector<std::uint8_t>>& buffers) noexcept {
    for (auto& buf : buffers) {
        if (recycled_plaintext_pool_.size() >= kRecycledPlaintextPoolMax) break;
        buf.clear();
        recycled_plaintext_pool_.push_back(std::move(buf));
    }
    buffers.clear();
}

gn_result_t SecuritySession::decrypt_batch_transport_stream(
    CryptoWorkerPool&                       pool,
    std::span<const std::uint8_t>           wire_bytes,
    std::vector<std::vector<std::uint8_t>>& out_plaintexts) {
    if (phase_.load(std::memory_order_acquire) != SecurityPhase::Transport)
        return GN_ERR_INVALID_ENVELOPE;

    /// Datagram mode: each notify_inbound_bytes call delivers exactly one
    /// self-framing datagram `[u64 LE nonce][cipher+tag]`. Bypass the
    /// stream accumulation buffer and window-based length-prefix parsing;
    /// InlineCrypto::decrypt handles nonce extraction and replay rejection.
    if (datagram_mode_ && inline_crypto_.seeded()) {
        std::vector<std::uint8_t> plaintext = take_plaintext_buffer();
        const gn_result_t rc = inline_crypto_.decrypt(wire_bytes, plaintext);
        if (rc != GN_OK) return rc;
        out_plaintexts.push_back(std::move(plaintext));
        return GN_OK;
    }

    if (!inline_crypto_.seeded()) {
        /// Vtable fallback path is per-call only; batch dispatch
        /// gains nothing without the inline fast path. Defer to the
        /// scalar walker.
        return decrypt_transport_stream(wire_bytes, out_plaintexts);
    }

    std::lock_guard lock(recv_mu_);

    if (recv_buffer_.size() + wire_bytes.size() > recv_buffer_cap_bytes_) {
        return GN_ERR_LIMIT_REACHED;
    }
    recv_buffer_.insert(recv_buffer_.end(),
                         wire_bytes.begin(), wire_bytes.end());

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

    /// Walk the buffer once to enumerate every complete cipher
    /// frame, remembering the wire-byte cursor positions so a
    /// per-frame failure can splice the cursor precisely. Empty /
    /// oversized prefixes are still rejected synchronously before
    /// any nonce is consumed.
    struct FrameSlot {
        std::size_t cipher_offset = 0;
        std::size_t cipher_size   = 0;
        std::size_t frame_end     = 0;  // cursor after this frame
    };
    std::vector<FrameSlot> slots;

    while (cursor + kFramePrefixBytes <= recv_buffer_.size()) {
        const std::uint16_t len = static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(recv_buffer_[cursor]) << 8) |
            static_cast<std::uint16_t>(recv_buffer_[cursor + 1]));
        if (len == 0) {
            cursor += kFramePrefixBytes;
            erase_consumed();
            return GN_ERR_INVALID_ENVELOPE;
        }
        if (len > kFrameCipherMaxBytes) {
            cursor += kFramePrefixBytes;
            erase_consumed();
            return GN_ERR_FRAME_TOO_LARGE;
        }
        const std::size_t total = kFramePrefixBytes + len;
        if (cursor + total > recv_buffer_.size()) break;

        slots.push_back({cursor + kFramePrefixBytes,
                         static_cast<std::size_t>(len),
                         cursor + total});
        cursor += total;
    }

    if (slots.empty()) {
        return GN_OK;  // partial — wait for more bytes
    }

    /// Batch-of-one falls through to the scalar path so the latch /
    /// cv handshake in `CryptoWorkerPool::run_batch` doesn't tax
    /// every single-frame tick.
    if (slots.size() == 1) {
        const auto& slot = slots.front();
        std::span<const std::uint8_t> cipher{
            recv_buffer_.data() + slot.cipher_offset, slot.cipher_size};
        std::vector<std::uint8_t> plaintext = take_plaintext_buffer();
        const gn_result_t rc = inline_crypto_.decrypt(cipher, plaintext);
        if (rc != GN_OK) {
            erase_consumed();
            return rc;
        }
        out_plaintexts.push_back(std::move(plaintext));
        erase_consumed();
        return GN_OK;
    }

    const std::size_t k = slots.size();
    const std::uint64_t nonce_base = inline_crypto_.reserve_recv_nonces(k);

    std::vector<std::vector<std::uint8_t>> batch_out;
    batch_out.resize(k);
    std::vector<CryptoWorkerPool::Job> jobs;
    jobs.reserve(k);
    for (std::size_t i = 0; i < k; ++i) {
        const auto& slot = slots[i];
        const std::size_t plain_size =
            slot.cipher_size - InlineCrypto::kTagBytes;
        batch_out[i] = take_plaintext_buffer();
        batch_out[i].resize(plain_size);
        std::span<const std::uint8_t> cipher{
            recv_buffer_.data() + slot.cipher_offset, slot.cipher_size};
        std::span<std::uint8_t> plain_slot{batch_out[i].data(), plain_size};
        jobs.push_back(inline_crypto_.make_decrypt_job(
            cipher, nonce_base + i, plain_slot));
    }

    pool.run_batch(jobs);

    for (std::size_t i = 0; i < k; ++i) {
        if (jobs[i].result_len == static_cast<std::size_t>(-1)) {
            /// Erase up to and including the failing frame so the
            /// next call starts at the next frame boundary. OK
            /// plaintexts already produced are discarded — the
            /// invariant matches the scalar walker, which never
            /// emits any plaintext on the call that hits AEAD
            /// failure.
            cursor = slots[i].frame_end;
            erase_consumed();
            return GN_ERR_INVALID_ENVELOPE;
        }
        batch_out[i].resize(jobs[i].result_len);
    }

    out_plaintexts.insert(out_plaintexts.end(),
                          std::make_move_iterator(batch_out.begin()),
                          std::make_move_iterator(batch_out.end()));
    erase_consumed();
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
    /// (`link.en.md` §3) catches the tear-down — defence-in-depth with
    /// the per-call cap here.
    if (recv_buffer_.size() + wire_bytes.size() > recv_buffer_cap_bytes_) {
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

        std::vector<std::uint8_t> plaintext = take_plaintext_buffer();
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
    gn_result_t& out_result,
    std::size_t recv_buffer_cap_bytes) {
    /// Stack-policy gate per `security-trust.en.md` §4: the provider
    /// declares which trust classes it may serve through
    /// `allowed_trust_mask`; the kernel rejects any mismatch before
    /// the handshake state is allocated. Refusing here keeps the
    /// upstream pipeline from leaking a half-initialised session
    /// into the registry on a misconfigured stack. The mask read
    /// goes through `SecurityEntry::trust_mask()` so `find_for_trust`
    /// and this call cannot drift on the gate's stance toward a
    /// throwing slot — both fold it to "deny".
    {
        const std::uint32_t mask = entry.trust_mask();
        const std::uint32_t bit  = 1u << static_cast<unsigned>(trust);
        if ((mask & bit) == 0u) {
            /// `out_result = INVALID_ENVELOPE` is the same code the
            /// protocol-layer trust gate in
            /// `core/kernel/host_api/notifications.cpp` returns;
            /// the caller maps both gates onto the
            /// `drop.trust_class_mismatch` metric so an operator
            /// watching the counter sees a uniform rate regardless
            /// of which gate fired. Per `security-trust.en.md` §4 + §9.
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
                                remote_static_pk_or_empty,
                                recv_buffer_cap_bytes);
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
