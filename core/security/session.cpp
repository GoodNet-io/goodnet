/// @file   core/security/session.cpp

#include "session.hpp"

#include <cstring>

namespace gn::core {

// ── SecuritySession ─────────────────────────────────────────────────

SecuritySession::SecuritySession(SecuritySession&& other) noexcept
    : vtable_(other.vtable_),
      provider_self_(other.provider_self_),
      state_(other.state_),
      phase_(other.phase_.load(std::memory_order_acquire)),
      conn_id_(other.conn_id_),
      keys_(other.keys_) {
    other.vtable_        = nullptr;
    other.provider_self_ = nullptr;
    other.state_         = nullptr;
    other.phase_.store(SecurityPhase::Closed, std::memory_order_release);
    other.conn_id_       = GN_INVALID_ID;
}

SecuritySession& SecuritySession::operator=(SecuritySession&& other) noexcept {
    if (this != &other) {
        close();
        vtable_        = other.vtable_;
        provider_self_ = other.provider_self_;
        state_         = other.state_;
        phase_.store(other.phase_.load(std::memory_order_acquire),
                      std::memory_order_release);
        conn_id_       = other.conn_id_;
        keys_          = other.keys_;
        other.vtable_        = nullptr;
        other.provider_self_ = nullptr;
        other.state_         = nullptr;
        other.phase_.store(SecurityPhase::Closed, std::memory_order_release);
        other.conn_id_       = GN_INVALID_ID;
    }
    return *this;
}

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
        vtable_->handshake_close(provider_self_, state_);
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
    /// Keys remain available to callers that need the channel-binding
    /// hash after close; they are zeroised by the provider's
    /// handshake_close per `noise-handshake.md` §5, but the SDK copy
    /// in `keys_` belongs to this struct's storage.
}

gn_result_t SecuritySession::open(
    const gn_security_provider_vtable_t* vtable,
    void* provider_self,
    gn_conn_id_t conn,
    gn_trust_class_t trust,
    gn_handshake_role_t role,
    std::span<const std::uint8_t, GN_PRIVATE_KEY_BYTES> local_static_sk,
    std::span<const std::uint8_t, GN_PUBLIC_KEY_BYTES>  local_static_pk,
    std::span<const std::uint8_t> remote_static_pk_or_empty)
{
    if (!vtable || !vtable->handshake_open) return GN_ERR_NULL_ARG;

    vtable_        = vtable;
    provider_self_ = provider_self;
    conn_id_       = conn;

    const std::uint8_t* remote_pk_ptr = nullptr;
    if (!remote_static_pk_or_empty.empty()) {
        if (remote_static_pk_or_empty.size() != GN_PUBLIC_KEY_BYTES) {
            return GN_ERR_NULL_ARG;
        }
        remote_pk_ptr = remote_static_pk_or_empty.data();
    }

    void* state = nullptr;
    const gn_result_t rc = vtable_->handshake_open(
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
    std::vector<std::uint8_t>& out_msg)
{
    if (phase_.load(std::memory_order_acquire) != SecurityPhase::Handshake)
        return GN_ERR_INVALID_ENVELOPE;
    if (!vtable_ || !vtable_->handshake_step) return GN_ERR_NOT_IMPLEMENTED;

    gn_secure_buffer_t step_out{};
    const gn_result_t rc = vtable_->handshake_step(
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
        step_out.free_fn(step_out.bytes);
    }

    /// Check completion. Provider returns nonzero when the handshake
    /// has reached the transport phase.
    if (vtable_->handshake_complete &&
        vtable_->handshake_complete(provider_self_, state_) != 0)
    {
        if (vtable_->export_transport_keys) {
            const gn_result_t er = vtable_->export_transport_keys(
                provider_self_, state_, &keys_);
            if (er != GN_OK) return er;
        }
        phase_.store(SecurityPhase::Transport, std::memory_order_release);
    }
    return GN_OK;
}

gn_result_t SecuritySession::encrypt_transport(
    std::span<const std::uint8_t> plaintext,
    std::vector<std::uint8_t>& out_cipher)
{
    if (phase_.load(std::memory_order_acquire) != SecurityPhase::Transport)
        return GN_ERR_INVALID_ENVELOPE;
    if (!vtable_ || !vtable_->encrypt) return GN_ERR_NOT_IMPLEMENTED;

    gn_secure_buffer_t enc_out{};
    const gn_result_t rc = vtable_->encrypt(
        provider_self_, state_,
        plaintext.data(), plaintext.size(),
        &enc_out);
    if (rc != GN_OK) return rc;

    if (enc_out.bytes && enc_out.size > 0) {
        out_cipher.assign(enc_out.bytes, enc_out.bytes + enc_out.size);
    } else {
        out_cipher.clear();
    }
    if (enc_out.free_fn && enc_out.bytes) {
        enc_out.free_fn(enc_out.bytes);
    }
    return GN_OK;
}

gn_result_t SecuritySession::enqueue_pending(
    std::vector<std::uint8_t>&& bytes,
    std::uint64_t hard_cap_bytes)
{
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
    std::vector<std::uint8_t>& out_plaintext)
{
    if (phase_.load(std::memory_order_acquire) != SecurityPhase::Transport)
        return GN_ERR_INVALID_ENVELOPE;
    if (!vtable_ || !vtable_->decrypt) return GN_ERR_NOT_IMPLEMENTED;

    gn_secure_buffer_t dec_out{};
    const gn_result_t rc = vtable_->decrypt(
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
        dec_out.free_fn(dec_out.bytes);
    }
    return GN_OK;
}

// ── Sessions ────────────────────────────────────────────────────────

std::shared_ptr<SecuritySession> Sessions::create(
    gn_conn_id_t conn,
    const gn_security_provider_vtable_t* vtable,
    void* provider_self,
    gn_trust_class_t trust,
    gn_handshake_role_t role,
    std::span<const std::uint8_t, GN_PRIVATE_KEY_BYTES> local_static_sk,
    std::span<const std::uint8_t, GN_PUBLIC_KEY_BYTES>  local_static_pk,
    std::span<const std::uint8_t> remote_static_pk_or_empty,
    gn_result_t& out_result)
{
    /// Stack-policy gate per `security-trust.md` §4: the provider
    /// declares which trust classes it may serve through
    /// `allowed_trust_mask`; the kernel rejects any mismatch before
    /// the handshake state is allocated. Refusing here keeps the
    /// upstream pipeline from leaking a half-initialised session
    /// into the registry on a misconfigured stack.
    if (vtable && vtable->allowed_trust_mask) {
        const std::uint32_t mask = vtable->allowed_trust_mask(provider_self);
        const std::uint32_t bit  = 1u << static_cast<unsigned>(trust);
        if ((mask & bit) == 0u) {
            out_result = GN_ERR_INVALID_ENVELOPE;
            return nullptr;
        }
    }

    /// Reject duplicate creation under the same `conn` id. Without
    /// this guard a second `create()` call silently overwrites the
    /// existing entry; an active borrower keeps the old session
    /// alive through `shared_ptr`, but new callers see a fresh
    /// session that lost the handshake state. The kernel pipeline
    /// allocates one session per `notify_connect`, so a duplicate
    /// here is a contract violation by the caller.
    {
        std::shared_lock lock(mu_);
        if (map_.count(conn) != 0) {
            out_result = GN_ERR_LIMIT_REACHED;
            return nullptr;
        }
    }

    auto session = std::make_shared<SecuritySession>();
    out_result = session->open(vtable, provider_self, conn, trust, role,
                                local_static_sk, local_static_pk,
                                remote_static_pk_or_empty);
    if (out_result != GN_OK) {
        return nullptr;
    }
    {
        std::unique_lock lock(mu_);
        /// Race re-check — another thread could have inserted between
        /// our shared-lock probe and the unique-lock acquire. `emplace`
        /// returns `inserted == false` on conflict; in that case we
        /// surface the same error and drop our new session on the
        /// floor (the existing one wins).
        const auto [_, inserted] = map_.emplace(conn, session);
        if (!inserted) {
            out_result = GN_ERR_LIMIT_REACHED;
            return nullptr;
        }
    }
    return session;
}

std::shared_ptr<SecuritySession> Sessions::find(
    gn_conn_id_t conn) const noexcept
{
    std::shared_lock lock(mu_);
    auto it = map_.find(conn);
    return (it == map_.end()) ? std::shared_ptr<SecuritySession>{} : it->second;
}

void Sessions::destroy(gn_conn_id_t conn) {
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

std::size_t Sessions::size() const {
    std::shared_lock lock(mu_);
    return map_.size();
}

} // namespace gn::core
