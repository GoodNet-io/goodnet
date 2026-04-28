/// @file   core/security/session.cpp

#include "session.hpp"

#include <cstring>

namespace gn::core {

// ── SecuritySession ─────────────────────────────────────────────────

SecuritySession::SecuritySession(SecuritySession&& other) noexcept
    : vtable_(other.vtable_),
      provider_self_(other.provider_self_),
      state_(other.state_),
      phase_(other.phase_),
      conn_id_(other.conn_id_),
      keys_(other.keys_) {
    other.vtable_        = nullptr;
    other.provider_self_ = nullptr;
    other.state_         = nullptr;
    other.phase_         = SecurityPhase::Closed;
    other.conn_id_       = GN_INVALID_ID;
}

SecuritySession& SecuritySession::operator=(SecuritySession&& other) noexcept {
    if (this != &other) {
        close();
        vtable_        = other.vtable_;
        provider_self_ = other.provider_self_;
        state_         = other.state_;
        phase_         = other.phase_;
        conn_id_       = other.conn_id_;
        keys_          = other.keys_;
        other.vtable_        = nullptr;
        other.provider_self_ = nullptr;
        other.state_         = nullptr;
        other.phase_         = SecurityPhase::Closed;
        other.conn_id_       = GN_INVALID_ID;
    }
    return *this;
}

SecuritySession::~SecuritySession() {
    close();
}

void SecuritySession::close() noexcept {
    if (vtable_ && state_ && vtable_->handshake_close) {
        vtable_->handshake_close(provider_self_, state_);
    }
    state_ = nullptr;
    phase_ = SecurityPhase::Closed;
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
        phase_ = SecurityPhase::Closed;
        return rc;
    }
    state_ = state;
    phase_ = SecurityPhase::Handshake;
    return GN_OK;
}

gn_result_t SecuritySession::advance_handshake(
    std::span<const std::uint8_t> incoming,
    std::vector<std::uint8_t>& out_msg)
{
    if (phase_ != SecurityPhase::Handshake) return GN_ERR_INVALID_ENVELOPE;
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
        phase_ = SecurityPhase::Transport;
    }
    return GN_OK;
}

gn_result_t SecuritySession::encrypt_transport(
    std::span<const std::uint8_t> plaintext,
    std::vector<std::uint8_t>& out_cipher)
{
    if (phase_ != SecurityPhase::Transport) return GN_ERR_INVALID_ENVELOPE;
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

gn_result_t SecuritySession::decrypt_transport(
    std::span<const std::uint8_t> ciphertext,
    std::vector<std::uint8_t>& out_plaintext)
{
    if (phase_ != SecurityPhase::Transport) return GN_ERR_INVALID_ENVELOPE;
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

SecuritySession* Sessions::create(
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
    auto session = std::make_unique<SecuritySession>();
    out_result = session->open(vtable, provider_self, conn, trust, role,
                                local_static_sk, local_static_pk,
                                remote_static_pk_or_empty);
    if (out_result != GN_OK) {
        return nullptr;
    }

    SecuritySession* raw = session.get();
    {
        std::unique_lock lock(mu_);
        map_[conn] = std::move(session);
    }
    return raw;
}

SecuritySession* Sessions::find(gn_conn_id_t conn) noexcept {
    std::shared_lock lock(mu_);
    auto it = map_.find(conn);
    return (it == map_.end()) ? nullptr : it->second.get();
}

void Sessions::destroy(gn_conn_id_t conn) {
    std::unique_ptr<SecuritySession> session;
    {
        std::unique_lock lock(mu_);
        auto it = map_.find(conn);
        if (it == map_.end()) return;
        session = std::move(it->second);
        map_.erase(it);
    }
    /// Destructor runs handshake_close while no lock is held.
}

std::size_t Sessions::size() const {
    std::shared_lock lock(mu_);
    return map_.size();
}

} // namespace gn::core
