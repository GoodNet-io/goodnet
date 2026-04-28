/// @file   core/security/session.hpp
/// @brief  Per-connection security state machine.
///
/// Implements `docs/contracts/security-trust.md` §3 + the handshake
/// loop described in `noise-handshake.md`. The kernel owns one
/// `SecuritySession` per active connection; the session drives the
/// security provider's `handshake_open → handshake_step` cycle, then
/// transitions to transport-phase encrypt/decrypt on completion.
///
/// The session is *not* thread-safe by itself — the kernel routes
/// every call through the connection's strand (single-writer
/// invariant per `transport.md` §4), so internal locking would only
/// add overhead. Concurrent sessions on different connections are
/// independent and may run in parallel.

#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <span>
#include <unordered_map>
#include <vector>

#include <sdk/security.h>
#include <sdk/trust.h>
#include <sdk/types.h>

namespace gn::core {

/// Phase of a per-connection security session.
enum class SecurityPhase : std::uint8_t {
    Handshake = 0,  ///< driving handshake_step until complete
    Transport = 1,  ///< exporting transport keys; encrypt/decrypt active
    Closed    = 2   ///< handshake_close has run, no further calls permitted
};

/// One security session bound to a single `gn_conn_id_t`.
///
/// Lifetime:
///  1. `notify_connect` allocates the session via `Sessions::create`.
///  2. The kernel calls `advance_handshake` with empty input to drive
///     the initiator's first message; for the responder this returns
///     an empty out_msg and waits for inbound.
///  3. Each `notify_inbound_bytes` while in `Handshake` phase routes
///     through `advance_handshake`; each call yields the next outgoing
///     handshake message (or empty).
///  4. When `handshake_complete` returns 1, the session calls
///     `export_transport_keys`, transitions to `Transport`, and zeroes
///     the handshake state.
///  5. Transport-phase frames flow through `encrypt_transport` /
///     `decrypt_transport`.
///  6. `notify_disconnect` triggers `Sessions::destroy`, which calls
///     `handshake_close` then `Closed`.
class SecuritySession {
public:
    SecuritySession() = default;

    SecuritySession(const SecuritySession&)            = delete;
    SecuritySession& operator=(const SecuritySession&) = delete;
    SecuritySession(SecuritySession&&)                 noexcept;
    SecuritySession& operator=(SecuritySession&&)      noexcept;
    ~SecuritySession();

    /// Open a session against the active security provider.
    ///
    /// @param vtable          provider vtable held by the SecurityRegistry
    /// @param provider_self   provider's `self` pointer (paired with vtable)
    /// @param conn            kernel connection id
    /// @param trust           trust class declared by the transport
    /// @param role            initiator/responder, from `notify_connect`
    /// @param local_static_sk local Ed25519 secret key (libsodium layout)
    /// @param local_static_pk local Ed25519 public key
    /// @param remote_static_pk peer Ed25519 pk if known up-front (IK
    ///                         initiator); pass empty span otherwise
    [[nodiscard]] gn_result_t open(
        const gn_security_provider_vtable_t* vtable,
        void* provider_self,
        gn_conn_id_t conn,
        gn_trust_class_t trust,
        gn_handshake_role_t role,
        std::span<const std::uint8_t, GN_PRIVATE_KEY_BYTES> local_static_sk,
        std::span<const std::uint8_t, GN_PUBLIC_KEY_BYTES>  local_static_pk,
        std::span<const std::uint8_t> remote_static_pk_or_empty);

    /// Drive one handshake step.
    ///
    /// On the first call, pass an empty span; the provider produces the
    /// initiator's first message (responder yields empty `out_msg` and
    /// waits). On every subsequent call, pass the bytes received from
    /// the transport.
    ///
    /// On completion the session internally calls
    /// `export_transport_keys`, transitions to `Transport` phase, and
    /// fills `out_keys`. After completion, the caller may use
    /// `encrypt_transport` / `decrypt_transport`.
    [[nodiscard]] gn_result_t advance_handshake(
        std::span<const std::uint8_t> incoming,
        std::vector<std::uint8_t>& out_msg);

    /// Encrypt a transport-phase plaintext frame.
    [[nodiscard]] gn_result_t encrypt_transport(
        std::span<const std::uint8_t> plaintext,
        std::vector<std::uint8_t>& out_cipher);

    /// Decrypt a transport-phase ciphertext frame.
    [[nodiscard]] gn_result_t decrypt_transport(
        std::span<const std::uint8_t> ciphertext,
        std::vector<std::uint8_t>& out_plaintext);

    /// Close the session and release the provider's per-connection
    /// state. Idempotent. Always called by `Sessions::destroy`.
    void close() noexcept;

    [[nodiscard]] SecurityPhase phase() const noexcept {
        return phase_.load(std::memory_order_acquire);
    }
    [[nodiscard]] bool is_open() const noexcept {
        return phase() != SecurityPhase::Closed;
    }

    [[nodiscard]] const gn_handshake_keys_t& transport_keys() const noexcept {
        return keys_;
    }

private:
    /// Borrowed; lifetime tied to the SecurityRegistry entry.
    const gn_security_provider_vtable_t* vtable_ = nullptr;
    void* provider_self_ = nullptr;
    /// Owned (allocated by provider in handshake_open, freed in
    /// handshake_close).
    void* state_ = nullptr;

    std::atomic<SecurityPhase>  phase_   {SecurityPhase::Closed};
    gn_conn_id_t                conn_id_ = GN_INVALID_ID;

    gn_handshake_keys_t keys_{};
};


/// Per-connection security session map. The kernel keeps one
/// `Sessions` instance; thunks look up the session for a given
/// `gn_conn_id_t` at every notify-class call.
class Sessions {
public:
    Sessions()                           = default;
    Sessions(const Sessions&)            = delete;
    Sessions& operator=(const Sessions&) = delete;

    /// Allocate and return a session for @p conn. The session is
    /// inserted into the map under @p conn; existing entries are
    /// replaced after closing.
    ///
    /// Returns a shared handle to the session. Holding the handle
    /// keeps the session alive past concurrent `destroy(conn)` calls
    /// — the entry is removed from the map but the session lives
    /// until the last shared reference drops, so an in-flight
    /// `phase()` / `encrypt_transport()` cannot race a free.
    [[nodiscard]] std::shared_ptr<SecuritySession> create(
        gn_conn_id_t conn,
        const gn_security_provider_vtable_t* vtable,
        void* provider_self,
        gn_trust_class_t trust,
        gn_handshake_role_t role,
        std::span<const std::uint8_t, GN_PRIVATE_KEY_BYTES> local_static_sk,
        std::span<const std::uint8_t, GN_PUBLIC_KEY_BYTES>  local_static_pk,
        std::span<const std::uint8_t> remote_static_pk_or_empty,
        gn_result_t& out_result);

    /// Look up the session for @p conn; empty handle if none.
    [[nodiscard]] std::shared_ptr<SecuritySession> find(
        gn_conn_id_t conn) const noexcept;

    /// Tear down the session for @p conn. Drops the map's reference;
    /// the session is freed once any concurrent borrower releases
    /// its own handle. Idempotent.
    void destroy(gn_conn_id_t conn);

    [[nodiscard]] std::size_t size() const;

private:
    mutable std::shared_mutex mu_;
    std::unordered_map<gn_conn_id_t, std::shared_ptr<SecuritySession>> map_;
};

} // namespace gn::core
