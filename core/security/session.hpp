/// @file   core/security/session.hpp
/// @brief  Per-connection security state machine.
///
/// Implements `docs/contracts/security-trust.md` §3 + the handshake
/// loop described in `plugins/security/noise/docs/handshake.md`. The kernel owns one
/// `SecuritySession` per active connection; the session drives the
/// security provider's `handshake_open → handshake_step` cycle, then
/// transitions to transport-phase encrypt/decrypt on completion.
///
/// The session is *not* thread-safe by itself — the kernel routes
/// every call through the connection's strand (single-writer
/// invariant per `link.md` §4), so internal locking would only
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

#include <core/registry/security.hpp>
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
///  1. `notify_connect` allocates the session via `SessionRegistry::create`.
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
///  6. `notify_disconnect` triggers `SessionRegistry::destroy`, which calls
///     `handshake_close` then `Closed`.
class SecuritySession {
public:
    SecuritySession() = default;

    SecuritySession(const SecuritySession&)            = delete;
    SecuritySession& operator=(const SecuritySession&) = delete;
    /// Non-movable: `pending_mu_` is non-movable, and ownership
    /// of an open handshake state crosses an ABI boundary that
    /// the move would silently break. The kernel keeps every
    /// session inside `SessionRegistry::map_` under `shared_ptr`, so
    /// move semantics are not part of the surface.
    SecuritySession(SecuritySession&&)                 = delete;
    SecuritySession& operator=(SecuritySession&&)      = delete;
    ~SecuritySession();

    /// Open a session against the active security provider.
    ///
    /// @param entry           snapshot of the active security provider
    ///                        from `SecurityRegistry::current()`. Carries
    ///                        the vtable pointer, the provider `self`,
    ///                        and a `lifetime_anchor` whose strong ref
    ///                        the session holds for the duration of
    ///                        every encrypt/decrypt that follows.
    /// @param conn            kernel connection id
    /// @param trust           trust class declared by the transport
    /// @param role            initiator/responder, from `notify_connect`
    /// @param local_static_sk local Ed25519 secret key (libsodium layout)
    /// @param local_static_pk local Ed25519 public key
    /// @param remote_static_pk peer Ed25519 pk if known up-front (IK
    ///                         initiator); pass empty span otherwise
    [[nodiscard]] gn_result_t open(
        const SecurityEntry& entry,
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
    /// state. Idempotent. Always called by `SessionRegistry::destroy`.
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

    /// Buffer one outbound plaintext frame while the session is in
    /// `Handshake` phase. Returns `GN_ERR_LIMIT_REACHED` when the
    /// already-buffered byte count would exceed @p hard_cap_bytes,
    /// `GN_ERR_INVALID_STATE` when called outside `Handshake` (the
    /// `Transport` path encrypts directly; a `Closed` session has
    /// nothing to drain into). Per `backpressure.md` §8.
    [[nodiscard]] gn_result_t enqueue_pending(
        std::vector<std::uint8_t>&& bytes,
        std::uint64_t hard_cap_bytes);

    /// Atomically remove every buffered plaintext from the queue and
    /// return them in arrival order. The kernel calls this once
    /// `advance_handshake` has moved the session to `Transport` so
    /// the buffered bytes can be encrypted and pushed through the
    /// transport. Idempotent — a second call returns an empty vector.
    [[nodiscard]] std::vector<std::vector<std::uint8_t>> take_pending();

    /// Sum of bytes currently buffered. Useful for tests and the
    /// observability surface.
    [[nodiscard]] std::uint64_t pending_bytes() const noexcept {
        return pending_bytes_.load(std::memory_order_relaxed);
    }

private:
    /// Borrowed; the strong reference in `security_anchor_` keeps
    /// the provider's `.so` mapped while this pointer is live.
    const gn_security_provider_vtable_t* vtable_ = nullptr;
    void* provider_self_ = nullptr;
    /// Strong reference to the security plugin's lifetime anchor.
    /// PluginManager observes through a `weak_ptr` between
    /// `unregister_security` and `dlclose`; while at least one
    /// session holds this anchor, the kernel keeps the provider's
    /// `.so` mapped past every in-flight encrypt/decrypt call
    /// (per `plugin-lifetime.md` §4).
    std::shared_ptr<void> security_anchor_;
    /// Owned (allocated by provider in handshake_open, freed in
    /// handshake_close).
    void* state_ = nullptr;

    std::atomic<SecurityPhase>  phase_   {SecurityPhase::Closed};
    gn_conn_id_t                conn_id_ = GN_INVALID_ID;

    gn_handshake_keys_t keys_{};

    /// Plaintext frames buffered while in `Handshake` phase. Drained
    /// by `take_pending` once the session reaches `Transport`. Guarded
    /// by `pending_mu_` because `enqueue_pending` (kernel send path)
    /// and `take_pending` (kernel inbound path) may run on different
    /// threads — see the contract note in §8 of `backpressure.md`.
    mutable std::mutex pending_mu_;
    std::vector<std::vector<std::uint8_t>> pending_;
    std::atomic<std::uint64_t>             pending_bytes_{0};
};


/// Per-connection security session map. The kernel keeps one
/// `SessionRegistry` instance; thunks look up the session for a given
/// `gn_conn_id_t` at every notify-class call.
class SessionRegistry {
public:
    SessionRegistry()                           = default;
    SessionRegistry(const SessionRegistry&)            = delete;
    SessionRegistry& operator=(const SessionRegistry&) = delete;

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
        const SecurityEntry& entry,
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
