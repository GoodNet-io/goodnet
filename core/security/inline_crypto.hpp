/// @file   core/security/inline_crypto.hpp
/// @brief  Kernel-side ChaCha20-Poly1305 IETF AEAD seeded from
///         transport keys exported by the security provider.
///
/// Per `plugins/security/noise/docs/handshake.md` §6 the kernel runs the
/// transport-phase AEAD directly on keys exported by the provider's
/// handshake. The vtable's `encrypt`/`decrypt` slots are reached only
/// when a provider declines to export keys (e.g. the null security
/// provider on loopback). The fast path lives here.

#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include <sdk/security.h>
#include <sdk/types.h>

#include <core/crypto/crypto_worker_pool.hpp>

namespace gn::core {

/// 64-entry sliding replay window for datagram mode.
/// Tracks the highest nonce seen (`base`) and a 64-bit bitmap of
/// the last 64 nonces relative to it. Used only when
/// `InlineCrypto::enable_datagram_mode()` has been called.
struct ReplayWindow {
    static constexpr std::uint64_t kSize = 64;
    std::uint64_t base = 0;
    std::uint64_t bits = 0;
    /// Record nonce @p n. Returns true and marks it seen if the nonce
    /// is within the live window and has not been seen before.
    /// Returns false (reject) when the nonce is too old or replayed.
    [[nodiscard]] bool check_and_record(std::uint64_t n) noexcept;
};

/// Per-connection symmetric AEAD state. One direction is keyed for
/// send, the other for receive; the counterpart on the peer mirrors
/// the assignment so frames flow under the same `(key, nonce)`
/// schedule both ways.
class InlineCrypto {
public:
    static constexpr std::size_t  kKeyBytes      = GN_CIPHER_KEY_BYTES;
    static constexpr std::size_t  kNonceBytes    = GN_CIPHER_NONCE_BYTES;
    static constexpr std::size_t  kTagBytes       = GN_AEAD_TAG_BYTES;
    /// Wire nonce size prepended in datagram mode: 8-byte LE uint64.
    static constexpr std::size_t  kNonceWireBytes = 8;

    /// Hard rekey threshold per `plugins/security/noise/docs/handshake.md` §4
    /// (matches WireGuard's interval). InlineCrypto refuses encrypt /
    /// decrypt past this nonce; the session closes and a fresh
    /// handshake follows. v1 leaves the inline-side rekey to a
    /// future provider-driven path; the threshold is unreachable in
    /// practice (1.15e18 frames at 1 Mpps is 36000 years).
    static constexpr std::uint64_t kRekeyNonceLimit = (1ULL << 60);

    InlineCrypto() noexcept = default;
    ~InlineCrypto();

    InlineCrypto(const InlineCrypto&)            = delete;
    InlineCrypto& operator=(const InlineCrypto&) = delete;

    /// Enable datagram mode. In this mode `encrypt` prepends an 8-byte
    /// LE nonce to the output; `decrypt` reads the nonce from the first
    /// 8 bytes and validates it through a `ReplayWindow` instead of the
    /// monotonic counter. MUST be called before `seed` so the window is
    /// initialised from `initial_recv_nonce` at seed time.
    void enable_datagram_mode() noexcept;
    [[nodiscard]] bool datagram_mode() const noexcept { return datagram_mode_; }

    /// Seed both directions from a handshake-result keys struct.
    /// Returns false when the keys are zeroed — the provider declined
    /// to export and the caller must fall back to the vtable path.
    [[nodiscard]] bool seed(const gn_handshake_keys_t& keys) noexcept;

    [[nodiscard]] bool seeded() const noexcept { return seeded_; }

    /// Encrypt one transport-phase frame. `out_cipher` is resized to
    /// `plaintext.size() + kTagBytes`. The send nonce advances by one
    /// per call. Returns `GN_ERR_INVALID_STATE` when not seeded or the
    /// nonce limit has been reached.
    [[nodiscard]] gn_result_t encrypt(
        std::span<const std::uint8_t> plaintext,
        std::vector<std::uint8_t>& out_cipher);

    /// Reserve K send nonces atomically. Returns the base nonce;
    /// jobs[i] uses `base + i`. Used by the kernel-side batch
    /// encrypt path: `drain_send_queue_with_encrypt` reserves K
    /// upfront, dispatches K parallel jobs through
    /// `CryptoWorkerPool`, coalesces ciphertext into the link's
    /// `send_batch`. Single-writer per-conn invariant
    /// (`PerConnQueue::drain_scheduled` CAS) keeps the
    /// reservation race-free across drainers.
    [[nodiscard]] std::uint64_t reserve_send_nonces(std::size_t k) noexcept;

    /// Build a `CryptoWorkerPool::Job` that encrypts @p plaintext
    /// at @p nonce into @p out_cipher. The returned Job borrows
    /// the InlineCrypto's send key for the lifetime of the job —
    /// caller MUST run the job through `pool.run_batch()` before
    /// the InlineCrypto is destroyed. `out_cipher` MUST already
    /// be sized to `plaintext.size() + kTagBytes`.
    [[nodiscard]] CryptoWorkerPool::Job make_encrypt_job(
        std::span<const std::uint8_t> plaintext,
        std::uint64_t                 nonce,
        std::span<std::uint8_t>       out_cipher) const noexcept;

    /// Decrypt one transport-phase frame. The recv nonce advances by
    /// one per call. Returns `GN_ERR_INVALID_ENVELOPE` on AEAD
    /// authentication failure — the kernel treats it as a fatal
    /// per-frame error and the link plugin's failure threshold tears
    /// the connection down.
    [[nodiscard]] gn_result_t decrypt(
        std::span<const std::uint8_t> ciphertext,
        std::vector<std::uint8_t>& out_plaintext);

    /// Reserve K recv nonces atomically. Returns the base nonce;
    /// jobs[i] uses `base + i`. Mirrors `reserve_send_nonces`. The
    /// single-writer per-conn invariant (only one inbound drain runs
    /// per `SecuritySession` at a time, serialised by the connection's
    /// strand) keeps the reservation race-free against concurrent
    /// receive paths on the same session.
    [[nodiscard]] std::uint64_t reserve_recv_nonces(std::size_t k) noexcept;

    /// Build a `CryptoWorkerPool::Job` that decrypts @p ciphertext
    /// at @p nonce into @p out_plain. The Job stores the AEAD
    /// success/failure flag into `result_len` — `0` means
    /// authentication failure, otherwise the plaintext length.
    /// `out_plain` MUST already be sized to
    /// `ciphertext.size() - kTagBytes`.
    [[nodiscard]] CryptoWorkerPool::Job make_decrypt_job(
        std::span<const std::uint8_t> ciphertext,
        std::uint64_t                 nonce,
        std::span<std::uint8_t>       out_plain) const noexcept;

    [[nodiscard]] std::uint64_t send_nonce() const noexcept {
        return send_nonce_.load(std::memory_order_relaxed);
    }
    [[nodiscard]] std::uint64_t recv_nonce() const noexcept {
        return recv_nonce_.load(std::memory_order_relaxed);
    }

    /// Bench-only seam: zero send + recv keys and flip `seeded_`
    /// back to false so subsequent `encrypt`/`decrypt` calls land
    /// `GN_ERR_INVALID_STATE` (the caller — `SecuritySession` —
    /// then falls through to the provider vtable, which is a
    /// copy-through for `gn.security.null`).
    ///
    /// The inline-crypto half of the post-handshake Noise→Null
    /// handoff PoC in `bench/showcase` §B.3. The hook is
    /// gated through `SecuritySession::_test_clear_inline_crypto`,
    /// which is compiled in only when the build defines
    /// `GOODNET_BENCH_SHOWCASE`. Default builds drop the caller
    /// entirely, so nothing in the kernel reaches this method.
    void clear_for_test() noexcept;

private:
    std::uint8_t               send_key_[kKeyBytes]{};
    std::uint8_t               recv_key_[kKeyBytes]{};
    std::atomic<std::uint64_t> send_nonce_{0};
    std::atomic<std::uint64_t> recv_nonce_{0};
    bool                       seeded_{false};
    bool                       datagram_mode_{false};
    ReplayWindow               recv_window_;
};

} // namespace gn::core
