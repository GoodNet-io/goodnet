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

/// Per-connection symmetric AEAD state. One direction is keyed for
/// send, the other for receive; the counterpart on the peer mirrors
/// the assignment so frames flow under the same `(key, nonce)`
/// schedule both ways.
class InlineCrypto {
public:
    static constexpr std::size_t  kKeyBytes   = GN_CIPHER_KEY_BYTES;
    static constexpr std::size_t  kNonceBytes = GN_CIPHER_NONCE_BYTES;
    static constexpr std::size_t  kTagBytes   = GN_AEAD_TAG_BYTES;

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
    /// This is the inline-crypto half of the post-handshake
    /// Noise→Null handoff PoC in `bench/showcase` (track Б, §B.3).
    /// Production-shape kernel-side handoff is a v1.x followup;
    /// for now this hook is gated through
    /// `SecuritySession::_test_clear_inline_crypto`, which checks
    /// the `GN_SHOWCASE_ALLOW_INLINE_DOWNGRADE=1` env var before
    /// calling here. Without the env var, nothing in the build
    /// reaches this method.
    void clear_for_test() noexcept;

private:
    std::uint8_t              send_key_[kKeyBytes]{};
    std::uint8_t              recv_key_[kKeyBytes]{};
    std::atomic<std::uint64_t> send_nonce_{0};
    std::atomic<std::uint64_t> recv_nonce_{0};
    bool                      seeded_{false};
};

} // namespace gn::core
