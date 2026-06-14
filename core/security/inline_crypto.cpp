/// @file   core/security/inline_crypto.cpp
/// @brief  Implementation of the kernel-side inline AEAD path.

#include "inline_crypto.hpp"

#include <sodium.h>

#include <cstring>

namespace gn::core {

namespace {

/// Build the 12-byte ChaCha20-Poly1305 IETF nonce from the Noise
/// 64-bit counter per `plugins/security/noise/cipher.hpp` — 4 zero
/// bytes followed by the counter in little-endian. Matches the
/// noise plugin's `CipherState::encrypt_with_ad` so the inline path
/// and the vtable path are wire-compatible should a session ever
/// fall back to the provider mid-flight.
inline void build_nonce(std::uint64_t n,
                        std::uint8_t  out[InlineCrypto::kNonceBytes]) noexcept {
    std::memset(out, 0, InlineCrypto::kNonceBytes);
    std::memcpy(out + 4, &n, sizeof(n));
}

/// Constant-time check that the keys struct carries non-zero key
/// material. A provider that opts out of inline crypto exports an
/// all-zero struct (per `null_export_transport_keys` in
/// `plugins/security/null/null.cpp`).
[[nodiscard]] bool keys_nonzero(const gn_handshake_keys_t& k) noexcept {
    std::uint8_t acc = 0;
    for (std::size_t i = 0; i < InlineCrypto::kKeyBytes; ++i) {
        acc |= k.send_cipher_key[i];
        acc |= k.recv_cipher_key[i];
    }
    return acc != 0;
}

/// `CryptoWorkerPool::JobFn` for ChaCha20-Poly1305 IETF AEAD
/// encrypt. Reads `key`, `nonce`, `plain`, writes `out`+tag and
/// stores the ciphertext length into `result_len`. Stamped into
/// every Job built by `make_encrypt_job`.
void chacha20poly1305_encrypt_job(CryptoWorkerPool::Job& job) noexcept {
    std::uint8_t nonce_buf[InlineCrypto::kNonceBytes];
    build_nonce(job.nonce, nonce_buf);
    unsigned long long clen = 0;
    crypto_aead_chacha20poly1305_ietf_encrypt(
        job.out.data(), &clen,
        job.plain.data(), job.plain.size(),
        /*ad*/    nullptr, 0,
        /*nsec*/  nullptr,
        nonce_buf, job.key);
    job.result_len = static_cast<std::size_t>(clen);
}

/// `CryptoWorkerPool::JobFn` for ChaCha20-Poly1305 IETF AEAD
/// decrypt. Reads `key`, `nonce`, `plain` (ciphertext span),
/// writes plaintext into `out`. Stores the plaintext length into
/// `result_len`; AEAD authentication failure is reported as
/// `static_cast<std::size_t>(-1)` because a successful decrypt of
/// a tag-only ciphertext legitimately produces zero-byte plaintext.
void chacha20poly1305_decrypt_job(CryptoWorkerPool::Job& job) noexcept {
    std::uint8_t nonce_buf[InlineCrypto::kNonceBytes];
    build_nonce(job.nonce, nonce_buf);
    unsigned long long mlen = 0;
    const int rc = crypto_aead_chacha20poly1305_ietf_decrypt(
        job.out.data(), &mlen,
        /*nsec*/ nullptr,
        job.plain.data(), job.plain.size(),
        /*ad*/   nullptr, 0,
        nonce_buf, job.key);
    if (rc != 0) {
        job.result_len = static_cast<std::size_t>(-1);
        return;
    }
    job.result_len = static_cast<std::size_t>(mlen);
}

} // namespace

bool ReplayWindow::check_and_record(std::uint64_t n) noexcept {
    if (n > base) {
        const std::uint64_t diff = n - base;
        bits = (diff >= kSize)
            ? std::uint64_t(1)
            : ((bits << diff) | std::uint64_t(1));
        base = n;
        return true;
    }
    const std::uint64_t back = base - n;
    if (back >= kSize) return false;
    const std::uint64_t bit = std::uint64_t(1) << back;
    if (bits & bit) return false;
    bits |= bit;
    return true;
}

InlineCrypto::~InlineCrypto() {
    sodium_memzero(send_key_, sizeof(send_key_));
    sodium_memzero(recv_key_, sizeof(recv_key_));
}

void InlineCrypto::enable_datagram_mode() noexcept {
    datagram_mode_ = true;
}

void InlineCrypto::clear_for_test() noexcept {
    /// Zero key material the same way ~InlineCrypto does, but
    /// drop `seeded_` so the next `encrypt`/`decrypt` returns
    /// `GN_ERR_INVALID_STATE` and the session walks the vtable
    /// fallback. Nonces left untouched — they're meaningless once
    /// keys are zero and resetting them would mask a bench bug
    /// where the session illegally re-encrypts after the
    /// handoff. See `inline_crypto.hpp` for the env-var gate.
    sodium_memzero(send_key_, sizeof(send_key_));
    sodium_memzero(recv_key_, sizeof(recv_key_));
    seeded_ = false;
}

bool InlineCrypto::seed(const gn_handshake_keys_t& keys) noexcept {
    if (!keys_nonzero(keys)) return false;
    std::memcpy(send_key_, keys.send_cipher_key, kKeyBytes);
    std::memcpy(recv_key_, keys.recv_cipher_key, kKeyBytes);
    send_nonce_.store(keys.initial_send_nonce, std::memory_order_release);
    recv_nonce_.store(keys.initial_recv_nonce, std::memory_order_release);
    if (datagram_mode_) {
        recv_window_.base = keys.initial_recv_nonce;
        recv_window_.bits = 0;
    }
    seeded_ = true;
    return true;
}

gn_result_t InlineCrypto::encrypt(
    std::span<const std::uint8_t> plaintext,
    std::vector<std::uint8_t>& out_cipher) {
    if (!seeded_) return GN_ERR_INVALID_STATE;

    const auto nonce = send_nonce_.fetch_add(1, std::memory_order_relaxed);
    if (nonce >= kRekeyNonceLimit) return GN_ERR_INVALID_STATE;

    std::uint8_t nonce_buf[kNonceBytes];
    build_nonce(nonce, nonce_buf);

    if (datagram_mode_) {
        out_cipher.resize(kNonceWireBytes + plaintext.size() + kTagBytes);
        std::memcpy(out_cipher.data(), &nonce, sizeof(nonce));
        unsigned long long clen = 0;
        crypto_aead_chacha20poly1305_ietf_encrypt(
            out_cipher.data() + kNonceWireBytes, &clen,
            plaintext.data(), plaintext.size(),
            /*ad*/   nullptr, 0,
            /*nsec*/ nullptr,
            nonce_buf, send_key_);
        out_cipher.resize(kNonceWireBytes + static_cast<std::size_t>(clen));
        return GN_OK;
    }

    out_cipher.resize(plaintext.size() + kTagBytes);
    unsigned long long clen = 0;
    crypto_aead_chacha20poly1305_ietf_encrypt(
        out_cipher.data(), &clen,
        plaintext.data(), plaintext.size(),
        /*ad*/    nullptr, 0,
        /*nsec*/  nullptr,
        nonce_buf, send_key_);
    out_cipher.resize(static_cast<std::size_t>(clen));
    return GN_OK;
}

std::uint64_t InlineCrypto::reserve_send_nonces(std::size_t k) noexcept {
    /// Atomic reservation — drainer that wins
    /// `PerConnQueue::drain_scheduled` is the only caller per
    /// connection; concurrent reservations across distinct
    /// connections do not race because each `InlineCrypto` is
    /// per-connection. The single-writer invariant from
    /// `link.en.md §4` is preserved.
    return send_nonce_.fetch_add(k, std::memory_order_relaxed);
}

CryptoWorkerPool::Job InlineCrypto::make_encrypt_job(
    std::span<const std::uint8_t> plaintext,
    std::uint64_t                 nonce,
    std::span<std::uint8_t>       out_cipher) const noexcept {
    CryptoWorkerPool::Job job{};
    job.fn    = &chacha20poly1305_encrypt_job;
    job.key   = send_key_;
    job.nonce = nonce;
    job.plain = plaintext;
    job.out   = out_cipher;
    return job;
}

std::uint64_t InlineCrypto::reserve_recv_nonces(std::size_t k) noexcept {
    /// Symmetric to `reserve_send_nonces`. Per-conn `SecuritySession`
    /// is single-writer on the inbound strand, so the reservation
    /// races only against itself across concurrent connections —
    /// each has its own `InlineCrypto` instance.
    return recv_nonce_.fetch_add(k, std::memory_order_relaxed);
}

CryptoWorkerPool::Job InlineCrypto::make_decrypt_job(
    std::span<const std::uint8_t> ciphertext,
    std::uint64_t                 nonce,
    std::span<std::uint8_t>       out_plain) const noexcept {
    CryptoWorkerPool::Job job{};
    job.fn    = &chacha20poly1305_decrypt_job;
    job.key   = recv_key_;
    job.nonce = nonce;
    job.plain = ciphertext;
    job.out   = out_plain;
    return job;
}

gn_result_t InlineCrypto::decrypt(
    std::span<const std::uint8_t> ciphertext,
    std::vector<std::uint8_t>& out_plaintext) {
    if (!seeded_) return GN_ERR_INVALID_STATE;

    if (datagram_mode_) {
        if (ciphertext.size() < kNonceWireBytes + kTagBytes)
            return GN_ERR_INVALID_ENVELOPE;

        std::uint64_t nonce = 0;
        std::memcpy(&nonce, ciphertext.data(), sizeof(nonce));

        if (!recv_window_.check_and_record(nonce))
            return GN_ERR_INVALID_ENVELOPE;

        std::uint8_t nonce_buf[kNonceBytes];
        build_nonce(nonce, nonce_buf);

        const auto cipher_span = ciphertext.subspan(kNonceWireBytes);
        out_plaintext.resize(cipher_span.size() - kTagBytes);
        unsigned long long mlen = 0;
        if (crypto_aead_chacha20poly1305_ietf_decrypt(
                out_plaintext.data(), &mlen,
                /*nsec*/ nullptr,
                cipher_span.data(), cipher_span.size(),
                /*ad*/   nullptr, 0,
                nonce_buf, recv_key_) != 0) {
            out_plaintext.clear();
            return GN_ERR_INVALID_ENVELOPE;
        }
        out_plaintext.resize(static_cast<std::size_t>(mlen));
        return GN_OK;
    }

    if (ciphertext.size() < kTagBytes) return GN_ERR_INVALID_ENVELOPE;

    const auto nonce = recv_nonce_.fetch_add(1, std::memory_order_relaxed);
    if (nonce >= kRekeyNonceLimit) return GN_ERR_INVALID_STATE;

    std::uint8_t nonce_buf[kNonceBytes];
    build_nonce(nonce, nonce_buf);

    out_plaintext.resize(ciphertext.size() - kTagBytes);
    unsigned long long mlen = 0;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            out_plaintext.data(), &mlen,
            /*nsec*/ nullptr,
            ciphertext.data(), ciphertext.size(),
            /*ad*/   nullptr, 0,
            nonce_buf, recv_key_) != 0) {
        out_plaintext.clear();
        return GN_ERR_INVALID_ENVELOPE;
    }
    out_plaintext.resize(static_cast<std::size_t>(mlen));
    return GN_OK;
}

} // namespace gn::core
