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
/// all-zero struct (per `plugins/security/null/null.cpp:74`).
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

} // namespace

InlineCrypto::~InlineCrypto() {
    sodium_memzero(send_key_, sizeof(send_key_));
    sodium_memzero(recv_key_, sizeof(recv_key_));
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
    seeded_ = true;
    return true;
}

gn_result_t InlineCrypto::encrypt(
    std::span<const std::uint8_t> plaintext,
    std::vector<std::uint8_t>& out_cipher) {
    if (!seeded_) return GN_ERR_INVALID_STATE;

    /// `fetch_add` serialises concurrent encrypts on the same
    /// connection so two callers never share a nonce — even when
    /// `host_api->send` is invoked from multiple plugin threads at
    /// once before TCP's strand serialises the byte enqueue. Once
    /// any caller crosses the rekey limit the counter stays past
    /// the limit forever, so every subsequent call refuses too.
    const auto nonce = send_nonce_.fetch_add(1, std::memory_order_relaxed);
    if (nonce >= kRekeyNonceLimit) return GN_ERR_INVALID_STATE;

    std::uint8_t nonce_buf[kNonceBytes];
    build_nonce(nonce, nonce_buf);

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
    /// `link.md §4` is preserved.
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

gn_result_t InlineCrypto::decrypt(
    std::span<const std::uint8_t> ciphertext,
    std::vector<std::uint8_t>& out_plaintext) {
    if (!seeded_) return GN_ERR_INVALID_STATE;
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
