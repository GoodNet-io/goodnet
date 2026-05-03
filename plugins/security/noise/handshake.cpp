// SPDX-License-Identifier: Apache-2.0
/// @file   plugins/security/noise/handshake.cpp
/// @brief  Noise XX state machine — initiator + responder pattern
///         on libsodium primitives.

#include "handshake.hpp"

#include <sodium.h>

#include <cstring>

namespace gn::noise {
namespace {

constexpr int xx_total_steps = 3;

/// X25519 ECDH. Returns the 32-byte shared secret, or nullopt if the
/// peer pk is the all-zero point (libsodium signals an error).
[[nodiscard]] std::optional<std::array<std::uint8_t, DH_OUTPUT_BYTES>>
dh(const PrivateKey& sk, const PublicKey& pk) noexcept {
    std::array<std::uint8_t, DH_OUTPUT_BYTES> out{};
    if (crypto_scalarmult(out.data(), sk.data(), pk.data()) != 0) {
        return std::nullopt;
    }
    return out;
}

void zeroize_key(std::array<std::uint8_t, DH_OUTPUT_BYTES>& v) noexcept {
    sodium_memzero(v.data(), DH_OUTPUT_BYTES);
}

} // namespace

Keypair generate_keypair() {
    Keypair kp;
    randombytes_buf(kp.sk.data(), DH_PRIVATE_KEY_BYTES);
    crypto_scalarmult_base(kp.pk.data(), kp.sk.data());
    return kp;
}

const char* protocol_name(Pattern p) noexcept {
    switch (p) {
        case Pattern::XX: return "Noise_XX_25519_ChaChaPoly_BLAKE2b";
    }
    return "";
}

HandshakeState::HandshakeState(Pattern pattern,
                                bool initiator,
                                const Keypair& static_keys)
    : pattern_(pattern),
      initiator_(initiator),
      steps_total_(xx_total_steps),
      s_sk_(static_keys.sk),
      s_pk_(static_keys.pk) {
    symmetric_.initialize(protocol_name(pattern));
}

HandshakeState::~HandshakeState() {
    sodium_memzero(s_sk_.data(), DH_PRIVATE_KEY_BYTES);
    sodium_memzero(e_sk_.data(), DH_PRIVATE_KEY_BYTES);
    sodium_memzero(s_pk_.data(), DH_PUBLIC_KEY_BYTES);
    sodium_memzero(e_pk_.data(), DH_PUBLIC_KEY_BYTES);
    sodium_memzero(rs_.data(),   DH_PUBLIC_KEY_BYTES);
    sodium_memzero(re_.data(),   DH_PUBLIC_KEY_BYTES);
}

namespace {

/// Move-time wipe — the moved-from source must not retain bytes
/// after the move ends its purpose. SymmetricState handles its own
/// chaining key and hash through its own move ops; this helper
/// covers the DH key arrays embedded in HandshakeState directly.
void wipe_dh_arrays(PrivateKey& s_sk, PublicKey& s_pk,
                     PrivateKey& e_sk, PublicKey& e_pk,
                     PublicKey&  rs,   PublicKey& re) noexcept {
    sodium_memzero(s_sk.data(), DH_PRIVATE_KEY_BYTES);
    sodium_memzero(s_pk.data(), DH_PUBLIC_KEY_BYTES);
    sodium_memzero(e_sk.data(), DH_PRIVATE_KEY_BYTES);
    sodium_memzero(e_pk.data(), DH_PUBLIC_KEY_BYTES);
    sodium_memzero(rs.data(),   DH_PUBLIC_KEY_BYTES);
    sodium_memzero(re.data(),   DH_PUBLIC_KEY_BYTES);
}

} // namespace

HandshakeState::HandshakeState(HandshakeState&& other) noexcept
    : pattern_(other.pattern_),
      initiator_(other.initiator_),
      step_(other.step_),
      steps_total_(other.steps_total_),
      symmetric_(std::move(other.symmetric_)),
      s_sk_(other.s_sk_),
      s_pk_(other.s_pk_),
      e_sk_(other.e_sk_),
      e_pk_(other.e_pk_),
      rs_(other.rs_),
      re_(other.re_),
      rs_known_(other.rs_known_) {
    wipe_dh_arrays(other.s_sk_, other.s_pk_,
                    other.e_sk_, other.e_pk_,
                    other.rs_,   other.re_);
}

HandshakeState& HandshakeState::operator=(HandshakeState&& other) noexcept {
    if (this != &other) {
        wipe_dh_arrays(s_sk_, s_pk_, e_sk_, e_pk_, rs_, re_);
        pattern_     = other.pattern_;
        initiator_   = other.initiator_;
        step_        = other.step_;
        steps_total_ = other.steps_total_;
        symmetric_   = std::move(other.symmetric_);
        s_sk_        = other.s_sk_;
        s_pk_        = other.s_pk_;
        e_sk_        = other.e_sk_;
        e_pk_        = other.e_pk_;
        rs_          = other.rs_;
        re_          = other.re_;
        rs_known_    = other.rs_known_;
        wipe_dh_arrays(other.s_sk_, other.s_pk_,
                        other.e_sk_, other.e_pk_,
                        other.rs_,   other.re_);
    }
    return *this;
}

bool HandshakeState::is_complete() const noexcept {
    return step_ >= steps_total_;
}

std::optional<std::vector<std::uint8_t>>
HandshakeState::write_message(std::span<const std::uint8_t> payload) {
    if (is_complete()) return std::nullopt;

    std::vector<std::uint8_t> out;
    out.reserve(DH_PUBLIC_KEY_BYTES * 2 + AEAD_TAG_BYTES * 3 + payload.size());

    auto write_e = [&]() {
        Keypair e = generate_keypair();
        e_pk_ = e.pk;
        e_sk_ = e.sk;
        out.insert(out.end(), e_pk_.begin(), e_pk_.end());
        symmetric_.mix_hash(
            std::span<const std::uint8_t>(e_pk_.data(), DH_PUBLIC_KEY_BYTES));
    };

    auto mix_dh = [&](const PrivateKey& sk, const PublicKey& pk) -> bool {
        auto shared = dh(sk, pk);
        if (!shared) return false;
        symmetric_.mix_key(
            std::span<const std::uint8_t>(shared->data(), DH_OUTPUT_BYTES));
        zeroize_key(*shared);
        return true;
    };

    auto encrypt_static = [&]() {
        auto enc = symmetric_.encrypt_and_hash(
            std::span<const std::uint8_t>(s_pk_.data(), DH_PUBLIC_KEY_BYTES));
        out.insert(out.end(), enc.begin(), enc.end());
    };

    auto encrypt_payload = [&]() {
        auto enc = symmetric_.encrypt_and_hash(payload);
        out.insert(out.end(), enc.begin(), enc.end());
    };

    switch (step_) {
        case 0: {
            // -> e
            write_e();
            encrypt_payload();
            break;
        }
        case 1: {
            // <- e, ee, s, es
            write_e();
            if (!mix_dh(e_sk_, re_)) return std::nullopt;          // ee
            encrypt_static();                                      // s
            if (!mix_dh(s_sk_, re_)) return std::nullopt;          // es (responder)
            encrypt_payload();
            break;
        }
        case 2: {
            // -> s, se
            encrypt_static();                                      // s
            if (!mix_dh(s_sk_, re_)) return std::nullopt;          // se (initiator)
            encrypt_payload();
            break;
        }
        default: return std::nullopt;
    }

    ++step_;
    return out;
}

std::optional<std::vector<std::uint8_t>>
HandshakeState::read_message(std::span<const std::uint8_t> message) {
    if (is_complete()) return std::nullopt;

    std::size_t offset = 0;

    auto read_e = [&]() -> bool {
        if (message.size() < offset + DH_PUBLIC_KEY_BYTES) return false;
        std::memcpy(re_.data(), message.data() + offset, DH_PUBLIC_KEY_BYTES);
        offset += DH_PUBLIC_KEY_BYTES;
        symmetric_.mix_hash(
            std::span<const std::uint8_t>(re_.data(), DH_PUBLIC_KEY_BYTES));
        return true;
    };

    auto read_encrypted_static = [&]() -> bool {
        const std::size_t enc_len = DH_PUBLIC_KEY_BYTES + AEAD_TAG_BYTES;
        if (message.size() < offset + enc_len) return false;
        auto plain = symmetric_.decrypt_and_hash(
            std::span<const std::uint8_t>(message.data() + offset, enc_len));
        if (!plain || plain->size() != DH_PUBLIC_KEY_BYTES) return false;
        std::memcpy(rs_.data(), plain->data(), DH_PUBLIC_KEY_BYTES);
        rs_known_ = true;
        offset += enc_len;
        return true;
    };

    auto mix_dh = [&](const PrivateKey& sk, const PublicKey& pk) -> bool {
        auto shared = dh(sk, pk);
        if (!shared) return false;
        symmetric_.mix_key(
            std::span<const std::uint8_t>(shared->data(), DH_OUTPUT_BYTES));
        zeroize_key(*shared);
        return true;
    };

    switch (step_) {
        case 0: {
            // -> e
            if (!read_e()) return std::nullopt;
            break;
        }
        case 1: {
            // <- e, ee, s, es
            if (!read_e()) return std::nullopt;
            if (!mix_dh(e_sk_, re_)) return std::nullopt;          // ee
            if (!read_encrypted_static()) return std::nullopt;     // s
            if (!mix_dh(e_sk_, rs_)) return std::nullopt;          // es (initiator)
            break;
        }
        case 2: {
            // -> s, se
            if (!read_encrypted_static()) return std::nullopt;     // s
            if (!mix_dh(e_sk_, rs_)) return std::nullopt;          // se (responder)
            break;
        }
        default: return std::nullopt;
    }

    auto plain = symmetric_.decrypt_and_hash(
        std::span<const std::uint8_t>(message.data() + offset,
                                       message.size() - offset));
    if (!plain) return std::nullopt;

    ++step_;
    return plain;
}

HandshakeState::TransportPair HandshakeState::split() {
    /// Per noise-handshake.md §5 clause 4: the long-term static
    /// private key, the ephemeral key pair, and the peer ephemeral
    /// key have no remaining purpose inside the handshake state once
    /// Split has produced the transport ciphers. The wipe runs on
    /// both the success path and the failure path — if the
    /// underlying split primitive throws, the secrets are still
    /// cleared before the exception propagates. The symmetric state
    /// clears its own chaining key inside `symmetric_.split()`.
    auto eager_wipe = [this]() noexcept {
        sodium_memzero(s_sk_.data(), DH_PRIVATE_KEY_BYTES);
        sodium_memzero(e_sk_.data(), DH_PRIVATE_KEY_BYTES);
        sodium_memzero(e_pk_.data(), DH_PUBLIC_KEY_BYTES);
        sodium_memzero(re_.data(),   DH_PUBLIC_KEY_BYTES);
    };

    SymmetricState::SplitPair pair;
    try {
        pair = symmetric_.split();
    } catch (...) {
        eager_wipe();
        throw;
    }

    TransportPair tp;
    if (initiator_) {
        tp.send = std::move(pair.first);
        tp.recv = std::move(pair.second);
    } else {
        tp.send = std::move(pair.second);
        tp.recv = std::move(pair.first);
    }

    eager_wipe();
    return tp;
}

bool HandshakeState::static_secret_zeroised_for_test() const noexcept {
    return sodium_is_zero(s_sk_.data(), DH_PRIVATE_KEY_BYTES) != 0;
}

bool HandshakeState::chaining_key_zeroised_for_test() const noexcept {
    return symmetric_.chaining_key_zeroised_for_test();
}

} // namespace gn::noise
