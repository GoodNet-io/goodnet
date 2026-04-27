// SPDX-License-Identifier: Apache-2.0
#include "handshake.hpp"

#include <sodium.h>

#include <cstring>

namespace gn::noise {
namespace {

constexpr int xx_total_steps = 3;
constexpr int ik_total_steps = 2;

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
        case Pattern::IK: return "Noise_IK_25519_ChaChaPoly_BLAKE2b";
    }
    return "";
}

HandshakeState::HandshakeState(Pattern pattern,
                                bool initiator,
                                const Keypair& static_keys,
                                std::optional<PublicKey> remote_static_pk)
    : pattern_(pattern),
      initiator_(initiator),
      steps_total_(pattern == Pattern::IK ? ik_total_steps : xx_total_steps),
      s_sk_(static_keys.sk),
      s_pk_(static_keys.pk) {
    symmetric_.initialize(protocol_name(pattern));

    if (pattern == Pattern::IK) {
        if (initiator) {
            // Initiator presets responder's static pk as the IK pre-message.
            if (!remote_static_pk) {
                // Defensive: contract requires it; default to all-zero so a
                // misuse fails the first DH rather than corrupts state.
                rs_.fill(0);
            } else {
                rs_ = *remote_static_pk;
                rs_known_ = true;
            }
            symmetric_.mix_hash(
                std::span<const std::uint8_t>(rs_.data(), DH_PUBLIC_KEY_BYTES));
        } else {
            // Responder mixes its own static pk as the pre-message.
            symmetric_.mix_hash(
                std::span<const std::uint8_t>(s_pk_.data(), DH_PUBLIC_KEY_BYTES));
        }
    }
}

HandshakeState::~HandshakeState() {
    sodium_memzero(s_sk_.data(), DH_PRIVATE_KEY_BYTES);
    sodium_memzero(e_sk_.data(), DH_PRIVATE_KEY_BYTES);
    sodium_memzero(s_pk_.data(), DH_PUBLIC_KEY_BYTES);
    sodium_memzero(e_pk_.data(), DH_PUBLIC_KEY_BYTES);
    sodium_memzero(rs_.data(),   DH_PUBLIC_KEY_BYTES);
    sodium_memzero(re_.data(),   DH_PUBLIC_KEY_BYTES);
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

    if (pattern_ == Pattern::XX) {
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
    } else {  // Pattern::IK
        switch (step_) {
            case 0: {
                // -> e, es, s, ss   (initiator)
                write_e();
                if (!mix_dh(e_sk_, rs_)) return std::nullopt;          // es
                encrypt_static();                                      // s
                if (!mix_dh(s_sk_, rs_)) return std::nullopt;          // ss
                encrypt_payload();
                break;
            }
            case 1: {
                // <- e, ee, se      (responder)
                write_e();
                if (!mix_dh(e_sk_, re_)) return std::nullopt;          // ee
                if (!mix_dh(s_sk_, re_)) return std::nullopt;          // se (responder)
                encrypt_payload();
                break;
            }
            default: return std::nullopt;
        }
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

    if (pattern_ == Pattern::XX) {
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
    } else {  // Pattern::IK
        switch (step_) {
            case 0: {
                // -> e, es, s, ss   (responder reads)
                if (!read_e()) return std::nullopt;
                if (!mix_dh(s_sk_, re_)) return std::nullopt;          // es (responder side)
                if (!read_encrypted_static()) return std::nullopt;     // s
                if (!mix_dh(s_sk_, rs_)) return std::nullopt;          // ss
                break;
            }
            case 1: {
                // <- e, ee, se      (initiator reads)
                if (!read_e()) return std::nullopt;
                if (!mix_dh(e_sk_, re_)) return std::nullopt;          // ee
                if (!mix_dh(e_sk_, rs_)) return std::nullopt;          // se (initiator side: peer's s mixed with our e)
                break;
            }
            default: return std::nullopt;
        }
    }

    auto plain = symmetric_.decrypt_and_hash(
        std::span<const std::uint8_t>(message.data() + offset,
                                       message.size() - offset));
    if (!plain) return std::nullopt;

    ++step_;
    return plain;
}

HandshakeState::TransportPair HandshakeState::split() {
    auto pair = symmetric_.split();
    TransportPair tp;
    if (initiator_) {
        tp.send = std::move(pair.first);
        tp.recv = std::move(pair.second);
    } else {
        tp.send = std::move(pair.second);
        tp.recv = std::move(pair.first);
    }

    // Ephemeral keys are no longer needed; zeroise eagerly to shorten
    // their lifetime in process memory.
    sodium_memzero(e_sk_.data(), DH_PRIVATE_KEY_BYTES);
    sodium_memzero(e_pk_.data(), DH_PUBLIC_KEY_BYTES);
    sodium_memzero(re_.data(),   DH_PUBLIC_KEY_BYTES);
    return tp;
}

} // namespace gn::noise
