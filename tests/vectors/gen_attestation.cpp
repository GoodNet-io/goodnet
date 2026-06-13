// SPDX-License-Identifier: Apache-2.0
/// @file   tests/vectors/gen_attestation.cpp
/// @brief  Generator for `tests/vectors/attestation.json`.
///
/// Per `docs/contracts/attestation.en.md` §2 the wire payload is
/// 232 bytes:
///   - 136 bytes attestation cert (user_pk||device_pk||expiry_be||sig)
///   - 32  bytes binding = current session's handshake_hash
///   - 64  bytes Ed25519 signature over (cert || binding) signed by
///         the local DEVICE secret key
///
/// Fixed seeds for the user keypair, device keypair, peer pubkey,
/// and handshake_hash. The output JSON contains every input + the
/// 232-byte payload (hex) + a known-good verification verdict.

#include "hex_util.hpp"

#include <sodium.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <span>
#include <string>
#include <vector>

namespace {

constexpr std::size_t kAttestationBytes  = 136;
constexpr std::size_t kPayloadBytes      = 232;
constexpr std::size_t kPublicKeyBytes    = 32;
constexpr std::size_t kSignatureBytes    = 64;

std::string json_escape(std::string_view s) {
    std::string out;
    out.reserve(s.size() + 2);
    out.push_back('"');
    for (char c : s) {
        if (c == '"' || c == '\\') out.push_back('\\');
        out.push_back(c);
    }
    out.push_back('"');
    return out;
}

void write_be64(std::uint8_t out[8], std::uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        out[7 - i] = static_cast<std::uint8_t>((v >> (i * 8)) & 0xFFu);
    }
}

}  // namespace

int main(int argc, char** argv) {
    if (sodium_init() < 0) {
        (void)std::fprintf(stderr, "sodium_init failed\n");
        return 1;
    }
    if (argc < 2) {
        (void)std::fprintf(stderr, "usage: %s <out.json>\n", argv[0]);
        return 1;
    }

    // Pinned seeds. Ed25519 secret key is derived deterministically
    // by `crypto_sign_seed_keypair` from the 32-byte seed.
    const std::array<std::uint8_t, 32> kUserSeed = {
        'a','t','t','e','s','t','-','u','s','e','r','-','s','e','e','d',
        '-','-','-','-','-','-','-','-','-','-','-','-','-','-','-','-',
    };
    const std::array<std::uint8_t, 32> kDeviceSeed = {
        'a','t','t','e','s','t','-','d','e','v','i','c','e','-','s','e',
        'e','d','-','-','-','-','-','-','-','-','-','-','-','-','-','-',
    };
    const std::array<std::uint8_t, 32> kPeerSeed = {
        'a','t','t','e','s','t','-','p','e','e','r','-','s','e','e','d',
        '-','-','-','-','-','-','-','-','-','-','-','-','-','-','-','-',
    };
    const std::array<std::uint8_t, 32> kHandshakeHash = {
        'a','t','t','e','s','t','a','t','i','o','n','-','h','s','-','h',
        'a','s','h','-','b','i','n','d','i','n','g','-','3','2','b','!',
    };
    constexpr std::int64_t kExpiryUnixTs = 2'000'000'000;  // Wed 2033

    std::uint8_t user_pk[crypto_sign_PUBLICKEYBYTES];
    std::uint8_t user_sk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_seed_keypair(user_pk, user_sk, kUserSeed.data());

    std::uint8_t device_pk[crypto_sign_PUBLICKEYBYTES];
    std::uint8_t device_sk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_seed_keypair(device_pk, device_sk, kDeviceSeed.data());

    std::uint8_t peer_pk[crypto_sign_PUBLICKEYBYTES];
    std::uint8_t peer_sk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_seed_keypair(peer_pk, peer_sk, kPeerSeed.data());

    // Step 1: build the canonical 72-byte cert payload, sign it with
    // the user key. Layout matches core/identity/attestation.cpp.
    std::array<std::uint8_t, 72> cert_canonical{};
    std::memcpy(cert_canonical.data(),      user_pk,   kPublicKeyBytes);
    std::memcpy(cert_canonical.data() + 32, device_pk, kPublicKeyBytes);
    write_be64(cert_canonical.data() + 64,
               static_cast<std::uint64_t>(kExpiryUnixTs));

    std::uint8_t cert_signature[kSignatureBytes];
    crypto_sign_detached(cert_signature, /*siglen_p=*/nullptr,
                         cert_canonical.data(), cert_canonical.size(),
                         user_sk);

    // Step 2: serialise the 136-byte cert.
    std::array<std::uint8_t, kAttestationBytes> cert_bytes{};
    std::memcpy(cert_bytes.data(),       user_pk,         kPublicKeyBytes);
    std::memcpy(cert_bytes.data() + 32,  device_pk,       kPublicKeyBytes);
    std::memcpy(cert_bytes.data() + 64,  cert_canonical.data() + 64, 8);
    std::memcpy(cert_bytes.data() + 72,  cert_signature,  kSignatureBytes);

    // Step 3: compose attestation || binding, sign with device sk.
    std::array<std::uint8_t, kAttestationBytes + 32> signed_input{};
    std::memcpy(signed_input.data(), cert_bytes.data(), kAttestationBytes);
    std::memcpy(signed_input.data() + kAttestationBytes,
                kHandshakeHash.data(), 32);

    std::uint8_t outer_signature[kSignatureBytes];
    crypto_sign_detached(outer_signature, /*siglen_p=*/nullptr,
                         signed_input.data(), signed_input.size(),
                         device_sk);

    // Step 4: build the 232-byte wire payload.
    std::array<std::uint8_t, kPayloadBytes> payload{};
    std::memcpy(payload.data(),       cert_bytes.data(),  kAttestationBytes);
    std::memcpy(payload.data() + 136, kHandshakeHash.data(), 32);
    std::memcpy(payload.data() + 168, outer_signature, kSignatureBytes);

    // Verification self-check.
    bool sig_ok = crypto_sign_verify_detached(
        outer_signature,
        signed_input.data(), signed_input.size(),
        device_pk) == 0;
    bool cert_ok = crypto_sign_verify_detached(
        cert_signature,
        cert_canonical.data(), cert_canonical.size(),
        user_pk) == 0;

    // Emit JSON.
    auto hex = [](std::span<const std::uint8_t> b) {
        return json_escape(gn::vectors::hex_encode(b));
    };

    std::string body;
    body += "{\n";
    body += "  " + std::string(json_escape("schema")) + ": "
         + json_escape("attestation/v1") + ",\n";
    body += "  " + std::string(json_escape("description")) + ": "
         + json_escape(
            "Ed25519 attestation payload per docs/contracts/"
            "attestation.en.md §2: 136-byte cert (user_pk||device_pk||"
            "expiry_be64||user-signature) + 32-byte handshake_hash "
            "binding + 64-byte detached signature over (cert||binding) "
            "by the device secret key. msg_id 0x11.") + ",\n";
    body += "  " + std::string(json_escape("system_msg_id")) + ": 17,\n";
    body += "  " + std::string(json_escape("user_seed"))     + ": " + hex(kUserSeed)   + ",\n";
    body += "  " + std::string(json_escape("device_seed"))   + ": " + hex(kDeviceSeed) + ",\n";
    body += "  " + std::string(json_escape("peer_seed"))     + ": " + hex(kPeerSeed)   + ",\n";
    body += "  " + std::string(json_escape("user_pk"))       + ": " + hex(user_pk)     + ",\n";
    body += "  " + std::string(json_escape("device_pk"))     + ": " + hex(device_pk)   + ",\n";
    body += "  " + std::string(json_escape("peer_pk"))       + ": " + hex(peer_pk)     + ",\n";
    body += "  " + std::string(json_escape("expiry_unix_ts")) + ": "
         + std::to_string(kExpiryUnixTs) + ",\n";
    body += "  " + std::string(json_escape("handshake_hash"))    + ": " + hex(kHandshakeHash) + ",\n";
    body += "  " + std::string(json_escape("cert_canonical_72")) + ": " + hex(cert_canonical) + ",\n";
    body += "  " + std::string(json_escape("cert_user_signature")) + ": " + hex(cert_signature) + ",\n";
    body += "  " + std::string(json_escape("cert_136"))             + ": " + hex(cert_bytes)     + ",\n";
    body += "  " + std::string(json_escape("device_signature"))     + ": " + hex(outer_signature) + ",\n";
    body += "  " + std::string(json_escape("payload_232"))          + ": " + hex(payload)         + ",\n";
    body += "  " + std::string(json_escape("verify_cert_under_user_pk")) + ": "
         + (cert_ok ? "true" : "false") + ",\n";
    body += "  " + std::string(json_escape("verify_signature_under_device_pk")) + ": "
         + (sig_ok ? "true" : "false") + "\n";
    body += "}\n";

    std::ofstream out(argv[1]);
    if (!out) {
        (void)std::fprintf(stderr, "cannot open %s\n", argv[1]);
        return 1;
    }
    out << body;
    out.close();

    std::cout << "wrote " << argv[1] << " (" << body.size() << " bytes)\n";
    return 0;
}
