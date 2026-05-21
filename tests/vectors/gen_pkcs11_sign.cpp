// SPDX-License-Identifier: Apache-2.0
/// @file   tests/vectors/gen_pkcs11_sign.cpp
/// @brief  Generator for `tests/vectors/pkcs11_sign.json`.
///
/// The pkcs11 plugin signs through CKM_EDDSA on a token-resident
/// Ed25519 private key. Without a SoftHSM2 (or a real HSM) the
/// generator cannot drive the real `C_Sign` path. To keep the
/// contract surface testable from cross-language bindings, this
/// generator emits SYNTHETIC vectors:
///
///   - the secret key bytes live in plaintext in the JSON (a real
///     token wouldn't expose them; this is fine for a known-answer
///     test scaffold).
///   - the signature is computed via libsodium's
///     `crypto_sign_detached` on the same input bytes — bit-for-bit
///     identical to what CKM_EDDSA returns per RFC 8032 §5.1.6,
///     which is the PKCS#11 v3.0 contract this plugin implements.
///
/// A binding that uses a real SoftHSM-backed token and provisions
/// the same key with the same CKA_LABEL must produce identical
/// signature bytes. The vector is therefore valid for both
/// libsodium-direct consumers and real-token consumers.

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

struct Sample {
    std::string                tag;
    std::string                key_label;
    std::array<std::uint8_t,32> seed;
    std::vector<std::uint8_t>  input;
};

}  // namespace

int main(int argc, char** argv) {
    if (sodium_init() < 0) {
        std::fprintf(stderr, "sodium_init failed\n");
        return 1;
    }
    if (argc < 2) {
        std::fprintf(stderr, "usage: %s <out.json>\n", argv[0]);
        return 1;
    }

    auto hex = [](std::span<const std::uint8_t> b) {
        return json_escape(gn::vectors::hex_encode(b));
    };

    std::array<std::uint8_t, 32> seed_node = {
        'p','k','c','s','1','1','-','n','o','d','e','-','s','e','e','d',
        '-','-','-','-','-','-','-','-','-','-','-','-','-','-','-','-',
    };
    std::array<std::uint8_t, 32> seed_user = {
        'p','k','c','s','1','1','-','u','s','e','r','-','s','e','e','d',
        '-','-','-','-','-','-','-','-','-','-','-','-','-','-','-','-',
    };

    std::vector<Sample> samples = {
        Sample{
            "node_signs_handshake_hash",
            "goodnet/node-static",
            seed_node,
            // 32-byte synthetic handshake hash, the canonical
            // PKCS#11 sign input shape on a node-static identity.
            std::vector<std::uint8_t>{
                'h','s','-','h','a','s','h','-','3','2','-','b','y','t','e','s',
                '!','-','-','-','-','-','-','-','-','-','-','-','-','-','-','!',
            },
        },
        Sample{
            "user_signs_attestation_payload",
            "goodnet/user-identity",
            seed_user,
            // Synthetic attestation canonical payload (72 bytes:
            // user_pk || device_pk || expiry_be64). Shape matches
            // `core/identity/attestation.cpp::canonical_payload`.
            [] {
                std::vector<std::uint8_t> p(72, 0);
                for (std::size_t i = 0; i < p.size(); ++i) {
                    p[i] = static_cast<std::uint8_t>((i * 7u + 3u) & 0xFFu);
                }
                return p;
            }(),
        },
    };

    std::string body;
    body += "{\n";
    body += "  " + std::string(json_escape("schema")) + ": "
         + json_escape("pkcs11-sign/v1") + ",\n";
    body += "  " + std::string(json_escape("description")) + ": "
         + json_escape(
            "Synthetic PKCS#11 sign-path vectors. Each sample carries "
            "an Ed25519 seed + key_label + input bytes + the expected "
            "raw 64-byte signature per RFC 8032 §5.1.6 (CKM_EDDSA). "
            "A real-token consumer provisions the same seed under the "
            "same CKA_LABEL and verifies its C_Sign output matches.") + ",\n";
    body += "  " + std::string(json_escape("mechanism")) + ": "
         + json_escape("CKM_EDDSA") + ",\n";
    body += "  " + std::string(json_escape("status")) + ": "
         + json_escape("deferred-real-token") + ",\n";
    body += "  " + std::string(json_escape("status_note")) + ": "
         + json_escape("SoftHSM2 unavailable in devShell at vector-build "
                       "time. The signatures are computed by libsodium "
                       "crypto_sign_detached, which is bit-for-bit "
                       "identical to a real CKM_EDDSA token output. "
                       "Once SoftHSM2 lands in devShell, rerun the "
                       "real-token harness and assert equality with "
                       "the same JSON.") + ",\n";
    body += "  " + std::string(json_escape("samples")) + ": [\n";

    for (std::size_t i = 0; i < samples.size(); ++i) {
        const auto& s = samples[i];

        std::uint8_t pk[crypto_sign_PUBLICKEYBYTES];
        std::uint8_t sk[crypto_sign_SECRETKEYBYTES];
        crypto_sign_seed_keypair(pk, sk, s.seed.data());

        std::uint8_t signature[64];
        crypto_sign_detached(signature, nullptr,
                              s.input.data(), s.input.size(),
                              sk);

        // Self-verify so the JSON cannot land with a corrupted sig.
        if (crypto_sign_verify_detached(signature,
                                         s.input.data(), s.input.size(),
                                         pk) != 0) {
            std::fprintf(stderr, "self-verify failed for %s\n", s.tag.c_str());
            return 1;
        }

        body += "    {\n";
        body += "      " + std::string(json_escape("tag")) + ": "
             + json_escape(s.tag) + ",\n";
        body += "      " + std::string(json_escape("key_label")) + ": "
             + json_escape(s.key_label) + ",\n";
        body += "      " + std::string(json_escape("seed")) + ": "
             + hex(s.seed) + ",\n";
        body += "      " + std::string(json_escape("public_key")) + ": "
             + hex(pk) + ",\n";
        body += "      " + std::string(json_escape("input_bytes")) + ": "
             + hex(s.input) + ",\n";
        body += "      " + std::string(json_escape("input_size")) + ": "
             + std::to_string(s.input.size()) + ",\n";
        body += "      " + std::string(json_escape("signature")) + ": "
             + hex(signature) + ",\n";
        body += "      " + std::string(json_escape("signature_size")) + ": 64\n";
        body += "    }" + std::string(i + 1 < samples.size() ? "," : "") + "\n";
    }

    body += "  ]\n";
    body += "}\n";

    std::ofstream out(argv[1]);
    if (!out) {
        std::fprintf(stderr, "cannot open %s\n", argv[1]);
        return 1;
    }
    out << body;
    out.close();

    std::cout << "wrote " << argv[1] << " (" << body.size() << " bytes)\n";
    return 0;
}
