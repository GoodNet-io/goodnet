// SPDX-License-Identifier: Apache-2.0
/// @file   tests/vectors/gen_gnet_wire.cpp
/// @brief  Generator for `tests/vectors/gnet_wire.json`.
///
/// Captures three canonical GNET frame shapes:
///   - system attestation envelope, msg_id 0x11, direct mode (flags=0)
///   - baseline user envelope, msg_id 0x100, direct mode (flags=0)
///   - large 64 KiB-class chunk, msg_id 0x200, relay-transit mode
///     (flags=0x03)
///
/// For each frame the JSON records the plaintext frame bytes
/// (what GnetProtocol::frame produces) plus a ChaCha20-Poly1305 IETF
/// encryption under a fixed key + nonce so binding authors can
/// verify both the framing path and the post-Noise transport
/// encryption end-to-end.

#include "deterministic_random.hpp"
#include "hex_util.hpp"

#include "protocol.hpp"
#include "wire.hpp"

#include <sodium.h>

#include <sdk/connection.h>
#include <sdk/cpp/types.hpp>

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

/// Fixed identity pks — same printable-seed construction as the
/// noise XX generator. Generator and consumer derive identical pks.
gn::PublicKey derive_pk(const std::array<std::uint8_t, 32>& seed) {
    gn::PublicKey pk{};
    crypto_scalarmult_base(pk.data(), seed.data());
    return pk;
}

constexpr std::array<std::uint8_t, 32> kLocalStaticSeed = {
    'g','n','e','t','-','l','o','c','a','l','-','p','k','-','s','e',
    'e','d','-','-','-','-','-','-','-','-','-','-','-','-','-','-',
};
constexpr std::array<std::uint8_t, 32> kRemoteStaticSeed = {
    'g','n','e','t','-','r','e','m','o','t','e','-','p','k','-','s',
    'e','e','d','-','-','-','-','-','-','-','-','-','-','-','-','-',
};
constexpr std::array<std::uint8_t, 32> kThirdPartySeed = {
    'g','n','e','t','-','t','h','i','r','d','-','p','a','r','t','y',
    '-','-','-','-','-','-','-','-','-','-','-','-','-','-','-','-',
};

constexpr std::array<std::uint8_t, 32> kFixedAeadKey = {
    'g','n','e','t','-','t','r','a','n','s','p','o','r','t','-','a',
    'e','a','d','-','k','e','y','-','0','1','2','3','4','5','6','7',
};
constexpr std::array<std::uint8_t, 32> kHandshakeHash = {
    'h','a','n','d','s','h','a','k','e','-','h','a','s','h','-','b',
    'i','n','d','i','n','g','-','3','2','-','b','y','t','e','s','!',
};

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

std::string hex_field_inner(std::string_view name,
                            std::span<const std::uint8_t> bytes,
                            int indent) {
    std::string pad(indent, ' ');
    return pad + std::string(json_escape(name)) + ": "
         + json_escape(gn::vectors::hex_encode(bytes));
}

std::vector<std::uint8_t> aead_encrypt(
    const std::array<std::uint8_t, 32>& key,
    std::uint64_t nonce_counter,
    std::span<const std::uint8_t> aad,
    std::span<const std::uint8_t> plaintext)
{
    // Encode the nonce per `plugins/security/noise/docs/handshake.md`
    // §5.1: 4 zero bytes followed by the 64-bit counter, little-endian.
    std::uint8_t nonce[crypto_aead_chacha20poly1305_IETF_NPUBBYTES] = {0};
    for (int i = 0; i < 8; ++i) {
        nonce[4 + i] = static_cast<std::uint8_t>(
            (nonce_counter >> (i * 8)) & 0xFFu);
    }
    std::vector<std::uint8_t> out(plaintext.size()
        + crypto_aead_chacha20poly1305_IETF_ABYTES);
    unsigned long long out_len = 0;
    crypto_aead_chacha20poly1305_ietf_encrypt(
        out.data(), &out_len,
        plaintext.data(), plaintext.size(),
        aad.data(), aad.size(),
        /*nsec=*/nullptr,
        nonce, key.data());
    out.resize(static_cast<std::size_t>(out_len));
    return out;
}

}  // namespace

namespace {

struct Sample {
    std::string                tag;          // JSON name
    std::string                description;  // human-readable
    std::uint32_t              msg_id;
    bool                       relay;        // force EXPLICIT_SENDER+RECEIVER
    bool                       broadcast;    // force BROADCAST mode
    std::vector<std::uint8_t>  payload;
    std::uint64_t              nonce_counter;
};

std::string render_sample(const Sample& s,
                           const gn::PublicKey& local_pk,
                           const gn::PublicKey& remote_pk,
                           const gn::PublicKey& third_party_pk)
{
    using namespace gn::plugins::gnet;

    GnetProtocol layer;
    auto* ctx = gn_ctx_make_for_test(
        local_pk.data(), remote_pk.data(),
        GN_INVALID_ID, GN_TRUST_PEER,
        (s.relay || s.broadcast) ? 1 : 0);
    if (!ctx) {
        std::fprintf(stderr, "ctx_make_for_test failed for %s\n", s.tag.c_str());
        std::exit(1);
    }

    gn_message_t env{};
    env.msg_id = s.msg_id;
    std::memcpy(env.sender_pk, local_pk.data(), 32);
    if (s.broadcast) {
        // ZERO receiver — frame() emits BROADCAST + EXPLICIT_SENDER.
        std::memset(env.receiver_pk, 0, 32);
    } else if (s.relay) {
        // Distinct third-party as receiver → relay-transit mode.
        std::memcpy(env.receiver_pk, third_party_pk.data(), 32);
    } else {
        std::memcpy(env.receiver_pk, remote_pk.data(), 32);
    }
    env.payload      = s.payload.empty() ? nullptr : s.payload.data();
    env.payload_size = s.payload.size();

    auto framed = layer.frame(*ctx, env);
    if (!framed) {
        std::fprintf(stderr, "frame() failed for %s\n", s.tag.c_str());
        gn_ctx_destroy(ctx);
        std::exit(1);
    }
    gn_ctx_destroy(ctx);
    auto cipher = aead_encrypt(kFixedAeadKey, s.nonce_counter,
                                std::span<const std::uint8_t>{},
                                *framed);

    std::string out;
    out += "    " + json_escape(s.tag) + ": {\n";
    out += "      " + json_escape("description") + ": "
         + json_escape(s.description) + ",\n";
    out += "      " + json_escape("msg_id") + ": "
         + std::to_string(s.msg_id) + ",\n";
    out += "      " + json_escape("mode") + ": "
         + json_escape(s.broadcast ? "broadcast"
                       : (s.relay ? "relay-transit" : "direct")) + ",\n";
    out += hex_field_inner("payload", s.payload, 6) + ",\n";
    out += hex_field_inner("frame_bytes", *framed, 6) + ",\n";
    out += "      " + json_escape("aead_nonce_counter") + ": "
         + std::to_string(s.nonce_counter) + ",\n";
    out += hex_field_inner("ciphertext", cipher, 6) + "\n";
    out += "    }";
    return out;
}

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

    const auto local_pk       = derive_pk(kLocalStaticSeed);
    const auto remote_pk      = derive_pk(kRemoteStaticSeed);
    const auto third_party_pk = derive_pk(kThirdPartySeed);

    // Sample payloads.
    std::vector<std::uint8_t> attestation_payload(232);
    for (std::size_t i = 0; i < attestation_payload.size(); ++i) {
        attestation_payload[i] = static_cast<std::uint8_t>(i & 0xFFu);
    }

    std::vector<std::uint8_t> baseline_payload = {
        'b','a','s','e','l','i','n','e','-','p','a','y','l','o','a','d',
        '-','m','s','g','-','0','x','1','0','0','\n',
    };

    // Large chunk — exercise the multi-frame-bytes path. The task
    // spec calls for a 64 KiB chunk; we cap at 4 KiB so the
    // committed JSON stays under the 50 KB in-tree budget (2x hex
    // bloat + AEAD tag overhead pushes a 64 KiB payload past 256
    // KB on disk). Cross-language consumers that need the
    // full-ceiling case regenerate locally with a larger size.
    constexpr std::size_t kLargePayloadBytes = 4096;
    std::vector<std::uint8_t> large_payload(kLargePayloadBytes);
    for (std::size_t i = 0; i < large_payload.size(); ++i) {
        large_payload[i] = static_cast<std::uint8_t>((i * 31u + 7u) & 0xFFu);
    }

    std::vector<Sample> samples = {
        Sample{
            "system_attestation",
            "system msg_id 0x11 — kernel-internal attestation envelope, "
            "232-byte payload, direct (post-Noise) mode",
            0x11u, /*relay=*/false, /*broadcast=*/false,
            attestation_payload, 0u,
        },
        Sample{
            "user_baseline",
            "user msg_id 0x100 — baseline application message, direct mode",
            0x100u, /*relay=*/false, /*broadcast=*/false,
            baseline_payload, 1u,
        },
        Sample{
            "large_chunk_relay",
            "user msg_id 0x200 — relay-transit, 4 KiB payload exercising "
            "the multi-frame-bytes path with EXPLICIT_SENDER + "
            "EXPLICIT_RECEIVER. The full 65458-byte ceiling case is "
            "regeneratable locally; capped here so the in-tree JSON "
            "stays under 50 KB per the test_vectors contract.",
            0x200u, /*relay=*/true, /*broadcast=*/false,
            large_payload, 2u,
        },
    };

    std::string body;
    body += "{\n";
    body += "  " + json_escape("schema") + ": "
         + json_escape("gnet-wire/v1") + ",\n";
    body += "  " + json_escape("description") + ": "
         + json_escape(
            "GNET v1 wire envelopes (per plugins/protocols/gnet/docs/"
            "wire-format.md) plus post-handshake ChaCha20-Poly1305 IETF "
            "ciphertexts under a fixed transport key + Noise-style "
            "nonce (4 zero bytes + LE counter). Empty AAD per v1 noise "
            "contract.") + ",\n";
    body += "  " + json_escape("magic") + ": "
         + json_escape("GNET") + ",\n";
    body += "  " + json_escape("version") + ": 1,\n";
    body += "  " + json_escape("prologue") + ": "
         + json_escape("goodnet/v1/noise") + ",\n";
    body += "  " + std::string(json_escape("local_pk")) + ": "
         + json_escape(gn::vectors::hex_encode(local_pk)) + ",\n";
    body += "  " + std::string(json_escape("remote_pk")) + ": "
         + json_escape(gn::vectors::hex_encode(remote_pk)) + ",\n";
    body += "  " + std::string(json_escape("third_party_pk")) + ": "
         + json_escape(gn::vectors::hex_encode(third_party_pk)) + ",\n";
    body += "  " + std::string(json_escape("aead_key")) + ": "
         + json_escape(gn::vectors::hex_encode(kFixedAeadKey)) + ",\n";
    body += "  " + std::string(json_escape("handshake_hash")) + ": "
         + json_escape(gn::vectors::hex_encode(kHandshakeHash)) + ",\n";
    body += "  " + json_escape("aead") + ": "
         + json_escape("ChaCha20-Poly1305-IETF") + ",\n";
    body += "  " + json_escape("aead_aad") + ": "
         + json_escape("") + ",\n";
    body += "  " + json_escape("samples") + ": {\n";
    for (std::size_t i = 0; i < samples.size(); ++i) {
        body += render_sample(samples[i], local_pk, remote_pk, third_party_pk);
        body += (i + 1 < samples.size()) ? ",\n" : "\n";
    }
    body += "  }\n";
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
