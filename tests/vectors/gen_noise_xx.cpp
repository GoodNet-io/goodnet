// SPDX-License-Identifier: Apache-2.0
/// @file   tests/vectors/gen_noise_xx.cpp
/// @brief  Generator for `tests/vectors/noise_xx.json`.
///
/// Pins initiator + responder static keys to fixed 32-byte seeds,
/// installs a deterministic libsodium PRNG over a fixed 32-byte
/// seed (so HandshakeState::write_message mints reproducible
/// ephemerals), drives the full XX three-message exchange, splits
/// into transport ciphers, sends one transport message
/// initiator -> responder, then dumps every wire artefact to JSON.
///
/// The output file is committed in-tree at
/// `tests/vectors/noise_xx.json` so cross-language Noise bindings
/// (Rust snow, Python noiseprotocol, JS noise-c, Go flynn/noise)
/// can replay the same inputs and compare bytes.
///
/// Invocation:
///   gen_noise_xx <out.json>
/// `nix run .#test` runs the consumer (`test_vectors_consume`) but
/// does not re-run this generator — the committed JSON is the
/// source of truth. Re-run by hand only when the wire format
/// changes (which requires a contract bump per
/// `plugins/security/noise/docs/handshake.md`).

#include "deterministic_random.hpp"
#include "hex_util.hpp"

#include "handshake.hpp"
#include "transport.hpp"

#include <sodium.h>

#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <span>
#include <string>
#include <vector>

namespace {

/// Build a Noise static keypair from a 32-byte seed by treating the
/// seed as the X25519 scalar (mod the group order, libsodium clamps).
/// Same construction used by both halves so generator and consumer
/// derive identical pks.
gn::noise::Keypair static_from_seed(const std::array<std::uint8_t, 32>& seed) {
    gn::noise::Keypair kp;
    std::memcpy(kp.sk.data(), seed.data(), 32);
    crypto_scalarmult_base(kp.pk.data(), kp.sk.data());
    return kp;
}

/// Initiator static seed — printable so an operator skimming the
/// JSON file can see «init-static» / «resp-static» without decoding.
constexpr std::array<std::uint8_t, 32> kInitStaticSeed = {
    'i','n','i','t','-','s','t','a','t','i','c','-','s','e','e','d',
    '-','-','-','-','-','-','-','-','-','-','-','-','-','-','-','-',
};
constexpr std::array<std::uint8_t, 32> kRespStaticSeed = {
    'r','e','s','p','-','s','t','a','t','i','c','-','s','e','e','d',
    '-','-','-','-','-','-','-','-','-','-','-','-','-','-','-','-',
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

std::string field(std::string_view name, std::string_view value_quoted_or_raw) {
    return std::string("  ") + std::string(json_escape(name))
         + ": " + std::string(value_quoted_or_raw);
}

std::string hex_field(std::string_view name, std::span<const std::uint8_t> bytes) {
    return field(name, json_escape(gn::vectors::hex_encode(bytes)));
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

    using namespace gn::noise;
    using gn::vectors::hex_encode;

    // Static keypairs — derived deterministically from the printable seeds.
    Keypair init_static = static_from_seed(kInitStaticSeed);
    Keypair resp_static = static_from_seed(kRespStaticSeed);

    // Install the deterministic PRNG. ALL ephemeral DH keys + every
    // other randombytes_buf call from this point on read from the
    // chacha20 stream. The seed is committed in
    // `deterministic_random.hpp` (`kCanonicalEphemeralSeed`).
    gn::vectors::install_deterministic_random(
        gn::vectors::kCanonicalEphemeralSeed);

    HandshakeState init{Pattern::XX, /*initiator=*/true,  init_static};
    HandshakeState resp{Pattern::XX, /*initiator=*/false, resp_static};

    // Empty payloads keep the JSON small. The handshake hash and
    // transport keys carry the same forward-secrecy property either
    // way, so binding authors do not need to round-trip arbitrary
    // payload bytes inside the handshake.
    const std::vector<std::uint8_t> empty;

    auto e1 = init.write_message(empty);
    if (!e1) { std::fprintf(stderr, "init.write msg1 failed\n"); return 1; }
    auto r1 = resp.read_message(*e1);
    if (!r1) { std::fprintf(stderr, "resp.read msg1 failed\n"); return 1; }

    auto e2 = resp.write_message(empty);
    if (!e2) { std::fprintf(stderr, "resp.write msg2 failed\n"); return 1; }
    auto r2 = init.read_message(*e2);
    if (!r2) { std::fprintf(stderr, "init.read msg2 failed\n"); return 1; }

    auto e3 = init.write_message(empty);
    if (!e3) { std::fprintf(stderr, "init.write msg3 failed\n"); return 1; }
    auto r3 = resp.read_message(*e3);
    if (!r3) { std::fprintf(stderr, "resp.read msg3 failed\n"); return 1; }

    if (!init.is_complete() || !resp.is_complete()) {
        std::fprintf(stderr, "handshake not complete after 3 messages\n");
        return 1;
    }

    // Snapshot the channel-binding hash before split() wipes anything.
    auto hh = init.handshake_hash();
    auto hh_resp = resp.handshake_hash();
    if (std::memcmp(hh.data(), hh_resp.data(), hh.size()) != 0) {
        std::fprintf(stderr, "handshake hashes diverge between sides\n");
        return 1;
    }

    auto init_pair = init.split();
    auto resp_pair = resp.split();

    // CipherState exposes key_for_export() for the inline-crypto seam.
    CipherKey init_send = init_pair.send.key_for_export();
    CipherKey init_recv = init_pair.recv.key_for_export();
    CipherKey resp_send = resp_pair.send.key_for_export();
    CipherKey resp_recv = resp_pair.recv.key_for_export();

    // Cross-verify keys: initiator.send must equal responder.recv.
    if (init_send != resp_recv || init_recv != resp_send) {
        std::fprintf(stderr, "transport key pair did not symmetrise\n");
        return 1;
    }

    // Send one transport message initiator -> responder under the
    // first post-Split nonce. The empty AD matches the v1 noise
    // contract per `plugins/security/noise/docs/handshake.md` §7.
    const std::vector<std::uint8_t> tx_plain = {
        'h','e','l','l','o','-','t','r','a','n','s','p','o','r','t',
    };
    auto tx_cipher = init_pair.send.encrypt_with_ad(
        std::span<const std::uint8_t>{}, tx_plain);
    auto rx_plain = resp_pair.recv.decrypt_with_ad(
        std::span<const std::uint8_t>{}, tx_cipher);
    if (!rx_plain || *rx_plain != tx_plain) {
        std::fprintf(stderr, "transport decrypt mismatch\n");
        return 1;
    }

    // Compose JSON. Hand-rolled to keep the generator dependency-free
    // beyond libsodium + noise objects.
    std::string body;
    body += "{\n";
    body += field("schema", json_escape("noise-xx/v1")) + ",\n";
    body += field("description", json_escape(
        "Noise_XX_25519_ChaChaPoly_BLAKE2b — three handshake messages "
        "+ transport split + first transport ciphertext. Deterministic "
        "via fixed static seeds + chacha20-seeded PRNG.")) + ",\n";
    body += field("protocol_name",
        json_escape("Noise_XX_25519_ChaChaPoly_BLAKE2b")) + ",\n";
    body += field("prologue", json_escape("goodnet/v1/noise")) + ",\n";
    body += hex_field("init_static_sk", init_static.sk) + ",\n";
    body += hex_field("init_static_pk", init_static.pk) + ",\n";
    body += hex_field("resp_static_sk", resp_static.sk) + ",\n";
    body += hex_field("resp_static_pk", resp_static.pk) + ",\n";
    body += hex_field("ephemeral_prng_seed",
        gn::vectors::kCanonicalEphemeralSeed) + ",\n";
    body += hex_field("handshake_msg1_e", *e1) + ",\n";
    body += hex_field("handshake_msg2_e_ee_s_es", *e2) + ",\n";
    body += hex_field("handshake_msg3_s_se", *e3) + ",\n";
    body += hex_field("handshake_hash", hh) + ",\n";
    body += hex_field("transport_init_send_key", init_send) + ",\n";
    body += hex_field("transport_init_recv_key", init_recv) + ",\n";
    body += hex_field("transport_resp_send_key", resp_send) + ",\n";
    body += hex_field("transport_resp_recv_key", resp_recv) + ",\n";
    body += hex_field("transport_msg_plaintext", tx_plain) + ",\n";
    body += hex_field("transport_msg_ciphertext", tx_cipher) + ",\n";
    body += field("transport_msg_nonce", "0") + ",\n";
    body += field("transport_msg_aad", json_escape("")) + "\n";
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
