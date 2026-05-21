// SPDX-License-Identifier: Apache-2.0
/// @file   tests/vectors/test_vectors_consume.cpp
/// @brief  Cross-implementation test vector consumer.
///
/// Each TEST() reads one JSON file from `tests/vectors/`, re-derives
/// the expected outputs through the C++ reference primitives, and
/// asserts byte-for-byte equality with the committed bytes. A
/// language binding (Rust, Python, JS, Go) that implements the same
/// primitives MUST produce the same bytes from the same inputs.
///
/// Path to the vectors directory is threaded through the
/// `GOODNET_VECTORS_DIR` compile-time define set by the
/// CMakeLists in this directory.

#include "deterministic_random.hpp"
#include "hex_util.hpp"

#include "handshake.hpp"
#include "transport.hpp"

#include "protocol.hpp"
#include "wire.hpp"

#include <sdk/connection.h>
#include <sdk/cpp/capability_tlv.hpp>

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <sodium.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <span>
#include <sstream>
#include <string>
#include <vector>

#ifndef GOODNET_VECTORS_DIR
#error "GOODNET_VECTORS_DIR must be defined at build time"
#endif

namespace {

using json = nlohmann::json;
using gn::vectors::hex_decode;
using gn::vectors::hex_encode;

std::filesystem::path vectors_dir() {
    return std::filesystem::path(GOODNET_VECTORS_DIR);
}

json load_vector(const std::string& name) {
    auto path = vectors_dir() / name;
    std::ifstream in(path);
    if (!in) {
        ADD_FAILURE() << "cannot open " << path;
        return {};
    }
    std::stringstream ss;
    ss << in.rdbuf();
    return json::parse(ss.str());
}

std::vector<std::uint8_t> hex_field(const json& j, const std::string& key) {
    return hex_decode(j.at(key).get<std::string>());
}

}  // namespace

// ── Noise XX ────────────────────────────────────────────────────────────

TEST(VectorsNoiseXX, ReproducesHandshakeAndTransportBytes) {
    ASSERT_GE(sodium_init(), 0);
    auto v = load_vector("noise_xx.json");
    ASSERT_FALSE(v.empty());

    auto init_sk = hex_field(v, "init_static_sk");
    auto init_pk = hex_field(v, "init_static_pk");
    auto resp_sk = hex_field(v, "resp_static_sk");
    auto resp_pk = hex_field(v, "resp_static_pk");
    auto seed    = hex_field(v, "ephemeral_prng_seed");
    ASSERT_EQ(init_sk.size(), 32u);
    ASSERT_EQ(resp_sk.size(), 32u);
    ASSERT_EQ(seed.size(),    32u);

    gn::noise::Keypair init_static, resp_static;
    std::memcpy(init_static.sk.data(), init_sk.data(), 32);
    std::memcpy(init_static.pk.data(), init_pk.data(), 32);
    std::memcpy(resp_static.sk.data(), resp_sk.data(), 32);
    std::memcpy(resp_static.pk.data(), resp_pk.data(), 32);

    std::array<std::uint8_t, 32> seed_arr{};
    std::memcpy(seed_arr.data(), seed.data(), 32);
    gn::vectors::install_deterministic_random(seed_arr);

    gn::noise::HandshakeState init{
        gn::noise::Pattern::XX, /*initiator=*/true,  init_static};
    gn::noise::HandshakeState resp{
        gn::noise::Pattern::XX, /*initiator=*/false, resp_static};

    const std::vector<std::uint8_t> empty;

    auto e1 = init.write_message(empty); ASSERT_TRUE(e1.has_value());
    auto r1 = resp.read_message(*e1);    ASSERT_TRUE(r1.has_value());
    auto e2 = resp.write_message(empty); ASSERT_TRUE(e2.has_value());
    auto r2 = init.read_message(*e2);    ASSERT_TRUE(r2.has_value());
    auto e3 = init.write_message(empty); ASSERT_TRUE(e3.has_value());
    auto r3 = resp.read_message(*e3);    ASSERT_TRUE(r3.has_value());

    EXPECT_EQ(hex_encode(*e1), v.at("handshake_msg1_e").get<std::string>());
    EXPECT_EQ(hex_encode(*e2),
              v.at("handshake_msg2_e_ee_s_es").get<std::string>());
    EXPECT_EQ(hex_encode(*e3),
              v.at("handshake_msg3_s_se").get<std::string>());

    auto hh = init.handshake_hash();
    EXPECT_EQ(hex_encode(std::span<const std::uint8_t>(hh.data(), hh.size())),
              v.at("handshake_hash").get<std::string>());

    auto init_pair = init.split();
    auto resp_pair = resp.split();
    EXPECT_EQ(hex_encode(init_pair.send.key_for_export()),
              v.at("transport_init_send_key").get<std::string>());
    EXPECT_EQ(hex_encode(init_pair.recv.key_for_export()),
              v.at("transport_init_recv_key").get<std::string>());
    EXPECT_EQ(hex_encode(resp_pair.send.key_for_export()),
              v.at("transport_resp_send_key").get<std::string>());
    EXPECT_EQ(hex_encode(resp_pair.recv.key_for_export()),
              v.at("transport_resp_recv_key").get<std::string>());

    auto tx_plain = hex_field(v, "transport_msg_plaintext");
    auto tx_cipher_expected = hex_field(v, "transport_msg_ciphertext");
    auto tx_cipher = init_pair.send.encrypt_with_ad(
        std::span<const std::uint8_t>{}, tx_plain);
    EXPECT_EQ(tx_cipher, tx_cipher_expected);
}

// ── GNET wire ───────────────────────────────────────────────────────────

TEST(VectorsGnetWire, ReproducesFrameAndCiphertextForEverySample) {
    ASSERT_GE(sodium_init(), 0);
    auto v = load_vector("gnet_wire.json");
    ASSERT_FALSE(v.empty());

    auto local_pk       = hex_field(v, "local_pk");
    auto remote_pk      = hex_field(v, "remote_pk");
    auto third_party_pk = hex_field(v, "third_party_pk");
    auto aead_key       = hex_field(v, "aead_key");
    ASSERT_EQ(local_pk.size(), 32u);
    ASSERT_EQ(remote_pk.size(), 32u);
    ASSERT_EQ(third_party_pk.size(), 32u);
    ASSERT_EQ(aead_key.size(), 32u);

    const auto& samples = v.at("samples");
    for (auto it = samples.begin(); it != samples.end(); ++it) {
        const std::string& tag = it.key();
        const auto& s = it.value();

        std::uint32_t msg_id = s.at("msg_id").get<std::uint32_t>();
        std::string   mode   = s.at("mode").get<std::string>();
        auto payload         = hex_field(s, "payload");
        auto expected_frame  = hex_field(s, "frame_bytes");
        auto expected_cipher = hex_field(s, "ciphertext");
        std::uint64_t nonce_counter =
            s.at("aead_nonce_counter").get<std::uint64_t>();

        bool relay     = (mode == "relay-transit");
        bool broadcast = (mode == "broadcast");

        auto* ctx = gn_ctx_make_for_test(
            local_pk.data(), remote_pk.data(),
            GN_INVALID_ID, GN_TRUST_PEER,
            (relay || broadcast) ? 1 : 0);
        ASSERT_NE(ctx, nullptr) << "tag=" << tag;

        gn_message_t env{};
        env.msg_id = msg_id;
        std::memcpy(env.sender_pk, local_pk.data(), 32);
        if (broadcast) {
            std::memset(env.receiver_pk, 0, 32);
        } else if (relay) {
            std::memcpy(env.receiver_pk, third_party_pk.data(), 32);
        } else {
            std::memcpy(env.receiver_pk, remote_pk.data(), 32);
        }
        env.payload      = payload.empty() ? nullptr : payload.data();
        env.payload_size = payload.size();

        gn::plugins::gnet::GnetProtocol layer;
        auto framed = layer.frame(*ctx, env);
        ASSERT_TRUE(framed.has_value()) << "tag=" << tag;

        EXPECT_EQ(*framed, expected_frame) << "tag=" << tag;
        gn_ctx_destroy(ctx);

        // AEAD round-trip — re-encrypt and compare.
        std::uint8_t nonce[crypto_aead_chacha20poly1305_IETF_NPUBBYTES] = {0};
        for (int i = 0; i < 8; ++i) {
            nonce[4 + i] = static_cast<std::uint8_t>(
                (nonce_counter >> (i * 8)) & 0xFFu);
        }
        std::vector<std::uint8_t> ct(
            framed->size() + crypto_aead_chacha20poly1305_IETF_ABYTES);
        unsigned long long ct_len = 0;
        ASSERT_EQ(crypto_aead_chacha20poly1305_ietf_encrypt(
            ct.data(), &ct_len,
            framed->data(), framed->size(),
            /*ad=*/nullptr, 0,
            /*nsec=*/nullptr,
            nonce, aead_key.data()), 0) << "tag=" << tag;
        ct.resize(static_cast<std::size_t>(ct_len));
        EXPECT_EQ(ct, expected_cipher) << "tag=" << tag;
    }
}

// ── Attestation ─────────────────────────────────────────────────────────

TEST(VectorsAttestation, ReproducesEd25519Payload) {
    ASSERT_GE(sodium_init(), 0);
    auto v = load_vector("attestation.json");
    ASSERT_FALSE(v.empty());

    auto user_seed   = hex_field(v, "user_seed");
    auto device_seed = hex_field(v, "device_seed");
    auto hs_hash     = hex_field(v, "handshake_hash");
    std::int64_t expiry = v.at("expiry_unix_ts").get<std::int64_t>();
    ASSERT_EQ(user_seed.size(),   32u);
    ASSERT_EQ(device_seed.size(), 32u);
    ASSERT_EQ(hs_hash.size(),     32u);

    std::uint8_t user_pk[crypto_sign_PUBLICKEYBYTES];
    std::uint8_t user_sk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_seed_keypair(user_pk, user_sk, user_seed.data());

    std::uint8_t device_pk[crypto_sign_PUBLICKEYBYTES];
    std::uint8_t device_sk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_seed_keypair(device_pk, device_sk, device_seed.data());

    EXPECT_EQ(hex_encode(std::span<const std::uint8_t>(user_pk, 32)),
              v.at("user_pk").get<std::string>());
    EXPECT_EQ(hex_encode(std::span<const std::uint8_t>(device_pk, 32)),
              v.at("device_pk").get<std::string>());

    // canonical 72-byte cert payload.
    std::array<std::uint8_t, 72> cert_canonical{};
    std::memcpy(cert_canonical.data(),      user_pk,   32);
    std::memcpy(cert_canonical.data() + 32, device_pk, 32);
    auto u = static_cast<std::uint64_t>(expiry);
    for (int i = 0; i < 8; ++i) {
        cert_canonical[64 + (7 - i)] =
            static_cast<std::uint8_t>((u >> (i * 8)) & 0xFFu);
    }
    EXPECT_EQ(hex_encode(cert_canonical),
              v.at("cert_canonical_72").get<std::string>());

    std::uint8_t cert_sig[64];
    crypto_sign_detached(cert_sig, nullptr,
                         cert_canonical.data(), cert_canonical.size(),
                         user_sk);
    EXPECT_EQ(hex_encode(std::span<const std::uint8_t>(cert_sig, 64)),
              v.at("cert_user_signature").get<std::string>());

    std::array<std::uint8_t, 136> cert_bytes{};
    std::memcpy(cert_bytes.data(),      user_pk,   32);
    std::memcpy(cert_bytes.data() + 32, device_pk, 32);
    std::memcpy(cert_bytes.data() + 64, cert_canonical.data() + 64, 8);
    std::memcpy(cert_bytes.data() + 72, cert_sig, 64);
    EXPECT_EQ(hex_encode(cert_bytes),
              v.at("cert_136").get<std::string>());

    std::array<std::uint8_t, 168> signed_input{};
    std::memcpy(signed_input.data(), cert_bytes.data(), 136);
    std::memcpy(signed_input.data() + 136, hs_hash.data(), 32);

    std::uint8_t outer_sig[64];
    crypto_sign_detached(outer_sig, nullptr,
                         signed_input.data(), signed_input.size(),
                         device_sk);
    EXPECT_EQ(hex_encode(std::span<const std::uint8_t>(outer_sig, 64)),
              v.at("device_signature").get<std::string>());

    std::array<std::uint8_t, 232> payload{};
    std::memcpy(payload.data(),       cert_bytes.data(),  136);
    std::memcpy(payload.data() + 136, hs_hash.data(),     32);
    std::memcpy(payload.data() + 168, outer_sig,          64);
    EXPECT_EQ(hex_encode(payload),
              v.at("payload_232").get<std::string>());

    EXPECT_TRUE(v.at("verify_cert_under_user_pk").get<bool>());
    EXPECT_TRUE(v.at("verify_signature_under_device_pk").get<bool>());
    EXPECT_EQ(crypto_sign_verify_detached(
        outer_sig, signed_input.data(), signed_input.size(), device_pk), 0);
}

// ── Capability TLV ──────────────────────────────────────────────────────

TEST(VectorsCapabilityBlob, ReencodesEverySample) {
    auto v = load_vector("capability_blob.json");
    ASSERT_FALSE(v.empty());

    const auto& samples = v.at("samples");
    for (const auto& s : samples) {
        std::string tag = s.at("tag").get<std::string>();
        std::vector<gn::sdk::TlvRecord> records;
        for (const auto& r : s.at("records")) {
            gn::sdk::TlvRecord rec;
            rec.type  = static_cast<std::uint16_t>(r.at("type").get<unsigned int>());
            rec.value = hex_decode(r.at("value").get<std::string>());
            records.push_back(std::move(rec));
        }
        auto enc = gn::sdk::encode_tlv(records);
        ASSERT_TRUE(enc.has_value()) << "tag=" << tag;

        auto expected_blob = hex_field(s, "blob");
        EXPECT_EQ(*enc, expected_blob) << "tag=" << tag;

        // Round-trip parse must reproduce the records.
        auto parsed = gn::sdk::parse_tlv(*enc);
        ASSERT_TRUE(parsed.has_value()) << "tag=" << tag;
        ASSERT_EQ(parsed->size(), records.size()) << "tag=" << tag;
        for (std::size_t i = 0; i < records.size(); ++i) {
            EXPECT_EQ((*parsed)[i].type,  records[i].type)  << "tag=" << tag << " i=" << i;
            EXPECT_EQ((*parsed)[i].value, records[i].value) << "tag=" << tag << " i=" << i;
        }
    }
}

// ── PKCS#11 sign (synthetic — see status field in JSON) ─────────────────

TEST(VectorsPkcs11Sign, ReproducesEd25519SignatureForEverySample) {
    ASSERT_GE(sodium_init(), 0);
    auto v = load_vector("pkcs11_sign.json");
    ASSERT_FALSE(v.empty());

    EXPECT_EQ(v.at("mechanism").get<std::string>(), "CKM_EDDSA");
    // status is "deferred-real-token" — the libsodium sign path is
    // bit-identical to a CKM_EDDSA token output, so the bytes
    // committed here remain the source of truth for real-token
    // bindings once SoftHSM2 lands in the devShell.

    const auto& samples = v.at("samples");
    for (const auto& s : samples) {
        std::string tag = s.at("tag").get<std::string>();
        auto seed = hex_field(s, "seed");
        auto input = hex_field(s, "input_bytes");
        auto expected_pk  = hex_field(s, "public_key");
        auto expected_sig = hex_field(s, "signature");

        std::uint8_t pk[crypto_sign_PUBLICKEYBYTES];
        std::uint8_t sk[crypto_sign_SECRETKEYBYTES];
        crypto_sign_seed_keypair(pk, sk, seed.data());
        EXPECT_EQ(hex_encode(std::span<const std::uint8_t>(pk, 32)),
                  hex_encode(expected_pk)) << "tag=" << tag;

        std::uint8_t sig[64];
        crypto_sign_detached(sig, nullptr,
                              input.data(), input.size(), sk);
        EXPECT_EQ(hex_encode(std::span<const std::uint8_t>(sig, 64)),
                  hex_encode(expected_sig)) << "tag=" << tag;
        EXPECT_EQ(crypto_sign_verify_detached(
            sig, input.data(), input.size(), pk), 0) << "tag=" << tag;
    }
}
