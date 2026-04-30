/// @file   tests/unit/plugins/transports/test_tls.cpp
/// @brief  Loopback TLS handshake + payload round-trip.

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <thread>
#include <vector>

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <plugins/transports/tls/tls.hpp>

#include <sdk/host_api.h>
#include <sdk/types.h>

namespace {

/// Generate an in-memory self-signed RSA-2048 cert + private key.
/// Used by the loopback test so neither side needs a filesystem
/// certificate. Returns false on any OpenSSL failure; on success
/// `cert_pem` and `key_pem` carry PEM-encoded text.
bool generate_self_signed(std::string& cert_pem, std::string& key_pem) {
    EVP_PKEY* pkey = EVP_PKEY_new();
    if (!pkey) return false;

    EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!kctx) { EVP_PKEY_free(pkey); return false; }
    bool ok =
        EVP_PKEY_keygen_init(kctx) > 0 &&
        EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 2048) > 0 &&
        EVP_PKEY_keygen(kctx, &pkey) > 0;
    EVP_PKEY_CTX_free(kctx);
    if (!ok) { EVP_PKEY_free(pkey); return false; }

    X509* x509 = X509_new();
    if (!x509) { EVP_PKEY_free(pkey); return false; }
    X509_set_version(x509, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    X509_gmtime_adj(X509_getm_notBefore(x509), 0);
    X509_gmtime_adj(X509_getm_notAfter(x509), 60L * 60L);  // 1 hour
    X509_set_pubkey(x509, pkey);

    X509_NAME* name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
        reinterpret_cast<const unsigned char*>("goodnet-test"), -1, -1, 0);
    X509_set_issuer_name(x509, name);

    if (X509_sign(x509, pkey, EVP_sha256()) == 0) {
        X509_free(x509);
        EVP_PKEY_free(pkey);
        return false;
    }

    BIO* cert_bio = BIO_new(BIO_s_mem());
    BIO* key_bio  = BIO_new(BIO_s_mem());
    if (!cert_bio || !key_bio) {
        if (cert_bio) BIO_free(cert_bio);
        if (key_bio)  BIO_free(key_bio);
        X509_free(x509);
        EVP_PKEY_free(pkey);
        return false;
    }
    PEM_write_bio_X509(cert_bio, x509);
    PEM_write_bio_PrivateKey(key_bio, pkey,
        nullptr, nullptr, 0, nullptr, nullptr);

    char* cert_data = nullptr;
    const auto cert_len = BIO_get_mem_data(cert_bio, &cert_data);
    cert_pem.assign(cert_data, static_cast<std::size_t>(cert_len));
    char* key_data = nullptr;
    const auto key_len = BIO_get_mem_data(key_bio, &key_data);
    key_pem.assign(key_data, static_cast<std::size_t>(key_len));

    BIO_free(cert_bio);
    BIO_free(key_bio);
    X509_free(x509);
    EVP_PKEY_free(pkey);
    return true;
}

struct TlsHarness {
    std::mutex                                  mu;
    std::vector<gn_conn_id_t>                   connects;
    std::vector<gn_handshake_role_t>            roles;
    std::vector<std::vector<std::uint8_t>>      inbound;

    static gn_result_t s_notify_connect(void* host_ctx,
                                         const std::uint8_t* /*remote_pk*/,
                                         const char* /*uri*/,
                                         const char* /*scheme*/,
                                         gn_trust_class_t /*trust*/,
                                         gn_handshake_role_t role,
                                         gn_conn_id_t* out_conn) {
        auto* h = static_cast<TlsHarness*>(host_ctx);
        std::lock_guard lk(h->mu);
        const auto id = static_cast<gn_conn_id_t>(h->connects.size() + 1);
        h->connects.push_back(id);
        h->roles.push_back(role);
        *out_conn = id;
        return GN_OK;
    }
    static gn_result_t s_notify_inbound(void* host_ctx, gn_conn_id_t,
                                         const std::uint8_t* bytes,
                                         std::size_t size) {
        auto* h = static_cast<TlsHarness*>(host_ctx);
        std::lock_guard lk(h->mu);
        h->inbound.emplace_back(bytes, bytes + size);
        return GN_OK;
    }
    static gn_result_t s_notify_disconnect(void*, gn_conn_id_t,
                                            gn_result_t) {
        return GN_OK;
    }
    static gn_result_t s_kick(void*, gn_conn_id_t) { return GN_OK; }

    host_api_t make_api() {
        host_api_t api{};
        api.api_size             = sizeof(host_api_t);
        api.host_ctx             = this;
        api.notify_connect       = &s_notify_connect;
        api.notify_inbound_bytes = &s_notify_inbound;
        api.notify_disconnect    = &s_notify_disconnect;
        api.kick_handshake       = &s_kick;
        return api;
    }
};

bool wait_for(auto&& predicate,
              std::chrono::milliseconds timeout = std::chrono::seconds{4}) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (predicate()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds{5});
    }
    return predicate();
}

} // namespace

TEST(TlsTransport_Capabilities, AdvertisesEncryptedPath) {
    const auto caps = gn::transport::tls::TlsTransport::capabilities();
    EXPECT_TRUE(caps.flags & GN_TRANSPORT_CAP_STREAM);
    EXPECT_TRUE(caps.flags & GN_TRANSPORT_CAP_RELIABLE);
    EXPECT_TRUE(caps.flags & GN_TRANSPORT_CAP_ORDERED);
    EXPECT_TRUE(caps.flags & GN_TRANSPORT_CAP_ENCRYPTED_PATH);
}

TEST(TlsTransport, RejectsListenWithoutCredentials) {
    auto t = std::make_shared<gn::transport::tls::TlsTransport>();
    /// No credentials wired and no host_api / config bound — the
    /// listen path must refuse rather than silently accept and fail
    /// every TLS handshake later.
    EXPECT_EQ(t->listen("tls://127.0.0.1:0"), GN_ERR_NOT_IMPLEMENTED);
    t->shutdown();
}

TEST(TlsTransport_VerifyDefault, ClientRejectsUntrustedCertWithoutOptOut) {
    /// Default-secure: a fresh `TlsTransport` client verifies the
    /// peer cert against OpenSSL's default trust store. A self-
    /// signed loopback cert chains to nothing trusted, so the
    /// handshake fails and `notify_connect` never publishes the
    /// initiator side. The harness records the responder-side
    /// connect from `accept` but no initiator-side completion.
    std::string cert, key;
    ASSERT_TRUE(generate_self_signed(cert, key));

    TlsHarness harness;
    auto api = harness.make_api();

    auto server = std::make_shared<gn::transport::tls::TlsTransport>();
    auto client = std::make_shared<gn::transport::tls::TlsTransport>();
    server->set_host_api(&api);
    client->set_host_api(&api);
    server->set_server_credentials(cert, key);
    /// Note: no `client->set_verify_peer(false)` — default verify
    /// stays on; this is the regression scenario.

    ASSERT_EQ(server->listen("tls://127.0.0.1:0"), GN_OK);
    const auto port = server->listen_port();
    ASSERT_GT(port, 0u);

    const std::string uri =
        "tls://127.0.0.1:" + std::to_string(port);
    /// `connect` returns GN_OK on enqueue — the failure surfaces
    /// asynchronously inside the handshake, not on the call.
    ASSERT_EQ(client->connect(uri), GN_OK);

    /// Wait for any handshake completion. With verify_peer on and
    /// no trust store match, the initiator side never publishes
    /// `notify_connect`. A two-second window catches a successful
    /// handshake on the pre-fix path.
    const bool any_initiator = wait_for([&] {
        std::lock_guard lk(harness.mu);
        for (auto role : harness.roles) {
            if (role == GN_ROLE_INITIATOR) return true;
        }
        return false;
    }, std::chrono::seconds{2});

    EXPECT_FALSE(any_initiator);

    client->shutdown();
    server->shutdown();
}

namespace {

/// Test harness variant that exposes a `transports.tls.verify_peer`
/// config bool. The caller sets `verify_peer_value` before binding
/// the api; an unbound variant leaves `config_get_bool` returning
/// `GN_ERR_UNKNOWN_RECEIVER`.
struct TlsConfigHarness : TlsHarness {
    std::optional<int32_t> verify_peer_value;

    static gn_result_t s_config_get_bool(void* host_ctx,
                                          const char* key,
                                          int32_t* out_value) {
        auto* h = static_cast<TlsConfigHarness*>(host_ctx);
        if (h && key && std::string_view{key} == "transports.tls.verify_peer"
            && h->verify_peer_value && out_value) {
            *out_value = *h->verify_peer_value;
            return GN_OK;
        }
        return GN_ERR_UNKNOWN_RECEIVER;
    }

    host_api_t make_api() {
        host_api_t api = TlsHarness::make_api();
        api.config_get_bool = &s_config_get_bool;
        return api;
    }
};

} // namespace

TEST(TlsTransport_VerifyDefault, ConfigOptOutLetsHandshakeSucceed) {
    /// `transports.tls.verify_peer = false` on the config flips the
    /// client to verify_none, matching the API opt-out.
    std::string cert, key;
    ASSERT_TRUE(generate_self_signed(cert, key));

    TlsConfigHarness harness;
    harness.verify_peer_value = 0;
    auto api = harness.make_api();

    auto server = std::make_shared<gn::transport::tls::TlsTransport>();
    auto client = std::make_shared<gn::transport::tls::TlsTransport>();
    server->set_host_api(&api);
    client->set_host_api(&api);
    server->set_server_credentials(cert, key);

    ASSERT_EQ(server->listen("tls://127.0.0.1:0"), GN_OK);
    const auto port = server->listen_port();
    const std::string uri =
        "tls://127.0.0.1:" + std::to_string(port);
    ASSERT_EQ(client->connect(uri), GN_OK);

    ASSERT_TRUE(wait_for([&] {
        std::lock_guard lk(harness.mu);
        return harness.connects.size() >= 2;
    }));

    client->shutdown();
    server->shutdown();
}

TEST(TlsTransport_VerifyDefault, ConfigUnboundEnforcesDefault) {
    /// Without the config key bound (`config_get_bool` returns
    /// `GN_ERR_UNKNOWN_RECEIVER`), the client stays in verify_peer
    /// mode and refuses the self-signed loopback cert.
    std::string cert, key;
    ASSERT_TRUE(generate_self_signed(cert, key));

    TlsConfigHarness harness;
    /// verify_peer_value left unset — config_get_bool returns miss.
    auto api = harness.make_api();

    auto server = std::make_shared<gn::transport::tls::TlsTransport>();
    auto client = std::make_shared<gn::transport::tls::TlsTransport>();
    server->set_host_api(&api);
    client->set_host_api(&api);
    server->set_server_credentials(cert, key);

    ASSERT_EQ(server->listen("tls://127.0.0.1:0"), GN_OK);
    const auto port = server->listen_port();
    const std::string uri =
        "tls://127.0.0.1:" + std::to_string(port);
    ASSERT_EQ(client->connect(uri), GN_OK);

    const bool any_initiator = wait_for([&] {
        std::lock_guard lk(harness.mu);
        for (auto role : harness.roles) {
            if (role == GN_ROLE_INITIATOR) return true;
        }
        return false;
    }, std::chrono::seconds{2});
    EXPECT_FALSE(any_initiator);

    client->shutdown();
    server->shutdown();
}

TEST(TlsTransport_KeyHygiene, ListenZeroisesOverrideKey) {
    /// `noise-handshake.md` §5b: once OpenSSL has copied the key
    /// bytes into its own context, the override buffer has no
    /// remaining purpose and is wiped eagerly. The observable
    /// flips from non-zero to zero across the listen call.
    std::string cert, key;
    ASSERT_TRUE(generate_self_signed(cert, key));

    auto t = std::make_shared<gn::transport::tls::TlsTransport>();
    t->set_server_credentials(cert, key);
    EXPECT_FALSE(t->key_pem_zeroised_for_test());

    ASSERT_EQ(t->listen("tls://127.0.0.1:0"), GN_OK);

    EXPECT_TRUE(t->key_pem_zeroised_for_test());

    t->shutdown();
}

TEST(TlsTransport, LoopbackHandshakeAndPayloadRoundTrip) {
    std::string cert, key;
    ASSERT_TRUE(generate_self_signed(cert, key))
        << "ephemeral cert generation failed";

    TlsHarness harness;
    auto api = harness.make_api();

    auto server = std::make_shared<gn::transport::tls::TlsTransport>();
    auto client = std::make_shared<gn::transport::tls::TlsTransport>();
    server->set_host_api(&api);
    client->set_host_api(&api);
    server->set_server_credentials(cert, key);
    /// Self-signed cert in this loopback fixture chains to nothing;
    /// the client opts out of peer-cert verification explicitly,
    /// matching the production "TLS as link encryption beneath
    /// Noise" path.
    client->set_verify_peer(false);

    ASSERT_EQ(server->listen("tls://127.0.0.1:0"), GN_OK);
    const auto port = server->listen_port();
    ASSERT_GT(port, 0u);

    const std::string uri =
        "tls://127.0.0.1:" + std::to_string(port);
    ASSERT_EQ(client->connect(uri), GN_OK);

    ASSERT_TRUE(wait_for([&] {
        std::lock_guard lk(harness.mu);
        return harness.connects.size() >= 2;
    }));
    {
        std::lock_guard lk(harness.mu);
        EXPECT_EQ(harness.connects.size(), 2u);
        const bool roles_pair =
            (harness.roles[0] == GN_ROLE_INITIATOR &&
             harness.roles[1] == GN_ROLE_RESPONDER) ||
            (harness.roles[0] == GN_ROLE_RESPONDER &&
             harness.roles[1] == GN_ROLE_INITIATOR);
        EXPECT_TRUE(roles_pair);
    }

    gn_conn_id_t initiator_id = 0;
    {
        std::lock_guard lk(harness.mu);
        for (std::size_t i = 0; i < harness.roles.size(); ++i) {
            if (harness.roles[i] == GN_ROLE_INITIATOR) {
                initiator_id = harness.connects[i];
                break;
            }
        }
    }
    ASSERT_NE(initiator_id, 0u);

    const std::vector<std::uint8_t> payload{0x11, 0x22, 0x33, 0x44, 0x55};
    auto rc1 = client->send(initiator_id,
        std::span<const std::uint8_t>(payload));
    auto rc2 = server->send(initiator_id,
        std::span<const std::uint8_t>(payload));
    EXPECT_TRUE(rc1 == GN_OK || rc2 == GN_OK);

    ASSERT_TRUE(wait_for([&] {
        std::lock_guard lk(harness.mu);
        return !harness.inbound.empty();
    }));
    {
        std::lock_guard lk(harness.mu);
        ASSERT_FALSE(harness.inbound.empty());
        EXPECT_EQ(harness.inbound.front(), payload);
    }

    client->shutdown();
    server->shutdown();
}
