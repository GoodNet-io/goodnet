/// @file   tests/unit/plugin/test_remote_host_security.cpp
/// @brief  End-to-end exercise of the subprocess SECURITY proxy slots.
///
/// Spawns the in-tree `remote_noise_stub` worker, drives its
/// security-provider vtable through `RemoteHost::security_vtable_proxy`,
/// and asserts the three-step handshake reaches the transport phase
/// with the worker-supplied keys round-tripping back over the wire.

#include <array>
#include <cstdlib>
#include <cstring>
#include <span>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <sdk/host_api.h>
#include <sdk/link.h>
#include <sdk/plugin.h>
#include <sdk/security.h>
#include <sdk/trust.h>

#include <core/kernel/plugin_context.hpp>
#include <core/plugin/remote_host.hpp>

namespace {

const char* worker_binary_path() {
    if (const char* env = std::getenv("GOODNET_REMOTE_NOISE_STUB_BINARY")) {
        return env;
    }
#ifdef GOODNET_REMOTE_NOISE_STUB_PATH
    return GOODNET_REMOTE_NOISE_STUB_PATH;
#else
    return "workers/remote_noise_stub";
#endif
}

void stub_log_emit(void* /*host_ctx*/, gn_log_level_t /*level*/,
                   const char* /*file*/, int32_t /*line*/,
                   const char* /*msg*/) {}

int32_t stub_is_shutdown_requested(void* /*host_ctx*/) { return 0; }

host_api_t make_stub_host_api() {
    host_api_t api{};
    api.api_size = sizeof(host_api_t);
    api.host_ctx = nullptr;
    api.log.api_size = sizeof(gn_log_api_t);
    api.log.emit = &stub_log_emit;
    api.is_shutdown_requested = &stub_is_shutdown_requested;
    return api;
}

}  // namespace

TEST(RemoteHostSecurity, ProxyExposesProviderId) {
    gn::core::PluginContext ctx;
    ctx.plugin_name = "remote_noise_stub_test";
    ctx.kind        = GN_PLUGIN_KIND_SECURITY;

    gn::core::RemoteHost host;
    std::string diag;
    ASSERT_EQ(host.spawn(worker_binary_path(),
                          std::span<const std::string>(),
                          ctx, make_stub_host_api(), diag), GN_OK) << diag;

    const gn_security_provider_vtable_t* vt = host.security_vtable_proxy();
    ASSERT_NE(vt, nullptr);
    ASSERT_NE(vt->provider_id, nullptr);
    EXPECT_STREQ(vt->provider_id(static_cast<void*>(&host)),
                 "remote_noise_stub");
}

TEST(RemoteHostSecurity, AllowedTrustMaskRoundsTrip) {
    gn::core::PluginContext ctx;
    ctx.plugin_name = "remote_noise_stub_test";
    ctx.kind        = GN_PLUGIN_KIND_SECURITY;

    gn::core::RemoteHost host;
    std::string diag;
    ASSERT_EQ(host.spawn(worker_binary_path(),
                          std::span<const std::string>(),
                          ctx, make_stub_host_api(), diag), GN_OK) << diag;

    void* self_handle = nullptr;
    ASSERT_EQ(host.call_init(&self_handle), GN_OK);

    const gn_security_provider_vtable_t* vt = host.security_vtable_proxy();
    ASSERT_NE(vt, nullptr);
    ASSERT_NE(vt->allowed_trust_mask, nullptr);
    const std::uint32_t mask = vt->allowed_trust_mask(static_cast<void*>(&host));
    const std::uint32_t expected =
        (1u << GN_TRUST_UNTRUSTED) | (1u << GN_TRUST_PEER) |
        (1u << GN_TRUST_LOOPBACK)  | (1u << GN_TRUST_INTRA_NODE);
    EXPECT_EQ(mask, expected);
}

TEST(RemoteHostSecurity, HandshakeReachesTransportPhase) {
    /// Drive the stub's three-step initiator handshake through the
    /// kernel-side proxy and confirm `handshake_complete` flips and
    /// `export_transport_keys` returns the worker's keys verbatim.
    gn::core::PluginContext ctx;
    ctx.plugin_name = "remote_noise_stub_test";
    ctx.kind        = GN_PLUGIN_KIND_SECURITY;

    gn::core::RemoteHost host;
    std::string diag;
    ASSERT_EQ(host.spawn(worker_binary_path(),
                          std::span<const std::string>(),
                          ctx, make_stub_host_api(), diag), GN_OK) << diag;

    void* self_handle = nullptr;
    ASSERT_EQ(host.call_init(&self_handle), GN_OK);

    const gn_security_provider_vtable_t* vt = host.security_vtable_proxy();
    ASSERT_NE(vt, nullptr);

    std::array<std::uint8_t, GN_PRIVATE_KEY_BYTES> local_sk{};
    std::array<std::uint8_t, GN_PUBLIC_KEY_BYTES>  local_pk{};
    for (size_t i = 0; i < local_sk.size(); ++i) local_sk[i] = static_cast<std::uint8_t>(i);
    for (size_t i = 0; i < local_pk.size(); ++i) local_pk[i] = static_cast<std::uint8_t>(0x80 + i);

    void* state = nullptr;
    ASSERT_EQ(vt->handshake_open(
        static_cast<void*>(&host), 42u,
        GN_TRUST_PEER, GN_ROLE_INITIATOR,
        local_sk.data(), local_pk.data(), nullptr, &state), GN_OK);
    ASSERT_NE(state, nullptr);

    // Step 1: initiator writes the e message.
    gn_secure_buffer_t out1{};
    ASSERT_EQ(vt->handshake_step(
        static_cast<void*>(&host), state, nullptr, 0, &out1), GN_OK);
    ASSERT_NE(out1.bytes, nullptr);
    EXPECT_EQ(out1.size, 8u);
    EXPECT_EQ(out1.bytes[0], 1);
    if (out1.bytes && out1.free_fn) out1.free_fn(out1.free_user_data, out1.bytes);
    EXPECT_EQ(vt->handshake_complete(static_cast<void*>(&host), state), 0);

    // Step 2: initiator reads peer's e, ee, s, es; no write back.
    const std::vector<std::uint8_t> peer_msg(8, 0x00);
    gn_secure_buffer_t out2{};
    ASSERT_EQ(vt->handshake_step(
        static_cast<void*>(&host), state,
        peer_msg.data(), peer_msg.size(), &out2), GN_OK);
    EXPECT_EQ(out2.bytes, nullptr);
    EXPECT_EQ(out2.size, 0u);
    EXPECT_EQ(vt->handshake_complete(static_cast<void*>(&host), state), 0);

    // Step 3: initiator writes the final s, se message.
    gn_secure_buffer_t out3{};
    ASSERT_EQ(vt->handshake_step(
        static_cast<void*>(&host), state, nullptr, 0, &out3), GN_OK);
    ASSERT_NE(out3.bytes, nullptr);
    EXPECT_EQ(out3.bytes[0], 3);
    if (out3.bytes && out3.free_fn) out3.free_fn(out3.free_user_data, out3.bytes);
    EXPECT_EQ(vt->handshake_complete(static_cast<void*>(&host), state), 1);

    gn_handshake_keys_t keys{};
    keys.api_size = sizeof(gn_handshake_keys_t);
    ASSERT_EQ(vt->export_transport_keys(
        static_cast<void*>(&host), state, &keys), GN_OK);
    EXPECT_EQ(keys.send_cipher_key[0], 0x10);
    EXPECT_EQ(keys.recv_cipher_key[0], 0x20);
    EXPECT_EQ(keys.handshake_hash[0], 0x30);
    EXPECT_EQ(keys.peer_static_pk[0], 0x40);

    vt->handshake_close(static_cast<void*>(&host), state);
}

TEST(RemoteHostSecurity, EncryptDecryptRoundTrip) {
    gn::core::PluginContext ctx;
    ctx.plugin_name = "remote_noise_stub_test";
    ctx.kind        = GN_PLUGIN_KIND_SECURITY;

    gn::core::RemoteHost host;
    std::string diag;
    ASSERT_EQ(host.spawn(worker_binary_path(),
                          std::span<const std::string>(),
                          ctx, make_stub_host_api(), diag), GN_OK) << diag;
    void* self_handle = nullptr;
    ASSERT_EQ(host.call_init(&self_handle), GN_OK);

    const gn_security_provider_vtable_t* vt = host.security_vtable_proxy();
    ASSERT_NE(vt, nullptr);

    std::array<std::uint8_t, GN_PRIVATE_KEY_BYTES> sk{};
    std::array<std::uint8_t, GN_PUBLIC_KEY_BYTES>  pk{};
    void* state = nullptr;
    ASSERT_EQ(vt->handshake_open(
        static_cast<void*>(&host), 1u,
        GN_TRUST_LOOPBACK, GN_ROLE_INITIATOR,
        sk.data(), pk.data(), nullptr, &state), GN_OK);

    const std::vector<std::uint8_t> plaintext = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE};
    gn_secure_buffer_t ct{};
    ASSERT_EQ(vt->encrypt(static_cast<void*>(&host), state,
                           plaintext.data(), plaintext.size(), &ct), GN_OK);
    ASSERT_NE(ct.bytes, nullptr);
    ASSERT_EQ(ct.size, plaintext.size());
    for (size_t i = 0; i < plaintext.size(); ++i) {
        EXPECT_EQ(ct.bytes[i], plaintext[i] ^ 0x55) << "byte " << i;
    }

    gn_secure_buffer_t pt{};
    ASSERT_EQ(vt->decrypt(static_cast<void*>(&host), state,
                           ct.bytes, ct.size, &pt), GN_OK);
    ASSERT_NE(pt.bytes, nullptr);
    ASSERT_EQ(pt.size, plaintext.size());
    for (size_t i = 0; i < plaintext.size(); ++i) {
        EXPECT_EQ(pt.bytes[i], plaintext[i]) << "byte " << i;
    }

    if (ct.bytes && ct.free_fn) ct.free_fn(ct.free_user_data, ct.bytes);
    if (pt.bytes && pt.free_fn) pt.free_fn(pt.free_user_data, pt.bytes);

    EXPECT_EQ(vt->rekey(static_cast<void*>(&host), state), GN_OK);
    vt->handshake_close(static_cast<void*>(&host), state);
}
