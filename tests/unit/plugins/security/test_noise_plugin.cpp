// SPDX-License-Identifier: Apache-2.0
/// @file   tests/unit/plugins/security/test_noise_plugin.cpp
/// @brief  dlopen + register + drive Noise XX handshake against the
///         .so plugin. Mirrors the harness used for the null provider:
///         a stub host_api captures the registered vtable, the test
///         exercises it directly. Two sessions run in the same test
///         (alice + bob) and shuttle handshake bytes between
///         themselves, then round-trip a transport-phase message.

#include <gtest/gtest.h>

#include <sodium.h>

#include <sdk/host_api.h>
#include <sdk/plugin.h>
#include <sdk/security.h>
#include <sdk/types.h>

#include <dlfcn.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#ifndef GOODNET_NOISE_PLUGIN_PATH
#error "GOODNET_NOISE_PLUGIN_PATH not defined; the build system must thread the .so path."
#endif

namespace {

struct NoisePluginHandle {
    using SdkVersionFn  = void        (*)(std::uint32_t*, std::uint32_t*, std::uint32_t*);
    using PluginInitFn  = gn_result_t (*)(const host_api_t*, void**);
    using PluginRegFn   = gn_result_t (*)(void*);
    using PluginUnregFn = gn_result_t (*)(void*);
    using PluginShutFn  = void        (*)(void*);
    using PluginDescFn  = const gn_plugin_descriptor_t* (*)(void);

    void*          handle      = nullptr;
    SdkVersionFn   sdk_version = nullptr;
    PluginInitFn   plugin_init = nullptr;
    PluginRegFn    plugin_reg  = nullptr;
    PluginUnregFn  plugin_unreg = nullptr;
    PluginShutFn   plugin_shut = nullptr;
    PluginDescFn   plugin_desc = nullptr;

    NoisePluginHandle() = default;
    NoisePluginHandle(const NoisePluginHandle&)            = delete;
    NoisePluginHandle& operator=(const NoisePluginHandle&) = delete;
    NoisePluginHandle(NoisePluginHandle&& o) noexcept { swap(o); }
    NoisePluginHandle& operator=(NoisePluginHandle&& o) noexcept {
        if (this != &o) { close(); swap(o); }
        return *this;
    }
    ~NoisePluginHandle() { close(); }

    void close() {
        if (handle) {
            ::dlclose(handle);
            handle = nullptr;
        }
        sdk_version = nullptr; plugin_init = nullptr; plugin_reg = nullptr;
        plugin_unreg = nullptr; plugin_shut = nullptr; plugin_desc = nullptr;
    }

    void swap(NoisePluginHandle& o) noexcept {
        std::swap(handle, o.handle);
        std::swap(sdk_version, o.sdk_version);
        std::swap(plugin_init, o.plugin_init);
        std::swap(plugin_reg,  o.plugin_reg);
        std::swap(plugin_unreg, o.plugin_unreg);
        std::swap(plugin_shut, o.plugin_shut);
        std::swap(plugin_desc, o.plugin_desc);
    }
};

template <class Fn>
Fn must_resolve(void* handle, const char* name) {
    ::dlerror();
    void* sym = ::dlsym(handle, name);
    const char* err = ::dlerror();
    EXPECT_EQ(err, nullptr) << "dlsym(" << name << "): " << (err ? err : "");
    return reinterpret_cast<Fn>(sym);
}

NoisePluginHandle load_plugin() {
    NoisePluginHandle h;
    h.handle = ::dlopen(GOODNET_NOISE_PLUGIN_PATH, RTLD_NOW | RTLD_LOCAL);
    if (!h.handle) {
        ADD_FAILURE() << "dlopen(\"" << GOODNET_NOISE_PLUGIN_PATH << "\"): "
                      << ::dlerror();
        return h;
    }
    h.sdk_version  = must_resolve<NoisePluginHandle::SdkVersionFn>(h.handle, "gn_plugin_sdk_version");
    h.plugin_init  = must_resolve<NoisePluginHandle::PluginInitFn>(h.handle, "gn_plugin_init");
    h.plugin_reg   = must_resolve<NoisePluginHandle::PluginRegFn>(h.handle, "gn_plugin_register");
    h.plugin_unreg = must_resolve<NoisePluginHandle::PluginUnregFn>(h.handle, "gn_plugin_unregister");
    h.plugin_shut  = must_resolve<NoisePluginHandle::PluginShutFn>(h.handle, "gn_plugin_shutdown");
    h.plugin_desc  = must_resolve<NoisePluginHandle::PluginDescFn>(h.handle, "gn_plugin_descriptor");
    return h;
}

struct CapturedRegistration {
    std::string                                provider_id;
    const gn_security_provider_vtable_t*       vtable      = nullptr;
    void*                                      self        = nullptr;
    int                                        register_calls   = 0;
    int                                        unregister_calls = 0;
};

CapturedRegistration g_captured;

gn_result_t stub_register_security(void* /*host_ctx*/,
                                   const char* provider_id,
                                   const gn_security_provider_vtable_s* vtable,
                                   void* self) {
    if (!provider_id || !vtable) return GN_ERR_NULL_ARG;
    g_captured.provider_id = provider_id;
    g_captured.vtable      = vtable;
    g_captured.self        = self;
    ++g_captured.register_calls;
    return GN_OK;
}

gn_result_t stub_unregister_security(void* /*host_ctx*/,
                                     const char* provider_id) {
    if (!provider_id) return GN_ERR_NULL_ARG;
    if (g_captured.provider_id != provider_id) return GN_ERR_NOT_FOUND;
    g_captured.provider_id.clear();
    g_captured.vtable = nullptr;
    g_captured.self   = nullptr;
    ++g_captured.unregister_calls;
    return GN_OK;
}

host_api_t make_stub_api() {
    host_api_t api{};
    api.api_size            = sizeof(host_api_t);
    api.host_ctx            = nullptr;
    api.register_security   = &stub_register_security;
    api.unregister_security = &stub_unregister_security;
    return api;
}

/// Minimal Ed25519 keypair generation for the test — libsodium's
/// `crypto_sign_keypair` produces sk in libsodium layout (64 bytes).
struct Ed25519Pair {
    std::array<std::uint8_t, GN_PUBLIC_KEY_BYTES>  pk{};
    std::array<std::uint8_t, GN_PRIVATE_KEY_BYTES> sk{};
};

Ed25519Pair make_keypair() {
    Ed25519Pair kp;
    ::crypto_sign_keypair(kp.pk.data(), kp.sk.data());
    return kp;
}

/// Drive a write-then-read step: caller side writes its next handshake
/// message, peer consumes it. Returns the bytes written so the peer
/// can feed them on its next call.
std::vector<std::uint8_t>
step(const gn_security_provider_vtable_t* vt, void* self, void* state,
     const std::vector<std::uint8_t>& incoming) {
    gn_secure_buffer_t buf{};
    EXPECT_EQ(vt->handshake_step(self, state,
                                  incoming.empty() ? nullptr : incoming.data(),
                                  incoming.size(),
                                  &buf), GN_OK);
    std::vector<std::uint8_t> out;
    if (buf.bytes && buf.size > 0) {
        out.assign(buf.bytes, buf.bytes + buf.size);
    }
    if (buf.free_fn && buf.bytes) {
        buf.free_fn(buf.free_user_data, buf.bytes);
    }
    return out;
}

}  // namespace

class NoisePluginTest : public ::testing::Test {
protected:
    void SetUp() override {
        g_captured = CapturedRegistration{};
        plugin_ = load_plugin();
        ASSERT_NE(plugin_.handle, nullptr);
        api_ = make_stub_api();
        ASSERT_EQ(plugin_.plugin_init(&api_, &plugin_self_), GN_OK);
        ASSERT_NE(plugin_self_, nullptr);
        ASSERT_EQ(plugin_.plugin_reg(plugin_self_), GN_OK);
        vtable_ = g_captured.vtable;
        ASSERT_NE(vtable_, nullptr);
    }

    void TearDown() override {
        if (plugin_self_) {
            EXPECT_EQ(plugin_.plugin_unreg(plugin_self_), GN_OK);
            plugin_.plugin_shut(plugin_self_);
            plugin_self_ = nullptr;
        }
    }

    NoisePluginHandle                    plugin_;
    host_api_t                           api_{};
    void*                                plugin_self_ = nullptr;
    const gn_security_provider_vtable_t* vtable_      = nullptr;
};

// ── descriptor / sdk version ─────────────────────────────────────────────

TEST_F(NoisePluginTest, SdkVersionMatchesHeader) {
    std::uint32_t maj = 0, min = 0, pat = 0;
    plugin_.sdk_version(&maj, &min, &pat);
    EXPECT_EQ(maj, GN_SDK_VERSION_MAJOR);
    EXPECT_EQ(min, GN_SDK_VERSION_MINOR);
    EXPECT_EQ(pat, GN_SDK_VERSION_PATCH);
}

TEST_F(NoisePluginTest, DescriptorAdvertisesNoiseExtension) {
    const auto* desc = plugin_.plugin_desc();
    ASSERT_NE(desc, nullptr);
    ASSERT_NE(desc->name, nullptr);
    EXPECT_STREQ(desc->name, "goodnet_security_noise");

    ASSERT_NE(desc->ext_provides, nullptr);
    bool found = false;
    for (const char* const* it = desc->ext_provides; *it != nullptr; ++it) {
        if (std::strcmp(*it, "gn.security.noise") == 0) found = true;
    }
    EXPECT_TRUE(found);
}

TEST_F(NoisePluginTest, ProviderIdEqualsNoise) {
    ASSERT_NE(vtable_->provider_id, nullptr);
    EXPECT_STREQ(vtable_->provider_id(plugin_self_), "noise");
}

// ── XX handshake round-trip ──────────────────────────────────────────────

TEST_F(NoisePluginTest, XxHandshakeReachesTransportPhase) {
    const auto alice_kp = make_keypair();
    const auto bob_kp   = make_keypair();

    void* alice = nullptr;
    void* bob   = nullptr;
    ASSERT_EQ(vtable_->handshake_open(plugin_self_, /*conn*/ 1,
                                       GN_TRUST_UNTRUSTED, GN_ROLE_INITIATOR,
                                       alice_kp.sk.data(), alice_kp.pk.data(),
                                       /*remote_pk*/ nullptr,
                                       &alice), GN_OK);
    ASSERT_EQ(vtable_->handshake_open(plugin_self_, /*conn*/ 2,
                                       GN_TRUST_UNTRUSTED, GN_ROLE_RESPONDER,
                                       bob_kp.sk.data(), bob_kp.pk.data(),
                                       /*remote_pk*/ nullptr,
                                       &bob), GN_OK);

    /// XX is three wire messages. Each `step()` call on the side
    /// that just received a message reads it and, when the local
    /// side is the writer for the next pattern step, produces the
    /// reply in the same call.
    std::vector<std::uint8_t> msg1 = step(vtable_, plugin_self_, alice, {});
    EXPECT_FALSE(msg1.empty());                    /// initiator writes msg1
    std::vector<std::uint8_t> msg2 = step(vtable_, plugin_self_, bob, msg1);
    EXPECT_FALSE(msg2.empty());                    /// responder reads msg1, writes msg2
    std::vector<std::uint8_t> msg3 = step(vtable_, plugin_self_, alice, msg2);
    EXPECT_FALSE(msg3.empty());                    /// initiator reads msg2, writes msg3
    std::vector<std::uint8_t> tail = step(vtable_, plugin_self_, bob, msg3);
    EXPECT_TRUE(tail.empty());                     /// responder reads msg3, handshake done

    EXPECT_NE(vtable_->handshake_complete(plugin_self_, alice), 0);
    EXPECT_NE(vtable_->handshake_complete(plugin_self_, bob), 0);

    /// Export keys on both sides; SDK exposes peer static pk + 32-byte
    /// channel-binding hash. Hash bytes match because the handshake
    /// transcript is identical on both sides.
    gn_handshake_keys_t alice_keys{};
    gn_handshake_keys_t bob_keys{};
    EXPECT_EQ(vtable_->export_transport_keys(plugin_self_, alice, &alice_keys), GN_OK);
    EXPECT_EQ(vtable_->export_transport_keys(plugin_self_, bob,   &bob_keys),   GN_OK);
    EXPECT_EQ(std::memcmp(alice_keys.handshake_hash, bob_keys.handshake_hash,
                           GN_HASH_BYTES), 0);

    /// Application-phase round-trip — alice encrypts, bob decrypts.
    const std::uint8_t plain[] = {'p','i','n','g'};
    gn_secure_buffer_t enc{};
    EXPECT_EQ(vtable_->encrypt(plugin_self_, alice, plain, sizeof(plain), &enc), GN_OK);
    ASSERT_NE(enc.bytes, nullptr);
    ASSERT_GT(enc.size, sizeof(plain));            /// cipher carries 16-byte tag

    gn_secure_buffer_t dec{};
    EXPECT_EQ(vtable_->decrypt(plugin_self_, bob, enc.bytes, enc.size, &dec), GN_OK);
    ASSERT_NE(dec.bytes, nullptr);
    EXPECT_EQ(dec.size, sizeof(plain));
    EXPECT_EQ(std::memcmp(dec.bytes, plain, sizeof(plain)), 0);

    if (enc.free_fn) enc.free_fn(enc.free_user_data, enc.bytes);
    if (dec.free_fn) dec.free_fn(dec.free_user_data, dec.bytes);

    /// Reverse direction works too.
    const std::uint8_t plain2[] = {'p','o','n','g'};
    gn_secure_buffer_t enc2{}, dec2{};
    EXPECT_EQ(vtable_->encrypt(plugin_self_, bob, plain2, sizeof(plain2), &enc2), GN_OK);
    EXPECT_EQ(vtable_->decrypt(plugin_self_, alice, enc2.bytes, enc2.size, &dec2), GN_OK);
    ASSERT_NE(dec2.bytes, nullptr);
    EXPECT_EQ(dec2.size, sizeof(plain2));
    EXPECT_EQ(std::memcmp(dec2.bytes, plain2, sizeof(plain2)), 0);
    if (enc2.free_fn) enc2.free_fn(enc2.free_user_data, enc2.bytes);
    if (dec2.free_fn) dec2.free_fn(dec2.free_user_data, dec2.bytes);

    vtable_->handshake_close(plugin_self_, alice);
    vtable_->handshake_close(plugin_self_, bob);
}

TEST_F(NoisePluginTest, EncryptRejectedBeforeHandshakeComplete) {
    const auto kp = make_keypair();
    void* state = nullptr;
    ASSERT_EQ(vtable_->handshake_open(plugin_self_, /*conn*/ 1,
                                       GN_TRUST_UNTRUSTED, GN_ROLE_INITIATOR,
                                       kp.sk.data(), kp.pk.data(),
                                       nullptr, &state), GN_OK);

    const std::uint8_t plain[] = {'x'};
    gn_secure_buffer_t out{};
    EXPECT_NE(vtable_->encrypt(plugin_self_, state, plain, sizeof(plain), &out), GN_OK);

    vtable_->handshake_close(plugin_self_, state);
}

TEST_F(NoisePluginTest, MalformedHandshakeBytesFail) {
    const auto kp = make_keypair();
    void* state = nullptr;
    ASSERT_EQ(vtable_->handshake_open(plugin_self_, /*conn*/ 2,
                                       GN_TRUST_UNTRUSTED, GN_ROLE_RESPONDER,
                                       kp.sk.data(), kp.pk.data(),
                                       nullptr, &state), GN_OK);

    /// Random short bytes — responder's first read expects a 32-byte
    /// ephemeral pk plus an encrypted-payload tail.
    const std::uint8_t junk[] = {0xAA, 0xBB, 0xCC};
    gn_secure_buffer_t out{};
    EXPECT_NE(vtable_->handshake_step(plugin_self_, state,
                                       junk, sizeof(junk), &out), GN_OK);

    vtable_->handshake_close(plugin_self_, state);
}
