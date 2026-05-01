/// @file   tests/unit/plugins/security/test_null.cpp
/// @brief  GoogleTest unit tests for the `null` security provider.
///
/// Per `docs/contracts/security-trust.md` §6 the null provider lives as
/// a plugin shared object — never linked statically into the kernel.
/// The build emits `libgoodnet_security_null.so` with hidden visibility
/// in standalone builds and default visibility for in-tree tests.
///
/// The test resolves the provider through `dlopen` to mirror how the
/// kernel loads it at runtime; this also exercises the `gn_plugin_*`
/// entry surface from `plugin.h`. The path to the .so is injected via
/// the CMake-generated define `GOODNET_NULL_PLUGIN_PATH`.

#include <gtest/gtest.h>

#include <dlfcn.h>

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

#include <sdk/abi.h>
#include <sdk/host_api.h>
#include <sdk/plugin.h>
#include <sdk/security.h>
#include <sdk/types.h>

#ifndef GOODNET_NULL_PLUGIN_PATH
#error "GOODNET_NULL_PLUGIN_PATH must be defined by the build system"
#endif

namespace {

/// Resolved entry symbols. RAII closes the handle on destruction; the
/// type is move-only so the load helper can return by value without
/// double-closing the dlopen handle.
struct NullPluginHandle {
    void* handle = nullptr;

    using SdkVersionFn   = void (*)(std::uint32_t*, std::uint32_t*, std::uint32_t*);
    using PluginInitFn   = gn_result_t (*)(const host_api_t*, void**);
    using PluginRegFn    = gn_result_t (*)(void*);
    using PluginUnregFn  = gn_result_t (*)(void*);
    using PluginShutFn   = void (*)(void*);
    using PluginDescFn   = const gn_plugin_descriptor_t* (*)(void);

    SdkVersionFn  sdk_version  = nullptr;
    PluginInitFn  plugin_init  = nullptr;
    PluginRegFn   plugin_reg   = nullptr;
    PluginUnregFn plugin_unreg = nullptr;
    PluginShutFn  plugin_shut  = nullptr;
    PluginDescFn  plugin_desc  = nullptr;

    NullPluginHandle() = default;
    NullPluginHandle(const NullPluginHandle&)            = delete;
    NullPluginHandle& operator=(const NullPluginHandle&) = delete;

    NullPluginHandle(NullPluginHandle&& other) noexcept { swap(other); }
    NullPluginHandle& operator=(NullPluginHandle&& other) noexcept {
        if (this != &other) {
            close();
            swap(other);
        }
        return *this;
    }

    ~NullPluginHandle() { close(); }

private:
    void close() noexcept {
        if (handle) {
            ::dlclose(handle);
            handle = nullptr;
        }
    }
    void swap(NullPluginHandle& o) noexcept {
        std::swap(handle,       o.handle);
        std::swap(sdk_version,  o.sdk_version);
        std::swap(plugin_init,  o.plugin_init);
        std::swap(plugin_reg,   o.plugin_reg);
        std::swap(plugin_unreg, o.plugin_unreg);
        std::swap(plugin_shut,  o.plugin_shut);
        std::swap(plugin_desc,  o.plugin_desc);
    }
};

template <class Fn>
Fn must_resolve(void* handle, const char* name) {
    ::dlerror();
    void* sym = ::dlsym(handle, name);
    const char* err = ::dlerror();
    EXPECT_EQ(err, nullptr) << "dlsym(" << name << ") failed: "
                            << (err ? err : "");
    return reinterpret_cast<Fn>(sym);
}

NullPluginHandle load_plugin() {
    NullPluginHandle h;
    h.handle = ::dlopen(GOODNET_NULL_PLUGIN_PATH, RTLD_NOW | RTLD_LOCAL);
    if (!h.handle) {
        ADD_FAILURE() << "dlopen(\"" << GOODNET_NULL_PLUGIN_PATH << "\") failed: "
                      << ::dlerror();
        return h;
    }
    h.sdk_version  = must_resolve<NullPluginHandle::SdkVersionFn>(
        h.handle, "gn_plugin_sdk_version");
    h.plugin_init  = must_resolve<NullPluginHandle::PluginInitFn>(
        h.handle, "gn_plugin_init");
    h.plugin_reg   = must_resolve<NullPluginHandle::PluginRegFn>(
        h.handle, "gn_plugin_register");
    h.plugin_unreg = must_resolve<NullPluginHandle::PluginUnregFn>(
        h.handle, "gn_plugin_unregister");
    h.plugin_shut  = must_resolve<NullPluginHandle::PluginShutFn>(
        h.handle, "gn_plugin_shutdown");
    h.plugin_desc  = must_resolve<NullPluginHandle::PluginDescFn>(
        h.handle, "gn_plugin_descriptor");
    return h;
}

/// Captured state populated by the host-side stub register_security.
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

/// Build a host_api populated only with the security registration stubs
/// the null plugin needs — every other entry stays NULL because the
/// plugin never calls them in init / register.
host_api_t make_stub_api() {
    host_api_t api{};
    api.api_size           = sizeof(host_api_t);
    api.host_ctx           = nullptr;
    api.register_security  = &stub_register_security;
    api.unregister_security = &stub_unregister_security;
    return api;
}

/// Helper: spin up plugin → init → register, return self handle and
/// the captured vtable for direct exercise.
struct LiveProvider {
    NullPluginHandle*                    plugin = nullptr;
    void*                                self   = nullptr;
    const gn_security_provider_vtable_t* vtable = nullptr;
};

}  // namespace

class NullPluginTest : public ::testing::Test {
protected:
    void SetUp() override {
        g_captured = CapturedRegistration{};
        plugin_ = load_plugin();
        ASSERT_NE(plugin_.handle, nullptr);

        api_ = make_stub_api();
    }

    LiveProvider activate() {
        LiveProvider lp{&plugin_, nullptr, nullptr};
        EXPECT_EQ(plugin_.plugin_init(&api_, &lp.self), GN_OK);
        EXPECT_NE(lp.self, nullptr);
        EXPECT_EQ(plugin_.plugin_reg(lp.self), GN_OK);
        lp.vtable = g_captured.vtable;
        EXPECT_NE(lp.vtable, nullptr);
        return lp;
    }

    void teardown(LiveProvider& lp) {
        if (!lp.self) return;
        EXPECT_EQ(plugin_.plugin_unreg(lp.self), GN_OK);
        plugin_.plugin_shut(lp.self);
        lp.self   = nullptr;
        lp.vtable = nullptr;
    }

    NullPluginHandle plugin_;
    host_api_t       api_{};
};

// ─── descriptor / sdk version ───────────────────────────────────────

TEST_F(NullPluginTest, SdkVersionMatchesHeader) {
    std::uint32_t maj = 0, min = 0, pat = 0;
    plugin_.sdk_version(&maj, &min, &pat);
    EXPECT_EQ(maj, GN_SDK_VERSION_MAJOR);
    EXPECT_EQ(min, GN_SDK_VERSION_MINOR);
    EXPECT_EQ(pat, GN_SDK_VERSION_PATCH);
}

TEST_F(NullPluginTest, DescriptorAdvertisesNullExtension) {
    const auto* desc = plugin_.plugin_desc();
    ASSERT_NE(desc, nullptr);
    ASSERT_NE(desc->name, nullptr);
    EXPECT_STREQ(desc->name, "goodnet_security_null");

    /// `ext_provides` is a null-terminated array containing
    /// "gn.security.null".
    ASSERT_NE(desc->ext_provides, nullptr);
    bool found = false;
    for (const char* const* it = desc->ext_provides; *it != nullptr; ++it) {
        if (std::strcmp(*it, "gn.security.null") == 0) found = true;
    }
    EXPECT_TRUE(found);
    /// ext_requires may be null for a leaf-provider plugin.
    EXPECT_EQ(desc->ext_requires, nullptr);
}

// ─── register / unregister ──────────────────────────────────────────

TEST_F(NullPluginTest, RegisterCallsHostAndCapturesVtable) {
    LiveProvider lp = activate();
    EXPECT_EQ(g_captured.register_calls, 1);
    EXPECT_EQ(g_captured.provider_id, "null");

    EXPECT_NE(lp.vtable, nullptr);
    EXPECT_EQ(lp.vtable->api_size, sizeof(gn_security_provider_vtable_t));

    teardown(lp);
    EXPECT_EQ(g_captured.unregister_calls, 1);
}

TEST_F(NullPluginTest, ProviderIdEqualsNull) {
    LiveProvider lp = activate();
    ASSERT_NE(lp.vtable, nullptr);
    ASSERT_NE(lp.vtable->provider_id, nullptr);
    EXPECT_STREQ(lp.vtable->provider_id(lp.self), "null");
    teardown(lp);
}

TEST_F(NullPluginTest, InitRejectsNullArgs) {
    void* self = nullptr;
    EXPECT_EQ(plugin_.plugin_init(nullptr, &self), GN_ERR_NULL_ARG);
    EXPECT_EQ(plugin_.plugin_init(&api_, nullptr), GN_ERR_NULL_ARG);
    EXPECT_EQ(plugin_.plugin_reg(nullptr), GN_ERR_NULL_ARG);
    EXPECT_EQ(plugin_.plugin_unreg(nullptr), GN_ERR_NULL_ARG);
}

// ─── handshake trivial paths ────────────────────────────────────────

TEST_F(NullPluginTest, HandshakeOpenSucceedsWithNullState) {
    LiveProvider lp = activate();
    void* state = reinterpret_cast<void*>(0xdeadbeef);
    const std::uint8_t sk[GN_PRIVATE_KEY_BYTES]{};
    const std::uint8_t pk[GN_PUBLIC_KEY_BYTES]{};
    EXPECT_EQ(lp.vtable->handshake_open(lp.self, /*conn*/ 1,
                                         GN_TRUST_LOOPBACK,
                                         GN_ROLE_INITIATOR,
                                         sk, pk, nullptr,
                                         &state),
              GN_OK);
    /// Null provider stores no per-conn state.
    EXPECT_EQ(state, nullptr);
    teardown(lp);
}

TEST_F(NullPluginTest, HandshakeOpenRejectsNullOut) {
    LiveProvider lp = activate();
    const std::uint8_t sk[GN_PRIVATE_KEY_BYTES]{};
    const std::uint8_t pk[GN_PUBLIC_KEY_BYTES]{};
    EXPECT_EQ(lp.vtable->handshake_open(lp.self, /*conn*/ 1,
                                         GN_TRUST_LOOPBACK,
                                         GN_ROLE_INITIATOR,
                                         sk, pk, nullptr,
                                         nullptr),
              GN_ERR_NULL_ARG);
    teardown(lp);
}

TEST_F(NullPluginTest, HandshakeStepProducesEmptyMessage) {
    LiveProvider lp = activate();
    gn_secure_buffer_t buf{};
    EXPECT_EQ(lp.vtable->handshake_step(lp.self, nullptr,
                                         /*incoming*/ nullptr,
                                         /*incoming_size*/ 0, &buf),
              GN_OK);
    EXPECT_EQ(buf.bytes,   nullptr);
    EXPECT_EQ(buf.size,    0u);
    EXPECT_EQ(buf.free_fn, nullptr);
    teardown(lp);
}

TEST_F(NullPluginTest, HandshakeStepRejectsNullOut) {
    LiveProvider lp = activate();
    EXPECT_EQ(lp.vtable->handshake_step(lp.self, nullptr,
                                         nullptr, 0, nullptr),
              GN_ERR_NULL_ARG);
    teardown(lp);
}

TEST_F(NullPluginTest, HandshakeCompleteIsOne) {
    LiveProvider lp = activate();
    EXPECT_EQ(lp.vtable->handshake_complete(lp.self, nullptr), 1);
    teardown(lp);
}

TEST_F(NullPluginTest, ExportTransportKeysReturnsZeroes) {
    LiveProvider lp = activate();
    gn_handshake_keys_t keys;
    /// Pre-fill with non-zero pattern; the call must zero-out.
    std::memset(&keys, 0xAA, sizeof(keys));
    EXPECT_EQ(lp.vtable->export_transport_keys(lp.self, nullptr, &keys),
              GN_OK);
    /// Inspect a few representative bytes — the call should have
    /// memset the entire struct to zero.
    EXPECT_EQ(keys.send_cipher_key[0], 0u);
    EXPECT_EQ(keys.recv_cipher_key[0], 0u);
    EXPECT_EQ(keys.initial_send_nonce, 0u);
    EXPECT_EQ(keys.initial_recv_nonce, 0u);
    teardown(lp);
}

TEST_F(NullPluginTest, RekeyIsNoOp) {
    LiveProvider lp = activate();
    EXPECT_EQ(lp.vtable->rekey(lp.self, nullptr), GN_OK);
    teardown(lp);
}

TEST_F(NullPluginTest, HandshakeCloseDoesNotCrash) {
    LiveProvider lp = activate();
    /// State is always nullptr for this provider; closing must be safe.
    lp.vtable->handshake_close(lp.self, nullptr);
    teardown(lp);
}

// ─── encrypt / decrypt ─────────────────────────────────────────────

TEST_F(NullPluginTest, EncryptCopiesPayloadBytes) {
    LiveProvider lp = activate();
    const std::uint8_t plaintext[] = {0x10, 0x20, 0x30, 0x40, 0x50};
    gn_secure_buffer_t out{};
    ASSERT_EQ(lp.vtable->encrypt(lp.self, nullptr,
                                   plaintext, sizeof(plaintext), &out),
              GN_OK);
    ASSERT_NE(out.bytes,    nullptr);
    ASSERT_NE(out.free_fn,  nullptr);
    EXPECT_EQ(out.size,     sizeof(plaintext));
    EXPECT_EQ(0, std::memcmp(out.bytes, plaintext, sizeof(plaintext)));

    /// The plugin allocates the buffer; we must free through the
    /// provided callback. Same-process here so this is a normal
    /// `std::free` — but the contract demands using `free_fn`.
    out.free_fn(out.bytes);
    teardown(lp);
}

TEST_F(NullPluginTest, DecryptCopiesPayloadBytes) {
    LiveProvider lp = activate();
    const std::uint8_t ciphertext[] = "abcdef";
    gn_secure_buffer_t out{};
    ASSERT_EQ(lp.vtable->decrypt(lp.self, nullptr,
                                   ciphertext, sizeof(ciphertext) - 1, &out),
              GN_OK);
    ASSERT_NE(out.bytes, nullptr);
    EXPECT_EQ(out.size,  sizeof(ciphertext) - 1);
    EXPECT_EQ(0, std::memcmp(out.bytes, ciphertext, sizeof(ciphertext) - 1));
    out.free_fn(out.bytes);
    teardown(lp);
}

TEST_F(NullPluginTest, EncryptDecryptRoundTrip) {
    LiveProvider lp = activate();
    const std::uint8_t input[] = {0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED};

    gn_secure_buffer_t enc{};
    ASSERT_EQ(lp.vtable->encrypt(lp.self, nullptr,
                                   input, sizeof(input), &enc),
              GN_OK);
    ASSERT_NE(enc.bytes, nullptr);

    gn_secure_buffer_t dec{};
    ASSERT_EQ(lp.vtable->decrypt(lp.self, nullptr,
                                   enc.bytes, enc.size, &dec),
              GN_OK);
    ASSERT_NE(dec.bytes, nullptr);
    EXPECT_EQ(dec.size,  sizeof(input));
    EXPECT_EQ(0, std::memcmp(dec.bytes, input, sizeof(input)));

    enc.free_fn(enc.bytes);
    dec.free_fn(dec.bytes);
    teardown(lp);
}

TEST_F(NullPluginTest, EncryptEmptyInputReturnsEmpty) {
    LiveProvider lp = activate();
    gn_secure_buffer_t out{};
    ASSERT_EQ(lp.vtable->encrypt(lp.self, nullptr,
                                   /*plaintext*/ nullptr,
                                   /*plaintext_size*/ 0, &out),
              GN_OK);
    EXPECT_EQ(out.bytes,   nullptr);
    EXPECT_EQ(out.size,    0u);
    EXPECT_EQ(out.free_fn, nullptr);

    /// Symmetric for decrypt of zero-length input.
    gn_secure_buffer_t out2{};
    ASSERT_EQ(lp.vtable->decrypt(lp.self, nullptr,
                                   nullptr, 0, &out2),
              GN_OK);
    EXPECT_EQ(out2.size, 0u);

    teardown(lp);
}

TEST_F(NullPluginTest, EncryptRejectsNullOut) {
    LiveProvider lp = activate();
    const std::uint8_t buf[1] = {0};
    EXPECT_EQ(lp.vtable->encrypt(lp.self, nullptr,
                                   buf, 1, /*out*/ nullptr),
              GN_ERR_NULL_ARG);
    EXPECT_EQ(lp.vtable->decrypt(lp.self, nullptr,
                                   buf, 1, /*out*/ nullptr),
              GN_ERR_NULL_ARG);
    teardown(lp);
}
