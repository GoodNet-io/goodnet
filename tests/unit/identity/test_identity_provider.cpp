/// @file   tests/unit/identity/test_identity_provider.cpp
/// @brief  Coverage for Phase 2 of the HSM-friendly identity refactor.
///
/// Drives `gn_core_install_identity_from_provider` end-to-end through
/// a stub extension that backs `gn_identity_signer_vtable_t` with a
/// libsodium-generated keypair held in test scope. The stub embeds
/// the vtable as the first member of a wrapper struct so the
/// kernel's `ctx = &vtable` convention lets the thunks recover their
/// state on every call.

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <memory>
#include <string>

#include <sodium.h>

#include <core/identity/node_identity.hpp>
#include <core/kernel/core_c_internal.hpp>
#include <sdk/core.h>
#include <sdk/extensions/identity.h>

namespace {

/// Wrapper struct: vtable first, libsodium keypair fields after. The
/// kernel hands `ctx = &vt` to every thunk; because `vt` is the first
/// member, the cast back to `StubProvider*` is well-defined.
struct StubProvider {
    gn_identity_signer_vtable_t  vt;
    std::array<std::uint8_t, 32> pk;
    std::array<std::uint8_t, 64> sk;  /// libsodium Ed25519 secret-key blob
};

extern "C" gn_result_t stub_get_pubkey(void* ctx,
                                       const char* key_label,
                                       std::uint8_t* out) {
    if (ctx == nullptr || key_label == nullptr || out == nullptr) {
        return GN_ERR_NULL_ARG;
    }
    auto* self = static_cast<StubProvider*>(ctx);
    /// The stub honours one fixed label so the test can assert the
    /// kernel does pass `key_label` through unmodified.
    if (std::strcmp(key_label, "stub-key") != 0) return GN_ERR_NOT_FOUND;
    std::memcpy(out, self->pk.data(), 32);
    return GN_OK;
}

extern "C" gn_result_t stub_sign(void* ctx,
                                  const char* key_label,
                                  const std::uint8_t* message,
                                  std::size_t message_len,
                                  std::uint8_t* out_sig) {
    if (ctx == nullptr || key_label == nullptr || out_sig == nullptr) {
        return GN_ERR_NULL_ARG;
    }
    if (message == nullptr && message_len != 0) return GN_ERR_NULL_ARG;
    if (std::strcmp(key_label, "stub-key") != 0) return GN_ERR_NOT_FOUND;
    auto* self = static_cast<StubProvider*>(ctx);
    unsigned long long sig_len = 0;
    if (::crypto_sign_detached(out_sig, &sig_len,
                                message, message_len,
                                self->sk.data()) != 0) {
        return GN_ERR_INVALID_STATE;
    }
    return GN_OK;
}

/// Build a fresh stub with a real libsodium keypair, populate the
/// vtable, register the extension, and return ownership through a
/// unique_ptr (test scope keeps the storage alive past the install).
[[nodiscard]] std::unique_ptr<StubProvider> make_and_register_stub(
    gn_core_t* core, const char* extension_id) {
    auto stub = std::make_unique<StubProvider>();
    std::memset(&stub->vt, 0, sizeof(stub->vt));
    stub->vt.api_size   = sizeof(gn_identity_signer_vtable_t);
    stub->vt.get_pubkey = &stub_get_pubkey;
    stub->vt.sign       = &stub_sign;
    if (::sodium_init() < 0) std::abort();
    if (::crypto_sign_keypair(stub->pk.data(), stub->sk.data()) != 0) {
        std::abort();
    }

    /// Register under the requested extension id. The kernel queries
    /// it by name through `gn_core_install_identity_from_provider`.
    const auto rc = core->kernel.extensions().register_extension(
        extension_id,
        GN_EXT_IDENTITY_SIGNER_VERSION,
        &stub->vt,
        /*lifetime_anchor*/ {});
    if (rc != GN_OK) return nullptr;
    return stub;
}

} // namespace

TEST(IdentityProvider, NullArgsRejected) {
    auto* core = gn_core_create();
    ASSERT_NE(core, nullptr);

    EXPECT_EQ(gn_core_install_identity_from_provider(
                 nullptr, "gn.identity.stub", "stub-key"),
              GN_ERR_NULL_ARG);
    EXPECT_EQ(gn_core_install_identity_from_provider(
                 core, nullptr, "stub-key"),
              GN_ERR_NULL_ARG);
    /// Empty extension id is treated the same as NULL — the registry
    /// rejects empty names so an explicit early bail keeps the
    /// caller's error site close to the bug.
    EXPECT_EQ(gn_core_install_identity_from_provider(
                 core, "", "stub-key"),
              GN_ERR_NULL_ARG);
    EXPECT_EQ(gn_core_install_identity_from_provider(
                 core, "gn.identity.stub", nullptr),
              GN_ERR_NULL_ARG);

    gn_core_destroy(core);
}

TEST(IdentityProvider, MissingExtensionReturnsNotFound) {
    auto* core = gn_core_create();
    ASSERT_NE(core, nullptr);

    /// No extension registered under this id — the registry miss
    /// surfaces as `GN_ERR_NOT_FOUND` straight through.
    EXPECT_EQ(gn_core_install_identity_from_provider(
                 core, "gn.identity.does_not_exist", "stub-key"),
              GN_ERR_NOT_FOUND);

    gn_core_destroy(core);
}

TEST(IdentityProvider, RegisterAndSignRoundTrip) {
    /// End-to-end proof that the install path wires a plugin-backed
    /// signer onto NodeIdentity and that signing through
    /// `signer()->sign(...)` round-trips with a libsodium verify
    /// against the public key the plugin reported.
    auto* core = gn_core_create();
    ASSERT_NE(core, nullptr);

    auto stub = make_and_register_stub(core, "gn.identity.stub");
    ASSERT_NE(stub, nullptr);

    /// Save the expected pubkey for later cross-check.
    std::array<std::uint8_t, 32> expected_pk = stub->pk;

    ASSERT_EQ(gn_core_install_identity_from_provider(
                 core, "gn.identity.stub", "stub-key"),
              GN_OK);

    /// The kernel-side NodeIdentity now exists; pull the snapshot
    /// and confirm `signer()->pubkey()` matches the stub's keypair.
    auto identity = core->kernel.node_identity();
    ASSERT_NE(identity.get(), nullptr);
    auto* signer = identity->signer();
    ASSERT_NE(signer, nullptr);

    std::array<std::uint8_t, 32> got_pk{};
    ASSERT_EQ(signer->pubkey(std::span<std::uint8_t, 32>{got_pk}), GN_OK);
    EXPECT_EQ(std::memcmp(got_pk.data(), expected_pk.data(), 32), 0);

    /// `user().public_key()` carries the same bytes — the kernel
    /// eagerly populated the cached binding identifier through
    /// `NodeIdentity::from_signer`.
    EXPECT_EQ(std::memcmp(identity->user().public_key().data(),
                           expected_pk.data(), 32), 0);

    /// Sign a fixed payload through the plugin signer and verify
    /// externally with libsodium — the actual private bytes are
    /// inside the stub, so a successful verify proves the kernel
    /// routed the call through the plugin (no in-process secret).
    const std::array<std::uint8_t, 11> message = {
        'p', 'h', 'a', 's', 'e', '-', 'p', 'r', 'o', 'v', '!'
    };
    std::array<std::uint8_t, 64> sig{};
    ASSERT_EQ(signer->sign(
                 std::span<const std::uint8_t>(message),
                 std::span<std::uint8_t, 64>{sig}),
              GN_OK);
    EXPECT_EQ(::crypto_sign_verify_detached(
                 sig.data(),
                 message.data(),
                 message.size(),
                 expected_pk.data()),
              0);

    /// Drop kernel before the stub storage to guarantee no
    /// after-free path runs through the signer.
    gn_core_destroy(core);
    stub.reset();
}

TEST(IdentityProvider, ApiSizeBelowMinimumRejects) {
    auto* core = gn_core_create();
    ASSERT_NE(core, nullptr);

    /// Build a stub with api_size = 0 — under the minimum that covers
    /// `get_pubkey + sign`. The kernel must reject the install up
    /// front rather than reach into uninitialised vtable slots.
    auto stub = std::make_unique<StubProvider>();
    std::memset(&stub->vt, 0, sizeof(stub->vt));
    stub->vt.api_size   = 0;
    stub->vt.get_pubkey = &stub_get_pubkey;
    stub->vt.sign       = &stub_sign;

    ASSERT_EQ(core->kernel.extensions().register_extension(
                 "gn.identity.stub_small",
                 GN_EXT_IDENTITY_SIGNER_VERSION,
                 &stub->vt,
                 /*lifetime_anchor*/ {}),
              GN_OK);

    EXPECT_EQ(gn_core_install_identity_from_provider(
                 core, "gn.identity.stub_small", "stub-key"),
              GN_ERR_VERSION_MISMATCH);

    /// No NodeIdentity should have been installed; init still has to
    /// be allowed to fall through to the default mint.
    EXPECT_FALSE(core->kernel.has_node_identity());

    gn_core_destroy(core);
}

TEST(IdentityProvider, MutuallyExclusiveWithFile) {
    namespace fs = std::filesystem;
    const auto tmp_dir = fs::temp_directory_path()
        / "gn_identity_provider_mutual_exclusion";
    fs::remove_all(tmp_dir);
    fs::create_directories(tmp_dir);
    const auto identity_path = (tmp_dir / "identity.bin").string();

    /// Persist a file-backed identity first.
    auto original = gn::core::identity::NodeIdentity::generate(
        /*expiry*/ 4'000'000'000);
    ASSERT_TRUE(original.has_value());
    ASSERT_TRUE(gn::core::identity::NodeIdentity::save_to_file(
                    *original, identity_path).has_value());

    auto* core = gn_core_create();
    ASSERT_NE(core, nullptr);

    auto stub = make_and_register_stub(core, "gn.identity.stub_mx");
    ASSERT_NE(stub, nullptr);

    /// File path wins first.
    ASSERT_EQ(gn_core_install_identity_from_file(core,
                                                  identity_path.c_str()),
              GN_OK);
    /// Second install through the provider path must surface as
    /// `GN_ERR_INVALID_STATE` so the operator's mistake is visible.
    EXPECT_EQ(gn_core_install_identity_from_provider(
                 core, "gn.identity.stub_mx", "stub-key"),
              GN_ERR_INVALID_STATE);

    gn_core_destroy(core);
    fs::remove_all(tmp_dir);
}
