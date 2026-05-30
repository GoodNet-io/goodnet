// SPDX-License-Identifier: Apache-2.0
/// @file   sdk/cpp/identity.hpp
/// @brief  Identity source variants for `gn::sdk::Core`.
///
/// `Core::Options::identity` selects among three key-material sources:
///
///   * `IdentityFromFile`     — file-backed default. The kernel reads
///                              the libsodium blob via
///                              `gn_core_install_identity_from_file`.
///                              An empty path defers to the XDG
///                              default (`$XDG_CONFIG_HOME/goodnet/
///                              identity.bin`).
///   * `IdentityFromProvider` — HSM-backed. The kernel queries the
///                              named `gn.identity.<backend>`
///                              extension (PKCS#11 today, TPM /
///                              Keychain / WebAuthn once those
///                              plugins ship) and routes every
///                              `sign()` through the plugin's
///                              `gn_identity_signer_vtable_t`. The
///                              private key never enters process
///                              memory.
///   * `IdentityFromMemory`   — in-process secret bytes. Test
///                              fixtures and ephemeral nodes only.
///                              `gn_core_install_identity_from_memory`
///                              is not yet available; see
///                              `docs/contracts/identity.en.md` §12.
///
/// `Identity` is a thin tagged-union over the three variants with
/// readable static factories:
///
/// @code
/// gn::sdk::Core core{{
///     .identity = gn::sdk::Identity::from_hsm({
///         .extension_id = "gn.identity.pkcs11",
///         .key_label    = "my-yubikey",
///     }),
/// }};
/// @endcode
///
/// The default-constructed `Identity` is `IdentityFromFile{}` with
/// an empty path (XDG default), so passing `Options{}` preserves
/// file-backed key material behaviour.

#pragma once

#include <array>
#include <cstdint>
#include <filesystem>
#include <string>
#include <utility>
#include <variant>

namespace gn::sdk {

/// File-backed identity. An empty @ref path resolves against
/// `$XDG_CONFIG_HOME/goodnet/identity.bin` (or
/// `$HOME/.config/goodnet/identity.bin`) at ctor time.
/// A non-empty path is taken verbatim.
struct IdentityFromFile {
    std::filesystem::path path;
};

/// Provider-backed identity. The kernel queries the named
/// extension under the canonical
/// `GN_EXT_IDENTITY_SIGNER_VERSION` pin (`sdk/extensions/
/// identity.h`), reads the `gn_identity_signer_vtable_t` from the
/// queried entry, and wraps it in an `IdentityPluginSigner`
/// adapter that routes every `sign()` through the plugin.
struct IdentityFromProvider {
    /// Canonical example: `"gn.identity.pkcs11"` (after the
    /// PKCS#11 dual-expose lands in v0.2). `"gn.identity.tpm"`,
    /// `"gn.identity.keychain"`, and `"gn.identity.webauthn"`
    /// follow once those backends ship.
    std::string extension_id;

    /// Plugin-opaque key identifier — PKCS#11 plugins forward it
    /// as `CKA_LABEL`, TPM plugins parse it as a persistent-handle
    /// string, Keychain plugins use it as the item name. The
    /// kernel passes the bytes through unmodified.
    std::string key_label;
};

/// In-process identity — 64-byte libsodium-layout Ed25519 secret.
/// Intended for unit tests and ephemeral nodes.
/// `gn_core_install_identity_from_memory` is not yet available;
/// construction throws `Error(GN_ERR_NOT_IMPLEMENTED)`.
struct IdentityFromMemory {
    std::array<std::uint8_t, 64> secret_key{};
};

/// Tagged-union wrapper over the three identity sources. Use the
/// static factories for readable construction at call sites.
class Identity {
public:
    using Source = std::variant<IdentityFromFile,
                                IdentityFromProvider,
                                IdentityFromMemory>;

    /// Default = file-backed at the XDG path.
    Identity() noexcept : src_{IdentityFromFile{}} {}

    explicit Identity(Source s) noexcept : src_{std::move(s)} {}

    /// File-backed factory. Empty path → XDG default.
    [[nodiscard]] static Identity from_file(IdentityFromFile f) {
        return Identity{Source{std::move(f)}};
    }

    /// HSM / provider-backed factory.
    [[nodiscard]] static Identity from_hsm(IdentityFromProvider p) {
        return Identity{Source{std::move(p)}};
    }

    /// In-memory identity factory — not yet implemented.
    /// @warning Throws gn::sdk::Error(GN_ERR_NOT_IMPLEMENTED) at runtime.
    ///          Do not use in production code.
    [[nodiscard]]
    [[deprecated("from_memory is not yet implemented — throws at runtime")]]
    static Identity from_memory(IdentityFromMemory m) {
        return Identity{Source{std::move(m)}};
    }

    /// Explicit "use the XDG default" alias for readability.
    [[nodiscard]] static Identity from_xdg_default() {
        return Identity{};
    }

    [[nodiscard]] const Source& source() const noexcept { return src_; }

private:
    Source src_;
};

}  // namespace gn::sdk
