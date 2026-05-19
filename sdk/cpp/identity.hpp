// SPDX-License-Identifier: Apache-2.0
/// @file   sdk/cpp/identity.hpp
/// @brief  Identity source variants for `gn::sdk::Core`.
///
/// Pre-Phase-5 `Core::Options` carried a single `identity_path`
/// field — the only knob the embedder had was "which file on disk
/// holds the libsodium-formatted secret". After the 5-phase HSM
/// refactor (`docs/contracts/identity.en.md` §12) the operator
/// picks among three sources:
///
///   * `IdentityFromFile`     — the legacy default. The kernel
///                              reads the libsodium blob with
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
///                              fixtures and ephemeral nodes only;
///                              the kernel writes the buffer to a
///                              `0600` tempfile under the runtime
///                              dir and forwards through
///                              `install_identity_from_file`, then
///                              unlinks the tempfile before the
///                              ctor returns. A dedicated C ABI
///                              entry is on the Phase 5.1 roadmap.
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
/// an empty path — i.e. the XDG default — so a downstream that
/// passes `Options{}` keeps the pre-Phase-5 behaviour.

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
/// `$HOME/.config/goodnet/identity.bin`) at ctor time, matching the
/// pre-Phase-5 default. A non-empty path is taken verbatim.
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
/// Used by unit tests and ephemeral nodes that mint a keypair on
/// the fly. The `Core` ctor writes the bytes to a `0600` tempfile
/// under the system runtime directory, calls
/// `gn_core_install_identity_from_file` against it, and unlinks
/// the tempfile before returning — the secret never lives on disk
/// past the install call. A dedicated
/// `gn_core_install_identity_from_memory` C ABI is reserved for
/// Phase 5.1; until then the tempfile shim keeps the kernel
/// surface untouched.
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

    /// Default = file-backed at the XDG path. Matches the
    /// pre-Phase-5 behaviour for hosts that pass `Options{}`.
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

    /// In-memory factory (tests, ephemeral nodes).
    [[nodiscard]] static Identity from_memory(IdentityFromMemory m) {
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
