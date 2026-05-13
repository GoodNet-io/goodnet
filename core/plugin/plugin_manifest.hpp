/// @file   core/plugin/plugin_manifest.hpp
/// @brief  Plugin integrity manifest — SHA-256 allowlist verified
///         before `dlopen`.
///
/// Plugin loading is the single most-trust-sensitive operation the
/// kernel performs: a `.so` it accepts becomes part of the kernel's
/// own address space. Without a manifest the kernel's only check is
/// "does this file have the right exported symbols", which any file
/// can satisfy. The manifest closes that gap by pinning each plugin
/// path to a cryptographic hash of the bytes the operator approved
/// at distribution time.
///
/// Lifecycle:
///   1. Operator builds the manifest at distribution time —
///      `goodnet manifest emit plugins/*.so > plugins.json`
///      (tooling lives outside this header).
///   2. Operator hands the manifest to `Kernel::set_plugin_manifest`
///      before reaching `Load` phase.
///   3. `PluginManager::load` consults the manifest before every
///      `dlopen`. A path not in the manifest, or a path whose
///      on-disk SHA-256 does not match the manifest's expectation,
///      fails with `GN_ERR_INTEGRITY_FAILED` and the corresponding
///      diagnostic.
///
/// `PluginManifest::empty()` means "manifest not installed" — the
/// kernel runs in developer mode and loads any plugin without
/// integrity checks. Production deployments install a manifest;
/// the empty-manifest path exists so in-tree fixtures, the demo,
/// and unit tests do not have to fabricate hashes for ephemeral
/// builds.
///
/// Per `docs/contracts/plugin-manifest.en.md`.

#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <sdk/types.h>

namespace gn::core {

/// SHA-256 digest sized for libsodium's `crypto_hash_sha256_BYTES`.
/// Defined as a fixed-size array so the manifest compares by value
/// without allocating; the caller serialises through hex.
using PluginHash = std::array<std::uint8_t, 32>;

/// Linkage mode the manifest declares for a single entry. The
/// kernel uses it to choose between `dlopen` and a subprocess
/// spawner over `sdk/remote/wire.h`. Defaults to `Dynamic` when
/// the manifest entry omits the field — preserves the historical
/// dlopen-only behaviour.
enum class ManifestKind : std::uint8_t {
    Dynamic = 0,   ///< dlopen path; the historical default
    Remote  = 1    ///< subprocess worker over the wire protocol
};

/// Single allowlist record: an absolute or build-relative plugin
/// path paired with the SHA-256 the operator approved. The
/// `kind`/`args` fields are only meaningful for remote entries and
/// are quietly ignored by the dlopen path.
struct ManifestEntry {
    std::string  path;
    PluginHash   sha256{};
    ManifestKind kind{ManifestKind::Dynamic};
    std::vector<std::string> args;  ///< argv tail handed to a remote worker
};

/// Operator-supplied integrity allowlist.
///
/// The class is value-typed and trivially copyable except for the
/// owned entries vector. Constructed empty by default; `parse`
/// populates from a JSON document, `add_entry` from a unit test
/// fixture.
class PluginManifest {
public:
    /// Parse @p json into an in-memory manifest.
    ///
    /// Format:
    /// @code
    ///   {
    ///     "plugins": [
    ///       { "path": "build/plugins/libgoodnet_tcp.so",
    ///         "sha256": "<64-hex>" },
    ///       ...
    ///     ]
    ///   }
    /// @endcode
    ///
    /// Returns `GN_OK` on success and stores entries in @p out.
    /// On parse failure returns `GN_ERR_INTEGRITY_FAILED` with a
    /// human-readable description in @p diagnostic. Duplicate paths,
    /// malformed hashes, and missing fields all fail this way — the
    /// manifest is the trust root, so an ambiguous spec is better
    /// rejected than tolerated.
    [[nodiscard]] static gn_result_t parse(std::string_view json,
                                            PluginManifest&  out,
                                            std::string&     diagnostic);

    /// Compute the SHA-256 of the file at @p path with libsodium.
    /// Streams the file in 64 KiB chunks so memory use is bounded.
    /// Returns `nullopt` on file-open / read failure.
    [[nodiscard]] static std::optional<PluginHash>
    sha256_of_file(const std::string& path) noexcept;

    /// Compute the SHA-256 of an already-opened file descriptor.
    /// The caller owns @p fd and is responsible for closing it; the
    /// function rewinds via `pread` so the descriptor's seek state
    /// is left untouched. Used by the kernel's load path to hash
    /// and `dlopen` the same inode (`/proc/self/fd/N`) so a
    /// concurrent symlink swap on the manifest path cannot route
    /// the dlopen to a different file than the one that hashed.
    /// Linux-only; non-Linux callers fall back to `sha256_of_file`.
    [[nodiscard]] static std::optional<PluginHash>
    sha256_of_fd(int fd) noexcept;

    /// Add a single entry programmatically. Used by tests and by
    /// the in-tree fixture path that builds a manifest at runtime.
    /// The path is canonicalised through `std::filesystem::
    /// weakly_canonical` before storage so subsequent `verify`
    /// lookups match equivalent path spellings.
    void add_entry(const std::string& path, const PluginHash& sha256);

    /// Verify @p path against the manifest.
    ///
    /// Returns `true` when:
    ///   1. The path appears in `entries`,
    ///   2. The on-disk SHA-256 of the file at that path matches
    ///      the manifest's expectation,
    ///   3. Both checks complete without I/O errors.
    ///
    /// On failure returns `false` and writes a diagnostic to
    /// @p diagnostic distinguishing missing-entry, hash-mismatch,
    /// and read-failure cases.
    [[nodiscard]] bool verify(const std::string& path,
                               std::string&       diagnostic) const;

    /// Verify against an already-hashed digest taken from an open
    /// file descriptor. The kernel computes the digest through
    /// `sha256_of_fd` and dlopens the same descriptor through
    /// `/proc/self/fd/N`; this overload accepts the precomputed
    /// digest so the manifest entry lookup uses @p path as the
    /// stable key while the hash comes from the inode the kernel
    /// is actually about to load.
    [[nodiscard]] bool verify_digest(const std::string& path,
                                      const PluginHash&  observed,
                                      std::string&       diagnostic) const;

    /// `true` when no entries were installed. The kernel treats
    /// empty as "developer mode": every plugin loads. Production
    /// installs a non-empty manifest.
    [[nodiscard]] bool empty() const noexcept { return entries_.empty(); }

    /// Cheap path-only membership check — no hashing. Used by the
    /// kernel's load path to short-circuit unlisted-path requests
    /// before opening + hashing the file.
    [[nodiscard]] bool contains(const std::string& path) const;

    /// Read-only access to the parsed entries; used by diagnostics
    /// and tests to walk the manifest without re-parsing.
    [[nodiscard]] const std::vector<ManifestEntry>& entries() const noexcept {
        return entries_;
    }

    /// Decode a 64-character hex string into a 32-byte digest.
    /// Returns `nullopt` on length mismatch or non-hex characters.
    [[nodiscard]] static std::optional<PluginHash>
    decode_hex(std::string_view hex) noexcept;

    /// Encode a 32-byte digest into a lowercase 64-character hex
    /// string. Used by the manifest-emit tooling and by test
    /// helpers that need to round-trip a generated hash.
    [[nodiscard]] static std::string encode_hex(const PluginHash& h);

private:
    std::vector<ManifestEntry> entries_;
};

}  // namespace gn::core
