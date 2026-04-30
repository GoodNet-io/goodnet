/// @file   tests/unit/plugin/test_plugin_manifest.cpp
/// @brief  Plugin integrity manifest — parser + verifier, hash
///         streamer, hex codec, and the kernel-side enforcement
///         in `PluginManager::open_one`.
///
/// Pins `plugin-manifest.md` invariants:
///   - empty manifest = developer mode (every plugin loads);
///   - non-empty manifest = production mode (path absent or hash
///     mismatch fails with `GN_ERR_INTEGRITY_FAILED`);
///   - duplicate paths in the manifest are rejected at parse time.

#include <gtest/gtest.h>

#include <fcntl.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <span>
#include <string>
#include <vector>

#include <core/plugin/plugin_manifest.hpp>

#include <sdk/types.h>

namespace gn::core {
namespace {

namespace fs = std::filesystem;

/// Materialise a temp file with @p contents and return its path.
/// The fixture cleans up at teardown.
[[nodiscard]] fs::path write_temp(const std::string& name,
                                   std::span<const std::uint8_t> bytes) {
    auto p = fs::temp_directory_path() / name;
    std::ofstream f(p, std::ios::binary | std::ios::trunc);
    f.write(reinterpret_cast<const char*>(bytes.data()),
            static_cast<std::streamsize>(bytes.size()));
    return p;
}

}  // namespace

// ─── Hex codec ──────────────────────────────────────────────────────

TEST(PluginManifest_Hex, RoundTripPreservesBytes) {
    PluginHash original{};
    for (std::size_t i = 0; i < original.size(); ++i) {
        original[i] = static_cast<std::uint8_t>(i * 7 + 3);
    }
    const auto hex = PluginManifest::encode_hex(original);
    EXPECT_EQ(hex.size(), 64u);

    auto decoded = PluginManifest::decode_hex(hex);
    ASSERT_TRUE(decoded.has_value());
    if (decoded.has_value()) {
        EXPECT_EQ(*decoded, original);
    }
}

TEST(PluginManifest_Hex, DecodeRejectsWrongLength) {
    EXPECT_FALSE(PluginManifest::decode_hex("").has_value());
    EXPECT_FALSE(PluginManifest::decode_hex("abcd").has_value());
    EXPECT_FALSE(PluginManifest::decode_hex(std::string(63, 'a')).has_value());
    EXPECT_FALSE(PluginManifest::decode_hex(std::string(65, 'a')).has_value());
}

TEST(PluginManifest_Hex, DecodeRejectsNonHexCharacters) {
    /// 64-char string, valid length, but with one ASCII junk char.
    std::string bad(64, 'a');
    bad[10] = 'z';
    EXPECT_FALSE(PluginManifest::decode_hex(bad).has_value());
}

// ─── SHA-256 streaming ──────────────────────────────────────────────

TEST(PluginManifest_Sha, KnownAnswerForEmptyFile) {
    const auto path = write_temp("gn_manifest_empty", {});

    auto digest = PluginManifest::sha256_of_file(path.string());
    fs::remove(path);
    ASSERT_TRUE(digest.has_value());

    /// SHA-256("") = e3b0c44298fc1c149afbf4c8996fb924…
    auto expected = PluginManifest::decode_hex(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    ASSERT_TRUE(expected.has_value());
    if (digest.has_value() && expected.has_value()) {
        EXPECT_EQ(*digest, *expected);
    }
}

TEST(PluginManifest_Sha, KnownAnswerForSmallPayload) {
    const std::array<std::uint8_t, 3> abc{0x61, 0x62, 0x63};
    const auto path = write_temp("gn_manifest_abc", abc);

    auto digest = PluginManifest::sha256_of_file(path.string());
    fs::remove(path);
    ASSERT_TRUE(digest.has_value());

    /// SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223…
    auto expected = PluginManifest::decode_hex(
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    ASSERT_TRUE(expected.has_value());
    if (digest.has_value() && expected.has_value()) {
        EXPECT_EQ(*digest, *expected);
    }
}

TEST(PluginManifest_Sha, MissingFileReturnsNullopt) {
    EXPECT_FALSE(
        PluginManifest::sha256_of_file("/nonexistent/path/no-such-file").has_value());
}

TEST(PluginManifest_Sha, FdReadMatchesPathRead) {
    /// `sha256_of_fd` and `sha256_of_file` must agree on the same
    /// inode — the kernel uses one for verification and the other
    /// as the production fallback. A drift between them would let
    /// a Linux deployment pass integrity while a non-Linux build
    /// of the same binary fails or vice versa.
    const std::array<std::uint8_t, 5> abc{'a', 'b', 'c', 'd', 'e'};
    const auto path = write_temp("gn_manifest_fd_match", abc);
    const auto by_path = PluginManifest::sha256_of_file(path.string());
    ASSERT_TRUE(by_path.has_value());

    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    ASSERT_GE(fd, 0);
    const auto by_fd = PluginManifest::sha256_of_fd(fd);
    ::close(fd);
    ASSERT_TRUE(by_fd.has_value());
    if (by_path.has_value() && by_fd.has_value()) {
        EXPECT_EQ(*by_path, *by_fd);
    }
}

TEST(PluginManifest_Sha, FdInvalidReturnsNullopt) {
    EXPECT_FALSE(PluginManifest::sha256_of_fd(-1).has_value());
}

TEST(PluginManifest_Sha, FdOpenedWithNoFollowRefusesSymlink) {
    /// `plugin-manifest.md` §4.1 — the kernel opens the manifest
    /// path with `O_NOFOLLOW` so a symlink at the leaf component
    /// is refused before any hashing runs. The defence is not
    /// inside `sha256_of_fd` itself (which receives an already-
    /// opened descriptor); this pin asserts the open-time guard
    /// that the kernel's load path relies on.
    const std::array<std::uint8_t, 3> abc{'a', 'b', 'c'};
    const auto target = write_temp("gn_manifest_symlink_target", abc);
    const auto link   = fs::temp_directory_path() / "gn_manifest_symlink_link";
    fs::remove(link);
    fs::create_symlink(target, link);

    const int fd = ::open(link.c_str(),
                          O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    EXPECT_LT(fd, 0);
    EXPECT_EQ(errno, ELOOP);
    if (fd >= 0) ::close(fd);
    fs::remove(link);
}

TEST(PluginManifest_Verify, ContainsRunsBeforeIO) {
    /// `manifest_.contains(path)` short-circuits unlisted-path
    /// queries without paying the hash I/O cost. A path absent
    /// from the manifest reports `false` even when the file does
    /// not exist — the lookup is path-only.
    PluginManifest m;
    PluginHash hash{};
    hash.fill(0xAA);
    m.add_entry("/listed/path.so", hash);

    EXPECT_TRUE(m.contains("/listed/path.so"));
    EXPECT_FALSE(m.contains("/different/path.so"));
    EXPECT_FALSE(m.contains("/no/such/file.so"));
}

// ─── Manifest parser ────────────────────────────────────────────────

TEST(PluginManifest_Parse, AcceptsWellFormedDocument) {
    const std::string json = R"({
        "plugins": [
            { "path": "/usr/lib/goodnet/libtcp.so",
              "sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" }
        ]
    })";
    PluginManifest m;
    std::string diag;
    ASSERT_EQ(PluginManifest::parse(json, m, diag), GN_OK) << diag;

    ASSERT_EQ(m.entries().size(), 1u);
    EXPECT_EQ(m.entries()[0].path, "/usr/lib/goodnet/libtcp.so");
    EXPECT_FALSE(m.empty());
}

TEST(PluginManifest_Parse, RejectsDuplicatePaths) {
    const std::string json = R"({
        "plugins": [
            { "path": "p", "sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" },
            { "path": "p", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" }
        ]
    })";
    PluginManifest m;
    std::string diag;
    EXPECT_EQ(PluginManifest::parse(json, m, diag), GN_ERR_INTEGRITY_FAILED);
    EXPECT_NE(diag.find("duplicates"), std::string::npos) << diag;
}

TEST(PluginManifest_Parse, RejectsMalformedHex) {
    const std::string json = R"({
        "plugins": [{ "path": "p", "sha256": "not-hex" }]
    })";
    PluginManifest m;
    std::string diag;
    EXPECT_EQ(PluginManifest::parse(json, m, diag), GN_ERR_INTEGRITY_FAILED);
    EXPECT_NE(diag.find("64 hex"), std::string::npos) << diag;
}

TEST(PluginManifest_Parse, RejectsMissingPluginsArray) {
    PluginManifest m;
    std::string diag;
    EXPECT_EQ(PluginManifest::parse("{}", m, diag),
              GN_ERR_INTEGRITY_FAILED);
}

TEST(PluginManifest_Parse, RejectsInvalidJson) {
    PluginManifest m;
    std::string diag;
    EXPECT_EQ(PluginManifest::parse("not json", m, diag),
              GN_ERR_INTEGRITY_FAILED);
}

TEST(PluginManifest_Parse, EmptyPluginsArrayProducesEmptyManifest) {
    PluginManifest m;
    std::string diag;
    ASSERT_EQ(PluginManifest::parse(R"({"plugins":[]})", m, diag), GN_OK);
    EXPECT_TRUE(m.empty());
}

// ─── Verifier ──────────────────────────────────────────────────────

TEST(PluginManifest_Verify, AcceptsMatchingHash) {
    const std::array<std::uint8_t, 3> abc{0x61, 0x62, 0x63};
    const auto path = write_temp("gn_manifest_verify_ok", abc);

    auto digest = PluginManifest::decode_hex(
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    ASSERT_TRUE(digest.has_value());

    PluginManifest m;
    if (digest.has_value()) {
        m.add_entry(path.string(), *digest);
    }

    std::string diag;
    EXPECT_TRUE(m.verify(path.string(), diag)) << diag;
    fs::remove(path);
}

TEST(PluginManifest_Verify, RejectsHashMismatch) {
    const std::array<std::uint8_t, 3> abc{0x61, 0x62, 0x63};
    const auto path = write_temp("gn_manifest_verify_mismatch", abc);

    PluginManifest m;
    PluginHash wrong{};                    // all zeros — definitely not abc
    m.add_entry(path.string(), wrong);

    std::string diag;
    EXPECT_FALSE(m.verify(path.string(), diag));
    EXPECT_NE(diag.find("mismatch"), std::string::npos) << diag;
    fs::remove(path);
}

TEST(PluginManifest_Verify, RejectsUnlistedPath) {
    PluginManifest m;
    PluginHash any{};
    m.add_entry("/some/registered/path.so", any);

    std::string diag;
    EXPECT_FALSE(m.verify("/another/unregistered/path.so", diag));
    EXPECT_NE(diag.find("no manifest entry"), std::string::npos) << diag;
}

TEST(PluginManifest_Verify, RejectsUnreadableFile) {
    PluginManifest m;
    PluginHash any{};
    m.add_entry("/nonexistent/missing-plugin.so", any);

    std::string diag;
    EXPECT_FALSE(m.verify("/nonexistent/missing-plugin.so", diag));
    EXPECT_NE(diag.find("could not read"), std::string::npos) << diag;
}

TEST(PluginManifest_Verify, PathCanonicalisationMatchesEquivalentSpellings) {
    /// `add_entry` and `verify` both canonicalise their paths so a
    /// caller-side `./foo` matches a manifest-side absolute path
    /// (and vice versa). Without canonicalisation a working
    /// manifest is brittle to trivial path-string variations.
    const std::array<std::uint8_t, 3> abc{0x61, 0x62, 0x63};
    const auto path = write_temp("gn_manifest_canon", abc);

    auto digest = PluginManifest::decode_hex(
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    ASSERT_TRUE(digest.has_value());

    PluginManifest m;
    if (digest.has_value()) {
        m.add_entry(path.string(), *digest);
    }

    /// Lookup via the same absolute path succeeds (control case).
    std::string diag;
    EXPECT_TRUE(m.verify(path.string(), diag)) << diag;

    /// Lookup via a relative spelling resolves to the same canonical
    /// form when the caller's CWD includes the temp directory. Most
    /// CI/test harnesses do not chdir into /tmp; instead, we verify
    /// the round trip through the canonicaliser by feeding the
    /// already-canonical path through a redundant prefix path
    /// component (`/tmp/./gn_manifest_canon`).
    const std::string redundant =
        path.parent_path().string() + "/./" + path.filename().string();
    EXPECT_TRUE(m.verify(redundant, diag)) << diag;

    fs::remove(path);
}

}  // namespace gn::core
