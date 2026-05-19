// SPDX-License-Identifier: Apache-2.0
/// @file   tests/unit/sdk/test_sdk_core.cpp
/// @brief  Coverage for the SDK DX layer that landed alongside the
///         public C-ABI rewrite: `Core` RAII wrapper,
///         `host_api_default()` singleton, and the per-code `Error`
///         hint table.
///
/// The kernel side is exercised through the publicly exported
/// `sdk/core.h` C ABI — no kernel-private headers — so this test
/// also pins the documented out-of-tree shape downstream apps see.

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <string>
#include <string_view>
#include <type_traits>
#include <variant>

#include <sdk/cpp/core.hpp>
#include <sdk/cpp/errors.hpp>
#include <sdk/cpp/host_api_default.hpp>
#include <sdk/cpp/identity.hpp>
#include <sdk/host_api.h>
#include <sdk/types.h>

namespace {

/// Every documented `gn_result_t` value. The hint table must return
/// a non-empty string for each one — unhandled codes default to a
/// generic fallback which is also non-empty (covered separately).
constexpr std::array<gn_result_t, 18> kAllCodes{{
    GN_OK,
    GN_ERR_NULL_ARG,
    GN_ERR_OUT_OF_MEMORY,
    GN_ERR_INVALID_ENVELOPE,
    GN_ERR_UNKNOWN_RECEIVER,
    GN_ERR_PAYLOAD_TOO_LARGE,
    GN_ERR_DEFRAME_INCOMPLETE,
    GN_ERR_DEFRAME_CORRUPT,
    GN_ERR_NOT_IMPLEMENTED,
    GN_ERR_VERSION_MISMATCH,
    GN_ERR_LIMIT_REACHED,
    GN_ERR_INVALID_STATE,
    GN_ERR_INTEGRITY_FAILED,
    GN_ERR_INTERNAL,
    GN_ERR_NOT_FOUND,
    GN_ERR_OUT_OF_RANGE,
    GN_ERR_FRAME_TOO_LARGE,
    GN_ERR_WIRE_DECODE,
}};

}  // namespace

// ─── Error / hint table ───────────────────────────────────────────

TEST(SdkError, HintForEveryDocumentedCode) {
    for (const auto code : kAllCodes) {
        const auto h = gn::sdk::Error::hint_for(code);
        EXPECT_FALSE(h.empty())
            << "hint missing for gn_result_t code "
            << static_cast<int>(code);
    }
}

TEST(SdkError, HintForUnknownCodeFallsBack) {
    // A code outside the documented range still returns a non-empty
    // hint so log lines never carry an empty trailing field.
    // GN_ERR_* values are in the -1..-17 range today; pick a code
    // outside that range to force the default-case branch. The
    // reinterpret round-trip keeps `-Wconversion` quiet since the
    // value is technically out of the enum's nominal range.
    gn_result_t fake = GN_OK;
    int probe = -99;
    std::memcpy(&fake, &probe, sizeof(int));
    const auto h = gn::sdk::Error::hint_for(fake);
    EXPECT_FALSE(h.empty());
}

TEST(SdkError, WhatIncludesContextAndCode) {
    gn::sdk::Error e(GN_ERR_NOT_FOUND, "Core::test");
    const std::string what = e.what();
    EXPECT_NE(what.find("Core::test"), std::string::npos);
    EXPECT_EQ(e.code(), GN_ERR_NOT_FOUND);
    // Per-instance hint matches the static lookup.
    EXPECT_EQ(e.hint(), gn::sdk::Error::hint_for(GN_ERR_NOT_FOUND));
}

TEST(SdkError, HintForInvalidStateMentionsLifecycle) {
    const auto h = gn::sdk::Error::hint_for(GN_ERR_INVALID_STATE);
    // Hint string is stable across releases; check the substring
    // bindings match on. ("gn_core_start" appears in the hint —
    // bindings that catch INVALID_STATE want this string.)
    EXPECT_NE(h.find("gn_core_start"), std::string_view::npos);
}

TEST(SdkError, HintForIntegrityMentionsSha) {
    const auto h = gn::sdk::Error::hint_for(GN_ERR_INTEGRITY_FAILED);
    EXPECT_NE(h.find("SHA-256"), std::string_view::npos);
}

// ─── Core ctor lifecycle ──────────────────────────────────────────

TEST(SdkCore, DefaultCtorDoesNotCrash) {
    // The XDG-default path has no installed manifest in the test
    // env (CI / nix sandbox). `Core` skips the manifest load and
    // walks init → start with a freshly minted identity — no
    // throw.
    EXPECT_NO_THROW({
        gn::sdk::Core core;
        (void)core.host_api();
    });
}

TEST(SdkCore, ExplicitOptionsEmptyDoesNotCrash) {
    gn::sdk::Core::Options opts;
    opts.config_json = "{}";
    EXPECT_NO_THROW({
        gn::sdk::Core core(opts);
        EXPECT_NE(core.host_api(), nullptr);
        EXPECT_NE(core.raw(), nullptr);
    });
}

TEST(SdkCore, MissingIdentityFileThrowsWithPath) {
    gn::sdk::Core::Options opts;
    opts.identity = gn::sdk::Identity::from_file({
        .path = "/var/empty/this-path-should-not-exist-for-tests.bin",
    });
    try {
        gn::sdk::Core core(opts);
        FAIL() << "expected Error";
    } catch (const gn::sdk::Error& e) {
        EXPECT_EQ(e.code(), GN_ERR_NOT_FOUND);
        // Failure message must surface the path so the operator can
        // fix the typo without rereading the source.
        const std::string what = e.what();
        EXPECT_NE(what.find("this-path-should-not-exist"),
                  std::string::npos);
    }
}

// ─── Phase 5 identity variants ────────────────────────────────────

TEST(SdkCore, DefaultIdentityIsFile) {
    // Default-constructed Options carries
    // `Identity{IdentityFromFile{}}`. The XDG-default ctor path
    // wraps the same shape, so a freshly minted kernel pubkey
    // comes back non-zero (no installed identity → kernel mints
    // inside `gn_core_init`).
    gn::sdk::Core::Options opts;
    static_assert(std::is_same_v<decltype(opts.identity),
                                 gn::sdk::Identity>);
    const auto& src = opts.identity.source();
    EXPECT_TRUE(std::holds_alternative<gn::sdk::IdentityFromFile>(src));
    EXPECT_TRUE(std::get<gn::sdk::IdentityFromFile>(src).path.empty());

    gn::sdk::Core core(opts);
    const auto pk = core.pubkey();
    bool all_zero = true;
    for (auto b : pk.bytes) {
        if (b != 0) { all_zero = false; break; }
    }
    EXPECT_FALSE(all_zero);
}

TEST(SdkCore, IdentityFromFileExplicitPath) {
    // `Identity::from_file({.path = ...})` must land on the file
    // dispatch and forward the path to
    // `gn_core_install_identity_from_file`. The DX layer has no
    // "dump installed identity back to disk" helper today (that
    // sits behind a Phase 5.1 C ABI), so we exercise the dispatch
    // by pointing at a deliberately non-existent file and
    // asserting the file thunk returned `NOT_FOUND` with the path
    // echoed back in the error context. The path-echo is the
    // operator-facing signal that the dispatch fired against
    // `IdentityFromFile` and not the default mint-on-init branch.
    namespace fs = std::filesystem;
    const auto tmp_dir =
        fs::temp_directory_path() / "gn-sdk-core-identity-explicit";
    fs::create_directories(tmp_dir);
    const auto id_path = tmp_dir / "identity.bin";
    fs::remove(id_path);

    gn::sdk::Core::Options opts;
    opts.identity = gn::sdk::Identity::from_file({.path = id_path});
    try {
        gn::sdk::Core core(opts);
        FAIL() << "expected NOT_FOUND";
    } catch (const gn::sdk::Error& e) {
        EXPECT_EQ(e.code(), GN_ERR_NOT_FOUND);
        const std::string what = e.what();
        EXPECT_NE(what.find("identity.bin"), std::string::npos);
    }

    fs::remove_all(tmp_dir);
}

TEST(SdkCore, IdentityFromProviderNotFoundThrows) {
    // No `gn.identity.bogus` extension is registered in the unit-
    // test kernel. The provider dispatch must surface
    // GN_ERR_NOT_FOUND with the extension id in the context so
    // operators can correlate against the kernel log.
    gn::sdk::Core::Options opts;
    opts.identity = gn::sdk::Identity::from_hsm({
        .extension_id = "gn.identity.bogus-not-registered",
        .key_label    = "any-label",
    });
    try {
        gn::sdk::Core core(opts);
        FAIL() << "expected NOT_FOUND";
    } catch (const gn::sdk::Error& e) {
        EXPECT_EQ(e.code(), GN_ERR_NOT_FOUND);
        const std::string what = e.what();
        EXPECT_NE(what.find("gn.identity.bogus-not-registered"),
                  std::string::npos);
    }
}

TEST(SdkCore, IdentityFromMemoryNotImplemented) {
    // Phase 5.1 will add `gn_core_install_identity_from_memory`.
    // Until then the SDK dispatch throws NOT_IMPLEMENTED so
    // embedders see the missing-feature signal at construction
    // time instead of a silent fallback to "kernel mints fresh".
    gn::sdk::Core::Options opts;
    opts.identity = gn::sdk::Identity::from_memory({
        .secret_key = {},  // zero-filled; content irrelevant here
    });
    try {
        gn::sdk::Core core(opts);
        FAIL() << "expected NOT_IMPLEMENTED";
    } catch (const gn::sdk::Error& e) {
        EXPECT_EQ(e.code(), GN_ERR_NOT_IMPLEMENTED);
        const std::string what = e.what();
        EXPECT_NE(what.find("Phase 5.1"), std::string::npos);
    }
}

TEST(SdkCore, MoveLeavesSourceEmpty) {
    gn::sdk::Core a;
    auto* raw_a = a.raw();
    EXPECT_NE(raw_a, nullptr);

    gn::sdk::Core b(std::move(a));
    EXPECT_EQ(a.raw(), nullptr);   // NOLINT(bugprone-use-after-move)
    EXPECT_EQ(b.raw(), raw_a);
}

TEST(SdkCore, PubKeyIsNonZero) {
    gn::sdk::Core core;
    const auto pk = core.pubkey();
    bool all_zero = true;
    for (auto b : pk.bytes) {
        if (b != 0) { all_zero = false; break; }
    }
    EXPECT_FALSE(all_zero);
}

// ─── host_api_default singleton ───────────────────────────────────

TEST(SdkHostApiDefault, ReturnsSamePointerTwice) {
    auto* a = gn::sdk::host_api_default();
    auto* b = gn::sdk::host_api_default();
    ASSERT_NE(a, nullptr);
    EXPECT_EQ(a, b);
}
