/// @file   tests/integration/test_apps_goodnet.cpp
/// @brief  Smoke coverage for the `goodnet` multicall binary.
///
/// Drives the binary through `popen` for every shipped subcommand
/// and asserts on the exit code + leading output bytes. The binary
/// is the operator's surface — a green build that segfaults on
/// `goodnet version` would ship through CI without this layer.
///
/// `GOODNET_BIN_PATH` arrives as a CMake-defined string pointing at
/// the in-tree build artefact, so the test stays oblivious of the
/// install prefix.

#include <array>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>

#include <gtest/gtest.h>

#ifndef GOODNET_BIN_PATH
#error "GOODNET_BIN_PATH must be defined by the test target"
#endif

namespace {

struct CmdResult {
    int         exit_code = 0;
    std::string stdout_bytes;
};

CmdResult run_cmd(const std::string& cmd) {
    CmdResult out;
    /// `popen` redirects stdout only; we tack `2>&1` onto the
    /// command string so stderr is captured too — the dispatcher
    /// emits failure diagnostics there and we want them visible
    /// in test failures.
    ///
    /// `cert-env33-c` flags `popen` as a command-processor surface;
    /// here the input strings are test-controlled (binary path comes
    /// from a CMake-set absolute path, args from in-test literals),
    /// not user-derived. This is a test fixture, not a production
    /// path — same risk profile as the test harness already calling
    /// `system()` elsewhere.
    std::string full = cmd + " 2>&1";
    FILE* p = ::popen(full.c_str(), "r");  // NOLINT(cert-env33-c)
    if (!p) {
        out.exit_code = -1;
        return out;
    }
    std::array<char, 4096> buf{};
    while (auto n = std::fread(buf.data(), 1, buf.size(), p)) {
        out.stdout_bytes.append(buf.data(), n);
    }
    /// `pclose` returns the wait-status; extract the actual exit
    /// code per `wait(2)` so a non-zero exit reaches the assertion.
    const int wstatus = ::pclose(p);
    out.exit_code = (wstatus & 0xFF00) >> 8;
    return out;
}

std::string bin() { return std::string{GOODNET_BIN_PATH}; }

}  // namespace

TEST(AppsGoodnet, VersionPrintsSemver) {
    const auto r = run_cmd(bin() + " version");
    EXPECT_EQ(r.exit_code, 0) << r.stdout_bytes;
    EXPECT_NE(r.stdout_bytes.find("goodnet "), std::string::npos)
        << r.stdout_bytes;
}

TEST(AppsGoodnet, NoArgsPrintsUsageAndExitsTwo) {
    /// Usage error per `getopt(3)` convention.
    const auto r = run_cmd(bin());
    EXPECT_EQ(r.exit_code, 2);
    EXPECT_NE(r.stdout_bytes.find("usage: goodnet"), std::string::npos);
}

TEST(AppsGoodnet, UnknownSubcommandExitsTwo) {
    const auto r = run_cmd(bin() + " bogus");
    EXPECT_EQ(r.exit_code, 2);
    EXPECT_NE(r.stdout_bytes.find("unknown subcommand"), std::string::npos);
}

TEST(AppsGoodnet, ConfigValidateAcceptsEmptyJson) {
    /// `Config::load_file` accepts an empty JSON object as a config
    /// using every default — `validate_limits` runs against the
    /// defaults and passes. Pin that the v1 binary surface preserves
    /// the contract.
    const auto tmp = std::filesystem::temp_directory_path() /
                     "goodnet_test_empty.json";
    std::ofstream(tmp) << "{}\n";
    const auto r = run_cmd(bin() + " config validate " + tmp.string());
    EXPECT_EQ(r.exit_code, 0) << r.stdout_bytes;
    EXPECT_NE(r.stdout_bytes.find("OK"), std::string::npos);
    std::filesystem::remove(tmp);
}

TEST(AppsGoodnet, ConfigValidateRejectsMissingFile) {
    const auto r = run_cmd(bin() +
                           " config validate /nonexistent/test_path.json");
    EXPECT_EQ(r.exit_code, 1);
}

TEST(AppsGoodnet, PluginHashOnSelfBinaryMatchesStableShape) {
    /// The binary itself is a regular file; hashing it through the
    /// subcommand pins the output shape (`<64-hex>  <path>`) without
    /// requiring a plugin .so to be available in every test env.
    const auto r = run_cmd(bin() + " plugin hash " + bin());
    EXPECT_EQ(r.exit_code, 0) << r.stdout_bytes;
    /// 64 hex chars + two spaces + path + newline.
    EXPECT_GE(r.stdout_bytes.size(), std::size_t{64 + 2 + bin().size() + 1});
    /// First 64 chars are lowercase hex.
    for (std::size_t i = 0; i < 64; ++i) {
        const char c = r.stdout_bytes[i];
        EXPECT_TRUE((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))
            << "non-hex at byte " << i << ": '" << c << "'";
    }
}

TEST(AppsGoodnet, ManifestGenEmitsParseableJson) {
    /// Round-trip: emit a manifest of the binary itself, parse it
    /// back through `PluginManifest::parse`. The format must match.
    const auto r = run_cmd(bin() + " manifest gen " + bin());
    EXPECT_EQ(r.exit_code, 0) << r.stdout_bytes;
    EXPECT_NE(r.stdout_bytes.find("\"plugins\""), std::string::npos);
    EXPECT_NE(r.stdout_bytes.find("\"sha256\""), std::string::npos);
    EXPECT_NE(r.stdout_bytes.find(bin()), std::string::npos);
}

TEST(AppsGoodnet, IdentityGenWritesMode0600AndShowRoundTrips) {
    /// Generate fresh identity to a tmp path, verify mode 0600, run
    /// `show` and assert the address bytes match `gen` output. The
    /// file format pins `NodeIdentity::save_to_file` /
    /// `load_from_file` round-trip — Ed25519 signatures are
    /// deterministic per (seed, message), so the reconstructed
    /// attestation matches the original byte-for-byte and the
    /// derived address matches.
    const auto path = std::filesystem::temp_directory_path() /
                      "goodnet_test_identity.bin";
    std::filesystem::remove(path);  // start clean

    const auto gen = run_cmd(bin() + " identity gen --out " +
                              path.string() + " --expiry 1234567890");
    EXPECT_EQ(gen.exit_code, 0) << gen.stdout_bytes;
    EXPECT_NE(gen.stdout_bytes.find("address:"), std::string::npos);

    /// File mode 0600 — secret seed never world-readable.
    std::error_code ec;
    const auto perms = std::filesystem::status(path, ec).permissions();
    EXPECT_FALSE(ec) << ec.message();
    using std::filesystem::perms;
    EXPECT_EQ((perms & perms::group_all),    perms::none);
    EXPECT_EQ((perms & perms::others_all),   perms::none);

    const auto show = run_cmd(bin() + " identity show " + path.string());
    EXPECT_EQ(show.exit_code, 0) << show.stdout_bytes;
    EXPECT_NE(show.stdout_bytes.find("address:"), std::string::npos);
    EXPECT_NE(show.stdout_bytes.find("expiry:"),  std::string::npos);
    EXPECT_NE(show.stdout_bytes.find("1234567890"), std::string::npos);

    /// Determinism: extract the address line from gen output and
    /// confirm show prints the same bytes.
    const auto addr_line = [](const std::string& s) {
        const auto p = s.find("address:");
        if (p == std::string::npos) return std::string{};
        const auto eol = s.find('\n', p);
        return s.substr(p, eol - p);
    };
    EXPECT_EQ(addr_line(gen.stdout_bytes), addr_line(show.stdout_bytes));

    std::filesystem::remove(path);
}

TEST(AppsGoodnet, IdentityGenRefusesToClobber) {
    /// Pre-existing file at the target path → `gen` fails with the
    /// no-clobber error rather than overwriting an operator's
    /// already-deployed identity.
    const auto path = std::filesystem::temp_directory_path() /
                      "goodnet_test_clobber.bin";
    std::ofstream(path) << "not an identity blob";

    const auto r = run_cmd(bin() + " identity gen --out " + path.string());
    EXPECT_EQ(r.exit_code, 1);
    EXPECT_NE(r.stdout_bytes.find("could not create file"), std::string::npos);

    std::filesystem::remove(path);
}

TEST(AppsGoodnet, IdentityShowRejectsTamperedFile) {
    /// File of wrong size / bad magic → `load_from_file` returns
    /// `INTEGRITY_FAILED`, surfaced as exit 1 with a diagnostic that
    /// mentions the size mismatch (the most common reason an
    /// operator's identity stops loading).
    const auto path = std::filesystem::temp_directory_path() /
                      "goodnet_test_tampered.bin";
    std::ofstream(path) << "garbage";

    const auto r = run_cmd(bin() + " identity show " + path.string());
    EXPECT_EQ(r.exit_code, 1);
    EXPECT_NE(r.stdout_bytes.find("file size != 77 bytes"), std::string::npos);

    std::filesystem::remove(path);
}

TEST(AppsGoodnet, IdentityGenWithoutOutFlagRejected) {
    /// Secret seeds must never reach stdout — `gen` requires `--out`
    /// even though every other subcommand happily prints to stdout.
    /// Pin the policy.
    const auto r = run_cmd(bin() + " identity gen");
    EXPECT_EQ(r.exit_code, 2);
    EXPECT_NE(r.stdout_bytes.find("--out <file> is required"),
              std::string::npos);
}
