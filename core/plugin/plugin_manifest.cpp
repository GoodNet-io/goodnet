/// @file   core/plugin/plugin_manifest.cpp
/// @brief  Implementation of the plugin integrity allowlist.

#include "plugin_manifest.hpp"

#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <memory>
#include <system_error>
#include <unordered_set>

#include <unistd.h>

#ifdef _WIN32
#include <io.h>
#endif

#include <nlohmann/json.hpp>
#include <sodium.h>

namespace gn::core {

namespace {

constexpr std::size_t kReadChunkBytes = std::size_t{64} * 1024;

/// RAII wrapper around `std::FILE*` so an early return — or a
/// future libsodium update that throws — cannot leak the
/// descriptor. `fclose`'s return value is intentionally ignored;
/// the manifest only reads, so a close error has no semantic
/// recovery path.
struct FileCloser {
    void operator()(std::FILE* f) const noexcept {
        if (f) (void)std::fclose(f);
    }
};
using FilePtr = std::unique_ptr<std::FILE, FileCloser>;

/// Canonicalise @p path so manifest entries match across trivial
/// representational differences (`./foo.so` vs `foo.so`,
/// build-relative vs absolute). Falls back to the original string
/// on filesystem errors so the verifier still produces a
/// deterministic "no manifest entry" diagnostic for paths that do
/// not exist.
[[nodiscard]] std::string canonicalise(const std::string& path) noexcept {
    try {
        std::error_code ec;
        auto abs = std::filesystem::weakly_canonical(path, ec);
        if (ec) return path;
        return abs.string();
    } catch (...) {
        return path;
    }
}

/// Convert one ASCII hex character into its 0..15 nibble. Returns
/// `-1` on a non-hex input so callers can fail the parse without a
/// throw.
[[nodiscard]] int decode_nibble(char c) noexcept {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

}  // namespace

std::optional<PluginHash>
PluginManifest::decode_hex(std::string_view hex) noexcept {
    if (hex.size() != 64) return std::nullopt;
    PluginHash out{};
    for (std::size_t i = 0; i < 32; ++i) {
        const int hi = decode_nibble(hex[2 * i]);
        const int lo = decode_nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return std::nullopt;
        out[i] = static_cast<std::uint8_t>((hi << 4) | lo);
    }
    return out;
}

std::string PluginManifest::encode_hex(const PluginHash& h) {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string out;
    out.resize(64);
    for (std::size_t i = 0; i < 32; ++i) {
        out[2 * i]     = kDigits[(h[i] >> 4) & 0xF];
        out[2 * i + 1] = kDigits[h[i] & 0xF];
    }
    return out;
}

std::optional<PluginHash>
PluginManifest::sha256_of_file(const std::string& path) noexcept {
    FilePtr f{std::fopen(path.c_str(), "rb")};
    if (!f) return std::nullopt;

    crypto_hash_sha256_state state;
    crypto_hash_sha256_init(&state);

    std::array<std::uint8_t, kReadChunkBytes> buffer{};
    while (true) {
        const std::size_t n =
            std::fread(buffer.data(), 1, buffer.size(), f.get());
        if (n > 0) {
            crypto_hash_sha256_update(&state, buffer.data(), n);
        }
        /// `fread` returns short on EOF *or* error. Distinguish via
        /// `ferror` so a read fault produces a `nullopt` rather than
        /// a hash of the prefix the kernel managed to read. Checking
        /// `feof` before the next iteration is what
        /// `clang-analyzer-unix.Stream` is asking for: stream
        /// position becomes indeterminate after a partial read, so
        /// the loop must exit before issuing another `fread`.
        if (std::ferror(f.get())) {
            return std::nullopt;
        }
        if (std::feof(f.get())) {
            break;
        }
    }

    PluginHash digest{};
    crypto_hash_sha256_final(&state, digest.data());
    return digest;
}

std::optional<PluginHash>
PluginManifest::sha256_of_fd(int fd) noexcept {
    /// Large-file support — `pread` walks `off_t` offsets; a
    /// 32-bit `off_t` would silently truncate plugins above 2 GiB.
    /// Compile-time check costs nothing and rejects a build that
    /// would silently roll over.
    static_assert(sizeof(off_t) >= 8,
                  "off_t must be 64-bit; build with _FILE_OFFSET_BITS=64");
    if (fd < 0) return std::nullopt;

    crypto_hash_sha256_state state;
    crypto_hash_sha256_init(&state);

    /// `pread` reads from an explicit offset so the descriptor's
    /// shared seek state stays at zero — the same fd can be passed
    /// onward to `dlopen` afterwards without an `lseek` rewind.
    std::array<std::uint8_t, kReadChunkBytes> buffer{};
    off_t off = 0;
    while (true) {
#ifdef _WIN32
        /// mingw lacks `pread`; ucrt offers `_lseeki64` + `_read`.
        /// The fd here belongs to one-shot manifest verification
        /// (`open` → `sha256_of_fd` → `dlopen`) so the absence of
        /// pread's "leaves seek alone" guarantee does not matter —
        /// dlopen reopens by `/proc/self/fd/N` on Linux only.
        if (::_lseeki64(fd, static_cast<__int64>(off), SEEK_SET) == -1) {
            return std::nullopt;
        }
        const int n = ::_read(fd, buffer.data(),
            static_cast<unsigned>(buffer.size()));
#else
        const ssize_t n = ::pread(fd, buffer.data(), buffer.size(), off);
#endif
        if (n < 0) return std::nullopt;
        if (n == 0) break;
        crypto_hash_sha256_update(&state, buffer.data(),
                                   static_cast<std::size_t>(n));
        off += n;
    }

    PluginHash digest{};
    crypto_hash_sha256_final(&state, digest.data());
    return digest;
}

void PluginManifest::add_entry(const std::string& path,
                                const PluginHash&  sha256) {
    entries_.push_back({canonicalise(path), sha256});
}

gn_result_t PluginManifest::parse(std::string_view  json,
                                   PluginManifest&   out,
                                   std::string&      diagnostic) {
    out.entries_.clear();

    nlohmann::json parsed;
    try {
        parsed = nlohmann::json::parse(json);
    } catch (const std::exception& e) {
        diagnostic = "manifest JSON parse failed: ";
        diagnostic += e.what();
        return GN_ERR_INTEGRITY_FAILED;
    }

    if (!parsed.is_object() || !parsed.contains("plugins")) {
        diagnostic = "manifest missing top-level `plugins` array";
        return GN_ERR_INTEGRITY_FAILED;
    }

    const auto& plugins = parsed["plugins"];
    if (!plugins.is_array()) {
        diagnostic = "manifest `plugins` must be an array";
        return GN_ERR_INTEGRITY_FAILED;
    }

    /// Detect duplicate paths up front. Two entries pinning the
    /// same path to different hashes would let a misbehaving
    /// distribution accept either binary; reject the ambiguity at
    /// parse time so the kernel never has to choose.
    std::unordered_set<std::string> seen;
    seen.reserve(plugins.size());

    for (const auto& entry : plugins) {
        if (!entry.is_object()) {
            diagnostic = "manifest entry is not an object";
            return GN_ERR_INTEGRITY_FAILED;
        }
        if (!entry.contains("path") || !entry["path"].is_string()) {
            diagnostic = "manifest entry missing `path` (string)";
            return GN_ERR_INTEGRITY_FAILED;
        }
        if (!entry.contains("sha256") || !entry["sha256"].is_string()) {
            diagnostic = "manifest entry missing `sha256` (hex string)";
            return GN_ERR_INTEGRITY_FAILED;
        }

        std::string path = entry["path"].get<std::string>();
        if (path.empty()) {
            diagnostic = "manifest entry has empty path";
            return GN_ERR_INTEGRITY_FAILED;
        }
        const auto digest = decode_hex(entry["sha256"].get<std::string>());
        if (!digest) {
            diagnostic = "manifest entry sha256 is not 64 hex chars: ";
            diagnostic += path;
            return GN_ERR_INTEGRITY_FAILED;
        }

        std::string canonical = canonicalise(path);
        if (!seen.insert(canonical).second) {
            diagnostic = "manifest entry duplicates path: ";
            diagnostic += path;
            return GN_ERR_INTEGRITY_FAILED;
        }

        out.entries_.push_back({std::move(canonical), *digest});
    }
    return GN_OK;
}

namespace {

/// Locate the manifest entry for @p path; canonicalises the lookup
/// so relative and absolute spellings collapse to the same key.
[[nodiscard]] std::vector<ManifestEntry>::const_iterator
find_entry(const std::vector<ManifestEntry>& entries,
           const std::string& path) {
    /// Linear scan is fine for v1: even a saturated deployment
    /// loads a few dozen plugins. A future revision can switch to
    /// a hash-keyed map if the count climbs.
    const std::string lookup = canonicalise(path);
    return std::find_if(entries.begin(), entries.end(),
        [&](const ManifestEntry& e) { return e.path == lookup; });
}

}  // namespace

bool PluginManifest::contains(const std::string& path) const {
    return find_entry(entries_, path) != entries_.end();
}

bool PluginManifest::verify(const std::string& path,
                             std::string&       diagnostic) const {
    /// Lookup before hashing so an unlisted path returns the
    /// "no manifest entry" diagnostic without paying the file
    /// I/O cost. Tests pin the diagnostic strings.
    const auto it = find_entry(entries_, path);
    if (it == entries_.end()) {
        diagnostic = "no manifest entry for path: ";
        diagnostic += path;
        return false;
    }

    const auto observed = sha256_of_file(path);
    if (!observed) {
        diagnostic = "could not read plugin for hashing: ";
        diagnostic += path;
        return false;
    }

    if (*observed != it->sha256) {
        diagnostic = "manifest sha256 mismatch on: ";
        diagnostic += path;
        diagnostic += " (expected ";
        diagnostic += encode_hex(it->sha256);
        diagnostic += ", observed ";
        diagnostic += encode_hex(*observed);
        diagnostic += ')';
        return false;
    }

    return true;
}

bool PluginManifest::verify_digest(const std::string& path,
                                    const PluginHash&  observed,
                                    std::string&       diagnostic) const {
    const auto it = find_entry(entries_, path);
    if (it == entries_.end()) {
        diagnostic = "no manifest entry for path: ";
        diagnostic += path;
        return false;
    }

    if (observed != it->sha256) {
        diagnostic = "manifest sha256 mismatch on: ";
        diagnostic += path;
        diagnostic += " (expected ";
        diagnostic += encode_hex(it->sha256);
        diagnostic += ", observed ";
        diagnostic += encode_hex(observed);
        diagnostic += ')';
        return false;
    }

    return true;
}

}  // namespace gn::core