// SPDX-License-Identifier: Apache-2.0
/// @file   sdk/cpp/core.cpp
/// @brief  Out-of-line implementation for `core.hpp`, `errors.hpp`,
///         and `host_api_default.hpp`.
///
/// Lives in one translation unit so the SHA-256 + JSON manifest
/// parsing + error-table footprint compiles once and links into
/// every downstream binary that pulls `GoodNet::sdk_dx`.

#include <sdk/cpp/core.hpp>
#include <sdk/cpp/errors.hpp>
#include <sdk/cpp/host_api_default.hpp>

#include <algorithm>
#include <array>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <ios>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <system_error>
#include <variant>
#include <vector>

#include <nlohmann/json.hpp>
#include <sodium.h>

namespace gn::sdk {

// ─── Error ─────────────────────────────────────────────────────────

namespace {

/// Per-`gn_result_t` actionable hint. Stable strings — bindings
/// can match on them. Kept short; the operator reads the result
/// code + this hint, opens the relevant contract doc, and fixes.
struct HintRow {
    gn_result_t      code;
    std::string_view hint;
};

constexpr std::array<HintRow, 18> kHints{{
    {GN_OK,
        "no error"},
    {GN_ERR_NULL_ARG,
        "Null argument where one was required. Check that the host_api / "
        "Core pointer is non-null and that subscribe callbacks are set."},
    {GN_ERR_OUT_OF_MEMORY,
        "Allocator returned null. Check kernel limits or raise the "
        "process RAM rlimit."},
    {GN_ERR_INVALID_ENVELOPE,
        "Envelope rejected — sender_pk zero, msg_id zero, or a "
        "_reserved slot non-zero. Zero-init the envelope struct."},
    {GN_ERR_UNKNOWN_RECEIVER,
        "Receiver public key is not a local identity and no relay path "
        "matches. Verify the peer pubkey hex and your routing config."},
    {GN_ERR_PAYLOAD_TOO_LARGE,
        "Payload exceeds the link plugin's max_payload_size. Chunk the "
        "send or raise the limit in config JSON."},
    {GN_ERR_DEFRAME_INCOMPLETE,
        "Partial frame buffered — not an error in itself; the kernel "
        "retries automatically once more bytes arrive."},
    {GN_ERR_DEFRAME_CORRUPT,
        "Wire frame failed magic / length / version check. Likely a "
        "version mismatch between the two ends or a non-GoodNet peer."},
    {GN_ERR_NOT_IMPLEMENTED,
        "The kernel build does not provide this entry. Rebuild with the "
        "missing feature flag or pick a different code path."},
    {GN_ERR_VERSION_MISMATCH,
        "Plugin SDK major != kernel SDK major. Rebuild the plugin against "
        "this kernel's `sdk/types.h`."},
    {GN_ERR_LIMIT_REACHED,
        "A rate / queue limit fired. Slow down sends, raise the limit in "
        "config JSON, or wait for the backpressure-clear event."},
    {GN_ERR_INVALID_STATE,
        "Core not in the right phase. Did you forget gn_core_start, "
        "or call after Core's destructor ran?"},
    {GN_ERR_INTEGRITY_FAILED,
        "Integrity check failed — manifest SHA-256 mismatch, tampered "
        "identity file, or strict-mode manifest absent. Re-run "
        "sha256sum on the plugin and compare against the manifest."},
    {GN_ERR_INTERNAL,
        "Kernel caught an exception at a C ABI boundary. Check stderr / "
        "the kernel log for the underlying cause; this is a bug to file."},
    {GN_ERR_NOT_FOUND,
        "Resource missing. Check the identity path, the plugin manifest "
        "path, the extension name, or the URI scheme registration."},
    {GN_ERR_OUT_OF_RANGE,
        "Value outside the contract's permitted range. Check trust "
        "class, priority bucket, or numeric config values."},
    {GN_ERR_FRAME_TOO_LARGE,
        "Wire frame exceeds the kMaxFrameBytes ceiling. Lower "
        "max_payload_size or split the message."},
    {GN_ERR_WIRE_DECODE,
        "Wire-format decode failed (CBOR type mismatch, EOF, bad tag). "
        "Check that both peers run compatible protocol layers."},
}};

[[nodiscard]] std::string_view lookup_hint(gn_result_t code) noexcept {
    for (const auto& row : kHints) {
        if (row.code == code) return row.hint;
    }
    return "unknown error code; see sdk/types.h for the result-code list.";
}

}  // namespace

Error::Error(gn_result_t code, std::string_view context)
    : code_(code) {
    std::ostringstream os;
    os << context << ": " << gn_strerror(code)
       << " (code=" << static_cast<int>(code) << ")";
    msg_ = os.str();
}

std::string_view Error::hint() const noexcept {
    return lookup_hint(code_);
}

std::string_view Error::hint_for(gn_result_t code) noexcept {
    return lookup_hint(code);
}

// ─── Helpers ───────────────────────────────────────────────────────

namespace {

[[nodiscard]] std::filesystem::path xdg_config_dir() {
    if (const char* xdg = std::getenv("XDG_CONFIG_HOME"); xdg && *xdg) {
        return std::filesystem::path(xdg) / "goodnet";
    }
    if (const char* home = std::getenv("HOME"); home && *home) {
        return std::filesystem::path(home) / ".config" / "goodnet";
    }
    // Last-ditch: a directory that exists but is unlikely to contain
    // a manifest — the loader will treat it as "no defaults".
    return std::filesystem::path("./.goodnet");
}

/// Decode a 64-character lowercase-hex string into a 32-byte buffer.
/// Returns true on success.
[[nodiscard]] bool decode_sha256_hex(std::string_view hex,
                                      std::uint8_t out[32]) noexcept {
    if (hex.size() != 64) return false;
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
        if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
        return -1;
    };
    for (std::size_t i = 0; i < 32; ++i) {
        const int hi = nibble(hex[2 * i]);
        const int lo = nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = static_cast<std::uint8_t>((hi << 4) | lo);
    }
    return true;
}

/// Compute SHA-256 of the file at @p path into @p out_digest. Used
/// by the `Core(Options{.plugins=...})` path when the caller leaves
/// `PluginEntry.sha256` zero-filled — the kernel's loader compares
/// this digest against its own readback, so the caller can hand the
/// build-tree path without pre-computing a hash.
[[nodiscard]] gn_result_t sha256_of_file(
    const std::filesystem::path& path,
    std::uint8_t out_digest[32]) noexcept {
    std::ifstream f(path, std::ios::binary);
    if (!f) return GN_ERR_NOT_FOUND;
    if (sodium_init() < 0) return GN_ERR_INTEGRITY_FAILED;
    crypto_hash_sha256_state st;
    crypto_hash_sha256_init(&st);
    std::vector<unsigned char> buf(64 * 1024);
    while (f.good()) {
        f.read(reinterpret_cast<char*>(buf.data()),
                static_cast<std::streamsize>(buf.size()));
        const auto n = f.gcount();
        if (n > 0) {
            crypto_hash_sha256_update(
                &st, buf.data(), static_cast<unsigned long long>(n));
        }
        if (!f.good() && !f.eof()) return GN_ERR_INTEGRITY_FAILED;
    }
    crypto_hash_sha256_final(&st, out_digest);
    return GN_OK;
}

[[nodiscard]] bool digest_is_zero(const std::uint8_t d[32]) noexcept {
    for (std::size_t i = 0; i < 32; ++i) {
        if (d[i] != 0) return false;
    }
    return true;
}

/// Parse a manifest JSON file into matched arrays of paths and
/// SHA-256 digests. Throws `Error` on any parse / schema failure.
struct ParsedManifest {
    std::vector<std::string>  paths;
    std::vector<std::uint8_t> digests;  // count * 32, packed
    std::vector<const char*>  c_paths;  // back-pointers for the C ABI
};

[[nodiscard]] ParsedManifest parse_manifest(
    const std::filesystem::path& path) {
    std::ifstream f(path);
    if (!f) {
        throw Error(GN_ERR_NOT_FOUND,
                    "Core: open manifest " + path.string());
    }
    nlohmann::json j;
    try {
        f >> j;
    } catch (const std::exception& e) {
        throw Error(GN_ERR_WIRE_DECODE,
                    std::string("Core: parse manifest ") + path.string() +
                        ": " + e.what());
    }
    if (!j.is_object() || !j.contains("plugins") ||
        !j["plugins"].is_array()) {
        throw Error(GN_ERR_WIRE_DECODE,
                    "Core: manifest missing top-level `plugins` array");
    }

    ParsedManifest out;
    out.paths.reserve(j["plugins"].size());
    out.digests.reserve(j["plugins"].size() * 32);

    for (const auto& entry : j["plugins"]) {
        if (!entry.is_object() ||
            !entry.contains("path") || !entry["path"].is_string() ||
            !entry.contains("sha256") || !entry["sha256"].is_string()) {
            throw Error(GN_ERR_WIRE_DECODE,
                        "Core: manifest entry missing path/sha256");
        }
        out.paths.emplace_back(entry["path"].get<std::string>());
        std::uint8_t digest[32];
        if (!decode_sha256_hex(entry["sha256"].get<std::string>(), digest)) {
            throw Error(GN_ERR_INTEGRITY_FAILED,
                        "Core: bad sha256 hex in manifest");
        }
        out.digests.insert(out.digests.end(), digest, digest + 32);
    }

    out.c_paths.reserve(out.paths.size());
    for (const auto& p : out.paths) out.c_paths.push_back(p.c_str());
    return out;
}

}  // namespace

// ─── Core ──────────────────────────────────────────────────────────

namespace {

[[nodiscard]] Core::Options xdg_default_options() {
    Core::Options opts;
    const auto dir = xdg_config_dir();
    {
        std::error_code ec;
        auto p = dir / "identity.bin";
        if (std::filesystem::exists(p, ec)) {
            opts.identity = Identity::from_file(IdentityFromFile{std::move(p)});
        }
        // Otherwise fall through to the default-constructed `Identity`
        // (IdentityFromFile with empty path) — the install dispatch
        // treats an empty path as "skip; let `gn_core_init` mint a
        // fresh keypair", which matches the pre-Phase-5 behaviour.
    }
    {
        std::error_code ec;
        auto p = dir / "manifest.json";
        if (std::filesystem::exists(p, ec)) opts.manifest_path = std::move(p);
    }
    if (const char* env = std::getenv("GOODNET_CONFIG_JSON");
        env && *env) {
        opts.config_json = env;
    }
    return opts;
}

/// `std::visit` overload helper. Lives here rather than in a public
/// SDK header because the Phase 5 ctor is the only place the SDK
/// needs it; downstream embedders prefer their own visitor patterns.
template <class... Ts>
struct overloaded : Ts... { using Ts::operator()...; };
template <class... Ts>
overloaded(Ts...) -> overloaded<Ts...>;

}  // namespace

Core::Core() : Core(xdg_default_options()) {}

Core::Core(Options opts) {
    core_ = gn_core_create();
    if (!core_) {
        throw Error(GN_ERR_OUT_OF_MEMORY, "Core: gn_core_create");
    }

    try {
        if (!opts.config_json.empty() && opts.config_json != "{}") {
            if (const auto rc = gn_core_reload_config_json(
                    core_, opts.config_json.c_str());
                rc != GN_OK) {
                throw Error(rc, "Core: gn_core_reload_config_json");
            }
        }

        // Phase 5 install dispatch: pick the C ABI entry per the
        // identity-source variant. File / provider land on the
        // matching `gn_core_install_identity_from_*` thunks; memory
        // is reserved for a Phase 5.1 C ABI entry and currently
        // surfaces as `GN_ERR_NOT_IMPLEMENTED` — the on-disk format
        // expects a signed attestation that we cannot mint from a
        // bare 64-byte secret without touching kernel-private code.
        std::visit(overloaded{
            [&](const IdentityFromFile& f) {
                if (f.path.empty()) {
                    // Empty path = "kernel mints a fresh keypair
                    // inside gn_core_init". Matches pre-Phase-5
                    // behaviour when no identity.bin exists in
                    // $XDG_CONFIG_HOME.
                    return;
                }
                if (const auto rc = gn_core_install_identity_from_file(
                        core_, f.path.string().c_str());
                    rc != GN_OK) {
                    throw Error(rc,
                        "Core: gn_core_install_identity_from_file: " +
                        f.path.string());
                }
            },
            [&](const IdentityFromProvider& p) {
                if (const auto rc = gn_core_install_identity_from_provider(
                        core_,
                        p.extension_id.c_str(),
                        p.key_label.c_str());
                    rc != GN_OK) {
                    throw Error(rc,
                        "Core: gn_core_install_identity_from_provider: "
                        "extension_id=" + p.extension_id +
                        " key_label=" + p.key_label);
                }
            },
            [&](const IdentityFromMemory&) {
                // TODO(sdk-ext / Phase 5.1): add
                // `gn_core_install_identity_from_memory` C ABI that
                // takes the 64-byte secret directly and reconstructs
                // a signed `NodeIdentity` in-place. The tempfile shim
                // discussed in the Phase 5 plan is not viable because
                // `NodeIdentity::load_from_file` verifies an
                // attestation signature we cannot mint without
                // re-running the kernel's keypair-derive +
                // attestation flow — which lives behind the C ABI.
                throw Error(GN_ERR_NOT_IMPLEMENTED,
                    "Core: IdentityFromMemory: needs Phase 5.1 "
                    "gn_core_install_identity_from_memory C ABI");
            },
        }, opts.identity.source());

        if (const auto rc = gn_core_init(core_); rc != GN_OK) {
            throw Error(rc, "Core: gn_core_init");
        }

        // Aggregate plugin set: manifest path + explicit
        // `Options.plugins` vector, concatenated. Either may be
        // empty.
        std::vector<std::string>  agg_paths;
        std::vector<std::uint8_t> agg_digests;

        if (!opts.manifest_path.empty()) {
            auto parsed = parse_manifest(opts.manifest_path);
            agg_paths   = std::move(parsed.paths);
            agg_digests = std::move(parsed.digests);
        }
        for (const auto& e : opts.plugins) {
            agg_paths.emplace_back(e.path.string());
            std::uint8_t d[32];
            if (digest_is_zero(e.sha256.data())) {
                if (const auto rc = sha256_of_file(e.path, d); rc != GN_OK) {
                    throw Error(rc,
                        "Core: sha256_of_file " + e.path.string());
                }
            } else {
                std::memcpy(d, e.sha256.data(), 32);
            }
            agg_digests.insert(agg_digests.end(), d, d + 32);
        }

        if (!agg_paths.empty()) {
            std::vector<const char*> c_paths;
            c_paths.reserve(agg_paths.size());
            for (const auto& p : agg_paths) c_paths.push_back(p.c_str());
            if (const auto rc = gn_core_load_plugins_batch(
                    core_,
                    c_paths.data(),
                    agg_digests.data(),
                    agg_paths.size());
                rc != GN_OK) {
                throw Error(rc, "Core: gn_core_load_plugins_batch");
            }
        }

        if (const auto rc = gn_core_start(core_); rc != GN_OK) {
            throw Error(rc, "Core: gn_core_start");
        }

        api_ = gn_core_host_api(core_);
        if (!api_) {
            throw Error(GN_ERR_INTERNAL, "Core: gn_core_host_api");
        }
    } catch (...) {
        gn_core_destroy(core_);
        core_ = nullptr;
        api_  = nullptr;
        throw;
    }
}

Core::Core(Core&& other) noexcept
    : core_(other.core_), api_(other.api_) {
    other.core_ = nullptr;
    other.api_  = nullptr;
}

Core& Core::operator=(Core&& other) noexcept {
    if (this != &other) {
        if (core_) {
            gn_core_stop(core_);
            gn_core_destroy(core_);
        }
        core_       = other.core_;
        api_        = other.api_;
        other.core_ = nullptr;
        other.api_  = nullptr;
    }
    return *this;
}

Core::~Core() {
    if (core_) {
        gn_core_stop(core_);
        gn_core_destroy(core_);
        core_ = nullptr;
        api_  = nullptr;
    }
}

Core::PubKey Core::pubkey() const {
    PubKey out{};
    if (const auto rc = gn_core_get_pubkey(core_, out.bytes); rc != GN_OK) {
        throw Error(rc, "Core::pubkey: gn_core_get_pubkey");
    }
    return out;
}

ConnectedSession Core::connect_to(std::string_view uri) {
    auto opt = ::gn::sdk::connect_to(api_, uri);
    if (!opt) {
        throw Error(GN_ERR_NOT_FOUND,
                    std::string("Core::connect_to: ") + std::string(uri));
    }
    return std::move(*opt);
}

LinkCarrier Core::listen_to(std::string_view uri) {
    auto opt = ::gn::sdk::listen_to(api_, uri);
    if (!opt) {
        throw Error(GN_ERR_NOT_FOUND,
                    std::string("Core::listen_to: ") + std::string(uri));
    }
    return std::move(*opt);
}

namespace {

/// Per-subscription state captured by the C ABI thunk. Holds the
/// optional connection-id filter alongside the lambda so a single
/// callback type works both for "any conn" subscriptions
/// (`conn == GN_INVALID_ID`) and conn-pinned ones.
struct MessageCallbackHolder {
    gn_conn_id_t                       filter_conn;
    MessageSubscription::Callback      cb;
};

void message_thunk(void* ud,
                    gn_conn_id_t conn,
                    std::uint32_t /*msg*/,
                    const std::uint8_t* payload,
                    std::size_t payload_size) {
    if (!ud) return;
    auto* h = static_cast<MessageCallbackHolder*>(ud);
    if (h->filter_conn != GN_INVALID_ID && h->filter_conn != conn) {
        return;
    }
    try {
        h->cb(conn, std::span<const std::uint8_t>(payload, payload_size));
    } catch (...) {
        // C ABI boundary is noexcept — swallow.
    }
}

void holder_deleter(void* p) noexcept {
    delete static_cast<MessageCallbackHolder*>(p);
}

}  // namespace

MessageSubscription Core::subscribe(gn_conn_id_t conn,
                                      std::uint32_t msg,
                                      MessageSubscription::Callback cb) {
    if (!cb) {
        throw Error(GN_ERR_NULL_ARG, "Core::subscribe: empty callback");
    }
    auto* holder = new MessageCallbackHolder{conn, std::move(cb)};
    const std::uint64_t token = gn_core_subscribe(
        core_, msg, &message_thunk, holder);
    if (token == 0) {
        delete holder;
        throw Error(GN_ERR_INVALID_STATE, "Core::subscribe: gn_core_subscribe");
    }
    return MessageSubscription(core_, token, holder, &holder_deleter);
}

void Core::send_to(gn_conn_id_t conn,
                    std::uint32_t msg,
                    std::span<const std::uint8_t> payload) {
    if (const auto rc = gn_core_send_to(core_, conn, msg,
                                          payload.data(), payload.size());
        rc != GN_OK) {
        throw Error(rc, "Core::send_to: gn_core_send_to");
    }
}

void Core::wait() {
    if (core_) gn_core_wait(core_);
}

void MessageSubscription::release() noexcept {
    if (core_ && token_) {
        gn_core_unsubscribe(core_, token_);
    }
    core_  = nullptr;
    token_ = 0;
    holder_.reset();
}

// ─── host_api_default ──────────────────────────────────────────────

host_api_t* host_api_default() {
    static std::once_flag init_flag;
    static Core*          instance = nullptr;
    std::call_once(init_flag, [] {
        instance = new Core();  // leaked intentionally — see header doc
    });
    return instance ? instance->host_api() : nullptr;
}

}  // namespace gn::sdk
