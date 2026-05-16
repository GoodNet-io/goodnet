/// @file   apps/goodnetd/subcommands/identity.cpp
/// @brief  `goodnet identity gen|show` — node identity lifecycle.
///
/// `gen --out <file> [--expiry <unix-ts>]` writes a fresh identity
/// to disk at file mode 0600 via `NodeIdentity::save_to_file`. The
/// `--out` flag is mandatory: secret seeds never reach stdout, and
/// the operator's redirect on a typo is otherwise unrecoverable.
/// `--expiry` defaults to 0 (no expiry — current attestation
/// semantics treat 0 as a permissive sentinel).
///
/// `show <file>` prints the public surface (address, user_pk,
/// device_pk, attestation expiry). Secret keys are never printed,
/// even when the file is owner-readable.

#include "../subcommands.hpp"

#include <charconv>
#include <cstdio>
#include <string>

#include <core/identity/node_identity.hpp>

namespace gn::apps::goodnet {

namespace {

void print_pk(const char* label, const ::gn::PublicKey& pk) {
    /// Stable lowercase hex — same shape as `goodnet plugin hash`
    /// output so operators can scan a multi-line dump consistently.
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(pk.size() * 2);
    for (const auto byte : pk) {
        out.push_back(kHex[(byte >> 4) & 0x0F]);
        out.push_back(kHex[byte & 0x0F]);
    }
    (void)std::fprintf(stdout, "%-12s%s\n", label, out.c_str());
}

int do_gen(std::span<const std::string_view> args) {
    std::string out_path;
    std::int64_t expiry_unix_ts = 0;

    for (std::size_t i = 0; i < args.size(); ++i) {
        const auto a = args[i];
        if (a == "--out") {
            if (i + 1 >= args.size()) {
                (void)std::fputs(
                    "goodnet identity gen: --out requires an argument\n",
                    stderr);
                return 2;
            }
            out_path.assign(args[++i]);
        } else if (a == "--expiry") {
            if (i + 1 >= args.size()) {
                (void)std::fputs(
                    "goodnet identity gen: --expiry requires an argument\n",
                    stderr);
                return 2;
            }
            const auto val = args[++i];
            const auto* first = val.data();
            const auto* last  = val.data() + val.size();
            const auto rc = std::from_chars(first, last, expiry_unix_ts);
            if (rc.ec != std::errc{} || rc.ptr != last) {
                (void)std::fprintf(stderr,
                    "goodnet identity gen: --expiry value '%.*s' is not a "
                    "signed 64-bit integer\n",
                    static_cast<int>(val.size()), val.data());
                return 2;
            }
        } else {
            (void)std::fprintf(stderr,
                "goodnet identity gen: unknown argument '%.*s'\n",
                static_cast<int>(a.size()), a.data());
            return 2;
        }
    }

    if (out_path.empty()) {
        (void)std::fputs(
            "goodnet identity gen: --out <file> is required (secret seeds "
            "must not reach stdout)\n",
            stderr);
        return 2;
    }

    auto identity = gn::core::identity::NodeIdentity::generate(expiry_unix_ts);
    if (!identity) {
        (void)std::fprintf(stderr,
            "goodnet identity gen: keypair generation failed (%s)\n",
            identity.error().what.empty()
                ? "unknown"
                : identity.error().what.c_str());
        return 1;
    }
    auto saved = gn::core::identity::NodeIdentity::save_to_file(
        *identity, out_path);
    if (!saved) {
        (void)std::fprintf(stderr,
            "goodnet identity gen: %s — %s\n",
            out_path.c_str(),
            saved.error().what.empty()
                ? "save failed"
                : saved.error().what.c_str());
        return 1;
    }

    (void)std::fprintf(stdout,
        "goodnet identity gen: wrote %s (mode 0600)\n", out_path.c_str());
    print_pk("address:", identity->address());
    print_pk("user_pk:", identity->user().public_key());
    print_pk("device_pk:", identity->device().public_key());
    return 0;
}

int do_show(std::span<const std::string_view> args) {
    if (args.size() != 1) {
        (void)std::fputs(
            "goodnet identity show: needs exactly one <file> argument\n",
            stderr);
        return 2;
    }
    const std::string path{args[0]};
    auto identity = gn::core::identity::NodeIdentity::load_from_file(path);
    if (!identity) {
        (void)std::fprintf(stderr,
            "goodnet identity show: %s — %s\n",
            path.c_str(),
            identity.error().what.empty()
                ? "load failed"
                : identity.error().what.c_str());
        return 1;
    }
    (void)std::fprintf(stdout, "goodnet identity show: %s\n", path.c_str());
    print_pk("address:", identity->address());
    print_pk("user_pk:", identity->user().public_key());
    print_pk("device_pk:", identity->device().public_key());
    (void)std::fprintf(stdout, "%-12s%lld\n",
                       "expiry:",
                       static_cast<long long>(
                           identity->attestation().expiry_unix_ts));
    return 0;
}

}  // namespace

int cmd_identity(std::span<const std::string_view> args) {
    if (args.empty()) {
        (void)std::fputs(
            "goodnet identity: action must be 'gen' or 'show'\n",
            stderr);
        return 2;
    }
    const auto action = args[0];
    if (action == "gen") {
        return do_gen(args.subspan(1));
    }
    if (action == "show") {
        return do_show(args.subspan(1));
    }
    (void)std::fprintf(stderr,
        "goodnet identity: unknown action '%.*s' (use 'gen' or 'show')\n",
        static_cast<int>(action.size()), action.data());
    return 2;
}

}  // namespace gn::apps::goodnet
