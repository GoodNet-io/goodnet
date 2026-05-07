/// @file   apps/goodnet-ssh/main.cpp
/// @brief  Argv dispatcher for the three operational modes.
///
/// Mode selection rules:
///   1. `--listen` flag anywhere in argv ⇒ listen mode.
///   2. `--bridge` flag ⇒ bridge mode (positional argument: peer pk).
///   3. First non-flag positional argument ⇒ wrap mode
///      (interpreted as `[user@]<peer-pk>`).
///   4. Otherwise — print usage and exit 2.
///
/// Mode 1 (wrap) replaces the process via `execvp`; modes 2 and 3
/// return through the normal exit path. The dispatcher itself never
/// touches a kernel handle — every kernel-aware operation lives in
/// the per-mode translation units.

#include "modes.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace {

void print_usage() {
    (void)std::fputs(
        "usage: goodnet-ssh [user@]<peer-pk>          # wrap mode (invoke ssh)\n"
        "       goodnet-ssh --bridge <peer-pk>        # ProxyCommand callee\n"
        "       goodnet-ssh --listen [opts]           # server-side forwarder\n"
        "\n"
        "common options:\n"
        "  --identity <path>          operator identity file\n"
        "                             (default: ~/.config/goodnet/identity.bin)\n"
        "\n"
        "bridge options:\n"
        "  --uri <uri>                override peers.json lookup\n"
        "                             (e.g. tcp://192.168.1.5:9000)\n"
        "\n"
        "listen options:\n"
        "  --listen-uri <uri>         URI to bind on (default tcp://0.0.0.0:9001)\n"
        "  --target <host:port>       forward target (default 127.0.0.1:22)\n",
        stderr);
}

/// Parse `host:port` into separate fields. Honours bracketed IPv6
/// (`[::1]:22`); plain hostnames work without brackets. Returns
/// false on missing port or non-numeric port.
[[nodiscard]] bool parse_host_port(std::string_view spec,
                                    std::string& out_host,
                                    std::uint16_t& out_port) {
    if (spec.empty()) return false;
    std::string_view host_part;
    std::string_view port_part;
    if (spec.front() == '[') {
        const auto rb = spec.find(']');
        if (rb == std::string_view::npos) return false;
        host_part = spec.substr(1, rb - 1);
        if (rb + 1 >= spec.size() || spec[rb + 1] != ':') return false;
        port_part = spec.substr(rb + 2);
    } else {
        const auto colon = spec.rfind(':');
        if (colon == std::string_view::npos) return false;
        host_part = spec.substr(0, colon);
        port_part = spec.substr(colon + 1);
    }
    if (host_part.empty() || port_part.empty()) return false;

    int port = 0;
    for (const char c : port_part) {
        if (c < '0' || c > '9') return false;
        port = port * 10 + (c - '0');
        if (port > 65535) return false;
    }
    if (port <= 0) return false;
    out_host.assign(host_part);
    out_port = static_cast<std::uint16_t>(port);
    return true;
}

/// Parse the bridge mode's argv tail (everything after `--bridge`).
/// On success populates @p out_pk and @p out_opts; on failure prints
/// usage to stderr and returns 2.
[[nodiscard]] int parse_bridge_args(
    std::span<const std::string_view> args,
    std::string& out_pk,
    gn::apps::goodnet_ssh::Options& out_opts) {
    bool seen_pk = false;
    for (std::size_t i = 0; i < args.size(); ++i) {
        const auto a = args[i];
        const auto need_val = [&](const char* flag) -> bool {
            if (i + 1 >= args.size()) {
                (void)std::fprintf(stderr,
                    "goodnet-ssh bridge: %s requires an argument\n", flag);
                return false;
            }
            return true;
        };
        if (a == "--identity") {
            if (!need_val("--identity")) return 2;
            out_opts.identity_path.assign(args[++i]);
        } else if (a == "--uri") {
            if (!need_val("--uri")) return 2;
            out_opts.override_uri.assign(args[++i]);
        } else if (!seen_pk && !a.empty() && a[0] != '-') {
            out_pk.assign(a);
            seen_pk = true;
        } else {
            (void)std::fprintf(stderr,
                "goodnet-ssh bridge: unknown argument '%.*s'\n",
                static_cast<int>(a.size()), a.data());
            return 2;
        }
    }
    if (!seen_pk) {
        (void)std::fputs(
            "goodnet-ssh bridge: peer-pk positional argument required\n",
            stderr);
        return 2;
    }
    return 0;
}

[[nodiscard]] int parse_listen_args(
    std::span<const std::string_view> args,
    gn::apps::goodnet_ssh::ListenOptions& out_opts) {
    for (std::size_t i = 0; i < args.size(); ++i) {
        const auto a = args[i];
        const auto need_val = [&](const char* flag) -> bool {
            if (i + 1 >= args.size()) {
                (void)std::fprintf(stderr,
                    "goodnet-ssh listen: %s requires an argument\n", flag);
                return false;
            }
            return true;
        };
        if (a == "--identity") {
            if (!need_val("--identity")) return 2;
            out_opts.common.identity_path.assign(args[++i]);
        } else if (a == "--listen-uri") {
            if (!need_val("--listen-uri")) return 2;
            out_opts.listen_uri.assign(args[++i]);
        } else if (a == "--target") {
            if (!need_val("--target")) return 2;
            std::string host;
            std::uint16_t port = 0;
            if (!parse_host_port(args[++i], host, port)) {
                (void)std::fprintf(stderr,
                    "goodnet-ssh listen: --target value '%.*s' must be "
                    "host:port\n",
                    static_cast<int>(args[i].size()), args[i].data());
                return 2;
            }
            out_opts.target_host = std::move(host);
            out_opts.target_port = port;
        } else {
            (void)std::fprintf(stderr,
                "goodnet-ssh listen: unknown argument '%.*s'\n",
                static_cast<int>(a.size()), a.data());
            return 2;
        }
    }
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        print_usage();
        return 2;
    }

    std::vector<std::string_view> args;
    args.reserve(static_cast<std::size_t>(argc) - 1);
    for (int i = 1; i < argc; ++i) {
        args.emplace_back(argv[i]);
    }

    // Mode dispatch. Listen wins over bridge wins over wrap because
    // the listen mode is the only one that legitimately runs without
    // a positional peer-pk; wrap mode's positional argument can
    // alias `--listen` only if the operator literally named a peer
    // `--listen`, which the base32 encoding never produces.
    const std::string_view first = args[0];

    if (first == "--listen" ||
        std::any_of(args.begin(), args.end(),
                    [](std::string_view s) { return s == "--listen"; })) {
        gn::apps::goodnet_ssh::ListenOptions opts;
        // Strip the `--listen` token from the vector before parsing
        // remaining options. Allow it anywhere in argv for systemd
        // unit `ExecStart=...` flexibility.
        std::vector<std::string_view> tail;
        tail.reserve(args.size());
        for (const auto a : args) {
            if (a != "--listen") tail.push_back(a);
        }
        if (const auto rc = parse_listen_args(tail, opts); rc != 0) {
            return rc;
        }
        return gn::apps::goodnet_ssh::run_listen(opts);
    }

    if (first == "--bridge") {
        gn::apps::goodnet_ssh::Options opts;
        std::string pk;
        if (const auto rc = parse_bridge_args(
                std::span<const std::string_view>(args.data() + 1,
                                                    args.size() - 1),
                pk, opts);
            rc != 0) {
            return rc;
        }
        return gn::apps::goodnet_ssh::run_bridge(pk, opts);
    }

    // Default: wrap mode. The first positional argument is taken
    // verbatim as `[user@]<peer-pk>` — the wrap path execs into ssh
    // and lets openssh's `ProxyCommand` re-enter this binary in
    // bridge mode.
    if (first == "-h" || first == "--help") {
        print_usage();
        return 0;
    }
    if (!first.empty() && first[0] == '-') {
        (void)std::fprintf(stderr,
            "goodnet-ssh: unknown leading flag '%.*s'\n",
            static_cast<int>(first.size()), first.data());
        print_usage();
        return 2;
    }
    return gn::apps::goodnet_ssh::run_wrap(first);
}
