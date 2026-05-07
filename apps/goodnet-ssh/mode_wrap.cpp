/// @file   apps/goodnet-ssh/mode_wrap.cpp
/// @brief  Mode 1 — user-facing wrapper that execs into openssh.
///
/// `goodnet-ssh user@<peer-pk>` is the operator-friendly surface:
/// the operator runs it as if it were `ssh user@host`, and the
/// wrapper rewires openssh's transport through the GoodNet kernel
/// using openssh's `ProxyCommand` mechanism.
///
/// The wrapper does not own a kernel handle. It builds a
/// `ProxyCommand=<self> --bridge <peer-pk>` argument, asks openssh
/// to dial a sentinel hostname (`dummy`), and `execvp`s ssh with
/// the right options. openssh launches the bridge as a child, pipes
/// stdin/stdout against it, and runs the SSH protocol over those
/// bytes — same shape as `ssh -o ProxyCommand="..." user@host`,
/// only the operator never has to type the ProxyCommand string.
///
/// The wrapper deliberately disables `StrictHostKeyChecking` /
/// `UserKnownHostsFile` because the GoodNet bridge already
/// authenticates the peer through Noise: a successful trust upgrade
/// proves the bridge is talking to the holder of the peer-pk private
/// key. SSH's host-key verification on top of that would force the
/// operator to maintain a parallel known_hosts file pinning what
/// the GoodNet handshake already pinned, with no security gain.

#include "modes.hpp"

#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>
#include <unistd.h>
#include <vector>

namespace gn::apps::goodnet_ssh {

namespace {

/// Resolve `/proc/self/exe` into an absolute filesystem path. Used
/// to construct the `ProxyCommand` so the bridge child invocation
/// reaches the same binary that ran the wrap mode.
[[nodiscard]] std::string own_executable_path() {
    namespace fs = std::filesystem;
    std::error_code ec;
    auto p = fs::read_symlink("/proc/self/exe", ec);
    if (ec || p.empty()) {
        // Fall back to argv[0]-style PATH search if /proc is missing
        // (containers without /proc, NetBSD, ...). The fallback is
        // good enough for non-Linux but never reached on Linux.
        return std::string{"goodnet-ssh"};
    }
    return p.string();
}

}  // namespace

int run_wrap(std::string_view user_at_pk) {
    // Split `[user@]<pk>` — the leading `<user>@` segment is optional.
    std::string user;
    std::string pk;
    if (const auto at = user_at_pk.find('@'); at != std::string_view::npos) {
        user.assign(user_at_pk.substr(0, at));
        pk.assign(user_at_pk.substr(at + 1));
    } else {
        pk.assign(user_at_pk);
    }
    if (pk.empty()) {
        (void)std::fputs(
            "goodnet-ssh wrap: empty peer-pk in target\n", stderr);
        return 2;
    }

    // ProxyCommand string. openssh hands the literal text to /bin/sh
    // -c, so quoting matters: the self-path can contain spaces if the
    // operator built into a path with whitespace. Quote the path with
    // single quotes and escape any embedded single quote. Cheap shell
    // hygiene because operators name their own directories.
    const std::string self = own_executable_path();
    std::string proxy_cmd;
    proxy_cmd.reserve(self.size() + pk.size() + 32);
    proxy_cmd.append("'");
    for (const char c : self) {
        if (c == '\'') {
            // POSIX shell single-quote escape: end-quote, escaped
            // quote, re-open. `foo'bar` → `'foo'\''bar'`.
            proxy_cmd.append("'\\''");
        } else {
            proxy_cmd.push_back(c);
        }
    }
    proxy_cmd.append("' --bridge ");
    proxy_cmd.append(pk);

    // Compose the ssh argv. The openssh rule is that flag arguments
    // come first, the host argument last (anything after the host is
    // the remote command). `dummy` stands in for the hostname; the
    // ProxyCommand bypasses real DNS so the resolver never sees it.
    const std::string proxy_opt = "ProxyCommand=" + proxy_cmd;
    const std::string host_arg  = user.empty()
                                      ? std::string{"dummy"}
                                      : user + "@dummy";

    std::vector<const char*> argv;
    argv.reserve(10);
    argv.push_back("ssh");
    argv.push_back("-o");
    argv.push_back(proxy_opt.c_str());
    // Disable host-key verification: the GoodNet bridge already
    // authenticated the peer-pk through Noise. Forcing the operator
    // to maintain a parallel known_hosts file pinning what is
    // already pinned by `peer-pk` adds no security and breaks the
    // «one address, one identity» promise.
    argv.push_back("-o");
    argv.push_back("StrictHostKeyChecking=no");
    argv.push_back("-o");
    argv.push_back("UserKnownHostsFile=/dev/null");
    argv.push_back(host_arg.c_str());
    argv.push_back(nullptr);

    ::execvp("ssh", const_cast<char* const*>(argv.data()));
    // `execvp` only returns on failure. ENOENT means ssh is missing
    // from PATH; surface a helpful hint instead of just `errno`.
    if (errno == ENOENT) {
        (void)std::fputs(
            "goodnet-ssh wrap: 'ssh' not found in PATH "
            "(install openssh-client)\n", stderr);
    } else {
        (void)std::fprintf(stderr,
            "goodnet-ssh wrap: execvp ssh failed: %s\n",
            std::strerror(errno));
    }
    return 127;
}

}  // namespace gn::apps::goodnet_ssh
