/// @file   apps/gssh/modes.hpp
/// @brief  Shared declarations for the three operational modes.
///
/// `gssh` is a single binary with three modes selected by
/// argv. The wrap mode invokes openssh with a `ProxyCommand` that
/// re-executes the same binary in bridge mode. The bridge mode owns
/// a kernel handle, dials the requested peer, and pipes stdin/stdout
/// against the connection. The listen mode listens for inbound
/// kernel-side connections and forwards bytes to a local TCP target
/// (default `localhost:22`).
///
/// Every mode shares a small set of constants (`kSshAppMsgId`, the
/// trust-upgrade timeout, the listen URI default) and helper types
/// (`Options`, `ListenOptions`). Pulling them into one header keeps
/// the per-mode translation units focused on flow control rather than
/// fragmentary configuration.

#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>

namespace gn::apps::gssh {

/// Application-level message id used by both bridge and listen modes
/// for SSH wire bytes. Sits above the kernel-canonical 0..0xFF range
/// so a future protocol layer that reserves low ids does not collide.
inline constexpr std::uint32_t kSshAppMsgId = 0x10000u;

/// Hard ceiling on the time the bridge mode waits for a connection
/// to reach the `TRUST_UPGRADED` event. Past this point the operator
/// is better served by an immediate non-zero exit than by an indefinite
/// stall — openssh's `ProxyCommand` does not surface progress, and a
/// hung bridge looks identical to a stuck handshake.
inline constexpr auto kTrustTimeout = std::chrono::seconds{15};

/// Default URI the listen mode binds when `--listen-uri` is omitted.
inline constexpr std::string_view kDefaultListenUri = "tcp://0.0.0.0:9001";

/// Default forwarding target when `--target` is omitted. The listen
/// mode opens a TCP socket here every time a fresh kernel connection
/// arrives and the first inbound bytes land on `kSshAppMsgId`.
inline constexpr std::string_view kDefaultTargetHost = "127.0.0.1";
inline constexpr std::uint16_t    kDefaultTargetPort = 22;

/// Options shared between bridge and listen modes for plugin loading
/// and identity. The wrap mode does not need either — it execs into
/// openssh and never touches a kernel handle.
struct Options {
    /// Path to the operator's persistent identity blob. The bridge
    /// mode loads it before reaching `gn_core_init` so the kernel
    /// uses the operator's long-term keypair instead of generating
    /// an ephemeral one. Empty string means «use the XDG default»
    /// (`~/.config/goodnet/identity.bin`).
    std::string identity_path;

    /// Optional override URI for direct connection. When set the
    /// bridge dials this URI instead of consulting `peers.json`.
    /// Useful for ad-hoc connectivity tests when the peer's address
    /// has not been catalogued yet.
    std::string override_uri;
};

/// Listen-mode-specific options. Inherits the shared `Options` plus
/// the URI to bind on and the local TCP target to forward inbound
/// bytes to.
struct ListenOptions {
    Options       common;
    std::string   listen_uri  = std::string{kDefaultListenUri};
    std::string   target_host = std::string{kDefaultTargetHost};
    std::uint16_t target_port = kDefaultTargetPort;
};

/// Mode 1: user-facing convenience wrapper. Resolves `[user@]<peer-pk>`,
/// builds the `ProxyCommand` string for openssh, and `execvp`s ssh.
/// Returns 127 on `execvp` failure (matching POSIX convention for
/// «command not executable»); never returns on success because the
/// process is replaced.
[[nodiscard]] int run_wrap(std::string_view user_at_pk);

/// Mode 2: ProxyCommand callee. Brings up a kernel, dials the peer,
/// pipes stdin/stdout against the connection. Returns 0 on clean EOF,
/// 1 on any failure path (load identity, connect, trust upgrade
/// timeout). All logging strict to stderr — stdout carries SSH wire
/// bytes for openssh to consume.
[[nodiscard]] int run_bridge(std::string_view peer_pk_str,
                              const Options& opts);

/// Mode 3: server-side forwarder. Brings up a kernel listening on
/// `opts.listen_uri`, opens a TCP socket to `opts.target_host:port`
/// every time a fresh inbound connection arrives, and pipes bytes
/// both ways. Returns 0 on clean SIGTERM/SIGINT shutdown, 1 on
/// startup failure.
[[nodiscard]] int run_listen(const ListenOptions& opts);

}  // namespace gn::apps::gssh
