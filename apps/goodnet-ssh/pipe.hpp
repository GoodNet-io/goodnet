/// @file   apps/goodnet-ssh/pipe.hpp
/// @brief  Thin helpers for byte-level forwarding between an OS fd
///         and a kernel connection.
///
/// Both bridge and listen modes pump bytes between an OS file
/// descriptor (stdin/stdout for the bridge, an upstream TCP socket
/// for the listen mode) and a `gn_conn_id_t`. The pump is
/// asymmetric: outbound (fd → kernel) is a synchronous read loop
/// driven by the mode itself; inbound (kernel → fd) is the kernel's
/// handler trampoline. The helpers here cover the parts both
/// directions need: `set_nonblocking`, `write_all`, and the constants
/// for buffer sizing.

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace gn::apps::goodnet_ssh {

/// Read buffer size. 16 KiB matches the kernel's framing ceiling for
/// a single AEAD record and is large enough that openssh's typical
/// 32-KiB write batches turn into two reads at most. Going larger
/// gains nothing because the kernel's send path internally splits
/// before encryption.
inline constexpr std::size_t kPipeBufferBytes = std::size_t{16} * 1024;

/// Switch @p fd to non-blocking mode through `fcntl(F_SETFL,
/// O_NONBLOCK)`. Returns the original flags on success, -1 on
/// failure (with errno preserved). The caller restores the prior
/// state with `restore_fd_flags(fd, original)` if a clean undo is
/// needed; the bridge does not bother because the process exits
/// shortly after.
[[nodiscard]] int make_fd_nonblocking(int fd);

/// Write @p bytes to @p fd, looping past `EINTR` and partial writes.
/// Returns 0 on success, -1 on a write failure that did not heal
/// (errno set by the underlying call). `EAGAIN` triggers a 1ms
/// sleep and retry — acceptable here because the bridge's stdout is
/// almost always openssh's stdin pipe, which only blocks under
/// genuine backpressure from the SSH transport.
[[nodiscard]] int write_all(int fd, std::span<const std::uint8_t> bytes);

}  // namespace gn::apps::goodnet_ssh
