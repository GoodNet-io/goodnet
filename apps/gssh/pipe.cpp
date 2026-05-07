/// @file   apps/gssh/pipe.cpp
/// @brief  Implementation of the bytes-pipe helpers.

#include "pipe.hpp"

#include <cerrno>
#include <chrono>
#include <fcntl.h>
#include <thread>
#include <unistd.h>

namespace gn::apps::gssh {

int make_fd_nonblocking(int fd) {
    const int flags = ::fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    if (::fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) return -1;
    return flags;
}

int write_all(int fd, std::span<const std::uint8_t> bytes) {
    std::size_t off = 0;
    while (off < bytes.size()) {
        const auto n = ::write(fd, bytes.data() + off, bytes.size() - off);
        if (n > 0) {
            off += static_cast<std::size_t>(n);
            continue;
        }
        if (n < 0 && (errno == EINTR)) continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            std::this_thread::sleep_for(std::chrono::milliseconds{1});
            continue;
        }
        return -1;
    }
    return 0;
}

}  // namespace gn::apps::gssh
