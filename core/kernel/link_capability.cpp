/// @file   core/kernel/link_capability.cpp
/// @brief  Implementation of the host-side link capability probe.

#include "link_capability.hpp"

#include <core/util/log.hpp>

#include <atomic>
#include <mutex>

#if defined(_WIN32)
#  include <winsock2.h>
#  include <ws2tcpip.h>
   using socket_t = SOCKET;
#  define GN_INVALID_SOCKET INVALID_SOCKET
#  define GN_CLOSE_SOCKET ::closesocket
#else
#  include <arpa/inet.h>
#  include <netinet/in.h>
#  include <sys/socket.h>
#  include <unistd.h>
   using socket_t = int;
#  define GN_INVALID_SOCKET (-1)
#  define GN_CLOSE_SOCKET ::close
#endif

namespace gn {

namespace {

/// Attempt to bind a fresh socket of @p domain × @p type to
/// wildcard:0. Returns `true` only when both `socket` and `bind`
/// succeeded; closes the descriptor before returning either way.
[[nodiscard]] bool probe_bind(int domain, int type) noexcept {
    const socket_t s = ::socket(domain, type, 0);
    if (s == GN_INVALID_SOCKET) return false;

    bool ok = false;
    if (domain == AF_INET) {
        sockaddr_in addr{};
        addr.sin_family      = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
        addr.sin_port        = 0;
        ok = ::bind(s, reinterpret_cast<const sockaddr*>(&addr),
                    sizeof(addr)) == 0;
    } else if (domain == AF_INET6) {
        sockaddr_in6 addr{};
        addr.sin6_family = AF_INET6;
        addr.sin6_addr   = in6addr_any;
        addr.sin6_port   = 0;
        ok = ::bind(s, reinterpret_cast<const sockaddr*>(&addr),
                    sizeof(addr)) == 0;
    }
    GN_CLOSE_SOCKET(s);
    return ok;
}

void default_probe(LinkCapability& out) noexcept {
    out.can_bind_udp_v4 = probe_bind(AF_INET,  SOCK_DGRAM);
    out.can_bind_udp_v6 = probe_bind(AF_INET6, SOCK_DGRAM);
    out.can_bind_tcp_v4 = probe_bind(AF_INET,  SOCK_STREAM);
    out.can_bind_tcp_v6 = probe_bind(AF_INET6, SOCK_STREAM);
}

struct ProbeState {
    std::mutex                   mu;
    LinkCapability               cached{};
    bool                         probed{false};
    LinkCapabilityProbeFn        seam{nullptr};
};

[[nodiscard]] ProbeState& state() {
    static ProbeState s;
    return s;
}

}  // namespace

const LinkCapability& host_link_capability() {
    auto& st = state();
    std::lock_guard lk(st.mu);
    if (!st.probed) {
        LinkCapability snapshot{};
        if (st.seam != nullptr) {
            st.seam(snapshot);
        } else {
            default_probe(snapshot);
        }
        st.cached = snapshot;
        st.probed = true;
        ::gn::log::info(
            "link capability: udp_v4={} udp_v6={} tcp_v4={} tcp_v6={}",
            st.cached.can_bind_udp_v4 ? "yes" : "no",
            st.cached.can_bind_udp_v6 ? "yes" : "no",
            st.cached.can_bind_tcp_v4 ? "yes" : "no",
            st.cached.can_bind_tcp_v6 ? "yes" : "no");
    }
    return st.cached;
}

void refresh_host_link_capability() noexcept {
    auto& st = state();
    std::lock_guard lk(st.mu);
    st.probed = false;
}

void set_link_capability_probe_for_testing(LinkCapabilityProbeFn fn) noexcept {
    auto& st = state();
    std::lock_guard lk(st.mu);
    st.seam   = fn;
    st.probed = false;
}

}  // namespace gn
