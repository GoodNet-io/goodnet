/// @file   apps/goodnet-ssh/mode_bridge.cpp
/// @brief  Mode 2 — `ProxyCommand` bridge.
///
/// Stub at scaffold time; the real implementation lands in the
/// follow-up commit that turns the bridge mode on.

#include "modes.hpp"

#include <cstdio>

namespace gn::apps::goodnet_ssh {

int run_bridge(std::string_view /*peer_pk_str*/, const Options& /*opts*/) {
    (void)std::fputs(
        "goodnet-ssh bridge: not implemented (scaffold)\n", stderr);
    return 1;
}

}  // namespace gn::apps::goodnet_ssh
