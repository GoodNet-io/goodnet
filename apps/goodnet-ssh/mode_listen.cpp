/// @file   apps/goodnet-ssh/mode_listen.cpp
/// @brief  Mode 3 — server-side forwarder.
///
/// Stub at scaffold time; the real implementation lands in the
/// follow-up commit that turns the listen mode on.

#include "modes.hpp"

#include <cstdio>

namespace gn::apps::goodnet_ssh {

int run_listen(const ListenOptions& /*opts*/) {
    (void)std::fputs(
        "goodnet-ssh listen: not implemented (scaffold)\n", stderr);
    return 1;
}

}  // namespace gn::apps::goodnet_ssh
