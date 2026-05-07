/// @file   apps/goodnet-ssh/mode_wrap.cpp
/// @brief  Mode 1 — user-facing wrapper that execs into openssh.
///
/// Stub at scaffold time; the real implementation lands in the
/// follow-up commit that turns the wrap mode on.

#include "modes.hpp"

#include <cstdio>

namespace gn::apps::goodnet_ssh {

int run_wrap(std::string_view /*user_at_pk*/) {
    (void)std::fputs(
        "goodnet-ssh wrap: not implemented (scaffold)\n", stderr);
    return 1;
}

}  // namespace gn::apps::goodnet_ssh
