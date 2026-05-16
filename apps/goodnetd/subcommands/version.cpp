/// @file   apps/goodnetd/subcommands/version.cpp
/// @brief  `goodnet version` — print version + git/build info.

#include "../subcommands.hpp"

#include <cstdio>

#ifndef GOODNET_VERSION_STRING
#define GOODNET_VERSION_STRING "0.0.0-unknown"
#endif

namespace gn::apps::goodnet {

int cmd_version(std::span<const std::string_view> args) {
    if (!args.empty()) {
        (void)std::fputs("goodnet version: takes no arguments\n", stderr);
        return 2;
    }
    (void)std::fprintf(stdout, "goodnet %s\n", GOODNET_VERSION_STRING);
    return 0;
}

}  // namespace gn::apps::goodnet
