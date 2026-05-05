/// @file   apps/goodnet/subcommands/config_validate.cpp
/// @brief  `goodnet config validate <file>` — pre-deploy config check.
///
/// Wraps `gn::core::Config::load_file`. Success prints a one-line OK
/// to stdout; failure prints the parser's diagnostic to stderr and
/// exits non-zero. Operators wire this into `ExecStartPre=` of their
/// systemd unit so a malformed config fails the unit start instead
/// of crashing the kernel mid-handshake.

#include "../subcommands.hpp"

#include <cstdio>
#include <string>

#include <core/config/config.hpp>

namespace gn::apps::goodnet {

int cmd_config_validate(std::span<const std::string_view> args) {
    if (args.size() != 1) {
        (void)std::fputs("goodnet config validate: needs exactly one <file> argument\n",
                          stderr);
        return 2;
    }
    const std::string path{args[0]};

    gn::core::Config cfg;
    std::string reason;
    const auto rc = cfg.load_file(path, &reason);
    if (rc != GN_OK) {
        (void)std::fprintf(stderr, "goodnet config validate: %s — %s\n",
                           path.c_str(), reason.c_str());
        return 1;
    }
    (void)std::fprintf(stdout, "goodnet config validate: %s OK\n", path.c_str());
    return 0;
}

}  // namespace gn::apps::goodnet
