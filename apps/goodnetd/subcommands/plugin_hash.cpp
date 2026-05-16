/// @file   apps/goodnetd/subcommands/plugin_hash.cpp
/// @brief  `goodnet plugin hash <so>` — print SHA-256 of a plugin .so.
///
/// Wraps `PluginManifest::sha256_of_file` so the operator's hash
/// matches what the kernel computes at load time exactly. Output is
/// the hex form `PluginManifest::encode_hex` produces, unprefixed,
/// followed by two spaces and the path — same shape as `sha256sum(1)`
/// so a manifest can be assembled with shell tooling if desired.

#include "../subcommands.hpp"

#include <cstdio>
#include <string>

#include <core/plugin/plugin_manifest.hpp>

namespace gn::apps::goodnet {

int cmd_plugin_hash(std::span<const std::string_view> args) {
    if (args.size() != 1) {
        (void)std::fputs("goodnet plugin hash: needs exactly one <so> argument\n",
                          stderr);
        return 2;
    }
    const std::string path{args[0]};

    const auto digest = gn::core::PluginManifest::sha256_of_file(path);
    if (!digest) {
        (void)std::fprintf(stderr,
                           "goodnet plugin hash: %s — failed to read file\n",
                           path.c_str());
        return 1;
    }
    const auto hex = gn::core::PluginManifest::encode_hex(*digest);
    (void)std::fprintf(stdout, "%s  %s\n", hex.c_str(), path.c_str());
    return 0;
}

}  // namespace gn::apps::goodnet
