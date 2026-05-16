/// @file   apps/goodnetd/subcommands/manifest_gen.cpp
/// @brief  `goodnet manifest gen <so>...` — emit `plugins.json`.
///
/// Streams a fresh manifest document to stdout in the format
/// `PluginManifest::parse` reads back: a single `"plugins"` array of
/// `{ "path", "sha256" }` records. Hashes come from
/// `PluginManifest::sha256_of_file` — same primitive the kernel uses
/// at load time, so a manifest emitted here verifies cleanly when
/// `PluginManager::load` runs against the same bytes.
///
/// Output is plain JSON without trailing newlines or comments so it
/// can be redirected straight into a file (`> plugins.json`) or
/// piped through `jq`. Failure on any path prints to stderr and the
/// process exits non-zero with no manifest written, leaving the
/// operator's previous file intact.

#include "../subcommands.hpp"

#include <cstdio>
#include <string>

#include <core/plugin/plugin_manifest.hpp>

namespace gn::apps::goodnet {

int cmd_manifest_gen(std::span<const std::string_view> args) {
    if (args.empty()) {
        (void)std::fputs("goodnet manifest gen: needs one or more <so> arguments\n",
                          stderr);
        return 2;
    }

    /// Hash every input first; only emit JSON once every digest is in
    /// hand so a partial failure does not leave half a manifest on
    /// stdout that the operator's redirect captures as a valid file.
    std::string out;
    out.reserve(args.size() * 128);
    out.append("{\n  \"plugins\": [\n");
    bool first = true;
    for (const auto path_sv : args) {
        const std::string path{path_sv};
        const auto digest = gn::core::PluginManifest::sha256_of_file(path);
        if (!digest) {
            (void)std::fprintf(stderr,
                               "goodnet manifest gen: %s — failed to read file\n",
                               path.c_str());
            return 1;
        }
        const auto hex = gn::core::PluginManifest::encode_hex(*digest);
        if (!first) out.append(",\n");
        first = false;
        out.append("    { \"path\": \"");
        out.append(path);
        out.append("\", \"sha256\": \"");
        out.append(hex);
        out.append("\" }");
    }
    out.append("\n  ]\n}\n");
    (void)std::fputs(out.c_str(), stdout);
    return 0;
}

}  // namespace gn::apps::goodnet
