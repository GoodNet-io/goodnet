/// @file   apps/goodnet/main.cpp
/// @brief  Multicall dispatcher for the `goodnet` operator CLI.
///
/// Resolves the first positional argument to a subcommand handler and
/// hands the remaining argv slice to it. Unknown / missing subcommand
/// prints usage and exits with code 2.
///
/// Subcommand handlers are pure functions in `subcommands.hpp`; this
/// file owns argv parsing only. The split keeps the dispatcher cheap
/// to extend (one row per new subcommand) and lets each handler stay
/// independently testable in unit tests.

#include "subcommands.hpp"

#include <cstdio>
#include <span>
#include <string_view>
#include <vector>

namespace {

void print_usage() {
    (void)std::fputs(
        "usage: goodnet <subcommand> [args...]\n"
        "\n"
        "subcommands:\n"
        "  version                       print version + build info\n"
        "  config validate <file>        validate a kernel config JSON file\n"
        "  plugin hash <so>              print SHA-256 of a plugin .so\n"
        "  manifest gen <so>...          emit plugins.json manifest entries\n"
        "  identity gen --out <file>     generate a fresh node identity (mode 0600)\n"
        "  identity show <file>          print public surface of a saved identity\n"
        "  run --config X --manifest Y --identity Z   load kernel + plugins, run until SIGTERM\n",
        stderr);
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        print_usage();
        return 2;
    }

    /// `string_view` slice over argv. Keeps the rest of the dispatch
    /// free of `char*` / pointer arithmetic.
    std::vector<std::string_view> args;
    args.reserve(static_cast<std::size_t>(argc) - 1);
    for (int i = 1; i < argc; ++i) {
        args.emplace_back(argv[i]);
    }

    using namespace gn::apps::goodnet;

    const std::string_view sub = args[0];
    const std::span<const std::string_view> tail{
        args.data() + 1, args.size() - 1};

    if (sub == "version") {
        return cmd_version(tail);
    }
    /// `config`, `plugin`, `manifest` are namespace heads with one
    /// nested action each in v1 — the action token lives in `tail[0]`.
    /// Future expansions land more actions under the same head; keep
    /// the dispatch flat (no nested handler tree) so the `git`-style
    /// surface stays consistent.
    if (sub == "config") {
        if (tail.empty() || tail[0] != "validate") {
            (void)std::fputs("goodnet config: action must be 'validate'\n", stderr);
            return 2;
        }
        return cmd_config_validate(tail.subspan(1));
    }
    if (sub == "plugin") {
        if (tail.empty() || tail[0] != "hash") {
            (void)std::fputs("goodnet plugin: action must be 'hash'\n", stderr);
            return 2;
        }
        return cmd_plugin_hash(tail.subspan(1));
    }
    if (sub == "manifest") {
        if (tail.empty() || tail[0] != "gen") {
            (void)std::fputs("goodnet manifest: action must be 'gen'\n", stderr);
            return 2;
        }
        return cmd_manifest_gen(tail.subspan(1));
    }
    if (sub == "identity") {
        return cmd_identity(tail);
    }
    if (sub == "run") {
        return cmd_run(tail);
    }

    (void)std::fprintf(stderr, "goodnet: unknown subcommand '%.*s'\n",
                 static_cast<int>(sub.size()), sub.data());
    print_usage();
    return 2;
}
