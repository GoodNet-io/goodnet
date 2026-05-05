/// @file   apps/goodnet/subcommands.hpp
/// @brief  Subcommand dispatch table for the `goodnet` multicall.
///
/// Each subcommand exposes one entry point taking the subcommand's
/// own argv slice (i.e. `argv[1..]` after the dispatcher peels the
/// subcommand name off `argv[0]`-style). Returns the process exit
/// code: 0 success, 1 generic failure, 2 usage error.

#pragma once

#include <span>
#include <string_view>

namespace gn::apps::goodnet {

[[nodiscard]] int cmd_version(std::span<const std::string_view> args);
[[nodiscard]] int cmd_config_validate(std::span<const std::string_view> args);
[[nodiscard]] int cmd_plugin_hash(std::span<const std::string_view> args);
[[nodiscard]] int cmd_manifest_gen(std::span<const std::string_view> args);

}  // namespace gn::apps::goodnet
