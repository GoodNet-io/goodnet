# apps/ — operator-facing CLI binaries.
#
# Today: `goodnet`, a BusyBox-style multicall covering the v1 operator
# surface (config validation, plugin hashing, manifest generation,
# version reporting). The `run` and `identity` subcommands ship in
# follow-up branches once NodeIdentity serialization and full
# plugin-load orchestration land.

add_subdirectory(goodnet)
