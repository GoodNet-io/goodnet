# goodnet — BusyBox-style multicall CLI.
#
# Single binary covers every operator-facing subcommand (run / config
# validate / plugin hash / manifest gen / identity gen|show / version).
# Flat dispatch — `git`-style two-token (`<binary> <subcommand>`),
# never namespaced (no `goodnet identity gen`-as-its-own-binary). The
# rationale follows `feedback_goodnet_no_orchestrator` + plan: shared
# linkage of kernel/SDK, single PATH entry, no «which goodnet bin do
# I have» systemd surprise.

add_executable(goodnet
    main.cpp
    subcommands/version.cpp
    subcommands/config_validate.cpp
    subcommands/plugin_hash.cpp
    subcommands/manifest_gen.cpp
)

target_link_libraries(goodnet
    PRIVATE
        goodnet_kernel
)

target_compile_features(goodnet PRIVATE cxx_std_23)

target_compile_definitions(goodnet
    PRIVATE
        "GOODNET_VERSION_STRING=\"${PROJECT_VERSION}\""
)

set_target_properties(goodnet PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    OUTPUT_NAME "goodnet"
)
