# goodnet — BusyBox-style multicall CLI.
#
# Single binary covers every operator-facing subcommand (run / config
# validate / plugin hash / manifest gen / identity gen|show / version).
# Flat dispatch — `git`-style two-token (`<binary> <subcommand>`),
# never namespaced (no `goodnet identity gen`-as-its-own-binary).
# Shared linkage of kernel/SDK, single PATH entry, no «which goodnet
# bin do I have» systemd surprise.

add_executable(goodnet
    main.cpp
    subcommands/version.cpp
    subcommands/config_validate.cpp
    subcommands/plugin_hash.cpp
    subcommands/manifest_gen.cpp
    subcommands/identity.cpp
    subcommands/run.cpp
)

target_link_libraries(goodnet
    PRIVATE
        goodnet_kernel
        GoodNet::protocol_gnet
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

# `nix build .#goodnet-core` lands the binary under `result/bin/`
# so composed deployments resolve `${goodnet-core}/bin/goodnet`
# through CMake's install layout.
install(TARGETS goodnet RUNTIME DESTINATION bin)
