# goodnetd — BusyBox-style multicall CLI.
#
# Single binary covers every operator-facing subcommand (run / config
# validate / plugin hash / manifest gen / identity gen|show / version).
# Flat dispatch — `git`-style two-token (`<binary> <subcommand>`),
# never namespaced (no `goodnetd identity gen`-as-its-own-binary).
# Shared linkage of kernel/SDK, single PATH entry, no «which goodnetd
# bin do I have» systemd surprise.

add_executable(goodnetd
    main.cpp
    subcommands/version.cpp
    subcommands/config_validate.cpp
    subcommands/plugin_hash.cpp
    subcommands/manifest_gen.cpp
    subcommands/identity.cpp
    subcommands/run.cpp
)

target_link_libraries(goodnetd
    PRIVATE
        goodnet_kernel
        GoodNet::protocol_gnet
)

target_compile_features(goodnetd PRIVATE cxx_std_23)

# Windows mingw: roll the C++/C runtime, libgcc, and winpthread
# into the executable so the shipped `goodnetd.exe` is a single file
# with no neighbouring .dll requirements. mingw provides static
# archives (`libstdc++.a`, `libgcc.a`, `libwinpthread.a`) alongside
# the .dll variants — `-static -static-libgcc -static-libstdc++`
# pins ld.bfd to the archives. Combined with `--disable-shared`
# rebuilds of spdlog / fmt / libsodium in `nix/goodnetd-windows.nix`,
# the final goodnetd.exe carries every dependency inline.
if(WIN32)
    target_link_options(goodnetd PRIVATE
        -static
        -static-libgcc
        -static-libstdc++
    )
endif()

target_compile_definitions(goodnetd
    PRIVATE
        "GOODNET_VERSION_STRING=\"${GOODNET_VERSION_FULL}\""
)

set_target_properties(goodnetd PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    OUTPUT_NAME "goodnetd"
)

# `nix build .#goodnetd-core` lands the binary under `result/bin/`
# so composed deployments resolve `${goodnetd-core}/bin/goodnetd`
# through CMake's install layout.
install(TARGETS goodnetd RUNTIME DESTINATION bin)
