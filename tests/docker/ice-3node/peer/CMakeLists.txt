# ice-3node peer harness binary.
#
# Stand-alone executable that drives the C ABI in `sdk/core.h` from
# inside the docker peer container. Links the kernel STATIC archive
# so the produced binary has no `libgoodnet_kernel.so` lookup at
# runtime — the `goodnet:nix-static` base image ships its kernel
# .so at `/lib/` but no `/etc/ld.so.conf` / ldconfig cache, so a
# shared link would need a `LD_LIBRARY_PATH=/lib` wedge in the
# entrypoint. Static keeps the runtime contract tight: the only
# .so the binary opens are the plugin .so set under `/plugins/`
# (loaded explicitly via `gn_core_load_plugins_batch`) and the
# nix-store paths the RUNPATH carries for libsodium / spdlog / fmt
# / libcrypto / libstdc++ / glibc (already in the base image).
#
# Built from the same dev shell as the rest of the tree
# (`nix develop --command ninja -C build-release peer_harness`).
# `run_all.sh` then copies the binary into the docker build context
# next to the Dockerfile so the `COPY harness` line resolves.

add_executable(peer_harness harness.cpp)

target_link_libraries(peer_harness
    PRIVATE
        GoodNet::sdk
        GoodNet::kernel
        OpenSSL::Crypto
        Threads::Threads
)
if(TARGET GoodNet::protocol_gnet)
    target_link_libraries(peer_harness PRIVATE GoodNet::protocol_gnet)
endif()

target_compile_features(peer_harness PRIVATE cxx_std_23)

set_target_properties(peer_harness PROPERTIES
    OUTPUT_NAME harness
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
)
