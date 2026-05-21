# Cross-implementation test vector generators + consumer.
#
# Generators (gen_*) run on demand to (re-)compute the JSON files in
# this directory. They are NOT part of `nix run .#test`; the
# committed JSON IS the source of truth and the consumer test
# (`test_vectors_consume`) replays the inputs through the C++
# reference primitives and asserts byte equality.
#
# Re-run a generator only when the underlying wire format is bumped:
#   $ cmake --build build --target gen_noise_xx \
#                                    gen_gnet_wire \
#                                    gen_attestation \
#                                    gen_capability_blob \
#                                    gen_pkcs11_sign
#   $ ./build/tests/vectors/gen_noise_xx tests/vectors/noise_xx.json
#   $ ./build/tests/vectors/gen_gnet_wire tests/vectors/gnet_wire.json
#   $ ./build/tests/vectors/gen_attestation tests/vectors/attestation.json
#   $ ./build/tests/vectors/gen_capability_blob tests/vectors/capability_blob.json
#   $ ./build/tests/vectors/gen_pkcs11_sign tests/vectors/pkcs11_sign.json

include(GoogleTest)

# Path the consumer test uses at runtime to locate the JSON fixtures.
set(_vectors_dir "${CMAKE_CURRENT_SOURCE_DIR}")

# ── Generators ───────────────────────────────────────────────────────────

add_executable(gen_noise_xx gen_noise_xx.cpp)
target_link_libraries(gen_noise_xx PRIVATE
    goodnet_noise_objects
    PkgConfig::SODIUM)
target_include_directories(gen_noise_xx PRIVATE
    "${CMAKE_SOURCE_DIR}/plugins/security/noise")
target_compile_features(gen_noise_xx PRIVATE cxx_std_23)
if(COMMAND goodnet_apply_pch)
    goodnet_apply_pch(gen_noise_xx)
endif()

add_executable(gen_gnet_wire gen_gnet_wire.cpp)
target_link_libraries(gen_gnet_wire PRIVATE
    GoodNet::sdk
    GoodNet::protocol_gnet
    goodnet_kernel
    PkgConfig::SODIUM)
target_include_directories(gen_gnet_wire PRIVATE
    "${CMAKE_SOURCE_DIR}/plugins/protocols/gnet")
target_compile_features(gen_gnet_wire PRIVATE cxx_std_23)
if(COMMAND goodnet_apply_pch)
    goodnet_apply_pch(gen_gnet_wire)
endif()

add_executable(gen_attestation gen_attestation.cpp)
target_link_libraries(gen_attestation PRIVATE
    PkgConfig::SODIUM)
target_compile_features(gen_attestation PRIVATE cxx_std_23)
if(COMMAND goodnet_apply_pch)
    goodnet_apply_pch(gen_attestation)
endif()

add_executable(gen_capability_blob gen_capability_blob.cpp)
target_link_libraries(gen_capability_blob PRIVATE
    GoodNet::sdk)
target_compile_features(gen_capability_blob PRIVATE cxx_std_23)
if(COMMAND goodnet_apply_pch)
    goodnet_apply_pch(gen_capability_blob)
endif()

add_executable(gen_pkcs11_sign gen_pkcs11_sign.cpp)
target_link_libraries(gen_pkcs11_sign PRIVATE
    PkgConfig::SODIUM)
target_compile_features(gen_pkcs11_sign PRIVATE cxx_std_23)
if(COMMAND goodnet_apply_pch)
    goodnet_apply_pch(gen_pkcs11_sign)
endif()

# ── Consumer test ────────────────────────────────────────────────────────

add_executable(test_vectors_consume test_vectors_consume.cpp)
target_link_libraries(test_vectors_consume PRIVATE
    GoodNet::sdk
    GoodNet::protocol_gnet
    goodnet_kernel
    goodnet_noise_objects
    nlohmann_json::nlohmann_json
    PkgConfig::SODIUM
    GTest::gtest
    GTest::gtest_main)
target_include_directories(test_vectors_consume PRIVATE
    "${CMAKE_SOURCE_DIR}/plugins/security/noise"
    "${CMAKE_SOURCE_DIR}/plugins/protocols/gnet")
target_compile_features(test_vectors_consume PRIVATE cxx_std_23)
target_compile_definitions(test_vectors_consume PRIVATE
    "GOODNET_VECTORS_DIR=\"${_vectors_dir}\"")
if(COMMAND goodnet_apply_pch)
    goodnet_apply_pch(test_vectors_consume)
endif()

gtest_discover_tests(test_vectors_consume
    DISCOVERY_TIMEOUT 30
    PROPERTIES TIMEOUT 60)
