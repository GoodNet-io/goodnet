cmake_minimum_required(VERSION 3.22)

if(NOT TARGET GoodNet::sdk)
    project(goodnet_security_noise
        VERSION   0.1.0
        LANGUAGES CXX)
    find_package(GoodNet REQUIRED)
    include(CTest)
    if(BUILD_TESTING)
        find_package(GTest      REQUIRED)
        find_package(rapidcheck QUIET)
        set(GOODNET_BUILD_TESTS ON)
    endif()
endif()

# Noise security provider — Apache-2.0. Implements the
# Noise_XX_25519_ChaChaPoly_BLAKE2b pattern from
# `plugins/security/noise/docs/handshake.md` on libsodium primitives.
#
# Two build artefacts share the same source files:
#   - `goodnet_noise_objects` OBJECT library carrying the crypto
#     primitives + state machines, linked into unit tests so they
#     exercise the implementation without going through dlopen.
#   - `goodnet_security_noise` SHARED plugin via `add_plugin()`,
#     exposing the gn_security_provider_vtable through the stable
#     C ABI; loaded by the kernel's plugin manager at runtime.

add_library(goodnet_noise_objects OBJECT
    hash.cpp
    hmac.cpp
    hkdf.cpp
    cipher.cpp
    symmetric.cpp
    handshake.cpp
    transport.cpp
)

target_link_libraries(goodnet_noise_objects PUBLIC PkgConfig::SODIUM)
target_compile_features(goodnet_noise_objects PUBLIC cxx_std_23)
target_compile_options(goodnet_noise_objects PRIVATE
    -Wall -Wextra -Wpedantic -Wno-unused-parameter)

target_include_directories(goodnet_noise_objects
    PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR}
    PRIVATE ${SODIUM_INCLUDE_DIRS})

set_target_properties(goodnet_noise_objects PROPERTIES
    POSITION_INDEPENDENT_CODE ON)

add_plugin(goodnet_security_noise
    noise.cpp
)
target_link_libraries(goodnet_security_noise
    PRIVATE goodnet_noise_objects PkgConfig::SODIUM)
target_include_directories(goodnet_security_noise
    PRIVATE ${SODIUM_INCLUDE_DIRS})

if(GOODNET_BUILD_TESTS)
    add_subdirectory(tests)
endif()
