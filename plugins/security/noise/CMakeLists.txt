# Noise security provider — Apache-2.0. Implements XX and IK patterns
# from `docs/contracts/noise-handshake.md` on libsodium primitives:
# X25519 (`crypto_scalarmult`), ChaCha20-Poly1305 IETF AEAD, BLAKE2b.
#
# This subdirectory ships the Noise crypto state machines as an OBJECT
# library so unit tests can link them directly. The dlopen-able plugin
# wrapper that exposes the SDK security-provider vtable lands in a
# follow-up once the kernel grows a security pipeline that drives
# `handshake_open` per `noise-handshake.md` and `security-trust.md`.

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
