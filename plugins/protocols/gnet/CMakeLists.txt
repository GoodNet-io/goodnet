# GNET — canonical mesh-framing implementation. Statically linked
# into the kernel binary; the source still lives here under plugins/
# so the kernel/plugin separation is structural, not implementation-
# detail.

add_library(goodnet_protocol_gnet STATIC
    wire.cpp
    protocol.cpp
)
add_library(GoodNet::protocol_gnet ALIAS goodnet_protocol_gnet)

target_include_directories(goodnet_protocol_gnet PUBLIC
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>"
    "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}>"
)

target_link_libraries(goodnet_protocol_gnet
    PUBLIC
        GoodNet::sdk
        GoodNet::ctx_accessors
    PRIVATE
        GoodNet::kernel
)

target_compile_features(goodnet_protocol_gnet PUBLIC cxx_std_23)

if(GOODNET_BUILD_TESTS)
    add_subdirectory(tests)
endif()
