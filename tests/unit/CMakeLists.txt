# Unit tests for the kernel and SDK.
#
# All `tests/unit/**/test_*.cpp` files are compiled into a single
# `goodnet_unit_tests` executable; CTest discovers individual cases via
# `gtest_discover_tests`.

include(GoogleTest)

# CONFIGURE_DEPENDS so adding a new test_*.cpp shows up on the next
# `cmake --build` without re-running configure.
file(GLOB_RECURSE goodnet_unit_test_sources
    CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/test_*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/*/test_*.cpp"
)

if(NOT goodnet_unit_test_sources)
    message(STATUS "tests/unit: no test_*.cpp sources found; skipping")
    return()
endif()

add_executable(goodnet_unit_tests ${goodnet_unit_test_sources})

target_link_libraries(goodnet_unit_tests
    PRIVATE
        goodnet_kernel
        GTest::gtest
        GTest::gtest_main
)

target_compile_features(goodnet_unit_tests PRIVATE cxx_std_23)

gtest_discover_tests(goodnet_unit_tests
    DISCOVERY_TIMEOUT 30
    PROPERTIES TIMEOUT 60
)
