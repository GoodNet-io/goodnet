# cmake/GoodNetTesting.cmake — helpers for GoodNet test integrations.
#
# Loaded both by the in-tree top-level CMakeLists.txt (so the monorepo
# aggregate build picks the helpers up) and by `GoodNetConfig.cmake`
# (so an out-of-tree plugin that does `find_package(GoodNet REQUIRED)`
# inherits them automatically). The two paths import the same file so
# the patched-target behaviour stays identical between in-tree and
# external standalone plugin builds.
#
# Currently exposes:
#   goodnet_patch_rapidcheck_targets()
#       Patches rapidcheck's imported targets to use the include path
#       reported by pkg-config. Works around a nixpkgs packaging quirk
#       where the `out` output ships the CMake config but the headers
#       live in the `dev` output, leaving the imported target's
#       INTERFACE_INCLUDE_DIRECTORIES pointing at a non-existent
#       `${_IMPORT_PREFIX}/include`. Idempotent and silent — a no-op
#       when rapidcheck or pkg-config is unavailable.
#
# Re-include guard: define each helper once. Plugins that pull this
# in via both `find_package(GoodNet)` and a direct `include()` should
# not produce "function already defined" warnings.

if(COMMAND goodnet_patch_rapidcheck_targets)
    return()
endif()

function(goodnet_patch_rapidcheck_targets)
    find_package(PkgConfig QUIET)
    if(NOT PkgConfig_FOUND)
        return()
    endif()

    pkg_check_modules(_GN_RAPIDCHECK_PC QUIET rapidcheck)
    if(NOT _GN_RAPIDCHECK_PC_FOUND)
        return()
    endif()

    # Patch every rapidcheck-* satellite target rapidcheck's
    # `rapidcheckConfig.cmake` may define. Each carries the same
    # broken `${_IMPORT_PREFIX}/include` path inherited from the
    # parent package layout.
    foreach(_target IN ITEMS
        rapidcheck
        rapidcheck_gtest
        rapidcheck_catch
        rapidcheck_doctest
        rapidcheck_gmock
        rapidcheck_boost
        rapidcheck_boost_test)
        if(TARGET ${_target})
            set_target_properties(${_target} PROPERTIES
                INTERFACE_INCLUDE_DIRECTORIES
                "${_GN_RAPIDCHECK_PC_INCLUDE_DIRS}")
        endif()
    endforeach()
endfunction()
