# cmake/goodnet_app.cmake — `goodnet_app(TARGET sources...)` helper.
#
# Convenience macro for downstream consumer projects: collapses the
# add_executable + target_link_libraries + RPATH boilerplate that
# every GoodNet app would otherwise re-type into a single call.
#
#     find_package(GoodNet REQUIRED)
#     goodnet_app(my_app main.cpp other.cpp)
#
# After the macro returns, the caller may attach additional
# target_* properties on the target (extra link libraries, compile
# options, etc.); the macro intentionally only owns the kernel +
# SDK link surface + the RPATH wiring that makes the resulting
# binary runnable straight out of `./build/`.
#
# RPATH wiring. Two directories matter at run time:
#   * `${GOODNET_LIB_DIR}` — kernel shared object lives here; the
#     `gn::sdk::Core` ctor `dlopen`s `libgoodnet_kernel.so` through
#     the ABI-stable `gn_core_*` entries.
#   * `${GOODNET_PLUGIN_PATH}` — baseline plugin .so set; the kernel
#     dispatches `dlopen` against this path when the manifest names
#     a plugin.
# Both come in through env vars the `app` devShell exports; the
# helper reads them through `$ENV{...}` at configure time, falling
# back to the standard nix profile / XDG locations when called
# outside of `nix develop`.
#
# C++23 across the SDK boundary — pin via `target_compile_features`.

if(NOT DEFINED _GOODNET_APP_INCLUDED)
    set(_GOODNET_APP_INCLUDED TRUE)
endif()

# Resolve the kernel lib dir + plugin path at module-load time.
# Cached so a re-configure does not re-walk the env / store paths
# every iteration.

if(NOT DEFINED GOODNET_LIB_DIR)
    if(DEFINED ENV{GOODNET_LIB_DIR})
        set(GOODNET_LIB_DIR "$ENV{GOODNET_LIB_DIR}" CACHE PATH
            "Directory containing libgoodnet_kernel.so")
    elseif(DEFINED ENV{GOODNET_CORE_LIB})
        get_filename_component(_gn_lib_dir "$ENV{GOODNET_CORE_LIB}" DIRECTORY)
        set(GOODNET_LIB_DIR "${_gn_lib_dir}" CACHE PATH
            "Directory containing libgoodnet_kernel.so")
    elseif(TARGET GoodNet::kernel_shared)
        # find_package(GoodNet) imported the kernel target; the
        # location lives on the target's IMPORTED_LOCATION property.
        get_target_property(_gn_kernel_loc GoodNet::kernel_shared
                            IMPORTED_LOCATION)
        if(_gn_kernel_loc)
            get_filename_component(_gn_lib_dir "${_gn_kernel_loc}" DIRECTORY)
            set(GOODNET_LIB_DIR "${_gn_lib_dir}" CACHE PATH
                "Directory containing libgoodnet_kernel.so")
        endif()
    endif()
endif()

if(NOT DEFINED GOODNET_PLUGIN_PATH)
    if(DEFINED ENV{GOODNET_PLUGIN_PATH})
        set(GOODNET_PLUGIN_PATH "$ENV{GOODNET_PLUGIN_PATH}" CACHE PATH
            "Directory containing GoodNet plugin .so files")
    else()
        if(DEFINED ENV{XDG_DATA_HOME})
            set(_gn_xdg "$ENV{XDG_DATA_HOME}")
        else()
            set(_gn_xdg "$ENV{HOME}/.local/share")
        endif()
        set(GOODNET_PLUGIN_PATH "${_gn_xdg}/goodnet/plugins" CACHE PATH
            "Directory containing GoodNet plugin .so files")
    endif()
endif()

# libsodium is required for the in-process SHA-256 of plugin .so
# files the kernel verifies through the manifest. Discover once at
# module load so per-target callers do not re-run pkg_check_modules.
if(NOT TARGET PkgConfig::SODIUM)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)
endif()

#
# goodnet_app(TARGET_NAME source1 [source2 ...])
#
# Wires an executable target to:
#   * `GoodNet::sdk`           — header-only C ABI include surface
#   * `GoodNet::sdk_dx`        — `gn::sdk::Core` + C++ lifecycle helpers
#   * `GoodNet::kernel_shared` — `libgoodnet_kernel.so` C ABI
#   * `PkgConfig::SODIUM`      — plugin manifest digest computation
#   * `cxx_std_23`             — the kernel ABI compiles under C++23
#   * BUILD_RPATH on `${GOODNET_LIB_DIR};${GOODNET_PLUGIN_PATH}`
#     so the binary runs straight out of the build tree without
#     LD_LIBRARY_PATH plumbing.
#
function(goodnet_app TARGET_NAME)
    add_executable(${TARGET_NAME} ${ARGN})

    target_link_libraries(${TARGET_NAME} PRIVATE
        GoodNet::sdk
        GoodNet::sdk_dx
        GoodNet::kernel_shared
        PkgConfig::SODIUM)

    target_compile_features(${TARGET_NAME} PRIVATE cxx_std_23)

    # BUILD_RPATH covers `./build/<target>` runs; INSTALL_RPATH
    # covers `cmake --install` deployments where the binary lands
    # under `<prefix>/bin/` and the kernel + plugins live under
    # `<prefix>/lib/` + `<prefix>/lib/goodnet/plugins/`. The two
    # rpaths are independent properties; both get set so a consumer
    # that runs `cmake --install` does not need a second `chrpath`
    # pass to make the installed binary runnable.
    set(_gn_build_rpath "")
    if(GOODNET_LIB_DIR)
        list(APPEND _gn_build_rpath "${GOODNET_LIB_DIR}")
    endif()
    if(GOODNET_PLUGIN_PATH)
        list(APPEND _gn_build_rpath "${GOODNET_PLUGIN_PATH}")
    endif()

    if(_gn_build_rpath)
        set_target_properties(${TARGET_NAME} PROPERTIES
            BUILD_RPATH   "${_gn_build_rpath}"
            INSTALL_RPATH "${_gn_build_rpath}")
    endif()
endfunction()
