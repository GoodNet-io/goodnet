# cmake/AddPlugin.cmake — `add_plugin(NAME sources...)` macro for plugin
# directories under plugins/. Centralises the build flags every plugin
# needs so individual CMakeLists files stay short and consistent.
#
# Behaviour:
#   - Default builds a SHARED library named `lib${NAME}.so`. The kernel
#     PluginManager opens it by that name through `dlopen`.
#   - Under `-DGOODNET_STATIC_PLUGINS=ON` the same source compiles into
#     an OBJECT library that the kernel links statically — useful for
#     embedded or test builds where dlopen is unavailable.
#   - Auto-links `GoodNet::sdk` so plugin code includes `<sdk/...>`
#     without per-target plumbing.
#   - Hides symbols by default for clean ABI — except in-tree builds
#     where tests link plugins directly and need every symbol visible.
#   - Adds size-optimisation flags for the SHARED case so the resulting
#     `.so` does not carry dead sections.
#
# Not applied to the mandatory mesh-framing implementation in
# `plugins/protocols/gnet/`. That target is a STATIC library linked
# directly into the kernel binary; it is structural, not a dlopen-able
# plugin, and uses its own CMakeLists.

if(NOT DEFINED _GOODNET_ADD_PLUGIN_INCLUDED)
    set(_GOODNET_ADD_PLUGIN_INCLUDED TRUE)
endif()

# In-tree build flag — the root CMakeLists.txt sets it TRUE before
# including this helper. Out-of-tree plugin builds load this file
# through `find_package(GoodNet)` and inherit FALSE; the visibility
# carve-out for in-tree tests then does not apply.
if(NOT DEFINED _GOODNET_IN_TREE)
    set(_GOODNET_IN_TREE FALSE CACHE INTERNAL
        "Building plugins in-tree alongside the kernel")
endif()

option(GOODNET_STATIC_PLUGINS
    "Compile plugins as OBJECT libraries linked statically into the kernel"
    OFF)

#
# add_plugin(NAME source1 [source2 ...])
#
# Defines the plugin target with the conventional flags. Callers may
# extend the target afterwards (e.g. `target_link_libraries(${NAME}
# PRIVATE Foo::Bar)`) — the macro intentionally does not own the link
# list beyond `GoodNet::sdk`.
#
function(add_plugin NAME)
    set(_sources ${ARGN})

    if(GOODNET_STATIC_PLUGINS)
        add_library(${NAME} OBJECT ${_sources})
        # Suffix every entry symbol with the plugin stem so multiple
        # plugins linked into the same binary don't collide. The
        # symbol-rename macros in `sdk/plugin.h` read both defines:
        # `GOODNET_STATIC_PLUGINS` gates the rename, and
        # `GN_PLUGIN_STATIC_NAME=<stem>` supplies the suffix token.
        string(REGEX REPLACE "^goodnet_" "" _stem "${NAME}")
        target_compile_definitions(${NAME} PRIVATE
            GOODNET_STATIC_PLUGINS=1
            GN_PLUGIN_STATIC_NAME=${_stem})
    else()
        add_library(${NAME} SHARED ${_sources})
        set_target_properties(${NAME} PROPERTIES
            PREFIX                   "lib"
            LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/plugins"
        )
        # Hide symbols only for standalone (out-of-tree) plugin builds.
        # In-tree tests link plugin objects directly and must see every
        # symbol regardless of visibility.
        if(NOT _GOODNET_IN_TREE)
            set_target_properties(${NAME} PROPERTIES
                CXX_VISIBILITY_PRESET     hidden
                VISIBILITY_INLINES_HIDDEN ON
            )
        endif()
    endif()

    # Every plugin uses the SDK; the link pulls includes through the
    # INTERFACE target so plugin sources write `#include <sdk/...>` cleanly.
    target_link_libraries(${NAME} PRIVATE GoodNet::sdk)

    # Per-plugin warning baseline mirrors the project-wide flags.
    target_compile_options(${NAME} PRIVATE
        -Wall -Wextra -Wpedantic
        -Wno-unused-parameter
    )

    # Size optimisation for shared output. Static builds inherit the
    # kernel's flags via the OBJECT-library link.
    if(NOT GOODNET_STATIC_PLUGINS AND NOT APPLE)
        target_compile_options(${NAME} PRIVATE -Os -ffunction-sections -fdata-sections)
        target_link_options(${NAME}    PRIVATE -Wl,--gc-sections)
    endif()

    # C++23 across the SDK boundary.
    target_compile_features(${NAME} PRIVATE cxx_std_23)

    # PIC required for SHARED on POSIX; harmless for OBJECT.
    set_target_properties(${NAME} PROPERTIES POSITION_INDEPENDENT_CODE ON)

    # ── Install ──────────────────────────────────────────────────────────
    # Operators that ran `make install` on this tree get every plugin's
    # `.so` under `${prefix}/lib/goodnet/plugins/`; the kernel's
    # PluginManager finds them through the manifest
    # (see `plugin-manifest.md`). OBJECT builds (static-plugin mode)
    # skip the install — they are linked into the host binary at build
    # time and have no standalone artefact to ship.
    #
    # The `LICENSE` file next to each plugin's CMakeLists.txt installs
    # alongside the `.so` so a deployment that ships only the install
    # tree still carries the plugin's license. Plugins authored from
    # the bundled-tree templates are MIT or Apache-2.0; the linker
    # exception in the kernel `LICENSE` covers the GPL boundary.
    if(NOT GOODNET_STATIC_PLUGINS)
        install(TARGETS ${NAME}
                LIBRARY DESTINATION lib/goodnet/plugins)
        if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
            install(FILES   "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE"
                    DESTINATION lib/goodnet/plugins
                    RENAME      "LICENSE.${NAME}")
        endif()
    endif()
endfunction()
