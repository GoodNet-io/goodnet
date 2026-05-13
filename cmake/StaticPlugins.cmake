# cmake/StaticPlugins.cmake — generator for the static-plugin registry.
#
# `goodnet_register_static_plugins(<host_target> <plugin_target>...)`
#
# Wires every passed plugin target into <host_target> for a static
# build (`-DGOODNET_STATIC_PLUGINS=ON`). Each plugin target was
# defined by `add_plugin(...)`; in static mode that produces an
# OBJECT library whose entry symbols carry a `_<stem>` suffix
# (`gn_plugin_init_link_tcp`, etc.), where `<stem>` is the target
# name with the leading `goodnet_` stripped.
#
# This function:
#   1. Generates `${CMAKE_BINARY_DIR}/static_plugins.cpp` from
#      `cmake/static_plugins.cpp.in`. The generated TU declares each
#      plugin's six entry symbols and gathers their addresses into
#      `gn_plugin_static_registry[]`.
#   2. Excludes `core/plugin/static_registry_default.cpp` from the
#      kernel build so the generated TU's definition is unique.
#   3. Adds the generated TU + every plugin object library to
#      <host_target>'s link list.
#
# Calls into `target_link_libraries` use PRIVATE so the registry
# shows up only in the kernel binary; downstream `find_package`
# consumers continue to build dynamic plugins by default.
#
# Example use in the root CMakeLists.txt:
#
#     if(GOODNET_STATIC_PLUGINS)
#         include(StaticPlugins)
#         goodnet_register_static_plugins(goodnet
#             goodnet_security_null
#             goodnet_link_ipc
#             goodnet_handler_heartbeat
#             ...
#         )
#     endif()

function(goodnet_register_static_plugins host_target)
    set(plugins ${ARGN})

    set(GOODNET_STATIC_PLUGIN_DECLS "")
    set(GOODNET_STATIC_PLUGIN_ENTRIES "")

    foreach(p IN LISTS plugins)
        # Strip `goodnet_` prefix to derive the suffix the plugin's
        # entry macros baked in via `-DGN_PLUGIN_STATIC_NAME=<stem>`.
        string(REGEX REPLACE "^goodnet_" "" stem "${p}")

        # Bracket-string each declaration so the trailing `;` does not
        # get interpreted as a CMake list separator when the value
        # gets substituted into the template by configure_file.
        string(APPEND GOODNET_STATIC_PLUGIN_DECLS
            [[void        gn_plugin_sdk_version_]] ${stem}
            [[(uint32_t*, uint32_t*, uint32_t*);
]]
            [[gn_result_t gn_plugin_init_]] ${stem}
            [[(const host_api_t*, void**);
]]
            [[gn_result_t gn_plugin_register_]] ${stem} [[(void*);
]]
            [[gn_result_t gn_plugin_unregister_]] ${stem} [[(void*);
]]
            [[void        gn_plugin_shutdown_]] ${stem} [[(void*);
]]
            [[const gn_plugin_descriptor_t* gn_plugin_descriptor_]] ${stem} [[(void);
]]
        )
        string(APPEND GOODNET_STATIC_PLUGIN_ENTRIES
            "    { \"${stem}\",\n"
            "      &gn_plugin_sdk_version_${stem},\n"
            "      &gn_plugin_init_${stem},\n"
            "      &gn_plugin_register_${stem},\n"
            "      &gn_plugin_unregister_${stem},\n"
            "      &gn_plugin_shutdown_${stem},\n"
            "      &gn_plugin_descriptor_${stem} },\n"
        )
    endforeach()

    configure_file(
        "${CMAKE_SOURCE_DIR}/cmake/static_plugins.cpp.in"
        "${CMAKE_BINARY_DIR}/static_plugins.cpp"
        @ONLY
    )

    # The generated TU's `gn_plugin_static_registry[]` definition
    # collides with the empty default array compiled into the kernel
    # OBJECT lib. Drop the default source file so the symbol stays
    # unique. The OBJECT lib is rebuilt from the trimmed source list.
    get_target_property(_kernel_srcs goodnet_kernel_objects SOURCES)
    list(FILTER _kernel_srcs EXCLUDE REGEX "plugin/static_registry_default\\.cpp$")
    set_target_properties(goodnet_kernel_objects PROPERTIES SOURCES "${_kernel_srcs}")

    target_sources(${host_target}
        PRIVATE "${CMAKE_BINARY_DIR}/static_plugins.cpp")

    # Link every plugin's entry OBJECT lib + its matching C++-class
    # _objects sibling when present. The objects lib carries the
    # plugin's implementation TUs (`ipc.cpp` → `goodnet_ipc_objects`,
    # etc.); OBJECT libs do not propagate transitively, so we resolve
    # the sibling explicitly. Plugins authored as a single TU
    # (security/null) have no _objects sibling — the plugin target
    # itself carries the whole implementation.
    foreach(p IN LISTS plugins)
        target_link_libraries(${host_target} PRIVATE ${p})
        string(REGEX REPLACE "^goodnet_(link|handler|security|strategy)_"
               "" _bare "${p}")
        set(_obj_target "goodnet_${_bare}_objects")
        if(TARGET ${_obj_target})
            target_link_libraries(${host_target} PRIVATE ${_obj_target})
        endif()
    endforeach()
endfunction()
