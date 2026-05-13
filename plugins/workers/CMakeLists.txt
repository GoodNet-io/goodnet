# Subprocess plugin workers — separate executables the kernel spawns
# over `sdk/remote/wire.h`. Tracked here so the in-tree `remote_echo`
# proof has a stable integration smoke; out-of-tree workers live in
# their own gits the same way other plugins do.

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/remote_echo/CMakeLists.txt")
    add_subdirectory(remote_echo)
endif()
