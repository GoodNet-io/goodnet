# Example apps. Built only when GOODNET_BUILD_EXAMPLES=ON. The flake
# wires a `nix run .#demo` target that flips the option on for the
# build it kicks.

add_subdirectory(two_node)
add_subdirectory(bench)
