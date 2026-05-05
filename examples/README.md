# examples/

Runnable scenarios that exercise the kernel + plugins as a host
program. Each example is a self-contained binary; none of them ship
in the operator install. Iterate locally through `nix run .#demo`
or build the example targets directly.

## Subdirectories

| Path | Binary | Role |
|---|---|---|
| `two_node/` | `goodnet-demo` | Two in-process kernels exchanging one frame over a real TCP socket under a Noise XX handshake |

## Build

The `GOODNET_BUILD_EXAMPLES` CMake option gates the examples tree;
default OFF in the Nix package, ON in the dev-shell quickstart:

```sh
nix run .#demo                    # configure (Release), build, run
# or
cmake -B build -DGOODNET_BUILD_EXAMPLES=ON
cmake --build build --target goodnet_demo
build/bin/goodnet-demo
```

## License

GPL-2.0 with Linking Exception. See top-level `LICENSE`.
