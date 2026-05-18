# examples/

Runnable scenarios that exercise the kernel + plugins as a host
program. Each example is a self-contained binary; none of them ship
in the operator install. Iterate locally through `nix run .#demo`
or build the example targets directly.

## Subdirectories

| Path | Binary | Role |
|---|---|---|
| `two_node/` | `goodnet-demo` | Two in-process kernels exchanging one frame over a real TCP socket under a Noise XX handshake |
| `bench/` | `goodnet-bench` | Throughput benchmark — two kernels in one process, Bob loops `host_api->send` against Alice as fast as the kernel accepts; reports payload Gbps |
| `hello-echo/` | — (source-only, not built) | DX reference: minimal client + server using the modern SDK sugar (`connect_to`, `listen_to`, `Subscription`), counted by `bench/comparison/runners/dx_loc_count.sh` against upstream "hello echo" samples for libp2p / iroh / etc. |

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
