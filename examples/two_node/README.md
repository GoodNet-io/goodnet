# two_node — Noise-over-TCP quickstart

Single binary that runs two GoodNet kernels in one process, talks
between them over a real loopback TCP socket under a Noise XX
handshake, and round-trips one application envelope. Closest path
from `git clone` to "two endpoints established a confidential
channel and exchanged a frame".

## Run

```sh
nix run .#demo
# or, manually:
nix develop
cmake -B build -G Ninja -DGOODNET_BUILD_EXAMPLES=ON
cmake --build build --target goodnet_demo
build/bin/goodnet-demo
```

Expected output (Release):

```
[demo] GoodNet two-node quickstart
[demo] noise plugin: …/libgoodnet_security_noise.so
2026-… info kernel constructed (max_connections=4096, max_extensions=256)
2026-… info kernel constructed (max_connections=4096, max_extensions=256)
[demo] alice listening on tcp://127.0.0.1:…
[demo] bob   dialling   tcp://127.0.0.1:…
[demo] noise XX completed; transport phase active
[demo] bob   send  msg_id=0xc0ffee payload="hello from bob"
[demo] alice recv payload="hello from bob"
[demo] ok
```

Debug build adds the `[kernel.cpp]` source-location prefix on the
`info` lines per the build-aware default pattern in
`core/util/log.hpp`.

## Source

`main.cpp` (≈260 lines) — kernel construct, plugin load through
`PluginManager.dlopen` for the noise provider, identity setup,
handler register, dual `notify_connect`, payload round-trip. Worth
reading as the shortest end-to-end host before writing your own.

The binary direct-links the TCP transport's OBJECT library and the
GNET protocol layer for compactness — production hosts that want
the full plugin-manager flow follow the `apps/goodnet/subcommands/
run.cpp` shape instead.

## License

Apache 2.0.
