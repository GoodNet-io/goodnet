# goodnet-protocol-raw

Opaque-payload protocol layer for GoodNet. Bypasses the GNET
mesh-framing header and routes the connection bytes straight to a
single handler — useful for simulation harnesses, PCAP replay, and
foreign-protocol passthrough scenarios where the application owns
the framing.

**Kind**: protocol layer · **Artefact**: STATIC library linked into
the host binary (not a dlopen plugin) · **License**: MIT
(see `LICENSE`)

## Build

In-tree, statically linked into the kernel:

```sh
nix build .#goodnet-protocol-raw
# result/lib/libgoodnet_protocol_raw.a
```

Standalone, against an installed kernel SDK:

```sh
cd plugins/protocols/raw
cmake -B build -DCMAKE_PREFIX_PATH=/usr/local -DBUILD_TESTING=OFF
cmake --build build
```

## Load

A host program calls
`kernel.set_protocol_layer(std::make_shared<RawProtocol>(...))` to
swap the active layer. v1 ships GNET as the default; `raw` is the
opt-in alternative for hosts that already have framing.

## Contract

- Kernel-side protocol-layer contract: `docs/contracts/protocol-layer.md`
- Opaque-payload semantics: a single handler receives every byte
  from a connection without any framing or routing tag.
