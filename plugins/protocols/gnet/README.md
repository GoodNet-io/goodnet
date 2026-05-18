# goodnet-protocol-gnet

Canonical mesh-framing protocol layer for GoodNet v1. Encodes
`gn_message_t` envelopes onto the wire with a 14-byte fixed header
plus optional 32-byte sender / receiver public keys (gated by
`flags`); decodes the inverse on inbound. Three modes: direct (no
PK on wire — peers learned identity at handshake), broadcast
(`EXPLICIT_SENDER` only), relay-transit (`EXPLICIT_SENDER` +
`EXPLICIT_RECEIVER`).

**Kind**: protocol layer · **Artefact**: STATIC library linked into
the kernel binary (not a dlopen plugin) · **License**: GPL-2.0 with Linking Exception
(see `LICENSE`)

## Build

In-tree, statically linked into the kernel:

```sh
nix build .#goodnet-protocol-gnet
# result/lib/libgoodnet_protocol_gnet.a (consumed by the kernel binary)
```

Standalone, against an installed kernel SDK:

```sh
cd plugins/protocols/gnet
cmake -B build -DCMAKE_PREFIX_PATH=/usr/local -DBUILD_TESTING=OFF
cmake --build build
```

## Load

Registered by the host program before `gn_core_start`. C ABI hosts
call `gn_core_register_protocol(core, &vt, self)` (see
`docs/contracts/core-c.en.md`). C++ hosts may call
`kernel.protocol_layers().register_layer(std::make_shared<GnetProtocol>(), &id)`
directly. There is no dlopen path for protocol layers in v1;
out-of-tree custom protocols ship as host programs that wrap
the kernel.

## Contract

- Wire format spec: [`docs/wire-format.md`](docs/wire-format.md)
- Kernel-side protocol-layer contract: `docs/contracts/protocol-layer.en.md`
