# goodnet-link-ipc

AF_UNIX SOCK_STREAM transport for GoodNet. `ipc:///run/goodnet.sock`
URIs land here. Listens with peer-cred + path normalisation gates
(rejects cross-UID and `..`-traversed paths), so an in-process
bridge plugin can declare `gn_trust_class = IntraNode` on its IPC
connection and receive the matching trust upgrade.

**Kind**: link · **Artefact**: dynamic plugin (`.so` via dlopen)
· **License**: MIT (see `LICENSE`)

## Build

In-tree, alongside the kernel:

```sh
nix build .#goodnet-link-ipc
# result/lib/goodnet/plugins/libgoodnet_link_ipc.so
```

Standalone, against an installed kernel SDK:

```sh
cd plugins/links/ipc
cmake -B build -DCMAKE_PREFIX_PATH=/usr/local -DBUILD_TESTING=OFF
cmake --build build
```

## Load

Manifest entry pins the SHA-256 digest; `gn_plugin_init` registers
the `ipc` scheme. See `docs/install.md` and
`docs/contracts/plugin-manifest.md` in the kernel tree.

## Contract

- Kernel-side link contract: `docs/contracts/link.md`
- IntraNode trust class for in-process bridges:
  `docs/contracts/security-trust.md` §3
- Bridge composition pattern: `docs/contracts/host-api.md` §8.1
