# apps/

Operator-facing binaries. Each app pulls the kernel through the
in-tree targets (`GoodNet::kernel`, `GoodNet::protocol_gnet`,
`GoodNet::ctx_accessors`) and ships as part of the kernel install.

## Subdirectories

| Path | Binary | Role |
|---|---|---|
| `goodnet/` | `goodnet` | BusyBox-style multicall: `version`, `config validate`, `plugin hash`, `manifest gen`, `identity gen`/`show`, `run` |

## Build

In-tree:

```sh
nix build .#default       # full repo, includes the apps
build/bin/goodnet --help
```

Or directly through the operator-facing alias:

```sh
nix run .#goodnet -- version
nix run .#node    -- --config /etc/goodnet/node.json --manifest ... --identity ...
```

## License

Apache 2.0 — see top-level `LICENSE` and the linking-exception text.
