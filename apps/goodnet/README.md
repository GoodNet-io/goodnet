# apps/goodnet — operator CLI

BusyBox-style multicall binary. One executable, flat dispatch by
subcommand.

```
goodnet version
goodnet config validate <file>
goodnet plugin hash <so>
goodnet manifest gen <so>...
goodnet identity gen --out <file> [--expiry <unix-seconds>]
goodnet identity show <file>
goodnet run --config <file> --manifest <file> --identity <file>
```

## Layout

| File | Subcommand |
|---|---|
| `main.cpp`                       | dispatch table, exit code conventions |
| `subcommands.hpp`                | dispatch declarations |
| `subcommands/version.cpp`        | build version string |
| `subcommands/config_validate.cpp`| JSON parse + Config validate |
| `subcommands/plugin_hash.cpp`    | SHA-256 of a plugin `.so` |
| `subcommands/manifest_gen.cpp`   | manifest emit for a list of `.so` paths |
| `subcommands/identity.cpp`       | NodeIdentity gen / show (77-byte binary format) |
| `subcommands/run.cpp`            | production node entry — load identity + config + manifest, construct kernel, dlopen plugins, install SIGTERM/SIGINT handler, drain on signal |

## Build

```sh
nix build .#goodnet              # via apps alias
# or
nix build .#default && build/bin/goodnet
```

## Tests

`tests/integration/test_apps_goodnet.cpp` drives the binary through
`popen` and asserts the documented exit codes + stdout shape.

## License

Apache 2.0.
