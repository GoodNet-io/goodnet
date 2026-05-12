# dist/

Operator distribution materials. Ships next to the kernel install
so a deployment recipe never has to hunt for the canonical reference
shape of a config or a systemd unit.

## Subdirectories

| Path | Role |
|---|---|
| `example/`  | Reference `node.json` (kernel config) and `plugins.json` (manifest); dropped into `/etc/goodnet/` and adjusted per deployment |
| `migrate/`  | Procedure for post-rc1 plugin spinoff out of the monorepo (`spinoff-cookbook.md`) |
| `systemd/`  | `goodnet.service` unit with `NoNewPrivileges`, `ProtectSystem`, `MemoryDenyWriteExecute`, etc. — drop into `/etc/systemd/system/` |

## Use

```sh
sudo cp dist/example/node.json    /etc/goodnet/node.json
sudo cp dist/example/plugins.json /etc/goodnet/plugins.json
sudo cp dist/systemd/goodnet.service /etc/systemd/system/goodnet.service
sudo systemctl enable --now goodnet
```

`docs/install.md` is the longer-form walkthrough.

## License

GPL-2.0 with Linking Exception. See top-level `LICENSE`.