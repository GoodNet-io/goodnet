# Installing GoodNet

This page covers a production install of the GoodNet kernel as a
systemd-managed service. Operators looking for a development build
should follow the `nix run .#dev` path in `README.md` — that hands
you a kernel + plugins built into `build/` without touching the
system.

---

## 1. What gets installed

A production install lays down four things on the host:

| Path | Owner | What |
|---|---|---|
| `/usr/bin/goodnet` | root | Multicall CLI binary — `goodnet run`, `config validate`, `plugin hash`, `manifest gen`, `version` |
| `/usr/lib/goodnet/lib*.so` | root | Plugin shared objects (transports, security providers, protocol layers, handlers) |
| `/etc/goodnet/node.json` | root | Kernel config — limits, log shape, profile selector |
| `/etc/goodnet/plugins.json` | root | Plugin manifest — path + SHA-256 per loadable .so |

Plus one user account and one state directory the systemd unit creates:

| Path | Owner | What |
|---|---|---|
| `goodnet:goodnet` | system user | UID the kernel runs as. No login shell, no home dir |
| `/var/lib/goodnet/` | `goodnet:goodnet`, mode `0750` | Plugin state (DHT routing tables, sync DBs, etc.) |

The kernel does not need root, raw sockets, or the host namespace
tree. The systemd unit (`dist/systemd/goodnet.service`) drops every
privilege the kernel does not require — see §4 for the hardening
matrix.

---

## 2. Building from source

GoodNet uses CMake + a Nix dev shell. From a clone of the repo:

```sh
nix run .#build       # release build, populates build-release/
sudo install -m 0755 build-release/bin/goodnet /usr/bin/goodnet
sudo install -d /usr/lib/goodnet
sudo install -m 0644 build-release/plugins/lib*.so /usr/lib/goodnet/
```

The `nix run .#dev` shell supplies every transitive build dep
(gcc 15, cmake, ninja, libsodium, asio, spdlog, fmt, nlohmann-json,
gtest) — host package versions do not matter as long as the dev
shell is on the build path.

A non-Nix host can use the system toolchain directly; the only
hard requirement is C++23 and libsodium 1.0.18+. CMake configure
flags:

```sh
cmake -B build-release -S . \
    -DCMAKE_BUILD_TYPE=Release \
    -DGOODNET_BUILD_TESTS=OFF \
    -DGOODNET_BUILD_EXAMPLES=OFF
cmake --build build-release -j
```

---

## 3. Configuring the node

### 3.1 Copy the example files

```sh
sudo install -d /etc/goodnet
sudo install -m 0644 dist/example/node.json    /etc/goodnet/node.json
sudo install -m 0644 dist/example/plugins.json /etc/goodnet/plugins.json
```

### 3.2 Edit `/etc/goodnet/node.json`

The example file picks the `server` profile and overrides nothing.
Every `limits.*` field has a built-in default per the active profile
— see `docs/contracts/config.md` §3 for the full schema. The two
common knobs:

- `profile` — `embedded` (≤ 64 conns, no relay), `server` (default).
- `log.format` / `log.level` — `json|console` and `trace|debug|info|warn|error`.

Validate the config before loading it:

```sh
goodnet config validate /etc/goodnet/node.json
```

The systemd unit's `ExecStartPre=` runs this same check; an
operator who edits the file in place gets unit-start failure rather
than a kernel that crashes mid-handshake.

### 3.3 Generate `/etc/goodnet/plugins.json`

The example manifest carries placeholder zero hashes. Regenerate
against your installed plugin .so paths:

```sh
sudo goodnet manifest gen /usr/lib/goodnet/lib*.so > /tmp/plugins.json
sudo install -m 0644 /tmp/plugins.json /etc/goodnet/plugins.json
```

PluginManager refuses to dlopen any path not present in the manifest
with `GN_ERR_INTEGRITY_FAILED` — the manifest is the trust root.
Re-run `manifest gen` after every plugin upgrade so the kernel sees
the new hash.

### 3.4 Generate the node identity

*(Lands in Wave 8.1.b — the `identity gen|show` subcommands ship in
the follow-up branch alongside the `run` subcommand. Until then,
build the kernel as a library and call
`gn::core::identity::NodeIdentity::generate(0)` from a host
program; serialize the device keypair with whatever format your
deployment already uses.)*

---

## 4. Installing the systemd unit

```sh
sudo install -m 0644 dist/systemd/goodnet.service \
                     /etc/systemd/system/goodnet.service
sudo useradd --system --no-create-home --shell /usr/sbin/nologin goodnet
sudo systemctl daemon-reload
sudo systemctl enable --now goodnet
```

The unit applies a hardening sandbox documented in
`dist/systemd/goodnet.service`:

| Knob | Effect |
|---|---|
| `User=goodnet` | runs as an unprivileged system user |
| `NoNewPrivileges=yes` | drops setuid / capabilities transitions |
| `ProtectSystem=strict` | rest of `/usr` mounted read-only |
| `ProtectHome=yes` | no `/home` access |
| `PrivateTmp=yes` | per-unit `/tmp` namespace |
| `PrivateDevices=yes` | no `/dev` access beyond `/dev/null`, `/dev/random`, `/dev/urandom` |
| `MemoryDenyWriteExecute=yes` | no JIT / code injection — the kernel's plugin loader uses `dlopen` once, not mmap-and-jump |

A custom build that mmap-and-execs (e.g. embedded JIT for a future
scripting plugin) drops `MemoryDenyWriteExecute` in a drop-in unit
file rather than the shipped one.

---

## 5. Operating the running node

```sh
systemctl status goodnet               # current state, last log lines
journalctl -u goodnet -f               # live log tail
goodnet config validate /etc/goodnet/node.json   # re-validate after edits
sudo systemctl reload goodnet          # re-read /etc/goodnet/node.json (v1.x)
sudo systemctl restart goodnet         # full restart with kernel teardown
```

Hot reload of the kernel config (without process restart) lands in
v1.x — until then `restart` is the supported path. The unit file's
`KillSignal=SIGTERM` + `TimeoutStopSec=30` gives plugins 30 seconds
to drain in-flight async work before `SIGKILL`.

---

## 6. What's not in this document

- **Reverse-proxy front-end** — operators running on the public
  internet should put nginx / HAProxy in front of the TCP listener
  for per-IP rate limiting (Wave 4.1-4.4 hardening plugin lands in
  v1.x; until then the reverse proxy is the recommended layer).
- **Multi-node mesh setup** — pairing identities, NAT traversal,
  seed-node configuration. Lands with the relay / DHT plugins in
  v1.x.
- **Backup and key rotation** — NodeIdentity rotation policy ships
  with the `identity` subcommand in Wave 8.1.b.
- **Monitoring integration** — the kernel exposes `host_api`
  counter slots; an exporter plugin (Prometheus, OpenTelemetry)
  scrapes them. Out-of-tree, ships per deployment.
