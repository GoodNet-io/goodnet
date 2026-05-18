# Installing GoodNet

This page covers a production install of the GoodNet kernel as a
systemd-managed service. Operators looking for a development
build should follow the **Quickstart** in `README.md` — that
hands you a kernel + plugins built into `build-release/` without
touching the system.

---

## 1. What gets installed

A production install lays down four things on the host:

| Path | Owner | What |
|---|---|---|
| `/usr/bin/goodnetd` | root | Multicall CLI binary — `goodnetd run`, `config validate`, `plugin hash`, `manifest gen`, `version` |
| `/usr/lib/goodnet/lib*.so` | root | Plugin shared objects (transports, security providers, protocol layers, handlers) |
| `/etc/goodnet/node.json` | root | Kernel config — limits, log shape, profile selector |
| `/etc/goodnet/plugins.json` | root | Plugin manifest — path + SHA-256 per loadable .so |

Plus one user account and one state directory the systemd unit creates:

| Path | Owner | What |
|---|---|---|
| `goodnet:goodnet` | system user | UID the kernel runs as. No login shell, no home dir |
| `/var/lib/goodnet/` | `goodnet:goodnet`, mode `0750` | Plugin state (DHT routing tables, sync DBs, etc.) |

The kernel does not need root, raw sockets, or the host namespace
tree. The systemd unit (`dist/systemd/goodnetd.service`) drops every
privilege the kernel does not require — see §4 for the hardening
matrix.

---

## 2. Building from source

GoodNet uses CMake + a Nix dev shell. From a clone of the repo:

```sh
nix run .#build -- release   # release build, populates build-release/
sudo install -m 0755 build-release/bin/goodnetd /usr/bin/goodnetd
sudo install -d /usr/lib/goodnet
sudo install -m 0644 build-release/plugins/lib*.so /usr/lib/goodnet/
```

The `nix develop` shell supplies every transitive build dep
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

### 2.1 Truly-static variant

```sh
nix run .#build -- static    # populates build-static/{bin,lib}/
```

Routes through `nix build .#goodnet-core-static`, a `pkgsStatic`
derivation that rebuilds the kernel + bundled plugin set under
musl + statically-archived OpenSSL, libsodium, spdlog, fmt,
libstdc++, libgcc. The resulting binaries under `build-static/bin/`
have **no dynamic dependencies**:

```sh
$ file build-static/bin/remote_echo
build-static/bin/remote_echo: ELF 64-bit LSB executable, x86-64,
  version 1 (SYSV), statically linked, not stripped
$ ldd build-static/bin/remote_echo
        not a dynamic executable
```

Use the static variant when:

- Shipping inside a `scratch` / `distroless` Docker base layer
  (no glibc closure, image size in the single-MiB range).
- Deploying onto a stripped embedded rootfs with no `/nix/store`
  or distro libc.
- Building a chroot-portable bundle for incident-response /
  air-gapped sites where the runtime libc cannot be relied upon.

The static cut bundles every plugin into the kernel archive
(`-DGOODNET_STATIC_PLUGINS=ON`), so there are no neighbouring
`.so` files — the entire artefact is one ELF. Plugins that need
POSIX-only subsystems (`handler-store/sqlite`, `handler-dns/c-ares`)
are dropped from the bundle automatically; deploy those through
the regular dynamic build.

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
— see `docs/contracts/config.en.md` §3 for the full schema. The two
common knobs:

- `profile` — `embedded` (≤ 64 conns, no relay), `server` (default).
- `log.format` / `log.level` — `json|console` and `trace|debug|info|warn|error`.

Validate the config before loading it:

```sh
goodnetd config validate /etc/goodnet/node.json
```

The systemd unit's `ExecStartPre=` runs this same check; an
operator who edits the file in place gets unit-start failure rather
than a kernel that crashes mid-handshake.

### 3.3 Generate `/etc/goodnet/plugins.json`

The example manifest carries placeholder zero hashes. Regenerate
against your installed plugin .so paths:

```sh
sudo goodnetd manifest gen /usr/lib/goodnet/lib*.so > /tmp/plugins.json
sudo install -m 0644 /tmp/plugins.json /etc/goodnet/plugins.json
```

PluginManager refuses to dlopen any path not present in the manifest
with `GN_ERR_INTEGRITY_FAILED` — the manifest is the trust root.
Re-run `manifest gen` after every plugin upgrade so the kernel sees
the new hash.

### 3.4 Generate the node identity

```sh
goodnetd identity gen --out /etc/goodnet/identity.bin
```

The file lands at mode `0600` and carries the magic-prefixed
77-byte layout `NodeIdentity::save_to_file` writes per
`identity.en.md` §4. Replace the path the systemd unit's
`--identity` flag (or the `identity_path` config key) points at
to make the kernel pick the new file up on next start.

Inspect a saved identity without revealing the secret keys:

```sh
goodnetd identity show /etc/goodnet/identity.bin
```

The command prints `address`, `user_pk`, `device_pk`, `expiry`
and exits 0; secret seeds never reach stdout.

---

## 4. Installing the systemd unit

```sh
sudo install -m 0644 dist/systemd/goodnetd.service \
                     /etc/systemd/system/goodnetd.service
sudo useradd --system --no-create-home --shell /usr/sbin/nologin goodnet
sudo systemctl daemon-reload
sudo systemctl enable --now goodnet
```

The unit applies a hardening sandbox documented in
`dist/systemd/goodnetd.service`:

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
systemctl status goodnetd              # current state, last log lines
journalctl -u goodnetd -f              # live log tail
goodnetd config validate /etc/goodnet/node.json   # re-validate after edits
sudo systemctl reload goodnetd         # re-read /etc/goodnet/node.json
sudo systemctl restart goodnetd        # full restart with kernel teardown
```

The kernel exposes `Kernel::reload_config(text)` as a C-API
(`core/kernel/kernel.cpp:173`) but the shipped `goodnetd` unit does
not wire a SIGHUP / `ExecReload=` handler; `systemctl reload
goodnetd` is therefore not supported on the upstream unit and
`restart` is the operator-facing path until a daemon-side handler
ships. The unit file's `KillSignal=SIGTERM` + `TimeoutStopSec=30`
gives plugins 30 seconds to drain in-flight async work before
`SIGKILL`.

---

## 6. What's not in this document

- **Production deployment beyond the basic install** — sizing,
  multi-node mesh setup, plugin manifest workflow under upgrade,
  resource limits, service composition. Covered in
  [`operator/deployment.en.md`](./operator/deployment.en.md).
- **gssh** — SSH-over-GoodNet bridge (single binary, three modes:
  user wrapper, ProxyCommand callee, server-side forwarder). The
  install recipe carries the kernel; gssh is an operator app
  running alongside it. Covered in
  [`operator/gssh.ru.md`](./operator/gssh.ru.md).
- **Operator-side C++ binding** — `bridges/cpp` ships RAII
  wrappers over `sdk/core.h` for apps consuming the kernel as a
  library. App authors read
  [`architecture/bridges-model.ru.md`](./architecture/bridges-model.ru.md);
  the binding repo lives at `GoodNet-io/bridges-cpp`.
- **Metrics scrape and alerting** — kernel and plugin counter
  catalogue plus SLI mapping in
  [`operator/metrics-catalog.en.md`](./operator/metrics-catalog.en.md).
  An exporter plugin (Prometheus, OpenTelemetry) scrapes the
  counters; out-of-tree, ships per deployment.
- **Runtime troubleshooting** — `gn_result_t` reference, common
  scenarios, where to look. Covered in
  [`operator/troubleshooting.ru.md`](./operator/troubleshooting.ru.md).
- **Reverse-proxy front-end** — operators running on the public
  internet put nginx / HAProxy in front of the TCP listener for
  per-IP rate limiting until a hardening plugin ships per-source
  bucketing. The reverse proxy is the recommended layer.
- **Backup and key rotation** — NodeIdentity rotation policy is
  not yet specified. Operators copy `/etc/goodnet/identity.bin`
  before generating a replacement and update each peer's
  `peers.json` entry by address.
