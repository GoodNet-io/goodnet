# Operator deployment

Long-form complement to [install](../install.en.md). The install
page covers single-node bring-up; this document covers the
questions that surface once the node is running: sizing, what
every systemd hardening flag buys, how peers find one another, and
how plugin manifests fit into a release process. Audience: sysadmins
running GoodNet on Linux, SREs folding it into fleet automation.

The install page is required reading first. Nothing here repeats
the basic file layout or build instructions.

---

## Contents

1. [Profiles and sizing](#1-profiles-and-sizing)
2. [Layout on disk](#2-layout-on-disk)
3. [systemd unit reference](#3-systemd-unit-reference)
4. [Multi-node mesh setup](#4-multi-node-mesh-setup)
5. [Plugin lifecycle in production](#5-plugin-lifecycle-in-production)
6. [Config schema reference](#6-config-schema-reference)
7. [Service composition](#7-service-composition)
8. [Logging](#8-logging)
9. [Resource limits](#9-resource-limits)
10. [Cross-references](#10-cross-references)

---

## 1. Profiles and sizing

Resource footprint is dominated by the live connection table,
per-connection send queues, and the plugin set. The kernel itself
is small: a stripped Release binary under 4 MiB, resident memory at
idle on the order of tens of MiB. Memory and CPU growth is bounded
by the limits the operator picks; defaults target a public-internet
server.

Three sizing classes cover most deployments. Figures below are
order-of-magnitude on an i5-1235U class CPU; benchmark the actual
plugin mix on target hardware before pinning capacity-planning
ceilings.

| Class | Plugins | Conns | RAM (steady) | CPU (steady) |
|---|---|---|---|---|
| Embedded | 1-2 transports + heartbeat | up to 64 | 30-60 MiB | under 5% of one core |
| Desktop  | tcp + ipc + security-noise | up to 512 | 80-150 MiB | 5-10% of one core |
| Server   | full transport + security set | up to 4096 | 200-500 MiB | scales linearly with conn count |

Throughput on the reference i5-1235U CPU, loopback, 16 KiB
payloads:

- Single TCP+Noise connection — 7 Gbps burst (1000-frame run,
  bench warmup before TCP write-buffer saturates), 6 Gbps
  sustained (5000-frame run with sender feedback loop). Inline
  ChaCha20-Poly1305 sets the ceiling; libsodium's
  `chacha20_encrypt_bytes` accounts for ~42% of cycles per
  `perf record`, `poly1305_blocks` ~30%.
- 4 connections, sustained (5000-frame each, four producer
  threads) — 19-21 Gbps aggregate; multi-conn beats the single-
  conn ceiling because the kernel's per-conn drain CAS lets four
  encrypt batches run on independent strands.

Real workloads underperform these numbers — physical NICs add
syscall overhead and serialisation, multi-tenant CPUs lose cache,
and application-side message processing eats into the budget.
Measure on target hardware before committing to capacity planning.

Aggregate throughput scales with connection count until the
io_context worker saturates or the per-conn send-queue ceiling
(`pending_queue_bytes_hard`, 4 MiB default) trips backpressure.

The `embedded` profile inherits a tighter baseline: 64 conns, 8 KiB
max frame, 256 timers, narrowed inject-rate limiter. The `desktop`
profile splits the difference at 512 conns. Switching profiles is
one line in `/etc/goodnet/node.json`; every unset `limits.*` field
re-derives from the new baseline.

---

## 2. Layout on disk

A production install plants files in five locations.

| Path | Owner | Mode | What |
|---|---|---|---|
| `/usr/bin/goodnet` | root | 0755 | Multicall binary — `run`, `config validate`, `plugin hash`, `manifest gen`, `identity gen`, `identity show`, `version` |
| `/usr/lib/goodnet/lib*.so` | root | 0644 | Plugin shared objects: transports, security providers, protocol layers, handlers |
| `/etc/goodnet/node.json` | root | 0644 | Kernel config (limits, log shape, profile selector) |
| `/etc/goodnet/plugins.json` | root | 0644 | Plugin manifest — `{ path, sha256 }` per loadable .so. Trust root for `dlopen` |
| `/etc/goodnet/identity.bin` | goodnet:goodnet | 0600 | Persistent node identity (77-byte magic-prefixed Ed25519 + Curve25519 layout per [identity](../contracts/identity.en.md) §4) |
| `/etc/goodnet/peers.json` | root | 0644 | Optional peer catalogue (multi-node deployments, §4) |
| `/var/lib/goodnet/` | goodnet:goodnet | 0750 | State directory; per-plugin subdirs materialise on first write |

Three principles: `/etc` holds operator intent (config + integrity
roots) and stays read-only at runtime; `/var/lib/goodnet/` is the
only path the daemon writes; the identity file stays `0600` and
group-owned by the `goodnet` system user. Back it up as root —
never widen the mode.

`goodnet:goodnet` has no login shell and no home directory. Plugins
needing persistent state create their own subdirectory under
`/var/lib/goodnet/<plugin-name>/` on first write; operators do not
pre-create them.

Logs flow through journald, not any path above. See §8.

---

## 3. systemd unit reference

The shipped unit `dist/systemd/goodnet.service` applies a
defence-in-depth sandbox. Each flag restricts a specific kernel
surface; together they reduce the blast radius of a hypothetical
plugin RCE to roughly "read the plugin's state directory and emit
network traffic". Exhaustive matrix:

| Flag | Effect | Why on |
|---|---|---|
| `User=goodnet` | Runs as unprivileged system user | The kernel does not need root or capabilities |
| `Group=goodnet` | Same group | Tied to `User=` for consistency |
| `NoNewPrivileges=yes` | Blocks setuid / setgid / file capability transitions | A loaded plugin cannot escalate via a setuid helper |
| `ProtectSystem=strict` | `/usr`, `/boot`, `/efi` mount read-only | A compromised kernel cannot rewrite its own binary or other system files |
| `ProtectHome=yes` | `/home`, `/root`, `/run/user` invisible | The kernel has no business in user homedirs |
| `PrivateTmp=yes` | Per-unit `/tmp` namespace | Isolates from cross-tenant `/tmp` predictability attacks |
| `PrivateDevices=yes` | Hides `/dev` except `/dev/null`, `/dev/zero`, `/dev/random`, `/dev/urandom`, `/dev/tty` | The kernel uses no raw devices |
| `ProtectKernelModules=yes` | Blocks `init_module` / `delete_module` | A loaded plugin cannot insert kernel modules |
| `ProtectKernelTunables=yes` | `/proc/sys`, `/sys` read-only | Cannot retune sysctls from a plugin |
| `ProtectControlGroups=yes` | `/sys/fs/cgroup` read-only | Cannot escape its own cgroup |
| `RestrictNamespaces=yes` | Blocks unshare / setns | Cannot create a private namespace to hide work |
| `RestrictRealtime=yes` | Blocks SCHED_FIFO / SCHED_RR | Cannot starve the rest of the host |
| `LockPersonality=yes` | Pins ABI personality at fork | Prevents `personality()` syscall games |
| `MemoryDenyWriteExecute=yes` | No W^X mapping transitions | Blocks classic shellcode injection — the kernel uses `dlopen` once, never `mmap+execute` |

The unit also pins three lifecycle behaviours:

- `KillSignal=SIGTERM` plus `TimeoutStopSec=30` — the kernel polls
  `is_shutdown_requested` from inside async callbacks (per
  [host-api](../contracts/host-api.en.md) §10) and unwinds plugins
  cleanly within the 30-second window.
- `Restart=no` — a node failure is a configuration or plugin error
  surfaced loudly. Operators wanting auto-restart drop in
  `Restart=on-failure` plus `RestartSec=5s` via a unit override.
- `ExecStartPre=/usr/bin/goodnet config validate` — catches malformed
  config at unit-start time rather than mid-handshake.

Two situations call for an override: a JIT plugin (future scripting,
embedded WASM runtime) needs `MemoryDenyWriteExecute=` cleared; a
host where journald is not the log sink needs `StandardOutput=` /
`StandardError=` overridden. Both go in
`/etc/systemd/system/goodnet.service.d/override.conf` so package
upgrades do not stomp on local edits.

---

## 4. Multi-node mesh setup

Mesh setup is three steps: generate an identity per node, exchange
addresses out-of-band, seed each node's `peers.json` with the seed
peers it should dial.

### 4.1 Identity generation

Each node owns its identity. Generate it on the host that will run
the node — secret seeds never leave the box.

```sh
sudo -u goodnet goodnet identity gen \
    --out /etc/goodnet/identity.bin
```

The file lands at mode `0600`. The command prints the public surface
to stdout:

```
goodnet identity gen: wrote /etc/goodnet/identity.bin (mode 0600)
address:    7f3c...d219    (52-character base32 in operator UI; hex shown here)
user_pk:    ...
device_pk:  ...
```

The `address` field is the 32-byte public identifier other nodes
use to reference this one. Save it; it is the value to paste into
peers' catalogues.

To inspect an existing identity without rewriting it:

```sh
sudo -u goodnet goodnet identity show /etc/goodnet/identity.bin
```

Secret seeds are never printed, even when the file is readable.

### 4.2 peers.json schema

`peers.json` lives at `/etc/goodnet/peers.json` and follows this
shape:

```json
{
  "peers": [
    {
      "pk":   "QFK4...XYZ7",
      "name": "alice-laptop",
      "uris": ["tcp://192.168.1.5:9001", "ice://"]
    },
    {
      "pk":   "PT2M...A0K1",
      "name": "bob-server",
      "uris": ["tcp://10.0.0.50:9001"]
    }
  ]
}
```

Field semantics:

- `pk` — the peer's address from `goodnet identity show`. 52
  characters base32 in the operator-facing form; the kernel
  accepts both base32 and hex.
- `name` — operator-facing label for logs and dashboards. Not
  part of cryptographic identity.
- `uris` — ordered list. The kernel walks them in order on dial,
  using the first reachable URI. See [uri](../contracts/uri.en.md)
  for the full URI scheme registry; transports register their own
  schemes (`tcp://`, `udp://`, `ipc://`, `tls://`, etc.).

The catalogue is edited by hand — no auto-discovery in v1 by
design; operators keep full control over which peers their node
considers known.

### 4.3 Bootstrapping a mesh

The simplest N-node topology is "every node knows the seed":

1. Pick one node as the seed (most reliably-reachable: public-IP
   server, well-known LAN address).
2. On the seed, run `identity gen` and record address + URI.
3. On every other node, write a `peers.json` with one entry: the
   seed's address and URI.
4. Distribute each non-seed node's address back to the seed's
   `peers.json` (or rely on the kernel's reverse-dial-on-incoming
   behaviour).

For larger meshes, generate each node's `peers.json` from a single
source of truth via Ansible / salt / a config repo. The format is
small enough that templating works cleanly.

NAT traversal between nodes unable to dial each other directly
lands with the relay / DHT plugins; in v1, a NAT'd peer reaches
out to a publicly-routable peer first (which caches the address)
or ships through a well-known relay. See the project ROADMAP.

---

## 5. Plugin lifecycle in production

`/etc/goodnet/plugins.json` is the trust root for `dlopen`.
PluginManager refuses any path absent from the manifest with
`GN_ERR_INTEGRITY_FAILED` — even when the path is correct and the
file exists. The manifest is a security boundary, not a convenience
cache.

### 5.1 Manifest generation

After installing or upgrading plugin .so files, regenerate the
manifest:

```sh
sudo goodnet manifest gen /usr/lib/goodnet/lib*.so > /tmp/plugins.json
sudo install -m 0644 /tmp/plugins.json /etc/goodnet/plugins.json
```

`manifest gen` emits one `{ path, sha256 }` record per input file
using the same hash primitive the kernel uses at load time, so the
output verifies cleanly against the bytes the kernel reads. Any
failure (missing file, unreadable bytes) prints to stderr and exits
non-zero with no manifest written — the previous file is left
intact.

Full schema in
[plugin-manifest](../contracts/plugin-manifest.en.md). Operators do
not write manifests by hand; `manifest gen` is the supported path.

### 5.2 Hash verification

To verify a single plugin's hash without regenerating the manifest:

```sh
goodnet plugin hash /usr/lib/goodnet/libgoodnet_security_noise.so
```

Output is lowercase hex SHA-256, comparable directly against a
manifest entry or upstream release announcement.

### 5.3 When to re-run

Re-run `manifest gen` whenever any plugin .so on the path list
changes: after `apt upgrade` / package upgrade touching
`/usr/lib/goodnet/`, after a fresh `nix run .#build -- release` + `install`,
and after replacing a single plugin for debugging or A/B testing.
Even a one-byte change shifts the digest.

The unit's `ExecStartPre=` does **not** call `manifest gen`.
Auto-regenerate on startup defeats the integrity-gate purpose. An
operator who upgrades a plugin and forgets to regenerate gets
`GN_ERR_INTEGRITY_FAILED` and a clean unit-start failure — the
intended outcome.

### 5.4 Adding a plugin

To add a new plugin to a running deployment:

1. Stop the unit: `sudo systemctl stop goodnet`.
2. Install the new .so: `sudo install -m 0644 new-plugin.so /usr/lib/goodnet/`.
3. Regenerate the manifest as in §5.1 above.
4. Validate the resulting config: `sudo goodnet config validate
   /etc/goodnet/node.json`.
5. Start the unit: `sudo systemctl start goodnet`.

No hot-load path in v1: plugins join the kernel through
`PluginManager::load` once at startup. Subsequent additions
require a restart.

---

## 6. Config schema reference

Full schema: [config](../contracts/config.en.md) §3, limits in
[limits](../contracts/limits.en.md) §2. Operator-facing summary
follows.

### 6.1 Required keys

A minimum-viable `node.json` is `{}` — every key has a default.
Identity and plugin directory paths come in through CLI flags
(`--identity`, `--manifest`); the config stays declarative.

### 6.2 Common keys

| Key | Type | Default | Purpose |
|---|---|---|---|
| `version` | int | 1 | Conventional schema version marker; v1 ignores it but operators set `1` so a future v2 binary detects the legacy shape |
| `profile` | string | `server` | Baseline limits set: `server` / `desktop` / `embedded`; unknown values fall back to `server` |
| `log.level` | string | `info` | Overall log floor: `trace` / `debug` / `info` / `warn` / `error` / `critical` / `off` |
| `log.console_level` | string | build-aware | Per-sink override for the colored stdout sink; set to `info` on Release for visible startup markers |
| `log.file` | string | empty | Path to a rotating-file sink; empty disables file logging |
| `log.format` | string | console | `console` (human, colored) or `json` (one record per line) |

### 6.3 Per-plugin namespaces

Plugins read their own knobs through dotted paths under their
namespace:

| Namespace | Owner | Example keys |
|---|---|---|
| `links.tcp.*` | TCP transport plugin | `listen_uri` |
| `links.tls.*` | TLS transport plugin | `cert_path`, `key_path` |
| `links.ipc.*` | IPC transport plugin | `socket_path` |
| `heartbeat.*` | Heartbeat handler | `interval_ms`, `timeout_ms` |
| `relay.*` | Relay plugin (post-v1) | `dedup_capacity` |
| `dht.*` | DHT plugin (post-v1) | bucket parameters |

The kernel does not parse plugin namespaces; it returns values
verbatim through `config_get`. Each plugin documents its keys in
its own README. A typo silently maps to `GN_ERR_NOT_FOUND` and the
plugin falls through to its default; v1 does not warn on unknown
keys (lands in v1.1 with a `reads_config` whitelist).

### 6.4 Hot reload

v1 ships a one-shot config load. `systemctl reload goodnet`
executes `Config::reload_config(text)` and re-derives limits (per
[config](../contracts/config.en.md) §3a).

Picked up by reload:

- `log.level`, `log.console_level`, `log.file`, `log.format` —
  spdlog re-routes before the next line.
- `limits.*` fields whose change does not require new at-startup
  allocation (most fields).
- Plugin-namespace values — plugins subscribed through
  `host_api->subscribe(GN_SUBSCRIBE_CONFIG_RELOAD, …)` re-read on
  signal fire.

Requires full restart:

- `max_connections`, `max_plugins`, `max_extensions`, `max_timers` —
  dimension registry tables at construction.
- Identity rotation (new `--identity` path).
- Adding or removing a plugin (see §5.4).

When in doubt, `systemctl restart goodnet`. The 30-second
TimeoutStopSec drains in-flight async cleanly; downtime is seconds,
not minutes.

---

## 7. Service composition

A typical deployment runs the kernel daemon plus additional
service-side apps as co-resident units. Pattern: "one unit per
process, ordered by After= chains".

### 7.1 Kernel unit

`goodnet.service` (§3) is the foundation. Dependent units bind to
it through ordering directives.

### 7.2 gssh listen

For SSH-over-GoodNet, `gssh --listen` runs as its own unit. It
does not depend on the kernel — it loads its own kernel + plugins
in-process — but typically runs on the same host as a kernel unit.

```ini
# /etc/systemd/system/gssh.service
[Unit]
Description=GoodNet SSH listen forwarder
After=network-online.target

[Service]
ExecStart=/usr/bin/gssh --listen
Environment=HOME=/var/lib/gssh
Restart=on-failure
RestartSec=5s
User=gssh
Group=gssh

[Install]
WantedBy=multi-user.target
```

See [gssh](./gssh.ru.md) for the full mode reference. gssh runs as
its own user (`gssh:gssh`) with its own state directory
(`/var/lib/gssh/`); it does not share identity material with the
kernel daemon.

### 7.3 Custom apps

Custom apps linked against the SDK or C++ bridges run under their
own units. Standard pattern:

```ini
[Unit]
Description=Custom GoodNet app
After=network-online.target goodnet.service
Requires=goodnet.service

[Service]
ExecStart=/usr/local/bin/my-app --config /etc/my-app/config.json
User=my-app-user
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

`After=goodnet.service` orders start; `Requires=` propagates
stops. Apps talking to the kernel through IPC (e.g., goodnet-panel)
need `Requires=`; apps running their own kernel in-process do not.

Hardening flags from §3 are good defaults to copy; drop them
per-flag in a unit override when an app needs an exception.

---

## 8. Logging

Logs flow through journald. The kernel writes to stderr; the unit
ties stderr to the journal; operators read via `journalctl`.

### 8.1 Live tail

```sh
journalctl -u goodnet -f
```

Filters work as expected:

```sh
journalctl -u goodnet --since "1 hour ago"
journalctl -u goodnet -p warning            # WARN+
journalctl -u goodnet | grep "plugin"
```

### 8.2 Log levels

spdlog respects six levels: `trace`, `debug`, `info`, `warn`,
`error`, `critical`. Release default pins WARN on the console sink;
INFO and below filter out. Production deployments typically want
INFO visible for kernel startup and plugin-load markers. Set both:

```json
"log": {
  "level":         "info",
  "console_level": "info"
}
```

`level` is the overall logger floor; `console_level` is the
console-sink override. The split lets DEBUG route to a file sink
while the journal stays at INFO.

### 8.3 Format

v1 ships `console` (human, optionally colored) and `json` (one
record per line). JSON is the format for Loki / Elasticsearch /
any aggregator consuming structured events. Console is the default
for journald — `journalctl` renders timestamps itself.

```json
"log": {
  "format": "json",
  "file":   "/var/log/goodnet/kernel.jsonl"
}
```

`log.file` enables a rotating-file sink alongside the console;
`log.max_size` and `log.max_files` control rotation (10 MiB / 5
files default). Journal-only deployments leave `log.file` empty.

### 8.4 Rotation

journald rotates on its own; cap journal size globally with
`SystemMaxUse=` in `/etc/systemd/journald.conf`. The file sink
uses spdlog's built-in rotation per `log.max_size` /
`log.max_files`. No logrotate integration ships — file sink is
self-rotating, journal is journald's job.

---

## 9. Resource limits

Limits live in two places: systemd unit ceilings that bound the
process from outside, and the `gn_limits_t` struct that bounds
internal kernel operations. Tune both for production.

### 9.1 systemd ceilings

The shipped unit does not pin specific ceilings; relevant knobs:

| Knob | Default | Rationale |
|---|---|---|
| `LimitNOFILE=` | inherits | File descriptors. Set to `max_connections * 2 + 256` as a baseline; one fd per conn plus headroom for listeners and timers |
| `MemoryMax=` | unlimited | Hard memory cap. Set to twice the steady-state RAM figure from §1 to give the kernel headroom under burst load |
| `MemoryHigh=` | unlimited | Soft memory cap; kernel slows allocations under pressure rather than killing the process |
| `TasksMax=` | inherits | Thread count cap. The kernel runs one service-executor thread plus a per-link plugin worker pool — TCP scales to `max(1, hardware_concurrency()/2)` workers, UDP / WS / IPC / TLS each pin one. On a 16-core box that adds up to ~9 link threads plus the service executor; 256 covers any v1 deployment with headroom |
| `CPUQuota=` | unlimited | CPU cap as a percentage. Set to `<percent>%` on shared hosts where the kernel must not starve neighbours |

A typical override file pinning these:

```ini
# /etc/systemd/system/goodnet.service.d/limits.conf
[Service]
LimitNOFILE=8192
MemoryMax=2G
MemoryHigh=1G
TasksMax=256
```

### 9.2 gn_limits_t — internal bounds

The kernel reads `gn_limits_t` from `/etc/goodnet/node.json` at
startup. Every limit-violation path records a metric drop reason
(per [limits](../contracts/limits.en.md) §5); an operator seeing
refused connections or dropped messages reads the breakdown and
tunes the relevant field. Common production overrides:

| Field | When to bump | When to lower |
|---|---|---|
| `max_connections` | Public-internet server with many simultaneous peers | Embedded / single-tenant deployments |
| `pending_queue_bytes_hard` | High-throughput peers, large message bursts | Memory-constrained hosts where 4 MiB per conn is too much |
| `max_payload_bytes` | App-layer protocol with large messages (file sync) | Tight wire-frame budgets on lossy links |
| `max_relay_ttl` | Multi-hop topology where relay-of-relay is intentional | Single-hop deployments — keep low to defend against amplification |
| `max_timers` | Plugin set with many active timers (heartbeat fan-out) | Embedded — the default 4096 is overkill for a 64-conn node |
| `inject_rate_per_source` | Bridge plugin volumes bursting under legitimate load | Hostile environments — tighter caps here harden against amplification |

### 9.3 Per-plugin quotas

Two `gn_limits_t` fields govern per-plugin behaviour:

- `max_timers_per_plugin` — sub-quota of `max_timers`. Default 0
  (no sub-quota; only the global ceiling applies). With multiple
  plugins, set this to at most `max_timers / max_plugins` so a
  single misbehaving plugin cannot starve siblings.
- `max_handlers_per_msg_id` — dispatch chain length per message
  ID. Default 8. Combined with `max_relay_ttl`, caps amplification
  on relay paths.

No per-plugin memory or CPU cap in v1. A plugin's footprint is
transitively bounded by the kernel limits above; tighter per-plugin
sandboxing is v1.1+.

---

## 10. Cross-references

- [install](../install.en.md) — single-node bring-up walkthrough
- [config](../contracts/config.en.md) — full kernel config schema
- [limits](../contracts/limits.en.md) — `gn_limits_t` field semantics
- [identity](../contracts/identity.en.md) — node identity layout and lifecycle
- [plugin-manifest](../contracts/plugin-manifest.en.md) — manifest schema and integrity gate
- [host-api](../contracts/host-api.en.md) — kernel/plugin API surface and shutdown semantics
- [uri](../contracts/uri.en.md) — URI scheme registry for `peers.json` entries
- [link](../contracts/link.en.md) — transport plugin contract
- [security-trust](../contracts/security-trust.en.md) — trust class policy for limit application
- [metrics](../contracts/metrics.en.md) — drop-reason metrics surface and cardinality cap
- [gssh](./gssh.ru.md) — SSH-over-GoodNet sibling guide (modes, peers.json, listen unit)
