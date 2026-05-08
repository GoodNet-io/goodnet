# Licensing — compatibility matrix and per-component decisions

The kernel sits at GPL-2.0 with a Linking Exception. The strategic
baseline plugins follow the same licence so the parts of the platform
that define competitive ground stay in the community. Periphery
plugins (templates, debug providers, host-OS-tied transports) ship
permissive (MIT) so the bundled tree stays useful as scaffold for new
plugin authors. The OpenSSL-tied TLS transport keeps Apache-2.0
because GPL-2 cannot statically link Apache-2.0 without an additional
licence-exception clause and the rest of OpenSSL 3.x is Apache-2.0
itself.

## Components

| Path | Licence | Bucket | Why |
|---|---|---|---|
| `core/` | GPL-2.0 + Linking Exception | kernel | strong copyleft on the kernel; plugin boundary released by the exception |
| `sdk/` | MIT | SDK | header-only ABI; permissive so any plugin author can link without licence drag |
| `plugins/protocols/gnet/` | GPL-2.0 + Linking Exception | strategic | mandatory mesh framing; structurally part of the kernel binary |
| `plugins/links/tcp/` | GPL-2.0 + Linking Exception | strategic | fundamental transport — free in the strong sense |
| `plugins/links/udp/` | GPL-2.0 + Linking Exception | strategic | fundamental transport |
| `plugins/links/ws/` | GPL-2.0 + Linking Exception | strategic | web-access bet; permissive licensing here would let a SaaS lift the WS gateway and never contribute back |
| `plugins/security/noise/` | GPL-2.0 + Linking Exception | strategic | crypto layer; strong copyleft mirrors GnuTLS's stance |
| `plugins/handlers/heartbeat/` | GPL-2.0 + Linking Exception | strategic | canonical reference handler — every new handler reads its source |
| `plugins/links/ipc/` | MIT | periphery | local AF_UNIX socket transport |
| `plugins/security/null/` | MIT | periphery | loopback / IntraNode-only debug provider |
| `plugins/protocols/raw/` | MIT | periphery | opaque-payload template for foreign-protocol bridges |
| `plugins/links/tls/` | Apache-2.0 | OpenSSL-tied | aligns with OpenSSL 3.x's Apache-2.0; GPL-2 link with OpenSSL would need an extra exception clause |
| `manifesto/` | CC-BY-SA-4.0 | text | book / publication artefact, not source |

## Compatibility matrix

Read this table top-down: the row is the project's licence, the
column is the dependency licence. `yes` means the row's licence
can incorporate or link the column's licence statically; `no¹`
points at the footnote explaining the exception.

| Project ↓ / Dep → | GPL-2.0 + LE | MIT | BSD-2/3 | Boost 1.0 | ISC | Apache-2.0 | LGPL-2.1 | OpenSSL 3.x |
|---|---|---|---|---|---|---|---|---|
| **GPL-2.0** | yes | yes | yes | yes | yes | no¹ | yes (link) | no¹ |
| **MIT** | yes | yes | yes | yes | yes | yes | yes | yes |
| **Apache-2.0** | yes² | yes | yes | yes | yes | yes | yes (link) | yes |

Notes:

1. Apache-2.0 carries a patent-retaliation clause that GPL-2.0
   considers an additional restriction. GPL-2 cannot statically link
   Apache-2.0 without an explicit Linking Exception that names the
   Apache-licensed dependency. OpenSSL 3.x is Apache-2.0, so a
   GPL-2-licensed TLS plugin would have to add an OpenSSL exception
   clause; we sidestep by keeping the TLS plugin Apache-2.0.
2. Apache-2.0 can incorporate GPL-2 only when the GPL-2 component
   carries an exception clause that releases the boundary the
   Apache-2.0 caller depends on. The Linking Exception in `core/
   LICENSE` is exactly such a clause for the SDK boundary.

## Upstream dependency audit

| Library | Used by | Upstream licence | Bucket compat |
|---|---|---|---|
| libsodium | `plugins/security/noise/` | ISC | compatible everywhere |
| spdlog | `core/` | MIT | compatible everywhere |
| fmt | `core/` | MIT | compatible everywhere |
| nlohmann/json | `core/config/` | MIT | compatible everywhere |
| asio (standalone) | `core/`, link plugins | Boost 1.0 | compatible everywhere |
| OpenSSL 3.x | `plugins/links/tls/` | Apache-2.0 | incompatible on GPL-2 link — TLS plugin stays Apache-2.0 |
| GoogleTest | `tests/` | BSD-3 | compatible everywhere (test-only) |
| RapidCheck | `tests/` | BSD-2 | compatible everywhere (test-only) |

## Decision rules

When a new plugin lands, classify it before the first commit:

1. **Strategic** — the plugin defines competitive ground that the
   project cannot let a fork enclose without contributing back.
   Examples: a new transport that opens a major access channel
   (QUIC, WebRTC, BLE). A new security pattern that operators rely
   on (a future Noise-IK provider, a post-quantum suite). A new
   reference handler that other implementations copy.
   → **GPL-2.0 with the Linking Exception**, copy
   `plugins/links/tcp/LICENSE` as the template.

2. **Periphery** — debug, template, host-OS-tied implementation that
   does not differentiate the platform. Examples: a Loopback
   provider, a packet-capture passthrough, a Windows-only named-pipe
   transport.
   → **MIT**, copy `plugins/security/null/LICENSE` as the template.

3. **Upstream-tied** — links a non-trivial library whose licence is
   incompatible with GPL-2 and a Linking Exception would be invasive
   to maintain (e.g. a library that itself depends on Apache-2.0 with
   patent terms).
   → match the upstream's licence (Apache-2.0 most often), copy
   `plugins/links/tls/LICENSE` as the template.

The Linking Exception means out-of-tree plugins choose freely
regardless of bucket — including proprietary. The bucket convention
shapes only what ships in `GoodNet-io/goodnet`.

## Spinoff licensing

When a plugin is lifted to its own `GoodNet-io/<plugin>` repository
(see `dist/migrate/spinoff-cookbook.md`), its `LICENSE` travels with
the tree. Strategic plugins promoted post-rc1 carry the GPL-2 +
Linking Exception text in full at the spinoff repo's root; the
in-tree thin pointer at `plugins/<kind>/<name>/LICENSE` references
the canonical kernel `core/LICENSE` while the plugin lives in the
monorepo.
