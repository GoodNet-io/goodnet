# GoodNet Documentation

This is the entry point. The rest of the directory grows alongside
the code; below is the map of where to look depending on what you
came for.

---

## Where to start

Brand-new — read the project [README](../README.md) at the repository
root. It states what GoodNet is, what the kernel knows, and what it
delegates to plugins.

Building from source — see the **Build** section of the root README.
The short version is `nix develop` and `cfg && b`.

Writing a plugin — start with the contracts in `contracts/`. The
plugin author's reading order is:

1. [`contracts/protocol-layer.md`](contracts/protocol-layer.md) —
   the envelope every plugin produces or consumes.
2. [`contracts/host-api.md`](contracts/host-api.md) — what the
   kernel offers in return.
3. [`contracts/plugin-lifetime.md`](contracts/plugin-lifetime.md) —
   when the kernel calls each entry point and what each phase may
   safely do.
4. The contract for the role you are filling: `link.md`,
   `handler-registration.md`, `noise-handshake.md`, etc.

---

## Directory layout

```
docs/
├── README.md             — this file
├── contracts/            — formal specifications: invariants, C ABI,
│                           wire layouts, sequencing rules
├── ROADMAP.md            — what is shipped and what is planned (TBD)
├── architecture/         — prose deep-dives: FSM, routing, multi-path,
│                           NAT pipeline, relay topology  (TBD)
├── protocol/             — wire-format walkthroughs and on-wire
│                           reference traces (TBD)
├── recipes/              — task-oriented guides: run a two-node mesh,
│                           write a transport, port a handler  (TBD)
├── impl/                 — language-specific implementation guides
│   ├── cpp/              — idiomatic patterns for C++ plugin authors
│   ├── rust/             — Rust authors
│   ├── python/           — Python authors
│   └── ...
└── Doxyfile              — API-reference generation (TBD)
```

The `(TBD)` directories appear as their content lands. Pre-RC, only
`contracts/` has substantive content; the rest is the announced plan.

---

## How the layers compose

```
recipes/         — "I want to do X — show me the steps"
   ↑
architecture/    — "how do the pieces fit together"
   ↑
contracts/       — "what is the exact rule between piece A and piece B"
   ↑
sdk/             — "what types and function pointers does the rule produce"
   ↑
core/, plugins/  — "how is the rule implemented for v1"
```

A reader who only wants to start a node stops at `recipes/`. An
operator debugging a production deployment stops at `architecture/`.
A plugin author writing in a new language reads `contracts/` plus
`impl/<their-language>/`. The contracts are the durable artefact;
the rest of the layers cite back to them.

---

## Stability

The contracts in `contracts/` are the system's source of truth for
v1.x. They change only in lockstep with the SDK ABI bump rules
spelled out in [`contracts/abi-evolution.md`](contracts/abi-evolution.md).
Other directories (architecture, recipes, impl) evolve more freely
as the surrounding ecosystem grows.

Per-document stability is declared in the document's header. Look
for the `Stability:` line.
