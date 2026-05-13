#!/usr/bin/env python3
"""Generate GoodNet architecture diagrams as SVG. Output: docs/img/*.svg

Requires: graphviz system package (in flake.nix), pip graphviz.
"""

from pathlib import Path
import graphviz
import yaml

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "img"
OUT.mkdir(parents=True, exist_ok=True)
FACTS = ROOT / "docs" / "_facts"


def load_facts(name: str) -> dict:
    """Read a livedoc fact-file. Falls back to an empty dict when
    the file is absent so first-run code paths still render — the
    caller is expected to guard slot counts with `or 0`."""
    p = FACTS / f"{name}.yaml"
    if not p.is_file():
        return {}
    return yaml.safe_load(p.read_text()) or {}

# ── Palette (Catppuccin Mocha) ───────────────────────────────────────────────

BG        = "#1e1e2e"  # surface
FG        = "#cdd6f4"  # text
BORDER    = "#585b70"  # overlay0
BLUE      = "#89b4fa"  # blue
LAVENDER  = "#b4befe"  # lavender
GREEN     = "#a6e3a1"  # green
PEACH     = "#fab387"  # peach
RED       = "#f38ba8"  # red
MAUVE     = "#cba6f7"  # mauve
TEAL      = "#94e2d5"  # teal
YELLOW    = "#f9e2af"  # yellow
SURFACE1  = "#45475a"  # surface1
SURFACE2  = "#585b70"  # surface2


def base_attrs():
    return {
        "graph_attr": {
            "bgcolor": BG,
            "fontname": "JetBrains Mono,Fira Code,monospace",
            "fontcolor": FG,
            "fontsize": "11",
            "pad": "0.4",
            "margin": "0",
            "rankdir": "TB",
        },
        "node_attr": {
            "fontname": "JetBrains Mono,Fira Code,monospace",
            "fontcolor": FG,
            "fontsize": "10",
            "style": "filled",
            "fillcolor": SURFACE1,
            "color": BORDER,
            "penwidth": "1.2",
            "shape": "box",
            "margin": "0.15,0.08",
        },
        "edge_attr": {
            "fontname": "JetBrains Mono,Fira Code,monospace",
            "fontcolor": BORDER,
            "fontsize": "9",
            "color": BORDER,
            "penwidth": "1.0",
            "arrowsize": "0.7",
        },
    }


# ═════════════════════════════════════════════════════════════════════════════
# 1. Architecture overview — kernel ABI table + 4 vtable kinds + 8 plugin gits
# ═════════════════════════════════════════════════════════════════════════════

def gen_architecture():
    g = graphviz.Digraph("architecture", format="svg", **base_attrs())
    g.attr(rankdir="TB", nodesep="0.5", ranksep="0.55", compound="true")

    # ── Kernel cluster — pure ABI surface, no orchestrator ───────────────
    with g.subgraph(name="cluster_kernel") as k:
        k.attr(
            label="Kernel  (pure ABI; no orchestrator)",
            labelloc="t",
            fontsize="13",
            fontcolor=LAVENDER,
            style="rounded,filled",
            fillcolor="#181825",
            color=LAVENDER,
            penwidth="1.5",
        )

        # host_api_t — single C ABI table handed to every plugin.
        # Slot families come from docs/_facts/host_api.yaml so this
        # label refreshes when sdk/host_api.h grows.
        facts = load_facts("host_api")
        n_slots = facts.get("named_slots") or "?"
        n_reserved = facts.get("reserved_slots") or 8
        fams = facts.get("families") or {}
        # Compact short family name (strip parenthetical doc-refs).
        family_lines = []
        for fam in sorted(fams):
            short_fam = fam.split("(")[0].strip()
            members = fams[fam]
            head = members[0] if members else ""
            tail = f" + {len(members)-1}" if len(members) > 1 else ""
            family_lines.append(f"  · {short_fam}: {head}{tail}")
        body = (
            f"host_api_t  (C ABI)\n"
            f"{n_slots} named slots + {n_reserved} reserved\n"
            + "\n".join(family_lines)
        ) if fams else (
            "host_api_t  (C ABI)\n"
            "run tools/livedoc.py to populate"
        )
        k.node("host_api", body,
               fillcolor=SURFACE1, color=BLUE, fontcolor=BLUE,
               shape="box", fontsize="9")

        # 4 registry kinds — handler / link / security / extension
        with k.subgraph() as row:
            row.attr(rank="same")
            row.node("reg_handler",  "HandlerRegistry\nGN_REGISTER_HANDLER",
                     fillcolor=SURFACE1, color=GREEN, fontcolor=GREEN, fontsize="9")
            row.node("reg_link",     "LinkRegistry\nGN_REGISTER_LINK",
                     fillcolor=SURFACE1, color=GREEN, fontcolor=GREEN, fontsize="9")
            row.node("reg_security", "SecurityRegistry\nregister_security",
                     fillcolor=SURFACE1, color=GREEN, fontcolor=GREEN, fontsize="9")
            row.node("reg_extension","ExtensionRegistry\nregister_extension",
                     fillcolor=SURFACE1, color=GREEN, fontcolor=GREEN, fontsize="9")

        # Connection registry + executor + signal channel
        with k.subgraph() as row:
            row.attr(rank="same")
            row.node("conn_reg", "ConnectionRegistry\n3 keys / 16 shards",
                     fillcolor=SURFACE1, color=TEAL, fontcolor=TEAL, fontsize="9")
            row.node("executor", "ServiceExecutor\nset_timer / posted tasks",
                     fillcolor=SURFACE1, color=TEAL, fontcolor=TEAL, fontsize="9")
            row.node("signal_bus","SignalChannel\nconn_state / config_reload",
                     fillcolor=SURFACE1, color=TEAL, fontcolor=TEAL,
                     shape="parallelogram", fontsize="9")

        # link host_api to its registries / subsystems
        for n in ("reg_handler", "reg_link", "reg_security",
                  "reg_extension", "conn_reg", "executor", "signal_bus"):
            k.edge("host_api", n, color=BORDER, arrowhead="none",
                   style="dashed")

    # ── 8 loadable plugin gits around the kernel ─────────────────────────
    plugins = [
        ("p_heartbeat", "handler-heartbeat",      PEACH),
        ("p_tcp",       "link-tcp",               PEACH),
        ("p_udp",       "link-udp",               PEACH),
        ("p_ws",        "link-ws",                PEACH),
        ("p_ipc",       "link-ipc",               PEACH),
        ("p_tls",       "link-tls",               PEACH),
        ("p_noise",     "security-noise",         PEACH),
        ("p_null",      "security-null",          PEACH),
    ]
    for nid, label, clr in plugins:
        g.node(nid, f"{label}\n.so  ·  own .git",
               fillcolor=BG, color=clr, fontcolor=clr,
               shape="component", fontsize="9")

    # Plugins talk to the kernel exclusively through host_api
    for nid, _, _ in plugins:
        g.edge(nid, "host_api", color=PEACH,
               dir="both", arrowhead="vee", arrowtail="vee", style="solid",
               fontcolor=PEACH)

    # ── Plugin↔plugin coordination via ExtensionRegistry ─────────────────
    g.node("ext_note",
           "plugin↔plugin coordination\n"
           "register_extension(name, version, vtable)\n"
           "query_extension_checked(name, version)",
           shape="note", color=MAUVE, fontcolor=MAUVE,
           style="filled", fillcolor="#181825", fontsize="9")
    g.edge("p_heartbeat", "ext_note", color=MAUVE, style="dashed",
           arrowhead="none")
    g.edge("ext_note", "reg_extension", color=MAUVE, style="dashed",
           arrowhead="vee")

    g.render(str(OUT / "architecture"), cleanup=True)


# ═════════════════════════════════════════════════════════════════════════════
# 2. Kernel FSM — 8 phases per docs/contracts/fsm-events.md §2
# ═════════════════════════════════════════════════════════════════════════════

def gen_kernel_fsm():
    g = graphviz.Digraph("kernel_fsm", format="svg", **base_attrs())
    g.attr(rankdir="LR", nodesep="0.3", ranksep="0.4")

    phases = [
        ("Load",        "shared objects mapped\nversion-checked"),
        ("Wire",        "host vtable populated\nhost_ctx allocated"),
        ("Resolve",     "service-graph toposort\nover plugin descriptors"),
        ("Ready",       "every plugin past init_all\nregistry tables empty but live"),
        ("Running",     "every plugin past register_all\ndispatch open"),
        ("PreShutdown", "new connections refused\nin-flight dispatches drained"),
        ("Shutdown",    "transports disconnected\nhandlers torn down"),
        ("Unload",      "shared objects unmapped\nhost vtable invalidated"),
    ]

    colors = [BLUE, BLUE, LAVENDER, GREEN, GREEN, YELLOW, PEACH, RED]

    for (name, desc), clr in zip(phases, colors):
        shape = "doubleoctagon" if name == "Running" else "box"
        g.node(name, f"{name}\n{desc}",
               color=clr, fontcolor=clr, shape=shape,
               style="filled,rounded", fillcolor=SURFACE1, fontsize="9")

    for i in range(len(phases) - 1):
        g.edge(phases[i][0], phases[i + 1][0], color=BORDER)

    # Контракт: linear, backward transitions запрещены; idempotent CAS
    g.node("rule",
           "Phases linear · backward forbidden\n"
           "Idempotent transitions: compare_exchange\n"
           "Commit-then-notify: state written first, event fires second",
           shape="note", color=SURFACE2, fontcolor=BORDER,
           style="filled", fillcolor="#181825", fontsize="9")
    g.edge("Unload", "rule", style="invis")

    g.render(str(OUT / "kernel_fsm"), cleanup=True)


# ═════════════════════════════════════════════════════════════════════════════
# 3. Connection FSM — per docs/contracts/conn-events.md, registry.md
# ═════════════════════════════════════════════════════════════════════════════

def gen_connection_fsm():
    g = graphviz.Digraph("conn_fsm", format="svg", **base_attrs())
    g.attr(rankdir="LR", nodesep="0.4", ranksep="0.5")

    # States observed by the kernel from notify_connect through notify_disconnect
    states = {
        "NotifyConnect":   (BLUE,     "box"),
        "Handshake":       (LAVENDER, "box"),
        "Transport":       (TEAL,     "box"),
        "TrustUpgraded":   (GREEN,    "doubleoctagon"),
        "Disconnected":    (RED,      "box"),
    }

    for name, (clr, shape) in states.items():
        g.node(name, name, color=clr, fontcolor=clr, shape=shape,
               style="filled,rounded", fillcolor=SURFACE1)

    # Happy path
    g.edge("NotifyConnect", "Handshake",
           color=BORDER, label="security session\nin Handshake phase")
    g.edge("Handshake", "Transport",
           color=GREEN, fontcolor=GREEN,
           label="Noise XX complete\nkeys derived")
    g.edge("Transport", "TrustUpgraded",
           color=GREEN, fontcolor=GREEN,
           label="attestation verified\nUntrusted → Peer")
    g.edge("TrustUpgraded", "Disconnected",
           color=BORDER, label="notify_disconnect")

    # Direct close paths
    g.edge("Transport",     "Disconnected", color=BORDER, label="close")
    g.edge("NotifyConnect", "Disconnected", color=RED, style="dashed",
           label="error")
    g.edge("Handshake",     "Disconnected", color=RED, style="dashed",
           label="handshake fail")

    # Events fired
    g.node("events",
           "Events on conn_state channel:\n"
           "  CONNECTED         → on notify_connect\n"
           "  DISCONNECTED      → on notify_disconnect\n"
           "  TRUST_UPGRADED    → Untrusted → Peer\n"
           "  BACKPRESSURE_*    → soft / clear watermarks",
           shape="note", color=SURFACE2, fontcolor=BORDER,
           style="filled", fillcolor="#181825", fontsize="9")
    g.edge("Disconnected", "events", style="invis")

    g.render(str(OUT / "connection_fsm"), cleanup=True)


# ═════════════════════════════════════════════════════════════════════════════
# 4. Inbound message path — per protocol-layer.md, handler-registration.md
# ═════════════════════════════════════════════════════════════════════════════

def gen_message_path_inbound():
    g = graphviz.Digraph("msg_inbound", format="svg", **base_attrs())
    g.attr(rankdir="TB", nodesep="0.3", ranksep="0.35")

    steps = [
        ("link_rx",  "Link plugin\nnotify_inbound_bytes(conn, bytes, size)", GREEN),
        ("decrypt",  "SecuritySession.decrypt_transport\n"
                     "wire bytes → plaintext frames\n"
                     "(2-byte length prefix per frame)",                    TEAL),
        ("deframe",  "Active IProtocolLayer.deframe\n"
                     "stream → gn_message_t envelopes",                    LAVENDER),
        ("router",   "Router\nlookup (protocol_id, msg_id) → chain",        BLUE),
    ]

    for nid, label, clr in steps:
        g.node(nid, label, color=clr, fontcolor=clr,
               style="filled,rounded", fillcolor=SURFACE1, fontsize="9")

    for i in range(len(steps) - 1):
        g.edge(steps[i][0], steps[i + 1][0], color=BORDER)

    # Handler chain — priority descending
    g.node("h0", "Handler[0]\npriority 255",
           color=PEACH, fontcolor=PEACH,
           style="filled,rounded", fillcolor=SURFACE1)
    g.node("h1", "Handler[1]\npriority 128",
           color=PEACH, fontcolor=PEACH,
           style="filled,rounded", fillcolor=SURFACE1)
    g.node("hN", "Handler[N]\npriority 0",
           color=PEACH, fontcolor=PEACH,
           style="filled,rounded", fillcolor=SURFACE1)

    g.edge("router", "h0", color=BORDER)
    g.edge("h0", "h1", label="CONTINUE",
           color=BLUE, fontcolor=BLUE)
    g.edge("h1", "hN", label="CONTINUE",
           color=BLUE, fontcolor=BLUE, style="dashed")

    # Outcomes per gn_propagation_t
    g.node("consumed", "CONSUMED\nstop chain", color=YELLOW, fontcolor=YELLOW,
           shape="oval", style="filled", fillcolor=SURFACE1)
    g.node("reject",   "REJECT\ndrop & close conn",
           color=RED, fontcolor=RED,
           shape="oval", style="filled", fillcolor=SURFACE1)

    g.edge("h0", "consumed", style="dashed", color=YELLOW)
    g.edge("h0", "reject",   style="dashed", color=RED)

    # on_result fires after every handle_message
    g.node("on_result",
           "on_result(envelope, propagation)\n"
           "fires after every handle_message\n"
           "regardless of return value",
           shape="note", color=SURFACE2, fontcolor=BORDER,
           style="filled", fillcolor="#181825", fontsize="9")
    g.edge("h0", "on_result", style="dashed", color=BORDER)

    g.render(str(OUT / "message_inbound"), cleanup=True)


# ═════════════════════════════════════════════════════════════════════════════
# 5. Outbound message path — application send → wire bytes
# ═════════════════════════════════════════════════════════════════════════════

def gen_message_path_outbound():
    g = graphviz.Digraph("msg_outbound", format="svg", **base_attrs())
    g.attr(rankdir="TB", nodesep="0.3", ranksep="0.35")

    steps = [
        ("plugin",   "Plugin call\nhost_api->send(conn, msg_id, payload)", PEACH),
        ("frame",    "Active IProtocolLayer.frame\n"
                     "envelope → wire bytes",                               LAVENDER),
        ("encrypt",  "SecuritySession.encrypt_transport\n"
                     "plaintext → ciphertext + length prefix",              TEAL),
        ("queue",    "Per-conn write queue\n"
                     "bytes_buffered accounting\n"
                     "watermarks (low/high/hard)",                          BLUE),
        ("link_tx",  "Link plugin send\n"
                     "(scheme dispatch via LinkRegistry)",                  GREEN),
        ("wire",     "wire bytes",                                          RED),
    ]

    for nid, label, clr in steps:
        shape = "oval" if nid == "wire" else "box"
        g.node(nid, label, color=clr, fontcolor=clr, shape=shape,
               style="filled,rounded", fillcolor=SURFACE1, fontsize="9")

    for i in range(len(steps) - 1):
        g.edge(steps[i][0], steps[i + 1][0], color=BORDER)

    # Backpressure side-effect
    g.node("bp_note",
           "Hard cap → GN_ERR_LIMIT_REACHED\n"
           "Soft watermark → BACKPRESSURE_SOFT event\n"
           "Clear watermark → BACKPRESSURE_CLEAR event",
           shape="note", color=SURFACE2, fontcolor=BORDER,
           style="filled", fillcolor="#181825", fontsize="9")
    g.edge("queue", "bp_note", style="dashed", color=BORDER, arrowhead="none")

    g.render(str(OUT / "message_outbound"), cleanup=True)


# ═════════════════════════════════════════════════════════════════════════════
# 6. Noise XX handshake — per security-trust.md, attestation.md
# ═════════════════════════════════════════════════════════════════════════════

def gen_noise_handshake():
    g = graphviz.Digraph("noise_handshake", format="svg", **base_attrs())
    g.attr(rankdir="TB", nodesep="0.4", ranksep="0.3", compound="true")

    with g.subgraph(name="cluster_xx") as xx:
        xx.attr(
            label="Noise_XX  (3 messages, mutual auth, no prior knowledge)",
            labelloc="t", fontsize="12", fontcolor=LAVENDER,
            style="rounded,filled", fillcolor="#181825",
            color=LAVENDER, penwidth="1.5",
        )

        xx.node("init_hdr", "Initiator", shape="plaintext",
                fontcolor=BLUE, fontsize="12")
        xx.node("resp_hdr", "Responder", shape="plaintext",
                fontcolor=GREEN, fontsize="12")
        with xx.subgraph() as s:
            s.attr(rank="same")
            s.node("init_hdr"); s.node("resp_hdr")

        # Step 0 — keys
        xx.node("init_keys", "Generate ephemeral\nkeypair (e_i)",
                color=BLUE, fontcolor=BLUE,
                style="filled,rounded", fillcolor=SURFACE1, fontsize="9")
        xx.node("resp_keys", "Has static keypair\n(s_r, S_r)",
                color=GREEN, fontcolor=GREEN,
                style="filled,rounded", fillcolor=SURFACE1, fontsize="9")
        with xx.subgraph() as s:
            s.attr(rank="same")
            s.node("init_keys"); s.node("resp_keys")
        xx.edge("init_hdr", "init_keys", style="invis")
        xx.edge("resp_hdr", "resp_keys", style="invis")

        # MSG 1 — →e
        xx.node("msg1",
                "MSG 1   →  e\n"
                "ephemeral pubkey (32 B)",
                shape="parallelogram", color=LAVENDER, fontcolor=LAVENDER,
                style="filled", fillcolor=SURFACE1, fontsize="9")
        xx.edge("init_keys", "msg1", color=BLUE)
        xx.edge("msg1", "resp_step1", color=GREEN)

        xx.node("resp_step1",
                "Generate ephemeral (e_r)\n"
                "ee = X25519(e_r, e_i)\n"
                "Encrypt static S_r under ee",
                color=GREEN, fontcolor=GREEN,
                style="filled,rounded", fillcolor=SURFACE1, fontsize="9")

        # MSG 2 — ←e, ee, s, es
        xx.node("msg2",
                "MSG 2   ←  e, ee, s, es\n"
                "ephemeral + encrypted static\n"
                "+ DH mixed into key",
                shape="parallelogram", color=LAVENDER, fontcolor=LAVENDER,
                style="filled", fillcolor=SURFACE1, fontsize="9")
        xx.edge("resp_step1", "msg2", color=GREEN)
        xx.edge("msg2", "init_step2", color=BLUE)

        xx.node("init_step2",
                "ee = X25519(e_i, e_r)\n"
                "Decrypt S_r\n"
                "se = X25519(S_i, e_r)\n"
                "Encrypt own static S_i",
                color=BLUE, fontcolor=BLUE,
                style="filled,rounded", fillcolor=SURFACE1, fontsize="9")

        # MSG 3 — →s, se
        xx.node("msg3",
                "MSG 3   →  s, se\n"
                "encrypted static\n"
                "+ DH proof",
                shape="parallelogram", color=LAVENDER, fontcolor=LAVENDER,
                style="filled", fillcolor=SURFACE1, fontsize="9")
        xx.edge("init_step2", "msg3", color=BLUE)
        xx.edge("msg3", "resp_step3", color=GREEN)

        xx.node("resp_step3",
                "Decrypt S_i\n"
                "se = X25519(e_r, S_i)\n"
                "Verify identity",
                color=GREEN, fontcolor=GREEN,
                style="filled,rounded", fillcolor=SURFACE1, fontsize="9")

        xx.node("split",
                "Split() → 2 CipherStates\n"
                "send_key + recv_key\n"
                "(ChaCha20-Poly1305 AEAD)",
                shape="octagon", color=YELLOW, fontcolor=YELLOW,
                style="filled", fillcolor=SURFACE1, fontsize="9")
        xx.edge("init_step2", "split", color=BLUE, style="dashed")
        xx.edge("resp_step3", "split", color=GREEN, style="dashed")

    # Attestation gate before TRUST_UPGRADED
    g.node("attest",
           "Attestation exchange\n"
           "232-byte payload over secured channel\n"
           "(per attestation.md)",
           shape="box", color=MAUVE, fontcolor=MAUVE,
           style="filled,rounded", fillcolor=SURFACE1, fontsize="9")
    g.edge("split", "attest", color=YELLOW)

    g.node("upgraded",
           "Trust upgraded:\n"
           "Untrusted → Peer\n"
           "TRUST_UPGRADED event fired",
           shape="doubleoctagon", color=GREEN, fontcolor=GREEN,
           style="filled", fillcolor=SURFACE1, fontsize="9")
    g.edge("attest", "upgraded", color=GREEN, label="verified")

    g.node("note",
           "Crypto: X25519 DH · ChaCha20-Poly1305 AEAD · BLAKE2b hash\n"
           "Loopback / IntraNode connections skip handshake;\n"
           "their trust class is final at notify_connect.",
           shape="note", color=SURFACE2, fontcolor=BORDER,
           style="filled", fillcolor="#181825", fontsize="9")
    g.edge("upgraded", "note", style="invis")

    g.render(str(OUT / "noise_handshake"), cleanup=True)


# ═════════════════════════════════════════════════════════════════════════════
# 7. Dispatch chain — per handler-registration.md §3
# ═════════════════════════════════════════════════════════════════════════════

def gen_dispatch_chain():
    g = graphviz.Digraph("dispatch_chain", format="svg", **base_attrs())
    g.attr(rankdir="TB", nodesep="0.35", ranksep="0.35")

    g.node("entry",
           "Envelope arrival\n(protocol_id, msg_id, sender_pk,\n"
           "receiver_pk, payload)",
           shape="oval", color=BLUE, fontcolor=BLUE,
           style="filled", fillcolor=SURFACE1, fontsize="10")

    g.node("lookup",
           "HandlerRegistry\nlookup_with_generation(protocol_id, msg_id)\n"
           "→ (chain snapshot, generation)",
           color=LAVENDER, fontcolor=LAVENDER,
           style="filled,rounded", fillcolor=SURFACE1, fontsize="9")
    g.edge("entry", "lookup", color=BORDER)

    g.node("iter",
           "Iterate snapshot in\npriority-descending order",
           color=LAVENDER, fontcolor=LAVENDER,
           style="filled,rounded", fillcolor=SURFACE1, fontsize="9")
    g.edge("lookup", "iter", color=BORDER)

    g.node("call",
           "h.handle_message(self, &env)\n"
           "→ gn_propagation_t r\n"
           "h.on_result(self, &env, r)   /* always */",
           color=PEACH, fontcolor=PEACH,
           style="filled,rounded", fillcolor=SURFACE1, fontsize="9")
    g.edge("iter", "call", color=BORDER)

    # Three propagation outcomes
    g.node("cont",
           "GN_PROPAGATION_CONTINUE\n→ next handler in chain",
           color=BLUE, fontcolor=BLUE,
           style="filled,rounded", fillcolor=SURFACE1, fontsize="9")
    g.node("consumed",
           "GN_PROPAGATION_CONSUMED\n→ stop chain (handled)",
           color=YELLOW, fontcolor=YELLOW,
           style="filled,rounded", fillcolor=SURFACE1, fontsize="9")
    g.node("reject",
           "GN_PROPAGATION_REJECT\n→ drop envelope; close conn;\n"
           "metric increment",
           color=RED, fontcolor=RED,
           style="filled,rounded", fillcolor=SURFACE1, fontsize="9")

    g.edge("call", "cont",     color=BLUE)
    g.edge("call", "consumed", color=YELLOW)
    g.edge("call", "reject",   color=RED)
    g.edge("cont", "iter",     color=BLUE, style="dashed")

    # Snapshot semantics
    g.node("note",
           "Chain materialised once at envelope arrival.\n"
           "Registration mid-dispatch is a no-op for this envelope —\n"
           "visible from the next dispatch.\n"
           "Snapshot's lifetime_anchor refs keep every handler vtable\n"
           "valid for the entire walk (no UAF on concurrent unregister).",
           shape="note", color=SURFACE2, fontcolor=BORDER,
           style="filled", fillcolor="#181825", fontsize="9")
    g.edge("reject", "note", style="invis")

    g.render(str(OUT / "dispatch_chain"), cleanup=True)


# ═════════════════════════════════════════════════════════════════════════════
# 8. Sharded ConnectionRegistry — per registry.md
# ═════════════════════════════════════════════════════════════════════════════

def gen_sharded_registry():
    g = graphviz.Digraph("sharded_registry", format="svg", **base_attrs())
    g.attr(rankdir="TB", nodesep="0.3", ranksep="0.45")

    g.node("entry",
           "insert_with_index(record, id, uri, pk)\n"
           "or  erase_with_index(id)",
           shape="oval", color=BLUE, fontcolor=BLUE,
           style="filled", fillcolor=SURFACE1, fontsize="10")

    g.node("locks",
           "Acquire triple of mutexes\n"
           "in fixed total order:\n"
           "  1. shard mutex (id mod 16)\n"
           "  2. URI-index mutex\n"
           "  3. pk-index mutex",
           color=YELLOW, fontcolor=YELLOW,
           style="filled,rounded", fillcolor=SURFACE1, fontsize="9")
    g.edge("entry", "locks", color=BORDER)

    # Three indexes — one record under all three keys
    with g.subgraph(name="cluster_indexes") as c:
        c.attr(label="Three indexes — record visible under all three keys or none",
               labelloc="t", fontsize="11", fontcolor=LAVENDER,
               style="rounded,filled", fillcolor="#181825",
               color=LAVENDER, penwidth="1.5")

        c.node("id_idx",
               "id index\n16 shards by (id mod 16)\nshared_mutex per shard",
               color=TEAL, fontcolor=TEAL,
               style="filled,rounded", fillcolor=SURFACE1, fontsize="9")
        c.node("uri_idx",
               "uri index\nstd::unordered_map<string, id>\nglobal mutex",
               color=MAUVE, fontcolor=MAUVE,
               style="filled,rounded", fillcolor=SURFACE1, fontsize="9")
        c.node("pk_idx",
               "pk index\nstd::unordered_map<pk, id>\nglobal mutex\n"
               "zero-pk skipped (responders)",
               color=MAUVE, fontcolor=MAUVE,
               style="filled,rounded", fillcolor=SURFACE1, fontsize="9")

    g.edge("locks", "id_idx",  color=TEAL)
    g.edge("locks", "uri_idx", color=MAUVE)
    g.edge("locks", "pk_idx",  color=MAUVE)

    # Properties
    g.node("rules",
           "All-or-nothing — collision on any key fails before mutation\n"
           "No reader-visible intermediate state\n"
           "Deadlock-free — fixed acquisition order across callers\n"
           "Snapshot variant for notify_disconnect:\n"
           "  capture endpoint + counters, then erase, atomically",
           shape="note", color=SURFACE2, fontcolor=BORDER,
           style="filled", fillcolor="#181825", fontsize="9")
    g.edge("pk_idx", "rules", style="invis")

    # find_conn_by_pk plugin-side surface
    g.node("plugin_view",
           "Plugin-side reads (lock-free):\n"
           "  host_api->find_conn_by_pk(pk, &conn)\n"
           "  host_api->get_endpoint(conn, &out)\n"
           "  host_api->for_each_connection(visitor)",
           shape="note", color=SURFACE2, fontcolor=PEACH,
           style="filled", fillcolor="#181825", fontsize="9")
    g.edge("entry", "plugin_view", style="dashed", color=PEACH,
           arrowhead="none")

    g.render(str(OUT / "sharded_registry"), cleanup=True)


# ═════════════════════════════════════════════════════════════════════════════
# 9. Backpressure — per backpressure.md, conn-events.md
# ═════════════════════════════════════════════════════════════════════════════

def gen_cas_backpressure():
    g = graphviz.Digraph("cas_backpressure", format="svg", **base_attrs())
    g.attr(rankdir="TB", nodesep="0.35", ranksep="0.35")

    g.node("send",
           "host_api->send(conn, msg_id, payload, size)\n"
           "→ link plugin's per-conn write queue",
           shape="oval", color=BLUE, fontcolor=BLUE,
           style="filled", fillcolor=SURFACE1, fontsize="10")

    g.node("hard",
           "bytes_buffered + size > pending_queue_bytes_hard ?",
           shape="diamond", color=RED, fontcolor=RED,
           style="filled", fillcolor=SURFACE1, fontsize="9")
    g.edge("send", "hard", color=BORDER)

    g.node("reject",
           "return GN_ERR_LIMIT_REACHED\n(hard-cap reject)",
           color=RED, fontcolor=RED, shape="oval",
           style="filled", fillcolor=SURFACE1, fontsize="9")
    g.edge("hard", "reject", label="yes", color=RED, fontcolor=RED)

    g.node("enqueue",
           "bytes_buffered += size\nwrite_queue.push(bytes)",
           color=GREEN, fontcolor=GREEN,
           style="filled,rounded", fillcolor=SURFACE1, fontsize="9")
    g.edge("hard", "enqueue", label="no", color=GREEN, fontcolor=GREEN)

    g.node("soft_check",
           "rising edge?\n!soft_signaled &&\nbytes_buffered > high",
           shape="diamond", color=YELLOW, fontcolor=YELLOW,
           style="filled", fillcolor=SURFACE1, fontsize="9")
    g.edge("enqueue", "soft_check", color=BORDER)

    g.node("fire_soft",
           "notify_backpressure(\n"
           "  GN_CONN_EVENT_BACKPRESSURE_SOFT,\n"
           "  pending_bytes)\n"
           "soft_signaled = true",
           color=YELLOW, fontcolor=YELLOW,
           style="filled,rounded", fillcolor=SURFACE1, fontsize="9")
    g.edge("soft_check", "fire_soft", label="yes",
           color=YELLOW, fontcolor=YELLOW)

    # Drain side
    g.node("drain",
           "async_write completion\nbytes_buffered -= written",
           color=MAUVE, fontcolor=MAUVE,
           style="filled,rounded", fillcolor=SURFACE1, fontsize="9")

    g.node("clear_check",
           "falling edge?\nsoft_signaled &&\nbytes_buffered < low",
           shape="diamond", color=TEAL, fontcolor=TEAL,
           style="filled", fillcolor=SURFACE1, fontsize="9")
    g.edge("drain", "clear_check", color=BORDER)

    g.node("fire_clear",
           "notify_backpressure(\n"
           "  GN_CONN_EVENT_BACKPRESSURE_CLEAR,\n"
           "  pending_bytes)\n"
           "soft_signaled = false",
           color=TEAL, fontcolor=TEAL,
           style="filled,rounded", fillcolor=SURFACE1, fontsize="9")
    g.edge("clear_check", "fire_clear", label="yes",
           color=TEAL, fontcolor=TEAL)

    # Watermark trio note
    g.node("trio",
           "Watermarks (gn_limits_t):\n"
           "  pending_queue_bytes_low   = 256 KiB\n"
           "  pending_queue_bytes_high  = 1 MiB\n"
           "  pending_queue_bytes_hard  = 4 MiB\n"
           "Invariant: 0 < low < high ≤ hard",
           shape="note", color=SURFACE2, fontcolor=BORDER,
           style="filled", fillcolor="#181825", fontsize="9")
    g.edge("fire_clear", "trio", style="invis")

    g.render(str(OUT / "cas_backpressure"), cleanup=True)


# ═════════════════════════════════════════════════════════════════════════════
# 10. dlopen pipeline — per plugin-lifetime.md, plugin-manifest.md
# ═════════════════════════════════════════════════════════════════════════════

def gen_dlopen_pipeline():
    g = graphviz.Digraph("dlopen_pipeline", format="svg", **base_attrs())
    g.attr(rankdir="TB", nodesep="0.3", ranksep="0.35")

    steps = [
        ("manifest",
         "PluginManager::discover\n"
         "scan plugin manifest files\n"
         "→ load order",                                       BLUE),
        ("dlopen",
         "dlopen(path, RTLD_LAZY | RTLD_LOCAL)\n"
         "resolve five mandatory entry symbols",               GREEN),
        ("version",
         "gn_plugin_sdk_version(&maj, &min, &patch)\n"
         "kernel rejects if maj != kernel.maj\n"
         "or min > kernel.min",                                LAVENDER),
        ("descriptor",
         "gn_plugin_descriptor()  (optional)\n"
         "name, version, kind,\n"
         "ext_requires / ext_provides",                        TEAL),
        ("init",
         "gn_plugin_init(api, &out_self)\n"
         "phase 4 — construct internal state\n"
         "MUST NOT call host_api->register_*",                 PEACH),
        ("register",
         "gn_plugin_register(self)\n"
         "phase 5 — atomic with siblings:\n"
         "host_api->register_vtable(KIND, …)\n"
         "host_api->register_security / register_extension",   YELLOW),
        ("running",
         "phase 6 — Running\n"
         "dispatch open; plugin live",                         GREEN),
    ]

    for nid, label, clr in steps:
        g.node(nid, label, color=clr, fontcolor=clr,
               style="filled,rounded", fillcolor=SURFACE1, fontsize="9")

    for i in range(len(steps) - 1):
        g.edge(steps[i][0], steps[i + 1][0], color=BORDER)

    # Teardown — mirror in reverse, with quiescence wait
    teardown = [
        ("pre_shut",
         "phase 7 — PreShutdown\n"
         "publish shutdown_requested\n"
         "drain in-flight dispatches",                         YELLOW),
        ("unreg",
         "gn_plugin_unregister(self)\n"
         "phase 8 — registry entries drop anchors",            PEACH),
        ("drain",
         "Quiescence wait\n"
         "weak observer waits for sentinel expiry\n"
         "(default 1 s)",                                      MAUVE),
        ("shut",
         "gn_plugin_shutdown(self)\n"
         "phase 9 — release internal state\n"
         "MUST NOT call host_api after return",                RED),
        ("dlclose",
         "dlclose(handle)\n"
         "phase 10 — unmap shared object\n"
         "leak handle on drain timeout",                       RED),
    ]

    for nid, label, clr in teardown:
        g.node(nid, label, color=clr, fontcolor=clr,
               style="filled,rounded", fillcolor=SURFACE1, fontsize="9")

    g.edge("running", "pre_shut", color=BORDER)
    for i in range(len(teardown) - 1):
        g.edge(teardown[i][0], teardown[i + 1][0], color=BORDER)

    # Two-phase activation note
    g.node("note",
           "Two-phase activation (phases 4–5):\n"
           "every plugin constructed before any is registered.\n"
           "Partial init failure → rollback_init only;\n"
           "no live traffic ever sees a half-built plugin.",
           shape="note", color=SURFACE2, fontcolor=BORDER,
           style="filled", fillcolor="#181825", fontsize="9")
    g.edge("dlclose", "note", style="invis")

    g.render(str(OUT / "dlopen_pipeline"), cleanup=True)


# ═════════════════════════════════════════════════════════════════════════════
# 11. C ABI boundary — host_api_t + sdk/cpp/ wrappers
# ═════════════════════════════════════════════════════════════════════════════

def gen_c_cpp_bridging():
    g = graphviz.Digraph("c_cpp_bridging", format="svg", **base_attrs())
    g.attr(rankdir="LR", nodesep="0.5", ranksep="0.6")

    # Plugin side — C++ wrapper
    with g.subgraph(name="cluster_plugin") as c:
        c.attr(label="Plugin (.so)  — C++ implementation",
               labelloc="t", fontsize="11", fontcolor=PEACH,
               style="rounded,filled", fillcolor="#181825",
               color=PEACH, penwidth="1.5")

        c.node("cpp_class",
               "class MyHandler\n: public goodnet::HandlerBase\n"
               "(sdk/cpp/handler.hpp)",
               color=PEACH, fontcolor=PEACH,
               style="filled,rounded", fillcolor=SURFACE1, fontsize="9")

        c.node("cpp_call",
               "send(conn, msg_id, payload)\n"
               "query_extension_checked(name, ver)\n"
               "set_timer(ms, fn, ud)\n"
               "subscribe_conn_state(cb, ud)",
               color=PEACH, fontcolor=PEACH,
               style="filled,rounded", fillcolor=SURFACE1, fontsize="9")

        c.node("trampoline",
               "Static trampolines\n"
               "static gn_propagation_t handle(void* self, …)\n"
               "  { return static_cast<MyHandler*>(self)\n"
               "      ->on_message(envelope); }",
               color=YELLOW, fontcolor=YELLOW,
               style="filled,rounded", fillcolor=SURFACE1, fontsize="8")

        c.edge("cpp_class", "trampoline", color=BORDER)
        c.edge("cpp_class", "cpp_call",   color=BORDER)

    # ABI boundary
    g.node("abi",
           "C ABI boundary\n"
           "host_api_t            (kernel → plugin)\n"
           "gn_handler_vtable_t   (plugin → kernel)\n"
           "gn_link_vtable_t      (plugin → kernel)\n"
           "gn_security_provider_vtable_t  (plugin → kernel)\n"
           "all extern \"C\", api_size first, _reserved tail",
           shape="parallelogram", color=YELLOW, fontcolor=YELLOW,
           style="filled", fillcolor=SURFACE1, fontsize="9")

    # Kernel side
    with g.subgraph(name="cluster_kernel") as c:
        c.attr(label="Kernel  — opaque C++ implementation",
               labelloc="t", fontsize="11", fontcolor=LAVENDER,
               style="rounded,filled", fillcolor="#181825",
               color=LAVENDER, penwidth="1.5")

        c.node("host_ctx",
               "host_ctx (opaque)\n"
               "PluginContext* on the kernel side\n"
               "passed back unchanged on every call",
               color=LAVENDER, fontcolor=LAVENDER,
               style="filled,rounded", fillcolor=SURFACE1, fontsize="9")

        c.node("subsystems",
               "HandlerRegistry · LinkRegistry\n"
               "SecurityRegistry · ExtensionRegistry\n"
               "ConnectionRegistry · ServiceExecutor\n"
               "SignalChannel<Event>",
               color=LAVENDER, fontcolor=LAVENDER,
               style="filled,rounded", fillcolor=SURFACE1, fontsize="9")

        c.edge("host_ctx", "subsystems", color=BORDER)

    # Edges
    g.edge("cpp_call", "abi",
           label="api->send(api->host_ctx, …)",
           color=YELLOW, fontcolor=YELLOW)
    g.edge("abi", "host_ctx",
           label="thunk dispatches\nbased on host_ctx",
           color=YELLOW, fontcolor=YELLOW)

    g.edge("trampoline", "abi", color=BORDER, style="dashed",
           label="vtable slot")

    g.node("note",
           "sdk/convenience.h — C inline wrappers (no per-language layer)\n"
           "sdk/cpp/* — typed C++ helpers (HandlerBase, LinkBase, …)\n"
           "Other-language bindings sit on the same C ABI.",
           shape="note", color=SURFACE2, fontcolor=BORDER,
           style="filled", fillcolor="#181825", fontsize="9")
    g.edge("subsystems", "note", style="invis")

    g.render(str(OUT / "c_cpp_bridging"), cleanup=True)


# ═════════════════════════════════════════════════════════════════════════════
# 12. Nonce window — replay protection
# ═════════════════════════════════════════════════════════════════════════════

def gen_nonce_window():
    g = graphviz.Digraph("nonce_window", format="svg", **base_attrs())
    g.attr(rankdir="TB", nodesep="0.35", ranksep="0.35")

    g.node("recv",
           "check_and_mark(nonce)",
           shape="oval", color=BLUE, fontcolor=BLUE,
           style="filled", fillcolor=SURFACE1, fontsize="10")

    g.node("too_old",
           "nonce <= last - 64 ?",
           shape="diamond", color=YELLOW, fontcolor=YELLOW,
           style="filled", fillcolor=SURFACE1, fontsize="9")
    g.edge("recv", "too_old", color=BORDER)

    g.node("reject_old",
           "REJECT\n(too old — outside window)",
           shape="oval", color=RED, fontcolor=RED,
           style="filled", fillcolor=SURFACE1, fontsize="9")
    g.edge("too_old", "reject_old", label="yes",
           color=RED, fontcolor=RED)

    g.node("ahead",
           "nonce > last ?",
           shape="diamond", color=YELLOW, fontcolor=YELLOW,
           style="filled", fillcolor=SURFACE1, fontsize="9")
    g.edge("too_old", "ahead", label="no",
           color=GREEN, fontcolor=GREEN)

    g.node("advance",
           "Advance window\n"
           "shift bits by (nonce - last)\n"
           "last = nonce; mark bit",
           color=GREEN, fontcolor=GREEN,
           style="filled,rounded", fillcolor=SURFACE1, fontsize="9")
    g.edge("ahead", "advance", label="yes",
           color=GREEN, fontcolor=GREEN)

    g.node("accept_adv",
           "ACCEPT",
           shape="oval", color=GREEN, fontcolor=GREEN,
           style="filled", fillcolor=SURFACE1, fontsize="9")
    g.edge("advance", "accept_adv", color=GREEN)

    g.node("in_window",
           "Check bit at\n(last - nonce) offset",
           color=TEAL, fontcolor=TEAL,
           style="filled,rounded", fillcolor=SURFACE1, fontsize="9")
    g.edge("ahead", "in_window", label="no\n(within window)",
           color=TEAL, fontcolor=TEAL)

    g.node("seen",
           "Bit set ?",
           shape="diamond", color=TEAL, fontcolor=TEAL,
           style="filled", fillcolor=SURFACE1, fontsize="9")
    g.edge("in_window", "seen", color=BORDER)

    g.node("reject_dup",
           "REJECT\n(replay)",
           shape="oval", color=RED, fontcolor=RED,
           style="filled", fillcolor=SURFACE1, fontsize="9")
    g.edge("seen", "reject_dup", label="yes",
           color=RED, fontcolor=RED)

    g.node("mark",
           "Set bit  →  ACCEPT",
           shape="oval", color=GREEN, fontcolor=GREEN,
           style="filled", fillcolor=SURFACE1, fontsize="9")
    g.edge("seen", "mark", label="no",
           color=GREEN, fontcolor=GREEN)

    g.node("window_note",
           "64-bit sliding window:\n"
           "  ┌─┬─┬─┬─┬─┬─┬─┬─┐\n"
           "  │1│0│1│1│0│1│1│1│ … (64 bits)\n"
           "  └─┴─┴─┴─┴─┴─┴─┴─┘\n"
           "                last ──►",
           shape="note", color=SURFACE2, fontcolor=BORDER,
           style="filled", fillcolor="#181825", fontsize="9")
    g.edge("mark", "window_note", style="invis")

    g.render(str(OUT / "nonce_window"), cleanup=True)


# ═════════════════════════════════════════════════════════════════════════════
# 13. Signal bus — per signal-channel.md, conn-events.md
# ═════════════════════════════════════════════════════════════════════════════

def gen_signal_bus():
    g = graphviz.Digraph("signal_bus", format="svg", **base_attrs())
    g.attr(rankdir="TB", nodesep="0.4", ranksep="0.45")

    # Channels — one SignalChannel per event type
    with g.subgraph(name="cluster_channels") as ch:
        ch.attr(label="SignalChannel<Event>  — typed pub/sub per event type",
                labelloc="t", fontsize="12", fontcolor=LAVENDER,
                style="rounded,filled", fillcolor="#181825",
                color=LAVENDER, penwidth="1.5")

        ch.node("conn_state_ch",
                "GN_SUBSCRIBE_CONN_STATE\n"
                "  CONNECTED · DISCONNECTED\n"
                "  TRUST_UPGRADED\n"
                "  BACKPRESSURE_SOFT / CLEAR\n"
                "payload = const gn_conn_event_t*",
                color=TEAL, fontcolor=TEAL,
                style="filled,rounded", fillcolor=SURFACE1, fontsize="9")

        ch.node("config_reload_ch",
                "GN_SUBSCRIBE_CONFIG_RELOAD\n"
                "  reload completed (no payload)\n"
                "subscriber re-reads config_get",
                color=TEAL, fontcolor=TEAL,
                style="filled,rounded", fillcolor=SURFACE1, fontsize="9")

        ch.node("phase_ch",
                "Kernel::subscribe(IPhaseObserver)\n"
                "  Load → Wire → … → Unload\n"
                "kernel-internal; not exposed via host_api",
                color=BLUE, fontcolor=BLUE,
                style="filled,rounded", fillcolor=SURFACE1, fontsize="9")

    # Publishers
    with g.subgraph(name="cluster_pub") as p:
        p.attr(label="Publishers", labelloc="t", fontsize="11",
               fontcolor=GREEN, style="rounded,filled", fillcolor=BG,
               color=GREEN, penwidth="1.2")
        p.node("link_pub",
               "Link plugins\nnotify_connect / notify_disconnect /\nnotify_backpressure",
               color=GREEN, fontcolor=GREEN,
               style="filled,rounded", fillcolor=SURFACE1, fontsize="9")
        p.node("attest_pub",
               "Attestation dispatcher\nupgrade_trust on success",
               color=GREEN, fontcolor=GREEN,
               style="filled,rounded", fillcolor=SURFACE1, fontsize="9")
        p.node("config_pub",
               "Config reloader",
               color=GREEN, fontcolor=GREEN,
               style="filled,rounded", fillcolor=SURFACE1, fontsize="9")

    # Subscribers
    with g.subgraph(name="cluster_sub") as s:
        s.attr(label="Subscribers", labelloc="t", fontsize="11",
               fontcolor=PEACH, style="rounded,filled", fillcolor=BG,
               color=PEACH, penwidth="1.2")
        s.node("any_plugin",
               "Any plugin\nhost_api->subscribe_conn_state\n"
               "host_api->subscribe_config_reload",
               color=PEACH, fontcolor=PEACH,
               style="filled,rounded", fillcolor=SURFACE1, fontsize="9")

    # Edges — publishers fire → channel; channel → subscribers
    g.edge("link_pub",   "conn_state_ch",     color=GREEN, fontcolor=GREEN,
           label="fire")
    g.edge("attest_pub", "conn_state_ch",     color=GREEN, fontcolor=GREEN,
           label="fire")
    g.edge("config_pub", "config_reload_ch",  color=GREEN, fontcolor=GREEN,
           label="fire")

    g.edge("conn_state_ch",    "any_plugin",  color=PEACH, fontcolor=PEACH,
           label="cb(payload, size)")
    g.edge("config_reload_ch", "any_plugin",  color=PEACH, fontcolor=PEACH,
           label="cb(NULL, 0)")

    # Lifetime + threading note
    g.node("note",
           "Each subscription pairs with a weak observer of the\n"
           "calling plugin's lifetime anchor (plugin-lifetime.md §4):\n"
           "callback whose plugin already unloaded is dropped silently.\n"
           "\n"
           "Subscribers run on the publishing thread —\n"
           "transport's strand for CONNECTED / DISCONNECTED /\n"
           "BACKPRESSURE_*; whichever thread completed the security\n"
           "handshake for TRUST_UPGRADED. State across kinds is\n"
           "guarded with a lock or posted through set_timer(0, …).",
           shape="note", color=SURFACE2, fontcolor=BORDER,
           style="filled", fillcolor="#181825", fontsize="9")
    g.edge("any_plugin", "note", style="invis")

    g.render(str(OUT / "signal_bus"), cleanup=True)


# ═════════════════════════════════════════════════════════════════════════════
# 14. Connection lifecycle — high-level dial through trust upgrade
# ═════════════════════════════════════════════════════════════════════════════

def gen_connection_lifecycle():
    g = graphviz.Digraph("connection_lifecycle", format="svg", **base_attrs())
    g.attr(rankdir="TB", nodesep="0.3", ranksep="0.35")

    g.node("dial",
           "Plugin / app dial\n"
           "scheme://host:port",
           shape="oval", color=BLUE, fontcolor=BLUE,
           style="filled", fillcolor=SURFACE1, fontsize="10")

    g.node("link",
           "Link plugin (scheme owner)\n"
           "opens transport socket\n"
           "computes TrustClass from observable\n"
           "(public IP → Untrusted; 127.0.0.1 → Loopback;\n"
           " IPC → Loopback; intra-process → IntraNode)",
           color=GREEN, fontcolor=GREEN,
           style="filled,rounded", fillcolor=SURFACE1, fontsize="9")
    g.edge("dial", "link", color=BORDER)

    g.node("notify_connect",
           "host_api->notify_connect(\n"
           "  remote_pk, uri, trust, role,\n"
           "  &out_conn)\n"
           "kernel allocates conn id\n"
           "creates SecuritySession in Handshake phase\n"
           "fires CONNECTED event",
           color=BLUE, fontcolor=BLUE,
           style="filled,rounded", fillcolor=SURFACE1, fontsize="9")
    g.edge("link", "notify_connect", color=BORDER)

    g.node("kick",
           "host_api->kick_handshake(conn)\n"
           "drives initiator's first message\n"
           "(no-op for responder; no-op for null security)",
           color=LAVENDER, fontcolor=LAVENDER,
           style="filled,rounded", fillcolor=SURFACE1, fontsize="9")
    g.edge("notify_connect", "kick", color=BORDER)

    g.node("hs",
           "Noise XX handshake over the secured channel\n"
           "(security session phase: Handshake → Transport)\n"
           "pending plaintexts buffered; drained post-handshake",
           color=TEAL, fontcolor=TEAL,
           style="filled,rounded", fillcolor=SURFACE1, fontsize="9")
    g.edge("kick", "hs", color=BORDER)

    g.node("attest",
           "Attestation exchange (232 B per side)\n"
           "AttestationDispatcher verifies remote payload\n"
           "pin_device_pk on first attestation",
           color=MAUVE, fontcolor=MAUVE,
           style="filled,rounded", fillcolor=SURFACE1, fontsize="9")
    g.edge("hs", "attest", color=BORDER)

    g.node("upgraded",
           "Trust upgraded: Untrusted → Peer\n"
           "TRUST_UPGRADED event fired\n"
           "endpoint.trust now reflects upgrade",
           shape="doubleoctagon", color=GREEN, fontcolor=GREEN,
           style="filled", fillcolor=SURFACE1, fontsize="9")
    g.edge("attest", "upgraded", color=GREEN, label="verified")

    # Steady state — application traffic
    g.node("steady",
           "Steady state:\n"
           "  inbound  bytes → decrypt → deframe → dispatch\n"
           "  outbound send  → frame → encrypt → write queue → wire",
           color=YELLOW, fontcolor=YELLOW,
           style="filled,rounded", fillcolor=SURFACE1, fontsize="9")
    g.edge("upgraded", "steady", color=GREEN)

    # Disconnect
    g.node("disconnect",
           "host_api->notify_disconnect(conn, reason)\n"
           "atomic snapshot-and-erase from registry\n"
           "DISCONNECTED event fired with payload\n"
           "security session destroyed; pending queues cleared",
           color=RED, fontcolor=RED,
           style="filled,rounded", fillcolor=SURFACE1, fontsize="9")
    g.edge("steady", "disconnect", color=RED)

    # Failure paths
    g.edge("hs",     "disconnect", color=RED, style="dashed",
           label="handshake fail")
    g.edge("attest", "disconnect", color=RED, style="dashed",
           label="attestation fail")

    # Multi-path note — sequential switch, NOT aggregation
    g.node("multipath_note",
           "Multi-path semantics:\n"
           "  sequential switch — dial new conn, disconnect old\n"
           "  NOT aggregation. Kernel does not own path selection;\n"
           "  any optimiser is a plugin coordinating via\n"
           "  ExtensionRegistry.",
           shape="note", color=SURFACE2, fontcolor=BORDER,
           style="filled", fillcolor="#181825", fontsize="9")
    g.edge("disconnect", "multipath_note", style="invis")

    g.render(str(OUT / "connection_lifecycle"), cleanup=True)


# ═════════════════════════════════════════════════════════════════════════════
# 15. Extension query — plugin↔plugin coordination, kernel as pure registry
# ═════════════════════════════════════════════════════════════════════════════

def gen_extension_query():
    g = graphviz.Digraph("extension_query", format="svg", **base_attrs())
    g.attr(rankdir="LR", nodesep="0.5", ranksep="0.6")

    # Provider plugin
    with g.subgraph(name="cluster_provider") as p:
        p.attr(label="Provider plugin", labelloc="t",
               fontsize="11", fontcolor=GREEN,
               style="rounded,filled", fillcolor="#181825",
               color=GREEN, penwidth="1.5")

        p.node("prov_vtable",
               "static const my_ext_v1_vtable_t my_ext_vtable = {\n"
               "    .api_size  = sizeof(my_ext_v1_vtable_t),\n"
               "    .do_thing  = &impl_do_thing,\n"
               "    .other     = &impl_other,\n"
               "};",
               color=GREEN, fontcolor=GREEN,
               style="filled,rounded", fillcolor=SURFACE1, fontsize="8")

        p.node("prov_register",
               "host_api->register_extension(\n"
               "    \"my-ext\",\n"
               "    GN_VERSION(1, 0, 0),\n"
               "    &my_ext_vtable)",
               color=GREEN, fontcolor=GREEN,
               style="filled,rounded", fillcolor=SURFACE1, fontsize="8")

        p.edge("prov_vtable", "prov_register", color=BORDER)

    # ExtensionRegistry
    g.node("ext_reg",
           "ExtensionRegistry\n"
           "name → (version, vtable, lifetime_anchor)\n"
           "single provider per name\n"
           "second register → GN_ERR_LIMIT_REACHED",
           shape="folder", color=MAUVE, fontcolor=MAUVE,
           style="filled", fillcolor=SURFACE1, fontsize="9")

    # Consumer plugin
    with g.subgraph(name="cluster_consumer") as c:
        c.attr(label="Consumer plugin", labelloc="t",
               fontsize="11", fontcolor=PEACH,
               style="rounded,filled", fillcolor="#181825",
               color=PEACH, penwidth="1.5")

        c.node("cons_query",
               "const void* vt = NULL;\n"
               "gn_result_t r =\n"
               "  host_api->query_extension_checked(\n"
               "      \"my-ext\",\n"
               "      GN_VERSION(1, 0, 0),\n"
               "      &vt);",
               color=PEACH, fontcolor=PEACH,
               style="filled,rounded", fillcolor=SURFACE1, fontsize="8")

        c.node("cons_branch",
               "switch (r) {\n"
               "  case GN_OK:                  use vt;\n"
               "  case GN_ERR_NOT_FOUND:       degrade gracefully;\n"
               "  case GN_ERR_VERSION_MISMATCH: too-old provider;\n"
               "}",
               color=PEACH, fontcolor=PEACH,
               style="filled,rounded", fillcolor=SURFACE1, fontsize="8")

        c.node("cons_call",
               "auto* api = static_cast<const my_ext_v1_vtable_t*>(vt);\n"
               "if (GN_API_HAS(api, do_thing))\n"
               "    api->do_thing(arg);",
               color=PEACH, fontcolor=PEACH,
               style="filled,rounded", fillcolor=SURFACE1, fontsize="8")

        c.edge("cons_query",  "cons_branch", color=BORDER)
        c.edge("cons_branch", "cons_call",   color=BORDER)

    # Wires
    g.edge("prov_register", "ext_reg",
           color=GREEN, fontcolor=GREEN,
           label="register_extension(name, ver, vt)")
    g.edge("ext_reg", "cons_query",
           color=PEACH, fontcolor=PEACH,
           label="query_extension_checked", dir="back")

    # Kernel role note
    g.node("kernel_role",
           "Kernel role — pure registry.\n"
           "  · stores (name → vtable) under lifetime_anchor\n"
           "  · checks version compatibility on query\n"
           "  · DOES NOT iterate extensions, DOES NOT orchestrate\n"
           "  · DOES NOT know what any extension does\n"
           "Plugins coordinate among themselves through this slot.",
           shape="note", color=SURFACE2, fontcolor=LAVENDER,
           style="filled", fillcolor="#181825", fontsize="9")
    g.edge("ext_reg", "kernel_role", style="invis")

    # Compatibility predicate note
    g.node("compat_note",
           "Compatibility predicate (gn_version_compatible):\n"
           "  registered.major == requested.major\n"
           "  registered.minor >= requested.minor\n"
           "  patch ignored.\n"
           "Older minor consumer always loads;\n"
           "newer minor consumer rejected with VERSION_MISMATCH.",
           shape="note", color=SURFACE2, fontcolor=BORDER,
           style="filled", fillcolor="#181825", fontsize="9")
    g.edge("cons_call", "compat_note", style="invis")

    g.render(str(OUT / "extension_query"), cleanup=True)


# ═════════════════════════════════════════════════════════════════════════════
# 16. Plugin separation — kernel + 8 plugins + integration-tests, each own git
# ═════════════════════════════════════════════════════════════════════════════

def gen_plugin_separation():
    g = graphviz.Digraph("plugin_separation", format="svg", **base_attrs())
    g.attr(rankdir="TB", nodesep="0.45", ranksep="0.5", compound="true")

    # Kernel git
    with g.subgraph(name="cluster_kernel_git") as k:
        k.attr(label="kernel git  (org/kernel)",
               labelloc="t", fontsize="12", fontcolor=LAVENDER,
               style="rounded,filled", fillcolor="#181825",
               color=LAVENDER, penwidth="1.5")

        k.node("kernel_src",
               "core/        kernel implementation\n"
               "sdk/         public C ABI headers\n"
               "             (host_api.h, plugin.h, …)\n"
               "tests/unit/  kernel-only tests\n"
               "nix/kernel-only/  slim subflake for plugins",
               color=LAVENDER, fontcolor=LAVENDER,
               style="filled,rounded", fillcolor=SURFACE1, fontsize="9")

    # SDK boundary
    g.node("sdk_boundary",
           "SDK boundary  (sdk/*.h)\n"
           "  host_api_t · gn_*_vtable_t · plugin entry points\n"
           "every plugin consumes this; kernel exports nothing else",
           shape="parallelogram", color=YELLOW, fontcolor=YELLOW,
           style="filled", fillcolor=SURFACE1, fontsize="9")
    g.edge("kernel_src", "sdk_boundary",
           lhead="cluster_kernel_git",
           color=YELLOW, arrowhead="none")

    # 8 plugin gits + integration-tests git
    plugins = [
        ("git_heartbeat", "handler-heartbeat",      PEACH),
        ("git_tcp",       "link-tcp",               PEACH),
        ("git_udp",       "link-udp",               PEACH),
        ("git_ws",        "link-ws",                PEACH),
        ("git_ipc",       "link-ipc",               PEACH),
        ("git_tls",       "link-tls",               PEACH),
        ("git_noise",     "security-noise",         PEACH),
        ("git_null",      "security-null",          PEACH),
        ("git_intg",      "integration-tests",      MAUVE),
    ]

    with g.subgraph(name="cluster_plugins") as p:
        p.attr(label="9 sibling repos — each own .git, own flake (kernel-only subflake), own bare mirror",
               labelloc="t", fontsize="11", fontcolor=GREEN,
               style="rounded,filled", fillcolor=BG,
               color=GREEN, penwidth="1.2")

        for nid, label, clr in plugins:
            p.node(nid,
                   f"{label}\n"
                   f".git/\n"
                   f"flake.nix → kernel-only subflake\n"
                   f"tests/  · own conformance suite",
                   color=clr, fontcolor=clr, shape="component",
                   style="filled", fillcolor=SURFACE1, fontsize="9")

    for nid, _, _ in plugins:
        g.edge("sdk_boundary", nid, color=YELLOW, style="dashed",
               arrowhead="vee")

    # Deployment modes
    g.node("deploy",
           "Deployment modes (per plugin):\n"
           "  · static archive — linked into kernel binary\n"
           "  · dynamic .so   — dlopen at runtime\n"
           "Single source supports both.",
           shape="note", color=SURFACE2, fontcolor=BORDER,
           style="filled", fillcolor="#181825", fontsize="9")
    g.edge("git_null", "deploy", style="invis")

    # Workflow note
    g.node("workflow",
           "Workflow:\n"
           "  · kernel .gitignore blocks plugins/handlers,\n"
           "    plugins/links, plugins/security/{noise,null}\n"
           "    so nested plugin .git/ are not auto-submodules.\n"
           "  · `nix run .#setup` clones every plugin from its mirror\n"
           "    into the slot; `nix run .#plugin -- pull` updates.\n"
           "  · post-rc1: each plugin pushed to org repo;\n"
           "    plugin's flake URL switches local-mirror → github.",
           shape="note", color=SURFACE2, fontcolor=BORDER,
           style="filled", fillcolor="#181825", fontsize="9")
    g.edge("git_intg", "workflow", style="invis")

    g.render(str(OUT / "plugin_separation"), cleanup=True)


# ═════════════════════════════════════════════════════════════════════════════
# 17. host_api KIND-tagged primitives — single ABI slots, kind enum value picks
# ═════════════════════════════════════════════════════════════════════════════

def gen_host_api_kinds():
    g = graphviz.Digraph("host_api_kinds", format="svg", **base_attrs())
    g.attr(rankdir="TB", nodesep="0.35", ranksep="0.5", compound="true")

    g.node("plugin",
           "Plugin",
           shape="component", color=PEACH, fontcolor=PEACH,
           style="filled", fillcolor=SURFACE1, fontsize="11")

    # Primitives — single slot each, parametrised by KIND enum value
    with g.subgraph(name="cluster_primitives") as p:
        p.attr(label="host_api_t — KIND-tagged primitives",
               labelloc="t", fontsize="12", fontcolor=LAVENDER,
               style="rounded,filled", fillcolor="#181825",
               color=LAVENDER, penwidth="1.5")

        # register_vtable — one slot, two kinds today
        p.node("register",
               "register_vtable(kind, meta, vtable, self, &out_id)\n"
               "  GN_REGISTER_HANDLER  →  HandlerRegistry\n"
               "  GN_REGISTER_LINK     →  LinkRegistry\n"
               "→ id encodes kind in top 4 bits;\n"
               "  unregister_vtable(id) routes back",
               color=BLUE, fontcolor=BLUE,
               style="filled,rounded", fillcolor=SURFACE1, fontsize="9")

        # Security has its own slot pair (not part of register_vtable)
        p.node("register_security",
               "register_security(provider_id, vtable, self)\n"
               "→ SecurityRegistry\n"
               "  v1: at most one active provider per kernel",
               color=BLUE, fontcolor=BLUE,
               style="filled,rounded", fillcolor=SURFACE1, fontsize="9")

        # Extensions — own slot pair
        p.node("register_extension",
               "register_extension(name, version, vtable)\n"
               "→ ExtensionRegistry\n"
               "  query_extension_checked(name, version, &vt)",
               color=BLUE, fontcolor=BLUE,
               style="filled,rounded", fillcolor=SURFACE1, fontsize="9")

        # Subscribe — channel-tagged, two channels today
        p.node("subscribe",
               "subscribe_conn_state(cb, ud, ud_destroy, &id)\n"
               "subscribe_config_reload(cb, ud, ud_destroy, &id)\n"
               "→ unsubscribe(id)  routes by tag in id top bits",
               color=GREEN, fontcolor=GREEN,
               style="filled,rounded", fillcolor=SURFACE1, fontsize="9")

        # for_each_connection — single iterator over conn registry
        p.node("for_each",
               "for_each_connection(visitor, ud)\n"
               "  per-shard read lock; visitor returns 0 to continue",
               color=TEAL, fontcolor=TEAL,
               style="filled,rounded", fillcolor=SURFACE1, fontsize="9")

        p.node("iterate_counters",
               "iterate_counters(visitor, ud)\n"
               "  walk metric counters",
               color=TEAL, fontcolor=TEAL,
               style="filled,rounded", fillcolor=SURFACE1, fontsize="9")

        # config_get — type-tagged read
        p.node("config_get",
               "config_get(key, type, index, out, ud, free)\n"
               "  GN_CFG_BOOL · INT64 · DOUBLE · STRING\n"
               "  ARRAY_SIZE · array element by index\n"
               "→ kernel rejects type mismatch with INVALID_ENVELOPE",
               color=YELLOW, fontcolor=YELLOW,
               style="filled,rounded", fillcolor=SURFACE1, fontsize="9")

        # find_conn_by_pk + get_endpoint — single-shape lookups
        p.node("get_lookups",
               "find_conn_by_pk(pk, &conn)\n"
               "get_endpoint(conn, &out_endpoint)",
               color=YELLOW, fontcolor=YELLOW,
               style="filled,rounded", fillcolor=SURFACE1, fontsize="9")

    # Wire plugin → primitives
    for n in ("register", "register_security", "register_extension",
              "subscribe", "for_each", "iterate_counters",
              "config_get", "get_lookups"):
        g.edge("plugin", n, color=BORDER, arrowhead="vee")

    # Kernel-side registries
    with g.subgraph(name="cluster_back") as b:
        b.attr(label="Kernel registries (opaque to plugins)",
               labelloc="t", fontsize="11", fontcolor=GREEN,
               style="rounded,filled", fillcolor=BG,
               color=GREEN, penwidth="1.2")
        b.node("k_handler",  "HandlerRegistry",
               color=GREEN, fontcolor=GREEN,
               style="filled,rounded", fillcolor=SURFACE1, fontsize="9")
        b.node("k_link",     "LinkRegistry",
               color=GREEN, fontcolor=GREEN,
               style="filled,rounded", fillcolor=SURFACE1, fontsize="9")
        b.node("k_security", "SecurityRegistry",
               color=GREEN, fontcolor=GREEN,
               style="filled,rounded", fillcolor=SURFACE1, fontsize="9")
        b.node("k_ext",      "ExtensionRegistry",
               color=GREEN, fontcolor=GREEN,
               style="filled,rounded", fillcolor=SURFACE1, fontsize="9")
        b.node("k_chan",     "SignalChannel<…>",
               color=GREEN, fontcolor=GREEN,
               style="filled,rounded", fillcolor=SURFACE1, fontsize="9")
        b.node("k_conn",     "ConnectionRegistry",
               color=GREEN, fontcolor=GREEN,
               style="filled,rounded", fillcolor=SURFACE1, fontsize="9")
        b.node("k_metrics",  "Counter store",
               color=GREEN, fontcolor=GREEN,
               style="filled,rounded", fillcolor=SURFACE1, fontsize="9")
        b.node("k_config",   "Config tree",
               color=GREEN, fontcolor=GREEN,
               style="filled,rounded", fillcolor=SURFACE1, fontsize="9")

    # Route the right primitive to the right registry
    g.edge("register",         "k_handler",  color=BLUE,
           label="kind=HANDLER", fontcolor=BLUE, fontsize="8")
    g.edge("register",         "k_link",     color=BLUE,
           label="kind=LINK",    fontcolor=BLUE, fontsize="8")
    g.edge("register_security","k_security", color=BLUE)
    g.edge("register_extension","k_ext",     color=BLUE)
    g.edge("subscribe",        "k_chan",     color=GREEN)
    g.edge("for_each",         "k_conn",     color=TEAL)
    g.edge("iterate_counters", "k_metrics",  color=TEAL)
    g.edge("config_get",       "k_config",   color=YELLOW)
    g.edge("get_lookups",      "k_conn",     color=YELLOW)

    # Discipline note — slot count auto-filled from facts so the
    # number never drifts behind sdk/host_api.h.
    _f = load_facts("host_api")
    _n = _f.get("named_slots") or "?"
    _r = _f.get("reserved_slots") or 8
    g.node("discipline",
           "Slot discipline:\n"
           "  · single ABI slot per primitive shape\n"
           "  · KIND enum (or channel id, or type tag) selects routing\n"
           "  · adding a new kind = enum value + kernel side; ABI stable\n"
           f"  · {_n} functional slots on host_api_t today + {_r} reserved\n"
           "History: pre-RC dedupe 41 → 21 KIND-tagged; post-RC growth\n"
           "re-introduced notify_*, key/sign, cap-blob and send_to\n"
           f"families → {_n} today.",
           shape="note", color=SURFACE2, fontcolor=BORDER,
           style="filled", fillcolor="#181825", fontsize="9")
    g.edge("k_config", "discipline", style="invis")

    g.render(str(OUT / "host_api_kinds"), cleanup=True)


# ═════════════════════════════════════════════════════════════════════════════
# 18. Composer extension surface — bit-63 kComposerIdBit dispatch
# ═════════════════════════════════════════════════════════════════════════════

def gen_composer_extension():
    g = graphviz.Digraph("composer_extension", format="svg",
                         **base_attrs())
    g.attr(rankdir="LR", nodesep="0.4", ranksep="0.55")

    g.node("plugin", "Link plugin (e.g. gn.link.tcp, gn.link.ice)\n"
                     "exports composer surface through\n"
                     "the extension vtable (gn_link_api_s)",
           color=GREEN, fontcolor=GREEN, fillcolor=SURFACE1,
           shape="box", fontsize="10")

    methods = [
        ("composer_listen",
         "open a server-side socket for a uri"),
        ("composer_connect",
         "open a client-side socket; conn-id returned\n"
         "with kComposerIdBit (bit-63) set"),
        ("composer_subscribe_data",
         "register per-conn inbound callback;\n"
         "kernel routes by conn-id top-bit"),
        ("composer_subscribe_accept",
         "register accept-bus callback;\n"
         "fired when peer connects to a listener"),
        ("composer_listen_port",
         "introspect the ephemeral port the\n"
         "listen socket was bound to"),
    ]
    for name, doc in methods:
        g.node(name, f"{name}\n{doc}",
               color=BLUE, fontcolor=BLUE, fillcolor=SURFACE1,
               shape="box", fontsize="9")
        g.edge("plugin", name, color=BORDER)

    g.node("dispatch",
           "Inbound dispatch\n"
           "  · conn-id bit-63 set?\n"
           "      → composer fan-out (plugin's per-cid map)\n"
           "  · clear?\n"
           "      → kernel registry / gn_handler_vtable",
           color=LAVENDER, fontcolor=LAVENDER, fillcolor=SURFACE1,
           shape="box", fontsize="9")
    g.edge("composer_subscribe_data", "dispatch", color=TEAL,
           label="data path")
    g.edge("composer_subscribe_accept", "dispatch", color=TEAL,
           label="accept path")

    g.node("note",
           "Why bit-63?\n"
           "  · conn ids are 63-bit ascending integers\n"
           "    (top bit was always zero before the composer landed)\n"
           "  · kComposerIdBit gives a no-cost discriminator without\n"
           "    growing host_api_t with a parallel registry",
           shape="note", color=SURFACE2, fontcolor=BORDER,
           style="filled", fillcolor="#181825", fontsize="9")
    g.edge("dispatch", "note", style="invis")

    g.render(str(OUT / "composer_extension"), cleanup=True)


# ═════════════════════════════════════════════════════════════════════════════
# 19. TURN stream framing — RFC 5389 §7.2.2 over TCP / TLS
# ═════════════════════════════════════════════════════════════════════════════

def gen_turn_stream_framing():
    g = graphviz.Digraph("turn_stream_framing", format="svg",
                         **base_attrs())
    g.attr(rankdir="TB", nodesep="0.4", ranksep="0.5")

    g.node("carrier",
           "Stream carrier\n"
           "  · gn.link.tcp  (turn:)\n"
           "  · gn.link.tls  (turns:)\n"
           "selected by ICE session per precedence: TLS > TCP > UDP",
           color=GREEN, fontcolor=GREEN, fillcolor=SURFACE1,
           shape="box", fontsize="10")

    g.node("encode",
           "encode_stream_frame(payload, out)\n"
           "  · reject if payload.size > 65535\n"
           "  · append uint16 big-endian length\n"
           "  · append payload bytes",
           color=BLUE, fontcolor=BLUE, fillcolor=SURFACE1,
           shape="box", fontsize="9")
    g.edge("carrier", "encode", color=BORDER, label="outbound")

    g.node("decode",
           "try_take_stream_frame(buf, out)\n"
           "  · need at least 2 bytes for length prefix\n"
           "  · read uint16 BE → frame size N\n"
           "  · need 2 + N bytes total\n"
           "  · hand N bytes to dispatch_inbound_message,\n"
           "    keep tail in buf for the next call",
           color=PEACH, fontcolor=PEACH, fillcolor=SURFACE1,
           shape="box", fontsize="9")
    g.edge("carrier", "decode", color=BORDER, label="inbound")

    g.node("dispatch",
           "dispatch_inbound_message(bytes)\n"
           "  · first byte ∈ {0x00, 0x01} → STUN header → STUN branch\n"
           "  · first byte ∈ {0x40 .. 0x4f} → ChannelData → fast path\n"
           "  · otherwise → drop, log warning",
           color=LAVENDER, fontcolor=LAVENDER, fillcolor=SURFACE1,
           shape="box", fontsize="9")
    g.edge("decode", "dispatch", color=TEAL)

    g.node("note",
           "Stream framing rationale\n"
           "  · TCP and TLS are byte streams; STUN messages have no\n"
           "    intrinsic boundary, so a length prefix is mandatory\n"
           "    per RFC 5389 §7.2.2 / RFC 5766 §11.6\n"
           "  · UDP needs no framing — each datagram is one message",
           shape="note", color=SURFACE2, fontcolor=BORDER,
           style="filled", fillcolor="#181825", fontsize="9")
    g.edge("dispatch", "note", style="invis")

    g.render(str(OUT / "turn_stream_framing"), cleanup=True)


# ═════════════════════════════════════════════════════════════════════════════
# 20. QUIC carrier dispatch — detect_carrier_scheme(suffix)
# ═════════════════════════════════════════════════════════════════════════════

def gen_quic_carrier_dispatch():
    g = graphviz.Digraph("quic_carrier_dispatch", format="svg",
                         **base_attrs())
    g.attr(rankdir="LR", nodesep="0.45", ranksep="0.55")

    g.node("dial",
           "gn.link.quic\n"
           "dial(\"quic://<suffix>\")",
           color=GREEN, fontcolor=GREEN, fillcolor=SURFACE1,
           shape="box", fontsize="10")

    g.node("detect",
           "detect_carrier_scheme(suffix)\n"
           "  · 64 hex chars (peer-pk hex)?\n"
           "  · else (host:port)?",
           color=BLUE, fontcolor=BLUE, fillcolor=SURFACE1,
           shape="box", fontsize="9")
    g.edge("dial", "detect", color=BORDER)

    g.node("ice", "gn.link.ice carrier\n"
                  "  · STUN/TURN candidate gather\n"
                  "  · ICE checks, nominate\n"
                  "  · QUIC over the nominated pair",
           color=TEAL, fontcolor=TEAL, fillcolor=SURFACE1,
           shape="box", fontsize="9")
    g.node("udp", "gn.link.udp carrier\n"
                  "  · plain UDP socket\n"
                  "  · QUIC handshake over host:port",
           color=YELLOW, fontcolor=YELLOW, fillcolor=SURFACE1,
           shape="box", fontsize="9")
    g.edge("detect", "ice", color=GREEN, label="hex")
    g.edge("detect", "udp", color=YELLOW, label="host:port")

    g.node("note",
           "Status\n"
           "  · route detection: GREEN (3 smoke tests in\n"
           "    test_quic.cpp::IceCarrierBridge)\n"
           "  · end-to-end QUIC over nominated ICE pair: PENDING\n"
           "    (needs signaling extraction API from IceLink — see\n"
           "    project_goodnet_post_compact memory)",
           shape="note", color=SURFACE2, fontcolor=BORDER,
           style="filled", fillcolor="#181825", fontsize="9")
    g.edge("ice", "note", style="invis")
    g.edge("udp", "note", style="invis")

    g.render(str(OUT / "quic_carrier_dispatch"), cleanup=True)


# ═════════════════════════════════════════════════════════════════════════════
# 21. Handler / link / security / extension kinds — fact-driven
# ═════════════════════════════════════════════════════════════════════════════

def gen_handler_kinds():
    g = graphviz.Digraph("handler_kinds", format="svg", **base_attrs())
    g.attr(rankdir="LR", nodesep="0.4", ranksep="0.55")

    facts_map = {
        "Handler":           ("handler_vtable", GREEN),
        "Link":              ("link_vtable", BLUE),
        "Security":          ("security_vtable", MAUVE),
        "Link extension":    ("extension_link", TEAL),
    }

    g.node("registry",
           "host_api->register_vtable(kind, meta, vtable, self)\n"
           "single entry point; kind selects family;\n"
           "returned id encodes the kind in its top 4 bits",
           color=LAVENDER, fontcolor=LAVENDER, fillcolor=SURFACE1,
           shape="box", fontsize="10")

    for kind, (fact_name, color) in facts_map.items():
        f = load_facts(fact_name)
        slots = [s["name"] for s in (f.get("slots") or [])]
        head = ", ".join(slots[:4])
        tail = f"  + {len(slots) - 4} more" if len(slots) > 4 else ""
        n = f.get("named_slots", len(slots))
        r = f.get("reserved_slots", "?")
        label = (
            f"{kind} vtable ({f.get('struct','?')})\n"
            f"{n} slots + {r} reserved\n"
            f"{head}{tail}"
        )
        nid = kind.lower().replace(" ", "_")
        g.node(nid, label,
               color=color, fontcolor=color, fillcolor=SURFACE1,
               shape="box", fontsize="9")
        g.edge("registry", nid, color=BORDER)

    g.node("note",
           "Slot counts auto-extracted from docs/_facts/*.yaml\n"
           "(libclang AST walk over sdk/*.h, run by\n"
           "tools/livedoc.py). Drift impossible — header changes\n"
           "land in the diagram next time make livedoc runs.",
           shape="note", color=SURFACE2, fontcolor=BORDER,
           style="filled", fillcolor="#181825", fontsize="9")
    g.edge("link_extension", "note", style="invis")

    g.render(str(OUT / "handler_kinds"), cleanup=True)


# ═════════════════════════════════════════════════════════════════════════════
# 22. Security pipeline — Noise XX/IK + attestation + trust class
# ═════════════════════════════════════════════════════════════════════════════

def gen_security_pipeline():
    g = graphviz.Digraph("security_pipeline", format="svg",
                         **base_attrs())
    g.attr(rankdir="TB", nodesep="0.35", ranksep="0.45")

    stages = [
        ("dial",     "dial(uri)",                        GREEN),
        ("conn",     "host_api->notify_connect()\n"
                     "kernel creates conn id +\n"
                     "SecuritySession (Handshake phase)",  BLUE),
        ("kick",     "host_api->kick_handshake(conn)\n"
                     "initiator drives first Noise message", LAVENDER),
        ("noise_xx", "Noise XX (3 messages)\n"
                     "  · e\n"
                     "  · e, ee, s, es\n"
                     "  · s, se\n"
                     "Noise IK is a wrapper that reuses\n"
                     "the same pattern enum for known-pk", TEAL),
        ("transit",  "SecuritySession → Transport phase\n"
                     "  · pending plaintexts drained\n"
                     "  · noise_*_cipher state holds N_send / N_recv",
                                                          PEACH),
        ("attest",   "Attestation exchange (232 B per side)\n"
                     "AttestationDispatcher verifies remote payload\n"
                     "pin_device_pk on first attestation",  MAUVE),
        ("upgrade",  "Trust upgraded: Untrusted → Peer\n"
                     "TRUST_UPGRADED event fired\n"
                     "Loopback / IntraNode set on connect\n"
                     "(immutable, not upgraded)",            YELLOW),
        ("ready",    "Connection READY\n"
                     "handler.on_inbound dispatches normally",
                                                          GREEN),
    ]
    for nid, label, color in stages:
        g.node(nid, label, color=color, fontcolor=color,
               fillcolor=SURFACE1, shape="box", fontsize="9")
    for (a, _, _), (b, _, _) in zip(stages, stages[1:]):
        g.edge(a, b, color=BORDER)

    g.node("note",
           "Touchpoints with host_api\n"
           "  · kick_handshake(conn) — drives initiator's first msg\n"
           "  · notify_inbound_bytes(conn, bytes) — feeds the cipher\n"
           "  · subscribe_conn_state(...) — emits TRUST_UPGRADED",
           shape="note", color=SURFACE2, fontcolor=BORDER,
           style="filled", fillcolor="#181825", fontsize="9")
    g.edge("ready", "note", style="invis")

    g.render(str(OUT / "security_pipeline"), cleanup=True)


# ═════════════════════════════════════════════════════════════════════════════
# 23. Link carrier family — plugins/links/* inventory
# ═════════════════════════════════════════════════════════════════════════════

def gen_link_carriers():
    g = graphviz.Digraph("link_carriers", format="svg", **base_attrs())
    g.attr(rankdir="TB", nodesep="0.35", ranksep="0.4")

    g.node("link_api",
           "gn_link_vtable_s (sdk/link.h)\n"
           "kernel-facing surface every link plugin implements",
           color=LAVENDER, fontcolor=LAVENDER, fillcolor=SURFACE1,
           shape="box", fontsize="10")

    plugins_dir = ROOT / "plugins" / "links"
    carriers: list[tuple[str, str]] = []
    if plugins_dir.is_dir():
        for p in sorted(plugins_dir.iterdir()):
            if not p.is_dir() or p.name.startswith("."):
                continue
            carriers.append((p.name, f"gn.link.{p.name}"))

    if not carriers:
        carriers = [
            ("udp", "gn.link.udp"),
            ("tcp", "gn.link.tcp"),
            ("ws",  "gn.link.ws"),
            ("tls", "gn.link.tls"),
            ("quic", "gn.link.quic"),
            ("ipc", "gn.link.ipc"),
            ("ice", "gn.link.ice"),
        ]

    # Hard-coded notes — these stay in source because they describe
    # design intent, not slot counts. They're verified manually
    # against the plugin READMEs.
    notes = {
        "udp":  "datagram; no framing; ≤8 KiB single-shot limit",
        "tcp":  "byte stream; TURN-over-TCP framing (16-bit BE len)",
        "ws":   "RFC 6455 WebSocket framing; mask handling per spec",
        "tls":  "stream framed like tcp; TURNS:// over TLS 1.3",
        "quic": "ngtcp2-backed; carrier scheme detect:\n"
                "  · 64 hex chars → gn.link.ice\n"
                "  · else → gn.link.udp",
        "ipc":  "AF_UNIX stream / datagram; Loopback trust",
        "ice":  "STUN/TURN candidate gather, ICE checks,\n"
                "Triggered + Regular Nomination, IPv6 happy-eyeballs",
    }

    for short, full in carriers:
        body = f"{full}\n{notes.get(short, '')}"
        composer = (plugins_dir / short / "include").is_dir()  # heuristic
        color = TEAL if composer else GREEN
        g.node(short, body, color=color, fontcolor=color,
               fillcolor=SURFACE1, shape="box", fontsize="9")
        g.edge("link_api", short, color=BORDER)

    g.node("note",
           "Composer surface (subset of plugins) — see\n"
           "composer_extension.svg for the bit-63 dispatch detail.\n"
           "Carrier list discovered from plugins/links/ at\n"
           "diagram-gen time; new plugins appear here automatically.",
           shape="note", color=SURFACE2, fontcolor=BORDER,
           style="filled", fillcolor="#181825", fontsize="9")
    g.edge(carriers[-1][0], "note", style="invis")

    g.render(str(OUT / "link_carriers"), cleanup=True)


# ═════════════════════════════════════════════════════════════════════════════
# Entry point
# ═════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    gen_architecture()
    gen_kernel_fsm()
    gen_connection_fsm()
    gen_message_path_inbound()
    gen_message_path_outbound()
    gen_noise_handshake()
    gen_dispatch_chain()
    gen_sharded_registry()
    gen_cas_backpressure()
    gen_dlopen_pipeline()
    gen_c_cpp_bridging()
    gen_nonce_window()
    gen_signal_bus()
    gen_connection_lifecycle()
    gen_extension_query()
    gen_plugin_separation()
    gen_host_api_kinds()
    gen_composer_extension()
    gen_turn_stream_framing()
    gen_quic_carrier_dispatch()
    gen_handler_kinds()
    gen_security_pipeline()
    gen_link_carriers()
