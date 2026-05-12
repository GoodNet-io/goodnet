#!/usr/bin/env python3
"""Refresh source-derived facts and inject into hand-written docs.

Usage:
    python3 tools/livedoc.py --all         # full refresh
    python3 tools/livedoc.py --abi         # ABI facts only
    python3 tools/livedoc.py --roadmap     # roadmap status only
    python3 tools/livedoc.py --diagrams    # SVG + canvas only
    python3 tools/livedoc.py --inject      # markdown rewrites only
    python3 tools/livedoc.py --check       # exit non-zero if drift

Reads:  sdk/*.h, plugins/**, docs/ROADMAP.en.md,
        tools/livedoc/roadmap_map.yaml
Writes: docs/_facts/*.yaml, docs/img/*.svg, docs/architecture.canvas,
        injects content between livedoc markers in docs/**/*.md

Idempotent — running twice in a row produces zero git diff when the
working tree state has not changed.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# Make the package importable regardless of cwd.
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import yaml  # noqa: E402

from livedoc import (  # noqa: E402
    abi_extract,
    config_keys,
    inventory,
    markdown_inject,
    metrics_catalog,
    renderers,
    rfc_coverage,
    roadmap_status,
    test_inventory,
)


REPO_ROOT = HERE.parent
DOCS_ROOT = REPO_ROOT / "docs"
FACTS_ROOT = DOCS_ROOT / "_facts"


def step_abi() -> None:
    abi_extract.write_all()


def step_roadmap() -> None:
    roadmap_status.write()


def step_catalogs() -> None:
    """Refresh fact-files that grep the source tree directly."""
    metrics_catalog.write()
    config_keys.write()
    rfc_coverage.write()
    test_inventory.write()


def _load_facts() -> dict:
    """Load every fact file into a single dict for the renderers."""
    out = {}
    for path in sorted(FACTS_ROOT.glob("*.yaml")):
        out[path.stem] = yaml.safe_load(path.read_text())
    return out


def _build_regions(facts: dict) -> dict[str, str]:
    """Pre-render every named region body keyed by marker name."""
    plugins = inventory.discover_all()
    regions = {
        "host_api_summary":       renderers.host_api_summary(facts["host_api"]),
        "host_api_slots":         renderers.host_api_slots(facts["host_api"]),
        "host_api_size":          renderers.abi_size(facts["host_api"]),
        "link_vtable_slots":      renderers.vtable_slots(
                                       facts["link_vtable"],
                                       title="Link plugin vtable"),
        "handler_vtable_slots":   renderers.vtable_slots(
                                       facts["handler_vtable"],
                                       title="Handler vtable"),
        "security_vtable_slots":  renderers.vtable_slots(
                                       facts["security_vtable"],
                                       title="Security provider vtable"),
        "extension_surface":      renderers.extension_surface(
                                       facts["extension_link"]),
        "roadmap_status_table":   renderers.roadmap_status_table(
                                       facts["roadmap_status"]),
        "link_carriers_list":     renderers.link_carriers_list(
                                       plugins["links"]),
        "plugin_inventory":       renderers.plugin_inventory(plugins),
        "metrics_catalog_table":  renderers.metrics_catalog_table(
                                       facts.get("metrics_catalog", {})),
        "config_keys_table":      renderers.config_keys_table(
                                       facts.get("config_keys", {})),
        "rfc_coverage_table":     renderers.rfc_coverage_table(
                                       facts.get("rfc_coverage", {})),
        "test_inventory_table":   renderers.test_inventory_table(
                                       facts.get("test_inventory", {})),
    }
    test_counts = (facts.get("test_inventory") or {}).get(
        "by_plugin", {},
    )
    # Diagram embeds — one marker per SVG. Captions short enough to
    # land under the image without scrolling. Add new SVGs here so
    # any prose doc can embed them via <!-- livedoc:embed_<name> -->.
    embed_specs = {
        "architecture":          "Kernel ABI surface, registries, and the eight plugin slots.",
        "kernel_fsm":            "Kernel lifecycle: created → started → stopped → destroyed.",
        "connection_fsm":        "Per-connection state machine through handshake to ready.",
        "connection_lifecycle":  "End-to-end conn lifetime: link → noise → attestation → ready.",
        "message_inbound":       "Inbound envelope path from socket bytes to handler dispatch.",
        "message_outbound":      "Outbound envelope path from host_api->send to wire bytes.",
        "noise_handshake":       "Noise XX three-message handshake with key derivation steps.",
        "security_pipeline":     "Security pipeline: dial → notify_connect → Noise → attestation → trust upgrade.",
        "dispatch_chain":        "Handler priority chain and propagation control.",
        "sharded_registry":      "Sharded registry layout: per-shard mutex + lock-free lookup.",
        "cas_backpressure":      "Backpressure CAS loop for per-connection drain scheduling.",
        "dlopen_pipeline":       "Plugin dlopen pipeline: discover → load → init → register.",
        "plugin_separation":     "Plugin process / git boundary — each plugin in its own checkout.",
        "c_cpp_bridging":        "C ABI ↔ C++ implementation bridging across the SDK boundary.",
        "nonce_window":          "Anti-replay nonce window in the Noise transport phase.",
        "signal_bus":            "Signal-bus fanout for OFFER / ANSWER / EOC.",
        "extension_query":       "Extension query path: query_extension_checked → vtable handoff.",
        "host_api_kinds":        "host_api_t KIND-tagged register/unregister discipline.",
        "composer_extension":    "Composer surface dispatch via bit-63 kComposerIdBit on conn-id.",
        "turn_stream_framing":   "TURN-over-TCP / TLS 16-bit length-prefix framing path.",
        "quic_carrier_dispatch": "QUIC carrier scheme detect: 64-hex → ICE, else → UDP.",
        "handler_kinds":         "Four vtable families: handler, link, security, link-extension.",
        "link_carriers":         "Link plugin family overview discovered from plugins/links/.",
    }
    for name, caption in embed_specs.items():
        regions[f"embed_{name}"] = renderers.embed_diagram(
            name, caption=caption,
        )
    # Per-plugin page bodies — one per discovered plugin. Marker
    # name is `plugin_page_<kind>_<name>`. Test count comes from
    # the inventory `by_plugin` map.
    for kind, entries in plugins.items():
        for entry in entries:
            marker = f"plugin_page_{kind}_{entry['name']}"
            key = f"{kind}/{entry['name']}"
            regions[marker] = renderers.plugin_page(
                entry, kind=kind, test_count=test_counts.get(key, 0),
            )
    return regions


def step_inject() -> list[Path]:
    facts = _load_facts()
    regions = _build_regions(facts)
    return markdown_inject.refresh_tree(DOCS_ROOT, regions)


def step_diagrams() -> None:
    """Spawn gen_diagrams.py + gen_canvas.py inside the same shell.

    Both scripts read docs/_facts/*.yaml, so step_abi() must run
    first. We invoke them as subprocesses so their argparse +
    main() blocks behave like a user CLI run.
    """
    for script in ("gen_diagrams.py", "gen_canvas.py"):
        path = HERE / script
        r = subprocess.run(
            [sys.executable, str(path)],
            cwd=REPO_ROOT,
            check=False,
        )
        if r.returncode != 0:
            raise SystemExit(f"livedoc: {script} exited {r.returncode}")


def run_all() -> list[Path]:
    step_abi()
    step_roadmap()
    step_catalogs()
    step_diagrams()
    return step_inject()


def run_check() -> int:
    """Re-render every output in a tmp tree; compare to the repo.

    Exits 0 if every generated file matches; non-zero otherwise so
    a future pre-commit hook can gate on this without extra glue.
    """
    with tempfile.TemporaryDirectory(prefix="livedoc-check-") as td:
        td_path = Path(td)
        # We can't redirect every output target cheaply, so the
        # check copies the docs tree, runs livedoc against the
        # copy, and diffs.
        shadow = td_path / "docs"
        shutil.copytree(DOCS_ROOT, shadow)
        # Run livedoc with DOCS_ROOT temporarily pointed at the
        # shadow. Each step module reads/writes through module-
        # level paths, so we have to monkeypatch them.
        _retarget(shadow)
        try:
            run_all()
            diff = subprocess.run(
                ["diff", "-r", str(DOCS_ROOT), str(shadow)],
                capture_output=True, text=True,
            )
        finally:
            _retarget(DOCS_ROOT)
        if diff.returncode == 0:
            print("livedoc check: clean (no drift)", file=sys.stderr)
            return 0
        print("livedoc check: drift detected", file=sys.stderr)
        print(diff.stdout, file=sys.stderr)
        return 1


def _retarget(docs: Path) -> None:
    """Point every module's DOCS-derived path at `docs`."""
    abi_extract.FACTS_ROOT = docs / "_facts"
    roadmap_status.FACTS_PATH = docs / "_facts" / "roadmap_status.yaml"
    roadmap_status.ROADMAP_PATH = docs / "ROADMAP.en.md"
    global FACTS_ROOT, DOCS_ROOT  # noqa: PLW0603
    FACTS_ROOT = docs / "_facts"
    DOCS_ROOT = docs


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--all", action="store_true")
    p.add_argument("--abi", action="store_true")
    p.add_argument("--roadmap", action="store_true")
    p.add_argument("--catalogs", action="store_true",
                   help="metrics + config keys + RFC coverage")
    p.add_argument("--diagrams", action="store_true")
    p.add_argument("--inject", action="store_true")
    p.add_argument("--check", action="store_true")
    a = p.parse_args(argv)

    if a.check:
        return run_check()

    if not any([a.all, a.abi, a.roadmap, a.catalogs,
                a.diagrams, a.inject]):
        a.all = True

    if a.all or a.abi:
        step_abi()
    if a.all or a.roadmap:
        step_roadmap()
    if a.all or a.catalogs:
        step_catalogs()
    if a.all or a.diagrams:
        step_diagrams()
    if a.all or a.inject:
        changed = step_inject()
        if changed:
            print(f"  injected into {len(changed)} markdown files",
                  file=sys.stderr)
            for p in changed:
                print(f"    - {p.relative_to(REPO_ROOT)}",
                      file=sys.stderr)
        else:
            print("  markdown injection: no changes", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
