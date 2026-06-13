"""Plugin tree walker — discovers link / handler / security /
strategy / extension plugins, returns inventories the renderers can
consume.

Each plugin lives in its own standalone git checkout under
`plugins/<kind>/<name>/`. The walker reads each plugin's
top-level `README.md` (if present) for a one-line description, and
greps the plugin source for scheme strings and composer-surface
exports.

In addition to the `plugins/<kind>/` tree, this module also walks
the `bridges/{cpp,python,rust,js}` siblings — those are cross-
language SDK bindings that ship as standalone sub-repos but are
NOT plugins (no vtable, no registry slot). The `bridges` inventory
is emitted as a separate fact file so docs can reference the
binding family alongside the plugin family without conflating
them.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).resolve().parents[2]
PLUGINS_ROOT = REPO_ROOT / "plugins"
BRIDGES_ROOT = REPO_ROOT / "bridges"
FACTS_PATH = REPO_ROOT / "docs" / "_facts" / "bridges_inventory.yaml"

SCHEME_RE = re.compile(r'GN_LINK_SCHEMES?\s*=\s*"([^"]+)"')
COMPOSER_HINT_RE = re.compile(r"composer_(listen|connect|subscribe)")


def _first_paragraph(md_path: Path) -> str:
    if not md_path.is_file():
        return ""
    text = md_path.read_text(errors="ignore")
    # Skip the H1 line + blank, capture first non-empty prose line.
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#") or s.startswith("---"):
            continue
        return s[:140]
    return ""


def _grep_plugin(plugin_dir: Path, pattern: str) -> str | None:
    try:
        r = subprocess.run(
            ["grep", "-rIn", "-m", "1",
             "--include=*.h", "--include=*.hpp",
             "--include=*.c", "--include=*.cpp",
             "--exclude-dir=.git", "--exclude-dir=.claude",
             "--exclude-dir=build", "--exclude-dir=build-release",
             "--exclude-dir=build-asan", "--exclude-dir=build-tsan",
             "--exclude-dir=build-mdns-test",
             pattern, str(plugin_dir)],
            capture_output=True, text=True, timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if r.returncode != 0:
        return None
    return r.stdout.splitlines()[0] if r.stdout else None


def _schemes_for(plugin_dir: Path) -> list[str]:
    hit = _grep_plugin(plugin_dir, r'GN_LINK_SCHEMES\?\s*=\s*"[^"]*"')
    if hit:
        m = SCHEME_RE.search(hit)
        if m:
            return [s.strip() for s in m.group(1).split(",") if s.strip()]
    # Fall back to plugin-dir name as a single scheme hint.
    return [plugin_dir.name]


def _composer_capability(plugin_dir: Path) -> bool:
    return _grep_plugin(plugin_dir, "composer_listen") is not None


def discover_kind(kind: str) -> list[dict]:
    """Discover plugins under plugins/<kind>/<name>/."""
    root = PLUGINS_ROOT / kind
    if not root.is_dir():
        return []
    out = []
    for plugin in sorted(root.iterdir()):
        if not plugin.is_dir():
            continue
        if plugin.name.startswith("."):
            continue
        rel = plugin.relative_to(REPO_ROOT).as_posix()
        entry = {
            "name": plugin.name,
            "path": rel,
            "notes": _first_paragraph(plugin / "README.md"),
        }
        if kind == "links":
            entry["schemes"] = _schemes_for(plugin)
            entry["composer"] = _composer_capability(plugin)
        out.append(entry)
    return out


def discover_links() -> list[dict]:
    return discover_kind("links")


def discover_handlers() -> list[dict]:
    return discover_kind("handlers")


def discover_security() -> list[dict]:
    return discover_kind("security")


def discover_extensions() -> list[dict]:
    return discover_kind("extensions")


def discover_strategies() -> list[dict]:
    return discover_kind("strategies")


def discover_all() -> dict[str, list[dict]]:
    return {
        "links":      discover_links(),
        "handlers":   discover_handlers(),
        "security":   discover_security(),
        "strategies": discover_strategies(),
        "extensions": discover_extensions(),
    }


# ── bridges/ — cross-language SDK bindings ──────────────────────────

# Marker files that disambiguate the binding's host language. Picked
# from each sub-repo's canonical build-system entry point so we don't
# false-positive on a stray header.
_BRIDGE_LANG_MARKERS = {
    "cpp":    ("CMakeLists.txt", "core.hpp"),
    "python": ("pyproject.toml", "setup.py", "setup.cfg"),
    "rust":   ("Cargo.toml",),
    "js":     ("package.json",),
}


def _bridge_lang(bridge_dir: Path) -> str:
    """Best-effort host-language tag for a bridges/<slot>/ sub-repo."""
    for lang, markers in _BRIDGE_LANG_MARKERS.items():
        if bridge_dir.name == lang:
            return lang
        for marker in markers:
            if (bridge_dir / marker).is_file():
                return lang
    return bridge_dir.name


def discover_bridges() -> list[dict]:
    """Enumerate `bridges/<slot>/` sub-repos.

    Each entry mirrors the plugin entry shape: `name`, `path`, and
    `notes` (first prose line of the bridge's `README.md`). The
    `lang` field tags the host language so renderers can group by
    binding family.
    """
    if not BRIDGES_ROOT.is_dir():
        return []
    out: list[dict] = []
    for bridge in sorted(BRIDGES_ROOT.iterdir()):
        if not bridge.is_dir():
            continue
        if bridge.name.startswith("."):
            continue
        rel = bridge.relative_to(REPO_ROOT).as_posix()
        out.append({
            "name":  bridge.name,
            "path":  rel,
            "lang":  _bridge_lang(bridge),
            "notes": _first_paragraph(bridge / "README.md"),
        })
    return out


def collect_bridges() -> dict:
    """Return the dict shape written to `bridges_inventory.yaml`."""
    bridges = discover_bridges()
    return {
        "total":   len(bridges),
        "bridges": bridges,
    }


def write(path: Path | None = None) -> Path:
    """Write the bridges inventory fact file."""
    if path is None:
        path = FACTS_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(collect_bridges(), sort_keys=False,
                                    allow_unicode=True))
    return path


def main(argv: list[str]) -> int:
    p = write()
    rel = p.relative_to(REPO_ROOT)
    d = yaml.safe_load(p.read_text())
    print(
        f"  bridges inventory → {rel}  ({d['total']} bridge sub-repos)",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
