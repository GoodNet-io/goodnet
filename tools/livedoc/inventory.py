"""Plugin tree walker — discovers link / handler / security /
extension plugins, returns inventories the renderers can consume.

Each plugin lives in its own standalone git checkout under
`plugins/<kind>/<name>/`. The walker reads each plugin's
top-level `README.md` (if present) for a one-line description, and
greps the plugin source for scheme strings and composer-surface
exports.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
PLUGINS_ROOT = REPO_ROOT / "plugins"

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
             "--exclude-dir=.git",
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


def discover_all() -> dict[str, list[dict]]:
    return {
        "links":      discover_links(),
        "handlers":   discover_handlers(),
        "security":   discover_security(),
        "extensions": discover_extensions(),
    }
