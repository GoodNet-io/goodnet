"""Roadmap-to-tree status resolver.

Reads `docs/ROADMAP.en.md`, extracts every `- **Feature**` bullet,
looks each one up in `tools/livedoc/roadmap_map.yaml`, evaluates
the mapped rule against the working tree, and emits
`docs/_facts/roadmap_status.yaml` with `done / partial / missing`
status plus a one-line evidence trace per feature.

The map is explicit, not heuristic — false positives (a feature
matched on a coincidental file name) would be worse than a stale
table, so the resolver only honors what the map declares.
"""

from __future__ import annotations

import re
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).resolve().parents[2]
ROADMAP_PATH = REPO_ROOT / "docs" / "ROADMAP.en.md"
MAP_PATH = Path(__file__).with_name("roadmap_map.yaml")
FACTS_PATH = REPO_ROOT / "docs" / "_facts" / "roadmap_status.yaml"

BULLET_RE = re.compile(r"^- \*\*([^*]+)\*\*", re.MULTILINE)
# Bullets after "## Non-goals" are explicitly excluded scope; the
# roadmap renders them as boundary markers, not tracked work.
NON_GOALS_RE = re.compile(r"^##\s+Non-goals\b", re.MULTILINE)


@dataclass
class Feature:
    name: str
    status: str          # done | partial | missing
    evidence: str


# ── Rule evaluation ─────────────────────────────────────────────────

def _grep_repo(pattern: str, *, paths: list[str]) -> str | None:
    """Return the first matching `file:line: line` or None.

    Uses ripgrep if available, falls back to grep -rIn. Skips
    .git/, build*/, node_modules/.
    """
    paths = [str(REPO_ROOT / p) for p in paths if (REPO_ROOT / p).exists()]
    if not paths:
        return None
    cmd = [
        "grep", "-rIn", "-m", "1",
        "--include=*.h", "--include=*.hpp",
        "--include=*.c", "--include=*.cpp",
        "--include=*.cc", "--include=*.cmake",
        "--include=CMakeLists.txt", "--include=*.yml",
        "--include=*.yaml", "--include=*.nix",
        "--exclude-dir=.git", "--exclude-dir=build*",
        "--exclude-dir=build-release", "--exclude-dir=node_modules",
        pattern, *paths,
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if r.returncode != 0:
        return None
    return r.stdout.splitlines()[0] if r.stdout else None


def _eval(rule, ctx_hints: list[str]) -> tuple[bool, str]:
    """Return (passes, evidence-string)."""
    if not isinstance(rule, dict):
        return False, "malformed rule"
    if "any" in rule:
        for inner in rule["any"]:
            ok, ev = _eval(inner, ctx_hints)
            if ok:
                return True, ev
        return False, "; ".join(ctx_hints[-3:]) or "no inner rule matched"
    if "all" in rule:
        evs = []
        for inner in rule["all"]:
            ok, ev = _eval(inner, ctx_hints)
            if not ok:
                return False, f"missing: {ev}"
            evs.append(ev)
        return True, "; ".join(evs)
    if "plugin_exists" in rule:
        path = REPO_ROOT / rule["plugin_exists"]
        ok = path.is_dir()
        ev = (f"{rule['plugin_exists']}/ present" if ok
              else f"{rule['plugin_exists']}/ absent")
        ctx_hints.append(ev)
        return ok, ev
    if "file_exists" in rule:
        path = REPO_ROOT / rule["file_exists"]
        ok = path.is_file()
        ev = (f"{rule['file_exists']} present" if ok
              else f"{rule['file_exists']} absent")
        ctx_hints.append(ev)
        return ok, ev
    if "extension_registered" in rule:
        ext = rule["extension_registered"]
        pat = rf"\"{re.escape(ext)}\""
        hit = _grep_repo(pat, paths=["plugins"])
        ok = hit is not None
        ev = (f"extension id {ext!r} registered ({_short(hit)})" if ok
              else f"extension id {ext!r} not registered in plugins/")
        ctx_hints.append(ev)
        return ok, ev
    if "symbol_in_kernel" in rule:
        sym = rule["symbol_in_kernel"]
        hit = _grep_repo(rf"\b{re.escape(sym)}\b",
                         paths=["core", "sdk"])
        ok = hit is not None
        ev = (f"symbol {sym!r} present ({_short(hit)})" if ok
              else f"symbol {sym!r} not found in core/ + sdk/")
        ctx_hints.append(ev)
        return ok, ev
    if "kernel_feature" in rule:
        tok = rule["kernel_feature"]
        hit = _grep_repo(re.escape(tok),
                         paths=["core", "plugins", "tests",
                                ".github", "CMakeLists.txt"])
        ok = hit is not None
        ev = (f"token {tok!r} found ({_short(hit)})" if ok
              else f"token {tok!r} absent")
        ctx_hints.append(ev)
        return ok, ev
    return False, f"unknown rule keys: {sorted(rule)}"


def _short(line: str | None) -> str:
    if not line:
        return ""
    # Trim "/abs/path/to/repo/" prefix for readability.
    s = line.replace(str(REPO_ROOT) + "/", "")
    if len(s) > 80:
        s = s[:77] + "..."
    return s


# ── Public API ──────────────────────────────────────────────────────

def parse_bullets(text: str | None = None) -> list[str]:
    """Return the list of bold-bracketed feature names from ROADMAP.

    Bullets under "## Non-goals" are excluded — the roadmap uses
    that section as a deliberate negative list, not work to track.
    """
    if text is None:
        text = ROADMAP_PATH.read_text()
    cut = NON_GOALS_RE.search(text)
    if cut:
        text = text[: cut.start()]
    return [m.strip() for m in BULLET_RE.findall(text)]


def resolve(name: str, mapping: dict) -> Feature:
    """Apply the mapping rule for one feature; return a Feature."""
    entry = mapping.get(name)
    if not entry:
        return Feature(name=name, status="missing",
                       evidence="no rule in roadmap_map.yaml")
    rule = entry.get("rule")
    ok, evidence = _eval(rule, []) if rule else (False, "no rule")
    if ok:
        return Feature(name=name, status="done", evidence=evidence)
    partial_rule = entry.get("partial_if")
    if partial_rule:
        ok_p, ev_p = _eval(partial_rule, [])
        if ok_p:
            return Feature(
                name=name,
                status="partial",
                evidence=f"{ev_p} (precursor present; full feature pending)",
            )
    return Feature(name=name, status="missing", evidence=evidence)


def compute() -> dict:
    """Resolve every bullet; return dict ready for YAML dump."""
    mapping = yaml.safe_load(MAP_PATH.read_text()).get("features", {})
    bullets = parse_bullets()
    features = [asdict(resolve(name, mapping)) for name in bullets]
    return {"features": features}


def write(path: Path = FACTS_PATH) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = compute()
    path.write_text(yaml.safe_dump(payload, sort_keys=False,
                                    allow_unicode=True))
    return path


def main(argv: list[str]) -> int:
    path = write()
    rel = path.relative_to(REPO_ROOT)
    payload = yaml.safe_load(path.read_text())
    n = len(payload["features"])
    done = sum(1 for f in payload["features"] if f["status"] == "done")
    partial = sum(1 for f in payload["features"] if f["status"] == "partial")
    missing = n - done - partial
    print(
        f"  roadmap status → {rel}  "
        f"({done} done, {partial} partial, {missing} missing)",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
