"""Resolve the hand-curated RFC map into a fact file.

The map (`tools/livedoc/rfc_coverage.yaml`) is authoritative — this
resolver only copies it through to `docs/_facts/rfc_coverage.yaml`
after a sanity check that referenced implementation paths actually
exist in the working tree (entries that point to missing paths are
downgraded with a `(stale)` note in `notes`, so a reader still sees
the row but knows the citation is suspect).
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).resolve().parents[2]
MAP_PATH = Path(__file__).with_name("rfc_coverage.yaml")
FACTS_PATH = REPO_ROOT / "docs" / "_facts" / "rfc_coverage.yaml"


def compute() -> dict:
    src = yaml.safe_load(MAP_PATH.read_text()) or {}
    rows = src.get("rfcs", [])
    out = []
    for r in rows:
        impl = r.get("implementation") or ""
        if impl and not (REPO_ROOT / impl).exists():
            r = dict(r)
            r["notes"] = (r.get("notes", "") + " (stale path)").strip()
        out.append(r)
    return {"rfcs": out}


def write(path: Path = FACTS_PATH) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(compute(), sort_keys=False,
                                    allow_unicode=True))
    return path


def main(argv: list[str]) -> int:
    p = write()
    rel = p.relative_to(REPO_ROOT)
    d = yaml.safe_load(p.read_text())
    print(f"  rfc coverage → {rel}  ({len(d['rfcs'])} RFC entries)",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
