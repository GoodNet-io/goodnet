"""Walk the test tree — kernel + per-plugin — and tally cases.

Counts every gtest / rapidcheck case-defining macro across:

  * `tests/` at the repo root (kernel-side tests)
  * `plugins/<kind>/<name>/tests/` for each plugin's own suite

Output: `docs/_facts/test_inventory.yaml`:

```yaml
total: 1108
groups:
  - tree: kernel
    count: 1041
    files: 87
  - tree: plugins/links/ice
    count: 47
    files: 5
  - ...
```

Plus `by_plugin: {<kind>/<name>: count}` for `plugin_page` lookups.
"""

from __future__ import annotations

import re
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).resolve().parents[2]
FACTS_PATH = REPO_ROOT / "docs" / "_facts" / "test_inventory.yaml"

# Match the gtest + rapidcheck case-defining macros. Word-boundary
# prefix so we don't grab `MY_TEST(` or similar custom macros that
# wrap the real ones — the inventory tracks the canonical surface.
_CASE_RE = re.compile(
    r"\b(TEST|TEST_F|TEST_P|TYPED_TEST|TYPED_TEST_P|"
    r"RC_GTEST_PROP|RC_GTEST_FIXTURE_PROP)\s*\("
)


def _count_cases(path: Path) -> int:
    try:
        text = path.read_text(errors="ignore")
    except OSError:
        return 0
    return len(_CASE_RE.findall(text))


def _walk(root: Path) -> tuple[int, int]:
    """Return (case_count, file_count) under `root`."""
    cases, files = 0, 0
    if not root.is_dir():
        return 0, 0
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix not in (".cpp", ".cc", ".c", ".hpp", ".h"):
            continue
        # Skip vendored / build outputs.
        if any(seg in (".git", "build", "build-release",
                       "build-asan", "build-tsan", "__pycache__")
               for seg in p.parts):
            continue
        n = _count_cases(p)
        if n:
            cases += n
            files += 1
    return cases, files


def collect() -> dict:
    groups: list[dict] = []
    by_plugin: dict[str, int] = {}

    # Kernel tests.
    kc, kf = _walk(REPO_ROOT / "tests")
    if kc or kf:
        groups.append({
            "tree": "kernel",
            "count": kc,
            "files": kf,
        })

    # Per-plugin tests.
    plug_root = REPO_ROOT / "plugins"
    if plug_root.is_dir():
        for kind in sorted(plug_root.iterdir()):
            if not kind.is_dir() or kind.name.startswith("."):
                continue
            for plugin in sorted(kind.iterdir()):
                if not plugin.is_dir() or plugin.name.startswith("."):
                    continue
                pc, pf = _walk(plugin / "tests")
                if pc or pf:
                    tree = f"plugins/{kind.name}/{plugin.name}"
                    groups.append({
                        "tree": tree,
                        "count": pc,
                        "files": pf,
                    })
                    by_plugin[f"{kind.name}/{plugin.name}"] = pc

    total = sum(g["count"] for g in groups)
    return {
        "total": total,
        "groups": groups,
        "by_plugin": by_plugin,
    }


def write(path: Path = FACTS_PATH) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(collect(), sort_keys=False,
                                    allow_unicode=True))
    return path


def main(argv: list[str]) -> int:
    p = write()
    rel = p.relative_to(REPO_ROOT)
    d = yaml.safe_load(p.read_text())
    print(
        f"  test inventory → {rel}  "
        f"({d['total']} cases across {len(d['groups'])} trees)",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
