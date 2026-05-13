"""Walk core/ and plugins/ for emit_counter / iterate_counters call sites.

Each counter name lives as a string literal at exactly one
emit-call site (or a handful). The walker collects all unique names
plus the file:line pairs that emit them — readers can navigate
from `docs/contracts/metrics.en.md` straight to the kernel /
plugin call that originates each value.

Output: `docs/_facts/metrics_catalog.yaml`:

```yaml
counters:
  - name: drop.queue_hard_cap
    family: drop
    sources:
      - file: core/...
        line: 551
```
"""

from __future__ import annotations

import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).resolve().parents[2]
FACTS_PATH = REPO_ROOT / "docs" / "_facts" / "metrics_catalog.yaml"

# emit_counter(host_ctx, "name") | iterate_counters(...) — name is
# the *first* string literal in the call. We don't try to parse C++
# fully; one literal match per line is enough for static call sites.
_EMIT_RE = re.compile(
    r'(emit_counter|iterate_counters)\s*\([^"]*"([^"]+)"',
)


def _grep_lines() -> list[tuple[str, int, str]]:
    paths = [p for p in ("core", "plugins", "apps")
             if (REPO_ROOT / p).is_dir()]
    if not paths:
        return []
    cmd = [
        "grep", "-rIn",
        "--include=*.cpp", "--include=*.hpp",
        "--include=*.c", "--include=*.h",
        "--exclude-dir=.git", "--exclude-dir=build",
        "--exclude-dir=build-release", "--exclude-dir=tests",
        "emit_counter\\|iterate_counters",
        *paths,
    ]
    try:
        r = subprocess.run(
            cmd, cwd=REPO_ROOT, capture_output=True, text=True,
            timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if r.returncode not in (0, 1):  # 1 = no match
        return []
    out: list[tuple[str, int, str]] = []
    for line in r.stdout.splitlines():
        # `path:N:content`
        parts = line.split(":", 2)
        if len(parts) != 3:
            continue
        path, n, content = parts
        try:
            out.append((path, int(n), content))
        except ValueError:
            continue
    return out


def collect() -> dict:
    by_name: dict[str, dict] = defaultdict(
        lambda: {"sources": [], "kinds": set()},
    )
    for path, line, content in _grep_lines():
        m = _EMIT_RE.search(content)
        if not m:
            continue
        kind, name = m.group(1), m.group(2)
        by_name[name]["sources"].append({"file": path, "line": line})
        by_name[name]["kinds"].add(kind)

    counters = []
    for name in sorted(by_name):
        family = name.split(".", 1)[0] if "." in name else "misc"
        entry = {
            "name": name,
            "family": family,
            "kinds": sorted(by_name[name]["kinds"]),
            "sources": by_name[name]["sources"],
        }
        counters.append(entry)
    return {"counters": counters}


def write(path: Path = FACTS_PATH) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(collect(), sort_keys=False,
                                    allow_unicode=True))
    return path


def main(argv: list[str]) -> int:
    p = write()
    rel = p.relative_to(REPO_ROOT)
    d = yaml.safe_load(p.read_text())
    print(f"  metrics catalog → {rel}  ({len(d['counters'])} counters)",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
