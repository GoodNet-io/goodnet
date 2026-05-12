"""Walk core/ + plugins/ for gn_config_get_* helper call sites.

Convention: every config key the kernel or a plugin reads goes
through one of the `gn_config_get_{int64,string,bool}` helpers
declared in `sdk/convenience.h`. Each call passes the key as the
second arg — a string literal that lives at one definitive site
(plus possibly a default-value branch).

Output: `docs/_facts/config_keys.yaml`:

```yaml
keys:
  - name: ice.turn_tls
    type: int64
    family: ice
    sources:
      - file: plugins/links/ice/...
        line: 144
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
FACTS_PATH = REPO_ROOT / "docs" / "_facts" / "config_keys.yaml"

# gn_config_get_<type>(api, "key", ...) — name is first literal.
_KEY_RE = re.compile(
    r'gn_config_get_(int64|string|bool|int32)\s*\([^"]*"([^"]+)"',
)


def _grep_lines() -> list[tuple[str, int, str]]:
    cmd = [
        "grep", "-rIn",
        "--include=*.cpp", "--include=*.hpp",
        "--include=*.c", "--include=*.h",
        "--exclude-dir=.git", "--exclude-dir=build",
        "--exclude-dir=build-release", "--exclude-dir=tests",
        "gn_config_get_",
        "core", "plugins", "apps",
    ]
    try:
        r = subprocess.run(
            cmd, cwd=REPO_ROOT, capture_output=True, text=True,
            timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if r.returncode not in (0, 1):
        return []
    out: list[tuple[str, int, str]] = []
    for line in r.stdout.splitlines():
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
    by_key: dict[str, dict] = defaultdict(
        lambda: {"sources": [], "types": set()},
    )
    for path, line, content in _grep_lines():
        m = _KEY_RE.search(content)
        if not m:
            continue
        typ, name = m.group(1), m.group(2)
        by_key[name]["sources"].append({"file": path, "line": line})
        by_key[name]["types"].add(typ)

    keys = []
    for name in sorted(by_key):
        family = name.split(".", 1)[0] if "." in name else "misc"
        keys.append({
            "name": name,
            "type": "/".join(sorted(by_key[name]["types"])),
            "family": family,
            "sources": by_key[name]["sources"],
        })
    return {"keys": keys}


def write(path: Path = FACTS_PATH) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(collect(), sort_keys=False,
                                    allow_unicode=True))
    return path


def main(argv: list[str]) -> int:
    p = write()
    rel = p.relative_to(REPO_ROOT)
    d = yaml.safe_load(p.read_text())
    print(f"  config keys catalog → {rel}  ({len(d['keys'])} keys)",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
