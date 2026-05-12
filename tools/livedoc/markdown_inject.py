"""Non-destructive placeholder rewriter for hand-written markdown.

A markdown file may host any number of `livedoc` regions; each
region is bounded by a pair of comment lines:

    <!-- livedoc:NAME -->
    ... regenerated content ...
    <!-- /livedoc:NAME -->

Calling `replace(text, name, new_body)` rewrites the body between
the markers and returns the new text. Everything outside markers
is preserved character-for-character — running the rewriter on a
file that's already up-to-date produces an identical string.

`refresh_file(path, regions)` runs every region present in `regions`
that also exists in the file. Regions absent from `regions` stay
untouched; regions absent from the file are silently skipped (the
hand-written doc decides which extracts it wants to host).

`refresh_tree(docs_root, regions)` walks every `.md` file under
`docs_root` and refreshes whatever markers it finds.
"""

from __future__ import annotations

import re
from pathlib import Path


_MARKER_RE_TEMPLATE = (
    r"(?P<open><!--\s*livedoc:{name}\s*-->)"
    r"(?P<body>.*?)"
    r"(?P<close><!--\s*/livedoc:{name}\s*-->)"
)


def _marker_re(name: str) -> re.Pattern:
    return re.compile(
        _MARKER_RE_TEMPLATE.format(name=re.escape(name)),
        re.DOTALL,
    )


_ANY_REGION_RE = re.compile(
    r"<!--\s*livedoc:([a-zA-Z0-9_\-]+)\s*-->",
)


def regions_in(text: str) -> list[str]:
    """Return the list of region names declared in the text."""
    return _ANY_REGION_RE.findall(text)


def replace(text: str, name: str, new_body: str) -> str:
    """Replace one region's body. Returns text unchanged if absent.

    The new body is sandwiched between newlines so the markers
    stay on their own lines even when the rendered content does
    not end in a newline.
    """
    pat = _marker_re(name)
    if not pat.search(text):
        return text
    body = new_body.rstrip("\n")

    def _sub(m: re.Match) -> str:
        return f"{m.group('open')}\n{body}\n{m.group('close')}"

    return pat.sub(_sub, text, count=1)


def refresh_file(
    path: Path,
    regions: dict[str, str],
) -> bool:
    """Rewrite any livedoc regions that appear in both `regions`
    and the file. Returns True if the file content changed.
    """
    original = path.read_text()
    updated = original
    for name, body in regions.items():
        updated = replace(updated, name, body)
    if updated != original:
        path.write_text(updated)
        return True
    return False


def refresh_tree(
    docs_root: Path,
    regions: dict[str, str],
) -> list[Path]:
    """Walk every .md under `docs_root`; refresh hosted regions.

    Returns the list of files actually changed.
    """
    changed: list[Path] = []
    for md in sorted(docs_root.rglob("*.md")):
        if refresh_file(md, regions):
            changed.append(md)
    return changed
