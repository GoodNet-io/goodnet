"""libclang AST walker over sdk/*.h — emits diff-friendly fact YAML.

Each public vtable becomes a `docs/_facts/<name>.yaml` with the
exact slot list, signatures, file:line back-references, doc-string
prefixes, and reserved-slot counts. Renderers and diagram
generators consume these files instead of hardcoding the same
shape in Python string literals.

The walker is conservative: it reads what the compiler reads, so
slot families are grouped by detecting `/* ── Family ─────── */`
banner comments above field declarations. Anything not under a
banner falls into the `misc` family.
"""

from __future__ import annotations

import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable

import yaml
from clang import cindex


REPO_ROOT = Path(__file__).resolve().parents[2]
SDK_ROOT = REPO_ROOT / "sdk"
FACTS_ROOT = REPO_ROOT / "docs" / "_facts"

BANNER_RE = re.compile(r"^\s*/\*\s*──+\s*([^─]+?)\s*──+")


@dataclass
class Slot:
    name: str
    signature: str
    file: str
    line: int
    family: str
    doc: str = ""


@dataclass
class VtableFacts:
    struct: str
    header: str
    named_slots: int = 0
    reserved_slots: int = 0
    families: dict[str, list[str]] = field(default_factory=dict)
    slots: list[Slot] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["slots"] = [asdict(s) for s in self.slots]
        return d


def _parse(header: Path) -> cindex.TranslationUnit:
    idx = cindex.Index.create()
    args = ["-Isdk", f"-I{REPO_ROOT}", "-std=c11"]
    tu = idx.parse(str(header), args=args)
    fatal = [d for d in tu.diagnostics if d.severity >= cindex.Diagnostic.Error]
    if fatal:
        msgs = "\n  ".join(d.spelling for d in fatal)
        raise RuntimeError(f"clang parse failed for {header}:\n  {msgs}")
    return tu


def _banner_lines(header: Path) -> dict[int, str]:
    """Map line-number → family-name for every `/* ── Foo ─── */` banner."""
    out: dict[int, str] = {}
    for n, line in enumerate(header.read_text().splitlines(), start=1):
        m = BANNER_RE.match(line)
        if m:
            family = m.group(1).strip()
            family = re.sub(r"\s+", " ", family)
            out[n] = family
    return out


def _resolve_family(line: int, banners: dict[int, str]) -> str:
    """Walk banners backward to find the closest one above `line`."""
    candidates = [n for n in banners if n < line]
    if not candidates:
        return "misc"
    return banners[max(candidates)]


def _signature(field_cur: cindex.Cursor) -> str:
    """Render a C function-pointer field signature compactly."""
    typ = field_cur.type
    # Pointee for function-pointer fields.
    pointee = typ.get_pointee()
    if pointee.kind == cindex.TypeKind.FUNCTIONPROTO:
        ret = pointee.get_result().spelling
        args = ", ".join(a.spelling for a in pointee.argument_types())
        return f"{ret} (*)({args})"
    return typ.spelling


def _doc_prefix(field_cur: cindex.Cursor) -> str:
    """First non-empty sentence of the cursor's leading comment block."""
    raw = field_cur.raw_comment or ""
    text = re.sub(r"^\s*[/*]+\s?", "", raw, flags=re.MULTILINE)
    text = re.sub(r"@\w+\s+\S+", "", text)  # drop @param, @return, etc.
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("@"):
            continue
        # First sentence — up to the first period followed by whitespace
        # or end-of-string.
        m = re.match(r"(.+?[.!?])(?:\s|$)", line)
        if m:
            return m.group(1).strip()
        return line
    return ""


def extract_vtable(
    header: Path,
    struct_name: str,
    *,
    skip_fields: Iterable[str] = (),
) -> VtableFacts:
    """Walk one vtable struct, return a VtableFacts."""
    tu = _parse(header)
    banners = _banner_lines(header)
    rel_header = header.relative_to(REPO_ROOT).as_posix()

    facts = VtableFacts(struct=struct_name, header=rel_header)
    skip = set(skip_fields)

    for cursor in tu.cursor.walk_preorder():
        if (cursor.kind != cindex.CursorKind.STRUCT_DECL
                or cursor.spelling != struct_name):
            continue
        for fld in cursor.get_children():
            if fld.kind != cindex.CursorKind.FIELD_DECL:
                continue
            if fld.spelling in skip:
                continue
            # Reserved tail array — counted, not listed by name.
            if fld.spelling == "_reserved":
                element_count = fld.type.element_count or 0
                facts.reserved_slots = element_count
                continue
            # Skip non-callable scalar fields (api_size, host_ctx, etc.)
            # unless they look like state. For livedoc purposes we
            # care about the function-pointer surface.
            pointee = fld.type.get_pointee()
            is_funcptr = pointee.kind == cindex.TypeKind.FUNCTIONPROTO
            if not is_funcptr:
                continue
            sig = _signature(fld)
            family = _resolve_family(fld.location.line, banners)
            slot = Slot(
                name=fld.spelling,
                signature=sig,
                file=rel_header,
                line=fld.location.line,
                family=family,
                doc=_doc_prefix(fld),
            )
            facts.slots.append(slot)
            facts.families.setdefault(family, []).append(fld.spelling)
        break

    facts.named_slots = len(facts.slots)
    return facts


# ── Per-vtable extractors ───────────────────────────────────────────

def extract_host_api() -> VtableFacts:
    return extract_vtable(
        SDK_ROOT / "host_api.h",
        "host_api_s",
        skip_fields={"api_size", "host_ctx"},
    )


def extract_link_vtable() -> VtableFacts:
    return extract_vtable(SDK_ROOT / "link.h", "gn_link_vtable_s")


def extract_handler_vtable() -> VtableFacts:
    return extract_vtable(SDK_ROOT / "handler.h", "gn_handler_vtable_s")


def extract_security_vtable() -> VtableFacts:
    return extract_vtable(
        SDK_ROOT / "security.h",
        "gn_security_provider_vtable_s",
    )


def extract_extension_link() -> VtableFacts:
    return extract_vtable(
        SDK_ROOT / "extensions" / "link.h",
        "gn_link_api_s",
    )


# ── YAML dump ───────────────────────────────────────────────────────

def _yaml_dump(facts: VtableFacts) -> str:
    """Stable diff-friendly YAML — sorted families, no anchors."""
    d = facts.to_dict()
    # Sort family keys for stable output. Family value lists keep
    # insertion order (matches source).
    d["families"] = {k: d["families"][k] for k in sorted(d["families"])}
    return yaml.safe_dump(d, sort_keys=False, width=80, allow_unicode=True)


def write_all(out_dir: Path = FACTS_ROOT) -> dict[str, Path]:
    """Run every extractor; return name → written-path map."""
    out_dir.mkdir(parents=True, exist_ok=True)
    targets = {
        "host_api": extract_host_api,
        "link_vtable": extract_link_vtable,
        "handler_vtable": extract_handler_vtable,
        "security_vtable": extract_security_vtable,
        "extension_link": extract_extension_link,
    }
    written = {}
    for name, fn in targets.items():
        facts = fn()
        path = out_dir / f"{name}.yaml"
        path.write_text(_yaml_dump(facts))
        written[name] = path
    return written


def main(argv: list[str]) -> int:
    written = write_all()
    for name, path in written.items():
        rel = path.relative_to(REPO_ROOT)
        print(f"  {name:<18s} → {rel}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
