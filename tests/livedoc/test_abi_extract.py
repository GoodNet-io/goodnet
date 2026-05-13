"""Unit tests for tools/livedoc/abi_extract.py."""

from __future__ import annotations

from livedoc import abi_extract


def test_extract_host_api_slot_count(tiny_repo):
    facts = abi_extract.extract_host_api()
    # The skeleton declares 3 named slots + _reserved[2].
    assert facts.named_slots == 3
    assert facts.reserved_slots == 2


def test_extract_host_api_family_grouping(tiny_repo):
    facts = abi_extract.extract_host_api()
    names = {s.name for s in facts.slots}
    assert names == {"send", "disconnect", "find_conn_by_pk"}
    # Banner family resolution.
    fam_of = {s.name: s.family for s in facts.slots}
    assert fam_of["send"] == "Messaging"
    assert fam_of["disconnect"] == "Messaging"
    assert fam_of["find_conn_by_pk"] == "Registry queries"


def test_extract_link_vtable(tiny_repo):
    facts = abi_extract.extract_link_vtable()
    assert facts.named_slots == 1
    assert facts.slots[0].name == "listen"


def test_extract_handler_vtable(tiny_repo):
    facts = abi_extract.extract_handler_vtable()
    assert facts.named_slots == 1
    assert facts.slots[0].name == "on_message"


def test_extract_security_vtable(tiny_repo):
    facts = abi_extract.extract_security_vtable()
    assert facts.named_slots == 1
    assert facts.slots[0].name == "handshake_open"


def test_extract_extension_link_composer(tiny_repo):
    facts = abi_extract.extract_extension_link()
    assert facts.slots[0].name == "composer_listen"
    assert facts.slots[0].family == "Composer surface"


def test_write_all_emits_five_yaml_files(tiny_repo):
    written = abi_extract.write_all()
    assert set(written) == {
        "host_api", "link_vtable", "handler_vtable",
        "security_vtable", "extension_link",
    }
    for path in written.values():
        assert path.exists()
        text = path.read_text()
        assert "named_slots:" in text
        assert "slots:" in text


def test_banner_re_handles_multiline_banner():
    """Banner that doesn't close `*/` on the same line still parses."""
    pat = abi_extract.BANNER_RE
    # Single-line.
    m1 = pat.match(
        "    /* ── Messaging ─────────────────────── */\n"
    )
    assert m1 and m1.group(1) == "Messaging"
    # Multi-line: just the opener with dashes; close is on a later
    # source line. The regex only needs the opener line.
    m2 = pat.match(
        "    /* ── Identity primitives (identity.en.md §5) ──────\n"
    )
    assert m2 and "Identity primitives" in m2.group(1)


def test_skipped_fields_excluded(tiny_repo):
    """api_size and host_ctx are skipped from the slot list."""
    facts = abi_extract.extract_host_api()
    names = {s.name for s in facts.slots}
    assert "api_size" not in names
    assert "host_ctx" not in names
