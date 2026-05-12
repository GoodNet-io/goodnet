"""Unit tests for tools/livedoc/test_inventory.py."""

from __future__ import annotations

import pytest

from livedoc import test_inventory


def test_case_re_matches_every_macro():
    samples = [
        "TEST(Foo, Bar) {",
        "TEST_F(MyFixture, Case) {",
        "TEST_P(Parametric, Case) {",
        "TYPED_TEST(Typed, Case) {",
        "TYPED_TEST_P(TypedP, Case) {",
        "RC_GTEST_PROP(Prop, name, (int x)) {",
        "RC_GTEST_FIXTURE_PROP(Fix, name, (int x)) {",
    ]
    for s in samples:
        assert test_inventory._CASE_RE.search(s) is not None, s


def test_case_re_skips_custom_macros():
    # Word-boundary prefix means custom wrappers like MY_TEST(...)
    # are NOT counted (they aren't part of the gtest surface).
    assert test_inventory._CASE_RE.search("MY_TEST(X, Y) {") is None
    assert test_inventory._CASE_RE.search("EXPECT_TEST(...)") is None


@pytest.fixture
def inventory_repo(tiny_repo, monkeypatch):
    monkeypatch.setattr(test_inventory, "REPO_ROOT", tiny_repo)
    monkeypatch.setattr(
        test_inventory, "FACTS_PATH",
        tiny_repo / "docs" / "_facts" / "test_inventory.yaml",
    )
    return tiny_repo


def test_collect_picks_kernel_and_plugin_trees(inventory_repo):
    out = test_inventory.collect()
    trees = {g["tree"] for g in out["groups"]}
    assert "kernel" in trees
    assert "plugins/links/tcp" in trees
    assert "plugins/handlers/heartbeat" in trees
    assert "plugins/security/null" in trees


def test_collect_total_matches_sum(inventory_repo):
    out = test_inventory.collect()
    s = sum(g["count"] for g in out["groups"])
    assert out["total"] == s


def test_by_plugin_keyed_by_kind_name(inventory_repo):
    out = test_inventory.collect()
    assert "links/tcp" in out["by_plugin"]
    assert out["by_plugin"]["links/tcp"] >= 2  # two TEST() macros


def test_write_emits_yaml(inventory_repo):
    path = test_inventory.write()
    text = path.read_text()
    assert "groups:" in text
    assert "by_plugin:" in text
    assert "kernel" in text


def test_kernel_skeleton_count_is_three(inventory_repo):
    """Kernel skeleton has TEST + TEST + TEST_F == 3 cases."""
    out = test_inventory.collect()
    kernel = [g for g in out["groups"] if g["tree"] == "kernel"][0]
    assert kernel["count"] == 3
