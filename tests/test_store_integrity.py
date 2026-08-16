"""A split store must announce itself instead of ageing in silence.

Measured in the running container on 2026-08-16: 49 database names existed at two
locations and 13 held genuinely diverged data — deduplication clusters at 5,898 rows in
one copy and 0 in the other, TrustGraph at 250 against 38. Nothing surfaced it. The
application read one copy, wrote one copy, reported success, and the other simply aged.

For a product sold on evidence that is disqualifying: an audit trail with half its rows
in a file nobody opens is worse than no audit trail, because it looks complete.

The check warns rather than refusing to boot, because a pre-existing split cannot be
resolved during a restart and taking a running system down to report history would do
more harm than the condition. ``FIXOPS_STRICT_STORES=1`` makes it fatal — the setting a
fresh install and CI should use, where a split means misconfiguration rather than history.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from core.store_integrity import (
    SplitStoreError,
    check_store_integrity,
    find_split_stores,
)


def _make(path: Path, name: str) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    db = path / name
    db.write_bytes(b"SQLite format 3\x00")
    return db


def test_clean_tree_reports_nothing(tmp_path: Path) -> None:
    _make(tmp_path / "data", "findings.db")
    _make(tmp_path / "data", "evidence.db")
    assert find_split_stores(tmp_path) == {}


def test_the_same_name_in_two_places_is_reported(tmp_path: Path) -> None:
    """The exact production shape: data/ and suite-api/data/."""
    _make(tmp_path / "data", "clusters.db")
    _make(tmp_path / "suite-api" / "data", "clusters.db")

    splits = find_split_stores(tmp_path)

    assert list(splits) == ["clusters.db"]
    assert len(splits["clusters.db"]) == 2


def test_three_locations_are_all_listed(tmp_path: Path) -> None:
    """analytics.db really did exist in three places."""
    for directory in ("data", "suite-api/data", ".fixops_data"):
        _make(tmp_path / directory, "analytics.db")

    assert len(find_split_stores(tmp_path)["analytics.db"]) == 3


def test_vendored_directories_are_ignored(tmp_path: Path) -> None:
    """A dependency's fixture database is not our split store."""
    _make(tmp_path / "data", "cache.db")
    _make(tmp_path / "node_modules" / "pkg", "cache.db")
    assert find_split_stores(tmp_path) == {}


def test_expected_repeats_can_be_ignored(tmp_path: Path) -> None:
    """Per-tenant databases legitimately repeat across tenant directories."""
    _make(tmp_path / "acme", "findings.db")
    _make(tmp_path / "globex", "findings.db")

    assert "findings.db" in find_split_stores(tmp_path)
    assert find_split_stores(tmp_path, ignore={"findings.db"}) == {}


def test_startup_warns_but_does_not_raise_by_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _make(tmp_path / "data", "trustgraph.db")
    _make(tmp_path / "suite-api" / "data", "trustgraph.db")
    monkeypatch.delenv("FIXOPS_STRICT_STORES", raising=False)

    with caplog.at_level("WARNING"):
        splits = check_store_integrity(tmp_path)

    assert "trustgraph.db" in splits
    assert any("store integrity" in record.message for record in caplog.records)


def test_strict_mode_refuses(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _make(tmp_path / "data", "trustgraph.db")
    _make(tmp_path / "suite-api" / "data", "trustgraph.db")
    monkeypatch.setenv("FIXOPS_STRICT_STORES", "1")

    with pytest.raises(SplitStoreError, match="more than one location"):
        check_store_integrity(tmp_path)


def test_strict_mode_passes_on_a_clean_tree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Strictness must not fire on a healthy deployment."""
    _make(tmp_path / "data", "findings.db")
    monkeypatch.setenv("FIXOPS_STRICT_STORES", "1")

    assert check_store_integrity(tmp_path) == {}


def test_an_unreadable_tree_never_stops_startup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A diagnostic must not become the reason the product will not start."""
    assert check_store_integrity(Path("/nonexistent-path-for-test")) == {}
