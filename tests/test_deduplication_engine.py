"""Tests for core.deduplication — DeduplicationService."""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[1] / "suite-core"))
sys.path.insert(0, str(Path(__file__).parents[1] / "suite-api"))

from core.deduplication import DeduplicationService


@pytest.fixture()
def svc(tmp_path: Path) -> DeduplicationService:
    return DeduplicationService(db_path=tmp_path / "dedup.db")


def test_suppress_cluster(svc: DeduplicationService) -> None:
    r = svc.suppress_cluster("c1", reason="false-positive")
    assert r["status"] == "suppressed"
    assert r["cluster_id"] == "c1"
    row = svc.get_cluster("c1")
    assert row is not None
    assert row["status"] == "suppressed"
    assert row["reason"] == "false-positive"


def test_accept_risk(svc: DeduplicationService) -> None:
    r = svc.accept_risk("c2", justification="low risk", approved_by="alice")
    assert r["status"] == "accepted"
    assert r["approved_by"] == "alice"
    row = svc.get_cluster("c2")
    assert row["status"] == "accepted"
    assert row["approved_by"] == "alice"


def test_dismiss_cluster(svc: DeduplicationService) -> None:
    r = svc.dismiss_cluster("c3", reason="not applicable")
    assert r["status"] == "dismissed"
    row = svc.get_cluster("c3")
    assert row["status"] == "dismissed"


def test_update_cluster_status_valid(svc: DeduplicationService) -> None:
    svc.suppress_cluster("c4", reason="noise")
    r = svc.update_cluster_status("c4", "resolved")
    assert r["status"] == "resolved"
    assert svc.get_cluster("c4")["status"] == "resolved"


def test_update_cluster_status_invalid(svc: DeduplicationService) -> None:
    svc.suppress_cluster("c5", reason="x")
    with pytest.raises(ValueError, match="Invalid status"):
        svc.update_cluster_status("c5", "bogus_state")


def test_get_cluster_missing(svc: DeduplicationService) -> None:
    assert svc.get_cluster("nonexistent") is None


def test_list_clusters_filtered(svc: DeduplicationService) -> None:
    svc.suppress_cluster("cx1", reason="r")
    svc.suppress_cluster("cx2", reason="r")
    svc.accept_risk("cx3", justification="j", approved_by="bob")
    suppressed = svc.list_clusters(status="suppressed")
    assert len(suppressed) == 2
    accepted = svc.list_clusters(status="accepted")
    assert len(accepted) == 1


def test_stats(svc: DeduplicationService) -> None:
    svc.suppress_cluster("s1", reason="r")
    svc.accept_risk("s2", justification="j", approved_by="bob")
    svc.dismiss_cluster("s3", reason="n/a")
    stats = svc.stats()
    assert stats["total"] == 3
    assert stats["by_status"]["suppressed"] == 1
    assert stats["by_status"]["accepted"] == 1
    assert stats["by_status"]["dismissed"] == 1
