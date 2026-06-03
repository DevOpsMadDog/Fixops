"""SPEC-030 AC-030-01 — NetworkAnalyzer is honest-empty on a fresh deploy.

Enforces the ingest-first / NO-MOCKS invariant: a NetworkAnalyzer pointed at a
brand-new DB (nothing ingested) must report all-zeros and empty lists — never
fabricated or auto-seeded demo zones/flows. Guards against a regression that
re-introduces demo seeding in _init_tables().
"""

from __future__ import annotations

import os
import tempfile

import pytest

from core.network_analyzer import NetworkAnalyzer


@pytest.fixture()
def fresh_analyzer() -> NetworkAnalyzer:
    d = tempfile.mkdtemp()
    return NetworkAnalyzer(db_path=os.path.join(d, "fresh_network.db"))


def test_fresh_stats_all_zero(fresh_analyzer: NetworkAnalyzer) -> None:
    stats = fresh_analyzer.get_network_stats()
    assert stats["zone_count"] == 0
    assert stats["flow_count"] == 0
    assert stats["violation_count"] == 0
    assert stats["allowed_flow_count"] == 0
    assert stats["denied_flow_count"] == 0
    assert stats["avg_risk_score"] == 0.0
    assert stats["zones_by_type"] == {}
    assert stats["violations_by_severity"] == {}


def test_fresh_zones_empty(fresh_analyzer: NetworkAnalyzer) -> None:
    assert fresh_analyzer.list_zones() == []


def test_no_autoseed_then_real_after_ingest(fresh_analyzer: NetworkAnalyzer) -> None:
    # Empty until a zone is actually defined (proves counts are ingest-derived).
    assert fresh_analyzer.get_network_stats()["zone_count"] == 0
    from core.network_analyzer import ZoneType

    fresh_analyzer.define_zone(name="dmz-1", zone_type=ZoneType.DMZ)
    assert fresh_analyzer.get_network_stats()["zone_count"] == 1
