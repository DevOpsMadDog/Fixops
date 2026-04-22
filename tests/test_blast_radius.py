"""Tests for Blast Radius + Crown Jewel (GAP-027 + GAP-046).

Covers:
  - AssetCriticalityEngine.tag_crown_jewel / list_crown_jewels / compute_blast_radius_score
  - VulnerabilityScoringEngine.factor_blast_radius / get_score_breakdown
  - RiskAggregatorEngine.get_score_breakdown
  - blast_radius_router smoke tests
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-api"))

from core.asset_criticality_engine import AssetCriticalityEngine
from core.risk_aggregator_engine import RiskAggregatorEngine
from core.vulnerability_scoring_engine import VulnerabilityScoringEngine

ORG = "org-blast-test"
ORG2 = "org-blast-other"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def asset_engine(tmp_path):
    return AssetCriticalityEngine(db_path=str(tmp_path / "ac.db"))


@pytest.fixture
def vuln_engine(tmp_path):
    return VulnerabilityScoringEngine(db_path=str(tmp_path / "vs.db"))


@pytest.fixture
def risk_engine(tmp_path):
    return RiskAggregatorEngine(db_path=str(tmp_path / "ra.db"))


def _tier_asset(engine, org, tier_score, name="asset"):
    """Register + score an asset so its criticality_tier is set."""
    asset = engine.register_asset(
        org_id=org, asset_name=name, asset_type="server",
        data_classification="confidential",
    )
    factors = [{"factor_name": "impact", "factor_category": "impact",
                "weight": 1.0, "value": tier_score / 10.0}]
    engine.score_asset(asset["id"], org, factors)
    return asset["id"]


# ---------------------------------------------------------------------------
# Crown Jewel tagging (GAP-046)
# ---------------------------------------------------------------------------

def test_tag_crown_jewel_creates_record(asset_engine):
    rec = asset_engine.tag_crown_jewel(ORG, "asset-123", "core revenue system")
    assert rec["asset_ref"] == "asset-123"
    assert rec["reason"] == "core revenue system"
    assert rec["org_id"] == ORG


def test_tag_crown_jewel_idempotent_unique(asset_engine):
    rec1 = asset_engine.tag_crown_jewel(ORG, "asset-dup", "v1 reason")
    rec2 = asset_engine.tag_crown_jewel(ORG, "asset-dup", "v2 updated")
    # Same id, reason updated
    assert rec1["id"] == rec2["id"]
    assert rec2["reason"] == "v2 updated"
    assert len(asset_engine.list_crown_jewels(ORG)) == 1


def test_tag_crown_jewel_empty_raises(asset_engine):
    with pytest.raises(ValueError):
        asset_engine.tag_crown_jewel("", "asset-x", "r")
    with pytest.raises(ValueError):
        asset_engine.tag_crown_jewel(ORG, "", "r")


def test_list_crown_jewels_org_isolation(asset_engine):
    asset_engine.tag_crown_jewel(ORG, "a1", "r")
    asset_engine.tag_crown_jewel(ORG, "a2", "r")
    asset_engine.tag_crown_jewel(ORG2, "z1", "r")
    assert len(asset_engine.list_crown_jewels(ORG)) == 2
    assert len(asset_engine.list_crown_jewels(ORG2)) == 1


def test_list_crown_jewels_empty_org(asset_engine):
    assert asset_engine.list_crown_jewels("no-such-org") == []


def test_is_crown_jewel_helper(asset_engine):
    asset_engine.tag_crown_jewel(ORG, "jewel-1", "cj")
    assert asset_engine.is_crown_jewel(ORG, "jewel-1")
    assert not asset_engine.is_crown_jewel(ORG, "not-tagged")
    assert not asset_engine.is_crown_jewel(ORG2, "jewel-1")


# ---------------------------------------------------------------------------
# Blast Radius (GAP-027)
# ---------------------------------------------------------------------------

def test_compute_blast_radius_score_range_0_100(asset_engine):
    asset_id = _tier_asset(asset_engine, ORG, 90, "critical-db")
    result = asset_engine.compute_blast_radius_score(ORG, asset_id)
    assert 0 <= result["score"] <= 100
    assert result["asset_ref"] == asset_id
    assert "contributing_factors" in result


def test_compute_blast_radius_unregistered_asset(asset_engine):
    # Raw ref not in DB - still returns 0-100 score with unassessed tier
    result = asset_engine.compute_blast_radius_score(ORG, "never-registered")
    assert 0 <= result["score"] <= 100
    assert result["contributing_factors"][0]["tier"] == "unassessed"


def test_compute_blast_radius_3_hop_walk(asset_engine):
    a = _tier_asset(asset_engine, ORG, 90, "A")   # tier-1
    b = _tier_asset(asset_engine, ORG, 70, "B")   # tier-2
    c = _tier_asset(asset_engine, ORG, 50, "C")   # tier-3
    d = _tier_asset(asset_engine, ORG, 30, "D")   # tier-4
    asset_engine.add_dependency(a, ORG, b)
    asset_engine.add_dependency(b, ORG, c)
    asset_engine.add_dependency(c, ORG, d)
    result = asset_engine.compute_blast_radius_score(ORG, a, max_hops=3)
    assert result["reachable_asset_count"] == 3
    assert result["hops_walked"] == 3
    refs = {f["asset_ref"] for f in result["contributing_factors"]}
    assert {a, b, c, d}.issubset(refs)


def test_compute_blast_radius_max_hops_respected(asset_engine):
    a = _tier_asset(asset_engine, ORG, 90, "A")
    b = _tier_asset(asset_engine, ORG, 70, "B")
    c = _tier_asset(asset_engine, ORG, 50, "C")
    asset_engine.add_dependency(a, ORG, b)
    asset_engine.add_dependency(b, ORG, c)
    result = asset_engine.compute_blast_radius_score(ORG, a, max_hops=1)
    # a (hop0) + b (hop1), c excluded
    assert result["reachable_asset_count"] == 1


def test_compute_blast_radius_crown_jewel_bump(asset_engine):
    a = _tier_asset(asset_engine, ORG, 90, "A")
    b = _tier_asset(asset_engine, ORG, 70, "B")
    asset_engine.add_dependency(a, ORG, b)
    before = asset_engine.compute_blast_radius_score(ORG, a)
    asset_engine.tag_crown_jewel(ORG, b, "mission-critical")
    after = asset_engine.compute_blast_radius_score(ORG, a)
    assert after["score"] > before["score"]
    # Confirm the contributor flagged as crown_jewel
    crown_flagged = [f for f in after["contributing_factors"] if f["crown_jewel"]]
    assert any(f["asset_ref"] == b for f in crown_flagged)


def test_compute_blast_radius_circular_safe(asset_engine):
    a = _tier_asset(asset_engine, ORG, 90, "A")
    b = _tier_asset(asset_engine, ORG, 70, "B")
    asset_engine.add_dependency(a, ORG, b)
    asset_engine.add_dependency(b, ORG, a)
    result = asset_engine.compute_blast_radius_score(ORG, a)
    # No infinite loop; each asset visited once
    refs = [f["asset_ref"] for f in result["contributing_factors"]]
    assert len(refs) == len(set(refs))


def test_compute_blast_radius_org_isolation(asset_engine):
    a = _tier_asset(asset_engine, ORG, 90, "A")
    z = _tier_asset(asset_engine, ORG2, 90, "Z")
    asset_engine.add_dependency(a, ORG, z)  # cross-org dep shouldn't matter for scoring ORG2 walks
    result_org2 = asset_engine.compute_blast_radius_score(ORG2, z)
    # org2 has no deps from z, so only the seed is walked
    assert result_org2["reachable_asset_count"] == 0


def test_compute_blast_radius_tier_weight_ordering(asset_engine):
    a_crit = _tier_asset(asset_engine, ORG, 90, "crit")
    a_low = _tier_asset(asset_engine, ORG, 10, "low")
    res_crit = asset_engine.compute_blast_radius_score(ORG, a_crit)
    res_low = asset_engine.compute_blast_radius_score(ORG, a_low)
    assert res_crit["score"] > res_low["score"]


# ---------------------------------------------------------------------------
# VulnerabilityScoringEngine.factor_blast_radius
# ---------------------------------------------------------------------------

def test_factor_blast_radius_updates_composite(vuln_engine):
    score = vuln_engine.score_vulnerability(
        org_id=ORG, vuln_id="v-1", cve_id="CVE-2024-1",
        cvss_score=7.0, epss_score=0.3, kev_listed=False,
        asset_criticality="medium",
    )
    original = score["composite_score"]
    updated = vuln_engine.factor_blast_radius(ORG, score["id"], 60.0)
    assert updated["composite_score"] != original
    assert updated["blast_radius_contribution"] == round(60.0 * 0.15, 2)


def test_factor_blast_radius_crown_jewel_multiplier_bumps_critical(vuln_engine):
    score = vuln_engine.score_vulnerability(
        org_id=ORG, vuln_id="v-crit", cvss_score=8.5, epss_score=0.6,
        kev_listed=True, asset_criticality="high",
    )
    no_crown = vuln_engine.factor_blast_radius(ORG, score["id"], 50.0, is_crown_jewel=False)
    # reset another score
    score2 = vuln_engine.score_vulnerability(
        org_id=ORG, vuln_id="v-crit2", cvss_score=8.5, epss_score=0.6,
        kev_listed=True, asset_criticality="high",
    )
    with_crown = vuln_engine.factor_blast_radius(ORG, score2["id"], 50.0, is_crown_jewel=True)
    assert with_crown["composite_score"] >= no_crown["composite_score"]
    assert with_crown["crown_jewel_applied"] is True


def test_factor_blast_radius_persists_breakdown(vuln_engine):
    score = vuln_engine.score_vulnerability(
        org_id=ORG, vuln_id="v-b", cvss_score=6.0,
    )
    vuln_engine.factor_blast_radius(ORG, score["id"], 40.0, is_crown_jewel=True)
    rows = vuln_engine.get_score_breakdown(ORG, score["id"])
    names = {r["factor_name"] for r in rows}
    assert "blast_radius" in names
    assert "crown_jewel_multiplier" in names


def test_factor_blast_radius_missing_finding_raises(vuln_engine):
    with pytest.raises(ValueError):
        vuln_engine.factor_blast_radius(ORG, "nonexistent", 50.0)


def test_factor_blast_radius_clamps_to_100(vuln_engine):
    score = vuln_engine.score_vulnerability(
        org_id=ORG, vuln_id="v-max", cvss_score=10.0, epss_score=1.0,
        kev_listed=True, asset_criticality="critical",
    )
    updated = vuln_engine.factor_blast_radius(ORG, score["id"], 100.0, is_crown_jewel=True)
    assert updated["composite_score"] <= 100.0


def test_factor_blast_radius_by_vuln_id(vuln_engine):
    """finding_id can be vuln_id, not just row id."""
    score = vuln_engine.score_vulnerability(
        org_id=ORG, vuln_id="v-lookup-alt", cvss_score=5.0,
    )
    updated = vuln_engine.factor_blast_radius(ORG, "v-lookup-alt", 30.0)
    assert updated["id"] == score["id"]


def test_factor_blast_radius_org_isolation(vuln_engine):
    score = vuln_engine.score_vulnerability(
        org_id=ORG, vuln_id="v-iso", cvss_score=5.0,
    )
    with pytest.raises(ValueError):
        vuln_engine.factor_blast_radius(ORG2, score["id"], 30.0)


# ---------------------------------------------------------------------------
# RiskAggregator.get_score_breakdown
# ---------------------------------------------------------------------------

def test_get_score_breakdown_lists_contributors(risk_engine):
    risk_engine.record_risk_score(ORG, {
        "entity_id": "entity-42",
        "entity_name": "payments-api",
        "entity_type": "application",
        "risk_score": 75.0,
        "risk_factors": ["cvss:8.0", "severity:high", "exposure:internet"],
    })
    result = risk_engine.get_score_breakdown(ORG, "entity-42")
    assert result["entity_ref"] == "entity-42"
    assert result["base_risk_score"] == 75.0
    names = [c["name"] for c in result["contributors"]]
    assert "cvss" in names
    assert "severity" in names
    assert "exposure" in names


def test_get_score_breakdown_empty(risk_engine):
    result = risk_engine.get_score_breakdown(ORG, "unknown-entity")
    assert result["base_risk_score"] is None
    # Contributors may be empty list; vuln engine lookup may add zero
    assert isinstance(result["contributors"], list)


def test_get_score_breakdown_org_isolation(risk_engine):
    risk_engine.record_risk_score(ORG, {
        "entity_id": "shared-ref",
        "entity_type": "asset",
        "risk_score": 50.0,
    })
    result_other = risk_engine.get_score_breakdown(ORG2, "shared-ref")
    assert result_other["base_risk_score"] is None


# ---------------------------------------------------------------------------
# Router smoke tests
# ---------------------------------------------------------------------------

@pytest.fixture
def client(tmp_path, monkeypatch):
    """Create a FastAPI TestClient with isolated engine DBs + api_key_auth override."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    # Reset module-level singletons
    import apps.api.blast_radius_router as br_mod
    from apps.api.auth_deps import api_key_auth
    br_mod._asset_engine = None
    br_mod._vuln_engine = None
    br_mod._risk_engine = None

    from core.asset_criticality_engine import AssetCriticalityEngine
    from core.risk_aggregator_engine import RiskAggregatorEngine
    from core.vulnerability_scoring_engine import VulnerabilityScoringEngine

    br_mod._asset_engine = AssetCriticalityEngine(db_path=str(tmp_path / "ac.db"))
    br_mod._vuln_engine = VulnerabilityScoringEngine(db_path=str(tmp_path / "vs.db"))
    br_mod._risk_engine = RiskAggregatorEngine(db_path=str(tmp_path / "ra.db"))

    app = FastAPI()
    app.include_router(br_mod.router)
    # Bypass auth in tests
    app.dependency_overrides[api_key_auth] = lambda: "test-key"
    return TestClient(app)


def test_router_post_crown_jewel(client):
    resp = client.post("/api/v1/blast-radius/crown-jewel", json={
        "org_id": ORG, "asset_ref": "crown-1", "reason": "prod db",
    })
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert data["record"]["asset_ref"] == "crown-1"


def test_router_get_crown_jewels(client):
    client.post("/api/v1/blast-radius/crown-jewel", json={
        "org_id": ORG, "asset_ref": "crown-a",
    })
    resp = client.get(f"/api/v1/blast-radius/crown-jewels?org_id={ORG}")
    assert resp.status_code == 200
    assert resp.json()["count"] == 1


def test_router_post_compute(client):
    resp = client.post("/api/v1/blast-radius/compute", json={
        "org_id": ORG, "asset_ref": "asset-smoke", "max_hops": 2,
    })
    assert resp.status_code == 200, resp.text
    assert "score" in resp.json()


def test_router_get_score_breakdown(client):
    resp = client.get(f"/api/v1/blast-radius/score-breakdown/some-ref?org_id={ORG}")
    assert resp.status_code == 200
    assert resp.json()["entity_ref"] == "some-ref"


def test_router_stats(client):
    client.post("/api/v1/blast-radius/crown-jewel", json={
        "org_id": ORG, "asset_ref": "stat-1",
    })
    resp = client.get(f"/api/v1/blast-radius/stats?org_id={ORG}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["crown_jewel_count"] == 1
