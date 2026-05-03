"""Tests for SBOMEngine.diff_sboms and GET /api/v1/sbom/assets/{id}/diff/{other_id}."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from fastapi import FastAPI

from core.sbom_engine import SBOMEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine(tmp_path):
    return SBOMEngine(data_dir=str(tmp_path))


@pytest.fixture
def org():
    return "org-diff-test"


def _asset(engine, org, name):
    return engine.register_asset(org, {"asset_name": name, "asset_type": "application"})


def _comp(engine, org, asset_id, name, version, risk_score=0.0, ecosystem="npm"):
    return engine.add_component(org, asset_id, {
        "component_name": name,
        "component_version": version,
        "component_type": "library",
        "ecosystem": ecosystem,
        "license": "MIT",
        "risk_score": risk_score,
    })


# ---------------------------------------------------------------------------
# Engine-level tests
# ---------------------------------------------------------------------------

def test_diff_added(engine, org):
    """Components in head but not base appear in added."""
    base = _asset(engine, org, "base-app")
    head = _asset(engine, org, "head-app")
    _comp(engine, org, base["id"], "lodash", "4.17.20")
    _comp(engine, org, head["id"], "lodash", "4.17.20")
    _comp(engine, org, head["id"], "express", "4.18.2")  # added only in head

    result = engine.diff_sboms(org, base["id"], head["id"])

    added_names = [c["component_name"] for c in result["added"]]
    assert "express" in added_names
    assert result["summary"]["added_count"] == 1
    assert result["summary"]["removed_count"] == 0


def test_diff_removed(engine, org):
    """Components in base but not head appear in removed."""
    base = _asset(engine, org, "base-v1")
    head = _asset(engine, org, "head-v1")
    _comp(engine, org, base["id"], "lodash", "4.17.20")
    _comp(engine, org, base["id"], "moment", "2.29.4")  # removed in head
    _comp(engine, org, head["id"], "lodash", "4.17.20")

    result = engine.diff_sboms(org, base["id"], head["id"])

    removed_names = [c["component_name"] for c in result["removed"]]
    assert "moment" in removed_names
    assert result["summary"]["removed_count"] == 1
    assert result["summary"]["added_count"] == 0


def test_diff_changed_version(engine, org):
    """Same purl with different version appears in changed with correct delta."""
    base = _asset(engine, org, "base-v2")
    head = _asset(engine, org, "head-v2")
    _comp(engine, org, base["id"], "axios", "1.3.0", risk_score=2.0)
    _comp(engine, org, head["id"], "axios", "1.6.0", risk_score=0.0)  # upgraded, lower risk

    result = engine.diff_sboms(org, base["id"], head["id"])

    assert result["summary"]["changed_count"] == 1
    ch = result["changed"][0]
    assert ch["component_name"] == "axios"
    assert ch["base_version"] == "1.3.0"
    assert ch["head_version"] == "1.6.0"
    assert ch["risk_delta"] == pytest.approx(-2.0)


def test_diff_summary_risk_delta(engine, org):
    """risk_delta in summary reflects net risk change across all components."""
    base = _asset(engine, org, "risk-base")
    head = _asset(engine, org, "risk-head")
    _comp(engine, org, base["id"], "pkg-a", "1.0", risk_score=5.0)
    _comp(engine, org, head["id"], "pkg-a", "1.0", risk_score=5.0)
    _comp(engine, org, head["id"], "pkg-b", "2.0", risk_score=8.0)  # new high-risk dep

    result = engine.diff_sboms(org, base["id"], head["id"])

    assert result["summary"]["base_risk_total"] == 5.0
    assert result["summary"]["head_risk_total"] == 13.0
    assert result["summary"]["risk_delta"] == 8.0


def test_diff_identical_assets(engine, org):
    """Diffing an asset against itself returns all-zero counts."""
    asset = _asset(engine, org, "same-app")
    _comp(engine, org, asset["id"], "react", "18.2.0")
    _comp(engine, org, asset["id"], "typescript", "5.0.0")

    result = engine.diff_sboms(org, asset["id"], asset["id"])

    assert result["summary"]["added_count"] == 0
    assert result["summary"]["removed_count"] == 0
    assert result["summary"]["changed_count"] == 0
    assert result["summary"]["risk_delta"] == 0.0


# ---------------------------------------------------------------------------
# Router-level (HTTP) test
# ---------------------------------------------------------------------------

def test_diff_route_404_unknown_base(tmp_path):
    """GET diff returns 404 when base asset does not exist."""
    import apps.api.sbom_router as sr
    from apps.api.auth_deps import api_key_auth

    app = FastAPI()
    # Isolate engine to tmp_path so we don't touch any on-disk state
    sr._engine = SBOMEngine(data_dir=str(tmp_path))
    app.include_router(sr.router)
    app.dependency_overrides[api_key_auth] = lambda: None

    client = TestClient(app)
    resp = client.get("/api/v1/sbom/assets/nonexistent/diff/also-nonexistent?org_id=org-x")
    assert resp.status_code == 404
