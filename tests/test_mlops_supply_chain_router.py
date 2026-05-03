"""
API-level tests for mlops_supply_chain_router.

Tests exercise all 6 HTTP endpoints via FastAPI TestClient with auth bypassed.
No network calls. Engine uses an isolated temp SQLite DB per test module.
"""

from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-api"))

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import apps.api.mlops_supply_chain_router as _rmod

import core.supply_chain_analyzer as _sc_mod


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    """Minimal FastAPI app with no-auth mlops_supply_chain_router and isolated DB."""
    db_path = str(tmp_path_factory.mktemp("sc_router") / "sc.db")
    from core.supply_chain_analyzer import SupplyChainAnalyzer
    _sc_mod._analyzer = SupplyChainAnalyzer(db_path=db_path)

    app = FastAPI()
    app.include_router(_rmod.router)

    # Bypass auth: override the api_key_auth dependency to a no-op
    try:
        from apps.api.auth_deps import api_key_auth
        app.dependency_overrides[api_key_auth] = lambda: "test-user"
    except Exception:
        pass

    yield TestClient(app)

    _sc_mod._analyzer = None


# ---------------------------------------------------------------------------
# POST /analyze/package
# ---------------------------------------------------------------------------


def test_analyze_package_safe_returns_200(client):
    """A clean package returns HTTP 200 with expected response fields."""
    resp = client.post(
        "/api/v1/mlops/supply-chain/analyze/package",
        json={"name": "requests", "version": "2.31.0", "ecosystem": "pypi"},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["package"] == "requests"
    assert "risk_score" in data
    assert "overall_risk" in data
    assert data["is_known_malicious"] is False


def test_analyze_package_known_malicious_ctx(client):
    """'ctx' is flagged as known malicious with risk_score >= 90 and overall_risk=critical."""
    resp = client.post(
        "/api/v1/mlops/supply-chain/analyze/package",
        json={"name": "ctx", "ecosystem": "pypi"},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["is_known_malicious"] is True
    assert data["risk_score"] >= 90.0
    assert data["overall_risk"] == "critical"


def test_analyze_package_typosquat_flagged(client):
    """'colourama' is detected as a typosquat of colorama."""
    resp = client.post(
        "/api/v1/mlops/supply-chain/analyze/package",
        json={"name": "colourama", "ecosystem": "pypi"},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["is_typosquat"] is True
    assert len(data["similar_packages"]) > 0


# ---------------------------------------------------------------------------
# POST /analyze/requirements
# ---------------------------------------------------------------------------


def test_analyze_requirements_clean_manifest(client):
    """A clean requirements.txt returns 200 with correct package count."""
    manifest = "requests==2.31.0\nnumpy>=1.24.0\nflask==3.0.0\n"
    resp = client.post(
        "/api/v1/mlops/supply-chain/analyze/requirements",
        json={"content": manifest, "ecosystem": "pypi"},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["total_packages"] == 3
    assert data["overall_risk"] in ("low", "medium", "high", "critical")
    assert len(data["packages"]) == 3


def test_analyze_requirements_malicious_raises_critical(client):
    """A manifest containing 'ctx' produces overall_risk=critical."""
    manifest = "ctx==0.1.0\nrequests==2.31.0\n"
    resp = client.post(
        "/api/v1/mlops/supply-chain/analyze/requirements",
        json={"content": manifest, "ecosystem": "pypi"},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["overall_risk"] == "critical"
    assert data["high_risk_count"] >= 1


# ---------------------------------------------------------------------------
# POST /analyze/typosquats
# ---------------------------------------------------------------------------


def test_detect_typosquats_finds_candidate(client):
    """'requestss' triggers typosquat detection for 'requests'."""
    resp = client.post(
        "/api/v1/mlops/supply-chain/analyze/typosquats",
        json={"package_name": "requestss", "ecosystem": "pypi"},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["is_typosquat"] is True
    assert "requests" in data["typosquat_candidates"]


def test_detect_typosquats_clean_name(client):
    """An unusual name that matches nothing is not a typosquat."""
    resp = client.post(
        "/api/v1/mlops/supply-chain/analyze/typosquats",
        json={"package_name": "uniquexyzpkg99", "ecosystem": "pypi"},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["is_typosquat"] is False
    assert data["typosquat_candidates"] == []


# ---------------------------------------------------------------------------
# GET /check/malicious
# ---------------------------------------------------------------------------


def test_check_malicious_known_bad(client):
    """ctx is flagged as malicious via GET query param."""
    resp = client.get(
        "/api/v1/mlops/supply-chain/check/malicious",
        params={"package": "ctx"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["is_known_malicious"] is True


def test_check_malicious_safe_package(client):
    """requests@2.31.0 is not malicious."""
    resp = client.get(
        "/api/v1/mlops/supply-chain/check/malicious",
        params={"package": "requests", "version": "2.31.0"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["is_known_malicious"] is False


def test_check_malicious_version_specific(client):
    """event-stream@3.3.6 is malicious; event-stream@3.3.5 is not."""
    r_bad = client.get(
        "/api/v1/mlops/supply-chain/check/malicious",
        params={"package": "event-stream", "version": "3.3.6"},
    )
    assert r_bad.status_code == 200
    assert r_bad.json()["is_known_malicious"] is True

    r_good = client.get(
        "/api/v1/mlops/supply-chain/check/malicious",
        params={"package": "event-stream", "version": "3.3.5"},
    )
    assert r_good.status_code == 200
    assert r_good.json()["is_known_malicious"] is False


# ---------------------------------------------------------------------------
# GET /analyses
# ---------------------------------------------------------------------------


def test_list_analyses_returns_list(client):
    """GET /analyses returns a JSON list."""
    resp = client.get(
        "/api/v1/mlops/supply-chain/analyses",
        params={"org_id": "org-list-test"},
    )
    assert resp.status_code == 200, resp.text
    assert isinstance(resp.json(), list)


def test_list_analyses_shows_stored_entry(client):
    """After storing an analysis via /analyze/package, it appears in /analyses."""
    org = "org-persist-check"
    client.post(
        "/api/v1/mlops/supply-chain/analyze/package",
        json={"name": "flask", "version": "3.0.0", "ecosystem": "pypi",
              "org_id": org, "store_result": True},
    )
    resp = client.get(
        "/api/v1/mlops/supply-chain/analyses",
        params={"org_id": org},
    )
    assert resp.status_code == 200, resp.text
    items = resp.json()
    assert len(items) >= 1
    assert any(item.get("package_name") == "flask" for item in items)


# ---------------------------------------------------------------------------
# GET /risk-summary
# ---------------------------------------------------------------------------


def test_risk_summary_shape(client):
    """GET /risk-summary returns 200 with all required fields."""
    resp = client.get(
        "/api/v1/mlops/supply-chain/risk-summary",
        params={"org_id": "org-summary-shape"},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert "total_analyzed" in data
    assert "high_risk_packages" in data
    assert "known_malicious_detected" in data
    assert data["org_id"] == "org-summary-shape"


def test_risk_summary_malicious_increments(client):
    """known_malicious_detected increments after storing a malicious package."""
    org = "org-malicious-incr"
    client.post(
        "/api/v1/mlops/supply-chain/analyze/package",
        json={"name": "ctx", "ecosystem": "pypi", "org_id": org, "store_result": True},
    )
    resp = client.get(
        "/api/v1/mlops/supply-chain/risk-summary",
        params={"org_id": org},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["known_malicious_detected"] >= 1
    assert data["total_analyzed"] >= 1
