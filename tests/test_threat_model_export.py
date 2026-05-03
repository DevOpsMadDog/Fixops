"""Tests for GET /api/v1/threat-models/{model_id}/export endpoint.

Covers:
  - 404 on unknown model
  - empty model export (no threats)
  - export includes all STRIDE/DREAD fields for a scored threat
  - matrix keys present in export
  - multiple threats all appear in export
  - average_dread_score computed correctly
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from fastapi import FastAPI

from core.threat_model import STRIDECategory, ThreatModelEngine
from apps.api.threat_model_router import router, _get_engine

try:
    from apps.api.auth_deps import api_key_auth as _api_key_auth
except ImportError:
    _api_key_auth = None


# ---------------------------------------------------------------------------
# App fixture — isolated engine per test
# ---------------------------------------------------------------------------

@pytest.fixture()
def client(tmp_path):
    app = FastAPI()
    app.include_router(router)

    db = str(tmp_path / "tm_export_test.db")
    engine = ThreatModelEngine(db_path=db)

    app.dependency_overrides[_get_engine] = lambda: engine
    # Bypass API key auth in tests
    if _api_key_auth is not None:
        app.dependency_overrides[_api_key_auth] = lambda: "test-key"
    yield TestClient(app), engine
    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _create_model(engine: ThreatModelEngine, name: str = "Export Test Model") -> str:
    return engine.create_model(
        name=name,
        system_description="REST API handling PII user data with auth tokens",
        data_flow_description="Client -> API Gateway -> Service -> DB",
        trust_boundaries=["external", "internal"],
        org_id="testorg",
    )


def _add_threat(engine: ThreatModelEngine, model_id: str,
                category: STRIDECategory = STRIDECategory.SPOOFING) -> str:
    return engine.add_threat(
        model_id=model_id,
        title=f"{category.value} threat",
        description=f"Test threat for {category.value}",
        stride_category=category,
        affected_component="api-gateway",
        org_id="testorg",
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestExportEndpoint:
    def test_export_unknown_model_returns_404(self, client):
        tc, _ = client
        resp = tc.get("/api/v1/threat-models/nonexistent-id/export")
        assert resp.status_code == 404
        assert "not found" in resp.json()["detail"].lower()

    def test_export_empty_model_returns_200(self, client):
        tc, engine = client
        model_id = _create_model(engine)
        resp = tc.get(f"/api/v1/threat-models/{model_id}/export")
        assert resp.status_code == 200
        body = resp.json()
        assert body["model_id"] == model_id
        assert body["threats"] == []
        assert body["total_threats"] == 0
        assert body["average_dread_score"] == 0.0
        assert body["export_version"] == "1.0"

    def test_export_contains_threat_fields(self, client):
        tc, engine = client
        model_id = _create_model(engine)
        threat_id = _add_threat(engine, model_id, STRIDECategory.TAMPERING)

        # Score the threat so DREAD fields appear
        from core.threat_model import DREADScore
        dread = DREADScore(damage=8, reproducibility=7, exploitability=6,
                           affected_users=5, discoverability=4)
        engine.score_threat(threat_id, dread)

        resp = tc.get(f"/api/v1/threat-models/{model_id}/export")
        assert resp.status_code == 200
        body = resp.json()

        assert body["total_threats"] == 1
        t = body["threats"][0]
        assert t["id"] == threat_id
        assert t["stride_category"].upper() == "TAMPERING"
        assert t["affected_component"] == "api-gateway"
        assert "dread_score" in t
        assert t["dread_total"] == pytest.approx(6.0)  # mean(8,7,6,5,4)=30/5

    def test_export_summary_keys_present(self, client):
        tc, engine = client
        model_id = _create_model(engine)
        _add_threat(engine, model_id, STRIDECategory.SPOOFING)

        resp = tc.get(f"/api/v1/threat-models/{model_id}/export")
        assert resp.status_code == 200
        body = resp.json()

        summary = body["summary"]
        assert "by_stride_category" in summary
        assert "by_status" in summary
        assert "total_threats" in summary
        assert "average_dread_score" in summary

    def test_export_threat_matrix_keys_present(self, client):
        tc, engine = client
        model_id = _create_model(engine)
        # auto-identify to populate matrix
        engine.auto_identify_threats(model_id)

        resp = tc.get(f"/api/v1/threat-models/{model_id}/export")
        assert resp.status_code == 200
        body = resp.json()

        matrix = body["threat_matrix"]
        # Matrix must be a dict keyed by STRIDE categories
        assert isinstance(matrix, dict)
        stride_values_upper = {c.value.upper() for c in STRIDECategory}
        for key in matrix:
            assert key.upper() in stride_values_upper

    def test_export_all_threats_included(self, client):
        tc, engine = client
        model_id = _create_model(engine)
        ids = [
            _add_threat(engine, model_id, STRIDECategory.SPOOFING),
            _add_threat(engine, model_id, STRIDECategory.DENIAL_OF_SERVICE),
            _add_threat(engine, model_id, STRIDECategory.ELEVATION_OF_PRIVILEGE),
        ]

        resp = tc.get(f"/api/v1/threat-models/{model_id}/export")
        assert resp.status_code == 200
        body = resp.json()

        assert body["total_threats"] == 3
        exported_ids = {t["id"] for t in body["threats"]}
        assert exported_ids == set(ids)

    def test_export_average_dread_score_correct(self, client):
        tc, engine = client
        model_id = _create_model(engine)
        from core.threat_model import DREADScore

        t1 = _add_threat(engine, model_id, STRIDECategory.SPOOFING)
        t2 = _add_threat(engine, model_id, STRIDECategory.INFORMATION_DISCLOSURE)

        # t1 total=mean(5,5,5,5,5)=5.0, t2 total=mean(3,3,3,3,3)=3.0, avg=(5+3)/2=4.0
        engine.score_threat(t1, DREADScore(damage=5, reproducibility=5,
                                           exploitability=5, affected_users=5,
                                           discoverability=5))
        engine.score_threat(t2, DREADScore(damage=3, reproducibility=3,
                                           exploitability=3, affected_users=3,
                                           discoverability=3))

        resp = tc.get(f"/api/v1/threat-models/{model_id}/export")
        assert resp.status_code == 200
        body = resp.json()
        assert body["average_dread_score"] == pytest.approx(4.0)
