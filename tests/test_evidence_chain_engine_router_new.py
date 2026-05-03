"""Tests for the 3 new evidence_chain_router endpoints.

Covers:
  GET  /api/v1/evidence-chain/            — summary
  POST /api/v1/evidence-chain/export-coverage  — verify_export_coverage
  GET  /api/v1/evidence-chain/verifications    — list_verifications

Run:
    pytest tests/test_evidence_chain_engine_router_new.py -v --timeout=10
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

_repo = Path(__file__).parent.parent
for _p in [str(_repo / "suite-core"), str(_repo / "suite-api")]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

from fastapi import FastAPI
from fastapi.testclient import TestClient

from apps.api.auth_deps import api_key_auth
from core.evidence_chain_engine import EvidenceChainEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine(tmp_path):
    return EvidenceChainEngine(db_path=str(tmp_path / "ec_new.db"))


@pytest.fixture
def client(tmp_path, monkeypatch):
    """TestClient wired to an isolated EvidenceChainEngine, auth bypassed."""
    import apps.api.evidence_chain_router as mod

    _eng = EvidenceChainEngine(db_path=str(tmp_path / "ec_router.db"))
    monkeypatch.setattr(mod, "_engine", _eng)

    from apps.api.evidence_chain_router import router
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[api_key_auth] = lambda: None
    return TestClient(app, raise_server_exceptions=True)


# ---------------------------------------------------------------------------
# 1. GET / — summary
# ---------------------------------------------------------------------------

class TestSummaryEndpoint:
    def test_summary_returns_200(self, client):
        resp = client.get("/api/v1/evidence-chain/")
        assert resp.status_code == 200

    def test_summary_has_router_key(self, client):
        body = client.get("/api/v1/evidence-chain/").json()
        assert body["router"] == "evidence-chain"

    def test_summary_has_stats_key(self, client):
        body = client.get("/api/v1/evidence-chain/").json()
        assert "stats" in body

    def test_summary_stats_contains_total_cases(self, client):
        body = client.get("/api/v1/evidence-chain/").json()
        assert "total_cases" in body["stats"]

    def test_summary_org_id_reflected(self, client):
        body = client.get("/api/v1/evidence-chain/?org_id=acme").json()
        assert body["org_id"] == "acme"


# ---------------------------------------------------------------------------
# 2. POST /export-coverage
# ---------------------------------------------------------------------------

class TestExportCoverage:
    def _seed_evidence(self, engine, org="cov-org"):
        case = engine.create_case(org, {"case_title": "Seed case", "case_type": "forensic"})
        engine.add_evidence(org, case["case_id"], {
            "evidence_type": "log",
            "filename": "auth.log",
            "hash_sha256": "abc123",
            "collected_by": "agent",
        })
        engine.add_evidence(org, case["case_id"], {
            "evidence_type": "file",
            "filename": "malware.bin",
            "hash_sha256": "def456",
            "collected_by": "analyst",
        })

    def test_export_coverage_returns_201(self, client):
        resp = client.post(
            "/api/v1/evidence-chain/export-coverage?org_id=cov-org",
            json={},
        )
        assert resp.status_code == 201

    def test_export_coverage_empty_org_zero_pct(self, client):
        resp = client.post(
            "/api/v1/evidence-chain/export-coverage?org_id=empty-org",
            json={},
        )
        body = resp.json()
        assert body["coverage_pct"] == 0.0
        assert body["total_org_evidence"] == 0

    def test_export_coverage_with_framework_filter(self, client, engine, monkeypatch):
        import apps.api.evidence_chain_router as mod
        monkeypatch.setattr(mod, "_engine", engine)
        self._seed_evidence(engine, "cov-org2")
        resp = client.post(
            "/api/v1/evidence-chain/export-coverage?org_id=cov-org2",
            json={"framework": "NIST CSF"},
        )
        body = resp.json()
        assert "coverage_pct" in body
        assert "gaps_count" in body
        assert "over_collection_count" in body

    def test_export_coverage_persists_verification(self, client, engine, monkeypatch):
        import apps.api.evidence_chain_router as mod
        monkeypatch.setattr(mod, "_engine", engine)
        client.post(
            "/api/v1/evidence-chain/export-coverage?org_id=persist-org",
            json={},
        )
        verifs = engine.list_verifications("persist-org")
        assert len(verifs) == 1

    def test_export_coverage_has_verification_id(self, client):
        resp = client.post(
            "/api/v1/evidence-chain/export-coverage?org_id=vid-org",
            json={},
        )
        body = resp.json()
        assert "verification_id" in body
        assert len(body["verification_id"]) == 36  # UUID4


# ---------------------------------------------------------------------------
# 3. GET /verifications
# ---------------------------------------------------------------------------

class TestListVerifications:
    def test_verifications_empty_returns_list(self, client):
        resp = client.get("/api/v1/evidence-chain/verifications?org_id=no-verif")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_verifications_after_coverage_check(self, client):
        for _ in range(2):
            client.post(
                "/api/v1/evidence-chain/export-coverage?org_id=list-org",
                json={},
            )
        resp = client.get("/api/v1/evidence-chain/verifications?org_id=list-org")
        assert resp.status_code == 200
        assert len(resp.json()) == 2

    def test_verifications_limit_respected(self, client):
        for _ in range(5):
            client.post(
                "/api/v1/evidence-chain/export-coverage?org_id=limit-org",
                json={},
            )
        resp = client.get(
            "/api/v1/evidence-chain/verifications?org_id=limit-org&limit=3"
        )
        assert resp.status_code == 200
        assert len(resp.json()) <= 3

    def test_verifications_has_coverage_pct_field(self, client):
        client.post(
            "/api/v1/evidence-chain/export-coverage?org_id=field-org",
            json={},
        )
        verifs = client.get(
            "/api/v1/evidence-chain/verifications?org_id=field-org"
        ).json()
        assert len(verifs) == 1
        assert "coverage_pct" in verifs[0]
        assert "verified_at" in verifs[0]
