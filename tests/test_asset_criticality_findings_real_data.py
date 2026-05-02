"""Tests for SecurityFindingsEngine → /api/v1/asset-criticality/assets fallback.

Validates the engine fallback added in
``asset_criticality_engine.list_assets_with_findings_fallback``:

1. Org with registered assets → returns those rows untouched
   (source="org_registered").
2. Org with no rows + no findings_engine reachable → structured
   needs_credentials hint (NEVER mocks).
3. Org with no rows + injected findings engine returning rows → projects
   distinct asset_id into asset records with derived criticality_score from
   severity weights (source="security_findings"). Multiple findings against
   the same asset roll up the score.
4. Tier mapping: 80+ → critical, 60+ → high, 40+ → medium, < 40 → low.
5. Filters apply against derived rows (criticality_tier, asset_type).
6. Org-registered rows take precedence over derived projection.
7. Router end-to-end through TestClient.
"""
from __future__ import annotations

import os
import sys
import uuid
from typing import Any, Dict, List, Optional

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def _make_engine(tmp_path):
    from core.asset_criticality_engine import AssetCriticalityEngine
    db = os.path.join(str(tmp_path), f"assetcrit_{uuid.uuid4().hex}.db")
    return AssetCriticalityEngine(db_path=db)


class _FakeFindingsEngine:
    """Stand-in for SecurityFindingsEngine.list_findings()."""

    def __init__(self, findings: List[Dict[str, Any]] = None,
                 raise_exc: Optional[Exception] = None):
        self._findings = findings or []
        self._raise = raise_exc

    def list_findings(self, org_id: str, status=None, severity=None,
                      source_tool=None):
        if self._raise is not None:
            raise self._raise
        return list(self._findings)


def test_returns_org_registered_when_assets_exist(tmp_path):
    eng = _make_engine(tmp_path)
    eng.register_asset(
        org_id="acme", asset_name="prod-db",
        asset_type="database", owner="dba",
    )
    out = eng.list_assets_with_findings_fallback("acme")
    assert out["source"] == "org_registered"
    assert out["total"] == 1
    assert out["assets"][0]["asset_name"] == "prod-db"


def test_returns_needs_credentials_when_findings_engine_returns_zero(tmp_path):
    eng = _make_engine(tmp_path)

    class _NoFindings:
        def list_findings(self, org_id, **kw):
            return []

    out = eng.list_assets_with_findings_fallback(
        "brand-new-org", findings_engine=_NoFindings(),
    )
    # Engine reachable but no findings → still needs_credentials envelope
    # (NEVER mocks, never invents an asset).
    assert out["assets"] == []
    assert out["source"] == "needs_credentials"
    assert "cloud-credential-backed connector" in out["hint"]


def test_projects_findings_into_distinct_assets_with_score(tmp_path):
    eng = _make_engine(tmp_path)
    fake = _FakeFindingsEngine(findings=[
        {"asset_id": "i-aaa", "asset_type": "ec2", "severity": "critical",
         "source_tool": "cspm_via_prowler", "created_at": "2026-05-02"},
        {"asset_id": "i-aaa", "asset_type": "ec2", "severity": "high",
         "source_tool": "cspm_via_trivy", "created_at": "2026-05-02"},
        {"asset_id": "saas:slack", "asset_type": "saas_application",
         "severity": "low", "source_tool": "appomni",
         "created_at": "2026-05-02"},
    ])
    out = eng.list_assets_with_findings_fallback("acme", findings_engine=fake)
    assert out["source"] == "security_findings"
    assert out["total"] == 2
    by_id = {a["id"]: a for a in out["assets"]}
    ec2 = by_id["i-aaa"]
    # 1 critical (25) + 1 high (15) = 40 → tier "medium"
    assert ec2["criticality_score"] == 40.0
    assert ec2["criticality_tier"] == "medium"
    assert ec2["findings_total"] == 2
    assert sorted(ec2["source_tools"]) == ["cspm_via_prowler", "cspm_via_trivy"]
    slack = by_id["saas:slack"]
    assert slack["criticality_score"] == 2.0
    assert slack["criticality_tier"] == "low"


def test_tier_mapping_promotes_to_critical(tmp_path):
    eng = _make_engine(tmp_path)
    # 4 critical (4*25=100) → tier "critical"
    fake = _FakeFindingsEngine(findings=[
        {"asset_id": "crown", "asset_type": "database", "severity": "critical"},
        {"asset_id": "crown", "asset_type": "database", "severity": "critical"},
        {"asset_id": "crown", "asset_type": "database", "severity": "critical"},
        {"asset_id": "crown", "asset_type": "database", "severity": "critical"},
    ])
    out = eng.list_assets_with_findings_fallback("acme", findings_engine=fake)
    assert out["assets"][0]["criticality_score"] == 100.0
    assert out["assets"][0]["criticality_tier"] == "critical"


def test_filters_apply_against_derived_rows(tmp_path):
    eng = _make_engine(tmp_path)
    # ec2-1: 4 critical → 100 → tier "critical"
    # rds-1: 1 low → 2 → tier "low"
    fake = _FakeFindingsEngine(findings=[
        {"asset_id": "ec2-1", "asset_type": "ec2", "severity": "critical"},
        {"asset_id": "ec2-1", "asset_type": "ec2", "severity": "critical"},
        {"asset_id": "ec2-1", "asset_type": "ec2", "severity": "critical"},
        {"asset_id": "ec2-1", "asset_type": "ec2", "severity": "critical"},
        {"asset_id": "rds-1", "asset_type": "rds", "severity": "low"},
    ])
    by_type = eng.list_assets_with_findings_fallback(
        "acme", asset_type="rds", findings_engine=fake,
    )
    assert by_type["total"] == 1
    assert by_type["assets"][0]["asset_type"] == "rds"

    by_tier = eng.list_assets_with_findings_fallback(
        "acme", criticality_tier="critical", findings_engine=fake,
    )
    assert by_tier["total"] == 1
    assert by_tier["assets"][0]["id"] == "ec2-1"


def test_org_rows_take_precedence_over_findings(tmp_path):
    eng = _make_engine(tmp_path)
    eng.register_asset(org_id="acme", asset_name="real-asset",
                       asset_type="database")
    fake = _FakeFindingsEngine(findings=[
        {"asset_id": "x", "asset_type": "ec2", "severity": "critical"},
    ])
    out = eng.list_assets_with_findings_fallback("acme", findings_engine=fake)
    assert out["source"] == "org_registered"
    assert out["assets"][0]["asset_name"] == "real-asset"


def test_findings_engine_raises_returns_connector_error(tmp_path):
    eng = _make_engine(tmp_path)
    fake = _FakeFindingsEngine(raise_exc=RuntimeError("db locked"))
    out = eng.list_assets_with_findings_fallback("acme", findings_engine=fake)
    assert out["source"] == "connector_error"
    assert "db locked" in out["error"]


def test_router_wired_to_fallback(tmp_path, monkeypatch):
    """End-to-end through the FastAPI router."""
    from fastapi.testclient import TestClient
    from fastapi import FastAPI
    from apps.api.asset_criticality_router import router as ac_router
    from apps.api.auth_deps import api_key_auth
    import apps.api.asset_criticality_router as ac_module

    ac_module._engine = None
    monkeypatch.setattr(
        "core.asset_criticality_engine._DEFAULT_DB",
        os.path.join(str(tmp_path), "ac_router.db"),
        raising=False,
    )
    # Force SecurityFindingsEngine to a tmp DB too so the router doesn't pick
    # up production findings during the test run.
    monkeypatch.setattr(
        "core.security_findings_engine._DEFAULT_DB",
        os.path.join(str(tmp_path), "sec_findings_router.db"),
        raising=False,
    )

    app = FastAPI()
    app.include_router(ac_router)
    app.dependency_overrides[api_key_auth] = lambda: True
    client = TestClient(app)

    r = client.get("/api/v1/asset-criticality/assets?org_id=brand-new-org")
    assert r.status_code == 200, r.text
    body = r.json()
    assert isinstance(body, dict)
    assert "assets" in body
    assert "source" in body
    # Empty tmp findings DB → needs_credentials envelope.
    assert body["source"] == "needs_credentials"
    assert body["total"] == 0


def test_router_error_path_unknown_asset(tmp_path, monkeypatch):
    """Sanity error path — GET /assets/{id} on missing id returns 404."""
    from fastapi.testclient import TestClient
    from fastapi import FastAPI
    from apps.api.asset_criticality_router import router as ac_router
    from apps.api.auth_deps import api_key_auth
    import apps.api.asset_criticality_router as ac_module

    ac_module._engine = None
    monkeypatch.setattr(
        "core.asset_criticality_engine._DEFAULT_DB",
        os.path.join(str(tmp_path), "ac_err.db"),
        raising=False,
    )

    app = FastAPI()
    app.include_router(ac_router)
    app.dependency_overrides[api_key_auth] = lambda: True
    client = TestClient(app)

    r = client.get("/api/v1/asset-criticality/assets/no-such-id?org_id=acme")
    assert r.status_code == 404
