"""Tests for AppOmniConnector → /api/v1/sspm/apps fallback.

Validates the engine fallback added in
``saas_security_posture_engine.list_apps_with_appomni_fallback``:

1. Org with registered apps → returns those rows untouched
   (source="org_registered").
2. Org with no rows + connector unconfigured (no APPOMNI_API_KEY)
   → structured needs_credentials hint (NEVER mocks).
3. Org with no rows + injected fake connector returning {status:"ok"} with
   findings → projects unique apps with derived risk_score from severity
   weights (source="appomni").
4. Connector returning {status:"api_error"} → connector_error envelope.
5. Filters apply against derived rows.
6. Org-registered rows take precedence over derived projection.
7. Router end-to-end through TestClient.
"""
from __future__ import annotations

import os
import sys
import uuid
from typing import Any, Dict, List

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def _make_engine(tmp_path):
    from core.saas_security_posture_engine import SaasSecurityPostureEngine
    db = os.path.join(str(tmp_path), f"sspm_{uuid.uuid4().hex}.db")
    return SaasSecurityPostureEngine(db_path=db)


class _FakeAppOmni:
    def __init__(self, status: str = "ok", findings: List[Dict[str, Any]] = None,
                 error: str = ""):
        self._status = status
        self._findings = findings or []
        self._error = error

    def sync(self, org_id: str):
        if self._status == "ok":
            return {
                "status": "ok",
                "mode": "live",
                "org_id": org_id,
                "findings_count": len(self._findings),
                "apps_count": len({f.get("app_id") for f in self._findings}),
                "findings_recorded": len(self._findings),
                "findings": self._findings,
                "ingested_at": "2026-05-03T00:00:00Z",
            }
        if self._status == "needs_credentials":
            return {"status": "needs_credentials", "hint": "Set APPOMNI_API_KEY"}
        if self._status == "api_error":
            return {"status": "api_error", "error": self._error or "boom"}
        return {"status": self._status}


def test_returns_org_registered_when_apps_exist(tmp_path):
    eng = _make_engine(tmp_path)
    eng.register_app("acme", {"app_name": "Slack", "app_category": "communication"})
    out = eng.list_apps_with_appomni_fallback("acme")
    assert out["source"] == "org_registered"
    assert out["total"] == 1
    assert out["apps"][0]["app_name"] == "Slack"


def test_returns_needs_credentials_when_no_data_and_no_creds(tmp_path, monkeypatch):
    eng = _make_engine(tmp_path)
    monkeypatch.delenv("APPOMNI_API_KEY", raising=False)
    out = eng.list_apps_with_appomni_fallback("brand-new-org")
    assert out["apps"] == []
    assert out["total"] == 0
    assert out["source"] == "needs_credentials"
    assert "APPOMNI_API_KEY" in out["hint"]


def test_projects_appomni_findings_into_unique_apps(tmp_path):
    eng = _make_engine(tmp_path)
    fake = _FakeAppOmni(
        status="ok",
        findings=[
            {"app_id": "salesforce", "app_name": "Salesforce",
             "category": "crm", "severity": "high"},
            {"app_id": "salesforce", "app_name": "Salesforce",
             "category": "crm", "severity": "medium"},
            {"app_id": "slack", "app_name": "Slack",
             "category": "communication", "severity": "low"},
        ],
    )
    out = eng.list_apps_with_appomni_fallback("acme", sspm_connector=fake)
    assert out["source"] == "appomni"
    assert out["total"] == 2
    by_id = {a["id"]: a for a in out["apps"]}
    sf = by_id["salesforce"]
    assert sf["app_name"] == "Salesforce"
    assert sf["risk_level"] == "high"
    assert sf["findings_total"] == 2
    # 1 high (5) + 1 medium (2) = 7.0
    assert sf["risk_score"] == 7.0
    slack = by_id["slack"]
    assert slack["risk_level"] == "low"
    assert slack["risk_score"] == 1.0


def test_connector_api_error_returns_envelope(tmp_path):
    eng = _make_engine(tmp_path)
    fake = _FakeAppOmni(status="api_error", error="401 Unauthorized")
    out = eng.list_apps_with_appomni_fallback("acme", sspm_connector=fake)
    assert out["source"] == "connector_error"
    assert "401" in out["error"]


def test_filters_apply_against_derived_rows(tmp_path):
    eng = _make_engine(tmp_path)
    fake = _FakeAppOmni(
        status="ok",
        findings=[
            {"app_id": "a", "category": "crm", "severity": "critical"},
            {"app_id": "b", "category": "communication", "severity": "low"},
        ],
    )
    out = eng.list_apps_with_appomni_fallback(
        "acme", risk_level="critical", sspm_connector=fake,
    )
    assert out["total"] == 1
    assert out["apps"][0]["id"] == "a"


def test_org_rows_take_precedence_over_appomni(tmp_path):
    eng = _make_engine(tmp_path)
    eng.register_app("acme", {"app_name": "Real", "app_category": "communication"})
    fake = _FakeAppOmni(
        status="ok",
        findings=[{"app_id": "x", "category": "crm", "severity": "critical"}],
    )
    out = eng.list_apps_with_appomni_fallback("acme", sspm_connector=fake)
    assert out["source"] == "org_registered"
    assert out["apps"][0]["app_name"] == "Real"


def test_router_wired_to_fallback(tmp_path, monkeypatch):
    """End-to-end through the FastAPI router."""
    from fastapi.testclient import TestClient
    from fastapi import FastAPI
    from apps.api.saas_security_posture_router import router as sspm_router
    from apps.api.auth_deps import api_key_auth
    import apps.api.saas_security_posture_router as sspm_module

    sspm_module._engine = None
    monkeypatch.setattr(
        "core.saas_security_posture_engine._DEFAULT_DB",
        os.path.join(str(tmp_path), "sspm_router.db"),
        raising=False,
    )
    monkeypatch.delenv("APPOMNI_API_KEY", raising=False)

    app = FastAPI()
    app.include_router(sspm_router)
    app.dependency_overrides[api_key_auth] = lambda: True
    client = TestClient(app)

    r = client.get("/api/v1/sspm/apps?org_id=brand-new-org")
    assert r.status_code == 200, r.text
    body = r.json()
    assert isinstance(body, dict)
    assert "apps" in body
    assert "source" in body
    assert body["source"] == "needs_credentials"


def test_router_error_path_unknown_app(tmp_path, monkeypatch):
    """Sanity error path — GET /apps/{id} on missing id returns 404."""
    from fastapi.testclient import TestClient
    from fastapi import FastAPI
    from apps.api.saas_security_posture_router import router as sspm_router
    from apps.api.auth_deps import api_key_auth
    import apps.api.saas_security_posture_router as sspm_module

    sspm_module._engine = None
    monkeypatch.setattr(
        "core.saas_security_posture_engine._DEFAULT_DB",
        os.path.join(str(tmp_path), "sspm_err.db"),
        raising=False,
    )

    app = FastAPI()
    app.include_router(sspm_router)
    app.dependency_overrides[api_key_auth] = lambda: True
    client = TestClient(app)

    r = client.get("/api/v1/sspm/apps/no-such-id?org_id=acme")
    assert r.status_code == 404
