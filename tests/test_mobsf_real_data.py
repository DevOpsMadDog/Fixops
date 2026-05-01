"""Tests for MobSFConnector → /api/v1/mobile-app-security/apps fallback.

Validates the engine fallback added in
``mobile_app_security_engine.list_apps_with_mobsf_fallback``:

1. Org with registered mas_apps → returns those rows untouched
   (source="org_registered").
2. Unconfigured connector (no MOBSF_API_URL / MOBSF_API_KEY) →
   structured ``needs_credentials`` envelope (NEVER mocks).
3. Configured connector with API failure → ``connector_error`` envelope
   surfaces the underlying error string.
4. Configured connector with empty scan corpus → ``needs_scan`` envelope.
5. Configured connector with real scans → projects each MobSF scan as a
   derived app (source="mobsf"), preserves filters.
6. Org-registered rows take precedence over derived projection.
7. ``MobSFConnector.normalize_app`` produces canonical mas_apps shape with
   correct platform / severity / risk_level mapping.
8. ``MobSFConnector.normalize_finding`` produces canonical mas_findings
   shape with valid finding_type + severity enums.
"""
from __future__ import annotations

import os
import sys
import uuid
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def _make_engine(tmp_path):
    from core.mobile_app_security_engine import MobileAppSecurityEngine
    db = os.path.join(str(tmp_path), f"mas_{uuid.uuid4().hex}.db")
    return MobileAppSecurityEngine(db_path=db)


class _FakeMobSFConnector:
    """Stand-in for MobSFConnector with controllable state."""

    def __init__(
        self,
        configured: bool = False,
        payload: Dict[str, Any] = None,
        raise_on_import: bool = False,
    ) -> None:
        self._configured = configured
        self._payload = payload
        self._raise = raise_on_import

    def is_configured(self) -> bool:
        return self._configured

    def import_findings(self, org_id: str) -> Dict[str, Any]:
        if self._raise:
            raise RuntimeError("simulated network outage")
        return self._payload or {"status": "ok", "apps": [], "findings": []}


# ----------------------------------------------------------------------------
# Engine fallback tests
# ----------------------------------------------------------------------------

def test_returns_org_registered_when_apps_exist(tmp_path):
    """Org-registered rows take precedence; MobSF is not consulted."""
    eng = _make_engine(tmp_path)
    eng.register_app("acme", {
        "app_name": "MyApp",
        "bundle_id": "com.acme.app",
        "platform": "ios",
        "category": "enterprise",
    })
    out = eng.list_apps_with_mobsf_fallback("acme")
    assert out["source"] == "org_registered"
    assert out["total"] == 1
    assert out["apps"][0]["app_name"] == "MyApp"


def test_unconfigured_returns_needs_credentials_envelope(tmp_path):
    """No MOBSF_API_URL/KEY → structured envelope, no mocks, no exceptions."""
    eng = _make_engine(tmp_path)
    fake = _FakeMobSFConnector(configured=False)
    out = eng.list_apps_with_mobsf_fallback("empty-org", mobsf_connector=fake)
    assert out["apps"] == []
    assert out["total"] == 0
    assert out["source"] == "needs_credentials"
    assert "MOBSF_API_URL" in out["hint"]
    assert "MOBSF_API_KEY" in out["hint"]


def test_mobsf_api_failure_returns_connector_error(tmp_path):
    """import_findings raising → connector_error envelope, never crashes."""
    eng = _make_engine(tmp_path)
    fake = _FakeMobSFConnector(configured=True, raise_on_import=True)
    out = eng.list_apps_with_mobsf_fallback("empty-org", mobsf_connector=fake)
    assert out["source"] == "connector_error"
    assert out["apps"] == []
    assert "simulated network outage" in out["error"]
    assert "verify" in out["hint"].lower()


def test_configured_but_empty_scans_returns_needs_scan(tmp_path):
    """MobSF up but no scans yet → needs_scan envelope."""
    eng = _make_engine(tmp_path)
    fake = _FakeMobSFConnector(
        configured=True,
        payload={"status": "ok", "apps": [], "findings": []},
    )
    out = eng.list_apps_with_mobsf_fallback("empty-org", mobsf_connector=fake)
    assert out["source"] == "needs_scan"
    assert out["apps"] == []
    assert "MobSF" in out["hint"]


def test_configured_calls_mobsf_api_projects_apps(tmp_path):
    """Real MobSF payload → projected apps with provenance."""
    eng = _make_engine(tmp_path)
    fake = _FakeMobSFConnector(
        configured=True,
        payload={
            "status": "ok",
            "apps": [
                {
                    "app_name": "DVIA-v2",
                    "bundle_id": "com.highaltitudehacks.DVIAswiftv2",
                    "platform": "ios",
                    "version": "2.0",
                    "category": "enterprise",
                    "risk_score": 87.5,
                    "risk_level": "critical",
                    "status": "active",
                    "last_scanned": "2026-05-02T10:00:00",
                    "mobsf_hash": "abc123",
                },
                {
                    "app_name": "DIVA-android",
                    "bundle_id": "jakhar.aseem.diva",
                    "platform": "android",
                    "version": "1.0",
                    "category": "enterprise",
                    "risk_score": 30.0,
                    "risk_level": "medium",
                    "status": "active",
                    "last_scanned": "2026-05-02T11:00:00",
                    "mobsf_hash": "def456",
                },
            ],
            "findings": [],
            "scans_pulled": 2,
            "scorecards_pulled": 2,
        },
    )
    out = eng.list_apps_with_mobsf_fallback("acme", mobsf_connector=fake)
    assert out["source"] == "mobsf"
    assert out["total"] == 2
    assert out["scans_pulled"] == 2
    by_bundle = {a["bundle_id"]: a for a in out["apps"]}
    dvia = by_bundle["com.highaltitudehacks.DVIAswiftv2"]
    assert dvia["platform"] == "ios"
    assert dvia["risk_level"] == "critical"
    assert dvia["risk_score"] == 87.5
    assert dvia["source"] == "mobsf"
    assert dvia["mobsf_hash"] == "abc123"
    assert dvia["id"].startswith("mobsf:")


def test_filters_apply_against_derived_rows(tmp_path):
    """Platform / risk_level filters work on projected rows."""
    eng = _make_engine(tmp_path)
    fake = _FakeMobSFConnector(
        configured=True,
        payload={
            "status": "ok",
            "apps": [
                {"app_name": "iosapp", "bundle_id": "ios.b", "platform": "ios",
                 "risk_level": "critical", "risk_score": 90.0},
                {"app_name": "androidapp", "bundle_id": "and.b",
                 "platform": "android", "risk_level": "low", "risk_score": 10.0},
            ],
        },
    )
    ios_only = eng.list_apps_with_mobsf_fallback(
        "acme", platform="ios", mobsf_connector=fake,
    )
    assert ios_only["total"] == 1
    assert ios_only["apps"][0]["bundle_id"] == "ios.b"
    crit_only = eng.list_apps_with_mobsf_fallback(
        "acme", risk_level="critical", mobsf_connector=fake,
    )
    assert crit_only["total"] == 1
    assert crit_only["apps"][0]["risk_level"] == "critical"


def test_org_rows_take_precedence_over_derived(tmp_path):
    """Even with MobSF data available, org-registered rows win."""
    eng = _make_engine(tmp_path)
    eng.register_app("acme", {
        "app_name": "real-app",
        "bundle_id": "com.acme.real",
        "platform": "android",
        "category": "banking",
    })
    fake = _FakeMobSFConnector(
        configured=True,
        payload={"status": "ok", "apps": [
            {"app_name": "ghost", "bundle_id": "g.b", "platform": "ios",
             "risk_score": 99.0, "risk_level": "critical"},
        ]},
    )
    out = eng.list_apps_with_mobsf_fallback("acme", mobsf_connector=fake)
    assert out["source"] == "org_registered"
    assert out["total"] == 1
    assert out["apps"][0]["app_name"] == "real-app"


# ----------------------------------------------------------------------------
# Connector unit tests — normalize_* + HTTP wrap
# ----------------------------------------------------------------------------

def test_normalize_mobsf_finding_to_aldeci_shape():
    """MobSF scorecard finding → canonical mas_findings shape with valid enums."""
    from connectors.mobsf_connector import MobSFConnector
    c = MobSFConnector(api_url="http://localhost:8000", api_key="test")
    finding = c.normalize_finding(
        org_id="acme",
        app_id="com.acme.app",
        finding={
            "title": "Application uses weak Hash algorithm",
            "description": "Uses MD5 in HmacKeyManager.java",
            "severity": "high",
            "cwe": "CWE-327",
            "masvs": "MASVS-CRYPTO-1",
        },
        section="high",
    )
    assert finding["app_id"] == "com.acme.app"
    assert finding["finding_type"] == "weak_crypto"
    assert finding["severity"] == "high"
    assert finding["cwe_id"] == "CWE-327"
    assert finding["owasp_category"] == "MASVS-CRYPTO-1"
    assert finding["status"] == "open"
    assert finding["source"] == "mobsf"
    # All enums valid
    from core.mobile_app_security_engine import (
        VALID_FINDING_TYPES, VALID_SEVERITIES, VALID_FINDING_STATUSES,
    )
    assert finding["finding_type"] in VALID_FINDING_TYPES
    assert finding["severity"] in VALID_SEVERITIES
    assert finding["status"] in VALID_FINDING_STATUSES


def test_normalize_mobsf_app_to_aldeci_shape():
    """MobSF scan record → canonical mas_apps shape with valid platform."""
    from connectors.mobsf_connector import MobSFConnector
    c = MobSFConnector(api_url="http://localhost:8000", api_key="test")
    app = c.normalize_app("acme", {
        "app_name": "DVIA",
        "package_name": "com.dvia.test",
        "scan_type": "ipa",
        "version_name": "2.0",
        "average_cvss": 8.7,
        "md5": "deadbeef",
        "timestamp": "2026-05-02T10:00:00",
    })
    assert app["platform"] == "ios"
    assert app["bundle_id"] == "com.dvia.test"
    assert app["risk_score"] == 87.0
    assert app["risk_level"] == "critical"
    assert app["mobsf_hash"] == "deadbeef"
    assert app["source"] == "mobsf"
    from core.mobile_app_security_engine import (
        VALID_PLATFORMS, VALID_RISK_LEVELS, VALID_CATEGORIES,
    )
    assert app["platform"] in VALID_PLATFORMS
    assert app["risk_level"] in VALID_RISK_LEVELS
    assert app["category"] in VALID_CATEGORIES


def test_is_configured_reads_env():
    """is_configured() reflects MOBSF_API_URL + MOBSF_API_KEY env presence."""
    from connectors.mobsf_connector import MobSFConnector
    c1 = MobSFConnector(api_url="", api_key="")
    assert c1.is_configured() is False
    c2 = MobSFConnector(api_url="http://localhost:8000", api_key="")
    assert c2.is_configured() is False
    c3 = MobSFConnector(api_url="http://localhost:8000", api_key="abc")
    assert c3.is_configured() is True


def test_import_findings_returns_needs_credentials_when_unconfigured():
    """Connector returns structured envelope, never raises, never mocks."""
    from connectors.mobsf_connector import MobSFConnector
    c = MobSFConnector(api_url="", api_key="")
    out = c.import_findings(org_id="acme")
    assert out["status"] == "needs_credentials"
    assert out["apps"] == []
    assert out["findings"] == []


def test_import_findings_handles_http_error():
    """When MobSF returns HTTP 401, connector returns error envelope."""
    from connectors.mobsf_connector import MobSFConnector
    c = MobSFConnector(api_url="http://localhost:8000", api_key="bad")
    fake_resp = MagicMock(status_code=401, text="unauthorized")
    fake_resp.json.side_effect = ValueError("not json")
    with patch("requests.get", return_value=fake_resp):
        out = c.import_findings(org_id="acme")
    assert out["status"] == "error"
    assert "401" in out.get("error", "")
    assert out["apps"] == []
    assert out["findings"] == []


# ----------------------------------------------------------------------------
# Router-level smoke test
# ----------------------------------------------------------------------------

def test_router_wired_to_fallback(tmp_path, monkeypatch):
    """End-to-end through the FastAPI router."""
    from fastapi.testclient import TestClient
    from fastapi import FastAPI
    from apps.api.mobile_app_security_router import router as mas_router
    from apps.api.auth_deps import api_key_auth
    import apps.api.mobile_app_security_router as mas_module

    mas_module._engine_instance = None
    monkeypatch.setattr(
        "core.mobile_app_security_engine._DEFAULT_DB",
        os.path.join(str(tmp_path), "mas_router.db"),
        raising=False,
    )
    # Force unconfigured
    monkeypatch.delenv("MOBSF_API_URL", raising=False)
    monkeypatch.delenv("MOBSF_API_KEY", raising=False)
    # Reset module-level connector singleton so it picks up the cleared env
    import connectors.mobsf_connector as mc
    mc._DEFAULT_CONNECTOR = None

    app = FastAPI()
    app.include_router(mas_router)
    app.dependency_overrides[api_key_auth] = lambda: True
    client = TestClient(app)

    r = client.get("/api/v1/mobile-app-security/apps?org_id=brand-new-org")
    assert r.status_code == 200, r.text
    body = r.json()
    assert isinstance(body, dict)
    assert "apps" in body
    assert "source" in body
    assert body["source"] == "needs_credentials"
    assert body["apps"] == []
    assert "MOBSF_API_URL" in body.get("hint", "")
