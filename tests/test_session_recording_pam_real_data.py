"""Tests for CyberArkConnector → /api/v1/session-recording/sessions fallback.

Validates the engine fallback added in
``privileged_session_recording_engine.list_sessions_with_pam_fallback``:

1. Org with recorded sessions → returns those rows untouched
   (source="org_registered").
2. Org with no rows + connector unconfigured (no CYBERARK_* env vars)
   → structured needs_credentials hint (NEVER mocks).
3. Org with no rows + injected fake connector returning {status:"ok"} with
   privileged accounts → projects each account into a session row
   (workload-style inventory) tagged source="cyberark_pam".
4. Connector returning {status:"api_error"} → connector_error envelope.
5. Filters apply against derived rows.
6. Org-registered rows take precedence over derived projection.
7. Router end-to-end through TestClient — must return 200 and the structured
   envelope (no bare list).
"""
from __future__ import annotations

import os
import sys
import uuid
from typing import Any, Dict, List

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def _make_engine(tmp_path):
    from core.privileged_session_recording_engine import (
        PrivilegedSessionRecordingEngine,
    )
    db = os.path.join(str(tmp_path), f"psr_{uuid.uuid4().hex}.db")
    return PrivilegedSessionRecordingEngine(db_path=db)


class _FakeCyberArk:
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
                "accounts_scanned": len(self._findings),
                "findings_recorded": len(self._findings),
                "findings": self._findings,
                "ingested_at": "2026-05-03T00:00:00Z",
            }
        if self._status == "needs_credentials":
            return {
                "status": "needs_credentials",
                "hint": "Set CYBERARK_BASE_URL/USER/PASS",
            }
        if self._status == "api_error":
            return {
                "status": "api_error",
                "error": self._error or "boom",
            }
        return {"status": self._status}


def test_returns_org_registered_when_sessions_exist(tmp_path):
    eng = _make_engine(tmp_path)
    eng.start_session("acme", {
        "user": "alice", "session_type": "ssh",
        "target_host": "bastion-01",
    })
    out = eng.list_sessions_with_pam_fallback("acme")
    assert out["source"] == "org_registered"
    assert out["total"] == 1
    assert out["sessions"][0]["user"] == "alice"


def test_returns_needs_credentials_when_no_data_and_no_creds(tmp_path, monkeypatch):
    eng = _make_engine(tmp_path)
    # Ensure CyberArk env is empty so the lazy import path returns
    # creds_present=False; do NOT inject a connector.
    for k in ("CYBERARK_BASE_URL", "CYBERARK_USER", "CYBERARK_PASS"):
        monkeypatch.delenv(k, raising=False)
    out = eng.list_sessions_with_pam_fallback("brand-new-org")
    assert out["sessions"] == []
    assert out["total"] == 0
    assert out["source"] == "needs_credentials"
    assert "CYBERARK_BASE_URL" in out["hint"]


def test_projects_cyberark_accounts_as_inventory_rows(tmp_path):
    eng = _make_engine(tmp_path)
    fake = _FakeCyberArk(
        status="ok",
        findings=[
            {
                "asset_id": "cyberark:account:42",
                "title": "CyberArk admin account",
                "severity": "high",
                "platform": "WindowsDomain",
                "safe": "DomainAdmins",
                "account_id": "42",
                "correlation_key": "cyberark_account|42",
            },
            {
                "asset_id": "cyberark:account:99",
                "title": "CyberArk linux root",
                "severity": "medium",
                "platform": "UnixSSH",
                "safe": "LinuxRoots",
                "account_id": "99",
                "correlation_key": "cyberark_account|99",
            },
        ],
    )
    out = eng.list_sessions_with_pam_fallback("acme", pam_connector=fake)
    assert out["source"] == "cyberark_pam"
    assert out["total"] == 2
    by_id = {r["id"]: r for r in out["sessions"]}
    assert by_id["42"]["session_type"] == "rdp"  # WindowsDomain → rdp
    assert by_id["99"]["session_type"] == "ssh"  # UnixSSH → ssh
    assert all(s["status"] == "inventory" for s in out["sessions"])
    assert all(s["source"] == "cyberark_pam" for s in out["sessions"])
    assert all(s["initiated_by"] == "cyberark_pam" for s in out["sessions"])


def test_connector_api_error_returns_envelope(tmp_path):
    eng = _make_engine(tmp_path)
    fake = _FakeCyberArk(status="api_error", error="503 from PAS")
    out = eng.list_sessions_with_pam_fallback("acme", pam_connector=fake)
    assert out["source"] == "connector_error"
    assert "503" in out["error"]
    assert out["sessions"] == []


def test_filters_apply_against_derived_rows(tmp_path):
    eng = _make_engine(tmp_path)
    fake = _FakeCyberArk(
        status="ok",
        findings=[
            {"account_id": "1", "platform": "UnixSSH", "safe": "L", "severity": "high"},
            {"account_id": "2", "platform": "OracleDB", "safe": "D", "severity": "low"},
        ],
    )
    out = eng.list_sessions_with_pam_fallback(
        "acme", session_type="database", pam_connector=fake,
    )
    assert out["total"] == 1
    assert out["sessions"][0]["session_type"] == "database"


def test_org_rows_take_precedence_over_pam(tmp_path):
    eng = _make_engine(tmp_path)
    eng.start_session("acme", {
        "user": "real-user", "session_type": "ssh", "target_host": "real-host",
    })
    fake = _FakeCyberArk(
        status="ok",
        findings=[{"account_id": "x", "platform": "UnixSSH", "safe": "L"}],
    )
    out = eng.list_sessions_with_pam_fallback("acme", pam_connector=fake)
    assert out["source"] == "org_registered"
    assert out["sessions"][0]["user"] == "real-user"


def test_router_wired_to_fallback(tmp_path, monkeypatch):
    """End-to-end through the FastAPI router."""
    from fastapi.testclient import TestClient
    from fastapi import FastAPI
    from apps.api.privileged_session_recording_router import router as psr_router
    from apps.api.auth_deps import api_key_auth
    import apps.api.privileged_session_recording_router as psr_module

    # Force a fresh engine pointed at tmp DB.
    psr_module._engine = None
    monkeypatch.setattr(
        "core.privileged_session_recording_engine._DEFAULT_DB",
        os.path.join(str(tmp_path), "psr_router.db"),
        raising=False,
    )
    # Ensure no CYBERARK env so we exercise the needs_credentials path through
    # the real connector lazy-import.
    for k in ("CYBERARK_BASE_URL", "CYBERARK_USER", "CYBERARK_PASS"):
        monkeypatch.delenv(k, raising=False)

    app = FastAPI()
    app.include_router(psr_router)
    app.dependency_overrides[api_key_auth] = lambda: True
    client = TestClient(app)

    r = client.get("/api/v1/session-recording/sessions?org_id=brand-new-org")
    assert r.status_code == 200, r.text
    body = r.json()
    assert isinstance(body, dict)
    assert "sessions" in body
    assert "source" in body
    assert body["source"] == "needs_credentials"


def test_router_error_path_invalid_session_id(tmp_path, monkeypatch):
    """Sanity error path — GET /sessions/{id} on missing id returns 404."""
    from fastapi.testclient import TestClient
    from fastapi import FastAPI
    from apps.api.privileged_session_recording_router import router as psr_router
    from apps.api.auth_deps import api_key_auth
    import apps.api.privileged_session_recording_router as psr_module

    psr_module._engine = None
    monkeypatch.setattr(
        "core.privileged_session_recording_engine._DEFAULT_DB",
        os.path.join(str(tmp_path), "psr_err.db"),
        raising=False,
    )

    app = FastAPI()
    app.include_router(psr_router)
    app.dependency_overrides[api_key_auth] = lambda: True
    client = TestClient(app)

    r = client.get("/api/v1/session-recording/sessions/missing-id?org_id=acme")
    assert r.status_code == 404
