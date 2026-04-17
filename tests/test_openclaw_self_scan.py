"""Tests for OpenClaw self-pentest endpoints.

Covers the 3 self-testing endpoints added to openclaw_router:
  POST /api/v1/openclaw/scan    — start_self_scan
  GET  /api/v1/openclaw/results — list_scan_results
  GET  /api/v1/openclaw/status  — get_scan_status

All tests use tmp_path SQLite DBs. Auth is bypassed by patching _AUTH_DEP
at the router module level before the FastAPI app is built.

Run: python -m pytest tests/test_openclaw_self_scan.py -v --timeout=30 -o "addopts="
"""

from __future__ import annotations

import os
import sys
import threading
from pathlib import Path
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest

# ── Path setup ───────────────────────────────────────────────────────────────
_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(_ROOT / "suite-core"))
sys.path.insert(0, str(_ROOT / "suite-api"))

os.environ.setdefault("FIXOPS_MODE", "dev")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token-openclaw")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-secret-at-least-32-characters-long!!")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

from fastapi import FastAPI
from fastapi.testclient import TestClient

import apps.api.openclaw_router as _oc_mod
from apps.api.auth_deps import api_key_auth
from core.openclaw_engine import OpenClawEngine


# ── Helpers ──────────────────────────────────────────────────────────────────

def _make_mock_owasp_report() -> Dict[str, Any]:
    return {
        "summary": {
            "total_probes": 20,
            "vulnerable": 2,
            "safe": 18,
            "risk_score": 35.0,
        },
        "categories": {},
        "generated_at": "2026-04-17T00:00:00+00:00",
    }


# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def setup(tmp_path):
    """Provides (client, engine) for each test with isolated DB and scan store.

    Auth is bypassed via app.dependency_overrides — the standard pattern used
    throughout the ALDECI test suite.
    """
    db = str(tmp_path / "oc.db")
    engine = OpenClawEngine(org_id="aldeci_self", db_path=db)

    # Isolate module-level state
    _oc_mod._engines.clear()
    _oc_mod._engines["aldeci_self"] = engine
    _oc_mod._scan_store.clear()

    app = FastAPI()
    app.include_router(_oc_mod.router)
    # Bypass API key auth — standard pattern across this test suite
    app.dependency_overrides[api_key_auth] = lambda: None

    client = TestClient(app, raise_server_exceptions=False)
    yield client, engine

    # Cleanup
    _oc_mod._engines.clear()
    _oc_mod._scan_store.clear()


# ── POST /api/v1/openclaw/scan ────────────────────────────────────────────────

class TestStartSelfScan:
    def test_returns_202(self, setup):
        client, _ = setup
        resp = client.post(
            "/api/v1/openclaw/scan",
            params={"org_id": "aldeci_self"},
            json={"target_url": "http://localhost:8000", "run_owasp_checks": False},
        )
        assert resp.status_code == 202, resp.text

    def test_response_has_scan_id(self, setup):
        client, _ = setup
        resp = client.post(
            "/api/v1/openclaw/scan",
            params={"org_id": "aldeci_self"},
            json={"target_url": "http://localhost:8000", "run_owasp_checks": False},
        )
        data = resp.json()
        assert "scan_id" in data
        assert data["scan_id"].startswith("self-scan-")

    def test_response_has_campaign_id(self, setup):
        client, _ = setup
        resp = client.post(
            "/api/v1/openclaw/scan",
            params={"org_id": "aldeci_self"},
            json={"target_url": "http://localhost:8000", "run_owasp_checks": False},
        )
        data = resp.json()
        assert "campaign_id" in data
        assert data["campaign_id"]

    def test_status_is_running(self, setup):
        client, _ = setup
        resp = client.post(
            "/api/v1/openclaw/scan",
            params={"org_id": "aldeci_self"},
            json={"target_url": "http://localhost:8000", "run_owasp_checks": False},
        )
        assert resp.json()["status"] == "running"

    def test_tasks_queued_positive(self, setup):
        client, _ = setup
        resp = client.post(
            "/api/v1/openclaw/scan",
            params={"org_id": "aldeci_self"},
            json={"target_url": "http://localhost:8000", "run_owasp_checks": False},
        )
        assert resp.json()["tasks_queued"] > 0

    def test_owasp_checks_flag_false(self, setup):
        client, _ = setup
        resp = client.post(
            "/api/v1/openclaw/scan",
            params={"org_id": "aldeci_self"},
            json={"target_url": "http://localhost:8000", "run_owasp_checks": False},
        )
        assert resp.json()["owasp_checks"] is False

    def test_owasp_checks_flag_true(self, setup):
        client, _ = setup
        with patch("apps.api.openclaw_router._run_owasp_async"):
            resp = client.post(
                "/api/v1/openclaw/scan",
                params={"org_id": "aldeci_self"},
                json={"target_url": "http://localhost:8000", "run_owasp_checks": True},
            )
        assert resp.json()["owasp_checks"] is True

    def test_scan_stored_in_module(self, setup):
        client, _ = setup
        resp = client.post(
            "/api/v1/openclaw/scan",
            params={"org_id": "aldeci_self"},
            json={"target_url": "http://localhost:8000", "run_owasp_checks": False},
        )
        scan_id = resp.json()["scan_id"]
        with _oc_mod._scan_store_lock:
            assert scan_id in _oc_mod._scan_store

    def test_creates_openclaw_campaign(self, setup):
        client, engine = setup
        resp = client.post(
            "/api/v1/openclaw/scan",
            params={"org_id": "aldeci_self"},
            json={"target_url": "http://localhost:8000", "run_owasp_checks": False},
        )
        campaign_id = resp.json()["campaign_id"]
        campaign = engine.get_campaign("aldeci_self", campaign_id)
        assert campaign is not None
        assert campaign["campaign_type"] == "web_app"

    def test_default_campaign_type_is_web_app(self, setup):
        client, engine = setup
        resp = client.post(
            "/api/v1/openclaw/scan",
            params={"org_id": "aldeci_self"},
            json={"run_owasp_checks": False},
        )
        campaign_id = resp.json()["campaign_id"]
        campaign = engine.get_campaign("aldeci_self", campaign_id)
        assert campaign["campaign_type"] == "web_app"

    def test_custom_campaign_type(self, setup):
        client, engine = setup
        resp = client.post(
            "/api/v1/openclaw/scan",
            params={"org_id": "aldeci_self"},
            json={"campaign_type": "cloud_security", "run_owasp_checks": False},
        )
        assert resp.status_code == 202, resp.text
        campaign_id = resp.json()["campaign_id"]
        campaign = engine.get_campaign("aldeci_self", campaign_id)
        assert campaign["campaign_type"] == "cloud_security"

    def test_invalid_campaign_type_falls_back_to_web_app(self, setup):
        client, engine = setup
        resp = client.post(
            "/api/v1/openclaw/scan",
            params={"org_id": "aldeci_self"},
            json={"campaign_type": "invalid_type", "run_owasp_checks": False},
        )
        assert resp.status_code == 202, resp.text
        campaign_id = resp.json()["campaign_id"]
        campaign = engine.get_campaign("aldeci_self", campaign_id)
        assert campaign["campaign_type"] == "web_app"

    def test_message_contains_status_hint(self, setup):
        client, _ = setup
        resp = client.post(
            "/api/v1/openclaw/scan",
            params={"org_id": "aldeci_self"},
            json={"run_owasp_checks": False},
        )
        msg = resp.json()["message"]
        assert "status" in msg.lower() or "poll" in msg.lower()

    def test_multiple_scans_creates_multiple_campaigns(self, setup):
        client, engine = setup
        for _ in range(3):
            r = client.post(
                "/api/v1/openclaw/scan",
                params={"org_id": "aldeci_self"},
                json={"run_owasp_checks": False},
            )
            assert r.status_code == 202
        campaigns = engine.list_campaigns("aldeci_self")
        assert len(campaigns) == 3

    def test_owasp_checks_stores_pending_status(self, setup):
        """With run_owasp_checks=True, scan record has owasp_status=pending."""
        client, _ = setup
        with patch("apps.api.openclaw_router._run_owasp_async"):
            resp = client.post(
                "/api/v1/openclaw/scan",
                params={"org_id": "aldeci_self"},
                json={"target_url": "http://localhost:8000", "run_owasp_checks": True},
            )
        assert resp.status_code == 202, resp.text
        scan_id = resp.json()["scan_id"]
        with _oc_mod._scan_store_lock:
            record = _oc_mod._scan_store[scan_id]
        assert record["owasp_status"] == "pending"

    def test_owasp_skipped_stores_skipped_status(self, setup):
        """With run_owasp_checks=False, scan record has owasp_status=skipped."""
        client, _ = setup
        resp = client.post(
            "/api/v1/openclaw/scan",
            params={"org_id": "aldeci_self"},
            json={"run_owasp_checks": False},
        )
        scan_id = resp.json()["scan_id"]
        with _oc_mod._scan_store_lock:
            record = _oc_mod._scan_store[scan_id]
        assert record["owasp_status"] == "skipped"


# ── GET /api/v1/openclaw/results ─────────────────────────────────────────────

class TestListScanResults:
    def test_empty_returns_zero(self, setup):
        client, _ = setup
        resp = client.get(
            "/api/v1/openclaw/results",
            params={"org_id": "aldeci_self"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0
        assert data["scans"] == []

    def test_lists_created_scans(self, setup):
        client, _ = setup
        client.post(
            "/api/v1/openclaw/scan",
            params={"org_id": "aldeci_self"},
            json={"run_owasp_checks": False},
        )
        resp = client.get(
            "/api/v1/openclaw/results",
            params={"org_id": "aldeci_self"},
        )
        data = resp.json()
        assert data["total"] == 1
        assert len(data["scans"]) == 1

    def test_multiple_scans_listed(self, setup):
        client, _ = setup
        for _ in range(3):
            client.post(
                "/api/v1/openclaw/scan",
                params={"org_id": "aldeci_self"},
                json={"run_owasp_checks": False},
            )
        resp = client.get(
            "/api/v1/openclaw/results",
            params={"org_id": "aldeci_self"},
        )
        assert resp.json()["total"] == 3

    def test_scans_have_scan_id_field(self, setup):
        client, _ = setup
        client.post(
            "/api/v1/openclaw/scan",
            params={"org_id": "aldeci_self"},
            json={"run_owasp_checks": False},
        )
        resp = client.get(
            "/api/v1/openclaw/results",
            params={"org_id": "aldeci_self"},
        )
        scan = resp.json()["scans"][0]
        assert "scan_id" in scan

    def test_scans_have_campaign_id(self, setup):
        client, _ = setup
        client.post(
            "/api/v1/openclaw/scan",
            params={"org_id": "aldeci_self"},
            json={"run_owasp_checks": False},
        )
        resp = client.get(
            "/api/v1/openclaw/results",
            params={"org_id": "aldeci_self"},
        )
        scan = resp.json()["scans"][0]
        assert "campaign_id" in scan

    def test_org_isolation(self, setup):
        client, _ = setup
        client.post(
            "/api/v1/openclaw/scan",
            params={"org_id": "aldeci_self"},
            json={"run_owasp_checks": False},
        )
        resp = client.get(
            "/api/v1/openclaw/results",
            params={"org_id": "other_org"},
        )
        assert resp.json()["total"] == 0

    def test_limit_parameter(self, setup):
        client, _ = setup
        for _ in range(5):
            client.post(
                "/api/v1/openclaw/scan",
                params={"org_id": "aldeci_self"},
                json={"run_owasp_checks": False},
            )
        resp = client.get(
            "/api/v1/openclaw/results",
            params={"org_id": "aldeci_self", "limit": 2},
        )
        assert len(resp.json()["scans"]) == 2

    def test_results_include_findings_fields(self, setup):
        client, _ = setup
        client.post(
            "/api/v1/openclaw/scan",
            params={"org_id": "aldeci_self"},
            json={"run_owasp_checks": False},
        )
        resp = client.get(
            "/api/v1/openclaw/results",
            params={"org_id": "aldeci_self"},
        )
        scan = resp.json()["scans"][0]
        assert "openclaw_findings_total" in scan
        assert "openclaw_findings_critical" in scan

    def test_results_have_target_url(self, setup):
        client, _ = setup
        client.post(
            "/api/v1/openclaw/scan",
            params={"org_id": "aldeci_self"},
            json={"target_url": "http://my-aldeci:9000", "run_owasp_checks": False},
        )
        resp = client.get(
            "/api/v1/openclaw/results",
            params={"org_id": "aldeci_self"},
        )
        scan = resp.json()["scans"][0]
        assert scan["target_url"] == "http://my-aldeci:9000"


# ── GET /api/v1/openclaw/status ──────────────────────────────────────────────

class TestGetScanStatus:
    def test_no_scans_returns_no_scans(self, setup):
        client, _ = setup
        resp = client.get(
            "/api/v1/openclaw/status",
            params={"org_id": "aldeci_self"},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "no_scans"

    def test_latest_scan_returned_when_no_scan_id(self, setup):
        client, _ = setup
        r = client.post(
            "/api/v1/openclaw/scan",
            params={"org_id": "aldeci_self"},
            json={"run_owasp_checks": False},
        )
        scan_id = r.json()["scan_id"]
        resp = client.get(
            "/api/v1/openclaw/status",
            params={"org_id": "aldeci_self"},
        )
        assert resp.status_code == 200
        assert resp.json()["scan_id"] == scan_id

    def test_specific_scan_id(self, setup):
        client, _ = setup
        r = client.post(
            "/api/v1/openclaw/scan",
            params={"org_id": "aldeci_self"},
            json={"run_owasp_checks": False},
        )
        scan_id = r.json()["scan_id"]
        resp = client.get(
            "/api/v1/openclaw/status",
            params={"org_id": "aldeci_self", "scan_id": scan_id},
        )
        assert resp.status_code == 200
        assert resp.json()["scan_id"] == scan_id

    def test_unknown_scan_id_returns_404(self, setup):
        client, _ = setup
        resp = client.get(
            "/api/v1/openclaw/status",
            params={"org_id": "aldeci_self", "scan_id": "nonexistent-scan-id"},
        )
        assert resp.status_code == 404

    def test_status_has_campaign_id(self, setup):
        client, _ = setup
        r = client.post(
            "/api/v1/openclaw/scan",
            params={"org_id": "aldeci_self"},
            json={"run_owasp_checks": False},
        )
        campaign_id = r.json()["campaign_id"]
        resp = client.get(
            "/api/v1/openclaw/status",
            params={"org_id": "aldeci_self"},
        )
        assert resp.json()["campaign_id"] == campaign_id

    def test_status_has_openclaw_findings(self, setup):
        client, _ = setup
        client.post(
            "/api/v1/openclaw/scan",
            params={"org_id": "aldeci_self"},
            json={"run_owasp_checks": False},
        )
        resp = client.get(
            "/api/v1/openclaw/status",
            params={"org_id": "aldeci_self"},
        )
        data = resp.json()
        assert "openclaw_findings" in data
        assert "total" in data["openclaw_findings"]
        assert "by_severity" in data["openclaw_findings"]

    def test_status_has_owasp_section(self, setup):
        client, _ = setup
        client.post(
            "/api/v1/openclaw/scan",
            params={"org_id": "aldeci_self"},
            json={"run_owasp_checks": False},
        )
        resp = client.get(
            "/api/v1/openclaw/status",
            params={"org_id": "aldeci_self"},
        )
        data = resp.json()
        assert "owasp" in data
        assert "status" in data["owasp"]
        assert "total_probes" in data["owasp"]
        assert "vulnerable_count" in data["owasp"]

    def test_status_has_posture_verdict(self, setup):
        client, _ = setup
        client.post(
            "/api/v1/openclaw/scan",
            params={"org_id": "aldeci_self"},
            json={"run_owasp_checks": False},
        )
        resp = client.get(
            "/api/v1/openclaw/status",
            params={"org_id": "aldeci_self"},
        )
        verdict = resp.json().get("posture_verdict")
        assert verdict in ("PASS", "MEDIUM_RISK", "HIGH_RISK", "CRITICAL")

    def test_posture_verdict_is_valid(self, setup):
        client, _ = setup
        client.post(
            "/api/v1/openclaw/scan",
            params={"org_id": "aldeci_self"},
            json={"run_owasp_checks": False},
        )
        resp = client.get(
            "/api/v1/openclaw/status",
            params={"org_id": "aldeci_self"},
        )
        assert resp.json()["posture_verdict"] in ("PASS", "MEDIUM_RISK", "HIGH_RISK", "CRITICAL")

    def test_org_isolation_status(self, setup):
        client, _ = setup
        client.post(
            "/api/v1/openclaw/scan",
            params={"org_id": "aldeci_self"},
            json={"run_owasp_checks": False},
        )
        resp = client.get(
            "/api/v1/openclaw/status",
            params={"org_id": "other_org"},
        )
        assert resp.json()["status"] == "no_scans"

    def test_cross_org_scan_id_returns_404(self, setup):
        client, _ = setup
        r = client.post(
            "/api/v1/openclaw/scan",
            params={"org_id": "aldeci_self"},
            json={"run_owasp_checks": False},
        )
        scan_id = r.json()["scan_id"]
        resp = client.get(
            "/api/v1/openclaw/status",
            params={"org_id": "other_org", "scan_id": scan_id},
        )
        assert resp.status_code == 404

    def test_owasp_skipped_when_not_requested(self, setup):
        client, _ = setup
        client.post(
            "/api/v1/openclaw/scan",
            params={"org_id": "aldeci_self"},
            json={"run_owasp_checks": False},
        )
        resp = client.get(
            "/api/v1/openclaw/status",
            params={"org_id": "aldeci_self"},
        )
        assert resp.json()["owasp"]["status"] == "skipped"

    def test_target_url_in_status(self, setup):
        client, _ = setup
        client.post(
            "/api/v1/openclaw/scan",
            params={"org_id": "aldeci_self"},
            json={"target_url": "http://aldeci.internal:8000", "run_owasp_checks": False},
        )
        resp = client.get(
            "/api/v1/openclaw/status",
            params={"org_id": "aldeci_self"},
        )
        assert resp.json()["target_url"] == "http://aldeci.internal:8000"

    def test_started_at_in_status(self, setup):
        client, _ = setup
        client.post(
            "/api/v1/openclaw/scan",
            params={"org_id": "aldeci_self"},
            json={"run_owasp_checks": False},
        )
        resp = client.get(
            "/api/v1/openclaw/status",
            params={"org_id": "aldeci_self"},
        )
        assert resp.json()["started_at"] is not None

    def test_tasks_queued_in_status(self, setup):
        client, _ = setup
        client.post(
            "/api/v1/openclaw/scan",
            params={"org_id": "aldeci_self"},
            json={"run_owasp_checks": False},
        )
        resp = client.get(
            "/api/v1/openclaw/status",
            params={"org_id": "aldeci_self"},
        )
        assert resp.json()["tasks_queued"] > 0
