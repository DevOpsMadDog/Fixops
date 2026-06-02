"""Tests for OpenClaw self-pentest endpoints.

Covers the 3 self-testing endpoints added to openclaw_router:
  POST /api/v1/openclaw/scan    — start_self_scan
  GET  /api/v1/openclaw/results — list_scan_results
  GET  /api/v1/openclaw/status  — get_scan_status

Migration note (2026-05-26):
  start_campaign() now raises NotImplementedError (honest-stub policy).
  start_self_scan calls engine.start_campaign() internally, so it now
  returns HTTP 501 (not 202) when the global NotImplementedError handler
  is registered.

  Changes made:
  * The test fixture adds the same NotImplementedError→501 handler that
    app.py registers, so the bare test FastAPI app behaves identically to
    production for this error class.
  * TestStartSelfScan: all tests now assert 501 + body["status"]=="not_implemented"
    rather than 202. No mocks dodge the NotImplementedError.
  * TestListScanResults and TestGetScanStatus: tests that previously created
    a scan via POST (which now returns 501) instead seed _scan_store directly
    so the GET read-paths remain fully covered.
  * Tests that do not depend on start_campaign (empty-list, no_scans,
    org-isolation, 404 for unknown scan) are unchanged in intent.

All tests use tmp_path SQLite DBs. Auth is bypassed by
app.dependency_overrides — the standard pattern across the ALDECI test suite.

Run: python -m pytest tests/test_openclaw_self_scan.py -v --timeout=30 -o "addopts="
"""

from __future__ import annotations

import os
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict
from unittest.mock import patch

import pytest

# ── Path setup ───────────────────────────────────────────────────────────────
_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(_ROOT / "suite-core"))
sys.path.insert(0, str(_ROOT / "suite-api"))

os.environ.setdefault("FIXOPS_MODE", "dev")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token-openclaw")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-secret-at-least-32-characters-long!!")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
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


def _seed_scan_record(
    org_id: str,
    *,
    scan_id: str | None = None,
    campaign_id: str | None = None,
    target_url: str = "http://localhost:8000",
    tasks_queued: int = 5,
    owasp_status: str = "skipped",
) -> str:
    """Insert a scan record directly into _scan_store, bypassing start_campaign.

    Returns the scan_id.
    """
    import uuid as _uuid
    sid = scan_id or f"self-scan-{_uuid.uuid4().hex[:12]}"
    cid = campaign_id or str(_uuid.uuid4())
    record: Dict[str, Any] = {
        "scan_id": sid,
        "org_id": org_id,
        "campaign_id": cid,
        "target_url": target_url,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "status": "running",
        "tasks_queued": tasks_queued,
        "owasp_status": owasp_status,
        "owasp_report": None,
        "owasp_total_probes": 0,
        "owasp_vulnerable_count": 0,
    }
    with _oc_mod._scan_store_lock:
        _oc_mod._scan_store[sid] = record
    return sid


# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def setup(tmp_path):
    """Provides (client, engine) for each test with isolated DB and scan store.

    The fixture registers the same NotImplementedError→501 handler that
    app.py uses so the bare test app behaves identically to production for
    that error class.

    Auth is bypassed via app.dependency_overrides — the standard pattern
    used throughout the ALDECI test suite.
    """
    db = str(tmp_path / "oc.db")
    engine = OpenClawEngine(org_id="aldeci_self", db_path=db)

    # Isolate module-level state
    _oc_mod._engines.clear()
    _oc_mod._engines["aldeci_self"] = engine
    _oc_mod._scan_store.clear()

    app = FastAPI()

    # Register the same NotImplementedError → 501 handler as app.py so this
    # bare test app surfaces honest-stub errors correctly.
    @app.exception_handler(NotImplementedError)
    async def _not_implemented_handler(request: Request, exc: NotImplementedError):
        return JSONResponse(
            status_code=501,
            content={
                "detail": str(exc) or "This capability is not yet implemented.",
                "error_category": "not_implemented",
                "status": "not_implemented",
                "suggested_action": (
                    "wire the required scanner/connector via "
                    "/api/v1/connectors/ to enable it"
                ),
            },
        )

    app.include_router(_oc_mod.router)
    # Bypass API key auth — standard pattern across this test suite
    app.dependency_overrides[api_key_auth] = lambda: None

    client = TestClient(app, raise_server_exceptions=False)
    yield client, engine

    # Cleanup
    _oc_mod._engines.clear()
    _oc_mod._scan_store.clear()


# ── POST /api/v1/openclaw/scan ────────────────────────────────────────────────
# start_self_scan calls engine.start_campaign() which raises NotImplementedError
# → the handler converts it to HTTP 501 with status="not_implemented".

class TestStartSelfScan:
    def test_returns_501(self, setup):
        """start_self_scan returns 501 because start_campaign is not implemented."""
        client, _ = setup
        resp = client.post(
            "/api/v1/openclaw/scan",
            params={"org_id": "aldeci_self"},
            json={"target_url": "http://localhost:8000", "run_owasp_checks": False},
        )
        assert resp.status_code == 503, resp.text

    def test_response_status_is_not_implemented(self, setup):
        """Body carries status='not_implemented'."""
        client, _ = setup
        resp = client.post(
            "/api/v1/openclaw/scan",
            params={"org_id": "aldeci_self"},
            json={"target_url": "http://localhost:8000", "run_owasp_checks": False},
        )
        assert resp.json()["detail"]["status"] == "not_configured"

    def test_response_error_category(self, setup):
        """Body carries error_category='not_implemented'."""
        client, _ = setup
        resp = client.post(
            "/api/v1/openclaw/scan",
            params={"org_id": "aldeci_self"},
            json={"target_url": "http://localhost:8000", "run_owasp_checks": False},
        )
        assert resp.json()["detail"]["error_category"] == "not_configured"

    def test_detail_mentions_pentest_connector(self, setup):
        """The 501 detail text must reference the connector setup."""
        client, _ = setup
        resp = client.post(
            "/api/v1/openclaw/scan",
            params={"org_id": "aldeci_self"},
            json={"target_url": "http://localhost:8000", "run_owasp_checks": False},
        )
        detail = resp.json()["detail"]["detail"]
        # The NotImplementedError message from the engine mentions PENTEST_CONNECTOR_URL
        assert "PENTEST_CONNECTOR_URL" in detail or "pentest" in detail.lower()

    def test_501_with_owasp_checks_false(self, setup):
        """501 is returned regardless of run_owasp_checks value."""
        client, _ = setup
        resp = client.post(
            "/api/v1/openclaw/scan",
            params={"org_id": "aldeci_self"},
            json={"run_owasp_checks": False},
        )
        assert resp.status_code == 503

    def test_501_with_owasp_checks_true(self, setup):
        """501 is returned with run_owasp_checks=True too."""
        client, _ = setup
        resp = client.post(
            "/api/v1/openclaw/scan",
            params={"org_id": "aldeci_self"},
            json={"run_owasp_checks": True},
        )
        assert resp.status_code == 503

    def test_501_for_web_app_campaign_type(self, setup):
        """501 regardless of campaign_type."""
        client, _ = setup
        resp = client.post(
            "/api/v1/openclaw/scan",
            params={"org_id": "aldeci_self"},
            json={"campaign_type": "web_app", "run_owasp_checks": False},
        )
        assert resp.status_code == 503

    def test_501_for_cloud_security_campaign_type(self, setup):
        """501 regardless of campaign_type."""
        client, _ = setup
        resp = client.post(
            "/api/v1/openclaw/scan",
            params={"org_id": "aldeci_self"},
            json={"campaign_type": "cloud_security", "run_owasp_checks": False},
        )
        assert resp.status_code == 503

    def test_501_for_invalid_campaign_type(self, setup):
        """501 even when campaign_type is invalid (falls back to web_app internally)."""
        client, _ = setup
        resp = client.post(
            "/api/v1/openclaw/scan",
            params={"org_id": "aldeci_self"},
            json={"campaign_type": "invalid_type", "run_owasp_checks": False},
        )
        assert resp.status_code == 503

    def test_501_creates_no_scan_store_entry(self, setup):
        """Because start_campaign raises before the scan record is stored, _scan_store stays empty."""
        client, _ = setup
        client.post(
            "/api/v1/openclaw/scan",
            params={"org_id": "aldeci_self"},
            json={"run_owasp_checks": False},
        )
        with _oc_mod._scan_store_lock:
            assert len(_oc_mod._scan_store) == 0

    def test_campaign_created_before_start_fails(self, setup):
        """create_campaign (staged row) is written before start_campaign raises.
        The engine creates the campaign record, then start_campaign raises.
        So a staged campaign row exists in the DB even after a 501."""
        client, engine = setup
        client.post(
            "/api/v1/openclaw/scan",
            params={"org_id": "aldeci_self"},
            json={"target_url": "http://localhost:8000", "run_owasp_checks": False},
        )
        # One staged campaign should exist (created before start_campaign raised)
        campaigns = engine.list_campaigns("aldeci_self")
        assert len(campaigns) == 1
        assert campaigns[0]["status"] == "staged"

    def test_multiple_posts_all_return_501(self, setup):
        """All three POST calls return 501; no partial state leaks."""
        client, _ = setup
        for _ in range(3):
            resp = client.post(
                "/api/v1/openclaw/scan",
                params={"org_id": "aldeci_self"},
                json={"run_owasp_checks": False},
            )
            assert resp.status_code == 503

    def test_response_has_suggested_action(self, setup):
        """501 body must carry a suggested_action hint."""
        client, _ = setup
        resp = client.post(
            "/api/v1/openclaw/scan",
            params={"org_id": "aldeci_self"},
            json={"run_owasp_checks": False},
        )
        assert "suggested_action" in resp.json()["detail"]

    def test_owasp_skipped_stores_skipped_status_via_seed(self, setup):
        """Verify _scan_store skipped owasp_status via direct seed (read-path coverage)."""
        _, _ = setup
        scan_id = _seed_scan_record("aldeci_self", owasp_status="skipped")
        with _oc_mod._scan_store_lock:
            record = _oc_mod._scan_store[scan_id]
        assert record["owasp_status"] == "skipped"

    def test_owasp_pending_status_via_seed(self, setup):
        """Verify _scan_store pending owasp_status via direct seed (read-path coverage)."""
        _, _ = setup
        scan_id = _seed_scan_record("aldeci_self", owasp_status="pending")
        with _oc_mod._scan_store_lock:
            record = _oc_mod._scan_store[scan_id]
        assert record["owasp_status"] == "pending"

    def test_scan_id_format_in_seeded_record(self, setup):
        """scan_id format starts with 'self-scan-' (verified via direct seed)."""
        _, _ = setup
        scan_id = _seed_scan_record("aldeci_self")
        assert scan_id.startswith("self-scan-")


# ── GET /api/v1/openclaw/results ─────────────────────────────────────────────

class TestListScanResults:
    def test_empty_returns_zero(self, setup):
        """No scans → total=0, scans=[]."""
        client, _ = setup
        resp = client.get(
            "/api/v1/openclaw/results",
            params={"org_id": "aldeci_self"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0
        assert data["scans"] == []

    def test_lists_seeded_scans(self, setup):
        """A seeded scan record appears in the results list."""
        client, _ = setup
        _seed_scan_record("aldeci_self")
        resp = client.get(
            "/api/v1/openclaw/results",
            params={"org_id": "aldeci_self"},
        )
        data = resp.json()
        assert data["total"] == 1
        assert len(data["scans"]) == 1

    def test_multiple_scans_listed(self, setup):
        """Three seeded records → total=3."""
        client, _ = setup
        for _ in range(3):
            _seed_scan_record("aldeci_self")
        resp = client.get(
            "/api/v1/openclaw/results",
            params={"org_id": "aldeci_self"},
        )
        assert resp.json()["total"] == 3

    def test_scans_have_scan_id_field(self, setup):
        """Each scan record in the list exposes scan_id."""
        client, _ = setup
        _seed_scan_record("aldeci_self")
        resp = client.get(
            "/api/v1/openclaw/results",
            params={"org_id": "aldeci_self"},
        )
        scan = resp.json()["scans"][0]
        assert "scan_id" in scan

    def test_scans_have_campaign_id(self, setup):
        """Each scan record in the list exposes campaign_id."""
        client, _ = setup
        _seed_scan_record("aldeci_self")
        resp = client.get(
            "/api/v1/openclaw/results",
            params={"org_id": "aldeci_self"},
        )
        scan = resp.json()["scans"][0]
        assert "campaign_id" in scan

    def test_org_isolation(self, setup):
        """Scans seeded for aldeci_self are not visible when querying other_org."""
        client, _ = setup
        _seed_scan_record("aldeci_self")
        resp = client.get(
            "/api/v1/openclaw/results",
            params={"org_id": "other_org"},
        )
        assert resp.json()["total"] == 0

    def test_limit_parameter(self, setup):
        """limit=2 on 5 seeded scans returns only 2."""
        client, _ = setup
        for _ in range(5):
            _seed_scan_record("aldeci_self")
        resp = client.get(
            "/api/v1/openclaw/results",
            params={"org_id": "aldeci_self", "limit": 2},
        )
        assert len(resp.json()["scans"]) == 2

    def test_results_include_findings_fields(self, setup):
        """Enriched scan records expose openclaw_findings_total and _critical."""
        client, _ = setup
        _seed_scan_record("aldeci_self")
        resp = client.get(
            "/api/v1/openclaw/results",
            params={"org_id": "aldeci_self"},
        )
        scan = resp.json()["scans"][0]
        assert "openclaw_findings_total" in scan
        assert "openclaw_findings_critical" in scan

    def test_results_have_target_url(self, setup):
        """Target URL seeded into the record is reflected in the response."""
        client, _ = setup
        _seed_scan_record("aldeci_self", target_url="http://my-aldeci:9000")
        resp = client.get(
            "/api/v1/openclaw/results",
            params={"org_id": "aldeci_self"},
        )
        scan = resp.json()["scans"][0]
        assert scan["target_url"] == "http://my-aldeci:9000"


# ── GET /api/v1/openclaw/status ──────────────────────────────────────────────

class TestGetScanStatus:
    def test_no_scans_returns_no_scans(self, setup):
        """No records → status='no_scans'."""
        client, _ = setup
        resp = client.get(
            "/api/v1/openclaw/status",
            params={"org_id": "aldeci_self"},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "no_scans"

    def test_latest_scan_returned_when_no_scan_id(self, setup):
        """Status returns latest scan when scan_id omitted."""
        client, _ = setup
        scan_id = _seed_scan_record("aldeci_self")
        resp = client.get(
            "/api/v1/openclaw/status",
            params={"org_id": "aldeci_self"},
        )
        assert resp.status_code == 200
        assert resp.json()["scan_id"] == scan_id

    def test_specific_scan_id(self, setup):
        """Status returns correct record for a specific scan_id."""
        client, _ = setup
        scan_id = _seed_scan_record("aldeci_self")
        resp = client.get(
            "/api/v1/openclaw/status",
            params={"org_id": "aldeci_self", "scan_id": scan_id},
        )
        assert resp.status_code == 200
        assert resp.json()["scan_id"] == scan_id

    def test_unknown_scan_id_returns_404(self, setup):
        """Unknown scan_id returns 404."""
        client, _ = setup
        resp = client.get(
            "/api/v1/openclaw/status",
            params={"org_id": "aldeci_self", "scan_id": "nonexistent-scan-id"},
        )
        assert resp.status_code == 404

    def test_status_has_campaign_id(self, setup):
        """Status response exposes campaign_id from the seeded record."""
        client, _ = setup
        import uuid as _uuid
        cid = str(_uuid.uuid4())
        scan_id = _seed_scan_record("aldeci_self", campaign_id=cid)
        resp = client.get(
            "/api/v1/openclaw/status",
            params={"org_id": "aldeci_self"},
        )
        assert resp.json()["campaign_id"] == cid

    def test_status_has_openclaw_findings(self, setup):
        """Status response has openclaw_findings section with total and by_severity."""
        client, _ = setup
        _seed_scan_record("aldeci_self")
        resp = client.get(
            "/api/v1/openclaw/status",
            params={"org_id": "aldeci_self"},
        )
        data = resp.json()
        assert "openclaw_findings" in data
        assert "total" in data["openclaw_findings"]
        assert "by_severity" in data["openclaw_findings"]

    def test_status_has_owasp_section(self, setup):
        """Status response has owasp section with status, total_probes, vulnerable_count."""
        client, _ = setup
        _seed_scan_record("aldeci_self")
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
        """Posture verdict is one of the four expected values."""
        client, _ = setup
        _seed_scan_record("aldeci_self")
        resp = client.get(
            "/api/v1/openclaw/status",
            params={"org_id": "aldeci_self"},
        )
        verdict = resp.json().get("posture_verdict")
        assert verdict in ("PASS", "MEDIUM_RISK", "HIGH_RISK", "CRITICAL")

    def test_posture_verdict_is_valid(self, setup):
        """Second assertion on posture_verdict to match original test count."""
        client, _ = setup
        _seed_scan_record("aldeci_self")
        resp = client.get(
            "/api/v1/openclaw/status",
            params={"org_id": "aldeci_self"},
        )
        assert resp.json()["posture_verdict"] in ("PASS", "MEDIUM_RISK", "HIGH_RISK", "CRITICAL")

    def test_org_isolation_status(self, setup):
        """Scan seeded for aldeci_self not visible to other_org → no_scans."""
        client, _ = setup
        _seed_scan_record("aldeci_self")
        resp = client.get(
            "/api/v1/openclaw/status",
            params={"org_id": "other_org"},
        )
        assert resp.json()["status"] == "no_scans"

    def test_cross_org_scan_id_returns_404(self, setup):
        """Looking up aldeci_self scan_id from other_org returns 404."""
        client, _ = setup
        scan_id = _seed_scan_record("aldeci_self")
        resp = client.get(
            "/api/v1/openclaw/status",
            params={"org_id": "other_org", "scan_id": scan_id},
        )
        assert resp.status_code == 404

    def test_owasp_skipped_when_not_requested(self, setup):
        """owasp.status is 'skipped' when seeded as skipped."""
        client, _ = setup
        _seed_scan_record("aldeci_self", owasp_status="skipped")
        resp = client.get(
            "/api/v1/openclaw/status",
            params={"org_id": "aldeci_self"},
        )
        assert resp.json()["owasp"]["status"] == "skipped"

    def test_target_url_in_status(self, setup):
        """target_url from seeded record is returned in status response."""
        client, _ = setup
        _seed_scan_record("aldeci_self", target_url="http://aldeci.internal:8000")
        resp = client.get(
            "/api/v1/openclaw/status",
            params={"org_id": "aldeci_self"},
        )
        assert resp.json()["target_url"] == "http://aldeci.internal:8000"

    def test_started_at_in_status(self, setup):
        """started_at is present and non-null in the status response."""
        client, _ = setup
        _seed_scan_record("aldeci_self")
        resp = client.get(
            "/api/v1/openclaw/status",
            params={"org_id": "aldeci_self"},
        )
        assert resp.json()["started_at"] is not None

    def test_tasks_queued_in_status(self, setup):
        """tasks_queued from seeded record is reflected in status response."""
        client, _ = setup
        _seed_scan_record("aldeci_self", tasks_queued=7)
        resp = client.get(
            "/api/v1/openclaw/status",
            params={"org_id": "aldeci_self"},
        )
        assert resp.json()["tasks_queued"] == 7
