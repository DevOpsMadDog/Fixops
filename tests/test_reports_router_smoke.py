"""
Smoke tests for reports_router — verifies /reports/templates is not shadowed
by exec_security_reports_router's former /{report_id} catch-all.

Mount-order bug fixed 2026-05-05: exec_security_reports_router previously
registered GET /api/v1/reports/{report_id} before reports_router (via grc_app.py
at line 3063, before reports_router at line 3272), swallowing /reports/templates
(and /reports/stats, /reports/schedules/list).

Fix: removed the catch-all GET /{report_id} and GET /recent from
exec_security_reports_router — those in-memory lookup routes were redundant
with executive_report_router which already owns /api/v1/reports/executive/*.

Test strategy: mount exec_security_reports_router BEFORE reports_router on a
minimal FastAPI app, exactly mirroring the bug scenario. /templates must return
200, not 404 from the (now-removed) catch-all.
"""

import os
import sys
from pathlib import Path

import pytest

# Path injection mirrors sitecustomize.py
_ROOT = Path(__file__).parent.parent
for _suite in ["suite-api", "suite-core", "suite-attack", "suite-feeds", "suite-evidence-risk", "suite-integrations"]:
    _p = str(_ROOT / _suite)
    if _p not in sys.path:
        sys.path.insert(0, _p)


@pytest.fixture(scope="module")
def reports_client():
    """Minimal FastAPI app with only the two conflicting routers mounted in the
    same order as the real app (exec_security_reports BEFORE reports_router).
    No auth middleware — tests the raw route matching logic.
    """
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from apps.api.exec_security_reports_router import router as exec_router
    from apps.api.reports_router import router as reports_router

    app = FastAPI()
    # Mount in the same order as the real app: exec first (grc_app line 3063),
    # reports second (app.py line 3272). This reproduces the original bug and
    # proves the fix holds.
    app.include_router(exec_router)
    app.include_router(reports_router)

    return TestClient(app)


def test_reports_templates_not_shadowed(reports_client):
    """GET /api/v1/reports/templates must return 200 + a list of templates.

    Regression guard: before the fix, exec_security_reports_router had
    GET /{report_id} which matched /templates first, returning 404
    'Report templates not found'.
    """
    r = reports_client.get("/api/v1/reports/templates")
    assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text[:200]}"
    body = r.json()
    assert "templates" in body, f"Missing 'templates' key: {body}"
    assert isinstance(body["templates"], list), "templates must be a list"
    assert len(body["templates"]) > 0, "templates list must not be empty"


def test_reports_stats_not_shadowed(reports_client):
    """GET /api/v1/reports/stats must return 200 — also previously shadowed."""
    r = reports_client.get("/api/v1/reports/stats")
    assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text[:200]}"
    body = r.json()
    assert "total_reports" in body


def test_reports_list(reports_client):
    """GET /api/v1/reports must return 200 + paginated items."""
    r = reports_client.get("/api/v1/reports")
    assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text[:200]}"
    body = r.json()
    assert "items" in body


def test_reports_schedules_list_not_shadowed(reports_client):
    """GET /api/v1/reports/schedules/list must not be swallowed by /{id}.

    Previously shadowed because /{report_id} in exec_security_reports_router
    would match /schedules before /schedules/list was reached.
    """
    r = reports_client.get("/api/v1/reports/schedules/list")
    assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text[:200]}"
