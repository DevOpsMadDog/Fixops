"""Multica #4048 — empty endpoint #31: fix_engine_router mounted.

Verifies the fix-engine remediation router is wired into app.py and reachable.
NOTE (2026-06-03): the router is mounted at the /api/v1/fix-engine/* prefix (not the
old /api/v1/remediation/* the test originally assumed — that prefix only serves
/remediation/tasks). Asserts the real mounted paths so this stays a true
router-is-mounted regression check.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client():
    from apps.api.app import create_app
    return TestClient(create_app(), raise_server_exceptions=False)


def test_fix_engine_templates_reachable(client):
    """GET /api/v1/fix-engine/templates must return 200 or 401 (auth), not 404/501."""
    resp = client.get("/api/v1/fix-engine/templates")
    assert resp.status_code not in (404, 501), (
        f"fix_engine_router templates not mounted — got {resp.status_code}"
    )


def test_fix_engine_playbooks_reachable(client):
    """GET /api/v1/fix-engine/playbooks must return 200 or 401, not 404/501."""
    resp = client.get("/api/v1/fix-engine/playbooks")
    assert resp.status_code not in (404, 501), (
        f"fix_engine_router playbooks not mounted — got {resp.status_code}"
    )
