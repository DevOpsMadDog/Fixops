"""Multica #4048 — empty endpoint #31: fix_engine_router mounted.

Verifies that /api/v1/remediation/playbooks and /api/v1/remediation/templates
are now reachable (not 404/501) after fix_engine_router was wired into app.py.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client():
    from apps.api.app import create_app
    return TestClient(create_app(), raise_server_exceptions=False)


def test_fix_engine_templates_reachable(client):
    """GET /api/v1/remediation/templates must return 200 or 401 (auth), not 404/501."""
    resp = client.get("/api/v1/remediation/templates")
    assert resp.status_code not in (404, 501), (
        f"fix_engine_router not mounted — got {resp.status_code}"
    )


def test_fix_engine_executions_reachable(client):
    """GET /api/v1/remediation/executions must return 200 or 401, not 404/501."""
    resp = client.get("/api/v1/remediation/executions")
    assert resp.status_code not in (404, 501), (
        f"fix_engine_router executions not mounted — got {resp.status_code}"
    )
