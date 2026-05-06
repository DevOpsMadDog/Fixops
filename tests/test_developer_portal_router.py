"""
Smoke tests for developer-portal alias endpoints (Multica #4026).

Covers:
  GET /api/v1/developer-portal/repos    -> 200
  GET /api/v1/developer-portal/findings -> 200
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client():
    from apps.api.auth_deps import api_key_auth
    from apps.api.developer_portal_router import alias_router

    app = FastAPI()
    app.include_router(alias_router)
    # Bypass auth — unit test, no token available
    app.dependency_overrides[api_key_auth] = lambda: None
    return TestClient(app, raise_server_exceptions=True)


def test_developer_portal_repos_200(client):
    resp = client.get(
        "/api/v1/developer-portal/repos",
        params={"org_id": "default", "developer_email": "test@example.com"},
    )
    assert resp.status_code == 200, resp.text
    assert isinstance(resp.json(), list)


def test_developer_portal_findings_200(client):
    resp = client.get(
        "/api/v1/developer-portal/findings",
        params={"org_id": "default", "developer_email": "test@example.com"},
    )
    assert resp.status_code == 200, resp.text
    assert isinstance(resp.json(), list)


def test_developer_portal_findings_author_filter(client):
    resp = client.get(
        "/api/v1/developer-portal/findings",
        params={
            "org_id": "default",
            "developer_email": "test@example.com",
            "author": "alice",
        },
    )
    assert resp.status_code == 200, resp.text
    assert isinstance(resp.json(), list)
