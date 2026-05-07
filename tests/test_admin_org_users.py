"""Smoke tests for GET/POST /api/v1/orgs/{org_id}/users — Multica #4128."""
from __future__ import annotations

import os
import sys
import uuid

import pytest
from fastapi import Depends, FastAPI, HTTPException, Security
from fastapi.security import APIKeyHeader
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-api"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))

TEST_KEY = "test-key-org-users"
_header_extractor = APIKeyHeader(name="X-API-Key", auto_error=False)


async def _test_auth(key: str = Security(_header_extractor)):
    if key != TEST_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")


def _make_app() -> FastAPI:
    """Minimal app: org_router with api_key_auth overridden by test stub."""
    from apps.api import auth_deps
    from apps.api.org_router import router as org_router

    app = FastAPI()
    app.dependency_overrides[auth_deps.api_key_auth] = _test_auth
    app.include_router(org_router)
    return app


@pytest.fixture(scope="module")
def client():
    return TestClient(_make_app(), raise_server_exceptions=True)


def _h():
    return {"X-API-Key": TEST_KEY}


# ── Smoke test 1: GET /api/v1/orgs/{org_id}/users returns 200 + items list ──

def test_list_org_users_returns_200(client):
    resp = client.get("/api/v1/orgs/smoke-org/users", headers=_h())
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    body = resp.json()
    assert "items" in body, f"Missing 'items' key: {body}"
    assert "total" in body, f"Missing 'total' key: {body}"
    assert isinstance(body["items"], list), "'items' must be a list"


# ── Smoke test 2: POST /api/v1/orgs/{org_id}/users creates user → 201 ──

def test_invite_org_user_returns_201(client):
    unique_email = f"invite-{uuid.uuid4().hex[:8]}@example.com"
    payload = {
        "email": unique_email,
        "role": "viewer",
        "first_name": "Test",
        "last_name": "Invitee",
    }
    resp = client.post("/api/v1/orgs/smoke-org/users", json=payload, headers=_h())
    assert resp.status_code == 201, f"Expected 201, got {resp.status_code}: {resp.text}"
    body = resp.json()
    assert body.get("email") == unique_email, f"Email mismatch: {body}"
    assert body.get("role") == "viewer", f"Role mismatch: {body}"
    assert "id" in body, f"Missing 'id' in response: {body}"
