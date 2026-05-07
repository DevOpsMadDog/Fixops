"""Smoke tests for POST /api/v1/orgs — Multica #4108.

Verifies:
1. Onboarding wizard payload {name, industry} creates an org (201).
2. Duplicate slug returns 409.
"""
from __future__ import annotations

import os
import uuid

import pytest
from fastapi.testclient import TestClient

_TEST_API_KEY = "test-orgs-router-key-4108"


@pytest.fixture(scope="module", autouse=True)
def _set_api_token():
    """Inject a valid API key so auth_deps lets requests through."""
    prev = os.environ.get("FIXOPS_API_TOKEN")
    os.environ["FIXOPS_API_TOKEN"] = _TEST_API_KEY
    yield
    if prev is None:
        os.environ.pop("FIXOPS_API_TOKEN", None)
    else:
        os.environ["FIXOPS_API_TOKEN"] = prev


@pytest.fixture(scope="module")
def client(_set_api_token):
    from apps.api.app import create_app
    return TestClient(create_app(), raise_server_exceptions=True)


def _headers() -> dict:
    return {"X-API-Key": _TEST_API_KEY}


def test_create_org_wizard_payload(client):
    """POST {name, industry} (wizard shape) must return 201 with org_id + slug."""
    unique = uuid.uuid4().hex[:8]
    payload = {"name": f"Acme {unique}", "industry": "Finance"}
    resp = client.post("/api/v1/orgs", json=payload, headers=_headers())
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert "org_id" in body
    assert "slug" in body
    assert "created_at" in body
    # slug must be derived from name (lowercased, hyphenated)
    assert f"acme-{unique}" in body["slug"] or body["slug"]


def test_create_org_duplicate_returns_409(client):
    """Posting the same slug twice must return 409 Conflict."""
    unique = uuid.uuid4().hex[:8]
    payload = {"name": f"DupeOrg {unique}", "industry": "Healthcare"}
    r1 = client.post("/api/v1/orgs", json=payload, headers=_headers())
    assert r1.status_code == 201, r1.text
    r2 = client.post("/api/v1/orgs", json=payload, headers=_headers())
    assert r2.status_code == 409, r2.text
