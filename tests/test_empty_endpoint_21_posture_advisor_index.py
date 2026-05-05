"""Multica #3982 — posture-advisor GET / wired to real recommendations engine.

Before fix: returned {"items": [], "count": 0} (hardcoded stub).
After fix: delegates to get_posture_advisor().list_recommendations() for real items.
"""
from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

API_KEY = "fixops_test_key_ep21"
os.environ["FIXOPS_API_TOKEN"] = API_KEY
os.environ.setdefault("FIXOPS_MODE", "dev")

from apps.api.app import create_app  # noqa: E402

HEADERS = {"X-API-Key": API_KEY}


@pytest.fixture(scope="module")
def client() -> TestClient:
    return TestClient(create_app())


def test_posture_index_returns_200(client: TestClient) -> None:
    """GET /api/v1/posture-advisor/ must return HTTP 200."""
    r = client.get("/api/v1/posture-advisor/", headers=HEADERS)
    assert r.status_code == 200, r.text


def test_posture_index_items_is_list_with_count(client: TestClient) -> None:
    """items must be a list and count must match its length (not hardcoded [])."""
    r = client.get("/api/v1/posture-advisor/", headers=HEADERS)
    data = r.json()
    assert "items" in data, f"missing items key: {data}"
    assert "count" in data, f"missing count key: {data}"
    assert isinstance(data["items"], list)
    assert data["count"] == len(data["items"]), "count must match len(items)"
    assert data.get("router") == "posture-advisor"
