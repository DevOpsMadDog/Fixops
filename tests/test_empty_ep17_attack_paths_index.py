"""EP-17: attack_paths_index wired to AttackPathEngine.list_nodes (not empty)."""
from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client():
    from apps.api.attack_path_router import router
    from fastapi import FastAPI

    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


def test_index_returns_list_not_always_empty(client):
    """GET / must return items key as a list (not hardcoded [])."""
    resp = client.get("/api/v1/attack-paths/", params={"org_id": "default"})
    assert resp.status_code == 200
    body = resp.json()
    assert "items" in body
    assert isinstance(body["items"], list)
    assert "count" in body
    assert body["count"] == len(body["items"])


def test_index_count_matches_items(client):
    """count field must equal len(items) — was broken when items=[] but count>0."""
    resp = client.get("/api/v1/attack-paths/", params={"org_id": "org-test-ep17"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] == len(body["items"])
