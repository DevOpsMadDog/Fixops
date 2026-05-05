"""Test #20 — wire /api/v1/playbooks/ to SecurityPlaybookEngine.

Verifies that the endpoint returns real playbook data (not an empty stub)
by falling through to SecurityPlaybookEngine.get_builtin_playbooks().
"""
from __future__ import annotations

import os
import pytest
from fastapi.testclient import TestClient

_API_TOKEN = "test-playbooks-token-20"
_AUTH = {"X-API-Key": _API_TOKEN}


@pytest.fixture(scope="module")
def client():
    os.environ["FIXOPS_API_TOKEN"] = _API_TOKEN
    from apps.api.app import create_app
    app = create_app()
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c
    os.environ.pop("FIXOPS_API_TOKEN", None)


def test_playbooks_returns_items(client: TestClient) -> None:
    """GET /api/v1/playbooks/ must return items list with at least one entry."""
    resp = client.get("/api/v1/playbooks/", headers=_AUTH)
    assert resp.status_code == 200, f"expected 200, got {resp.status_code}: {resp.text[:200]}"
    data = resp.json()
    assert "items" in data, f"missing 'items' key: {data}"
    assert isinstance(data["items"], list), "'items' must be a list"
    assert len(data["items"]) > 0, (
        "items list is empty — SecurityPlaybookEngine fallback not wired correctly"
    )
    assert "total" in data
    assert data["total"] == len(data["items"])


def test_playbooks_item_shape(client: TestClient) -> None:
    """Each playbook item must have at least a name field."""
    resp = client.get("/api/v1/playbooks/", headers=_AUTH)
    assert resp.status_code == 200
    items = resp.json()["items"]
    assert len(items) > 0
    first = items[0]
    assert "name" in first, f"playbook missing 'name': {first}"
