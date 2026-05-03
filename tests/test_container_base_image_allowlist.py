"""Tests for container base-image allowlist — engine + router.

Coverage:
  1. add_allowlist_entry — happy path
  2. add_allowlist_entry — duplicate rejected (400)
  3. list_allowlist — returns all entries for org
  4. check_image_allowed — exact tag match
  5. check_image_allowed — wildcard '*' match
  6. check_image_allowed — not-on-list returns allowed=False
  7. remove_allowlist_entry — deletes and returns 200
  8. remove_allowlist_entry — missing entry returns 404

Usage:
    pytest tests/test_container_base_image_allowlist.py -v --timeout=10
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

# ---------------------------------------------------------------------------
# Engine-level fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def engine(tmp_path):
    from core.container_registry_security_engine import ContainerRegistrySecurityEngine

    db = str(tmp_path / "test_allowlist.db")
    return ContainerRegistrySecurityEngine(db_path=db)


ORG = "test-org"


# ---------------------------------------------------------------------------
# 1. Engine: add_allowlist_entry happy path
# ---------------------------------------------------------------------------


def test_add_allowlist_entry_creates_record(engine):
    entry = engine.add_allowlist_entry(ORG, {"image": "python", "tag_pattern": "3.12-slim", "reason": "approved base"})
    assert entry["id"]
    assert entry["image"] == "python"
    assert entry["tag_pattern"] == "3.12-slim"
    assert entry["org_id"] == ORG


# ---------------------------------------------------------------------------
# 2. Engine: duplicate rejected
# ---------------------------------------------------------------------------


def test_add_allowlist_entry_duplicate_raises(engine):
    engine.add_allowlist_entry(ORG, {"image": "ubuntu", "tag_pattern": "22.04"})
    with pytest.raises(ValueError, match="already exists"):
        engine.add_allowlist_entry(ORG, {"image": "ubuntu", "tag_pattern": "22.04"})


# ---------------------------------------------------------------------------
# 3. Engine: list_allowlist returns entries
# ---------------------------------------------------------------------------


def test_list_allowlist_returns_entries(engine):
    engine.add_allowlist_entry(ORG, {"image": "alpine"})
    engine.add_allowlist_entry(ORG, {"image": "debian", "tag_pattern": "bookworm-slim"})
    entries = engine.list_allowlist(ORG)
    images = [e["image"] for e in entries]
    assert "alpine" in images
    assert "debian" in images


# ---------------------------------------------------------------------------
# 4. Engine: check exact tag match
# ---------------------------------------------------------------------------


def test_check_image_allowed_exact_match(engine):
    engine.add_allowlist_entry(ORG, {"image": "python", "tag_pattern": "3.11"})
    result = engine.check_image_allowed(ORG, "python", "3.11")
    assert result["allowed"] is True
    assert result["matched_entry"]["image"] == "python"


# ---------------------------------------------------------------------------
# 5. Engine: wildcard '*' matches any tag
# ---------------------------------------------------------------------------


def test_check_image_allowed_wildcard(engine):
    engine.add_allowlist_entry(ORG, {"image": "gcr.io/distroless/base", "tag_pattern": "*"})
    result = engine.check_image_allowed(ORG, "gcr.io/distroless/base", "nonroot")
    assert result["allowed"] is True


# ---------------------------------------------------------------------------
# 6. Engine: image not on allowlist
# ---------------------------------------------------------------------------


def test_check_image_not_allowed(engine):
    result = engine.check_image_allowed(ORG, "random-unknown-image", "latest")
    assert result["allowed"] is False
    assert result["matched_entry"] is None


# ---------------------------------------------------------------------------
# Router fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def app(tmp_path):
    from apps.api.auth_deps import api_key_auth
    from apps.api.container_registry_security_router import router, _get_engine
    from core.container_registry_security_engine import ContainerRegistrySecurityEngine

    _eng = ContainerRegistrySecurityEngine(db_path=str(tmp_path / "router_allowlist.db"))

    test_app = FastAPI()
    test_app.include_router(router)
    test_app.dependency_overrides[api_key_auth] = lambda: None
    test_app.dependency_overrides[_get_engine] = lambda: _eng
    return test_app


@pytest.fixture()
def client(app):
    return TestClient(app)


# ---------------------------------------------------------------------------
# 7. Router: DELETE removes entry
# ---------------------------------------------------------------------------


def test_router_delete_allowlist_entry(client):
    resp = client.post(
        "/api/v1/container-registry-security/allowlist",
        params={"org_id": ORG},
        json={"image": "node", "tag_pattern": "20-alpine", "reason": "CI base"},
    )
    assert resp.status_code == 201
    entry_id = resp.json()["id"]

    del_resp = client.delete(
        f"/api/v1/container-registry-security/allowlist/{entry_id}",
        params={"org_id": ORG},
    )
    assert del_resp.status_code == 200
    assert del_resp.json()["deleted"] is True


# ---------------------------------------------------------------------------
# 8. Router: DELETE missing entry returns 404
# ---------------------------------------------------------------------------


def test_router_delete_nonexistent_entry_returns_404(client):
    resp = client.delete(
        "/api/v1/container-registry-security/allowlist/nonexistent-id",
        params={"org_id": ORG},
    )
    assert resp.status_code == 404
