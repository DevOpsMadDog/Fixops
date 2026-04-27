"""Tests for the Global Feed Registry.

1. Discovery — registry catalogs at least cisa_kev / mitre_attack / sigmahq
2. List endpoint — returns every registered feed
3. Detail endpoint — returns full metadata for one feed
4. Refresh endpoint — triggers importer and updates last_imported_at
5. Status field — reflects ok/error after refresh

The refresh tests substitute the importer callable so tests stay offline.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
for sub in ("suite-feeds", "suite-core", "suite-api"):
    p = str(REPO_ROOT / sub)
    if p not in sys.path:
        sys.path.insert(0, p)

from feeds import registry as feed_registry  # noqa: E402


@pytest.fixture(autouse=True)
def _isolate_registry_state(tmp_path, monkeypatch):
    """Each test gets a fresh DB + a fresh discovery pass."""
    db_path = str(tmp_path / "test_feed_registry.db")
    feed_registry._reset_for_tests()
    # Pin the default DB so list/get/refresh share the same temp store
    monkeypatch.setattr(feed_registry, "_DEFAULT_DB", db_path)
    yield
    feed_registry._reset_for_tests()


# ---------------------------------------------------------------------------
# Test 1: discovery picks up the 3 importers shipped today
# ---------------------------------------------------------------------------

def test_discovery_finds_shipped_importers():
    ids = feed_registry.registered_feed_ids()
    assert "cisa_kev" in ids, f"cisa_kev not registered (got {ids})"
    assert "mitre_attack" in ids, f"mitre_attack not registered (got {ids})"
    assert "sigmahq" in ids, f"sigmahq not registered (got {ids})"
    assert len(ids) >= 3


# ---------------------------------------------------------------------------
# Test 2: list endpoint returns every feed with required metadata
# ---------------------------------------------------------------------------

def test_list_endpoint_returns_all_feeds():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from apps.api.feed_registry_router import router

    app = FastAPI()
    # Override auth to no-op for tests
    from apps.api.auth_deps import api_key_auth
    app.dependency_overrides[api_key_auth] = lambda: None
    app.include_router(router)
    client = TestClient(app)

    resp = client.get("/api/v1/feeds/registry")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert isinstance(body, list)
    ids = {f["id"] for f in body}
    assert {"cisa_kev", "mitre_attack", "sigmahq"}.issubset(ids)

    sample = body[0]
    for required in (
        "id", "display_name", "source_url", "source_type",
        "license", "refresh_interval_seconds",
        "last_imported_at", "last_entry_count", "last_status",
    ):
        assert required in sample, f"Missing field {required!r} in registry entry"


# ---------------------------------------------------------------------------
# Test 3: detail endpoint returns full metadata for one feed
# ---------------------------------------------------------------------------

def test_detail_endpoint_returns_metadata():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from apps.api.feed_registry_router import router
    from apps.api.auth_deps import api_key_auth

    app = FastAPI()
    app.dependency_overrides[api_key_auth] = lambda: None
    app.include_router(router)
    client = TestClient(app)

    resp = client.get("/api/v1/feeds/registry/cisa_kev")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["id"] == "cisa_kev"
    assert "cisa.gov" in body["source_url"]
    assert body["source_type"] == "json"
    assert body["refresh_interval_seconds"] == 86_400

    # 404 path
    missing = client.get("/api/v1/feeds/registry/does-not-exist")
    assert missing.status_code == 404


# ---------------------------------------------------------------------------
# Test 4: refresh triggers the importer and updates last_imported_at
# ---------------------------------------------------------------------------

def test_refresh_updates_last_imported_at(monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from apps.api.feed_registry_router import router
    from apps.api.auth_deps import api_key_auth

    feed_registry._ensure_discovered()
    calls = {"n": 0}

    def _fake_importer():
        calls["n"] += 1
        return {"imported": 7, "skipped": 0, "source_count": 7}

    monkeypatch.setitem(
        feed_registry._FEEDS["cisa_kev"].__dict__,
        "importer_callable",
        _fake_importer,
    )

    app = FastAPI()
    app.dependency_overrides[api_key_auth] = lambda: None
    app.include_router(router)
    client = TestClient(app)

    # Pre-state: never imported
    pre = client.get("/api/v1/feeds/registry/cisa_kev").json()
    assert pre["last_imported_at"] is None

    # Trigger refresh
    refresh = client.post("/api/v1/feeds/registry/cisa_kev/refresh")
    assert refresh.status_code == 200, refresh.text
    body = refresh.json()
    assert body["status"] == "ok"
    assert body["imported_at"] is not None
    assert body["entry_count"] == 7
    assert calls["n"] == 1

    # Post-state: detail endpoint reflects new state
    post = client.get("/api/v1/feeds/registry/cisa_kev").json()
    assert post["last_imported_at"] == body["imported_at"]
    assert post["last_status"] == "ok"
    assert post["last_entry_count"] == 7


# ---------------------------------------------------------------------------
# Test 5: status reflects ok/error after refresh
# ---------------------------------------------------------------------------

def test_status_reflects_ok_and_error(monkeypatch):
    feed_registry._ensure_discovered()

    # ---- ok path ----
    monkeypatch.setitem(
        feed_registry._FEEDS["sigmahq"].__dict__,
        "importer_callable",
        lambda: {"rules": 42, "skipped": 0},
    )
    ok_result = feed_registry.refresh_feed("sigmahq")
    assert ok_result["status"] == "ok"
    assert ok_result["entry_count"] == 42

    detail = feed_registry.get_feed("sigmahq")
    assert detail["last_status"] == "ok"
    assert detail["last_error"] is None

    # ---- error path ----
    def _boom():
        raise RuntimeError("network exploded")

    monkeypatch.setitem(
        feed_registry._FEEDS["mitre_attack"].__dict__,
        "importer_callable",
        _boom,
    )
    err_result = feed_registry.refresh_feed("mitre_attack")
    assert err_result["status"] == "error"
    assert "RuntimeError" in (err_result["error"] or "")
    assert "network exploded" in (err_result["error"] or "")

    detail_err = feed_registry.get_feed("mitre_attack")
    assert detail_err["last_status"] == "error"
    assert detail_err["last_imported_at"] is not None  # timestamp captured even on failure
