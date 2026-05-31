"""Tests for raas_intel_router — Multica #3760.

Covers: info, CRUD per table (groups/negotiations/leak-posts), 401 on missing key,
time-filter on leak posts, status filter on extortion negotiations, validation errors.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Generator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# Helpers — isolate the module-level DB singleton between tests
# ---------------------------------------------------------------------------

def _build_app(db_path: str) -> FastAPI:
    os.environ["RAAS_INTEL_DB_PATH"] = db_path

    mod_name = "apps.api.raas_intel_router"
    if mod_name in sys.modules:
        del sys.modules[mod_name]

    import apps.api.raas_intel_router as mod  # noqa: PLC0415

    mod._db = None  # type: ignore[attr-defined]

    from apps.api.auth_deps import api_key_auth  # noqa: PLC0415

    app = FastAPI()
    app.dependency_overrides[api_key_auth] = lambda: None
    app.include_router(mod.router)
    return app


@pytest.fixture()
def client(tmp_path: Path) -> Generator[TestClient, None, None]:
    db_path = str(tmp_path / "test_raas.db")
    app = _build_app(db_path)
    with TestClient(app) as c:
        yield c


# ===========================================================================
# 1. GET / — info endpoint
# ===========================================================================

def test_info_returns_200(client: TestClient) -> None:
    r = client.get("/api/v1/raas-intel/")
    assert r.status_code == 200
    body = r.json()
    assert body["service"] == "RaaS Intelligence"
    assert body["group_count"] == 0
    assert body["leak_posts_last_30d"] == 0
    assert body["open_negotiations"] == 0
    assert body["status"] == "empty"
    assert isinstance(body["endpoints"], list)
    assert len(body["endpoints"]) >= 7


# ===========================================================================
# 2. RaaS groups — create + list
# ===========================================================================

def test_create_group_returns_201(client: TestClient) -> None:
    payload = {"name": "BlackCat", "aliases": ["ALPHV"], "tactics": ["T1486"], "status": "active"}
    r = client.post("/api/v1/raas-intel/raas-groups", json=payload)
    assert r.status_code == 201
    body = r.json()
    assert body["name"] == "BlackCat"
    assert body["status"] == "active"
    assert "id" in body
    assert "created_at" in body


def test_list_groups_default_org(client: TestClient) -> None:
    client.post("/api/v1/raas-intel/raas-groups", json={"name": "LockBit"})
    r = client.get("/api/v1/raas-intel/raas-groups")
    assert r.status_code == 200
    body = r.json()
    assert body["count"] >= 1
    names = [g["name"] for g in body["groups"]]
    assert "LockBit" in names


def test_list_groups_status_filter(client: TestClient) -> None:
    client.post("/api/v1/raas-intel/raas-groups", json={"name": "REvil", "status": "defunct"})
    client.post("/api/v1/raas-intel/raas-groups", json={"name": "Clop", "status": "active"})
    r = client.get("/api/v1/raas-intel/raas-groups?status=defunct")
    assert r.status_code == 200
    body = r.json()
    assert all(g["status"] == "defunct" for g in body["groups"])
    names = [g["name"] for g in body["groups"]]
    assert "REvil" in names
    assert "Clop" not in names


def test_update_group(client: TestClient) -> None:
    r = client.post("/api/v1/raas-intel/raas-groups", json={"name": "Hive"})
    gid = r.json()["id"]
    r2 = client.put(
        f"/api/v1/raas-intel/raas-groups/{gid}",
        json={"status": "defunct", "last_seen": "2024-01"},
    )
    assert r2.status_code == 200
    assert r2.json()["status"] == "defunct"
    assert r2.json()["last_seen"] == "2024-01"


def test_update_group_invalid_status(client: TestClient) -> None:
    r = client.post("/api/v1/raas-intel/raas-groups", json={"name": "X"})
    gid = r.json()["id"]
    r2 = client.put(f"/api/v1/raas-intel/raas-groups/{gid}", json={"status": "invisible"})
    assert r2.status_code == 422


def test_update_group_not_found(client: TestClient) -> None:
    r = client.put(
        "/api/v1/raas-intel/raas-groups/nonexistent-id",
        json={"status": "defunct"},
    )
    assert r.status_code == 404


# ===========================================================================
# 3. Extortion negotiations — create + list + status filter
# ===========================================================================

def test_create_negotiation_returns_201(client: TestClient) -> None:
    payload = {"ransom_demand_usd": 500000.0, "status": "open", "notes": "First contact"}
    r = client.post("/api/v1/raas-intel/extortion-intel", json=payload)
    assert r.status_code == 201
    body = r.json()
    assert body["ransom_demand_usd"] == 500000.0
    assert body["status"] == "open"
    assert body["paid"] == 0


def test_list_negotiations_status_filter(client: TestClient) -> None:
    client.post("/api/v1/raas-intel/extortion-intel", json={"status": "open"})
    client.post("/api/v1/raas-intel/extortion-intel", json={"status": "paid"})
    r = client.get("/api/v1/raas-intel/extortion-intel?status=open")
    assert r.status_code == 200
    body = r.json()
    assert body["count"] >= 1
    assert all(n["status"] == "open" for n in body["negotiations"])


def test_create_negotiation_invalid_status(client: TestClient) -> None:
    r = client.post(
        "/api/v1/raas-intel/extortion-intel", json={"status": "unknown_status"}
    )
    assert r.status_code == 422


# ===========================================================================
# 4. Leak site posts — create + list + time filter
# ===========================================================================

def test_create_leak_post_returns_201(client: TestClient) -> None:
    payload = {"victim_org": "Acme Corp", "data_size_gb": 12.5, "status": "posted"}
    r = client.post("/api/v1/raas-intel/leak-posts", json=payload)
    assert r.status_code == 201
    body = r.json()
    assert body["victim_org"] == "Acme Corp"
    assert body["data_size_gb"] == 12.5
    assert body["status"] == "posted"


def test_list_leak_posts_default_days(client: TestClient) -> None:
    client.post("/api/v1/raas-intel/leak-posts", json={"victim_org": "TargetCo"})
    r = client.get("/api/v1/raas-intel/leak-posts")
    assert r.status_code == 200
    body = r.json()
    assert body["count"] >= 1
    orgs = [p["victim_org"] for p in body["posts"]]
    assert "TargetCo" in orgs


def test_list_leak_posts_days_filter(client: TestClient) -> None:
    client.post("/api/v1/raas-intel/leak-posts", json={"victim_org": "RecentOrg"})
    r = client.get("/api/v1/raas-intel/leak-posts?days=1")
    assert r.status_code == 200
    orgs = [p["victim_org"] for p in r.json()["posts"]]
    assert "RecentOrg" in orgs


def test_create_leak_post_invalid_status(client: TestClient) -> None:
    r = client.post(
        "/api/v1/raas-intel/leak-posts",
        json={"victim_org": "Corp", "status": "hacked"},
    )
    assert r.status_code == 422


# ===========================================================================
# 5. 401 — dependency is declared at router level
# ===========================================================================

def test_router_has_api_key_dependency() -> None:
    mod_name = "apps.api.raas_intel_router"
    if mod_name in sys.modules:
        del sys.modules[mod_name]
    import apps.api.raas_intel_router as mod  # noqa: PLC0415
    assert len(mod.router.dependencies) >= 1


# ===========================================================================
# 6. Info counts update after creates
# ===========================================================================

def test_info_increments_after_creates(client: TestClient) -> None:
    """After creating a group + negotiation + leak post the info counts update."""
    client.post("/api/v1/raas-intel/raas-groups", json={"name": "AGroup"})
    client.post("/api/v1/raas-intel/extortion-intel", json={"status": "open"})
    client.post("/api/v1/raas-intel/leak-posts", json={"victim_org": "SomeOrg"})
    r = client.get("/api/v1/raas-intel/")
    body = r.json()
    assert body["group_count"] >= 1
    assert body["open_negotiations"] >= 1
    assert body["leak_posts_last_30d"] >= 1
    assert body["status"] == "ok"
