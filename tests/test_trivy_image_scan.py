"""Tests for trivy_scan_router (POST /api/v1/trivy/image queue model).

No mocks — uses the real TrivyScanEngine pointed at a tmp_path SQLite DB.
When the trivy CLI binary is not installed the engine returns deterministic
mock output (3 vulns: HIGH/MEDIUM/LOW), which exercises the full
queue -> SQLite -> bucket -> fetch round-trip.
"""
from __future__ import annotations

import os

import pytest

os.environ.setdefault("FIXOPS_API_TOKEN", "test-key")

from fastapi import FastAPI
from fastapi.testclient import TestClient

# tests/conftest.py may have already set FIXOPS_API_TOKEN to a long token —
# resolve at import time so HEADERS matches whatever the env carries.
_API_TOKEN = os.environ.get("FIXOPS_API_TOKEN", "test-key") or "test-key"
HEADERS = {"X-API-Key": _API_TOKEN}


@pytest.fixture()
def client(tmp_path, monkeypatch):
    """Build a minimal FastAPI app, point the engine at a tmp SQLite DB."""
    # Force the engine singleton to use a fresh tmp DB for each test.
    db_path = tmp_path / "trivy_scans.db"
    import core.trivy_scan_engine as engine_mod
    engine_mod.reset_trivy_scan_engine()
    engine_mod._engine_singleton = engine_mod.TrivyScanEngine(db_path=str(db_path))

    from apps.api.trivy_scan_router import router

    app = FastAPI()
    app.include_router(router)
    yield TestClient(app, raise_server_exceptions=True)

    engine_mod.reset_trivy_scan_engine()


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


def test_root_returns_capability_summary(client):
    r = client.get("/api/v1/trivy/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "trivy_scan_engine"
    assert "vuln" in body["scanners"]
    assert "secret" in body["scanners"]
    assert "config" in body["scanners"]
    assert "license" in body["scanners"]
    assert "json" in body["supported_formats"]
    assert "CRITICAL" in body["valid_severities"]
    assert body["status"] in ("ok", "empty", "degraded")
    assert body["scan_count"] == 0  # fresh DB


# ---------------------------------------------------------------------------
# POST /image — queue
# ---------------------------------------------------------------------------


def test_post_image_queues_scan_and_returns_envelope(client):
    r = client.post(
        "/api/v1/trivy/image",
        json={"image": "nginx:1.25-alpine"},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["image"] == "nginx:1.25-alpine"
    assert body["scan_id"]
    assert body["queued_at"]
    # uuid4 string length sanity check
    assert len(body["scan_id"]) >= 32


def test_post_image_rejects_empty_image(client):
    r = client.post(
        "/api/v1/trivy/image",
        json={"image": "   "},
        headers=HEADERS,
    )
    assert r.status_code == 422


def test_post_image_rejects_invalid_severity(client):
    r = client.post(
        "/api/v1/trivy/image",
        json={"image": "nginx:latest", "severities": ["BOGUS"]},
        headers=HEADERS,
    )
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# GET /image/{scan_id} — round-trip
# ---------------------------------------------------------------------------


def test_get_image_scan_round_trip(client):
    enq = client.post(
        "/api/v1/trivy/image",
        json={
            "image": "alpine:3.19",
            "severities": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
            "ignore_unfixed": True,
        },
        headers=HEADERS,
    )
    assert enq.status_code == 200, enq.text
    scan_id = enq.json()["scan_id"]

    fetch = client.get(f"/api/v1/trivy/image/{scan_id}", headers=HEADERS)
    assert fetch.status_code == 200, fetch.text
    rec = fetch.json()

    assert rec["scan_id"] == scan_id
    assert rec["image"] == "alpine:3.19"
    # Either real trivy ran, or mock returned — both reach completed state.
    assert rec["status"] == "completed"
    assert isinstance(rec["severity_counts"], dict)
    # Buckets exist for every valid severity (zero is allowed).
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"):
        assert sev in rec["severity_counts"]
    total = sum(rec["severity_counts"].values())
    assert total >= 0
    assert isinstance(rec["vulnerabilities"], list)


def test_get_image_scan_unknown_id_returns_404(client):
    r = client.get("/api/v1/trivy/image/does-not-exist", headers=HEADERS)
    assert r.status_code == 404


def test_capability_summary_increments_after_scan(client):
    pre = client.get("/api/v1/trivy/", headers=HEADERS).json()
    assert pre["scan_count"] == 0

    client.post(
        "/api/v1/trivy/image",
        json={"image": "busybox:1.36"},
        headers=HEADERS,
    )

    post = client.get("/api/v1/trivy/", headers=HEADERS).json()
    assert post["scan_count"] == 1
    assert post["status"] in ("ok", "degraded")


# ---------------------------------------------------------------------------
# Engine direct (no router) — singleton + persistence
# ---------------------------------------------------------------------------


def test_engine_singleton_persists_across_calls(tmp_path):
    import core.trivy_scan_engine as engine_mod
    engine_mod.reset_trivy_scan_engine()
    db_path = tmp_path / "engine_singleton.db"
    engine_mod._engine_singleton = engine_mod.TrivyScanEngine(db_path=str(db_path))

    e1 = engine_mod.get_trivy_scan_engine()
    e2 = engine_mod.get_trivy_scan_engine()
    assert e1 is e2

    queued = e1.queue_scan(image="redis:7.2")
    sid = queued["scan_id"]

    fetched = e2.get_scan(sid)
    assert fetched is not None
    assert fetched["image"] == "redis:7.2"
    assert fetched["status"] == "completed"

    engine_mod.reset_trivy_scan_engine()
