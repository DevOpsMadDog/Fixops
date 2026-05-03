"""Tests for grype_router — ALDECI.

Uses a minimal FastAPI app to avoid the slow create_app() path. Each test
gets an isolated SQLite DB via tmp_path and resets the GrypeScanEngine
singleton so state doesn't bleed between tests.

NO MOCKS: tests exercise the real engine. When the grype binary is not
available (CI default) the engine records jobs as ``unavailable`` rather
than emitting fake vulnerabilities, and the tests assert that contract.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

# conftest.py sets FIXOPS_API_TOKEN before this import; we read the canonical
# value via the shared API_TOKEN fixture.
from tests.conftest import API_TOKEN

from fastapi import FastAPI
from fastapi.testclient import TestClient

HEADERS = {"X-API-Key": API_TOKEN}


@pytest.fixture()
def client(tmp_path: Path):
    """Spin up a fresh FastAPI app with an isolated grype DB per test."""
    db_path = tmp_path / "grype_scans.db"

    from core import grype_scan_engine as engine_mod
    engine_mod.reset_grype_scan_engine()
    # Force the singleton to use the tmp DB by pre-instantiating it.
    engine_mod.get_grype_scan_engine(db_path=str(db_path))

    from apps.api.grype_router import router

    app = FastAPI()
    app.include_router(router)
    yield TestClient(app, raise_server_exceptions=True)

    engine_mod.reset_grype_scan_engine()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_capability_summary_returns_expected_shape(client):
    r = client.get("/api/v1/grype/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "Grype"
    assert set(body["input_types"]) == {"image", "sbom", "dir"}
    assert set(body["output_formats"]) >= {"json", "table", "cyclonedx", "sarif"}
    assert set(body["severities"]) == {
        "Negligible", "Low", "Medium", "High", "Critical",
    }
    assert body["status"] in {"ok", "empty"}
    assert isinstance(body["binary_available"], bool)
    assert body["scan_count"] == 0  # fresh tmp DB


def test_post_scan_queues_job_and_returns_handle(client):
    r = client.post(
        "/api/v1/grype/scan",
        json={"input_type": "image", "target": "nginx:1.25"},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert "scan_id" in body and len(body["scan_id"]) >= 16
    assert body["input_type"] == "image"
    assert body["target"] == "nginx:1.25"
    assert "queued_at" in body and body["queued_at"]


def test_get_scan_detail_returns_severity_counts_and_vulns(client):
    queued = client.post(
        "/api/v1/grype/scan",
        json={"input_type": "sbom", "target": "/tmp/sbom.json"},
        headers=HEADERS,
    ).json()
    scan_id = queued["scan_id"]

    r = client.get(f"/api/v1/grype/scan/{scan_id}", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["scan_id"] == scan_id
    assert body["input_type"] == "sbom"
    assert body["target"] == "/tmp/sbom.json"
    counts = body["severity_counts"]
    for sev in ("Critical", "High", "Medium", "Low", "Negligible"):
        assert sev in counts and isinstance(counts[sev], int)
    assert isinstance(body["vulnerabilities"], list)
    # Without grype installed the engine MUST record unavailable, not fake data.
    assert body["status"] in {"complete", "unavailable", "failed", "queued", "scanning"}
    if body["status"] == "unavailable":
        assert body["vulnerabilities"] == []
        assert body["error"] and "grype" in body["error"].lower()


def test_get_scan_unknown_id_returns_404(client):
    r = client.get("/api/v1/grype/scan/does-not-exist-1234567890", headers=HEADERS)
    assert r.status_code == 404
    assert "not found" in r.json()["detail"].lower()


def test_post_scan_invalid_input_type_returns_422(client):
    r = client.post(
        "/api/v1/grype/scan",
        json={"input_type": "vagueness", "target": "x"},
        headers=HEADERS,
    )
    assert r.status_code == 422


def test_post_scan_invalid_scope_returns_422(client):
    r = client.post(
        "/api/v1/grype/scan",
        json={"input_type": "image", "target": "alpine:3", "scope": "Bogus"},
        headers=HEADERS,
    )
    assert r.status_code == 422


def test_dir_scan_with_only_fixed_flag_persists(client):
    queued = client.post(
        "/api/v1/grype/scan",
        json={
            "input_type": "dir",
            "target": "/tmp/proj",
            "only_fixed": True,
        },
        headers=HEADERS,
    ).json()
    scan_id = queued["scan_id"]

    detail = client.get(f"/api/v1/grype/scan/{scan_id}", headers=HEADERS).json()
    assert detail["input_type"] == "dir"
    assert detail["only_fixed"] is True


def test_capability_status_flips_to_ok_after_first_scan(client):
    cap0 = client.get("/api/v1/grype/", headers=HEADERS).json()
    assert cap0["scan_count"] == 0
    assert cap0["status"] == "empty"

    client.post(
        "/api/v1/grype/scan",
        json={"input_type": "image", "target": "alpine:3.19"},
        headers=HEADERS,
    )
    cap1 = client.get("/api/v1/grype/", headers=HEADERS).json()
    assert cap1["scan_count"] == 1
    assert cap1["status"] == "ok"


def test_missing_auth_header_returns_401(client):
    r = client.get("/api/v1/grype/")
    assert r.status_code in (401, 403)
