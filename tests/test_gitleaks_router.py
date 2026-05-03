"""Tests for gitleaks_router — ALDECI.

Uses a minimal FastAPI app to avoid the slow create_app() path. Each test
gets an isolated SQLite DB via tmp_path and resets the GitleaksScanEngine
singleton so state doesn't bleed between tests.

NO MOCKS: tests exercise the real engine. When the gitleaks binary is not
available (CI default) the engine records jobs as ``unavailable`` rather
than emitting fake secrets, and the tests assert that contract.
"""
from __future__ import annotations

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
    """Spin up a fresh FastAPI app with an isolated gitleaks DB per test."""
    db_path = tmp_path / "gitleaks_scans.db"

    from core import gitleaks_scan_engine as engine_mod
    engine_mod.reset_gitleaks_scan_engine()
    # Force the singleton to use the tmp DB by pre-instantiating it.
    engine_mod.get_gitleaks_scan_engine(db_path=str(db_path))

    from apps.api.gitleaks_router import router

    app = FastAPI()
    app.include_router(router)
    yield TestClient(app, raise_server_exceptions=True)

    engine_mod.reset_gitleaks_scan_engine()


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


def test_capability_summary_returns_expected_shape(client):
    r = client.get("/api/v1/gitleaks/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "Gitleaks"
    # Spec rules (subset assertion — at least the 12 listed must be present).
    expected = {
        "aws-access-key",
        "aws-secret-key",
        "github-pat",
        "github-fine-grained-pat",
        "slack-token",
        "stripe-access-token",
        "gcp-service-account",
        "azure-storage-account",
        "jwt",
        "npm-access-token",
        "pypi-token",
        "private-key",
    }
    assert expected.issubset(set(body["default_rules"]))
    assert set(body["scan_modes"]) >= {"detect", "protect"}
    assert isinstance(body["binary_available"], bool)
    assert body["status"] in {"ok", "empty"}
    assert body["scan_count"] == 0  # fresh tmp DB


# ---------------------------------------------------------------------------
# Rule catalog
# ---------------------------------------------------------------------------


def test_rules_endpoint_returns_full_catalog_with_descriptions(client):
    r = client.get("/api/v1/gitleaks/rules", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["count"] >= 12
    assert isinstance(body["rules"], list)
    # Every rule must carry rule_id, description, severity.
    for rule in body["rules"]:
        assert rule["rule_id"]
        assert rule["description"]
        assert rule["severity"] in {"critical", "high", "medium", "low"}
    # Spot-check that AWS access key + private-key are in there.
    rule_ids = {r["rule_id"] for r in body["rules"]}
    assert "aws-access-key" in rule_ids
    assert "private-key" in rule_ids


# ---------------------------------------------------------------------------
# POST /scan
# ---------------------------------------------------------------------------


def test_post_scan_queues_job_and_returns_handle(client, tmp_path):
    repo = tmp_path / "fake-repo"
    repo.mkdir()
    r = client.post(
        "/api/v1/gitleaks/scan",
        json={"repo_path": str(repo)},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert "scan_id" in body and len(body["scan_id"]) >= 16
    assert body["repo_path"] == str(repo)
    assert body["branch"] is None
    assert "queued_at" in body and body["queued_at"]


def test_post_scan_with_branch_and_history_persists(client, tmp_path):
    repo = tmp_path / "src"
    repo.mkdir()
    queued = client.post(
        "/api/v1/gitleaks/scan",
        json={
            "repo_path": str(repo),
            "branch": "main",
            "all_history": True,
            "exclude_paths": ["vendor/", "node_modules/"],
        },
        headers=HEADERS,
    ).json()
    scan_id = queued["scan_id"]

    detail = client.get(f"/api/v1/gitleaks/scan/{scan_id}", headers=HEADERS).json()
    assert detail["repo_path"] == str(repo)
    assert detail["branch"] == "main"
    assert detail["all_history"] is True


def test_post_scan_rejects_empty_repo_path(client):
    r = client.post(
        "/api/v1/gitleaks/scan",
        json={"repo_path": "   "},
        headers=HEADERS,
    )
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# GET /scan/{scan_id}
# ---------------------------------------------------------------------------


def test_get_scan_detail_returns_secret_counts_and_secrets(client, tmp_path):
    repo = tmp_path / "scan-target"
    repo.mkdir()
    queued = client.post(
        "/api/v1/gitleaks/scan",
        json={"repo_path": str(repo)},
        headers=HEADERS,
    ).json()
    scan_id = queued["scan_id"]

    r = client.get(f"/api/v1/gitleaks/scan/{scan_id}", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["scan_id"] == scan_id
    assert body["repo_path"] == str(repo)
    assert body["status"] in {
        "queued", "scanning", "complete", "failed", "unavailable"
    }
    assert "secret_counts" in body
    assert "by_rule" in body["secret_counts"]
    assert isinstance(body["secrets"], list)
    # Without gitleaks installed the engine MUST record unavailable, not fake data.
    if body["status"] == "unavailable":
        assert body["secrets"] == []
        assert body["error"] and "gitleaks" in body["error"].lower()


def test_get_scan_unknown_id_returns_404(client):
    r = client.get(
        "/api/v1/gitleaks/scan/does-not-exist-1234567890", headers=HEADERS
    )
    assert r.status_code == 404
    assert "not found" in r.json()["detail"].lower()


# ---------------------------------------------------------------------------
# Capability flips after first scan
# ---------------------------------------------------------------------------


def test_capability_status_flips_to_ok_after_first_scan(client, tmp_path):
    cap0 = client.get("/api/v1/gitleaks/", headers=HEADERS).json()
    assert cap0["scan_count"] == 0
    assert cap0["status"] == "empty"

    repo = tmp_path / "first-scan"
    repo.mkdir()
    client.post(
        "/api/v1/gitleaks/scan",
        json={"repo_path": str(repo)},
        headers=HEADERS,
    )
    cap1 = client.get("/api/v1/gitleaks/", headers=HEADERS).json()
    assert cap1["scan_count"] == 1
    assert cap1["status"] == "ok"


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------


def test_missing_auth_header_returns_401_or_403(client):
    r = client.get("/api/v1/gitleaks/")
    assert r.status_code in (401, 403)
