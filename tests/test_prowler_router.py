"""Tests for the Prowler CSPM scan router (real engine, no mocks).

Covers the new /api/v1/prowler/* async-queue endpoints backed by
core.prowler_scan_engine.ProwlerScanEngine.

Uses a tmp_path SQLite to keep tests hermetic and points the singleton
lookup at the per-test instance.
"""
from __future__ import annotations

import importlib

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture
def prowler_app(tmp_path, monkeypatch):
    """Build a FastAPI app mounting only the Prowler router with an isolated DB."""
    db_path = tmp_path / "prowler_scans.db"

    engine_module = importlib.import_module("core.prowler_scan_engine")
    importlib.reload(engine_module)

    isolated_engine = engine_module.ProwlerScanEngine(db_path=str(db_path))

    def _get_engine(*_a, **_k):
        return isolated_engine

    monkeypatch.setattr(engine_module, "get_prowler_scan_engine", _get_engine)

    router_module = importlib.import_module("apps.api.prowler_router")
    importlib.reload(router_module)

    # The router pulls api_key_auth as a dependency; override so the
    # TestClient can call without supplying credentials.
    from apps.api import auth_deps

    app = FastAPI()
    app.dependency_overrides[auth_deps.api_key_auth] = lambda: True
    app.include_router(router_module.router)
    client = TestClient(app)
    return client, isolated_engine, db_path


# ---------------------------------------------------------------------------
# Capability + catalog
# ---------------------------------------------------------------------------


def test_capability_summary_empty(prowler_app):
    client, _engine, _db = prowler_app
    resp = client.get("/api/v1/prowler/")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["service"] == "Prowler"
    assert "aws" in body["providers"]
    assert "azure" in body["providers"]
    assert "gcp" in body["providers"]
    assert "kubernetes" in body["providers"]
    assert "cis" in body["compliance_frameworks"]
    assert "fedramp" in body["compliance_frameworks"]
    assert body["severity_levels"] == ["low", "medium", "high", "critical"]
    assert body["scan_count"] == 0
    # No prowler binary in CI → status will be "unavailable"; if installed → "empty".
    assert body["status"] in ("empty", "unavailable")


def test_providers_catalog(prowler_app):
    client, _engine, _db = prowler_app
    resp = client.get("/api/v1/prowler/providers")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    providers = {p["provider"] for p in body}
    assert providers == {"aws", "azure", "gcp", "kubernetes"}
    aws = next(p for p in body if p["provider"] == "aws")
    assert aws["check_count"] > 0
    assert "cis" in aws["compliance_frameworks"]


def test_compliance_frameworks_catalog(prowler_app):
    client, _engine, _db = prowler_app
    resp = client.get("/api/v1/prowler/compliance/frameworks")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    frameworks = {f["framework"] for f in body}
    assert {
        "cis", "pci-dss", "hipaa", "gdpr", "iso27001", "soc2",
        "nist-800-53", "fedramp", "aws-well-architected",
    }.issubset(frameworks)
    pci = next(f for f in body if f["framework"] == "pci-dss")
    assert "Payment Card" in pci["description"]


# ---------------------------------------------------------------------------
# Queue + fetch
# ---------------------------------------------------------------------------


def test_queue_scan_returns_envelope(prowler_app):
    client, _engine, _db = prowler_app
    resp = client.post(
        "/api/v1/prowler/scan/queue",
        json={
            "provider": "aws",
            "region": "us-east-1",
            "compliance_frameworks": ["cis", "pci-dss", "soc2"],
            "services": ["s3", "iam"],
        },
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["scan_id"].startswith("prowler-")
    assert body["provider"] == "aws"
    assert body["region"] == "us-east-1"
    assert body["queued_at"]
    # Without prowler binary the engine records the request as "unavailable";
    # with the binary present it would be "queued".
    assert body["status"] in ("queued", "unavailable")


def test_queue_scan_rejects_invalid_provider(prowler_app):
    client, _engine, _db = prowler_app
    resp = client.post(
        "/api/v1/prowler/scan/queue",
        json={"provider": "oracle-cloud"},
    )
    assert resp.status_code == 422, resp.text


def test_queue_scan_rejects_invalid_compliance_framework(prowler_app):
    client, _engine, _db = prowler_app
    resp = client.post(
        "/api/v1/prowler/scan/queue",
        json={
            "provider": "azure",
            "compliance_frameworks": ["cis", "made-up-framework"],
        },
    )
    assert resp.status_code == 422, resp.text


def test_get_scan_roundtrip_with_engine_update(prowler_app):
    client, engine, _db = prowler_app
    create = client.post(
        "/api/v1/prowler/scan/queue",
        json={
            "provider": "gcp",
            "region": "us-central1",
            "compliance_frameworks": ["cis", "iso27001"],
        },
    )
    assert create.status_code == 201, create.text
    scan_id = create.json()["scan_id"]

    # Engine-side update (mirrors the worker that would consume the queue).
    engine.update_scan(
        scan_id,
        status="completed",
        severity_counts={"low": 4, "medium": 7, "high": 2, "critical": 1},
        compliance_counts={
            "cis": {"passed": 110, "failed": 14},
            "iso27001": {"passed": 55, "failed": 6},
        },
        findings=[
            {
                "check_id": "iam_password_policy_minimum_length_14",
                "severity": "high",
                "service": "iam",
                "region": "global",
                "resource": "password-policy",
                "status": "FAIL",
                "framework_mapping": ["cis-1.8", "iso27001-A.9.4.3"],
            },
            {
                "check_id": "s3_bucket_public_access",
                "severity": "critical",
                "service": "s3",
                "region": "us-central1",
                "resource": "bucket/customer-data",
                "status": "FAIL",
                "framework_mapping": ["cis-2.1.5", "iso27001-A.13.1.3"],
            },
        ],
    )

    fetch = client.get(f"/api/v1/prowler/scan/{scan_id}")
    assert fetch.status_code == 200, fetch.text
    body = fetch.json()
    assert body["scan_id"] == scan_id
    assert body["provider"] == "gcp"
    assert body["region"] == "us-central1"
    assert body["status"] == "completed"
    assert body["completed_at"]
    assert body["severity_counts"]["critical"] == 1
    assert body["severity_counts"]["high"] == 2
    assert body["compliance_counts"]["by_framework"]["cis"]["passed"] == 110
    assert body["compliance_counts"]["by_framework"]["cis"]["failed"] == 14
    assert len(body["findings"]) == 2
    assert body["findings"][0]["check_id"] == "iam_password_policy_minimum_length_14"
    assert body["findings"][1]["status"] == "FAIL"


def test_get_scan_unknown_returns_404(prowler_app):
    client, _engine, _db = prowler_app
    resp = client.get("/api/v1/prowler/scan/prowler-does-not-exist")
    assert resp.status_code == 404, resp.text


def test_capability_summary_after_scan_increments_count(prowler_app):
    client, _engine, _db = prowler_app
    create = client.post(
        "/api/v1/prowler/scan/queue",
        json={"provider": "kubernetes", "compliance_frameworks": ["cis"]},
    )
    assert create.status_code == 201

    resp = client.get("/api/v1/prowler/")
    body = resp.json()
    assert body["scan_count"] == 1
