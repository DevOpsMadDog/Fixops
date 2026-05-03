"""Tests for tfsec IaC scan router (real engine, no mocks).

Uses tmp_path SQLite to keep tests hermetic. The engine constructor accepts a
``db_path`` and returns a fresh non-singleton instance, then we monkey-patch
the singleton lookup so the router shares that instance.
"""

from __future__ import annotations

import importlib

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture
def tfsec_app(tmp_path, monkeypatch):
    """Build a tiny FastAPI app mounting only the tfsec router with an isolated DB."""
    db_path = tmp_path / "tfsec_scans.db"

    engine_module = importlib.import_module("core.tfsec_scan_engine")
    importlib.reload(engine_module)

    isolated_engine = engine_module.TfsecScanEngine(db_path=str(db_path))

    def _get_engine(*_a, **_k):
        return isolated_engine

    monkeypatch.setattr(engine_module, "get_tfsec_scan_engine", _get_engine)

    router_module = importlib.import_module("apps.api.tfsec_router")
    importlib.reload(router_module)
    monkeypatch.setattr(router_module, "get_tfsec_scan_engine", _get_engine)

    app = FastAPI()
    app.include_router(router_module.router)
    client = TestClient(app)
    return client, isolated_engine, db_path


# ---------------------------------------------------------------------------
# GET /
# ---------------------------------------------------------------------------


def test_capability_summary_envelope(tfsec_app):
    client, _engine, _db = tfsec_app
    resp = client.get("/api/v1/tfsec/")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["service"] == "tfsec"
    assert body["scope"] == "terraform-only"
    assert body["status"] in ("ok", "empty", "degraded")
    # All 8 providers must be present.
    for prov in (
        "aws", "azure", "gcp", "digitalocean",
        "kubernetes", "cloudstack", "github", "oracle",
    ):
        assert prov in body["providers"], f"missing provider {prov}"
    assert body["severity_levels"] == ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    assert body["scan_count"] == 0


def test_capability_status_flips_to_ok_after_scan(tfsec_app):
    client, engine, _db = tfsec_app
    create = client.post(
        "/api/v1/tfsec/scan",
        json={"target_path": "/tmp/terraform-module"},
    )
    assert create.status_code == 201, create.text
    engine.update_status(
        create.json()["scan_id"],
        "completed",
        severity_counts={"CRITICAL": 1, "HIGH": 2, "MEDIUM": 0, "LOW": 4},
    )
    body = client.get("/api/v1/tfsec/").json()
    assert body["scan_count"] == 1
    # Without a real tfsec binary present, status will be "degraded";
    # if tfsec is installed (rare in CI) it will be "ok".
    assert body["status"] in ("ok", "degraded")


# ---------------------------------------------------------------------------
# GET /providers
# ---------------------------------------------------------------------------


def test_provider_catalog_has_8_entries_with_rule_counts(tfsec_app):
    client, _engine, _db = tfsec_app
    resp = client.get("/api/v1/tfsec/providers")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["total_providers"] == 8
    assert body["total_rules"] > 0
    names = {entry["provider"] for entry in body["providers"]}
    assert names == {
        "aws", "azure", "gcp", "digitalocean",
        "kubernetes", "cloudstack", "github", "oracle",
    }
    # AWS must dominate the rule count.
    aws_entry = next(e for e in body["providers"] if e["provider"] == "aws")
    assert aws_entry["rule_count"] >= 100
    assert aws_entry["description"]


# ---------------------------------------------------------------------------
# POST /scan
# ---------------------------------------------------------------------------


def test_queue_scan_returns_queued_envelope(tfsec_app):
    client, _engine, _db = tfsec_app
    resp = client.post(
        "/api/v1/tfsec/scan",
        json={
            "target_path": "/tmp/terraform-module",
            "exclude_checks": ["AVD-AWS-0001", "aws-s3-block-public-acls"],
            "minimum_severity": "MEDIUM",
            "soft_fail": True,
        },
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["scan_id"].startswith("tfsec-")
    assert body["target_path"] == "/tmp/terraform-module"
    assert body["queued_at"]
    # Without a tfsec binary present, the engine records as "record_only";
    # if installed it queues normally.
    assert body["status"] in ("queued", "record_only")


def test_queue_scan_rejects_blank_target(tfsec_app):
    client, _engine, _db = tfsec_app
    resp = client.post("/api/v1/tfsec/scan", json={"target_path": "   "})
    # Pydantic min_length=1 strips? Actually Pydantic preserves whitespace, so
    # engine validation will reject — accept both 400 and 422.
    assert resp.status_code in (400, 422), resp.text


def test_queue_scan_rejects_shell_metachars(tfsec_app):
    client, _engine, _db = tfsec_app
    resp = client.post(
        "/api/v1/tfsec/scan",
        json={"target_path": "/tmp/foo;rm -rf /"},
    )
    assert resp.status_code in (400, 422), resp.text


def test_queue_scan_rejects_invalid_severity(tfsec_app):
    client, _engine, _db = tfsec_app
    resp = client.post(
        "/api/v1/tfsec/scan",
        json={"target_path": "/tmp/x", "minimum_severity": "BANANA"},
    )
    assert resp.status_code in (400, 422), resp.text


# ---------------------------------------------------------------------------
# GET /scan/{scan_id}
# ---------------------------------------------------------------------------


def test_get_scan_unknown_returns_404(tfsec_app):
    client, _engine, _db = tfsec_app
    resp = client.get("/api/v1/tfsec/scan/tfsec-does-not-exist")
    assert resp.status_code == 404


def test_get_scan_roundtrip_with_engine_update(tfsec_app):
    client, engine, _db = tfsec_app
    create = client.post(
        "/api/v1/tfsec/scan",
        json={
            "target_path": "/tmp/iac/aws-s3",
            "minimum_severity": "LOW",
        },
    )
    assert create.status_code == 201
    scan_id = create.json()["scan_id"]

    # Engine-side update (mirrors what a worker would do)
    engine.update_status(
        scan_id,
        "completed",
        severity_counts={"CRITICAL": 1, "HIGH": 3, "MEDIUM": 5, "LOW": 12},
        provider_counts={"aws": 18, "kubernetes": 3},
        findings=[
            {
                "rule_id": "AVD-AWS-0001",
                "severity": "CRITICAL",
                "provider": "aws",
                "resource": "aws_s3_bucket.public",
                "file_path": "main.tf",
                "line": 42,
                "description": "S3 bucket has public access enabled.",
            },
            {
                "rule_id": "AVD-AWS-0089",
                "severity": "HIGH",
                "provider": "aws",
                "resource": "aws_db_instance.db",
                "file_path": "db.tf",
                "line": 17,
                "description": "RDS instance not encrypted at rest.",
            },
        ],
        exit_code=1,
    )

    fetch = client.get(f"/api/v1/tfsec/scan/{scan_id}")
    assert fetch.status_code == 200, fetch.text
    body = fetch.json()
    assert body["scan_id"] == scan_id
    assert body["status"] == "completed"
    assert body["completed_at"]
    assert body["severity_counts"]["CRITICAL"] == 1
    assert body["severity_counts"]["HIGH"] == 3
    assert body["severity_counts"]["MEDIUM"] == 5
    assert body["severity_counts"]["LOW"] == 12
    assert body["provider_counts"]["aws"] == 18
    assert body["provider_counts"]["kubernetes"] == 3
    assert body["exit_code"] == 1
    assert len(body["findings"]) == 2
    # Spot-check finding shape
    f0 = body["findings"][0]
    assert f0["rule_id"] == "AVD-AWS-0001"
    assert f0["severity"] == "CRITICAL"
    assert f0["provider"] == "aws"
    assert f0["file_path"] == "main.tf"
    assert f0["line"] == 42
    # Internal _request envelope must NOT leak in API response.
    assert "_request" not in body


def test_engine_record_only_when_tfsec_missing(tfsec_app):
    """If the tfsec binary is absent the engine still queues and returns record_only."""
    client, engine, _db = tfsec_app
    # The CI sandbox typically lacks tfsec; assert engine reflects that gracefully.
    body = client.get("/api/v1/tfsec/").json()
    if not body["tfsec_binary_available"]:
        create = client.post(
            "/api/v1/tfsec/scan",
            json={"target_path": "/tmp/iac"},
        )
        assert create.status_code == 201
        assert create.json()["status"] == "record_only"
