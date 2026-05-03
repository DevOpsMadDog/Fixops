"""Tests for the Nuclei DAST scan router (real engine, no mocks).

Mounts only the nuclei router on a tiny FastAPI app, points the engine
singleton at a tmp_path SQLite, and exercises the four documented endpoints:

  GET  /api/v1/nuclei/                  capability summary envelope
  GET  /api/v1/nuclei/templates         catalog with category counts
  POST /api/v1/nuclei/scan              queue a scan (validates SSRF + body)
  GET  /api/v1/nuclei/scan/{scan_id}    fetch + 404 on unknown

Each test gets its own DB through the ``nuclei_app`` fixture which patches
``get_nuclei_scan_engine`` to return an isolated engine bound to ``tmp_path``.
"""

from __future__ import annotations

import importlib

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture
def nuclei_app(tmp_path, monkeypatch):
    """Build a tiny FastAPI app mounting only the Nuclei router."""
    db_path = tmp_path / "nuclei_scans.db"

    engine_module = importlib.import_module("core.nuclei_scan_engine")
    importlib.reload(engine_module)

    isolated_engine = engine_module.NucleiScanEngine(db_path=str(db_path))

    def _get_engine(*_a, **_k):
        return isolated_engine

    monkeypatch.setattr(engine_module, "get_nuclei_scan_engine", _get_engine)

    router_module = importlib.import_module("apps.api.nuclei_router")
    importlib.reload(router_module)
    monkeypatch.setattr(router_module, "get_nuclei_scan_engine", _get_engine)

    # Override auth dependency for templates importer routes (read:scans
    # is enforced at platform_app mount-time; here we mount bare so the
    # api_key_auth dep is the only gate — patch to a no-op).
    from apps.api import auth_deps as _auth_deps

    def _noop_auth(*_a, **_k):
        return True

    monkeypatch.setattr(_auth_deps, "api_key_auth", _noop_auth)

    app = FastAPI()
    app.include_router(router_module.router)
    client = TestClient(app)
    return client, isolated_engine, db_path


def test_capability_summary_envelope(nuclei_app):
    client, _engine, _db = nuclei_app
    resp = client.get("/api/v1/nuclei/")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["service"] == "Nuclei"
    assert body["engine"] == "nuclei_scan_engine"
    # No scans yet → "empty" if nuclei present, else "unavailable".
    assert body["status"] in ("empty", "unavailable")
    # All required template categories present.
    for cat in (
        "cves",
        "exposures",
        "misconfigurations",
        "technologies",
        "vulnerabilities",
        "takeovers",
        "default-logins",
        "fuzzing",
        "exposed-panels",
        "exposed-tokens",
    ):
        assert cat in body["template_categories"], f"missing category {cat}"
    # Severity vocabulary matches spec.
    for sev in ("info", "low", "medium", "high", "critical"):
        assert sev in body["severity_levels"]
    assert body["scan_count"] == 0


def test_templates_catalog_returns_categories(nuclei_app):
    client, _engine, _db = nuclei_app
    resp = client.get("/api/v1/nuclei/templates")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "categories" in body
    assert "category_counts" in body
    assert "total_templates" in body
    # All canonical categories appear with int counts.
    cat_names = [c["name"] for c in body["categories"]]
    for required in ("cves", "exposures", "misconfigurations"):
        assert required in cat_names
    for entry in body["categories"]:
        assert isinstance(entry["template_count"], int)
        assert entry["template_count"] >= 0


def test_queue_scan_returns_queued_envelope(nuclei_app):
    client, _engine, _db = nuclei_app
    resp = client.post(
        "/api/v1/nuclei/scan",
        json={
            "target_url": "https://example.com",
            "template_categories": ["cves", "exposures"],
            "severity_threshold": "high",
            "follow_redirects": True,
            "rate_limit": 50,
        },
    )
    assert resp.status_code == 202, resp.text
    body = resp.json()
    assert body["scan_id"].startswith("nuclei-")
    assert body["target_url"] == "https://example.com"
    assert body["template_categories"] == ["cves", "exposures"]
    assert body["severity_threshold"] == "high"
    assert body["follow_redirects"] is True
    assert body["rate_limit"] == 50
    # Status will be queued only when nuclei binary is present, otherwise
    # the engine records "unavailable" up-front.
    assert body["status"] in ("queued", "unavailable")
    assert body["queued_at"]


def test_queue_scan_blocks_ssrf_localhost(nuclei_app):
    client, _engine, _db = nuclei_app
    resp = client.post(
        "/api/v1/nuclei/scan",
        json={"target_url": "http://127.0.0.1/admin"},
    )
    assert resp.status_code in (400, 422), resp.text
    detail = resp.json().get("detail", "")
    text = detail if isinstance(detail, str) else " ".join(str(e) for e in detail)
    assert "blocked" in text.lower() or "private" in text.lower()


def test_queue_scan_rejects_non_http_scheme(nuclei_app):
    client, _engine, _db = nuclei_app
    resp = client.post(
        "/api/v1/nuclei/scan",
        json={"target_url": "file:///etc/passwd"},
    )
    assert resp.status_code in (400, 422), resp.text


def test_queue_scan_rejects_unknown_category(nuclei_app):
    client, _engine, _db = nuclei_app
    resp = client.post(
        "/api/v1/nuclei/scan",
        json={
            "target_url": "https://example.com",
            "template_categories": ["not-a-real-category"],
        },
    )
    assert resp.status_code in (400, 422), resp.text


def test_get_scan_404_for_unknown(nuclei_app):
    client, _engine, _db = nuclei_app
    resp = client.get("/api/v1/nuclei/scan/nuclei-does-not-exist")
    assert resp.status_code == 404


def test_get_scan_roundtrip_with_status_update(nuclei_app):
    client, engine, _db = nuclei_app
    create = client.post(
        "/api/v1/nuclei/scan",
        json={
            "target_url": "https://example.org",
            "template_categories": ["cves", "vulnerabilities"],
            "severity_threshold": "medium",
        },
    )
    assert create.status_code == 202, create.text
    scan_id = create.json()["scan_id"]

    # Engine-side completion (mirrors what a worker would do).
    engine.update_status(
        scan_id,
        "completed",
        severity_counts={"high": 2, "medium": 5, "low": 12, "info": 3, "critical": 1},
        category_counts={"cves": 4, "vulnerabilities": 8},
        findings=[
            {
                "template_id": "CVE-2021-44228-log4shell",
                "severity": "critical",
                "category": "cves",
                "matched_url": "https://example.org/api/log",
                "extracted_results": ["JNDI lookup successful"],
            },
            {
                "template_id": "exposed-git-config",
                "severity": "medium",
                "category": "exposures",
                "matched_url": "https://example.org/.git/config",
                "extracted_results": [],
            },
        ],
        exit_code=0,
    )

    fetch = client.get(f"/api/v1/nuclei/scan/{scan_id}")
    assert fetch.status_code == 200, fetch.text
    body = fetch.json()
    assert body["scan_id"] == scan_id
    assert body["status"] == "completed"
    assert body["completed_at"]
    assert body["severity_counts"]["high"] == 2
    assert body["severity_counts"]["critical"] == 1
    assert body["category_counts"]["cves"] == 4
    assert body["exit_code"] == 0
    assert len(body["findings"]) == 2
    assert body["findings"][0]["template_id"] == "CVE-2021-44228-log4shell"
    assert body["findings"][0]["matched_url"].startswith("https://example.org")


def test_capability_summary_after_scan_increments_count(nuclei_app):
    client, _engine, _db = nuclei_app
    create = client.post(
        "/api/v1/nuclei/scan",
        json={"target_url": "https://example.com"},
    )
    assert create.status_code == 202
    resp = client.get("/api/v1/nuclei/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["scan_count"] == 1
    assert body["status"] in ("ok", "unavailable")
