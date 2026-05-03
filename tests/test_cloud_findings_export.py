"""Tests for cloud-findings CSV export endpoint and engine method.

Covers:
- export_findings_csv engine: returns CSV with correct headers
- export_findings_csv engine: rows match ingested findings
- export_findings_csv engine: provider/severity/status filters work
- export_findings_csv engine: empty result still has header row
- GET /api/v1/cloud-findings/export/csv: 200 with text/csv content-type
- GET /api/v1/cloud-findings/export/csv: Content-Disposition filename contains org_id
"""
from __future__ import annotations

import csv
import io
import os

import pytest

os.environ.setdefault("FIXOPS_MODE", "dev")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")

from core.cloud_security_findings_engine import CloudSecurityFindingsEngine

ORG = "org-export-test"


@pytest.fixture
def engine(tmp_path):
    return CloudSecurityFindingsEngine(db_path=str(tmp_path / "export_test.db"))


def _ingest(engine, overrides=None):
    base = dict(
        org_id=ORG,
        provider="aws",
        account_id="acct-001",
        region="us-east-1",
        resource_type="s3",
        resource_id="bucket-alpha",
        finding_title="Public S3 bucket",
        finding_type="misconfiguration",
        severity="high",
        cvss_score=7.5,
        remediation="Disable public access",
    )
    if overrides:
        base.update(overrides)
    return engine.ingest_finding(**base)


# ---------------------------------------------------------------------------
# Engine-level tests
# ---------------------------------------------------------------------------

def test_export_csv_has_header_row(engine):
    _ingest(engine)
    csv_str = engine.export_findings_csv(org_id=ORG)
    reader = csv.DictReader(io.StringIO(csv_str))
    expected = {
        "id", "org_id", "provider", "account_id", "region", "resource_type",
        "resource_id", "finding_title", "finding_type", "severity", "status",
        "cvss_score", "remediation", "detected_at", "resolved_at",
    }
    assert expected == set(reader.fieldnames)


def test_export_csv_rows_match_findings(engine):
    _ingest(engine)
    _ingest(engine, overrides={"resource_id": "bucket-beta", "severity": "critical"})
    csv_str = engine.export_findings_csv(org_id=ORG)
    rows = list(csv.DictReader(io.StringIO(csv_str)))
    assert len(rows) == 2
    resource_ids = {r["resource_id"] for r in rows}
    assert resource_ids == {"bucket-alpha", "bucket-beta"}


def test_export_csv_severity_filter(engine):
    _ingest(engine, overrides={"resource_id": "bucket-low", "severity": "low"})
    _ingest(engine, overrides={"resource_id": "bucket-high", "severity": "high"})
    csv_str = engine.export_findings_csv(org_id=ORG, severity="low")
    rows = list(csv.DictReader(io.StringIO(csv_str)))
    assert len(rows) == 1
    assert rows[0]["severity"] == "low"
    assert rows[0]["resource_id"] == "bucket-low"


def test_export_csv_empty_org_returns_header_only(engine):
    csv_str = engine.export_findings_csv(org_id="nonexistent-org")
    lines = [l for l in csv_str.splitlines() if l.strip()]
    # Only the header row, no data rows
    assert len(lines) == 1
    assert "id" in lines[0]
    assert "severity" in lines[0]


# ---------------------------------------------------------------------------
# HTTP endpoint tests
# ---------------------------------------------------------------------------

@pytest.fixture
def client(tmp_path):
    from fastapi.testclient import TestClient
    from fastapi import FastAPI
    import sys

    # Patch engine to use tmp_path DB
    import apps.api.cloud_security_findings_router as mod
    mod._engine = CloudSecurityFindingsEngine(db_path=str(tmp_path / "http_export.db"))

    app = FastAPI()
    app.include_router(mod.router)

    # Bypass auth for tests
    from apps.api.auth_deps import api_key_auth
    app.dependency_overrides[api_key_auth] = lambda: None

    yield TestClient(app)

    # Cleanup override
    mod._engine = None
    app.dependency_overrides.clear()


def test_export_csv_endpoint_status_and_content_type(client, tmp_path):
    # Seed a finding directly into the patched engine
    import apps.api.cloud_security_findings_router as mod
    mod._engine.ingest_finding(
        org_id="org-http",
        provider="gcp",
        account_id="proj-001",
        region="us-central1",
        resource_type="vm",
        resource_id="instance-1",
        finding_title="Open firewall rule",
        finding_type="misconfiguration",
        severity="critical",
        cvss_score=9.1,
        remediation="Restrict firewall",
    )
    resp = client.get("/api/v1/cloud-findings/export/csv?org_id=org-http")
    assert resp.status_code == 200
    assert "text/csv" in resp.headers["content-type"]


def test_export_csv_endpoint_content_disposition_contains_org(client):
    resp = client.get("/api/v1/cloud-findings/export/csv?org_id=my-tenant")
    assert resp.status_code == 200
    cd = resp.headers.get("content-disposition", "")
    assert "my-tenant" in cd
    assert "attachment" in cd
