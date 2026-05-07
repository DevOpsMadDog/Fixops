"""Test findings export endpoint (CSV + JSON).

Tests for GET /api/v1/security-findings/export?format={csv|json}&org_id=X
Multica #4148.
"""
import csv
import json
from io import StringIO

import pytest


def test_export_findings_csv(authenticated_client):
    """Test CSV export of findings."""
    org_id = "test-org-export"
    # Setup: record a finding
    create_resp = authenticated_client.post(
        "/api/v1/security-findings/findings",
        json={
            "org_id": org_id,
            "title": "SQL Injection in login",
            "finding_type": "vulnerability",
            "source_tool": "Burp",
            "severity": "critical",
            "cvss_score": 9.8,
            "asset_id": "app-001",
            "asset_type": "web-app",
            "description": "Unvalidated input in login form",
            "remediation": "Use parameterized queries",
        },
    )
    assert create_resp.status_code == 200
    finding_id = create_resp.json()["id"]

    # Export as CSV
    export_resp = authenticated_client.get(
        f"/api/v1/security-findings/export?org_id={org_id}&format=csv",
    )
    assert export_resp.status_code == 200
    assert "text/csv" in export_resp.headers.get("content-type", "")
    assert f"findings_{org_id}.csv" in export_resp.headers.get("content-disposition", "")

    # Parse CSV
    csv_lines = export_resp.text.strip().split("\n")
    assert len(csv_lines) >= 2  # header + at least 1 row
    reader = csv.DictReader(StringIO(export_resp.text))
    rows = list(reader)
    assert len(rows) == 1
    assert rows[0]["id"] == finding_id
    assert rows[0]["title"] == "SQL Injection in login"
    assert rows[0]["severity"] == "critical"
    assert rows[0]["source_tool"] == "Burp"
    assert rows[0]["asset_id"] == "app-001"
    assert rows[0]["status"] == "open"


def test_export_findings_json(authenticated_client):
    """Test JSON export of findings."""
    org_id = "test-org-export-json"
    # Setup: record 2 findings
    for i in range(2):
        authenticated_client.post(
            "/api/v1/security-findings/findings",
            json={
                "org_id": org_id,
                "title": f"Finding {i}",
                "finding_type": "vulnerability",
                "source_tool": "Semgrep",
                "severity": "high" if i == 0 else "medium",
                "cvss_score": 7.0 + i,
                "asset_id": f"asset-{i}",
                "description": f"Test finding {i}",
                "remediation": "Fix it",
            },
        )

    # Export as JSON
    export_resp = authenticated_client.get(
        f"/api/v1/security-findings/export?org_id={org_id}&format=json",
    )
    assert export_resp.status_code == 200
    assert "application/json" in export_resp.headers.get("content-type", "")
    assert f"findings_{org_id}.json" in export_resp.headers.get("content-disposition", "")

    # Parse JSON
    findings = json.loads(export_resp.text)
    assert len(findings) == 2
    # Results are sorted by cvss_score desc, so highest cvss (Finding 1 with 8.0) comes first
    assert findings[0]["title"] == "Finding 1"
    assert findings[1]["title"] == "Finding 0"
    assert findings[0]["severity"] == "medium"
    assert findings[1]["severity"] == "high"


def test_export_findings_empty(authenticated_client):
    """Test export of empty findings list."""
    org_id = "test-org-empty-export"
    # No findings recorded for this org

    # Export as CSV
    export_resp = authenticated_client.get(
        f"/api/v1/security-findings/export?org_id={org_id}&format=csv",
    )
    assert export_resp.status_code == 200
    csv_lines = export_resp.text.strip().split("\n")
    assert len(csv_lines) == 1  # header only


def test_export_findings_invalid_format(authenticated_client):
    """Test export with invalid format param."""
    org_id = "test-org-invalid"
    export_resp = authenticated_client.get(
        f"/api/v1/security-findings/export?org_id={org_id}&format=xml",
    )
    assert export_resp.status_code == 422  # validation error


def test_export_findings_default_format(authenticated_client):
    """Test export defaults to CSV when format not specified."""
    org_id = "test-org-default"
    # Setup: record a finding
    authenticated_client.post(
        "/api/v1/security-findings/findings",
        json={
            "org_id": org_id,
            "title": "Test finding",
            "finding_type": "vulnerability",
            "source_tool": "Trivy",
            "severity": "low",
            "cvss_score": 3.0,
            "asset_id": "asset-1",
            "description": "Test",
            "remediation": "Fix",
        },
    )

    # Export without format param (should default to CSV)
    export_resp = authenticated_client.get(
        f"/api/v1/security-findings/export?org_id={org_id}",
    )
    assert export_resp.status_code == 200
    assert "text/csv" in export_resp.headers.get("content-type", "")
