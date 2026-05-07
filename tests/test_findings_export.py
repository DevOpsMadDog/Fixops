"""Test findings export endpoint (CSV + JSON).

Tests for GET /api/v1/security-findings/export?format={csv|json}&org_id=X
Multica #4148.
"""
import csv
import json
from io import StringIO

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_export_findings_csv(client: AsyncClient, org_id: str = "test-org-export"):
    """Test CSV export of findings."""
    # Setup: record a finding
    create_resp = await client.post(
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
    export_resp = await client.get(
        f"/api/v1/security-findings/export?org_id={org_id}&format=csv",
    )
    assert export_resp.status_code == 200
    assert export_resp.headers["content-type"] == "text/csv; charset=utf-8"
    assert f"findings_{org_id}.csv" in export_resp.headers["content-disposition"]

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


@pytest.mark.asyncio
async def test_export_findings_json(client: AsyncClient, org_id: str = "test-org-export-json"):
    """Test JSON export of findings."""
    # Setup: record 2 findings
    for i in range(2):
        await client.post(
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
    export_resp = await client.get(
        f"/api/v1/security-findings/export?org_id={org_id}&format=json",
    )
    assert export_resp.status_code == 200
    assert export_resp.headers["content-type"] == "application/json"
    assert f"findings_{org_id}.json" in export_resp.headers["content-disposition"]

    # Parse JSON
    findings = json.loads(export_resp.text)
    assert len(findings) == 2
    assert findings[0]["title"] == "Finding 0"
    assert findings[1]["title"] == "Finding 1"
    assert findings[0]["severity"] == "high"
    assert findings[1]["severity"] == "medium"


@pytest.mark.asyncio
async def test_export_findings_empty(client: AsyncClient, org_id: str = "test-org-empty-export"):
    """Test export of empty findings list."""
    # No findings recorded for this org

    # Export as CSV
    export_resp = await client.get(
        f"/api/v1/security-findings/export?org_id={org_id}&format=csv",
    )
    assert export_resp.status_code == 200
    csv_lines = export_resp.text.strip().split("\n")
    assert len(csv_lines) == 1  # header only


@pytest.mark.asyncio
async def test_export_findings_invalid_format(client: AsyncClient, org_id: str = "test-org-invalid"):
    """Test export with invalid format param."""
    export_resp = await client.get(
        f"/api/v1/security-findings/export?org_id={org_id}&format=xml",
    )
    assert export_resp.status_code == 422  # validation error


@pytest.mark.asyncio
async def test_export_findings_default_format(client: AsyncClient, org_id: str = "test-org-default"):
    """Test export defaults to CSV when format not specified."""
    # Setup: record a finding
    await client.post(
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
    export_resp = await client.get(
        f"/api/v1/security-findings/export?org_id={org_id}",
    )
    assert export_resp.status_code == 200
    assert export_resp.headers["content-type"] == "text/csv; charset=utf-8"
