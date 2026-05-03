"""Tests for the Data Export Router (/api/v1/export).

Covers CSV/JSON download of alerts, vulnerabilities, compliance, and assets,
including format validation, Content-Disposition headers, and optional filters.

Total: 18 tests.
"""

from __future__ import annotations

import csv
import io
import json
import os
import sqlite3
import tempfile
from pathlib import Path
from unittest import mock

import pytest
from fastapi.testclient import TestClient

# ---------------------------------------------------------------------------
# Helpers — seed minimal SQLite DBs in a temp dir
# ---------------------------------------------------------------------------

def _seed_alerts(db_path: str, org_id: str = "testorg") -> None:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS at_alerts (
            id TEXT PRIMARY KEY,
            org_id TEXT NOT NULL,
            title TEXT NOT NULL DEFAULT '',
            source_system TEXT NOT NULL DEFAULT 'siem',
            severity TEXT NOT NULL DEFAULT 'medium',
            priority TEXT NOT NULL DEFAULT 'p3',
            raw_alert_json TEXT NOT NULL DEFAULT '{}',
            status TEXT NOT NULL DEFAULT 'new',
            assigned_to TEXT NOT NULL DEFAULT '',
            triage_notes TEXT NOT NULL DEFAULT '',
            escalation_reason TEXT NOT NULL DEFAULT '',
            ingested_at DATETIME,
            triaged_at DATETIME,
            resolved_at DATETIME
        );
    """)
    conn.execute(
        "INSERT INTO at_alerts (id, org_id, title, severity, status, ingested_at) VALUES (?,?,?,?,?,?)",
        ("a1", org_id, "Critical breach", "critical", "new", "2024-01-01T00:00:00"),
    )
    conn.execute(
        "INSERT INTO at_alerts (id, org_id, title, severity, status, ingested_at) VALUES (?,?,?,?,?,?)",
        ("a2", org_id, "Low noise event", "low", "resolved", "2024-01-02T00:00:00"),
    )
    conn.commit()
    conn.close()


def _seed_vulns(db_path: str, org_id: str = "testorg") -> None:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS vuln_findings (
            id TEXT PRIMARY KEY,
            org_id TEXT NOT NULL,
            scan_id TEXT NOT NULL DEFAULT '',
            cve_id TEXT NOT NULL DEFAULT '',
            title TEXT NOT NULL DEFAULT '',
            severity TEXT NOT NULL DEFAULT 'medium',
            cvss_score REAL NOT NULL DEFAULT 0.0,
            finding_status TEXT NOT NULL DEFAULT 'open',
            affected_asset TEXT NOT NULL DEFAULT '',
            plugin_id TEXT NOT NULL DEFAULT '',
            description TEXT NOT NULL DEFAULT '',
            remediation TEXT NOT NULL DEFAULT '',
            detected_at DATETIME,
            resolved_at DATETIME
        );
    """)
    conn.execute(
        "INSERT INTO vuln_findings (id, org_id, cve_id, title, severity, cvss_score, detected_at) VALUES (?,?,?,?,?,?,?)",
        ("v1", org_id, "CVE-2024-1234", "Log4Shell variant", "critical", 9.8, "2024-01-01"),
    )
    conn.execute(
        "INSERT INTO vuln_findings (id, org_id, cve_id, title, severity, cvss_score, detected_at) VALUES (?,?,?,?,?,?,?)",
        ("v2", org_id, "CVE-2024-5678", "XSS in dashboard", "medium", 5.4, "2024-01-02"),
    )
    conn.commit()
    conn.close()


def _seed_assets(db_path: str, org_id: str = "testorg") -> None:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS managed_assets (
            id TEXT PRIMARY KEY,
            org_id TEXT NOT NULL,
            name TEXT NOT NULL,
            asset_type TEXT NOT NULL,
            hostname TEXT,
            ip_address TEXT,
            cloud_provider TEXT,
            region TEXT,
            owner_email TEXT,
            owner_name TEXT,
            team TEXT,
            business_unit TEXT,
            criticality TEXT NOT NULL DEFAULT 'medium',
            criticality_tier TEXT NOT NULL DEFAULT 'T3',
            data_classification TEXT NOT NULL DEFAULT 'internal',
            environment TEXT NOT NULL DEFAULT 'production',
            lifecycle TEXT NOT NULL DEFAULT 'discovered',
            risk_score REAL NOT NULL DEFAULT 0.0,
            finding_count INTEGER NOT NULL DEFAULT 0,
            first_discovered TEXT NOT NULL DEFAULT '',
            last_seen TEXT NOT NULL DEFAULT '',
            compliance_scope TEXT NOT NULL DEFAULT '[]',
            tags TEXT NOT NULL DEFAULT '[]',
            metadata TEXT NOT NULL DEFAULT '{}'
        );
    """)
    conn.execute(
        "INSERT INTO managed_assets (id, org_id, name, asset_type, criticality, environment, first_discovered, last_seen) VALUES (?,?,?,?,?,?,?,?)",
        ("as1", org_id, "prod-api-1", "server", "critical", "production", "2024-01-01", "2024-01-10"),
    )
    conn.execute(
        "INSERT INTO managed_assets (id, org_id, name, asset_type, criticality, environment, first_discovered, last_seen) VALUES (?,?,?,?,?,?,?,?)",
        ("as2", org_id, "dev-db-1", "database", "medium", "development", "2024-01-01", "2024-01-09"),
    )
    conn.commit()
    conn.close()


def _seed_compliance(db_path: str, org_id: str = "testorg") -> None:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS compliance_assessments (
            id TEXT PRIMARY KEY,
            org_id TEXT NOT NULL,
            cloud_provider TEXT NOT NULL DEFAULT 'aws',
            framework TEXT NOT NULL,
            scope TEXT NOT NULL DEFAULT '{}',
            status TEXT NOT NULL DEFAULT 'running',
            total_controls INTEGER NOT NULL DEFAULT 0,
            passed INTEGER NOT NULL DEFAULT 0,
            failed INTEGER NOT NULL DEFAULT 0,
            not_applicable INTEGER NOT NULL DEFAULT 0,
            score REAL NOT NULL DEFAULT 0.0,
            created_at DATETIME
        );
        CREATE TABLE IF NOT EXISTS control_results (
            id TEXT PRIMARY KEY,
            org_id TEXT NOT NULL,
            assessment_id TEXT NOT NULL,
            control_id TEXT NOT NULL,
            control_name TEXT NOT NULL DEFAULT '',
            section TEXT NOT NULL DEFAULT '',
            severity TEXT NOT NULL DEFAULT 'medium',
            status TEXT NOT NULL DEFAULT 'manual_check',
            evidence TEXT NOT NULL DEFAULT '',
            resource_id TEXT NOT NULL DEFAULT '',
            resource_type TEXT NOT NULL DEFAULT ''
        );
    """)
    conn.execute(
        "INSERT INTO compliance_assessments (id, org_id, framework, created_at) VALUES (?,?,?,?)",
        ("ca1", org_id, "SOC2", "2024-01-01"),
    )
    conn.execute(
        "INSERT INTO control_results (id, org_id, assessment_id, control_id, control_name, status) VALUES (?,?,?,?,?,?)",
        ("cr1", org_id, "ca1", "CC1.1", "Control Access", "passed"),
    )
    conn.execute(
        "INSERT INTO control_results (id, org_id, assessment_id, control_id, control_name, status) VALUES (?,?,?,?,?,?)",
        ("cr2", org_id, "ca1", "CC2.1", "Encrypt Data", "failed"),
    )
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def tmp_data(tmp_path):
    """Yields a temp directory and patches export_router DB path helpers."""
    alert_db = str(tmp_path / "alert_triage.db")
    vuln_db = str(tmp_path / "vuln_scan.db")
    asset_db = str(tmp_path / "asset_inventory.db")
    compliance_db = str(tmp_path / "testorg_cloud_compliance.db")

    _seed_alerts(alert_db)
    _seed_vulns(vuln_db)
    _seed_assets(asset_db)
    _seed_compliance(compliance_db)

    with mock.patch("apps.api.export_router._alert_db_path", return_value=alert_db), \
         mock.patch("apps.api.export_router._vuln_db_path", return_value=vuln_db), \
         mock.patch("apps.api.export_router._asset_db_path", return_value=asset_db), \
         mock.patch("apps.api.export_router._compliance_db_path", return_value=compliance_db):
        yield tmp_path


@pytest.fixture()
def client(tmp_data):
    from apps.api.export_router import router
    from apps.api.auth_deps import api_key_auth
    from fastapi import FastAPI
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[api_key_auth] = lambda: None  # bypass auth in tests
    return TestClient(app)


# ---------------------------------------------------------------------------
# 1. Alerts — CSV
# ---------------------------------------------------------------------------

def test_export_alerts_csv_status_200(client):
    r = client.get("/api/v1/export/alerts?format=csv&org_id=testorg")
    assert r.status_code == 200


def test_export_alerts_csv_content_type(client):
    r = client.get("/api/v1/export/alerts?format=csv&org_id=testorg")
    assert "text/csv" in r.headers["content-type"]


def test_export_alerts_csv_content_disposition(client):
    r = client.get("/api/v1/export/alerts?format=csv&org_id=testorg")
    assert "attachment" in r.headers["content-disposition"]
    assert ".csv" in r.headers["content-disposition"]


def test_export_alerts_csv_has_header_row(client):
    r = client.get("/api/v1/export/alerts?format=csv&org_id=testorg")
    reader = csv.DictReader(io.StringIO(r.text))
    assert "id" in reader.fieldnames
    assert "severity" in reader.fieldnames


def test_export_alerts_csv_row_count(client):
    r = client.get("/api/v1/export/alerts?format=csv&org_id=testorg")
    reader = csv.DictReader(io.StringIO(r.text))
    rows = list(reader)
    assert len(rows) == 2


def test_export_alerts_csv_severity_filter(client):
    r = client.get("/api/v1/export/alerts?format=csv&org_id=testorg&severity=critical")
    reader = csv.DictReader(io.StringIO(r.text))
    rows = list(reader)
    assert len(rows) == 1
    assert rows[0]["severity"] == "critical"


# ---------------------------------------------------------------------------
# 2. Alerts — JSON
# ---------------------------------------------------------------------------

def test_export_alerts_json_status_200(client):
    r = client.get("/api/v1/export/alerts?format=json&org_id=testorg")
    assert r.status_code == 200


def test_export_alerts_json_content_type(client):
    r = client.get("/api/v1/export/alerts?format=json&org_id=testorg")
    assert "application/json" in r.headers["content-type"]


def test_export_alerts_json_is_array(client):
    r = client.get("/api/v1/export/alerts?format=json&org_id=testorg")
    data = json.loads(r.text)
    assert isinstance(data, list)
    assert len(data) == 2


def test_export_alerts_json_has_record_count_header(client):
    r = client.get("/api/v1/export/alerts?format=json&org_id=testorg")
    assert r.headers.get("x-record-count") == "2"


# ---------------------------------------------------------------------------
# 3. Vulnerabilities
# ---------------------------------------------------------------------------

def test_export_vulns_csv_row_count(client):
    r = client.get("/api/v1/export/vulnerabilities?format=csv&org_id=testorg")
    reader = csv.DictReader(io.StringIO(r.text))
    rows = list(reader)
    assert len(rows) == 2


def test_export_vulns_json_keys(client):
    r = client.get("/api/v1/export/vulnerabilities?format=json&org_id=testorg")
    data = json.loads(r.text)
    cve_ids = {row["cve_id"] for row in data}
    assert "CVE-2024-1234" in cve_ids
    assert "CVE-2024-5678" in cve_ids


# ---------------------------------------------------------------------------
# 4. Compliance
# ---------------------------------------------------------------------------

def test_export_compliance_csv_row_count(client):
    r = client.get("/api/v1/export/compliance?format=csv&org_id=testorg")
    reader = csv.DictReader(io.StringIO(r.text))
    rows = list(reader)
    assert len(rows) == 2


def test_export_compliance_status_filter(client):
    r = client.get("/api/v1/export/compliance?format=csv&org_id=testorg&status=failed")
    reader = csv.DictReader(io.StringIO(r.text))
    rows = list(reader)
    assert len(rows) == 1
    assert rows[0]["status"] == "failed"


# ---------------------------------------------------------------------------
# 5. Assets
# ---------------------------------------------------------------------------

def test_export_assets_csv_row_count(client):
    r = client.get("/api/v1/export/assets?format=csv&org_id=testorg")
    reader = csv.DictReader(io.StringIO(r.text))
    rows = list(reader)
    assert len(rows) == 2


def test_export_assets_env_filter(client):
    r = client.get("/api/v1/export/assets?format=csv&org_id=testorg&environment=production")
    reader = csv.DictReader(io.StringIO(r.text))
    rows = list(reader)
    assert len(rows) == 1
    assert rows[0]["environment"] == "production"


# ---------------------------------------------------------------------------
# 6. Invalid format returns 400
# ---------------------------------------------------------------------------

def test_invalid_format_returns_400(client):
    r = client.get("/api/v1/export/alerts?format=xlsx&org_id=testorg")
    assert r.status_code == 400


# ---------------------------------------------------------------------------
# 7. Empty org returns empty data gracefully
# ---------------------------------------------------------------------------

def test_empty_org_csv_returns_header_only(client):
    r = client.get("/api/v1/export/alerts?format=csv&org_id=no_such_org")
    reader = csv.DictReader(io.StringIO(r.text))
    rows = list(reader)
    assert rows == []


# ---------------------------------------------------------------------------
# 8. Dashboard export — new endpoint GET /api/v1/export/dashboard
# ---------------------------------------------------------------------------

def test_export_dashboard_json_status_200(client):
    r = client.get("/api/v1/export/dashboard?format=json&org_id=testorg")
    assert r.status_code == 200


def test_export_dashboard_json_has_five_severity_tiers(client):
    r = client.get("/api/v1/export/dashboard?format=json&org_id=testorg")
    data = json.loads(r.text)
    assert isinstance(data, list)
    assert len(data) == 5
    severities = [row["severity"] for row in data]
    assert set(severities) == {"critical", "high", "medium", "low", "info"}


def test_export_dashboard_json_critical_alert_count(client):
    r = client.get("/api/v1/export/dashboard?format=json&org_id=testorg")
    data = json.loads(r.text)
    critical = next(row for row in data if row["severity"] == "critical")
    # Seeded data: 1 critical alert, 1 critical asset
    assert critical["alert_count"] == 1
    assert critical["asset_count"] == 1


def test_export_dashboard_json_zero_counts_for_unseen_tiers(client):
    r = client.get("/api/v1/export/dashboard?format=json&org_id=testorg")
    data = json.loads(r.text)
    info_row = next(row for row in data if row["severity"] == "info")
    # No seeded data for info tier
    assert info_row["alert_count"] == 0
    assert info_row["open_vuln_count"] == 0
    assert info_row["asset_count"] == 0


def test_export_dashboard_csv_status_200(client):
    r = client.get("/api/v1/export/dashboard?format=csv&org_id=testorg")
    assert r.status_code == 200
    assert "text/csv" in r.headers["content-type"]


def test_export_dashboard_csv_columns(client):
    r = client.get("/api/v1/export/dashboard?format=csv&org_id=testorg")
    reader = csv.DictReader(io.StringIO(r.text))
    assert set(reader.fieldnames) == {"org_id", "severity", "alert_count", "open_vuln_count", "asset_count"}
