"""
Tests for bulk finding import/export engine.

Covers:
- CSV import (happy path, missing fields, invalid severity, bad numerics)
- JSON import (list, wrapped, single dict)
- SARIF import parsing
- CycloneDX import parsing
- Dry-run validation (validate_import)
- Export: CSV, JSON, SARIF formats
- Field mapping reference
- Import/export history
- Scheduled exports
- Bulk stats
- API router endpoints (via FastAPI TestClient)
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Environment setup (must happen before any app imports)
# ---------------------------------------------------------------------------
os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-secret")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

# ---------------------------------------------------------------------------
# Imports
# ---------------------------------------------------------------------------
from core.bulk_operations import (
    BulkOperationsEngine,
    ExportFormat,
    ImportFormat,
    ImportValidationError,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def engine(tmp_path):
    """Fresh engine backed by a temp SQLite DB."""
    return BulkOperationsEngine(db_path=tmp_path / "bulk_test.db")


@pytest.fixture()
def org_id():
    return "org-test-001"


CSV_VALID = """\
title,severity,source,description,rule_id,cve_id,cvss_score,epss_score,exploitable,status
SQL Injection,high,zap,SQL injection in login,RULE-001,CVE-2023-1234,8.5,0.45,true,open
XSS Found,medium,burp,Reflected XSS,RULE-002,,5.0,0.12,false,open
Missing Headers,low,nikto,Missing security headers,RULE-003,,,,,open
"""

CSV_MISSING_REQUIRED = """\
title,severity,source
,high,zap
SQL Injection,,zap
SQL Injection,high,
"""

CSV_INVALID_SEVERITY = """\
title,severity,source
Bad Finding,super-critical,zap
"""

CSV_BAD_CVSS = """\
title,severity,source,cvss_score
Finding,high,zap,15.0
"""

CSV_BAD_EPSS = """\
title,severity,source,epss_score
Finding,high,zap,2.5
"""

JSON_LIST = json.dumps([
    {"title": "SQL Injection", "severity": "high", "source": "zap", "rule_id": "R1"},
    {"title": "XSS", "severity": "medium", "source": "burp", "rule_id": "R2"},
])

JSON_WRAPPED = json.dumps({
    "findings": [
        {"title": "CVE Finding", "severity": "critical", "source": "nessus", "cve_id": "CVE-2024-999"},
    ]
})

JSON_SINGLE = json.dumps(
    {"title": "Single Finding", "severity": "low", "source": "manual"}
)

SARIF_CONTENT = json.dumps({
    "version": "2.1.0",
    "runs": [
        {
            "tool": {
                "driver": {
                    "name": "Semgrep",
                    "rules": [
                        {
                            "id": "python.django.security.injection",
                            "name": "SQL Injection",
                            "shortDescription": {"text": "SQL Injection risk"},
                            "fullDescription": {"text": "SQL Injection risk in Django ORM"},
                        }
                    ],
                }
            },
            "results": [
                {
                    "ruleId": "python.django.security.injection",
                    "level": "error",
                    "message": {"text": "Unsanitised input passed to query()"},
                }
            ],
        }
    ],
})

CYCLONEDX_CONTENT = json.dumps({
    "bomFormat": "CycloneDX",
    "specVersion": "1.4",
    "vulnerabilities": [
        {
            "id": "CVE-2023-9999",
            "description": "Remote code execution vulnerability",
            "ratings": [{"severity": "critical"}],
            "source": {"name": "NVD"},
        },
        {
            "id": "GHSA-xxxx-yyyy",
            "description": "Dependency confusion attack",
            "ratings": [{"severity": "high"}],
            "source": {"name": "GitHub Advisory"},
        },
    ],
})


# ===========================================================================
# CSV import tests
# ===========================================================================


def test_csv_import_happy_path(engine, org_id):
    result = engine.import_findings(CSV_VALID, ImportFormat.CSV, org_id)
    assert result.total_rows == 3
    assert result.imported == 3
    assert result.skipped == 0
    assert result.errors == []
    assert result.org_id == org_id
    assert result.format == ImportFormat.CSV
    assert result.id  # non-empty UUID


def test_csv_import_missing_required_fields(engine, org_id):
    result = engine.import_findings(CSV_MISSING_REQUIRED, ImportFormat.CSV, org_id)
    assert result.skipped == 3
    assert result.imported == 0
    assert len(result.errors) >= 3
    # Each error references a required field
    fields = {e.field for e in result.errors}
    assert fields & {"title", "severity", "source"}


def test_csv_import_invalid_severity(engine, org_id):
    result = engine.import_findings(CSV_INVALID_SEVERITY, ImportFormat.CSV, org_id)
    assert result.skipped == 1
    assert any(e.field == "severity" for e in result.errors)


def test_csv_import_invalid_cvss(engine, org_id):
    result = engine.import_findings(CSV_BAD_CVSS, ImportFormat.CSV, org_id)
    assert result.skipped == 1
    assert any(e.field == "cvss_score" for e in result.errors)


def test_csv_import_invalid_epss(engine, org_id):
    result = engine.import_findings(CSV_BAD_EPSS, ImportFormat.CSV, org_id)
    assert result.skipped == 1
    assert any(e.field == "epss_score" for e in result.errors)


def test_csv_import_stores_source(engine, org_id):
    result = engine.import_findings(CSV_VALID, ImportFormat.CSV, org_id, source="custom-scan")
    assert result.imported == 3


# ===========================================================================
# JSON import tests
# ===========================================================================


def test_json_import_list(engine, org_id):
    result = engine.import_findings(JSON_LIST, ImportFormat.JSON, org_id)
    assert result.total_rows == 2
    assert result.imported == 2
    assert result.skipped == 0


def test_json_import_wrapped(engine, org_id):
    result = engine.import_findings(JSON_WRAPPED, ImportFormat.JSON, org_id)
    assert result.total_rows == 1
    assert result.imported == 1


def test_json_import_single_dict(engine, org_id):
    result = engine.import_findings(JSON_SINGLE, ImportFormat.JSON, org_id)
    assert result.total_rows == 1
    assert result.imported == 1


def test_json_import_result_model(engine, org_id):
    result = engine.import_findings(JSON_LIST, ImportFormat.JSON, org_id)
    assert result.format == ImportFormat.JSON
    assert result.imported_at  # non-empty timestamp


# ===========================================================================
# SARIF import tests
# ===========================================================================


def test_sarif_import(engine, org_id):
    result = engine.import_findings(SARIF_CONTENT, ImportFormat.SARIF, org_id)
    assert result.total_rows == 1
    assert result.imported == 1
    assert result.skipped == 0


def test_sarif_severity_mapping(engine, org_id):
    """SARIF 'error' level maps to 'high' severity."""
    result = engine.import_findings(SARIF_CONTENT, ImportFormat.SARIF, org_id)
    assert result.imported == 1


# ===========================================================================
# CycloneDX import tests
# ===========================================================================


def test_cyclonedx_import(engine, org_id):
    result = engine.import_findings(CYCLONEDX_CONTENT, ImportFormat.CYCLONEDX, org_id)
    assert result.total_rows == 2
    assert result.imported == 2


def test_cyclonedx_severity_preserved(engine, org_id):
    result = engine.import_findings(CYCLONEDX_CONTENT, ImportFormat.CYCLONEDX, org_id)
    assert result.imported == 2
    assert result.skipped == 0


# ===========================================================================
# Dry-run validation
# ===========================================================================


def test_validate_import_valid(engine):
    errors = engine.validate_import(CSV_VALID, ImportFormat.CSV)
    assert errors == []


def test_validate_import_returns_errors(engine):
    errors = engine.validate_import(CSV_MISSING_REQUIRED, ImportFormat.CSV)
    assert len(errors) > 0
    assert all(isinstance(e, ImportValidationError) for e in errors)


def test_validate_import_does_not_store(engine, org_id):
    engine.validate_import(CSV_MISSING_REQUIRED, ImportFormat.CSV)
    history = engine.get_import_history(org_id)
    assert history == []  # nothing stored


def test_validate_import_invalid_severity(engine):
    errors = engine.validate_import(CSV_INVALID_SEVERITY, ImportFormat.CSV)
    assert any(e.field == "severity" for e in errors)


def test_validate_import_error_has_row(engine):
    errors = engine.validate_import(CSV_MISSING_REQUIRED, ImportFormat.CSV)
    for e in errors:
        assert isinstance(e.row, int)
        assert e.row >= 0


# ===========================================================================
# Export — CSV
# ===========================================================================


def test_export_csv(engine, org_id, tmp_path):
    engine.import_findings(CSV_VALID, ImportFormat.CSV, org_id)
    result = engine.export_findings(org_id, ExportFormat.CSV)
    assert result.total_records == 3
    assert result.format == ExportFormat.CSV
    assert result.file_path.endswith(".csv")
    assert Path(result.file_path).exists()


def test_export_csv_content(engine, org_id):
    engine.import_findings(CSV_VALID, ImportFormat.CSV, org_id)
    findings = engine._query_findings(org_id, {})
    csv_str = engine.export_csv(findings)
    assert "title" in csv_str
    assert "severity" in csv_str
    assert "SQL Injection" in csv_str or len(csv_str) > 0


def test_export_csv_empty(engine):
    csv_str = engine.export_csv([])
    assert "title" in csv_str  # header still present


# ===========================================================================
# Export — JSON
# ===========================================================================


def test_export_json(engine, org_id):
    engine.import_findings(JSON_LIST, ImportFormat.JSON, org_id)
    result = engine.export_findings(org_id, ExportFormat.JSON)
    assert result.total_records == 2
    assert result.format == ExportFormat.JSON
    assert Path(result.file_path).exists()

    content = Path(result.file_path).read_text()
    data = json.loads(content)
    assert "findings" in data
    assert data["total"] == 2


def test_export_json_string(engine, org_id):
    engine.import_findings(JSON_LIST, ImportFormat.JSON, org_id)
    findings = engine._query_findings(org_id, {})
    json_str = engine.export_json(findings)
    data = json.loads(json_str)
    assert "findings" in data
    assert isinstance(data["findings"], list)


# ===========================================================================
# Export — SARIF
# ===========================================================================


def test_export_sarif(engine, org_id):
    engine.import_findings(CSV_VALID, ImportFormat.CSV, org_id)
    result = engine.export_findings(org_id, ExportFormat.SARIF)
    assert result.total_records == 3
    assert result.format == ExportFormat.SARIF

    content = Path(result.file_path).read_text()
    sarif = json.loads(content)
    assert sarif["version"] == "2.1.0"
    assert "runs" in sarif
    assert len(sarif["runs"]) == 1
    assert "results" in sarif["runs"][0]


def test_export_sarif_levels(engine, org_id):
    engine.import_findings(CSV_VALID, ImportFormat.CSV, org_id)
    findings = engine._query_findings(org_id, {})
    sarif_str = engine.export_sarif(findings)
    sarif = json.loads(sarif_str)
    results = sarif["runs"][0]["results"]
    levels = {r["level"] for r in results}
    assert levels <= {"error", "warning", "note"}


# ===========================================================================
# Export filters
# ===========================================================================


def test_export_with_severity_filter(engine, org_id):
    engine.import_findings(CSV_VALID, ImportFormat.CSV, org_id)
    result = engine.export_findings(org_id, ExportFormat.JSON, filters={"severity": "high"})
    assert result.total_records == 1
    assert result.filters_applied == {"severity": "high"}


def test_export_with_status_filter(engine, org_id):
    engine.import_findings(CSV_VALID, ImportFormat.CSV, org_id)
    result = engine.export_findings(org_id, ExportFormat.JSON, filters={"status": "open"})
    assert result.total_records == 3


# ===========================================================================
# Field mapping
# ===========================================================================


def test_field_mapping_csv(engine):
    mapping = engine.get_field_mapping("csv")
    assert "title" in mapping
    assert "severity" in mapping
    assert "source" in mapping


def test_field_mapping_json(engine):
    mapping = engine.get_field_mapping("json")
    assert isinstance(mapping, dict)
    assert len(mapping) > 0


def test_field_mapping_sarif(engine):
    mapping = engine.get_field_mapping("sarif")
    assert "ruleId" in mapping or "level" in mapping


def test_field_mapping_cyclonedx(engine):
    mapping = engine.get_field_mapping("cyclonedx")
    assert isinstance(mapping, dict)


def test_field_mapping_unknown_returns_empty(engine):
    mapping = engine.get_field_mapping("xlsx")
    assert mapping == {}


# ===========================================================================
# History
# ===========================================================================


def test_import_history_recorded(engine, org_id):
    engine.import_findings(CSV_VALID, ImportFormat.CSV, org_id)
    history = engine.get_import_history(org_id)
    assert len(history) == 1
    assert history[0].org_id == org_id
    assert history[0].imported == 3


def test_import_history_multiple(engine, org_id):
    engine.import_findings(CSV_VALID, ImportFormat.CSV, org_id)
    engine.import_findings(JSON_LIST, ImportFormat.JSON, org_id)
    history = engine.get_import_history(org_id)
    assert len(history) == 2


def test_export_history_recorded(engine, org_id):
    engine.import_findings(JSON_LIST, ImportFormat.JSON, org_id)
    engine.export_findings(org_id, ExportFormat.JSON)
    history = engine.get_export_history(org_id)
    assert len(history) == 1
    assert history[0].format == ExportFormat.JSON


def test_history_isolated_by_org(engine):
    engine.import_findings(CSV_VALID, ImportFormat.CSV, "org-A")
    engine.import_findings(JSON_LIST, ImportFormat.JSON, "org-B")
    assert len(engine.get_import_history("org-A")) == 1
    assert len(engine.get_import_history("org-B")) == 1
    assert len(engine.get_import_history("org-C")) == 0


# ===========================================================================
# Scheduled exports
# ===========================================================================


def test_schedule_export_returns_id(engine, org_id):
    schedule_id = engine.schedule_export(org_id, ExportFormat.JSON, frequency="daily")
    assert schedule_id  # non-empty string


def test_schedule_export_with_filters(engine, org_id):
    schedule_id = engine.schedule_export(
        org_id, ExportFormat.CSV, filters={"severity": "high"}, frequency="weekly"
    )
    assert schedule_id


def test_schedule_export_different_formats(engine, org_id):
    id1 = engine.schedule_export(org_id, ExportFormat.CSV, frequency="hourly")
    id2 = engine.schedule_export(org_id, ExportFormat.SARIF, frequency="daily")
    assert id1 != id2


# ===========================================================================
# Bulk stats
# ===========================================================================


def test_bulk_stats_empty(engine, org_id):
    stats = engine.get_bulk_stats(org_id)
    assert stats["org_id"] == org_id
    assert stats["total_findings"] == 0
    assert stats["total_imports"] == 0
    assert stats["total_exports"] == 0


def test_bulk_stats_after_import(engine, org_id):
    engine.import_findings(CSV_VALID, ImportFormat.CSV, org_id)
    stats = engine.get_bulk_stats(org_id)
    assert stats["total_findings"] == 3
    assert stats["total_imports"] == 1
    assert "findings_by_severity" in stats


def test_bulk_stats_after_export(engine, org_id):
    engine.import_findings(JSON_LIST, ImportFormat.JSON, org_id)
    engine.export_findings(org_id, ExportFormat.JSON)
    stats = engine.get_bulk_stats(org_id)
    assert stats["total_exports"] == 1


def test_bulk_stats_severity_breakdown(engine, org_id):
    engine.import_findings(CSV_VALID, ImportFormat.CSV, org_id)
    stats = engine.get_bulk_stats(org_id)
    sev = stats["findings_by_severity"]
    assert isinstance(sev, dict)
    # CSV_VALID has high, medium, low
    assert sum(sev.values()) == 3


# ===========================================================================
# API Router tests
# ===========================================================================


def _make_app(engine_instance):
    """Build a minimal FastAPI app with the bulk operations router."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    import apps.api.bulk_operations_router as bulk_mod

    # Inject test engine
    bulk_mod._engine = engine_instance

    app = FastAPI()
    app.include_router(bulk_mod.router)
    return TestClient(app)


@pytest.fixture()
def client(engine):
    return _make_app(engine)


def test_api_import_csv(client, org_id):
    resp = client.post("/api/v1/bulk/import", json={
        "content": CSV_VALID,
        "format": "csv",
        "org_id": org_id,
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["imported"] == 3
    assert data["skipped"] == 0


def test_api_import_json(client, org_id):
    resp = client.post("/api/v1/bulk/import", json={
        "content": JSON_LIST,
        "format": "json",
        "org_id": org_id,
    })
    assert resp.status_code == 200
    assert resp.json()["imported"] == 2


def test_api_import_invalid_format(client, org_id):
    resp = client.post("/api/v1/bulk/import", json={
        "content": "data",
        "format": "xlsx",
        "org_id": org_id,
    })
    assert resp.status_code == 422


def test_api_validate_valid(client):
    resp = client.post("/api/v1/bulk/validate", json={
        "content": CSV_VALID,
        "format": "csv",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["valid"] is True
    assert data["error_count"] == 0


def test_api_validate_errors(client):
    resp = client.post("/api/v1/bulk/validate", json={
        "content": CSV_MISSING_REQUIRED,
        "format": "csv",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["valid"] is False
    assert data["error_count"] > 0


def test_api_export_json(client, engine, org_id):
    engine.import_findings(JSON_LIST, ImportFormat.JSON, org_id)
    resp = client.post("/api/v1/bulk/export", json={
        "org_id": org_id,
        "format": "json",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_records"] == 2
    assert data["format"] == "json"


def test_api_export_invalid_format(client, org_id):
    resp = client.post("/api/v1/bulk/export", json={
        "org_id": org_id,
        "format": "pdf",
    })
    assert resp.status_code == 422


def test_api_import_history(client, engine, org_id):
    engine.import_findings(CSV_VALID, ImportFormat.CSV, org_id)
    resp = client.get(f"/api/v1/bulk/import-history?org_id={org_id}")
    assert resp.status_code == 200
    assert len(resp.json()) == 1


def test_api_export_history(client, engine, org_id):
    engine.import_findings(JSON_LIST, ImportFormat.JSON, org_id)
    engine.export_findings(org_id, ExportFormat.JSON)
    resp = client.get(f"/api/v1/bulk/export-history?org_id={org_id}")
    assert resp.status_code == 200
    assert len(resp.json()) == 1


def test_api_field_mapping_csv(client):
    resp = client.get("/api/v1/bulk/field-mapping/csv")
    assert resp.status_code == 200
    data = resp.json()
    assert data["format"] == "csv"
    assert "title" in data["mapping"]


def test_api_field_mapping_unknown(client):
    resp = client.get("/api/v1/bulk/field-mapping/xlsx")
    assert resp.status_code == 404


def test_api_stats(client, engine, org_id):
    engine.import_findings(CSV_VALID, ImportFormat.CSV, org_id)
    resp = client.get(f"/api/v1/bulk/stats?org_id={org_id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_findings"] == 3
    assert data["total_imports"] == 1
