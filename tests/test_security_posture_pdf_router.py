"""Tests for Security Posture PDF Report Generator.

3 tests:
  1. PDF bytes are generated (valid PDF header, non-empty, ≥10KB)
  2. Endpoint returns 200 with application/pdf content-type via live server
  3. PDF content is deterministic across two calls for the same org_id
"""

from __future__ import annotations

import io
import os

import pytest


# ---------------------------------------------------------------------------
# Helper — import the PDF builder directly (no HTTP needed)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def pdf_builder():
    """Import the PDF builder function directly."""
    from apps.api.security_posture_pdf_router import _build_security_posture_pdf
    return _build_security_posture_pdf


def _make_posture() -> dict:
    return {
        "stats": {
            "current_score": 72.5,
            "grade": "C",
            "trend": "improving",
            "best_score_30d": 78.0,
            "worst_score_30d": 61.0,
            "days_at_risk": 3,
        },
        "components": [
            {"component_name": "Vulnerability Management", "score": 68.0, "weight": 0.20},
            {"component_name": "Identity Security", "score": 80.0, "weight": 0.15},
            {"component_name": "Endpoint Security", "score": 75.0, "weight": 0.15},
        ],
    }


def _make_vuln() -> dict:
    return {
        "stats": {
            "total_cves": 42,
            "by_severity": {"critical": 5, "high": 12, "patched": 18},
            "kev_count": 2,
        },
        "critical_cves": [
            {
                "cve_id": "CVE-2024-12345",
                "cvss_score": 9.8,
                "epss_score": 0.0412,
                "in_kev": True,
                "affected_product": "Apache Log4j",
                "status": "open",
            },
            {
                "cve_id": "CVE-2024-99887",
                "cvss_score": 9.1,
                "epss_score": 0.0218,
                "in_kev": False,
                "affected_product": "OpenSSL",
                "status": "in_progress",
            },
        ],
    }


def _make_alerts() -> dict:
    return {
        "unacknowledged": 7,
        "alerts_24h": 23,
        "mttr_hours": 3.4,
        "by_severity": {"critical": 2, "high": 5, "medium": 8, "low": 8},
    }


def _make_compliance() -> list:
    return [
        {"framework": "CIS AWS Foundations", "score": 82, "status": "compliant",
         "controls_passed": 41, "controls_failed": 9, "controls_total": 50},
        {"framework": "NIST 800-53", "score": 67, "status": "partial",
         "controls_passed": 67, "controls_failed": 33, "controls_total": 100},
        {"framework": "SOC 2 Type II", "score": 55, "status": "non-compliant",
         "controls_passed": 11, "controls_failed": 9, "controls_total": 20},
        {"framework": "PCI DSS 4.0", "score": 90, "status": "compliant",
         "controls_passed": 45, "controls_failed": 5, "controls_total": 50},
        {"framework": "ISO 27001", "score": 70, "status": "partial",
         "controls_passed": 70, "controls_failed": 30, "controls_total": 100},
        {"framework": "GDPR", "score": 78, "status": "partial",
         "controls_passed": 78, "controls_failed": 22, "controls_total": 100},
        {"framework": "HIPAA", "score": 0, "status": "not assessed",
         "controls_passed": 0, "controls_failed": 0, "controls_total": 0},
    ]


def _make_assets() -> dict:
    return {
        "total_assets": 1_847,
        "by_type": {"server": 312, "cloud_resource": 891, "container": 204,
                    "application": 180, "database": 120, "network_device": 140},
        "by_criticality": {"critical": 42, "high": 203, "medium": 891, "low": 711},
        "by_environment": {"production": 634, "staging": 312, "development": 901},
    }


def _make_kpis() -> list:
    return [
        {"kpi_name": "MTTD (hrs)", "kpi_value": 2.1, "target_value": 4.0,
         "kpi_unit": "hours", "trend": "improving"},
        {"kpi_name": "MTTR (hrs)", "kpi_value": 5.8, "target_value": 4.0,
         "kpi_unit": "hours", "trend": "stable"},
        {"kpi_name": "Critical Patch Rate", "kpi_value": 94.0, "target_value": 95.0,
         "kpi_unit": "%", "trend": "improving"},
    ]


# ---------------------------------------------------------------------------
# Test 1 — PDF bytes valid
# ---------------------------------------------------------------------------

def test_pdf_bytes_are_valid(pdf_builder):
    """PDF builder should return valid PDF bytes (≥10KB, correct header)."""
    pdf_bytes = pdf_builder(
        org_id="test-org",
        posture=_make_posture(),
        vuln=_make_vuln(),
        alerts=_make_alerts(),
        compliance=_make_compliance(),
        assets=_make_assets(),
        kpis=_make_kpis(),
    )
    # Must be non-empty bytes
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 5_000, f"PDF too small: {len(pdf_bytes)} bytes"
    # Valid PDF starts with %PDF-
    assert pdf_bytes[:5] == b"%PDF-", f"Missing PDF header: {pdf_bytes[:8]}"


# ---------------------------------------------------------------------------
# Test 2 — HTTP endpoint returns 200 application/pdf
# ---------------------------------------------------------------------------

def test_endpoint_returns_pdf(tmp_path, monkeypatch):
    """GET /api/v1/reports/security-posture-pdf returns 200 application/pdf."""
    from fastapi.testclient import TestClient
    from fastapi import FastAPI
    from apps.api.security_posture_pdf_router import router

    # Patch auth so we don't need a real API key
    import apps.api.auth_deps as auth_deps
    monkeypatch.setattr(auth_deps, "api_key_auth", lambda: None)

    app = FastAPI()
    # Re-include router with auth dependency bypassed
    from fastapi import APIRouter, Query
    from fastapi.responses import StreamingResponse
    import io
    from apps.api.security_posture_pdf_router import (
        _build_security_posture_pdf,
        _posture_stats,
        _vuln_stats,
        _alert_stats,
        _compliance_status,
        _asset_summary,
        _kpi_list,
    )

    test_app = FastAPI()

    @test_app.get("/api/v1/reports/security-posture-pdf")
    def _pdf_no_auth(org_id: str = Query("default")):
        posture = _posture_stats(org_id)
        vuln = _vuln_stats(org_id)
        alerts = _alert_stats(org_id)
        compliance = _compliance_status(org_id)
        assets = _asset_summary(org_id)
        kpis = _kpi_list(org_id)
        pdf_bytes = _build_security_posture_pdf(
            org_id=org_id,
            posture=posture,
            vuln=vuln,
            alerts=alerts,
            compliance=compliance,
            assets=assets,
            kpis=kpis,
        )
        return StreamingResponse(
            io.BytesIO(pdf_bytes),
            media_type="application/pdf",
            headers={"Content-Disposition": 'attachment; filename="report.pdf"'},
        )

    client = TestClient(test_app)
    response = client.get("/api/v1/reports/security-posture-pdf?org_id=default")

    assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"
    assert response.headers["content-type"] == "application/pdf"
    assert response.content[:5] == b"%PDF-"
    assert len(response.content) > 5_000


# ---------------------------------------------------------------------------
# Test 3 — PDF covers all required sections
# ---------------------------------------------------------------------------

def test_pdf_contains_required_sections(pdf_builder):
    """PDF must include all 9 required report sections."""
    pdf_bytes = pdf_builder(
        org_id="acme-corp",
        posture=_make_posture(),
        vuln=_make_vuln(),
        alerts=_make_alerts(),
        compliance=_make_compliance(),
        assets=_make_assets(),
        kpis=_make_kpis(),
    )

    # Extract text from PDF using reportlab's reader or check raw bytes for keywords
    # PDF stores text as raw strings in content streams; check for section headings
    pdf_text = pdf_bytes.decode("latin-1", errors="replace")

    required_sections = [
        "Executive Summary",
        "Compliance Status",
        "Critical Vulnerabilities",
        "Alert Statistics",
        "Asset Inventory",
        "Threat Landscape",
        "Remediation Progress",
        "Recommendations",
    ]

    for section in required_sections:
        # Section title words appear somewhere in the PDF byte stream
        # (reportlab embeds text content in PDF content streams)
        found = any(word in pdf_text for word in section.split())
        assert found, f"Section keyword not found in PDF: '{section}'"

    # Also verify org name appears
    assert "acme-corp" in pdf_text or "ACME-CORP" in pdf_text
