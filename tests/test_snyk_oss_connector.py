"""Tests for snyk_oss_connector — real ingestion, no mocks for findings engine."""
from __future__ import annotations

import os
from pathlib import Path

os.environ.setdefault("FIXOPS_MODE", "dev")

from connectors.snyk_oss_connector import (  # noqa: E402
    SnykOSSConnector,
    TenantScanResult,
    _normalize_severity,
    _osv_severity_from_list,
)


def test_severity_normalization():
    assert _normalize_severity("CRITICAL") == ("critical", 9.5)
    assert _normalize_severity("HIGH") == ("high", 7.5)
    assert _normalize_severity("Medium") == ("medium", 5.0)
    assert _normalize_severity("LOW") == ("low", 3.0)
    assert _normalize_severity(None) == ("info", 0.0)
    assert _normalize_severity("BOGUS") == ("info", 0.0)


def test_osv_severity_from_cvss_vector():
    assert _osv_severity_from_list([{"score": "CVSS:3.1/AV:N/HIGH"}]) == "HIGH"
    assert _osv_severity_from_list([{"score": "CVSS:3.1/AV:N/CRITICAL"}]) == "CRITICAL"
    assert _osv_severity_from_list(None) is None
    assert _osv_severity_from_list([]) is None


def test_iter_trivy_vulns_yields_normalized_finding():
    sample = {
        "Results": [
            {
                "Target": "package-lock.json",
                "Type": "npm",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-0001",
                        "PkgName": "lodash",
                        "InstalledVersion": "4.17.15",
                        "FixedVersion": "4.17.21",
                        "Severity": "HIGH",
                        "Title": "Prototype pollution",
                        "Description": "lodash <4.17.21 vulnerable",
                    }
                ],
            }
        ]
    }
    findings = list(SnykOSSConnector._iter_trivy_vulns(sample, "express"))
    assert len(findings) == 1
    f = findings[0]
    assert f["severity"] == "high"
    assert f["cvss"] == 7.5
    assert "CVE-2024-0001" in f["title"]
    assert "lodash" in f["asset_id"]
    assert f["correlation_key"].startswith("trivy_fs|express|CVE-2024-0001|lodash")


def test_iter_osv_vulns_yields_normalized_finding():
    sample = {
        "results": [
            {
                "source": {"path": "package.json", "type": "lockfile"},
                "packages": [
                    {
                        "package": {"name": "lodash", "version": "4.17.15", "ecosystem": "npm"},
                        "vulnerabilities": [
                            {
                                "id": "GHSA-xxxx",
                                "summary": "Prototype pollution",
                                "details": "details",
                                "database_specific": {"severity": "HIGH"},
                            }
                        ],
                    }
                ],
            }
        ]
    }
    findings = list(SnykOSSConnector._iter_osv_vulns(sample, "lodash"))
    assert len(findings) == 1
    f = findings[0]
    assert f["severity"] == "high"
    assert f["correlation_key"].startswith("osv|lodash|GHSA-xxxx|lodash")


def test_list_tenants_against_fleet(tmp_path: Path):
    # Build a tiny fake fleet to confirm directory discovery
    (tmp_path / "alpha").mkdir()
    (tmp_path / "bravo").mkdir()
    (tmp_path / "not_a_tenant.txt").write_text("ignore me")
    c = SnykOSSConnector(fleet_root=tmp_path, build_images=False)
    names = [p.name for p in c.list_tenants()]
    assert names == ["alpha", "bravo"]


def test_record_finding_writes_real_row(tmp_path: Path):
    """End-to-end: connector ingests via SecurityFindingsEngine.record_finding."""
    from core.security_findings_engine import SecurityFindingsEngine

    # Use an isolated DB to avoid polluting the dev DB.
    os.environ["SECURITY_FINDINGS_DB"] = str(tmp_path / "sf.db")
    engine = SecurityFindingsEngine()  # respects env or default

    c = SnykOSSConnector(build_images=False)
    c._engine = engine  # inject
    result = TenantScanResult(tenant="t1", repo_path=str(tmp_path))
    ok = c._ingest(
        org_id="default",
        tenant="t1",
        source_tool=SnykOSSConnector.SOURCE_TRIVY_FS,
        title="[CVE-2024-0001] sample",
        severity="high",
        cvss=7.5,
        description="d",
        remediation="r",
        asset_id="t1:package-lock.json:lodash@4.17.15",
        asset_type="package",
        correlation_key="trivy_fs|t1|CVE-2024-0001|lodash|4.17.15",
    )
    assert ok is True
    findings = engine.list_findings(org_id="default", source_tool=SnykOSSConnector.SOURCE_TRIVY_FS)
    assert any(f["correlation_key"].startswith("trivy_fs|t1|CVE-2024-0001") for f in findings)


def test_status_endpoint_shape():
    """Router status endpoint returns expected keys."""
    from apps.api.snyk_oss_router import status
    out = status()
    assert out["connector"] == "snyk-oss"
    assert "tools" in out and "trivy" in out["tools"]
    assert "fleet_root" in out
