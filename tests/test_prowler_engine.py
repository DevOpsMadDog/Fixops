"""Tests for Prowler CSPM Engine — ALDECI.

Covers: scan lifecycle, finding ingestion (dedup), compliance mapping,
summary stats, bulk ingest, provider/severity validation.
"""
from __future__ import annotations

import json
import os
import tempfile
import pytest

# Ensure suite paths are importable
import sys
_repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _sub in ("suite-core", "suite-api", "suite-feeds", "suite-attack",
             "suite-evidence-risk", "suite-integrations"):
    _p = os.path.join(_repo, _sub)
    if _p not in sys.path:
        sys.path.insert(0, _p)


from core.prowler_engine import ProwlerEngine


@pytest.fixture
def engine(tmp_path):
    db = str(tmp_path / "prowler_test.db")
    return ProwlerEngine(db_path=db)


# ---------------------------------------------------------------------------
# Scan lifecycle
# ---------------------------------------------------------------------------

class TestScanLifecycle:
    def test_create_scan(self, engine):
        scan = engine.create_scan(org_id="org1", provider="aws", account_id="123456")
        assert scan["id"]
        assert scan["org_id"] == "org1"
        assert scan["provider"] == "aws"
        assert scan["status"] == "pending"
        assert scan["account_id"] == "123456"

    def test_create_scan_invalid_provider(self, engine):
        with pytest.raises(ValueError, match="provider must be"):
            engine.create_scan(org_id="org1", provider="oracle")

    def test_start_scan(self, engine):
        scan = engine.create_scan(org_id="org1", provider="aws")
        started = engine.start_scan(scan_id=scan["id"], org_id="org1")
        assert started["status"] == "running"
        assert started["started_at"] is not None

    def test_complete_scan(self, engine):
        scan = engine.create_scan(org_id="org1", provider="aws")
        engine.start_scan(scan_id=scan["id"], org_id="org1")
        completed = engine.complete_scan(
            scan_id=scan["id"], org_id="org1",
            checks_total=100, checks_passed=85, checks_failed=15,
            prowler_version="4.0.0",
        )
        assert completed["status"] == "completed"
        assert completed["checks_total"] == 100
        assert completed["checks_passed"] == 85
        assert completed["checks_failed"] == 15
        assert completed["prowler_version"] == "4.0.0"
        assert completed["completed_at"] is not None

    def test_fail_scan(self, engine):
        scan = engine.create_scan(org_id="org1", provider="aws")
        engine.start_scan(scan_id=scan["id"], org_id="org1")
        failed = engine.fail_scan(
            scan_id=scan["id"], org_id="org1",
            error_message="AWS credentials expired",
        )
        assert failed["status"] == "failed"
        assert failed["error_message"] == "AWS credentials expired"

    def test_get_scan(self, engine):
        scan = engine.create_scan(org_id="org1", provider="azure")
        fetched = engine.get_scan(scan_id=scan["id"], org_id="org1")
        assert fetched["id"] == scan["id"]
        assert fetched["provider"] == "azure"

    def test_get_scan_not_found(self, engine):
        with pytest.raises(KeyError):
            engine.get_scan(scan_id="nonexistent", org_id="org1")

    def test_get_scan_wrong_org(self, engine):
        scan = engine.create_scan(org_id="org1", provider="aws")
        with pytest.raises(KeyError):
            engine.get_scan(scan_id=scan["id"], org_id="org2")

    def test_list_scans(self, engine):
        engine.create_scan(org_id="org1", provider="aws")
        engine.create_scan(org_id="org1", provider="azure")
        engine.create_scan(org_id="org2", provider="gcp")
        scans = engine.list_scans(org_id="org1")
        assert len(scans) == 2

    def test_list_scans_filter_provider(self, engine):
        engine.create_scan(org_id="org1", provider="aws")
        engine.create_scan(org_id="org1", provider="azure")
        scans = engine.list_scans(org_id="org1", provider="aws")
        assert len(scans) == 1
        assert scans[0]["provider"] == "aws"

    def test_list_scans_filter_status(self, engine):
        s1 = engine.create_scan(org_id="org1", provider="aws")
        engine.create_scan(org_id="org1", provider="aws")
        engine.start_scan(scan_id=s1["id"], org_id="org1")
        scans = engine.list_scans(org_id="org1", status="running")
        assert len(scans) == 1


# ---------------------------------------------------------------------------
# Finding ingestion
# ---------------------------------------------------------------------------

class TestFindingIngestion:
    def test_ingest_finding(self, engine):
        scan = engine.create_scan(org_id="org1", provider="aws")
        finding = engine.ingest_finding(
            scan_id=scan["id"],
            org_id="org1",
            provider="aws",
            account_id="123456",
            region="us-east-1",
            service="s3",
            check_id="s3_bucket_public_access",
            check_title="S3 Bucket has public access enabled",
            severity="critical",
            resource_type="AWS::S3::Bucket",
            resource_id="my-public-bucket",
            resource_arn="arn:aws:s3:::my-public-bucket",
            status_extended="Bucket my-public-bucket has public read access",
            risk="Data exposure via public S3 bucket",
            remediation="Block all public access",
            remediation_url="https://docs.aws.amazon.com/s3/block-public-access",
        )
        assert finding["id"]
        assert finding["severity"] == "critical"
        assert finding["status"] == "open"
        assert finding["check_id"] == "s3_bucket_public_access"
        assert finding["cis_benchmark"] == "CIS Amazon Web Services Foundations Benchmark v1.5.0"

    def test_ingest_finding_invalid_severity(self, engine):
        scan = engine.create_scan(org_id="org1", provider="aws")
        with pytest.raises(ValueError, match="severity must be"):
            engine.ingest_finding(
                scan_id=scan["id"], org_id="org1", provider="aws",
                account_id="", region="", service="s3",
                check_id="test", check_title="test",
                severity="extreme",
            )

    def test_finding_dedup(self, engine):
        scan = engine.create_scan(org_id="org1", provider="aws")
        f1 = engine.ingest_finding(
            scan_id=scan["id"], org_id="org1", provider="aws",
            account_id="123", region="us-east-1", service="s3",
            check_id="s3_check_1", check_title="Check 1",
            severity="high", resource_id="bucket-1",
        )
        f2 = engine.ingest_finding(
            scan_id=scan["id"], org_id="org1", provider="aws",
            account_id="123", region="us-east-1", service="s3",
            check_id="s3_check_1", check_title="Check 1",
            severity="high", resource_id="bucket-1",
        )
        # Dedup: same check_id + resource_id + open status → returns existing
        assert f1["id"] == f2["id"]

    def test_dedup_allows_different_resource(self, engine):
        scan = engine.create_scan(org_id="org1", provider="aws")
        f1 = engine.ingest_finding(
            scan_id=scan["id"], org_id="org1", provider="aws",
            account_id="123", region="", service="s3",
            check_id="s3_check_1", check_title="Check 1",
            severity="high", resource_id="bucket-1",
        )
        f2 = engine.ingest_finding(
            scan_id=scan["id"], org_id="org1", provider="aws",
            account_id="123", region="", service="s3",
            check_id="s3_check_1", check_title="Check 1",
            severity="high", resource_id="bucket-2",
        )
        assert f1["id"] != f2["id"]

    def test_dedup_allows_after_resolve(self, engine):
        scan = engine.create_scan(org_id="org1", provider="aws")
        f1 = engine.ingest_finding(
            scan_id=scan["id"], org_id="org1", provider="aws",
            account_id="123", region="", service="s3",
            check_id="s3_check_1", check_title="Check 1",
            severity="high", resource_id="bucket-1",
        )
        engine.resolve_finding(finding_id=f1["id"], org_id="org1")
        f2 = engine.ingest_finding(
            scan_id=scan["id"], org_id="org1", provider="aws",
            account_id="123", region="", service="s3",
            check_id="s3_check_1", check_title="Check 1",
            severity="high", resource_id="bucket-1",
        )
        # After resolving, a new finding with same key should be created
        assert f1["id"] != f2["id"]

    def test_resolve_finding(self, engine):
        scan = engine.create_scan(org_id="org1", provider="aws")
        f = engine.ingest_finding(
            scan_id=scan["id"], org_id="org1", provider="aws",
            account_id="", region="", service="iam",
            check_id="iam_check_1", check_title="IAM check",
            severity="medium", resource_id="user-1",
        )
        resolved = engine.resolve_finding(finding_id=f["id"], org_id="org1")
        assert resolved["status"] == "resolved"
        assert resolved["resolved_at"] is not None

    def test_resolve_finding_not_found(self, engine):
        with pytest.raises(KeyError):
            engine.resolve_finding(finding_id="nonexistent", org_id="org1")

    def test_suppress_finding(self, engine):
        scan = engine.create_scan(org_id="org1", provider="aws")
        f = engine.ingest_finding(
            scan_id=scan["id"], org_id="org1", provider="aws",
            account_id="", region="", service="ec2",
            check_id="ec2_check_1", check_title="EC2 check",
            severity="low", resource_id="i-12345",
        )
        suppressed = engine.suppress_finding(finding_id=f["id"], org_id="org1")
        assert suppressed["status"] == "suppressed"

    def test_suppress_finding_not_found(self, engine):
        with pytest.raises(KeyError):
            engine.suppress_finding(finding_id="nonexistent", org_id="org1")

    def test_get_finding(self, engine):
        scan = engine.create_scan(org_id="org1", provider="aws")
        f = engine.ingest_finding(
            scan_id=scan["id"], org_id="org1", provider="aws",
            account_id="123", region="eu-west-1", service="rds",
            check_id="rds_check_1", check_title="RDS check",
            severity="high", resource_id="db-1",
        )
        fetched = engine.get_finding(finding_id=f["id"], org_id="org1")
        assert fetched["check_id"] == "rds_check_1"
        assert fetched["region"] == "eu-west-1"

    def test_get_finding_not_found(self, engine):
        with pytest.raises(KeyError):
            engine.get_finding(finding_id="nonexistent", org_id="org1")

    def test_get_findings_list(self, engine):
        scan = engine.create_scan(org_id="org1", provider="aws")
        engine.ingest_finding(
            scan_id=scan["id"], org_id="org1", provider="aws",
            account_id="", region="", service="s3",
            check_id="check_1", check_title="C1",
            severity="critical", resource_id="r1",
        )
        engine.ingest_finding(
            scan_id=scan["id"], org_id="org1", provider="aws",
            account_id="", region="", service="iam",
            check_id="check_2", check_title="C2",
            severity="high", resource_id="r2",
        )
        findings = engine.get_findings(org_id="org1")
        assert len(findings) == 2

    def test_get_findings_filter_severity(self, engine):
        scan = engine.create_scan(org_id="org1", provider="aws")
        engine.ingest_finding(
            scan_id=scan["id"], org_id="org1", provider="aws",
            account_id="", region="", service="s3",
            check_id="check_1", check_title="C1",
            severity="critical", resource_id="r1",
        )
        engine.ingest_finding(
            scan_id=scan["id"], org_id="org1", provider="aws",
            account_id="", region="", service="s3",
            check_id="check_2", check_title="C2",
            severity="low", resource_id="r2",
        )
        findings = engine.get_findings(org_id="org1", severity="critical")
        assert len(findings) == 1
        assert findings[0]["severity"] == "critical"

    def test_get_findings_filter_service(self, engine):
        scan = engine.create_scan(org_id="org1", provider="aws")
        engine.ingest_finding(
            scan_id=scan["id"], org_id="org1", provider="aws",
            account_id="", region="", service="s3",
            check_id="check_1", check_title="C1",
            severity="medium", resource_id="r1",
        )
        engine.ingest_finding(
            scan_id=scan["id"], org_id="org1", provider="aws",
            account_id="", region="", service="iam",
            check_id="check_2", check_title="C2",
            severity="medium", resource_id="r2",
        )
        findings = engine.get_findings(org_id="org1", service="s3")
        assert len(findings) == 1

    def test_get_findings_org_isolation(self, engine):
        scan1 = engine.create_scan(org_id="org1", provider="aws")
        scan2 = engine.create_scan(org_id="org2", provider="aws")
        engine.ingest_finding(
            scan_id=scan1["id"], org_id="org1", provider="aws",
            account_id="", region="", service="s3",
            check_id="check_1", check_title="C1",
            severity="high", resource_id="r1",
        )
        engine.ingest_finding(
            scan_id=scan2["id"], org_id="org2", provider="aws",
            account_id="", region="", service="s3",
            check_id="check_1", check_title="C1",
            severity="high", resource_id="r1",
        )
        assert len(engine.get_findings(org_id="org1")) == 1
        assert len(engine.get_findings(org_id="org2")) == 1


# ---------------------------------------------------------------------------
# Bulk ingest
# ---------------------------------------------------------------------------

class TestBulkIngest:
    def test_bulk_ingest(self, engine):
        scan = engine.create_scan(org_id="org1", provider="aws")
        findings_list = [
            {
                "provider": "aws", "account_id": "123", "region": "us-east-1",
                "service": "s3", "check_id": f"check_{i}", "check_title": f"Check {i}",
                "severity": "high", "resource_id": f"res_{i}",
            }
            for i in range(5)
        ]
        result = engine.bulk_ingest_findings(
            scan_id=scan["id"], org_id="org1", findings_list=findings_list
        )
        assert result["ingested"] == 5
        assert result["skipped_duplicates"] == 0

    def test_bulk_ingest_with_duplicates(self, engine):
        scan = engine.create_scan(org_id="org1", provider="aws")
        # Ingest one first
        engine.ingest_finding(
            scan_id=scan["id"], org_id="org1", provider="aws",
            account_id="123", region="", service="s3",
            check_id="check_0", check_title="Check 0",
            severity="high", resource_id="res_0",
        )
        findings_list = [
            {
                "provider": "aws", "account_id": "123", "region": "",
                "service": "s3", "check_id": "check_0", "check_title": "Check 0",
                "severity": "high", "resource_id": "res_0",
            },
            {
                "provider": "aws", "account_id": "123", "region": "",
                "service": "iam", "check_id": "check_1", "check_title": "Check 1",
                "severity": "medium", "resource_id": "res_1",
            },
        ]
        result = engine.bulk_ingest_findings(
            scan_id=scan["id"], org_id="org1", findings_list=findings_list
        )
        assert result["ingested"] == 1
        assert result["skipped_duplicates"] == 1


# ---------------------------------------------------------------------------
# Compliance
# ---------------------------------------------------------------------------

class TestCompliance:
    def test_ingest_compliance(self, engine):
        scan = engine.create_scan(org_id="org1", provider="aws")
        comp = engine.ingest_compliance(
            scan_id=scan["id"], org_id="org1", provider="aws",
            framework="CIS Amazon Web Services Foundations Benchmark v1.5.0",
            section="1.1", description="IAM root account MFA",
            total_checks=10, passed_checks=8, failed_checks=2,
        )
        assert comp["compliance_pct"] == 80.0
        assert comp["framework"] == "CIS Amazon Web Services Foundations Benchmark v1.5.0"

    def test_compliance_pct_calculation(self, engine):
        scan = engine.create_scan(org_id="org1", provider="aws")
        comp = engine.ingest_compliance(
            scan_id=scan["id"], org_id="org1", provider="aws",
            framework="CIS", section="2.1",
            total_checks=3, passed_checks=1, failed_checks=2,
        )
        assert comp["compliance_pct"] == pytest.approx(33.33, abs=0.01)

    def test_compliance_pct_zero_checks(self, engine):
        scan = engine.create_scan(org_id="org1", provider="aws")
        comp = engine.ingest_compliance(
            scan_id=scan["id"], org_id="org1", provider="aws",
            framework="CIS", section="3.1",
            total_checks=0, passed_checks=0, failed_checks=0,
        )
        assert comp["compliance_pct"] == 0.0

    def test_get_compliance(self, engine):
        scan = engine.create_scan(org_id="org1", provider="aws")
        engine.ingest_compliance(
            scan_id=scan["id"], org_id="org1", provider="aws",
            framework="CIS AWS", section="1.1",
            total_checks=10, passed_checks=8, failed_checks=2,
        )
        engine.ingest_compliance(
            scan_id=scan["id"], org_id="org1", provider="aws",
            framework="CIS AWS", section="2.1",
            total_checks=5, passed_checks=5, failed_checks=0,
        )
        results = engine.get_compliance(org_id="org1")
        assert len(results) == 2

    def test_get_compliance_filter_framework(self, engine):
        scan = engine.create_scan(org_id="org1", provider="aws")
        engine.ingest_compliance(
            scan_id=scan["id"], org_id="org1", provider="aws",
            framework="CIS AWS", section="1.1",
            total_checks=10, passed_checks=8, failed_checks=2,
        )
        engine.ingest_compliance(
            scan_id=scan["id"], org_id="org1", provider="aws",
            framework="NIST 800-53", section="AC-1",
            total_checks=5, passed_checks=3, failed_checks=2,
        )
        results = engine.get_compliance(org_id="org1", framework="CIS AWS")
        assert len(results) == 1

    def test_get_compliance_summary(self, engine):
        scan = engine.create_scan(org_id="org1", provider="aws")
        engine.ingest_compliance(
            scan_id=scan["id"], org_id="org1", provider="aws",
            framework="CIS AWS", section="1.1",
            total_checks=10, passed_checks=8, failed_checks=2,
        )
        engine.ingest_compliance(
            scan_id=scan["id"], org_id="org1", provider="aws",
            framework="CIS AWS", section="2.1",
            total_checks=10, passed_checks=10, failed_checks=0,
        )
        summary = engine.get_compliance_summary(org_id="org1")
        assert "CIS AWS" in summary
        assert summary["CIS AWS"]["total_checks"] == 20
        assert summary["CIS AWS"]["passed_checks"] == 18
        assert summary["CIS AWS"]["compliance_pct"] == 90.0


# ---------------------------------------------------------------------------
# Summary stats
# ---------------------------------------------------------------------------

class TestSummary:
    def test_empty_summary(self, engine):
        summary = engine.get_summary(org_id="org1")
        assert summary["total_scans"] == 0
        assert summary["total_findings"] == 0
        assert summary["open_findings"] == 0

    def test_summary_with_data(self, engine):
        scan = engine.create_scan(org_id="org1", provider="aws")
        engine.start_scan(scan_id=scan["id"], org_id="org1")
        engine.ingest_finding(
            scan_id=scan["id"], org_id="org1", provider="aws",
            account_id="123", region="us-east-1", service="s3",
            check_id="check_1", check_title="C1",
            severity="critical", resource_id="r1",
        )
        engine.ingest_finding(
            scan_id=scan["id"], org_id="org1", provider="aws",
            account_id="123", region="us-east-1", service="iam",
            check_id="check_2", check_title="C2",
            severity="high", resource_id="r2",
        )
        engine.ingest_finding(
            scan_id=scan["id"], org_id="org1", provider="aws",
            account_id="123", region="us-east-1", service="s3",
            check_id="check_3", check_title="C3",
            severity="medium", resource_id="r3",
        )
        engine.complete_scan(scan_id=scan["id"], org_id="org1",
                             checks_total=100, checks_passed=97, checks_failed=3)

        summary = engine.get_summary(org_id="org1")
        assert summary["total_scans"] == 1
        assert summary["completed_scans"] == 1
        assert summary["total_findings"] == 3
        assert summary["open_findings"] == 3
        assert summary["by_severity"]["critical"] == 1
        assert summary["by_severity"]["high"] == 1
        assert summary["by_severity"]["medium"] == 1
        assert summary["by_provider"]["aws"] == 3
        assert len(summary["top_services"]) == 2  # s3 and iam

    def test_summary_org_isolation(self, engine):
        scan1 = engine.create_scan(org_id="org1", provider="aws")
        scan2 = engine.create_scan(org_id="org2", provider="aws")
        engine.ingest_finding(
            scan_id=scan1["id"], org_id="org1", provider="aws",
            account_id="", region="", service="s3",
            check_id="check_1", check_title="C1",
            severity="critical", resource_id="r1",
        )
        engine.ingest_finding(
            scan_id=scan2["id"], org_id="org2", provider="aws",
            account_id="", region="", service="s3",
            check_id="check_1", check_title="C1",
            severity="critical", resource_id="r1",
        )
        s1 = engine.get_summary(org_id="org1")
        s2 = engine.get_summary(org_id="org2")
        assert s1["total_findings"] == 1
        assert s2["total_findings"] == 1

    def test_summary_resolved_not_open(self, engine):
        scan = engine.create_scan(org_id="org1", provider="aws")
        f = engine.ingest_finding(
            scan_id=scan["id"], org_id="org1", provider="aws",
            account_id="", region="", service="s3",
            check_id="check_1", check_title="C1",
            severity="critical", resource_id="r1",
        )
        engine.resolve_finding(finding_id=f["id"], org_id="org1")
        summary = engine.get_summary(org_id="org1")
        assert summary["total_findings"] == 1
        assert summary["open_findings"] == 0
        assert summary["by_severity"]["critical"] == 0


# ---------------------------------------------------------------------------
# Multi-provider
# ---------------------------------------------------------------------------

class TestMultiProvider:
    def test_azure_scan(self, engine):
        scan = engine.create_scan(org_id="org1", provider="azure")
        finding = engine.ingest_finding(
            scan_id=scan["id"], org_id="org1", provider="azure",
            account_id="sub-123", region="eastus", service="storage",
            check_id="storage_account_public_access",
            check_title="Storage account allows public access",
            severity="high", resource_id="storageaccount1",
        )
        assert finding["provider"] == "azure"
        assert finding["cis_benchmark"] == "CIS Microsoft Azure Foundations Benchmark v2.0.0"

    def test_gcp_scan(self, engine):
        scan = engine.create_scan(org_id="org1", provider="gcp")
        finding = engine.ingest_finding(
            scan_id=scan["id"], org_id="org1", provider="gcp",
            account_id="project-123", region="us-central1", service="compute",
            check_id="compute_firewall_default_allow",
            check_title="Default firewall allows all traffic",
            severity="critical", resource_id="default-allow-all",
        )
        assert finding["provider"] == "gcp"
        assert finding["cis_benchmark"] == "CIS Google Cloud Platform Foundation Benchmark v1.3.0"

    def test_multi_provider_summary(self, engine):
        for prov in ("aws", "azure", "gcp"):
            scan = engine.create_scan(org_id="org1", provider=prov)
            engine.ingest_finding(
                scan_id=scan["id"], org_id="org1", provider=prov,
                account_id="", region="", service="storage",
                check_id=f"{prov}_check_1", check_title="Check 1",
                severity="high", resource_id=f"{prov}_res_1",
            )
        summary = engine.get_summary(org_id="org1")
        assert summary["by_provider"]["aws"] == 1
        assert summary["by_provider"]["azure"] == 1
        assert summary["by_provider"]["gcp"] == 1
