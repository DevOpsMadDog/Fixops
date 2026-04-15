"""Tests for CloudSecurityEngine — CSPM + cloud misconfiguration tracking."""

from __future__ import annotations

import json
import tempfile
import pytest

from core.cloud_security_engine import CloudSecurityEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_engine(tmp_path):
    """Return a CloudSecurityEngine backed by a temp directory."""
    return CloudSecurityEngine(org_id="org-test", db_dir=str(tmp_path))


@pytest.fixture
def alt_engine(tmp_path):
    """Second org engine — used for isolation tests."""
    return CloudSecurityEngine(org_id="org-other", db_dir=str(tmp_path))


@pytest.fixture
def sample_account():
    return {
        "account_id": "123456789012",
        "account_name": "Production AWS",
        "provider": "aws",
        "region": "us-east-1",
        "status": "healthy",
        "resource_count": 500,
        "finding_count": 12,
        "risk_score": 42.5,
    }


@pytest.fixture
def sample_finding(sample_account):
    return {
        "account_id": sample_account["account_id"],
        "resource_id": "sg-0abc123",
        "resource_type": "aws_security_group",
        "resource_name": "default-sg",
        "region": "us-east-1",
        "severity": "critical",
        "category": "network",
        "title": "Security group allows unrestricted inbound access",
        "description": "Port 22 open to 0.0.0.0/0",
        "remediation": "Restrict SSH access to known IP ranges",
        "status": "open",
        "cis_control": "CIS 5.2",
        "compliance_frameworks": ["pci_dss", "cis_aws_v1.5"],
        "risk_score": 9.1,
    }


@pytest.fixture
def sample_resource(sample_account):
    return {
        "account_id": sample_account["account_id"],
        "resource_id": "s3-bucket-prod",
        "resource_type": "aws_s3_bucket",
        "resource_name": "company-prod-data",
        "region": "us-east-1",
        "tags": {"env": "prod", "team": "security"},
        "security_score": 72.0,
        "finding_count": 3,
        "is_public": True,
        "is_encrypted": False,
    }


@pytest.fixture
def sample_benchmark(sample_account):
    return {
        "account_id": sample_account["account_id"],
        "benchmark": "cis_aws_v1.5",
        "pass_count": 87,
        "fail_count": 13,
        "score": 87.0,
    }


# ---------------------------------------------------------------------------
# Account Tests
# ---------------------------------------------------------------------------

class TestAddAccount:
    def test_add_account_returns_record(self, tmp_engine, sample_account):
        rec = tmp_engine.add_account("org-test", sample_account)
        assert rec["id"]
        assert rec["org_id"] == "org-test"
        assert rec["account_id"] == sample_account["account_id"]
        assert rec["provider"] == "aws"
        assert rec["status"] == "healthy"
        assert rec["risk_score"] == 42.5

    def test_add_account_missing_account_id_raises(self, tmp_engine):
        with pytest.raises(ValueError, match="account_id"):
            tmp_engine.add_account("org-test", {"provider": "aws"})

    def test_add_account_invalid_provider_raises(self, tmp_engine):
        with pytest.raises(ValueError, match="provider"):
            tmp_engine.add_account("org-test", {"account_id": "123", "provider": "invalid"})

    def test_add_account_invalid_status_raises(self, tmp_engine):
        with pytest.raises(ValueError, match="status"):
            tmp_engine.add_account("org-test", {"account_id": "123", "status": "unknown"})

    def test_add_account_all_providers(self, tmp_engine):
        for provider in ("aws", "azure", "gcp", "alibaba"):
            rec = tmp_engine.add_account("org-test", {"account_id": f"acc-{provider}", "provider": provider})
            assert rec["provider"] == provider


class TestListAccounts:
    def test_list_accounts_empty(self, tmp_engine):
        assert tmp_engine.list_accounts("org-test") == []

    def test_list_accounts_returns_created(self, tmp_engine, sample_account):
        tmp_engine.add_account("org-test", sample_account)
        results = tmp_engine.list_accounts("org-test")
        assert len(results) == 1
        assert results[0]["account_id"] == sample_account["account_id"]

    def test_list_accounts_filter_by_provider(self, tmp_engine):
        tmp_engine.add_account("org-test", {"account_id": "aws-1", "provider": "aws"})
        tmp_engine.add_account("org-test", {"account_id": "azure-1", "provider": "azure"})
        aws_only = tmp_engine.list_accounts("org-test", provider="aws")
        assert len(aws_only) == 1
        assert aws_only[0]["account_id"] == "aws-1"

    def test_list_accounts_org_isolation(self, tmp_engine, alt_engine, sample_account):
        tmp_engine.add_account("org-test", sample_account)
        assert alt_engine.list_accounts("org-other") == []


# ---------------------------------------------------------------------------
# Finding Tests
# ---------------------------------------------------------------------------

class TestAddFinding:
    def test_add_finding_returns_record(self, tmp_engine, sample_finding):
        rec = tmp_engine.add_finding("org-test", sample_finding)
        assert rec["id"]
        assert rec["severity"] == "critical"
        assert rec["category"] == "network"
        assert rec["status"] == "open"
        assert isinstance(rec["compliance_frameworks"], list)
        assert "pci_dss" in rec["compliance_frameworks"]

    def test_add_finding_missing_account_id_raises(self, tmp_engine):
        with pytest.raises(ValueError, match="account_id"):
            tmp_engine.add_finding("org-test", {"severity": "low"})

    def test_add_finding_invalid_severity_raises(self, tmp_engine):
        with pytest.raises(ValueError, match="severity"):
            tmp_engine.add_finding("org-test", {"account_id": "123", "severity": "extreme"})

    def test_add_finding_invalid_category_raises(self, tmp_engine):
        with pytest.raises(ValueError, match="category"):
            tmp_engine.add_finding("org-test", {"account_id": "123", "category": "unknown"})

    def test_add_finding_all_severities(self, tmp_engine):
        for sev in ("critical", "high", "medium", "low", "info"):
            rec = tmp_engine.add_finding("org-test", {"account_id": "acc-1", "severity": sev})
            assert rec["severity"] == sev


class TestListFindings:
    def test_list_findings_empty(self, tmp_engine):
        assert tmp_engine.list_findings("org-test") == []

    def test_list_findings_returns_created(self, tmp_engine, sample_finding):
        tmp_engine.add_finding("org-test", sample_finding)
        results = tmp_engine.list_findings("org-test")
        assert len(results) == 1
        assert isinstance(results[0]["compliance_frameworks"], list)

    def test_list_findings_filter_by_severity(self, tmp_engine):
        tmp_engine.add_finding("org-test", {"account_id": "acc-1", "severity": "critical"})
        tmp_engine.add_finding("org-test", {"account_id": "acc-1", "severity": "low"})
        crits = tmp_engine.list_findings("org-test", severity="critical")
        assert len(crits) == 1

    def test_list_findings_filter_by_category(self, tmp_engine):
        tmp_engine.add_finding("org-test", {"account_id": "acc-1", "category": "iam"})
        tmp_engine.add_finding("org-test", {"account_id": "acc-1", "category": "network"})
        iam = tmp_engine.list_findings("org-test", category="iam")
        assert len(iam) == 1

    def test_list_findings_filter_by_account_id(self, tmp_engine):
        tmp_engine.add_finding("org-test", {"account_id": "acc-1"})
        tmp_engine.add_finding("org-test", {"account_id": "acc-2"})
        acc1 = tmp_engine.list_findings("org-test", account_id="acc-1")
        assert len(acc1) == 1

    def test_list_findings_filter_by_status(self, tmp_engine):
        tmp_engine.add_finding("org-test", {"account_id": "acc-1", "status": "open"})
        tmp_engine.add_finding("org-test", {"account_id": "acc-1", "status": "suppressed"})
        open_only = tmp_engine.list_findings("org-test", status="open")
        assert len(open_only) == 1

    def test_list_findings_org_isolation(self, tmp_engine, alt_engine, sample_finding):
        tmp_engine.add_finding("org-test", sample_finding)
        assert alt_engine.list_findings("org-other") == []


class TestResolveFinding:
    def test_resolve_finding_marks_resolved(self, tmp_engine, sample_finding):
        rec = tmp_engine.add_finding("org-test", sample_finding)
        result = tmp_engine.resolve_finding("org-test", rec["id"])
        assert result is True
        findings = tmp_engine.list_findings("org-test", status="resolved")
        assert len(findings) == 1
        assert findings[0]["resolved_at"] is not None

    def test_resolve_finding_wrong_org_returns_false(self, tmp_engine, sample_finding):
        rec = tmp_engine.add_finding("org-test", sample_finding)
        result = tmp_engine.resolve_finding("org-other", rec["id"])
        assert result is False

    def test_resolve_finding_nonexistent_returns_false(self, tmp_engine):
        assert tmp_engine.resolve_finding("org-test", "nonexistent-id") is False


# ---------------------------------------------------------------------------
# Resource Tests
# ---------------------------------------------------------------------------

class TestAddResource:
    def test_add_resource_returns_record(self, tmp_engine, sample_resource):
        rec = tmp_engine.add_resource("org-test", sample_resource)
        assert rec["id"]
        assert rec["is_public"] is True
        assert rec["is_encrypted"] is False
        assert isinstance(rec["tags"], dict)
        assert rec["tags"]["env"] == "prod"

    def test_add_resource_missing_account_id_raises(self, tmp_engine):
        with pytest.raises(ValueError, match="account_id"):
            tmp_engine.add_resource("org-test", {"resource_type": "bucket"})

    def test_add_resource_defaults(self, tmp_engine):
        rec = tmp_engine.add_resource("org-test", {"account_id": "acc-1"})
        assert rec["is_public"] is False
        assert rec["is_encrypted"] is True
        assert rec["security_score"] == 100.0


class TestListResources:
    def test_list_resources_empty(self, tmp_engine):
        assert tmp_engine.list_resources("org-test") == []

    def test_list_resources_filter_by_public(self, tmp_engine):
        tmp_engine.add_resource("org-test", {"account_id": "acc-1", "is_public": True})
        tmp_engine.add_resource("org-test", {"account_id": "acc-1", "is_public": False})
        public = tmp_engine.list_resources("org-test", is_public=True)
        assert len(public) == 1

    def test_list_resources_filter_by_account(self, tmp_engine):
        tmp_engine.add_resource("org-test", {"account_id": "acc-1"})
        tmp_engine.add_resource("org-test", {"account_id": "acc-2"})
        acc1 = tmp_engine.list_resources("org-test", account_id="acc-1")
        assert len(acc1) == 1

    def test_list_resources_org_isolation(self, tmp_engine, alt_engine, sample_resource):
        tmp_engine.add_resource("org-test", sample_resource)
        assert alt_engine.list_resources("org-other") == []


# ---------------------------------------------------------------------------
# Benchmark Tests
# ---------------------------------------------------------------------------

class TestAddBenchmarkResult:
    def test_add_benchmark_returns_record(self, tmp_engine, sample_benchmark):
        rec = tmp_engine.add_benchmark_result("org-test", sample_benchmark)
        assert rec["id"]
        assert rec["benchmark"] == "cis_aws_v1.5"
        assert rec["pass_count"] == 87
        assert rec["fail_count"] == 13
        assert rec["score"] == 87.0

    def test_add_benchmark_auto_score(self, tmp_engine):
        rec = tmp_engine.add_benchmark_result("org-test", {
            "account_id": "acc-1",
            "benchmark": "pci_dss",
            "pass_count": 80,
            "fail_count": 20,
        })
        assert rec["score"] == 80.0

    def test_add_benchmark_invalid_benchmark_raises(self, tmp_engine):
        with pytest.raises(ValueError, match="benchmark"):
            tmp_engine.add_benchmark_result("org-test", {
                "account_id": "acc-1",
                "benchmark": "unknown_bench",
            })

    def test_add_benchmark_missing_account_raises(self, tmp_engine):
        with pytest.raises(ValueError, match="account_id"):
            tmp_engine.add_benchmark_result("org-test", {"benchmark": "cis_aws_v1.5"})


class TestListBenchmarks:
    def test_list_benchmarks_empty(self, tmp_engine):
        assert tmp_engine.list_benchmarks("org-test") == []

    def test_list_benchmarks_returns_created(self, tmp_engine, sample_benchmark):
        tmp_engine.add_benchmark_result("org-test", sample_benchmark)
        results = tmp_engine.list_benchmarks("org-test")
        assert len(results) == 1

    def test_list_benchmarks_filter_by_account(self, tmp_engine):
        tmp_engine.add_benchmark_result("org-test", {"account_id": "acc-1", "benchmark": "cis_aws_v1.5"})
        tmp_engine.add_benchmark_result("org-test", {"account_id": "acc-2", "benchmark": "pci_dss"})
        acc1 = tmp_engine.list_benchmarks("org-test", account_id="acc-1")
        assert len(acc1) == 1

    def test_list_benchmarks_org_isolation(self, tmp_engine, alt_engine, sample_benchmark):
        tmp_engine.add_benchmark_result("org-test", sample_benchmark)
        assert alt_engine.list_benchmarks("org-other") == []


# ---------------------------------------------------------------------------
# Stats Tests
# ---------------------------------------------------------------------------

class TestGetCloudStats:
    def test_stats_empty_org(self, tmp_engine):
        stats = tmp_engine.get_cloud_stats("org-test")
        assert stats["total_accounts"] == 0
        assert stats["total_findings"] == 0
        assert stats["benchmark_pass_rate"] == 0.0

    def test_stats_reflect_data(self, tmp_engine, sample_account, sample_finding, sample_benchmark):
        tmp_engine.add_account("org-test", sample_account)
        tmp_engine.add_finding("org-test", sample_finding)
        tmp_engine.add_benchmark_result("org-test", sample_benchmark)

        stats = tmp_engine.get_cloud_stats("org-test")
        assert stats["total_accounts"] == 1
        assert stats["by_provider"]["aws"] == 1
        assert stats["total_findings"] == 1
        assert stats["by_severity"].get("critical", 0) == 1
        assert stats["by_category"].get("network", 0) == 1
        assert stats["benchmark_pass_rate"] == 87.0
        assert stats["avg_risk_score"] == 42.5

    def test_stats_critical_resources(self, tmp_engine):
        tmp_engine.add_resource("org-test", {"account_id": "acc-1", "is_public": True})
        tmp_engine.add_resource("org-test", {"account_id": "acc-1", "is_public": False})
        stats = tmp_engine.get_cloud_stats("org-test")
        assert stats["critical_resources"] == 1

    def test_stats_org_isolation(self, tmp_engine, alt_engine, sample_account):
        tmp_engine.add_account("org-test", sample_account)
        stats = alt_engine.get_cloud_stats("org-other")
        assert stats["total_accounts"] == 0
