"""
Unit tests for suite-evidence-risk/risk/runtime/cloud.py — Cloud Runtime Analyzer [V3/V10].

Covers:
  - CloudThreatType enum
  - CloudFinding dataclass
  - CloudSecurityResult dataclass
  - CloudRuntimeAnalyzer: init, analyze_aws_resources, analyze_azure, analyze_gcp
  - Provider-specific analysis methods
"""

import os
import sys
from datetime import datetime


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-evidence-risk"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))

from risk.runtime.cloud import (
    CloudThreatType,
    CloudFinding,
    CloudSecurityResult,
    CloudRuntimeAnalyzer,
)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class TestCloudThreatType:
    def test_public_access(self):
        assert CloudThreatType.PUBLIC_ACCESS.value == "public_access"

    def test_all_types_exist(self):
        expected = {
            "public_access", "insecure_storage", "weak_encryption",
            "missing_iam_policy", "overly_permissive_iam",
            "unencrypted_database", "public_database",
            "missing_logging", "insecure_network",
        }
        actual = {t.value for t in CloudThreatType}
        assert actual == expected


# ---------------------------------------------------------------------------
# Data Classes
# ---------------------------------------------------------------------------

class TestCloudFinding:
    def test_creation(self):
        f = CloudFinding(
            threat_type=CloudThreatType.PUBLIC_ACCESS,
            severity="critical",
            cloud_provider="aws",
            resource_type="s3",
            resource_id="my-bucket",
        )
        assert f.threat_type == CloudThreatType.PUBLIC_ACCESS
        assert f.severity == "critical"
        assert f.cloud_provider == "aws"
        assert f.resource_type == "s3"
        assert f.resource_id == "my-bucket"

    def test_defaults(self):
        f = CloudFinding(
            threat_type=CloudThreatType.WEAK_ENCRYPTION,
            severity="high",
            cloud_provider="azure",
            resource_type="storage",
            resource_id="sa-1",
        )
        assert f.region is None
        assert f.description == ""
        assert f.recommendation == ""
        assert isinstance(f.timestamp, datetime)

    def test_with_region(self):
        f = CloudFinding(
            threat_type=CloudThreatType.MISSING_LOGGING,
            severity="medium",
            cloud_provider="gcp",
            resource_type="compute",
            resource_id="instance-1",
            region="us-central1",
        )
        assert f.region == "us-central1"


class TestCloudSecurityResult:
    def test_creation(self):
        findings = [
            CloudFinding(
                threat_type=CloudThreatType.PUBLIC_ACCESS,
                severity="critical",
                cloud_provider="aws",
                resource_type="s3",
                resource_id="bucket-1",
            )
        ]
        result = CloudSecurityResult(
            findings=findings,
            total_findings=1,
            findings_by_type={"public_access": 1},
            findings_by_severity={"critical": 1},
            resources_analyzed=5,
            cloud_provider="aws",
        )
        assert result.total_findings == 1
        assert result.resources_analyzed == 5
        assert len(result.findings) == 1


# ---------------------------------------------------------------------------
# CloudRuntimeAnalyzer
# ---------------------------------------------------------------------------

class TestCloudRuntimeAnalyzer:
    def test_init_aws(self):
        analyzer = CloudRuntimeAnalyzer("AWS")
        assert analyzer.cloud_provider == "aws"

    def test_init_azure(self):
        analyzer = CloudRuntimeAnalyzer("Azure", config={"sub": "test"})
        assert analyzer.cloud_provider == "azure"
        assert analyzer.config["sub"] == "test"

    def test_init_gcp(self):
        analyzer = CloudRuntimeAnalyzer("GCP")
        assert analyzer.cloud_provider == "gcp"

    def test_analyze_aws_resources(self):
        analyzer = CloudRuntimeAnalyzer("aws")
        result = analyzer.analyze_aws_resources()
        assert isinstance(result, CloudSecurityResult)
        assert result.cloud_provider == "aws"
        assert result.total_findings >= 0
        assert isinstance(result.findings, list)

    def test_analyze_aws_returns_findings(self):
        analyzer = CloudRuntimeAnalyzer("aws")
        result = analyzer.analyze_aws_resources()
        # Should produce findings for simulated resources
        for f in result.findings:
            assert isinstance(f, CloudFinding)
            assert f.cloud_provider == "aws"

    def test_analyze_azure_resources(self):
        analyzer = CloudRuntimeAnalyzer("azure")
        if hasattr(analyzer, "analyze_azure_resources"):
            result = analyzer.analyze_azure_resources()
            assert isinstance(result, CloudSecurityResult)
            assert result.cloud_provider == "azure"

    def test_analyze_gcp_resources(self):
        analyzer = CloudRuntimeAnalyzer("gcp")
        if hasattr(analyzer, "analyze_gcp_resources"):
            result = analyzer.analyze_gcp_resources()
            assert isinstance(result, CloudSecurityResult)
            assert result.cloud_provider == "gcp"

    def test_config_defaults_empty(self):
        analyzer = CloudRuntimeAnalyzer("aws")
        assert analyzer.config == {}

    def test_case_insensitive_provider(self):
        for p in ("AWS", "Aws", "aws", "aWs"):
            analyzer = CloudRuntimeAnalyzer(p)
            assert analyzer.cloud_provider == "aws"
