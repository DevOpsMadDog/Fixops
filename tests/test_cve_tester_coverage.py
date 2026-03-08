"""Coverage tests for core.cve_tester — CVETestResult and CVETester."""
import os
import sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

from core.cve_tester import CVETestResult


class TestCVETestResult:
    def test_creation(self):
        result = CVETestResult(
            cve_id="CVE-2024-001",
            vulnerable=True,
            confidence=0.95,
            evidence={"exploit": "SQL injection confirmed"},
            test_method="active_scan",
            target_url="http://localhost:8080/login",
            severity="critical",
            cvss_score=9.8,
            description="SQL injection in login endpoint",
            remediation="Use parameterized queries",
        )
        assert result.cve_id == "CVE-2024-001"
        assert result.vulnerable is True
        assert result.confidence == 0.95

    def test_not_vulnerable(self):
        result = CVETestResult(
            cve_id="CVE-2024-002",
            vulnerable=False,
            confidence=0.8,
            evidence={},
            test_method="passive_scan",
            target_url="http://localhost:8080",
            severity="low",
            cvss_score=2.1,
            description="Test CVE",
            remediation="No action needed",
        )
        assert result.vulnerable is False
        assert result.verdict == "UNVERIFIED"

    def test_defaults(self):
        result = CVETestResult(
            cve_id="CVE-2024-003",
            vulnerable=True,
            confidence=0.7,
            evidence={"test": True},
            test_method="scan",
            target_url="http://test",
            severity="medium",
            cvss_score=5.5,
            description="Test",
            remediation="Fix it",
        )
        assert result.verification_chain == ""
        assert result.verdict == "UNVERIFIED"
        assert result.applicability_score == 0
        assert result.test_coverage_score == 0
        assert result.confidence_score == 0

    def test_with_all_fields(self):
        result = CVETestResult(
            cve_id="CVE-2024-004",
            vulnerable=True,
            confidence=0.99,
            evidence={"payload": "'; DROP TABLE--"},
            test_method="exploit",
            target_url="http://target:8080",
            severity="critical",
            cvss_score=10.0,
            description="Full RCE",
            remediation="Patch immediately",
            verification_chain="hash-chain-abc",
            verdict="CONFIRMED",
            applicability_score=95,
            test_coverage_score=90,
            confidence_score=99,
            how_to_verify="Run exploit.py against target",
        )
        assert result.verdict == "CONFIRMED"
        assert result.applicability_score == 95
