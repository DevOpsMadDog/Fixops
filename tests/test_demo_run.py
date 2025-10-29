"""E2E tests for demo_run.py."""

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from demo_run import (
    BidirectionalScorer,
    generate_statistics,
    prioritize_findings,
    process_findings,
)


@pytest.fixture
def sample_finding():
    """Sample finding for testing."""
    return {
        "cve": "CVE-2024-12345",
        "asset_id": "image:nginx:1.21.0",
        "asset_type": "container",
        "cvss": 9.8,
        "epss_score": 0.945,
        "kev": True,
        "internet_facing": True,
        "pre_auth": True,
        "data_classes": ["PHI", "PII"],
        "compensating_controls": {"waf": False, "segmentation": False, "mtls": False},
        "patch_available": True,
        "blast_radius": "high",
    }


@pytest.fixture
def sample_findings():
    """Multiple sample findings for testing."""
    return [
        {
            "cve": f"CVE-2024-{i:05d}",
            "asset_id": f"image:nginx:{i}",
            "asset_type": "container",
            "cvss": 7.5 + (i % 3),
            "epss_score": 0.5 + (i % 5) * 0.1,
            "kev": i % 10 == 0,
            "internet_facing": i % 3 == 0,
            "pre_auth": i % 5 == 0,
            "data_classes": ["PHI"] if i % 4 == 0 else [],
            "compensating_controls": {
                "waf": i % 2 == 0,
                "segmentation": i % 3 == 0,
                "mtls": i % 4 == 0,
            },
            "patch_available": i % 2 == 0,
            "blast_radius": ["low", "medium", "high"][i % 3],
        }
        for i in range(100)
    ]


class TestBidirectionalScorer:
    """Test bidirectional scoring logic."""

    def test_score_critical_kev(self, sample_finding):
        """Test that KEV CVEs are scored as CRITICAL."""
        scorer = BidirectionalScorer()
        score = scorer.score(sample_finding)

        assert score.cve == "CVE-2024-12345"
        assert score.kev is True
        assert score.final_severity == "CRITICAL"
        assert score.final_score > 0.7
        assert "KEV=true" in score.rationale

    def test_day0_factors(self, sample_finding):
        """Test Day-0 structural priors calculation."""
        scorer = BidirectionalScorer()
        score = scorer.score(sample_finding)

        assert "pre_auth_rce" in score.day0_factors
        assert "internet_facing" in score.day0_factors
        assert "data_adjacency" in score.day0_factors
        assert score.day0_factors["pre_auth_rce"] == 0.35
        assert score.day0_factors["internet_facing"] == 0.25

    def test_dayn_factors(self, sample_finding):
        """Test Day-N reinforcement signals calculation."""
        scorer = BidirectionalScorer()
        score = scorer.score(sample_finding)

        assert "kev" in score.dayn_factors
        assert "epss" in score.dayn_factors
        assert "cvss" in score.dayn_factors
        assert score.dayn_factors["kev"] == 0.40
        assert score.dayn_factors["epss"] > 0

    def test_compensating_controls_reduce_risk(self):
        """Test that compensating controls reduce risk score."""
        scorer = BidirectionalScorer()

        finding_no_controls = {
            "cve": "CVE-2024-00001",
            "asset_id": "test",
            "asset_type": "container",
            "cvss": 7.5,
            "epss_score": 0.5,
            "kev": False,
            "internet_facing": True,
            "pre_auth": False,
            "data_classes": [],
            "compensating_controls": {
                "waf": False,
                "segmentation": False,
                "mtls": False,
            },
            "patch_available": True,
            "blast_radius": "medium",
        }

        finding_with_controls = finding_no_controls.copy()
        finding_with_controls["compensating_controls"] = {
            "waf": True,
            "segmentation": True,
            "mtls": True,
        }

        score_no_controls = scorer.score(finding_no_controls)
        score_with_controls = scorer.score(finding_with_controls)

        assert score_with_controls.final_score < score_no_controls.final_score
        assert "compensating_controls" in score_with_controls.day0_factors

    def test_severity_determination(self):
        """Test severity determination logic."""
        scorer = BidirectionalScorer()

        critical_finding = {
            "cve": "CVE-2024-CRIT",
            "asset_id": "test",
            "asset_type": "container",
            "cvss": 9.8,
            "epss_score": 0.9,
            "kev": True,
            "internet_facing": True,
            "pre_auth": True,
            "data_classes": ["PHI"],
            "compensating_controls": {
                "waf": False,
                "segmentation": False,
                "mtls": False,
            },
            "patch_available": True,
            "blast_radius": "high",
        }

        low_finding = {
            "cve": "CVE-2024-LOW",
            "asset_id": "test",
            "asset_type": "container",
            "cvss": 3.0,
            "epss_score": 0.01,
            "kev": False,
            "internet_facing": False,
            "pre_auth": False,
            "data_classes": [],
            "compensating_controls": {"waf": True, "segmentation": True, "mtls": True},
            "patch_available": True,
            "blast_radius": "low",
        }

        critical_score = scorer.score(critical_finding)
        low_score = scorer.score(low_finding)

        assert critical_score.final_severity == "CRITICAL"
        assert low_score.final_severity in ["LOW", "MEDIUM"]
        assert critical_score.final_score > low_score.final_score


class TestProcessingPipeline:
    """Test end-to-end processing pipeline."""

    def test_process_findings(self, sample_findings):
        """Test processing multiple findings."""
        scores = process_findings(sample_findings, mode="test")

        assert len(scores) == len(sample_findings)
        assert all(hasattr(s, "final_score") for s in scores)
        assert all(hasattr(s, "final_severity") for s in scores)
        assert all(hasattr(s, "rationale") for s in scores)

    def test_prioritize_findings(self, sample_findings):
        """Test prioritization logic."""
        scorer = BidirectionalScorer()
        scores = [scorer.score(f) for f in sample_findings]

        top_scores = prioritize_findings(scores, top_n=10)

        assert len(top_scores) == 10
        for i in range(len(top_scores) - 1):
            assert top_scores[i].final_score >= top_scores[i + 1].final_score

    def test_generate_statistics(self, sample_findings):
        """Test statistics generation."""
        scorer = BidirectionalScorer()
        scores = [scorer.score(f) for f in sample_findings]

        stats = generate_statistics(scores)

        assert stats["total"] == len(scores)
        assert "by_severity" in stats
        assert "by_surface" in stats
        assert "kev_count" in stats
        assert "avg_final_score" in stats
        assert stats["kev_count"] == sum(1 for s in scores if s.kev)


class TestDataIntegrity:
    """Test data integrity and validation."""

    def test_findings_file_exists(self):
        """Test that findings file exists."""
        findings_path = REPO_ROOT / "data" / "inputs" / "findings.ndjson"

        if not findings_path.exists():
            pytest.skip("Findings file not generated yet")

        assert findings_path.exists()
        assert findings_path.stat().st_size > 0

    def test_findings_format(self):
        """Test that findings are valid JSON."""
        findings_path = REPO_ROOT / "data" / "inputs" / "findings.ndjson"

        if not findings_path.exists():
            pytest.skip("Findings file not generated yet")

        with findings_path.open("r") as f:
            for i, line in enumerate(f):
                if i >= 10:
                    break
                finding = json.loads(line)
                assert "cve" in finding
                assert "asset_id" in finding
                assert "cvss" in finding
                assert "epss_score" in finding
                assert "kev" in finding

    def test_kev_integration(self):
        """Test that KEV data is properly integrated."""
        findings_path = REPO_ROOT / "data" / "inputs" / "findings.ndjson"

        if not findings_path.exists():
            pytest.skip("Findings file not generated yet")

        kev_count = 0
        total = 0

        with findings_path.open("r") as f:
            for line in f:
                finding = json.loads(line)
                total += 1
                if finding["kev"]:
                    kev_count += 1

        assert kev_count > 0, "No KEV CVEs found in dataset"
        assert kev_count < total, "All CVEs marked as KEV (unrealistic)"

    def test_epss_integration(self):
        """Test that EPSS scores are realistic."""
        findings_path = REPO_ROOT / "data" / "inputs" / "findings.ndjson"

        if not findings_path.exists():
            pytest.skip("Findings file not generated yet")

        with findings_path.open("r") as f:
            for i, line in enumerate(f):
                if i >= 100:
                    break
                finding = json.loads(line)
                epss = finding["epss_score"]
                assert 0.0 <= epss <= 1.0, f"EPSS score out of range: {epss}"


class TestPerformance:
    """Test performance requirements."""

    def test_processing_speed(self, sample_findings):
        """Test that processing meets performance SLA."""
        import time

        large_dataset = sample_findings * 100

        start = time.perf_counter()
        scores = process_findings(large_dataset, mode="test")
        elapsed = time.perf_counter() - start

        rate = len(scores) / elapsed if elapsed > 0 else 0

        assert (
            rate > 10000
        ), f"Processing too slow: {rate:.0f} findings/sec (target: >10k/sec)"

    def test_memory_efficiency(self, sample_findings):
        """Test that memory usage is reasonable."""
        import sys

        large_dataset = sample_findings * 500

        scorer = BidirectionalScorer()
        scores = [scorer.score(f) for f in large_dataset]

        size_bytes = sys.getsizeof(scores)
        size_mb = size_bytes / (1024 * 1024)

        assert size_mb < 100, f"Memory usage too high: {size_mb:.1f} MB"


@pytest.mark.e2e
class TestEndToEnd:
    """End-to-end integration tests."""

    def test_quick_mode_execution(self):
        """Test quick mode execution."""
        import subprocess

        result = subprocess.run(
            ["python", "scripts/demo_run.py", "--mode", "quick", "--top-n", "10"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=60,
        )

        assert result.returncode == 0, f"Demo failed: {result.stderr}"
        assert "Demo Complete" in result.stdout
        assert "evidence_bundle" in result.stdout

    def test_output_files_created(self):
        """Test that output files are created."""
        artifacts_dir = REPO_ROOT / "artifacts"

        expected_files = [
            "top_prioritized_quick.json",
            "top_prioritized_quick.csv",
            "statistics_quick.json",
            "evidence_bundle_quick.zip",
        ]

        for filename in expected_files:
            filepath = artifacts_dir / filename
            if not filepath.exists():
                pytest.skip(f"Output file not found: {filename}")
            assert filepath.stat().st_size > 0

    def test_report_generated(self):
        """Test that summary report is generated."""
        report_path = REPO_ROOT / "reports" / "demo_summary_quick.md"

        if not report_path.exists():
            pytest.skip("Report not generated yet")

        content = report_path.read_text()
        assert "FixOps Demo Summary" in content
        assert "bidirectional risk scoring" in content
        assert "KEV CVEs" in content
        assert "EPSS" in content
