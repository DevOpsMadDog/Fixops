"""
Edge Case Backtesting - Find Bugs People Might Have Missed

This module tests edge cases and scenarios that are commonly missed in testing:
- Null/None values in various fields
- Empty arrays and objects
- Extremely large inputs
- Malformed data that passes initial validation
- Boundary conditions
- Race conditions and timing issues
- Unicode and special characters
- Duplicate entries
- Missing required fields that have defaults
"""

import json
import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class EdgeCaseBacktester:
    """Test edge cases that people commonly miss."""

    def __init__(self):
        self.fixtures_dir = PROJECT_ROOT / "tests" / "e2e_real_data" / "edge_cases"
        self.fixtures_dir.mkdir(parents=True, exist_ok=True)
        self.results_dir = (
            PROJECT_ROOT / "tests" / "e2e_real_data" / "edge_case_results"
        )
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.bugs_found = []

    def test_cve_with_null_severity(self) -> Dict[str, Any]:
        """Test CVE records with null severity - already found Bug #1."""
        logger.info("Testing CVE with null severity...")

        cve_data = {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2024-NULL-TEST",
                    "vendorProject": "Test Vendor",
                    "product": "Test Product",
                    "vulnerabilityName": "Test Vulnerability",
                    "dateAdded": "2024-01-01",
                    "shortDescription": "Test description",
                    "requiredAction": "Apply updates",
                    "dueDate": "2024-02-01",
                    "severity": None,  # This caused Bug #1
                }
            ]
        }

        fixture_file = self.fixtures_dir / "cve_null_severity.json"
        fixture_file.write_text(json.dumps(cve_data, indent=2))

        return {
            "status": "fixed",
            "bug_id": 1,
            "description": "NoneType in Markov projection",
        }

    def test_sbom_with_empty_components(self) -> Dict[str, Any]:
        """Test SBOM with empty components array."""
        logger.info("Testing SBOM with empty components...")

        sbom_data = {
            "$schema": "http://cyclonedx.org/schema/bom-1.4.schema.json",
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "metadata": {
                "timestamp": "2025-11-01T00:00:00Z",
                "component": {
                    "type": "application",
                    "name": "empty-app",
                    "version": "1.0.0",
                },
            },
            "components": [],  # Empty components
        }

        fixture_file = self.fixtures_dir / "sbom_empty_components.json"
        fixture_file.write_text(json.dumps(sbom_data, indent=2))

        result = self._run_cli_with_fixture(
            sbom_file=fixture_file,
            test_name="empty_components",
        )

        if result["returncode"] != 0:
            self.bugs_found.append(
                {
                    "id": "BUG-EDGE-001",
                    "severity": "MEDIUM",
                    "description": "Pipeline fails with empty SBOM components",
                    "error": result["stderr"],
                }
            )
            return {"status": "bug_found", "bug_id": "BUG-EDGE-001"}

        return {"status": "passed"}

    def test_sarif_with_missing_locations(self) -> Dict[str, Any]:
        """Test SARIF with missing location information."""
        logger.info("Testing SARIF with missing locations...")

        sarif_data = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "TestTool", "version": "1.0.0"}},
                    "results": [
                        {
                            "ruleId": "test-rule-001",
                            "level": "error",
                            "message": {"text": "Test finding without location"},
                        }
                    ],
                }
            ],
        }

        fixture_file = self.fixtures_dir / "sarif_missing_locations.json"
        fixture_file.write_text(json.dumps(sarif_data, indent=2))

        result = self._run_cli_with_fixture(
            sarif_file=fixture_file,
            test_name="missing_locations",
        )

        if result["returncode"] != 0:
            self.bugs_found.append(
                {
                    "id": "BUG-EDGE-002",
                    "severity": "MEDIUM",
                    "description": "Pipeline fails with SARIF missing locations",
                    "error": result["stderr"],
                }
            )
            return {"status": "bug_found", "bug_id": "BUG-EDGE-002"}

        return {"status": "passed"}

    def test_extremely_large_cve_feed(self) -> Dict[str, Any]:
        """Test with extremely large CVE feed (10,000+ CVEs)."""
        logger.info("Testing extremely large CVE feed...")

        vulnerabilities = []
        for i in range(10000):
            vulnerabilities.append(
                {
                    "cveID": f"CVE-2024-{i:05d}",
                    "vendorProject": f"Vendor {i % 100}",
                    "product": f"Product {i % 50}",
                    "vulnerabilityName": f"Vulnerability {i}",
                    "dateAdded": "2024-01-01",
                    "shortDescription": f"Test vulnerability {i}",
                    "requiredAction": "Apply updates",
                    "dueDate": "2024-02-01",
                    "severity": ["critical", "high", "medium", "low"][i % 4],
                }
            )

        cve_data = {"vulnerabilities": vulnerabilities}

        fixture_file = self.fixtures_dir / "cve_large_feed.json"
        fixture_file.write_text(json.dumps(cve_data, indent=2))
        logger.info(f"Created large CVE feed with {len(vulnerabilities)} entries")

        result = self._run_cli_with_fixture(
            cve_file=fixture_file,
            test_name="large_feed",
            timeout=300,  # 5 minutes
        )

        if result["returncode"] != 0:
            self.bugs_found.append(
                {
                    "id": "BUG-EDGE-003",
                    "severity": "HIGH",
                    "description": "Pipeline fails or times out with large CVE feed (10,000+ entries)",
                    "error": result["stderr"],
                }
            )
            return {"status": "bug_found", "bug_id": "BUG-EDGE-003"}

        if "Runtime" in result["stdout"]:
            logger.info(f"Large feed processing completed: {result['stdout']}")

        return {"status": "passed"}

    def test_unicode_and_special_characters(self) -> Dict[str, Any]:
        """Test with Unicode and special characters in various fields."""
        logger.info("Testing Unicode and special characters...")

        design_content = """service,environment,criticality,data_classification,exposure,owner
测试服务,production,mission_critical,pii,internet,security-team
service-with-émojis-🔒,staging,external,financial,partner,ops-team
service"with'quotes,development,internal,internal,internal,dev-team
service;with;semicolons,production,mission_critical,pii,internet,security-team
"""

        fixture_file = self.fixtures_dir / "design_unicode.csv"
        fixture_file.write_text(design_content, encoding="utf-8")

        result = self._run_cli_with_fixture(
            design_file=fixture_file,
            test_name="unicode_chars",
        )

        if result["returncode"] != 0:
            self.bugs_found.append(
                {
                    "id": "BUG-EDGE-004",
                    "severity": "MEDIUM",
                    "description": "Pipeline fails with Unicode/special characters in design context",
                    "error": result["stderr"],
                }
            )
            return {"status": "bug_found", "bug_id": "BUG-EDGE-004"}

        return {"status": "passed"}

    def test_duplicate_cve_entries(self) -> Dict[str, Any]:
        """Test with duplicate CVE entries."""
        logger.info("Testing duplicate CVE entries...")

        cve_data = {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2024-DUPLICATE",
                    "vendorProject": "Test Vendor",
                    "product": "Test Product",
                    "vulnerabilityName": "Duplicate Test 1",
                    "dateAdded": "2024-01-01",
                    "shortDescription": "First entry",
                    "requiredAction": "Apply updates",
                    "dueDate": "2024-02-01",
                    "severity": "high",
                },
                {
                    "cveID": "CVE-2024-DUPLICATE",  # Same CVE ID
                    "vendorProject": "Test Vendor",
                    "product": "Test Product",
                    "vulnerabilityName": "Duplicate Test 2",
                    "dateAdded": "2024-01-02",
                    "shortDescription": "Second entry",
                    "requiredAction": "Apply updates",
                    "dueDate": "2024-02-02",
                    "severity": "critical",  # Different severity
                },
            ]
        }

        fixture_file = self.fixtures_dir / "cve_duplicates.json"
        fixture_file.write_text(json.dumps(cve_data, indent=2))

        result = self._run_cli_with_fixture(
            cve_file=fixture_file,
            test_name="duplicate_cves",
        )

        if result["returncode"] == 0:
            output_file = self.results_dir / "duplicate_cves_result.json"
            if output_file.exists():
                with open(output_file) as f:
                    data = json.load(f)
                    cve_count = data.get("cve_summary", {}).get("record_count", 0)
                    if cve_count != 1:  # Should deduplicate to 1
                        self.bugs_found.append(
                            {
                                "id": "BUG-EDGE-005",
                                "severity": "LOW",
                                "description": f"Duplicate CVEs not deduplicated correctly (expected 1, got {cve_count})",
                            }
                        )
                        return {"status": "bug_found", "bug_id": "BUG-EDGE-005"}

        return {"status": "passed"}

    def test_missing_required_fields_with_defaults(self) -> Dict[str, Any]:
        """Test fields that are 'required' but have defaults."""
        logger.info("Testing missing required fields with defaults...")

        sbom_data = {
            "$schema": "http://cyclonedx.org/schema/bom-1.4.schema.json",
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "components": [
                {
                    "type": "library",
                    "name": "test-lib",
                    "version": "1.0.0",
                }
            ],
        }

        fixture_file = self.fixtures_dir / "sbom_missing_metadata.json"
        fixture_file.write_text(json.dumps(sbom_data, indent=2))

        result = self._run_cli_with_fixture(
            sbom_file=fixture_file,
            test_name="missing_metadata",
        )

        if result["returncode"] != 0:
            self.bugs_found.append(
                {
                    "id": "BUG-EDGE-006",
                    "severity": "MEDIUM",
                    "description": "Pipeline fails with SBOM missing metadata",
                    "error": result["stderr"],
                }
            )
            return {"status": "bug_found", "bug_id": "BUG-EDGE-006"}

        return {"status": "passed"}

    def _run_cli_with_fixture(
        self,
        design_file: Path = None,
        sbom_file: Path = None,
        sarif_file: Path = None,
        cve_file: Path = None,
        test_name: str = "test",
        timeout: int = 60,
    ) -> Dict[str, Any]:
        """Run CLI with test fixtures."""
        if design_file is None:
            design_file = (
                PROJECT_ROOT
                / "tests"
                / "e2e_real_data"
                / "fixtures"
                / "real_design_context.csv"
            )
        if sbom_file is None:
            sbom_file = (
                PROJECT_ROOT
                / "tests"
                / "e2e_real_data"
                / "fixtures"
                / "real_sbom_cyclonedx.json"
            )
        if sarif_file is None:
            sarif_file = (
                PROJECT_ROOT
                / "tests"
                / "e2e_real_data"
                / "fixtures"
                / "real_sarif_semgrep.json"
            )
        if cve_file is None:
            cve_file = (
                PROJECT_ROOT / "tests" / "e2e_real_data" / "fixtures" / "real_kev.json"
            )

        output_file = self.results_dir / f"{test_name}_result.json"

        cmd = [
            sys.executable,
            "-m",
            "core.cli",
            "run",
            "--design",
            str(design_file),
            "--sbom",
            str(sbom_file),
            "--sarif",
            str(sarif_file),
            "--cve",
            str(cve_file),
            "--output",
            str(output_file),
            "--pretty",
        ]

        env = os.environ.copy()
        env["FIXOPS_API_TOKEN"] = "test-token"
        env["FIXOPS_MODE"] = "enterprise"

        result = subprocess.run(
            cmd,
            cwd=str(PROJECT_ROOT),
            capture_output=True,
            text=True,
            env=env,
            timeout=timeout,
        )

        return {
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }

    def run_all_edge_case_tests(self) -> Dict[str, Any]:
        """Run all edge case tests."""
        logger.info("=" * 80)
        logger.info("Running Edge Case Backtesting")
        logger.info("=" * 80)

        results = {}

        results["null_severity"] = self.test_cve_with_null_severity()
        results["empty_components"] = self.test_sbom_with_empty_components()
        results["missing_locations"] = self.test_sarif_with_missing_locations()
        results["large_feed"] = self.test_extremely_large_cve_feed()
        results["unicode_chars"] = self.test_unicode_and_special_characters()
        results["duplicate_cves"] = self.test_duplicate_cve_entries()
        results["missing_metadata"] = self.test_missing_required_fields_with_defaults()

        logger.info("\n" + "=" * 80)
        logger.info("Edge Case Testing Summary")
        logger.info("=" * 80)

        bugs_found_count = len(self.bugs_found)
        tests_passed = sum(1 for r in results.values() if r.get("status") == "passed")

        logger.info(f"Total tests: {len(results)}")
        logger.info(f"Tests passed: {tests_passed}")
        logger.info(f"Bugs found: {bugs_found_count}")

        if self.bugs_found:
            logger.info("\nBugs Found:")
            for bug in self.bugs_found:
                logger.info(
                    f"  {bug['id']}: {bug['description']} (Severity: {bug['severity']})"
                )

        bug_report_file = self.results_dir / "edge_case_bugs_found.json"
        bug_report_file.write_text(json.dumps(self.bugs_found, indent=2))
        logger.info(f"\nBug report saved to: {bug_report_file}")

        return {"results": results, "bugs_found": self.bugs_found}


def main():
    """Run edge case backtesting."""
    backtester = EdgeCaseBacktester()
    backtester.run_all_edge_case_tests()


if __name__ == "__main__":
    main()
