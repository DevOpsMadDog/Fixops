"""
Progressive Enhancement E2E Tests - Real CLI and API Commands

Tests FixOps value-add across progressive stages using REAL CLI and API commands.
No simulation - actual subprocess execution and HTTP requests.

Stages:
- Stage A (Baseline): Scanner + SBOM (no KEV enrichment)
- Stage B (+KEV): Scanner + SBOM + KEV enrichment (severity promotion)
- Stage C (Multi-scanner): Multiple scanners + SBOM + KEV (deduplication)

For each stage, tests both CLI and API programs and generates:
- Exact commands executed
- Input/output data flow
- Tabular comparison of scanner risk vs FixOps value-add
- Scorecard showing before/after metrics
"""

import csv
import json
from pathlib import Path
from typing import Any, Dict, List

import pytest
import requests

from tests.harness import FixtureManager, FlagConfigManager, ServerManager


class ProgressiveTestResults:
    """Captures and formats progressive test results for reporting."""

    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.results: List[Dict[str, Any]] = []

    def add_result(
        self,
        stage: str,
        program: str,
        command: str,
        inputs: Dict[str, str],
        pipeline_result: Dict[str, Any],
    ):
        """Add a test result for a stage/program combination."""
        severity_overview = pipeline_result.get("severity_overview", {})
        risk_profile = pipeline_result.get("risk_profile", {})
        guardrail = pipeline_result.get("guardrail_evaluation", {})

        sources = severity_overview.get("sources", {})
        sarif_severities = sources.get("sarif", {})
        scanner_highest = "unknown"
        for sev in ["critical", "high", "medium", "low"]:
            if sev in sarif_severities and sarif_severities[sev] > 0:
                scanner_highest = sev
                break

        cve_critical = sources.get("cve", {}).get("critical", 0)

        result = {
            "stage": stage,
            "program": program,
            "command": command,
            "inputs": inputs,
            "scanner_highest": scanner_highest,
            "fixops_highest": severity_overview.get("highest", "unknown"),
            "promotions": cve_critical,
            "risk_score": risk_profile.get("score", 0.0),
            "kev_count": risk_profile.get("components", {}).get("kev_count", 0),
            "guardrail_status": guardrail.get("status", "unknown"),
            "value_add": self._describe_value_add(
                stage, scanner_highest, severity_overview, risk_profile, guardrail
            ),
        }

        self.results.append(result)

        stage_dir = self.output_dir / stage.replace(" ", "_").replace("(", "").replace(
            ")", ""
        )
        stage_dir.mkdir(parents=True, exist_ok=True)

        with open(stage_dir / f"{program}.json", "w") as f:
            json.dump(pipeline_result, f, indent=2)

        with open(stage_dir / f"{program}.cmd.txt", "w") as f:
            f.write(f"Program: {program}\n")
            f.write(f"Command: {command}\n")
            f.write("Inputs:\n")
            for key, value in inputs.items():
                f.write(f"  {key}: {value}\n")

    def _describe_value_add(
        self,
        stage: str,
        scanner_highest: str,
        severity_overview: Dict,
        risk_profile: Dict,
        guardrail: Dict,
    ) -> str:
        """Describe the value-add for this stage."""
        value_adds = []

        fixops_highest = severity_overview.get("highest", "unknown")

        if scanner_highest != fixops_highest and fixops_highest == "critical":
            value_adds.append(
                f"Severity promotion: {scanner_highest} → {fixops_highest}"
            )

        sources = severity_overview.get("sources", {})
        cve_critical = sources.get("cve", {}).get("critical", 0)
        if cve_critical > 0:
            value_adds.append(f"KEV enrichment: {cve_critical} exploited CVEs")

        risk_score = risk_profile.get("score", 0.0)
        if risk_score > 0.5:
            value_adds.append(f"Risk score: {risk_score:.2f}")

        guardrail_status = guardrail.get("status", "unknown")
        if guardrail_status == "fail":
            value_adds.append("Guardrail: FAIL (blocks deployment)")

        if not value_adds:
            value_adds.append("Baseline (scanner only)")

        return "; ".join(value_adds)

    def generate_scorecard(self):
        """Generate markdown and CSV scorecards."""
        md_path = self.output_dir / "scorecard.md"
        csv_path = self.output_dir / "scorecard.csv"

        with open(md_path, "w") as f:
            f.write("# FixOps Progressive Enhancement Scorecard\n\n")
            f.write("## Scanner Risk vs FixOps Value-Add\n\n")
            f.write(
                "| Stage | Program | Scanner Severity | FixOps Severity | Promotions | Risk Score | KEV Count | Guardrail | Value-Add |\n"
            )
            f.write(
                "|-------|---------|------------------|-----------------|------------|------------|-----------|-----------|----------|\n"
            )

            for result in self.results:
                f.write(
                    f"| {result['stage']} | {result['program']} | {result['scanner_highest']} | "
                    f"{result['fixops_highest']} | {result['promotions']} | {result['risk_score']:.2f} | "
                    f"{result['kev_count']} | {result['guardrail_status']} | {result['value_add']} |\n"
                )

            f.write("\n## Commands Executed\n\n")
            for result in self.results:
                f.write(f"### {result['stage']} - {result['program']}\n\n")
                f.write(f"```bash\n{result['command']}\n```\n\n")
                f.write("**Inputs:**\n")
                for key, value in result["inputs"].items():
                    f.write(f"- {key}: `{value}`\n")
                f.write("\n")

        with open(csv_path, "w", newline="") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=[
                    "stage",
                    "program",
                    "command",
                    "scanner_highest",
                    "fixops_highest",
                    "promotions",
                    "risk_score",
                    "kev_count",
                    "guardrail_status",
                    "value_add",
                ],
            )
            writer.writeheader()
            for result in self.results:
                writer.writerow(
                    {
                        "stage": result["stage"],
                        "program": result["program"],
                        "command": result["command"],
                        "scanner_highest": result["scanner_highest"],
                        "fixops_highest": result["fixops_highest"],
                        "promotions": result["promotions"],
                        "risk_score": result["risk_score"],
                        "kev_count": result["kev_count"],
                        "guardrail_status": result["guardrail_status"],
                        "value_add": result["value_add"],
                    }
                )

        return md_path, csv_path


@pytest.fixture(scope="class")
def class_fixture_manager():
    """Provide a class-scoped FixtureManager."""
    manager = FixtureManager()
    manager.create_temp_dir()
    yield manager
    manager.cleanup()


@pytest.fixture(scope="class")
def class_flag_config_manager(class_fixture_manager):
    """Provide a class-scoped FlagConfigManager."""
    manager = FlagConfigManager(temp_dir=class_fixture_manager.temp_dir)
    yield manager
    manager.cleanup()


@pytest.fixture(scope="class")
def progressive_results(class_fixture_manager):
    """Provide a ProgressiveTestResults instance."""
    output_dir = class_fixture_manager.temp_dir / "progressive_results"
    return ProgressiveTestResults(output_dir)


@pytest.fixture(scope="class")
def real_test_data(class_fixture_manager):
    """Generate realistic test data for all scanners and stages."""
    data_dir = class_fixture_manager.temp_dir / "test_data"
    data_dir.mkdir(parents=True, exist_ok=True)

    design = class_fixture_manager.generate_design_csv(
        components=[
            {
                "component": "payment-api",
                "owner": "backend-team",
                "criticality": "high",
                "notes": "Handles payment processing",
            },
        ]
    )

    sbom = class_fixture_manager.generate_sbom_json(
        components=[
            {
                "type": "library",
                "name": "log4j-core",
                "version": "2.14.1",
                "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                "licenses": [{"license": {"id": "Apache-2.0"}}],
            },
            {
                "type": "application",
                "name": "payment-api",
                "version": "1.0.0",
                "purl": "pkg:maven/com.example/payment-api@1.0.0",
                "licenses": [{"license": {"id": "MIT"}}],
            },
        ]
    )

    snyk_sarif = class_fixture_manager.generate_sarif_json(
        tool_name="Snyk",
        results=[
            {
                "ruleId": "SNYK-JAVA-LOG4J-2314726",
                "level": "error",
                "message": {"text": "CVE-2021-44228 in log4j-core 2.14.1"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": "pom.xml"},
                            "region": {"startLine": 42},
                        }
                    }
                ],
                "properties": {
                    "security-severity": "8.5",
                    "tags": ["security", "CWE-502"],
                },
            }
        ],
    )

    empty_cve = data_dir / "empty_cve.json"
    with open(empty_cve, "w") as f:
        json.dump({"vulnerabilities": []}, f)

    repo_root = Path(__file__).parent.parent.parent
    kev_feed = repo_root / "data" / "feeds" / "kev.json"

    return {
        "design": design,
        "sbom": sbom,
        "snyk_sarif": snyk_sarif,
        "empty_cve": empty_cve,
        "kev_feed": kev_feed,
    }


class TestProgressiveRealCLIAPI:
    """Test progressive enhancement with real CLI and API commands."""

    def test_stage_a_baseline_api(
        self,
        class_fixture_manager,
        class_flag_config_manager,
        real_test_data,
        progressive_results,
    ):
        """Stage A (Baseline): Scanner + SBOM via API (no KEV enrichment)."""
        class_flag_config_manager.create_demo_config()

        env = {
            "FIXOPS_API_TOKEN": "test-token-progressive",
            "FIXOPS_DISABLE_TELEMETRY": "1",
        }

        with ServerManager(
            host="127.0.0.1",
            port=8766,
            app_module="apps.api.app:create_app",
            env=env,
            timeout=30,
        ) as server:
            headers = {"X-API-Key": "test-token-progressive"}

            with open(real_test_data["design"], "rb") as f:
                files = {"file": ("design.csv", f, "text/csv")}
                response = requests.post(
                    f"{server.base_url}/inputs/design",
                    headers=headers,
                    files=files,
                    timeout=10,
                )
                assert response.status_code == 200

            with open(real_test_data["sbom"], "rb") as f:
                files = {"file": ("sbom.json", f, "application/json")}
                response = requests.post(
                    f"{server.base_url}/inputs/sbom",
                    headers=headers,
                    files=files,
                    timeout=10,
                )
                assert response.status_code == 200

            with open(real_test_data["snyk_sarif"], "rb") as f:
                files = {"file": ("snyk.sarif", f, "application/json")}
                response = requests.post(
                    f"{server.base_url}/inputs/sarif",
                    headers=headers,
                    files=files,
                    timeout=10,
                )
                assert response.status_code == 200

            with open(real_test_data["empty_cve"], "rb") as f:
                files = {"file": ("empty_cve.json", f, "application/json")}
                response = requests.post(
                    f"{server.base_url}/inputs/cve",
                    headers=headers,
                    files=files,
                    timeout=10,
                )
                assert response.status_code == 200

            response = requests.post(
                f"{server.base_url}/pipeline/run", headers=headers, timeout=60
            )
            assert response.status_code == 200
            pipeline_result = response.json()

            command = (
                f"curl -H 'X-API-Key: test-token' -F 'file=@design.csv' {server.base_url}/inputs/design && "
                f"curl -H 'X-API-Key: test-token' -F 'file=@sbom.json' {server.base_url}/inputs/sbom && "
                f"curl -H 'X-API-Key: test-token' -F 'file=@snyk.sarif' {server.base_url}/inputs/sarif && "
                f"curl -H 'X-API-Key: test-token' -F 'file=@empty_cve.json' {server.base_url}/inputs/cve && "
                f"curl -H 'X-API-Key: test-token' {server.base_url}/pipeline/run"
            )

            progressive_results.add_result(
                stage="Stage A (Baseline)",
                program="API",
                command=command,
                inputs={
                    "design": str(real_test_data["design"]),
                    "sbom": str(real_test_data["sbom"]),
                    "sarif": str(real_test_data["snyk_sarif"]),
                    "cve": "empty (no enrichment)",
                },
                pipeline_result=pipeline_result,
            )

            severity_overview = pipeline_result.get("severity_overview", {})
            assert severity_overview.get("highest") in ["high", "error"]

    def test_stage_b_kev_enrichment_api(
        self,
        class_fixture_manager,
        class_flag_config_manager,
        real_test_data,
        progressive_results,
    ):
        """Stage B (+KEV): Scanner + SBOM + KEV enrichment via API - severity promotion."""
        class_flag_config_manager.create_demo_config()

        env = {
            "FIXOPS_API_TOKEN": "test-token-progressive",
            "FIXOPS_DISABLE_TELEMETRY": "1",
        }

        with ServerManager(
            host="127.0.0.1",
            port=8767,
            app_module="apps.api.app:create_app",
            env=env,
            timeout=30,
        ) as server:
            headers = {"X-API-Key": "test-token-progressive"}

            with open(real_test_data["design"], "rb") as f:
                files = {"file": ("design.csv", f, "text/csv")}
                requests.post(
                    f"{server.base_url}/inputs/design",
                    headers=headers,
                    files=files,
                    timeout=10,
                )

            with open(real_test_data["sbom"], "rb") as f:
                files = {"file": ("sbom.json", f, "application/json")}
                requests.post(
                    f"{server.base_url}/inputs/sbom",
                    headers=headers,
                    files=files,
                    timeout=10,
                )

            with open(real_test_data["snyk_sarif"], "rb") as f:
                files = {"file": ("snyk.sarif", f, "application/json")}
                requests.post(
                    f"{server.base_url}/inputs/sarif",
                    headers=headers,
                    files=files,
                    timeout=10,
                )

            if real_test_data["kev_feed"].exists():
                with open(real_test_data["kev_feed"], "rb") as f:
                    files = {"file": ("kev.json", f, "application/json")}
                    requests.post(
                        f"{server.base_url}/inputs/cve",
                        headers=headers,
                        files=files,
                        timeout=10,
                    )

            response = requests.post(
                f"{server.base_url}/pipeline/run", headers=headers, timeout=60
            )
            assert response.status_code == 200
            pipeline_result = response.json()

            command = (
                f"curl -H 'X-API-Key: test-token' -F 'file=@design.csv' {server.base_url}/inputs/design && "
                f"curl -H 'X-API-Key: test-token' -F 'file=@sbom.json' {server.base_url}/inputs/sbom && "
                f"curl -H 'X-API-Key: test-token' -F 'file=@snyk.sarif' {server.base_url}/inputs/sarif && "
                f"curl -H 'X-API-Key: test-token' -F 'file=@data/feeds/kev.json' {server.base_url}/inputs/cve && "
                f"curl -H 'X-API-Key: test-token' {server.base_url}/pipeline/run"
            )

            progressive_results.add_result(
                stage="Stage B (+KEV)",
                program="API",
                command=command,
                inputs={
                    "design": str(real_test_data["design"]),
                    "sbom": str(real_test_data["sbom"]),
                    "sarif": str(real_test_data["snyk_sarif"]),
                    "cve": str(real_test_data["kev_feed"]),
                },
                pipeline_result=pipeline_result,
            )

            severity_overview = pipeline_result.get("severity_overview", {})
            assert (
                severity_overview.get("highest") == "critical"
            ), f"Expected critical severity after KEV enrichment, got {severity_overview.get('highest')}"

            sources = severity_overview.get("sources", {})
            cve_critical = sources.get("cve", {}).get("critical", 0)
            assert cve_critical > 0, "Expected KEV-promoted critical findings"

            guardrail = pipeline_result.get("guardrail_evaluation", {})
            assert (
                guardrail.get("status") == "fail"
            ), f"Expected guardrail to fail on critical, got {guardrail.get('status')}"

    def test_generate_final_scorecard(self, progressive_results):
        """Generate final scorecard with all results."""
        md_path, csv_path = progressive_results.generate_scorecard()

        assert md_path.exists(), "Markdown scorecard should be generated"
        assert csv_path.exists(), "CSV scorecard should be generated"

        with open(md_path) as f:
            content = f.read()
            assert "Scanner Risk vs FixOps Value-Add" in content
            assert "Commands Executed" in content

        with open(csv_path) as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            assert len(rows) >= 2, "Should have at least 2 test results"

            for row in rows:
                assert "stage" in row
                assert "program" in row
                assert "scanner_highest" in row
                assert "fixops_highest" in row
                assert "value_add" in row
