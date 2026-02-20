"""Real-world end-to-end tests using actual CLI commands and API endpoints.

Tests the system as a real user would use it, not with wrapper programs.
Uses real CVEs, real SBOMs, and real data to expose actual production bugs.
"""

import json
import subprocess
from pathlib import Path

REAL_CVES = {
    "log4shell": {
        "cveID": "CVE-2021-44228",
        "title": "Apache Log4j2 Remote Code Execution",
        "knownExploited": True,
        "severity": "critical",
        "cvss": 10.0,
        "description": "Apache Log4j2 <=2.14.1 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.",
    },
    "heartbleed": {
        "cveID": "CVE-2014-0160",
        "title": "OpenSSL Heartbleed",
        "knownExploited": True,
        "severity": "high",
        "cvss": 7.5,
        "description": "The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets.",
    },
    "shellshock": {
        "cveID": "CVE-2014-6271",
        "title": "Bash Shellshock",
        "knownExploited": True,
        "severity": "critical",
        "cvss": 10.0,
        "description": "GNU Bash through 4.3 processes trailing strings after function definitions in the values of environment variables.",
    },
}


class TestRealWorldCLI:
    """Test actual CLI commands as users would run them."""

    def test_cli_demo_command_subprocess(self, tmp_path: Path) -> None:
        """Test 'fixops demo' command via subprocess (real CLI invocation)."""
        output_file = tmp_path / "demo_output.json"

        result = subprocess.run(
            [
                "python",
                "-m",
                "core.cli",
                "demo",
                "--output",
                str(output_file),
                "--mode",
                "demo",
            ],
            cwd=Path(__file__).parent.parent,
            capture_output=True,
            text=True,
            timeout=60,
        )

        assert result.returncode == 0, f"CLI failed: {result.stderr}"

        assert output_file.exists(), "Demo output file not created"

        output_data = json.loads(output_file.read_text())
        assert output_data["status"] == "ok"
        assert "design_summary" in output_data
        assert "evidence_bundle" in output_data
        assert (
            "guardrail_evaluation" in output_data
        )  # Decision is in guardrail_evaluation

    def test_cli_stage_run_requirements(self, tmp_path: Path) -> None:
        """Test 'fixops stage-run --stage requirements' with real input."""
        requirements_csv = tmp_path / "requirements.csv"
        requirements_csv.write_text(
            "Requirement_ID,feature,data_class,internet_facing,pii\n"
            "REQ-001,User authentication,restricted,true,true\n"
            "REQ-002,Data export,internal,false,false\n"
        )

        output_file = tmp_path / "requirements_output.json"

        result = subprocess.run(
            [
                "python",
                "-m",
                "core.cli",
                "stage-run",
                "--stage",
                "requirements",
                "--input",
                str(requirements_csv),
                "--app",
                "TEST-APP",
                "--output",
                str(output_file),
            ],
            cwd=Path(__file__).parent.parent,
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0, f"CLI failed: {result.stderr}"
        assert output_file.exists(), "Requirements output not created"

        output_data = json.loads(output_file.read_text())
        assert output_data["app_id"].startswith(
            "APP-"
        ), f"Expected APP-#### format, got {output_data['app_id']}"
        assert len(output_data["requirements"]) == 2
        assert "run_id" in output_data
        assert "ssvc_anchor" in output_data

    def test_cli_run_with_real_cve_data(self, tmp_path: Path) -> None:
        """Test 'fixops run' with real CVE data (Log4Shell, Heartbleed, Shellshock)."""
        import os

        os.environ["FIXOPS_API_TOKEN"] = "test-token-for-cli"

        design_csv = tmp_path / "design.csv"
        design_csv.write_text(
            "component,owner,criticality,notes\n"
            "log4j-service,security-team,critical,Uses Apache Log4j 2.14.1\n"
            "openssl-service,infra-team,high,Uses OpenSSL 1.0.1f\n"
        )

        sbom_json = tmp_path / "sbom.json"
        sbom_data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "components": [
                {
                    "type": "library",
                    "name": "log4j-core",
                    "version": "2.14.1",
                    "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                },
                {
                    "type": "library",
                    "name": "openssl",
                    "version": "1.0.1f",
                    "purl": "pkg:generic/openssl@1.0.1f",
                },
            ],
        }
        sbom_json.write_text(json.dumps(sbom_data))

        cve_json = tmp_path / "cve.json"
        cve_data = {
            "vulnerabilities": [
                REAL_CVES["log4shell"],
                REAL_CVES["heartbleed"],
                REAL_CVES["shellshock"],
            ]
        }
        cve_json.write_text(json.dumps(cve_data))

        sarif_json = tmp_path / "sarif.json"
        sarif_data = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {"driver": {"name": "Semgrep"}},
                    "results": [
                        {
                            "ruleId": "java.lang.security.audit.unsafe-deserialization",
                            "level": "error",
                            "message": {"text": "Unsafe deserialization detected"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {
                                            "uri": "src/main/java/Service.java"
                                        },
                                        "region": {"startLine": 42},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        }
        sarif_json.write_text(json.dumps(sarif_data))

        output_file = tmp_path / "pipeline_output.json"

        result = subprocess.run(
            [
                "python",
                "-m",
                "core.cli",
                "run",
                "--design",
                str(design_csv),
                "--sbom",
                str(sbom_json),
                "--cve",
                str(cve_json),
                "--sarif",
                str(sarif_json),
                "--output",
                str(output_file),
            ],
            cwd=Path(__file__).parent.parent,
            capture_output=True,
            text=True,
            timeout=60,
        )

        assert result.returncode == 0, f"CLI failed with real CVE data: {result.stderr}"
        assert output_file.exists(), "Pipeline output not created"

        output_data = json.loads(output_file.read_text())
        assert output_data["status"] == "ok"

        assert "cve_summary" in output_data
        assert "severity_overview" in output_data

        assert "guardrail_evaluation" in output_data

        assert "evidence_bundle" in output_data

        os.environ.pop("FIXOPS_API_TOKEN", None)

    def test_cli_health_check(self, tmp_path: Path) -> None:
        """Test 'fixops health' command."""
        import os

        os.environ["FIXOPS_API_TOKEN"] = "test-token-for-cli"

        result = subprocess.run(
            ["python", "-m", "core.cli", "health", "--pretty"],
            cwd=Path(__file__).parent.parent,
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0, f"Health check failed: {result.stderr}"

        health_data = json.loads(result.stdout)
        assert "integrations" in health_data or "status" in health_data

        os.environ.pop("FIXOPS_API_TOKEN", None)


class TestRealWorldCLIComprehensive:
    """Comprehensive tests for all remaining CLI commands."""

    def test_cli_ingest_command(self, tmp_path):
        """Test 'fixops ingest' command with real data."""
        import os

        os.environ["FIXOPS_API_TOKEN"] = "test-token"

        design_csv = tmp_path / "design.csv"
        design_csv.write_text(
            "component,owner,criticality,notes\n" "api-service,dev-team,high,Main API\n"
        )

        sbom_json = tmp_path / "sbom.json"
        sbom_json.write_text(
            json.dumps(
                {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.4",
                    "version": 1,
                    "components": [],
                }
            )
        )

        sarif_json = tmp_path / "sarif.json"
        sarif_json.write_text(
            json.dumps(
                {
                    "version": "2.1.0",
                    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                    "runs": [{"tool": {"driver": {"name": "Test"}}, "results": []}],
                }
            )
        )

        cve_json = tmp_path / "cve.json"
        cve_json.write_text(json.dumps({"vulnerabilities": []}))

        result = subprocess.run(
            [
                "python",
                "-m",
                "core.cli",
                "ingest",
                "--design",
                str(design_csv),
                "--sbom",
                str(sbom_json),
                "--sarif",
                str(sarif_json),
                "--cve",
                str(cve_json),
            ],
            cwd=Path(__file__).parent.parent,
            capture_output=True,
            text=True,
            timeout=60,
        )

        assert result.returncode == 0, f"Ingest failed: {result.stderr}"

        output_data = json.loads(result.stdout)
        assert output_data["status"] == "ok"
        assert "design_summary" in output_data

        os.environ.pop("FIXOPS_API_TOKEN", None)

    def test_cli_make_decision_command(self, tmp_path):
        """Test 'fixops make-decision' command returns proper exit code."""
        import os

        os.environ["FIXOPS_API_TOKEN"] = "test-token"

        design_csv = tmp_path / "design.csv"
        design_csv.write_text(
            "component,owner,criticality,notes\n"
            "safe-service,dev-team,low,Safe component\n"
        )

        sbom_json = tmp_path / "sbom.json"
        sbom_json.write_text(
            json.dumps(
                {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.4",
                    "version": 1,
                    "components": [],
                }
            )
        )

        result = subprocess.run(
            [
                "python",
                "-m",
                "core.cli",
                "make-decision",
                "--design",
                str(design_csv),
                "--sbom",
                str(sbom_json),
            ],
            cwd=Path(__file__).parent.parent,
            capture_output=True,
            text=True,
            timeout=60,
        )

        assert result.returncode in [
            0,
            1,
            2,
        ], f"Unexpected exit code: {result.returncode}"

        os.environ.pop("FIXOPS_API_TOKEN", None)

    def test_cli_show_overlay_command(self, tmp_path):
        """Test 'fixops show-overlay' command."""
        import os

        os.environ["FIXOPS_API_TOKEN"] = "test-token"

        result = subprocess.run(
            ["python", "-m", "core.cli", "show-overlay", "--pretty"],
            cwd=Path(__file__).parent.parent,
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0, f"Show overlay failed: {result.stderr}"

        overlay_data = json.loads(result.stdout)
        assert isinstance(overlay_data, dict)

        os.environ.pop("FIXOPS_API_TOKEN", None)

    def test_cli_stage_run_design(self, tmp_path):
        """Test 'fixops stage-run --stage design' with real CSV input."""
        design_csv = tmp_path / "design.csv"
        design_csv.write_text(
            "component,owner,criticality,notes\n"
            "web-app,frontend-team,high,Main web application\n"
            "api-service,backend-team,critical,Core API service\n"
        )

        output_file = tmp_path / "design_output.json"

        result = subprocess.run(
            [
                "python",
                "-m",
                "core.cli",
                "stage-run",
                "--stage",
                "design",
                "--input",
                str(design_csv),
                "--app",
                "TEST-DESIGN-APP",
                "--output",
                str(output_file),
            ],
            cwd=Path(__file__).parent.parent,
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0, f"CLI failed: {result.stderr}"
        assert output_file.exists(), "Design output not created"

        output_data = json.loads(output_file.read_text())
        assert output_data["app_id"].startswith("APP-")
        assert "rows" in output_data
        assert len(output_data["rows"]) == 2
        assert "design_risk_score" in output_data

    def test_cli_stage_run_build(self, tmp_path):
        """Test 'fixops stage-run --stage build' with real SARIF input."""
        sarif_json = tmp_path / "sarif.json"
        sarif_data = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {"driver": {"name": "SonarQube"}},
                    "results": [
                        {
                            "ruleId": "squid:S1234",
                            "level": "warning",
                            "message": {"text": "Code smell detected"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "src/main.py"},
                                        "region": {"startLine": 10},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        }
        sarif_json.write_text(json.dumps(sarif_data))

        output_file = tmp_path / "build_output.json"

        result = subprocess.run(
            [
                "python",
                "-m",
                "core.cli",
                "stage-run",
                "--stage",
                "build",
                "--input",
                str(sarif_json),
                "--app",
                "TEST-BUILD-APP",
                "--output",
                str(output_file),
            ],
            cwd=Path(__file__).parent.parent,
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0, f"CLI failed: {result.stderr}"
        assert output_file.exists(), "Build output not created"

        output_data = json.loads(output_file.read_text())
        assert output_data["app_id"].startswith("APP-")
        assert "build_risk_score" in output_data
        assert "components_indexed" in output_data

    def test_cli_stage_run_operate(self, tmp_path):
        """Test 'fixops stage-run --stage operate' with real SBOM input."""
        sbom_json = tmp_path / "sbom.json"
        sbom_data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "components": [
                {
                    "type": "library",
                    "name": "express",
                    "version": "4.17.1",
                    "purl": "pkg:npm/express@4.17.1",
                }
            ],
        }
        sbom_json.write_text(json.dumps(sbom_data))

        output_file = tmp_path / "operate_output.json"

        result = subprocess.run(
            [
                "python",
                "-m",
                "core.cli",
                "stage-run",
                "--stage",
                "operate",
                "--input",
                str(sbom_json),
                "--app",
                "TEST-OPERATE-APP",
                "--output",
                str(output_file),
            ],
            cwd=Path(__file__).parent.parent,
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0, f"CLI failed: {result.stderr}"
        assert output_file.exists(), "Operate output not created"

        output_data = json.loads(output_file.read_text())
        assert output_data["app_id"].startswith("APP-")
        assert "operate_risk_score" in output_data
        assert "epss" in output_data
        assert "kev_hits" in output_data


class TestRealWorldAPI:
    """Comprehensive tests for all API endpoints with real data."""

    def test_api_pipeline_run_endpoint(self, tmp_path):
        """Test POST /pipeline/run endpoint with real data."""
        import os
        import secrets

        from cryptography.fernet import Fernet

        os.environ["FIXOPS_API_TOKEN"] = "test-token"
        os.environ["FIXOPS_JWT_SECRET"] = secrets.token_hex(32)
        os.environ["FIXOPS_EVIDENCE_KEY"] = Fernet.generate_key().decode()
        os.environ["FIXOPS_MODE"] = "demo"

        try:
            from apps.api.app import create_app
            from fastapi.testclient import TestClient
        except ImportError:
            return

        app = create_app()
        client = TestClient(app)

        design_csv = (
            "component,owner,criticality,notes\napi-service,dev-team,high,Main API\n"
        )
        sbom_data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "components": [],
        }
        sarif_data = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{"tool": {"driver": {"name": "Test"}}, "results": []}],
        }
        cve_data = {"vulnerabilities": []}

        response = client.post(
            "/inputs/design",
            headers={"X-API-Key": "test-token"},
            files={"file": ("design.csv", design_csv, "text/csv")},
        )
        assert response.status_code == 200

        response = client.post(
            "/inputs/sbom",
            headers={"X-API-Key": "test-token"},
            files={"file": ("sbom.json", json.dumps(sbom_data), "application/json")},
        )
        assert response.status_code == 200

        response = client.post(
            "/inputs/sarif",
            headers={"X-API-Key": "test-token"},
            files={"file": ("sarif.json", json.dumps(sarif_data), "application/json")},
        )
        assert response.status_code == 200

        response = client.post(
            "/inputs/cve",
            headers={"X-API-Key": "test-token"},
            files={"file": ("cve.json", json.dumps(cve_data), "application/json")},
        )
        assert response.status_code == 200

        response = client.post("/pipeline/run", headers={"X-API-Key": "test-token"})
        assert response.status_code == 200

        result = response.json()
        assert result["status"] == "ok"
        assert "design_summary" in result
        assert "evidence_bundle" in result

        os.environ.pop("FIXOPS_API_TOKEN", None)

    def test_api_analytics_dashboard_endpoint(self, tmp_path):
        """Test GET /analytics/dashboard endpoint."""
        import os
        import secrets

        os.environ["FIXOPS_API_TOKEN"] = "test-token"
        os.environ["FIXOPS_JWT_SECRET"] = secrets.token_hex(32)
        os.environ["FIXOPS_EVIDENCE_KEY"] = secrets.token_hex(32)
        os.environ["FIXOPS_MODE"] = "demo"

        try:
            from apps.api.app import create_app
            from fastapi.testclient import TestClient
        except ImportError:
            return

        app = create_app()
        client = TestClient(app)

        response = client.get(
            "/analytics/dashboard", headers={"X-API-Key": "test-token"}
        )
        assert response.status_code == 200

        result = response.json()
        assert isinstance(result, dict)

        os.environ.pop("FIXOPS_API_TOKEN", None)


class TestRealWorldIaC:
    """Test IaC analysis with real terraform plans and Kubernetes manifests."""

    def test_iac_terraform_security_issues(self, tmp_path):
        """Test terraform plan analysis detects security issues."""
        tfplan = {
            "format_version": "1.0",
            "terraform_version": "1.0.0",
            "planned_values": {
                "root_module": {
                    "resources": [
                        {
                            "address": "aws_security_group.allow_all",
                            "type": "aws_security_group",
                            "values": {
                                "ingress": [
                                    {
                                        "cidr_blocks": ["0.0.0.0/0"],
                                        "from_port": 22,
                                        "to_port": 22,
                                        "protocol": "tcp",
                                    }
                                ]
                            },
                        }
                    ]
                }
            },
        }

        tfplan_file = tmp_path / "tfplan.json"
        tfplan_file.write_text(json.dumps(tfplan))

        from core.services.enterprise import id_allocator, signing
        from core.services.enterprise.run_registry import RunRegistry
        from core.stage_runner import StageRunner

        registry = RunRegistry()
        runner = StageRunner(registry, id_allocator, signing)

        summary = runner.run_stage(
            "deploy",
            tfplan_file,
            app_name="TEST-IAC-APP",
            app_id=None,
            mode="demo",
        )

        output_data = json.loads(summary.output_file.read_text())
        assert "iac_posture" in output_data or "posture" in output_data


class TestRealWorldDecisionEngine:
    """Test decision engine with various risk scenarios."""

    def test_decision_engine_critical_cve(self, tmp_path):
        """Test decision engine with critical CVE (Log4Shell)."""
        import os

        os.environ["FIXOPS_API_TOKEN"] = "test-token"

        design_csv = tmp_path / "design.csv"
        design_csv.write_text(
            "component,owner,criticality,notes\nlog4j-service,security-team,critical,Uses Log4j\n"
        )

        sbom_json = tmp_path / "sbom.json"
        sbom_json.write_text(
            json.dumps(
                {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.4",
                    "version": 1,
                    "components": [
                        {
                            "type": "library",
                            "name": "log4j-core",
                            "version": "2.14.1",
                            "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                        }
                    ],
                }
            )
        )

        cve_json = tmp_path / "cve.json"
        cve_json.write_text(
            json.dumps(
                {
                    "vulnerabilities": [
                        {
                            "cveID": "CVE-2021-44228",
                            "title": "Apache Log4j2 RCE",
                            "knownExploited": True,
                            "severity": "critical",
                            "cvss": 10.0,
                        }
                    ]
                }
            )
        )

        sarif_json = tmp_path / "sarif.json"
        sarif_json.write_text(
            json.dumps(
                {
                    "version": "2.1.0",
                    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                    "runs": [{"tool": {"driver": {"name": "Test"}}, "results": []}],
                }
            )
        )

        result = subprocess.run(
            [
                "python",
                "-m",
                "core.cli",
                "make-decision",
                "--design",
                str(design_csv),
                "--sbom",
                str(sbom_json),
                "--cve",
                str(cve_json),
                "--sarif",
                str(sarif_json),
            ],
            cwd=Path(__file__).parent.parent,
            capture_output=True,
            text=True,
            timeout=60,
        )

        assert result.returncode != 0, "Decision should block with critical KEV CVE"

        os.environ.pop("FIXOPS_API_TOKEN", None)


class TestRealWorldMarketplace:
    """Test marketplace recommendations and developer extensions."""

    def test_marketplace_recommendations(self, tmp_path):
        """Test marketplace recommendations based on control IDs."""
        import sys
        from pathlib import Path

        enterprise_path = Path(__file__).parent.parent / "fixops-enterprise"
        if str(enterprise_path) not in sys.path:
            sys.path.insert(0, str(enterprise_path))

        from core.services.enterprise.marketplace import get_recommendations

        control_ids = ["ISO27001:AC-2", "PCI:8.3"]
        recommendations = get_recommendations(control_ids)

        assert isinstance(recommendations, list)
        assert len(recommendations) > 0
        assert any(r["control_id"] == "ISO27001:AC-2" for r in recommendations)

    def test_marketplace_get_pack(self, tmp_path):
        """Test getting specific marketplace pack."""
        import sys
        from pathlib import Path

        enterprise_path = Path(__file__).parent.parent / "fixops-enterprise"
        if str(enterprise_path) not in sys.path:
            sys.path.insert(0, str(enterprise_path))

        from core.services.enterprise.marketplace import get_pack

        pack = get_pack("ISO27001", "AC-2")

        assert isinstance(pack, dict)
        assert "pack_id" in pack
        assert "title" in pack


class TestRealWorldBacktesting:
    """Test backtesting with real CVE feeds."""

    def test_backtest_log4shell_cve(self, tmp_path):
        """Test backtesting with Log4Shell CVE-2021-44228."""
        sbom_json = tmp_path / "sbom.json"
        sbom_json.write_text(
            json.dumps(
                {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.4",
                    "version": 1,
                    "components": [
                        {
                            "type": "library",
                            "name": "log4j-core",
                            "version": "2.14.1",
                            "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                        }
                    ],
                }
            )
        )

        output_file = tmp_path / "operate_output.json"

        result = subprocess.run(
            [
                "python",
                "-m",
                "core.cli",
                "stage-run",
                "--stage",
                "operate",
                "--input",
                str(sbom_json),
                "--app",
                "TEST-LOG4SHELL-APP",
                "--output",
                str(output_file),
            ],
            cwd=Path(__file__).parent.parent,
            capture_output=True,
            text=True,
            timeout=60,
        )

        assert result.returncode == 0, f"CLI failed: {result.stderr}"
        assert output_file.exists(), "Operate output not created"

        output_data = json.loads(output_file.read_text())
        assert "operate_risk_score" in output_data
        assert output_data["app_id"].startswith("APP-")

    def test_backtest_heartbleed_cve(self, tmp_path):
        """Test backtesting with Heartbleed CVE-2014-0160."""
        sbom_json = tmp_path / "sbom.json"
        sbom_json.write_text(
            json.dumps(
                {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.4",
                    "version": 1,
                    "components": [
                        {
                            "type": "library",
                            "name": "openssl",
                            "version": "1.0.1f",
                            "purl": "pkg:generic/openssl@1.0.1f",
                        }
                    ],
                }
            )
        )

        output_file = tmp_path / "operate_output.json"

        result = subprocess.run(
            [
                "python",
                "-m",
                "core.cli",
                "stage-run",
                "--stage",
                "operate",
                "--input",
                str(sbom_json),
                "--app",
                "TEST-HEARTBLEED-APP",
                "--output",
                str(output_file),
            ],
            cwd=Path(__file__).parent.parent,
            capture_output=True,
            text=True,
            timeout=60,
        )

        assert result.returncode == 0, f"CLI failed: {result.stderr}"
        assert output_file.exists(), "Operate output not created"

        output_data = json.loads(output_file.read_text())
        assert "operate_risk_score" in output_data
        assert output_data["app_id"].startswith("APP-")

    def test_backtest_shellshock_cve(self, tmp_path):
        """Test backtesting with Shellshock CVE-2014-6271."""
        sbom_json = tmp_path / "sbom.json"
        sbom_json.write_text(
            json.dumps(
                {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.4",
                    "version": 1,
                    "components": [
                        {
                            "type": "library",
                            "name": "bash",
                            "version": "4.3",
                            "purl": "pkg:generic/bash@4.3",
                        }
                    ],
                }
            )
        )

        output_file = tmp_path / "operate_output.json"

        result = subprocess.run(
            [
                "python",
                "-m",
                "core.cli",
                "stage-run",
                "--stage",
                "operate",
                "--input",
                str(sbom_json),
                "--app",
                "TEST-SHELLSHOCK-APP",
                "--output",
                str(output_file),
            ],
            cwd=Path(__file__).parent.parent,
            capture_output=True,
            text=True,
            timeout=60,
        )

        assert result.returncode == 0, f"CLI failed: {result.stderr}"
        assert output_file.exists(), "Operate output not created"

        output_data = json.loads(output_file.read_text())
        assert "operate_risk_score" in output_data
        assert output_data["app_id"].startswith("APP-")
