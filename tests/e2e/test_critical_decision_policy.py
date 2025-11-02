"""E2E tests for critical decision policy overrides.

This test suite verifies that the DecisionPolicyEngine correctly overrides
verdicts for critical vulnerability combinations like internet-facing SQL
injection in authentication services.
"""

import json
import tempfile
from pathlib import Path

from tests.harness.cli_runner import CLIRunner
from tests.harness.fixture_manager import FixtureManager
from tests.harness.server_manager import ServerManager


class TestCriticalDecisionPolicy:
    """Test critical decision policy overrides for security vulnerabilities."""

    def test_internet_facing_sqli_blocked_via_api(
        self, server_manager: ServerManager, fixture_manager: FixtureManager
    ):
        """Test that internet-facing SQL injection is blocked via API."""
        sast_data = {
            "runs": [
                {
                    "tool": {"driver": {"name": "semgrep"}},
                    "results": [
                        {
                            "ruleId": "sql-injection",
                            "level": "error",
                            "message": {"text": "SQL injection vulnerability detected"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {
                                            "uri": "src/auth/login.py"
                                        },
                                        "region": {"startLine": 42},
                                    }
                                }
                            ],
                            "properties": {
                                "cwe": ["CWE-89"],
                                "severity": "high",
                            },
                        }
                    ],
                }
            ]
        }

        cnapp_data = {
            "exposures": [
                {
                    "type": "internet-facing",
                    "traits": ["public", "internet"],
                    "service": "authentication-service",
                }
            ]
        }

        context_data = {
            "service_name": "authentication-service",
            "service_type": "auth",
            "exposure": "internet-facing",
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            sast_path = Path(tmpdir) / "sast.sarif"
            cnapp_path = Path(tmpdir) / "cnapp.json"
            context_path = Path(tmpdir) / "context.json"

            sast_path.write_text(json.dumps(sast_data))
            cnapp_path.write_text(json.dumps(cnapp_data))
            context_path.write_text(json.dumps(context_data))

            response = server_manager.upload_files(
                sast=str(sast_path),
                cnapp=str(cnapp_path),
                context=str(context_path),
            )

            assert response.status_code == 200
            result = response.json()

            assert "verdict" in result
            assert result["verdict"] == "block", (
                f"Expected verdict 'block' for internet-facing SQL injection, "
                f"got '{result['verdict']}'"
            )

            if "enhanced_decision" in result:
                enhanced = result["enhanced_decision"]
                assert enhanced.get("final_decision") == "block"

                disagreement = enhanced.get("disagreement_areas", [])
                policy_overrides = [
                    d for d in disagreement if "policy_override" in str(d)
                ]
                assert (
                    len(policy_overrides) > 0
                ), "Expected policy override in disagreement_areas"

                summary = enhanced.get("summary", "")
                assert (
                    "policy" in summary.lower()
                ), f"Expected policy reason in summary, got: {summary}"

    def test_auth_path_sqli_blocked_via_cli(
        self, cli_runner: CLIRunner, fixture_manager: FixtureManager
    ):
        """Test that SQL injection in authentication path is blocked via CLI."""
        sast_data = {
            "runs": [
                {
                    "tool": {"driver": {"name": "semgrep"}},
                    "results": [
                        {
                            "ruleId": "sql-injection",
                            "level": "error",
                            "message": {"text": "SQL injection in authentication"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {
                                            "uri": "src/services/auth_service.py"
                                        },
                                        "region": {"startLine": 100},
                                    }
                                }
                            ],
                            "properties": {
                                "cwe": ["CWE-89"],
                                "severity": "high",
                            },
                        }
                    ],
                }
            ]
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            sast_path = Path(tmpdir) / "sast.sarif"
            sast_path.write_text(json.dumps(sast_data))

            result = cli_runner.run(
                ["analyze", "--sast", str(sast_path), "--format", "json"]
            )

            assert result.returncode == 0
            output = json.loads(result.stdout)

            assert "verdict" in output
            assert output["verdict"] == "block", (
                f"Expected verdict 'block' for auth path SQL injection, "
                f"got '{output['verdict']}'"
            )

    def test_non_internet_facing_sqli_not_auto_blocked(
        self, server_manager: ServerManager, fixture_manager: FixtureManager
    ):
        """Test that non-internet-facing SQL injection is not auto-blocked."""
        sast_data = {
            "runs": [
                {
                    "tool": {"driver": {"name": "semgrep"}},
                    "results": [
                        {
                            "ruleId": "sql-injection",
                            "level": "error",
                            "message": {"text": "SQL injection vulnerability"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {
                                            "uri": "src/internal/query.py"
                                        },
                                        "region": {"startLine": 50},
                                    }
                                }
                            ],
                            "properties": {
                                "cwe": ["CWE-89"],
                                "severity": "high",
                            },
                        }
                    ],
                }
            ]
        }

        cnapp_data = {
            "exposures": [
                {
                    "type": "internal",
                    "traits": ["private", "intranet"],
                    "service": "internal-service",
                }
            ]
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            sast_path = Path(tmpdir) / "sast.sarif"
            cnapp_path = Path(tmpdir) / "cnapp.json"

            sast_path.write_text(json.dumps(sast_data))
            cnapp_path.write_text(json.dumps(cnapp_data))

            response = server_manager.upload_files(
                sast=str(sast_path), cnapp=str(cnapp_path)
            )

            assert response.status_code == 200
            result = response.json()

            assert "verdict" in result
            assert result["verdict"] in ["review", "allow"], (
                f"Expected verdict 'review' or 'allow' for internal SQL injection, "
                f"got '{result['verdict']}'"
            )

    def test_critical_internet_facing_blocked(
        self, server_manager: ServerManager, fixture_manager: FixtureManager
    ):
        """Test that critical severity + internet-facing is blocked."""
        sast_data = {
            "runs": [
                {
                    "tool": {"driver": {"name": "semgrep"}},
                    "results": [
                        {
                            "ruleId": "remote-code-execution",
                            "level": "error",
                            "message": {"text": "Remote code execution vulnerability"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {
                                            "uri": "src/api/upload.py"
                                        },
                                        "region": {"startLine": 200},
                                    }
                                }
                            ],
                            "properties": {
                                "cwe": ["CWE-94"],
                                "severity": "critical",
                            },
                        }
                    ],
                }
            ]
        }

        cnapp_data = {
            "exposures": [
                {
                    "type": "internet-facing",
                    "traits": ["public", "internet"],
                    "service": "api-service",
                }
            ]
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            sast_path = Path(tmpdir) / "sast.sarif"
            cnapp_path = Path(tmpdir) / "cnapp.json"

            sast_path.write_text(json.dumps(sast_data))
            cnapp_path.write_text(json.dumps(cnapp_data))

            response = server_manager.upload_files(
                sast=str(sast_path), cnapp=str(cnapp_path)
            )

            assert response.status_code == 200
            result = response.json()

            assert "verdict" in result
            assert result["verdict"] == "block", (
                f"Expected verdict 'block' for critical internet-facing vulnerability, "
                f"got '{result['verdict']}'"
            )

    def test_high_severity_non_sqli_not_auto_blocked(
        self, server_manager: ServerManager, fixture_manager: FixtureManager
    ):
        """Test that high severity non-SQL injection is not auto-blocked by SQLi policy."""
        sast_data = {
            "runs": [
                {
                    "tool": {"driver": {"name": "semgrep"}},
                    "results": [
                        {
                            "ruleId": "xss-vulnerability",
                            "level": "error",
                            "message": {"text": "Cross-site scripting vulnerability"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {
                                            "uri": "src/web/render.py"
                                        },
                                        "region": {"startLine": 75},
                                    }
                                }
                            ],
                            "properties": {
                                "cwe": ["CWE-79"],
                                "severity": "high",
                            },
                        }
                    ],
                }
            ]
        }

        cnapp_data = {
            "exposures": [
                {
                    "type": "internet-facing",
                    "traits": ["public", "internet"],
                    "service": "web-service",
                }
            ]
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            sast_path = Path(tmpdir) / "sast.sarif"
            cnapp_path = Path(tmpdir) / "cnapp.json"

            sast_path.write_text(json.dumps(sast_data))
            cnapp_path.write_text(json.dumps(cnapp_data))

            response = server_manager.upload_files(
                sast=str(sast_path), cnapp=str(cnapp_path)
            )

            assert response.status_code == 200
            result = response.json()

            assert "verdict" in result
            assert result["verdict"] in ["review", "allow"], (
                f"Expected verdict 'review' or 'allow' for XSS (not SQLi policy), "
                f"got '{result['verdict']}'"
            )

    def test_policy_override_confidence_boost(
        self, server_manager: ServerManager, fixture_manager: FixtureManager
    ):
        """Test that policy override increases confidence score."""
        sast_data = {
            "runs": [
                {
                    "tool": {"driver": {"name": "semgrep"}},
                    "results": [
                        {
                            "ruleId": "sql-injection",
                            "level": "error",
                            "message": {"text": "SQL injection vulnerability"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {
                                            "uri": "src/auth/login.py"
                                        },
                                        "region": {"startLine": 42},
                                    }
                                }
                            ],
                            "properties": {
                                "cwe": ["CWE-89"],
                                "severity": "high",
                            },
                        }
                    ],
                }
            ]
        }

        cnapp_data = {
            "exposures": [
                {
                    "type": "internet-facing",
                    "traits": ["public", "internet"],
                    "service": "authentication-service",
                }
            ]
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            sast_path = Path(tmpdir) / "sast.sarif"
            cnapp_path = Path(tmpdir) / "cnapp.json"

            sast_path.write_text(json.dumps(sast_data))
            cnapp_path.write_text(json.dumps(cnapp_data))

            response = server_manager.upload_files(
                sast=str(sast_path), cnapp=str(cnapp_path)
            )

            assert response.status_code == 200
            result = response.json()

            if "enhanced_decision" in result:
                enhanced = result["enhanced_decision"]
                confidence = enhanced.get("consensus_confidence", 0.0)
                assert (
                    confidence >= 0.85
                ), f"Expected confidence >= 0.85 with policy override, got {confidence}"

    def test_exact_screenshot_scenario(
        self, server_manager: ServerManager, fixture_manager: FixtureManager
    ):
        """Test the exact scenario from the user's screenshot.

        SQL Injection in User Authentication, EPSS=12.0%, Verdict should be BLOCK.
        """
        sast_data = {
            "runs": [
                {
                    "tool": {"driver": {"name": "semgrep"}},
                    "results": [
                        {
                            "ruleId": "sql-injection-user-auth",
                            "level": "error",
                            "message": {"text": "SQL Injection in User Authentication"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {
                                            "uri": "src/auth/user_authentication.py"
                                        },
                                        "region": {"startLine": 100},
                                    }
                                }
                            ],
                            "properties": {
                                "cwe": ["CWE-89"],
                                "severity": "high",
                                "epss": 0.12,  # 12% EPSS
                            },
                        }
                    ],
                }
            ]
        }

        cnapp_data = {
            "exposures": [
                {
                    "type": "internet-facing",
                    "traits": ["public", "internet"],
                    "service": "user-authentication-service",
                }
            ]
        }

        context_data = {
            "service_name": "user-authentication-service",
            "service_type": "authentication",
            "exposure": "internet-facing",
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            sast_path = Path(tmpdir) / "sast.sarif"
            cnapp_path = Path(tmpdir) / "cnapp.json"
            context_path = Path(tmpdir) / "context.json"

            sast_path.write_text(json.dumps(sast_data))
            cnapp_path.write_text(json.dumps(cnapp_data))
            context_path.write_text(json.dumps(context_data))

            response = server_manager.upload_files(
                sast=str(sast_path),
                cnapp=str(cnapp_path),
                context=str(context_path),
            )

            assert response.status_code == 200
            result = response.json()

            assert "verdict" in result
            assert result["verdict"] == "block", (
                f"CRITICAL FAILURE: SQL Injection in User Authentication with "
                f"internet-facing exposure got verdict '{result['verdict']}' "
                f"instead of 'block'. This leaves companies vulnerable!"
            )

            if "enhanced_decision" in result:
                enhanced = result["enhanced_decision"]
                assert enhanced.get("final_decision") == "block"

                confidence = enhanced.get("consensus_confidence", 0.0)
                assert (
                    confidence >= 0.80
                ), f"Expected high confidence for critical security issue, got {confidence}"

                summary = enhanced.get("summary", "")
                assert (
                    "policy" in summary.lower() or "block" in summary.lower()
                ), f"Expected policy override documented in summary: {summary}"
