"""E2E tests for critical decision policy overrides.

This test suite verifies that the DecisionPolicyEngine correctly overrides
verdicts for critical vulnerability combinations like internet-facing SQL
injection in authentication services.

It also tests the comprehensive architectural fix that wires risk scoring
into decision logic with configurable thresholds and feature flags.
"""

import json
import tempfile
from pathlib import Path

from tests.harness.cli_runner import CLIRunner
from tests.harness.fixture_manager import FixtureManager
from tests.harness.flag_config_manager import FlagConfigManager
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


class TestRiskBasedDecisions:
    """Test comprehensive architectural fix: risk-based decision logic."""

    def test_high_risk_score_triggers_block(
        self, server_manager: ServerManager, fixture_manager: FixtureManager
    ):
        """Test that high risk score (≥0.85) triggers BLOCK verdict."""
        sast_data = {
            "runs": [
                {
                    "tool": {"driver": {"name": "semgrep"}},
                    "results": [
                        {
                            "ruleId": "critical-vulnerability",
                            "level": "error",
                            "message": {
                                "text": "Critical vulnerability with high risk"
                            },
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {
                                            "uri": "src/api/handler.py"
                                        },
                                        "region": {"startLine": 100},
                                    }
                                }
                            ],
                            "properties": {
                                "cwe": ["CWE-94"],
                                "severity": "critical",
                                "risk_score": 0.90,  # High risk score
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
                f"Expected verdict 'block' for risk_score=0.90 (≥0.85 threshold), "
                f"got '{result['verdict']}'"
            )

    def test_medium_risk_score_triggers_review(
        self, server_manager: ServerManager, fixture_manager: FixtureManager
    ):
        """Test that medium risk score (0.60-0.85) triggers REVIEW verdict."""
        sast_data = {
            "runs": [
                {
                    "tool": {"driver": {"name": "semgrep"}},
                    "results": [
                        {
                            "ruleId": "medium-vulnerability",
                            "level": "warning",
                            "message": {"text": "Medium risk vulnerability"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "src/lib/util.py"},
                                        "region": {"startLine": 50},
                                    }
                                }
                            ],
                            "properties": {
                                "cwe": ["CWE-79"],
                                "severity": "medium",
                                "risk_score": 0.70,  # Medium risk score
                            },
                        }
                    ],
                }
            ]
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            sast_path = Path(tmpdir) / "sast.sarif"
            sast_path.write_text(json.dumps(sast_data))

            response = server_manager.upload_files(sast=str(sast_path))

            assert response.status_code == 200
            result = response.json()

            assert "verdict" in result
            assert result["verdict"] == "review", (
                f"Expected verdict 'review' for risk_score=0.70 (0.60-0.85 range), "
                f"got '{result['verdict']}'"
            )

    def test_low_risk_score_triggers_allow(
        self, server_manager: ServerManager, fixture_manager: FixtureManager
    ):
        """Test that low risk score (<0.60) triggers ALLOW verdict."""
        sast_data = {
            "runs": [
                {
                    "tool": {"driver": {"name": "semgrep"}},
                    "results": [
                        {
                            "ruleId": "low-vulnerability",
                            "level": "note",
                            "message": {"text": "Low risk vulnerability"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "src/test/mock.py"},
                                        "region": {"startLine": 20},
                                    }
                                }
                            ],
                            "properties": {
                                "cwe": ["CWE-200"],
                                "severity": "low",
                                "risk_score": 0.30,  # Low risk score
                            },
                        }
                    ],
                }
            ]
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            sast_path = Path(tmpdir) / "sast.sarif"
            sast_path.write_text(json.dumps(sast_data))

            response = server_manager.upload_files(sast=str(sast_path))

            assert response.status_code == 200
            result = response.json()

            assert "verdict" in result
            assert result["verdict"] == "allow", (
                f"Expected verdict 'allow' for risk_score=0.30 (<0.60 threshold), "
                f"got '{result['verdict']}'"
            )

    def test_exposure_multiplier_escalates_verdict(
        self, server_manager: ServerManager, fixture_manager: FixtureManager
    ):
        """Test that exposure multipliers escalate verdicts correctly."""
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
                                        "artifactLocation": {"uri": "src/api/query.py"},
                                        "region": {"startLine": 75},
                                    }
                                }
                            ],
                            "properties": {
                                "cwe": ["CWE-89"],
                                "severity": "high",
                                "risk_score": 0.50,  # Base risk below REVIEW threshold
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
            assert result["verdict"] in ["review", "block"], (
                f"Expected verdict escalated by exposure multiplier, "
                f"got '{result['verdict']}'"
            )

    def test_risk_engine_disabled_uses_severity_only(
        self,
        server_manager: ServerManager,
        fixture_manager: FixtureManager,
        flag_config_manager: FlagConfigManager,
    ):
        """Test that disabling risk engine falls back to severity-based decisions."""
        flag_config = {
            "fixops.decision.use_risk_engine": False,
        }

        sast_data = {
            "runs": [
                {
                    "tool": {"driver": {"name": "semgrep"}},
                    "results": [
                        {
                            "ruleId": "high-severity-vuln",
                            "level": "error",
                            "message": {"text": "High severity vulnerability"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "src/app/main.py"},
                                        "region": {"startLine": 100},
                                    }
                                }
                            ],
                            "properties": {
                                "cwe": ["CWE-94"],
                                "severity": "high",
                                "risk_score": 0.95,  # High risk score (should be ignored)
                            },
                        }
                    ],
                }
            ]
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            sast_path = Path(tmpdir) / "sast.sarif"
            sast_path.write_text(json.dumps(sast_data))

            config_path = flag_config_manager.create_config(flag_config)

            with server_manager.start_server(overlay_config=str(config_path)):
                response = server_manager.upload_files(sast=str(sast_path))

                assert response.status_code == 200
                result = response.json()

                assert "verdict" in result
                assert result["verdict"] in ["review", "allow"], (
                    f"Expected severity-based verdict with risk engine disabled, "
                    f"got '{result['verdict']}'"
                )

    def test_policy_pre_consensus_seeds_providers_correctly(
        self, server_manager: ServerManager, fixture_manager: FixtureManager
    ):
        """Test that policy pre-consensus seeds LLM providers with correct base action."""
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
                                            "uri": "src/auth/authenticate.py"
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
            assert result["verdict"] == "block"

            if "enhanced_decision" in result:
                enhanced = result["enhanced_decision"]
                disagreement = enhanced.get("disagreement_areas", [])

                policy_overrides = [
                    d for d in disagreement if "policy_override" in str(d)
                ]
                assert (
                    len(policy_overrides) > 0
                ), "Expected policy override in disagreement_areas with pre-consensus"

    def test_telemetry_proves_risk_based_decision(
        self, server_manager: ServerManager, fixture_manager: FixtureManager
    ):
        """Test that telemetry proves risk-based decision logic is used.

        This test verifies the comprehensive architectural fix that wires
        risk scoring (EPSS + KEV + Bayesian + Markov) into the decision engine.
        """
        sast_data = {
            "runs": [
                {
                    "tool": {"driver": {"name": "semgrep"}},
                    "results": [
                        {
                            "ruleId": "sql-injection",
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

        with tempfile.TemporaryDirectory() as tmpdir:
            sast_path = Path(tmpdir) / "sast.sarif"
            cnapp_path = Path(tmpdir) / "cnapp.json"

            sast_path.write_text(json.dumps(sast_data))
            cnapp_path.write_text(json.dumps(cnapp_data))

            response = server_manager.upload_files(
                sast=str(sast_path),
                cnapp=str(cnapp_path),
            )

            assert response.status_code == 200
            result = response.json()

            assert "verdict" in result
            assert result["verdict"] == "block", (
                f"Expected verdict 'block' for internet-facing SQL injection, "
                f"got '{result['verdict']}'"
            )

            assert "enhanced_decision" in result, "Expected enhanced_decision in result"
            enhanced = result["enhanced_decision"]

            assert "telemetry" in enhanced, "Expected telemetry in enhanced_decision"
            telemetry = enhanced["telemetry"]

            assert (
                "decision_strategy" in telemetry
            ), "Expected decision_strategy in telemetry to prove which path was used"

            decision_strategy = telemetry["decision_strategy"]
            assert decision_strategy in ["risk_based", "severity"], (
                f"Expected decision_strategy to be 'risk_based' or 'severity', "
                f"got '{decision_strategy}'"
            )

            if decision_strategy == "risk_based":
                assert (
                    "raw_risk" in telemetry
                ), "Expected raw_risk in telemetry when decision_strategy is risk_based"
                assert (
                    telemetry["raw_risk"] is not None
                ), "Expected raw_risk to be non-null when risk_based strategy is used"
                assert telemetry["raw_risk"] > 0.0, (
                    f"Expected raw_risk > 0.0 when risk_based strategy is used, "
                    f"got {telemetry['raw_risk']}"
                )

                assert (
                    "thresholds_used" in telemetry
                ), "Expected thresholds_used in telemetry when decision_strategy is risk_based"
                thresholds = telemetry["thresholds_used"]
                assert (
                    "block" in thresholds
                ), "Expected block threshold in thresholds_used"
                assert (
                    "review" in thresholds
                ), "Expected review threshold in thresholds_used"

                assert (
                    "inputs" in telemetry
                ), "Expected inputs in telemetry to show risk profile components"
                inputs = telemetry["inputs"]
                assert inputs is not None, "Expected inputs to be non-null"

                if "risk_profile_method" in inputs and inputs["risk_profile_method"]:
                    method = inputs["risk_profile_method"]
                    assert (
                        "epss" in method
                    ), f"Expected EPSS in risk_profile_method, got '{method}'"

                if (
                    "risk_profile_components" in inputs
                    and inputs["risk_profile_components"]
                ):
                    components = inputs["risk_profile_components"]
                    assert isinstance(
                        components, dict
                    ), "Expected risk_profile_components to be a dict"

            assert (
                "policy_pre_consensus" in telemetry
            ), "Expected policy_pre_consensus in telemetry"
            assert (
                "policy_triggered" in telemetry
            ), "Expected policy_triggered in telemetry"
