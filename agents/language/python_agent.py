"""Python Language Agent

Language-specific agent for Python codebases.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from agents.core.agent_framework import AgentConfig, AgentType
from agents.design_time.code_repo_agent import CodeRepoAgent

logger = logging.getLogger(__name__)


class PythonAgent(CodeRepoAgent):
    """Python-specific code repository agent."""

    def __init__(
        self,
        config: AgentConfig,
        fixops_api_url: str,
        fixops_api_key: str,
        repo_url: str,
        repo_branch: str = "main",
    ):
        """Initialize Python agent."""
        super().__init__(config, fixops_api_url, fixops_api_key, repo_url, repo_branch)
        self.language = "python"
        self.config.agent_type = AgentType.LANGUAGE

    async def _collect_sarif(self) -> Optional[Dict[str, Any]]:
        """Collect SARIF data using Python-specific scanners."""
        try:
            # Use proprietary Python analyzer
            from risk.reachability.languages.python import PythonAnalyzer

            analyzer = PythonAnalyzer()
            findings = analyzer.analyze_codebase(self.repo_path)

            # Convert to SARIF format
            sarif = {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {
                            "driver": {
                                "name": "FixOps Python Analyzer",
                                "version": "1.0.0",
                            }
                        },
                        "results": [
                            {
                                "ruleId": f.get("rule_id", ""),
                                "level": f.get("severity", "warning"),
                                "message": {"text": f.get("message", "")},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {
                                                "uri": f.get("file", "")
                                            },
                                            "region": {
                                                "startLine": f.get("line", 0),
                                                "startColumn": f.get("column", 0),
                                            },
                                        }
                                    }
                                ],
                            }
                            for f in findings
                        ],
                    }
                ],
            }

            return sarif

        except Exception as e:
            logger.error(f"Error collecting Python SARIF: {e}")
            # Fallback to OSS tools
            return await self._collect_sarif_oss_fallback()

    async def _collect_sarif_oss_fallback(self) -> Optional[Dict[str, Any]]:
        """Collect SARIF using OSS tools as fallback."""
        try:
            import json
            import subprocess

            # Try Semgrep
            result = subprocess.run(
                ["semgrep", "--config", "p/python", "--json", self.repo_path],
                capture_output=True,
                text=True,
                timeout=300,
            )

            if result.returncode == 0:
                semgrep_data = json.loads(result.stdout)
                # Convert Semgrep to SARIF
                return self._semgrep_to_sarif(semgrep_data)

            # Try Bandit
            result = subprocess.run(
                ["bandit", "-r", self.repo_path, "-f", "json"],
                capture_output=True,
                text=True,
                timeout=180,
            )

            if result.returncode == 0:
                bandit_data = json.loads(result.stdout)
                # Convert Bandit to SARIF
                return self._bandit_to_sarif(bandit_data)

        except Exception as e:
            logger.error(f"Error in OSS fallback: {e}")

        return None

    def _semgrep_to_sarif(self, semgrep_data: Dict[str, Any]) -> Dict[str, Any]:
        """Convert Semgrep output to SARIF."""
        results = []
        for finding in semgrep_data.get("results", []):
            results.append(
                {
                    "ruleId": finding.get("check_id", ""),
                    "level": self._map_severity(
                        finding.get("extra", {}).get("severity", "warning")
                    ),
                    "message": {
                        "text": finding.get("extra", {}).get(
                            "message", finding.get("check_id", "")
                        )
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": finding.get("path", "")},
                                "region": {
                                    "startLine": finding.get("start", {}).get(
                                        "line", 0
                                    ),
                                    "startColumn": finding.get("start", {}).get(
                                        "col", 0
                                    ),
                                },
                            }
                        }
                    ],
                }
            )

        return {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Semgrep",
                            "version": "1.0.0",
                        }
                    },
                    "results": results,
                }
            ],
        }

    def _map_severity(self, severity: str) -> str:
        """Map tool severity to SARIF level."""
        severity_map = {
            "error": "error",
            "warning": "warning",
            "info": "note",
            "note": "note",
        }
        return severity_map.get(severity.lower(), "warning")

    def _bandit_to_sarif(self, bandit_data: Dict[str, Any]) -> Dict[str, Any]:
        """Convert Bandit output to SARIF."""
        results = []
        for finding in bandit_data.get("results", []):
            # Map Bandit severity to SARIF level
            severity = finding.get("issue_severity", "MEDIUM").upper()
            level = (
                "error"
                if severity == "HIGH"
                else "warning"
                if severity == "MEDIUM"
                else "note"
            )

            results.append(
                {
                    "ruleId": finding.get("test_id", ""),
                    "level": level,
                    "message": {"text": finding.get("issue_text", "")},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": finding.get("filename", "")
                                },
                                "region": {
                                    "startLine": finding.get("line_number", 0),
                                    "startColumn": 1,
                                },
                            }
                        }
                    ],
                }
            )

        return {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Bandit",
                            "version": "1.0.0",
                        }
                    },
                    "results": results,
                }
            ],
        }

    async def _collect_sbom(self) -> Optional[Dict[str, Any]]:
        """Collect SBOM using Python-specific generator."""
        try:
            from pathlib import Path

            from risk.sbom.generator import SBOMFormat, SBOMGenerator

            generator = SBOMGenerator()

            # Python-specific SBOM generation
            sbom = generator.generate_from_codebase(
                Path(self.repo_path), SBOMFormat.CYCLONEDX
            )

            # Python-specific enhancements
            # - Parse requirements.txt, setup.py, pyproject.toml
            # - Include Python version
            # - Include virtual environment info

            return sbom

        except Exception as e:
            logger.error(f"Error collecting Python SBOM: {e}")
            return None
