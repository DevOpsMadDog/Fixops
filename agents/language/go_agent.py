"""Go Language Agent

Language-specific agent for Go codebases.
"""

import logging
from typing import Any, Dict, Optional

from agents.core.agent_framework import AgentConfig, AgentType
from agents.design_time.code_repo_agent import CodeRepoAgent

logger = logging.getLogger(__name__)


class GoAgent(CodeRepoAgent):
    """Go-specific code repository agent."""

    def __init__(
        self,
        config: AgentConfig,
        fixops_api_url: str,
        fixops_api_key: str,
        repo_url: str,
        repo_branch: str = "main",
    ):
        """Initialize Go agent."""
        super().__init__(config, fixops_api_url, fixops_api_key, repo_url, repo_branch)
        self.language = "go"
        self.config.agent_type = AgentType.LANGUAGE

    async def _collect_sarif(self) -> Optional[Dict[str, Any]]:
        """Collect SARIF using Go-specific analyzers."""
        try:
            # Use proprietary Go analyzer
            from risk.reachability.languages.go import GoAnalyzer

            analyzer = GoAnalyzer()
            findings = analyzer.analyze_codebase(self.repo_path)

            return self._findings_to_sarif(findings, "FixOps Go Analyzer")

        except Exception as e:
            logger.error(f"Error collecting Go SARIF: {e}")
            return await self._collect_sarif_oss_fallback()

    async def _collect_sarif_oss_fallback(self) -> Optional[Dict[str, Any]]:
        """Collect SARIF using OSS tools (Semgrep, Gosec)."""
        try:
            import json
            import subprocess

            # Try Semgrep (exit code 1 when matches are found)
            result = subprocess.run(
                ["semgrep", "--config", "p/go", "--json", self.repo_path],
                capture_output=True,
                text=True,
                timeout=300,
            )

            # Semgrep returns 0 for no matches, 1 for matches found
            if result.returncode in [0, 1] and result.stdout:
                try:
                    return self._semgrep_to_sarif(json.loads(result.stdout))
                except json.JSONDecodeError:
                    logger.warning("Failed to parse Semgrep output")

            # Try Gosec (exit code 1 when vulnerabilities are found)
            result = subprocess.run(
                ["gosec", "-fmt", "json", "./..."],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                timeout=180,
            )

            # Gosec returns 0 for no issues, 1 when vulnerabilities are found
            if result.returncode in [0, 1] and result.stdout:
                try:
                    return self._gosec_to_sarif(json.loads(result.stdout))
                except json.JSONDecodeError:
                    logger.warning("Failed to parse Gosec output")

        except Exception as e:
            logger.error(f"Error in OSS fallback: {e}")

        return None

    def _findings_to_sarif(self, findings: list, tool_name: str) -> Dict[str, Any]:
        """Convert findings to SARIF format."""
        return {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": tool_name, "version": "1.0.0"}},
                    "results": [
                        {
                            "ruleId": f.get("rule_id", ""),
                            "level": f.get("severity", "warning"),
                            "message": {"text": f.get("message", "")},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": f.get("file", "")},
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

    def _semgrep_to_sarif(self, semgrep_data: Dict[str, Any]) -> Dict[str, Any]:
        """Convert Semgrep output to SARIF."""
        # Normalize Semgrep findings before conversion
        findings = []
        for result in semgrep_data.get("results", []):
            findings.append(
                {
                    "rule_id": result.get("check_id", ""),
                    "severity": result.get("extra", {}).get("severity", "warning"),
                    "file": result.get("path", ""),
                    "line": result.get("start", {}).get("line", 0),
                    "column": result.get("start", {}).get("col", 0),
                    "message": result.get("extra", {}).get(
                        "message", result.get("check_id", "")
                    ),
                }
            )
        return self._findings_to_sarif(findings, "Semgrep")

    def _gosec_to_sarif(self, gosec_data: Dict[str, Any]) -> Dict[str, Any]:
        """Convert Gosec output to SARIF."""
        findings = []
        for issue in gosec_data.get("Issues", []):
            findings.append(
                {
                    "rule_id": issue.get("rule_id", ""),
                    "severity": issue.get("severity", "medium"),
                    "file": issue.get("file", ""),
                    "line": issue.get("line", 0),
                    "column": issue.get("column", 0),
                    "message": issue.get("details", ""),
                }
            )
        return self._findings_to_sarif(findings, "Gosec")
