"""Python Language Agent

Language-specific agent for Python codebases.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from agents.core.agent_framework import (
    BaseAgent,
    AgentConfig,
    AgentType,
    AgentData,
)
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
            return self._findings_to_sarif("FixOps Python Analyzer", findings)
        
        except Exception as e:
            logger.error(f"Error collecting Python SARIF: {e}")
            # Fallback to OSS tools
            return await self._collect_sarif_oss_fallback()
    
    async def _collect_sarif_oss_fallback(self) -> Optional[Dict[str, Any]]:
        """Collect SARIF using OSS tools as fallback."""
        try:
            import subprocess
            import json
            
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
        findings: List[Dict[str, Any]] = []
        for result in semgrep_data.get("results", []):
            start = result.get("start", {})
            extra = result.get("extra", {})
            findings.append({
                "rule_id": result.get("check_id", ""),
                "severity": extra.get("severity", "warning"),
                "file": result.get("path", ""),
                "line": start.get("line", 0),
                "column": start.get("col", 0),
                "message": extra.get("message") or result.get("message", ""),
            })
        return self._findings_to_sarif("Semgrep", findings)
    
    def _bandit_to_sarif(self, bandit_data: Dict[str, Any]) -> Dict[str, Any]:
        """Convert Bandit output to SARIF."""
        findings: List[Dict[str, Any]] = []
        for result in bandit_data.get("results", []):
            findings.append({
                "rule_id": result.get("test_id", ""),
                "severity": result.get("issue_severity", "warning"),
                "file": result.get("filename", ""),
                "line": result.get("line_number", 0),
                "column": result.get("col_offset", 0),
                "message": result.get("issue_text", ""),
            })
        return self._findings_to_sarif("Bandit", findings)

    def _findings_to_sarif(
        self,
        tool_name: str,
        findings: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Normalize FixOps findings into SARIF 2.1."""
        return {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": tool_name,
                            "version": "1.0.0",
                        }
                    },
                    "results": [
                        {
                            "ruleId": finding.get("rule_id", ""),
                            "level": finding.get("severity", "warning"),
                            "message": {"text": finding.get("message", "")},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {
                                            "uri": finding.get("file", "")
                                        },
                                        "region": {
                                            "startLine": finding.get("line", 0),
                                            "startColumn": finding.get("column", 0),
                                        },
                                    }
                                }
                            ],
                        }
                        for finding in findings
                    ],
                }
            ],
        }
    
    async def _collect_sbom(self) -> Optional[Dict[str, Any]]:
        """Collect SBOM using Python-specific generator."""
        try:
            from risk.sbom.generator import SBOMGenerator, SBOMFormat
            from pathlib import Path
            
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
