"""JavaScript Language Agent

Language-specific agent for JavaScript/TypeScript codebases.
"""

from agents.design_time.code_repo_agent import CodeRepoAgent
from agents.core.agent_framework import AgentConfig, AgentType
from typing import Optional, Dict, Any
import logging

logger = logging.getLogger(__name__)


class JavaScriptAgent(CodeRepoAgent):
    """JavaScript/TypeScript-specific code repository agent."""
    
    def __init__(
        self,
        config: AgentConfig,
        fixops_api_url: str,
        fixops_api_key: str,
        repo_url: str,
        repo_branch: str = "main",
    ):
        """Initialize JavaScript agent."""
        super().__init__(config, fixops_api_url, fixops_api_key, repo_url, repo_branch)
        self.language = "javascript"
        self.config.agent_type = AgentType.LANGUAGE
    
    async def _collect_sarif(self) -> Optional[Dict[str, Any]]:
        """Collect SARIF using JavaScript-specific analyzers."""
        try:
            # Use proprietary JavaScript analyzer
            from risk.reachability.languages.javascript import JavaScriptAnalyzer
            
            analyzer = JavaScriptAnalyzer()
            findings = analyzer.analyze_codebase(self.repo_path)
            
            # Convert to SARIF format
            return self._findings_to_sarif(findings, "FixOps JavaScript Analyzer")
        
        except Exception as e:
            logger.error(f"Error collecting JavaScript SARIF: {e}")
            return await self._collect_sarif_oss_fallback()
    
    async def _collect_sarif_oss_fallback(self) -> Optional[Dict[str, Any]]:
        """Collect SARIF using OSS tools (ESLint, Semgrep)."""
        try:
            import subprocess
            import json
            
            # Try Semgrep
            result = subprocess.run(
                ["semgrep", "--config", "p/javascript", "--json", self.repo_path],
                capture_output=True,
                text=True,
                timeout=300,
            )
            
            if result.returncode == 0:
                return self._semgrep_to_sarif(json.loads(result.stdout))
            
            # Try ESLint
            result = subprocess.run(
                ["eslint", "--format", "json", self.repo_path],
                capture_output=True,
                text=True,
                timeout=180,
            )
            
            if result.returncode == 0:
                return self._eslint_to_sarif(json.loads(result.stdout))
        
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
        return self._findings_to_sarif(semgrep_data.get("results", []), "Semgrep")
    
    def _eslint_to_sarif(self, eslint_data: Dict[str, Any]) -> Dict[str, Any]:
        """Convert ESLint output to SARIF."""
        findings = []
        for file_data in eslint_data:
            for message in file_data.get("messages", []):
                findings.append({
                    "rule_id": message.get("ruleId", ""),
                    "severity": message.get("severity", 2),
                    "file": file_data.get("filePath", ""),
                    "line": message.get("line", 0),
                    "column": message.get("column", 0),
                    "message": message.get("message", ""),
                })
        return self._findings_to_sarif(findings, "ESLint")
