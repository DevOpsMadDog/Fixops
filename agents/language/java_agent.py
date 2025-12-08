"""Java Language Agent

Language-specific agent for Java codebases.
"""

import asyncio
import logging
from typing import Optional, Dict, Any, List, Tuple

from agents.design_time.code_repo_agent import CodeRepoAgent
from agents.core.agent_framework import AgentConfig, AgentType

logger = logging.getLogger(__name__)


class JavaAgent(CodeRepoAgent):
    """Java-specific code repository agent."""
    
    def __init__(
        self,
        config: AgentConfig,
        fixops_api_url: str,
        fixops_api_key: str,
        repo_url: str,
        repo_branch: str = "main",
    ):
        """Initialize Java agent."""
        super().__init__(config, fixops_api_url, fixops_api_key, repo_url, repo_branch)
        self.language = "java"
        self.config.agent_type = AgentType.LANGUAGE
    
    async def _collect_sarif(self) -> Optional[Dict[str, Any]]:
        """Collect SARIF using Java-specific analyzers."""
        try:
            # Use proprietary Java analyzer
            from risk.reachability.languages.java import JavaAnalyzer
            
            analyzer = JavaAnalyzer()
            findings = analyzer.analyze_codebase(self.repo_path)
            
            return self._findings_to_sarif(findings, "FixOps Java Analyzer")
        
        except Exception as e:
            logger.error(f"Error collecting Java SARIF: {e}")
            return await self._collect_sarif_oss_fallback()
    
    async def _collect_sarif_oss_fallback(self) -> Optional[Dict[str, Any]]:
        """Collect SARIF using OSS tools (CodeQL, Semgrep, SpotBugs)."""
        try:
            import json
            
            # Try CodeQL
            codeql_cmd = ["codeql", "database", "analyze", "--format=sarif", self.repo_path]
            returncode, stdout, _ = await self._run_subprocess_async(
                codeql_cmd,
                timeout=600,
            )
            
            if returncode == 0:
                return json.loads(stdout)
            
            # Try Semgrep
            semgrep_cmd = ["semgrep", "--config", "p/java", "--json", self.repo_path]
            returncode, stdout, _ = await self._run_subprocess_async(
                semgrep_cmd,
                timeout=300,
            )
            
            if returncode in (0, 1):
                return self._semgrep_to_sarif(json.loads(stdout))
        
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
        findings = []
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
        return self._findings_to_sarif(findings, "Semgrep")

    async def _run_subprocess_async(
        self,
        cmd: List[str],
        cwd: Optional[str] = None,
        timeout: Optional[int] = None,
    ) -> Tuple[int, str, str]:
        """Run subprocess without blocking the event loop."""
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout)
        except asyncio.TimeoutError:
            process.kill()
            stdout, stderr = await process.communicate()
            raise RuntimeError(f"Command timed out: {' '.join(cmd)}")
        
        return process.returncode, stdout.decode(), stderr.decode()
