"""OSS Fallback Engine

Manages fallback to OSS tools when proprietary analyzers fail or are disabled.
"""

from __future__ import annotations

import logging
import subprocess
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class FallbackStrategy(Enum):
    """Fallback strategy options."""
    
    PROPRIETARY_FIRST = "proprietary_first"  # Try proprietary, fallback to OSS
    OSS_FIRST = "oss_first"  # Try OSS, fallback to proprietary
    PROPRIETARY_ONLY = "proprietary_only"  # Only use proprietary
    OSS_ONLY = "oss_only"  # Only use OSS


class ResultCombination(Enum):
    """How to combine proprietary and OSS results."""
    
    MERGE = "merge"  # Merge all results
    REPLACE = "replace"  # Replace with fallback results
    BEST_OF = "best_of"  # Use best results from either


@dataclass
class OSSTool:
    """OSS tool configuration."""
    
    name: str
    enabled: bool
    path: str
    config_path: Optional[str] = None
    args: List[str] = None
    timeout: int = 300  # seconds


@dataclass
class AnalysisResult:
    """Analysis result from proprietary or OSS tool."""
    
    source: str  # "proprietary" or "oss"
    tool_name: Optional[str] = None
    findings: List[Dict[str, Any]] = None
    success: bool = True
    error: Optional[str] = None
    execution_time: float = 0.0


class OSSFallbackEngine:
    """OSS Fallback Engine - Manages fallback to OSS tools."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize OSS fallback engine."""
        self.config = config
        self.strategy = FallbackStrategy(
            config.get("strategy", "proprietary_first")
        )
        self.result_combination = ResultCombination(
            config.get("result_combination", "merge")
        )
        self.oss_tools: Dict[str, OSSTool] = {}
        self._load_oss_tools()
    
    def _load_oss_tools(self):
        """Load OSS tool configurations."""
        oss_config = self.config.get("oss_tools", {})
        
        for tool_name, tool_config in oss_config.items():
            if tool_config.get("enabled", False):
                self.oss_tools[tool_name] = OSSTool(
                    name=tool_name,
                    enabled=True,
                    path=tool_config.get("path", f"/usr/local/bin/{tool_name}"),
                    config_path=tool_config.get("config_path"),
                    args=tool_config.get("args", []),
                    timeout=tool_config.get("timeout", 300),
                )
    
    def analyze_with_fallback(
        self,
        language: str,
        codebase_path: str,
        proprietary_analyzer: callable,
        proprietary_config: Optional[Dict[str, Any]] = None,
    ) -> AnalysisResult:
        """Analyze with proprietary-first, OSS fallback."""
        language_config = self.config.get("analysis_engines", {}).get(
            "languages", {}
        ).get(language, {})
        
        # Check if proprietary is enabled
        proprietary_enabled = language_config.get("proprietary", "enabled") == "enabled"
        oss_fallback_enabled = (
            language_config.get("oss_fallback", {}).get("enabled", False)
        )
        
        results = []
        
        # Try proprietary first (if enabled and strategy allows)
        if (
            proprietary_enabled
            and self.strategy
            in [FallbackStrategy.PROPRIETARY_FIRST, FallbackStrategy.PROPRIETARY_ONLY]
        ):
            try:
                proprietary_result = self._run_proprietary(
                    proprietary_analyzer, codebase_path, proprietary_config
                )
                if proprietary_result.success:
                    results.append(proprietary_result)
                    # If proprietary succeeded and strategy is proprietary_only, return
                    if self.strategy == FallbackStrategy.PROPRIETARY_ONLY:
                        return self._combine_results(results)
                else:
                    # Log the actual error for troubleshooting
                    logger.error(f"Proprietary analysis failed: {proprietary_result.error}")
            except Exception as e:
                logger.warning(f"Proprietary analysis failed: {e}")
                if self.strategy == FallbackStrategy.PROPRIETARY_ONLY:
                    # Propagate the actual error for troubleshooting
                    return AnalysisResult(
                        source="proprietary",
                        success=False,
                        error=f"Proprietary analysis failed: {str(e)}",
                        findings=[],
                    )
        
        # Try OSS (if enabled and strategy allows)
        if (
            oss_fallback_enabled
            and self.strategy
            in [FallbackStrategy.PROPRIETARY_FIRST, FallbackStrategy.OSS_FIRST, FallbackStrategy.OSS_ONLY]
        ):
            oss_tools = language_config.get("oss_fallback", {}).get("tools", [])
            
            for tool_name in oss_tools:
                if tool_name in self.oss_tools:
                    tool = self.oss_tools[tool_name]
                    if tool.enabled:
                        try:
                            oss_result = self._run_oss_tool(
                                tool, language, codebase_path
                            )
                            if oss_result.success:
                                results.append(oss_result)
                                # If OSS succeeded and strategy is oss_only, return
                                if self.strategy == FallbackStrategy.OSS_ONLY:
                                    return self._combine_results(results)
                        except Exception as e:
                            logger.warning(f"OSS tool {tool_name} failed: {e}")
                            continue
        
        # For OSS_FIRST strategy, if OSS succeeded, we may still try proprietary as fallback
        if self.strategy == FallbackStrategy.OSS_FIRST and proprietary_enabled and not results:
            try:
                proprietary_result = self._run_proprietary(
                    proprietary_analyzer, codebase_path, proprietary_config
                )
                if proprietary_result.success:
                    results.append(proprietary_result)
            except Exception as e:
                logger.warning(f"Proprietary fallback failed: {e}")
        
        # Combine results
        return self._combine_results(results)
    
    def _run_proprietary(
        self, analyzer: callable, codebase_path: str, config: Optional[Dict[str, Any]]
    ) -> AnalysisResult:
        """Run proprietary analyzer."""
        import time
        
        start_time = time.time()
        
        try:
            findings = analyzer(codebase_path, config or {})
            execution_time = time.time() - start_time
            
            return AnalysisResult(
                source="proprietary",
                findings=findings,
                success=True,
                execution_time=execution_time,
            )
        except Exception as e:
            execution_time = time.time() - start_time
            return AnalysisResult(
                source="proprietary",
                findings=[],
                success=False,
                error=str(e),
                execution_time=execution_time,
            )
    
    def _run_oss_tool(
        self, tool: OSSTool, language: str, codebase_path: str
    ) -> AnalysisResult:
        """Run OSS tool."""
        import time
        
        start_time = time.time()
        
        try:
            # Build command
            cmd = [tool.path]
            
            # Add language-specific args
            if language == "python":
                if tool.name == "semgrep":
                    cmd.extend(["--config", "p/python", "--json", codebase_path])
                elif tool.name == "bandit":
                    cmd.extend(["-r", codebase_path, "-f", "json"])
            elif language == "javascript":
                if tool.name == "semgrep":
                    cmd.extend(["--config", "p/javascript", "--json", codebase_path])
                elif tool.name == "eslint":
                    cmd.extend(["--format", "json", codebase_path])
            # ... add more language/tool combinations
            
            # Add custom args
            if tool.args:
                cmd.extend(tool.args)
            
            # Run tool
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=tool.timeout,
            )
            
            execution_time = time.time() - start_time
            
            if result.returncode == 0:
                # Parse output (tool-specific)
                findings = self._parse_oss_output(tool.name, result.stdout)
                
                return AnalysisResult(
                    source="oss",
                    tool_name=tool.name,
                    findings=findings,
                    success=True,
                    execution_time=execution_time,
                )
            else:
                return AnalysisResult(
                    source="oss",
                    tool_name=tool.name,
                    findings=[],
                    success=False,
                    error=result.stderr,
                    execution_time=execution_time,
                )
        
        except subprocess.TimeoutExpired:
            execution_time = time.time() - start_time
            return AnalysisResult(
                source="oss",
                tool_name=tool.name,
                findings=[],
                success=False,
                error="Timeout",
                execution_time=execution_time,
            )
        except Exception as e:
            execution_time = time.time() - start_time
            return AnalysisResult(
                source="oss",
                tool_name=tool.name,
                findings=[],
                success=False,
                error=str(e),
                execution_time=execution_time,
            )
    
    def _parse_oss_output(self, tool_name: str, output: str) -> List[Dict[str, Any]]:
        """Parse OSS tool output to FixOps format."""
        import json
        
        findings = []
        
        try:
            if tool_name == "semgrep":
                # Parse Semgrep JSON output
                data = json.loads(output)
                for result in data.get("results", []):
                    findings.append({
                        "rule_id": result.get("check_id", ""),
                        "severity": result.get("extra", {}).get("severity", "medium"),
                        "file": result.get("path", ""),
                        "line": result.get("start", {}).get("line", 0),
                        "message": result.get("message", ""),
                        "source": "oss",
                        "tool": "semgrep",
                    })
            
            elif tool_name == "bandit":
                # Parse Bandit JSON output
                data = json.loads(output)
                for result in data.get("results", []):
                    findings.append({
                        "rule_id": result.get("test_id", ""),
                        "severity": result.get("issue_severity", "medium"),
                        "file": result.get("filename", ""),
                        "line": result.get("line_number", 0),
                        "message": result.get("issue_text", ""),
                        "source": "oss",
                        "tool": "bandit",
                    })
            
            # ... add more tool parsers
            
        except Exception as e:
            logger.error(f"Failed to parse {tool_name} output: {e}")
        
        return findings
    
    def _combine_results(self, results: List[AnalysisResult]) -> AnalysisResult:
        """Combine multiple analysis results."""
        if not results:
            return AnalysisResult(
                source="combined",
                findings=[],
                success=False,
                error="No results available",
            )
        
        if self.result_combination == ResultCombination.REPLACE:
            # Use last result (fallback)
            return results[-1]
        
        elif self.result_combination == ResultCombination.BEST_OF:
            # Use result with most findings
            best_result = max(results, key=lambda r: len(r.findings or []))
            return best_result
        
        else:  # MERGE
            # Merge all findings
            all_findings = []
            for result in results:
                if result.findings:
                    all_findings.extend(result.findings)
            
            # Deduplicate (same file, line, rule_id)
            seen = set()
            unique_findings = []
            for finding in all_findings:
                key = (
                    finding.get("file", ""),
                    finding.get("line", 0),
                    finding.get("rule_id", ""),
                )
                if key not in seen:
                    seen.add(key)
                    unique_findings.append(finding)
            
            # Use first successful result as base
            base_result = next((r for r in results if r.success), results[0])
            
            return AnalysisResult(
                source="combined",
                findings=unique_findings,
                success=any(r.success for r in results),
                execution_time=sum(r.execution_time for r in results),
            )
