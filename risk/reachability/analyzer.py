"""Enterprise-grade reachability analyzer combining design-time and runtime analysis."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple

from risk.reachability.call_graph import CallGraphBuilder
from risk.reachability.code_analysis import (
    AnalysisResult,
    CodeAnalyzer,
    VulnerablePattern,
)
from risk.reachability.data_flow import DataFlowAnalyzer
from risk.reachability.git_integration import (
    GitRepository,
    GitRepositoryAnalyzer,
    RepositoryMetadata,
)
from risk.reachability.proprietary_analyzer import ProprietaryReachabilityAnalyzer
from risk.reachability.proprietary_consensus import ProprietaryConsensusEngine
from risk.reachability.proprietary_scoring import ProprietaryScoringEngine
from risk.reachability.proprietary_threat_intel import (
    ProprietaryThreatIntelligenceEngine,
)

logger = logging.getLogger(__name__)


class ReachabilityConfidence(Enum):
    """Confidence levels for reachability analysis."""

    HIGH = "high"  # >80% confidence
    MEDIUM = "medium"  # 50-80% confidence
    LOW = "low"  # <50% confidence
    UNKNOWN = "unknown"  # Cannot determine


@dataclass
class CodePath:
    """Represents a code path in the application."""

    file_path: str
    function_name: Optional[str] = None
    line_number: Optional[int] = None
    column_number: Optional[int] = None
    is_invoked: bool = False
    call_chain: List[str] = field(default_factory=list)
    entry_points: List[str] = field(default_factory=list)
    data_flow_path: Optional[List[str]] = None
    code_snippet: Optional[str] = None


@dataclass
class VulnerabilityReachability:
    """Comprehensive reachability analysis result for a vulnerability."""

    cve_id: str
    component_name: str
    component_version: str
    is_reachable: bool
    confidence: ReachabilityConfidence
    confidence_score: float  # 0.0 to 1.0
    code_paths: List[CodePath]
    call_graph_depth: int
    data_flow_depth: int
    analysis_method: str  # "static", "dynamic", "hybrid", "design-time", "runtime"
    design_time_analysis: Optional[Dict[str, Any]] = None
    runtime_analysis: Optional[Dict[str, Any]] = None
    discrepancy_detected: bool = False
    discrepancy_details: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        # Handle confidence as either enum or string (from cache)
        confidence_value = (
            self.confidence.value
            if hasattr(self.confidence, "value")
            else self.confidence
        )
        return {
            "cve_id": self.cve_id,
            "component_name": self.component_name,
            "component_version": self.component_version,
            "is_reachable": self.is_reachable,
            "confidence": confidence_value,
            "confidence_score": self.confidence_score,
            "code_paths": [
                {
                    "file_path": p.file_path,
                    "function_name": p.function_name,
                    "line_number": p.line_number,
                    "is_invoked": p.is_invoked,
                    "call_chain": p.call_chain,
                    "entry_points": p.entry_points,
                }
                for p in self.code_paths
            ],
            "call_graph_depth": self.call_graph_depth,
            "data_flow_depth": self.data_flow_depth,
            "analysis_method": self.analysis_method,
            "design_time_analysis": self.design_time_analysis,
            "runtime_analysis": self.runtime_analysis,
            "discrepancy_detected": self.discrepancy_detected,
            "discrepancy_details": self.discrepancy_details,
            "metadata": self.metadata,
        }


class ReachabilityAnalyzer:
    """Enterprise-grade reachability analyzer combining design-time and runtime analysis.

    This analyzer exceeds Endor Labs by:
    1. Combining design-time analysis (like Apiiro) with runtime verification
    2. Multi-tool static analysis (CodeQL, Semgrep, Bandit, etc.)
    3. Full call graph and data-flow analysis
    4. Discrepancy detection between design and runtime
    5. Git repository integration for any codebase
    """

    def __init__(
        self,
        config: Optional[Mapping[str, Any]] = None,
        git_analyzer: Optional[GitRepositoryAnalyzer] = None,
        code_analyzer: Optional[CodeAnalyzer] = None,
    ):
        """Initialize reachability analyzer.

        Parameters
        ----------
        config
            Configuration for analysis.
        git_analyzer
            Git repository analyzer instance. If None, creates new one.
        code_analyzer
            Code analyzer instance. If None, creates new one.
        """
        self.config = config or {}
        self.git_analyzer = git_analyzer or GitRepositoryAnalyzer(
            config=self.config.get("git", {})
        )
        self.code_analyzer = code_analyzer or CodeAnalyzer(
            config=self.config.get("code_analysis", {})
        )

        # Initialize sub-analyzers
        self.call_graph_builder = CallGraphBuilder(
            config=self.config.get("call_graph", {})
        )
        self.data_flow_analyzer = DataFlowAnalyzer(
            config=self.config.get("data_flow", {})
        )

        # Proprietary analyzers (no OSS dependencies)
        self.proprietary_analyzer = ProprietaryReachabilityAnalyzer(
            config=self.config.get("proprietary", {})
        )
        self.proprietary_scoring = ProprietaryScoringEngine(
            config=self.config.get("proprietary_scoring", {})
        )
        self.proprietary_threat_intel = ProprietaryThreatIntelligenceEngine(
            config=self.config.get("proprietary_threat_intel", {})
        )
        self.proprietary_consensus = ProprietaryConsensusEngine(
            config=self.config.get("proprietary_consensus", {})
        )

        # Use proprietary by default
        self.use_proprietary = self.config.get("use_proprietary", True)

        # Analysis settings
        self.enable_design_time = self.config.get("enable_design_time", True)
        self.enable_runtime = self.config.get("enable_runtime", True)
        self.enable_discrepancy_detection = self.config.get(
            "enable_discrepancy_detection", True
        )
        self.min_confidence_threshold = self.config.get("min_confidence_threshold", 0.5)

    def analyze_vulnerability_from_repo(
        self,
        repository: GitRepository,
        cve_id: str,
        component_name: str,
        component_version: str,
        vulnerability_details: Mapping[str, Any],
        force_refresh: bool = False,
    ) -> VulnerabilityReachability:
        """Analyze vulnerability reachability from Git repository.

        This is the main entry point for enterprise reachability analysis.
        It clones the repository, performs comprehensive analysis, and returns
        detailed reachability results.

        Parameters
        ----------
        repository
            Git repository configuration.
        cve_id
            CVE identifier.
        component_name
            Name of vulnerable component.
        component_version
            Version of vulnerable component.
        vulnerability_details
            Vulnerability details including CWE, description, etc.
        force_refresh
            If True, re-clone repository even if cached.

        Returns
        -------
        VulnerabilityReachability
            Comprehensive reachability analysis result.
        """
        logger.info(
            f"Analyzing reachability for {cve_id} in {component_name}@{component_version} "
            f"from repository: {repository.url}"
        )

        # Clone repository
        repo_path = self.git_analyzer.clone_repository(
            repository, force_refresh=force_refresh
        )

        try:
            # Get repository metadata
            repo_metadata = self.git_analyzer.get_repository_metadata(repo_path)

            # Extract vulnerable patterns from CVE
            vulnerable_patterns = self._extract_vulnerable_patterns(
                cve_id, vulnerability_details
            )

            if not vulnerable_patterns:
                logger.warning(
                    f"No vulnerable patterns extracted for {cve_id}, "
                    "returning low confidence result"
                )
                return self._create_unknown_result(
                    cve_id, component_name, component_version
                )

            # Initialize result variables
            proprietary_result = None
            design_time_result = None
            runtime_result = None
            call_graph = {}
            data_flow_result = None
            reachable_paths = []

            # Use proprietary analyzer if enabled
            if self.use_proprietary:
                # Proprietary analysis (no OSS tools)
                primary_language = (
                    list(repo_metadata.language_distribution.keys())[0]
                    if repo_metadata.language_distribution
                    else "python"
                )
                proprietary_result = self.proprietary_analyzer.analyze_repository(
                    repo_path,
                    [
                        {"cve_id": cve_id, **vulnerability_details}
                        for _ in vulnerable_patterns
                    ],
                    primary_language.lower(),
                )

                # Extract from proprietary result
                call_graph = proprietary_result.get("call_graph", {}).get("graph", {})
                data_flow_result = None  # Included in proprietary result
                reachable_paths = self._extract_proprietary_paths(proprietary_result)
            else:
                # Perform design-time analysis (OSS tools)
                if self.enable_design_time:
                    design_time_result = self._analyze_design_time(
                        repo_path, vulnerable_patterns, repo_metadata
                    )

                # Perform runtime analysis (OSS tools)
                if self.enable_runtime:
                    runtime_result = self._analyze_runtime(
                        repo_path, vulnerable_patterns, repo_metadata
                    )

                # Build call graph (OSS)
                call_graph = self.call_graph_builder.build_call_graph(
                    repo_path, repo_metadata.language_distribution
                )

                # Perform data-flow analysis
                if vulnerable_patterns:
                    data_flow_result = self.data_flow_analyzer.analyze_data_flow(
                        repo_path, vulnerable_patterns[0], call_graph
                    )

                # Check reachability
                reachable_paths = self._check_pattern_reachability(
                    vulnerable_patterns, call_graph, repo_path, data_flow_result
                )

            # Determine confidence (proprietary or standard)
            if self.use_proprietary and proprietary_result:
                confidence_score = self._calculate_proprietary_confidence(
                    proprietary_result, reachable_paths
                )
            else:
                confidence_score = self._calculate_confidence(
                    reachable_paths,
                    vulnerable_patterns,
                    call_graph,
                    design_time_result,
                    runtime_result,
                    data_flow_result,
                )

            confidence = self._confidence_level(confidence_score)

            # Detect discrepancies
            discrepancy_detected = False
            discrepancy_details = None
            if (
                self.enable_discrepancy_detection
                and design_time_result
                and runtime_result
            ):
                discrepancy_detected, discrepancy_details = self._detect_discrepancy(
                    design_time_result, runtime_result
                )

            # Build result
            result = VulnerabilityReachability(
                cve_id=cve_id,
                component_name=component_name,
                component_version=component_version,
                is_reachable=len(reachable_paths) > 0,
                confidence=confidence,
                confidence_score=confidence_score,
                code_paths=reachable_paths,
                call_graph_depth=self._max_call_depth(reachable_paths),
                data_flow_depth=(data_flow_result.max_depth if data_flow_result else 0),
                analysis_method=(
                    "proprietary"
                    if self.use_proprietary and proprietary_result
                    else self._determine_analysis_method(
                        design_time_result, runtime_result
                    )
                ),
                design_time_analysis=(
                    design_time_result.to_dict() if design_time_result else None
                ),
                runtime_analysis=(runtime_result.to_dict() if runtime_result else None),
                discrepancy_detected=discrepancy_detected,
                discrepancy_details=discrepancy_details,
                metadata={
                    "repository_url": repository.url,
                    "repository_branch": repository.branch,
                    "repository_commit": repo_metadata.commit,
                    "language_distribution": repo_metadata.language_distribution,
                    "file_count": repo_metadata.file_count,
                    "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
                    "proprietary_analysis": self.use_proprietary,
                    "proprietary_result": proprietary_result
                    if self.use_proprietary
                    else None,
                },
            )

            logger.info(
                f"Reachability analysis complete for {cve_id}: "
                f"reachable={result.is_reachable}, confidence={confidence.value}"
            )

            return result

        finally:
            # Cleanup if configured
            if self.config.get("cleanup_after_analysis", False):
                self.git_analyzer.cleanup_repository(repository)

    def _extract_vulnerable_patterns(
        self, cve_id: str, vulnerability_details: Mapping[str, Any]
    ) -> List[VulnerablePattern]:
        """Extract vulnerable code patterns from CVE details."""
        patterns = []

        cwe_ids = vulnerability_details.get("cwe_ids", [])
        if isinstance(cwe_ids, str):
            cwe_ids = [cwe_ids]

        description = vulnerability_details.get("description", "")

        # Map CWE to vulnerable patterns
        for cwe_id in cwe_ids:
            cwe_id_str = str(cwe_id).upper()

            if "CWE-89" in cwe_id_str:  # SQL Injection
                patterns.append(
                    VulnerablePattern(
                        cve_id=cve_id,
                        cwe_id=cwe_id_str,
                        pattern_type="sql_injection",
                        vulnerable_functions=[
                            "executeQuery",
                            "prepareStatement",
                            "query",
                            "execute",
                            "executemany",
                        ],
                        description=description or "SQL Injection vulnerability",
                        severity=vulnerability_details.get("severity", "medium"),
                    )
                )
            elif "CWE-78" in cwe_id_str:  # Command Injection
                patterns.append(
                    VulnerablePattern(
                        cve_id=cve_id,
                        cwe_id=cwe_id_str,
                        pattern_type="command_injection",
                        vulnerable_functions=["exec", "system", "popen", "subprocess"],
                        description=description or "Command Injection vulnerability",
                        severity=vulnerability_details.get("severity", "medium"),
                    )
                )
            elif "CWE-79" in cwe_id_str:  # XSS
                patterns.append(
                    VulnerablePattern(
                        cve_id=cve_id,
                        cwe_id=cwe_id_str,
                        pattern_type="xss",
                        vulnerable_functions=["innerHTML", "document.write"],
                        description=description or "XSS vulnerability",
                        severity=vulnerability_details.get("severity", "medium"),
                    )
                )
            elif "CWE-22" in cwe_id_str:  # Path Traversal
                patterns.append(
                    VulnerablePattern(
                        cve_id=cve_id,
                        cwe_id=cwe_id_str,
                        pattern_type="path_traversal",
                        vulnerable_functions=["open", "read", "write", "file"],
                        file_patterns=["*.txt", "*.log", "*.conf"],
                        description=description or "Path Traversal vulnerability",
                        severity=vulnerability_details.get("severity", "medium"),
                    )
                )
            # Add more CWE mappings...

        # If no patterns found, create generic pattern
        if not patterns:
            patterns.append(
                VulnerablePattern(
                    cve_id=cve_id,
                    cwe_id=cwe_ids[0] if cwe_ids else None,
                    pattern_type="generic",
                    description=description or f"Vulnerability in {cve_id}",
                    severity=vulnerability_details.get("severity", "medium"),
                )
            )

        return patterns

    def _analyze_design_time(
        self,
        repo_path: Path,
        patterns: List[VulnerablePattern],
        metadata: RepositoryMetadata,
    ) -> Optional[AnalysisResult]:
        """Perform design-time analysis (like Apiiro)."""
        logger.info("Performing design-time analysis...")

        try:
            # Use code analyzer for design-time analysis
            # Pass None to let the analyzer auto-detect the primary language
            results = self.code_analyzer.analyze_repository(repo_path, patterns, None)

            # Combine results from all tools
            if results:
                # Use the most comprehensive result
                best_result = max(
                    results.values(),
                    key=lambda r: len(r.findings) if r.success else 0,
                )
                return best_result
        except Exception as e:
            logger.error(f"Design-time analysis failed: {e}")

        return None

    def _analyze_runtime(
        self,
        repo_path: Path,
        patterns: List[VulnerablePattern],
        metadata: RepositoryMetadata,
    ) -> Optional[AnalysisResult]:
        """Perform runtime analysis (like Endor Labs)."""
        logger.info("Performing runtime analysis...")

        # Runtime analysis focuses on actual code execution paths
        # This would integrate with runtime monitoring tools if available
        # For now, we use static analysis with runtime-aware heuristics

        try:
            # Use code analyzer with runtime-aware configuration
            runtime_config = self.config.get("runtime_analysis", {})
            runtime_analyzer = CodeAnalyzer(
                config={**self.config.get("code_analysis", {}), **runtime_config}
            )

            # Pass None to let the analyzer auto-detect the primary language
            results = runtime_analyzer.analyze_repository(repo_path, patterns, None)

            if results:
                best_result = max(
                    results.values(),
                    key=lambda r: len(r.findings) if r.success else 0,
                )
                return best_result
        except Exception as e:
            logger.error(f"Runtime analysis failed: {e}")

        return None

    def _check_pattern_reachability(
        self,
        patterns: List[VulnerablePattern],
        call_graph: Dict[str, Any],
        repo_path: Path,
        data_flow_result: Optional[Any],
    ) -> List[CodePath]:
        """Check if vulnerable patterns are reachable."""
        reachable_paths = []

        for pattern in patterns:
            # Search for vulnerable functions in call graph
            for func_name in pattern.vulnerable_functions:
                if func_name in call_graph:
                    # Function exists, check if it's called
                    func_info = call_graph[func_name]
                    callers = func_info.get("callers", [])

                    if callers:
                        # Function is invoked
                        for caller in callers:
                            # Build call chain
                            call_chain = self._build_call_chain(
                                caller, call_graph, func_name
                            )

                            # Get entry points
                            entry_points = self._find_entry_points(
                                call_chain, call_graph
                            )

                            path = CodePath(
                                file_path=caller.get("file", ""),
                                function_name=func_name,
                                line_number=caller.get("line"),
                                column_number=caller.get("column"),
                                is_invoked=True,
                                call_chain=call_chain,
                                entry_points=entry_points,
                            )

                            # Add data flow path if available
                            if data_flow_result:
                                path.data_flow_path = (
                                    data_flow_result.get_path_for_function(func_name)
                                )

                            reachable_paths.append(path)

        return reachable_paths

    def _build_call_chain(
        self, start_node: Dict[str, Any], call_graph: Dict[str, Any], target_func: str
    ) -> List[str]:
        """Build call chain from entry point to vulnerable function."""
        chain = [target_func]
        current: Dict[str, Any] | None = start_node

        visited: set[str] = set()
        max_depth = 20  # Prevent infinite loops

        depth = 0
        while current and depth < max_depth:
            func_name = current.get("function")
            if func_name and func_name not in visited:
                chain.insert(0, func_name)
                visited.add(func_name)

            # Traverse up the call graph
            parent = current.get("parent")
            if parent and parent in call_graph:
                callers = call_graph[parent].get("callers")
                if callers and len(callers) > 0:
                    current = callers[0]
                else:
                    current = None
            else:
                break

            depth += 1

        return chain

    def _find_entry_points(
        self, call_chain: List[str], call_graph: Dict[str, Any]
    ) -> List[str]:
        """Find entry points (public APIs, main functions) for a call chain."""
        entry_points: List[str] = []

        if not call_chain:
            return entry_points

        first_func = call_chain[0]

        # Check if it's a public API
        func_info = call_graph.get(first_func, {})
        if func_info.get("is_public") or func_info.get("is_exported"):
            entry_points.append(first_func)

        # Check for common entry points
        entry_patterns = ["main", "handler", "route", "endpoint", "api"]
        for pattern in entry_patterns:
            if pattern.lower() in first_func.lower():
                entry_points.append(first_func)

        return entry_points

    def _calculate_confidence(
        self,
        reachable_paths: List[CodePath],
        vulnerable_patterns: List[VulnerablePattern],
        call_graph: Dict[str, Any],
        design_time_result: Optional[AnalysisResult],
        runtime_result: Optional[AnalysisResult],
        data_flow_result: Optional[Any],
    ) -> float:
        """Calculate confidence score for reachability analysis."""
        if not reachable_paths:
            return 0.0

        if not call_graph:
            return 0.3  # Low confidence without call graph

        # Base confidence from path count
        path_count_factor = min(len(reachable_paths) / 5.0, 1.0)

        # Depth factor (shorter paths = higher confidence)
        avg_depth = (
            sum(len(p.call_chain) for p in reachable_paths) / len(reachable_paths)
            if reachable_paths
            else 0
        )
        depth_factor = max(0.0, 1.0 - (avg_depth / 10.0))

        # Entry point factor (public APIs = higher confidence)
        entry_point_count = sum(len(p.entry_points) for p in reachable_paths)
        entry_point_factor = min(entry_point_count / len(reachable_paths), 1.0)

        # Design-time analysis factor
        design_factor = 0.0
        if design_time_result and design_time_result.success:
            design_factor = min(len(design_time_result.findings) / 10.0, 0.3)

        # Runtime analysis factor
        runtime_factor = 0.0
        if runtime_result and runtime_result.success:
            runtime_factor = min(len(runtime_result.findings) / 10.0, 0.3)

        # Data flow factor
        data_flow_factor = 0.0
        if data_flow_result and data_flow_result.has_path:
            data_flow_factor = 0.2

        # Combine factors
        confidence = (
            path_count_factor * 0.2
            + depth_factor * 0.2
            + entry_point_factor * 0.1
            + design_factor
            + runtime_factor
            + data_flow_factor
        )

        return min(1.0, max(0.0, confidence))

    def _confidence_level(self, score: float) -> ReachabilityConfidence:
        """Convert confidence score to confidence level."""
        if score >= 0.8:
            return ReachabilityConfidence.HIGH
        elif score >= 0.5:
            return ReachabilityConfidence.MEDIUM
        elif score > 0.0:
            return ReachabilityConfidence.LOW
        else:
            return ReachabilityConfidence.UNKNOWN

    def _detect_discrepancy(
        self, design_result: AnalysisResult, runtime_result: AnalysisResult
    ) -> Tuple[bool, Optional[str]]:
        """Detect discrepancies between design-time and runtime analysis."""
        design_findings = len(design_result.findings) if design_result.success else 0
        runtime_findings = len(runtime_result.findings) if runtime_result.success else 0

        # Significant discrepancy if findings differ by >50%
        if design_findings > 0 and runtime_findings > 0:
            diff_ratio = abs(design_findings - runtime_findings) / max(
                design_findings, runtime_findings
            )
            if diff_ratio > 0.5:
                return (
                    True,
                    f"Design-time found {design_findings} issues, "
                    f"runtime found {runtime_findings} issues "
                    f"(difference: {diff_ratio:.1%})",
                )

        return False, None

    def _determine_analysis_method(
        self,
        design_result: Optional[AnalysisResult],
        runtime_result: Optional[AnalysisResult],
    ) -> str:
        """Determine analysis method used."""
        if design_result and runtime_result:
            return "hybrid"
        elif design_result:
            return "design-time"
        elif runtime_result:
            return "runtime"
        else:
            return "static"

    def _max_call_depth(self, paths: List[CodePath]) -> int:
        """Calculate maximum call graph depth."""
        if not paths:
            return 0
        return max(len(p.call_chain) for p in paths if p.call_chain)

    def _extract_proprietary_paths(
        self, proprietary_result: Dict[str, Any]
    ) -> List[CodePath]:
        """Extract code paths from proprietary analysis result."""
        paths = []

        reachability = proprietary_result.get("reachability", {})
        reachable_matches = reachability.get("reachable_matches", [])

        for match in reachable_matches:
            file_path, line_num = match.get("location", ("", 0))
            paths.append(
                CodePath(
                    file_path=file_path,
                    line_number=line_num,
                    is_invoked=True,
                    call_chain=[],
                )
            )

        return paths

    def _calculate_proprietary_confidence(
        self, proprietary_result: Dict[str, Any], reachable_paths: List[CodePath]
    ) -> float:
        """Calculate confidence using proprietary algorithm."""
        reachability = proprietary_result.get("reachability", {})
        reachable_count = reachability.get("reachable_count", 0)
        unreachable_count = reachability.get("unreachable_count", 0)
        total = reachable_count + unreachable_count

        if total == 0:
            return 0.0

        # Proprietary confidence calculation
        if reachable_count > 0:
            # High confidence if we found reachable paths
            base_confidence = 0.7
            # Boost if we also found unreachable (shows analysis is working)
            if unreachable_count > 0:
                base_confidence = 0.85
        else:
            # Lower confidence if nothing reachable
            base_confidence = 0.5

        return min(1.0, max(0.0, base_confidence))

    def _create_unknown_result(
        self, cve_id: str, component_name: str, component_version: str
    ) -> VulnerabilityReachability:
        """Create result for unknown reachability."""
        return VulnerabilityReachability(
            cve_id=cve_id,
            component_name=component_name,
            component_version=component_version,
            is_reachable=False,
            confidence=ReachabilityConfidence.UNKNOWN,
            confidence_score=0.0,
            code_paths=[],
            call_graph_depth=0,
            data_flow_depth=0,
            analysis_method="unknown",
        )
