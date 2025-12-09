"""Code analysis for reachability determination."""

from __future__ import annotations

import logging
import os
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Set

logger = logging.getLogger(__name__)


class AnalysisTool(Enum):
    """Supported static analysis tools."""

    CODEQL = "codeql"
    SEMGREP = "semgrep"
    SONARQUBE = "sonarqube"
    BANDIT = "bandit"  # Python-specific
    ESLINT = "eslint"  # JavaScript-specific
    CUSTOM = "custom"


@dataclass
class VulnerablePattern:
    """Represents a vulnerable code pattern."""

    cve_id: str
    cwe_id: Optional[str] = None
    pattern_type: str = ""  # e.g., "sql_injection", "command_injection"
    vulnerable_functions: List[str] = field(default_factory=list)
    vulnerable_classes: List[str] = field(default_factory=list)
    vulnerable_apis: List[str] = field(default_factory=list)
    file_patterns: List[str] = field(default_factory=list)  # e.g., "*.sql", "*.sh"
    description: str = ""
    severity: str = "medium"


@dataclass
class CodeLocation:
    """Represents a location in code."""

    file_path: str
    line_number: int
    column_number: Optional[int] = None
    function_name: Optional[str] = None
    class_name: Optional[str] = None
    code_snippet: Optional[str] = None


@dataclass
class AnalysisResult:
    """Result of code analysis."""

    tool: AnalysisTool
    success: bool
    findings: List[Dict[str, Any]] = field(default_factory=list)
    call_graph: Optional[Dict[str, Any]] = None
    data_flow: Optional[Dict[str, Any]] = None
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class CodeAnalyzer:
    """Enterprise code analyzer supporting multiple tools."""

    def __init__(
        self,
        config: Optional[Mapping[str, Any]] = None,
        tools: Optional[List[AnalysisTool]] = None,
    ):
        """Initialize code analyzer.

        Parameters
        ----------
        config
            Configuration for analysis tools.
        tools
            List of tools to use. If None, uses all available.
        """
        self.config = config or {}
        self.tools = tools or [AnalysisTool.SEMGREP, AnalysisTool.CODEQL]

        # Tool configurations
        self.tool_configs = {
            AnalysisTool.CODEQL: self.config.get("codeql", {}),
            AnalysisTool.SEMGREP: self.config.get("semgrep", {}),
            AnalysisTool.SONARQUBE: self.config.get("sonarqube", {}),
            AnalysisTool.BANDIT: self.config.get("bandit", {}),
            AnalysisTool.ESLINT: self.config.get("eslint", {}),
        }

        # Check tool availability
        self.available_tools = self._check_tool_availability()

    def _check_tool_availability(self) -> Set[AnalysisTool]:
        """Check which analysis tools are available."""
        available = set()

        for tool in self.tools:
            if self._is_tool_available(tool):
                available.add(tool)
            else:
                logger.warning(f"Tool {tool.value} is not available")

        return available

    def _is_tool_available(self, tool: AnalysisTool) -> bool:
        """Check if a tool is available."""
        try:
            if tool == AnalysisTool.CODEQL:
                result = subprocess.run(
                    ["codeql", "version"],
                    capture_output=True,
                    timeout=5,
                )
                return result.returncode == 0
            elif tool == AnalysisTool.SEMGREP:
                result = subprocess.run(
                    ["semgrep", "--version"],
                    capture_output=True,
                    timeout=5,
                )
                return result.returncode == 0
            elif tool == AnalysisTool.BANDIT:
                result = subprocess.run(
                    ["bandit", "--version"],
                    capture_output=True,
                    timeout=5,
                )
                return result.returncode == 0
            elif tool == AnalysisTool.ESLINT:
                result = subprocess.run(
                    ["eslint", "--version"],
                    capture_output=True,
                    timeout=5,
                )
                return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

        return False

    def analyze_repository(
        self,
        repo_path: Path,
        vulnerable_patterns: List[VulnerablePattern],
        language: Optional[str] = None,
    ) -> Dict[AnalysisTool, AnalysisResult]:
        """Analyze repository for vulnerable patterns.

        Parameters
        ----------
        repo_path
            Path to repository.
        vulnerable_patterns
            List of vulnerable patterns to search for.
        language
            Primary language of repository. If None, auto-detect.

        Returns
        -------
        Dict[AnalysisTool, AnalysisResult]
            Analysis results from each tool.
        """
        if language is None:
            language = self._detect_primary_language(repo_path)

        results: Dict[AnalysisTool, AnalysisResult] = {}

        for tool in self.available_tools:
            try:
                if tool == AnalysisTool.CODEQL:
                    result = self._analyze_with_codeql(
                        repo_path, vulnerable_patterns, language
                    )
                elif tool == AnalysisTool.SEMGREP:
                    result = self._analyze_with_semgrep(
                        repo_path, vulnerable_patterns, language
                    )
                elif tool == AnalysisTool.BANDIT and language == "Python":
                    result = self._analyze_with_bandit(repo_path, vulnerable_patterns)
                elif tool == AnalysisTool.ESLINT and language in (
                    "JavaScript",
                    "TypeScript",
                ):
                    result = self._analyze_with_eslint(repo_path, vulnerable_patterns)
                else:
                    logger.warning(f"Skipping {tool.value} for language {language}")
                    continue

                results[tool] = result
            except Exception as e:
                logger.error(f"Analysis failed with {tool.value}: {e}")
                results[tool] = AnalysisResult(
                    tool=tool,
                    success=False,
                    errors=[str(e)],
                )

        return results

    def _analyze_with_codeql(
        self,
        repo_path: Path,
        vulnerable_patterns: List[VulnerablePattern],
        language: str,
    ) -> AnalysisResult:
        """Analyze with CodeQL."""
        # Note: config available for future tool configuration
        _ = self.tool_configs[AnalysisTool.CODEQL]
        database_path = repo_path / ".codeql" / "database"

        # Create CodeQL database if needed
        if not database_path.exists():
            logger.info("Creating CodeQL database...")
            self._create_codeql_database(repo_path, language, database_path)

        # Query for vulnerable patterns
        findings = []
        for pattern in vulnerable_patterns:
            query_results = self._query_codeql_database(
                database_path, pattern, language
            )
            findings.extend(query_results)

        return AnalysisResult(
            tool=AnalysisTool.CODEQL,
            success=True,
            findings=findings,
            metadata={"database_path": str(database_path)},
        )

    def _create_codeql_database(
        self, repo_path: Path, language: str, database_path: Path
    ) -> None:
        """Create CodeQL database for repository."""
        database_path.parent.mkdir(parents=True, exist_ok=True)

        # Map language to CodeQL language
        codeql_lang_map = {
            "Python": "python",
            "JavaScript": "javascript",
            "TypeScript": "javascript",  # CodeQL uses javascript for both
            "Java": "java",
            "C++": "cpp",
            "C": "cpp",
            "C#": "csharp",
            "Go": "go",
        }

        codeql_lang = codeql_lang_map.get(language, "python")

        cmd = [
            "codeql",
            "database",
            "create",
            str(database_path),
            f"--language={codeql_lang}",
            f"--source-root={repo_path}",
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,  # 10 minutes
        )

        if result.returncode != 0:
            raise RuntimeError(f"CodeQL database creation failed: {result.stderr}")

    def _query_codeql_database(
        self, database_path: Path, pattern: VulnerablePattern, language: str
    ) -> List[Dict[str, Any]]:
        """Query CodeQL database for vulnerable patterns."""
        # This is a simplified version - in production, you'd use actual CodeQL queries
        # For now, we'll use a generic query approach

        findings = []

        # Build query based on pattern
        if pattern.pattern_type == "sql_injection":
            # Query for SQL injection patterns
            query_file = self._get_codeql_query("sql_injection", language)
            if query_file:
                findings.extend(self._execute_codeql_query(database_path, query_file))

        return findings

    def _get_codeql_query(self, pattern_type: str, language: str) -> Optional[Path]:
        """Get CodeQL query file for pattern type."""
        # In production, you'd have a library of CodeQL queries
        # For now, return None (would need actual query files)
        return None

    def _execute_codeql_query(
        self, database_path: Path, query_file: Path
    ) -> List[Dict[str, Any]]:
        """Execute CodeQL query and parse results."""
        cmd = [
            "codeql",
            "query",
            "run",
            str(query_file),
            "--database",
            str(database_path),
            "--format=json",
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )

        if result.returncode != 0:
            logger.warning(f"CodeQL query failed: {result.stderr}")
            return []

        # Parse JSON results
        import json

        try:
            data = json.loads(result.stdout)
            return data.get("results", [])
        except json.JSONDecodeError:
            return []

    def _analyze_with_semgrep(
        self,
        repo_path: Path,
        vulnerable_patterns: List[VulnerablePattern],
        language: str,
    ) -> AnalysisResult:
        """Analyze with Semgrep."""
        # Note: config available for future tool configuration
        _ = self.tool_configs[AnalysisTool.SEMGREP]
        output_file = repo_path / ".semgrep_results.json"

        # Build Semgrep rules from vulnerable patterns
        rules = self._build_semgrep_rules(vulnerable_patterns, language)

        if not rules:
            return AnalysisResult(
                tool=AnalysisTool.SEMGREP,
                success=False,
                errors=["No Semgrep rules generated"],
            )

        # Write rules to temporary file
        import json
        import tempfile

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            import yaml

            yaml.dump({"rules": rules}, f)
            rules_file = Path(f.name)

        try:
            # Run Semgrep
            cmd = [
                "semgrep",
                "--config",
                str(rules_file),
                "--json",
                "--output",
                str(output_file),
                str(repo_path),
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,
            )

            # Parse results
            findings = []
            if output_file.exists():
                with open(output_file) as f:
                    data = json.load(f)
                    findings = data.get("results", [])

            return AnalysisResult(
                tool=AnalysisTool.SEMGREP,
                success=result.returncode == 0,
                findings=findings,
                errors=[result.stderr] if result.returncode != 0 else [],
            )
        finally:
            rules_file.unlink(missing_ok=True)
            output_file.unlink(missing_ok=True)

    def _build_semgrep_rules(
        self, patterns: List[VulnerablePattern], language: str
    ) -> List[Dict[str, Any]]:
        """Build Semgrep rules from vulnerable patterns."""
        rules = []

        lang_map = {
            "Python": "python",
            "JavaScript": "javascript",
            "TypeScript": "typescript",
            "Java": "java",
            "Go": "go",
        }

        semgrep_lang = lang_map.get(language, "python")

        for pattern in patterns:
            if pattern.pattern_type == "sql_injection":
                # Create SQL injection rule
                rule = {
                    "id": f"sql-injection-{pattern.cve_id}",
                    "message": f"Potential SQL injection: {pattern.description}",
                    "languages": [semgrep_lang],
                    "severity": pattern.severity,
                    "patterns": [
                        {
                            "pattern-either": [
                                {
                                    "pattern": f"$X({func})"
                                    for func in pattern.vulnerable_functions
                                }
                            ]
                        }
                    ],
                }
                rules.append(rule)
            elif pattern.pattern_type == "command_injection":
                # Create command injection rule
                rule = {
                    "id": f"command-injection-{pattern.cve_id}",
                    "message": f"Potential command injection: {pattern.description}",
                    "languages": [semgrep_lang],
                    "severity": pattern.severity,
                    "patterns": [
                        {
                            "pattern-either": [
                                {
                                    "pattern": f"$X({func})"
                                    for func in pattern.vulnerable_functions
                                }
                            ]
                        }
                    ],
                }
                rules.append(rule)

        return rules

    def _analyze_with_bandit(
        self, repo_path: Path, patterns: List[VulnerablePattern]
    ) -> AnalysisResult:
        """Analyze Python code with Bandit."""
        output_file = repo_path / ".bandit_results.json"

        cmd = [
            "bandit",
            "-r",
            str(repo_path),
            "-f",
            "json",
            "-o",
            str(output_file),
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )

        findings = []
        if output_file.exists():
            import json

            with open(output_file) as f:
                data = json.load(f)
                findings = data.get("results", [])

        return AnalysisResult(
            tool=AnalysisTool.BANDIT,
            success=result.returncode == 0,
            findings=findings,
        )

    def _analyze_with_eslint(
        self, repo_path: Path, patterns: List[VulnerablePattern]
    ) -> AnalysisResult:
        """Analyze JavaScript/TypeScript with ESLint."""
        # ESLint integration would go here
        # For now, return empty result
        return AnalysisResult(
            tool=AnalysisTool.ESLINT,
            success=False,
            errors=["ESLint integration not yet implemented"],
        )

    def _detect_primary_language(self, repo_path: Path) -> str:
        """Detect primary programming language of repository."""
        lang_counts: Dict[str, int] = {}

        lang_extensions = {
            ".py": "Python",
            ".js": "JavaScript",
            ".ts": "TypeScript",
            ".java": "Java",
            ".go": "Go",
            ".rs": "Rust",
            ".cpp": "C++",
            ".c": "C",
            ".cs": "C#",
            ".rb": "Ruby",
            ".php": "PHP",
        }

        for root, dirs, files in os.walk(repo_path):
            # Skip common ignored directories
            dirs[:] = [d for d in dirs if d not in {".git", "node_modules", "vendor"}]

            for file in files:
                ext = Path(file).suffix.lower()
                if ext in lang_extensions:
                    lang = lang_extensions[ext]
                    lang_counts[lang] = lang_counts.get(lang, 0) + 1

        if not lang_counts:
            return "Unknown"

        return max(lang_counts.items(), key=lambda x: x[1])[0]
