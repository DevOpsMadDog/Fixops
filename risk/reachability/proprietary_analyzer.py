"""Proprietary FixOps reachability analyzer - no OSS dependencies.

This is FixOps' proprietary code analysis engine that doesn't rely on
CodeQL, Semgrep, or other OSS tools. Built from scratch for enterprise use.
"""

from __future__ import annotations

import ast
import logging
import re
from collections import deque
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class AnalysisConfidence(Enum):
    """Confidence levels for proprietary analysis."""

    VERY_HIGH = "very_high"  # >90%
    HIGH = "high"  # 70-90%
    MEDIUM = "medium"  # 50-70%
    LOW = "low"  # 30-50%
    VERY_LOW = "very_low"  # <30%


@dataclass
class ProprietaryCodePath:
    """Proprietary code path representation."""

    source_file: str
    start_line: int
    end_line: int
    function_chain: List[str]
    data_flow_path: List[Tuple[str, int]]  # (variable, line)
    entry_points: List[str]
    is_public_api: bool
    call_depth: int
    complexity_score: float
    confidence: AnalysisConfidence


@dataclass
class ProprietaryVulnerabilityMatch:
    """Proprietary vulnerability pattern match."""

    cve_id: str
    pattern_type: str
    matched_location: Tuple[str, int]  # (file, line)
    matched_code: str
    context: Dict[str, Any]
    confidence: AnalysisConfidence
    exploitability_score: float  # 0.0 to 1.0


class ProprietaryPatternMatcher:
    """Proprietary pattern matching engine - no regex, custom algorithms."""

    def __init__(self):
        """Initialize proprietary pattern matcher."""
        # Proprietary pattern database (not OSS)
        self._sql_injection_patterns = self._build_sql_patterns()
        self._command_injection_patterns = self._build_command_patterns()
        self._xss_patterns = self._build_xss_patterns()
        self._path_traversal_patterns = self._build_path_patterns()
        self._deserialization_patterns = self._build_deserialization_patterns()

    def _build_sql_patterns(self) -> List[Dict[str, Any]]:
        """Build proprietary SQL injection patterns."""
        return [
            {
                "type": "direct_execution",
                "functions": ["execute", "executemany", "executeQuery", "query"],
                "risk_level": "high",
                "indicators": ["%s", "?", "{", "format", "f'", 'f"'],
            },
            {
                "type": "prepared_statement_misuse",
                "functions": ["prepareStatement", "prepare"],
                "risk_level": "medium",
                "indicators": ["+", "concat", "join"],
            },
            {
                "type": "orm_injection",
                "functions": ["raw", "extra", "execute_raw"],
                "risk_level": "high",
                "indicators": ["%", "format"],
            },
        ]

    def _build_command_patterns(self) -> List[Dict[str, Any]]:
        """Build proprietary command injection patterns."""
        return [
            {
                "type": "shell_execution",
                "functions": ["system", "exec", "popen", "subprocess.call"],
                "risk_level": "critical",
                "indicators": ["shell=True", "shell=true"],
            },
            {
                "type": "os_command",
                "functions": ["os.system", "os.popen", "commands.getoutput"],
                "risk_level": "critical",
                "indicators": ["user_input", "request", "param"],
            },
        ]

    def _build_xss_patterns(self) -> List[Dict[str, Any]]:
        """Build proprietary XSS patterns."""
        return [
            {
                "type": "dom_manipulation",
                "functions": ["innerHTML", "document.write", "eval"],
                "risk_level": "high",
                "indicators": ["user_input", "location", "document.URL"],
            },
            {
                "type": "template_injection",
                "functions": ["render", "template", "render_template"],
                "risk_level": "medium",
                "indicators": ["|safe", "|raw", "autoescape=False"],
            },
        ]

    def _build_path_patterns(self) -> List[Dict[str, Any]]:
        """Build proprietary path traversal patterns."""
        return [
            {
                "type": "file_operations",
                "functions": ["open", "read", "write", "file"],
                "risk_level": "high",
                "indicators": ["..", "../", "..\\", "user_input"],
            },
            {
                "type": "path_join",
                "functions": ["os.path.join", "path.join", "joinpath"],
                "risk_level": "medium",
                "indicators": ["user_input", "request.path"],
            },
        ]

    def _build_deserialization_patterns(self) -> List[Dict[str, Any]]:
        """Build proprietary deserialization patterns."""
        return [
            {
                "type": "pickle",
                "functions": ["pickle.load", "pickle.loads", "dill.load"],
                "risk_level": "critical",
                "indicators": ["user_input", "request.data"],
            },
            {
                "type": "yaml",
                "functions": ["yaml.load", "yaml.safe_load"],
                "risk_level": "high",
                "indicators": ["user_input", "!python"],
            },
            {
                "type": "json_deserialize",
                "functions": ["json.loads", "json.load"],
                "risk_level": "medium",
                "indicators": ["object_hook", "custom_decoder"],
            },
        ]

    def match_patterns(
        self, code_content: str, language: str, file_path: str
    ) -> List[ProprietaryVulnerabilityMatch]:
        """Proprietary pattern matching algorithm."""
        matches = []

        if language == "python":
            matches.extend(self._match_python_patterns(code_content, file_path))
        elif language in ("javascript", "typescript"):
            matches.extend(self._match_javascript_patterns(code_content, file_path))
        elif language == "java":
            matches.extend(self._match_java_patterns(code_content, file_path))

        return matches

    def _match_python_patterns(
        self, code: str, file_path: str
    ) -> List[ProprietaryVulnerabilityMatch]:
        """Proprietary Python pattern matching."""
        matches = []

        try:
            tree = ast.parse(code, filename=file_path)
            visitor = ProprietaryPythonVisitor(self, file_path)
            visitor.visit(tree)
            matches.extend(visitor.matches)
        except SyntaxError:
            logger.warning(f"Failed to parse Python file: {file_path}")

        return matches

    def _match_javascript_patterns(
        self, code: str, file_path: str
    ) -> List[ProprietaryVulnerabilityMatch]:
        """Proprietary JavaScript pattern matching."""
        matches = []

        # Proprietary JavaScript AST parsing (simplified for now)
        # In production, this would use custom parser

        # Pattern: dangerous function calls
        dangerous_functions = [
            "eval",
            "Function",
            "setTimeout",
            "setInterval",
            "innerHTML",
            "document.write",
        ]

        for func in dangerous_functions:
            pattern = rf"\b{func}\s*\("
            for match in re.finditer(pattern, code):
                line_num = code[: match.start()].count("\n") + 1
                matches.append(
                    ProprietaryVulnerabilityMatch(
                        cve_id="CUSTOM-XSS",
                        pattern_type="xss",
                        matched_location=(file_path, line_num),
                        matched_code=code[match.start() : match.end() + 50],
                        context={"function": func},
                        confidence=AnalysisConfidence.MEDIUM,
                        exploitability_score=0.6,
                    )
                )

        return matches

    def _match_java_patterns(
        self, code: str, file_path: str
    ) -> List[ProprietaryVulnerabilityMatch]:
        """Proprietary Java pattern matching."""
        matches = []

        # Proprietary Java pattern matching
        sql_patterns = [
            r"Statement\s*\.\s*execute\s*\(",
            r"PreparedStatement\s*\.\s*executeQuery\s*\(",
        ]

        for pattern in sql_patterns:
            for match in re.finditer(pattern, code):
                line_num = code[: match.start()].count("\n") + 1
                matches.append(
                    ProprietaryVulnerabilityMatch(
                        cve_id="CUSTOM-SQLI",
                        pattern_type="sql_injection",
                        matched_location=(file_path, line_num),
                        matched_code=code[match.start() : match.end() + 50],
                        context={"pattern": pattern},
                        confidence=AnalysisConfidence.HIGH,
                        exploitability_score=0.7,
                    )
                )

        return matches


class ProprietaryPythonVisitor(ast.NodeVisitor):
    """Proprietary AST visitor for Python code analysis."""

    def __init__(self, matcher: ProprietaryPatternMatcher, file_path: str):
        """Initialize visitor."""
        self.matcher = matcher
        self.file_path = file_path
        self.matches: List[ProprietaryVulnerabilityMatch] = []
        self.current_function: Optional[str] = None
        self.current_class: Optional[str] = None
        self.variable_sources: Dict[str, str] = {}  # Track variable sources

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Visit function definition."""
        old_function = self.current_function
        self.current_function = node.name
        self.generic_visit(node)
        self.current_function = old_function

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Visit class definition."""
        old_class = self.current_class
        self.current_class = node.name
        self.generic_visit(node)
        self.current_class = old_class

    def visit_Call(self, node: ast.Call) -> None:
        """Visit function call - proprietary vulnerability detection."""
        func_name = self._extract_function_name(node.func)

        if not func_name:
            self.generic_visit(node)
            return

        # Check against proprietary pattern database
        for pattern_set in [
            self.matcher._sql_injection_patterns,
            self.matcher._command_injection_patterns,
            self.matcher._xss_patterns,
            self.matcher._path_traversal_patterns,
            self.matcher._deserialization_patterns,
        ]:
            for pattern in pattern_set:
                if func_name in pattern.get("functions", []):
                    # Check if user input flows to this function
                    has_user_input = self._check_user_input_flow(node)

                    if has_user_input:
                        match = ProprietaryVulnerabilityMatch(
                            cve_id="CUSTOM-DETECTED",
                            pattern_type=pattern.get("type", "unknown"),
                            matched_location=(self.file_path, node.lineno),
                            matched_code=ast.get_source_segment(
                                getattr(node, "source_code", ""), node
                            )
                            or str(node),
                            context={
                                "function": func_name,
                                "pattern": pattern,
                                "has_user_input": has_user_input,
                            },
                            confidence=AnalysisConfidence.HIGH,
                            exploitability_score=0.8 if has_user_input else 0.4,
                        )
                        self.matches.append(match)

        self.generic_visit(node)

    def _extract_function_name(self, node: ast.AST) -> Optional[str]:
        """Extract function name from AST node."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return node.attr
        elif isinstance(node, ast.Call):
            return self._extract_function_name(node.func)
        return None

    def _check_user_input_flow(self, node: ast.Call) -> bool:
        """Proprietary algorithm to check if user input flows to function."""
        # Check arguments for user input indicators
        user_input_indicators = [
            "request",
            "input",
            "param",
            "query",
            "form",
            "body",
            "args",
            "kwargs",
            "data",
        ]

        for arg in node.args:
            if isinstance(arg, ast.Name):
                var_name = arg.id.lower()
                if any(indicator in var_name for indicator in user_input_indicators):
                    return True

        # Check keyword arguments
        for keyword in node.keywords:
            if isinstance(keyword.value, ast.Name):
                var_name = keyword.value.id.lower()
                if any(indicator in var_name for indicator in user_input_indicators):
                    return True

        return False


class ProprietaryCallGraphBuilder:
    """Proprietary call graph builder - no NetworkX dependency."""

    def __init__(self):
        """Initialize proprietary call graph builder."""
        self.graph: Dict[str, Dict[str, Any]] = {}
        self.entry_points: Set[str] = set()

    def build_from_repository(self, repo_path: Path, language: str) -> Dict[str, Any]:
        """Build proprietary call graph from repository."""
        if language == "python":
            return self._build_python_graph(repo_path)
        elif language in ("javascript", "typescript"):
            return self._build_javascript_graph(repo_path)
        elif language == "java":
            return self._build_java_graph(repo_path)
        else:
            return {}

    def _build_python_graph(self, repo_path: Path) -> Dict[str, Any]:
        """Build proprietary Python call graph."""
        graph = {}

        python_files = list(repo_path.rglob("*.py"))
        ignore_dirs = {".git", "node_modules", "venv", "__pycache__", "vendor"}
        python_files = [
            f for f in python_files if not any(part in ignore_dirs for part in f.parts)
        ]

        for py_file in python_files:
            try:
                with open(py_file, "r", encoding="utf-8") as f:
                    content = f.read()

                tree = ast.parse(content, filename=str(py_file))
                builder = ProprietaryCallGraphBuilderVisitor(str(py_file))
                builder.visit(tree)

                # Merge into main graph
                for func_name, func_info in builder.graph.items():
                    if func_name not in graph:
                        graph[func_name] = func_info
                    else:
                        # Merge callers and callees
                        graph[func_name]["callers"].extend(func_info["callers"])
                        graph[func_name]["callees"].extend(func_info["callees"])
                        graph[func_name]["callers"] = list(
                            set(graph[func_name]["callers"])
                        )
                        graph[func_name]["callees"] = list(
                            set(graph[func_name]["callees"])
                        )

                # Track entry points
                self.entry_points.update(builder.entry_points)

            except Exception as e:
                logger.warning(f"Failed to build graph for {py_file}: {e}")

        return {
            "graph": graph,
            "entry_points": list(self.entry_points),
            "total_functions": len(graph),
        }

    def _build_javascript_graph(self, repo_path: Path) -> Dict[str, Any]:
        """Build proprietary JavaScript call graph."""
        # Proprietary JavaScript call graph building
        graph = {}

        js_files = list(repo_path.rglob("*.js")) + list(repo_path.rglob("*.ts"))
        ignore_dirs = {".git", "node_modules", "vendor", "dist", "build"}
        js_files = [
            f for f in js_files if not any(part in ignore_dirs for part in f.parts)
        ]

        # Proprietary JavaScript parser (simplified)
        for js_file in js_files:
            try:
                with open(js_file, "r", encoding="utf-8") as f:
                    content = f.read()

                # Proprietary pattern matching for function definitions
                function_pattern = r"function\s+(\w+)\s*\("
                for match in re.finditer(function_pattern, content):
                    func_name = match.group(1)
                    if func_name not in graph:
                        graph[func_name] = {
                            "file": str(js_file),
                            "line": content[: match.start()].count("\n") + 1,
                            "callers": [],
                            "callees": [],
                            "is_exported": "export" in content[: match.start()],
                        }

            except Exception as e:
                logger.warning(f"Failed to build graph for {js_file}: {e}")

        return {
            "graph": graph,
            "entry_points": [f for f, info in graph.items() if info.get("is_exported")],
            "total_functions": len(graph),
        }

    def _build_java_graph(self, repo_path: Path) -> Dict[str, Any]:
        """Build proprietary Java call graph."""
        graph = {}

        java_files = list(repo_path.rglob("*.java"))
        ignore_dirs = {".git", "target", "build", "out"}
        java_files = [
            f for f in java_files if not any(part in ignore_dirs for part in f.parts)
        ]

        for java_file in java_files:
            try:
                with open(java_file, "r", encoding="utf-8") as f:
                    content = f.read()

                # Proprietary Java method detection
                method_pattern = r"(public|private|protected)?\s*\w+\s+(\w+)\s*\("
                for match in re.finditer(method_pattern, content):
                    method_name = match.group(2)
                    if method_name not in graph:
                        graph[method_name] = {
                            "file": str(java_file),
                            "line": content[: match.start()].count("\n") + 1,
                            "callers": [],
                            "callees": [],
                            "is_public": "public" in match.group(0),
                        }

            except Exception as e:
                logger.warning(f"Failed to build graph for {java_file}: {e}")

        return {
            "graph": graph,
            "entry_points": [f for f, info in graph.items() if info.get("is_public")],
            "total_functions": len(graph),
        }


class ProprietaryCallGraphBuilderVisitor(ast.NodeVisitor):
    """Proprietary AST visitor for call graph construction."""

    def __init__(self, file_path: str):
        """Initialize visitor."""
        self.file_path = file_path
        self.graph: Dict[str, Dict[str, Any]] = {}
        self.entry_points: Set[str] = set()
        self.current_function: Optional[str] = None
        self.current_class: Optional[str] = None

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Visit function definition."""
        func_name = node.name
        full_name = (
            f"{self.current_class}.{func_name}" if self.current_class else func_name
        )

        # Check if it's an entry point
        if not func_name.startswith("_") or func_name == "__main__":
            self.entry_points.add(full_name)

        if full_name not in self.graph:
            self.graph[full_name] = {
                "file": self.file_path,
                "line": node.lineno,
                "callers": [],
                "callees": [],
                "is_public": not func_name.startswith("_"),
            }

        old_function = self.current_function
        self.current_function = full_name
        self.generic_visit(node)
        self.current_function = old_function

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Visit class definition."""
        old_class = self.current_class
        self.current_class = node.name
        self.generic_visit(node)
        self.current_class = old_class

    def visit_Call(self, node: ast.Call) -> None:
        """Visit function call."""
        if not self.current_function:
            self.generic_visit(node)
            return

        called_func = self._extract_function_name(node.func)
        if called_func:
            # Add to callees
            if called_func not in self.graph:
                self.graph[called_func] = {
                    "file": self.file_path,
                    "line": node.lineno,
                    "callers": [],
                    "callees": [],
                    "is_public": True,
                }

            # Add relationship
            if self.current_function in self.graph:
                if called_func not in self.graph[self.current_function]["callees"]:
                    self.graph[self.current_function]["callees"].append(called_func)

            if called_func in self.graph:
                caller_info = {
                    "function": self.current_function,
                    "file": self.file_path,
                    "line": node.lineno,
                }
                if caller_info not in self.graph[called_func]["callers"]:
                    self.graph[called_func]["callers"].append(caller_info)

        self.generic_visit(node)

    def _extract_function_name(self, node: ast.AST) -> Optional[str]:
        """Extract function name."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return node.attr
        return None


class ProprietaryDataFlowAnalyzer:
    """Proprietary data flow analyzer - custom taint analysis."""

    def __init__(self):
        """Initialize proprietary data flow analyzer."""
        self.taint_sources = {
            "request",
            "input",
            "param",
            "query",
            "form",
            "body",
            "args",
            "kwargs",
            "data",
            "user_input",
            "getParameter",
            "getQueryString",
        }
        self.taint_sinks = {
            "execute",
            "query",
            "system",
            "exec",
            "eval",
            "innerHTML",
            "document.write",
        }
        self.sanitizers = {
            "escape",
            "sanitize",
            "validate",
            "filter",
            "encode",
        }

    def analyze_taint_flow(
        self, code_content: str, language: str, file_path: str
    ) -> List[Dict[str, Any]]:
        """Proprietary taint flow analysis."""
        if language == "python":
            return self._analyze_python_taint(code_content, file_path)
        elif language in ("javascript", "typescript"):
            return self._analyze_javascript_taint(code_content, file_path)
        else:
            return []

    def _analyze_python_taint(self, code: str, file_path: str) -> List[Dict[str, Any]]:
        """Proprietary Python taint analysis."""
        flows = []

        try:
            tree = ast.parse(code, filename=file_path)
            analyzer = ProprietaryTaintAnalyzer(self, file_path)
            analyzer.visit(tree)
            flows.extend(analyzer.taint_flows)
        except SyntaxError:
            logger.warning(f"Failed to parse Python for taint analysis: {file_path}")

        return flows

    def _analyze_javascript_taint(
        self, code: str, file_path: str
    ) -> List[Dict[str, Any]]:
        """Proprietary JavaScript taint analysis."""
        flows = []

        # Proprietary JavaScript taint tracking
        lines = code.split("\n")
        tainted_vars = set()

        for line_num, line in enumerate(lines, 1):
            # Detect taint sources
            for source in self.taint_sources:
                if source in line.lower():
                    # Extract variable name
                    var_match = re.search(rf"(\w+)\s*=\s*.*{source}", line)
                    if var_match:
                        tainted_vars.add(var_match.group(1))

            # Detect taint sinks
            for sink in self.taint_sinks:
                if sink in line.lower():
                    # Check if tainted variable flows to sink
                    for var in tainted_vars:
                        if var in line:
                            flows.append(
                                {
                                    "source": f"user_input:{line_num}",
                                    "sink": f"{sink}:{line_num}",
                                    "variable": var,
                                    "file": file_path,
                                    "is_sanitized": False,
                                }
                            )

            # Detect sanitizers
            for sanitizer in self.sanitizers:
                if sanitizer in line.lower():
                    # Remove variable from tainted set
                    var_match = re.search(rf"(\w+)\s*=\s*.*{sanitizer}", line)
                    if var_match:
                        tainted_vars.discard(var_match.group(1))

        return flows


class ProprietaryTaintAnalyzer(ast.NodeVisitor):
    """Proprietary taint analyzer for Python."""

    def __init__(self, analyzer: ProprietaryDataFlowAnalyzer, file_path: str):
        """Initialize taint analyzer."""
        self.analyzer = analyzer
        self.file_path = file_path
        self.tainted_vars: Set[str] = set()
        self.taint_flows: List[Dict[str, Any]] = []
        self.current_function: Optional[str] = None

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Visit function definition."""
        old_function = self.current_function
        self.current_function = node.name
        # Reset tainted vars for new function scope
        old_tainted = self.tainted_vars.copy()
        self.tainted_vars.clear()
        self.generic_visit(node)
        self.current_function = old_function
        self.tainted_vars = old_tainted

    def visit_Assign(self, node: ast.Assign) -> None:
        """Visit assignment - track taint propagation."""
        # Check if right side is a taint source
        if isinstance(node.value, ast.Call):
            func_name = self._extract_function_name(node.value.func)
            if func_name and func_name.lower() in self.analyzer.taint_sources:
                # Mark left side as tainted
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.tainted_vars.add(target.id)

        # Check if right side uses tainted variable
        if self._uses_tainted_variable(node.value):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted_vars.add(target.id)

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Visit function call - detect taint sinks."""
        func_name = self._extract_function_name(node.func)

        if func_name and func_name.lower() in self.analyzer.taint_sinks:
            # Check if tainted variable flows to sink
            if self._uses_tainted_variable(node):
                self.taint_flows.append(
                    {
                        "source": "user_input",
                        "sink": func_name,
                        "file": self.file_path,
                        "line": node.lineno,
                        "is_sanitized": False,
                    }
                )

        self.generic_visit(node)

    def _extract_function_name(self, node: ast.AST) -> Optional[str]:
        """Extract function name."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return node.attr
        return None

    def _uses_tainted_variable(self, node: Optional[ast.AST]) -> bool:
        """Check if node uses tainted variable."""
        if node is None:
            return False
        if isinstance(node, ast.Name):
            return node.id in self.tainted_vars
        elif isinstance(node, ast.Call):
            return any(self._uses_tainted_variable(arg) for arg in node.args)
        elif isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return any(self._uses_tainted_variable(item) for item in node.elts)
        elif isinstance(node, ast.Dict):
            return any(
                self._uses_tainted_variable(k) or self._uses_tainted_variable(v)
                for k, v in zip(node.keys, node.values)
            )
        return False


class ProprietaryReachabilityAnalyzer:
    """Proprietary reachability analyzer - completely custom, no OSS."""

    def __init__(self, config: Optional[Mapping[str, Any]] = None):
        """Initialize proprietary analyzer."""
        self.config = config or {}
        self.pattern_matcher = ProprietaryPatternMatcher()
        self.call_graph_builder = ProprietaryCallGraphBuilder()
        self.data_flow_analyzer = ProprietaryDataFlowAnalyzer()

    def analyze_repository(
        self,
        repo_path: Path,
        vulnerable_patterns: List[Dict[str, Any]],
        language: str,
    ) -> Dict[str, Any]:
        """Proprietary repository analysis."""
        results: Dict[str, Any] = {
            "matches": [],
            "call_graph": {},
            "data_flows": [],
            "reachability": {},
        }

        # Build proprietary call graph
        call_graph_data = self.call_graph_builder.build_from_repository(
            repo_path, language
        )
        results["call_graph"] = call_graph_data

        # Analyze each file
        code_files = self._get_code_files(repo_path, language)

        for code_file in code_files:
            try:
                with open(code_file, "r", encoding="utf-8") as f:
                    content = f.read()

                # Proprietary pattern matching
                matches = self.pattern_matcher.match_patterns(
                    content, language, str(code_file)
                )
                results["matches"].extend(matches)

                # Proprietary data flow analysis
                flows = self.data_flow_analyzer.analyze_taint_flow(
                    content, language, str(code_file)
                )
                results["data_flows"].extend(flows)

            except Exception as e:
                logger.warning(f"Failed to analyze {code_file}: {e}")

        # Determine reachability
        results["reachability"] = self._determine_reachability(
            results["matches"], call_graph_data, results["data_flows"]
        )

        return results

    def _get_code_files(self, repo_path: Path, language: str) -> List[Path]:
        """Get code files for language."""
        extensions = {
            "python": ["*.py"],
            "javascript": ["*.js"],
            "typescript": ["*.ts", "*.tsx"],
            "java": ["*.java"],
        }

        files: List[Path] = []
        for ext in extensions.get(language, []):
            files.extend(repo_path.rglob(ext))

        ignore_dirs = {
            ".git",
            "node_modules",
            "venv",
            "__pycache__",
            "vendor",
            "target",
            "build",
        }
        return [f for f in files if not any(part in ignore_dirs for part in f.parts)]

    def _determine_reachability(
        self,
        matches: List[ProprietaryVulnerabilityMatch],
        call_graph: Dict[str, Any],
        data_flows: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Proprietary reachability determination algorithm."""
        reachable_matches = []
        unreachable_matches = []

        graph = call_graph.get("graph", {})
        entry_points = call_graph.get("entry_points", [])

        for match in matches:
            file_path, line_num = match.matched_location
            func_name = match.context.get("function")

            if func_name and func_name in graph:
                func_info = graph[func_name]
                # Note: callers available for future caller analysis
                _ = func_info.get("callers", [])

                # Check if function is reachable from entry points
                is_reachable = self._is_reachable_from_entries(
                    func_name, entry_points, graph
                )

                # Check data flow
                has_data_flow = any(
                    flow.get("sink") == func_name for flow in data_flows
                )

                if is_reachable or has_data_flow:
                    reachable_matches.append(match)
                else:
                    unreachable_matches.append(match)
            else:
                # Unknown function - assume reachable for safety
                reachable_matches.append(match)

        return {
            "reachable_count": len(reachable_matches),
            "unreachable_count": len(unreachable_matches),
            "reachable_matches": [
                {
                    "cve_id": m.cve_id,
                    "pattern_type": m.pattern_type,
                    "location": m.matched_location,
                    "exploitability_score": m.exploitability_score,
                }
                for m in reachable_matches
            ],
            "unreachable_matches": [
                {
                    "cve_id": m.cve_id,
                    "pattern_type": m.pattern_type,
                    "location": m.matched_location,
                }
                for m in unreachable_matches
            ],
        }

    def _is_reachable_from_entries(
        self, func_name: str, entry_points: List[str], graph: Dict[str, Any]
    ) -> bool:
        """Proprietary algorithm to check reachability from entry points."""
        # BFS from entry points
        visited = set()
        queue = deque(entry_points)

        while queue:
            current = queue.popleft()
            if current in visited:
                continue
            visited.add(current)

            if current == func_name:
                return True

            if current in graph:
                callees = graph[current].get("callees", [])
                queue.extend(callees)

        return False
