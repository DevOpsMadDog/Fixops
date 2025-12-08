"""Call graph construction for reachability analysis."""

from __future__ import annotations

import ast
import logging
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Set

logger = logging.getLogger(__name__)


class CallGraphBuilder:
    """Build call graphs from source code for reachability analysis."""
    
    def __init__(self, config: Optional[Mapping[str, Any]] = None):
        """Initialize call graph builder.
        
        Parameters
        ----------
        config
            Configuration for call graph construction.
        """
        self.config = config or {}
        self.max_depth = self.config.get("max_depth", 50)
        self.include_imports = self.config.get("include_imports", True)
    
    def build_call_graph(
        self, repo_path: Path, language_distribution: Optional[Dict[str, int]] = None
    ) -> Dict[str, Any]:
        """Build call graph for repository.
        
        Parameters
        ----------
        repo_path
            Path to repository.
        language_distribution
            Distribution of languages in repository.
        
        Returns
        -------
        Dict[str, Any]
            Call graph representation.
        """
        if language_distribution is None:
            language_distribution = {}
        
        # Determine primary language
        primary_lang = (
            max(language_distribution.items(), key=lambda x: x[1])[0]
            if language_distribution
            else "Python"
        )
        
        call_graph: Dict[str, Any] = {}
        
        if primary_lang == "Python":
            call_graph = self._build_python_call_graph(repo_path)
        elif primary_lang in ("JavaScript", "TypeScript"):
            call_graph = self._build_javascript_call_graph(repo_path)
        elif primary_lang == "Java":
            call_graph = self._build_java_call_graph(repo_path)
        else:
            logger.warning(f"Call graph building not yet implemented for {primary_lang}")
            call_graph = self._build_generic_call_graph(repo_path)
        
        return call_graph
    
    def _build_python_call_graph(self, repo_path: Path) -> Dict[str, Any]:
        """Build call graph for Python code."""
        call_graph: Dict[str, Any] = {}
        
        # Find all Python files
        python_files = list(repo_path.rglob("*.py"))
        
        # Ignore common directories
        ignore_dirs = {".git", "node_modules", "venv", ".venv", "__pycache__", "vendor"}
        python_files = [
            f
            for f in python_files
            if not any(part in ignore_dirs for part in f.parts)
        ]
        
        for py_file in python_files:
            try:
                with open(py_file, "r", encoding="utf-8") as f:
                    content = f.read()
                
                tree = ast.parse(content, filename=str(py_file))
                visitor = PythonCallGraphVisitor(str(py_file), call_graph)
                visitor.visit(tree)
            except Exception as e:
                logger.warning(f"Failed to parse {py_file}: {e}")
        
        return call_graph
    
    def _build_javascript_call_graph(self, repo_path: Path) -> Dict[str, Any]:
        """Build call graph for JavaScript/TypeScript code."""
        # Simplified implementation - in production, use a proper JS parser
        call_graph: Dict[str, Any] = {}
        logger.info("JavaScript call graph building - simplified implementation")
        return call_graph
    
    def _build_java_call_graph(self, repo_path: Path) -> Dict[str, Any]:
        """Build call graph for Java code."""
        # Simplified implementation - in production, use a proper Java parser
        call_graph: Dict[str, Any] = {}
        logger.info("Java call graph building - simplified implementation")
        return call_graph
    
    def _build_generic_call_graph(self, repo_path: Path) -> Dict[str, Any]:
        """Build generic call graph using heuristics."""
        call_graph: Dict[str, Any] = {}
        logger.info("Generic call graph building - heuristic-based")
        return call_graph


class PythonCallGraphVisitor(ast.NodeVisitor):
    """AST visitor for building Python call graphs."""
    
    def __init__(self, file_path: str, call_graph: Dict[str, Any]):
        """Initialize visitor.
        
        Parameters
        ----------
        file_path
            Path to Python file being analyzed.
        call_graph
            Call graph dictionary to populate.
        """
        self.file_path = file_path
        self.call_graph = call_graph
        self.current_function: Optional[str] = None
        self.current_class: Optional[str] = None
    
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Visit function definition."""
        func_name = node.name
        full_name = (
            f"{self.current_class}.{func_name}"
            if self.current_class
            else func_name
        )
        
        # Store function info
        if full_name not in self.call_graph:
            self.call_graph[full_name] = {
                "file": self.file_path,
                "line": node.lineno,
                "callers": [],
                "callees": [],
                "is_public": not func_name.startswith("_"),
                "is_exported": False,  # Would need to check __all__ or exports
            }
        
        # Track current function
        old_function = self.current_function
        self.current_function = full_name
        
        # Visit function body to find calls
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
            return
        
        # Extract called function name
        if isinstance(node.func, ast.Name):
            called_func = node.func.id
        elif isinstance(node.func, ast.Attribute):
            called_func = node.func.attr
        else:
            return
        
        # Add to call graph
        if called_func not in self.call_graph:
            self.call_graph[called_func] = {
                "file": self.file_path,
                "line": node.lineno,
                "callers": [],
                "callees": [],
                "is_public": True,
                "is_exported": False,
            }
        
        # Add caller relationship
        caller_info = {
            "function": self.current_function,
            "file": self.file_path,
            "line": node.lineno,
            "parent": None,  # Would need more analysis to determine
        }
        
        if caller_info not in self.call_graph[called_func]["callers"]:
            self.call_graph[called_func]["callers"].append(caller_info)
        
        # Add callee relationship
        if self.current_function in self.call_graph:
            callee_info = {
                "function": called_func,
                "file": self.file_path,
                "line": node.lineno,
            }
            if callee_info not in self.call_graph[self.current_function]["callees"]:
                self.call_graph[self.current_function]["callees"].append(callee_info)
