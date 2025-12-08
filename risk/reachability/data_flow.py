"""Data flow analysis for exploitability verification."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

logger = logging.getLogger(__name__)


@dataclass
class DataFlowPath:
    """Represents a data flow path."""
    
    source: str  # Source location
    sink: str  # Sink location
    path: List[str]  # Path from source to sink
    is_tainted: bool  # Whether data is tainted
    sanitization_points: List[str] = field(default_factory=list)


@dataclass
class DataFlowResult:
    """Result of data flow analysis."""
    
    has_path: bool
    paths: List[DataFlowPath] = field(default_factory=list)
    max_depth: int = 0
    sanitization_found: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def get_path_for_function(self, func_name: str) -> Optional[List[str]]:
        """Get data flow path for a specific function."""
        for path in self.paths:
            if func_name in path.path:
                return path.path
        return None


class DataFlowAnalyzer:
    """Analyze data flow for exploitability verification."""
    
    def __init__(self, config: Optional[Mapping[str, Any]] = None):
        """Initialize data flow analyzer.
        
        Parameters
        ----------
        config
            Configuration for data flow analysis.
        """
        self.config = config or {}
        self.max_path_length = self.config.get("max_path_length", 20)
        self.enable_taint_analysis = self.config.get("enable_taint_analysis", True)
    
    def analyze_data_flow(
        self,
        repo_path: Path,
        vulnerable_pattern: Any,  # VulnerablePattern
        call_graph: Dict[str, Any],
    ) -> DataFlowResult:
        """Analyze data flow for vulnerable pattern.
        
        Parameters
        ----------
        repo_path
            Path to repository.
        vulnerable_pattern
            Vulnerable pattern to analyze.
        call_graph
            Call graph for the repository.
        
        Returns
        -------
        DataFlowResult
            Data flow analysis result.
        """
        # Simplified implementation
        # In production, this would use proper taint analysis
        
        paths: List[DataFlowPath] = []
        
        # For SQL injection, check if user input flows to SQL queries
        if vulnerable_pattern.pattern_type == "sql_injection":
            paths = self._analyze_sql_injection_flow(
                repo_path, vulnerable_pattern, call_graph
            )
        elif vulnerable_pattern.pattern_type == "command_injection":
            paths = self._analyze_command_injection_flow(
                repo_path, vulnerable_pattern, call_graph
            )
        
        return DataFlowResult(
            has_path=len(paths) > 0,
            paths=paths,
            max_depth=max(len(p.path) for p in paths) if paths else 0,
            sanitization_found=any(p.sanitization_points for p in paths),
        )
    
    def _analyze_sql_injection_flow(
        self,
        repo_path: Path,
        pattern: Any,
        call_graph: Dict[str, Any],
    ) -> List[DataFlowPath]:
        """Analyze data flow for SQL injection."""
        paths = []
        
        # Find SQL query functions
        sql_functions = ["executeQuery", "prepareStatement", "query", "execute"]
        
        for func_name in sql_functions:
            if func_name in call_graph:
                # Check if user input flows to this function
                # Simplified: in production, use proper taint analysis
                path = DataFlowPath(
                    source="user_input",
                    sink=func_name,
                    path=["user_input", func_name],
                    is_tainted=True,
                )
                paths.append(path)
        
        return paths
    
    def _analyze_command_injection_flow(
        self,
        repo_path: Path,
        pattern: Any,
        call_graph: Dict[str, Any],
    ) -> List[DataFlowPath]:
        """Analyze data flow for command injection."""
        paths = []
        
        # Find command execution functions
        cmd_functions = ["exec", "system", "popen", "subprocess"]
        
        for func_name in cmd_functions:
            if func_name in call_graph:
                path = DataFlowPath(
                    source="user_input",
                    sink=func_name,
                    path=["user_input", func_name],
                    is_tainted=True,
                )
                paths.append(path)
        
        return paths
