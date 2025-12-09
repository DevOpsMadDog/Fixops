"""FixOps IAST (Interactive Application Security Testing) Engine

Proprietary runtime analysis that instruments applications to detect
vulnerabilities during execution.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Mapping, Optional, Set

logger = logging.getLogger(__name__)


class VulnerabilityType(Enum):
    """Vulnerability types detected by IAST."""

    SQL_INJECTION = "sql_injection"
    COMMAND_INJECTION = "command_injection"
    XSS = "xss"
    PATH_TRAVERSAL = "path_traversal"
    DESERIALIZATION = "deserialization"
    AUTHENTICATION_BYPASS = "authentication_bypass"
    AUTHORIZATION_BYPASS = "authorization_bypass"
    CRYPTOGRAPHIC_WEAKNESS = "cryptographic_weakness"
    INSECURE_CONFIGURATION = "insecure_configuration"


@dataclass
class IASTFinding:
    """IAST finding representation."""

    vulnerability_type: VulnerabilityType
    severity: str  # critical, high, medium, low
    source_file: str
    line_number: int
    function_name: str
    request_id: Optional[str] = None
    user_id: Optional[str] = None
    stack_trace: List[str] = field(default_factory=list)
    request_data: Dict[str, Any] = field(default_factory=dict)
    response_data: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    confidence: float = 1.0  # 0.0 to 1.0


@dataclass
class IASTConfig:
    """IAST configuration."""

    enabled: bool = True
    instrumentation_mode: str = "selective"  # selective, full, minimal
    languages: List[str] = field(
        default_factory=lambda: ["python", "javascript", "java"]
    )
    vulnerability_types: List[VulnerabilityType] = field(
        default_factory=lambda: list(VulnerabilityType)
    )
    sampling_rate: float = 1.0  # 0.0 to 1.0
    max_findings_per_request: int = 10
    enable_stack_trace: bool = True
    enable_request_capture: bool = True
    enable_response_capture: bool = False  # Privacy concern


class IASTInstrumentation:
    """Proprietary IAST instrumentation engine."""

    def __init__(self, config: IASTConfig):
        """Initialize IAST instrumentation."""
        self.config = config
        self.instrumented_functions: Set[str] = set()
        self.findings: List[IASTFinding] = []
        self.lock = threading.Lock()

    def instrument_function(
        self, module_name: str, function_name: str, function_obj: Any
    ) -> Any:
        """Instrument a function for IAST monitoring."""
        if not self.config.enabled:
            return function_obj

        full_name = f"{module_name}.{function_name}"

        if full_name in self.instrumented_functions:
            return function_obj

        # Create instrumented wrapper
        def instrumented_wrapper(*args, **kwargs):
            """Instrumented function wrapper."""
            start_time = time.time()
            request_id = self._get_request_id()

            try:
                # Execute original function
                result = function_obj(*args, **kwargs)

                # Analyze for vulnerabilities
                self._analyze_execution(full_name, args, kwargs, result, request_id)

                return result

            except Exception as e:
                # Analyze exception for vulnerabilities
                self._analyze_exception(full_name, e, request_id)
                raise

        self.instrumented_functions.add(full_name)
        return instrumented_wrapper

    def _get_request_id(self) -> Optional[str]:
        """Get current request ID from context."""
        # In production, this would extract from request context
        import uuid

        return str(uuid.uuid4())

    def _analyze_execution(
        self,
        function_name: str,
        args: tuple,
        kwargs: dict,
        result: Any,
        request_id: Optional[str],
    ) -> None:
        """Analyze function execution for vulnerabilities."""
        # Proprietary vulnerability detection logic

        # Check for SQL injection patterns
        if self._detect_sql_injection(function_name, args, kwargs):
            self._record_finding(
                VulnerabilityType.SQL_INJECTION,
                function_name,
                severity="high",
                request_id=request_id,
            )

        # Check for command injection
        if self._detect_command_injection(function_name, args, kwargs):
            self._record_finding(
                VulnerabilityType.COMMAND_INJECTION,
                function_name,
                severity="critical",
                request_id=request_id,
            )

        # Check for XSS
        if self._detect_xss(function_name, args, kwargs, result):
            self._record_finding(
                VulnerabilityType.XSS,
                function_name,
                severity="high",
                request_id=request_id,
            )

        # Check for path traversal
        if self._detect_path_traversal(function_name, args, kwargs):
            self._record_finding(
                VulnerabilityType.PATH_TRAVERSAL,
                function_name,
                severity="high",
                request_id=request_id,
            )

    def _detect_sql_injection(
        self, function_name: str, args: tuple, kwargs: dict
    ) -> bool:
        """Proprietary SQL injection detection."""
        sql_keywords = ["SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "UNION"]
        dangerous_functions = ["execute", "executemany", "query", "executeQuery"]

        if not any(df in function_name.lower() for df in dangerous_functions):
            return False

        # Check arguments for SQL keywords
        for arg in list(args) + list(kwargs.values()):
            if isinstance(arg, str):
                arg_upper = arg.upper()
                if any(keyword in arg_upper for keyword in sql_keywords):
                    # Check for user input patterns
                    if any(
                        indicator in str(arg).lower()
                        for indicator in ["request", "input", "param", "query"]
                    ):
                        return True

        return False

    def _detect_command_injection(
        self, function_name: str, args: tuple, kwargs: dict
    ) -> bool:
        """Proprietary command injection detection."""
        dangerous_functions = [
            "system",
            "exec",
            "popen",
            "subprocess.call",
            "subprocess.run",
        ]

        if not any(df in function_name.lower() for df in dangerous_functions):
            return False

        # Check for shell=True or user input
        for arg in list(args) + list(kwargs.values()):
            if isinstance(arg, (str, dict)):
                arg_str = str(arg).lower()
                if "shell=true" in arg_str or any(
                    indicator in arg_str
                    for indicator in ["request", "input", "param", "user_input"]
                ):
                    return True

        return False

    def _detect_xss(
        self, function_name: str, args: tuple, kwargs: dict, result: Any
    ) -> bool:
        """Proprietary XSS detection."""
        dangerous_functions = ["innerHTML", "document.write", "eval", "render"]

        if not any(df in function_name.lower() for df in dangerous_functions):
            return False

        # Check if user input flows to dangerous function
        for arg in list(args) + list(kwargs.values()):
            if isinstance(arg, str):
                if any(
                    indicator in arg.lower()
                    for indicator in ["request", "input", "param", "query", "user"]
                ):
                    # Check for XSS patterns
                    xss_patterns = ["<script", "javascript:", "onerror=", "onclick="]
                    if any(pattern in arg.lower() for pattern in xss_patterns):
                        return True

        return False

    def _detect_path_traversal(
        self, function_name: str, args: tuple, kwargs: dict
    ) -> bool:
        """Proprietary path traversal detection."""
        file_functions = ["open", "read", "write", "file", "readfile"]

        if not any(ff in function_name.lower() for ff in file_functions):
            return False

        # Check for path traversal patterns
        for arg in list(args) + list(kwargs.values()):
            if isinstance(arg, str):
                if any(
                    pattern in arg
                    for pattern in ["../", "..\\", "..", "/etc/", "/proc/"]
                ):
                    if any(
                        indicator in arg.lower()
                        for indicator in ["request", "input", "param", "user"]
                    ):
                        return True

        return False

    def _analyze_exception(
        self, function_name: str, exception: Exception, request_id: Optional[str]
    ) -> None:
        """Analyze exceptions for vulnerabilities."""
        # Check for authentication/authorization bypass
        if (
            "unauthorized" in str(exception).lower()
            or "forbidden" in str(exception).lower()
        ):
            self._record_finding(
                VulnerabilityType.AUTHORIZATION_BYPASS,
                function_name,
                severity="high",
                request_id=request_id,
            )

    def _record_finding(
        self,
        vuln_type: VulnerabilityType,
        function_name: str,
        severity: str = "medium",
        request_id: Optional[str] = None,
    ) -> None:
        """Record IAST finding."""
        with self.lock:
            if len(self.findings) >= self.config.max_findings_per_request * 100:
                return  # Rate limiting

            finding = IASTFinding(
                vulnerability_type=vuln_type,
                severity=severity,
                source_file=function_name.split(".")[0]
                if "." in function_name
                else "unknown",
                line_number=0,  # Would be extracted from stack trace
                function_name=function_name,
                request_id=request_id,
                stack_trace=self._get_stack_trace()
                if self.config.enable_stack_trace
                else [],
            )

            self.findings.append(finding)

    def _get_stack_trace(self) -> List[str]:
        """Get current stack trace."""
        import traceback

        return traceback.format_stack()

    def get_findings(self, limit: Optional[int] = None) -> List[IASTFinding]:
        """Get IAST findings."""
        with self.lock:
            findings = self.findings.copy()
            if limit:
                findings = findings[:limit]
            return findings

    def clear_findings(self) -> None:
        """Clear findings."""
        with self.lock:
            self.findings.clear()


@dataclass
class IASTResult:
    """IAST analysis result."""

    findings: List[IASTFinding]
    total_findings: int
    findings_by_type: Dict[str, int]
    findings_by_severity: Dict[str, int]
    analysis_duration_seconds: float
    requests_analyzed: int
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class IASTAnalyzer:
    """FixOps IAST Analyzer - Proprietary runtime analysis."""

    def __init__(self, config: Optional[IASTConfig] = None):
        """Initialize IAST analyzer."""
        self.config = config or IASTConfig()
        self.instrumentation = IASTInstrumentation(self.config)
        self.start_time: Optional[float] = None
        self.request_count = 0

    def start_monitoring(self) -> None:
        """Start IAST monitoring."""
        self.config.enabled = True
        self.start_time = time.time()
        self.request_count = 0
        logger.info("IAST monitoring started")

    def stop_monitoring(self) -> None:
        """Stop IAST monitoring."""
        self.config.enabled = False
        logger.info("IAST monitoring stopped")

    def instrument_application(self, application_module: Any) -> None:
        """Instrument application for IAST monitoring."""
        # In production, this would use bytecode manipulation or AST transformation
        # For now, this is a placeholder for the instrumentation framework
        logger.info(f"Instrumenting application: {application_module}")

    def analyze_runtime(self) -> IASTResult:
        """Analyze runtime findings."""
        findings = self.instrumentation.get_findings()

        # Group by type and severity
        findings_by_type: Dict[str, int] = {}
        findings_by_severity: Dict[str, int] = {}

        for finding in findings:
            vuln_type = finding.vulnerability_type.value
            findings_by_type[vuln_type] = findings_by_type.get(vuln_type, 0) + 1

            severity = finding.severity
            findings_by_severity[severity] = findings_by_severity.get(severity, 0) + 1

        duration = time.time() - self.start_time if self.start_time else 0.0

        return IASTResult(
            findings=findings,
            total_findings=len(findings),
            findings_by_type=findings_by_type,
            findings_by_severity=findings_by_severity,
            analysis_duration_seconds=duration,
            requests_analyzed=self.request_count,
        )

    def get_instrumentation(self) -> IASTInstrumentation:
        """Get instrumentation instance."""
        return self.instrumentation
