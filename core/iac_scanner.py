"""
Enterprise-grade IaC scanning module with checkov and tfsec integration.

This module provides real scanning capabilities for Infrastructure-as-Code files
using industry-standard tools (checkov, tfsec) with proper async handling,
error recovery, and result normalization.
"""

import asyncio
import json
import logging
import os
import shutil
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from uuid import uuid4

from core.iac_models import IaCFinding, IaCFindingStatus, IaCProvider
from core.safe_path_ops import (
    TRUSTED_ROOT,
    PathContainmentError,
    safe_isdir,
    safe_isfile,
    safe_iterdir,
    safe_read_text,
    safe_tempdir,
    safe_write_text,
)

logger = logging.getLogger(__name__)


class ScannerType(str, Enum):
    """Supported IaC scanner types."""

    CHECKOV = "checkov"
    TFSEC = "tfsec"


class ScanStatus(str, Enum):
    """Scan job status."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class ScanResult:
    """Result of an IaC scan."""

    scan_id: str
    status: ScanStatus
    scanner: ScannerType
    provider: IaCProvider
    target_path: str
    findings: List[IaCFinding] = field(default_factory=list)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    error_message: Optional[str] = None
    raw_output: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API responses."""
        return {
            "scan_id": self.scan_id,
            "status": self.status.value,
            "scanner": self.scanner.value,
            "provider": self.provider.value,
            "target_path": self.target_path,
            "findings_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": (
                self.completed_at.isoformat() if self.completed_at else None
            ),
            "duration_seconds": self.duration_seconds,
            "error_message": self.error_message,
            "metadata": self.metadata,
        }


# Hardcoded paths under TRUSTED_ROOT - NOT configurable via environment variables
# This is intentional to prevent CodeQL py/path-injection alerts
# All paths MUST be under TRUSTED_ROOT (/var/fixops) for security
SCAN_BASE_PATH = TRUSTED_ROOT + "/scans"
# Custom policies directory is hardcoded under TRUSTED_ROOT to prevent path injection
# Operators can place custom checkov policies in this directory
CUSTOM_POLICIES_PATH = TRUSTED_ROOT + "/policies"


@dataclass
class ScannerConfig:
    """Configuration for IaC scanners."""

    checkov_path: str = "checkov"
    tfsec_path: str = "tfsec"
    timeout_seconds: int = 300
    max_file_size_mb: int = 50
    skip_download: bool = False
    # custom_policies_dir is hardcoded to CUSTOM_POLICIES_PATH - NOT configurable
    # Operators can place custom checkov policies in /var/fixops/policies
    custom_policies_dir: str = CUSTOM_POLICIES_PATH
    excluded_checks: List[str] = field(default_factory=list)
    soft_fail: bool = False
    # base_path is hardcoded to SCAN_BASE_PATH (under TRUSTED_ROOT) - NOT configurable
    # This prevents CodeQL py/path-injection alerts by ensuring the base is a constant
    base_path: str = SCAN_BASE_PATH

    @classmethod
    def from_env(cls) -> "ScannerConfig":
        """Create config from environment variables."""
        # Note: base_path and custom_policies_dir are intentionally NOT configurable
        # via environment variables to prevent CodeQL py/path-injection alerts
        return cls(
            checkov_path=os.getenv("FIXOPS_CHECKOV_PATH", "checkov"),
            tfsec_path=os.getenv("FIXOPS_TFSEC_PATH", "tfsec"),
            timeout_seconds=int(os.getenv("FIXOPS_SCAN_TIMEOUT", "300")),
            max_file_size_mb=int(os.getenv("FIXOPS_MAX_FILE_SIZE_MB", "50")),
            skip_download=os.getenv("FIXOPS_SKIP_DOWNLOAD", "false").lower() == "true",
            # custom_policies_dir uses hardcoded constant, not environment variable
            custom_policies_dir=CUSTOM_POLICIES_PATH,
            excluded_checks=(
                os.getenv("FIXOPS_EXCLUDED_CHECKS", "").split(",")
                if os.getenv("FIXOPS_EXCLUDED_CHECKS")
                else []
            ),
            soft_fail=os.getenv("FIXOPS_SOFT_FAIL", "false").lower() == "true",
            # base_path uses hardcoded constant, not environment variable
            base_path=SCAN_BASE_PATH,
        )


class IaCScanner:
    """
    Enterprise IaC scanner with checkov and tfsec integration.

    Features:
    - Async scanning with proper timeout handling
    - Support for multiple IaC providers (Terraform, CloudFormation, Kubernetes, etc.)
    - Result normalization to unified finding format
    - Path traversal protection
    - Configurable via environment variables
    """

    def __init__(self, config: Optional[ScannerConfig] = None):
        """Initialize the scanner with configuration."""
        self.config = config or ScannerConfig.from_env()
        self._checkov_available: Optional[bool] = None
        self._tfsec_available: Optional[bool] = None

    def _verify_containment(self, path: Path) -> str:
        """
        Verify that a path is contained within the base directory.

        This is a CodeQL-recognized sanitizer pattern using two-stage containment:
        1. Verify base_path is under TRUSTED_ROOT constant (untaints base_path)
        2. Verify candidate path is under base_path

        Args:
            path: Path to verify

        Returns:
            The verified path as a string (safe to use in file operations)

        Raises:
            ValueError: If path escapes the base directory
        """
        trusted_root = os.path.realpath(TRUSTED_ROOT)
        base = os.path.realpath(self.config.base_path)
        candidate = os.path.realpath(str(path))
        if os.path.commonpath([trusted_root, base]) != trusted_root:
            raise ValueError(f"Base path escapes trusted root: {self.config.base_path}")
        if os.path.commonpath([base, candidate]) != base:
            raise ValueError(f"Path escapes base directory: {path}")
        return candidate

    def _is_checkov_available(self) -> bool:
        """Check if checkov is installed and available."""
        if self._checkov_available is None:
            self._checkov_available = shutil.which(self.config.checkov_path) is not None
        return self._checkov_available

    def _is_tfsec_available(self) -> bool:
        """Check if tfsec is installed and available."""
        if self._tfsec_available is None:
            self._tfsec_available = shutil.which(self.config.tfsec_path) is not None
        return self._tfsec_available

    def get_available_scanners(self) -> List[ScannerType]:
        """Get list of available scanners."""
        available = []
        if self._is_checkov_available():
            available.append(ScannerType.CHECKOV)
        if self._is_tfsec_available():
            available.append(ScannerType.TFSEC)
        return available

    def _detect_provider(self, target_path: str) -> IaCProvider:
        """Auto-detect IaC provider from file contents or extension."""
        path_str = target_path
        base_path = self.config.base_path

        # Use safe sink wrappers which have inline sanitization for CodeQL
        try:
            if safe_isfile(path_str, base_path):
                suffix = os.path.splitext(path_str)[1].lower()
                name = os.path.basename(path_str).lower()

                # Check for Helm Chart.yaml first (before other YAML checks)
                if name == "chart.yaml":
                    return IaCProvider.HELM
                elif suffix in (".tf", ".tfvars"):
                    return IaCProvider.TERRAFORM
                elif suffix in (".yaml", ".yml"):
                    # Read file using safe wrapper
                    content = safe_read_text(path_str, base_path, max_bytes=1000)
                    if "AWSTemplateFormatVersion" in content or "Resources:" in content:
                        return IaCProvider.CLOUDFORMATION
                    elif "apiVersion:" in content and "kind:" in content:
                        return IaCProvider.KUBERNETES
                    elif "hosts:" in content or "tasks:" in content:
                        return IaCProvider.ANSIBLE
                elif suffix == ".json":
                    # Read file using safe wrapper
                    content = safe_read_text(path_str, base_path, max_bytes=1000)
                    if "AWSTemplateFormatVersion" in content:
                        return IaCProvider.CLOUDFORMATION

            elif safe_isdir(path_str, base_path):
                # Iterate directory using safe wrapper
                for child_path in safe_iterdir(path_str, base_path):
                    child_name = os.path.basename(child_path)
                    child_suffix = os.path.splitext(child_name)[1].lower()
                    if child_suffix == ".tf":
                        return IaCProvider.TERRAFORM
                    elif child_name.lower() == "chart.yaml":
                        return IaCProvider.HELM

        except PathContainmentError:
            raise ValueError(f"Path escapes base directory: {target_path}")

        return IaCProvider.TERRAFORM

    def _map_severity(self, severity: str) -> str:
        """Map scanner-specific severity to normalized severity."""
        severity_lower = severity.lower()
        if severity_lower in ("critical", "high"):
            return "high"
        elif severity_lower in ("medium", "moderate"):
            return "medium"
        elif severity_lower in ("low", "info", "informational"):
            return "low"
        return "medium"

    def _parse_checkov_output(
        self, output: str, provider: IaCProvider, target_path: str
    ) -> List[IaCFinding]:
        """Parse checkov JSON output into normalized findings."""
        findings: List[IaCFinding] = []

        try:
            data = json.loads(output)
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse checkov output as JSON: {e}")
            return findings

        results = data.get("results", {})
        failed_checks = results.get("failed_checks", [])

        for check in failed_checks:
            finding = IaCFinding(
                id=str(uuid4()),
                provider=provider,
                status=IaCFindingStatus.OPEN,
                severity=self._map_severity(
                    check.get("check_result", {}).get("result", "FAILED")
                ),
                title=check.get("check_id", "Unknown Check"),
                description=check.get("check", {}).get(
                    "name", check.get("check_id", "Unknown")
                ),
                file_path=check.get("file_path", target_path),
                line_number=check.get("file_line_range", [0, 0])[0],
                resource_type=check.get("resource", "unknown"),
                resource_name=check.get(
                    "resource_address", check.get("resource", "unknown")
                ),
                rule_id=check.get("check_id", "UNKNOWN"),
                remediation=check.get("guideline", None),
                metadata={
                    "scanner": "checkov",
                    "check_type": check.get("check_type", "unknown"),
                    "bc_check_id": check.get("bc_check_id"),
                    "evaluations": check.get("evaluations"),
                    "file_line_range": check.get("file_line_range"),
                },
            )
            findings.append(finding)

        return findings

    def _parse_tfsec_output(
        self, output: str, provider: IaCProvider, target_path: str
    ) -> List[IaCFinding]:
        """Parse tfsec JSON output into normalized findings."""
        findings: List[IaCFinding] = []

        try:
            data = json.loads(output)
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse tfsec output as JSON: {e}")
            return findings

        results = data.get("results", [])
        if results is None:
            results = []

        for result in results:
            location = result.get("location", {})
            finding = IaCFinding(
                id=str(uuid4()),
                provider=provider,
                status=IaCFindingStatus.OPEN,
                severity=self._map_severity(result.get("severity", "MEDIUM")),
                title=result.get("rule_id", "Unknown Rule"),
                description=result.get(
                    "description", result.get("rule_description", "Unknown")
                ),
                file_path=location.get("filename", target_path),
                line_number=location.get("start_line", 0),
                resource_type=result.get("resource", "unknown"),
                resource_name=result.get("resource", "unknown"),
                rule_id=result.get("rule_id", result.get("long_id", "UNKNOWN")),
                remediation=result.get("resolution", None),
                metadata={
                    "scanner": "tfsec",
                    "rule_provider": result.get("rule_provider"),
                    "rule_service": result.get("rule_service"),
                    "impact": result.get("impact"),
                    "links": result.get("links", []),
                    "end_line": location.get("end_line"),
                },
            )
            findings.append(finding)

        return findings

    async def _run_checkov(
        self,
        target_path: str,
        provider: IaCProvider,
    ) -> Tuple[List[IaCFinding], str, Optional[str]]:
        """Run checkov scanner asynchronously."""
        # Three-stage containment check (CodeQL requires inline check before sink)
        trusted_root = os.path.realpath(TRUSTED_ROOT)
        base = os.path.realpath(self.config.base_path)
        verified_path = os.path.realpath(str(target_path))
        # Helper for startswith-based containment check (CodeQL-recognized pattern)
        trusted_prefix = (
            trusted_root if trusted_root.endswith(os.sep) else trusted_root + os.sep
        )
        base_prefix = base if base.endswith(os.sep) else base + os.sep
        # Stage 1: candidate must be under trusted_root (de-taints for CodeQL)
        if not (
            verified_path == trusted_root or verified_path.startswith(trusted_prefix)
        ):
            raise ValueError(f"Path escapes trusted root: {target_path}")
        # Stage 2: base must be under trusted_root
        if not (base == trusted_root or base.startswith(trusted_prefix)):
            raise ValueError(f"Base path escapes trusted root: {self.config.base_path}")
        # Stage 3: candidate must be under base
        if not (verified_path == base or verified_path.startswith(base_prefix)):
            raise ValueError(f"Path escapes base directory: {target_path}")

        # Check if path is directory (verified_path is now de-tainted)
        is_dir = os.path.isdir(verified_path)

        cmd = [
            self.config.checkov_path,
            "-d" if is_dir else "-f",
            verified_path,
            "--output",
            "json",
            "--compact",
        ]

        if self.config.skip_download:
            cmd.append("--skip-download")

        # Only use custom policies if the hardcoded policies directory exists
        # This allows operators to optionally place policies in /var/fixops/policies/
        if self.config.custom_policies_dir and os.path.isdir(
            self.config.custom_policies_dir
        ):
            cmd.extend(["--external-checks-dir", self.config.custom_policies_dir])

        for check in self.config.excluded_checks:
            if check.strip():
                cmd.extend(["--skip-check", check.strip()])

        framework_map = {
            IaCProvider.TERRAFORM: "terraform",
            IaCProvider.CLOUDFORMATION: "cloudformation",
            IaCProvider.KUBERNETES: "kubernetes",
            IaCProvider.ANSIBLE: "ansible",
            IaCProvider.HELM: "helm",
        }
        if provider in framework_map:
            cmd.extend(["--framework", framework_map[provider]])

        logger.info(f"Running checkov: {' '.join(cmd)}")

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=self.config.timeout_seconds
            )

            output = stdout.decode("utf-8", errors="replace")
            error_output = stderr.decode("utf-8", errors="replace")

            if process.returncode not in (0, 1):
                return (
                    [],
                    output,
                    f"Checkov exited with code {process.returncode}: {error_output}",
                )

            findings = self._parse_checkov_output(output, provider, str(target_path))
            return findings, output, None

        except asyncio.TimeoutError:
            return (
                [],
                "",
                f"Checkov scan timed out after {self.config.timeout_seconds} seconds",
            )
        except FileNotFoundError:
            return [], "", "Checkov is not installed or not in PATH"
        except Exception as e:
            return [], "", f"Checkov scan failed: {str(e)}"

    async def _run_tfsec(
        self,
        target_path: str,
        provider: IaCProvider,
    ) -> Tuple[List[IaCFinding], str, Optional[str]]:
        """Run tfsec scanner asynchronously."""
        if provider != IaCProvider.TERRAFORM:
            return [], "", "tfsec only supports Terraform files"

        # Three-stage containment check (CodeQL requires inline check before sink)
        trusted_root = os.path.realpath(TRUSTED_ROOT)
        base = os.path.realpath(self.config.base_path)
        verified_path = os.path.realpath(str(target_path))
        # Helper for startswith-based containment check (CodeQL-recognized pattern)
        trusted_prefix = (
            trusted_root if trusted_root.endswith(os.sep) else trusted_root + os.sep
        )
        base_prefix = base if base.endswith(os.sep) else base + os.sep
        # Stage 1: candidate must be under trusted_root (de-taints for CodeQL)
        if not (
            verified_path == trusted_root or verified_path.startswith(trusted_prefix)
        ):
            raise ValueError(f"Path escapes trusted root: {target_path}")
        # Stage 2: base must be under trusted_root
        if not (base == trusted_root or base.startswith(trusted_prefix)):
            raise ValueError(f"Base path escapes trusted root: {self.config.base_path}")
        # Stage 3: candidate must be under base
        if not (verified_path == base or verified_path.startswith(base_prefix)):
            raise ValueError(f"Path escapes base directory: {target_path}")

        cmd = [
            self.config.tfsec_path,
            verified_path,
            "--format",
            "json",
        ]

        if self.config.soft_fail:
            cmd.append("--soft-fail")

        for check in self.config.excluded_checks:
            if check.strip():
                cmd.extend(["--exclude", check.strip()])

        logger.info(f"Running tfsec: {' '.join(cmd)}")

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=self.config.timeout_seconds
            )

            output = stdout.decode("utf-8", errors="replace")
            error_output = stderr.decode("utf-8", errors="replace")

            if process.returncode not in (0, 1):
                return (
                    [],
                    output,
                    f"tfsec exited with code {process.returncode}: {error_output}",
                )

            findings = self._parse_tfsec_output(output, provider, str(target_path))
            return findings, output, None

        except asyncio.TimeoutError:
            return (
                [],
                "",
                f"tfsec scan timed out after {self.config.timeout_seconds} seconds",
            )
        except FileNotFoundError:
            return [], "", "tfsec is not installed or not in PATH"
        except Exception as e:
            return [], "", f"tfsec scan failed: {str(e)}"

    async def scan_content(
        self,
        content: str,
        filename: str,
        provider: Optional[IaCProvider] = None,
        scanner: Optional[ScannerType] = None,
    ) -> ScanResult:
        """
        Scan IaC content provided as a string.

        Creates a temporary file under the base path, scans it, and cleans up.
        This ensures the temp file passes containment checks.

        Args:
            content: IaC file content as string
            filename: Original filename (used for provider detection)
            provider: IaC provider type (auto-detected if not specified)
            scanner: Scanner to use (auto-selected if not specified)

        Returns:
            ScanResult with findings and metadata
        """
        # Generate a safe filename based on extension only - no user input in path
        # Extract extension from filename using os.path.splitext (CodeQL-safe)
        _, ext = os.path.splitext(os.path.basename(filename))
        # Allowlist of valid IaC extensions
        valid_extensions = {".tf", ".tfvars", ".yaml", ".yml", ".json", ".j2", ".tpl"}
        if ext.lower() not in valid_extensions:
            ext = ".tf"  # Default to terraform
        # Generate completely safe filename with no user input
        safe_filename = f"content{ext}"

        # Use safe_tempdir wrapper which has inline sanitization for CodeQL
        # This ensures the temp directory is created under a validated base path
        base_path = self.config.base_path
        with safe_tempdir(base_path) as temp_dir:
            # Use os.path.join instead of Path() to avoid CodeQL sink
            temp_file = os.path.join(temp_dir, safe_filename)
            # Use safe_write_text wrapper which has inline sanitization for CodeQL
            safe_write_text(temp_file, base_path, content)

            scan_id = str(uuid4())
            started_at = datetime.now()

            try:
                # Containment check will pass since temp_dir is under base_path
                detected_provider = provider or self._detect_provider(temp_file)
                selected_scanner = scanner

                if not selected_scanner:
                    available = self.get_available_scanners()
                    if not available:
                        return ScanResult(
                            scan_id=scan_id,
                            status=ScanStatus.FAILED,
                            scanner=ScannerType.CHECKOV,
                            provider=detected_provider,
                            target_path=filename,
                            started_at=started_at,
                            completed_at=datetime.now(),
                            error_message="No IaC scanner available",
                        )
                    selected_scanner = available[0]

                if selected_scanner == ScannerType.CHECKOV:
                    findings, raw_output, error = await self._run_checkov(
                        temp_file, detected_provider
                    )
                else:
                    findings, raw_output, error = await self._run_tfsec(
                        temp_file, detected_provider
                    )

                completed_at = datetime.now()
                duration = (completed_at - started_at).total_seconds()

                if error:
                    return ScanResult(
                        scan_id=scan_id,
                        status=ScanStatus.FAILED,
                        scanner=selected_scanner,
                        provider=detected_provider,
                        target_path=filename,
                        started_at=started_at,
                        completed_at=completed_at,
                        duration_seconds=duration,
                        error_message=error,
                        raw_output=raw_output,
                    )

                for finding in findings:
                    finding.file_path = filename

                return ScanResult(
                    scan_id=scan_id,
                    status=ScanStatus.COMPLETED,
                    scanner=selected_scanner,
                    provider=detected_provider,
                    target_path=filename,
                    findings=findings,
                    started_at=started_at,
                    completed_at=completed_at,
                    duration_seconds=duration,
                    raw_output=raw_output,
                )
            except Exception as e:
                return ScanResult(
                    scan_id=scan_id,
                    status=ScanStatus.FAILED,
                    scanner=scanner or ScannerType.CHECKOV,
                    provider=provider or IaCProvider.TERRAFORM,
                    target_path=filename,
                    started_at=started_at,
                    completed_at=datetime.now(),
                    error_message=str(e),
                )


_default_scanner: Optional[IaCScanner] = None


def get_iac_scanner() -> IaCScanner:
    """Get the default IaC scanner instance."""
    global _default_scanner
    if _default_scanner is None:
        _default_scanner = IaCScanner()
    return _default_scanner
