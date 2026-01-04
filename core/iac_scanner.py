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
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from uuid import uuid4

from core.iac_models import IaCFinding, IaCFindingStatus, IaCProvider

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


@dataclass
class ScannerConfig:
    """Configuration for IaC scanners."""

    checkov_path: str = "checkov"
    tfsec_path: str = "tfsec"
    timeout_seconds: int = 300
    max_file_size_mb: int = 50
    skip_download: bool = False
    custom_policies_dir: Optional[str] = None
    excluded_checks: List[str] = field(default_factory=list)
    soft_fail: bool = False

    @classmethod
    def from_env(cls) -> "ScannerConfig":
        """Create config from environment variables."""
        return cls(
            checkov_path=os.getenv("FIXOPS_CHECKOV_PATH", "checkov"),
            tfsec_path=os.getenv("FIXOPS_TFSEC_PATH", "tfsec"),
            timeout_seconds=int(os.getenv("FIXOPS_SCAN_TIMEOUT", "300")),
            max_file_size_mb=int(os.getenv("FIXOPS_MAX_FILE_SIZE_MB", "50")),
            skip_download=os.getenv("FIXOPS_SKIP_DOWNLOAD", "false").lower() == "true",
            custom_policies_dir=os.getenv("FIXOPS_CUSTOM_POLICIES_DIR"),
            excluded_checks=(
                os.getenv("FIXOPS_EXCLUDED_CHECKS", "").split(",")
                if os.getenv("FIXOPS_EXCLUDED_CHECKS")
                else []
            ),
            soft_fail=os.getenv("FIXOPS_SOFT_FAIL", "false").lower() == "true",
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

    def _validate_path(self, target_path: str, base_path: Optional[str] = None) -> Path:
        """
        Validate and resolve the target path with security checks.

        Prevents path traversal attacks by ensuring the resolved path
        stays within the allowed base directory.
        """
        path = Path(target_path)

        if base_path:
            base = Path(base_path).resolve()
            resolved = (base / path).resolve()
            try:
                resolved.relative_to(base)
            except ValueError:
                raise ValueError(
                    f"Path traversal detected: {target_path} escapes base path {base_path}"
                )
            return resolved

        resolved = path.resolve()
        if not resolved.exists():
            raise FileNotFoundError(f"Target path does not exist: {target_path}")

        return resolved

    def _detect_provider(self, target_path: Path) -> IaCProvider:
        """Auto-detect IaC provider from file contents or extension."""
        if target_path.is_file():
            suffix = target_path.suffix.lower()
            name = target_path.name.lower()

            # Check for Helm Chart.yaml first (before other YAML checks)
            if name == "chart.yaml":
                return IaCProvider.HELM
            elif suffix in (".tf", ".tfvars"):
                return IaCProvider.TERRAFORM
            elif suffix in (".yaml", ".yml"):
                content = target_path.read_text(errors="ignore")[:1000]
                if "AWSTemplateFormatVersion" in content or "Resources:" in content:
                    return IaCProvider.CLOUDFORMATION
                elif "apiVersion:" in content and "kind:" in content:
                    return IaCProvider.KUBERNETES
                elif "hosts:" in content or "tasks:" in content:
                    return IaCProvider.ANSIBLE
            elif suffix == ".json":
                content = target_path.read_text(errors="ignore")[:1000]
                if "AWSTemplateFormatVersion" in content:
                    return IaCProvider.CLOUDFORMATION

        elif target_path.is_dir():
            for child in target_path.iterdir():
                if child.suffix == ".tf":
                    return IaCProvider.TERRAFORM
                elif child.name == "Chart.yaml":
                    return IaCProvider.HELM

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
        self, target_path: Path, provider: IaCProvider
    ) -> Tuple[List[IaCFinding], str, Optional[str]]:
        """Run checkov scanner asynchronously."""
        cmd = [
            self.config.checkov_path,
            "-d" if target_path.is_dir() else "-f",
            str(target_path),
            "--output",
            "json",
            "--compact",
        ]

        if self.config.skip_download:
            cmd.append("--skip-download")

        if self.config.custom_policies_dir:
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
        self, target_path: Path, provider: IaCProvider
    ) -> Tuple[List[IaCFinding], str, Optional[str]]:
        """Run tfsec scanner asynchronously."""
        if provider != IaCProvider.TERRAFORM:
            return [], "", "tfsec only supports Terraform files"

        cmd = [
            self.config.tfsec_path,
            str(target_path),
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

    async def scan(
        self,
        target_path: str,
        provider: Optional[IaCProvider] = None,
        scanner: Optional[ScannerType] = None,
        base_path: Optional[str] = None,
    ) -> ScanResult:
        """
        Perform an IaC security scan.

        Args:
            target_path: Path to file or directory to scan
            provider: IaC provider type (auto-detected if not specified)
            scanner: Scanner to use (auto-selected if not specified)
            base_path: Base path for security validation (optional)

        Returns:
            ScanResult with findings and metadata
        """
        scan_id = str(uuid4())
        started_at = datetime.utcnow()

        try:
            resolved_path = self._validate_path(target_path, base_path)
        except (ValueError, FileNotFoundError) as e:
            return ScanResult(
                scan_id=scan_id,
                status=ScanStatus.FAILED,
                scanner=scanner or ScannerType.CHECKOV,
                provider=provider or IaCProvider.TERRAFORM,
                target_path=target_path,
                started_at=started_at,
                completed_at=datetime.utcnow(),
                error_message=str(e),
            )

        if provider is None:
            provider = self._detect_provider(resolved_path)

        if scanner is None:
            if provider == IaCProvider.TERRAFORM and self._is_tfsec_available():
                scanner = ScannerType.TFSEC
            elif self._is_checkov_available():
                scanner = ScannerType.CHECKOV
            else:
                return ScanResult(
                    scan_id=scan_id,
                    status=ScanStatus.FAILED,
                    scanner=ScannerType.CHECKOV,
                    provider=provider,
                    target_path=target_path,
                    started_at=started_at,
                    completed_at=datetime.utcnow(),
                    error_message="No IaC scanner available. Install checkov or tfsec.",
                )

        if scanner == ScannerType.CHECKOV:
            findings, raw_output, error = await self._run_checkov(
                resolved_path, provider
            )
        else:
            findings, raw_output, error = await self._run_tfsec(resolved_path, provider)

        completed_at = datetime.utcnow()
        duration = (completed_at - started_at).total_seconds()

        return ScanResult(
            scan_id=scan_id,
            status=ScanStatus.FAILED if error else ScanStatus.COMPLETED,
            scanner=scanner,
            provider=provider,
            target_path=target_path,
            findings=findings,
            started_at=started_at,
            completed_at=completed_at,
            duration_seconds=duration,
            error_message=error,
            raw_output=raw_output if error else None,
            metadata={
                "resolved_path": str(resolved_path),
                "findings_by_severity": {
                    "high": len([f for f in findings if f.severity == "high"]),
                    "medium": len([f for f in findings if f.severity == "medium"]),
                    "low": len([f for f in findings if f.severity == "low"]),
                },
            },
        )

    async def scan_content(
        self,
        content: str,
        filename: str,
        provider: Optional[IaCProvider] = None,
        scanner: Optional[ScannerType] = None,
    ) -> ScanResult:
        """
        Scan IaC content provided as a string.

        Creates a temporary file, scans it, and cleans up.

        Args:
            content: IaC file content as string
            filename: Original filename (used for provider detection)
            provider: IaC provider type (auto-detected if not specified)
            scanner: Scanner to use (auto-selected if not specified)

        Returns:
            ScanResult with findings and metadata
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_file = Path(temp_dir) / filename
            temp_file.write_text(content)

            result = await self.scan(
                str(temp_file),
                provider=provider,
                scanner=scanner,
                base_path=temp_dir,
            )

            for finding in result.findings:
                finding.file_path = filename

            return result

    async def scan_multiple(
        self,
        target_paths: List[str],
        provider: Optional[IaCProvider] = None,
        scanner: Optional[ScannerType] = None,
        base_path: Optional[str] = None,
        max_concurrent: int = 5,
    ) -> List[ScanResult]:
        """
        Scan multiple paths concurrently.

        Args:
            target_paths: List of paths to scan
            provider: IaC provider type (auto-detected per path if not specified)
            scanner: Scanner to use (auto-selected if not specified)
            base_path: Base path for security validation (optional)
            max_concurrent: Maximum concurrent scans

        Returns:
            List of ScanResults
        """
        semaphore = asyncio.Semaphore(max_concurrent)

        async def scan_with_semaphore(path: str) -> ScanResult:
            async with semaphore:
                return await self.scan(path, provider, scanner, base_path)

        tasks = [scan_with_semaphore(path) for path in target_paths]
        return await asyncio.gather(*tasks)


_default_scanner: Optional[IaCScanner] = None


def get_iac_scanner() -> IaCScanner:
    """Get the default IaC scanner instance."""
    global _default_scanner
    if _default_scanner is None:
        _default_scanner = IaCScanner()
    return _default_scanner
