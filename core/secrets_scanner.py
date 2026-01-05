"""
Enterprise-grade secrets scanning module with gitleaks and trufflehog integration.

This module provides real scanning capabilities for detecting secrets in code
using industry-standard tools (gitleaks, trufflehog) with proper async handling,
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

from core.safe_path_ops import (
    TRUSTED_ROOT,
    PathContainmentError,
    safe_exists,
    safe_get_parent_dirs,
    safe_isdir,
    safe_subprocess_run,
    safe_write_text,
)
from core.secrets_models import SecretFinding, SecretStatus, SecretType

logger = logging.getLogger(__name__)


class SecretsScanner(str, Enum):
    """Supported secrets scanner types."""

    GITLEAKS = "gitleaks"
    TRUFFLEHOG = "trufflehog"


class SecretsScanStatus(str, Enum):
    """Scan job status."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class SecretsScanResult:
    """Result of a secrets scan."""

    scan_id: str
    status: SecretsScanStatus
    scanner: SecretsScanner
    target_path: str
    repository: str
    branch: str
    findings: List[SecretFinding] = field(default_factory=list)
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
            "target_path": self.target_path,
            "repository": self.repository,
            "branch": self.branch,
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


SCAN_BASE_PATH = os.getenv("FIXOPS_SCAN_BASE_PATH", "/var/fixops/scans")


@dataclass
class SecretsScannerConfig:
    """Configuration for secrets scanners."""

    gitleaks_path: str = "gitleaks"
    trufflehog_path: str = "trufflehog"
    timeout_seconds: int = 300
    max_file_size_mb: int = 50
    custom_config_path: Optional[str] = None
    entropy_threshold: float = 4.5
    scan_history: bool = True
    max_depth: int = 1000
    base_path: str = SCAN_BASE_PATH

    @classmethod
    def from_env(cls) -> "SecretsScannerConfig":
        """Create config from environment variables."""
        return cls(
            gitleaks_path=os.getenv("FIXOPS_GITLEAKS_PATH", "gitleaks"),
            trufflehog_path=os.getenv("FIXOPS_TRUFFLEHOG_PATH", "trufflehog"),
            timeout_seconds=int(os.getenv("FIXOPS_SECRETS_SCAN_TIMEOUT", "300")),
            max_file_size_mb=int(os.getenv("FIXOPS_MAX_FILE_SIZE_MB", "50")),
            custom_config_path=os.getenv("FIXOPS_SECRETS_CONFIG_PATH"),
            entropy_threshold=float(os.getenv("FIXOPS_ENTROPY_THRESHOLD", "4.5")),
            scan_history=os.getenv("FIXOPS_SCAN_HISTORY", "true").lower() == "true",
            max_depth=int(os.getenv("FIXOPS_SCAN_MAX_DEPTH", "1000")),
            base_path=os.getenv("FIXOPS_SCAN_BASE_PATH", "/var/fixops/scans"),
        )


class SecretsDetector:
    """
    Enterprise secrets detector with gitleaks and trufflehog integration.

    Features:
    - Async scanning with proper timeout handling
    - Support for filesystem and git repository scanning
    - Result normalization to unified finding format
    - Path traversal protection
    - Configurable via environment variables
    - Entropy-based detection support
    """

    def __init__(self, config: Optional[SecretsScannerConfig] = None):
        """Initialize the detector with configuration."""
        self.config = config or SecretsScannerConfig.from_env()
        self._gitleaks_available: Optional[bool] = None
        self._trufflehog_available: Optional[bool] = None

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

    def _is_gitleaks_available(self) -> bool:
        """Check if gitleaks is installed and available."""
        if self._gitleaks_available is None:
            self._gitleaks_available = (
                shutil.which(self.config.gitleaks_path) is not None
            )
        return self._gitleaks_available

    def _is_trufflehog_available(self) -> bool:
        """Check if trufflehog is installed and available."""
        if self._trufflehog_available is None:
            self._trufflehog_available = (
                shutil.which(self.config.trufflehog_path) is not None
            )
        return self._trufflehog_available

    def get_available_scanners(self) -> List[SecretsScanner]:
        """Get list of available scanners."""
        available = []
        if self._is_gitleaks_available():
            available.append(SecretsScanner.GITLEAKS)
        if self._is_trufflehog_available():
            available.append(SecretsScanner.TRUFFLEHOG)
        return available

    def _validate_path(self, target_path: str) -> Path:
        """
        Validate and resolve the target path with security checks.

        Security measures:
        1. Reject null bytes in path
        2. Normalize path to prevent traversal via os.path.normpath
        3. For relative paths: join with base_path and resolve
        4. For absolute paths: verify they're within base_path (pre-validated by router)
        5. Resolve using os.path.realpath (CodeQL-recognized sanitizer)
        6. Verify resolved path stays within base directory using os.path.commonpath
        """
        # Sanitize the path string - reject null bytes
        if "\x00" in target_path:
            raise ValueError(f"Invalid path: {target_path} contains null bytes")

        # Normalize the path to collapse .. and . components
        normalized = os.path.normpath(target_path)

        # Get server-controlled base path using realpath (CodeQL-recognized sanitizer)
        base = os.path.realpath(self.config.base_path)

        # Handle both relative and absolute paths
        if os.path.isabs(normalized):
            # For absolute paths (pre-validated by router), resolve and verify containment
            candidate = os.path.realpath(normalized)
        else:
            # Reject path traversal attempts in relative paths
            if (
                normalized.startswith("..")
                or "/../" in normalized
                or normalized == ".."
            ):
                raise ValueError(f"Path traversal detected: {target_path}")
            # Join with base path and resolve using realpath
            candidate = os.path.realpath(os.path.join(base, normalized))

        # Verify the resolved path stays within the base directory using commonpath
        # This is the containment check that CodeQL recognizes
        if os.path.commonpath([base, candidate]) != base:
            raise ValueError(f"Path escapes base directory: {target_path}")

        # Use safe_exists wrapper which has inline sanitization for CodeQL
        try:
            if not safe_exists(candidate, self.config.base_path):
                raise FileNotFoundError(f"Target path does not exist: {target_path}")
        except PathContainmentError:
            raise ValueError(f"Path escapes base directory: {target_path}")

        return Path(candidate)

    def _map_secret_type(self, rule_id: str, description: str = "") -> SecretType:
        """Map scanner-specific rule to normalized secret type."""
        rule_lower = rule_id.lower()
        desc_lower = description.lower()

        if "aws" in rule_lower or "aws" in desc_lower:
            return SecretType.AWS_KEY
        elif "api" in rule_lower or "api" in desc_lower:
            return SecretType.API_KEY
        # Check database-related patterns BEFORE password to handle "database-password"
        elif (
            "database" in rule_lower
            or "mysql" in rule_lower
            or "postgres" in rule_lower
            or ("db" in rule_lower and "password" in rule_lower)
        ):
            return SecretType.DATABASE_CREDENTIAL
        elif "password" in rule_lower or "password" in desc_lower:
            return SecretType.PASSWORD
        elif "token" in rule_lower or "token" in desc_lower:
            return SecretType.TOKEN
        elif "private" in rule_lower and "key" in rule_lower:
            return SecretType.PRIVATE_KEY
        elif "certificate" in rule_lower or "cert" in rule_lower:
            return SecretType.CERTIFICATE
        else:
            return SecretType.GENERIC

    def _parse_gitleaks_output(
        self, output: str, repository: str, branch: str
    ) -> List[SecretFinding]:
        """Parse gitleaks JSON output into normalized findings."""
        findings: List[SecretFinding] = []

        if not output.strip():
            return findings

        try:
            data = json.loads(output)
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse gitleaks output as JSON: {e}")
            return findings

        if not isinstance(data, list):
            data = [data] if data else []

        for item in data:
            finding = SecretFinding(
                id=str(uuid4()),
                secret_type=self._map_secret_type(
                    item.get("RuleID", ""), item.get("Description", "")
                ),
                status=SecretStatus.ACTIVE,
                file_path=item.get("File", "unknown"),
                line_number=item.get("StartLine", 0),
                repository=repository,
                branch=branch,
                commit_hash=item.get("Commit"),
                matched_pattern=(
                    item.get("Match", "")[:100] if item.get("Match") else None
                ),
                entropy_score=item.get("Entropy"),
                metadata={
                    "scanner": "gitleaks",
                    "rule_id": item.get("RuleID"),
                    "description": item.get("Description"),
                    "author": item.get("Author"),
                    "email": item.get("Email"),
                    "date": item.get("Date"),
                    "message": item.get("Message"),
                    "fingerprint": item.get("Fingerprint"),
                    "tags": item.get("Tags", []),
                },
            )
            findings.append(finding)

        return findings

    def _parse_trufflehog_output(
        self, output: str, repository: str, branch: str
    ) -> List[SecretFinding]:
        """Parse trufflehog JSON output into normalized findings."""
        findings: List[SecretFinding] = []

        if not output.strip():
            return findings

        for line in output.strip().split("\n"):
            if not line.strip():
                continue

            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue

            source_metadata = item.get("SourceMetadata", {}).get("Data", {})
            file_info = source_metadata.get("Filesystem", {}) or source_metadata.get(
                "Git", {}
            )

            finding = SecretFinding(
                id=str(uuid4()),
                secret_type=self._map_secret_type(
                    item.get("DetectorName", ""), item.get("DecoderName", "")
                ),
                status=SecretStatus.ACTIVE,
                file_path=file_info.get("file", file_info.get("File", "unknown")),
                line_number=file_info.get("line", 0),
                repository=repository,
                branch=branch,
                commit_hash=file_info.get("commit"),
                matched_pattern=item.get("Raw", "")[:100] if item.get("Raw") else None,
                entropy_score=None,
                metadata={
                    "scanner": "trufflehog",
                    "detector_name": item.get("DetectorName"),
                    "decoder_name": item.get("DecoderName"),
                    "verified": item.get("Verified", False),
                    "raw_v2": item.get("RawV2"),
                    "redacted": item.get("Redacted"),
                    "extra_data": item.get("ExtraData", {}),
                },
            )
            findings.append(finding)

        return findings

    async def _run_gitleaks(
        self,
        target_path: Path,
        repository: str,
        branch: str,
        is_git_repo: bool,
    ) -> Tuple[List[SecretFinding], str, Optional[str]]:
        """Run gitleaks scanner asynchronously."""
        # Two-stage containment check (CodeQL requires TRUSTED_ROOT anchor)
        trusted_root = os.path.realpath(TRUSTED_ROOT)
        base = os.path.realpath(self.config.base_path)
        verified_path = os.path.realpath(str(target_path))
        if os.path.commonpath([trusted_root, base]) != trusted_root:
            raise ValueError(f"Base path escapes trusted root: {self.config.base_path}")
        if os.path.commonpath([base, verified_path]) != base:
            raise ValueError(f"Path escapes base directory: {target_path}")

        cmd = [
            self.config.gitleaks_path,
            "detect",
            "--source",
            verified_path,
            "--report-format",
            "json",
            "--report-path",
            "/dev/stdout",
            "--exit-code",
            "0",
        ]

        if not is_git_repo or not self.config.scan_history:
            cmd.append("--no-git")

        if self.config.custom_config_path:
            cmd.extend(["--config", self.config.custom_config_path])

        logger.info(f"Running gitleaks: {' '.join(cmd)}")

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
                    f"Gitleaks exited with code {process.returncode}: {error_output}",
                )

            findings = self._parse_gitleaks_output(output, repository, branch)
            return findings, output, None

        except asyncio.TimeoutError:
            return (
                [],
                "",
                f"Gitleaks scan timed out after {self.config.timeout_seconds} seconds",
            )
        except FileNotFoundError:
            return [], "", "Gitleaks is not installed or not in PATH"
        except Exception as e:
            return [], "", f"Gitleaks scan failed: {str(e)}"

    async def _run_trufflehog(
        self,
        target_path: Path,
        repository: str,
        branch: str,
        is_git_repo: bool,
    ) -> Tuple[List[SecretFinding], str, Optional[str]]:
        """Run trufflehog scanner asynchronously."""
        # Two-stage containment check (CodeQL requires TRUSTED_ROOT anchor)
        trusted_root = os.path.realpath(TRUSTED_ROOT)
        base = os.path.realpath(self.config.base_path)
        verified_path = os.path.realpath(str(target_path))
        if os.path.commonpath([trusted_root, base]) != trusted_root:
            raise ValueError(f"Base path escapes trusted root: {self.config.base_path}")
        if os.path.commonpath([base, verified_path]) != base:
            raise ValueError(f"Path escapes base directory: {target_path}")

        if is_git_repo and self.config.scan_history:
            cmd = [
                self.config.trufflehog_path,
                "git",
                f"file://{verified_path}",
                "--json",
                "--no-update",
            ]
            if self.config.max_depth:
                cmd.extend(["--max-depth", str(self.config.max_depth)])
        else:
            cmd = [
                self.config.trufflehog_path,
                "filesystem",
                verified_path,
                "--json",
                "--no-update",
            ]

        logger.info(f"Running trufflehog: {' '.join(cmd)}")

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

            if process.returncode not in (0, 1, 183):
                return (
                    [],
                    output,
                    f"Trufflehog exited with code {process.returncode}: {error_output}",
                )

            findings = self._parse_trufflehog_output(output, repository, branch)
            return findings, output, None

        except asyncio.TimeoutError:
            return (
                [],
                "",
                f"Trufflehog scan timed out after {self.config.timeout_seconds} seconds",
            )
        except FileNotFoundError:
            return [], "", "Trufflehog is not installed or not in PATH"
        except Exception as e:
            return [], "", f"Trufflehog scan failed: {str(e)}"

    def _is_git_repo(self, path: Path) -> bool:
        """Check if the path is inside a git repository."""
        path_str = str(path)
        base_path = self.config.base_path

        # Use safe sink wrappers which have inline sanitization for CodeQL
        try:
            # Iterate through parent directories looking for .git
            for parent_dir in safe_get_parent_dirs(path_str, base_path):
                git_dir = os.path.join(parent_dir, ".git")
                # Use safe_exists to check for .git directory
                if safe_exists(git_dir, base_path):
                    return True
        except PathContainmentError:
            raise ValueError(f"Path escapes base directory: {path}")

        return False

    def _get_repo_info(self, path: Path) -> Tuple[str, str]:
        """Extract repository name and branch from git repo."""
        if not self._is_git_repo(path):
            return str(path), "main"

        try:
            path_str = str(path)
            base_path = self.config.base_path

            # Determine cwd using safe_isdir wrapper
            try:
                is_dir = safe_isdir(path_str, base_path)
            except PathContainmentError:
                raise ValueError(f"Path escapes base directory: {path}")

            cwd_path = path_str if is_dir else os.path.dirname(path_str)

            # Use safe_subprocess_run wrapper which has inline sanitization for CodeQL
            result = safe_subprocess_run(
                ["git", "rev-parse", "--show-toplevel"],
                cwd=cwd_path,
                base_path=base_path,
                timeout=5,
            )
            repo_path = result.stdout.strip() if result.returncode == 0 else str(path)
            repo_name = os.path.basename(repo_path)

            result = safe_subprocess_run(
                ["git", "rev-parse", "--abbrev-ref", "HEAD"],
                cwd=cwd_path,
                base_path=base_path,
                timeout=5,
            )
            branch = result.stdout.strip() if result.returncode == 0 else "main"

            return repo_name, branch
        except PathContainmentError:
            return str(path), "main"
        except Exception:
            return str(path), "main"

    async def scan(
        self,
        target_path: str,
        repository: Optional[str] = None,
        branch: Optional[str] = None,
        scanner: Optional[SecretsScanner] = None,
    ) -> SecretsScanResult:
        """
        Perform a secrets scan.

        Args:
            target_path: Path to file or directory to scan (must be pre-validated by caller)
            repository: Repository name (auto-detected if not specified)
            branch: Branch name (auto-detected if not specified)
            scanner: Scanner to use (auto-selected if not specified)

        Returns:
            SecretsScanResult with findings and metadata

        Note: Path traversal protection is handled at the API layer using
        server-side configured base paths. Callers must validate paths before
        calling this method.
        """
        scan_id = str(uuid4())
        started_at = datetime.utcnow()

        try:
            resolved_path = self._validate_path(target_path)
        except (ValueError, FileNotFoundError) as e:
            return SecretsScanResult(
                scan_id=scan_id,
                status=SecretsScanStatus.FAILED,
                scanner=scanner or SecretsScanner.GITLEAKS,
                target_path=target_path,
                repository=repository or "unknown",
                branch=branch or "main",
                started_at=started_at,
                completed_at=datetime.utcnow(),
                error_message=str(e),
            )

        is_git_repo = self._is_git_repo(resolved_path)

        if repository is None or branch is None:
            detected_repo, detected_branch = self._get_repo_info(resolved_path)
            repository = repository or detected_repo
            branch = branch or detected_branch

        if scanner is None:
            if self._is_gitleaks_available():
                scanner = SecretsScanner.GITLEAKS
            elif self._is_trufflehog_available():
                scanner = SecretsScanner.TRUFFLEHOG
            else:
                return SecretsScanResult(
                    scan_id=scan_id,
                    status=SecretsScanStatus.FAILED,
                    scanner=SecretsScanner.GITLEAKS,
                    target_path=target_path,
                    repository=repository,
                    branch=branch,
                    started_at=started_at,
                    completed_at=datetime.utcnow(),
                    error_message="No secrets scanner available. Install gitleaks or trufflehog.",
                )

        if scanner == SecretsScanner.GITLEAKS:
            findings, raw_output, error = await self._run_gitleaks(
                resolved_path, repository, branch, is_git_repo
            )
        else:
            findings, raw_output, error = await self._run_trufflehog(
                resolved_path, repository, branch, is_git_repo
            )

        completed_at = datetime.utcnow()
        duration = (completed_at - started_at).total_seconds()

        return SecretsScanResult(
            scan_id=scan_id,
            status=SecretsScanStatus.FAILED if error else SecretsScanStatus.COMPLETED,
            scanner=scanner,
            target_path=target_path,
            repository=repository,
            branch=branch,
            findings=findings,
            started_at=started_at,
            completed_at=completed_at,
            duration_seconds=duration,
            error_message=error,
            raw_output=raw_output if error else None,
            metadata={
                "resolved_path": str(resolved_path),
                "is_git_repo": is_git_repo,
                "findings_by_type": {
                    secret_type.value: len(
                        [f for f in findings if f.secret_type == secret_type]
                    )
                    for secret_type in SecretType
                    if any(f.secret_type == secret_type for f in findings)
                },
            },
        )

    async def scan_content(
        self,
        content: str,
        filename: str,
        repository: str = "inline",
        branch: str = "main",
        scanner: Optional[SecretsScanner] = None,
    ) -> SecretsScanResult:
        """
        Scan content provided as a string for secrets.

        Creates a temporary file under the base path, scans it, and cleans up.
        This ensures the temp file passes containment checks.

        Args:
            content: File content as string
            filename: Original filename
            repository: Repository name
            branch: Branch name
            scanner: Scanner to use (auto-selected if not specified)

        Returns:
            SecretsScanResult with findings and metadata
        """
        # Generate a safe filename based on extension only - no user input in path
        # Extract extension from filename using os.path.splitext (CodeQL-safe)
        _, ext = os.path.splitext(os.path.basename(filename))
        # Allowlist of valid source code extensions for secrets scanning
        valid_extensions = {
            ".py",
            ".js",
            ".ts",
            ".java",
            ".go",
            ".rb",
            ".php",
            ".sh",
            ".bash",
            ".yaml",
            ".yml",
            ".json",
            ".xml",
            ".env",
            ".conf",
            ".cfg",
            ".ini",
            ".tf",
            ".tfvars",
            ".properties",
            ".toml",
            ".txt",
        }
        if ext.lower() not in valid_extensions:
            ext = ".txt"  # Default to text
        # Generate completely safe filename with no user input
        safe_filename = f"content{ext}"

        # Create temp directory under base_path so containment checks pass
        # Two-stage containment check (CodeQL requires TRUSTED_ROOT anchor)
        trusted_root = os.path.realpath(TRUSTED_ROOT)
        base_path = self.config.base_path
        base = os.path.realpath(base_path)
        if os.path.commonpath([trusted_root, base]) != trusted_root:
            raise ValueError(f"Base path escapes trusted root: {base_path}")
        os.makedirs(base, exist_ok=True)

        with tempfile.TemporaryDirectory(dir=base) as temp_dir:
            temp_file = Path(temp_dir) / safe_filename
            # Use safe_write_text wrapper which has inline sanitization for CodeQL
            safe_write_text(str(temp_file), base_path, content)

            scan_id = str(uuid4())
            started_at = datetime.now()

            try:
                selected_scanner = scanner

                if not selected_scanner:
                    available = self.get_available_scanners()
                    if not available:
                        return SecretsScanResult(
                            scan_id=scan_id,
                            status=SecretsScanStatus.FAILED,
                            scanner=SecretsScanner.GITLEAKS,
                            target_path=filename,
                            repository=repository,
                            branch=branch,
                            started_at=started_at,
                            completed_at=datetime.now(),
                            error_message="No secrets scanner available",
                        )
                    selected_scanner = available[0]

                # Temp files are never in a git repo
                is_git_repo = False

                # Containment check will pass since temp_dir is under base_path
                if selected_scanner == SecretsScanner.GITLEAKS:
                    findings, raw_output, error = await self._run_gitleaks(
                        temp_file,
                        repository,
                        branch,
                        is_git_repo,
                    )
                else:
                    findings, raw_output, error = await self._run_trufflehog(
                        temp_file,
                        repository,
                        branch,
                        is_git_repo,
                    )

                completed_at = datetime.now()
                duration = (completed_at - started_at).total_seconds()

                if error:
                    return SecretsScanResult(
                        scan_id=scan_id,
                        status=SecretsScanStatus.FAILED,
                        scanner=selected_scanner,
                        target_path=filename,
                        repository=repository,
                        branch=branch,
                        started_at=started_at,
                        completed_at=completed_at,
                        duration_seconds=duration,
                        error_message=error,
                        raw_output=raw_output,
                    )

                for finding in findings:
                    finding.file_path = filename

                return SecretsScanResult(
                    scan_id=scan_id,
                    status=SecretsScanStatus.COMPLETED,
                    scanner=selected_scanner,
                    target_path=filename,
                    repository=repository,
                    branch=branch,
                    findings=findings,
                    started_at=started_at,
                    completed_at=completed_at,
                    duration_seconds=duration,
                    raw_output=raw_output,
                )
            except Exception as e:
                return SecretsScanResult(
                    scan_id=scan_id,
                    status=SecretsScanStatus.FAILED,
                    scanner=scanner or SecretsScanner.GITLEAKS,
                    target_path=filename,
                    repository=repository,
                    branch=branch,
                    started_at=started_at,
                    completed_at=datetime.now(),
                    error_message=str(e),
                )

    async def scan_multiple(
        self,
        target_paths: List[str],
        repository: Optional[str] = None,
        branch: Optional[str] = None,
        scanner: Optional[SecretsScanner] = None,
        max_concurrent: int = 5,
    ) -> List[SecretsScanResult]:
        """
        Scan multiple paths concurrently.

        Args:
            target_paths: List of paths to scan (must be pre-validated by caller)
            repository: Repository name (auto-detected per path if not specified)
            branch: Branch name (auto-detected per path if not specified)
            scanner: Scanner to use (auto-selected if not specified)
            max_concurrent: Maximum concurrent scans

        Returns:
            List of SecretsScanResults

        Note: Path traversal protection is handled at the API layer using
        server-side configured base paths. Callers must validate paths before
        calling this method.
        """
        semaphore = asyncio.Semaphore(max_concurrent)

        async def scan_with_semaphore(path: str) -> SecretsScanResult:
            async with semaphore:
                return await self.scan(path, repository, branch, scanner)

        tasks = [scan_with_semaphore(path) for path in target_paths]
        return await asyncio.gather(*tasks)


_default_detector: Optional[SecretsDetector] = None


def get_secrets_detector() -> SecretsDetector:
    """Get the default secrets detector instance."""
    global _default_detector
    if _default_detector is None:
        _default_detector = SecretsDetector()
    return _default_detector
