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
    safe_tempdir,
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


# Hardcoded paths under TRUSTED_ROOT - NOT configurable via environment variables
# This is intentional to prevent CodeQL py/path-injection alerts
# All paths MUST be under TRUSTED_ROOT (/var/fixops) for security
SCAN_BASE_PATH = TRUSTED_ROOT + "/scans"
# Custom config directory is hardcoded under TRUSTED_ROOT to prevent path injection
# Operators can place custom gitleaks config in this directory
CUSTOM_CONFIG_PATH = TRUSTED_ROOT + "/configs/gitleaks.toml"


@dataclass
class SecretsScannerConfig:
    """Configuration for secrets scanners.

    Note: base_path and custom_config_path are NOT configurable - they are
    hardcoded constants under TRUSTED_ROOT to prevent CodeQL py/path-injection alerts.
    All file operations use SCAN_BASE_PATH and CUSTOM_CONFIG_PATH directly.
    """

    gitleaks_path: str = "gitleaks"
    trufflehog_path: str = "trufflehog"
    timeout_seconds: int = 300
    max_file_size_mb: int = 50
    entropy_threshold: float = 4.5
    scan_history: bool = True
    max_depth: int = 1000
    # Note: base_path and custom_config_path are removed from config
    # Use SCAN_BASE_PATH and CUSTOM_CONFIG_PATH constants directly

    @classmethod
    def from_env(cls) -> "SecretsScannerConfig":
        """Create config from environment variables."""
        # Note: base_path and custom_config_path are intentionally NOT configurable
        # via environment variables to prevent CodeQL py/path-injection alerts
        return cls(
            gitleaks_path=os.getenv("FIXOPS_GITLEAKS_PATH", "gitleaks"),
            trufflehog_path=os.getenv("FIXOPS_TRUFFLEHOG_PATH", "trufflehog"),
            timeout_seconds=int(os.getenv("FIXOPS_SECRETS_SCAN_TIMEOUT", "300")),
            max_file_size_mb=int(os.getenv("FIXOPS_MAX_FILE_SIZE_MB", "50")),
            entropy_threshold=float(os.getenv("FIXOPS_ENTROPY_THRESHOLD", "4.5")),
            scan_history=os.getenv("FIXOPS_SCAN_HISTORY", "true").lower() == "true",
            max_depth=int(os.getenv("FIXOPS_SCAN_MAX_DEPTH", "1000")),
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
        # Use hardcoded SCAN_BASE_PATH constant - NOT configurable
        base = os.path.realpath(SCAN_BASE_PATH)
        candidate = os.path.realpath(str(path))
        if os.path.commonpath([trusted_root, base]) != trusted_root:
            raise ValueError(f"Base path escapes trusted root: {SCAN_BASE_PATH}")
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
        target_path: str,
        repository: str,
        branch: str,
        is_git_repo: bool,
    ) -> Tuple[List[SecretFinding], str, Optional[str]]:
        """Run gitleaks scanner asynchronously."""
        # Three-stage containment check (CodeQL requires inline check before sink)
        trusted_root = os.path.realpath(TRUSTED_ROOT)
        # Use hardcoded SCAN_BASE_PATH constant - NOT configurable
        base = os.path.realpath(SCAN_BASE_PATH)
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
            raise ValueError(f"Base path escapes trusted root: {SCAN_BASE_PATH}")
        # Stage 3: candidate must be under base
        if not (verified_path == base or verified_path.startswith(base_prefix)):
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

        # Only use custom config if the hardcoded config file exists
        # This allows operators to optionally place a config in /var/fixops/configs/
        # Use hardcoded CUSTOM_CONFIG_PATH constant - NOT configurable
        if os.path.isfile(CUSTOM_CONFIG_PATH):
            cmd.extend(["--config", CUSTOM_CONFIG_PATH])

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
        target_path: str,
        repository: str,
        branch: str,
        is_git_repo: bool,
    ) -> Tuple[List[SecretFinding], str, Optional[str]]:
        """Run trufflehog scanner asynchronously."""
        # Three-stage containment check (CodeQL requires inline check before sink)
        trusted_root = os.path.realpath(TRUSTED_ROOT)
        # Use hardcoded SCAN_BASE_PATH constant - NOT configurable
        base = os.path.realpath(SCAN_BASE_PATH)
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
            raise ValueError(f"Base path escapes trusted root: {SCAN_BASE_PATH}")
        # Stage 3: candidate must be under base
        if not (verified_path == base or verified_path.startswith(base_prefix)):
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

    def _is_git_repo(self, path: str) -> bool:
        """Check if the path is inside a git repository."""
        path_str = str(path)
        # Use hardcoded SCAN_BASE_PATH constant - NOT configurable
        base_path = SCAN_BASE_PATH

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

    def _get_repo_info(self, path: str) -> Tuple[str, str]:
        """Extract repository name and branch from git repo."""
        if not self._is_git_repo(path):
            return str(path), "main"

        try:
            path_str = str(path)
            # Use hardcoded SCAN_BASE_PATH constant - NOT configurable
            base_path = SCAN_BASE_PATH

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
        # Map user extension to hardcoded safe extension - NO user input in path
        # This ensures CodeQL sees the filename as completely server-generated
        extension_map = {
            ".py": ".py",
            ".js": ".js",
            ".ts": ".ts",
            ".java": ".java",
            ".go": ".go",
            ".rb": ".rb",
            ".php": ".php",
            ".sh": ".sh",
            ".bash": ".bash",
            ".yaml": ".yaml",
            ".yml": ".yml",
            ".json": ".json",
            ".xml": ".xml",
            ".env": ".env",
            ".conf": ".conf",
            ".cfg": ".cfg",
            ".ini": ".ini",
            ".tf": ".tf",
            ".tfvars": ".tfvars",
            ".properties": ".properties",
            ".toml": ".toml",
            ".txt": ".txt",
        }
        # Extract extension from filename for lookup only
        _, user_ext = os.path.splitext(os.path.basename(filename))
        # Use hardcoded extension from map, defaulting to .txt
        # The get() returns a hardcoded string literal, not user input
        safe_ext = extension_map.get(user_ext.lower(), ".txt")
        # Generate completely safe filename with hardcoded extension
        safe_filename = "content" + safe_ext

        # Use safe_tempdir wrapper which has inline sanitization for CodeQL
        # This ensures the temp directory is created under a validated base path
        # Use hardcoded SCAN_BASE_PATH constant - NOT configurable
        base_path = SCAN_BASE_PATH
        with safe_tempdir(base_path) as temp_dir:
            # Use os.path.join instead of Path() to avoid CodeQL sink
            temp_file = os.path.join(temp_dir, safe_filename)
            # Use safe_write_text wrapper which has inline sanitization for CodeQL
            safe_write_text(temp_file, base_path, content)

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


_default_detector: Optional[SecretsDetector] = None


def get_secrets_detector() -> SecretsDetector:
    """Get the default secrets detector instance."""
    global _default_detector
    if _default_detector is None:
        _default_detector = SecretsDetector()
    return _default_detector
