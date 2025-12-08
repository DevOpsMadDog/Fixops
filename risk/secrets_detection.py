"""FixOps Secrets Detection Engine - Proprietary secrets scanning."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class SecretType(Enum):
    """Secret types."""
    
    API_KEY = "api_key"
    PASSWORD = "password"
    ACCESS_TOKEN = "access_token"
    PRIVATE_KEY = "private_key"
    DATABASE_CREDENTIAL = "database_credential"
    AWS_CREDENTIAL = "aws_credential"
    GCP_CREDENTIAL = "gcp_credential"
    AZURE_CREDENTIAL = "azure_credential"
    GITHUB_TOKEN = "github_token"
    SLACK_TOKEN = "slack_token"


@dataclass
class SecretFinding:
    """Secret finding."""
    
    secret_type: SecretType
    severity: str  # critical, high, medium, low
    file_path: str
    line_number: int
    matched_pattern: str
    context: str = ""  # Surrounding code
    recommendation: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class SecretsDetectionResult:
    """Secrets detection result."""
    
    findings: List[SecretFinding]
    total_findings: int
    findings_by_type: Dict[str, int]
    files_scanned: int
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class SecretsDetector:
    """FixOps Secrets Detector - Proprietary secrets scanning."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize secrets detector."""
        self.config = config or {}
        self.patterns = self._build_secret_patterns()
        self.exclude_paths = self.config.get(
            "exclude_paths",
            [".git", "node_modules", "venv", "__pycache__", ".venv"],
        )
    
    def _build_secret_patterns(self) -> Dict[SecretType, List[Dict[str, Any]]]:
        """Build proprietary secret detection patterns."""
        return {
            SecretType.API_KEY: [
                {
                    "pattern": r'(?:api[_-]?key|apikey)\s*[=:]\s*["\']([A-Za-z0-9_\-]{20,})["\']',
                    "severity": "high",
                },
                {
                    "pattern": r'(?:api[_-]?key|apikey)\s*[=:]\s*([A-Za-z0-9_\-]{20,})',
                    "severity": "high",
                },
            ],
            SecretType.PASSWORD: [
                {
                    "pattern": r'(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\']{8,})["\']',
                    "severity": "critical",
                },
            ],
            SecretType.ACCESS_TOKEN: [
                {
                    "pattern": r'(?:access[_-]?token|access_token)\s*[=:]\s*["\']([A-Za-z0-9_\-]{20,})["\']',
                    "severity": "high",
                },
            ],
            SecretType.PRIVATE_KEY: [
                {
                    "pattern": r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----',
                    "severity": "critical",
                },
            ],
            SecretType.AWS_CREDENTIAL: [
                {
                    "pattern": r'AWS_ACCESS_KEY_ID\s*=\s*["\']([A-Z0-9]{20})["\']',
                    "severity": "critical",
                },
                {
                    "pattern": r'AWS_SECRET_ACCESS_KEY\s*=\s*["\']([A-Za-z0-9/+=]{40})["\']',
                    "severity": "critical",
                },
            ],
            SecretType.GCP_CREDENTIAL: [
                {
                    "pattern": r'type:\s*service_account',
                    "severity": "high",
                },
                {
                    "pattern": r'private_key_id:\s*["\']([^"\']+)["\']',
                    "severity": "high",
                },
            ],
            SecretType.GITHUB_TOKEN: [
                {
                    "pattern": r'github[_-]?token\s*[=:]\s*["\'](ghp_[A-Za-z0-9]{36})["\']',
                    "severity": "high",
                },
            ],
        }
    
    def scan(self, path: Path) -> SecretsDetectionResult:
        """Scan codebase for secrets."""
        findings = []
        files_scanned = 0
        
        # Find all code files
        code_extensions = {
            ".py",
            ".js",
            ".ts",
            ".java",
            ".go",
            ".rb",
            ".php",
            ".yaml",
            ".yml",
            ".json",
            ".env",
            ".properties",
            ".conf",
            ".config",
        }
        
        for file_path in path.rglob("*"):
            if file_path.is_file() and file_path.suffix in code_extensions:
                # Check if excluded
                if any(exclude in str(file_path) for exclude in self.exclude_paths):
                    continue
                
                try:
                    file_findings = self._scan_file(file_path)
                    findings.extend(file_findings)
                    files_scanned += 1
                except Exception as e:
                    logger.warning(f"Failed to scan {file_path}: {e}")
        
        return self._build_result(findings, files_scanned)
    
    def _scan_file(self, file_path: Path) -> List[SecretFinding]:
        """Scan a single file for secrets."""
        findings = []
        
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            lines = content.split("\n")
            
            for secret_type, patterns in self.patterns.items():
                for pattern_config in patterns:
                    pattern = pattern_config["pattern"]
                    severity = pattern_config["severity"]
                    
                    matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                    
                    for match in matches:
                        line_number = content[: match.start()].count("\n") + 1
                        
                        # Get context (3 lines before and after)
                        context_start = max(0, line_number - 4)
                        context_end = min(len(lines), line_number + 2)
                        context = "\n".join(lines[context_start:context_end])
                        
                        finding = SecretFinding(
                            secret_type=secret_type,
                            severity=severity,
                            file_path=str(file_path),
                            line_number=line_number,
                            matched_pattern=match.group(0)[:50],  # First 50 chars
                            context=context,
                            recommendation=self._get_recommendation(secret_type),
                        )
                        
                        findings.append(finding)
        
        except Exception as e:
            logger.warning(f"Failed to scan file {file_path}: {e}")
        
        return findings
    
    def _get_recommendation(self, secret_type: SecretType) -> str:
        """Get recommendation for secret type."""
        recommendations = {
            SecretType.API_KEY: "Use environment variables or secrets management service",
            SecretType.PASSWORD: "Use secrets management service (AWS Secrets Manager, etc.)",
            SecretType.ACCESS_TOKEN: "Store in environment variables or secrets management",
            SecretType.PRIVATE_KEY: "Store private keys in secure key management system",
            SecretType.AWS_CREDENTIAL: "Use IAM roles or AWS Secrets Manager",
            SecretType.GCP_CREDENTIAL: "Use service account keys stored securely",
            SecretType.GITHUB_TOKEN: "Use GitHub secrets or environment variables",
        }
        return recommendations.get(secret_type, "Remove hardcoded secrets and use secure storage")
    
    def _build_result(
        self, findings: List[SecretFinding], files_scanned: int
    ) -> SecretsDetectionResult:
        """Build secrets detection result."""
        findings_by_type: Dict[str, int] = {}
        
        for finding in findings:
            secret_type = finding.secret_type.value
            findings_by_type[secret_type] = findings_by_type.get(secret_type, 0) + 1
        
        return SecretsDetectionResult(
            findings=findings,
            total_findings=len(findings),
            findings_by_type=findings_by_type,
            files_scanned=files_scanned,
        )
