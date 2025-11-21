"""
Database models for FixOps secrets detection.
"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, Optional


class SecretType(str, Enum):
    """Types of secrets that can be detected."""

    API_KEY = "api_key"
    PASSWORD = "password"
    TOKEN = "token"
    CERTIFICATE = "certificate"
    PRIVATE_KEY = "private_key"
    AWS_KEY = "aws_key"
    DATABASE_CREDENTIAL = "database_credential"
    GENERIC = "generic"


class SecretStatus(str, Enum):
    """Secret finding status."""

    ACTIVE = "active"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


@dataclass
class SecretFinding:
    """Secret detection finding."""

    id: str
    secret_type: SecretType
    status: SecretStatus
    file_path: str
    line_number: int
    repository: str
    branch: str
    commit_hash: Optional[str] = None
    matched_pattern: Optional[str] = None
    entropy_score: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    detected_at: datetime = field(default_factory=datetime.utcnow)
    resolved_at: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API responses."""
        return {
            "id": self.id,
            "secret_type": self.secret_type.value,
            "status": self.status.value,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "repository": self.repository,
            "branch": self.branch,
            "commit_hash": self.commit_hash,
            "matched_pattern": self.matched_pattern,
            "entropy_score": self.entropy_score,
            "metadata": self.metadata,
            "detected_at": self.detected_at.isoformat(),
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
        }


@dataclass
class SecretScanConfig:
    """Configuration for secret scanning."""

    id: str
    name: str
    enabled: bool
    patterns: Dict[str, Any] = field(default_factory=dict)
    exclusions: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API responses."""
        return {
            "id": self.id,
            "name": self.name,
            "enabled": self.enabled,
            "patterns": self.patterns,
            "exclusions": self.exclusions,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }
