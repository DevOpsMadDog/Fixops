"""Canonical data models for FixOps findings and events."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any, Dict, List, Optional
from enum import Enum


class FindingStage(str, Enum):
    DESIGN = "design"
    BUILD = "build"
    DEPLOY = "deploy"
    RUNTIME = "runtime"


class FindingSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(str, Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    SUPPRESSED = "suppressed"


@dataclass
class CanonicalLocation:
    """Standardized location information."""
    
    path: str
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    snippet: Optional[str] = None
    repo_url: Optional[str] = None
    commit_sha: Optional[str] = None
    
    def fingerprint_str(self) -> str:
        return f"{self.path}:{self.start_line or 0}"


@dataclass
class CanonicalTool:
    """Tool that generated the finding."""
    
    name: str
    version: Optional[str] = None
    vendor: Optional[str] = None


@dataclass
class CanonicalFinding:
    """
    Standardized finding model across all FixOps integrations.
    Used for deduplication and correlation.
    """
    
    id: str  # Unique ID (UUID)
    title: str
    description: str
    severity: FindingSeverity
    stage: FindingStage
    tool: CanonicalTool
    location: Optional[CanonicalLocation] = None
    
    # Context
    service_name: Optional[str] = None
    component_name: Optional[str] = None
    
    # Vulnerability Identifiers
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    rule_id: Optional[str] = None
    
    # Metadata
    status: FindingStatus = FindingStatus.OPEN
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    tags: Dict[str, str] = field(default_factory=dict)
    
    # Computed
    fingerprint: str = field(init=False)
    
    def __post_init__(self):
        self.fingerprint = self._generate_fingerprint()
    
    def _generate_fingerprint(self) -> str:
        """Generate a stable fingerprint for deduplication."""
        # Core identity components
        parts = [
            self.tool.name,
            self.rule_id or self.title,
            self.component_name or "unknown",
            self.location.fingerprint_str() if self.location else "global",
            self.cve_id or ""
        ]
        
        # Normalize and hash
        raw = "|".join(str(p).lower().strip() for p in parts)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CorrelationGroup:
    """A group of correlated findings."""
    
    id: str
    primary_finding_id: str
    related_finding_ids: List[str]
    strategy: str
    confidence: float
    root_cause: Optional[str] = None
