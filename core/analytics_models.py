"""
Database models for FixOps analytics and metrics.
"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, Optional


class FindingSeverity(str, Enum):
    """Finding severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(str, Enum):
    """Finding status."""

    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"


class DecisionOutcome(str, Enum):
    """Decision outcome."""

    BLOCK = "block"
    ALERT = "alert"
    ALLOW = "allow"
    REVIEW = "review"


@dataclass
class Finding:
    """Security finding record."""

    id: str
    application_id: Optional[str]
    service_id: Optional[str]
    rule_id: str
    severity: FindingSeverity
    status: FindingStatus
    title: str
    description: str
    source: str
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    epss_score: Optional[float] = None
    exploitable: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    resolved_at: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API responses."""
        return {
            "id": self.id,
            "application_id": self.application_id,
            "service_id": self.service_id,
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "status": self.status.value,
            "title": self.title,
            "description": self.description,
            "source": self.source,
            "cve_id": self.cve_id,
            "cvss_score": self.cvss_score,
            "epss_score": self.epss_score,
            "exploitable": self.exploitable,
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
        }


@dataclass
class Decision:
    """Decision record from multi-LLM consensus."""

    id: str
    finding_id: str
    outcome: DecisionOutcome
    confidence: float
    reasoning: str
    llm_votes: Dict[str, Any] = field(default_factory=dict)
    policy_matched: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API responses."""
        return {
            "id": self.id,
            "finding_id": self.finding_id,
            "outcome": self.outcome.value,
            "confidence": self.confidence,
            "reasoning": self.reasoning,
            "llm_votes": self.llm_votes,
            "policy_matched": self.policy_matched,
            "created_at": self.created_at.isoformat(),
        }


@dataclass
class Metric:
    """Metrics record for dashboard."""

    id: str
    metric_type: str
    metric_name: str
    value: float
    unit: str
    timestamp: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API responses."""
        return {
            "id": self.id,
            "metric_type": self.metric_type,
            "metric_name": self.metric_name,
            "value": self.value,
            "unit": self.unit,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata,
        }
