"""Data models for Pentagi pen testing integration."""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional


class PenTestStatus(Enum):
    """Status of a pen test."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ExploitabilityLevel(Enum):
    """Exploitability level from pen test results."""

    CONFIRMED_EXPLOITABLE = "confirmed_exploitable"
    LIKELY_EXPLOITABLE = "likely_exploitable"
    UNEXPLOITABLE = "unexploitable"
    BLOCKED = "blocked"
    INCONCLUSIVE = "inconclusive"


class PenTestPriority(Enum):
    """Priority for pen test execution."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class PenTestRequest:
    """Pen test request model."""

    id: str
    finding_id: str
    target_url: str
    vulnerability_type: str
    test_case: str
    priority: PenTestPriority
    status: PenTestStatus = PenTestStatus.PENDING
    created_at: datetime = field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    pentagi_job_id: Optional[str] = None
    metadata: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "finding_id": self.finding_id,
            "target_url": self.target_url,
            "vulnerability_type": self.vulnerability_type,
            "test_case": self.test_case,
            "priority": self.priority.value,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat()
            if self.completed_at
            else None,
            "pentagi_job_id": self.pentagi_job_id,
            "metadata": self.metadata,
        }


@dataclass
class PenTestResult:
    """Pen test result model."""

    id: str
    request_id: str
    finding_id: str
    exploitability: ExploitabilityLevel
    exploit_successful: bool
    evidence: str
    steps_taken: List[str] = field(default_factory=list)
    artifacts: List[str] = field(default_factory=list)
    confidence_score: float = 0.0
    execution_time_seconds: float = 0.0
    created_at: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "request_id": self.request_id,
            "finding_id": self.finding_id,
            "exploitability": self.exploitability.value,
            "exploit_successful": self.exploit_successful,
            "evidence": self.evidence,
            "steps_taken": self.steps_taken,
            "artifacts": self.artifacts,
            "confidence_score": self.confidence_score,
            "execution_time_seconds": self.execution_time_seconds,
            "created_at": self.created_at.isoformat(),
            "metadata": self.metadata,
        }


@dataclass
class PenTestConfig:
    """Pentagi configuration model."""

    id: str
    name: str
    pentagi_url: str
    api_key: Optional[str] = None
    enabled: bool = True
    max_concurrent_tests: int = 5
    timeout_seconds: int = 300
    auto_trigger: bool = False
    target_environments: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "pentagi_url": self.pentagi_url,
            "api_key": "***" if self.api_key else None,
            "enabled": self.enabled,
            "max_concurrent_tests": self.max_concurrent_tests,
            "timeout_seconds": self.timeout_seconds,
            "auto_trigger": self.auto_trigger,
            "target_environments": self.target_environments,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "metadata": self.metadata,
        }
