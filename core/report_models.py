"""
Database models for FixOps report management.
"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, Optional


class ReportType(str, Enum):
    """Report types."""

    SECURITY_SUMMARY = "security_summary"
    COMPLIANCE = "compliance"
    RISK_ASSESSMENT = "risk_assessment"
    VULNERABILITY = "vulnerability"
    AUDIT = "audit"
    CUSTOM = "custom"


class ReportFormat(str, Enum):
    """Report output formats."""

    PDF = "pdf"
    HTML = "html"
    JSON = "json"
    CSV = "csv"
    SARIF = "sarif"


class ReportStatus(str, Enum):
    """Report generation status."""

    PENDING = "pending"
    GENERATING = "generating"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class Report:
    """Report record."""

    id: str
    name: str
    report_type: ReportType
    format: ReportFormat
    status: ReportStatus
    parameters: Dict[str, Any] = field(default_factory=dict)
    file_path: Optional[str] = None
    file_size: Optional[int] = None
    generated_by: Optional[str] = None
    error_message: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API responses."""
        return {
            "id": self.id,
            "name": self.name,
            "report_type": self.report_type.value,
            "format": self.format.value,
            "status": self.status.value,
            "parameters": self.parameters,
            "file_path": self.file_path,
            "file_size": self.file_size,
            "generated_by": self.generated_by,
            "error_message": self.error_message,
            "created_at": self.created_at.isoformat(),
            "completed_at": self.completed_at.isoformat()
            if self.completed_at
            else None,
        }


@dataclass
class ReportSchedule:
    """Scheduled report configuration."""

    id: str
    report_type: ReportType
    format: ReportFormat
    schedule_cron: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    enabled: bool = True
    last_run_at: Optional[datetime] = None
    next_run_at: Optional[datetime] = None
    created_by: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API responses."""
        return {
            "id": self.id,
            "report_type": self.report_type.value,
            "format": self.format.value,
            "schedule_cron": self.schedule_cron,
            "parameters": self.parameters,
            "enabled": self.enabled,
            "last_run_at": self.last_run_at.isoformat() if self.last_run_at else None,
            "next_run_at": self.next_run_at.isoformat() if self.next_run_at else None,
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


@dataclass
class ReportTemplate:
    """Report template configuration."""

    id: str
    name: str
    report_type: ReportType
    description: str
    template_config: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API responses."""
        return {
            "id": self.id,
            "name": self.name,
            "report_type": self.report_type.value,
            "description": self.description,
            "template_config": self.template_config,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }
