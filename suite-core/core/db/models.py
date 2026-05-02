"""
SQLAlchemy 2.0 declarative models for ALdeci CTEM+ Platform — P0 customer data tables.

Design constraints:
- Dual-dialect: ALL types must work on both PostgreSQL and SQLite.
  - String(36) for UUIDs (no postgresql.UUID)
  - JSON for array/jsonb columns (no postgresql.ARRAY / postgresql.JSONB)
  - sa.false() / sa.true() for boolean server defaults
  - uuid.uuid4() Python-side default (no gen_random_uuid())
- Every model has org_id (String(64)) for multi-tenant isolation.
- Use SQLAlchemy 2.0 ``DeclarativeBase`` + ``Mapped``/``mapped_column``.
- Timestamps are timezone-aware (UTC); server_default uses CURRENT_TIMESTAMP
  which both dialects understand.

Tables defined here:
  - Finding               — vulnerability finding from any scanner
  - EvidenceBundle        — cryptographically signed compliance evidence
  - RemediationTask       — remediation work item linked to a finding
  - PipelineRun           — brain pipeline execution record (12-step CTEM)

ADR reference: docs/DATABASE_MIGRATION_PLAN.md
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import structlog
from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    text,
)
from sqlalchemy import (
    false as sa_false,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Declarative base
# ---------------------------------------------------------------------------

class Base(DeclarativeBase):
    """Shared metadata for all P0 models.

    Separate from the enterprise ``security.py`` / ``user.py`` Base so that
    these models can be migrated independently without touching the legacy
    migration tree under ``suite-core/core/db/enterprise/migrations/``.
    """
    pass


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _new_uuid() -> str:
    """Generate a new UUID string — used as Python-side primary key default."""
    return str(uuid.uuid4())


def _utcnow() -> datetime:
    """Return current UTC datetime (timezone-aware)."""
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------

class Finding(Base):
    """
    Vulnerability finding normalised from any scanner or inbound connector.

    Corresponds to the ``findings`` table created by migration
    ``alembic/versions/001_initial_schema.py``.  The ORM model uses
    SQLite-compatible types (String for UUID, JSON for arrays) so that
    unit tests and local dev can run against SQLite without modification.

    Multi-tenancy: every query MUST filter on org_id.
    """

    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=_new_uuid,
        nullable=False,
    )
    org_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    # Core finding data
    title: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)

    # Vulnerability identifiers
    cve_id: Mapped[Optional[str]] = mapped_column(String(32), nullable=True, index=True)
    cwe_id: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)

    # Source information
    source: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    # Location
    location: Mapped[Optional[str]] = mapped_column(String(1000), nullable=True)

    # Risk scoring
    risk_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    epss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    cvss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # Threat intel flags
    kev: Mapped[bool] = mapped_column(
        Boolean,
        server_default=sa_false(),
        default=False,
        nullable=False,
    )

    # Lifecycle
    status: Mapped[str] = mapped_column(
        String(32),
        server_default=text("'open'"),
        default="open",
        nullable=False,
        index=True,
    )

    # Deduplication
    correlation_key: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=text("CURRENT_TIMESTAMP"),
        default=_utcnow,
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=text("CURRENT_TIMESTAMP"),
        onupdate=_utcnow,
        default=_utcnow,
        nullable=False,
    )

    # Relationships
    remediations: Mapped[List["RemediationTask"]] = relationship(
        "RemediationTask",
        back_populates="finding",
        cascade="all, delete-orphan",
        lazy="select",
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "org_id": self.org_id,
            "title": self.title,
            "severity": self.severity,
            "cve_id": self.cve_id,
            "cwe_id": self.cwe_id,
            "source": self.source,
            "location": self.location,
            "risk_score": self.risk_score,
            "epss_score": self.epss_score,
            "cvss_score": self.cvss_score,
            "kev": self.kev,
            "status": self.status,
            "correlation_key": self.correlation_key,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    def __repr__(self) -> str:
        return f"<Finding id={self.id} org={self.org_id} severity={self.severity}>"


# ---------------------------------------------------------------------------
# EvidenceBundle
# ---------------------------------------------------------------------------

class EvidenceBundle(Base):
    """
    Cryptographically signed compliance evidence bundle.

    Corresponds to the ``evidence_bundles`` table created by migration 001.
    The ``bundle_json`` column holds the full serialised evidence payload as
    a JSON-compatible Python dict (SQLite stores as TEXT, PostgreSQL as JSONB).

    Signing is handled externally by ``suite-core/core/crypto.py``.  This
    model only persists the result alongside the signature metadata.
    """

    __tablename__ = "evidence_bundles"

    id: Mapped[str] = mapped_column(
        "bundle_id",
        String(36),
        primary_key=True,
        default=_new_uuid,
        nullable=False,
    )
    org_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    # Compliance framework (e.g. "NIST_SSDF", "SOC2", "PCI_DSS")
    framework: Mapped[Optional[str]] = mapped_column(String(32), nullable=True, index=True)

    # Signing state
    signed: Mapped[bool] = mapped_column(
        Boolean,
        server_default=sa_false(),
        default=False,
        nullable=False,
    )
    # RSA-SHA256 base64 signature and algorithm identifier
    signature_algorithm: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)

    # Full evidence payload — JSON-compatible
    bundle_json: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        "payload",
        JSON,
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=text("CURRENT_TIMESTAMP"),
        default=_utcnow,
        nullable=False,
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "org_id": self.org_id,
            "framework": self.framework,
            "signed": self.signed,
            "signature_algorithm": self.signature_algorithm,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self) -> str:
        return f"<EvidenceBundle id={self.id} org={self.org_id} framework={self.framework}>"


# ---------------------------------------------------------------------------
# RemediationTask
# ---------------------------------------------------------------------------

class RemediationTask(Base):
    """
    Remediation work item linked to a Finding.

    Created when a Brain Pipeline step or AutoFix engine generates a fix
    candidate.  Tracks the lifecycle from ``pending`` through ``applied`` or
    ``rejected``.

    fix_type mirrors the 10 types defined in AutoFixEngine (e.g.
    "dependency_upgrade", "code_change", "config_change", etc.).
    """

    __tablename__ = "remediation_tasks"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=_new_uuid,
        nullable=False,
    )
    org_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    # Foreign key to finding — nullable so tasks can exist without a linked finding
    finding_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        ForeignKey("findings.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # Remediation metadata
    fix_type: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    # Lifecycle: pending → in_progress → applied | rejected | failed
    status: Mapped[str] = mapped_column(
        String(32),
        server_default=text("'pending'"),
        default="pending",
        nullable=False,
        index=True,
    )

    # Details stored as JSON (diff, PR URL, commit SHA, etc.)
    details: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=text("CURRENT_TIMESTAMP"),
        default=_utcnow,
        nullable=False,
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Relationships
    finding: Mapped[Optional["Finding"]] = relationship(
        "Finding", back_populates="remediations"
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "org_id": self.org_id,
            "finding_id": self.finding_id,
            "fix_type": self.fix_type,
            "status": self.status,
            "details": self.details,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }

    def __repr__(self) -> str:
        return (
            f"<RemediationTask id={self.id} org={self.org_id} "
            f"status={self.status} fix_type={self.fix_type}>"
        )


# ---------------------------------------------------------------------------
# PipelineRun
# ---------------------------------------------------------------------------

class PipelineRun(Base):
    """
    Brain Pipeline execution record — one row per ``BrainPipeline.run()`` call.

    Written by the brain pipeline integration shim
    ``suite-core/core/brain_pipeline_db.py`` after each run completes.  All
    existing sqlite3 behaviour in the pipeline is UNTOUCHED; this model adds
    a parallel durable write to the enterprise database.

    ``steps_json`` holds the serialised list of ``StepResult.to_dict()``
    objects from ``PipelineResult.steps``.  This allows post-hoc analysis
    without re-running the pipeline.

    ``result_summary`` holds ``PipelineResult.to_dict()`` minus the full
    steps list (to avoid doubling storage).
    """

    __tablename__ = "pipeline_runs"

    id: Mapped[str] = mapped_column(
        "run_id",
        String(36),
        primary_key=True,
        default=_new_uuid,
        nullable=False,
    )
    org_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    # Lifecycle: pending → running → completed | failed | partial
    status: Mapped[str] = mapped_column(
        String(32),
        server_default=text("'pending'"),
        default="pending",
        nullable=False,
        index=True,
    )

    # Timing
    started_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    finished_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    total_duration_ms: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # Summary counts from PipelineResult
    findings_ingested: Mapped[int] = mapped_column(
        Integer, server_default=text("0"), default=0, nullable=False
    )
    clusters_created: Mapped[int] = mapped_column(
        Integer, server_default=text("0"), default=0, nullable=False
    )
    exposure_cases_created: Mapped[int] = mapped_column(
        Integer, server_default=text("0"), default=0, nullable=False
    )
    critical_cases: Mapped[int] = mapped_column(
        Integer, server_default=text("0"), default=0, nullable=False
    )
    avg_risk_score: Mapped[float] = mapped_column(
        Float, server_default=text("0.0"), default=0.0, nullable=False
    )

    # Full serialised step results (JSON array of StepResult dicts)
    steps_json: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)

    # Condensed result summary (JSON object — PipelineResult.to_dict() minus steps)
    result_summary: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)

    # Input summary (counts of findings by severity, source breakdown)
    input_summary: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "run_id": self.id,
            "org_id": self.org_id,
            "status": self.status,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "total_duration_ms": self.total_duration_ms,
            "findings_ingested": self.findings_ingested,
            "clusters_created": self.clusters_created,
            "exposure_cases_created": self.exposure_cases_created,
            "critical_cases": self.critical_cases,
            "avg_risk_score": self.avg_risk_score,
        }

    def __repr__(self) -> str:
        return (
            f"<PipelineRun id={self.id} org={self.org_id} "
            f"status={self.status} duration_ms={self.total_duration_ms}>"
        )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "Base",
    "Finding",
    "EvidenceBundle",
    "RemediationTask",
    "PipelineRun",
]
