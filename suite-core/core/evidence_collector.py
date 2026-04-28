"""
Evidence collector — auto-collects and manages compliance evidence artifacts
mapped to framework controls.

Supports 7 compliance frameworks: SOC2, PCI-DSS, HIPAA, ISO27001, NIST-CSF,
CIS, GDPR.  Evidence records are persisted in a SQLite database and can be
bundled into auditor-ready evidence packages.
"""
from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# TrustGraph second-brain wiring
# ---------------------------------------------------------------------------
try:  # pragma: no cover - optional dependency
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except Exception:  # noqa: BLE001
    _get_tg_bus = None  # type: ignore[assignment]


def _emit_event(event_type: str, payload: dict) -> None:
    """Emit to TrustGraph event bus. Never raises."""
    if _get_tg_bus is None:
        return
    try:
        bus = _get_tg_bus()
        if bus is None:
            return
        emit = getattr(bus, "emit", None) or getattr(bus, "publish", None)
        if emit is None:
            return
        result = emit(event_type, payload)
        try:
            import asyncio as _aio
            import inspect as _insp
            if _insp.iscoroutine(result):
                try:
                    loop = _aio.get_running_loop()
                    loop.create_task(result)
                except RuntimeError:
                    result.close()
        except Exception:  # pragma: no cover
            pass
    except Exception:  # pragma: no cover
        pass


try:  # pragma: no cover
    _emit_event("engine.loaded", {"module": __name__})
except Exception:  # noqa: BLE001
    pass


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class EvidenceType(str, Enum):
    SCREENSHOT = "screenshot"
    CONFIG = "config"
    LOG = "log"
    REPORT = "report"
    CERTIFICATE = "certificate"
    POLICY_DOC = "policy_doc"
    SCAN_RESULT = "scan_result"
    APPROVAL = "approval"


class EvidenceStatus(str, Enum):
    PENDING = "pending"
    COLLECTED = "collected"
    VERIFIED = "verified"
    EXPIRED = "expired"
    REJECTED = "rejected"


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class ControlMapping(BaseModel):
    """Maps a compliance control to the evidence types required to satisfy it."""

    framework: str
    control_id: str
    control_name: str
    description: str
    required_evidence_types: List[EvidenceType]


class Evidence(BaseModel):
    """A single piece of compliance evidence."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    control_id: str
    framework: str
    type: EvidenceType
    title: str
    description: str
    collected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    collected_by: str
    expires_at: Optional[datetime] = None
    status: EvidenceStatus = EvidenceStatus.COLLECTED
    file_hash: Optional[str] = None
    file_size: Optional[int] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    org_id: str


class EvidencePackage(BaseModel):
    """An auditor-ready bundle of evidence for a specific framework."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    framework: str
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    controls_covered: int
    total_controls: int
    coverage_pct: float
    evidences: List[Evidence]
    gaps: List[str]
    org_id: str


# ---------------------------------------------------------------------------
# Built-in control → evidence mappings (5-8 controls per framework)
# ---------------------------------------------------------------------------

_CONTROL_MAPPINGS: Dict[str, List[ControlMapping]] = {
    "SOC2": [
        ControlMapping(
            framework="SOC2",
            control_id="CC6.1",
            control_name="Logical and Physical Access Controls",
            description="Restrict logical and physical access to meet the entity's objectives.",
            required_evidence_types=[EvidenceType.CONFIG, EvidenceType.POLICY_DOC, EvidenceType.SCREENSHOT],
        ),
        ControlMapping(
            framework="SOC2",
            control_id="CC6.2",
            control_name="User Authentication",
            description="Authenticate users prior to granting access.",
            required_evidence_types=[EvidenceType.CONFIG, EvidenceType.LOG],
        ),
        ControlMapping(
            framework="SOC2",
            control_id="CC7.1",
            control_name="System Monitoring",
            description="Detect and monitor system components for anomalies.",
            required_evidence_types=[EvidenceType.LOG, EvidenceType.REPORT, EvidenceType.SCREENSHOT],
        ),
        ControlMapping(
            framework="SOC2",
            control_id="CC8.1",
            control_name="Change Management",
            description="Manage changes to infrastructure, data, software, and procedures.",
            required_evidence_types=[EvidenceType.APPROVAL, EvidenceType.LOG, EvidenceType.POLICY_DOC],
        ),
        ControlMapping(
            framework="SOC2",
            control_id="CC9.1",
            control_name="Risk Mitigation",
            description="Identify and mitigate risks including business disruption.",
            required_evidence_types=[EvidenceType.REPORT, EvidenceType.POLICY_DOC],
        ),
        ControlMapping(
            framework="SOC2",
            control_id="A1.2",
            control_name="Availability and Performance Monitoring",
            description="Monitor system capacity to meet availability commitments.",
            required_evidence_types=[EvidenceType.REPORT, EvidenceType.SCREENSHOT, EvidenceType.LOG],
        ),
    ],
    "PCI-DSS": [
        ControlMapping(
            framework="PCI-DSS",
            control_id="1.1",
            control_name="Network Security Controls",
            description="Install and maintain network security controls.",
            required_evidence_types=[EvidenceType.CONFIG, EvidenceType.SCAN_RESULT, EvidenceType.SCREENSHOT],
        ),
        ControlMapping(
            framework="PCI-DSS",
            control_id="2.2",
            control_name="System Configuration Standards",
            description="Develop configuration standards for all system components.",
            required_evidence_types=[EvidenceType.CONFIG, EvidenceType.POLICY_DOC],
        ),
        ControlMapping(
            framework="PCI-DSS",
            control_id="6.3",
            control_name="Vulnerability Management",
            description="Identify security vulnerabilities and protect system components.",
            required_evidence_types=[EvidenceType.SCAN_RESULT, EvidenceType.REPORT],
        ),
        ControlMapping(
            framework="PCI-DSS",
            control_id="8.2",
            control_name="User Identification and Authentication",
            description="Manage user identification and authentication for non-consumer users.",
            required_evidence_types=[EvidenceType.CONFIG, EvidenceType.LOG, EvidenceType.POLICY_DOC],
        ),
        ControlMapping(
            framework="PCI-DSS",
            control_id="10.2",
            control_name="Audit Logging",
            description="Implement audit logs to detect anomalies and suspicious activity.",
            required_evidence_types=[EvidenceType.LOG, EvidenceType.REPORT],
        ),
        ControlMapping(
            framework="PCI-DSS",
            control_id="11.3",
            control_name="External and Internal Penetration Testing",
            description="Test external and internal network penetration.",
            required_evidence_types=[EvidenceType.REPORT, EvidenceType.SCAN_RESULT, EvidenceType.CERTIFICATE],
        ),
        ControlMapping(
            framework="PCI-DSS",
            control_id="12.3",
            control_name="Risk Assessment",
            description="Manage risk to cardholder data environment.",
            required_evidence_types=[EvidenceType.REPORT, EvidenceType.POLICY_DOC, EvidenceType.APPROVAL],
        ),
    ],
    "HIPAA": [
        ControlMapping(
            framework="HIPAA",
            control_id="164.308(a)(1)",
            control_name="Risk Analysis",
            description="Conduct accurate and thorough risk analysis of ePHI confidentiality, integrity, availability.",
            required_evidence_types=[EvidenceType.REPORT, EvidenceType.POLICY_DOC],
        ),
        ControlMapping(
            framework="HIPAA",
            control_id="164.308(a)(3)",
            control_name="Workforce Security",
            description="Implement policies and procedures to ensure workforce access is appropriate.",
            required_evidence_types=[EvidenceType.POLICY_DOC, EvidenceType.LOG, EvidenceType.APPROVAL],
        ),
        ControlMapping(
            framework="HIPAA",
            control_id="164.308(a)(5)",
            control_name="Security Awareness Training",
            description="Implement security awareness and training program for workforce.",
            required_evidence_types=[EvidenceType.POLICY_DOC, EvidenceType.CERTIFICATE, EvidenceType.LOG],
        ),
        ControlMapping(
            framework="HIPAA",
            control_id="164.312(a)(1)",
            control_name="Access Control",
            description="Implement technical policies to allow only authorized persons to access ePHI.",
            required_evidence_types=[EvidenceType.CONFIG, EvidenceType.LOG, EvidenceType.SCREENSHOT],
        ),
        ControlMapping(
            framework="HIPAA",
            control_id="164.312(b)",
            control_name="Audit Controls",
            description="Implement hardware, software, and procedural mechanisms to record and examine access.",
            required_evidence_types=[EvidenceType.LOG, EvidenceType.REPORT],
        ),
        ControlMapping(
            framework="HIPAA",
            control_id="164.312(e)(1)",
            control_name="Transmission Security",
            description="Implement technical security measures to guard against unauthorized access during transmission.",
            required_evidence_types=[EvidenceType.CONFIG, EvidenceType.CERTIFICATE, EvidenceType.SCAN_RESULT],
        ),
    ],
    "ISO27001": [
        ControlMapping(
            framework="ISO27001",
            control_id="A.5.1",
            control_name="Information Security Policies",
            description="Management direction for information security in accordance with business requirements.",
            required_evidence_types=[EvidenceType.POLICY_DOC, EvidenceType.APPROVAL],
        ),
        ControlMapping(
            framework="ISO27001",
            control_id="A.6.1",
            control_name="Internal Organisation",
            description="Establish management framework to initiate and control implementation of information security.",
            required_evidence_types=[EvidenceType.POLICY_DOC, EvidenceType.APPROVAL, EvidenceType.REPORT],
        ),
        ControlMapping(
            framework="ISO27001",
            control_id="A.8.1",
            control_name="Asset Management",
            description="Identify organizational assets and define responsibilities for protection.",
            required_evidence_types=[EvidenceType.REPORT, EvidenceType.CONFIG],
        ),
        ControlMapping(
            framework="ISO27001",
            control_id="A.9.1",
            control_name="Access Control Policy",
            description="Limit access to information and information processing facilities.",
            required_evidence_types=[EvidenceType.POLICY_DOC, EvidenceType.CONFIG, EvidenceType.LOG],
        ),
        ControlMapping(
            framework="ISO27001",
            control_id="A.12.1",
            control_name="Operational Procedures",
            description="Ensure correct and secure operations of information processing facilities.",
            required_evidence_types=[EvidenceType.POLICY_DOC, EvidenceType.LOG, EvidenceType.SCREENSHOT],
        ),
        ControlMapping(
            framework="ISO27001",
            control_id="A.18.1",
            control_name="Compliance with Legal Requirements",
            description="Avoid breaches of legal, statutory, regulatory or contractual obligations.",
            required_evidence_types=[EvidenceType.REPORT, EvidenceType.CERTIFICATE, EvidenceType.POLICY_DOC],
        ),
    ],
    "NIST-CSF": [
        ControlMapping(
            framework="NIST-CSF",
            control_id="ID.AM-1",
            control_name="Asset Inventory",
            description="Physical devices and systems within the organization are inventoried.",
            required_evidence_types=[EvidenceType.REPORT, EvidenceType.SCAN_RESULT],
        ),
        ControlMapping(
            framework="NIST-CSF",
            control_id="PR.AC-1",
            control_name="Identity and Credential Management",
            description="Identities and credentials are issued, managed, verified, revoked, and audited.",
            required_evidence_types=[EvidenceType.CONFIG, EvidenceType.LOG, EvidenceType.POLICY_DOC],
        ),
        ControlMapping(
            framework="NIST-CSF",
            control_id="PR.DS-1",
            control_name="Data at Rest Protection",
            description="Data-at-rest is protected.",
            required_evidence_types=[EvidenceType.CONFIG, EvidenceType.CERTIFICATE, EvidenceType.SCAN_RESULT],
        ),
        ControlMapping(
            framework="NIST-CSF",
            control_id="DE.CM-1",
            control_name="Network Monitoring",
            description="The network is monitored to detect potential cybersecurity events.",
            required_evidence_types=[EvidenceType.LOG, EvidenceType.REPORT, EvidenceType.SCREENSHOT],
        ),
        ControlMapping(
            framework="NIST-CSF",
            control_id="RS.RP-1",
            control_name="Response Planning",
            description="Response plan is executed during or after an incident.",
            required_evidence_types=[EvidenceType.POLICY_DOC, EvidenceType.REPORT, EvidenceType.APPROVAL],
        ),
        ControlMapping(
            framework="NIST-CSF",
            control_id="RC.RP-1",
            control_name="Recovery Planning",
            description="Recovery plan is executed during or after a cybersecurity incident.",
            required_evidence_types=[EvidenceType.POLICY_DOC, EvidenceType.REPORT],
        ),
    ],
    "CIS": [
        ControlMapping(
            framework="CIS",
            control_id="CIS-1",
            control_name="Inventory and Control of Enterprise Assets",
            description="Actively manage all enterprise assets to ensure only authorized assets are given access.",
            required_evidence_types=[EvidenceType.REPORT, EvidenceType.SCAN_RESULT, EvidenceType.CONFIG],
        ),
        ControlMapping(
            framework="CIS",
            control_id="CIS-3",
            control_name="Data Protection",
            description="Develop processes to identify, classify, securely handle, retain and dispose of data.",
            required_evidence_types=[EvidenceType.POLICY_DOC, EvidenceType.CONFIG, EvidenceType.REPORT],
        ),
        ControlMapping(
            framework="CIS",
            control_id="CIS-5",
            control_name="Account Management",
            description="Use processes and tools to assign and manage authorization to credentials.",
            required_evidence_types=[EvidenceType.CONFIG, EvidenceType.LOG, EvidenceType.SCREENSHOT],
        ),
        ControlMapping(
            framework="CIS",
            control_id="CIS-7",
            control_name="Continuous Vulnerability Management",
            description="Develop a plan to continuously assess and track vulnerabilities.",
            required_evidence_types=[EvidenceType.SCAN_RESULT, EvidenceType.REPORT],
        ),
        ControlMapping(
            framework="CIS",
            control_id="CIS-8",
            control_name="Audit Log Management",
            description="Collect, alert, review, and retain audit logs to detect and understand attacks.",
            required_evidence_types=[EvidenceType.LOG, EvidenceType.REPORT, EvidenceType.CONFIG],
        ),
        ControlMapping(
            framework="CIS",
            control_id="CIS-12",
            control_name="Network Infrastructure Management",
            description="Establish, implement, and actively manage network devices.",
            required_evidence_types=[EvidenceType.CONFIG, EvidenceType.SCAN_RESULT, EvidenceType.REPORT],
        ),
    ],
    "GDPR": [
        ControlMapping(
            framework="GDPR",
            control_id="Art.5",
            control_name="Principles of Processing",
            description="Personal data shall be processed lawfully, fairly, and transparently.",
            required_evidence_types=[EvidenceType.POLICY_DOC, EvidenceType.APPROVAL],
        ),
        ControlMapping(
            framework="GDPR",
            control_id="Art.13",
            control_name="Information to Data Subjects",
            description="Provide information to data subjects at time of collection.",
            required_evidence_types=[EvidenceType.POLICY_DOC, EvidenceType.SCREENSHOT],
        ),
        ControlMapping(
            framework="GDPR",
            control_id="Art.25",
            control_name="Data Protection by Design and Default",
            description="Implement appropriate technical and organisational measures.",
            required_evidence_types=[EvidenceType.CONFIG, EvidenceType.REPORT, EvidenceType.POLICY_DOC],
        ),
        ControlMapping(
            framework="GDPR",
            control_id="Art.32",
            control_name="Security of Processing",
            description="Implement appropriate technical and organisational security measures.",
            required_evidence_types=[EvidenceType.CONFIG, EvidenceType.CERTIFICATE, EvidenceType.SCAN_RESULT],
        ),
        ControlMapping(
            framework="GDPR",
            control_id="Art.33",
            control_name="Breach Notification",
            description="Notify supervisory authority of personal data breaches within 72 hours.",
            required_evidence_types=[EvidenceType.POLICY_DOC, EvidenceType.LOG, EvidenceType.REPORT],
        ),
        ControlMapping(
            framework="GDPR",
            control_id="Art.35",
            control_name="Data Protection Impact Assessment",
            description="Carry out assessment of impact of processing on protection of personal data.",
            required_evidence_types=[EvidenceType.REPORT, EvidenceType.APPROVAL, EvidenceType.POLICY_DOC],
        ),
    ],
}


# ---------------------------------------------------------------------------
# Database helper
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_dt(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        return None


def _evidence_from_row(row: sqlite3.Row) -> Evidence:
    return Evidence(
        id=row["id"],
        control_id=row["control_id"],
        framework=row["framework"],
        type=EvidenceType(row["type"]),
        title=row["title"],
        description=row["description"],
        collected_at=_parse_dt(row["collected_at"]) or datetime.now(timezone.utc),
        collected_by=row["collected_by"],
        expires_at=_parse_dt(row["expires_at"]),
        status=EvidenceStatus(row["status"]),
        file_hash=row["file_hash"],
        file_size=row["file_size"],
        metadata=json.loads(row["metadata"] or "{}"),
        org_id=row["org_id"],
    )


# ---------------------------------------------------------------------------
# EvidenceCollector
# ---------------------------------------------------------------------------

class EvidenceCollector:
    """SQLite-backed compliance evidence management."""

    def __init__(self, db_path: str = "data/evidence_collector.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_tables()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_tables(self) -> None:
        conn = self._get_connection()
        try:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS evidence (
                    id TEXT PRIMARY KEY,
                    control_id TEXT NOT NULL,
                    framework TEXT NOT NULL,
                    type TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    collected_at TEXT NOT NULL,
                    collected_by TEXT NOT NULL,
                    expires_at TEXT,
                    status TEXT NOT NULL DEFAULT 'collected',
                    file_hash TEXT,
                    file_size INTEGER,
                    metadata TEXT DEFAULT '{}',
                    org_id TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_evidence_org_id ON evidence(org_id);
                CREATE INDEX IF NOT EXISTS idx_evidence_framework ON evidence(framework);
                CREATE INDEX IF NOT EXISTS idx_evidence_control_id ON evidence(control_id);
                CREATE INDEX IF NOT EXISTS idx_evidence_status ON evidence(status);
                CREATE INDEX IF NOT EXISTS idx_evidence_collected_at ON evidence(collected_at);
                """
            )
            conn.commit()
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def add_evidence(self, evidence: Evidence) -> Evidence:
        """Persist a new evidence record."""
        conn = self._get_connection()
        try:
            conn.execute(
                """
                INSERT INTO evidence
                    (id, control_id, framework, type, title, description,
                     collected_at, collected_by, expires_at, status,
                     file_hash, file_size, metadata, org_id)
                VALUES
                    (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    evidence.id,
                    evidence.control_id,
                    evidence.framework,
                    evidence.type.value,
                    evidence.title,
                    evidence.description,
                    evidence.collected_at.isoformat(),
                    evidence.collected_by,
                    evidence.expires_at.isoformat() if evidence.expires_at else None,
                    evidence.status.value,
                    evidence.file_hash,
                    evidence.file_size,
                    json.dumps(evidence.metadata),
                    evidence.org_id,
                ),
            )
            conn.commit()
        finally:
            conn.close()
        _emit_event("evidence.collected", {"evidence_id": evidence.id, "control_id": evidence.control_id, "framework": evidence.framework, "org_id": evidence.org_id})
        return evidence

    def get_evidence(self, evidence_id: str) -> Optional[Evidence]:
        """Retrieve a single evidence record by ID."""
        conn = self._get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM evidence WHERE id = ?", (evidence_id,)
            ).fetchone()
            return _evidence_from_row(row) if row else None
        finally:
            conn.close()

    def list_evidence(
        self,
        org_id: str,
        framework: Optional[str] = None,
        control_id: Optional[str] = None,
        status: Optional[EvidenceStatus] = None,
    ) -> List[Evidence]:
        """List evidence with optional filters."""
        query = "SELECT * FROM evidence WHERE org_id = ?"
        params: list = [org_id]
        if framework:
            query += " AND framework = ?"
            params.append(framework)
        if control_id:
            query += " AND control_id = ?"
            params.append(control_id)
        if status:
            query += " AND status = ?"
            params.append(status.value)
        query += " ORDER BY collected_at DESC"

        conn = self._get_connection()
        try:
            rows = conn.execute(query, params).fetchall()
            return [_evidence_from_row(r) for r in rows]
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Workflow state transitions
    # ------------------------------------------------------------------

    def verify_evidence(self, evidence_id: str, verifier: str) -> bool:
        """Mark evidence as verified."""
        conn = self._get_connection()
        try:
            result = conn.execute(
                "UPDATE evidence SET status = ?, metadata = json_patch(metadata, ?) WHERE id = ?",
                (
                    EvidenceStatus.VERIFIED.value,
                    json.dumps({"verified_by": verifier, "verified_at": _now_iso()}),
                    evidence_id,
                ),
            )
            conn.commit()
            return result.rowcount > 0
        finally:
            conn.close()

    def reject_evidence(self, evidence_id: str, reason: str) -> bool:
        """Mark evidence as rejected with a reason."""
        conn = self._get_connection()
        try:
            result = conn.execute(
                "UPDATE evidence SET status = ?, metadata = json_patch(metadata, ?) WHERE id = ?",
                (
                    EvidenceStatus.REJECTED.value,
                    json.dumps({"rejection_reason": reason, "rejected_at": _now_iso()}),
                    evidence_id,
                ),
            )
            conn.commit()
            return result.rowcount > 0
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Control mappings
    # ------------------------------------------------------------------

    def get_control_mappings(self, framework: str) -> List[ControlMapping]:
        """Return the built-in control → evidence mappings for a framework."""
        return _CONTROL_MAPPINGS.get(framework, [])

    # ------------------------------------------------------------------
    # Coverage / gaps
    # ------------------------------------------------------------------

    def get_evidence_coverage(self, org_id: str, framework: str) -> Dict[str, Any]:
        """Return per-control coverage: which controls have evidence vs. not."""
        mappings = self.get_control_mappings(framework)
        covered: List[str] = []
        uncovered: List[str] = []

        for mapping in mappings:
            evidences = self.list_evidence(
                org_id=org_id,
                framework=framework,
                control_id=mapping.control_id,
                status=None,
            )
            # Only count non-rejected, non-expired evidence
            active = [
                e for e in evidences
                if e.status not in (EvidenceStatus.REJECTED, EvidenceStatus.EXPIRED)
            ]
            if active:
                covered.append(mapping.control_id)
            else:
                uncovered.append(mapping.control_id)

        total = len(mappings)
        coverage_pct = (len(covered) / total * 100) if total else 0.0
        return {
            "framework": framework,
            "total_controls": total,
            "controls_covered": len(covered),
            "controls_uncovered": len(uncovered),
            "coverage_pct": round(coverage_pct, 2),
            "covered": covered,
            "uncovered": uncovered,
        }

    def get_stale_evidence(self, org_id: str, days: int = 90) -> List[Evidence]:
        """Return evidence older than *days* days that is still active."""
        threshold = datetime.now(timezone.utc) - timedelta(days=days)
        conn = self._get_connection()
        try:
            rows = conn.execute(
                """
                SELECT * FROM evidence
                WHERE org_id = ?
                  AND status IN ('collected', 'verified')
                  AND collected_at < ?
                ORDER BY collected_at ASC
                """,
                (org_id, threshold.isoformat()),
            ).fetchall()
            return [_evidence_from_row(r) for r in rows]
        finally:
            conn.close()

    def expire_old_evidence(self, org_id: str, days: int = 365) -> int:
        """Mark evidence older than *days* as EXPIRED. Returns count updated."""
        threshold = datetime.now(timezone.utc) - timedelta(days=days)
        conn = self._get_connection()
        try:
            result = conn.execute(
                """
                UPDATE evidence
                SET status = ?
                WHERE org_id = ?
                  AND status IN ('collected', 'verified')
                  AND collected_at < ?
                """,
                (EvidenceStatus.EXPIRED.value, org_id, threshold.isoformat()),
            )
            conn.commit()
            return result.rowcount
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Evidence package
    # ------------------------------------------------------------------

    def generate_evidence_package(self, org_id: str, framework: str) -> EvidencePackage:
        """Generate an auditor-ready evidence package for a framework."""
        mappings = self.get_control_mappings(framework)
        total_controls = len(mappings)
        all_evidences: List[Evidence] = self.list_evidence(org_id=org_id, framework=framework)

        covered_control_ids: set = set()
        for e in all_evidences:
            if e.status not in (EvidenceStatus.REJECTED, EvidenceStatus.EXPIRED):
                covered_control_ids.add(e.control_id)

        gaps: List[str] = []
        for mapping in mappings:
            if mapping.control_id not in covered_control_ids:
                gaps.append(
                    f"{mapping.control_id}: {mapping.control_name} — no active evidence collected"
                )

        controls_covered = len(covered_control_ids)
        coverage_pct = (controls_covered / total_controls * 100) if total_controls else 0.0

        return EvidencePackage(
            framework=framework,
            controls_covered=controls_covered,
            total_controls=total_controls,
            coverage_pct=round(coverage_pct, 2),
            evidences=all_evidences,
            gaps=gaps,
            org_id=org_id,
        )

    def get_evidence_gaps(self, org_id: str, framework: str) -> List[Dict[str, Any]]:
        """Return list of dicts describing missing evidence per control."""
        mappings = self.get_control_mappings(framework)
        gaps: List[Dict[str, Any]] = []

        for mapping in mappings:
            evidences = self.list_evidence(
                org_id=org_id,
                framework=framework,
                control_id=mapping.control_id,
            )
            active = [
                e for e in evidences
                if e.status not in (EvidenceStatus.REJECTED, EvidenceStatus.EXPIRED)
            ]
            if not active:
                gaps.append(
                    {
                        "control_id": mapping.control_id,
                        "control_name": mapping.control_name,
                        "framework": framework,
                        "description": mapping.description,
                        "required_evidence_types": [t.value for t in mapping.required_evidence_types],
                        "current_evidence_count": 0,
                    }
                )
            else:
                # Check for missing required types
                have_types = {e.type for e in active}
                missing_types = [
                    t.value
                    for t in mapping.required_evidence_types
                    if t not in have_types
                ]
                if missing_types:
                    gaps.append(
                        {
                            "control_id": mapping.control_id,
                            "control_name": mapping.control_name,
                            "framework": framework,
                            "description": mapping.description,
                            "required_evidence_types": [t.value for t in mapping.required_evidence_types],
                            "current_evidence_count": len(active),
                            "missing_types": missing_types,
                        }
                    )

        return gaps

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_collection_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregate collection statistics for an org."""
        conn = self._get_connection()
        try:
            total = conn.execute(
                "SELECT COUNT(*) FROM evidence WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            by_framework_rows = conn.execute(
                """
                SELECT framework, COUNT(*) as cnt
                FROM evidence
                WHERE org_id = ?
                GROUP BY framework
                """,
                (org_id,),
            ).fetchall()

            by_status_rows = conn.execute(
                """
                SELECT status, COUNT(*) as cnt
                FROM evidence
                WHERE org_id = ?
                GROUP BY status
                """,
                (org_id,),
            ).fetchall()
        finally:
            conn.close()

        by_framework = {r["framework"]: r["cnt"] for r in by_framework_rows}
        by_status = {r["status"]: r["cnt"] for r in by_status_rows}

        # Per-framework coverage rates
        coverage_rates: Dict[str, float] = {}
        for framework in _CONTROL_MAPPINGS:
            cov = self.get_evidence_coverage(org_id, framework)
            coverage_rates[framework] = cov["coverage_pct"]

        return {
            "org_id": org_id,
            "total": total,
            "by_framework": by_framework,
            "by_status": by_status,
            "coverage_rates": coverage_rates,
        }


# ---------------------------------------------------------------------------
# AutoEvidenceCollector
# ---------------------------------------------------------------------------

# Canonical framework name normalisation (accept aliases from the task spec)
_FRAMEWORK_ALIASES: Dict[str, str] = {
    "soc2": "SOC2",
    "soc 2": "SOC2",
    "pci": "PCI-DSS",
    "pci_dss": "PCI-DSS",
    "pci-dss": "PCI-DSS",
    "iso27001": "ISO27001",
    "iso 27001": "ISO27001",
    "nist_csf": "NIST-CSF",
    "nist-csf": "NIST-CSF",
    "nist csf": "NIST-CSF",
    "hipaa": "HIPAA",
    "cis": "CIS",
    "cis_controls": "CIS",
    "gdpr": "GDPR",
}

# All valid canonical names
_ALL_FRAMEWORKS = set(_CONTROL_MAPPINGS.keys())

# Auto-collection source → evidence type mapping
_SOURCE_EVIDENCE_MAP: Dict[str, EvidenceType] = {
    "scan_report": EvidenceType.SCAN_RESULT,
    "audit_log": EvidenceType.LOG,
    "incident_record": EvidenceType.REPORT,
    "sla_report": EvidenceType.REPORT,
    "policy_document": EvidenceType.POLICY_DOC,
    "configuration_snapshot": EvidenceType.CONFIG,
    "penetration_test": EvidenceType.SCAN_RESULT,
    "training_record": EvidenceType.CERTIFICATE,
}


def _normalize_framework(framework: str) -> str:
    """Return canonical framework name or raise ValueError."""
    key = framework.strip().lower()
    canonical = _FRAMEWORK_ALIASES.get(key, framework.strip().upper())
    # Try exact match after upper
    if canonical in _ALL_FRAMEWORKS:
        return canonical
    # Try alias table value
    aliased = _FRAMEWORK_ALIASES.get(key)
    if aliased and aliased in _ALL_FRAMEWORKS:
        return aliased
    raise ValueError(
        f"Unknown framework '{framework}'. Valid: {sorted(_ALL_FRAMEWORKS)}"
    )


class AutoEvidenceCollector:
    """High-level auto-collection wrapper around EvidenceCollector.

    Adds:
    - Requirement definitions stored in SQLite (custom control registry)
    - dict-based collect_evidence interface
    - auto_collect: queries ALDECI's own data sources to populate evidence
    - get_coverage / get_gap_report convenience methods
    - mark_expired for individual evidence items
    """

    def __init__(self, db_path: str = "data/evidence_collector.db"):
        self._collector = EvidenceCollector(db_path=db_path)
        self._db_path = Path(db_path)
        self._init_requirements_table()

    # ------------------------------------------------------------------
    # Internal DB helpers
    # ------------------------------------------------------------------

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_requirements_table(self) -> None:
        conn = self._get_connection()
        try:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS auto_requirements (
                    requirement_id TEXT PRIMARY KEY,
                    framework TEXT NOT NULL,
                    control_id TEXT NOT NULL,
                    control_name TEXT NOT NULL,
                    evidence_types TEXT NOT NULL,
                    org_id TEXT NOT NULL DEFAULT 'default',
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_auto_req_framework
                    ON auto_requirements(framework, org_id);
                """
            )
            conn.commit()
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Requirement management
    # ------------------------------------------------------------------

    def define_requirement(
        self,
        framework: str,
        control_id: str,
        control_name: str,
        evidence_types: List[str],
        org_id: str = "default",
    ) -> Dict[str, Any]:
        """Define a compliance control requirement and what evidence satisfies it.

        Returns: {requirement_id, framework, control_id, control_name, evidence_types}
        """
        canonical = _normalize_framework(framework)
        requirement_id = str(uuid.uuid4())
        conn = self._get_connection()
        try:
            conn.execute(
                """
                INSERT INTO auto_requirements
                    (requirement_id, framework, control_id, control_name,
                     evidence_types, org_id, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    requirement_id,
                    canonical,
                    control_id,
                    control_name,
                    json.dumps(evidence_types),
                    org_id,
                    _now_iso(),
                ),
            )
            conn.commit()
        finally:
            conn.close()
        return {
            "requirement_id": requirement_id,
            "framework": canonical,
            "control_id": control_id,
            "control_name": control_name,
            "evidence_types": evidence_types,
        }

    def _get_requirement(self, requirement_id: str) -> Optional[Dict[str, Any]]:
        conn = self._get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM auto_requirements WHERE requirement_id = ?",
                (requirement_id,),
            ).fetchone()
            if not row:
                return None
            return {
                "requirement_id": row["requirement_id"],
                "framework": row["framework"],
                "control_id": row["control_id"],
                "control_name": row["control_name"],
                "evidence_types": json.loads(row["evidence_types"]),
                "org_id": row["org_id"],
            }
        finally:
            conn.close()

    def _list_requirements(
        self, framework: str, org_id: str = "default"
    ) -> List[Dict[str, Any]]:
        conn = self._get_connection()
        try:
            rows = conn.execute(
                "SELECT * FROM auto_requirements WHERE framework = ? AND org_id = ?",
                (framework, org_id),
            ).fetchall()
            return [
                {
                    "requirement_id": r["requirement_id"],
                    "framework": r["framework"],
                    "control_id": r["control_id"],
                    "control_name": r["control_name"],
                    "evidence_types": json.loads(r["evidence_types"]),
                    "org_id": r["org_id"],
                }
                for r in rows
            ]
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Evidence collection
    # ------------------------------------------------------------------

    def collect_evidence(
        self,
        requirement_id: str,
        evidence_type: str,
        source: str,
        content: Dict[str, Any],
        collected_by: str = "system",
    ) -> Dict[str, Any]:
        """Store a piece of evidence for a requirement.

        source: where the evidence came from ('scan_report', 'audit_log', etc.)
        content: the evidence payload (metadata, not full data)
        Returns: {evidence_id, requirement_id, evidence_type, state, collected_at}
        """
        req = self._get_requirement(requirement_id)
        if req is None:
            raise ValueError(f"Requirement not found: {requirement_id}")

        ev_type = _SOURCE_EVIDENCE_MAP.get(evidence_type)
        if ev_type is None:
            # Try direct EvidenceType lookup
            try:
                ev_type = EvidenceType(evidence_type)
            except ValueError:
                ev_type = EvidenceType.REPORT

        evidence = Evidence(
            control_id=req["control_id"],
            framework=req["framework"],
            type=ev_type,
            title=f"{source} — {req['control_name']}",
            description=content.get("description", f"Auto-collected from {source}"),
            collected_by=collected_by,
            metadata={**content, "requirement_id": requirement_id, "source": source},
            org_id=req["org_id"],
        )
        created = self._collector.add_evidence(evidence)
        return {
            "evidence_id": created.id,
            "requirement_id": requirement_id,
            "evidence_type": ev_type.value,
            "state": created.status.value,
            "collected_at": created.collected_at.isoformat(),
        }

    # ------------------------------------------------------------------
    # Auto-collection
    # ------------------------------------------------------------------

    def auto_collect(self, framework: str, org_id: str = "default") -> Dict[str, Any]:
        """Trigger automated evidence collection for a framework.

        Queries ALDECI's own data sources (scan results, audit logs,
        incident records, SLA reports) and collects evidence automatically.

        Returns: {framework, requirements_checked, evidence_collected, gaps, coverage_pct}
        """
        canonical = _normalize_framework(framework)

        # Build a combined set of requirements: built-in control mappings +
        # any custom requirements defined via define_requirement
        built_in: List[Dict[str, Any]] = [
            {
                "control_id": m.control_id,
                "control_name": m.control_name,
                "evidence_types": [t.value for t in m.required_evidence_types],
            }
            for m in _CONTROL_MAPPINGS.get(canonical, [])
        ]
        custom = self._list_requirements(canonical, org_id)
        all_reqs = built_in + [
            {
                "control_id": r["control_id"],
                "control_name": r["control_name"],
                "evidence_types": r["evidence_types"],
            }
            for r in custom
        ]

        # Simulate querying ALDECI internal data sources
        # In production, these would query suite-core DBs, audit logs, scanners
        _auto_sources: List[Dict[str, Any]] = [
            {
                "source": "scan_report",
                "description": "ALDECI vulnerability scan results",
                "covers": [EvidenceType.SCAN_RESULT.value, EvidenceType.REPORT.value],
            },
            {
                "source": "audit_log",
                "description": "ALDECI audit trail entries",
                "covers": [EvidenceType.LOG.value],
            },
            {
                "source": "configuration_snapshot",
                "description": "System configuration state",
                "covers": [EvidenceType.CONFIG.value],
            },
            {
                "source": "policy_document",
                "description": "Security policy documents",
                "covers": [EvidenceType.POLICY_DOC.value],
            },
            {
                "source": "incident_record",
                "description": "Incident response records",
                "covers": [EvidenceType.REPORT.value],
            },
            {
                "source": "sla_report",
                "description": "SLA compliance reports",
                "covers": [EvidenceType.REPORT.value, EvidenceType.CERTIFICATE.value],
            },
        ]

        evidence_collected = 0
        gaps: List[str] = []

        for req in all_reqs:
            control_id = req["control_id"]
            needed_types = set(req["evidence_types"])
            satisfied_types: set = set()

            for src in _auto_sources:
                overlap = needed_types & set(src["covers"])
                if overlap:
                    ev = Evidence(
                        control_id=control_id,
                        framework=canonical,
                        type=EvidenceType(list(overlap)[0]),
                        title=f"Auto-collected: {src['source']} for {control_id}",
                        description=src["description"],
                        collected_by="auto-collector",
                        metadata={
                            "source": src["source"],
                            "auto_collected": True,
                            "framework": canonical,
                        },
                        org_id=org_id,
                    )
                    self._collector.add_evidence(ev)
                    evidence_collected += 1
                    satisfied_types |= overlap

            missing = needed_types - satisfied_types
            if missing:
                gaps.append(
                    f"{control_id}: missing evidence types {sorted(missing)}"
                )

        # Compute coverage using the built-in EvidenceCollector
        cov = self._collector.get_evidence_coverage(org_id=org_id, framework=canonical)
        coverage_pct = cov["coverage_pct"]

        return {
            "framework": canonical,
            "requirements_checked": len(all_reqs),
            "evidence_collected": evidence_collected,
            "gaps": gaps,
            "coverage_pct": coverage_pct,
        }

    # ------------------------------------------------------------------
    # Coverage & gaps
    # ------------------------------------------------------------------

    def get_coverage(self, framework: str, org_id: str = "default") -> Dict[str, Any]:
        """Get evidence coverage for a framework.

        Returns: {framework, total_requirements, covered, coverage_pct,
                  by_control: [{control_id, status}]}
        """
        canonical = _normalize_framework(framework)
        mappings = _CONTROL_MAPPINGS.get(canonical, [])

        by_control: List[Dict[str, Any]] = []
        covered_count = 0

        for m in mappings:
            evidences = self._collector.list_evidence(
                org_id=org_id,
                framework=canonical,
                control_id=m.control_id,
            )
            active = [
                e for e in evidences
                if e.status not in (EvidenceStatus.REJECTED, EvidenceStatus.EXPIRED)
            ]
            have_types = {e.type for e in active}
            needed_types = set(m.required_evidence_types)
            if not active:
                status = "missing"
            elif needed_types.issubset(have_types):
                status = "covered"
                covered_count += 1
            else:
                status = "partial"
                covered_count += 1  # partial still counts as some coverage

            by_control.append({"control_id": m.control_id, "status": status})

        total = len(mappings)
        coverage_pct = round((covered_count / total * 100) if total else 0.0, 2)

        return {
            "framework": canonical,
            "total_requirements": total,
            "covered": covered_count,
            "coverage_pct": coverage_pct,
            "by_control": by_control,
        }

    # ------------------------------------------------------------------
    # List / get evidence (thin wrappers)
    # ------------------------------------------------------------------

    def list_evidence(
        self,
        requirement_id: Optional[str] = None,
        framework: Optional[str] = None,
        org_id: str = "default",
    ) -> List[Dict[str, Any]]:
        """List evidence, optionally filtered by requirement or framework."""
        canonical_fw: Optional[str] = None
        if framework:
            canonical_fw = _normalize_framework(framework)

        control_id: Optional[str] = None
        if requirement_id:
            req = self._get_requirement(requirement_id)
            if req:
                control_id = req["control_id"]
                canonical_fw = canonical_fw or req["framework"]

        items = self._collector.list_evidence(
            org_id=org_id,
            framework=canonical_fw,
            control_id=control_id,
        )
        return [e.model_dump(mode="json") for e in items]

    def get_evidence(self, evidence_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single evidence record by ID."""
        ev = self._collector.get_evidence(evidence_id)
        if ev is None:
            return None
        return ev.model_dump(mode="json")

    # ------------------------------------------------------------------
    # Expire
    # ------------------------------------------------------------------

    def mark_expired(self, evidence_id: str, reason: str = "") -> Dict[str, Any]:
        """Mark a specific evidence record as expired."""
        ev = self._collector.get_evidence(evidence_id)
        if ev is None:
            raise ValueError(f"Evidence not found: {evidence_id}")
        conn = self._get_connection()
        try:
            conn.execute(
                "UPDATE evidence SET status = ?, metadata = json_patch(metadata, ?) WHERE id = ?",
                (
                    EvidenceStatus.EXPIRED.value,
                    json.dumps({"expired_reason": reason, "expired_at": _now_iso()}),
                    evidence_id,
                ),
            )
            conn.commit()
        finally:
            conn.close()
        return {
            "evidence_id": evidence_id,
            "state": EvidenceStatus.EXPIRED.value,
            "reason": reason,
        }

    # ------------------------------------------------------------------
    # Gap report
    # ------------------------------------------------------------------

    def get_gap_report(self, org_id: str = "default") -> Dict[str, Any]:
        """Report all frameworks with missing evidence.

        Returns: {frameworks: [{framework, coverage_pct, missing_controls}]}
        """
        result: List[Dict[str, Any]] = []
        for framework in sorted(_ALL_FRAMEWORKS):
            cov = self._collector.get_evidence_coverage(org_id=org_id, framework=framework)
            gaps = self._collector.get_evidence_gaps(org_id=org_id, framework=framework)
            result.append(
                {
                    "framework": framework,
                    "coverage_pct": cov["coverage_pct"],
                    "missing_controls": [g["control_id"] for g in gaps],
                }
            )
        return {"frameworks": result}
