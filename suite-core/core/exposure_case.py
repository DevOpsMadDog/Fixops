"""
Exposure Case Model — Step 4 of the ALdeci Brain Data Flow.

Collapses 100 noisy scanner findings into ~32 actionable Exposure Cases.
Each case is a first-class entity with a full lifecycle:
    OPEN → TRIAGING → FIXING → RESOLVED → CLOSED

An Exposure Case groups deduplication clusters that share the same root
vulnerability/weakness across multiple assets, creating a single
remediation unit with blast-radius awareness.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


class CaseStatus(str, Enum):
    """Lifecycle states for an Exposure Case."""

    OPEN = "open"
    TRIAGING = "triaging"
    FIXING = "fixing"
    RESOLVED = "resolved"
    CLOSED = "closed"
    ACCEPTED_RISK = "accepted_risk"
    FALSE_POSITIVE = "false_positive"


class CasePriority(str, Enum):
    """Priority levels for Exposure Cases."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


VALID_TRANSITIONS: Dict[CaseStatus, Set[CaseStatus]] = {
    CaseStatus.OPEN: {
        CaseStatus.TRIAGING,
        CaseStatus.ACCEPTED_RISK,
        CaseStatus.FALSE_POSITIVE,
    },
    CaseStatus.TRIAGING: {
        CaseStatus.FIXING,
        CaseStatus.ACCEPTED_RISK,
        CaseStatus.FALSE_POSITIVE,
        CaseStatus.OPEN,
    },
    CaseStatus.FIXING: {CaseStatus.RESOLVED, CaseStatus.TRIAGING, CaseStatus.OPEN},
    CaseStatus.RESOLVED: {CaseStatus.CLOSED, CaseStatus.OPEN},
    CaseStatus.CLOSED: {CaseStatus.OPEN},
    CaseStatus.ACCEPTED_RISK: {CaseStatus.OPEN},
    CaseStatus.FALSE_POSITIVE: {CaseStatus.OPEN},
}


@dataclass
class ExposureCase:
    """A single Exposure Case grouping related findings/clusters."""

    case_id: str
    title: str
    description: str = ""
    status: CaseStatus = CaseStatus.OPEN
    priority: CasePriority = CasePriority.MEDIUM
    org_id: str = ""
    # Root cause
    root_cve: Optional[str] = None
    root_cwe: Optional[str] = None
    root_component: Optional[str] = None
    # Scope
    affected_assets: List[str] = field(default_factory=list)
    cluster_ids: List[str] = field(default_factory=list)
    finding_count: int = 0
    # Risk scoring
    risk_score: float = 0.0
    epss_score: Optional[float] = None
    in_kev: bool = False
    blast_radius: int = 0
    # Assignment
    assigned_to: Optional[str] = None
    assigned_team: Optional[str] = None
    # SLA
    sla_due: Optional[str] = None
    sla_breached: bool = False
    # Timestamps
    created_at: str = ""
    updated_at: str = ""
    resolved_at: Optional[str] = None
    closed_at: Optional[str] = None
    # Remediation
    remediation_plan: Optional[str] = None
    playbook_id: Optional[str] = None
    autofix_pr_url: Optional[str] = None
    # Metadata
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        now = datetime.now(timezone.utc).isoformat()
        if not self.created_at:
            self.created_at = now
        if not self.updated_at:
            self.updated_at = now
        if not self.case_id:
            self.case_id = f"EC-{uuid.uuid4().hex[:12].upper()}"

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        d["priority"] = self.priority.value
        return d


class ExposureCaseManager:
    """Manages Exposure Case lifecycle with SQLite persistence and Knowledge Graph integration."""

    _instance: Optional["ExposureCaseManager"] = None
    _lock = threading.Lock()

    def __init__(self, db_path: str = "fixops_exposure_cases.db") -> None:
        self.db_path = db_path
        self._conn_lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._create_tables()
        logger.info("ExposureCaseManager initialized: db=%s", db_path)

    @classmethod
    def get_instance(
        cls, db_path: str = "fixops_exposure_cases.db"
    ) -> "ExposureCaseManager":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls(db_path=db_path)
        return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        with cls._lock:
            if cls._instance is not None:
                cls._instance.close()
                cls._instance = None

    def _create_tables(self) -> None:
        with self._conn_lock:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS exposure_cases (
                    case_id         TEXT PRIMARY KEY,
                    title           TEXT NOT NULL,
                    description     TEXT NOT NULL DEFAULT '',
                    status          TEXT NOT NULL DEFAULT 'open',
                    priority        TEXT NOT NULL DEFAULT 'medium',
                    org_id          TEXT NOT NULL DEFAULT '',
                    root_cve        TEXT,
                    root_cwe        TEXT,
                    root_component  TEXT,
                    affected_assets TEXT NOT NULL DEFAULT '[]',
                    cluster_ids     TEXT NOT NULL DEFAULT '[]',
                    finding_count   INTEGER NOT NULL DEFAULT 0,
                    risk_score      REAL NOT NULL DEFAULT 0.0,
                    epss_score      REAL,
                    in_kev          INTEGER NOT NULL DEFAULT 0,
                    blast_radius    INTEGER NOT NULL DEFAULT 0,
                    assigned_to     TEXT,
                    assigned_team   TEXT,
                    sla_due         TEXT,
                    sla_breached    INTEGER NOT NULL DEFAULT 0,
                    created_at      TEXT NOT NULL,
                    updated_at      TEXT NOT NULL,
                    resolved_at     TEXT,
                    closed_at       TEXT,
                    remediation_plan TEXT,
                    playbook_id     TEXT,
                    autofix_pr_url  TEXT,
                    tags            TEXT NOT NULL DEFAULT '[]',
                    metadata        TEXT NOT NULL DEFAULT '{}'
                );
                CREATE INDEX IF NOT EXISTS idx_ec_org ON exposure_cases(org_id);
                CREATE INDEX IF NOT EXISTS idx_ec_status ON exposure_cases(status);
                CREATE INDEX IF NOT EXISTS idx_ec_priority ON exposure_cases(priority);
                CREATE INDEX IF NOT EXISTS idx_ec_cve ON exposure_cases(root_cve);
            """
            )

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------
    def create_case(self, case: ExposureCase) -> ExposureCase:
        """Create a new Exposure Case."""
        now = datetime.now(timezone.utc).isoformat()
        case.created_at = case.created_at or now
        case.updated_at = now
        with self._conn_lock:
            self._conn.execute(
                """INSERT INTO exposure_cases (
                    case_id, title, description, status, priority, org_id,
                    root_cve, root_cwe, root_component,
                    affected_assets, cluster_ids, finding_count,
                    risk_score, epss_score, in_kev, blast_radius,
                    assigned_to, assigned_team, sla_due, sla_breached,
                    created_at, updated_at, resolved_at, closed_at,
                    remediation_plan, playbook_id, autofix_pr_url, tags, metadata
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    case.case_id,
                    case.title,
                    case.description,
                    case.status.value,
                    case.priority.value,
                    case.org_id,
                    case.root_cve,
                    case.root_cwe,
                    case.root_component,
                    json.dumps(case.affected_assets),
                    json.dumps(case.cluster_ids),
                    case.finding_count,
                    case.risk_score,
                    case.epss_score,
                    1 if case.in_kev else 0,
                    case.blast_radius,
                    case.assigned_to,
                    case.assigned_team,
                    case.sla_due,
                    1 if case.sla_breached else 0,
                    case.created_at,
                    case.updated_at,
                    case.resolved_at,
                    case.closed_at,
                    case.remediation_plan,
                    case.playbook_id,
                    case.autofix_pr_url,
                    json.dumps(case.tags),
                    json.dumps(case.metadata, default=str),
                ),
            )
            self._conn.commit()
        self._persist_to_brain(case)
        self._emit_event(case, "exposure_case.created")
        return case

    def get_case(self, case_id: str) -> Optional[ExposureCase]:
        """Get an Exposure Case by ID."""
        with self._conn_lock:
            row = self._conn.execute(
                "SELECT * FROM exposure_cases WHERE case_id = ?", (case_id,)
            ).fetchone()
        if not row:
            return None
        return self._row_to_case(row)

    def list_cases(
        self,
        org_id: Optional[str] = None,
        status: Optional[str] = None,
        priority: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """List Exposure Cases with filtering."""
        conditions, params = [], []
        if org_id:
            conditions.append("org_id = ?")
            params.append(org_id)
        if status:
            conditions.append("status = ?")
            params.append(status)
        if priority:
            conditions.append("priority = ?")
            params.append(priority)
        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        with self._conn_lock:
            total = self._conn.execute(
                f"SELECT COUNT(*) FROM exposure_cases {where}", params
            ).fetchone()[0]
            rows = self._conn.execute(
                f"SELECT * FROM exposure_cases {where} ORDER BY risk_score DESC, updated_at DESC LIMIT ? OFFSET ?",
                params + [limit, offset],
            ).fetchall()
        return {
            "cases": [self._row_to_case(r).to_dict() for r in rows],
            "total": total,
            "limit": limit,
            "offset": offset,
        }

    def transition(
        self, case_id: str, new_status: CaseStatus, actor: str = "system"
    ) -> ExposureCase:
        """Transition a case to a new lifecycle state with validation."""
        case = self.get_case(case_id)
        if not case:
            raise ValueError(f"Case {case_id} not found")
        allowed = VALID_TRANSITIONS.get(case.status, set())
        if new_status not in allowed:
            raise ValueError(
                f"Invalid transition: {case.status.value} → {new_status.value}. "
                f"Allowed: {[s.value for s in allowed]}"
            )
        now = datetime.now(timezone.utc).isoformat()
        old_status = case.status
        case.status = new_status
        case.updated_at = now
        if new_status == CaseStatus.RESOLVED:
            case.resolved_at = now
        elif new_status == CaseStatus.CLOSED:
            case.closed_at = now
        with self._conn_lock:
            self._conn.execute(
                "UPDATE exposure_cases SET status=?, updated_at=?, resolved_at=?, closed_at=? WHERE case_id=?",
                (new_status.value, now, case.resolved_at, case.closed_at, case_id),
            )
            self._conn.commit()
        self._persist_to_brain(case)
        self._emit_event(
            case,
            "exposure_case.transitioned",
            extra={
                "from": old_status.value,
                "to": new_status.value,
                "actor": actor,
            },
        )
        return case

    def update_case(self, case_id: str, updates: Dict[str, Any]) -> ExposureCase:
        """Update case fields (not status — use transition() for that)."""
        case = self.get_case(case_id)
        if not case:
            raise ValueError(f"Case {case_id} not found")
        now = datetime.now(timezone.utc).isoformat()
        for key, val in updates.items():
            if key in ("status", "case_id", "created_at"):
                continue
            if hasattr(case, key):
                setattr(case, key, val)
        case.updated_at = now
        with self._conn_lock:
            self._conn.execute(
                """UPDATE exposure_cases SET
                    title=?, description=?, priority=?, assigned_to=?, assigned_team=?,
                    sla_due=?, sla_breached=?, remediation_plan=?, playbook_id=?,
                    autofix_pr_url=?, tags=?, metadata=?, risk_score=?,
                    affected_assets=?, cluster_ids=?, finding_count=?,
                    blast_radius=?, root_cve=?, root_cwe=?, root_component=?,
                    epss_score=?, in_kev=?, updated_at=?
                WHERE case_id=?""",
                (
                    case.title,
                    case.description,
                    case.priority.value
                    if isinstance(case.priority, CasePriority)
                    else case.priority,
                    case.assigned_to,
                    case.assigned_team,
                    case.sla_due,
                    1 if case.sla_breached else 0,
                    case.remediation_plan,
                    case.playbook_id,
                    case.autofix_pr_url,
                    json.dumps(case.tags),
                    json.dumps(case.metadata, default=str),
                    case.risk_score,
                    json.dumps(case.affected_assets),
                    json.dumps(case.cluster_ids),
                    case.finding_count,
                    case.blast_radius,
                    case.root_cve,
                    case.root_cwe,
                    case.root_component,
                    case.epss_score,
                    1 if case.in_kev else 0,
                    now,
                    case_id,
                ),
            )
            self._conn.commit()
        self._persist_to_brain(case)
        return case

    def add_clusters(
        self, case_id: str, cluster_ids: List[str], finding_count_delta: int = 0
    ) -> ExposureCase:
        """Add deduplication clusters to an existing case."""
        case = self.get_case(case_id)
        if not case:
            raise ValueError(f"Case {case_id} not found")
        existing = set(case.cluster_ids)
        new_ids = [c for c in cluster_ids if c not in existing]
        if not new_ids:
            return case
        case.cluster_ids = case.cluster_ids + new_ids
        case.finding_count += finding_count_delta
        return self.update_case(
            case_id,
            {
                "cluster_ids": case.cluster_ids,
                "finding_count": case.finding_count,
            },
        )

    def stats(self, org_id: Optional[str] = None) -> Dict[str, Any]:
        """Get exposure case statistics."""
        where = "WHERE org_id = ?" if org_id else ""
        params = [org_id] if org_id else []
        with self._conn_lock:
            total = self._conn.execute(
                f"SELECT COUNT(*) FROM exposure_cases {where}", params
            ).fetchone()[0]
            by_status = {}
            for row in self._conn.execute(
                f"SELECT status, COUNT(*) FROM exposure_cases {where} GROUP BY status",
                params,
            ):
                by_status[row[0]] = row[1]
            by_priority = {}
            for row in self._conn.execute(
                f"SELECT priority, COUNT(*) FROM exposure_cases {where} GROUP BY priority",
                params,
            ):
                by_priority[row[0]] = row[1]
            avg_risk = (
                self._conn.execute(
                    f"SELECT AVG(risk_score) FROM exposure_cases {where}", params
                ).fetchone()[0]
                or 0
            )
            kev_count = self._conn.execute(
                f"SELECT COUNT(*) FROM exposure_cases {where} {'AND' if org_id else 'WHERE'} in_kev=1",
                params,
            ).fetchone()[0]
        return {
            "total_cases": total,
            "by_status": by_status,
            "by_priority": by_priority,
            "avg_risk_score": round(avg_risk, 4),
            "kev_cases": kev_count,
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _row_to_case(self, row) -> ExposureCase:
        """Convert a database row to an ExposureCase."""
        return ExposureCase(
            case_id=row[0],
            title=row[1],
            description=row[2],
            status=CaseStatus(row[3]),
            priority=CasePriority(row[4]),
            org_id=row[5],
            root_cve=row[6],
            root_cwe=row[7],
            root_component=row[8],
            affected_assets=json.loads(row[9]),
            cluster_ids=json.loads(row[10]),
            finding_count=row[11],
            risk_score=row[12],
            epss_score=row[13],
            in_kev=bool(row[14]),
            blast_radius=row[15],
            assigned_to=row[16],
            assigned_team=row[17],
            sla_due=row[18],
            sla_breached=bool(row[19]),
            created_at=row[20],
            updated_at=row[21],
            resolved_at=row[22],
            closed_at=row[23],
            remediation_plan=row[24],
            playbook_id=row[25],
            autofix_pr_url=row[26],
            tags=json.loads(row[27]),
            metadata=json.loads(row[28]),
        )

    def _persist_to_brain(self, case: ExposureCase) -> None:
        """Write exposure case to Knowledge Graph."""
        try:
            from core.knowledge_brain import (
                EdgeType,
                EntityType,
                GraphEdge,
                GraphNode,
                get_brain,
            )

            brain = get_brain()
            brain.upsert_node(
                GraphNode(
                    node_id=f"exposure_case:{case.case_id}",
                    node_type=EntityType.EXPOSURE_CASE,
                    org_id=case.org_id,
                    properties={
                        "title": case.title,
                        "status": case.status.value,
                        "priority": case.priority.value,
                        "risk_score": case.risk_score,
                        "finding_count": case.finding_count,
                        "blast_radius": case.blast_radius,
                        "root_cve": case.root_cve,
                        "in_kev": case.in_kev,
                    },
                )
            )
            # Link to clusters
            for cid in case.cluster_ids:
                brain.add_edge(
                    GraphEdge(
                        source_id=f"exposure_case:{case.case_id}",
                        target_id=f"cluster:{cid}",
                        edge_type=EdgeType.GROUPS,
                    )
                )
            # Link to CVE
            if case.root_cve:
                brain.add_edge(
                    GraphEdge(
                        source_id=f"exposure_case:{case.case_id}",
                        target_id=f"cve:{case.root_cve}",
                        edge_type=EdgeType.REFERENCES,
                    )
                )
        except Exception as e:
            logger.warning("Failed to persist exposure case to brain: %s", e)

    def _emit_event(
        self, case: ExposureCase, event_type: str, extra: Optional[Dict] = None
    ) -> None:
        """Emit event to the event bus."""
        try:
            import asyncio

            from core.event_bus import Event, get_event_bus

            bus = get_event_bus()
            data = {
                "case_id": case.case_id,
                "status": case.status.value,
                "org_id": case.org_id,
            }
            if extra:
                data.update(extra)
            event = Event(
                event_type=event_type, source="exposure_case_manager", data=data
            )
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(bus.emit(event))
            except RuntimeError:
                asyncio.run(bus.emit(event))
        except Exception as e:
            logger.debug("Event emit failed (non-critical): %s", e)

    def close(self) -> None:
        with self._conn_lock:
            self._conn.close()


def get_case_manager(db_path: str = "fixops_exposure_cases.db") -> ExposureCaseManager:
    """Get the global ExposureCaseManager instance."""
    return ExposureCaseManager.get_instance(db_path=db_path)
