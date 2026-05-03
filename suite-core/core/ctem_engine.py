"""CTEM Engine — Continuous Threat Exposure Management 5-Stage Cycle.

Implements the Gartner CTEM framework:
  Stage 1: SCOPING       — define asset scope and business context
  Stage 2: DISCOVERY     — auto-discover exposures from findings
  Stage 3: PRIORITIZATION — risk-rank by business impact
  Stage 4: VALIDATION    — confirm exploitability
  Stage 5: MOBILIZATION  — assign ownership and remediation plans

Usage:
    from core.ctem_engine import CTEMEngine, get_ctem_engine
    engine = get_ctem_engine()
    cycle = engine.start_cycle("Q2-2026 Assessment", org_id="acme")
    engine.scope_assets(cycle.id, asset_ids=["ast-001", "ast-002"])
"""

from __future__ import annotations

import json
import os
import threading
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

import structlog
from pydantic import BaseModel, Field

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


logger = structlog.get_logger(__name__)

_DEFAULT_DB = os.getenv("FIXOPS_CTEM_DB", ".fixops_data/ctem.db")


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class CTEMStage(str, Enum):
    SCOPING = "scoping"
    DISCOVERY = "discovery"
    PRIORITIZATION = "prioritization"
    VALIDATION = "validation"
    MOBILIZATION = "mobilization"


class ExposureStatus(str, Enum):
    IDENTIFIED = "identified"
    ASSESSED = "assessed"
    VALIDATED = "validated"
    REMEDIATED = "remediated"
    ACCEPTED = "accepted"


# Stage progression order
_STAGE_ORDER: List[CTEMStage] = [
    CTEMStage.SCOPING,
    CTEMStage.DISCOVERY,
    CTEMStage.PRIORITIZATION,
    CTEMStage.VALIDATION,
    CTEMStage.MOBILIZATION,
]


# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------


class Exposure(BaseModel):
    id: str = Field(default_factory=lambda: f"exp-{uuid.uuid4().hex[:12]}")
    title: str
    description: str = ""
    stage: CTEMStage = CTEMStage.SCOPING
    status: ExposureStatus = ExposureStatus.IDENTIFIED
    assets: List[str] = Field(default_factory=list)
    findings: List[str] = Field(default_factory=list)
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    business_impact: str = ""
    remediation_plan: str = ""
    owner: str = ""
    org_id: str = "default"
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class CTEMCycle(BaseModel):
    id: str = Field(default_factory=lambda: f"cycle-{uuid.uuid4().hex[:12]}")
    name: str
    start_date: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    current_stage: CTEMStage = CTEMStage.SCOPING
    exposures: List[str] = Field(default_factory=list)
    completion_pct: float = Field(default=0.0, ge=0.0, le=100.0)
    org_id: str = "default"


# ---------------------------------------------------------------------------
# SQLite persistence layer
# ---------------------------------------------------------------------------


class _CTEMDB:
    """SQLite persistence for CTEM cycles and exposures."""

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        os.makedirs(
            os.path.dirname(db_path) if os.path.dirname(db_path) else ".",
            exist_ok=True,
        )
        # FEATURE-5: route through DBAdapter so DATABASE_URL switches to postgres.
        # When DATABASE_URL is unset, persistent_connect() returns a sqlite3.Connection
        # with the same WAL/synchronous PRAGMAs we used to set inline.
        from core.db_adapter import get_adapter
        self._db = get_adapter(db_path)
        self._conn = self._db.persistent_connect()
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self) -> None:
        with self._lock:
            self._conn.executescript("""
                CREATE TABLE IF NOT EXISTS ctem_cycles (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    start_date TEXT NOT NULL,
                    current_stage TEXT NOT NULL,
                    exposures TEXT DEFAULT '[]',
                    completion_pct REAL DEFAULT 0.0,
                    org_id TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_cycles_org ON ctem_cycles(org_id);

                CREATE TABLE IF NOT EXISTS ctem_exposures (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    description TEXT DEFAULT '',
                    stage TEXT NOT NULL,
                    status TEXT NOT NULL,
                    assets TEXT DEFAULT '[]',
                    findings TEXT DEFAULT '[]',
                    risk_score REAL DEFAULT 0.0,
                    business_impact TEXT DEFAULT '',
                    remediation_plan TEXT DEFAULT '',
                    owner TEXT DEFAULT '',
                    org_id TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_exposures_org ON ctem_exposures(org_id);
                CREATE INDEX IF NOT EXISTS idx_exposures_stage ON ctem_exposures(stage);
                CREATE INDEX IF NOT EXISTS idx_exposures_status ON ctem_exposures(status);
            """)
            self._conn.commit()

    # Cycle operations

    def upsert_cycle(self, cycle: CTEMCycle) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT OR REPLACE INTO ctem_cycles
                   (id, name, start_date, current_stage, exposures, completion_pct, org_id)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    cycle.id,
                    cycle.name,
                    cycle.start_date,
                    cycle.current_stage.value,
                    json.dumps(cycle.exposures),
                    cycle.completion_pct,
                    cycle.org_id,
                ),
            )
            self._conn.commit()

    def get_cycle(self, cycle_id: str) -> Optional[CTEMCycle]:
        with self._lock:
            row = self._conn.execute(
                "SELECT id, name, start_date, current_stage, exposures, completion_pct, org_id "
                "FROM ctem_cycles WHERE id = ?",
                (cycle_id,),
            ).fetchone()
        return self._row_to_cycle(row) if row else None

    def list_cycles(self, org_id: str) -> List[CTEMCycle]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, name, start_date, current_stage, exposures, completion_pct, org_id "
                "FROM ctem_cycles WHERE org_id = ? ORDER BY start_date DESC",
                (org_id,),
            ).fetchall()
        return [self._row_to_cycle(r) for r in rows]

    def delete_cycle(self, cycle_id: str) -> bool:
        """Delete a cycle and disassociate its exposures. Returns True if a row was deleted."""
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM ctem_cycles WHERE id = ?", (cycle_id,)
            )
            self._conn.commit()
            return cur.rowcount > 0

    def _row_to_cycle(self, row: tuple) -> CTEMCycle:
        return CTEMCycle(
            id=row[0],
            name=row[1],
            start_date=row[2],
            current_stage=CTEMStage(row[3]),
            exposures=json.loads(row[4]),
            completion_pct=row[5],
            org_id=row[6],
        )

    # Exposure operations

    def upsert_exposure(self, exposure: Exposure) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT OR REPLACE INTO ctem_exposures
                   (id, title, description, stage, status, assets, findings,
                    risk_score, business_impact, remediation_plan, owner, org_id, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    exposure.id,
                    exposure.title,
                    exposure.description,
                    exposure.stage.value,
                    exposure.status.value,
                    json.dumps(exposure.assets),
                    json.dumps(exposure.findings),
                    exposure.risk_score,
                    exposure.business_impact,
                    exposure.remediation_plan,
                    exposure.owner,
                    exposure.org_id,
                    exposure.created_at,
                ),
            )
            self._conn.commit()

    def get_exposure(self, exposure_id: str) -> Optional[Exposure]:
        with self._lock:
            row = self._conn.execute(
                "SELECT id, title, description, stage, status, assets, findings, "
                "risk_score, business_impact, remediation_plan, owner, org_id, created_at "
                "FROM ctem_exposures WHERE id = ?",
                (exposure_id,),
            ).fetchone()
        return self._row_to_exposure(row) if row else None

    def list_exposures_for_cycle(self, exposure_ids: List[str]) -> List[Exposure]:
        if not exposure_ids:
            return []
        placeholders = ",".join("?" * len(exposure_ids))
        with self._lock:
            rows = self._conn.execute(
                f"SELECT id, title, description, stage, status, assets, findings, "  # nosec B608
                f"risk_score, business_impact, remediation_plan, owner, org_id, created_at "
                f"FROM ctem_exposures WHERE id IN ({placeholders}) "
                f"ORDER BY risk_score DESC",
                exposure_ids,
            ).fetchall()
        return [self._row_to_exposure(r) for r in rows]

    def list_exposures_by_org(self, org_id: str) -> List[Exposure]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, title, description, stage, status, assets, findings, "
                "risk_score, business_impact, remediation_plan, owner, org_id, created_at "
                "FROM ctem_exposures WHERE org_id = ? ORDER BY risk_score DESC",
                (org_id,),
            ).fetchall()
        return [self._row_to_exposure(r) for r in rows]

    def _row_to_exposure(self, row: tuple) -> Exposure:
        return Exposure(
            id=row[0],
            title=row[1],
            description=row[2],
            stage=CTEMStage(row[3]),
            status=ExposureStatus(row[4]),
            assets=json.loads(row[5]),
            findings=json.loads(row[6]),
            risk_score=row[7],
            business_impact=row[8],
            remediation_plan=row[9],
            owner=row[10],
            org_id=row[11],
            created_at=row[12],
        )


# ---------------------------------------------------------------------------
# CTEMEngine
# ---------------------------------------------------------------------------


class CTEMEngine:
    """Continuous Threat Exposure Management engine — SQLite-backed."""

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self._db = _CTEMDB(db_path)
        logger.info("CTEMEngine initialised", db_path=db_path)

    # ------------------------------------------------------------------
    # Cycle management
    # ------------------------------------------------------------------

    def start_cycle(self, name: str, org_id: str = "default") -> CTEMCycle:
        """Create and persist a new CTEM cycle, beginning at SCOPING."""
        cycle = CTEMCycle(name=name, org_id=org_id)
        self._db.upsert_cycle(cycle)
        logger.info("CTEM cycle started", cycle_id=cycle.id, name=name, org_id=org_id)
        self._emit_event(
            "ctem.cycle.started",
            {"cycle_id": cycle.id, "name": name, "org_id": org_id, "stage": cycle.current_stage.value},
        )
        return cycle

    def advance_stage(self, cycle_id: str) -> CTEMCycle:
        """Advance cycle to the next stage. Raises ValueError if already at MOBILIZATION."""
        cycle = self._db.get_cycle(cycle_id)
        if not cycle:
            raise ValueError(f"Cycle '{cycle_id}' not found")

        current_idx = _STAGE_ORDER.index(cycle.current_stage)
        if current_idx >= len(_STAGE_ORDER) - 1:
            raise ValueError(
                f"Cycle '{cycle_id}' is already at final stage MOBILIZATION"
            )

        next_stage = _STAGE_ORDER[current_idx + 1]
        cycle.current_stage = next_stage

        # Recompute completion percentage: each stage is 20%
        cycle.completion_pct = min(100.0, (current_idx + 1) * 20.0)

        self._db.upsert_cycle(cycle)
        logger.info(
            "CTEM cycle advanced",
            cycle_id=cycle_id,
            stage=next_stage.value,
            completion_pct=cycle.completion_pct,
        )
        self._emit_event(
            "ctem.cycle.advanced",
            {
                "cycle_id": cycle_id,
                "org_id": cycle.org_id,
                "stage": next_stage.value,
                "completion_pct": cycle.completion_pct,
            },
        )
        return cycle

    def get_cycle(self, cycle_id: str) -> CTEMCycle:
        """Retrieve a cycle by ID. Raises ValueError if not found."""
        cycle = self._db.get_cycle(cycle_id)
        if not cycle:
            raise ValueError(f"Cycle '{cycle_id}' not found")
        return cycle

    def list_cycles(self, org_id: str = "default") -> List[CTEMCycle]:
        """List all cycles for an org, newest first."""
        return self._db.list_cycles(org_id)

    def delete_cycle(self, cycle_id: str) -> None:
        """Soft-delete (hard-delete) a cycle by ID. Raises ValueError if not found."""
        cycle = self._db.get_cycle(cycle_id)
        if not cycle:
            raise ValueError(f"Cycle '{cycle_id}' not found")
        self._db.delete_cycle(cycle_id)

    # ------------------------------------------------------------------
    # Exposure management
    # ------------------------------------------------------------------

    def add_exposure(self, exposure: Exposure) -> Exposure:
        """Persist an exposure and link it to any matching cycles for the org."""
        self._db.upsert_exposure(exposure)

        # Auto-link to the most recent active cycle for this org
        cycles = self._db.list_cycles(exposure.org_id)
        if cycles:
            latest_cycle = cycles[0]
            if exposure.id not in latest_cycle.exposures:
                latest_cycle.exposures.append(exposure.id)
                self._db.upsert_cycle(latest_cycle)

        logger.info(
            "Exposure added",
            exposure_id=exposure.id,
            title=exposure.title,
            org_id=exposure.org_id,
        )
        self._emit_event(
            "ctem.exposure.added",
            {
                "exposure_id": exposure.id,
                "title": exposure.title,
                "org_id": exposure.org_id,
                "stage": exposure.stage.value,
                "status": exposure.status.value,
                "risk_score": exposure.risk_score,
                "asset_count": len(exposure.assets),
            },
        )
        return exposure

    def update_exposure(
        self, exposure_id: str, updates: Dict[str, Any]
    ) -> Exposure:
        """Apply partial updates to an exposure. Raises ValueError if not found."""
        exposure = self._db.get_exposure(exposure_id)
        if not exposure:
            raise ValueError(f"Exposure '{exposure_id}' not found")

        # Apply field updates
        updated = exposure.model_copy(update=updates)
        self._db.upsert_exposure(updated)
        logger.info("Exposure updated", exposure_id=exposure_id, fields=list(updates.keys()))
        self._emit_event(
            "ctem.exposure.updated",
            {
                "exposure_id": exposure_id,
                "org_id": updated.org_id,
                "fields": list(updates.keys()),
                "stage": updated.stage.value,
                "status": updated.status.value,
            },
        )
        return updated

    def get_exposures(self, cycle_id: str) -> List[Exposure]:
        """Return all exposures linked to a cycle, sorted by risk_score descending."""
        cycle = self._db.get_cycle(cycle_id)
        if not cycle:
            raise ValueError(f"Cycle '{cycle_id}' not found")
        return self._db.list_exposures_for_cycle(cycle.exposures)

    # ------------------------------------------------------------------
    # Stage-specific operations
    # ------------------------------------------------------------------

    def scope_assets(self, cycle_id: str, asset_ids: List[str]) -> CTEMCycle:
        """Stage 1 — define the asset scope for this cycle."""
        cycle = self._db.get_cycle(cycle_id)
        if not cycle:
            raise ValueError(f"Cycle '{cycle_id}' not found")

        # Create a scoping exposure that captures the asset list
        scoping_exposure = Exposure(
            title=f"Asset Scope — {cycle.name}",
            description=f"Scoped {len(asset_ids)} assets for CTEM cycle",
            stage=CTEMStage.SCOPING,
            status=ExposureStatus.IDENTIFIED,
            assets=asset_ids,
            org_id=cycle.org_id,
        )
        self._db.upsert_exposure(scoping_exposure)

        if scoping_exposure.id not in cycle.exposures:
            cycle.exposures.append(scoping_exposure.id)
            self._db.upsert_cycle(cycle)

        logger.info(
            "Assets scoped",
            cycle_id=cycle_id,
            asset_count=len(asset_ids),
        )
        return cycle

    def discover_exposures(self, cycle_id: str) -> List[Exposure]:
        """Stage 2 — auto-create discovery exposures from existing scoped assets."""
        cycle = self._db.get_cycle(cycle_id)
        if not cycle:
            raise ValueError(f"Cycle '{cycle_id}' not found")

        existing = self._db.list_exposures_for_cycle(cycle.exposures)
        scoped_assets: List[str] = []
        for exp in existing:
            scoped_assets.extend(exp.assets)

        discovered: List[Exposure] = []
        if scoped_assets:
            discovery_exposure = Exposure(
                title=f"Discovery Run — {cycle.name}",
                description=f"Auto-discovered exposures across {len(scoped_assets)} scoped assets",
                stage=CTEMStage.DISCOVERY,
                status=ExposureStatus.IDENTIFIED,
                assets=list(set(scoped_assets)),
                org_id=cycle.org_id,
            )
            self._db.upsert_exposure(discovery_exposure)
            if discovery_exposure.id not in cycle.exposures:
                cycle.exposures.append(discovery_exposure.id)
                self._db.upsert_cycle(cycle)
            discovered.append(discovery_exposure)

        logger.info(
            "Discovery completed",
            cycle_id=cycle_id,
            discovered_count=len(discovered),
        )
        return discovered

    def prioritize_exposures(self, cycle_id: str) -> List[Exposure]:
        """Stage 3 — risk-rank all exposures in this cycle."""
        cycle = self._db.get_cycle(cycle_id)
        if not cycle:
            raise ValueError(f"Cycle '{cycle_id}' not found")

        exposures = self._db.list_exposures_for_cycle(cycle.exposures)
        prioritized: List[Exposure] = []

        for exposure in exposures:
            # Compute a risk score based on asset count and findings count
            asset_factor = min(1.0, len(exposure.assets) / 10.0)
            finding_factor = min(1.0, len(exposure.findings) / 5.0)
            base_score = exposure.risk_score if exposure.risk_score > 0 else 50.0
            computed_score = min(100.0, base_score * (1 + asset_factor * 0.3 + finding_factor * 0.2))

            updated = exposure.model_copy(
                update={
                    "stage": CTEMStage.PRIORITIZATION,
                    "status": ExposureStatus.ASSESSED,
                    "risk_score": round(computed_score, 2),
                }
            )
            self._db.upsert_exposure(updated)
            prioritized.append(updated)

        logger.info(
            "Prioritization completed",
            cycle_id=cycle_id,
            exposure_count=len(prioritized),
        )
        self._emit_event(
            "ctem.exposures.prioritized",
            {
                "cycle_id": cycle_id,
                "org_id": cycle.org_id,
                "exposure_count": len(prioritized),
                "stage": CTEMStage.PRIORITIZATION.value,
                "max_risk_score": max((e.risk_score for e in prioritized), default=0.0),
            },
        )
        return prioritized

    def validate_exposure(self, exposure_id: str, validated: bool) -> Exposure:
        """Stage 4 — confirm or reject exploitability of an exposure."""
        exposure = self._db.get_exposure(exposure_id)
        if not exposure:
            raise ValueError(f"Exposure '{exposure_id}' not found")

        new_status = ExposureStatus.VALIDATED if validated else ExposureStatus.ACCEPTED
        updated = exposure.model_copy(
            update={
                "stage": CTEMStage.VALIDATION,
                "status": new_status,
            }
        )
        self._db.upsert_exposure(updated)
        logger.info(
            "Exposure validated",
            exposure_id=exposure_id,
            validated=validated,
            status=new_status.value,
        )
        self._emit_event(
            "ctem.exposure.validated",
            {
                "exposure_id": exposure_id,
                "org_id": updated.org_id,
                "validated": validated,
                "status": new_status.value,
                "stage": CTEMStage.VALIDATION.value,
                "risk_score": updated.risk_score,
            },
        )
        return updated

    def mobilize_remediation(
        self, exposure_id: str, owner: str, plan: str
    ) -> Exposure:
        """Stage 5 — assign ownership and remediation plan to an exposure."""
        exposure = self._db.get_exposure(exposure_id)
        if not exposure:
            raise ValueError(f"Exposure '{exposure_id}' not found")

        updated = exposure.model_copy(
            update={
                "stage": CTEMStage.MOBILIZATION,
                "status": ExposureStatus.ASSESSED,
                "owner": owner,
                "remediation_plan": plan,
            }
        )
        self._db.upsert_exposure(updated)
        logger.info(
            "Remediation mobilized",
            exposure_id=exposure_id,
            owner=owner,
        )
        self._emit_event(
            "ctem.remediation.mobilized",
            {
                "exposure_id": exposure_id,
                "org_id": updated.org_id,
                "owner": owner,
                "stage": CTEMStage.MOBILIZATION.value,
                "status": updated.status.value,
                "has_plan": bool(plan),
            },
        )
        return updated

    # ------------------------------------------------------------------
    # Dashboard and stats
    # ------------------------------------------------------------------

    def get_ctem_dashboard(self, org_id: str = "default") -> Dict[str, Any]:
        """Return cycle progress and exposure statistics for the org dashboard."""
        cycles = self._db.list_cycles(org_id)
        exposures = self._db.list_exposures_by_org(org_id)

        status_counts: Dict[str, int] = {s.value: 0 for s in ExposureStatus}
        stage_counts: Dict[str, int] = {s.value: 0 for s in CTEMStage}
        total_risk = 0.0

        for exp in exposures:
            status_counts[exp.status.value] += 1
            stage_counts[exp.stage.value] += 1
            total_risk += exp.risk_score

        active_cycles = [c for c in cycles if c.current_stage != CTEMStage.MOBILIZATION]
        avg_risk = round(total_risk / len(exposures), 2) if exposures else 0.0

        return {
            "org_id": org_id,
            "total_cycles": len(cycles),
            "active_cycles": len(active_cycles),
            "total_exposures": len(exposures),
            "average_risk_score": avg_risk,
            "exposures_by_status": status_counts,
            "exposures_by_stage": stage_counts,
            "cycles": [
                {
                    "id": c.id,
                    "name": c.name,
                    "stage": c.current_stage.value,
                    "completion_pct": c.completion_pct,
                    "exposure_count": len(c.exposures),
                }
                for c in cycles
            ],
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    def get_ctem_stats(self, org_id: str = "default") -> Dict[str, Any]:
        """Return aggregate CTEM statistics for the org."""
        cycles = self._db.list_cycles(org_id)
        exposures = self._db.list_exposures_by_org(org_id)

        remediated = sum(1 for e in exposures if e.status == ExposureStatus.REMEDIATED)
        validated = sum(1 for e in exposures if e.status == ExposureStatus.VALIDATED)
        critical = sum(1 for e in exposures if e.risk_score >= 75.0)
        high = sum(1 for e in exposures if 50.0 <= e.risk_score < 75.0)
        medium = sum(1 for e in exposures if 25.0 <= e.risk_score < 50.0)
        low = sum(1 for e in exposures if e.risk_score < 25.0)

        remediation_rate = (
            round(remediated / len(exposures) * 100, 1) if exposures else 0.0
        )

        return {
            "org_id": org_id,
            "cycles": {
                "total": len(cycles),
                "by_stage": {
                    stage.value: sum(1 for c in cycles if c.current_stage == stage)
                    for stage in CTEMStage
                },
            },
            "exposures": {
                "total": len(exposures),
                "remediated": remediated,
                "validated": validated,
                "remediation_rate_pct": remediation_rate,
                "by_severity": {
                    "critical": critical,
                    "high": high,
                    "medium": medium,
                    "low": low,
                },
            },
        }

    # ------------------------------------------------------------------
    # TrustGraph event emission (best-effort, non-blocking)
    # ------------------------------------------------------------------

    def _emit_event(self, event_type: str, payload: Dict[str, Any]) -> None:
        """Emit an event to the TrustGraph event bus. Never raises."""
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
            # Handle async emit signatures
            try:
                import asyncio
                import inspect
                if inspect.iscoroutine(result):
                    try:
                        loop = asyncio.get_running_loop()
                        loop.create_task(result)
                    except RuntimeError:
                        result.close()
            except Exception:  # pragma: no cover
                pass
        except Exception:  # pragma: no cover - best-effort telemetry
            logger.debug("ctem trustgraph emit failed", event=event_type)


# ---------------------------------------------------------------------------
# Singleton accessor
# ---------------------------------------------------------------------------

_engine: Optional[CTEMEngine] = None
_engine_lock = threading.Lock()


def get_ctem_engine() -> CTEMEngine:
    """Return the process-wide CTEMEngine singleton."""
    global _engine
    if _engine is None:
        with _engine_lock:
            if _engine is None:
                _engine = CTEMEngine()
    return _engine
