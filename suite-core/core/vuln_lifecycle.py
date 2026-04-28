"""
Vulnerability Lifecycle Tracker for ALDECI.

Tracks every finding from discovery to resolution using a state machine
backed by SQLite. Provides flow metrics, bottleneck detection, and
stage distribution analytics.

State Machine (valid transitions):
  DISCOVERED  → TRIAGED, WONT_FIX
  TRIAGED     → ASSIGNED, WONT_FIX
  ASSIGNED    → IN_PROGRESS, WONT_FIX
  IN_PROGRESS → FIXED, WONT_FIX
  FIXED       → VERIFIED
  VERIFIED    → CLOSED, REOPENED
  CLOSED      → REOPENED
  REOPENED    → TRIAGED, WONT_FIX
  WONT_FIX    → REOPENED

Compliance: SOC2 CC7.2, ISO27001 A.16 (Incident management)
"""

from __future__ import annotations

import logging
import sqlite3
import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)


# ============================================================================
# ENUMS
# ============================================================================


class LifecycleStage(str, Enum):
    """Stages in the vulnerability lifecycle state machine."""

    DISCOVERED = "discovered"
    TRIAGED = "triaged"
    ASSIGNED = "assigned"
    IN_PROGRESS = "in_progress"
    FIXED = "fixed"
    VERIFIED = "verified"
    CLOSED = "closed"
    REOPENED = "reopened"
    WONT_FIX = "wont_fix"

    def __str__(self) -> str:
        return self.value


# ============================================================================
# STATE MACHINE DEFINITION
# ============================================================================

# Maps each stage to the set of valid next stages
_VALID_TRANSITIONS: Dict[LifecycleStage, Set[LifecycleStage]] = {
    LifecycleStage.DISCOVERED: {
        LifecycleStage.TRIAGED,
        LifecycleStage.WONT_FIX,
    },
    LifecycleStage.TRIAGED: {
        LifecycleStage.ASSIGNED,
        LifecycleStage.WONT_FIX,
    },
    LifecycleStage.ASSIGNED: {
        LifecycleStage.IN_PROGRESS,
        LifecycleStage.WONT_FIX,
    },
    LifecycleStage.IN_PROGRESS: {
        LifecycleStage.FIXED,
        LifecycleStage.WONT_FIX,
    },
    LifecycleStage.FIXED: {
        LifecycleStage.VERIFIED,
    },
    LifecycleStage.VERIFIED: {
        LifecycleStage.CLOSED,
        LifecycleStage.REOPENED,
    },
    LifecycleStage.CLOSED: {
        LifecycleStage.REOPENED,
    },
    LifecycleStage.REOPENED: {
        LifecycleStage.TRIAGED,
        LifecycleStage.WONT_FIX,
    },
    LifecycleStage.WONT_FIX: {
        LifecycleStage.REOPENED,
    },
}

# Stages considered "terminal" (no active remediation effort)
_TERMINAL_STAGES: Set[LifecycleStage] = {
    LifecycleStage.CLOSED,
    LifecycleStage.WONT_FIX,
}


# ============================================================================
# MODELS
# ============================================================================


class LifecycleEvent(BaseModel):
    """A single state-transition event in a finding's lifecycle."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    finding_id: str = Field(..., description="ID of the finding being tracked")
    from_stage: Optional[LifecycleStage] = Field(
        None, description="Previous stage (None for initial discovery)"
    )
    to_stage: LifecycleStage = Field(..., description="New stage after this transition")
    changed_by: str = Field(..., description="User or system that triggered the change")
    reason: str = Field(default="", description="Reason or notes for the transition")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When the transition occurred",
    )
    org_id: str = Field(..., description="Organization ID for multi-tenancy")


class TransitionError(Exception):
    """Raised when an invalid lifecycle transition is attempted."""
    pass


# ============================================================================
# CORE CLASS
# ============================================================================


class VulnLifecycle:
    """
    SQLite-backed vulnerability lifecycle tracker.

    Tracks every finding from DISCOVERED through CLOSED/WONT_FIX,
    enforcing a defined state machine and providing flow analytics.
    """

    def __init__(self, db_path: str = "data/vuln_lifecycle.db") -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_tables()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_tables(self) -> None:
        conn = self._get_connection()
        try:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS lifecycle_events (
                    id          TEXT PRIMARY KEY,
                    finding_id  TEXT NOT NULL,
                    from_stage  TEXT,
                    to_stage    TEXT NOT NULL,
                    changed_by  TEXT NOT NULL,
                    reason      TEXT NOT NULL DEFAULT '',
                    timestamp   TEXT NOT NULL,
                    org_id      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_lifecycle_finding
                    ON lifecycle_events (finding_id);

                CREATE INDEX IF NOT EXISTS idx_lifecycle_org
                    ON lifecycle_events (org_id, to_stage);

                CREATE INDEX IF NOT EXISTS idx_lifecycle_timestamp
                    ON lifecycle_events (timestamp);
                """
            )
            conn.commit()
        finally:
            conn.close()

    def _row_to_event(self, row: sqlite3.Row) -> LifecycleEvent:
        return LifecycleEvent(
            id=row["id"],
            finding_id=row["finding_id"],
            from_stage=(
                LifecycleStage(row["from_stage"]) if row["from_stage"] else None
            ),
            to_stage=LifecycleStage(row["to_stage"]),
            changed_by=row["changed_by"],
            reason=row["reason"] or "",
            timestamp=datetime.fromisoformat(row["timestamp"]),
            org_id=row["org_id"],
        )

    # ------------------------------------------------------------------
    # State machine
    # ------------------------------------------------------------------

    def validate_transition(
        self,
        from_stage: Optional[LifecycleStage],
        to_stage: LifecycleStage,
    ) -> bool:
        """
        Return True if the transition is allowed by the state machine.

        A None from_stage is valid only when transitioning to DISCOVERED
        (initial placement of a finding into the lifecycle).
        """
        if from_stage is None:
            return to_stage == LifecycleStage.DISCOVERED
        allowed = _VALID_TRANSITIONS.get(from_stage, set())
        return to_stage in allowed

    # ------------------------------------------------------------------
    # Write operations
    # ------------------------------------------------------------------

    def transition(
        self,
        finding_id: str,
        to_stage: LifecycleStage,
        changed_by: str,
        reason: str = "",
        org_id: str = "default",
    ) -> LifecycleEvent:
        """
        Record a stage transition for a finding.

        Validates the transition against the state machine before persisting.
        Raises TransitionError for invalid transitions.
        """
        current = self.get_current_stage(finding_id)

        if not self.validate_transition(current, to_stage):
            from_label = current.value if current else "none"
            raise TransitionError(
                f"Invalid transition for finding {finding_id}: "
                f"{from_label} → {to_stage.value}"
            )

        event = LifecycleEvent(
            finding_id=finding_id,
            from_stage=current,
            to_stage=to_stage,
            changed_by=changed_by,
            reason=reason,
            org_id=org_id,
        )

        conn = self._get_connection()
        try:
            conn.execute(
                """INSERT INTO lifecycle_events
                   (id, finding_id, from_stage, to_stage, changed_by, reason, timestamp, org_id)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    event.id,
                    event.finding_id,
                    event.from_stage.value if event.from_stage else None,
                    event.to_stage.value,
                    event.changed_by,
                    event.reason,
                    event.timestamp.isoformat(),
                    event.org_id,
                ),
            )
            conn.commit()
        finally:
            conn.close()

        _logger.info(
            "lifecycle_transition",
            extra={
                "finding_id": finding_id,
                "from_stage": current.value if current else None,
                "to_stage": to_stage.value,
                "changed_by": changed_by,
            },
        )
        return event

    # ------------------------------------------------------------------
    # Read operations
    # ------------------------------------------------------------------

    def get_lifecycle(self, finding_id: str) -> List[LifecycleEvent]:
        """Return full chronological event history for a finding."""
        conn = self._get_connection()
        try:
            rows = conn.execute(
                """SELECT * FROM lifecycle_events
                   WHERE finding_id = ?
                   ORDER BY timestamp ASC""",
                (finding_id,),
            ).fetchall()
            return [self._row_to_event(r) for r in rows]
        finally:
            conn.close()

    def get_current_stage(self, finding_id: str) -> Optional[LifecycleStage]:
        """Return the current (most recent) stage of a finding, or None if unknown."""
        conn = self._get_connection()
        try:
            row = conn.execute(
                """SELECT to_stage FROM lifecycle_events
                   WHERE finding_id = ?
                   ORDER BY timestamp DESC
                   LIMIT 1""",
                (finding_id,),
            ).fetchone()
            return LifecycleStage(row["to_stage"]) if row else None
        finally:
            conn.close()

    def get_stage_distribution(self, org_id: str) -> Dict[str, int]:
        """
        Return a count of findings currently at each stage for the org.

        Uses the latest event per finding to determine current stage.
        """
        conn = self._get_connection()
        try:
            rows = conn.execute(
                """SELECT to_stage, COUNT(*) AS cnt
                   FROM (
                       SELECT finding_id,
                              to_stage,
                              ROW_NUMBER() OVER (
                                  PARTITION BY finding_id
                                  ORDER BY timestamp DESC
                              ) AS rn
                       FROM lifecycle_events
                       WHERE org_id = ?
                   )
                   WHERE rn = 1
                   GROUP BY to_stage""",
                (org_id,),
            ).fetchall()
            distribution = {stage.value: 0 for stage in LifecycleStage}
            for row in rows:
                distribution[row["to_stage"]] = row["cnt"]
            return distribution
        finally:
            conn.close()

    def get_avg_time_per_stage(self, org_id: str) -> Dict[str, Optional[float]]:
        """
        Return average hours spent at each stage across all findings in the org.

        Computed as the time between entering a stage and leaving it.
        Findings still in a stage are excluded from the average.
        """
        conn = self._get_connection()
        try:
            rows = conn.execute(
                """SELECT finding_id, from_stage, to_stage, timestamp
                   FROM lifecycle_events
                   WHERE org_id = ?
                   ORDER BY finding_id, timestamp ASC""",
                (org_id,),
            ).fetchall()
        finally:
            conn.close()

        # Build per-finding event lists
        by_finding: Dict[str, List[Dict[str, Any]]] = {}
        for row in rows:
            fid = row["finding_id"]
            by_finding.setdefault(fid, []).append(
                {
                    "from_stage": row["from_stage"],
                    "to_stage": row["to_stage"],
                    "timestamp": datetime.fromisoformat(row["timestamp"]),
                }
            )

        # Accumulate durations per stage
        stage_durations: Dict[str, List[float]] = {s.value: [] for s in LifecycleStage}
        for events in by_finding.values():
            for i, evt in enumerate(events):
                entered_stage = evt["to_stage"]
                entered_at = evt["timestamp"]
                # Find when the finding left this stage
                if i + 1 < len(events):
                    left_at = events[i + 1]["timestamp"]
                    hours = (left_at - entered_at).total_seconds() / 3600
                    if hours >= 0 and entered_stage in stage_durations:
                        stage_durations[entered_stage].append(hours)

        result: Dict[str, Optional[float]] = {}
        for stage in LifecycleStage:
            durations = stage_durations[stage.value]
            result[stage.value] = (
                sum(durations) / len(durations) if durations else None
            )
        return result

    def get_bottlenecks(self, org_id: str) -> List[Dict[str, Any]]:
        """
        Return stages sorted by average dwell time (descending).

        Stages with the highest average hours are bottlenecks.
        Only stages with at least one completed dwell are included.
        """
        avg_times = self.get_avg_time_per_stage(org_id)
        bottlenecks = [
            {"stage": stage, "avg_hours": hours}
            for stage, hours in avg_times.items()
            if hours is not None
        ]
        bottlenecks.sort(key=lambda x: x["avg_hours"], reverse=True)
        return bottlenecks

    def get_flow_metrics(self, org_id: str) -> Dict[str, Any]:
        """
        Return flow metrics for the org:

        - throughput: findings that reached CLOSED or WONT_FIX (resolved count)
        - cycle_time_hours: avg hours from IN_PROGRESS to FIXED (active work time)
        - lead_time_hours: avg hours from DISCOVERED to CLOSED/WONT_FIX (total time)
        - wip: findings currently in active stages (not CLOSED/WONT_FIX)
        - reopen_rate: fraction of findings that were REOPENED at least once
        """
        conn = self._get_connection()
        try:
            rows = conn.execute(
                """SELECT finding_id, to_stage, timestamp
                   FROM lifecycle_events
                   WHERE org_id = ?
                   ORDER BY finding_id, timestamp ASC""",
                (org_id,),
            ).fetchall()
        finally:
            conn.close()

        # Group by finding
        by_finding: Dict[str, List[Dict[str, Any]]] = {}
        for row in rows:
            fid = row["finding_id"]
            by_finding.setdefault(fid, []).append(
                {
                    "stage": row["to_stage"],
                    "timestamp": datetime.fromisoformat(row["timestamp"]),
                }
            )

        resolved_count = 0
        lead_times: List[float] = []
        cycle_times: List[float] = []
        wip_count = 0
        reopen_count = 0

        for fid, events in by_finding.items():
            stages_seen = [e["stage"] for e in events]
            current_stage = stages_seen[-1] if stages_seen else None

            # WIP: active (not terminal)
            if current_stage not in (
                LifecycleStage.CLOSED.value,
                LifecycleStage.WONT_FIX.value,
            ):
                wip_count += 1

            # Throughput: findings that reached a terminal stage
            terminal_values = {s.value for s in _TERMINAL_STAGES}
            if current_stage in terminal_values:
                resolved_count += 1

            # Reopen rate
            if LifecycleStage.REOPENED.value in stages_seen:
                reopen_count += 1

            # Lead time: DISCOVERED → CLOSED or WONT_FIX
            discovery_events = [
                e for e in events if e["stage"] == LifecycleStage.DISCOVERED.value
            ]
            terminal_events = [
                e for e in events if e["stage"] in terminal_values
            ]
            if discovery_events and terminal_events:
                lead_hours = (
                    terminal_events[-1]["timestamp"] - discovery_events[0]["timestamp"]
                ).total_seconds() / 3600
                if lead_hours >= 0:
                    lead_times.append(lead_hours)

            # Cycle time: IN_PROGRESS → FIXED
            ip_events = [
                e for e in events if e["stage"] == LifecycleStage.IN_PROGRESS.value
            ]
            fixed_events = [
                e for e in events if e["stage"] == LifecycleStage.FIXED.value
            ]
            if ip_events and fixed_events:
                cycle_hours = (
                    fixed_events[0]["timestamp"] - ip_events[0]["timestamp"]
                ).total_seconds() / 3600
                if cycle_hours >= 0:
                    cycle_times.append(cycle_hours)

        total_findings = len(by_finding)
        return {
            "throughput": resolved_count,
            "cycle_time_hours": (
                sum(cycle_times) / len(cycle_times) if cycle_times else None
            ),
            "lead_time_hours": (
                sum(lead_times) / len(lead_times) if lead_times else None
            ),
            "wip": wip_count,
            "reopen_rate": (
                reopen_count / total_findings if total_findings > 0 else 0.0
            ),
            "total_findings": total_findings,
        }
