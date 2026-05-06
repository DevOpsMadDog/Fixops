"""
Vulnerability Lifecycle Tracker — unified state machine for findings across 32+ scanners.

Tracks the complete lifecycle of a vulnerability from discovery through remediation:
  discovered → triaging → confirmed → assigned → in_remediation → fixed → verified → closed

Terminal states: false_positive, accepted_risk, wont_fix, closed
"""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except ImportError:  # pragma: no cover - bus optional
    _get_tg_bus = None

try:
    import structlog
    logger = structlog.get_logger(__name__)
except ImportError:
    import logging
    logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# State machine definition
# ---------------------------------------------------------------------------

LIFECYCLE_STATES = [
    "discovered",
    "triaging",
    "confirmed",
    "assigned",
    "in_remediation",
    "fixed",
    "verified",
    "closed",
    "false_positive",
    "accepted_risk",
    "wont_fix",
]

# States that count as "open" (not yet resolved)
OPEN_STATES = {"discovered", "triaging", "confirmed", "assigned", "in_remediation", "fixed", "verified"}

# Terminal states — findings that are done
TERMINAL_STATES = {"closed", "false_positive", "accepted_risk", "wont_fix"}

# Valid transitions: state → set of allowed next states
VALID_TRANSITIONS: Dict[str, set] = {
    "discovered":     {"triaging", "false_positive", "wont_fix", "accepted_risk"},
    "triaging":       {"confirmed", "false_positive", "wont_fix", "accepted_risk"},
    "confirmed":      {"assigned", "accepted_risk", "wont_fix", "false_positive"},
    "assigned":       {"in_remediation", "wont_fix", "accepted_risk"},
    "in_remediation": {"fixed", "confirmed", "wont_fix", "accepted_risk"},  # confirmed = regression
    "fixed":          {"verified", "confirmed", "wont_fix", "accepted_risk"},  # confirmed = regression
    "verified":       {"closed", "wont_fix", "accepted_risk"},
    # Terminal states: no further transitions
    "closed":         set(),
    "false_positive": set(),
    "accepted_risk":  set(),
    "wont_fix":       set(),
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_iso(s: str) -> Optional[datetime]:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# VulnLifecycleTracker
# ---------------------------------------------------------------------------

class VulnLifecycleTracker:
    """
    Thread-safe SQLite-backed tracker for vulnerability lifecycles.

    Each finding from any scanner gets a lifecycle_id that persists across
    re-scans. State transitions are validated against the state machine and
    logged with full audit trail.
    """

    def __init__(self, db_path: str = "data/vuln_lifecycle.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_db()

    # ------------------------------------------------------------------
    # DB setup
    # ------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        # WAL mode for concurrent read safety
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def _init_db(self) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.executescript("""
                    CREATE TABLE IF NOT EXISTS lifecycles (
                        lifecycle_id TEXT PRIMARY KEY,
                        finding_id   TEXT NOT NULL,
                        org_id       TEXT NOT NULL DEFAULT 'default',
                        state        TEXT NOT NULL DEFAULT 'discovered',
                        severity     TEXT,
                        title        TEXT,
                        source       TEXT,
                        finding_data TEXT,
                        created_at   TEXT NOT NULL,
                        updated_at   TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS transitions (
                        id           TEXT PRIMARY KEY,
                        lifecycle_id TEXT NOT NULL,
                        from_state   TEXT NOT NULL,
                        to_state     TEXT NOT NULL,
                        actor        TEXT NOT NULL DEFAULT 'system',
                        notes        TEXT,
                        transitioned_at TEXT NOT NULL,
                        FOREIGN KEY (lifecycle_id) REFERENCES lifecycles(lifecycle_id)
                    );

                    CREATE UNIQUE INDEX IF NOT EXISTS idx_lifecycle_finding_org
                        ON lifecycles(finding_id, org_id);

                    CREATE INDEX IF NOT EXISTS idx_lifecycle_state_org
                        ON lifecycles(state, org_id);

                    CREATE INDEX IF NOT EXISTS idx_transitions_lifecycle
                        ON transitions(lifecycle_id);

                    CREATE INDEX IF NOT EXISTS idx_lifecycle_updated
                        ON lifecycles(updated_at);
                """)
                conn.commit()
            finally:
                conn.close()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def register_finding(self, finding: dict, org_id: str = "default") -> str:
        """
        Register a new finding. Returns lifecycle_id.
        Idempotent: same finding_id + org_id returns existing lifecycle_id.
        """
        finding_id = str(finding.get("id") or finding.get("finding_id") or uuid.uuid4())
        now = _now_iso()

        with self._lock:
            conn = self._connect()
            try:
                # Check for existing record (idempotency)
                row = conn.execute(
                    "SELECT lifecycle_id FROM lifecycles WHERE finding_id = ? AND org_id = ?",
                    (finding_id, org_id),
                ).fetchone()
                if row:
                    return row["lifecycle_id"]

                lifecycle_id = str(uuid.uuid4())
                conn.execute(
                    """INSERT INTO lifecycles
                       (lifecycle_id, finding_id, org_id, state, severity, title, source, finding_data, created_at, updated_at)
                       VALUES (?, ?, ?, 'discovered', ?, ?, ?, ?, ?, ?)""",
                    (
                        lifecycle_id,
                        finding_id,
                        org_id,
                        finding.get("severity"),
                        finding.get("title"),
                        finding.get("source"),
                        json.dumps(finding),
                        now,
                        now,
                    ),
                )
                # Record the initial "discovered" pseudo-transition
                conn.execute(
                    """INSERT INTO transitions
                       (id, lifecycle_id, from_state, to_state, actor, notes, transitioned_at)
                       VALUES (?, ?, '', 'discovered', 'system', 'initial registration', ?)""",
                    (str(uuid.uuid4()), lifecycle_id, now),
                )
                conn.commit()
                self._emit_event(
                    "vuln_lifecycle.registered",
                    {
                        "lifecycle_id": lifecycle_id,
                        "finding_id": finding_id,
                        "org_id": org_id,
                        "severity": finding.get("severity"),
                        "state": "discovered",
                    },
                )
                return lifecycle_id
            finally:
                conn.close()

    def transition(
        self,
        lifecycle_id: str,
        new_state: str,
        actor: str = "system",
        notes: str = "",
    ) -> dict:
        """
        Transition a finding to a new state.
        Validates against the state machine.
        Returns the transition record.
        Raises ValueError on invalid transition or unknown lifecycle_id.
        """
        if new_state not in LIFECYCLE_STATES:
            raise ValueError(f"Unknown state: {new_state!r}. Valid: {LIFECYCLE_STATES}")

        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT state FROM lifecycles WHERE lifecycle_id = ?",
                    (lifecycle_id,),
                ).fetchone()
                if not row:
                    raise ValueError(f"lifecycle_id not found: {lifecycle_id!r}")

                current_state = row["state"]

                allowed = VALID_TRANSITIONS.get(current_state, set())
                if new_state not in allowed:
                    raise ValueError(
                        f"Invalid transition {current_state!r} → {new_state!r}. "
                        f"Allowed: {sorted(allowed)}"
                    )

                now = _now_iso()
                transition_id = str(uuid.uuid4())
                conn.execute(
                    """INSERT INTO transitions
                       (id, lifecycle_id, from_state, to_state, actor, notes, transitioned_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (transition_id, lifecycle_id, current_state, new_state, actor, notes, now),
                )
                conn.execute(
                    "UPDATE lifecycles SET state = ?, updated_at = ? WHERE lifecycle_id = ?",
                    (new_state, now, lifecycle_id),
                )
                conn.commit()

                record = {
                    "id": transition_id,
                    "lifecycle_id": lifecycle_id,
                    "from_state": current_state,
                    "to_state": new_state,
                    "actor": actor,
                    "notes": notes,
                    "transitioned_at": now,
                }
                self._emit_event("vuln_lifecycle.transitioned", record)
                return record
            finally:
                conn.close()

    def get_lifecycle(self, lifecycle_id: str) -> Optional[dict]:
        """Full lifecycle record with transition history."""
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT * FROM lifecycles WHERE lifecycle_id = ?",
                (lifecycle_id,),
            ).fetchone()
            if not row:
                return None

            record = dict(row)
            record["finding_data"] = json.loads(record["finding_data"] or "{}")

            transitions = conn.execute(
                """SELECT * FROM transitions WHERE lifecycle_id = ?
                   ORDER BY transitioned_at ASC""",
                (lifecycle_id,),
            ).fetchall()
            record["history"] = [dict(t) for t in transitions]
            return record
        finally:
            conn.close()

    def get_by_finding_id(self, finding_id: str, org_id: str = "default") -> Optional[dict]:
        """Lookup lifecycle by original scanner finding_id."""
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT lifecycle_id FROM lifecycles WHERE finding_id = ? AND org_id = ?",
                (finding_id, org_id),
            ).fetchone()
            if not row:
                return None
            return self.get_lifecycle(row["lifecycle_id"])
        finally:
            conn.close()

    def list_by_state(self, state: str, org_id: str = "default") -> List[dict]:
        """All findings in a given state for an org."""
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT * FROM lifecycles WHERE state = ? AND org_id = ? ORDER BY updated_at DESC",
                (state, org_id),
            ).fetchall()
            result = []
            for row in rows:
                record = dict(row)
                record["finding_data"] = json.loads(record["finding_data"] or "{}")
                result.append(record)
            return result
        finally:
            conn.close()

    def get_metrics(self, org_id: str = "default") -> dict:
        """
        Returns aggregated metrics for an org:
          - by_state: count per state
          - avg_time_to_fix_days: average days from discovered → fixed
          - open_count: total in open states
          - closed_this_week: closed/verified/terminal in last 7 days
          - false_positive_rate: false_positives / total
        """
        conn = self._connect()
        try:
            # Counts by state
            rows = conn.execute(
                "SELECT state, COUNT(*) as cnt FROM lifecycles WHERE org_id = ? GROUP BY state",
                (org_id,),
            ).fetchall()
            by_state: Dict[str, int] = {row["state"]: row["cnt"] for row in rows}

            total = sum(by_state.values())
            open_count = sum(by_state.get(s, 0) for s in OPEN_STATES)
            fp_count = by_state.get("false_positive", 0)
            false_positive_rate = (fp_count / total) if total > 0 else 0.0

            # Closed this week
            week_ago = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
            closed_row = conn.execute(
                """SELECT COUNT(*) as cnt FROM lifecycles
                   WHERE org_id = ? AND state IN ('closed','false_positive','accepted_risk','wont_fix')
                   AND updated_at >= ?""",
                (org_id, week_ago),
            ).fetchone()
            closed_this_week = closed_row["cnt"] if closed_row else 0

            # Average time to fix: discovered_at → first fixed transition
            # We join the initial 'discovered' transition with the first 'fixed' transition per lifecycle
            fix_rows = conn.execute(
                """
                SELECT
                    t_start.transitioned_at AS started,
                    t_fix.transitioned_at   AS fixed
                FROM transitions t_start
                JOIN transitions t_fix ON t_start.lifecycle_id = t_fix.lifecycle_id
                JOIN lifecycles lc ON lc.lifecycle_id = t_start.lifecycle_id
                WHERE lc.org_id = ?
                  AND t_start.to_state = 'discovered'
                  AND t_fix.to_state = 'fixed'
                  AND t_fix.transitioned_at = (
                      SELECT MIN(transitioned_at) FROM transitions
                      WHERE lifecycle_id = t_start.lifecycle_id AND to_state = 'fixed'
                  )
                """,
                (org_id,),
            ).fetchall()

            durations = []
            for r in fix_rows:
                start = _parse_iso(r["started"])
                end = _parse_iso(r["fixed"])
                if start and end:
                    durations.append((end - start).total_seconds() / 86400.0)

            avg_time_to_fix_days = (sum(durations) / len(durations)) if durations else 0.0

            return {
                "by_state": by_state,
                "avg_time_to_fix_days": round(avg_time_to_fix_days, 2),
                "open_count": open_count,
                "closed_this_week": closed_this_week,
                "false_positive_rate": round(false_positive_rate, 4),
            }
        finally:
            conn.close()

    def bulk_register(self, findings: List[dict], org_id: str = "default") -> List[str]:
        """
        Register multiple findings in a single transaction.
        Returns list of lifecycle_ids in the same order as input.
        Idempotent: existing finding_id+org_id pairs return their existing lifecycle_id.

        Performance: O(1) lock acquisitions + O(1) DB open/close vs O(N) for the
        naive loop. ~10x faster at N=100 findings.
        """
        if not findings:
            return []

        now = _now_iso()

        # Build (finding_id, finding) pairs up-front (outside lock)
        pairs: List[tuple] = []
        for f in findings:
            fid = str(f.get("id") or f.get("finding_id") or uuid.uuid4())
            pairs.append((fid, f))

        result_ids: List[str] = [None] * len(pairs)  # type: ignore[list-item]

        with self._lock:
            conn = self._connect()
            try:
                # Single pass: resolve existing, collect new
                new_indices: List[int] = []
                new_rows: List[tuple] = []       # lifecycle INSERT rows
                new_trans: List[tuple] = []      # transitions INSERT rows
                new_ids: List[str] = []

                for idx, (finding_id, finding) in enumerate(pairs):
                    row = conn.execute(
                        "SELECT lifecycle_id FROM lifecycles WHERE finding_id = ? AND org_id = ?",
                        (finding_id, org_id),
                    ).fetchone()
                    if row:
                        result_ids[idx] = row["lifecycle_id"]
                    else:
                        lifecycle_id = str(uuid.uuid4())
                        transition_id = str(uuid.uuid4())
                        new_rows.append((
                            lifecycle_id, finding_id, org_id,
                            finding.get("severity"), finding.get("title"),
                            finding.get("source"), json.dumps(finding),
                            now, now,
                        ))
                        new_trans.append((
                            transition_id, lifecycle_id, now,
                        ))
                        new_indices.append(idx)
                        new_ids.append(lifecycle_id)

                if new_rows:
                    conn.executemany(
                        """INSERT INTO lifecycles
                           (lifecycle_id, finding_id, org_id, state, severity, title,
                            source, finding_data, created_at, updated_at)
                           VALUES (?, ?, ?, 'discovered', ?, ?, ?, ?, ?, ?)""",
                        new_rows,
                    )
                    conn.executemany(
                        """INSERT INTO transitions
                           (id, lifecycle_id, from_state, to_state, actor, notes, transitioned_at)
                           VALUES (?, ?, '', 'discovered', 'system', 'initial registration', ?)""",
                        new_trans,
                    )
                    conn.commit()

                    for idx, lifecycle_id in zip(new_indices, new_ids):
                        result_ids[idx] = lifecycle_id
            finally:
                conn.close()

        # Emit events outside the lock (best-effort, non-blocking)
        for idx, lifecycle_id in zip(new_indices, new_ids):
            finding_id, finding = pairs[idx]
            self._emit_event(
                "vuln_lifecycle.registered",
                {
                    "lifecycle_id": lifecycle_id,
                    "finding_id": finding_id,
                    "org_id": org_id,
                    "severity": finding.get("severity"),
                    "state": "discovered",
                },
            )

        return result_ids

    # ------------------------------------------------------------------
    # TrustGraph event emission (best-effort, non-blocking)
    # ------------------------------------------------------------------

    def _emit_event(self, event_type: str, payload: "dict[str, Any]") -> None:
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
            pass

