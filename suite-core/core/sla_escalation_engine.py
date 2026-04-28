"""
SLA Escalation Engine — Auto-escalation for breached SLA findings.

Monitors tracked findings for SLA deadline breaches and automatically
triggers escalation actions based on how long the breach has persisted:

  0-24h past deadline  → notify
  24-72h past deadline → reassign
  72h+ past deadline   → escalate_severity + create_incident

Stores escalation history in SQLite (WAL mode).

Compliance: SOC2 CC7.2, ISO27001 A.12.6.1, NIST SP 800-137
"""
from __future__ import annotations

import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import structlog

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# DB path
# ---------------------------------------------------------------------------

_DB_PATH = str(
    Path(__file__).resolve().parents[2] / "data" / "sla_escalation.db"
)

# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

_SCHEMA = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS escalation_policies (
    org_id                  TEXT PRIMARY KEY,
    breach_threshold_hours  INTEGER NOT NULL DEFAULT 24,
    auto_action             TEXT NOT NULL DEFAULT 'notify',
    severity_bump           INTEGER NOT NULL DEFAULT 0,
    updated_at              TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS escalation_events (
    id          TEXT PRIMARY KEY,
    finding_id  TEXT NOT NULL,
    org_id      TEXT NOT NULL,
    action      TEXT NOT NULL,
    hours_past  REAL NOT NULL,
    note        TEXT,
    created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_esc_finding ON escalation_events(finding_id);
CREATE INDEX IF NOT EXISTS idx_esc_org     ON escalation_events(org_id);

CREATE TABLE IF NOT EXISTS sla_tracked_findings (
    finding_id  TEXT NOT NULL,
    org_id      TEXT NOT NULL,
    severity    TEXT NOT NULL DEFAULT 'medium',
    deadline    TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'active',
    PRIMARY KEY (finding_id, org_id)
);
CREATE INDEX IF NOT EXISTS idx_tf_org ON sla_tracked_findings(org_id, status);
"""

# ---------------------------------------------------------------------------
# Action constants
# ---------------------------------------------------------------------------


class EscalationAction:
    NOTIFY = "notify"
    REASSIGN = "reassign"
    ESCALATE_SEVERITY = "escalate_severity"
    CREATE_INCIDENT = "create_incident"
    OVERRIDE_SLA = "override_sla"


_ALL_ACTIONS = {
    EscalationAction.NOTIFY,
    EscalationAction.REASSIGN,
    EscalationAction.ESCALATE_SEVERITY,
    EscalationAction.CREATE_INCIDENT,
    EscalationAction.OVERRIDE_SLA,
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _now_iso() -> str:
    return _now().isoformat()


def _parse_dt(value: str) -> datetime:
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _actions_for_hours(hours_past: float) -> list[str]:
    """Return the auto-escalation actions for a given hours-past-deadline value."""
    if hours_past < 24:
        return [EscalationAction.NOTIFY]
    if hours_past < 72:
        return [EscalationAction.REASSIGN]
    return [EscalationAction.ESCALATE_SEVERITY, EscalationAction.CREATE_INCIDENT]


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class SLAEscalationEngine:
    """Auto-escalation engine for breached SLA findings.

    Args:
        db_path: Path to SQLite database file.  Defaults to
                 ``data/sla_escalation.db`` relative to the repo root.
    """

    def __init__(self, db_path: str = _DB_PATH) -> None:
        self._db_path = db_path
        self._lock = threading.Lock()
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    # ------------------------------------------------------------------
    # DB helpers
    # ------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._lock, self._connect() as conn:
            conn.executescript(_SCHEMA)
            conn.commit()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check_sla_breaches(self, org_id: str = "default") -> list[dict]:
        """Scan all tracked findings for SLA breaches.

        Returns a list of breach-event dicts, one per breached finding.
        Only findings whose deadline has already passed are included.
        """
        now = _now()
        breaches: list[dict] = []

        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT finding_id, severity, deadline
                FROM sla_tracked_findings
                WHERE org_id = ? AND status = 'active'
                """,
                (org_id,),
            ).fetchall()

        for row in rows:
            deadline = _parse_dt(row["deadline"])
            if now <= deadline:
                continue  # not yet breached

            hours_past = (now - deadline).total_seconds() / 3600
            breaches.append(
                {
                    "finding_id": row["finding_id"],
                    "severity": row["severity"],
                    "deadline": row["deadline"],
                    "hours_past_deadline": round(hours_past, 2),
                    "recommended_actions": _actions_for_hours(hours_past),
                }
            )

        _logger.info(
            "sla_breach_check",
            org_id=org_id,
            breaches_found=len(breaches),
        )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("FINDING_CREATED", {"entity_type": "sla_escalation", "org_id": org_id, "source_engine": "sla_escalation"})
            except Exception:
                pass

        return breaches

    def escalate(
        self,
        finding_id: str,
        action: str,
        org_id: str = "default",
        note: Optional[str] = None,
    ) -> dict:
        """Execute an escalation action for a finding.

        Records the escalation event and returns the escalation record.
        Raises ValueError for unknown actions.
        """
        if action not in _ALL_ACTIONS:
            raise ValueError(
                f"Unknown escalation action '{action}'. "
                f"Valid actions: {sorted(_ALL_ACTIONS)}"
            )

        now = _now()
        hours_past = 0.0

        with self._connect() as conn:
            row = conn.execute(
                "SELECT deadline FROM sla_tracked_findings WHERE finding_id = ? AND org_id = ?",
                (finding_id, org_id),
            ).fetchone()
            if row:
                deadline = _parse_dt(row["deadline"])
                if now > deadline:
                    hours_past = (now - deadline).total_seconds() / 3600

            event_id = str(uuid.uuid4())
            created_at = now.isoformat()
            conn.execute(
                """
                INSERT INTO escalation_events
                    (id, finding_id, org_id, action, hours_past, note, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (event_id, finding_id, org_id, action, round(hours_past, 2), note, created_at),
            )
            conn.commit()

        record = {
            "id": event_id,
            "finding_id": finding_id,
            "org_id": org_id,
            "action": action,
            "hours_past_deadline": round(hours_past, 2),
            "note": note,
            "created_at": created_at,
        }
        _logger.info("escalation_executed", finding_id=finding_id, action=action, org_id=org_id)
        return record

    def get_escalation_history(
        self,
        finding_id: Optional[str] = None,
        org_id: str = "default",
    ) -> list[dict]:
        """List escalation events, optionally filtered by finding_id."""
        with self._connect() as conn:
            if finding_id:
                rows = conn.execute(
                    """
                    SELECT id, finding_id, org_id, action, hours_past, note, created_at
                    FROM escalation_events
                    WHERE org_id = ? AND finding_id = ?
                    ORDER BY created_at DESC
                    """,
                    (org_id, finding_id),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT id, finding_id, org_id, action, hours_past, note, created_at
                    FROM escalation_events
                    WHERE org_id = ?
                    ORDER BY created_at DESC
                    """,
                    (org_id,),
                ).fetchall()

        return [dict(r) for r in rows]

    def run_escalation_cycle(self, org_id: str = "default") -> dict:
        """Full cycle: check breaches → auto-escalate per policy → return summary.

        Returns:
            {
                "breaches_found": int,
                "escalations_triggered": int,
                "actions": [{"finding_id": ..., "action": ...}, ...]
            }
        """
        policy = self.get_escalation_policy(org_id)
        breaches = self.check_sla_breaches(org_id)

        triggered_actions: list[dict] = []

        for breach in breaches:
            hours_past = breach["hours_past_deadline"]
            threshold = policy.get("breach_threshold_hours", 24)

            if hours_past < threshold:
                continue  # not past org-specific threshold yet

            actions = _actions_for_hours(hours_past)

            # If severity_bump is enabled and not already included, add escalate_severity
            if policy.get("severity_bump") and EscalationAction.ESCALATE_SEVERITY not in actions:
                actions = [EscalationAction.ESCALATE_SEVERITY] + actions

            for action in actions:
                record = self.escalate(
                    finding_id=breach["finding_id"],
                    action=action,
                    org_id=org_id,
                    note=f"Auto-escalated after {hours_past:.1f}h past deadline",
                )
                triggered_actions.append(
                    {"finding_id": breach["finding_id"], "action": action, "record_id": record["id"]}
                )

        summary = {
            "breaches_found": len(breaches),
            "escalations_triggered": len(triggered_actions),
            "actions": triggered_actions,
        }
        _logger.info("escalation_cycle_complete", org_id=org_id, **{k: v for k, v in summary.items() if k != "actions"})
        return summary

    def set_escalation_policy(self, policy: dict, org_id: str = "default") -> dict:
        """Configure escalation policy for an org.

        Args:
            policy: dict with keys:
                - breach_threshold_hours (int): hours past deadline before auto-action fires
                - auto_action (str): default action to take
                - severity_bump (bool): whether to bump severity on escalation
            org_id: Organisation identifier.

        Returns:
            The stored policy dict.
        """
        breach_threshold_hours = int(policy.get("breach_threshold_hours", 24))
        auto_action = policy.get("auto_action", EscalationAction.NOTIFY)
        severity_bump = bool(policy.get("severity_bump", False))
        updated_at = _now_iso()

        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO escalation_policies
                    (org_id, breach_threshold_hours, auto_action, severity_bump, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(org_id) DO UPDATE SET
                    breach_threshold_hours = excluded.breach_threshold_hours,
                    auto_action            = excluded.auto_action,
                    severity_bump          = excluded.severity_bump,
                    updated_at             = excluded.updated_at
                """,
                (org_id, breach_threshold_hours, auto_action, int(severity_bump), updated_at),
            )
            conn.commit()

        stored = {
            "org_id": org_id,
            "breach_threshold_hours": breach_threshold_hours,
            "auto_action": auto_action,
            "severity_bump": severity_bump,
            "updated_at": updated_at,
        }
        _logger.info("escalation_policy_set", org_id=org_id)
        return stored

    def get_escalation_policy(self, org_id: str = "default") -> dict:
        """Return the escalation policy for an org, or sensible defaults."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM escalation_policies WHERE org_id = ?",
                (org_id,),
            ).fetchone()

        if row:
            return {
                "org_id": row["org_id"],
                "breach_threshold_hours": row["breach_threshold_hours"],
                "auto_action": row["auto_action"],
                "severity_bump": bool(row["severity_bump"]),
                "updated_at": row["updated_at"],
            }

        # Return defaults if no policy configured yet
        return {
            "org_id": org_id,
            "breach_threshold_hours": 24,
            "auto_action": EscalationAction.NOTIFY,
            "severity_bump": False,
            "updated_at": None,
        }

    # ------------------------------------------------------------------
    # Convenience: register a finding for escalation tracking
    # ------------------------------------------------------------------

    def track_finding(
        self,
        finding_id: str,
        deadline: datetime,
        severity: str = "medium",
        org_id: str = "default",
    ) -> dict:
        """Register a finding so the engine can monitor its SLA deadline.

        This is a low-level helper used by tests and integration wiring.
        Production code should use the existing SLAEngine/SLAManager for
        primary tracking and call this to sync findings into the escalation
        engine's own table.
        """
        deadline_iso = deadline.isoformat() if deadline.tzinfo else deadline.replace(tzinfo=timezone.utc).isoformat()

        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO sla_tracked_findings (finding_id, org_id, severity, deadline, status)
                VALUES (?, ?, ?, ?, 'active')
                ON CONFLICT(finding_id, org_id) DO UPDATE SET
                    deadline = excluded.deadline,
                    severity = excluded.severity,
                    status   = 'active'
                """,
                (finding_id, org_id, severity, deadline_iso),
            )
            conn.commit()

        return {
            "finding_id": finding_id,
            "org_id": org_id,
            "severity": severity,
            "deadline": deadline_iso,
            "status": "active",
        }
