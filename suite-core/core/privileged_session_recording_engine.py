"""Privileged Session Recording Engine — ALDECI.

Records and audits privileged access sessions (SSH, RDP, database, API, etc.)
with real-time alert detection and risk analytics.

Features:
- Session lifecycle: start → recording → paused/completed/failed/archived
- Per-session alert tracking (suspicious_command, data_exfiltration, etc.)
- High-risk session detection (alerts_count > 3)
- Stats: active sessions, avg duration, by_session_type, by_alert_type

Compliance: NIST SP 800-53 AU-14 (Session Audit), PCI-DSS 10.x,
            CIS Control 8 (Audit Log Management)
"""

from __future__ import annotations

import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "privileged_session_recording.db"
)

_VALID_SESSION_TYPES = {"ssh", "rdp", "database", "api", "console", "winrm", "telnet"}
_VALID_RECORDING_STATUSES = {"recording", "paused", "completed", "failed", "archived"}
_VALID_ALERT_TYPES = {
    "suspicious_command", "data_exfiltration", "privilege_escalation",
    "policy_violation", "anomaly",
}


class PrivilegedSessionRecordingEngine:
    """Engine for privileged session recording and alert management."""

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # DB INIT
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS psr_sessions (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    user             TEXT NOT NULL DEFAULT '',
                    session_type     TEXT NOT NULL DEFAULT 'ssh',
                    target_host      TEXT NOT NULL DEFAULT '',
                    target_ip        TEXT NOT NULL DEFAULT '',
                    initiated_by     TEXT NOT NULL DEFAULT '',
                    status           TEXT NOT NULL DEFAULT 'recording',
                    duration_seconds INTEGER NOT NULL DEFAULT 0,
                    commands_count   INTEGER NOT NULL DEFAULT 0,
                    keystrokes_count INTEGER NOT NULL DEFAULT 0,
                    alerts_count     INTEGER NOT NULL DEFAULT 0,
                    started_at       DATETIME,
                    ended_at         DATETIME,
                    recording_url    TEXT NOT NULL DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS psr_alerts (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    session_id      TEXT NOT NULL,
                    alert_type      TEXT NOT NULL DEFAULT 'anomaly',
                    severity        TEXT NOT NULL DEFAULT 'medium',
                    description     TEXT NOT NULL DEFAULT '',
                    command_context TEXT NOT NULL DEFAULT '',
                    detected_at     DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_psr_sessions_org    ON psr_sessions(org_id);
                CREATE INDEX IF NOT EXISTS idx_psr_sessions_status ON psr_sessions(org_id, status);
                CREATE INDEX IF NOT EXISTS idx_psr_alerts_org      ON psr_alerts(org_id);
                CREATE INDEX IF NOT EXISTS idx_psr_alerts_session  ON psr_alerts(session_id);
            """)

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    # ------------------------------------------------------------------
    # SESSION MANAGEMENT
    # ------------------------------------------------------------------

    def start_session(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Start a new privileged session recording. Returns the session record."""
        user = data.get("user", "").strip()
        if not user:
            raise ValueError("user is required")

        session_type = data.get("session_type", "ssh")
        if session_type not in _VALID_SESSION_TYPES:
            raise ValueError(
                f"Invalid session_type '{session_type}'. Must be one of {sorted(_VALID_SESSION_TYPES)}"
            )

        target_host = data.get("target_host", "").strip()
        if not target_host:
            raise ValueError("target_host is required")

        session_id = str(uuid.uuid4())
        now = self._now()

        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO psr_sessions
                   (id, org_id, user, session_type, target_host, target_ip,
                    initiated_by, status, duration_seconds, commands_count,
                    keystrokes_count, alerts_count, started_at, ended_at, recording_url)
                   VALUES (?,?,?,?,?,?,?,'recording',0,0,0,0,?,NULL,'')""",
                (
                    session_id, org_id, user, session_type, target_host,
                    data.get("target_ip", ""),
                    data.get("initiated_by", ""),
                    now,
                ),
            )
        _logger.info(
            "psr.session_started org=%s session_id=%s user=%s target=%s",
            org_id, session_id, user, target_host,
        )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("IDENTITY_UPDATED", {"entity_type": "privileged_session_recording", "org_id": org_id, "source_engine": "privileged_session_recording"})
            except Exception:
                pass

        return self.get_session(org_id, session_id)

    def end_session(
        self,
        org_id: str,
        session_id: str,
        end_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """End a session. Sets status=completed, ended_at, duration_seconds, recording_url."""
        sess = self.get_session(org_id, session_id)
        if sess is None:
            raise ValueError(f"Session '{session_id}' not found for org '{org_id}'")

        now = self._now()
        duration_seconds = int(end_data.get("duration_seconds", 0))
        recording_url = end_data.get("recording_url", "")

        with self._lock, self._conn() as conn:
            conn.execute(
                """UPDATE psr_sessions
                   SET status='completed', ended_at=?, duration_seconds=?, recording_url=?
                   WHERE org_id=? AND id=?""",
                (now, duration_seconds, recording_url, org_id, session_id),
            )
        _logger.info(
            "psr.session_ended org=%s session_id=%s duration=%ds",
            org_id, session_id, duration_seconds,
        )
        return self.get_session(org_id, session_id)

    def list_sessions(
        self,
        org_id: str,
        user: Optional[str] = None,
        session_type: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List sessions for org, optionally filtered, ordered by started_at DESC."""
        query = "SELECT * FROM psr_sessions WHERE org_id=?"
        params: List[Any] = [org_id]
        if user:
            query += " AND user=?"
            params.append(user)
        if session_type:
            query += " AND session_type=?"
            params.append(session_type)
        if status:
            query += " AND status=?"
            params.append(status)
        query += " ORDER BY started_at DESC"
        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # PAM CONNECTOR FALLBACK (CyberArk)
    # ------------------------------------------------------------------

    def list_sessions_with_pam_fallback(
        self,
        org_id: str,
        user: Optional[str] = None,
        session_type: Optional[str] = None,
        status: Optional[str] = None,
        pam_connector: Any = None,
    ) -> Dict[str, Any]:
        """List PSR sessions; fall back to CyberArk PAM privileged accounts.

        Behaviour (ranked):

        1. Org has recorded sessions → ``source="org_registered"``.
        2. Else if a CyberArk connector is available *and* its env creds are
           present, call ``sync()`` and project each privileged account into
           an inventory-style session row → ``source="cyberark_pam"``. The
           projected rows are flagged ``status="inventory"`` because the PAM
           account is a session *target*, not an active recording — useful for
           on-call SOC visibility while no real session is in flight.
        3. Else if creds *or* the SDK are missing → ``source="needs_credentials"``
           with a structured hint. NEVER mocks.
        4. Connector returned ``status != "ok"`` (e.g. ``api_error``) →
           ``source="connector_error"``.
        5. Connector OK but returned zero accounts → ``source="needs_data"``.

        Filters apply against the projected rows in modes 2/4/5 too.
        """
        if not isinstance(org_id, str) or not org_id.strip():
            raise ValueError("org_id is required")

        org_rows = self.list_sessions(
            org_id, user=user, session_type=session_type, status=status,
        )
        if org_rows:
            return {
                "sessions": org_rows,
                "total": len(org_rows),
                "source": "org_registered",
            }

        creds_present = False
        connector_unavailable_reason: Optional[str] = None
        if pam_connector is None:
            try:
                from connectors.cyberark_connector import (  # type: ignore
                    _creds_present,
                    get_cyberark_connector,
                )
                creds_present = bool(_creds_present())
                if creds_present:
                    pam_connector = get_cyberark_connector()
            except (ImportError, RuntimeError) as exc:
                connector_unavailable_reason = f"connector_import_failed: {exc}"
        else:
            creds_present = True

        if not creds_present or pam_connector is None:
            return {
                "sessions": [],
                "total": 0,
                "source": "needs_credentials",
                "hint": (
                    "Set CYBERARK_BASE_URL, CYBERARK_USER, and CYBERARK_PASS "
                    "to enable CyberArk PAM privileged-account inventory, or "
                    "POST /api/v1/session-recording/sessions to start a "
                    "session manually."
                ),
                **({"reason": connector_unavailable_reason}
                   if connector_unavailable_reason else {}),
            }

        try:
            payload = pam_connector.sync(org_id)
        except Exception as exc:  # noqa: BLE001 - never let connector crash list
            _logger.warning(
                "CyberArk sync failed for org=%s: %s", org_id, exc,
            )
            return {
                "sessions": [],
                "total": 0,
                "source": "connector_error",
                "error": str(exc)[:500],
            }

        connector_status = (payload or {}).get("status", "")
        if connector_status == "needs_credentials":
            return {
                "sessions": [],
                "total": 0,
                "source": "needs_credentials",
                "hint": payload.get("hint", "CyberArk credentials missing."),
            }
        if connector_status != "ok":
            return {
                "sessions": [],
                "total": 0,
                "source": "connector_error",
                "error": str(payload.get("error") or connector_status)[:500],
            }

        accounts = payload.get("findings") or []
        derived: List[Dict[str, Any]] = []
        for acct in accounts:
            platform = (acct.get("platform") or "").lower()
            # Map CyberArk platform → ALDECI session_type bucket.
            if "ssh" in platform or "linux" in platform or "unix" in platform:
                stype = "ssh"
            elif "winrm" in platform:
                stype = "winrm"
            elif "rdp" in platform or "windows" in platform:
                stype = "rdp"
            elif any(db in platform for db in ("oracle", "sql", "postgres", "mysql")):
                stype = "database"
            else:
                stype = "console"
            derived.append({
                "id": acct.get("account_id") or acct.get("correlation_key"),
                "org_id": org_id,
                "user": "",  # CyberArk lists target accounts; user is the connecting agent
                "session_type": stype,
                "target_host": acct.get("safe", "") or "unknown",
                "target_ip": "",
                "initiated_by": "cyberark_pam",
                "status": "inventory",
                "duration_seconds": 0,
                "commands_count": 0,
                "keystrokes_count": 0,
                "alerts_count": 0,
                "started_at": None,
                "ended_at": None,
                "recording_url": "",
                "source": "cyberark_pam",
                "platform": acct.get("platform", ""),
                "severity": acct.get("severity", "low"),
            })

        # Apply filters against derived rows.
        if user:
            derived = [d for d in derived if d["user"] == user]
        if session_type:
            derived = [d for d in derived if d["session_type"] == session_type]
        if status:
            derived = [d for d in derived if d["status"] == status]

        if not derived:
            return {
                "sessions": [],
                "total": 0,
                "source": "needs_data",
                "hint": (
                    "CyberArk reachable but returned no privileged accounts "
                    "matching the requested filters."
                ),
            }

        return {
            "sessions": derived,
            "total": len(derived),
            "source": "cyberark_pam",
        }

    def get_session(self, org_id: str, session_id: str) -> Optional[Dict[str, Any]]:
        """Fetch a single session scoped to org_id. Returns None if not found."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM psr_sessions WHERE org_id=? AND id=?",
                (org_id, session_id),
            ).fetchone()
        return self._row(row) if row else None

    # ------------------------------------------------------------------
    # ALERT MANAGEMENT
    # ------------------------------------------------------------------

    def record_alert(
        self,
        org_id: str,
        session_id: str,
        alert_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Record a session alert and increment session.alerts_count."""
        sess = self.get_session(org_id, session_id)
        if sess is None:
            raise ValueError(f"Session '{session_id}' not found for org '{org_id}'")

        alert_type = alert_data.get("alert_type", "anomaly")
        if alert_type not in _VALID_ALERT_TYPES:
            raise ValueError(
                f"Invalid alert_type '{alert_type}'. Must be one of {sorted(_VALID_ALERT_TYPES)}"
            )

        alert_id = str(uuid.uuid4())
        now = self._now()

        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO psr_alerts
                   (id, org_id, session_id, alert_type, severity,
                    description, command_context, detected_at)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (
                    alert_id, org_id, session_id, alert_type,
                    alert_data.get("severity", "medium"),
                    alert_data.get("description", ""),
                    alert_data.get("command_context", ""),
                    now,
                ),
            )
            conn.execute(
                "UPDATE psr_sessions SET alerts_count=alerts_count+1 WHERE org_id=? AND id=?",
                (org_id, session_id),
            )
        _logger.info(
            "psr.alert_recorded org=%s session_id=%s alert_type=%s",
            org_id, session_id, alert_type,
        )
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM psr_alerts WHERE id=?", (alert_id,)
            ).fetchone()
        return self._row(row)

    def list_alerts(
        self,
        org_id: str,
        session_id: Optional[str] = None,
        alert_type: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List alerts for org, optionally filtered by session, type, or severity."""
        query = "SELECT * FROM psr_alerts WHERE org_id=?"
        params: List[Any] = [org_id]
        if session_id:
            query += " AND session_id=?"
            params.append(session_id)
        if alert_type:
            query += " AND alert_type=?"
            params.append(alert_type)
        if severity:
            query += " AND severity=?"
            params.append(severity)
        query += " ORDER BY detected_at DESC"
        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # STATS
    # ------------------------------------------------------------------

    def get_recording_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregate recording stats for the org."""
        with self._conn() as conn:
            total_sessions = conn.execute(
                "SELECT COUNT(*) FROM psr_sessions WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            active_sessions = conn.execute(
                "SELECT COUNT(*) FROM psr_sessions WHERE org_id=? AND status='recording'",
                (org_id,),
            ).fetchone()[0]

            total_alerts = conn.execute(
                "SELECT COUNT(*) FROM psr_alerts WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            high_risk_sessions = conn.execute(
                "SELECT COUNT(*) FROM psr_sessions WHERE org_id=? AND alerts_count>3",
                (org_id,),
            ).fetchone()[0]

            avg_row = conn.execute(
                """SELECT AVG(duration_seconds) FROM psr_sessions
                   WHERE org_id=? AND status='completed'""",
                (org_id,),
            ).fetchone()[0]

            by_type = conn.execute(
                """SELECT session_type, COUNT(*) AS cnt
                   FROM psr_sessions WHERE org_id=?
                   GROUP BY session_type""",
                (org_id,),
            ).fetchall()

            by_alert = conn.execute(
                """SELECT alert_type, COUNT(*) AS cnt
                   FROM psr_alerts WHERE org_id=?
                   GROUP BY alert_type""",
                (org_id,),
            ).fetchall()

        avg_duration_minutes = round((avg_row / 60.0), 2) if avg_row else 0.0

        return {
            "total_sessions": total_sessions,
            "active_sessions": active_sessions,
            "total_alerts": total_alerts,
            "high_risk_sessions": high_risk_sessions,
            "avg_duration_minutes": avg_duration_minutes,
            "by_session_type": {r["session_type"]: r["cnt"] for r in by_type},
            "by_alert_type": {r["alert_type"]: r["cnt"] for r in by_alert},
        }
