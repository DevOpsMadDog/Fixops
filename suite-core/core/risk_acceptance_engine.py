"""Risk acceptance workflow — formal process for accepting security risks."""
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import structlog

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = structlog.get_logger()

ACCEPTANCE_STATES = ["pending_review", "approved", "rejected", "expired", "revoked"]
RISK_LEVELS = ["low", "medium", "high", "critical"]


class RiskAcceptanceEngine:
    def __init__(self, db_path: str = "data/risk_acceptance.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_tables()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.execute("PRAGMA journal_mode=WAL")
        conn.row_factory = sqlite3.Row
        return conn

    def _init_tables(self) -> None:
        conn = self._get_connection()
        try:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS risk_acceptances (
                    acceptance_id TEXT PRIMARY KEY,
                    finding_id TEXT NOT NULL,
                    org_id TEXT NOT NULL DEFAULT 'default',
                    requestor TEXT NOT NULL,
                    justification TEXT NOT NULL,
                    risk_level TEXT NOT NULL,
                    state TEXT NOT NULL DEFAULT 'pending_review',
                    expiry_days INTEGER NOT NULL,
                    submitted_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    approver TEXT,
                    approver_notes TEXT,
                    reject_reason TEXT,
                    revoke_reason TEXT,
                    revoker TEXT,
                    resolved_at TEXT,
                    auto_waiver_exception_id TEXT
                );

                CREATE TABLE IF NOT EXISTS risk_acceptance_audit (
                    audit_id TEXT PRIMARY KEY,
                    acceptance_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    notes TEXT,
                    timestamp TEXT NOT NULL,
                    FOREIGN KEY (acceptance_id) REFERENCES risk_acceptances(acceptance_id)
                );

                CREATE INDEX IF NOT EXISTS idx_ra_finding ON risk_acceptances(finding_id);
                CREATE INDEX IF NOT EXISTS idx_ra_org ON risk_acceptances(org_id);
                CREATE INDEX IF NOT EXISTS idx_ra_state ON risk_acceptances(state);
                CREATE INDEX IF NOT EXISTS idx_ra_expires ON risk_acceptances(expires_at);
                CREATE INDEX IF NOT EXISTS idx_raa_acceptance ON risk_acceptance_audit(acceptance_id);
                """
            )
            # Additive migration for legacy DBs lacking auto_waiver_exception_id column
            cols = conn.execute("PRAGMA table_info(risk_acceptances)").fetchall()
            col_names = {c["name"] if isinstance(c, sqlite3.Row) else c[1] for c in cols}
            if "auto_waiver_exception_id" not in col_names:
                try:
                    conn.execute(
                        "ALTER TABLE risk_acceptances ADD COLUMN auto_waiver_exception_id TEXT"
                    )
                except sqlite3.OperationalError:
                    pass
            conn.commit()
        finally:
            conn.close()

    def _row_to_dict(self, row: sqlite3.Row) -> dict:
        return dict(row)

    def _append_audit(self, conn: sqlite3.Connection, acceptance_id: str,
                      action: str, actor: str, notes: str = "") -> None:
        conn.execute(
            """INSERT INTO risk_acceptance_audit
               (audit_id, acceptance_id, action, actor, notes, timestamp)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                str(uuid.uuid4()),
                acceptance_id,
                action,
                actor,
                notes,
                datetime.now(timezone.utc).isoformat(),
            ),
        )

    def submit_acceptance(
        self,
        finding_id: str,
        requestor: str,
        justification: str,
        risk_level: str,
        expiry_days: int = 90,
        org_id: str = "default",
    ) -> dict:
        """Submit a risk acceptance request."""
        if risk_level not in RISK_LEVELS:
            raise ValueError(
                f"Invalid risk_level '{risk_level}'. Must be one of: {RISK_LEVELS}"
            )

        acceptance_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(days=expiry_days)

        conn = self._get_connection()
        try:
            conn.execute(
                """INSERT INTO risk_acceptances
                   (acceptance_id, finding_id, org_id, requestor, justification,
                    risk_level, state, expiry_days, submitted_at, expires_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    acceptance_id,
                    finding_id,
                    org_id,
                    requestor,
                    justification,
                    risk_level,
                    "pending_review",
                    expiry_days,
                    now.isoformat(),
                    expires_at.isoformat(),
                ),
            )
            self._append_audit(conn, acceptance_id, "submitted", requestor, justification)
            conn.commit()
            _logger.info(
                "risk_acceptance_submitted",
                acceptance_id=acceptance_id,
                finding_id=finding_id,
                requestor=requestor,
            )
        finally:
            conn.close()

        return self.get_acceptance(acceptance_id)  # type: ignore[return-value]

    def approve(self, acceptance_id: str, approver: str, notes: str = "") -> dict:
        """Approve a pending acceptance."""
        conn = self._get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM risk_acceptances WHERE acceptance_id = ?",
                (acceptance_id,),
            ).fetchone()
            if row is None:
                raise ValueError(f"Acceptance '{acceptance_id}' not found")
            if row["state"] != "pending_review":
                raise ValueError(
                    f"Cannot approve acceptance in state '{row['state']}'"
                )
            now = datetime.now(timezone.utc).isoformat()
            conn.execute(
                """UPDATE risk_acceptances
                   SET state = 'approved', approver = ?, approver_notes = ?, resolved_at = ?
                   WHERE acceptance_id = ?""",
                (approver, notes, now, acceptance_id),
            )
            self._append_audit(conn, acceptance_id, "approved", approver, notes)
            conn.commit()
            _logger.info("risk_acceptance_approved", acceptance_id=acceptance_id, approver=approver)
        finally:
            conn.close()

        return self.get_acceptance(acceptance_id)  # type: ignore[return-value]

    def reject(self, acceptance_id: str, approver: str, reason: str) -> dict:
        """Reject a pending acceptance."""
        conn = self._get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM risk_acceptances WHERE acceptance_id = ?",
                (acceptance_id,),
            ).fetchone()
            if row is None:
                raise ValueError(f"Acceptance '{acceptance_id}' not found")
            if row["state"] != "pending_review":
                raise ValueError(
                    f"Cannot reject acceptance in state '{row['state']}'"
                )
            now = datetime.now(timezone.utc).isoformat()
            conn.execute(
                """UPDATE risk_acceptances
                   SET state = 'rejected', approver = ?, reject_reason = ?, resolved_at = ?
                   WHERE acceptance_id = ?""",
                (approver, reason, now, acceptance_id),
            )
            self._append_audit(conn, acceptance_id, "rejected", approver, reason)
            conn.commit()
            _logger.info("risk_acceptance_rejected", acceptance_id=acceptance_id, approver=approver)
        finally:
            conn.close()

        return self.get_acceptance(acceptance_id)  # type: ignore[return-value]

    def revoke(self, acceptance_id: str, revoker: str, reason: str) -> dict:
        """Revoke an approved acceptance before expiry."""
        conn = self._get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM risk_acceptances WHERE acceptance_id = ?",
                (acceptance_id,),
            ).fetchone()
            if row is None:
                raise ValueError(f"Acceptance '{acceptance_id}' not found")
            if row["state"] != "approved":
                raise ValueError(
                    f"Cannot revoke acceptance in state '{row['state']}'. Only approved acceptances can be revoked."
                )
            now = datetime.now(timezone.utc).isoformat()
            conn.execute(
                """UPDATE risk_acceptances
                   SET state = 'revoked', revoker = ?, revoke_reason = ?, resolved_at = ?
                   WHERE acceptance_id = ?""",
                (revoker, reason, now, acceptance_id),
            )
            self._append_audit(conn, acceptance_id, "revoked", revoker, reason)
            conn.commit()
            _logger.info("risk_acceptance_revoked", acceptance_id=acceptance_id, revoker=revoker)
        finally:
            conn.close()

        return self.get_acceptance(acceptance_id)  # type: ignore[return-value]

    def get_acceptance(self, acceptance_id: str) -> Optional[dict]:
        """Get single acceptance record with full audit trail."""
        conn = self._get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM risk_acceptances WHERE acceptance_id = ?",
                (acceptance_id,),
            ).fetchone()
            if row is None:
                return None
            record = self._row_to_dict(row)
            audit_rows = conn.execute(
                "SELECT * FROM risk_acceptance_audit WHERE acceptance_id = ? ORDER BY timestamp ASC",
                (acceptance_id,),
            ).fetchall()
            record["audit_trail"] = [self._row_to_dict(a) for a in audit_rows]
            return record
        finally:
            conn.close()

    def get_by_finding(self, finding_id: str, org_id: str = "default") -> Optional[dict]:
        """Get active acceptance for a finding (most recent non-rejected)."""
        conn = self._get_connection()
        try:
            row = conn.execute(
                """SELECT * FROM risk_acceptances
                   WHERE finding_id = ? AND org_id = ? AND state NOT IN ('rejected', 'revoked')
                   ORDER BY submitted_at DESC LIMIT 1""",
                (finding_id, org_id),
            ).fetchone()
            if row is None:
                return None
            record = self._row_to_dict(row)
            audit_rows = conn.execute(
                "SELECT * FROM risk_acceptance_audit WHERE acceptance_id = ? ORDER BY timestamp ASC",
                (record["acceptance_id"],),
            ).fetchall()
            record["audit_trail"] = [self._row_to_dict(a) for a in audit_rows]
            return record
        finally:
            conn.close()

    def list_acceptances(self, org_id: str = "default", state: Optional[str] = None) -> list:
        """List acceptances filtered by state."""
        conn = self._get_connection()
        try:
            if state is not None:
                rows = conn.execute(
                    "SELECT * FROM risk_acceptances WHERE org_id = ? AND state = ? ORDER BY submitted_at DESC",
                    (org_id, state),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM risk_acceptances WHERE org_id = ? ORDER BY submitted_at DESC",
                    (org_id,),
                ).fetchall()
            return [self._row_to_dict(r) for r in rows]
        finally:
            conn.close()

    def check_expired(self, org_id: str = "default") -> list:
        """Find and mark expired acceptances. Returns list of newly expired."""
        now = datetime.now(timezone.utc).isoformat()
        conn = self._get_connection()
        newly_expired = []
        try:
            rows = conn.execute(
                """SELECT * FROM risk_acceptances
                   WHERE org_id = ? AND state = 'approved' AND expires_at <= ?""",
                (org_id, now),
            ).fetchall()
            for row in rows:
                acceptance_id = row["acceptance_id"]
                conn.execute(
                    "UPDATE risk_acceptances SET state = 'expired' WHERE acceptance_id = ?",
                    (acceptance_id,),
                )
                self._append_audit(conn, acceptance_id, "expired", "system", "Acceptance period elapsed")
                newly_expired.append(self._row_to_dict(row))
            if newly_expired:
                conn.commit()
                _logger.info("risk_acceptances_expired", count=len(newly_expired), org_id=org_id)
        finally:
            conn.close()
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("RISK_ASSESSED", {"entity_type": "risk_acceptance", "org_id": org_id, "source_engine": "risk_acceptance"})
            except Exception:
                pass

        return newly_expired

    def get_metrics(self, org_id: str = "default") -> dict:
        """Return metrics summary for an org."""
        conn = self._get_connection()
        try:
            rows = conn.execute(
                "SELECT state, risk_level, COUNT(*) as cnt FROM risk_acceptances WHERE org_id = ? GROUP BY state, risk_level",
                (org_id,),
            ).fetchall()
            metrics: dict = {
                "total": 0,
                "pending": 0,
                "approved": 0,
                "rejected": 0,
                "expired": 0,
                "revoked": 0,
                "by_risk_level": {level: 0 for level in RISK_LEVELS},
            }
            for row in rows:
                state = row["state"]
                risk_level = row["risk_level"]
                cnt = row["cnt"]
                metrics["total"] += cnt
                if state == "pending_review":
                    metrics["pending"] += cnt
                elif state in metrics:
                    metrics[state] += cnt
                if risk_level in metrics["by_risk_level"]:
                    metrics["by_risk_level"][risk_level] += cnt
            return metrics
        finally:
            conn.close()

    def link_auto_waiver(
        self,
        org_id: str,
        acceptance_id: str,
        auto_waiver_exception_id: str,
    ) -> dict:
        """Link a risk acceptance record to its source auto-waiver exception for traceability."""
        conn = self._get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM risk_acceptances WHERE acceptance_id = ? AND org_id = ?",
                (acceptance_id, org_id),
            ).fetchone()
            if row is None:
                raise ValueError(
                    f"Acceptance '{acceptance_id}' not found for org '{org_id}'"
                )
            conn.execute(
                "UPDATE risk_acceptances SET auto_waiver_exception_id = ? WHERE acceptance_id = ? AND org_id = ?",
                (auto_waiver_exception_id, acceptance_id, org_id),
            )
            self._append_audit(
                conn,
                acceptance_id,
                "auto_waiver_linked",
                "system",
                f"linked to auto_waiver_exception_id={auto_waiver_exception_id}",
            )
            conn.commit()
        finally:
            conn.close()
        return self.get_acceptance(acceptance_id)  # type: ignore[return-value]

    def is_accepted(self, finding_id: str, org_id: str = "default") -> bool:
        """Check if finding currently has an active approval."""
        now = datetime.now(timezone.utc).isoformat()
        conn = self._get_connection()
        try:
            row = conn.execute(
                """SELECT acceptance_id FROM risk_acceptances
                   WHERE finding_id = ? AND org_id = ? AND state = 'approved' AND expires_at > ?
                   LIMIT 1""",
                (finding_id, org_id, now),
            ).fetchone()
            return row is not None
        finally:
            conn.close()
