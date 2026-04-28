"""Secrets rotation tracker — manage lifecycle of exposed secret remediation."""
from __future__ import annotations

import hashlib
import os
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

import structlog

_logger = structlog.get_logger(__name__)

ROTATION_STATES = ["pending", "in_progress", "rotated", "verified", "failed", "deferred"]
SECRET_TYPES = [
    "api_key", "password", "token", "certificate",
    "ssh_key", "database_credential", "oauth_secret",
]

# SLA hours by severity
_SLA_HOURS: dict[str, int] = {
    "critical": 4,
    "high": 24,
    "medium": 72,
    "low": 168,
}

# Valid state transitions
_VALID_TRANSITIONS: dict[str, list[str]] = {
    "pending":     ["in_progress", "deferred", "failed"],
    "in_progress": ["rotated", "failed", "deferred"],
    "rotated":     ["verified", "failed"],
    "verified":    [],
    "failed":      ["pending", "in_progress"],
    "deferred":    ["pending", "in_progress", "failed"],
}

_DB_ENV = "FIXOPS_DATA_DIR"
_DEFAULT_DB_DIR = ".fixops_data"
_THREAD_LOCAL = threading.local()


def _db_path(db_path: str) -> str:
    if os.path.isabs(db_path):
        return db_path
    data_dir = os.environ.get(_DB_ENV, _DEFAULT_DB_DIR)
    os.makedirs(data_dir, exist_ok=True)
    return os.path.join(data_dir, db_path)


class SecretsRotationTracker:
    def __init__(self, db_path: str = "secrets_rotation.db"):
        self._db_path = _db_path(db_path)
        self._local = threading.local()
        self._init_db()

    # ------------------------------------------------------------------
    # DB helpers
    # ------------------------------------------------------------------

    def _conn(self) -> sqlite3.Connection:
        if not getattr(self._local, "conn", None):
            conn = sqlite3.connect(self._db_path, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            self._local.conn = conn
        return self._local.conn

    def _init_db(self) -> None:
        conn = self._conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS rotations (
                rotation_id     TEXT PRIMARY KEY,
                org_id          TEXT NOT NULL DEFAULT 'default',
                secret_type     TEXT NOT NULL,
                exposed_location TEXT NOT NULL,
                detection_source TEXT NOT NULL DEFAULT 'scanner',
                severity        TEXT NOT NULL DEFAULT 'high',
                state           TEXT NOT NULL DEFAULT 'pending',
                sla_deadline    TEXT NOT NULL,
                assignee        TEXT,
                rotated_by      TEXT,
                new_secret_hash TEXT,
                verifier        TEXT,
                verify_notes    TEXT,
                fail_reason     TEXT,
                defer_reason    TEXT,
                defer_until     TEXT,
                created_at      TEXT NOT NULL,
                updated_at      TEXT NOT NULL,
                rotated_at      TEXT,
                verified_at     TEXT
            );
            CREATE TABLE IF NOT EXISTS rotation_audit (
                audit_id        TEXT PRIMARY KEY,
                rotation_id     TEXT NOT NULL,
                from_state      TEXT,
                to_state        TEXT NOT NULL,
                actor           TEXT,
                notes           TEXT,
                ts              TEXT NOT NULL,
                FOREIGN KEY (rotation_id) REFERENCES rotations(rotation_id)
            );
            CREATE INDEX IF NOT EXISTS idx_rot_org  ON rotations(org_id);
            CREATE INDEX IF NOT EXISTS idx_rot_state ON rotations(state);
            CREATE INDEX IF NOT EXISTS idx_audit_rid ON rotation_audit(rotation_id);
        """)
        conn.commit()

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _row_to_dict(self, row: sqlite3.Row) -> dict:
        return dict(row)

    def _get_raw(self, rotation_id: str) -> Optional[sqlite3.Row]:
        cur = self._conn().execute(
            "SELECT * FROM rotations WHERE rotation_id = ?", (rotation_id,)
        )
        return cur.fetchone()

    def _write_audit(self, rotation_id: str, from_state: Optional[str],
                     to_state: str, actor: Optional[str] = None, notes: str = "") -> None:
        self._conn().execute(
            """INSERT INTO rotation_audit
               (audit_id, rotation_id, from_state, to_state, actor, notes, ts)
               VALUES (?,?,?,?,?,?,?)""",
            (str(uuid.uuid4()), rotation_id, from_state, to_state, actor, notes, self._now()),
        )

    def _transition(self, rotation_id: str, to_state: str,
                    actor: Optional[str] = None, notes: str = "") -> dict:
        row = self._get_raw(rotation_id)
        if row is None:
            raise ValueError(f"Rotation {rotation_id!r} not found")
        current = row["state"]
        allowed = _VALID_TRANSITIONS.get(current, [])
        if to_state not in allowed:
            raise ValueError(
                f"Invalid transition: {current!r} -> {to_state!r}. "
                f"Allowed from {current!r}: {allowed}"
            )
        return current

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def register_exposure(
        self,
        secret_type: str,
        exposed_location: str,
        detection_source: str = "scanner",
        severity: str = "high",
        org_id: str = "default",
    ) -> dict:
        """Register an exposed secret for rotation tracking."""
        if secret_type not in SECRET_TYPES:
            raise ValueError(
                f"Invalid secret_type {secret_type!r}. Must be one of: {SECRET_TYPES}"
            )
        if severity not in _SLA_HOURS:
            severity = "high"

        rotation_id = str(uuid.uuid4())
        now = self._now()
        sla_hours = _SLA_HOURS[severity]
        deadline = (datetime.now(timezone.utc) + timedelta(hours=sla_hours)).isoformat()

        conn = self._conn()
        conn.execute(
            """INSERT INTO rotations
               (rotation_id, org_id, secret_type, exposed_location, detection_source,
                severity, state, sla_deadline, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (rotation_id, org_id, secret_type, exposed_location, detection_source,
             severity, "pending", deadline, now, now),
        )
        self._write_audit(rotation_id, None, "pending", notes="exposure registered")
        conn.commit()

        _logger.info(
            "secrets_rotation.registered",
            rotation_id=rotation_id, secret_type=secret_type,
            severity=severity, sla_deadline=deadline,
        )
        return self.get_rotation(rotation_id)

    def start_rotation(self, rotation_id: str, assignee: str) -> dict:
        """Mark rotation as in_progress."""
        from_state = self._transition(rotation_id, "in_progress", actor=assignee)
        now = self._now()
        conn = self._conn()
        conn.execute(
            "UPDATE rotations SET state='in_progress', assignee=?, updated_at=? WHERE rotation_id=?",
            (assignee, now, rotation_id),
        )
        self._write_audit(rotation_id, from_state, "in_progress", actor=assignee)
        conn.commit()
        return self.get_rotation(rotation_id)

    def confirm_rotation(
        self,
        rotation_id: str,
        rotated_by: str,
        new_secret_hash: Optional[str] = None,
    ) -> dict:
        """Confirm secret has been rotated. Stores hash of new secret (not value)."""
        from_state = self._transition(rotation_id, "rotated", actor=rotated_by)
        now = self._now()
        # If caller passed a raw value, hash it; if it looks like a hash already, store as-is
        stored_hash = new_secret_hash
        if new_secret_hash and len(new_secret_hash) not in (64, 128):
            stored_hash = hashlib.sha256(new_secret_hash.encode()).hexdigest()

        conn = self._conn()
        conn.execute(
            """UPDATE rotations SET state='rotated', rotated_by=?, new_secret_hash=?,
               rotated_at=?, updated_at=? WHERE rotation_id=?""",
            (rotated_by, stored_hash, now, now, rotation_id),
        )
        self._write_audit(rotation_id, from_state, "rotated", actor=rotated_by)
        conn.commit()
        return self.get_rotation(rotation_id)

    def verify_rotation(
        self, rotation_id: str, verifier: str, notes: str = ""
    ) -> dict:
        """Mark rotation as verified (scanner no longer detects old secret)."""
        from_state = self._transition(rotation_id, "verified", actor=verifier)
        now = self._now()
        conn = self._conn()
        conn.execute(
            """UPDATE rotations SET state='verified', verifier=?, verify_notes=?,
               verified_at=?, updated_at=? WHERE rotation_id=?""",
            (verifier, notes, now, now, rotation_id),
        )
        self._write_audit(rotation_id, from_state, "verified", actor=verifier, notes=notes)
        conn.commit()
        return self.get_rotation(rotation_id)

    def fail_rotation(self, rotation_id: str, reason: str) -> dict:
        """Mark rotation as failed."""
        from_state = self._transition(rotation_id, "failed")
        now = self._now()
        conn = self._conn()
        conn.execute(
            "UPDATE rotations SET state='failed', fail_reason=?, updated_at=? WHERE rotation_id=?",
            (reason, now, rotation_id),
        )
        self._write_audit(rotation_id, from_state, "failed", notes=reason)
        conn.commit()
        return self.get_rotation(rotation_id)

    def defer_rotation(
        self, rotation_id: str, reason: str, defer_until: str
    ) -> dict:
        """Defer rotation with justification."""
        from_state = self._transition(rotation_id, "deferred")
        now = self._now()
        conn = self._conn()
        conn.execute(
            """UPDATE rotations SET state='deferred', defer_reason=?, defer_until=?,
               updated_at=? WHERE rotation_id=?""",
            (reason, defer_until, now, rotation_id),
        )
        self._write_audit(rotation_id, from_state, "deferred",
                          notes=f"defer until {defer_until}: {reason}")
        conn.commit()
        return self.get_rotation(rotation_id)

    def get_rotation(self, rotation_id: str) -> Optional[dict]:
        row = self._get_raw(rotation_id)
        if row is None:
            return None
        return self._row_to_dict(row)

    def list_rotations(
        self,
        org_id: str = "default",
        state: Optional[str] = None,
        secret_type: Optional[str] = None,
    ) -> list[dict]:
        query = "SELECT * FROM rotations WHERE org_id = ?"
        params: list = [org_id]
        if state:
            query += " AND state = ?"
            params.append(state)
        if secret_type:
            query += " AND secret_type = ?"
            params.append(secret_type)
        query += " ORDER BY created_at DESC"
        cur = self._conn().execute(query, params)
        return [self._row_to_dict(r) for r in cur.fetchall()]

    def get_overdue(self, org_id: str = "default") -> list[dict]:
        """Find rotations past their SLA deadline that are still pending/in_progress."""
        now = self._now()
        cur = self._conn().execute(
            """SELECT * FROM rotations
               WHERE org_id = ? AND state IN ('pending','in_progress')
               AND sla_deadline < ?
               ORDER BY sla_deadline ASC""",
            (org_id, now),
        )
        return [self._row_to_dict(r) for r in cur.fetchall()]

    def get_metrics(self, org_id: str = "default") -> dict:
        """Return aggregated rotation metrics for the org."""
        rows = self.list_rotations(org_id=org_id)
        total = len(rows)

        by_state: dict[str, int] = {s: 0 for s in ROTATION_STATES}
        by_secret_type: dict[str, int] = {t: 0 for t in SECRET_TYPES}

        rotate_durations: list[float] = []
        for r in rows:
            state = r.get("state", "pending")
            if state in by_state:
                by_state[state] += 1
            stype = r.get("secret_type", "")
            if stype in by_secret_type:
                by_secret_type[stype] += 1
            # compute time_to_rotate for completed rotations
            if r.get("rotated_at") and r.get("created_at"):
                try:
                    created = datetime.fromisoformat(r["created_at"])
                    rotated = datetime.fromisoformat(r["rotated_at"])
                    hours = (rotated - created).total_seconds() / 3600
                    rotate_durations.append(hours)
                except Exception:
                    pass

        overdue_count = len(self.get_overdue(org_id=org_id))
        avg_hours = (
            sum(rotate_durations) / len(rotate_durations) if rotate_durations else 0.0
        )

        return {
            "total": total,
            "by_state": by_state,
            "overdue_count": overdue_count,
            "avg_time_to_rotate_hours": float(avg_hours),
            "by_secret_type": by_secret_type,
        }

    def get_audit_trail(self, rotation_id: str) -> list[dict]:
        """Get full state transition history for a rotation."""
        cur = self._conn().execute(
            "SELECT * FROM rotation_audit WHERE rotation_id = ? ORDER BY ts ASC",
            (rotation_id,),
        )
        return [dict(r) for r in cur.fetchall()]
