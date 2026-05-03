"""Ransomware Protection Engine — ALDECI.

Tracks ransomware detection patterns, backup validation,
and containment playbook execution.

Capabilities:
  - Detection registration: behavioral, signature, honeypot, heuristic, network, endpoint
  - Containment lifecycle: none → in_progress → contained → eradicated
  - Backup validation: full/incremental/differential/snapshot/cloud with immutable+encrypted flags
  - Playbook execution with execution_count tracking
  - Protection status: active detections, valid backups, unprotected systems
  - Unvalidated backups: unknown/invalid or not validated in 30 days

Compliance: NIST CSF RS.MI-2, ISO 27001 A.8.7 (Malware protection)
"""

from __future__ import annotations

import json
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

_DEFAULT_DB_DIR = str(
    Path(__file__).resolve().parents[2] / ".fixops_data"
)

_VALID_DETECTION_TYPES = {
    "behavioral", "signature", "honeypot", "heuristic", "network", "endpoint",
}

_VALID_CONTAINMENT_STATUSES = {
    "none", "in_progress", "contained", "eradicated",
}

_VALID_BACKUP_TYPES = {
    "full", "incremental", "differential", "snapshot", "cloud",
}

_VALID_TRIGGER_TYPES = {
    "automatic", "manual", "threshold", "scheduled",
}

_VALID_VALIDATION_STATUSES = {
    "valid", "invalid", "partial", "unknown",
}

_VALID_EXTORTION_MODELS = {
    "double", "triple", "quadruple", "single", "ddos", "data_only",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class RansomwareProtectionEngine:
    """SQLite WAL-backed Ransomware Protection engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/ransomware_protection.db
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path is None:
            db_path = str(Path(_DEFAULT_DB_DIR) / "ransomware_protection.db")
        self._db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS ransomware_detections (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    detection_name      TEXT NOT NULL,
                    detection_type      TEXT NOT NULL DEFAULT 'behavioral',
                    affected_systems    TEXT NOT NULL DEFAULT '[]',
                    file_extensions     TEXT NOT NULL DEFAULT '[]',
                    confidence          REAL NOT NULL DEFAULT 0.5,
                    severity            TEXT NOT NULL DEFAULT 'high',
                    status              TEXT NOT NULL DEFAULT 'active',
                    containment_status  TEXT NOT NULL DEFAULT 'none',
                    detected_at         TEXT NOT NULL,
                    contained_at        TEXT,
                    created_at          TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_rd_org
                    ON ransomware_detections (org_id, status, containment_status, severity);

                CREATE TABLE IF NOT EXISTS backup_validations (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    system_name         TEXT NOT NULL,
                    backup_type         TEXT NOT NULL DEFAULT 'full',
                    backup_location     TEXT NOT NULL DEFAULT '',
                    last_validated      TEXT,
                    validation_status   TEXT NOT NULL DEFAULT 'unknown',
                    recovery_time_mins  INTEGER NOT NULL DEFAULT 0,
                    immutable           INTEGER NOT NULL DEFAULT 0,
                    encrypted           INTEGER NOT NULL DEFAULT 0,
                    retention_days      INTEGER NOT NULL DEFAULT 30,
                    created_at          TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_bv_org
                    ON backup_validations (org_id, system_name, validation_status);

                CREATE TABLE IF NOT EXISTS containment_playbooks (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    playbook_name   TEXT NOT NULL,
                    trigger_type    TEXT NOT NULL DEFAULT 'manual',
                    steps           TEXT NOT NULL DEFAULT '[]',
                    estimated_mins  INTEGER NOT NULL DEFAULT 60,
                    execution_count INTEGER NOT NULL DEFAULT 0,
                    last_executed   TEXT,
                    created_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_cp_org
                    ON containment_playbooks (org_id, trigger_type);

                CREATE TABLE IF NOT EXISTS raas_groups (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    group_name          TEXT NOT NULL,
                    aliases             TEXT NOT NULL DEFAULT '[]',
                    active_since        TEXT,
                    extortion_model     TEXT NOT NULL DEFAULT 'double',
                    avg_ransom_usd      INTEGER NOT NULL DEFAULT 0,
                    known_sectors       TEXT NOT NULL DEFAULT '[]',
                    active              INTEGER NOT NULL DEFAULT 1,
                    created_at          TEXT NOT NULL,
                    updated_at          TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_rg_org
                    ON raas_groups (org_id, active, extortion_model);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Detection methods
    # ------------------------------------------------------------------

    def register_detection(
        self,
        org_id: str,
        detection_name: str,
        detection_type: str = "behavioral",
        affected_systems: Optional[List[str]] = None,
        file_extensions: Optional[List[str]] = None,
        confidence: float = 0.5,
        severity: str = "high",
    ) -> Dict[str, Any]:
        """Register a new ransomware detection."""
        if detection_type not in _VALID_DETECTION_TYPES:
            raise ValueError(f"Invalid detection_type: {detection_type}")
        confidence = max(0.0, min(1.0, confidence))
        now = _now_iso()
        rec_id = str(uuid.uuid4())
        systems_json = json.dumps(affected_systems or [])
        extensions_json = json.dumps(file_extensions or [])
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO ransomware_detections
                        (id, org_id, detection_name, detection_type, affected_systems,
                         file_extensions, confidence, severity, status, containment_status,
                         detected_at, contained_at, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', 'none', ?, NULL, ?)
                    """,
                    (rec_id, org_id, detection_name, detection_type, systems_json,
                     extensions_json, confidence, severity, now, now),
                )
        if _get_tg_bus:
            try:
                bus = _get_tg_bus()
                if bus:
                    bus.emit("THREAT_DETECTED", {"entity_type": "ransomware_detection", "entity_id": str(rec_id), "org_id": org_id, "source_engine": "ransomware_protection_engine"})
            except Exception:
                pass  # Event emission should never break the main operation
        return self.get_detection(rec_id, org_id)

    def get_detection(self, detection_id: str, org_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM ransomware_detections WHERE id=? AND org_id=?",
                    (detection_id, org_id),
                ).fetchone()
        if row is None:
            return None
        return self._row_to_dict(row)

    def update_containment(
        self,
        detection_id: str,
        org_id: str,
        containment_status: str,
    ) -> Dict[str, Any]:
        """Update containment status; set contained_at if status=contained."""
        if containment_status not in _VALID_CONTAINMENT_STATUSES:
            raise ValueError(f"Invalid containment_status: {containment_status}")
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT id FROM ransomware_detections WHERE id=? AND org_id=?",
                    (detection_id, org_id),
                ).fetchone()
                if row is None:
                    raise ValueError(f"Detection {detection_id} not found")
                if containment_status == "contained":
                    conn.execute(
                        """
                        UPDATE ransomware_detections
                        SET containment_status=?, contained_at=?, status='contained'
                        WHERE id=? AND org_id=?
                        """,
                        (containment_status, now, detection_id, org_id),
                    )
                else:
                    conn.execute(
                        """
                        UPDATE ransomware_detections
                        SET containment_status=?
                        WHERE id=? AND org_id=?
                        """,
                        (containment_status, detection_id, org_id),
                    )
            return self.get_detection(detection_id, org_id)

    def list_detections(
        self, org_id: str, status: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        with self._lock:
            with self._conn() as conn:
                if status:
                    rows = conn.execute(
                        "SELECT * FROM ransomware_detections WHERE org_id=? AND status=? ORDER BY detected_at DESC",
                        (org_id, status),
                    ).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT * FROM ransomware_detections WHERE org_id=? ORDER BY detected_at DESC",
                        (org_id,),
                    ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Backup methods
    # ------------------------------------------------------------------

    def register_backup(
        self,
        org_id: str,
        system_name: str,
        backup_type: str = "full",
        backup_location: str = "",
        immutable: bool = False,
        encrypted: bool = False,
        retention_days: int = 30,
    ) -> Dict[str, Any]:
        """Register a backup target."""
        if backup_type not in _VALID_BACKUP_TYPES:
            raise ValueError(f"Invalid backup_type: {backup_type}")
        now = _now_iso()
        rec_id = str(uuid.uuid4())
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO backup_validations
                        (id, org_id, system_name, backup_type, backup_location,
                         last_validated, validation_status, recovery_time_mins,
                         immutable, encrypted, retention_days, created_at)
                    VALUES (?, ?, ?, ?, ?, NULL, 'unknown', 0, ?, ?, ?, ?)
                    """,
                    (rec_id, org_id, system_name, backup_type, backup_location,
                     1 if immutable else 0, 1 if encrypted else 0, retention_days, now),
                )
            return self.get_backup(rec_id, org_id)

    def get_backup(self, backup_id: str, org_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM backup_validations WHERE id=? AND org_id=?",
                    (backup_id, org_id),
                ).fetchone()
        if row is None:
            return None
        return dict(row)

    def validate_backup(
        self,
        backup_id: str,
        org_id: str,
        validation_status: str,
        recovery_time_mins: int = 0,
    ) -> Dict[str, Any]:
        """Record backup validation result."""
        if validation_status not in _VALID_VALIDATION_STATUSES:
            raise ValueError(f"Invalid validation_status: {validation_status}")
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT id FROM backup_validations WHERE id=? AND org_id=?",
                    (backup_id, org_id),
                ).fetchone()
                if row is None:
                    raise ValueError(f"Backup {backup_id} not found")
                conn.execute(
                    """
                    UPDATE backup_validations
                    SET last_validated=?, validation_status=?, recovery_time_mins=?
                    WHERE id=? AND org_id=?
                    """,
                    (now, validation_status, recovery_time_mins, backup_id, org_id),
                )
            return self.get_backup(backup_id, org_id)

    def get_unvalidated_backups(self, org_id: str) -> List[Dict[str, Any]]:
        """Backups with unknown/invalid status or not validated in 30 days."""
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    """
                    SELECT * FROM backup_validations
                    WHERE org_id=?
                      AND (
                          validation_status IN ('unknown', 'invalid')
                          OR last_validated IS NULL
                          OR julianday('now') - julianday(last_validated) > 30
                      )
                    ORDER BY system_name
                    """,
                    (org_id,),
                ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Playbook methods
    # ------------------------------------------------------------------

    def create_playbook(
        self,
        org_id: str,
        playbook_name: str,
        trigger_type: str = "manual",
        steps: Optional[List[Any]] = None,
        estimated_mins: int = 60,
    ) -> Dict[str, Any]:
        """Create a containment playbook."""
        if trigger_type not in _VALID_TRIGGER_TYPES:
            raise ValueError(f"Invalid trigger_type: {trigger_type}")
        now = _now_iso()
        rec_id = str(uuid.uuid4())
        steps_json = json.dumps(steps or [])
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO containment_playbooks
                        (id, org_id, playbook_name, trigger_type, steps,
                         estimated_mins, execution_count, last_executed, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, 0, NULL, ?)
                    """,
                    (rec_id, org_id, playbook_name, trigger_type, steps_json,
                     estimated_mins, now),
                )
            return self._get_playbook(rec_id, org_id)

    def _get_playbook(self, playbook_id: str, org_id: str) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM containment_playbooks WHERE id=? AND org_id=?",
                (playbook_id, org_id),
            ).fetchone()
        if row is None:
            return None
        d = dict(row)
        d["steps"] = json.loads(d.get("steps", "[]"))
        return d

    def execute_playbook(self, playbook_id: str, org_id: str) -> Dict[str, Any]:
        """Increment execution_count and record last_executed."""
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT id FROM containment_playbooks WHERE id=? AND org_id=?",
                    (playbook_id, org_id),
                ).fetchone()
                if row is None:
                    raise ValueError(f"Playbook {playbook_id} not found")
                conn.execute(
                    """
                    UPDATE containment_playbooks
                    SET execution_count = execution_count + 1, last_executed=?
                    WHERE id=? AND org_id=?
                    """,
                    (now, playbook_id, org_id),
                )
            return self._get_playbook(playbook_id, org_id)

    # ------------------------------------------------------------------
    # Status / summary
    # ------------------------------------------------------------------

    def get_protection_status(self, org_id: str) -> Dict[str, Any]:
        """Aggregate protection status metrics."""
        with self._lock:
            with self._conn() as conn:
                det_row = conn.execute(
                    """
                    SELECT
                        COUNT(*) FILTER (WHERE status='active') AS active_detections,
                        COUNT(*) FILTER (WHERE status='contained') AS contained_detections
                    FROM ransomware_detections WHERE org_id=?
                    """,
                    (org_id,),
                ).fetchone()
                bak_row = conn.execute(
                    """
                    SELECT
                        COUNT(*) FILTER (WHERE validation_status='valid') AS valid_backups,
                        COUNT(*) FILTER (WHERE validation_status='invalid') AS invalid_backups,
                        COUNT(*) FILTER (WHERE immutable=1) AS immutable_backups,
                        COUNT(DISTINCT system_name) AS systems_with_backups
                    FROM backup_validations WHERE org_id=?
                    """,
                    (org_id,),
                ).fetchone()

                # Unprotected: active detections whose affected_systems have no valid backup
                active_rows = conn.execute(
                    "SELECT affected_systems FROM ransomware_detections WHERE org_id=? AND status='active'",
                    (org_id,),
                ).fetchall()
                valid_systems = {
                    r[0] for r in conn.execute(
                        "SELECT system_name FROM backup_validations WHERE org_id=? AND validation_status='valid'",
                        (org_id,),
                    ).fetchall()
                }

        unprotected = 0
        for arow in active_rows:
            systems = json.loads(arow[0] or "[]")
            for sys in systems:
                if sys not in valid_systems:
                    unprotected += 1
                    break

        return {
            "active_detections": det_row["active_detections"],
            "contained_detections": det_row["contained_detections"],
            "valid_backups": bak_row["valid_backups"],
            "invalid_backups": bak_row["invalid_backups"],
            "immutable_backups": bak_row["immutable_backups"],
            "systems_with_backups": bak_row["systems_with_backups"],
            "unprotected_systems": unprotected,
        }

    def get_summary(self, org_id: str) -> Dict[str, Any]:
        """Summary of detections, backup coverage, and recovery time."""
        with self._lock:
            with self._conn() as conn:
                det_rows = conn.execute(
                    "SELECT status, severity FROM ransomware_detections WHERE org_id=?",
                    (org_id,),
                ).fetchall()
                bak_stats = conn.execute(
                    """
                    SELECT
                        COUNT(*) AS total_backups,
                        COUNT(*) FILTER (WHERE validation_status='valid') AS valid_backups,
                        AVG(recovery_time_mins) AS avg_recovery
                    FROM backup_validations WHERE org_id=?
                    """,
                    (org_id,),
                ).fetchone()

        by_status: Dict[str, int] = {}
        by_severity: Dict[str, int] = {}
        for row in det_rows:
            by_status[row["status"]] = by_status.get(row["status"], 0) + 1
            by_severity[row["severity"]] = by_severity.get(row["severity"], 0) + 1

        total_backups = bak_stats["total_backups"] or 0
        valid_backups = bak_stats["valid_backups"] or 0
        backup_coverage_pct = valid_backups / max(1, total_backups) * 100

        return {
            "total_detections": len(det_rows),
            "by_status": by_status,
            "by_severity": by_severity,
            "backup_coverage_pct": round(backup_coverage_pct, 2),
            "avg_recovery_time_mins": round(bak_stats["avg_recovery"] or 0, 2),
        }

    # ------------------------------------------------------------------
    # RaaS group methods
    # ------------------------------------------------------------------

    def register_raas_group(
        self,
        org_id: str,
        group_name: str,
        aliases: Optional[List[str]] = None,
        active_since: Optional[str] = None,
        extortion_model: str = "double",
        avg_ransom_usd: int = 0,
        known_sectors: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Register a RaaS threat actor group with extortion intel."""
        if extortion_model not in _VALID_EXTORTION_MODELS:
            raise ValueError(f"Invalid extortion_model: {extortion_model}")
        now = _now_iso()
        rec_id = str(uuid.uuid4())
        aliases_json = json.dumps(aliases or [])
        sectors_json = json.dumps(known_sectors or [])
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO raas_groups
                        (id, org_id, group_name, aliases, active_since,
                         extortion_model, avg_ransom_usd, known_sectors,
                         active, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
                    """,
                    (rec_id, org_id, group_name, aliases_json, active_since,
                     extortion_model, avg_ransom_usd, sectors_json, now, now),
                )
        return self.get_raas_group(rec_id, org_id)

    def get_raas_group(self, group_id: str, org_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM raas_groups WHERE id=? AND org_id=?",
                    (group_id, org_id),
                ).fetchone()
        if row is None:
            return None
        return self._raas_row_to_dict(row)

    def list_raas_groups(
        self, org_id: str, active_only: bool = True
    ) -> List[Dict[str, Any]]:
        """List RaaS groups for an org, optionally filtering to active ones."""
        with self._lock:
            with self._conn() as conn:
                if active_only:
                    rows = conn.execute(
                        "SELECT * FROM raas_groups WHERE org_id=? AND active=1 ORDER BY group_name",
                        (org_id,),
                    ).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT * FROM raas_groups WHERE org_id=? ORDER BY group_name",
                        (org_id,),
                    ).fetchall()
        return [self._raas_row_to_dict(r) for r in rows]

    def deactivate_raas_group(self, group_id: str, org_id: str) -> Dict[str, Any]:
        """Mark a RaaS group as no longer active."""
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT id FROM raas_groups WHERE id=? AND org_id=?",
                    (group_id, org_id),
                ).fetchone()
                if row is None:
                    raise ValueError(f"RaaS group {group_id} not found")
                conn.execute(
                    "UPDATE raas_groups SET active=0, updated_at=? WHERE id=? AND org_id=?",
                    (now, group_id, org_id),
                )
        return self.get_raas_group(group_id, org_id)

    @staticmethod
    def _raas_row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        for field in ("aliases", "known_sectors"):
            if field in d and isinstance(d[field], str):
                try:
                    d[field] = json.loads(d[field])
                except (json.JSONDecodeError, TypeError):
                    d[field] = []
        d["active"] = bool(d.get("active", 1))
        return d

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        for field in ("affected_systems", "file_extensions"):
            if field in d and isinstance(d[field], str):
                try:
                    d[field] = json.loads(d[field])
                except (json.JSONDecodeError, TypeError):
                    d[field] = []
        return d
