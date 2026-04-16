"""Privacy & GDPR Compliance Engine — ALDECI.

Manages GDPR/CCPA/PIPEDA/LGPD privacy compliance:
  - Data Subject Request (DSR) lifecycle with regulation-aware due dates
  - Consent record management with purpose tracking and withdrawal
  - Privacy incident reporting with DPA notification deadlines
  - Record of Processing Activities (RoPA) management
  - Privacy stats dashboard per org

Compliance: GDPR Art 12-22 (DSRs), Art 30 (RoPA), Art 33-34 (Breach Notification),
            CCPA §1798.100-199, PIPEDA, LGPD
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

_DEFAULT_DB_DIR = Path(__file__).resolve().parents[2] / ".fixops_data"

_VALID_REQUEST_TYPES = {
    "access", "erasure", "portability", "rectification", "restriction", "objection"
}
_VALID_DSR_STATUSES = {
    "received", "processing", "fulfilled", "rejected", "expired"
}
_VALID_REGULATIONS = {"gdpr", "ccpa", "pipeda", "lgpd"}
_VALID_PURPOSES = {
    "marketing", "analytics", "functional", "personalization", "third_party_sharing"
}
_VALID_CONSENT_SOURCES = {"website", "app", "call", "paper"}
_VALID_INCIDENT_TYPES = {
    "breach", "unauthorized_access", "accidental_disclosure", "third_party_breach"
}
_VALID_INCIDENT_SEVERITIES = {"critical", "high", "medium", "low"}
_VALID_INCIDENT_STATUSES = {"detected", "assessing", "notified", "resolved"}
_VALID_DATA_TYPES = {"email", "name", "ssn", "financial", "health", "biometric"}
_VALID_LEGAL_BASES = {
    "consent", "legitimate_interest", "contract", "legal_obligation",
    "vital_interests", "public_task"
}

# Due date windows in days by regulation
_DSR_DUE_DAYS: Dict[str, int] = {
    "gdpr": 30,
    "ccpa": 45,
    "pipeda": 30,
    "lgpd": 15,
}

# DPA notification threshold: breach severity requiring notification
_DPA_NOTIFICATION_HOURS = 72  # GDPR Art 33


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_iso(s: str) -> datetime:
    return datetime.fromisoformat(s)


class PrivacyGDPREngine:
    """SQLite WAL-backed Privacy & GDPR compliance engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    Each org uses its own database file.
    """

    def __init__(self, db_dir: Optional[str] = None) -> None:
        self._db_dir = Path(db_dir) if db_dir else _DEFAULT_DB_DIR
        self._db_dir.mkdir(parents=True, exist_ok=True)
        self._locks: Dict[str, threading.RLock] = {}
        self._locks_meta = threading.Lock()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _db_path(self, org_id: str) -> str:
        return str(self._db_dir / f"{org_id}_privacy_gdpr.db")

    def _lock(self, org_id: str) -> threading.RLock:
        with self._locks_meta:
            if org_id not in self._locks:
                self._locks[org_id] = threading.RLock()
            return self._locks[org_id]

    def _conn(self, org_id: str) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path(org_id), timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_org(self, org_id: str) -> None:
        with self._lock(org_id):
            with self._conn(org_id) as conn:
                conn.execute("PRAGMA journal_mode=WAL")
                conn.executescript("""
                    CREATE TABLE IF NOT EXISTS data_subject_requests (
                        id                  TEXT PRIMARY KEY,
                        org_id              TEXT NOT NULL,
                        request_type        TEXT NOT NULL,
                        subject_email       TEXT NOT NULL,
                        subject_name        TEXT NOT NULL DEFAULT '',
                        identity_verified   INTEGER NOT NULL DEFAULT 0,
                        status              TEXT NOT NULL DEFAULT 'received',
                        regulation          TEXT NOT NULL DEFAULT 'gdpr',
                        due_date            TEXT NOT NULL,
                        fulfilled_date      TEXT,
                        notes               TEXT NOT NULL DEFAULT '',
                        created_at          TEXT NOT NULL
                    );

                    CREATE INDEX IF NOT EXISTS idx_dsr_org_status
                        ON data_subject_requests (org_id, status);
                    CREATE INDEX IF NOT EXISTS idx_dsr_org_type
                        ON data_subject_requests (org_id, request_type);

                    CREATE TABLE IF NOT EXISTS consent_records (
                        id               TEXT PRIMARY KEY,
                        org_id           TEXT NOT NULL,
                        subject_email    TEXT NOT NULL,
                        purpose          TEXT NOT NULL,
                        consent_given    INTEGER NOT NULL DEFAULT 1,
                        consent_date     TEXT NOT NULL,
                        withdrawal_date  TEXT,
                        source           TEXT NOT NULL DEFAULT 'website',
                        version          TEXT NOT NULL DEFAULT '',
                        ip_address       TEXT NOT NULL DEFAULT '',
                        created_at       TEXT NOT NULL
                    );

                    CREATE INDEX IF NOT EXISTS idx_consent_org_email
                        ON consent_records (org_id, subject_email);
                    CREATE INDEX IF NOT EXISTS idx_consent_org_purpose
                        ON consent_records (org_id, purpose);

                    CREATE TABLE IF NOT EXISTS privacy_incidents (
                        id                      TEXT PRIMARY KEY,
                        org_id                  TEXT NOT NULL,
                        incident_type           TEXT NOT NULL,
                        severity                TEXT NOT NULL DEFAULT 'medium',
                        records_affected        INTEGER NOT NULL DEFAULT 0,
                        data_types_affected     TEXT NOT NULL DEFAULT '[]',
                        status                  TEXT NOT NULL DEFAULT 'detected',
                        dpa_notified            INTEGER NOT NULL DEFAULT 0,
                        notification_deadline   TEXT,
                        notification_sent_date  TEXT,
                        description             TEXT NOT NULL DEFAULT '',
                        created_at              TEXT NOT NULL
                    );

                    CREATE INDEX IF NOT EXISTS idx_incident_org_status
                        ON privacy_incidents (org_id, status);
                    CREATE INDEX IF NOT EXISTS idx_incident_org_severity
                        ON privacy_incidents (org_id, severity);

                    CREATE TABLE IF NOT EXISTS processing_activities (
                        id                      TEXT PRIMARY KEY,
                        org_id                  TEXT NOT NULL,
                        activity_name           TEXT NOT NULL,
                        purpose                 TEXT NOT NULL DEFAULT '',
                        legal_basis             TEXT NOT NULL DEFAULT 'consent',
                        data_categories         TEXT NOT NULL DEFAULT '[]',
                        data_subjects           TEXT NOT NULL DEFAULT '[]',
                        retention_period_days   INTEGER NOT NULL DEFAULT 365,
                        third_party_recipients  TEXT NOT NULL DEFAULT '[]',
                        international_transfers TEXT NOT NULL DEFAULT '[]',
                        dpiad_required          INTEGER NOT NULL DEFAULT 0,
                        created_at              TEXT NOT NULL
                    );

                    CREATE INDEX IF NOT EXISTS idx_proc_org
                        ON processing_activities (org_id);
                """)

    def _ensure_org(self, org_id: str) -> None:
        """Ensure org DB is initialised (idempotent)."""
        db = Path(self._db_path(org_id))
        if not db.exists():
            self._init_org(org_id)
        else:
            # ensure WAL and schema are applied
            self._init_org(org_id)

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        # Convert stored JSON strings back to lists
        for field in ("data_types_affected", "data_categories", "data_subjects",
                      "third_party_recipients", "international_transfers"):
            if field in d and isinstance(d[field], str):
                try:
                    d[field] = json.loads(d[field])
                except (json.JSONDecodeError, TypeError):
                    pass
        # Convert integer booleans
        for field in ("identity_verified", "consent_given", "dpa_notified", "dpiad_required"):
            if field in d:
                d[field] = bool(d[field])
        return d

    # ------------------------------------------------------------------
    # Data Subject Requests
    # ------------------------------------------------------------------

    def create_dsr(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a Data Subject Request. Sets regulation-aware due date."""
        self._ensure_org(org_id)

        request_type = data.get("request_type", "access")
        if request_type not in _VALID_REQUEST_TYPES:
            raise ValueError(f"Invalid request_type: {request_type}. Must be one of {_VALID_REQUEST_TYPES}")

        subject_email = (data.get("subject_email") or "").strip()
        if not subject_email:
            raise ValueError("subject_email is required.")

        regulation = data.get("regulation", "gdpr").lower()
        if regulation not in _VALID_REGULATIONS:
            raise ValueError(f"Invalid regulation: {regulation}. Must be one of {_VALID_REGULATIONS}")

        now = _now_iso()
        due_days = _DSR_DUE_DAYS.get(regulation, 30)
        due_date = (datetime.now(timezone.utc) + timedelta(days=due_days)).isoformat()

        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "request_type": request_type,
            "subject_email": subject_email,
            "subject_name": data.get("subject_name", ""),
            "identity_verified": 1 if data.get("identity_verified", False) else 0,
            "status": "received",
            "regulation": regulation,
            "due_date": due_date,
            "fulfilled_date": None,
            "notes": data.get("notes", ""),
            "created_at": now,
        }

        with self._lock(org_id):
            with self._conn(org_id) as conn:
                conn.execute(
                    """INSERT INTO data_subject_requests
                       (id, org_id, request_type, subject_email, subject_name,
                        identity_verified, status, regulation, due_date,
                        fulfilled_date, notes, created_at)
                       VALUES (:id, :org_id, :request_type, :subject_email, :subject_name,
                               :identity_verified, :status, :regulation, :due_date,
                               :fulfilled_date, :notes, :created_at)""",
                    record,
                )

        record["identity_verified"] = bool(record["identity_verified"])
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("CONTROL_ASSESSED", {"entity_type": "privacy_gdpr", "org_id": org_id, "source_engine": "privacy_gdpr"})
            except Exception:
                pass

        return record

    def list_dsrs(
        self,
        org_id: str,
        status: Optional[str] = None,
        request_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List DSRs with optional filters. Adds overdue flag."""
        self._ensure_org(org_id)
        sql = "SELECT * FROM data_subject_requests WHERE org_id = ?"
        params: list = [org_id]
        if status:
            sql += " AND status = ?"
            params.append(status)
        if request_type:
            sql += " AND request_type = ?"
            params.append(request_type)
        sql += " ORDER BY created_at DESC"

        now = _now_iso()
        with self._conn(org_id) as conn:
            rows = [self._row(r) for r in conn.execute(sql, params).fetchall()]

        for r in rows:
            due = r.get("due_date")
            r["overdue"] = (
                due is not None
                and r.get("status") not in ("fulfilled", "rejected", "expired")
                and due < now
            )
        return rows

    def fulfill_dsr(self, org_id: str, request_id: str, notes: str = "") -> bool:
        """Mark a DSR as fulfilled. Returns True if found."""
        self._ensure_org(org_id)
        now = _now_iso()
        with self._lock(org_id):
            with self._conn(org_id) as conn:
                cur = conn.execute(
                    """UPDATE data_subject_requests
                       SET status = 'fulfilled', fulfilled_date = ?, notes = ?
                       WHERE org_id = ? AND id = ?""",
                    (now, notes, org_id, request_id),
                )
                return cur.rowcount > 0

    def update_dsr_status(self, org_id: str, request_id: str, status: str) -> bool:
        """Update DSR status. Returns True if found."""
        if status not in _VALID_DSR_STATUSES:
            raise ValueError(f"Invalid status: {status}. Must be one of {_VALID_DSR_STATUSES}")
        self._ensure_org(org_id)
        with self._lock(org_id):
            with self._conn(org_id) as conn:
                cur = conn.execute(
                    "UPDATE data_subject_requests SET status = ? WHERE org_id = ? AND id = ?",
                    (status, org_id, request_id),
                )
                return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Consent Records
    # ------------------------------------------------------------------

    def record_consent(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Save a consent record."""
        self._ensure_org(org_id)

        subject_email = (data.get("subject_email") or "").strip()
        if not subject_email:
            raise ValueError("subject_email is required.")

        purpose = data.get("purpose", "functional")
        if purpose not in _VALID_PURPOSES:
            raise ValueError(f"Invalid purpose: {purpose}. Must be one of {_VALID_PURPOSES}")

        source = data.get("source", "website")
        if source not in _VALID_CONSENT_SOURCES:
            raise ValueError(f"Invalid source: {source}. Must be one of {_VALID_CONSENT_SOURCES}")

        now = _now_iso()
        consent_given = data.get("consent_given", True)
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "subject_email": subject_email,
            "purpose": purpose,
            "consent_given": 1 if consent_given else 0,
            "consent_date": data.get("consent_date", now),
            "withdrawal_date": None,
            "source": source,
            "version": data.get("version", ""),
            "ip_address": data.get("ip_address", ""),
            "created_at": now,
        }

        with self._lock(org_id):
            with self._conn(org_id) as conn:
                conn.execute(
                    """INSERT INTO consent_records
                       (id, org_id, subject_email, purpose, consent_given,
                        consent_date, withdrawal_date, source, version, ip_address, created_at)
                       VALUES (:id, :org_id, :subject_email, :purpose, :consent_given,
                               :consent_date, :withdrawal_date, :source, :version,
                               :ip_address, :created_at)""",
                    record,
                )

        record["consent_given"] = bool(record["consent_given"])
        return record

    def list_consents(
        self,
        org_id: str,
        subject_email: Optional[str] = None,
        purpose: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List consent records with optional filters."""
        self._ensure_org(org_id)
        sql = "SELECT * FROM consent_records WHERE org_id = ?"
        params: list = [org_id]
        if subject_email:
            sql += " AND subject_email = ?"
            params.append(subject_email)
        if purpose:
            sql += " AND purpose = ?"
            params.append(purpose)
        sql += " ORDER BY created_at DESC"
        with self._conn(org_id) as conn:
            return [self._row(r) for r in conn.execute(sql, params).fetchall()]

    def withdraw_consent(self, org_id: str, consent_id: str) -> bool:
        """Mark consent as withdrawn. Returns True if found."""
        self._ensure_org(org_id)
        now = _now_iso()
        with self._lock(org_id):
            with self._conn(org_id) as conn:
                cur = conn.execute(
                    """UPDATE consent_records
                       SET consent_given = 0, withdrawal_date = ?
                       WHERE org_id = ? AND id = ?""",
                    (now, org_id, consent_id),
                )
                return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Privacy Incidents
    # ------------------------------------------------------------------

    def report_incident(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a privacy incident record.

        Sets notification_deadline to 72h from creation for GDPR breaches
        where records_affected > 250 (or any critical/high severity breach).
        """
        self._ensure_org(org_id)

        incident_type = data.get("incident_type", "breach")
        if incident_type not in _VALID_INCIDENT_TYPES:
            raise ValueError(f"Invalid incident_type: {incident_type}. Must be one of {_VALID_INCIDENT_TYPES}")

        severity = data.get("severity", "medium")
        if severity not in _VALID_INCIDENT_SEVERITIES:
            raise ValueError(f"Invalid severity: {severity}. Must be one of {_VALID_INCIDENT_SEVERITIES}")

        records_affected = int(data.get("records_affected", 0))
        data_types = data.get("data_types_affected", [])
        if isinstance(data_types, str):
            try:
                data_types = json.loads(data_types)
            except json.JSONDecodeError:
                data_types = [data_types]

        now_dt = datetime.now(timezone.utc)
        now = now_dt.isoformat()

        # Set DPA notification deadline for breaches requiring notification
        notification_deadline = None
        requires_notification = (
            incident_type == "breach"
            and (records_affected > 250 or severity in ("critical", "high"))
        )
        if requires_notification:
            deadline_dt = now_dt + timedelta(hours=_DPA_NOTIFICATION_HOURS)
            notification_deadline = deadline_dt.isoformat()

        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "incident_type": incident_type,
            "severity": severity,
            "records_affected": records_affected,
            "data_types_affected": json.dumps(data_types),
            "status": "detected",
            "dpa_notified": 0,
            "notification_deadline": notification_deadline,
            "notification_sent_date": None,
            "description": data.get("description", ""),
            "created_at": now,
        }

        with self._lock(org_id):
            with self._conn(org_id) as conn:
                conn.execute(
                    """INSERT INTO privacy_incidents
                       (id, org_id, incident_type, severity, records_affected,
                        data_types_affected, status, dpa_notified, notification_deadline,
                        notification_sent_date, description, created_at)
                       VALUES (:id, :org_id, :incident_type, :severity, :records_affected,
                               :data_types_affected, :status, :dpa_notified,
                               :notification_deadline, :notification_sent_date,
                               :description, :created_at)""",
                    record,
                )

        record["data_types_affected"] = data_types
        record["dpa_notified"] = False
        return record

    def list_incidents(
        self,
        org_id: str,
        status: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List privacy incidents with optional filters."""
        self._ensure_org(org_id)
        sql = "SELECT * FROM privacy_incidents WHERE org_id = ?"
        params: list = [org_id]
        if status:
            sql += " AND status = ?"
            params.append(status)
        if severity:
            sql += " AND severity = ?"
            params.append(severity)
        sql += " ORDER BY created_at DESC"
        with self._conn(org_id) as conn:
            return [self._row(r) for r in conn.execute(sql, params).fetchall()]

    def notify_dpa(self, org_id: str, incident_id: str) -> bool:
        """Mark DPA as notified for an incident. Returns True if found."""
        self._ensure_org(org_id)
        now = _now_iso()
        with self._lock(org_id):
            with self._conn(org_id) as conn:
                cur = conn.execute(
                    """UPDATE privacy_incidents
                       SET dpa_notified = 1, notification_sent_date = ?, status = 'notified'
                       WHERE org_id = ? AND id = ?""",
                    (now, org_id, incident_id),
                )
                return cur.rowcount > 0

    def update_incident_status(self, org_id: str, incident_id: str, status: str) -> bool:
        """Update incident status. Returns True if found."""
        if status not in _VALID_INCIDENT_STATUSES:
            raise ValueError(f"Invalid status: {status}. Must be one of {_VALID_INCIDENT_STATUSES}")
        self._ensure_org(org_id)
        with self._lock(org_id):
            with self._conn(org_id) as conn:
                cur = conn.execute(
                    "UPDATE privacy_incidents SET status = ? WHERE org_id = ? AND id = ?",
                    (status, org_id, incident_id),
                )
                return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Processing Activities (RoPA)
    # ------------------------------------------------------------------

    def add_processing_activity(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a processing activity (RoPA record — GDPR Art 30)."""
        self._ensure_org(org_id)

        activity_name = (data.get("activity_name") or "").strip()
        if not activity_name:
            raise ValueError("activity_name is required.")

        legal_basis = data.get("legal_basis", "consent")
        if legal_basis not in _VALID_LEGAL_BASES:
            raise ValueError(f"Invalid legal_basis: {legal_basis}. Must be one of {_VALID_LEGAL_BASES}")

        def _to_json(v: Any) -> str:
            if isinstance(v, list):
                return json.dumps(v)
            if isinstance(v, str):
                try:
                    json.loads(v)
                    return v
                except json.JSONDecodeError:
                    return json.dumps([v])
            return json.dumps([])

        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "activity_name": activity_name,
            "purpose": data.get("purpose", ""),
            "legal_basis": legal_basis,
            "data_categories": _to_json(data.get("data_categories", [])),
            "data_subjects": _to_json(data.get("data_subjects", [])),
            "retention_period_days": int(data.get("retention_period_days", 365)),
            "third_party_recipients": _to_json(data.get("third_party_recipients", [])),
            "international_transfers": _to_json(data.get("international_transfers", [])),
            "dpiad_required": 1 if data.get("dpiad_required", False) else 0,
            "created_at": now,
        }

        with self._lock(org_id):
            with self._conn(org_id) as conn:
                conn.execute(
                    """INSERT INTO processing_activities
                       (id, org_id, activity_name, purpose, legal_basis, data_categories,
                        data_subjects, retention_period_days, third_party_recipients,
                        international_transfers, dpiad_required, created_at)
                       VALUES (:id, :org_id, :activity_name, :purpose, :legal_basis,
                               :data_categories, :data_subjects, :retention_period_days,
                               :third_party_recipients, :international_transfers,
                               :dpiad_required, :created_at)""",
                    record,
                )

        return self._row_from_dict(record)

    @staticmethod
    def _row_from_dict(d: Dict[str, Any]) -> Dict[str, Any]:
        """Convert raw insert dict to API-friendly dict."""
        result = dict(d)
        for field in ("data_categories", "data_subjects",
                      "third_party_recipients", "international_transfers"):
            if field in result and isinstance(result[field], str):
                try:
                    result[field] = json.loads(result[field])
                except (json.JSONDecodeError, TypeError):
                    pass
        for field in ("dpiad_required",):
            if field in result:
                result[field] = bool(result[field])
        return result

    def list_processing_activities(self, org_id: str) -> List[Dict[str, Any]]:
        """List all processing activities (RoPA) for org."""
        self._ensure_org(org_id)
        with self._conn(org_id) as conn:
            rows = conn.execute(
                "SELECT * FROM processing_activities WHERE org_id = ? ORDER BY created_at DESC",
                (org_id,),
            ).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_privacy_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated privacy stats for org."""
        self._ensure_org(org_id)
        now = _now_iso()

        with self._conn(org_id) as conn:
            total_dsrs = conn.execute(
                "SELECT COUNT(*) FROM data_subject_requests WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            by_status_rows = conn.execute(
                """SELECT status, COUNT(*) as cnt
                   FROM data_subject_requests WHERE org_id = ?
                   GROUP BY status""",
                (org_id,),
            ).fetchall()
            by_status = {r["status"]: r["cnt"] for r in by_status_rows}

            overdue_dsrs = conn.execute(
                """SELECT COUNT(*) FROM data_subject_requests
                   WHERE org_id = ? AND status NOT IN ('fulfilled','rejected','expired')
                   AND due_date < ?""",
                (org_id, now),
            ).fetchone()[0]

            total_consents = conn.execute(
                "SELECT COUNT(*) FROM consent_records WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            active_consents = conn.execute(
                """SELECT COUNT(*) FROM consent_records
                   WHERE org_id = ? AND consent_given = 1 AND withdrawal_date IS NULL""",
                (org_id,),
            ).fetchone()[0]

            total_incidents = conn.execute(
                "SELECT COUNT(*) FROM privacy_incidents WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            incidents_requiring_notification = conn.execute(
                """SELECT COUNT(*) FROM privacy_incidents
                   WHERE org_id = ? AND notification_deadline IS NOT NULL
                   AND dpa_notified = 0""",
                (org_id,),
            ).fetchone()[0]

            processing_activities = conn.execute(
                "SELECT COUNT(*) FROM processing_activities WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            # Data types inventory from processing activities
            activity_rows = conn.execute(
                "SELECT data_categories FROM processing_activities WHERE org_id = ?",
                (org_id,),
            ).fetchall()
            data_types_set: set = set()
            for row in activity_rows:
                try:
                    cats = json.loads(row["data_categories"])
                    if isinstance(cats, list):
                        data_types_set.update(cats)
                except (json.JSONDecodeError, TypeError):
                    pass

        return {
            "total_dsrs": total_dsrs,
            "by_status": by_status,
            "overdue_dsrs": overdue_dsrs,
            "total_consents": total_consents,
            "active_consents": active_consents,
            "total_incidents": total_incidents,
            "incidents_requiring_notification": incidents_requiring_notification,
            "processing_activities": processing_activities,
            "data_types_inventory": sorted(data_types_set),
        }
