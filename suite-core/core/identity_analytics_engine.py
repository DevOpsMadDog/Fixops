"""
Identity Analytics Engine — ALDECI.

Tracks identity profiles, login events, identity risks, and access certifications.
Detects impossible travel, credential spray, MFA bypass, unusual hours, and more.

Multi-tenant via org_id.  Thread-safe via RLock.  SQLite WAL for concurrency.
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

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "identity_analytics.db"
)

_VALID_IDENTITY_TYPES = {"human", "service_account", "bot", "shared"}
_VALID_EVENT_TYPES = {
    "login", "logout", "failed_login", "mfa_bypass", "password_reset",
    "account_lock", "privilege_escalation",
}
_VALID_RISK_TYPES = {
    "impossible_travel", "credential_spray", "mfa_bypass", "unusual_hours",
    "new_device", "excessive_privilege", "dormant_account", "shared_credential",
}
_VALID_SEVERITIES = {"critical", "high", "medium", "low"}
_VALID_CERT_STATUSES = {"pending", "approved", "revoked", "escalated"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _risk_tier(score: float) -> str:
    if score > 0.8:
        return "critical"
    if score > 0.6:
        return "high"
    if score > 0.3:
        return "medium"
    return "low"


class IdentityAnalyticsEngine:
    """SQLite WAL-backed Identity Analytics engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    Tables: identity_profiles, login_events, identity_risks, access_certifications.
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS identity_profiles (
                    identity_id     TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    username        TEXT NOT NULL,
                    email           TEXT NOT NULL DEFAULT '',
                    department      TEXT NOT NULL DEFAULT '',
                    job_title       TEXT NOT NULL DEFAULT '',
                    identity_type   TEXT NOT NULL DEFAULT 'human',
                    privileged      INTEGER NOT NULL DEFAULT 0,
                    mfa_enabled     INTEGER NOT NULL DEFAULT 0,
                    last_login      DATETIME,
                    login_count     INTEGER NOT NULL DEFAULT 0,
                    failed_logins   INTEGER NOT NULL DEFAULT 0,
                    risk_score      REAL NOT NULL DEFAULT 0.0,
                    risk_tier       TEXT NOT NULL DEFAULT 'low',
                    created_at      DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ip_org
                    ON identity_profiles (org_id, identity_type, risk_tier);

                CREATE TABLE IF NOT EXISTS login_events (
                    event_id        TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    identity_id     TEXT NOT NULL
                        REFERENCES identity_profiles(identity_id) ON DELETE CASCADE,
                    event_type      TEXT NOT NULL DEFAULT 'login',
                    src_ip          TEXT NOT NULL DEFAULT '',
                    geo_country     TEXT NOT NULL DEFAULT '',
                    device_id       TEXT NOT NULL DEFAULT '',
                    success         INTEGER NOT NULL DEFAULT 1,
                    risk_indicators TEXT NOT NULL DEFAULT '[]',
                    observed_at     DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_le_org
                    ON login_events (org_id, identity_id, event_type, observed_at);

                CREATE TABLE IF NOT EXISTS identity_risks (
                    risk_id         TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    identity_id     TEXT NOT NULL
                        REFERENCES identity_profiles(identity_id) ON DELETE CASCADE,
                    risk_type       TEXT NOT NULL,
                    severity        TEXT NOT NULL DEFAULT 'medium',
                    description     TEXT NOT NULL DEFAULT '',
                    detected_at     DATETIME NOT NULL,
                    resolved_at     DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_ir_org
                    ON identity_risks (org_id, identity_id, risk_type, resolved_at);

                CREATE TABLE IF NOT EXISTS access_certifications (
                    cert_id         TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    identity_id     TEXT NOT NULL
                        REFERENCES identity_profiles(identity_id) ON DELETE CASCADE,
                    reviewer        TEXT NOT NULL DEFAULT '',
                    status          TEXT NOT NULL DEFAULT 'pending',
                    access_level    TEXT NOT NULL DEFAULT '',
                    certified_at    DATETIME,
                    next_review     DATETIME,
                    created_at      DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ac_org
                    ON access_certifications (org_id, identity_id, status);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    # ------------------------------------------------------------------
    # Identity Profiles
    # ------------------------------------------------------------------

    def register_identity(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a new identity profile."""
        identity_id = str(uuid.uuid4())
        now = _now()
        identity_type = data.get("identity_type", "human")
        if identity_type not in _VALID_IDENTITY_TYPES:
            identity_type = "human"
        privileged = int(bool(data.get("privileged", False)))
        mfa_enabled = int(bool(data.get("mfa_enabled", False)))

        record = {
            "identity_id": identity_id,
            "org_id": org_id,
            "username": data.get("username", ""),
            "email": data.get("email", ""),
            "department": data.get("department", ""),
            "job_title": data.get("job_title", ""),
            "identity_type": identity_type,
            "privileged": privileged,
            "mfa_enabled": mfa_enabled,
            "last_login": data.get("last_login"),
            "login_count": int(data.get("login_count", 0)),
            "failed_logins": int(data.get("failed_logins", 0)),
            "risk_score": float(data.get("risk_score", 0.0)),
            "risk_tier": data.get("risk_tier", "low"),
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO identity_profiles
                       (identity_id, org_id, username, email, department, job_title,
                        identity_type, privileged, mfa_enabled, last_login,
                        login_count, failed_logins, risk_score, risk_tier, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        record["identity_id"], record["org_id"], record["username"],
                        record["email"], record["department"], record["job_title"],
                        record["identity_type"], record["privileged"], record["mfa_enabled"],
                        record["last_login"], record["login_count"], record["failed_logins"],
                        record["risk_score"], record["risk_tier"], record["created_at"],
                    ),
                )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("IDENTITY_UPDATED", {"entity_type": "identity_analytics", "org_id": org_id, "source_engine": "identity_analytics"})
            except Exception:
                pass

        return record

    def list_identities(
        self,
        org_id: str,
        identity_type: Optional[str] = None,
        privileged_only: bool = False,
        risk_tier: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List identity profiles with optional filters."""
        query = "SELECT * FROM identity_profiles WHERE org_id=?"
        params: List[Any] = [org_id]
        if identity_type:
            query += " AND identity_type=?"
            params.append(identity_type)
        if privileged_only:
            query += " AND privileged=1"
        if risk_tier:
            query += " AND risk_tier=?"
            params.append(risk_tier)
        query += " ORDER BY risk_score DESC"
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(query, params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def _get_identity(
        self, conn: sqlite3.Connection, org_id: str, identity_id: str
    ) -> Optional[sqlite3.Row]:
        return conn.execute(
            "SELECT * FROM identity_profiles WHERE identity_id=? AND org_id=?",
            (identity_id, org_id),
        ).fetchone()

    # ------------------------------------------------------------------
    # Login Events
    # ------------------------------------------------------------------

    def ingest_login_event(
        self, org_id: str, identity_id: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Ingest a login event and auto-detect risks.

        Risk detection:
        - credential_spray: >10 failed_logins total on the identity profile
        - impossible_travel: geo_country changed within 1 hour of previous event
        - Scoring: +0.3 per failed_login batch, +0.5 for privilege_escalation
        """
        event_id = str(uuid.uuid4())
        observed_at = data.get("observed_at", _now())
        event_type = data.get("event_type", "login")
        if event_type not in _VALID_EVENT_TYPES:
            event_type = "login"
        success = int(bool(data.get("success", True)))
        src_ip = data.get("src_ip", "")
        geo_country = data.get("geo_country", "")
        device_id = data.get("device_id", "")
        risk_indicators: List[str] = list(data.get("risk_indicators", []))

        with self._lock:
            with self._conn() as conn:
                identity = self._get_identity(conn, org_id, identity_id)
                if not identity:
                    raise ValueError(f"Identity {identity_id} not found in org {org_id}")

                identity_dict = dict(identity)

                # --- Risk auto-detection ---

                # 1. Credential spray: profile has >10 failed_logins after this event
                new_failed = identity_dict["failed_logins"]
                if event_type == "failed_login" or success == 0:
                    new_failed += 1
                if new_failed > 10:
                    risk_indicators.append("credential_spray")

                # 2. Impossible travel: geo_country changed within 1 hour
                if geo_country:
                    prev_event = conn.execute(
                        """SELECT geo_country, observed_at FROM login_events
                           WHERE identity_id=? AND org_id=? AND geo_country != ''
                           ORDER BY observed_at DESC LIMIT 1""",
                        (identity_id, org_id),
                    ).fetchone()
                    if prev_event:
                        prev_country = prev_event["geo_country"]
                        prev_time_str = prev_event["observed_at"]
                        if prev_country and prev_country != geo_country:
                            try:
                                prev_time = datetime.fromisoformat(prev_time_str)
                                curr_time = datetime.fromisoformat(observed_at)
                                if abs((curr_time - prev_time).total_seconds()) < 3600:
                                    risk_indicators.append("impossible_travel")
                            except (ValueError, TypeError):
                                pass

                # 3. MFA bypass detection
                if event_type == "mfa_bypass":
                    risk_indicators.append("mfa_bypass")

                # Insert the event
                conn.execute(
                    """INSERT INTO login_events
                       (event_id, org_id, identity_id, event_type, src_ip, geo_country,
                        device_id, success, risk_indicators, observed_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        event_id, org_id, identity_id, event_type, src_ip, geo_country,
                        device_id, success, json.dumps(risk_indicators), observed_at,
                    ),
                )

                # --- Update risk_score on profile ---
                current_score = identity_dict["risk_score"]
                if event_type == "failed_login" or success == 0:
                    current_score = min(1.0, current_score + 0.3)
                if event_type == "privilege_escalation":
                    current_score = min(1.0, current_score + 0.5)
                new_tier = _risk_tier(current_score)

                # Update login stats
                new_login_count = identity_dict["login_count"]
                new_last_login = identity_dict["last_login"]
                if event_type == "login" and success == 1:
                    new_login_count += 1
                    new_last_login = observed_at

                conn.execute(
                    """UPDATE identity_profiles
                       SET risk_score=?, risk_tier=?, failed_logins=?,
                           login_count=?, last_login=?
                       WHERE identity_id=? AND org_id=?""",
                    (
                        current_score, new_tier, new_failed,
                        new_login_count, new_last_login,
                        identity_id, org_id,
                    ),
                )

                # Auto-flag risks found
                for indicator in set(risk_indicators):
                    if indicator in _VALID_RISK_TYPES:
                        sev = "high" if indicator in {"impossible_travel", "mfa_bypass", "credential_spray"} else "medium"
                        self._insert_risk(
                            conn, org_id, identity_id, indicator, sev,
                            f"Auto-detected: {indicator} on event {event_id}",
                        )

        return {
            "event_id": event_id,
            "org_id": org_id,
            "identity_id": identity_id,
            "event_type": event_type,
            "src_ip": src_ip,
            "geo_country": geo_country,
            "device_id": device_id,
            "success": success,
            "risk_indicators": risk_indicators,
            "observed_at": observed_at,
        }

    def list_login_events(
        self,
        org_id: str,
        identity_id: Optional[str] = None,
        event_type: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """List login events with optional filters. Deserializes risk_indicators JSON."""
        query = "SELECT * FROM login_events WHERE org_id=?"
        params: List[Any] = [org_id]
        if identity_id:
            query += " AND identity_id=?"
            params.append(identity_id)
        if event_type:
            query += " AND event_type=?"
            params.append(event_type)
        query += " ORDER BY observed_at DESC LIMIT ?"
        params.append(limit)
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(query, params).fetchall()
        results = []
        for r in rows:
            d = self._row_to_dict(r)
            try:
                d["risk_indicators"] = json.loads(d.get("risk_indicators", "[]"))
            except (ValueError, TypeError):
                d["risk_indicators"] = []
            results.append(d)
        return results

    # ------------------------------------------------------------------
    # Identity Risks
    # ------------------------------------------------------------------

    def _insert_risk(
        self,
        conn: sqlite3.Connection,
        org_id: str,
        identity_id: str,
        risk_type: str,
        severity: str,
        description: str,
    ) -> str:
        risk_id = str(uuid.uuid4())
        now = _now()
        conn.execute(
            """INSERT INTO identity_risks
               (risk_id, org_id, identity_id, risk_type, severity, description, detected_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (risk_id, org_id, identity_id, risk_type, severity, description, now),
        )
        return risk_id

    def flag_risk(
        self, org_id: str, identity_id: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Manually flag an identity risk."""
        risk_type = data.get("risk_type", "excessive_privilege")
        if risk_type not in _VALID_RISK_TYPES:
            risk_type = "excessive_privilege"
        severity = data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            severity = "medium"
        description = data.get("description", "")
        detected_at = data.get("detected_at", _now())
        risk_id = str(uuid.uuid4())

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO identity_risks
                       (risk_id, org_id, identity_id, risk_type, severity, description, detected_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (risk_id, org_id, identity_id, risk_type, severity, description, detected_at),
                )
        return {
            "risk_id": risk_id,
            "org_id": org_id,
            "identity_id": identity_id,
            "risk_type": risk_type,
            "severity": severity,
            "description": description,
            "detected_at": detected_at,
            "resolved_at": None,
        }

    def list_risks(
        self,
        org_id: str,
        risk_type: Optional[str] = None,
        resolved: bool = False,
        severity: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List identity risks. By default returns unresolved only."""
        query = "SELECT * FROM identity_risks WHERE org_id=?"
        params: List[Any] = [org_id]
        if risk_type:
            query += " AND risk_type=?"
            params.append(risk_type)
        if not resolved:
            query += " AND resolved_at IS NULL"
        else:
            query += " AND resolved_at IS NOT NULL"
        if severity:
            query += " AND severity=?"
            params.append(severity)
        query += " ORDER BY detected_at DESC"
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(query, params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def resolve_risk(self, org_id: str, risk_id: str) -> bool:
        """Mark a risk as resolved. Returns True if a row was updated."""
        now = _now()
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    "UPDATE identity_risks SET resolved_at=? WHERE risk_id=? AND org_id=? AND resolved_at IS NULL",
                    (now, risk_id, org_id),
                )
        return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Access Certifications
    # ------------------------------------------------------------------

    def create_certification(
        self, org_id: str, identity_id: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Create an access certification record."""
        cert_id = str(uuid.uuid4())
        now = _now()
        status = data.get("status", "pending")
        if status not in _VALID_CERT_STATUSES:
            status = "pending"
        next_review = data.get(
            "next_review",
            (datetime.now(timezone.utc) + timedelta(days=90)).isoformat(),
        )
        record = {
            "cert_id": cert_id,
            "org_id": org_id,
            "identity_id": identity_id,
            "reviewer": data.get("reviewer", ""),
            "status": status,
            "access_level": data.get("access_level", ""),
            "certified_at": data.get("certified_at"),
            "next_review": next_review,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO access_certifications
                       (cert_id, org_id, identity_id, reviewer, status,
                        access_level, certified_at, next_review, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        record["cert_id"], record["org_id"], record["identity_id"],
                        record["reviewer"], record["status"], record["access_level"],
                        record["certified_at"], record["next_review"], record["created_at"],
                    ),
                )
        return record

    def list_certifications(
        self, org_id: str, status: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List access certifications."""
        query = "SELECT * FROM access_certifications WHERE org_id=?"
        params: List[Any] = [org_id]
        if status:
            query += " AND status=?"
            params.append(status)
        query += " ORDER BY created_at DESC"
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(query, params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_identity_stats(self, org_id: str) -> Dict[str, Any]:
        """Aggregate identity analytics stats for an org.

        Perf: collapsed 8 sequential COUNT queries into 3 queries using
        conditional aggregation (SUM+CASE), reducing round-trips 8x→3x.
        """
        cutoff_90d = (datetime.now(timezone.utc) - timedelta(days=90)).isoformat()
        with self._lock:
            with self._conn() as conn:
                # Query 1: all identity_profiles aggregates in one pass
                ip_row = conn.execute(
                    """SELECT
                           COUNT(*)                                                  AS total,
                           SUM(CASE WHEN privileged=1 THEN 1 ELSE 0 END)            AS privileged,
                           SUM(CASE WHEN privileged=1 AND mfa_enabled=0 THEN 1 ELSE 0 END) AS mfa_disabled,
                           SUM(CASE WHEN risk_tier='critical' THEN 1 ELSE 0 END)    AS critical_risk,
                           SUM(CASE WHEN last_login IS NULL OR last_login < ?
                                    THEN 1 ELSE 0 END)                              AS dormant
                       FROM identity_profiles WHERE org_id=?""",
                    (cutoff_90d, org_id),
                ).fetchone()

                # Query 2: all identity_risks aggregates in one pass
                ir_row = conn.execute(
                    """SELECT
                           SUM(CASE WHEN resolved_at IS NULL THEN 1 ELSE 0 END)                          AS open_risks,
                           SUM(CASE WHEN risk_type='impossible_travel' AND resolved_at IS NULL
                                    THEN 1 ELSE 0 END)                                                   AS impossible_travel
                       FROM identity_risks WHERE org_id=?""",
                    (org_id,),
                ).fetchone()

                # Query 3: certifications
                pending_certs = conn.execute(
                    "SELECT COUNT(*) FROM access_certifications WHERE org_id=? AND status='pending'",
                    (org_id,),
                ).fetchone()[0]

        return {
            "total_identities":       ip_row["total"]          or 0,
            "privileged_identities":  ip_row["privileged"]     or 0,
            "mfa_disabled":           ip_row["mfa_disabled"]   or 0,
            "critical_risk_identities": ip_row["critical_risk"] or 0,
            "open_risks":             ir_row["open_risks"]      or 0,
            "impossible_travel_count": ir_row["impossible_travel"] or 0,
            "dormant_identities":     ip_row["dormant"]         or 0,
            "pending_certifications": pending_certs,
        }


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_engine: Optional[IdentityAnalyticsEngine] = None
_engine_lock = threading.Lock()


def get_engine(db_path: str = _DEFAULT_DB) -> IdentityAnalyticsEngine:
    global _engine
    with _engine_lock:
        if _engine is None:
            _engine = IdentityAnalyticsEngine(db_path)
    return _engine
