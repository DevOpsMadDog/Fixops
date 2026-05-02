"""PKI Management Engine — ALDECI.

Manages PKI certificates and certificate authorities across their full
lifecycle: issuance, revocation, expiry monitoring, and audit logging.

Compliance: NIST SP 800-57, CABF Baseline Requirements, ISO/IEC 27001 A.10
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "pki_management.db"
)

_VALID_KEY_ALGORITHMS = {"RSA", "ECDSA", "DSA"}
_VALID_CERT_TYPES = {"root_ca", "intermediate_ca", "server", "client", "code_signing", "email"}
_VALID_CERT_STATUSES = {"active", "expired", "revoked", "pending", "suspended"}
_VALID_CA_TYPES = {"root", "intermediate", "external"}
_VALID_CA_STATUSES = {"active", "inactive", "compromised"}
_VALID_ENTITY_TYPES = {"certificate", "ca"}
_VALID_AUDIT_ACTIONS = {"issued", "renewed", "revoked", "suspended", "reinstated", "expired"}


class PKIManagementEngine:
    """SQLite WAL-backed PKI Management engine.

    Thread-safe via RLock. Multi-tenant via org_id.
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
                CREATE TABLE IF NOT EXISTS pki_certificates (
                    id                TEXT PRIMARY KEY,
                    org_id            TEXT NOT NULL,
                    common_name       TEXT NOT NULL,
                    serial_number     TEXT NOT NULL DEFAULT '',
                    issuer            TEXT NOT NULL DEFAULT '',
                    subject_alt_names TEXT NOT NULL DEFAULT '[]',
                    key_algorithm     TEXT NOT NULL DEFAULT 'RSA',
                    key_size          INTEGER NOT NULL DEFAULT 2048,
                    cert_type         TEXT NOT NULL DEFAULT 'server',
                    status            TEXT NOT NULL DEFAULT 'active',
                    issued_at         TEXT NOT NULL DEFAULT '',
                    expires_at        TEXT NOT NULL,
                    revoked_at        TEXT,
                    revoke_reason     TEXT NOT NULL DEFAULT '',
                    auto_renew        INTEGER NOT NULL DEFAULT 0,
                    created_at        TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS pki_cas (
                    id            TEXT PRIMARY KEY,
                    org_id        TEXT NOT NULL,
                    name          TEXT NOT NULL,
                    ca_type       TEXT NOT NULL DEFAULT 'root',
                    subject       TEXT NOT NULL DEFAULT '',
                    key_algorithm TEXT NOT NULL DEFAULT 'RSA',
                    status        TEXT NOT NULL DEFAULT 'active',
                    cert_count    INTEGER NOT NULL DEFAULT 0,
                    created_at    TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS pki_audit_log (
                    id           TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    entity_type  TEXT NOT NULL,
                    entity_id    TEXT NOT NULL,
                    action       TEXT NOT NULL,
                    actor        TEXT NOT NULL DEFAULT '',
                    details      TEXT NOT NULL DEFAULT '',
                    performed_at TEXT NOT NULL
                );
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Certificates
    # ------------------------------------------------------------------

    def issue_certificate(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Issue a new PKI certificate."""
        common_name = data.get("common_name", "")
        if not common_name:
            raise ValueError("common_name is required")
        expires_at = data.get("expires_at", "")
        if not expires_at:
            raise ValueError("expires_at is required")

        key_algorithm = data.get("key_algorithm", "RSA")
        if key_algorithm not in _VALID_KEY_ALGORITHMS:
            raise ValueError(
                f"Invalid key_algorithm '{key_algorithm}'. "
                f"Valid: {sorted(_VALID_KEY_ALGORITHMS)}"
            )

        cert_type = data.get("cert_type", "server")
        if cert_type not in _VALID_CERT_TYPES:
            raise ValueError(
                f"Invalid cert_type '{cert_type}'. "
                f"Valid: {sorted(_VALID_CERT_TYPES)}"
            )

        now = datetime.now(timezone.utc).isoformat()
        cert_id = str(uuid.uuid4())
        san = data.get("subject_alt_names") or []
        san_json = json.dumps(san) if isinstance(san, list) else (san or "[]")

        row = {
            "id": cert_id,
            "org_id": org_id,
            "common_name": common_name,
            "serial_number": data.get("serial_number") or "",
            "issuer": data.get("issuer") or "",
            "subject_alt_names": san_json,
            "key_algorithm": key_algorithm,
            "key_size": int(data.get("key_size") or 2048),
            "cert_type": cert_type,
            "status": data.get("status") or "active",
            "issued_at": data.get("issued_at") or now,
            "expires_at": expires_at,
            "revoked_at": None,
            "revoke_reason": "",
            "auto_renew": 1 if data.get("auto_renew", False) else 0,
            "created_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO pki_certificates
                        (id, org_id, common_name, serial_number, issuer,
                         subject_alt_names, key_algorithm, key_size, cert_type,
                         status, issued_at, expires_at, revoked_at, revoke_reason,
                         auto_renew, created_at)
                    VALUES
                        (:id, :org_id, :common_name, :serial_number, :issuer,
                         :subject_alt_names, :key_algorithm, :key_size, :cert_type,
                         :status, :issued_at, :expires_at, :revoked_at, :revoke_reason,
                         :auto_renew, :created_at)
                    """,
                    row,
                )
        self.log_audit(org_id, "certificate", cert_id, "issued", data.get("actor", "system"))
        return self._format_cert(row)

    def list_certificates(
        self,
        org_id: str,
        cert_type: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List certificates with optional filters."""
        query = "SELECT * FROM pki_certificates WHERE org_id = ?"
        params: list = [org_id]
        if cert_type:
            query += " AND cert_type = ?"
            params.append(cert_type)
        if status:
            query += " AND status = ?"
            params.append(status)
        query += " ORDER BY created_at DESC"
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(query, params).fetchall()
        return [self._format_cert(dict(r)) for r in rows]

    def get_certificate(self, org_id: str, cert_id: str) -> Optional[Dict[str, Any]]:
        """Get a single certificate by ID with org isolation."""
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM pki_certificates WHERE id = ? AND org_id = ?",
                    (cert_id, org_id),
                ).fetchone()
        if row is None:
            return None
        return self._format_cert(dict(row))

    def revoke_certificate(
        self, org_id: str, cert_id: str, reason: str
    ) -> Dict[str, Any]:
        """Revoke a certificate and log the action."""
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    UPDATE pki_certificates
                    SET status = 'revoked', revoked_at = ?, revoke_reason = ?
                    WHERE id = ? AND org_id = ?
                    """,
                    (now, reason, cert_id, org_id),
                )
        self.log_audit(org_id, "certificate", cert_id, "revoked", "system", reason)
        return self.get_certificate(org_id, cert_id) or {}

    def get_expiring_certificates(
        self, org_id: str, days_ahead: int = 30
    ) -> List[Dict[str, Any]]:
        """Return active certs expiring within days_ahead days."""
        now = datetime.now(timezone.utc)
        threshold = (now + timedelta(days=days_ahead)).isoformat()
        now_iso = now.isoformat()
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    """
                    SELECT * FROM pki_certificates
                    WHERE org_id = ?
                      AND status = 'active'
                      AND expires_at <= ?
                      AND expires_at > ?
                    ORDER BY expires_at ASC
                    """,
                    (org_id, threshold, now_iso),
                ).fetchall()
        return [self._format_cert(dict(r)) for r in rows]

    # ------------------------------------------------------------------
    # Certificate Authorities
    # ------------------------------------------------------------------

    def register_ca(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a new certificate authority."""
        ca_type = data.get("ca_type", "root")
        if ca_type not in _VALID_CA_TYPES:
            raise ValueError(
                f"Invalid ca_type '{ca_type}'. Valid: {sorted(_VALID_CA_TYPES)}"
            )

        now = datetime.now(timezone.utc).isoformat()
        ca_id = str(uuid.uuid4())
        row = {
            "id": ca_id,
            "org_id": org_id,
            "name": data.get("name", ""),
            "ca_type": ca_type,
            "subject": data.get("subject", ""),
            "key_algorithm": data.get("key_algorithm", "RSA"),
            "status": data.get("status", "active"),
            "cert_count": int(data.get("cert_count", 0)),
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO pki_cas
                        (id, org_id, name, ca_type, subject, key_algorithm,
                         status, cert_count, created_at)
                    VALUES
                        (:id, :org_id, :name, :ca_type, :subject, :key_algorithm,
                         :status, :cert_count, :created_at)
                    """,
                    row,
                )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ASSET_DISCOVERED", {"entity_type": "pki_management", "org_id": org_id, "source_engine": "pki_management"})
            except Exception:
                pass

        return row

    def list_cas(
        self, org_id: str, status: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List CAs with optional status filter."""
        query = "SELECT * FROM pki_cas WHERE org_id = ?"
        params: list = [org_id]
        if status:
            query += " AND status = ?"
            params.append(status)
        query += " ORDER BY created_at DESC"
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Audit Log
    # ------------------------------------------------------------------

    def log_audit(
        self,
        org_id: str,
        entity_type: str,
        entity_id: str,
        action: str,
        actor: str,
        details: str = "",
    ) -> Dict[str, Any]:
        """Insert an audit log record."""
        now = datetime.now(timezone.utc).isoformat()
        entry = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "entity_type": entity_type,
            "entity_id": entity_id,
            "action": action,
            "actor": actor,
            "details": details,
            "performed_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO pki_audit_log
                        (id, org_id, entity_type, entity_id, action, actor,
                         details, performed_at)
                    VALUES
                        (:id, :org_id, :entity_type, :entity_id, :action, :actor,
                         :details, :performed_at)
                    """,
                    entry,
                )
        return entry

    def get_audit_log(
        self,
        org_id: str,
        entity_id: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """Retrieve recent audit log entries."""
        query = "SELECT * FROM pki_audit_log WHERE org_id = ?"
        params: list = [org_id]
        if entity_id:
            query += " AND entity_id = ?"
            params.append(entity_id)
        query += " ORDER BY performed_at DESC LIMIT ?"
        params.append(limit)
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_pki_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated PKI statistics for an org."""
        with self._lock:
            with self._conn() as conn:
                total = conn.execute(
                    "SELECT COUNT(*) FROM pki_certificates WHERE org_id = ?", (org_id,)
                ).fetchone()[0]
                active = conn.execute(
                    "SELECT COUNT(*) FROM pki_certificates WHERE org_id = ? AND status = 'active'",
                    (org_id,),
                ).fetchone()[0]
                expired = conn.execute(
                    "SELECT COUNT(*) FROM pki_certificates WHERE org_id = ? AND status = 'expired'",
                    (org_id,),
                ).fetchone()[0]
                revoked = conn.execute(
                    "SELECT COUNT(*) FROM pki_certificates WHERE org_id = ? AND status = 'revoked'",
                    (org_id,),
                ).fetchone()[0]
                now = datetime.now(timezone.utc)
                threshold_30 = (now + timedelta(days=30)).isoformat()
                now_iso = now.isoformat()
                expiring_30d = conn.execute(
                    """
                    SELECT COUNT(*) FROM pki_certificates
                    WHERE org_id = ? AND status = 'active'
                      AND expires_at <= ? AND expires_at > ?
                    """,
                    (org_id, threshold_30, now_iso),
                ).fetchone()[0]
                total_cas = conn.execute(
                    "SELECT COUNT(*) FROM pki_cas WHERE org_id = ?", (org_id,)
                ).fetchone()[0]
                by_cert_type_rows = conn.execute(
                    """
                    SELECT cert_type, COUNT(*) as cnt
                    FROM pki_certificates WHERE org_id = ?
                    GROUP BY cert_type
                    """,
                    (org_id,),
                ).fetchall()
                by_key_algo_rows = conn.execute(
                    """
                    SELECT key_algorithm, COUNT(*) as cnt
                    FROM pki_certificates WHERE org_id = ?
                    GROUP BY key_algorithm
                    """,
                    (org_id,),
                ).fetchall()

        return {
            "total_certs": total,
            "active_certs": active,
            "expired_certs": expired,
            "revoked_certs": revoked,
            "expiring_30d": expiring_30d,
            "total_cas": total_cas,
            "by_cert_type": {r["cert_type"]: r["cnt"] for r in by_cert_type_rows},
            "by_key_algorithm": {r["key_algorithm"]: r["cnt"] for r in by_key_algo_rows},
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _format_cert(row: Dict[str, Any]) -> Dict[str, Any]:
        """Deserialize JSON fields in a certificate row."""
        san = row.get("subject_alt_names", "[]")
        if isinstance(san, str):
            try:
                row["subject_alt_names"] = json.loads(san)
            except (json.JSONDecodeError, TypeError):
                row["subject_alt_names"] = []
        row["auto_renew"] = bool(row.get("auto_renew", 0))
        return row
