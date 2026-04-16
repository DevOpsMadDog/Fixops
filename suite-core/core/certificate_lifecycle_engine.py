"""Certificate Lifecycle Engine — ALDECI.

Tracks SSL/TLS, code-signing, client, and CA certificates across their full
lifecycle: registration, expiry monitoring, renewal, and revocation.

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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "certificate_lifecycle.db"
)

_VALID_CERT_TYPES = {"ssl", "code_signing", "client", "ca"}


def _compute_status(expiry_date: str) -> str:
    """Compute certificate status from expiry_date ISO string."""
    if not expiry_date:
        return "active"
    try:
        expiry = datetime.fromisoformat(expiry_date)
        # Make naive datetimes UTC-aware for comparison
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        if expiry < now:
            return "expired"
        if expiry < now + timedelta(days=30):
            return "expiring"
        return "active"
    except ValueError:
        return "active"


class CertificateLifecycleEngine:
    """SQLite WAL-backed Certificate Lifecycle engine.

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
                CREATE TABLE IF NOT EXISTS certificates (
                    cert_id       TEXT PRIMARY KEY,
                    org_id        TEXT NOT NULL,
                    domain        TEXT NOT NULL DEFAULT '',
                    issuer        TEXT NOT NULL DEFAULT '',
                    cert_type     TEXT NOT NULL DEFAULT 'ssl',
                    expiry_date   TEXT NOT NULL DEFAULT '',
                    san_list      TEXT NOT NULL DEFAULT '[]',
                    auto_renew    INTEGER NOT NULL DEFAULT 0,
                    revoked       INTEGER NOT NULL DEFAULT 0,
                    revoke_reason TEXT NOT NULL DEFAULT '',
                    created_at    TEXT NOT NULL,
                    updated_at    TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_certs_org
                    ON certificates (org_id, cert_type);

                CREATE INDEX IF NOT EXISTS idx_certs_expiry
                    ON certificates (org_id, expiry_date);

                CREATE TABLE IF NOT EXISTS renewal_history (
                    renewal_id      TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    cert_id         TEXT NOT NULL,
                    old_expiry_date TEXT NOT NULL DEFAULT '',
                    new_expiry_date TEXT NOT NULL DEFAULT '',
                    renewed_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_renewals_cert
                    ON renewal_history (org_id, cert_id);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _row_to_dict(self, row: Any) -> Dict[str, Any]:
        d = dict(row)
        d["san_list"] = json.loads(d.get("san_list") or "[]")
        d["auto_renew"] = bool(d.get("auto_renew", 0))
        d["revoked"] = bool(d.get("revoked", 0))
        # Inject computed status
        if d.get("revoked"):
            d["status"] = "revoked"
        else:
            d["status"] = _compute_status(d.get("expiry_date", ""))
        return d

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def register_certificate(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a new certificate. Returns the full certificate record."""
        cert_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        cert_type = data.get("cert_type", "ssl")
        if cert_type not in _VALID_CERT_TYPES:
            cert_type = "ssl"

        san_list = data.get("san_list", [])
        if not isinstance(san_list, list):
            san_list = []

        auto_renew = bool(data.get("auto_renew", False))
        expiry_date = data.get("expiry_date", "")

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO certificates
                        (cert_id, org_id, domain, issuer, cert_type, expiry_date,
                         san_list, auto_renew, revoked, revoke_reason, created_at, updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        cert_id, org_id,
                        data.get("domain", ""),
                        data.get("issuer", ""),
                        cert_type,
                        expiry_date,
                        json.dumps(san_list),
                        1 if auto_renew else 0,
                        0, "",
                        now, now,
                    ),
                )

        result = {
            "cert_id": cert_id,
            "org_id": org_id,
            "domain": data.get("domain", ""),
            "issuer": data.get("issuer", ""),
            "cert_type": cert_type,
            "expiry_date": expiry_date,
            "san_list": san_list,
            "auto_renew": auto_renew,
            "revoked": False,
            "revoke_reason": "",
            "status": _compute_status(expiry_date),
            "created_at": now,
            "updated_at": now,
        }
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ASSET_DISCOVERED", {"entity_type": "certificate_lifecycle", "org_id": org_id, "source_engine": "certificate_lifecycle"})
            except Exception:
                pass

        return result

    def list_certificates(
        self,
        org_id: str,
        cert_type: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List certificates for an org, optionally filtered by cert_type and/or status."""
        query = "SELECT * FROM certificates WHERE org_id = ?"
        params: list = [org_id]
        if cert_type:
            query += " AND cert_type = ?"
            params.append(cert_type)
        query += " ORDER BY expiry_date ASC"

        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(query, params).fetchall()

        certs = [self._row_to_dict(r) for r in rows]

        if status:
            certs = [c for c in certs if c["status"] == status]
        return certs

    def get_certificate(self, org_id: str, cert_id: str) -> Optional[Dict[str, Any]]:
        """Fetch a single certificate by cert_id (org-scoped)."""
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM certificates WHERE org_id = ? AND cert_id = ?",
                    (org_id, cert_id),
                ).fetchone()
        return self._row_to_dict(row) if row else None

    def get_expiring_certificates(
        self, org_id: str, days_ahead: int = 30
    ) -> List[Dict[str, Any]]:
        """Return non-revoked certificates expiring within the next N days."""
        now = datetime.now(timezone.utc)
        cutoff = (now + timedelta(days=days_ahead)).isoformat()
        now_iso = now.isoformat()

        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    """
                    SELECT * FROM certificates
                    WHERE org_id = ?
                      AND revoked = 0
                      AND expiry_date != ''
                      AND expiry_date <= ?
                      AND expiry_date >= ?
                    ORDER BY expiry_date ASC
                    """,
                    (org_id, cutoff, now_iso),
                ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def renew_certificate(
        self, org_id: str, cert_id: str, new_expiry_date: str
    ) -> Dict[str, Any]:
        """Renew a certificate by updating its expiry date and logging the renewal."""
        now = datetime.now(timezone.utc).isoformat()
        renewal_id = str(uuid.uuid4())

        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM certificates WHERE org_id = ? AND cert_id = ?",
                    (org_id, cert_id),
                ).fetchone()
                if not row:
                    raise ValueError(f"Certificate not found: {cert_id}")

                old_expiry = row["expiry_date"]

                conn.execute(
                    "UPDATE certificates SET expiry_date = ?, updated_at = ? WHERE cert_id = ?",
                    (new_expiry_date, now, cert_id),
                )
                conn.execute(
                    """
                    INSERT INTO renewal_history
                        (renewal_id, org_id, cert_id, old_expiry_date, new_expiry_date, renewed_at)
                    VALUES (?,?,?,?,?,?)
                    """,
                    (renewal_id, org_id, cert_id, old_expiry, new_expiry_date, now),
                )

        return {
            "cert_id": cert_id,
            "org_id": org_id,
            "old_expiry_date": old_expiry,
            "new_expiry_date": new_expiry_date,
            "renewal_id": renewal_id,
            "renewed_at": now,
            "status": _compute_status(new_expiry_date),
        }

    def revoke_certificate(
        self, org_id: str, cert_id: str, reason: str
    ) -> Dict[str, Any]:
        """Revoke a certificate. Returns confirmation record."""
        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM certificates WHERE org_id = ? AND cert_id = ?",
                    (org_id, cert_id),
                ).fetchone()
                if not row:
                    raise ValueError(f"Certificate not found: {cert_id}")

                conn.execute(
                    "UPDATE certificates SET revoked = 1, revoke_reason = ?, updated_at = ? WHERE cert_id = ?",
                    (reason, now, cert_id),
                )

        return {
            "cert_id": cert_id,
            "org_id": org_id,
            "status": "revoked",
            "reason": reason,
            "revoked_at": now,
        }

    def get_renewal_history(
        self, org_id: str, cert_id: str
    ) -> List[Dict[str, Any]]:
        """Return all renewal records for a certificate."""
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    """
                    SELECT * FROM renewal_history
                    WHERE org_id = ? AND cert_id = ?
                    ORDER BY renewed_at DESC
                    """,
                    (org_id, cert_id),
                ).fetchall()
        return [dict(r) for r in rows]

    def get_certificate_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated certificate statistics for the org."""
        now = datetime.now(timezone.utc)
        expiring_cutoff = (now + timedelta(days=30)).isoformat()
        now_iso = now.isoformat()

        with self._lock:
            with self._conn() as conn:
                total = conn.execute(
                    "SELECT COUNT(*) FROM certificates WHERE org_id = ?", (org_id,)
                ).fetchone()[0]

                revoked_count = conn.execute(
                    "SELECT COUNT(*) FROM certificates WHERE org_id = ? AND revoked = 1",
                    (org_id,),
                ).fetchone()[0]

                expired_count = conn.execute(
                    """
                    SELECT COUNT(*) FROM certificates
                    WHERE org_id = ? AND revoked = 0
                      AND expiry_date != '' AND expiry_date < ?
                    """,
                    (org_id, now_iso),
                ).fetchone()[0]

                expiring_30d = conn.execute(
                    """
                    SELECT COUNT(*) FROM certificates
                    WHERE org_id = ? AND revoked = 0
                      AND expiry_date != ''
                      AND expiry_date >= ? AND expiry_date <= ?
                    """,
                    (org_id, now_iso, expiring_cutoff),
                ).fetchone()[0]

                active_count = conn.execute(
                    """
                    SELECT COUNT(*) FROM certificates
                    WHERE org_id = ? AND revoked = 0
                      AND (expiry_date = '' OR expiry_date > ?)
                    """,
                    (org_id, expiring_cutoff),
                ).fetchone()[0]

                by_type_rows = conn.execute(
                    "SELECT cert_type, COUNT(*) as cnt FROM certificates WHERE org_id = ? GROUP BY cert_type",
                    (org_id,),
                ).fetchall()

        return {
            "org_id": org_id,
            "total": total,
            "active": active_count,
            "expiring_30d": expiring_30d,
            "expired": expired_count,
            "revoked": revoked_count,
            "by_type": {r["cert_type"]: r["cnt"] for r in by_type_rows},
        }
