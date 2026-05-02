"""TLS Certificate Management Engine — ALDECI.

Track TLS/SSL certificate inventory, expiry alerts, and weak configuration detection.

Compliance: PCI DSS 4.0 req 4.2, NIST SP 800-52r2, CIS Controls v8 3.10
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# TrustGraph second-brain wiring
# ---------------------------------------------------------------------------
try:  # pragma: no cover - optional dependency
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except Exception:  # noqa: BLE001
    _get_tg_bus = None  # type: ignore[assignment]


def _emit_event(event_type: str, payload: dict) -> None:
    """Emit to TrustGraph event bus. Never raises."""
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
            import asyncio as _aio
            import inspect as _insp
            if _insp.iscoroutine(result):
                try:
                    loop = _aio.get_running_loop()
                    loop.create_task(result)
                except RuntimeError:
                    result.close()
        except Exception:  # pragma: no cover
            pass
    except Exception:  # pragma: no cover
        pass


try:  # pragma: no cover
    _emit_event("engine.loaded", {"module": __name__})
except Exception:  # noqa: BLE001
    pass


import json
import logging
import socket
import sqlite3
import ssl
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "certificates.db"
)

# Weak algorithm patterns
_WEAK_ALGORITHMS = {"md5", "sha1", "md2", "md4"}
_WEAK_KEY_SIZES = {"RSA": 2048, "DSA": 2048, "EC": 224}


class CertificateManager:
    """SQLite WAL-backed TLS certificate inventory and alerting engine.

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
                    id            TEXT PRIMARY KEY,
                    org_id        TEXT NOT NULL,
                    domain        TEXT NOT NULL,
                    issuer        TEXT NOT NULL DEFAULT '',
                    serial        TEXT NOT NULL DEFAULT '',
                    not_before    DATETIME NOT NULL,
                    not_after     DATETIME NOT NULL,
                    algorithm     TEXT NOT NULL DEFAULT '',
                    key_size      INTEGER NOT NULL DEFAULT 0,
                    san_list      TEXT NOT NULL DEFAULT '[]',
                    wildcard      INTEGER NOT NULL DEFAULT 0,
                    self_signed   INTEGER NOT NULL DEFAULT 0,
                    created_at    DATETIME NOT NULL,
                    updated_at    DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_cert_org
                    ON certificates (org_id, not_after);

                CREATE INDEX IF NOT EXISTS idx_cert_domain
                    ON certificates (domain);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        d["san_list"] = json.loads(d.get("san_list") or "[]")
        d["wildcard"] = bool(d["wildcard"])
        d["self_signed"] = bool(d["self_signed"])
        return d

    @staticmethod
    def _days_until(dt_str: str) -> int:
        try:
            exp = datetime.fromisoformat(dt_str)
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            delta = exp - datetime.now(timezone.utc)
            return int(delta.total_seconds() / 86400)
        except Exception:
            return 0

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def add_certificate(self, org_id: str, cert: Dict[str, Any]) -> str:
        """Add a certificate to inventory. Returns the new cert ID."""
        cert_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        # Detect self-signed: issuer == domain or issuer contains domain
        domain = cert.get("domain", "")
        issuer = cert.get("issuer", "")
        self_signed = bool(
            issuer and domain and (issuer == domain or domain in issuer or issuer in domain)
        )

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO certificates
                        (id, org_id, domain, issuer, serial, not_before, not_after,
                         algorithm, key_size, san_list, wildcard, self_signed,
                         created_at, updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        cert_id,
                        org_id,
                        domain,
                        issuer,
                        cert.get("serial", ""),
                        cert.get("not_before", now),
                        cert.get("not_after", now),
                        cert.get("algorithm", ""),
                        int(cert.get("key_size", 0)),
                        json.dumps(cert.get("san_list", [])),
                        1 if cert.get("wildcard") else 0,
                        1 if self_signed else 0,
                        now,
                        now,
                    ),
                )
        _emit_event("cert_manager.cert_added", {
            "cert_id": cert_id,
            "org_id": org_id,
            "domain": domain,
            "issuer": issuer,
            "self_signed": self_signed,
            "not_after": cert.get("not_after", now),
        })
        return cert_id

    def list_certificates(
        self,
        org_id: str,
        expired_only: bool = False,
        expiring_days: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """List certificates for an org. Optionally filter by expiry."""
        now = datetime.now(timezone.utc).isoformat()
        params: list = [org_id]

        if expired_only:
            query = "SELECT * FROM certificates WHERE org_id=? AND not_after < ? ORDER BY not_after ASC"
            params.append(now)
        elif expiring_days is not None:
            cutoff = (datetime.now(timezone.utc) + timedelta(days=expiring_days)).isoformat()
            query = (
                "SELECT * FROM certificates WHERE org_id=? AND not_after >= ? AND not_after <= ? "
                "ORDER BY not_after ASC"
            )
            params.extend([now, cutoff])
        else:
            query = "SELECT * FROM certificates WHERE org_id=? ORDER BY not_after ASC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_certificate(self, cert_id: str, org_id: str) -> Optional[Dict[str, Any]]:
        """Fetch a single certificate by ID, scoped to org."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM certificates WHERE id=? AND org_id=?",
                (cert_id, org_id),
            ).fetchone()
        return self._row_to_dict(row) if row else None

    def update_certificate(self, cert_id: str, org_id: str, updates: Dict[str, Any]) -> bool:
        """Update allowed fields on a certificate. Returns True if updated."""
        allowed = {
            "domain", "issuer", "serial", "not_before", "not_after",
            "algorithm", "key_size", "san_list", "wildcard", "self_signed",
        }
        fields = {k: v for k, v in updates.items() if k in allowed}
        if not fields:
            return False

        if "san_list" in fields:
            fields["san_list"] = json.dumps(fields["san_list"])
        if "wildcard" in fields:
            fields["wildcard"] = 1 if fields["wildcard"] else 0
        if "self_signed" in fields:
            fields["self_signed"] = 1 if fields["self_signed"] else 0

        fields["updated_at"] = datetime.now(timezone.utc).isoformat()
        set_clause = ", ".join(f"{k}=?" for k in fields)
        values = list(fields.values()) + [cert_id, org_id]

        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    f"UPDATE certificates SET {set_clause} WHERE id=? AND org_id=?",  # nosec B608
                    values,
                )
        return cur.rowcount > 0

    def delete_certificate(self, cert_id: str, org_id: str) -> bool:
        """Delete a certificate from inventory. Returns True if deleted."""
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    "DELETE FROM certificates WHERE id=? AND org_id=?",
                    (cert_id, org_id),
                )
        deleted = cur.rowcount > 0
        if deleted:
            _emit_event("cert_manager.cert_deleted", {
                "cert_id": cert_id,
                "org_id": org_id,
            })
        return deleted

    # ------------------------------------------------------------------
    # Alerting
    # ------------------------------------------------------------------

    def get_expiry_alerts(self, org_id: str) -> Dict[str, List[Dict[str, Any]]]:
        """Return certs grouped by expiry urgency."""
        now = datetime.now(timezone.utc)
        thresholds = {
            "expired": now,
            "expiring_7d": now + timedelta(days=7),
            "expiring_30d": now + timedelta(days=30),
            "expiring_90d": now + timedelta(days=90),
        }

        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM certificates WHERE org_id=? ORDER BY not_after ASC",
                (org_id,),
            ).fetchall()

        result: Dict[str, List[Dict[str, Any]]] = {
            "expired": [],
            "expiring_7d": [],
            "expiring_30d": [],
            "expiring_90d": [],
        }
        for row in rows:
            d = self._row_to_dict(row)
            try:
                exp = datetime.fromisoformat(d["not_after"])
                if exp.tzinfo is None:
                    exp = exp.replace(tzinfo=timezone.utc)
            except Exception:
                continue

            if exp < thresholds["expired"]:
                result["expired"].append(d)
            elif exp <= thresholds["expiring_7d"]:
                result["expiring_7d"].append(d)
            elif exp <= thresholds["expiring_30d"]:
                result["expiring_30d"].append(d)
            elif exp <= thresholds["expiring_90d"]:
                result["expiring_90d"].append(d)

        return result

    # ------------------------------------------------------------------
    # Live check
    # ------------------------------------------------------------------

    def check_certificate(self, domain: str, port: int = 443, timeout: int = 5) -> Dict[str, Any]:
        """Probe a live domain and return its TLS certificate details."""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((domain, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as tls:
                    peer = tls.getpeercert()
                    tls.getpeercert(binary_form=True)
                    cipher_info = tls.cipher()
        except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as exc:
            return {"error": str(exc), "domain": domain, "reachable": False}
        except Exception as exc:
            return {"error": str(exc), "domain": domain, "reachable": False}

        if not peer:
            return {"error": "no certificate returned", "domain": domain, "reachable": True}

        # Parse subject/issuer
        def _dn(rdns: tuple) -> str:
            return ", ".join(
                f"{k}={v}" for rdn in rdns for k, v in rdn
            ) if rdns else ""

        not_before_raw = peer.get("notBefore", "")
        not_after_raw = peer.get("notAfter", "")

        def _parse_ssl_date(s: str) -> str:
            try:
                return datetime.strptime(s, "%b %d %H:%M:%S %Y %Z").replace(
                    tzinfo=timezone.utc
                ).isoformat()
            except Exception:
                return s

        san_list: List[str] = [
            v for kind, v in peer.get("subjectAltName", []) if kind == "DNS"
        ]

        not_after_iso = _parse_ssl_date(not_after_raw)
        days_remaining = self._days_until(not_after_iso)

        return {
            "domain": domain,
            "reachable": True,
            "subject": _dn(peer.get("subject", ())),
            "issuer": _dn(peer.get("issuer", ())),
            "serial": str(peer.get("serialNumber", "")),
            "not_before": _parse_ssl_date(not_before_raw),
            "not_after": not_after_iso,
            "days_remaining": days_remaining,
            "san_list": san_list,
            "wildcard": any(s.startswith("*.") for s in san_list),
            "cipher": cipher_info[0] if cipher_info else "",
            "tls_version": cipher_info[1] if cipher_info else "",
            "algorithm": peer.get("signatureAlgorithm", ""),
        }

    # ------------------------------------------------------------------
    # Weak cert detection
    # ------------------------------------------------------------------

    def get_weak_certificates(self, org_id: str) -> List[Dict[str, Any]]:
        """Return certs with weak algorithms, small key sizes, or self-signed."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM certificates WHERE org_id=?", (org_id,)
            ).fetchall()

        weak = []
        now = datetime.now(timezone.utc)
        for row in rows:
            d = self._row_to_dict(row)
            reasons: List[str] = []

            alg_lower = (d.get("algorithm") or "").lower()
            for weak_alg in _WEAK_ALGORITHMS:
                if weak_alg in alg_lower:
                    reasons.append(f"Weak signature algorithm: {d['algorithm']}")
                    break

            key_size = d.get("key_size", 0)
            if key_size > 0:
                alg_family = "EC" if "ec" in alg_lower else ("DSA" if "dsa" in alg_lower else "RSA")
                min_size = _WEAK_KEY_SIZES.get(alg_family, 2048)
                if key_size < min_size:
                    reasons.append(f"Small key size: {key_size} bits ({alg_family} minimum {min_size})")

            if d.get("self_signed"):
                reasons.append("Self-signed certificate")

            try:
                exp = datetime.fromisoformat(d["not_after"])
                if exp.tzinfo is None:
                    exp = exp.replace(tzinfo=timezone.utc)
                if exp < now:
                    reasons.append("Certificate is expired")
            except Exception:
                pass

            if reasons:
                d["weak_reasons"] = reasons
                weak.append(d)

        return weak

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_cert_stats(self, org_id: str) -> Dict[str, Any]:
        """Return summary statistics for an org's certificate inventory."""
        now = datetime.now(timezone.utc).isoformat()
        cutoff_30d = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()

        with self._conn() as conn:
            total = conn.execute(
                "SELECT COUNT(*) FROM certificates WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            expired = conn.execute(
                "SELECT COUNT(*) FROM certificates WHERE org_id=? AND not_after < ?",
                (org_id, now),
            ).fetchone()[0]

            expiring_soon = conn.execute(
                "SELECT COUNT(*) FROM certificates WHERE org_id=? AND not_after >= ? AND not_after <= ?",
                (org_id, now, cutoff_30d),
            ).fetchone()[0]

            issuer_rows = conn.execute(
                "SELECT issuer, COUNT(*) as cnt FROM certificates WHERE org_id=? GROUP BY issuer ORDER BY cnt DESC",
                (org_id,),
            ).fetchall()

            validity_row = conn.execute(
                """
                SELECT AVG(
                    CAST((julianday(not_after) - julianday(not_before)) AS INTEGER)
                ) FROM certificates WHERE org_id=?
                """,
                (org_id,),
            ).fetchone()

        healthy = total - expired - expiring_soon
        by_issuer = {r["issuer"] or "Unknown": r["cnt"] for r in issuer_rows}
        avg_validity = round(validity_row[0] or 0, 1)

        return {
            "total": total,
            "expired": expired,
            "expiring_soon": expiring_soon,
            "healthy": max(0, healthy),
            "by_issuer": by_issuer,
            "avg_validity_days": avg_validity,
        }
