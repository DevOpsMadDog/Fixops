"""Data Lake Security Engine — ALDECI.

Tracks data store security posture, access patterns, and exfiltration risk
across cloud data lakes (S3, GCS, Blob, HDFS, Snowflake, Redshift).

Compliance: NIST SP 800-53 SC-28, ISO/IEC 27001 A.8.2, SOC 2 CC6.7
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "data_lake_security.db"
)

_VALID_STORE_TYPES = {"s3", "gcs", "blob", "hdfs", "snowflake", "redshift"}
_VALID_CLASSIFICATIONS = {"public", "internal", "confidential", "restricted"}
_VALID_ACCESS_TYPES = {"read", "write", "delete", "admin"}

# Risk weights for assessment
_ISSUE_WEIGHTS = {
    "no_encryption_at_rest": 30,
    "no_access_logging": 20,
    "public_data_store": 25,
    "restricted_no_encryption": 40,
    "restricted_no_logging": 30,
    "confidential_public": 35,
}


class DataLakeSecurityEngine:
    """SQLite WAL-backed Data Lake Security engine.

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
                CREATE TABLE IF NOT EXISTS data_stores (
                    store_id            TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    name                TEXT NOT NULL DEFAULT '',
                    store_type          TEXT NOT NULL DEFAULT 's3',
                    classification      TEXT NOT NULL DEFAULT 'internal',
                    encryption_at_rest  INTEGER NOT NULL DEFAULT 1,
                    access_logging      INTEGER NOT NULL DEFAULT 1,
                    registered_at       TEXT NOT NULL,
                    updated_at          TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ds_org_class
                    ON data_stores (org_id, classification);

                CREATE TABLE IF NOT EXISTS access_patterns (
                    pattern_id      TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    store_id        TEXT NOT NULL,
                    user_or_role    TEXT NOT NULL DEFAULT '',
                    access_type     TEXT NOT NULL DEFAULT 'read',
                    bytes_accessed  INTEGER NOT NULL DEFAULT 0,
                    is_anomalous    INTEGER NOT NULL DEFAULT 0,
                    recorded_at     TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ap_org_store
                    ON access_patterns (org_id, store_id, recorded_at DESC);
                CREATE INDEX IF NOT EXISTS idx_ap_org_anomalous
                    ON access_patterns (org_id, is_anomalous, recorded_at DESC);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    # ------------------------------------------------------------------
    # Data Store CRUD
    # ------------------------------------------------------------------

    def register_data_store(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a data store with classification and security config."""
        store_type = data.get("store_type", "s3")
        if store_type not in _VALID_STORE_TYPES:
            store_type = "s3"
        classification = data.get("classification", "internal")
        if classification not in _VALID_CLASSIFICATIONS:
            classification = "internal"

        store_id = str(uuid.uuid4())
        now = self._now()
        record: Dict[str, Any] = {
            "store_id": store_id,
            "org_id": org_id,
            "name": str(data.get("name", "")),
            "store_type": store_type,
            "classification": classification,
            "encryption_at_rest": 1 if bool(data.get("encryption_at_rest", True)) else 0,
            "access_logging": 1 if bool(data.get("access_logging", True)) else 0,
            "registered_at": now,
            "updated_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO data_stores
                       (store_id, org_id, name, store_type, classification,
                        encryption_at_rest, access_logging, registered_at, updated_at)
                       VALUES
                       (:store_id,:org_id,:name,:store_type,:classification,
                        :encryption_at_rest,:access_logging,:registered_at,:updated_at)""",
                    record,
                )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "data_lake_security", "org_id": org_id, "source_engine": "data_lake_security"})
            except Exception:
                pass

        return self._fmt_store(record)

    def list_data_stores(
        self,
        org_id: str,
        classification: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List data stores with optional classification filter."""
        sql = "SELECT * FROM data_stores WHERE org_id=?"
        params: list = [org_id]
        if classification:
            sql += " AND classification=?"
            params.append(classification)
        sql += " ORDER BY registered_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._fmt_store(dict(r)) for r in rows]

    def _get_store(self, org_id: str, store_id: str) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM data_stores WHERE org_id=? AND store_id=?",
                (org_id, store_id),
            ).fetchone()
        return self._fmt_store(dict(row)) if row else None

    # ------------------------------------------------------------------
    # Security Assessment
    # ------------------------------------------------------------------

    def run_security_assessment(self, org_id: str, store_id: str) -> Dict[str, Any]:
        """Run a security assessment on a data store.

        Returns findings list and security_score 0-100.
        """
        store = self._get_store(org_id, store_id)
        if not store:
            return {
                "store_id": store_id,
                "org_id": org_id,
                "findings": [{"issue": "store_not_found", "severity": "critical",
                               "recommendation": "Register the data store first"}],
                "security_score": 0,
                "assessed_at": self._now(),
            }

        findings = []
        deductions = 0

        enc = store["encryption_at_rest"]
        log = store["access_logging"]
        cls = store["classification"]

        if not enc:
            weight = _ISSUE_WEIGHTS["no_encryption_at_rest"]
            if cls in ("restricted", "confidential"):
                weight = _ISSUE_WEIGHTS.get(f"{cls}_no_encryption", weight + 10)
            findings.append({
                "issue": "no_encryption_at_rest",
                "severity": "critical" if cls in ("restricted", "confidential") else "high",
                "recommendation": "Enable server-side encryption (SSE-KMS or equivalent)",
            })
            deductions += weight

        if not log:
            weight = _ISSUE_WEIGHTS["no_access_logging"]
            if cls == "restricted":
                weight = _ISSUE_WEIGHTS["restricted_no_logging"]
            findings.append({
                "issue": "no_access_logging",
                "severity": "high" if cls in ("restricted", "confidential") else "medium",
                "recommendation": "Enable access logging to detect unauthorised access",
            })
            deductions += weight

        if cls == "public":
            findings.append({
                "issue": "public_classification",
                "severity": "medium",
                "recommendation": "Confirm data truly needs public exposure; consider internal classification",
            })
            deductions += _ISSUE_WEIGHTS["no_encryption_at_rest"] // 3

        if cls == "restricted" and not enc:
            findings.append({
                "issue": "restricted_data_unencrypted",
                "severity": "critical",
                "recommendation": "Restricted data MUST be encrypted at rest immediately",
            })
            # already counted above

        if cls == "confidential" and cls == "public":
            findings.append({
                "issue": "confidential_data_public",
                "severity": "critical",
                "recommendation": "Reclassify or restrict access immediately",
            })
            deductions += _ISSUE_WEIGHTS["confidential_public"]

        score = max(0, 100 - deductions)
        return {
            "store_id": store_id,
            "org_id": org_id,
            "store": store,
            "findings": findings,
            "security_score": score,
            "assessed_at": self._now(),
        }

    # ------------------------------------------------------------------
    # Access Patterns
    # ------------------------------------------------------------------

    def record_access_pattern(
        self,
        org_id: str,
        store_id: str,
        data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Record an access event for a data store."""
        access_type = data.get("access_type", "read")
        if access_type not in _VALID_ACCESS_TYPES:
            access_type = "read"

        pattern_id = str(uuid.uuid4())
        now = self._now()
        record: Dict[str, Any] = {
            "pattern_id": pattern_id,
            "org_id": org_id,
            "store_id": store_id,
            "user_or_role": str(data.get("user_or_role", "")),
            "access_type": access_type,
            "bytes_accessed": int(data.get("bytes_accessed", 0)),
            "is_anomalous": 1 if bool(data.get("is_anomalous", False)) else 0,
            "recorded_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO access_patterns
                       (pattern_id, org_id, store_id, user_or_role, access_type,
                        bytes_accessed, is_anomalous, recorded_at)
                       VALUES
                       (:pattern_id,:org_id,:store_id,:user_or_role,:access_type,
                        :bytes_accessed,:is_anomalous,:recorded_at)""",
                    record,
                )
        return self._fmt_pattern(record)

    def get_access_patterns(
        self,
        org_id: str,
        store_id: str,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """Return recent access patterns for a store."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM access_patterns WHERE org_id=? AND store_id=? "
                "ORDER BY recorded_at DESC LIMIT ?",
                (org_id, store_id, limit),
            ).fetchall()
        return [self._fmt_pattern(dict(r)) for r in rows]

    # ------------------------------------------------------------------
    # Exfiltration Risk
    # ------------------------------------------------------------------

    def detect_data_exfiltration_risk(self, org_id: str, store_id: str) -> Dict[str, Any]:
        """Compute exfiltration risk score and indicators for a store."""
        store = self._get_store(org_id, store_id)
        if not store:
            return {"store_id": store_id, "risk_score": 0, "indicators": [],
                    "error": "store_not_found"}

        with self._conn() as conn:
            # Anomalous accesses in last 24h (approximate — using last 50 records)
            patterns = conn.execute(
                "SELECT * FROM access_patterns WHERE org_id=? AND store_id=? "
                "ORDER BY recorded_at DESC LIMIT 200",
                (org_id, store_id),
            ).fetchall()

        indicators = []
        risk_score = 0

        anomalous = [p for p in patterns if p["is_anomalous"]]
        delete_ops = [p for p in patterns if p["access_type"] == "delete"]
        admin_ops = [p for p in patterns if p["access_type"] == "admin"]
        large_reads = [p for p in patterns if p["bytes_accessed"] > 1_000_000_000]  # >1GB

        if anomalous:
            indicators.append({
                "indicator": "anomalous_access_detected",
                "count": len(anomalous),
                "severity": "high",
            })
            risk_score += min(40, len(anomalous) * 10)

        if delete_ops:
            indicators.append({
                "indicator": "bulk_delete_operations",
                "count": len(delete_ops),
                "severity": "medium",
            })
            risk_score += min(20, len(delete_ops) * 5)

        if admin_ops:
            indicators.append({
                "indicator": "admin_access_recorded",
                "count": len(admin_ops),
                "severity": "medium",
            })
            risk_score += min(15, len(admin_ops) * 5)

        if large_reads:
            total_bytes = sum(p["bytes_accessed"] for p in large_reads)
            indicators.append({
                "indicator": "large_data_reads",
                "count": len(large_reads),
                "total_bytes": total_bytes,
                "severity": "high",
            })
            risk_score += min(30, len(large_reads) * 10)

        # Classification risk bump
        if store["classification"] == "restricted":
            risk_score = min(100, int(risk_score * 1.5))
        elif store["classification"] == "confidential":
            risk_score = min(100, int(risk_score * 1.25))

        if not store["encryption_at_rest"]:
            indicators.append({
                "indicator": "unencrypted_store",
                "severity": "critical",
            })
            risk_score = min(100, risk_score + 20)

        return {
            "store_id": store_id,
            "org_id": org_id,
            "risk_score": min(100, risk_score),
            "indicators": indicators,
            "assessed_at": self._now(),
        }

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_data_lake_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregate data lake security stats for the org."""
        with self._conn() as conn:
            store_rows = conn.execute(
                "SELECT classification, encryption_at_rest, COUNT(*) as cnt "
                "FROM data_stores WHERE org_id=? GROUP BY classification, encryption_at_rest",
                (org_id,),
            ).fetchall()

            total_stores = conn.execute(
                "SELECT COUNT(*) FROM data_stores WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            unencrypted = conn.execute(
                "SELECT COUNT(*) FROM data_stores WHERE org_id=? AND encryption_at_rest=0",
                (org_id,),
            ).fetchone()[0]

            # Anomalous accesses — approximate last 24h via last 500 records
            anomalous_24h = conn.execute(
                "SELECT COUNT(*) FROM access_patterns "
                "WHERE org_id=? AND is_anomalous=1 "
                "AND recorded_at >= datetime('now','-1 day')",
                (org_id,),
            ).fetchone()[0]

        by_classification: Dict[str, int] = {}
        for r in store_rows:
            cls = r["classification"]
            by_classification[cls] = by_classification.get(cls, 0) + int(r["cnt"])

        return {
            "org_id": org_id,
            "stores": total_stores,
            "by_classification": by_classification,
            "unencrypted_count": unencrypted,
            "anomalous_accesses_24h": anomalous_24h,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _fmt_store(row: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "store_id": row.get("store_id", ""),
            "org_id": row.get("org_id", ""),
            "name": row.get("name", ""),
            "store_type": row.get("store_type", ""),
            "classification": row.get("classification", ""),
            "encryption_at_rest": bool(row.get("encryption_at_rest", 1)),
            "access_logging": bool(row.get("access_logging", 1)),
            "registered_at": row.get("registered_at", ""),
            "updated_at": row.get("updated_at", ""),
        }

    @staticmethod
    def _fmt_pattern(row: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "pattern_id": row.get("pattern_id", ""),
            "org_id": row.get("org_id", ""),
            "store_id": row.get("store_id", ""),
            "user_or_role": row.get("user_or_role", ""),
            "access_type": row.get("access_type", ""),
            "bytes_accessed": int(row.get("bytes_accessed", 0)),
            "is_anomalous": bool(row.get("is_anomalous", 0)),
            "recorded_at": row.get("recorded_at", ""),
        }
