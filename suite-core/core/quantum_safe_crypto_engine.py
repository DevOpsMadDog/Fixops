"""
QuantumSafeCryptoEngine — ALDECI.

Tracks cryptographic assets, assesses quantum vulnerability, and manages
migration to post-quantum algorithms (CRYSTALS-Kyber, CRYSTALS-Dilithium,
FALCON, SPHINCS+).

SQLite-backed, thread-safe, multi-tenant (per org_id).

Compliance: NIST SP 800-208 (post-quantum standards), FIPS 203/204/205.
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "quantum_safe_crypto.db"
)

VALID_ASSET_TYPES = frozenset({
    "tls_certificate", "vpn", "signing_key", "encryption_key",
    "code_signing", "database_encryption", "api_key", "ssh_key"
})

# Algorithms considered quantum-vulnerable (based on Shor's algorithm threat)
QUANTUM_VULNERABLE_ALGORITHMS = frozenset({"rsa", "ecdsa", "dh"})

VALID_ALGORITHMS = frozenset({
    "rsa", "ecdsa", "dh", "aes", "3des", "sha1", "sha256", "sha384", "sha512"
})

VALID_MIGRATION_STATUSES = frozenset({
    "not_started", "planned", "in_progress", "completed", "exempt"
})

VALID_RISK_LEVELS = frozenset({"critical", "high", "medium", "low"})

VALID_ASSESSMENT_STATUSES = frozenset({"planned", "running", "completed"})

VALID_MIGRATION_PRIORITIES = frozenset({"immediate", "high", "medium", "low", "scheduled"})

VALID_MIGRATION_RUN_STATUSES = frozenset({
    "planned", "in_progress", "testing", "completed", "failed"
})

# Recommended PQC algorithms per classical algorithm
_RECOMMENDED_PQC = {
    "rsa": "CRYSTALS-Dilithium",
    "ecdsa": "CRYSTALS-Dilithium",
    "dh": "CRYSTALS-Kyber",
    "aes": "AES-256",
    "3des": "AES-256",
    "sha1": "SHA-384",
    "sha256": "SHA-384",
    "sha384": "none",
    "sha512": "none",
}


class QuantumSafeCryptoEngine:
    """
    SQLite-backed quantum-safe crypto migration management engine.

    All public methods are thread-safe via RLock.

    Args:
        db_path: Path to SQLite database. Defaults to
                 .fixops_data/quantum_safe_crypto.db.
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
        with self._get_conn() as conn:
            conn.executescript(
                """
                PRAGMA journal_mode=WAL;

                CREATE TABLE IF NOT EXISTS qsc_assets (
                    id                   TEXT PRIMARY KEY,
                    org_id               TEXT NOT NULL,
                    asset_name           TEXT NOT NULL,
                    asset_type           TEXT NOT NULL,
                    current_algorithm    TEXT NOT NULL,
                    key_size             INTEGER DEFAULT 0,
                    quantum_vulnerable   INTEGER NOT NULL DEFAULT 0,
                    recommended_algorithm TEXT DEFAULT 'none',
                    migration_status     TEXT DEFAULT 'not_started',
                    risk_level           TEXT DEFAULT 'low',
                    discovered_at        DATETIME NOT NULL,
                    migrated_at          DATETIME,
                    created_at           DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_qsc_assets_org
                    ON qsc_assets (org_id);

                CREATE INDEX IF NOT EXISTS idx_qsc_assets_org_type
                    ON qsc_assets (org_id, asset_type);

                CREATE TABLE IF NOT EXISTS qsc_assessments (
                    id                      TEXT PRIMARY KEY,
                    org_id                  TEXT NOT NULL,
                    assessment_name         TEXT NOT NULL,
                    scope                   TEXT DEFAULT '',
                    total_assets            INTEGER DEFAULT 0,
                    vulnerable_assets       INTEGER DEFAULT 0,
                    migrated_assets         INTEGER DEFAULT 0,
                    quantum_readiness_score REAL DEFAULT 0.0,
                    status                  TEXT DEFAULT 'planned',
                    assessed_at             DATETIME,
                    created_at              DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_qsc_assess_org
                    ON qsc_assessments (org_id);

                CREATE TABLE IF NOT EXISTS qsc_migrations (
                    id             TEXT PRIMARY KEY,
                    org_id         TEXT NOT NULL,
                    asset_id       TEXT NOT NULL,
                    from_algorithm TEXT NOT NULL DEFAULT '',
                    to_algorithm   TEXT NOT NULL DEFAULT '',
                    priority       TEXT NOT NULL DEFAULT 'medium',
                    status         TEXT NOT NULL DEFAULT 'planned',
                    planned_date   DATETIME,
                    completed_date DATETIME,
                    migrated_by    TEXT DEFAULT '',
                    created_at     DATETIME NOT NULL,
                    FOREIGN KEY (asset_id) REFERENCES qsc_assets(id)
                );

                CREATE INDEX IF NOT EXISTS idx_qsc_mig_org_asset
                    ON qsc_migrations (org_id, asset_id);
                """
            )

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Assets
    # ------------------------------------------------------------------

    def register_asset(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Register a cryptographic asset.

        data keys: asset_name (required), asset_type (required),
                   current_algorithm (required), key_size, risk_level,
                   migration_status, discovered_at.
        Sets quantum_vulnerable based on current_algorithm.
        Sets recommended_algorithm based on current_algorithm.
        Raises ValueError for invalid asset_type, current_algorithm, or migration_status.
        """
        asset_type = data.get("asset_type", "")
        if asset_type not in VALID_ASSET_TYPES:
            raise ValueError(
                f"Invalid asset_type '{asset_type}'. Valid: {sorted(VALID_ASSET_TYPES)}"
            )

        current_algorithm = data.get("current_algorithm", "")
        if current_algorithm not in VALID_ALGORITHMS:
            raise ValueError(
                f"Invalid current_algorithm '{current_algorithm}'. "
                f"Valid: {sorted(VALID_ALGORITHMS)}"
            )

        migration_status = data.get("migration_status", "not_started")
        if migration_status not in VALID_MIGRATION_STATUSES:
            raise ValueError(
                f"Invalid migration_status '{migration_status}'. "
                f"Valid: {sorted(VALID_MIGRATION_STATUSES)}"
            )

        now = datetime.now(timezone.utc).isoformat()
        rec_id = str(uuid.uuid4())
        asset_name = data.get("asset_name", "")
        key_size = int(data.get("key_size", 0))
        quantum_vulnerable = current_algorithm in QUANTUM_VULNERABLE_ALGORITHMS
        recommended_algorithm = _RECOMMENDED_PQC.get(current_algorithm, "none")
        risk_level = data.get("risk_level", "low")
        if risk_level not in VALID_RISK_LEVELS:
            risk_level = "low"
        _raw_discovered_at = data.get("discovered_at")
        discovered_at = _raw_discovered_at if _raw_discovered_at is not None else now

        with self._lock:
            with self._get_conn() as conn:
                conn.execute(
                    """
                    INSERT INTO qsc_assets
                        (id, org_id, asset_name, asset_type, current_algorithm,
                         key_size, quantum_vulnerable, recommended_algorithm,
                         migration_status, risk_level, discovered_at, migrated_at, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)
                    """,
                    (rec_id, org_id, asset_name, asset_type, current_algorithm,
                     key_size, int(quantum_vulnerable), recommended_algorithm,
                     migration_status, risk_level, discovered_at, now),
                )

        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ASSET_DISCOVERED", {"entity_type": "quantum_safe_crypto", "org_id": org_id, "source_engine": "quantum_safe_crypto"})
            except Exception:
                pass

        return {
            "id": rec_id,
            "org_id": org_id,
            "asset_name": asset_name,
            "asset_type": asset_type,
            "current_algorithm": current_algorithm,
            "key_size": key_size,
            "quantum_vulnerable": quantum_vulnerable,
            "recommended_algorithm": recommended_algorithm,
            "migration_status": migration_status,
            "risk_level": risk_level,
            "discovered_at": discovered_at,
            "migrated_at": None,
            "created_at": now,
        }

    def list_assets(
        self,
        org_id: str,
        asset_type: Optional[str] = None,
        quantum_vulnerable: Optional[bool] = None,
        migration_status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return assets for the org, optionally filtered."""
        query = "SELECT * FROM qsc_assets WHERE org_id = ?"
        params: List[Any] = [org_id]

        if asset_type is not None:
            query += " AND asset_type = ?"
            params.append(asset_type)
        if quantum_vulnerable is not None:
            query += " AND quantum_vulnerable = ?"
            params.append(int(quantum_vulnerable))
        if migration_status is not None:
            query += " AND migration_status = ?"
            params.append(migration_status)

        query += " ORDER BY created_at DESC"

        with self._lock:
            with self._get_conn() as conn:
                rows = conn.execute(query, params).fetchall()

        result = []
        for r in rows:
            d = dict(r)
            d["quantum_vulnerable"] = bool(d.get("quantum_vulnerable", 0))
            result.append(d)
        return result

    def get_asset(self, org_id: str, asset_id: str) -> Optional[Dict[str, Any]]:
        """Return a single asset by id with org isolation, or None."""
        with self._lock:
            with self._get_conn() as conn:
                row = conn.execute(
                    "SELECT * FROM qsc_assets WHERE id = ? AND org_id = ?",
                    (asset_id, org_id),
                ).fetchone()

        if not row:
            return None
        d = dict(row)
        d["quantum_vulnerable"] = bool(d.get("quantum_vulnerable", 0))
        return d

    def update_migration_status(
        self,
        org_id: str,
        asset_id: str,
        migration_status: str,
        migrated_at: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Update migration_status on an asset.

        Raises ValueError for invalid migration_status.
        Returns updated asset or None if not found.
        """
        if migration_status not in VALID_MIGRATION_STATUSES:
            raise ValueError(
                f"Invalid migration_status '{migration_status}'. "
                f"Valid: {sorted(VALID_MIGRATION_STATUSES)}"
            )

        now = datetime.now(timezone.utc).isoformat()
        effective_migrated_at = migrated_at if migrated_at else (
            now if migration_status == "completed" else None
        )

        with self._lock:
            with self._get_conn() as conn:
                conn.execute(
                    """
                    UPDATE qsc_assets
                    SET migration_status = ?, migrated_at = ?
                    WHERE id = ? AND org_id = ?
                    """,
                    (migration_status, effective_migrated_at, asset_id, org_id),
                )
                row = conn.execute(
                    "SELECT * FROM qsc_assets WHERE id = ? AND org_id = ?",
                    (asset_id, org_id),
                ).fetchone()

        if not row:
            return None
        d = dict(row)
        d["quantum_vulnerable"] = bool(d.get("quantum_vulnerable", 0))
        return d

    # ------------------------------------------------------------------
    # Assessments
    # ------------------------------------------------------------------

    def create_assessment(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create a quantum readiness assessment.

        data keys: assessment_name (required), scope.
        Status defaults to "planned".
        """
        now = datetime.now(timezone.utc).isoformat()
        rec_id = str(uuid.uuid4())
        assessment_name = data.get("assessment_name", "")
        scope = data.get("scope", "")
        status = "planned"

        with self._lock:
            with self._get_conn() as conn:
                conn.execute(
                    """
                    INSERT INTO qsc_assessments
                        (id, org_id, assessment_name, scope, total_assets,
                         vulnerable_assets, migrated_assets, quantum_readiness_score,
                         status, assessed_at, created_at)
                    VALUES (?, ?, ?, ?, 0, 0, 0, 0.0, ?, NULL, ?)
                    """,
                    (rec_id, org_id, assessment_name, scope, status, now),
                )

        return {
            "id": rec_id,
            "org_id": org_id,
            "assessment_name": assessment_name,
            "scope": scope,
            "total_assets": 0,
            "vulnerable_assets": 0,
            "migrated_assets": 0,
            "quantum_readiness_score": 0.0,
            "status": status,
            "assessed_at": None,
            "created_at": now,
        }

    def complete_assessment(
        self,
        org_id: str,
        assessment_id: str,
        total_assets: int,
        vulnerable_assets: int,
        migrated_assets: int,
    ) -> Dict[str, Any]:
        """
        Complete an assessment with asset counts.

        Computes quantum_readiness_score = migrated_assets/total_assets*100 if total_assets>0.
        Sets status=completed, assessed_at=now.
        Returns updated assessment or empty dict if not found.
        """
        now = datetime.now(timezone.utc).isoformat()
        score = (migrated_assets / total_assets * 100.0) if total_assets > 0 else 0.0
        score = round(score, 2)

        with self._lock:
            with self._get_conn() as conn:
                conn.execute(
                    """
                    UPDATE qsc_assessments
                    SET total_assets = ?, vulnerable_assets = ?, migrated_assets = ?,
                        quantum_readiness_score = ?, status = 'completed', assessed_at = ?
                    WHERE id = ? AND org_id = ?
                    """,
                    (total_assets, vulnerable_assets, migrated_assets, score, now,
                     assessment_id, org_id),
                )
                row = conn.execute(
                    "SELECT * FROM qsc_assessments WHERE id = ? AND org_id = ?",
                    (assessment_id, org_id),
                ).fetchone()

        return dict(row) if row else {}

    def list_assessments(
        self, org_id: str, status: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Return assessments for the org, optionally filtered by status."""
        query = "SELECT * FROM qsc_assessments WHERE org_id = ?"
        params: List[Any] = [org_id]

        if status is not None:
            query += " AND status = ?"
            params.append(status)

        query += " ORDER BY created_at DESC"

        with self._lock:
            with self._get_conn() as conn:
                rows = conn.execute(query, params).fetchall()

        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Migrations
    # ------------------------------------------------------------------

    def create_migration(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create a migration plan for an asset.

        data keys: asset_id (required), from_algorithm, to_algorithm,
                   priority, planned_date, migrated_by.
        Status defaults to "planned".
        Raises ValueError for invalid priority.
        """
        priority = data.get("priority", "medium")
        if priority not in VALID_MIGRATION_PRIORITIES:
            raise ValueError(
                f"Invalid priority '{priority}'. Valid: {sorted(VALID_MIGRATION_PRIORITIES)}"
            )

        now = datetime.now(timezone.utc).isoformat()
        rec_id = str(uuid.uuid4())
        asset_id = data.get("asset_id", "")
        from_algorithm = data.get("from_algorithm", "")
        to_algorithm = data.get("to_algorithm", "")
        planned_date = data.get("planned_date")
        migrated_by = data.get("migrated_by", "")

        with self._lock:
            with self._get_conn() as conn:
                conn.execute(
                    """
                    INSERT INTO qsc_migrations
                        (id, org_id, asset_id, from_algorithm, to_algorithm,
                         priority, status, planned_date, completed_date, migrated_by, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, 'planned', ?, NULL, ?, ?)
                    """,
                    (rec_id, org_id, asset_id, from_algorithm, to_algorithm,
                     priority, planned_date, migrated_by, now),
                )

        return {
            "id": rec_id,
            "org_id": org_id,
            "asset_id": asset_id,
            "from_algorithm": from_algorithm,
            "to_algorithm": to_algorithm,
            "priority": priority,
            "status": "planned",
            "planned_date": planned_date,
            "completed_date": None,
            "migrated_by": migrated_by,
            "created_at": now,
        }

    def list_migrations(
        self,
        org_id: str,
        asset_id: Optional[str] = None,
        status: Optional[str] = None,
        priority: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return migrations for the org, optionally filtered."""
        query = "SELECT * FROM qsc_migrations WHERE org_id = ?"
        params: List[Any] = [org_id]

        if asset_id is not None:
            query += " AND asset_id = ?"
            params.append(asset_id)
        if status is not None:
            query += " AND status = ?"
            params.append(status)
        if priority is not None:
            query += " AND priority = ?"
            params.append(priority)

        query += " ORDER BY created_at DESC"

        with self._lock:
            with self._get_conn() as conn:
                rows = conn.execute(query, params).fetchall()

        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_quantum_stats(self, org_id: str) -> Dict[str, Any]:
        """
        Return aggregate quantum crypto statistics for the org.

        Keys: total_assets, quantum_vulnerable, migrated, migration_progress_pct,
              critical_vulnerable, by_asset_type, by_migration_status, by_current_algorithm.
        """
        with self._lock:
            with self._get_conn() as conn:
                agg = conn.execute(
                    """
                    SELECT
                        COUNT(*) as total,
                        SUM(quantum_vulnerable) as vulnerable,
                        SUM(CASE WHEN migration_status = 'completed' THEN 1 ELSE 0 END) as migrated
                    FROM qsc_assets WHERE org_id = ?
                    """,
                    (org_id,),
                ).fetchone()

                critical_vulnerable = conn.execute(
                    """
                    SELECT COUNT(*) FROM qsc_assets
                    WHERE org_id = ? AND quantum_vulnerable = 1 AND risk_level = 'critical'
                    """,
                    (org_id,),
                ).fetchone()[0]

                by_type_rows = conn.execute(
                    """
                    SELECT asset_type, COUNT(*) as cnt
                    FROM qsc_assets WHERE org_id = ?
                    GROUP BY asset_type
                    """,
                    (org_id,),
                ).fetchall()

                by_status_rows = conn.execute(
                    """
                    SELECT migration_status, COUNT(*) as cnt
                    FROM qsc_assets WHERE org_id = ?
                    GROUP BY migration_status
                    """,
                    (org_id,),
                ).fetchall()

                by_algo_rows = conn.execute(
                    """
                    SELECT current_algorithm, COUNT(*) as cnt
                    FROM qsc_assets WHERE org_id = ?
                    GROUP BY current_algorithm
                    """,
                    (org_id,),
                ).fetchall()

        total = agg["total"] or 0
        vulnerable = agg["vulnerable"] or 0
        migrated = agg["migrated"] or 0
        progress_pct = round((migrated / total) * 100.0, 2) if total > 0 else 0.0

        return {
            "total_assets": total,
            "quantum_vulnerable": vulnerable,
            "migrated": migrated,
            "migration_progress_pct": progress_pct,
            "critical_vulnerable": critical_vulnerable or 0,
            "by_asset_type": {r["asset_type"]: r["cnt"] for r in by_type_rows},
            "by_migration_status": {r["migration_status"]: r["cnt"] for r in by_status_rows},
            "by_current_algorithm": {r["current_algorithm"]: r["cnt"] for r in by_algo_rows},
        }
