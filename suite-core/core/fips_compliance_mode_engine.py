"""FIPS Compliance Mode Engine — ALDECI.

GAP-042: Federal RFP gate. FIPS 140-3 mode toggle + PQC (NIST post-quantum)
inventory + legacy crypto usage scan + FedRAMP-ready evidence export.

Capabilities:
  - FIPS mode lifecycle: activate_fips_mode / deactivate_fips_mode
  - PQC algorithm registry (ML-KEM, ML-DSA, SPHINCS+ categories kem/signature/hybrid)
  - Legacy crypto usage scanning (rsa-2048/3072/4096, ecdsa-p256/384)
  - FIPS readiness score (0-100): weighted pqc_coverage (0.5) + no_legacy (0.3) + fips_mode_on (0.2)
  - FedRAMP audit evidence export (JSON)
  - Per-org_id isolation (multi-tenant), WAL+RLock thread safety

Compliance: FIPS 140-3, FedRAMP High, NIST SP 800-208, CNSA 2.0, NSM-10
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

_DEFAULT_DB_DIR = str(
    Path(__file__).resolve().parents[2] / ".fixops_data"
)

# NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA / SPHINCS+)
_PQC_ALGOS = {
    # ML-KEM (Key Encapsulation) — FIPS 203
    "ml-kem-512",
    "ml-kem-768",
    "ml-kem-1024",
    # ML-DSA (Digital Signature) — FIPS 204
    "ml-dsa-44",
    "ml-dsa-65",
    "ml-dsa-87",
    # SPHINCS+ / SLH-DSA — FIPS 205
    "sphincs+-sha2-128s",
    "sphincs+-sha2-128f",
    "sphincs+-sha2-192s",
    "sphincs+-sha2-192f",
    "sphincs+-sha2-256s",
    "sphincs+-sha2-256f",
    "sphincs+-shake-128s",
    "sphincs+-shake-128f",
    "sphincs+-shake-192s",
    "sphincs+-shake-192f",
    "sphincs+-shake-256s",
    "sphincs+-shake-256f",
}

# Legacy / classical algos vulnerable to Shor's algorithm
_LEGACY_ALGOS = {
    "rsa-2048",
    "rsa-3072",
    "rsa-4096",
    "ecdsa-p256",
    "ecdsa-p384",
    "ecdsa-p521",
    "dh-2048",
    "dh-3072",
    "dsa-2048",
}

_VALID_ALGOS = _PQC_ALGOS | _LEGACY_ALGOS
_VALID_CATEGORIES = {"kem", "signature", "hybrid"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_legacy(algo: str) -> bool:
    return algo.lower() in _LEGACY_ALGOS


def _is_pqc(algo: str) -> bool:
    return algo.lower() in _PQC_ALGOS


class FIPSComplianceModeEngine:
    """SQLite WAL-backed FIPS 140-3 compliance + PQC inventory engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/fips_compliance_mode.db
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path is None:
            db_path = str(Path(_DEFAULT_DB_DIR) / "fips_compliance_mode.db")
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
                CREATE TABLE IF NOT EXISTS fips_status (
                    id                 TEXT PRIMARY KEY,
                    org_id             TEXT NOT NULL UNIQUE,
                    fips_mode          INTEGER NOT NULL DEFAULT 0,
                    activated_at       TEXT,
                    last_verified_at   TEXT,
                    created_at         TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_fs_org
                    ON fips_status (org_id);

                CREATE TABLE IF NOT EXISTS crypto_usage_scan (
                    id           TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    scan_id      TEXT NOT NULL,
                    algo         TEXT NOT NULL,
                    legacy_flag  INTEGER NOT NULL DEFAULT 0,
                    file_ref     TEXT NOT NULL DEFAULT '',
                    created_at   TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_cus_org_scan
                    ON crypto_usage_scan (org_id, scan_id, legacy_flag);

                CREATE TABLE IF NOT EXISTS pqc_inventory (
                    id           TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    service_ref  TEXT NOT NULL,
                    algo         TEXT NOT NULL,
                    category     TEXT NOT NULL,
                    created_at   TEXT NOT NULL,
                    UNIQUE(org_id, service_ref, algo)
                );

                CREATE INDEX IF NOT EXISTS idx_pi_org
                    ON pqc_inventory (org_id, category, algo);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # FIPS mode lifecycle
    # ------------------------------------------------------------------

    def _emit(self, event: str, payload: Dict[str, Any]) -> None:
        if _get_tg_bus is None:
            return
        try:
            bus = _get_tg_bus()
            if bus:
                bus.emit(event, payload)
        except Exception:
            pass

    def activate_fips_mode(self, org_id: str) -> Dict[str, Any]:
        """Activate FIPS 140-3 mode for an org. Idempotent."""
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT id FROM fips_status WHERE org_id=?",
                    (org_id,),
                ).fetchone()
                if row is None:
                    rec_id = str(uuid.uuid4())
                    conn.execute(
                        """
                        INSERT INTO fips_status
                            (id, org_id, fips_mode, activated_at, last_verified_at, created_at)
                        VALUES (?, ?, 1, ?, ?, ?)
                        """,
                        (rec_id, org_id, now, now, now),
                    )
                else:
                    conn.execute(
                        """
                        UPDATE fips_status
                        SET fips_mode=1, activated_at=COALESCE(activated_at, ?), last_verified_at=?
                        WHERE org_id=?
                        """,
                        (now, now, org_id),
                    )
        self._emit(
            "FIPS_MODE_ACTIVATED",
            {
                "entity_type": "fips_status",
                "entity_id": org_id,
                "org_id": org_id,
                "source_engine": "fips_compliance_mode_engine",
            },
        )
        return self.get_fips_status(org_id)

    def deactivate_fips_mode(self, org_id: str) -> Dict[str, Any]:
        """Deactivate FIPS 140-3 mode for an org. Idempotent."""
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT id FROM fips_status WHERE org_id=?",
                    (org_id,),
                ).fetchone()
                if row is None:
                    rec_id = str(uuid.uuid4())
                    conn.execute(
                        """
                        INSERT INTO fips_status
                            (id, org_id, fips_mode, activated_at, last_verified_at, created_at)
                        VALUES (?, ?, 0, NULL, ?, ?)
                        """,
                        (rec_id, org_id, now, now),
                    )
                else:
                    conn.execute(
                        """
                        UPDATE fips_status
                        SET fips_mode=0, last_verified_at=?
                        WHERE org_id=?
                        """,
                        (now, org_id),
                    )
        self._emit(
            "FIPS_MODE_DEACTIVATED",
            {
                "entity_type": "fips_status",
                "entity_id": org_id,
                "org_id": org_id,
                "source_engine": "fips_compliance_mode_engine",
            },
        )
        return self.get_fips_status(org_id)

    def get_fips_status(self, org_id: str) -> Dict[str, Any]:
        """Return current FIPS status for an org (default: fips_mode=0)."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM fips_status WHERE org_id=?",
                (org_id,),
            ).fetchone()
        if row is None:
            return {
                "org_id": org_id,
                "fips_mode": 0,
                "activated_at": None,
                "last_verified_at": None,
                "created_at": None,
            }
        return dict(row)

    # ------------------------------------------------------------------
    # PQC inventory
    # ------------------------------------------------------------------

    def register_pqc_algo(
        self,
        org_id: str,
        service_ref: str,
        algo: str,
        category: str,
    ) -> Dict[str, Any]:
        """Register a PQC (or legacy) algorithm usage for a service."""
        algo_norm = algo.lower().strip()
        cat_norm = category.lower().strip()
        if algo_norm not in _VALID_ALGOS:
            raise ValueError(
                f"Invalid algo '{algo}'. Must be one of: {sorted(_VALID_ALGOS)}"
            )
        if cat_norm not in _VALID_CATEGORIES:
            raise ValueError(
                f"Invalid category '{category}'. Must be one of: {sorted(_VALID_CATEGORIES)}"
            )
        now = _now_iso()
        rec_id = str(uuid.uuid4())
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO pqc_inventory
                        (id, org_id, service_ref, algo, category, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (rec_id, org_id, service_ref, algo_norm, cat_norm, now),
                )
                row = conn.execute(
                    """
                    SELECT * FROM pqc_inventory
                    WHERE org_id=? AND service_ref=? AND algo=?
                    """,
                    (org_id, service_ref, algo_norm),
                ).fetchone()
        self._emit(
            "PQC_ALGO_REGISTERED",
            {
                "entity_type": "pqc_inventory",
                "entity_id": str(row["id"]) if row else rec_id,
                "org_id": org_id,
                "source_engine": "fips_compliance_mode_engine",
            },
        )
        return dict(row) if row else {}

    def list_pqc_inventory(
        self,
        org_id: str,
        category: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List PQC inventory entries, optionally filtered by category."""
        sql = "SELECT * FROM pqc_inventory WHERE org_id=?"
        params: List[Any] = [org_id]
        if category:
            cat_norm = category.lower().strip()
            if cat_norm not in _VALID_CATEGORIES:
                raise ValueError(
                    f"Invalid category '{category}'. "
                    f"Must be one of: {sorted(_VALID_CATEGORIES)}"
                )
            sql += " AND category=?"
            params.append(cat_norm)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Crypto usage scan
    # ------------------------------------------------------------------

    def scan_crypto_usage(self, org_id: str) -> Dict[str, Any]:
        """Scan pqc_inventory, detect legacy algos, persist a scan record.

        For each row in pqc_inventory for org_id:
          - Write a crypto_usage_scan row with legacy_flag=1 for legacy algos.
          - legacy_flag=0 for PQC algos.

        Idempotent: each call creates a new scan_id; historical scans preserved.
        """
        now = _now_iso()
        scan_id = str(uuid.uuid4())
        legacy_count = 0
        pqc_count = 0
        with self._lock:
            with self._conn() as conn:
                inv_rows = conn.execute(
                    "SELECT service_ref, algo FROM pqc_inventory WHERE org_id=?",
                    (org_id,),
                ).fetchall()
                for inv in inv_rows:
                    algo = inv["algo"]
                    legacy_flag = 1 if _is_legacy(algo) else 0
                    if legacy_flag:
                        legacy_count += 1
                    else:
                        pqc_count += 1
                    rec_id = str(uuid.uuid4())
                    conn.execute(
                        """
                        INSERT INTO crypto_usage_scan
                            (id, org_id, scan_id, algo, legacy_flag, file_ref, created_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            rec_id,
                            org_id,
                            scan_id,
                            algo,
                            legacy_flag,
                            inv["service_ref"],
                            now,
                        ),
                    )
        self._emit(
            "CRYPTO_USAGE_SCANNED",
            {
                "entity_type": "crypto_usage_scan",
                "entity_id": scan_id,
                "org_id": org_id,
                "source_engine": "fips_compliance_mode_engine",
            },
        )
        return {
            "scan_id": scan_id,
            "org_id": org_id,
            "scanned_at": now,
            "total_scanned": legacy_count + pqc_count,
            "legacy_count": legacy_count,
            "pqc_count": pqc_count,
        }

    def list_crypto_scans(
        self,
        org_id: str,
        scan_id: Optional[str] = None,
        legacy_only: bool = False,
    ) -> List[Dict[str, Any]]:
        """List crypto usage scan entries."""
        sql = "SELECT * FROM crypto_usage_scan WHERE org_id=?"
        params: List[Any] = [org_id]
        if scan_id:
            sql += " AND scan_id=?"
            params.append(scan_id)
        if legacy_only:
            sql += " AND legacy_flag=1"
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Readiness score
    # ------------------------------------------------------------------

    def fips_readiness_score(self, org_id: str) -> Dict[str, Any]:
        """FIPS/PQC readiness score 0-100.

        Formula: round(pqc_coverage * 0.5 + no_legacy * 0.3 + fips_mode_on * 0.2) * 100

        Where:
          - pqc_coverage = pqc_rows / total_rows  (1.0 if no rows)
          - no_legacy    = 1 - (legacy_rows / total_rows)  (1.0 if no rows)
          - fips_mode_on = 1 if fips_mode=1 else 0

        Edge cases:
          - No inventory + FIPS off → baseline (coverage/no_legacy default 1.0 each) → 80
          - All legacy + FIPS off → low
          - All ML-DSA + FIPS on → 100
        """
        with self._conn() as conn:
            total_row = conn.execute(
                "SELECT COUNT(*) as c FROM pqc_inventory WHERE org_id=?",
                (org_id,),
            ).fetchone()
            total = int(total_row["c"] or 0)

            pqc_rows = 0
            legacy_rows = 0
            if total > 0:
                inv = conn.execute(
                    "SELECT algo FROM pqc_inventory WHERE org_id=?",
                    (org_id,),
                ).fetchall()
                for r in inv:
                    if _is_legacy(r["algo"]):
                        legacy_rows += 1
                    elif _is_pqc(r["algo"]):
                        pqc_rows += 1

            fips_row = conn.execute(
                "SELECT fips_mode FROM fips_status WHERE org_id=?",
                (org_id,),
            ).fetchone()
            fips_mode_on = 1 if (fips_row and int(fips_row["fips_mode"]) == 1) else 0

        if total == 0:
            pqc_coverage = 1.0
            no_legacy = 1.0
        else:
            pqc_coverage = pqc_rows / total
            no_legacy = 1.0 - (legacy_rows / total)

        raw = (pqc_coverage * 0.5) + (no_legacy * 0.3) + (float(fips_mode_on) * 0.2)
        score = int(round(raw * 100))
        score = max(0, min(100, score))

        if score >= 90:
            level = "excellent"
        elif score >= 75:
            level = "good"
        elif score >= 50:
            level = "fair"
        elif score >= 25:
            level = "poor"
        else:
            level = "critical"

        return {
            "org_id": org_id,
            "score": score,
            "level": level,
            "pqc_coverage": round(pqc_coverage, 4),
            "no_legacy": round(no_legacy, 4),
            "fips_mode_on": fips_mode_on,
            "total_inventory": total,
            "pqc_rows": pqc_rows,
            "legacy_rows": legacy_rows,
            "weights": {"pqc_coverage": 0.5, "no_legacy": 0.3, "fips_mode": 0.2},
        }

    # ------------------------------------------------------------------
    # Evidence export
    # ------------------------------------------------------------------

    def export_fips_evidence(self, org_id: str) -> Dict[str, Any]:
        """Export JSON-serialisable FedRAMP/FIPS audit evidence.

        Shape:
          {
            "schema_version": "1.0",
            "org_id": str,
            "generated_at": iso,
            "fips_status": { ... },
            "readiness": { ... },
            "pqc_inventory": [ ... ],
            "latest_scan": { scan_id, scanned_at, total, legacy, pqc, entries: [ ... ] },
            "frameworks": [ "FIPS 140-3", "FedRAMP High", "NIST SP 800-208",
                            "CNSA 2.0", "NSM-10" ],
          }
        """
        status = self.get_fips_status(org_id)
        readiness = self.fips_readiness_score(org_id)
        inventory = self.list_pqc_inventory(org_id)

        with self._conn() as conn:
            latest = conn.execute(
                """
                SELECT scan_id, MAX(created_at) AS scanned_at
                FROM crypto_usage_scan
                WHERE org_id=?
                GROUP BY scan_id
                ORDER BY scanned_at DESC
                LIMIT 1
                """,
                (org_id,),
            ).fetchone()

        latest_scan: Dict[str, Any] = {}
        if latest and latest["scan_id"]:
            entries = self.list_crypto_scans(org_id, scan_id=latest["scan_id"])
            legacy = sum(1 for e in entries if e.get("legacy_flag") == 1)
            pqc = sum(1 for e in entries if e.get("legacy_flag") == 0)
            latest_scan = {
                "scan_id": latest["scan_id"],
                "scanned_at": latest["scanned_at"],
                "total": len(entries),
                "legacy": legacy,
                "pqc": pqc,
                "entries": entries,
            }

        return {
            "schema_version": "1.0",
            "org_id": org_id,
            "generated_at": _now_iso(),
            "fips_status": status,
            "readiness": readiness,
            "pqc_inventory": inventory,
            "latest_scan": latest_scan,
            "frameworks": [
                "FIPS 140-3",
                "FedRAMP High",
                "NIST SP 800-208",
                "CNSA 2.0",
                "NSM-10",
            ],
        }

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def stats(self, org_id: str) -> Dict[str, Any]:
        """Aggregate stats for an org."""
        with self._conn() as conn:
            inv_total = conn.execute(
                "SELECT COUNT(*) AS c FROM pqc_inventory WHERE org_id=?",
                (org_id,),
            ).fetchone()["c"]

            by_cat_rows = conn.execute(
                """
                SELECT category, COUNT(*) AS c FROM pqc_inventory
                WHERE org_id=? GROUP BY category
                """,
                (org_id,),
            ).fetchall()
            by_category = {r["category"]: int(r["c"]) for r in by_cat_rows}

            by_algo_rows = conn.execute(
                """
                SELECT algo, COUNT(*) AS c FROM pqc_inventory
                WHERE org_id=? GROUP BY algo
                """,
                (org_id,),
            ).fetchall()
            by_algo = {r["algo"]: int(r["c"]) for r in by_algo_rows}

            legacy_count = conn.execute(
                "SELECT COUNT(*) AS c FROM crypto_usage_scan WHERE org_id=? AND legacy_flag=1",
                (org_id,),
            ).fetchone()["c"]
            scan_total = conn.execute(
                "SELECT COUNT(*) AS c FROM crypto_usage_scan WHERE org_id=?",
                (org_id,),
            ).fetchone()["c"]

            scan_runs = conn.execute(
                "SELECT COUNT(DISTINCT scan_id) AS c FROM crypto_usage_scan WHERE org_id=?",
                (org_id,),
            ).fetchone()["c"]

        status = self.get_fips_status(org_id)
        readiness = self.fips_readiness_score(org_id)

        return {
            "org_id": org_id,
            "fips_mode": int(status.get("fips_mode", 0) or 0),
            "activated_at": status.get("activated_at"),
            "inventory_total": int(inv_total or 0),
            "inventory_by_category": by_category,
            "inventory_by_algo": by_algo,
            "scan_total_entries": int(scan_total or 0),
            "scan_legacy_entries": int(legacy_count or 0),
            "scan_runs": int(scan_runs or 0),
            "readiness_score": readiness["score"],
            "readiness_level": readiness["level"],
        }


_engine: Optional[FIPSComplianceModeEngine] = None


def get_engine() -> FIPSComplianceModeEngine:
    """Return process-wide singleton."""
    global _engine
    if _engine is None:
        _engine = FIPSComplianceModeEngine()
    return _engine
