"""
SecurityPostureBenchmarkingEngine — ALDECI.

Benchmarks security posture against industry frameworks (CIS, NIST, ISO 27001,
SOC 2, PCI-DSS, HIPAA, custom), tracks per-control results, and enables
peer-group comparison.

SQLite-backed, thread-safe, multi-tenant (per org_id).

Compliance: SOC2 CC4.1, NIST SP 800-53 CA-2 (security assessments).
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "security_posture_benchmarking.db"
)

VALID_FRAMEWORKS = frozenset({
    "cis", "nist", "iso27001", "soc2", "pci_dss", "hipaa", "custom"
})
VALID_CATEGORIES = frozenset({
    "network", "endpoint", "cloud", "identity", "application",
    "data", "operations", "compliance"
})
VALID_STATUSES = frozenset({"active", "archived", "draft"})
VALID_CONTROL_RESULTS = frozenset({"pass", "fail", "partial", "not_applicable"})
VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low"})
VALID_PEER_GROUPS = frozenset({
    "enterprise", "smb", "startup", "government", "healthcare", "finance", "retail"
})


class SecurityPostureBenchmarkingEngine:
    """
    SQLite-backed security posture benchmarking engine.

    All public methods are thread-safe via RLock.

    Args:
        db_path: Path to SQLite database. Defaults to
                 .fixops_data/security_posture_benchmarking.db.
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

                CREATE TABLE IF NOT EXISTS spb_benchmarks (
                    id                 TEXT PRIMARY KEY,
                    org_id             TEXT NOT NULL,
                    benchmark_name     TEXT NOT NULL,
                    framework          TEXT NOT NULL,
                    version            TEXT DEFAULT '',
                    category           TEXT NOT NULL,
                    total_controls     INTEGER DEFAULT 0,
                    passed_controls    INTEGER DEFAULT 0,
                    score              REAL DEFAULT 0.0,
                    industry_avg_score REAL DEFAULT 0.0,
                    percentile         INTEGER DEFAULT 50,
                    status             TEXT DEFAULT 'draft',
                    last_assessed      DATETIME,
                    created_at         DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_spb_bench_org
                    ON spb_benchmarks (org_id);

                CREATE INDEX IF NOT EXISTS idx_spb_bench_org_framework
                    ON spb_benchmarks (org_id, framework);

                CREATE TABLE IF NOT EXISTS spb_controls (
                    id           TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    benchmark_id TEXT NOT NULL,
                    control_id   TEXT DEFAULT '',
                    title        TEXT DEFAULT '',
                    description  TEXT DEFAULT '',
                    result       TEXT NOT NULL,
                    severity     TEXT NOT NULL,
                    remediation  TEXT DEFAULT '',
                    assessed_at  DATETIME NOT NULL,
                    created_at   DATETIME NOT NULL,
                    FOREIGN KEY (benchmark_id) REFERENCES spb_benchmarks(id)
                );

                CREATE INDEX IF NOT EXISTS idx_spb_ctrl_org_bench
                    ON spb_controls (org_id, benchmark_id);

                CREATE TABLE IF NOT EXISTS spb_comparisons (
                    id             TEXT PRIMARY KEY,
                    org_id         TEXT NOT NULL,
                    benchmark_id   TEXT NOT NULL,
                    peer_group     TEXT NOT NULL,
                    peer_avg_score REAL NOT NULL DEFAULT 0.0,
                    our_score      REAL NOT NULL DEFAULT 0.0,
                    gap            REAL NOT NULL DEFAULT 0.0,
                    percentile_rank INTEGER DEFAULT 50,
                    created_at     DATETIME NOT NULL,
                    FOREIGN KEY (benchmark_id) REFERENCES spb_benchmarks(id)
                );

                CREATE INDEX IF NOT EXISTS idx_spb_cmp_org_bench
                    ON spb_comparisons (org_id, benchmark_id);
                """
            )

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Benchmarks
    # ------------------------------------------------------------------

    def create_benchmark(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create a new benchmark record.

        data keys: benchmark_name (required), framework (required), category (required),
                   version, total_controls, score, industry_avg_score, percentile.
        Returns the created benchmark.
        Raises ValueError for invalid framework or category.
        """
        framework = data.get("framework", "")
        if framework not in VALID_FRAMEWORKS:
            raise ValueError(f"Invalid framework '{framework}'. Valid: {sorted(VALID_FRAMEWORKS)}")

        category = data.get("category", "")
        if category not in VALID_CATEGORIES:
            raise ValueError(f"Invalid category '{category}'. Valid: {sorted(VALID_CATEGORIES)}")

        now = datetime.now(timezone.utc).isoformat()
        rec_id = str(uuid.uuid4())
        benchmark_name = data.get("benchmark_name", "")
        version = data.get("version", "")
        total_controls = int(data.get("total_controls", 0))
        score = float(data.get("score", 0.0))
        industry_avg_score = float(data.get("industry_avg_score", 0.0))
        percentile = int(data.get("percentile", 50))
        status = data.get("status", "draft")
        if status not in VALID_STATUSES:
            status = "draft"

        with self._lock:
            with self._get_conn() as conn:
                conn.execute(
                    """
                    INSERT INTO spb_benchmarks
                        (id, org_id, benchmark_name, framework, version, category,
                         total_controls, passed_controls, score, industry_avg_score,
                         percentile, status, last_assessed, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, NULL, ?)
                    """,
                    (rec_id, org_id, benchmark_name, framework, version, category,
                     total_controls, score, industry_avg_score, percentile, status, now),
                )

        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("CONTROL_ASSESSED", {"entity_type": "security_posture_benchmarking", "org_id": org_id, "source_engine": "security_posture_benchmarking"})
            except Exception:
                pass

        return {
            "id": rec_id,
            "org_id": org_id,
            "benchmark_name": benchmark_name,
            "framework": framework,
            "version": version,
            "category": category,
            "total_controls": total_controls,
            "passed_controls": 0,
            "score": score,
            "industry_avg_score": industry_avg_score,
            "percentile": percentile,
            "status": status,
            "last_assessed": None,
            "created_at": now,
        }

    def list_benchmarks(
        self,
        org_id: str,
        framework: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return benchmarks for the org, optionally filtered by framework and status."""
        query = "SELECT * FROM spb_benchmarks WHERE org_id = ?"
        params: List[Any] = [org_id]

        if framework is not None:
            query += " AND framework = ?"
            params.append(framework)
        if status is not None:
            query += " AND status = ?"
            params.append(status)

        query += " ORDER BY created_at DESC"

        with self._lock:
            with self._get_conn() as conn:
                rows = conn.execute(query, params).fetchall()

        return [dict(r) for r in rows]

    def get_benchmark(self, org_id: str, benchmark_id: str) -> Optional[Dict[str, Any]]:
        """Return a single benchmark by id with org isolation, or None."""
        with self._lock:
            with self._get_conn() as conn:
                row = conn.execute(
                    "SELECT * FROM spb_benchmarks WHERE id = ? AND org_id = ?",
                    (benchmark_id, org_id),
                ).fetchone()

        return dict(row) if row else None

    def list_benchmarks_with_cis_fallback(
        self,
        org_id: str,
        framework: Optional[str] = None,
        status: Optional[str] = None,
        cis_db_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        """List org-registered benchmarks; if none, project the imported CIS
        Benchmark catalog as a derived benchmark library.

        - source="org_registered" when the org has registered its own benchmarks.
        - source="cis-benchmark-derived" when the response is projected from the
          imported CIS XCCDF catalog (real public data, not seeded).
        - source="empty" when neither side has any data.

        Each CIS-derived row is shaped to match the spb_benchmarks contract so
        the UI renders the same component. framework defaults to "cis"; category
        defaults to "compliance"; total_controls is the rule count;
        score/percentile are 0 (assessment not yet run for this org).

        Returns:
            {"benchmarks": [...], "total": N, "source": str, "cis_total_controls": N}
        """
        rows = self.list_benchmarks(org_id, framework=framework, status=status)
        if rows:
            return {"benchmarks": rows, "total": len(rows), "source": "org_registered"}

        # Engine has no rows for this org — try real CIS Benchmark side-DB.
        from pathlib import Path as _Path

        if cis_db_path is None:
            cis_db_path = str(_Path("data") / "cis_benchmark.db")
        if not _Path(cis_db_path).exists():
            return {
                "benchmarks": [],
                "total": 0,
                "source": "empty",
                "hint": "POST /api/v1/posture-benchmarking/import-cis to populate the CIS Benchmark catalog, "
                        "or create a benchmark manually via POST /api/v1/posture-benchmarking/benchmarks.",
            }

        # If the caller filtered for a non-CIS framework, the CIS fallback
        # cannot satisfy it — return structured empty.
        if framework and framework != "cis":
            return {
                "benchmarks": [],
                "total": 0,
                "source": "empty",
                "hint": (
                    f"No org benchmarks registered for framework={framework!r}. "
                    f"CIS Benchmark catalog is the only available public-source fallback "
                    f"(call POST /api/v1/posture-benchmarking/import-cis first)."
                ),
            }

        try:
            with sqlite3.connect(cis_db_path) as cis_conn:
                cis_conn.row_factory = sqlite3.Row
                cis_rows = cis_conn.execute(
                    """
                    SELECT benchmark_id,
                           benchmark_version,
                           benchmark_title,
                           COUNT(*) AS total_controls,
                           MAX(imported_at) AS last_imported
                    FROM cis_controls
                    GROUP BY benchmark_id, benchmark_version, benchmark_title
                    ORDER BY benchmark_id
                    """
                ).fetchall()
                total_controls_global = cis_conn.execute(
                    "SELECT COUNT(*) FROM cis_controls"
                ).fetchone()[0]
        except sqlite3.Error as exc:
            _logger.warning(
                "CIS-fallback read failed for %s: %s", cis_db_path, exc
            )
            return {
                "benchmarks": [],
                "total": 0,
                "source": "empty",
                "hint": "POST /api/v1/posture-benchmarking/import-cis to populate the CIS Benchmark catalog.",
            }

        if not cis_rows:
            return {
                "benchmarks": [],
                "total": 0,
                "source": "empty",
                "hint": "POST /api/v1/posture-benchmarking/import-cis to populate the CIS Benchmark catalog.",
            }

        derived: List[Dict[str, Any]] = []
        for r in cis_rows:
            bench_id_raw = (r["benchmark_id"] or "").strip()
            if not bench_id_raw:
                continue
            inferred_framework = "cis"
            if status and "draft" != status:
                # Derived rows have no assessment results yet — only "draft"
                # matches. Caller filtered to a different status.
                continue
            derived.append({
                "id": f"cis:{bench_id_raw}",
                "org_id": org_id,
                "benchmark_name": (r["benchmark_title"] or bench_id_raw)[:500],
                "framework": inferred_framework,
                "version": (r["benchmark_version"] or "")[:50],
                "category": "compliance",
                "total_controls": int(r["total_controls"] or 0),
                "passed_controls": 0,
                "score": 0.0,
                "industry_avg_score": 0.0,
                "percentile": 0,
                "status": "draft",
                "last_assessed": None,
                "created_at": r["last_imported"] or "",
                "source": "cis-benchmark",
                "source_benchmark_id": bench_id_raw,
            })

        return {
            "benchmarks": derived,
            "total": len(derived),
            "source": "cis-benchmark-derived",
            "cis_total_controls": int(total_controls_global or 0),
            "hint": (
                "Derived from imported CIS Benchmark catalog. Run an assessment via "
                "POST /api/v1/posture-benchmarking/benchmarks to record your own "
                "scores, or POST /api/v1/posture-benchmarking/controls to record "
                "individual control results."
            ),
        }

    # ------------------------------------------------------------------
    # Controls
    # ------------------------------------------------------------------

    def record_control(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Record a control assessment result.

        data keys: benchmark_id (required), control_id, title, description,
                   result (required), severity (required), remediation.
        Updates the benchmark's passed_controls count and score.
        Raises ValueError for invalid result or severity.
        """
        result = data.get("result", "")
        if result not in VALID_CONTROL_RESULTS:
            raise ValueError(f"Invalid result '{result}'. Valid: {sorted(VALID_CONTROL_RESULTS)}")

        severity = data.get("severity", "")
        if severity not in VALID_SEVERITIES:
            raise ValueError(f"Invalid severity '{severity}'. Valid: {sorted(VALID_SEVERITIES)}")

        now = datetime.now(timezone.utc).isoformat()
        rec_id = str(uuid.uuid4())
        benchmark_id = data.get("benchmark_id", "")
        control_id = data.get("control_id", "")
        title = data.get("title", "")
        description = data.get("description", "")
        remediation = data.get("remediation", "")

        with self._lock:
            with self._get_conn() as conn:
                conn.execute(
                    """
                    INSERT INTO spb_controls
                        (id, org_id, benchmark_id, control_id, title, description,
                         result, severity, remediation, assessed_at, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (rec_id, org_id, benchmark_id, control_id, title, description,
                     result, severity, remediation, now, now),
                )

                # Recompute score from controls
                counts = conn.execute(
                    """
                    SELECT
                        COUNT(*) as total,
                        SUM(CASE WHEN result = 'pass' THEN 1 ELSE 0 END) as passed
                    FROM spb_controls
                    WHERE org_id = ? AND benchmark_id = ?
                    """,
                    (org_id, benchmark_id),
                ).fetchone()

                total = counts["total"] or 0
                passed = counts["passed"] or 0
                new_score = round((passed / total) * 100.0, 2) if total > 0 else 0.0

                conn.execute(
                    """
                    UPDATE spb_benchmarks
                    SET total_controls = ?, passed_controls = ?, score = ?
                    WHERE id = ? AND org_id = ?
                    """,
                    (total, passed, new_score, benchmark_id, org_id),
                )

        return {
            "id": rec_id,
            "org_id": org_id,
            "benchmark_id": benchmark_id,
            "control_id": control_id,
            "title": title,
            "description": description,
            "result": result,
            "severity": severity,
            "remediation": remediation,
            "assessed_at": now,
            "created_at": now,
        }

    def list_controls(
        self,
        org_id: str,
        benchmark_id: Optional[str] = None,
        result: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return controls for the org, optionally filtered by benchmark, result, severity."""
        query = "SELECT * FROM spb_controls WHERE org_id = ?"
        params: List[Any] = [org_id]

        if benchmark_id is not None:
            query += " AND benchmark_id = ?"
            params.append(benchmark_id)
        if result is not None:
            query += " AND result = ?"
            params.append(result)
        if severity is not None:
            query += " AND severity = ?"
            params.append(severity)

        query += " ORDER BY assessed_at DESC"

        with self._lock:
            with self._get_conn() as conn:
                rows = conn.execute(query, params).fetchall()

        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Comparisons
    # ------------------------------------------------------------------

    def add_comparison(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Add a peer-group comparison for a benchmark.

        data keys: benchmark_id (required), peer_group (required),
                   peer_avg_score, our_score, percentile_rank.
        Computes gap = our_score - peer_avg_score.
        Raises ValueError for invalid peer_group.
        """
        peer_group = data.get("peer_group", "")
        if peer_group not in VALID_PEER_GROUPS:
            raise ValueError(
                f"Invalid peer_group '{peer_group}'. Valid: {sorted(VALID_PEER_GROUPS)}"
            )

        now = datetime.now(timezone.utc).isoformat()
        rec_id = str(uuid.uuid4())
        benchmark_id = data.get("benchmark_id", "")
        peer_avg_score = float(data.get("peer_avg_score", 0.0))
        our_score = float(data.get("our_score", 0.0))
        gap = round(our_score - peer_avg_score, 2)
        percentile_rank = int(data.get("percentile_rank", 50))

        with self._lock:
            with self._get_conn() as conn:
                conn.execute(
                    """
                    INSERT INTO spb_comparisons
                        (id, org_id, benchmark_id, peer_group, peer_avg_score,
                         our_score, gap, percentile_rank, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (rec_id, org_id, benchmark_id, peer_group, peer_avg_score,
                     our_score, gap, percentile_rank, now),
                )

        return {
            "id": rec_id,
            "org_id": org_id,
            "benchmark_id": benchmark_id,
            "peer_group": peer_group,
            "peer_avg_score": peer_avg_score,
            "our_score": our_score,
            "gap": gap,
            "percentile_rank": percentile_rank,
            "created_at": now,
        }

    def list_comparisons(
        self, org_id: str, benchmark_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Return comparisons for the org, optionally filtered by benchmark_id."""
        query = "SELECT * FROM spb_comparisons WHERE org_id = ?"
        params: List[Any] = [org_id]

        if benchmark_id is not None:
            query += " AND benchmark_id = ?"
            params.append(benchmark_id)

        query += " ORDER BY created_at DESC"

        with self._lock:
            with self._get_conn() as conn:
                rows = conn.execute(query, params).fetchall()

        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Assessment lifecycle
    # ------------------------------------------------------------------

    def complete_assessment(self, org_id: str, benchmark_id: str) -> Dict[str, Any]:
        """
        Mark a benchmark assessment complete.

        Sets last_assessed=now, status=active, recomputes score from controls.
        Returns the updated benchmark or empty dict if not found.
        """
        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            with self._get_conn() as conn:
                counts = conn.execute(
                    """
                    SELECT
                        COUNT(*) as total,
                        SUM(CASE WHEN result = 'pass' THEN 1 ELSE 0 END) as passed
                    FROM spb_controls
                    WHERE org_id = ? AND benchmark_id = ?
                    """,
                    (org_id, benchmark_id),
                ).fetchone()

                total = counts["total"] or 0
                passed = counts["passed"] or 0
                new_score = round((passed / total) * 100.0, 2) if total > 0 else 0.0

                conn.execute(
                    """
                    UPDATE spb_benchmarks
                    SET last_assessed = ?, status = 'active',
                        total_controls = ?, passed_controls = ?, score = ?
                    WHERE id = ? AND org_id = ?
                    """,
                    (now, total, passed, new_score, benchmark_id, org_id),
                )

                row = conn.execute(
                    "SELECT * FROM spb_benchmarks WHERE id = ? AND org_id = ?",
                    (benchmark_id, org_id),
                ).fetchone()

        return dict(row) if row else {}

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_benchmarking_stats(self, org_id: str) -> Dict[str, Any]:
        """
        Return aggregate benchmarking statistics for the org.

        Keys: total_benchmarks, active_benchmarks, avg_score,
              above_industry_avg, critical_failures, by_framework, by_category.
        """
        with self._lock:
            with self._get_conn() as conn:
                agg = conn.execute(
                    """
                    SELECT
                        COUNT(*) as total,
                        SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) as active,
                        AVG(score) as avg_score,
                        SUM(CASE WHEN score > industry_avg_score THEN 1 ELSE 0 END) as above_avg
                    FROM spb_benchmarks WHERE org_id = ?
                    """,
                    (org_id,),
                ).fetchone()

                critical_failures = conn.execute(
                    """
                    SELECT COUNT(*) FROM spb_controls
                    WHERE org_id = ? AND result = 'fail' AND severity = 'critical'
                    """,
                    (org_id,),
                ).fetchone()[0]

                by_framework_rows = conn.execute(
                    """
                    SELECT framework, COUNT(*) as cnt
                    FROM spb_benchmarks WHERE org_id = ?
                    GROUP BY framework
                    """,
                    (org_id,),
                ).fetchall()

                by_category_rows = conn.execute(
                    """
                    SELECT category, COUNT(*) as cnt
                    FROM spb_benchmarks WHERE org_id = ?
                    GROUP BY category
                    """,
                    (org_id,),
                ).fetchall()

        by_framework = {r["framework"]: r["cnt"] for r in by_framework_rows}
        by_category = {r["category"]: r["cnt"] for r in by_category_rows}

        return {
            "total_benchmarks": agg["total"] or 0,
            "active_benchmarks": agg["active"] or 0,
            "avg_score": round(float(agg["avg_score"] or 0.0), 2),
            "above_industry_avg": agg["above_avg"] or 0,
            "critical_failures": critical_failures or 0,
            "by_framework": by_framework,
            "by_category": by_category,
        }
