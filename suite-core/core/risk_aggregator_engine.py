"""Risk Aggregator Engine — ALDECI.

Aggregates risk scores from all security engines into a unified,
composite organisational risk posture with per-entity tracking,
heatmaps, threshold enforcement, and trend analysis.

Compliance: NIST CSF ID.RA, ISO/IEC 27001 A.8, SOC 2 CC3.2
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

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "risk_aggregator.db"
)

_VALID_ENTITY_TYPES = {"asset", "user", "network", "application", "vendor"}
_VALID_SEVERITIES = {"critical", "high", "medium", "low"}
_VALID_THRESHOLD_ACTIONS = {"alert", "escalate", "block"}


def _score_to_severity(score: float) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def _score_to_grade(score: float) -> str:
    if score <= 20:
        return "A"
    if score <= 40:
        return "B"
    if score <= 60:
        return "C"
    if score <= 80:
        return "D"
    return "F"


class RiskAggregatorEngine:
    """SQLite WAL-backed Risk Aggregator engine.

    Thread-safe via RLock.  Multi-tenant via org_id.
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
                CREATE TABLE IF NOT EXISTS risk_scores (
                    score_id      TEXT PRIMARY KEY,
                    org_id        TEXT NOT NULL,
                    source_engine TEXT NOT NULL DEFAULT '',
                    entity_type   TEXT NOT NULL DEFAULT 'asset',
                    entity_id     TEXT NOT NULL DEFAULT '',
                    entity_name   TEXT NOT NULL DEFAULT '',
                    risk_score    REAL NOT NULL DEFAULT 0,
                    risk_factors  TEXT NOT NULL DEFAULT '[]',
                    severity      TEXT NOT NULL DEFAULT 'low',
                    recorded_at   TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_rs_org
                    ON risk_scores (org_id, entity_type, severity);

                CREATE INDEX IF NOT EXISTS idx_rs_entity
                    ON risk_scores (org_id, entity_id);

                CREATE TABLE IF NOT EXISTS risk_thresholds (
                    threshold_id TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    entity_type  TEXT NOT NULL DEFAULT 'asset',
                    threshold    REAL NOT NULL DEFAULT 70,
                    action       TEXT NOT NULL DEFAULT 'alert',
                    created_at   TEXT NOT NULL,
                    updated_at   TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_rt_org
                    ON risk_thresholds (org_id, entity_type);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        for field in ("risk_factors",):
            if field in d and isinstance(d[field], str):
                try:
                    d[field] = json.loads(d[field])
                except (json.JSONDecodeError, TypeError):
                    pass
        return d

    # ------------------------------------------------------------------
    # Risk Scores
    # ------------------------------------------------------------------

    def record_risk_score(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Record a risk score for an entity.

        Required keys: entity_id, risk_score
        Optional keys: source_engine, entity_type, entity_name, risk_factors, severity
        """
        entity_type = data.get("entity_type", "asset")
        if entity_type not in _VALID_ENTITY_TYPES:
            raise ValueError(f"entity_type must be one of {_VALID_ENTITY_TYPES}")

        risk_score = float(data.get("risk_score", 0))
        if not (0 <= risk_score <= 100):
            raise ValueError("risk_score must be between 0 and 100")

        severity = data.get("severity") or _score_to_severity(risk_score)
        if severity not in _VALID_SEVERITIES:
            raise ValueError(f"severity must be one of {_VALID_SEVERITIES}")

        risk_factors = data.get("risk_factors", [])

        score_id = str(uuid.uuid4())
        now = self._now()
        row = {
            "score_id": score_id,
            "org_id": org_id,
            "source_engine": data.get("source_engine", ""),
            "entity_type": entity_type,
            "entity_id": data.get("entity_id", ""),
            "entity_name": data.get("entity_name", ""),
            "risk_score": risk_score,
            "risk_factors": json.dumps(risk_factors),
            "severity": severity,
            "recorded_at": now,
        }
        with self._lock, self._conn() as conn:
            conn.execute(
                """
                INSERT INTO risk_scores
                    (score_id, org_id, source_engine, entity_type, entity_id,
                     entity_name, risk_score, risk_factors, severity, recorded_at)
                VALUES
                    (:score_id, :org_id, :source_engine, :entity_type, :entity_id,
                     :entity_name, :risk_score, :risk_factors, :severity, :recorded_at)
                """,
                row,
            )
        result = dict(row)
        result["risk_factors"] = risk_factors
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("RISK_ASSESSED", {"entity_type": "risk_aggregator", "org_id": org_id, "source_engine": "risk_aggregator"})
            except Exception as exc:
                _logger.warning("RISK_ASSESSED emit failed: %s", exc)

        return result

    def list_risk_scores(
        self,
        org_id: str,
        entity_type: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """List latest risk scores, optionally filtered."""
        query = "SELECT * FROM risk_scores WHERE org_id = ?"
        params: list = [org_id]
        if entity_type:
            query += " AND entity_type = ?"
            params.append(entity_type)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        query += " ORDER BY recorded_at DESC LIMIT ?"
        params.append(limit)
        with self._lock, self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_entity_risk(self, org_id: str, entity_id: str) -> Dict[str, Any]:
        """Return the latest risk score and full history for an entity."""
        with self._lock, self._conn() as conn:
            rows = conn.execute(
                """
                SELECT * FROM risk_scores
                WHERE org_id = ? AND entity_id = ?
                ORDER BY recorded_at DESC
                """,
                (org_id, entity_id),
            ).fetchall()

        if not rows:
            return {"entity_id": entity_id, "latest": None, "history": []}

        history = [self._row_to_dict(r) for r in rows]
        return {
            "entity_id": entity_id,
            "entity_name": history[0].get("entity_name", ""),
            "entity_type": history[0].get("entity_type", ""),
            "latest": history[0],
            "history": history,
        }

    def get_risk_heatmap(self, org_id: str) -> Dict[str, Any]:
        """Return counts per entity_type per severity bucket."""
        with self._lock, self._conn() as conn:
            rows = conn.execute(
                """
                SELECT entity_type, severity, COUNT(*) AS cnt
                FROM risk_scores
                WHERE org_id = ?
                GROUP BY entity_type, severity
                """,
                (org_id,),
            ).fetchall()

        heatmap: Dict[str, Dict[str, int]] = {}
        for r in rows:
            et = r["entity_type"]
            sev = r["severity"]
            if et not in heatmap:
                heatmap[et] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            heatmap[et][sev] = r["cnt"]

        return {"org_id": org_id, "heatmap": heatmap}

    def get_top_risks(self, org_id: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Return the highest risk entities (latest score per entity)."""
        with self._lock, self._conn() as conn:
            rows = conn.execute(
                """
                SELECT rs.*
                FROM risk_scores rs
                INNER JOIN (
                    SELECT entity_id, MAX(recorded_at) AS max_ts
                    FROM risk_scores
                    WHERE org_id = ?
                    GROUP BY entity_id
                ) latest ON rs.entity_id = latest.entity_id
                         AND rs.recorded_at = latest.max_ts
                WHERE rs.org_id = ?
                ORDER BY rs.risk_score DESC
                LIMIT ?
                """,
                (org_id, org_id, limit),
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def calculate_org_risk_score(self, org_id: str) -> Dict[str, Any]:
        """Calculate composite organisational risk score (0-100) with trend."""
        with self._lock, self._conn() as conn:
            # Latest score per entity
            latest_rows = conn.execute(
                """
                SELECT rs.entity_type, rs.risk_score, rs.recorded_at
                FROM risk_scores rs
                INNER JOIN (
                    SELECT entity_id, MAX(recorded_at) AS max_ts
                    FROM risk_scores
                    WHERE org_id = ?
                    GROUP BY entity_id
                ) latest ON rs.entity_id = latest.entity_id
                         AND rs.recorded_at = latest.max_ts
                WHERE rs.org_id = ?
                """,
                (org_id, org_id),
            ).fetchall()

            # Previous period scores (for trend)
            previous_rows = conn.execute(
                """
                SELECT AVG(risk_score) AS avg_score
                FROM risk_scores
                WHERE org_id = ?
                  AND recorded_at < (
                      SELECT MIN(recorded_at) FROM (
                          SELECT recorded_at FROM risk_scores
                          WHERE org_id = ?
                          ORDER BY recorded_at DESC
                          LIMIT (SELECT COUNT(DISTINCT entity_id) FROM risk_scores WHERE org_id = ?)
                      )
                  )
                """,
                (org_id, org_id, org_id),
            ).fetchone()

        if not latest_rows:
            return {
                "org_id": org_id,
                "org_risk_score": 0,
                "grade": "A",
                "breakdown": {},
                "trend": "stable",
                "entity_count": 0,
            }

        scores = [r["risk_score"] for r in latest_rows]
        org_score = round(sum(scores) / len(scores), 2)
        grade = _score_to_grade(org_score)

        breakdown: Dict[str, float] = {}
        type_totals: Dict[str, list] = {}
        for r in latest_rows:
            et = r["entity_type"]
            type_totals.setdefault(et, []).append(r["risk_score"])
        for et, sc_list in type_totals.items():
            breakdown[et] = round(sum(sc_list) / len(sc_list), 2)

        # Trend
        prev_avg = previous_rows["avg_score"] if previous_rows else None
        if prev_avg is None:
            trend = "stable"
        elif org_score > prev_avg + 2:
            trend = "worsening"
        elif org_score < prev_avg - 2:
            trend = "improving"
        else:
            trend = "stable"

        return {
            "org_id": org_id,
            "org_risk_score": org_score,
            "grade": grade,
            "breakdown": breakdown,
            "trend": trend,
            "entity_count": len(scores),
        }

    # ------------------------------------------------------------------
    # Risk Thresholds
    # ------------------------------------------------------------------

    def create_risk_threshold(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a risk threshold rule.

        Required keys: entity_type, threshold, action
        """
        entity_type = data.get("entity_type", "asset")
        if entity_type not in _VALID_ENTITY_TYPES:
            raise ValueError(f"entity_type must be one of {_VALID_ENTITY_TYPES}")

        action = data.get("action", "alert")
        if action not in _VALID_THRESHOLD_ACTIONS:
            raise ValueError(f"action must be one of {_VALID_THRESHOLD_ACTIONS}")

        threshold = float(data.get("threshold", 70))
        if not (0 <= threshold <= 100):
            raise ValueError("threshold must be between 0 and 100")

        threshold_id = str(uuid.uuid4())
        now = self._now()
        row = {
            "threshold_id": threshold_id,
            "org_id": org_id,
            "entity_type": entity_type,
            "threshold": threshold,
            "action": action,
            "created_at": now,
            "updated_at": now,
        }
        with self._lock, self._conn() as conn:
            conn.execute(
                """
                INSERT INTO risk_thresholds
                    (threshold_id, org_id, entity_type, threshold, action,
                     created_at, updated_at)
                VALUES
                    (:threshold_id, :org_id, :entity_type, :threshold, :action,
                     :created_at, :updated_at)
                """,
                row,
            )
        return dict(row)

    def list_risk_thresholds(self, org_id: str) -> List[Dict[str, Any]]:
        """List all risk thresholds for an org."""
        with self._lock, self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM risk_thresholds WHERE org_id = ? ORDER BY created_at DESC",
                (org_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # Brain Graph Sync
    # ------------------------------------------------------------------

    def sync_from_brain_graph(
        self,
        org_id: str,
        brain_db_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Pull finding nodes from the brain graph and compute risk scores.

        Queries brain_nodes WHERE node_type = 'finding' AND (org_id = ? OR org_id IS NULL),
        derives a risk score from CVSS / severity / exposure stored in node properties,
        and records each as an entity risk score in the risk_scores table.

        Returns a summary dict with counts of processed and skipped nodes.
        """
        import os

        if brain_db_path is None:
            brain_db_path = os.environ.get(
                "FIXOPS_BRAIN_DB_PATH",
                str(Path(__file__).resolve().parents[2] / "data" / "fixops_brain.db"),
            )

        # CVSS → base risk (0–100)
        def _cvss_to_risk(cvss: float) -> float:
            # CVSS 0–10 → risk 0–100 with non-linear amplification for high scores
            if cvss >= 9.0:
                return 95.0
            if cvss >= 7.0:
                return 70.0 + (cvss - 7.0) / 2.0 * 25.0
            if cvss >= 4.0:
                return 30.0 + (cvss - 4.0) / 3.0 * 40.0
            return cvss / 4.0 * 30.0

        # Severity string → multiplier applied on top of CVSS-derived base
        _SEV_MULT = {
            "critical": 1.0,  # already at top of scale
            "high": 0.95,
            "medium": 0.75,
            "low": 0.50,
            "info": 0.25,
        }

        processed = 0
        skipped = 0
        errors = 0

        try:
            brain_conn = sqlite3.connect(brain_db_path, timeout=10)
            brain_conn.row_factory = sqlite3.Row
            try:
                rows = brain_conn.execute(
                    """
                    SELECT node_id, org_id, properties
                    FROM brain_nodes
                    WHERE node_type = 'finding'
                      AND (org_id = ? OR org_id IS NULL)
                    ORDER BY updated_at DESC
                    """,
                    (org_id,),
                ).fetchall()
            finally:
                brain_conn.close()
        except sqlite3.OperationalError as exc:
            _logger.warning("sync_from_brain_graph: cannot open brain db %s: %s", brain_db_path, exc)
            return {"org_id": org_id, "processed": 0, "skipped": 0, "errors": 1, "brain_db": brain_db_path}

        self._now()
        for row in rows:
            try:
                props: Dict[str, Any] = json.loads(row["properties"]) if row["properties"] else {}
                node_id: str = row["node_id"]

                # Use finding_id from properties; fall back to node_id suffix
                entity_id = props.get("finding_id") or node_id.replace("finding:", "")
                if not entity_id:
                    skipped += 1
                    continue

                # Derive CVSS score (look for multiple common field names)
                cvss_raw = (
                    props.get("cvss_score")
                    or props.get("cvss")
                    or props.get("base_score")
                    or 0.0
                )
                try:
                    cvss = float(cvss_raw)
                except (TypeError, ValueError):
                    cvss = 0.0
                cvss = max(0.0, min(10.0, cvss))

                # Severity string
                severity = str(props.get("severity", "medium")).lower()
                sev_mult = _SEV_MULT.get(severity, 0.75)

                # Exposure flag (e.g. internet-facing asset)
                exposure = props.get("exposure", "").lower()
                exposure_mult = 1.2 if exposure in ("internet", "public", "external") else 1.0

                # Base risk from CVSS; if no CVSS, fall back to severity mapping
                if cvss > 0.0:
                    base_risk = _cvss_to_risk(cvss)
                else:
                    base_risk = {
                        "critical": 85.0,
                        "high": 65.0,
                        "medium": 40.0,
                        "low": 20.0,
                        "info": 5.0,
                    }.get(severity, 40.0)

                risk_score = min(base_risk * sev_mult * exposure_mult, 100.0)
                risk_score = round(risk_score, 2)

                # Build risk factors list for traceability
                risk_factors = []
                if cvss > 0:
                    risk_factors.append(f"cvss:{cvss}")
                if severity:
                    risk_factors.append(f"severity:{severity}")
                if exposure:
                    risk_factors.append(f"exposure:{exposure}")
                cve_id = props.get("cve_id") or props.get("cve")
                if cve_id:
                    risk_factors.append(f"cve:{cve_id}")

                self.record_risk_score(
                    org_id=org_id,
                    data={
                        "entity_id": entity_id,
                        "entity_name": props.get("title") or props.get("name") or entity_id,
                        "entity_type": "application",
                        "source_engine": "brain_graph_sync",
                        "risk_score": risk_score,
                        "risk_factors": risk_factors,
                        "severity": severity if severity in _VALID_SEVERITIES else None,
                    },
                )
                processed += 1
            except Exception as exc:  # noqa: BLE001 — per-row error must not abort the batch
                _logger.warning("sync_from_brain_graph: error processing row %s: %s", row["node_id"] if row else "?", exc)
                errors += 1

        _logger.info(
            "sync_from_brain_graph: org=%s processed=%d skipped=%d errors=%d",
            org_id, processed, skipped, errors,
        )
        return {
            "org_id": org_id,
            "processed": processed,
            "skipped": skipped,
            "errors": errors,
            "brain_db": brain_db_path,
        }

    # ------------------------------------------------------------------
    # Score Breakdown (GAP-027)
    # ------------------------------------------------------------------

    def get_score_breakdown(
        self, org_id: str, entity_ref: str
    ) -> Dict[str, Any]:
        """Return all score contributors for an entity.

        Aggregates:
          - Latest risk_score + risk_factors from risk_scores (this engine)
          - Any vulnerability scoring breakdown (cvss/epss/kev/blast_radius/crown_jewel)
            from VulnerabilityScoringEngine for matching asset_id
        Returns dict with contributors list + composite snapshot.
        """
        contributors: List[Dict[str, Any]] = []
        base_score: Optional[float] = None
        severity: Optional[str] = None

        with self._lock, self._conn() as conn:
            latest = conn.execute(
                """SELECT * FROM risk_scores
                   WHERE org_id = ? AND entity_id = ?
                   ORDER BY recorded_at DESC LIMIT 1""",
                (org_id, entity_ref),
            ).fetchone()

        if latest:
            latest_dict = self._row_to_dict(latest)
            base_score = latest_dict.get("risk_score")
            severity = latest_dict.get("severity")
            for factor in latest_dict.get("risk_factors", []) or []:
                if isinstance(factor, str) and ":" in factor:
                    name, value = factor.split(":", 1)
                    contributors.append({
                        "source": "risk_aggregator",
                        "name": name,
                        "value": value,
                    })
                else:
                    contributors.append({
                        "source": "risk_aggregator",
                        "name": str(factor),
                        "value": None,
                    })

        # Pull from VulnerabilityScoringEngine if importable
        vuln_contributors: List[Dict[str, Any]] = []
        try:
            from core.vulnerability_scoring_engine import VulnerabilityScoringEngine

            vse = VulnerabilityScoringEngine()
            vuln_scores = vse.list_scores(org_id, asset_id=entity_ref)
            for vs in vuln_scores[:5]:  # cap
                vuln_contributors.append({
                    "source": "vulnerability_scoring_engine",
                    "vuln_score_id": vs.get("id"),
                    "composite_score": vs.get("composite_score"),
                    "cvss": vs.get("cvss_score"),
                    "epss": vs.get("epss_score"),
                    "kev_listed": bool(vs.get("kev_listed")),
                    "priority_tier": vs.get("priority_tier"),
                })
                breakdown = vse.get_score_breakdown(org_id, vs.get("id"))
                for b in breakdown:
                    vuln_contributors.append({
                        "source": "vulnerability_scoring_engine",
                        "name": b.get("factor_name"),
                        "value": b.get("factor_value"),
                        "weight": b.get("factor_weight"),
                        "contribution": b.get("contribution"),
                    })
        except Exception as exc:  # noqa: BLE001 — optional enrichment
            _logger.debug("get_score_breakdown: vuln scoring unavailable: %s", exc)

        contributors.extend(vuln_contributors)

        return {
            "org_id": org_id,
            "entity_ref": entity_ref,
            "base_risk_score": base_score,
            "severity": severity,
            "contributor_count": len(contributors),
            "contributors": contributors,
        }

    def get_aggregator_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated risk statistics."""
        with self._lock, self._conn() as conn:
            entity_count = conn.execute(
                "SELECT COUNT(DISTINCT entity_id) FROM risk_scores WHERE org_id = ?",
                (org_id,),
            ).fetchone()[0]

            high_risk_count = conn.execute(
                """
                SELECT COUNT(DISTINCT rs.entity_id)
                FROM risk_scores rs
                INNER JOIN (
                    SELECT entity_id, MAX(recorded_at) AS max_ts
                    FROM risk_scores WHERE org_id = ? GROUP BY entity_id
                ) latest ON rs.entity_id = latest.entity_id
                         AND rs.recorded_at = latest.max_ts
                WHERE rs.org_id = ? AND rs.severity IN ('critical', 'high')
                """,
                (org_id, org_id),
            ).fetchone()[0]

            last_updated_row = conn.execute(
                "SELECT MAX(recorded_at) FROM risk_scores WHERE org_id = ?",
                (org_id,),
            ).fetchone()

        org_score_data = self.calculate_org_risk_score(org_id)

        return {
            "org_id": org_id,
            "entities_tracked": entity_count,
            "high_risk_count": high_risk_count,
            "org_risk_score": org_score_data["org_risk_score"],
            "grade": org_score_data["grade"],
            "last_updated": last_updated_row[0] if last_updated_row else None,
        }
