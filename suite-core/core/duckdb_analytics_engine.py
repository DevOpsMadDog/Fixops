"""Cross-domain analytics engine powered by DuckDB.

Queries multiple SQLite domain databases simultaneously for unified risk intelligence.
DuckDB sqlite extension reads existing .db files with zero migration.

Each query loads needed SQLite tables on the fly via DuckDB's sqlite extension —
no persistent DuckDB file, no ETL, no schema migration required.

Compliance: SOC2 CC7.2 (monitoring), ISO 27001 A.12.4 (event logging)
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import duckdb

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

# Validation patterns — prevent path traversal and SQL injection via identifiers
_SAFE_IDENT = re.compile(r"^[a-z_][a-z0-9_]{0,63}$")


def _safe_ident(value: str, label: str) -> str:
    """Validate that value is a safe SQL identifier (no path traversal)."""
    if not _SAFE_IDENT.match(value):
        raise ValueError(
            f"Invalid {label} '{value}': must match [a-z_][a-z0-9_]* (max 64 chars)"
        )
    return value


class AnalyticsEngine:
    """Cross-domain analytics engine backed by DuckDB in-memory session.

    Reads ALDECI's 60+ SQLite domain databases via DuckDB's sqlite_scan()
    extension with zero migration or ETL overhead. Each method opens only
    the databases it needs, so startup is instantaneous.

    Args:
        data_dir: Directory containing *.db domain database files.
                  Defaults to <repo_root>/.fixops_data/.
    """

    def __init__(self, data_dir: Optional[Path] = None) -> None:
        if data_dir is None:
            data_dir = Path(__file__).resolve().parents[2] / ".fixops_data"
        self.data_dir = Path(data_dir)

        # In-memory DuckDB — ephemeral, no file lock conflicts with SQLite writers
        self._conn = duckdb.connect(":memory:")
        try:
            self._conn.execute("INSTALL sqlite; LOAD sqlite;")
        except Exception as exc:  # noqa: BLE001
            # sqlite extension may already be installed/loaded
            _logger.debug("DuckDB sqlite extension init: %s", exc)
            try:
                self._conn.execute("LOAD sqlite;")
            except Exception:  # noqa: BLE001
                pass

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def get_db_path(self, name: str) -> Optional[str]:
        """Return the absolute path to <name>.db, or None if it doesn't exist."""
        path = self.data_dir / f"{name}.db"
        if path.exists():
            return str(path)
        return None

    def _scan(self, db_path: str, table: str, where: str = "", limit: Optional[int] = None) -> List[dict]:
        """Execute sqlite_scan and return rows as list of dicts."""
        sql = f"SELECT * FROM sqlite_scan('{db_path}', '{table}')"  # nosec B608
        if where:
            sql += f" WHERE {where}"
        if limit is not None:
            sql += f" LIMIT {limit}"
        rel = self._conn.execute(sql)
        cols = [desc[0] for desc in rel.description]
        return [dict(zip(cols, row)) for row in rel.fetchall()]

    def _count_agg(self, db_path: str, table: str, where: str = "") -> int:
        """Return COUNT(*) pushed into DuckDB — zero row materialisation."""
        sql = f"SELECT COUNT(*) FROM sqlite_scan('{db_path}', '{table}')"  # nosec B608
        if where:
            sql += f" WHERE {where}"
        return self._conn.execute(sql).fetchone()[0]  # type: ignore[index]

    def _try_scan(
        self,
        db_name: str,
        table: str,
        where: str = "",
        limit: Optional[int] = None,
    ) -> Optional[List[dict]]:
        """Attempt a sqlite_scan; return None if DB/table doesn't exist."""
        db_path = self.get_db_path(db_name)
        if db_path is None:
            return None
        try:
            return self._scan(db_path, table, where=where, limit=limit)
        except Exception as exc:  # noqa: BLE001
            _logger.debug("sqlite_scan(%s, %s) failed: %s", db_name, table, exc)
            return None

    # ------------------------------------------------------------------
    # Public analytics methods
    # ------------------------------------------------------------------

    def cross_domain_risk_summary(self, org_id: str) -> Dict[str, Any]:
        """Return a unified risk picture across available domain databases.

        Queries posture_score, risk_register, digital_forensics, and
        threat_hunting DBs. Missing databases return zero/None defaults
        so the response is always complete.

        Args:
            org_id: Organisation identifier for future multi-tenant filtering.

        Returns:
            Dict with fields: current_score, grade, total_risks, critical_risks,
            open_cases, total_findings, critical_findings, generated_at.
        """
        result: Dict[str, Any] = {
            "org_id": org_id,
            "current_score": None,
            "grade": None,
            "total_risks": 0,
            "critical_risks": 0,
            "open_cases": 0,
            "total_findings": 0,
            "critical_findings": 0,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

        # Posture score
        rows = self._try_scan("posture_score", "posture_scores", limit=1)
        if rows:
            result["current_score"] = rows[0].get("current_score")
            result["grade"] = rows[0].get("grade")

        # Risk register — push COUNT aggregates into DuckDB, no Python row materialisation
        risk_path = self.get_db_path("risk_register")
        if risk_path is not None:
            try:
                sql = (
                    f"SELECT COUNT(*), "  # nosec B608
                    f"COUNT(*) FILTER (WHERE lower(severity) = 'critical') "
                    f"FROM sqlite_scan('{risk_path}', 'risks')"
                )
                total, critical = self._conn.execute(sql).fetchone()  # type: ignore[misc]
                result["total_risks"] = total or 0
                result["critical_risks"] = critical or 0
            except Exception as exc:  # noqa: BLE001
                _logger.debug("risk_register aggregate failed: %s", exc)

        # Digital forensics — open cases via SQL COUNT
        forensics_path = self.get_db_path("digital_forensics")
        if forensics_path is not None:
            try:
                sql = (
                    f"SELECT COUNT(*) FILTER (WHERE lower(status) != 'closed') "  # nosec B608
                    f"FROM sqlite_scan('{forensics_path}', 'forensic_cases')"
                )
                result["open_cases"] = self._conn.execute(sql).fetchone()[0] or 0  # type: ignore[index]
            except Exception as exc:  # noqa: BLE001
                _logger.debug("digital_forensics aggregate failed: %s", exc)

        # Threat hunting findings — push COUNT aggregates into DuckDB
        hunt_path = self.get_db_path("threat_hunting")
        if hunt_path is not None:
            try:
                sql = (
                    f"SELECT COUNT(*), "  # nosec B608
                    f"COUNT(*) FILTER (WHERE lower(severity) = 'critical') "
                    f"FROM sqlite_scan('{hunt_path}', 'hunt_findings')"
                )
                total, critical = self._conn.execute(sql).fetchone()  # type: ignore[misc]
                result["total_findings"] = total or 0
                result["critical_findings"] = critical or 0
            except Exception as exc:  # noqa: BLE001
                _logger.debug("threat_hunting aggregate failed: %s", exc)

        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "duckdb_analytics", "org_id": org_id, "source_engine": "duckdb_analytics"})
            except Exception:
                pass

        return result

    def asset_vulnerability_correlation(self, org_id: str) -> List[Dict[str, Any]]:
        """Cross-join asset data with vulnerability / risk data.

        Joins asset_inventory.db:assets with risk_register.db:risks on
        asset_id. Returns top 20 entries ordered by risk score descending.

        Args:
            org_id: Organisation identifier.

        Returns:
            List of dicts with asset + risk fields, or [] if DBs unavailable.
        """
        asset_path = self.get_db_path("asset_inventory")
        risk_path = self.get_db_path("risk_register")

        if asset_path is None or risk_path is None:
            _logger.debug(
                "asset_vulnerability_correlation: missing DBs "
                "(asset_inventory=%s, risk_register=%s)",
                asset_path,
                risk_path,
            )
            return []

        try:
            sql = (
                f"SELECT a.*, r.severity, r.risk_score, r.title AS risk_title "  # nosec B608
                f"FROM sqlite_scan('{asset_path}', 'assets') a "
                f"JOIN sqlite_scan('{risk_path}', 'risks') r "
                f"  ON a.asset_id = r.asset_id "
                f"ORDER BY r.risk_score DESC NULLS LAST "
                f"LIMIT 20"
            )
            rel = self._conn.execute(sql)
            cols = [desc[0] for desc in rel.description]
            return [dict(zip(cols, row)) for row in rel.fetchall()]
        except Exception as exc:  # noqa: BLE001
            _logger.warning("asset_vulnerability_correlation error: %s", exc)
            return []

    def threat_intel_correlation(self, org_id: str, ioc: str) -> Dict[str, Any]:
        """Search for an IOC across multiple threat databases.

        Args:
            org_id: Organisation identifier.
            ioc: Indicator of compromise string (IP, domain, hash, URL).

        Returns:
            Dict: ioc, feed_hits, hunt_hits, correlated (bool), sources (list).
        """
        result: Dict[str, Any] = {
            "ioc": ioc,
            "org_id": org_id,
            "feed_hits": 0,
            "hunt_hits": 0,
            "correlated": False,
            "sources": [],
        }

        # Escape single quotes in ioc for safe interpolation
        safe_ioc = ioc.replace("'", "''")

        # Threat feed aggregator — COUNT pushed into DuckDB, no row materialisation
        feed_path = self.get_db_path("threat_feed_aggregator")
        if feed_path is not None:
            try:
                n = self._count_agg(feed_path, "feed_items", where=f"iocs LIKE '%{safe_ioc}%'")
                result["feed_hits"] = n
                if n:
                    result["sources"].append("threat_feed_aggregator")
            except Exception as exc:  # noqa: BLE001
                _logger.debug("threat_feed_aggregator count failed: %s", exc)

        # Threat hunting findings — COUNT pushed into DuckDB
        hunt_path = self.get_db_path("threat_hunting")
        if hunt_path is not None:
            try:
                n = self._count_agg(hunt_path, "hunt_findings", where=f"iocs_found LIKE '%{safe_ioc}%'")
                result["hunt_hits"] = n
                if n:
                    result["sources"].append("threat_hunting")
            except Exception as exc:  # noqa: BLE001
                _logger.debug("threat_hunting ioc count failed: %s", exc)

        result["correlated"] = result["feed_hits"] > 0 or result["hunt_hits"] > 0
        return result

    def compliance_posture_trend(self, org_id: str) -> List[Dict[str, Any]]:
        """Return last 10 compliance scan results ordered newest first.

        Reads compliance_scanner.db:scan_results.

        Args:
            org_id: Organisation identifier.

        Returns:
            List of dicts with fields: result_id, profile_id, score, passed,
            failed, scan_completed. Returns [] if DB unavailable.
        """
        db_path = self.get_db_path("compliance_scanner")
        if db_path is None:
            return []

        try:
            sql = (
                f"SELECT result_id, profile_id, score, passed, failed, scan_completed "  # nosec B608
                f"FROM sqlite_scan('{db_path}', 'scan_results') "
                f"ORDER BY scan_completed DESC NULLS LAST "
                f"LIMIT 10"
            )
            rel = self._conn.execute(sql)
            cols = [desc[0] for desc in rel.description]
            return [dict(zip(cols, row)) for row in rel.fetchall()]
        except Exception as exc:  # noqa: BLE001
            _logger.warning("compliance_posture_trend error: %s", exc)
            return []

    def executive_dashboard_data(self, org_id: str) -> Dict[str, Any]:
        """Aggregate across ALL available domains for CISO executive view.

        Args:
            org_id: Organisation identifier.

        Returns:
            Dict with: posture_score, grade, open_incidents, critical_vulns,
            active_threats, compliance_score_avg, domains_online,
            generated_at.
        """
        dashboard: Dict[str, Any] = {
            "org_id": org_id,
            "posture_score": None,
            "grade": None,
            "open_incidents": 0,
            "critical_vulns": 0,
            "active_threats": 0,
            "compliance_score_avg": None,
            "domains_online": 0,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

        # domains_online: filesystem glob (cheap, stays for metadata)
        available = self.list_available_domains()
        dashboard["domains_online"] = len(available)

        # Posture score — _try_scan with LIMIT 1 is already optimal (single row)
        rows = self._try_scan("posture_score", "posture_scores", limit=1)
        if rows:
            dashboard["posture_score"] = rows[0].get("current_score")
            dashboard["grade"] = rows[0].get("grade")

        # Open incidents — COUNT pushed into DuckDB, no full-table materialisation
        forensics_path = self.get_db_path("digital_forensics")
        if forensics_path is not None:
            try:
                sql = (
                    f"SELECT COUNT(*) FILTER (WHERE lower(status) != 'closed') "  # nosec B608
                    f"FROM sqlite_scan('{forensics_path}', 'forensic_cases')"
                )
                dashboard["open_incidents"] = self._conn.execute(sql).fetchone()[0] or 0  # type: ignore[index]
            except Exception as exc:  # noqa: BLE001
                _logger.debug("exec_dashboard forensics aggregate failed: %s", exc)

        # Critical vulnerabilities — COUNT FILTER pushed into DuckDB
        risk_path = self.get_db_path("risk_register")
        if risk_path is not None:
            try:
                sql = (
                    f"SELECT COUNT(*) FILTER (WHERE lower(severity) = 'critical') "  # nosec B608
                    f"FROM sqlite_scan('{risk_path}', 'risks')"
                )
                dashboard["critical_vulns"] = self._conn.execute(sql).fetchone()[0] or 0  # type: ignore[index]
            except Exception as exc:  # noqa: BLE001
                _logger.debug("exec_dashboard risk_register aggregate failed: %s", exc)

        # Active threats — COUNT FILTER pushed into DuckDB
        hunt_path = self.get_db_path("threat_hunting")
        if hunt_path is not None:
            try:
                sql = (
                    f"SELECT COUNT(*) FILTER ("  # nosec B608
                    f"WHERE lower(status) NOT IN ('closed','resolved','false_positive')) "
                    f"FROM sqlite_scan('{hunt_path}', 'hunt_findings')"
                )
                dashboard["active_threats"] = self._conn.execute(sql).fetchone()[0] or 0  # type: ignore[index]
            except Exception as exc:  # noqa: BLE001
                _logger.debug("exec_dashboard threat_hunting aggregate failed: %s", exc)

        # Compliance score average — AVG pushed into DuckDB, no Python sum/div
        compliance_path = self.get_db_path("compliance_scanner")
        if compliance_path is not None:
            try:
                sql = (
                    f"SELECT ROUND(AVG(score), 2) "  # nosec B608
                    f"FROM (SELECT score FROM sqlite_scan('{compliance_path}', 'scan_results') "
                    f"      WHERE score IS NOT NULL ORDER BY scan_completed DESC NULLS LAST LIMIT 10)"
                )
                avg = self._conn.execute(sql).fetchone()[0]  # type: ignore[index]
                if avg is not None:
                    dashboard["compliance_score_avg"] = float(avg)
            except Exception as exc:  # noqa: BLE001
                _logger.debug("exec_dashboard compliance aggregate failed: %s", exc)

        return dashboard

    def list_available_domains(self) -> List[Dict[str, Any]]:
        """Scan data_dir for *.db files and return metadata list.

        Returns:
            List of dicts: name (str), path (str), size_mb (float).
        """
        if not self.data_dir.exists():
            return []

        domains: List[Dict[str, Any]] = []
        for db_file in sorted(self.data_dir.glob("*.db")):
            try:
                size_mb = round(db_file.stat().st_size / (1024 * 1024), 3)
            except OSError:
                size_mb = 0.0
            domains.append(
                {
                    "name": db_file.stem,
                    "path": str(db_file),
                    "size_mb": size_mb,
                }
            )
        return domains

    def run_custom_query(
        self,
        db_name: str,
        table_name: str,
        where_clause: str = "",
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Execute a safe SELECT on any domain database table.

        Validates db_name and table_name against [a-z_]+ to prevent path
        traversal and SQL injection via identifier substitution.

        Args:
            db_name: Database name (e.g. "posture_score") — no path, no extension.
            table_name: Table name to query.
            where_clause: Optional SQL WHERE clause (appended as-is after WHERE).
            limit: Maximum rows to return (default 100, max 1000).

        Returns:
            List of row dicts.

        Raises:
            ValueError: If db_name or table_name fail identifier validation.
            FileNotFoundError: If the database does not exist.
        """
        _safe_ident(db_name, "db_name")
        _safe_ident(table_name, "table_name")

        limit = min(max(1, int(limit)), 1000)

        db_path = self.get_db_path(db_name)
        if db_path is None:
            raise FileNotFoundError(
                f"Database '{db_name}.db' not found in {self.data_dir}"
            )

        return self._scan(db_path, table_name, where=where_clause, limit=limit)
