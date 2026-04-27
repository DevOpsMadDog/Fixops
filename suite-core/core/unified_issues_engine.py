"""Unified Issues Engine — ALDECI (GAP-049 + GAP-066).

Federation layer that queries existing domain tables (security_findings,
exposure_cases, at_alerts) and normalises them into a single issue shape
for a unified /issues queue, counts, and diff-mode UI.

This is *not* a new domain engine with its own tables. It deliberately
re-uses the DB files already produced by:

    - ``core.security_findings_engine.SecurityFindingsEngine``
      → ``.fixops_data/security_findings_engine.db`` (table ``security_findings``)
    - ``core.exposure_case.ExposureCaseManager``
      → ``fixops_exposure_cases.db`` (table ``exposure_cases``)
    - ``core.alert_triage_engine.AlertTriageEngine``
      → ``.fixops_data/alert_triage.db`` (table ``at_alerts``)

Missing source tables degrade gracefully — they contribute zero rows.

GAP-049: unified /issues queue
GAP-066: diff-mode across scans using GAP-063 lifecycle columns.

Compliance: NIST SP 800-53 (unified finding view), ISO 27001 A.12.6.
"""
from __future__ import annotations

import json
import logging
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

_logger = logging.getLogger(__name__)

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


# Default DB paths — mirror what the source engines use.
_FIXOPS_DATA = Path(__file__).resolve().parents[2] / ".fixops_data"
_DEFAULT_FINDINGS_DB = str(_FIXOPS_DATA / "security_findings_engine.db")
_DEFAULT_ALERTS_DB = str(_FIXOPS_DATA / "alert_triage.db")
# ExposureCaseManager uses ``fixops_exposure_cases.db`` relative to CWD, which
# for this repo resolves to the repo root.
_DEFAULT_EXPOSURES_DB = str(Path(__file__).resolve().parents[2] / "fixops_exposure_cases.db")


_NORMALIZED_STATUSES = {
    # canonical normalized set — these are what callers filter on
    "open", "in_progress", "resolved", "suppressed", "false_positive",
    "new", "triaging", "escalated", "investigating", "duplicate",
    "closed", "accepted_risk", "fixing",
}
_NORMALIZED_SEVERITIES = {"critical", "high", "medium", "low", "info", "informational"}
_NORMALIZED_SOURCES = {"findings", "exposures", "alerts"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _severity_from_priority(priority: Optional[str]) -> str:
    """Map alert-triage p1..p4 priority back to a severity bucket for filtering."""
    return {
        "p1": "critical", "p2": "high", "p3": "medium", "p4": "low",
    }.get((priority or "").lower(), "medium")


def _normalize_status(source: str, raw: Optional[str]) -> str:
    """Normalize per-engine status strings to the unified set."""
    s = (raw or "").strip().lower().replace("-", "_")
    # security_findings lifecycle uses "in-progress", exposure uses "open"/"triaging"...
    # the normalised form keeps both but collapses hyphens → underscores.
    return s or "open"


class UnifiedIssuesEngine:
    """Federation over findings + exposures + alerts, no new tables."""

    def __init__(
        self,
        findings_db: str = _DEFAULT_FINDINGS_DB,
        exposures_db: str = _DEFAULT_EXPOSURES_DB,
        alerts_db: str = _DEFAULT_ALERTS_DB,
    ) -> None:
        self.findings_db = findings_db
        self.exposures_db = exposures_db
        self.alerts_db = alerts_db
        self._lock = threading.RLock()
        # Pipeline → Issues bridge: refresh epoch is bumped every time the
        # event_bus delivers FINDINGS_INDEX_REFRESH or PIPELINE_COMPLETED.
        # The /api/v1/issues/index-state endpoint reads this so the UI can
        # auto-poll without admin clicking "Refresh Finding Index".
        self._refresh_epoch: int = 0
        self._last_refresh_at: Optional[str] = None
        self._last_refresh_run_id: Optional[str] = None
        self._last_findings_mirrored: int = 0
        self._subscribed: bool = False
        self._subscribe_to_pipeline_events()

    def _subscribe_to_pipeline_events(self) -> None:
        """Subscribe to brain-pipeline events so the federation index refreshes
        automatically when the pipeline finishes mirroring findings.

        Failure to subscribe is non-fatal — the engine still works, just without
        push-style refresh signals.
        """
        if self._subscribed:
            return
        try:
            from core.event_bus import EventType, get_event_bus  # noqa: PLC0415
            bus = get_event_bus()
            bus.subscribe(EventType.FINDINGS_INDEX_REFRESH, self._on_refresh_event)
            bus.subscribe(EventType.PIPELINE_COMPLETED, self._on_refresh_event)
            self._subscribed = True
            _logger.info(
                "unified_issues: subscribed to pipeline → issues bridge "
                "(FINDINGS_INDEX_REFRESH + PIPELINE_COMPLETED)"
            )
        except (ImportError, AttributeError, RuntimeError) as exc:
            _logger.warning(
                "unified_issues: pipeline event subscription skipped: %s",
                exc,
            )

    def _on_refresh_event(self, data: Dict[str, Any]) -> None:
        """Sync subscriber — bumps refresh epoch and records last refresh
        metadata. The event_bus runs sync subscribers in an executor so this
        does not block the pipeline.
        """
        with self._lock:
            self._refresh_epoch += 1
            self._last_refresh_at = _now_iso()
            self._last_refresh_run_id = (
                data.get("run_id") if isinstance(data, dict) else None
            )
            mirrored = (
                data.get("findings_mirrored")
                if isinstance(data, dict) and "findings_mirrored" in data
                else (data.get("findings_mirrored_to_dashboard")
                      if isinstance(data, dict) else None)
            )
            if isinstance(mirrored, int):
                self._last_findings_mirrored = mirrored

    def index_state(self) -> Dict[str, Any]:
        """Return current refresh-epoch state for UI polling.

        Used by ``/api/v1/issues/index-state`` so the Issues dashboard can
        long-poll on a single integer instead of refetching the whole queue.
        """
        with self._lock:
            return {
                "refresh_epoch": self._refresh_epoch,
                "last_refresh_at": self._last_refresh_at,
                "last_refresh_run_id": self._last_refresh_run_id,
                "last_findings_mirrored": self._last_findings_mirrored,
                "subscribed": self._subscribed,
            }

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @staticmethod
    def _connect(db_path: str) -> Optional[sqlite3.Connection]:
        """Open an SQLite connection if the file exists. Returns None otherwise.

        We never *create* the DB here — federation only reads from what
        the source engines have already provisioned. This prevents the
        federation layer from accidentally masking a missing engine.
        """
        if not Path(db_path).exists():
            return None
        try:
            conn = sqlite3.connect(db_path, timeout=5)
            conn.row_factory = sqlite3.Row
            return conn
        except sqlite3.Error as exc:  # pragma: no cover - defensive
            _logger.warning("unified_issues: failed to open %s: %s", db_path, exc)
            return None

    @staticmethod
    def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
        row = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=? LIMIT 1",
            (name,),
        ).fetchone()
        return bool(row)

    @staticmethod
    def _column_names(conn: sqlite3.Connection, table: str) -> set:
        try:
            return {r["name"] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()}
        except sqlite3.Error:
            return set()

    # ------------------------------------------------------------------
    # Row normalizers
    # ------------------------------------------------------------------

    @staticmethod
    def _findings_row_to_issue(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        return {
            "id": d.get("id"),
            "source_engine": "findings",
            "severity": (d.get("severity") or "medium").lower(),
            "title": d.get("title") or "",
            "status": _normalize_status("findings", d.get("status")),
            "first_seen_at": d.get("first_seen_at") or d.get("first_seen") or d.get("created_at") or "",
            "resolved_at": d.get("resolved_at"),
            "owner": d.get("assigned_to") or "",
            "correlation_key": d.get("correlation_key") or "",
            "scan_id": d.get("scan_id") or "",
            "previous_violation_id": d.get("previous_violation_id"),
            "asset_id": d.get("asset_id") or "",
            "metadata": {
                "source_tool": d.get("source_tool"),
                "cvss_score": d.get("cvss_score"),
                "finding_type": d.get("finding_type"),
            },
        }

    @staticmethod
    def _exposure_row_to_issue(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        # Priority on exposure cases maps to severity
        priority = (d.get("priority") or "medium").lower()
        severity = {
            "critical": "critical", "high": "high", "medium": "medium",
            "low": "low", "info": "info",
        }.get(priority, "medium")
        # affected_assets is JSON → first element is a useful asset_id fallback
        asset_id = ""
        try:
            assets = json.loads(d.get("affected_assets") or "[]")
            if assets and isinstance(assets, list):
                asset_id = str(assets[0])
        except (ValueError, TypeError):
            pass
        return {
            "id": d.get("case_id"),
            "source_engine": "exposures",
            "severity": severity,
            "title": d.get("title") or "",
            "status": _normalize_status("exposures", d.get("status")),
            "first_seen_at": d.get("created_at") or "",
            "resolved_at": d.get("resolved_at"),
            "owner": d.get("assigned_to") or d.get("assigned_team") or "",
            "correlation_key": d.get("root_cve") or d.get("root_cwe") or d.get("case_id") or "",
            "scan_id": "",
            "previous_violation_id": None,
            "asset_id": asset_id,
            "metadata": {
                "priority": priority,
                "risk_score": d.get("risk_score"),
                "in_kev": bool(d.get("in_kev")),
                "finding_count": d.get("finding_count"),
            },
        }

    @staticmethod
    def _alert_row_to_issue(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        severity = (d.get("severity") or _severity_from_priority(d.get("priority"))).lower()
        return {
            "id": d.get("id"),
            "source_engine": "alerts",
            "severity": severity,
            "title": d.get("title") or "",
            "status": _normalize_status("alerts", d.get("status")),
            "first_seen_at": d.get("ingested_at") or "",
            "resolved_at": d.get("resolved_at"),
            "owner": d.get("assigned_to") or "",
            "correlation_key": d.get("id") or "",
            "scan_id": "",
            "previous_violation_id": None,
            "asset_id": "",
            "metadata": {
                "source_system": d.get("source_system"),
                "priority": d.get("priority"),
            },
        }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def unified_list(
        self,
        org_id: str,
        filters: Optional[Dict[str, Any]] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Federate rows across findings + exposures + alerts.

        Filters (all optional):
          severity           : 'critical' | 'high' | 'medium' | 'low' | 'info'
          status             : normalised status (open, resolved, …)
          source             : 'findings' | 'exposures' | 'alerts' (single source only)
          first_seen_after   : ISO timestamp, inclusive
          first_seen_before  : ISO timestamp, exclusive
        """
        if not org_id:
            raise ValueError("org_id is required")
        filters = dict(filters or {})
        severity = filters.get("severity")
        status = filters.get("status")
        source = filters.get("source")
        after = filters.get("first_seen_after")
        before = filters.get("first_seen_before")
        limit = max(1, min(int(limit or 100), 1000))

        if source and source not in _NORMALIZED_SOURCES:
            raise ValueError(f"source must be one of {sorted(_NORMALIZED_SOURCES)}")

        issues: List[Dict[str, Any]] = []

        # --- Findings ---------------------------------------------------
        if not source or source == "findings":
            conn = self._connect(self.findings_db)
            if conn is not None:
                try:
                    if self._table_exists(conn, "security_findings"):
                        sql = "SELECT * FROM security_findings WHERE org_id = ?"
                        params: List[Any] = [org_id]
                        if severity:
                            sql += " AND LOWER(severity) = ?"
                            params.append(severity.lower())
                        if status:
                            sql += " AND REPLACE(LOWER(status),'-','_') = ?"
                            params.append(status.lower().replace("-", "_"))
                        if after:
                            sql += " AND (first_seen_at >= ? OR (first_seen_at = '' AND created_at >= ?))"
                            params.extend([after, after])
                        if before:
                            sql += " AND (first_seen_at < ? OR (first_seen_at = '' AND created_at < ?))"
                            params.extend([before, before])
                        sql += " ORDER BY first_seen_at DESC, created_at DESC LIMIT ?"
                        params.append(limit)
                        for row in conn.execute(sql, params).fetchall():
                            issues.append(self._findings_row_to_issue(row))
                finally:
                    conn.close()

        # --- Exposure cases --------------------------------------------
        if not source or source == "exposures":
            conn = self._connect(self.exposures_db)
            if conn is not None:
                try:
                    if self._table_exists(conn, "exposure_cases"):
                        sql = "SELECT * FROM exposure_cases WHERE org_id = ?"
                        params = [org_id]
                        if severity:
                            # exposures use priority not severity — map 1:1
                            sql += " AND LOWER(priority) = ?"
                            params.append(severity.lower())
                        if status:
                            sql += " AND REPLACE(LOWER(status),'-','_') = ?"
                            params.append(status.lower().replace("-", "_"))
                        if after:
                            sql += " AND created_at >= ?"
                            params.append(after)
                        if before:
                            sql += " AND created_at < ?"
                            params.append(before)
                        sql += " ORDER BY created_at DESC LIMIT ?"
                        params.append(limit)
                        for row in conn.execute(sql, params).fetchall():
                            issues.append(self._exposure_row_to_issue(row))
                finally:
                    conn.close()

        # --- Alerts -----------------------------------------------------
        if not source or source == "alerts":
            conn = self._connect(self.alerts_db)
            if conn is not None:
                try:
                    if self._table_exists(conn, "at_alerts"):
                        sql = "SELECT * FROM at_alerts WHERE org_id = ?"
                        params = [org_id]
                        if severity:
                            sql += " AND LOWER(severity) = ?"
                            params.append(severity.lower())
                        if status:
                            sql += " AND REPLACE(LOWER(status),'-','_') = ?"
                            params.append(status.lower().replace("-", "_"))
                        if after:
                            sql += " AND ingested_at >= ?"
                            params.append(after)
                        if before:
                            sql += " AND ingested_at < ?"
                            params.append(before)
                        sql += " ORDER BY ingested_at DESC LIMIT ?"
                        params.append(limit)
                        for row in conn.execute(sql, params).fetchall():
                            issues.append(self._alert_row_to_issue(row))
                finally:
                    conn.close()

        # Final global sort by first_seen_at desc, capped at limit
        issues.sort(
            key=lambda it: (it.get("first_seen_at") or ""),
            reverse=True,
        )
        result_issues = issues[:limit]
        _emit_event("unified_issues_engine.unified_list", {
            "engine": "unified_issues_engine",
            "org_id": org_id,
            "returned": len(result_issues),
            "limit": limit,
        })
        return result_issues

    def issue_counts_by_source(self, org_id: str) -> Dict[str, int]:
        """Return per-source counts + total for the org."""
        if not org_id:
            raise ValueError("org_id is required")

        counts = {"findings": 0, "exposures": 0, "alerts": 0, "total": 0}

        conn = self._connect(self.findings_db)
        if conn is not None:
            try:
                if self._table_exists(conn, "security_findings"):
                    row = conn.execute(
                        "SELECT COUNT(*) AS c FROM security_findings WHERE org_id = ?",
                        (org_id,),
                    ).fetchone()
                    counts["findings"] = int(row["c"] if row else 0)
            finally:
                conn.close()

        conn = self._connect(self.exposures_db)
        if conn is not None:
            try:
                if self._table_exists(conn, "exposure_cases"):
                    row = conn.execute(
                        "SELECT COUNT(*) AS c FROM exposure_cases WHERE org_id = ?",
                        (org_id,),
                    ).fetchone()
                    counts["exposures"] = int(row["c"] if row else 0)
            finally:
                conn.close()

        conn = self._connect(self.alerts_db)
        if conn is not None:
            try:
                if self._table_exists(conn, "at_alerts"):
                    row = conn.execute(
                        "SELECT COUNT(*) AS c FROM at_alerts WHERE org_id = ?",
                        (org_id,),
                    ).fetchone()
                    counts["alerts"] = int(row["c"] if row else 0)
            finally:
                conn.close()

        counts["total"] = counts["findings"] + counts["exposures"] + counts["alerts"]
        _emit_event("unified_issues_engine.issue_counts_by_source", {
            "engine": "unified_issues_engine",
            "org_id": org_id,
            "findings": counts["findings"],
            "exposures": counts["exposures"],
            "alerts": counts["alerts"],
            "total": counts["total"],
        })
        return counts

    def compute_diff(
        self,
        org_id: str,
        baseline_scan_id: str,
        current_scan_id: str,
    ) -> Dict[str, Any]:
        """GAP-066 diff mode across two scans.

        Uses the GAP-063 lifecycle columns on ``security_findings``:
          - first_seen_at, previous_violation_id, resolved_at, scan_id, correlation_key.

        Classification:
          - ``new``        : rows in current scan whose correlation_key isn't in baseline
          - ``unchanged``  : rows in current scan whose correlation_key IS in baseline
          - ``resolved``   : rows in baseline whose correlation_key is missing from current

        Edge cases:
          - empty baseline → everything in current is "new"
          - empty current  → everything in baseline is "resolved"
          - identical scan ids → ValueError
        """
        if not org_id:
            raise ValueError("org_id is required")
        if baseline_scan_id == current_scan_id:
            raise ValueError("baseline_scan_id and current_scan_id must differ")

        new_list: List[Dict[str, Any]] = []
        unchanged_ids: List[str] = []
        resolved_list: List[Dict[str, Any]] = []
        affected_components: set = set()

        conn = self._connect(self.findings_db)
        if conn is None:
            return {
                "new": [],
                "unchanged_ids": [],
                "resolved": [],
                "summary": {
                    "new_count": 0, "unchanged_count": 0, "resolved_count": 0,
                    "baseline_scan_id": baseline_scan_id,
                    "current_scan_id": current_scan_id,
                },
                "affected_components": [],
                "computed_at": _now_iso(),
            }

        try:
            if not self._table_exists(conn, "security_findings"):
                return {
                    "new": [],
                    "unchanged_ids": [],
                    "resolved": [],
                    "summary": {
                        "new_count": 0, "unchanged_count": 0, "resolved_count": 0,
                        "baseline_scan_id": baseline_scan_id,
                        "current_scan_id": current_scan_id,
                    },
                    "affected_components": [],
                    "computed_at": _now_iso(),
                }

            baseline_rows = conn.execute(
                """SELECT id, correlation_key, title, severity, asset_id, first_seen_at,
                          resolved_at, status
                   FROM security_findings
                   WHERE org_id = ? AND scan_id = ?""",
                (org_id, baseline_scan_id),
            ).fetchall()
            current_rows = conn.execute(
                """SELECT id, correlation_key, title, severity, asset_id, first_seen_at,
                          resolved_at, status, previous_violation_id
                   FROM security_findings
                   WHERE org_id = ? AND scan_id = ?""",
                (org_id, current_scan_id),
            ).fetchall()
        finally:
            conn.close()

        baseline_by_key: Dict[str, sqlite3.Row] = {}
        for r in baseline_rows:
            key = r["correlation_key"] or ""
            if key and key not in baseline_by_key:
                baseline_by_key[key] = r

        current_keys: set = set()
        for r in current_rows:
            key = r["correlation_key"] or ""
            title = r["title"] or ""
            severity = (r["severity"] or "medium").lower()
            asset_id = r["asset_id"] or ""
            if asset_id:
                affected_components.add(asset_id)
            entry = {
                "id": r["id"],
                "correlation_key": key,
                "title": title,
                "severity": severity,
                "asset_id": asset_id,
                "first_seen_at": r["first_seen_at"] or "",
                "status": r["status"] or "open",
            }
            if not key:
                # Can't correlate → NEW by definition
                new_list.append(entry)
                continue
            current_keys.add(key)
            if key in baseline_by_key:
                unchanged_ids.append(r["id"])
            else:
                new_list.append(entry)

        resolved_keys = set(baseline_by_key.keys()) - current_keys
        for key in resolved_keys:
            r = baseline_by_key[key]
            asset_id = r["asset_id"] or ""
            if asset_id:
                affected_components.add(asset_id)
            resolved_list.append(
                {
                    "id": r["id"],
                    "correlation_key": key,
                    "title": r["title"] or "",
                    "severity": (r["severity"] or "medium").lower(),
                    "asset_id": asset_id,
                    "first_seen_at": r["first_seen_at"] or "",
                    "resolved_at": r["resolved_at"],
                    "status": r["status"] or "open",
                }
            )

        return {
            "new": new_list,
            "unchanged_ids": unchanged_ids,
            "resolved": resolved_list,
            "summary": {
                "new_count": len(new_list),
                "unchanged_count": len(unchanged_ids),
                "resolved_count": len(resolved_list),
                "baseline_scan_id": baseline_scan_id,
                "current_scan_id": current_scan_id,
            },
            "affected_components": sorted(affected_components),
            "computed_at": _now_iso(),
        }

    def diff_history(self, org_id: str, limit: int = 20) -> List[Dict[str, Any]]:
        """Return the list of scans (scan_id + first_seen_at) observed for the org.

        This powers the UI's scan selector for the diff view — it is computed
        on the fly from ``security_findings`` (no extra table required).
        """
        if not org_id:
            raise ValueError("org_id is required")
        limit = max(1, min(int(limit or 20), 200))
        conn = self._connect(self.findings_db)
        if conn is None:
            return []
        try:
            if not self._table_exists(conn, "security_findings"):
                return []
            rows = conn.execute(
                """SELECT scan_id,
                          MIN(first_seen_at) AS started_at,
                          MAX(COALESCE(last_seen, first_seen_at)) AS finished_at,
                          COUNT(*) AS finding_count
                   FROM security_findings
                   WHERE org_id = ? AND scan_id != ''
                   GROUP BY scan_id
                   ORDER BY finished_at DESC
                   LIMIT ?""",
                (org_id, limit),
            ).fetchall()
        finally:
            conn.close()

        return [
            {
                "scan_id": r["scan_id"],
                "started_at": r["started_at"] or "",
                "finished_at": r["finished_at"] or "",
                "finding_count": int(r["finding_count"] or 0),
            }
            for r in rows
        ]

    def issue_stats(self, org_id: str) -> Dict[str, Any]:
        """Return combined counts-by-source + by-severity + by-status.

        Used by the /issues/stats endpoint to power headline tiles on the
        unified queue page.
        """
        if not org_id:
            raise ValueError("org_id is required")

        counts = self.issue_counts_by_source(org_id)

        by_severity: Dict[str, int] = {}
        by_status: Dict[str, int] = {}

        for issue in self.unified_list(org_id, limit=1000):
            sev = issue.get("severity") or "medium"
            st = issue.get("status") or "open"
            by_severity[sev] = by_severity.get(sev, 0) + 1
            by_status[st] = by_status.get(st, 0) + 1

        stats = {
            "counts": counts,
            "by_severity": by_severity,
            "by_status": by_status,
            "computed_at": _now_iso(),
        }
        _emit_event("unified_issues_engine.issue_stats", {
            "engine": "unified_issues_engine",
            "org_id": org_id,
            "total": counts.get("total", 0),
            "severity_breakdown": by_severity,
        })
        return stats


_engine_instance: Optional[UnifiedIssuesEngine] = None
_engine_lock = threading.Lock()


def get_unified_issues_engine(
    findings_db: Optional[str] = None,
    exposures_db: Optional[str] = None,
    alerts_db: Optional[str] = None,
) -> UnifiedIssuesEngine:
    """Return a process-wide singleton unless overriding DB paths are supplied.

    The router uses the no-arg form so there is one shared federation
    instance. Tests should pass explicit paths (which bypasses the cache).
    """
    global _engine_instance
    if findings_db or exposures_db or alerts_db:
        return UnifiedIssuesEngine(
            findings_db=findings_db or _DEFAULT_FINDINGS_DB,
            exposures_db=exposures_db or _DEFAULT_EXPOSURES_DB,
            alerts_db=alerts_db or _DEFAULT_ALERTS_DB,
        )
    with _engine_lock:
        if _engine_instance is None:
            _engine_instance = UnifiedIssuesEngine()
        return _engine_instance
