"""Security Change Management Engine — ALDECI. SQLite WAL + RLock + org_id isolation.

Manages security change requests with full approval workflow:
  - Change lifecycle from draft through completion or rollback
  - Approver decision tracking (approved/rejected/pending)
  - Aggregated stats with daily completion counts and type/status breakdowns
  - GAP-011 material change diff: computes new/unchanged/resolved bucket deltas
    across prior vs current scan runs via correlation_key JOIN (builds on GAP-063
    findings lifecycle columns). Emits PR-webhook friendly JSON shape.

Compliance: ITIL v4, ISO 20000, SOC2 CC8.1, NIST SP 800-128
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "security_change_management.db"
)

_VALID_CHANGE_TYPES = {
    "patch", "configuration", "architecture", "access_control",
    "firewall_rule", "certificate", "policy", "emergency",
}
_VALID_PRIORITIES = {"critical", "high", "medium", "low"}
_VALID_CHANGE_STATUSES = {
    "draft", "review", "approved", "scheduled", "implementing",
    "completed", "rejected", "rolled_back",
}
_VALID_RISK_LEVELS = {"critical", "high", "medium", "low"}
_VALID_DECISIONS = {"approved", "rejected", "pending"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _today_prefix() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


class SecurityChangeManagementEngine:
    """SQLite WAL-backed Security Change Management engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/security_change_management.db
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
                CREATE TABLE IF NOT EXISTS scm_changes (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    title            TEXT NOT NULL DEFAULT '',
                    change_type      TEXT NOT NULL DEFAULT 'patch',
                    description      TEXT NOT NULL DEFAULT '',
                    priority         TEXT NOT NULL DEFAULT 'medium',
                    risk_level       TEXT NOT NULL DEFAULT 'medium',
                    requested_by     TEXT NOT NULL DEFAULT '',
                    assigned_to      TEXT NOT NULL DEFAULT '',
                    affected_systems TEXT NOT NULL DEFAULT '',
                    rollback_plan    TEXT NOT NULL DEFAULT '',
                    status           TEXT NOT NULL DEFAULT 'draft',
                    notes            TEXT NOT NULL DEFAULT '',
                    created_at       DATETIME,
                    scheduled_at     DATETIME,
                    completed_at     DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_scm_changes_org
                    ON scm_changes (org_id, change_type, status, priority);

                CREATE TABLE IF NOT EXISTS scm_approvals (
                    id          TEXT PRIMARY KEY,
                    org_id      TEXT NOT NULL,
                    change_id   TEXT NOT NULL,
                    approver    TEXT NOT NULL DEFAULT '',
                    decision    TEXT NOT NULL DEFAULT 'pending',
                    comments    TEXT NOT NULL DEFAULT '',
                    decided_at  DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_scm_approvals_org
                    ON scm_approvals (org_id, change_id);

                -- GAP-011 material change events (scan-pair deltas)
                CREATE TABLE IF NOT EXISTS material_change_events (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    prior_scan_id    TEXT NOT NULL,
                    current_scan_id  TEXT NOT NULL,
                    delta_json       TEXT NOT NULL DEFAULT '{}',
                    computed_at      TEXT NOT NULL DEFAULT '',
                    pr_ref           TEXT NOT NULL DEFAULT ''
                );

                CREATE UNIQUE INDEX IF NOT EXISTS ux_material_change_events_org_pair
                    ON material_change_events (org_id, prior_scan_id, current_scan_id);

                CREATE INDEX IF NOT EXISTS idx_material_change_events_pr
                    ON material_change_events (org_id, pr_ref);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    # ------------------------------------------------------------------
    # Changes
    # ------------------------------------------------------------------

    def create_change(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new security change request in draft status."""
        title = (data.get("title") or "").strip()
        if not title:
            raise ValueError("title is required.")

        change_type = data.get("change_type", "patch")
        if change_type not in _VALID_CHANGE_TYPES:
            raise ValueError(
                f"Invalid change_type '{change_type}'. "
                f"Must be one of {sorted(_VALID_CHANGE_TYPES)}"
            )

        priority = data.get("priority", "medium")
        if priority not in _VALID_PRIORITIES:
            raise ValueError(
                f"Invalid priority '{priority}'. "
                f"Must be one of {sorted(_VALID_PRIORITIES)}"
            )

        risk_level = data.get("risk_level", "medium")
        if risk_level not in _VALID_RISK_LEVELS:
            raise ValueError(
                f"Invalid risk_level '{risk_level}'. "
                f"Must be one of {sorted(_VALID_RISK_LEVELS)}"
            )

        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "title": title,
            "change_type": change_type,
            "description": data.get("description", ""),
            "priority": priority,
            "risk_level": risk_level,
            "requested_by": data.get("requested_by", ""),
            "assigned_to": data.get("assigned_to", ""),
            "affected_systems": data.get("affected_systems", ""),
            "rollback_plan": data.get("rollback_plan", ""),
            "status": "draft",
            "notes": "",
            "created_at": now,
            "scheduled_at": data.get("scheduled_at", None),
            "completed_at": None,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO scm_changes
                       (id, org_id, title, change_type, description, priority,
                        risk_level, requested_by, assigned_to, affected_systems,
                        rollback_plan, status, notes, created_at, scheduled_at, completed_at)
                       VALUES (:id, :org_id, :title, :change_type, :description, :priority,
                               :risk_level, :requested_by, :assigned_to, :affected_systems,
                               :rollback_plan, :status, :notes, :created_at, :scheduled_at,
                               :completed_at)""",
                    record,
                )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "security_change_management", "org_id": org_id, "source_engine": "security_change_management"})
            except Exception:
                pass

        return record

    def list_changes(
        self,
        org_id: str,
        change_type: Optional[str] = None,
        status: Optional[str] = None,
        priority: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List changes with optional filters."""
        sql = "SELECT * FROM scm_changes WHERE org_id = ?"
        params: List[Any] = [org_id]
        if change_type:
            sql += " AND change_type = ?"
            params.append(change_type)
        if status:
            sql += " AND status = ?"
            params.append(status)
        if priority:
            sql += " AND priority = ?"
            params.append(priority)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    def get_change(self, org_id: str, change_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single change by ID within the org."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM scm_changes WHERE org_id = ? AND id = ?",
                (org_id, change_id),
            ).fetchone()
        return self._row(row) if row else None

    def update_change_status(
        self,
        org_id: str,
        change_id: str,
        status: str,
        notes: str = "",
    ) -> Optional[Dict[str, Any]]:
        """Update change status. Sets completed_at if status=completed."""
        if status not in _VALID_CHANGE_STATUSES:
            raise ValueError(
                f"Invalid status '{status}'. "
                f"Must be one of {sorted(_VALID_CHANGE_STATUSES)}"
            )
        now = _now_iso()
        completed_at = now if status == "completed" else None
        with self._lock:
            with self._conn() as conn:
                if completed_at is not None:
                    conn.execute(
                        """UPDATE scm_changes
                           SET status = ?, notes = ?, completed_at = ?
                           WHERE org_id = ? AND id = ?""",
                        (status, notes, completed_at, org_id, change_id),
                    )
                else:
                    conn.execute(
                        """UPDATE scm_changes
                           SET status = ?, notes = ?
                           WHERE org_id = ? AND id = ?""",
                        (status, notes, org_id, change_id),
                    )
        return self.get_change(org_id, change_id)

    # ------------------------------------------------------------------
    # Approvals
    # ------------------------------------------------------------------

    def add_approver(
        self,
        org_id: str,
        change_id: str,
        approver_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Add an approval record for a change."""
        decision = approver_data.get("decision", "pending")
        if decision not in _VALID_DECISIONS:
            raise ValueError(
                f"Invalid decision '{decision}'. "
                f"Must be one of {sorted(_VALID_DECISIONS)}"
            )

        now = _now_iso()
        decided_at = None if decision == "pending" else now

        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "change_id": change_id,
            "approver": approver_data.get("approver", ""),
            "decision": decision,
            "comments": approver_data.get("comments", ""),
            "decided_at": decided_at,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO scm_approvals
                       (id, org_id, change_id, approver, decision, comments, decided_at)
                       VALUES (:id, :org_id, :change_id, :approver, :decision,
                               :comments, :decided_at)""",
                    record,
                )
        return record

    def list_approvals(
        self,
        org_id: str,
        change_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List approvals, optionally filtered by change_id."""
        sql = "SELECT * FROM scm_approvals WHERE org_id = ?"
        params: List[Any] = [org_id]
        if change_id:
            sql += " AND change_id = ?"
            params.append(change_id)
        sql += " ORDER BY decided_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_change_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated change management statistics for an org."""
        today = _today_prefix()
        with self._conn() as conn:
            total_changes = conn.execute(
                "SELECT COUNT(*) FROM scm_changes WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            pending_review = conn.execute(
                "SELECT COUNT(*) FROM scm_changes WHERE org_id = ? AND status = 'review'",
                (org_id,),
            ).fetchone()[0]

            approved_changes = conn.execute(
                "SELECT COUNT(*) FROM scm_changes WHERE org_id = ? AND status = 'approved'",
                (org_id,),
            ).fetchone()[0]

            completed_today = conn.execute(
                "SELECT COUNT(*) FROM scm_changes WHERE org_id = ? "
                "AND status = 'completed' AND completed_at LIKE ?",
                (org_id, f"{today}%"),
            ).fetchone()[0]

            emergency_changes = conn.execute(
                "SELECT COUNT(*) FROM scm_changes WHERE org_id = ? "
                "AND change_type = 'emergency'",
                (org_id,),
            ).fetchone()[0]

            type_rows = conn.execute(
                "SELECT change_type, COUNT(*) as cnt FROM scm_changes "
                "WHERE org_id = ? GROUP BY change_type",
                (org_id,),
            ).fetchall()
            by_type = {r["change_type"]: r["cnt"] for r in type_rows}

            status_rows = conn.execute(
                "SELECT status, COUNT(*) as cnt FROM scm_changes "
                "WHERE org_id = ? GROUP BY status",
                (org_id,),
            ).fetchall()
            by_status = {r["status"]: r["cnt"] for r in status_rows}

        return {
            "total_changes": total_changes,
            "pending_review": pending_review,
            "approved_changes": approved_changes,
            "completed_today": completed_today,
            "emergency_changes": emergency_changes,
            "by_type": by_type,
            "by_status": by_status,
        }

    # ------------------------------------------------------------------
    # GAP-011 — Material Change Diff (builds on GAP-063 findings lifecycle)
    # ------------------------------------------------------------------

    @staticmethod
    def _findings_db_path() -> str:
        """Path to the security_findings_engine SQLite DB."""
        return str(
            Path(__file__).resolve().parents[2]
            / ".fixops_data"
            / "security_findings_engine.db"
        )

    def _load_scan_findings(
        self,
        org_id: str,
        scan_id: str,
    ) -> List[Dict[str, Any]]:
        """Load findings for a given (org_id, scan_id) from the findings DB.

        Returns an empty list if the findings DB or scan doesn't exist.
        Uses the GAP-063 columns: correlation_key, first_seen_at, resolved_at,
        previous_violation_id.
        """
        findings_db = self._findings_db_path()
        if not Path(findings_db).exists():
            return []
        try:
            conn = sqlite3.connect(findings_db, timeout=10)
            conn.row_factory = sqlite3.Row
            try:
                rows = conn.execute(
                    """SELECT id, title, severity, cvss_score, asset_id, asset_type,
                              source_tool, status, correlation_key, scan_id,
                              first_seen_at, resolved_at, previous_violation_id
                       FROM security_findings
                       WHERE org_id = ? AND scan_id = ?""",
                    (org_id, scan_id),
                ).fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()
        except sqlite3.Error as exc:
            _logger.warning("load_scan_findings failed: %s", exc)
            return []

    @staticmethod
    def _risk_weight(severity: str) -> float:
        """Risk-surface weight for a given severity (aligned with CVSS tiers)."""
        return {
            "critical": 10.0,
            "high": 7.5,
            "medium": 5.0,
            "low": 2.5,
            "informational": 0.5,
            "info": 0.5,
        }.get((severity or "medium").lower(), 5.0)

    def compute_material_change_diff(
        self,
        org_id: str,
        prior_scan_id: str,
        current_scan_id: str,
        pr_ref: str = "",
    ) -> Dict[str, Any]:
        """Compute a PR-webhook friendly risk-surface diff between two scans.

        Joins findings by ``correlation_key`` (GAP-063) and buckets each finding
        into: ``new`` (in current only), ``unchanged`` (in both, still open),
        ``resolved`` (in prior but not current, or resolved_at set in current).

        Per-component (asset_id) risk deltas are emitted. The full event is
        persisted idempotently via INSERT OR IGNORE on
        ``(org_id, prior_scan_id, current_scan_id)``.

        Returns the persisted event dict (with ``delta`` field decoded).
        """
        if not prior_scan_id or not current_scan_id:
            raise ValueError("prior_scan_id and current_scan_id are required")
        if prior_scan_id == current_scan_id:
            raise ValueError("prior_scan_id and current_scan_id must differ")

        prior = self._load_scan_findings(org_id, prior_scan_id)
        current = self._load_scan_findings(org_id, current_scan_id)

        # Index by correlation_key; fall back to composite when empty
        def _key(f: Dict[str, Any]) -> str:
            return (
                f.get("correlation_key")
                or f"{f.get('source_tool', '')}|{f.get('title', '')}|{f.get('asset_id', '')}"
            )

        prior_map: Dict[str, Dict[str, Any]] = {_key(f): f for f in prior}
        current_map: Dict[str, Dict[str, Any]] = {_key(f): f for f in current}

        new_keys = set(current_map) - set(prior_map)
        common_keys = set(current_map) & set(prior_map)
        resolved_keys = set(prior_map) - set(current_map)

        new_bucket: List[Dict[str, Any]] = []
        unchanged_bucket: List[Dict[str, Any]] = []
        resolved_bucket: List[Dict[str, Any]] = []

        # Per-component (asset) risk surface
        component_prior: Dict[str, float] = {}
        component_current: Dict[str, float] = {}

        for k in new_keys:
            f = current_map[k]
            if (f.get("status") or "").lower() == "resolved":
                # Already-resolved finding in current scan — treat as resolved
                resolved_bucket.append(f)
            else:
                new_bucket.append(f)
                asset = f.get("asset_id") or ""
                component_current[asset] = (
                    component_current.get(asset, 0.0) + self._risk_weight(f.get("severity", ""))
                )

        for k in common_keys:
            cur_f = current_map[k]
            pr_f = prior_map[k]
            # If current row is resolved or has resolved_at, count as resolved
            if (cur_f.get("status") or "").lower() == "resolved" or cur_f.get("resolved_at"):
                resolved_bucket.append(cur_f)
            else:
                unchanged_bucket.append(cur_f)
                asset = cur_f.get("asset_id") or ""
                component_current[asset] = (
                    component_current.get(asset, 0.0) + self._risk_weight(cur_f.get("severity", ""))
                )
            # Prior-side component weight
            asset_p = pr_f.get("asset_id") or ""
            component_prior[asset_p] = (
                component_prior.get(asset_p, 0.0) + self._risk_weight(pr_f.get("severity", ""))
            )

        for k in resolved_keys:
            f = prior_map[k]
            resolved_bucket.append(f)
            asset = f.get("asset_id") or ""
            component_prior[asset] = (
                component_prior.get(asset, 0.0) + self._risk_weight(f.get("severity", ""))
            )

        # Build per-component deltas (risk-surface delta = current - prior)
        components: List[Dict[str, Any]] = []
        all_assets = set(component_prior) | set(component_current)
        for asset in sorted(all_assets):
            prior_w = component_prior.get(asset, 0.0)
            curr_w = component_current.get(asset, 0.0)
            components.append({
                "asset_id": asset,
                "prior_risk": round(prior_w, 2),
                "current_risk": round(curr_w, 2),
                "delta": round(curr_w - prior_w, 2),
            })

        total_prior = round(sum(component_prior.values()), 2)
        total_current = round(sum(component_current.values()), 2)

        def _summarize(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
            return [
                {
                    "id": r.get("id"),
                    "correlation_key": r.get("correlation_key"),
                    "title": r.get("title"),
                    "severity": r.get("severity"),
                    "asset_id": r.get("asset_id"),
                    "source_tool": r.get("source_tool"),
                }
                for r in rows
            ]

        delta: Dict[str, Any] = {
            "prior_scan_id": prior_scan_id,
            "current_scan_id": current_scan_id,
            "counts": {
                "new": len(new_bucket),
                "unchanged": len(unchanged_bucket),
                "resolved": len(resolved_bucket),
            },
            "risk_surface": {
                "prior_total": total_prior,
                "current_total": total_current,
                "delta": round(total_current - total_prior, 2),
            },
            "components": components,
            "findings": {
                "new": _summarize(new_bucket),
                "unchanged": _summarize(unchanged_bucket),
                "resolved": _summarize(resolved_bucket),
            },
            "pr_ref": pr_ref,
        }

        event_id = str(uuid.uuid4())
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                # INSERT OR IGNORE — idempotent on (org_id, prior_scan_id, current_scan_id)
                conn.execute(
                    """INSERT OR IGNORE INTO material_change_events
                       (id, org_id, prior_scan_id, current_scan_id, delta_json, computed_at, pr_ref)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (
                        event_id,
                        org_id,
                        prior_scan_id,
                        current_scan_id,
                        json.dumps(delta),
                        now,
                        pr_ref or "",
                    ),
                )
                # If caller provided a pr_ref and the existing row had none, update it.
                if pr_ref:
                    conn.execute(
                        """UPDATE material_change_events
                           SET pr_ref = ?
                           WHERE org_id = ? AND prior_scan_id = ? AND current_scan_id = ?
                             AND (pr_ref IS NULL OR pr_ref = '')""",
                        (pr_ref, org_id, prior_scan_id, current_scan_id),
                    )
                row = conn.execute(
                    """SELECT * FROM material_change_events
                       WHERE org_id = ? AND prior_scan_id = ? AND current_scan_id = ?""",
                    (org_id, prior_scan_id, current_scan_id),
                ).fetchone()

        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit(
                        "ENTITY_UPDATED",
                        {
                            "entity_type": "material_change_event",
                            "org_id": org_id,
                            "source_engine": "security_change_management",
                            "prior_scan_id": prior_scan_id,
                            "current_scan_id": current_scan_id,
                            "pr_ref": pr_ref,
                            "counts": delta["counts"],
                        },
                    )
            except Exception:
                pass

        result = dict(row) if row else {
            "id": event_id,
            "org_id": org_id,
            "prior_scan_id": prior_scan_id,
            "current_scan_id": current_scan_id,
            "delta_json": json.dumps(delta),
            "computed_at": now,
            "pr_ref": pr_ref or "",
        }
        # Decode delta_json into structured delta for consumer convenience.
        try:
            result["delta"] = json.loads(result.get("delta_json") or "{}")
        except (TypeError, ValueError):
            result["delta"] = delta
        return result

    def list_material_events(
        self,
        org_id: str,
        pr_ref: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List material-change events for an org, optionally filtered by pr_ref."""
        sql = "SELECT * FROM material_change_events WHERE org_id = ?"
        params: List[Any] = [org_id]
        if pr_ref:
            sql += " AND pr_ref = ?"
            params.append(pr_ref)
        sql += " ORDER BY computed_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        results: List[Dict[str, Any]] = []
        for r in rows:
            rec = dict(r)
            try:
                rec["delta"] = json.loads(rec.get("delta_json") or "{}")
            except (TypeError, ValueError):
                rec["delta"] = {}
            results.append(rec)
        return results

    def get_material_event(self, event_id: str) -> Optional[Dict[str, Any]]:
        """Fetch a single material-change event by id (org-agnostic lookup by PK)."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM material_change_events WHERE id = ?",
                (event_id,),
            ).fetchone()
        if not row:
            return None
        rec = dict(row)
        try:
            rec["delta"] = json.loads(rec.get("delta_json") or "{}")
        except (TypeError, ValueError):
            rec["delta"] = {}
        return rec

    def record_pr_webhook(
        self,
        org_id: str,
        pr_ref: str,
        event_id: str,
    ) -> Optional[Dict[str, Any]]:
        """Associate a PR ref with an existing material-change event.

        Returns the updated event, or None if not found / org mismatch.
        """
        if not pr_ref:
            raise ValueError("pr_ref is required")
        with self._lock:
            with self._conn() as conn:
                existing = conn.execute(
                    "SELECT * FROM material_change_events WHERE id = ? AND org_id = ?",
                    (event_id, org_id),
                ).fetchone()
                if not existing:
                    return None
                conn.execute(
                    "UPDATE material_change_events SET pr_ref = ? WHERE id = ? AND org_id = ?",
                    (pr_ref, event_id, org_id),
                )
        return self.get_material_event(event_id)

    def get_material_change_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated material-change-event stats for an org."""
        with self._conn() as conn:
            total = conn.execute(
                "SELECT COUNT(*) FROM material_change_events WHERE org_id = ?",
                (org_id,),
            ).fetchone()[0]
            with_pr = conn.execute(
                "SELECT COUNT(*) FROM material_change_events "
                "WHERE org_id = ? AND pr_ref != ''",
                (org_id,),
            ).fetchone()[0]
            rows = conn.execute(
                "SELECT delta_json FROM material_change_events WHERE org_id = ?",
                (org_id,),
            ).fetchall()
        total_new = total_unchanged = total_resolved = 0
        total_risk_delta = 0.0
        for r in rows:
            try:
                d = json.loads(r["delta_json"] or "{}")
            except (TypeError, ValueError):
                continue
            counts = d.get("counts") or {}
            total_new += int(counts.get("new", 0) or 0)
            total_unchanged += int(counts.get("unchanged", 0) or 0)
            total_resolved += int(counts.get("resolved", 0) or 0)
            total_risk_delta += float((d.get("risk_surface") or {}).get("delta", 0.0) or 0.0)
        return {
            "total_events": total,
            "events_with_pr_ref": with_pr,
            "total_findings_new": total_new,
            "total_findings_unchanged": total_unchanged,
            "total_findings_resolved": total_resolved,
            "aggregate_risk_delta": round(total_risk_delta, 2),
        }
