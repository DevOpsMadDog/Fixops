"""Security Findings Engine — ALDECI. SQLite WAL + RLock + org_id isolation.

Unified findings aggregator across all security scanners and tools.
  - Centralizes security findings from SAST/DAST/SIEM/EDR/CSPM/etc.
  - Deduplicates findings (same title+source_tool+asset_id per org, status != resolved)
  - Tracks remediation lifecycle with evidence and suppression workflows
  - Full findings summary with per-severity and per-tool breakdowns

Compliance: NIST SP 800-53, CIS Controls, ISO 27001 A.12.6
"""
from __future__ import annotations

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

try:
    from core.notification_engine import NotificationEngine as _NotificationEngine
    _notification_engine: Optional[_NotificationEngine] = _NotificationEngine()
except Exception:  # pragma: no cover
    _notification_engine = None


_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "security_findings_engine.db"
)

_VALID_FINDING_TYPES = {
    "vulnerability", "misconfiguration", "policy-violation", "anomaly",
    "secret-exposure", "compliance-gap", "malware", "data-leak",
}
_VALID_SOURCE_TOOLS = {
    "SAST", "DAST", "SIEM", "EDR", "CSPM", "CNAPP",
    "Nessus", "Qualys", "Burp", "Semgrep", "Trivy", "custom",
}
_VALID_SEVERITIES = {"critical", "high", "medium", "low", "informational"}
_VALID_EVIDENCE_TYPES = {
    "screenshot", "log", "network-capture", "code-snippet", "config", "report",
}
_VALID_STATUSES = {"open", "in-progress", "resolved", "suppressed", "false-positive"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class SecurityFindingsEngine:
    """SQLite WAL-backed Security Findings engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/security_findings_engine.db
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
            # Step 1: Create the base table (without lifecycle indexes that
            # reference columns added by the migration). This is the only
            # statement needed for fresh DBs to bootstrap the schema.
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS security_findings (
                    id                    TEXT PRIMARY KEY,
                    org_id                TEXT NOT NULL,
                    title                 TEXT NOT NULL DEFAULT '',
                    finding_type          TEXT NOT NULL DEFAULT 'vulnerability',
                    source_tool           TEXT NOT NULL DEFAULT 'custom',
                    severity              TEXT NOT NULL DEFAULT 'medium',
                    cvss_score            REAL NOT NULL DEFAULT 0.0,
                    asset_id              TEXT NOT NULL DEFAULT '',
                    asset_type            TEXT NOT NULL DEFAULT '',
                    description           TEXT NOT NULL DEFAULT '',
                    remediation           TEXT NOT NULL DEFAULT '',
                    status                TEXT NOT NULL DEFAULT 'open',
                    first_seen            TEXT NOT NULL DEFAULT '',
                    last_seen             TEXT NOT NULL DEFAULT '',
                    occurrence_count      INTEGER NOT NULL DEFAULT 1,
                    assigned_to           TEXT NOT NULL DEFAULT '',
                    created_at            TEXT NOT NULL DEFAULT '',
                    -- GAP-063 violation lifecycle columns
                    correlation_key       TEXT NOT NULL DEFAULT '',
                    scan_id               TEXT NOT NULL DEFAULT '',
                    first_seen_at         TEXT NOT NULL DEFAULT '',
                    previous_violation_id TEXT,
                    resolved_at           TEXT,
                    unchanged_scan_count  INTEGER NOT NULL DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS finding_evidence (
                    id            TEXT PRIMARY KEY,
                    finding_id    TEXT NOT NULL,
                    org_id        TEXT NOT NULL,
                    evidence_type TEXT NOT NULL DEFAULT 'log',
                    content       TEXT NOT NULL DEFAULT '',
                    collected_at  TEXT NOT NULL DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS finding_suppressions (
                    id             TEXT PRIMARY KEY,
                    finding_id     TEXT NOT NULL,
                    org_id         TEXT NOT NULL,
                    reason         TEXT NOT NULL DEFAULT '',
                    suppressed_by  TEXT NOT NULL DEFAULT '',
                    expires_at     TEXT NOT NULL DEFAULT '',
                    created_at     TEXT NOT NULL DEFAULT ''
                );
                """
            )
            # Step 2: Idempotent migration — adds lifecycle columns BEFORE
            # creating any indexes that reference them. Critical: indexes
            # were previously inside the executescript above and would FAIL
            # on pre-existing DBs that lacked correlation_key.
            self._ensure_lifecycle_schema(conn)
            # Step 3: Now safe to create lifecycle indexes (columns exist)
            conn.executescript(
                """
                CREATE INDEX IF NOT EXISTS idx_sf_findings_org
                    ON security_findings (org_id, status, severity, source_tool);

                CREATE INDEX IF NOT EXISTS idx_sf_findings_asset
                    ON security_findings (org_id, asset_id);

                CREATE INDEX IF NOT EXISTS idx_sf_dedup
                    ON security_findings (org_id, title, source_tool, asset_id, status);

                CREATE INDEX IF NOT EXISTS idx_sf_lifecycle_corr
                    ON security_findings (org_id, correlation_key, status);

                CREATE INDEX IF NOT EXISTS idx_sf_lifecycle_scan
                    ON security_findings (org_id, scan_id);

                CREATE INDEX IF NOT EXISTS idx_sf_lifecycle_prev
                    ON security_findings (org_id, previous_violation_id);

                CREATE INDEX IF NOT EXISTS idx_sf_lifecycle_first_seen
                    ON security_findings (org_id, first_seen_at);

                CREATE INDEX IF NOT EXISTS idx_sf_lifecycle_resolved
                    ON security_findings (org_id, resolved_at);

                CREATE INDEX IF NOT EXISTS idx_sf_evidence_finding
                    ON finding_evidence (finding_id, org_id);

                CREATE INDEX IF NOT EXISTS idx_sf_suppressions_finding
                    ON finding_suppressions (finding_id, org_id);
                """
            )

    def _ensure_lifecycle_schema(self, conn: sqlite3.Connection) -> None:
        """Idempotent migration — add GAP-063 lifecycle columns if missing.

        Safe to run on both fresh and pre-existing DBs. Backfills
        `first_seen_at = COALESCE(first_seen, created_at, NOW())` for legacy rows.
        """
        cols = {row["name"] for row in conn.execute("PRAGMA table_info(security_findings)").fetchall()}
        added_new_column = False
        if "correlation_key" not in cols:
            conn.execute("ALTER TABLE security_findings ADD COLUMN correlation_key TEXT NOT NULL DEFAULT ''")
            added_new_column = True
        if "scan_id" not in cols:
            conn.execute("ALTER TABLE security_findings ADD COLUMN scan_id TEXT NOT NULL DEFAULT ''")
            added_new_column = True
        if "first_seen_at" not in cols:
            conn.execute("ALTER TABLE security_findings ADD COLUMN first_seen_at TEXT NOT NULL DEFAULT ''")
            added_new_column = True
        if "previous_violation_id" not in cols:
            conn.execute("ALTER TABLE security_findings ADD COLUMN previous_violation_id TEXT")
            added_new_column = True
        if "resolved_at" not in cols:
            conn.execute("ALTER TABLE security_findings ADD COLUMN resolved_at TEXT")
            added_new_column = True
        if "unchanged_scan_count" not in cols:
            conn.execute("ALTER TABLE security_findings ADD COLUMN unchanged_scan_count INTEGER NOT NULL DEFAULT 0")
            added_new_column = True

        if added_new_column:
            now = _now_iso()
            # One-shot backfill: first_seen_at = COALESCE(first_seen, created_at, NOW())
            conn.execute(
                """UPDATE security_findings
                   SET first_seen_at = CASE
                     WHEN first_seen_at IS NULL OR first_seen_at = ''
                       THEN COALESCE(NULLIF(first_seen, ''), NULLIF(created_at, ''), ?)
                     ELSE first_seen_at
                   END""",
                (now,),
            )
            # Back-fill resolved_at for rows already status='resolved'
            conn.execute(
                """UPDATE security_findings
                   SET resolved_at = COALESCE(resolved_at, NULLIF(last_seen, ''), ?)
                   WHERE status = 'resolved' AND (resolved_at IS NULL OR resolved_at = '')""",
                (now,),
            )
            # Ensure indexes exist (may have been skipped if table pre-existed without columns)
            conn.executescript(
                """
                CREATE INDEX IF NOT EXISTS idx_sf_lifecycle_corr
                    ON security_findings (org_id, correlation_key, status);
                CREATE INDEX IF NOT EXISTS idx_sf_lifecycle_scan
                    ON security_findings (org_id, scan_id);
                CREATE INDEX IF NOT EXISTS idx_sf_lifecycle_prev
                    ON security_findings (org_id, previous_violation_id);
                CREATE INDEX IF NOT EXISTS idx_sf_lifecycle_first_seen
                    ON security_findings (org_id, first_seen_at);
                CREATE INDEX IF NOT EXISTS idx_sf_lifecycle_resolved
                    ON security_findings (org_id, resolved_at);
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
    # Findings
    # ------------------------------------------------------------------

    def record_finding(
        self,
        org_id: str,
        title: str,
        finding_type: str,
        source_tool: str,
        severity: str,
        cvss_score: float,
        asset_id: str,
        asset_type: str,
        description: str,
        remediation: str,
        correlation_key: Optional[str] = None,
        scan_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Record a finding; dedup if same (org+title+source_tool+asset_id) and not resolved.

        GAP-063: If ``correlation_key`` is provided it becomes the stable identity
        for the violation lifecycle. When dedup finds an existing open row with the
        same correlation_key the returned record preserves its original
        ``first_seen_at``. New rows get ``first_seen_at = NOW()``.
        """
        cvss_score = max(0.0, min(10.0, float(cvss_score)))
        now = _now_iso()
        # Default correlation_key = sha-safe string composed from dedup keys.
        corr_key = (correlation_key or f"{source_tool}|{title}|{asset_id}").strip()
        scan_id_val = (scan_id or "").strip()

        with self._lock:
            with self._conn() as conn:
                # Prefer correlation_key match when present (stable identity).
                # If the caller passes a scan_id, we only dedup within the same
                # scan_id — cross-scan matches are handled later by
                # ``reconcile_scans`` which produces the proper
                # previous_violation_id chain.
                existing = None
                if corr_key:
                    if scan_id_val:
                        existing = conn.execute(
                            """SELECT * FROM security_findings
                               WHERE org_id = ? AND correlation_key = ?
                                 AND scan_id = ?
                                 AND status != 'resolved'
                               LIMIT 1""",
                            (org_id, corr_key, scan_id_val),
                        ).fetchone()
                    else:
                        existing = conn.execute(
                            """SELECT * FROM security_findings
                               WHERE org_id = ? AND correlation_key = ?
                                 AND scan_id = ''
                                 AND status != 'resolved'
                               LIMIT 1""",
                            (org_id, corr_key),
                        ).fetchone()
                if not existing and not scan_id_val:
                    # Legacy fallback for callers that never provide scan_id:
                    # dedup by (title, source_tool, asset_id).
                    existing = conn.execute(
                        """SELECT * FROM security_findings
                           WHERE org_id = ? AND title = ? AND source_tool = ? AND asset_id = ?
                             AND scan_id = ''
                             AND status != 'resolved'
                           LIMIT 1""",
                        (org_id, title, source_tool, asset_id),
                    ).fetchone()

                if existing:
                    # Increment occurrence_count, update last_seen, and back-fill
                    # correlation_key / scan_id if missing.
                    new_corr = existing["correlation_key"] or corr_key
                    new_scan = scan_id_val or (existing["scan_id"] or "")
                    conn.execute(
                        """UPDATE security_findings
                           SET occurrence_count = occurrence_count + 1,
                               last_seen = ?,
                               correlation_key = ?,
                               scan_id = ?
                           WHERE id = ?""",
                        (now, new_corr, new_scan, existing["id"]),
                    )
                    updated = conn.execute(
                        "SELECT * FROM security_findings WHERE id = ?",
                        (existing["id"],),
                    ).fetchone()
                    return self._row(updated)

                # New finding
                record: Dict[str, Any] = {
                    "id": str(uuid.uuid4()),
                    "org_id": org_id,
                    "title": title,
                    "finding_type": finding_type,
                    "source_tool": source_tool,
                    "severity": severity,
                    "cvss_score": cvss_score,
                    "asset_id": asset_id,
                    "asset_type": asset_type,
                    "description": description,
                    "remediation": remediation,
                    "status": "open",
                    "first_seen": now,
                    "last_seen": now,
                    "occurrence_count": 1,
                    "assigned_to": "",
                    "created_at": now,
                    "correlation_key": corr_key,
                    "scan_id": scan_id_val,
                    "first_seen_at": now,
                    "previous_violation_id": None,
                    "resolved_at": None,
                    "unchanged_scan_count": 0,
                }
                conn.execute(
                    """INSERT INTO security_findings
                       (id, org_id, title, finding_type, source_tool, severity,
                        cvss_score, asset_id, asset_type, description, remediation,
                        status, first_seen, last_seen, occurrence_count, assigned_to, created_at,
                        correlation_key, scan_id, first_seen_at, previous_violation_id,
                        resolved_at, unchanged_scan_count)
                       VALUES (:id, :org_id, :title, :finding_type, :source_tool, :severity,
                               :cvss_score, :asset_id, :asset_type, :description, :remediation,
                               :status, :first_seen, :last_seen, :occurrence_count,
                               :assigned_to, :created_at,
                               :correlation_key, :scan_id, :first_seen_at,
                               :previous_violation_id, :resolved_at, :unchanged_scan_count)""",
                    record,
                )
                if severity == "critical" and _notification_engine is not None:
                    _notification_engine.send_slack_alert(
                        text=f"New critical finding recorded by {source_tool}",
                        finding=record,
                    )
                return record

    def update_status(
        self,
        finding_id: str,
        org_id: str,
        status: str,
        assigned_to: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Update finding status; if resolved, set resolved_at and update last_seen."""
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM security_findings WHERE id = ? AND org_id = ?",
                    (finding_id, org_id),
                ).fetchone()
                if not row:
                    return None

                updates: Dict[str, Any] = {"status": status, "id": finding_id}
                if status == "resolved":
                    updates["last_seen"] = now
                    # GAP-063: stamp resolved_at on transition to resolved
                    updates["resolved_at"] = row["resolved_at"] or now
                else:
                    updates["last_seen"] = row["last_seen"]
                    # If un-resolving, clear resolved_at
                    updates["resolved_at"] = None if status in ("open", "in-progress") else row["resolved_at"]

                if assigned_to is not None:
                    updates["assigned_to"] = assigned_to
                else:
                    updates["assigned_to"] = row["assigned_to"]

                conn.execute(
                    """UPDATE security_findings
                       SET status = :status,
                           last_seen = :last_seen,
                           assigned_to = :assigned_to,
                           resolved_at = :resolved_at
                       WHERE id = :id""",
                    updates,
                )
                updated = conn.execute(
                    "SELECT * FROM security_findings WHERE id = ?",
                    (finding_id,),
                ).fetchone()
                return self._row(updated)

    def add_evidence(
        self,
        finding_id: str,
        org_id: str,
        evidence_type: str,
        content: str,
    ) -> Dict[str, Any]:
        """Add evidence to a finding."""
        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "finding_id": finding_id,
            "org_id": org_id,
            "evidence_type": evidence_type,
            "content": content,
            "collected_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO finding_evidence
                       (id, finding_id, org_id, evidence_type, content, collected_at)
                       VALUES (:id, :finding_id, :org_id, :evidence_type, :content, :collected_at)""",
                    record,
                )
        return record

    def suppress_finding(
        self,
        finding_id: str,
        org_id: str,
        reason: str,
        suppressed_by: str,
        expires_at: str,
    ) -> Optional[Dict[str, Any]]:
        """Suppress a finding; updates finding status to suppressed."""
        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "finding_id": finding_id,
            "org_id": org_id,
            "reason": reason,
            "suppressed_by": suppressed_by,
            "expires_at": expires_at,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO finding_suppressions
                       (id, finding_id, org_id, reason, suppressed_by, expires_at, created_at)
                       VALUES (:id, :finding_id, :org_id, :reason, :suppressed_by,
                               :expires_at, :created_at)""",
                    record,
                )
                conn.execute(
                    "UPDATE security_findings SET status = 'suppressed' WHERE id = ? AND org_id = ?",
                    (finding_id, org_id),
                )
        return record

    def get_finding(self, finding_id: str, org_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a finding with its evidence and suppression."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM security_findings WHERE id = ? AND org_id = ?",
                (finding_id, org_id),
            ).fetchone()
            if not row:
                return None
            result = self._row(row)

            evidence_rows = conn.execute(
                "SELECT * FROM finding_evidence WHERE finding_id = ? AND org_id = ? ORDER BY collected_at DESC",
                (finding_id, org_id),
            ).fetchall()
            result["evidence"] = [self._row(e) for e in evidence_rows]

            suppression_rows = conn.execute(
                "SELECT * FROM finding_suppressions WHERE finding_id = ? AND org_id = ? ORDER BY created_at DESC",
                (finding_id, org_id),
            ).fetchall()
            result["suppressions"] = [self._row(s) for s in suppression_rows]

        return result

    def list_findings(
        self,
        org_id: str,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        source_tool: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List findings with optional filters."""
        sql = "SELECT * FROM security_findings WHERE org_id = ?"
        params: List[Any] = [org_id]
        if status:
            sql += " AND status = ?"
            params.append(status)
        if severity:
            sql += " AND severity = ?"
            params.append(severity)
        if source_tool:
            sql += " AND source_tool = ?"
            params.append(source_tool)
        sql += " ORDER BY cvss_score DESC, created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    def get_asset_findings(self, org_id: str, asset_id: str) -> List[Dict[str, Any]]:
        """Get all findings for a specific asset."""
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT * FROM security_findings
                   WHERE org_id = ? AND asset_id = ?
                   ORDER BY cvss_score DESC, created_at DESC""",
                (org_id, asset_id),
            ).fetchall()
        return [self._row(r) for r in rows]

    def get_findings_summary(self, org_id: str) -> Dict[str, Any]:
        """Summary: counts, severity breakdown, source breakdown, avg cvss, top assets."""
        with self._conn() as conn:
            total_row = conn.execute(
                "SELECT COUNT(*) AS cnt FROM security_findings WHERE org_id = ?",
                (org_id,),
            ).fetchone()
            total = total_row["cnt"] if total_row else 0

            status_rows = conn.execute(
                """SELECT status, COUNT(*) AS cnt
                   FROM security_findings WHERE org_id = ?
                   GROUP BY status""",
                (org_id,),
            ).fetchall()
            status_counts: Dict[str, int] = {r["status"]: r["cnt"] for r in status_rows}

            severity_rows = conn.execute(
                """SELECT severity, COUNT(*) AS cnt
                   FROM security_findings WHERE org_id = ?
                   GROUP BY severity""",
                (org_id,),
            ).fetchall()
            severity_breakdown: Dict[str, int] = {r["severity"]: r["cnt"] for r in severity_rows}

            tool_rows = conn.execute(
                """SELECT source_tool, COUNT(*) AS cnt
                   FROM security_findings WHERE org_id = ?
                   GROUP BY source_tool""",
                (org_id,),
            ).fetchall()
            by_source_tool: Dict[str, int] = {r["source_tool"]: r["cnt"] for r in tool_rows}

            avg_row = conn.execute(
                "SELECT AVG(cvss_score) AS avg_cvss FROM security_findings WHERE org_id = ?",
                (org_id,),
            ).fetchone()
            avg_cvss = round(avg_row["avg_cvss"] or 0.0, 2)

            top_asset_rows = conn.execute(
                """SELECT asset_id, COUNT(*) AS cnt
                   FROM security_findings
                   WHERE org_id = ? AND status = 'open'
                   GROUP BY asset_id
                   ORDER BY cnt DESC
                   LIMIT 5""",
                (org_id,),
            ).fetchall()
            top_assets = [{"asset_id": r["asset_id"], "open_findings": r["cnt"]} for r in top_asset_rows]

        return {
            "total": total,
            "open": status_counts.get("open", 0),
            "resolved": status_counts.get("resolved", 0),
            "suppressed": status_counts.get("suppressed", 0),
            "in_progress": status_counts.get("in-progress", 0),
            "false_positive": status_counts.get("false-positive", 0),
            "by_severity": severity_breakdown,
            "by_source_tool": by_source_tool,
            "avg_cvss_score": avg_cvss,
            "top_assets_by_open_findings": top_assets,
        }

    # ------------------------------------------------------------------
    # GAP-063 Violation lifecycle
    # ------------------------------------------------------------------

    def reconcile_scans(
        self,
        org_id: str,
        prior_scan_id: str,
        current_scan_id: str,
    ) -> Dict[str, Any]:
        """Diff two scans and assign new/unchanged/resolved classification.

        Matches rows by ``(org_id, correlation_key)``. The result for the caller
        is the three buckets of IDs; as a side effect:

          - findings in ``current`` matching an open row in ``prior`` have their
            ``previous_violation_id`` set to the prior row and ``unchanged_scan_count``
            incremented;
          - findings present in ``prior`` but absent from ``current`` get
            ``status='resolved'`` and ``resolved_at=NOW()``.
        """
        if prior_scan_id == current_scan_id:
            raise ValueError("prior_scan_id and current_scan_id must differ")

        now = _now_iso()
        new_ids: List[str] = []
        unchanged_ids: List[str] = []
        resolved_ids: List[str] = []
        previous_id_map: Dict[str, str] = {}

        with self._lock:
            with self._conn() as conn:
                prior_rows = conn.execute(
                    """SELECT id, correlation_key FROM security_findings
                       WHERE org_id = ? AND scan_id = ?""",
                    (org_id, prior_scan_id),
                ).fetchall()
                current_rows = conn.execute(
                    """SELECT id, correlation_key FROM security_findings
                       WHERE org_id = ? AND scan_id = ?""",
                    (org_id, current_scan_id),
                ).fetchall()

                prior_by_key: Dict[str, str] = {}
                for r in prior_rows:
                    key = r["correlation_key"] or ""
                    if key and key not in prior_by_key:
                        prior_by_key[key] = r["id"]

                current_keys = set()
                for r in current_rows:
                    key = r["correlation_key"] or ""
                    if not key:
                        # No correlation key → always NEW (can't match lifecycle)
                        new_ids.append(r["id"])
                        continue
                    current_keys.add(key)
                    if key in prior_by_key:
                        unchanged_ids.append(r["id"])
                        previous_id_map[r["id"]] = prior_by_key[key]
                    else:
                        new_ids.append(r["id"])

                # Apply previous_violation_id + increment unchanged_scan_count
                for curr_id, prev_id in previous_id_map.items():
                    conn.execute(
                        """UPDATE security_findings
                           SET previous_violation_id = ?,
                               unchanged_scan_count = unchanged_scan_count + 1
                           WHERE id = ? AND org_id = ?""",
                        (prev_id, curr_id, org_id),
                    )

                # Preserve original first_seen_at across the lifecycle chain.
                # For unchanged rows, inherit the earliest first_seen_at from prior.
                for curr_id, prev_id in previous_id_map.items():
                    prior_first = conn.execute(
                        "SELECT first_seen_at FROM security_findings WHERE id = ? AND org_id = ?",
                        (prev_id, org_id),
                    ).fetchone()
                    if prior_first and prior_first["first_seen_at"]:
                        conn.execute(
                            """UPDATE security_findings
                               SET first_seen_at = ?
                               WHERE id = ? AND org_id = ?
                                 AND (first_seen_at IS NULL OR first_seen_at = ''
                                      OR first_seen_at > ?)""",
                            (prior_first["first_seen_at"], curr_id, org_id, prior_first["first_seen_at"]),
                        )

                # Resolve: keys present in prior but absent from current
                resolved_keys = set(prior_by_key.keys()) - current_keys
                for key in resolved_keys:
                    prior_id = prior_by_key[key]
                    row = conn.execute(
                        "SELECT status, resolved_at FROM security_findings WHERE id = ? AND org_id = ?",
                        (prior_id, org_id),
                    ).fetchone()
                    if row and row["status"] != "resolved":
                        conn.execute(
                            """UPDATE security_findings
                               SET status = 'resolved',
                                   resolved_at = ?,
                                   last_seen = ?
                               WHERE id = ? AND org_id = ?""",
                            (now, now, prior_id, org_id),
                        )
                    resolved_ids.append(prior_id)

        return {
            "org_id": org_id,
            "prior_scan_id": prior_scan_id,
            "current_scan_id": current_scan_id,
            "new_count": len(new_ids),
            "unchanged_count": len(unchanged_ids),
            "resolved_count": len(resolved_ids),
            "new_violation_ids": new_ids,
            "unchanged_violation_ids": unchanged_ids,
            "resolved_violation_ids": resolved_ids,
            "reconciled_at": now,
        }

    def lifecycle_summary(self, org_id: str, days: int = 7) -> Dict[str, Any]:
        """Rolling summary of new / unchanged / resolved over the last N days."""
        if days <= 0:
            days = 7
        cutoff_dt = datetime.now(timezone.utc) - timedelta(days=days)
        cutoff = cutoff_dt.isoformat()
        with self._conn() as conn:
            new_row = conn.execute(
                """SELECT COUNT(*) AS cnt FROM security_findings
                   WHERE org_id = ? AND first_seen_at >= ?""",
                (org_id, cutoff),
            ).fetchone()
            resolved_row = conn.execute(
                """SELECT COUNT(*) AS cnt FROM security_findings
                   WHERE org_id = ? AND resolved_at IS NOT NULL AND resolved_at >= ?""",
                (org_id, cutoff),
            ).fetchone()
            unchanged_row = conn.execute(
                """SELECT COUNT(*) AS cnt FROM security_findings
                   WHERE org_id = ?
                     AND status = 'open'
                     AND previous_violation_id IS NOT NULL
                     AND last_seen >= ?""",
                (org_id, cutoff),
            ).fetchone()

        return {
            "org_id": org_id,
            "window_days": days,
            "window_start": cutoff,
            "new_last_Nd": new_row["cnt"] if new_row else 0,
            "unchanged_last_Nd": unchanged_row["cnt"] if unchanged_row else 0,
            "resolved_last_Nd": resolved_row["cnt"] if resolved_row else 0,
        }

    def lifecycle_history(self, finding_id: str, org_id: str, max_depth: int = 50) -> List[Dict[str, Any]]:
        """Walk previous_violation_id chain, returning ancestors oldest-first.

        Cycle-safe (bounded by ``max_depth`` and a visited set).
        """
        visited: set = set()
        chain: List[Dict[str, Any]] = []
        current_id: Optional[str] = finding_id
        depth = 0

        with self._conn() as conn:
            while current_id and depth < max_depth:
                if current_id in visited:
                    break
                visited.add(current_id)
                row = conn.execute(
                    """SELECT id, previous_violation_id, first_seen_at, last_seen,
                              resolved_at, status, severity, title, correlation_key,
                              scan_id, unchanged_scan_count
                       FROM security_findings WHERE id = ? AND org_id = ?""",
                    (current_id, org_id),
                ).fetchone()
                if not row:
                    break
                chain.append(self._row(row))
                current_id = row["previous_violation_id"]
                depth += 1

        # chain is newest→oldest; return oldest→newest for readability
        chain.reverse()
        return chain

    def count_lifecycle_by_day(self, org_id: str, day_iso: str) -> Dict[str, int]:
        """Return new/unchanged/resolved counts for a single day (UTC date prefix).

        Used by ``security_posture_history_engine`` to populate daily snapshots.
        ``day_iso`` should be ``YYYY-MM-DD``.
        """
        day_prefix = day_iso[:10]
        next_day = (datetime.fromisoformat(day_prefix) + timedelta(days=1)).date().isoformat()
        with self._conn() as conn:
            new_row = conn.execute(
                """SELECT COUNT(*) AS cnt FROM security_findings
                   WHERE org_id = ?
                     AND first_seen_at >= ?
                     AND first_seen_at < ?""",
                (org_id, day_prefix, next_day),
            ).fetchone()
            resolved_row = conn.execute(
                """SELECT COUNT(*) AS cnt FROM security_findings
                   WHERE org_id = ?
                     AND resolved_at IS NOT NULL
                     AND resolved_at >= ?
                     AND resolved_at < ?""",
                (org_id, day_prefix, next_day),
            ).fetchone()
            unchanged_row = conn.execute(
                """SELECT COUNT(*) AS cnt FROM security_findings
                   WHERE org_id = ?
                     AND status = 'open'
                     AND previous_violation_id IS NOT NULL
                     AND last_seen >= ?
                     AND last_seen < ?""",
                (org_id, day_prefix, next_day),
            ).fetchone()
        return {
            "new": new_row["cnt"] if new_row else 0,
            "unchanged": unchanged_row["cnt"] if unchanged_row else 0,
            "resolved": resolved_row["cnt"] if resolved_row else 0,
        }
