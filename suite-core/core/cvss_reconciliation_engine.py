"""CVSS Cross-Tool Reconciliation Engine.

When the same CVE/finding is reported by multiple scanners (semgrep, trivy,
grype, snyk) with DIFFERENT CVSS scores, this engine:

  1. Groups multi-tool findings by CVE (or by normalised title when no CVE).
  2. Surfaces the per-tool CVSS divergence (min/max/spread).
  3. Accepts a team override: who, when, why, and what the authoritative CVSS is.
  4. Persists the decision org-scoped in SQLite.
  5. Exposes the authoritative CVSS downstream via ``get_authoritative_cvss()``.

Design
------
- SQLite-backed (same pattern as SmartDedup / SecurityFindingsEngine).
- No mocks, no stubs, no placeholder data.
- Org-scoped: every record carries org_id so multi-tenant isolation is preserved.
- Minimal dependencies: stdlib + pydantic.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

_DB_PATH = Path(__file__).parent / "cvss_reconciliation.db"

# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class ToolCvssEntry(BaseModel):
    """CVSS score reported by a single scanner tool."""

    tool: str
    finding_id: str
    cvss_score: float = Field(ge=0.0, le=10.0)
    severity: str = ""
    source_url: str = ""


class CvssConflictGroup(BaseModel):
    """One CVE (or title) seen by 2+ tools with diverging CVSS scores."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    org_id: str
    cve_id: str                          # canonical identifier (CVE-YYYY-NNNN or title slug)
    tool_scores: List[ToolCvssEntry]     # one entry per tool
    min_cvss: float
    max_cvss: float
    spread: float                        # max - min
    finding_ids: List[str]              # all finding IDs in this group
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    @property
    def has_divergence(self) -> bool:
        """True when two or more tools disagree by more than 0.5 CVSS points."""
        return self.spread > 0.5


class CvssOverrideDecision(BaseModel):
    """Team-validated authoritative CVSS decision for a conflict group."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    org_id: str
    conflict_group_id: str
    cve_id: str
    authoritative_cvss: float = Field(ge=0.0, le=10.0)
    authoritative_severity: str         # critical | high | medium | low | info
    decided_by: str                     # user / team identifier
    reason: str                         # mandatory justification
    decided_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    supersedes_id: Optional[str] = None  # previous decision this replaces


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class CvssReconciliationEngine:
    """Detect and resolve CVSS divergence across scanning tools.

    Usage::

        engine = CvssReconciliationEngine()

        # Analyse a batch of findings from multiple scanners
        groups = engine.detect_conflicts(findings, org_id="acme")

        # A team member reviews and picks the authoritative CVSS
        decision = engine.record_override(
            org_id="acme",
            conflict_group_id=groups[0].id,
            cve_id="CVE-2023-1234",
            authoritative_cvss=8.5,
            authoritative_severity="high",
            decided_by="alice@example.com",
            reason="Trivy score accounts for default config; semgrep score is for worst-case.",
        )

        # Downstream consumers ask for the authoritative score
        score = engine.get_authoritative_cvss("acme", "CVE-2023-1234")
        # => 8.5
    """

    def __init__(self, db_path: Optional[Path] = None) -> None:
        self._db_path = db_path or _DB_PATH
        self._init_db()

    # ------------------------------------------------------------------
    # DB bootstrap
    # ------------------------------------------------------------------

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS cvss_conflict_groups (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    cve_id          TEXT NOT NULL,
                    tool_scores     TEXT NOT NULL DEFAULT '[]',
                    finding_ids     TEXT NOT NULL DEFAULT '[]',
                    min_cvss        REAL NOT NULL DEFAULT 0.0,
                    max_cvss        REAL NOT NULL DEFAULT 0.0,
                    spread          REAL NOT NULL DEFAULT 0.0,
                    created_at      TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_cg_org ON cvss_conflict_groups(org_id);
                CREATE INDEX IF NOT EXISTS idx_cg_cve ON cvss_conflict_groups(org_id, cve_id);

                CREATE TABLE IF NOT EXISTS cvss_override_decisions (
                    id                      TEXT PRIMARY KEY,
                    org_id                  TEXT NOT NULL,
                    conflict_group_id       TEXT NOT NULL,
                    cve_id                  TEXT NOT NULL,
                    authoritative_cvss      REAL NOT NULL,
                    authoritative_severity  TEXT NOT NULL DEFAULT '',
                    decided_by              TEXT NOT NULL,
                    reason                  TEXT NOT NULL,
                    decided_at              TEXT NOT NULL,
                    supersedes_id           TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_od_org ON cvss_override_decisions(org_id);
                CREATE INDEX IF NOT EXISTS idx_od_cve ON cvss_override_decisions(org_id, cve_id);
                CREATE INDEX IF NOT EXISTS idx_od_group ON cvss_override_decisions(conflict_group_id);
                """
            )

    # ------------------------------------------------------------------
    # Core: detect conflicts
    # ------------------------------------------------------------------

    def detect_conflicts(
        self,
        findings: List[Dict[str, Any]],
        org_id: str,
        min_spread: float = 0.0,
        persist: bool = True,
    ) -> List[CvssConflictGroup]:
        """Analyse a batch of findings and return CVSS conflict groups.

        A conflict group is created for every CVE (or title slug when no CVE)
        that appears in findings from at least two different tools.  Groups
        with a CVSS spread below ``min_spread`` are still returned but flagged
        via :attr:`CvssConflictGroup.has_divergence`.

        Args:
            findings:   List of finding dicts.  Each dict must have at least:
                        ``id`` (or ``finding_id``), ``scanner`` (or ``tool``),
                        ``cvss_score`` (or ``cvss``).  ``cve_id`` / ``cve`` is
                        strongly recommended for accurate grouping.
            org_id:     Tenant identifier.
            min_spread: Only persist / return groups whose CVSS spread is >=
                        this threshold.  Default 0.0 returns all multi-tool groups.
            persist:    Write groups to SQLite (default True).

        Returns:
            List of :class:`CvssConflictGroup` instances, one per conflicting CVE.
        """
        if not findings:
            return []

        # Group findings by CVE / title key and scanner
        # key -> {scanner -> (finding_id, cvss_score, severity)}
        from collections import defaultdict
        import re

        def _fid(f: Dict[str, Any]) -> str:
            for field in ("id", "finding_id", "uid"):
                v = f.get(field)
                if v:
                    return str(v)
            return str(uuid.uuid4())

        def _tool(f: Dict[str, Any]) -> str:
            for field in ("scanner", "tool", "source", "provider", "scanner_type"):
                v = f.get(field)
                if v and isinstance(v, str):
                    return v.strip().lower()
            return "unknown"

        def _cvss(f: Dict[str, Any]) -> Optional[float]:
            for field in ("cvss_score", "cvss", "cvss_v3", "base_score"):
                v = f.get(field)
                if v is not None:
                    try:
                        score = float(v)
                        if 0.0 <= score <= 10.0:
                            return score
                    except (TypeError, ValueError):
                        pass
            return None

        def _severity(f: Dict[str, Any]) -> str:
            for field in ("severity", "risk", "priority"):
                v = f.get(field)
                if v and isinstance(v, str):
                    return v.strip().lower()
            return ""

        def _cve_key(f: Dict[str, Any]) -> Optional[str]:
            for field in ("cve_id", "cve", "vulnerability_id"):
                v = f.get(field)
                if v and isinstance(v, str):
                    m = re.search(r"CVE-\d{4}-\d{4,}", str(v), re.IGNORECASE)
                    if m:
                        return m.group(0).upper()
            # Try title+description
            for field in ("title", "description", "name"):
                v = f.get(field, "")
                m = re.search(r"CVE-\d{4}-\d{4,}", str(v), re.IGNORECASE)
                if m:
                    return m.group(0).upper()
            return None

        def _title_slug(f: Dict[str, Any]) -> str:
            for field in ("title", "rule_id", "check_id", "name"):
                v = f.get(field)
                if v and isinstance(v, str):
                    return re.sub(r"[^a-z0-9]", "-", v.strip().lower())[:60]
            return ""

        # Accumulate: cve_key -> list of (finding_id, tool, cvss, severity)
        key_map: Dict[str, List[Tuple[str, str, float, str]]] = defaultdict(list)

        for f in findings:
            cvss = _cvss(f)
            if cvss is None:
                continue  # no CVSS — cannot contribute to reconciliation
            fid = _fid(f)
            tool = _tool(f)
            sev = _severity(f)
            key = _cve_key(f) or _title_slug(f)
            if not key:
                continue
            key_map[key].append((fid, tool, cvss, sev))

        groups: List[CvssConflictGroup] = []

        for cve_key, entries in key_map.items():
            # Need entries from at least 2 distinct tools to be a conflict candidate
            tools_seen: Dict[str, Tuple[str, float, str]] = {}
            for fid, tool, cvss, sev in entries:
                if tool not in tools_seen:
                    tools_seen[tool] = (fid, cvss, sev)
                else:
                    # Keep the entry with the higher CVSS per tool
                    if cvss > tools_seen[tool][1]:
                        tools_seen[tool] = (fid, cvss, sev)

            if len(tools_seen) < 2:
                continue

            scores = [cv for _, cv, _ in tools_seen.values()]
            min_c = min(scores)
            max_c = max(scores)
            spread = round(max_c - min_c, 4)

            if spread < min_spread:
                continue

            tool_entries = [
                ToolCvssEntry(
                    tool=tool,
                    finding_id=fid,
                    cvss_score=cv,
                    severity=sev,
                )
                for tool, (fid, cv, sev) in tools_seen.items()
            ]
            all_fids = [fid for fid, _, _ in tools_seen.values()]

            group = CvssConflictGroup(
                org_id=org_id,
                cve_id=cve_key,
                tool_scores=tool_entries,
                min_cvss=round(min_c, 4),
                max_cvss=round(max_c, 4),
                spread=spread,
                finding_ids=all_fids,
            )
            groups.append(group)

            if persist:
                self._persist_group(group)

        logger.info(
            "detect_conflicts: org=%s findings=%d conflict_groups=%d",
            org_id,
            len(findings),
            len(groups),
        )
        return groups

    # ------------------------------------------------------------------
    # Core: record team override
    # ------------------------------------------------------------------

    def record_override(
        self,
        org_id: str,
        conflict_group_id: str,
        cve_id: str,
        authoritative_cvss: float,
        authoritative_severity: str,
        decided_by: str,
        reason: str,
    ) -> CvssOverrideDecision:
        """Record a team-validated authoritative CVSS decision.

        Raises:
            ValueError: If ``decided_by`` or ``reason`` are blank.
        """
        if not decided_by or not decided_by.strip():
            raise ValueError("decided_by must not be blank")
        if not reason or not reason.strip():
            raise ValueError("reason must not be blank — a justification is required")
        if not (0.0 <= authoritative_cvss <= 10.0):
            raise ValueError(f"authoritative_cvss must be in [0, 10], got {authoritative_cvss}")

        # Find the most recent existing decision for this group (to set supersedes_id)
        supersedes_id: Optional[str] = None
        with self._conn() as conn:
            row = conn.execute(
                """SELECT id FROM cvss_override_decisions
                   WHERE org_id = ? AND conflict_group_id = ?
                   ORDER BY decided_at DESC LIMIT 1""",
                (org_id, conflict_group_id),
            ).fetchone()
            if row:
                supersedes_id = row["id"]

        decision = CvssOverrideDecision(
            org_id=org_id,
            conflict_group_id=conflict_group_id,
            cve_id=cve_id,
            authoritative_cvss=round(float(authoritative_cvss), 4),
            authoritative_severity=authoritative_severity.strip().lower(),
            decided_by=decided_by.strip(),
            reason=reason.strip(),
            supersedes_id=supersedes_id,
        )
        self._persist_decision(decision)
        logger.info(
            "record_override: org=%s cve=%s cvss=%.1f by=%s",
            org_id,
            cve_id,
            authoritative_cvss,
            decided_by,
        )
        return decision

    # ------------------------------------------------------------------
    # Downstream lookup
    # ------------------------------------------------------------------

    def get_authoritative_cvss(
        self, org_id: str, cve_id: str
    ) -> Optional[Dict[str, Any]]:
        """Return the latest authoritative CVSS decision for a CVE.

        Returns ``None`` if no decision has been recorded yet.

        The returned dict includes:
          - ``authoritative_cvss``: float
          - ``authoritative_severity``: str
          - ``decided_by``: str
          - ``reason``: str
          - ``decided_at``: ISO-8601 str
          - ``decision_id``: str
          - ``conflict_group_id``: str
        """
        with self._conn() as conn:
            row = conn.execute(
                """SELECT id, authoritative_cvss, authoritative_severity,
                          decided_by, reason, decided_at, conflict_group_id
                   FROM cvss_override_decisions
                   WHERE org_id = ? AND cve_id = ?
                   ORDER BY decided_at DESC LIMIT 1""",
                (org_id, cve_id),
            ).fetchone()
        if not row:
            return None
        return {
            "authoritative_cvss":     row["authoritative_cvss"],
            "authoritative_severity": row["authoritative_severity"],
            "decided_by":             row["decided_by"],
            "reason":                 row["reason"],
            "decided_at":             row["decided_at"],
            "decision_id":            row["id"],
            "conflict_group_id":      row["conflict_group_id"],
        }

    def list_conflicts(
        self,
        org_id: str,
        min_spread: float = 0.0,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """List conflict groups for an org with optional spread filter.

        Each item in the returned list is a dict with the conflict group data
        plus an ``override`` key that is ``None`` or the latest decision dict.
        """
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT * FROM cvss_conflict_groups
                   WHERE org_id = ? AND spread >= ?
                   ORDER BY spread DESC
                   LIMIT ?""",
                (org_id, min_spread, limit),
            ).fetchall()

        result = []
        for row in rows:
            group_dict = {
                "id":           row["id"],
                "org_id":       row["org_id"],
                "cve_id":       row["cve_id"],
                "tool_scores":  json.loads(row["tool_scores"]),
                "finding_ids":  json.loads(row["finding_ids"]),
                "min_cvss":     row["min_cvss"],
                "max_cvss":     row["max_cvss"],
                "spread":       row["spread"],
                "created_at":   row["created_at"],
                "override":     self.get_authoritative_cvss(row["org_id"], row["cve_id"]),
            }
            result.append(group_dict)
        return result

    def list_overrides(self, org_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Return all recorded override decisions for an org (newest first)."""
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT * FROM cvss_override_decisions
                   WHERE org_id = ?
                   ORDER BY decided_at DESC
                   LIMIT ?""",
                (org_id, limit),
            ).fetchall()
        return [
            {
                "id":                     r["id"],
                "org_id":                 r["org_id"],
                "conflict_group_id":      r["conflict_group_id"],
                "cve_id":                 r["cve_id"],
                "authoritative_cvss":     r["authoritative_cvss"],
                "authoritative_severity": r["authoritative_severity"],
                "decided_by":             r["decided_by"],
                "reason":                 r["reason"],
                "decided_at":             r["decided_at"],
                "supersedes_id":          r["supersedes_id"],
            }
            for r in rows
        ]

    # ------------------------------------------------------------------
    # Private persistence helpers
    # ------------------------------------------------------------------

    def _persist_group(self, group: CvssConflictGroup) -> None:
        with self._conn() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO cvss_conflict_groups
                   (id, org_id, cve_id, tool_scores, finding_ids,
                    min_cvss, max_cvss, spread, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    group.id,
                    group.org_id,
                    group.cve_id,
                    json.dumps([e.model_dump() for e in group.tool_scores]),
                    json.dumps(group.finding_ids),
                    group.min_cvss,
                    group.max_cvss,
                    group.spread,
                    group.created_at,
                ),
            )

    def _persist_decision(self, decision: CvssOverrideDecision) -> None:
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO cvss_override_decisions
                   (id, org_id, conflict_group_id, cve_id,
                    authoritative_cvss, authoritative_severity,
                    decided_by, reason, decided_at, supersedes_id)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    decision.id,
                    decision.org_id,
                    decision.conflict_group_id,
                    decision.cve_id,
                    decision.authoritative_cvss,
                    decision.authoritative_severity,
                    decision.decided_by,
                    decision.reason,
                    decision.decided_at,
                    decision.supersedes_id,
                ),
            )
