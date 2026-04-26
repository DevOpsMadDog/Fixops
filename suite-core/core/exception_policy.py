"""
Vulnerability Exception Policy Engine — ALDECI.

Provides org-wide suppression/exception policies with versioning and
auto-re-evaluation. Rules are persisted in SQLite and evaluated against
incoming findings using AND-combined criteria.

Supported actions:
- suppress  — hide the finding entirely
- downgrade — reduce severity to a specified level
- defer     — push the finding out by N days

Versioning: every publish_version() snapshot is stored and can be rolled back.
"""

from __future__ import annotations

import json
import logging
import re
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import uuid4

from pydantic import BaseModel, Field

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except ImportError:  # pragma: no cover - bus optional
    _get_tg_bus = None

_logger = logging.getLogger(__name__)

_DEFAULT_DB_PATH = Path(__file__).parent.parent.parent / "data" / "exception_policy.db"


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class MatchCriteria(BaseModel):
    """Criteria fields are AND-combined — all specified fields must match."""

    cve_pattern: Optional[str] = Field(None, description="Regex matched against cve_id")
    scanner: Optional[str] = Field(None, description="Exact scanner name match")
    severity: Optional[str] = Field(None, description="Exact severity match (critical/high/medium/low/info)")
    min_age_days: Optional[int] = Field(None, ge=0, description="Finding must be at least this many days old")
    max_cvss: Optional[float] = Field(None, ge=0.0, le=10.0, description="CVSS score must be <= this value")
    component_pattern: Optional[str] = Field(None, description="Regex matched against component/package name")


class ExceptionRule(BaseModel):
    """A single exception policy rule."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    name: str
    description: str = ""
    criteria: MatchCriteria
    action: str = Field(..., description="suppress | downgrade | defer")
    downgrade_to: Optional[str] = Field(None, description="Target severity when action=downgrade")
    defer_days: Optional[int] = Field(None, ge=1, description="Days to defer when action=defer")
    expires_at: Optional[datetime] = None
    enabled: bool = True
    created_by: str = "system"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    version: int = 1


class PolicyVersion(BaseModel):
    """Snapshot of all rules at a point in time."""

    version: int
    rules: List[ExceptionRule]
    published_at: datetime
    published_by: str
    changelog: str = ""


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class ExceptionPolicyEngine:
    """SQLite-backed exception policy engine with versioning."""

    def __init__(self, db_path: Optional[Path] = None) -> None:
        self.db_path = Path(db_path) if db_path else _DEFAULT_DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        with self._lock:
            conn = sqlite3.connect(str(self.db_path))
            try:
                cursor = conn.cursor()

                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS exception_rules (
                        id TEXT PRIMARY KEY,
                        org_id TEXT NOT NULL,
                        name TEXT NOT NULL,
                        description TEXT DEFAULT '',
                        criteria TEXT NOT NULL,
                        action TEXT NOT NULL,
                        downgrade_to TEXT,
                        defer_days INTEGER,
                        expires_at TEXT,
                        enabled INTEGER DEFAULT 1,
                        created_by TEXT DEFAULT 'system',
                        created_at TEXT NOT NULL,
                        version INTEGER DEFAULT 1
                    )
                    """
                )

                cursor.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_rules_org
                    ON exception_rules (org_id, enabled)
                    """
                )

                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS policy_versions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        org_id TEXT NOT NULL,
                        version INTEGER NOT NULL,
                        rules_snapshot TEXT NOT NULL,
                        published_at TEXT NOT NULL,
                        published_by TEXT NOT NULL,
                        changelog TEXT DEFAULT '',
                        UNIQUE(org_id, version)
                    )
                    """
                )

                # Tracks which finding IDs were suppressed / acted upon
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS suppression_log (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        org_id TEXT NOT NULL,
                        finding_id TEXT NOT NULL,
                        rule_id TEXT NOT NULL,
                        action TEXT NOT NULL,
                        evaluated_at TEXT NOT NULL,
                        active INTEGER DEFAULT 1
                    )
                    """
                )

                cursor.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_suppression_org
                    ON suppression_log (org_id, active)
                    """
                )

                conn.commit()
            finally:
                conn.close()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _row_to_rule(self, row: sqlite3.Row) -> ExceptionRule:
        criteria_dict = json.loads(row["criteria"])
        return ExceptionRule(
            id=row["id"],
            name=row["name"],
            description=row["description"] or "",
            criteria=MatchCriteria(**criteria_dict),
            action=row["action"],
            downgrade_to=row["downgrade_to"],
            defer_days=row["defer_days"],
            expires_at=datetime.fromisoformat(row["expires_at"]) if row["expires_at"] else None,
            enabled=bool(row["enabled"]),
            created_by=row["created_by"] or "system",
            created_at=datetime.fromisoformat(row["created_at"]),
            version=row["version"],
        )

    def _matches_criteria(self, finding: Dict[str, Any], criteria: MatchCriteria) -> bool:
        """Return True iff finding matches ALL specified criteria fields."""
        # CVE pattern
        if criteria.cve_pattern is not None:
            cve_id = finding.get("cve_id", "") or ""
            if not re.search(criteria.cve_pattern, cve_id, re.IGNORECASE):
                return False

        # Scanner
        if criteria.scanner is not None:
            scanner = finding.get("scanner", "") or finding.get("source", "") or ""
            if scanner.lower() != criteria.scanner.lower():
                return False

        # Severity
        if criteria.severity is not None:
            severity = finding.get("severity", "") or ""
            if severity.lower() != criteria.severity.lower():
                return False

        # Min age
        if criteria.min_age_days is not None:
            first_seen_raw = finding.get("first_seen") or finding.get("created_at") or finding.get("discovered_at")
            if first_seen_raw is None:
                return False
            if isinstance(first_seen_raw, str):
                first_seen = datetime.fromisoformat(first_seen_raw.replace("Z", "+00:00"))
            elif isinstance(first_seen_raw, datetime):
                first_seen = first_seen_raw
            else:
                return False
            if not first_seen.tzinfo:
                first_seen = first_seen.replace(tzinfo=timezone.utc)
            age_days = (datetime.now(timezone.utc) - first_seen).days
            if age_days < criteria.min_age_days:
                return False

        # Max CVSS
        if criteria.max_cvss is not None:
            cvss = finding.get("cvss_score") or finding.get("cvss") or finding.get("score")
            if cvss is None:
                return False
            try:
                if float(cvss) > criteria.max_cvss:
                    return False
            except (TypeError, ValueError):
                return False

        # Component pattern
        if criteria.component_pattern is not None:
            component = (
                finding.get("component")
                or finding.get("package")
                or finding.get("package_name")
                or finding.get("asset")
                or ""
            )
            if not re.search(criteria.component_pattern, str(component), re.IGNORECASE):
                return False

        return True

    def _apply_action(self, finding: Dict[str, Any], rule: ExceptionRule) -> Dict[str, Any]:
        """Build the evaluation result dict for a matched rule."""
        result: Dict[str, Any] = {
            "finding_id": finding.get("id", finding.get("finding_id", "")),
            "matched_rule_id": rule.id,
            "matched_rule_name": rule.name,
            "action": rule.action,
            "original_severity": finding.get("severity"),
        }
        if rule.action == "suppress":
            result["suppressed"] = True
        elif rule.action == "downgrade":
            result["new_severity"] = rule.downgrade_to
            result["suppressed"] = False
        elif rule.action == "defer":
            defer_until = datetime.now(timezone.utc) + timedelta(days=rule.defer_days or 30)
            result["defer_until"] = defer_until.isoformat()
            result["suppressed"] = False
        return result

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def add_rule(self, rule: ExceptionRule, org_id: str = "default") -> ExceptionRule:
        """Persist a new rule and return it."""
        with self._lock:
            conn = sqlite3.connect(str(self.db_path))
            try:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO exception_rules
                    (id, org_id, name, description, criteria, action, downgrade_to,
                     defer_days, expires_at, enabled, created_by, created_at, version)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        rule.id,
                        org_id,
                        rule.name,
                        rule.description,
                        rule.criteria.model_dump_json(),
                        rule.action,
                        rule.downgrade_to,
                        rule.defer_days,
                        rule.expires_at.isoformat() if rule.expires_at else None,
                        int(rule.enabled),
                        rule.created_by,
                        rule.created_at.isoformat(),
                        rule.version,
                    ),
                )
                conn.commit()
            finally:
                conn.close()
        _logger.info("Added exception rule %s (%s) for org %s", rule.id, rule.name, org_id)
        self._emit_event(
            "exception_policy.rule.added",
            {"rule_id": rule.id, "name": rule.name, "org_id": org_id, "action": rule.action},
        )
        return rule

    def update_rule(self, rule_id: str, updates: Dict[str, Any], org_id: str = "default") -> ExceptionRule:
        """Update fields of an existing rule, incrementing its version."""
        with self._lock:
            conn = sqlite3.connect(str(self.db_path))
            conn.row_factory = sqlite3.Row
            try:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT * FROM exception_rules WHERE id = ? AND org_id = ?",
                    (rule_id, org_id),
                )
                row = cursor.fetchone()
                if row is None:
                    raise KeyError(f"Rule {rule_id!r} not found for org {org_id!r}")

                existing = self._row_to_rule(row)
                existing_dict = existing.model_dump()

                # Merge criteria sub-dict if provided
                if "criteria" in updates:
                    if isinstance(updates["criteria"], dict):
                        merged_criteria = existing_dict["criteria"].copy()
                        merged_criteria.update(updates["criteria"])
                        updates = {**updates, "criteria": merged_criteria}

                existing_dict.update(updates)
                existing_dict["version"] = existing.version + 1

                updated = ExceptionRule(**existing_dict)

                # Handle criteria serialization
                criteria_json = updated.criteria.model_dump_json()

                cursor.execute(
                    """
                    UPDATE exception_rules
                    SET name=?, description=?, criteria=?, action=?, downgrade_to=?,
                        defer_days=?, expires_at=?, enabled=?, version=?
                    WHERE id=? AND org_id=?
                    """,
                    (
                        updated.name,
                        updated.description,
                        criteria_json,
                        updated.action,
                        updated.downgrade_to,
                        updated.defer_days,
                        updated.expires_at.isoformat() if updated.expires_at else None,
                        int(updated.enabled),
                        updated.version,
                        rule_id,
                        org_id,
                    ),
                )
                conn.commit()
            finally:
                conn.close()
        _logger.info("Updated exception rule %s (now v%d)", rule_id, updated.version)
        return updated

    def delete_rule(self, rule_id: str, org_id: str = "default") -> None:
        """Permanently delete a rule."""
        with self._lock:
            conn = sqlite3.connect(str(self.db_path))
            try:
                cursor = conn.cursor()
                cursor.execute(
                    "DELETE FROM exception_rules WHERE id = ? AND org_id = ?",
                    (rule_id, org_id),
                )
                if cursor.rowcount == 0:
                    raise KeyError(f"Rule {rule_id!r} not found for org {org_id!r}")
                conn.commit()
            finally:
                conn.close()
        _logger.info("Deleted exception rule %s", rule_id)

    def list_rules(self, org_id: str = "default", enabled_only: bool = False) -> List[ExceptionRule]:
        """Return all rules for an org, optionally filtered to enabled only."""
        with self._lock:
            conn = sqlite3.connect(str(self.db_path))
            conn.row_factory = sqlite3.Row
            try:
                cursor = conn.cursor()
                if enabled_only:
                    cursor.execute(
                        "SELECT * FROM exception_rules WHERE org_id=? AND enabled=1 ORDER BY created_at",
                        (org_id,),
                    )
                else:
                    cursor.execute(
                        "SELECT * FROM exception_rules WHERE org_id=? ORDER BY created_at",
                        (org_id,),
                    )
                rows = cursor.fetchall()
            finally:
                conn.close()
        return [self._row_to_rule(r) for r in rows]

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------

    def evaluate_finding(self, finding: Dict[str, Any], org_id: str = "default") -> Dict[str, Any]:
        """
        Evaluate a single finding against all enabled, non-expired rules.

        Returns a result dict with keys:
          - action: "none" | "suppress" | "downgrade" | "defer"
          - matched_rule_id / matched_rule_name (if matched)
          - suppressed, new_severity, defer_until (based on action)
          - original_severity
        """
        now = datetime.now(timezone.utc)
        rules = self.list_rules(org_id, enabled_only=True)

        for rule in rules:
            # Skip expired
            if rule.expires_at and rule.expires_at.replace(tzinfo=timezone.utc if not rule.expires_at.tzinfo else rule.expires_at.tzinfo) <= now:
                continue
            if self._matches_criteria(finding, rule.criteria):
                result = self._apply_action(finding, rule)
                # Log to suppression_log
                finding_id = finding.get("id", finding.get("finding_id", ""))
                if finding_id:
                    self._log_suppression(org_id, finding_id, rule.id, rule.action)
                return result

        return {
            "finding_id": finding.get("id", finding.get("finding_id", "")),
            "action": "none",
            "suppressed": False,
            "original_severity": finding.get("severity"),
            "matched_rule_id": None,
            "matched_rule_name": None,
        }

    def evaluate_batch(self, findings: List[Dict[str, Any]], org_id: str = "default") -> List[Dict[str, Any]]:
        """Evaluate a list of findings, returning one result dict per finding."""
        return [self.evaluate_finding(f, org_id) for f in findings]

    def _log_suppression(self, org_id: str, finding_id: str, rule_id: str, action: str) -> None:
        with self._lock:
            conn = sqlite3.connect(str(self.db_path))
            try:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO suppression_log (org_id, finding_id, rule_id, action, evaluated_at, active)
                    VALUES (?, ?, ?, ?, ?, 1)
                    """,
                    (org_id, finding_id, rule_id, action, datetime.now(timezone.utc).isoformat()),
                )
                conn.commit()
            finally:
                conn.close()

    # ------------------------------------------------------------------
    # Versioning
    # ------------------------------------------------------------------

    def publish_version(
        self,
        org_id: str = "default",
        published_by: str = "system",
        changelog: str = "",
    ) -> PolicyVersion:
        """Snapshot the current rules as a new policy version."""
        rules = self.list_rules(org_id)

        with self._lock:
            conn = sqlite3.connect(str(self.db_path))
            conn.row_factory = sqlite3.Row
            try:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT COALESCE(MAX(version), 0) FROM policy_versions WHERE org_id=?",
                    (org_id,),
                )
                row = cursor.fetchone()
                next_version = (row[0] or 0) + 1

                snapshot = json.dumps([r.model_dump(mode="json") for r in rules])
                now = datetime.now(timezone.utc)

                cursor.execute(
                    """
                    INSERT INTO policy_versions (org_id, version, rules_snapshot, published_at, published_by, changelog)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (org_id, next_version, snapshot, now.isoformat(), published_by, changelog),
                )
                conn.commit()
            finally:
                conn.close()

        pv = PolicyVersion(
            version=next_version,
            rules=rules,
            published_at=datetime.now(timezone.utc),
            published_by=published_by,
            changelog=changelog,
        )
        _logger.info("Published policy version %d for org %s", next_version, org_id)
        return pv

    def get_version_history(self, org_id: str = "default") -> List[PolicyVersion]:
        """Return all published versions for an org, newest first."""
        with self._lock:
            conn = sqlite3.connect(str(self.db_path))
            conn.row_factory = sqlite3.Row
            try:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT * FROM policy_versions WHERE org_id=? ORDER BY version DESC",
                    (org_id,),
                )
                rows = cursor.fetchall()
            finally:
                conn.close()

        versions: List[PolicyVersion] = []
        for row in rows:
            rules_data = json.loads(row["rules_snapshot"])
            rules = [ExceptionRule(**rd) for rd in rules_data]
            versions.append(
                PolicyVersion(
                    version=row["version"],
                    rules=rules,
                    published_at=datetime.fromisoformat(row["published_at"]),
                    published_by=row["published_by"],
                    changelog=row["changelog"] or "",
                )
            )
        return versions

    def rollback_to_version(self, org_id: str, version: int) -> None:
        """Restore the rules from a previously published version snapshot."""
        history = self.get_version_history(org_id)
        target: Optional[PolicyVersion] = None
        for pv in history:
            if pv.version == version:
                target = pv
                break

        if target is None:
            raise KeyError(f"Policy version {version} not found for org {org_id!r}")

        with self._lock:
            conn = sqlite3.connect(str(self.db_path))
            try:
                cursor = conn.cursor()
                # Remove existing rules for org
                cursor.execute("DELETE FROM exception_rules WHERE org_id=?", (org_id,))
                # Re-insert snapshot rules
                for rule in target.rules:
                    criteria_json = rule.criteria.model_dump_json()
                    cursor.execute(
                        """
                        INSERT INTO exception_rules
                        (id, org_id, name, description, criteria, action, downgrade_to,
                         defer_days, expires_at, enabled, created_by, created_at, version)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            rule.id,
                            org_id,
                            rule.name,
                            rule.description,
                            criteria_json,
                            rule.action,
                            rule.downgrade_to,
                            rule.defer_days,
                            rule.expires_at.isoformat() if rule.expires_at else None,
                            int(rule.enabled),
                            rule.created_by,
                            rule.created_at.isoformat() if isinstance(rule.created_at, datetime) else rule.created_at,
                            rule.version,
                        ),
                    )
                conn.commit()
            finally:
                conn.close()
        _logger.info("Rolled org %s back to policy version %d", org_id, version)

    # ------------------------------------------------------------------
    # Maintenance
    # ------------------------------------------------------------------

    def expire_rules(self, org_id: str = "default") -> int:
        """Disable rules whose expires_at is in the past. Returns count disabled."""
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            conn = sqlite3.connect(str(self.db_path))
            try:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    UPDATE exception_rules
                    SET enabled = 0
                    WHERE org_id=? AND enabled=1 AND expires_at IS NOT NULL AND expires_at <= ?
                    """,
                    (org_id, now),
                )
                count = cursor.rowcount
                conn.commit()
            finally:
                conn.close()
        if count:
            _logger.info("Expired %d rule(s) for org %s", count, org_id)
        return count

    def get_suppression_stats(self, org_id: str = "default") -> Dict[str, Any]:
        """Return stats: rules count, findings suppressed, breakdown by action."""
        rules = self.list_rules(org_id)
        total_rules = len(rules)
        enabled_rules = sum(1 for r in rules if r.enabled)

        with self._lock:
            conn = sqlite3.connect(str(self.db_path))
            conn.row_factory = sqlite3.Row
            try:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT action, COUNT(*) as cnt FROM suppression_log WHERE org_id=? AND active=1 GROUP BY action",
                    (org_id,),
                )
                action_rows = cursor.fetchall()

                cursor.execute(
                    "SELECT COUNT(DISTINCT finding_id) FROM suppression_log WHERE org_id=? AND active=1",
                    (org_id,),
                )
                findings_row = cursor.fetchone()
            finally:
                conn.close()

        by_action: Dict[str, int] = {r["action"]: r["cnt"] for r in action_rows}
        total_findings_acted = findings_row[0] if findings_row else 0

        return {
            "org_id": org_id,
            "total_rules": total_rules,
            "enabled_rules": enabled_rules,
            "disabled_rules": total_rules - enabled_rules,
            "total_findings_acted": total_findings_acted,
            "by_action": by_action,
        }

    def re_evaluate_all(self, org_id: str = "default") -> Dict[str, Any]:
        """
        Re-evaluate all previously acted-upon findings against the current rule set.

        Marks suppression_log entries inactive if the finding no longer matches
        any rule. Returns counts of unchanged, released, and total.
        """
        with self._lock:
            conn = sqlite3.connect(str(self.db_path))
            conn.row_factory = sqlite3.Row
            try:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT DISTINCT finding_id FROM suppression_log
                    WHERE org_id=? AND active=1
                    """,
                    (org_id,),
                )
                finding_ids = [row["finding_id"] for row in cursor.fetchall()]
            finally:
                conn.close()

        released = 0
        unchanged = 0

        for fid in finding_ids:
            # Re-evaluate with a minimal proxy finding (id only — rules that
            # need full finding data will not match and findings get released)
            proxy = {"id": fid, "finding_id": fid}
            result = self.evaluate_finding(proxy, org_id)
            if result.get("action") == "none":
                # No rule matched — deactivate log entries
                self._deactivate_suppression(org_id, fid)
                released += 1
            else:
                unchanged += 1

        return {
            "org_id": org_id,
            "total_evaluated": len(finding_ids),
            "unchanged": unchanged,
            "released": released,
        }

    def _deactivate_suppression(self, org_id: str, finding_id: str) -> None:
        with self._lock:
            conn = sqlite3.connect(str(self.db_path))
            try:
                cursor = conn.cursor()
                cursor.execute(
                    "UPDATE suppression_log SET active=0 WHERE org_id=? AND finding_id=?",
                    (org_id, finding_id),
                )
                conn.commit()
            finally:
                conn.close()

    # ------------------------------------------------------------------
    # TrustGraph event emission (best-effort, non-blocking)
    # ------------------------------------------------------------------

    def _emit_event(self, event_type: str, payload: "dict[str, Any]") -> None:
        """Emit an event to the TrustGraph event bus. Never raises."""
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
                import asyncio
                import inspect
                if inspect.iscoroutine(result):
                    try:
                        loop = asyncio.get_running_loop()
                        loop.create_task(result)
                    except RuntimeError:
                        result.close()
            except Exception:  # pragma: no cover
                pass
        except Exception:  # pragma: no cover - best-effort telemetry
            pass

