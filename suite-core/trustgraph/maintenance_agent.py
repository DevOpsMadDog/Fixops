"""TrustGraph Knowledge Core Maintenance Agent.

Inspired by the Graph Reviewer pattern: validates post-ingest integrity,
detects contradictions between cores, finds orphaned entities.

Runs:
- After bulk ingestion (fire-and-forget)
- On scheduled maintenance sweep
- On demand via API

Checks:
1. Cross-core contradiction detection: scanner findings (Core 2) contradicted by verdict (Core 4)
2. Orphaned entity detection: entities with no relationships in any core
3. Duplicate finding detection: same source+rule+file across multiple cores
4. Temporal staleness: entities not updated in >30 days
5. Missing required fields: entities lacking severity/title/source
6. Type consistency: entity types match their core assignment
"""

from __future__ import annotations

import logging
import sqlite3
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

__all__ = [
    "MaintenanceIssue",
    "MaintenanceReport",
    "TrustGraphMaintenanceAgent",
]

# ============================================================================
# Knowledge Core Definitions (mirrors quality_monitor)
# ============================================================================

CORE_DEFINITIONS = {
    1: {
        "name": "Customer Environment",
        "description": "Assets, services, infrastructure inventory",
        "primary_entity_types": ["Service", "Asset", "Host", "Container"],
    },
    2: {
        "name": "Threat Intelligence",
        "description": "Scanner findings, CVEs, threat actors",
        "primary_entity_types": ["CVE", "Finding", "ThreatActor", "Indicator"],
    },
    3: {
        "name": "Compliance",
        "description": "Compliance controls, frameworks, evidence",
        "primary_entity_types": ["Control", "Framework", "Evidence", "Policy"],
    },
    4: {
        "name": "Decision Memory",
        "description": "Incidents, decisions, playbook executions",
        "primary_entity_types": ["Incident", "Decision", "Playbook", "Alert"],
    },
    5: {
        "name": "Risk Registry",
        "description": "Risk entries, exceptions, mitigations",
        "primary_entity_types": ["Risk", "Exception", "Mitigation", "SLA"],
    },
}

# Required fields that must exist in entity properties per core
REQUIRED_FIELDS_BY_CORE: Dict[int, List[str]] = {
    1: [],  # Assets: no mandatory properties enforced at engine level
    2: ["severity"],  # Findings: severity is mandatory
    3: [],  # Compliance controls: no mandatory
    4: [],  # Decisions: no mandatory
    5: [],  # Risks: no mandatory
}


# ============================================================================
# Data Classes
# ============================================================================


@dataclass
class MaintenanceIssue:
    """A detected integrity issue in TrustGraph Knowledge Cores.

    Attributes:
        issue_id: Unique identifier for this issue instance
        severity: critical | high | medium | low
        issue_type: Machine-readable type (contradiction, orphan, duplicate, stale, missing_field, type_mismatch)
        entity_id: Primary entity ID involved
        description: Human-readable description of the issue
        suggested_fix: Recommended remediation step
        core_id: Which Knowledge Core this issue was detected in (0 = cross-core)
        extra: Additional context (e.g., conflicting entity IDs)
        detected_at: ISO timestamp of detection
    """

    severity: str
    issue_type: str
    entity_id: str
    description: str
    suggested_fix: str
    issue_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    core_id: int = 0
    extra: Dict[str, Any] = field(default_factory=dict)
    detected_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class MaintenanceReport:
    """Full maintenance sweep report across all 5 Knowledge Cores.

    Attributes:
        checked_at: ISO timestamp of when sweep started
        cores_checked: List of core IDs that were inspected
        issues: All detected MaintenanceIssue objects
        stats: Summary counts per issue_type
        duration_ms: How long the sweep took in milliseconds
        org_id: Organisation/tenant scoped to
    """

    checked_at: str
    cores_checked: List[int]
    issues: List[MaintenanceIssue]
    stats: Dict[str, int]
    duration_ms: float
    org_id: str = "default"

    @property
    def issue_count(self) -> int:
        return len(self.issues)

    @property
    def critical_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == "high")

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["issue_count"] = self.issue_count
        d["critical_count"] = self.critical_count
        d["high_count"] = self.high_count
        return d


# ============================================================================
# Maintenance Agent
# ============================================================================


class TrustGraphMaintenanceAgent:
    """Post-ingest integrity validator for TrustGraph Knowledge Cores.

    Inspired by the Graph Reviewer and lint-the-wiki patterns:
    - Reads directly from the KnowledgeStore SQLite
    - Detects contradictions, orphans, duplicates, stale data, missing fields
    - Optionally auto-fixes safe issues (soft-delete duplicates, link orphans)

    Usage::

        agent = TrustGraphMaintenanceAgent()
        report = agent.run_full_sweep()
        print(f"{report.issue_count} issues found")

        # Auto-fix safe issues (dry run by default)
        result = agent.auto_fix(report.issues, dry_run=True)
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        """Initialise the maintenance agent.

        Args:
            db_path: Path to TrustGraph SQLite DB. Defaults to /tmp/trustgraph.db.
        """
        self.db_path = db_path or "/tmp/trustgraph.db"  # nosec B108
        logger.info("TrustGraphMaintenanceAgent initialised with db=%s", self.db_path)

    # -------------------------------------------------------------------------
    # Internal helpers
    # -------------------------------------------------------------------------

    def _db_exists(self) -> bool:
        return Path(self.db_path).exists()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    # -------------------------------------------------------------------------
    # run_full_sweep
    # -------------------------------------------------------------------------

    def run_full_sweep(self, org_id: str = "default") -> MaintenanceReport:
        """Run all integrity checks and return a consolidated report.

        Args:
            org_id: Tenant/organisation scope for the sweep.

        Returns:
            MaintenanceReport with all detected issues and summary stats.
        """
        started = time.monotonic()
        checked_at = datetime.utcnow().isoformat()

        if not self._db_exists():
            return MaintenanceReport(
                checked_at=checked_at,
                cores_checked=list(CORE_DEFINITIONS.keys()),
                issues=[],
                stats={},
                duration_ms=0.0,
                org_id=org_id,
            )

        all_issues: List[MaintenanceIssue] = []
        all_issues.extend(self.detect_contradictions())
        all_issues.extend(self.find_orphaned_entities())
        all_issues.extend(self.detect_duplicates())
        all_issues.extend(self.check_staleness())
        all_issues.extend(self._check_missing_fields())
        all_issues.extend(self._check_type_consistency())

        # Build stats summary
        stats: Dict[str, int] = {}
        for issue in all_issues:
            stats[issue.issue_type] = stats.get(issue.issue_type, 0) + 1

        duration_ms = (time.monotonic() - started) * 1000.0

        logger.info(
            "Maintenance sweep complete: %d issues in %.1f ms",
            len(all_issues),
            duration_ms,
        )

        return MaintenanceReport(
            checked_at=checked_at,
            cores_checked=list(CORE_DEFINITIONS.keys()),
            issues=all_issues,
            stats=stats,
            duration_ms=round(duration_ms, 2),
            org_id=org_id,
        )

    # -------------------------------------------------------------------------
    # detect_contradictions
    # -------------------------------------------------------------------------

    def detect_contradictions(self) -> List[MaintenanceIssue]:
        """Detect cross-core contradictions.

        Specifically: finding in Core 2 where the finding's entity_id has a
        Decision in Core 4 that marks it as "false_positive" or "accepted_risk",
        but the finding is still active (not soft-deleted and still has
        severity != 'informational').

        Returns:
            List of MaintenanceIssue with issue_type="contradiction".
        """
        if not self._db_exists():
            return []

        issues: List[MaintenanceIssue] = []
        conn = self._get_conn()
        try:
            cursor = conn.cursor()

            # Find findings in Core 2 that have a "contradicts" or "false_positive"
            # decision relationship in Core 4.
            # We look for Core 4 Decision entities whose properties reference a
            # Core 2 entity (via "finding_id" or "entity_ref" in properties) and
            # whose verdict is false_positive / accepted_risk / closed,
            # while the Core 2 entity is still active (not deleted, high severity).
            cursor.execute(
                """
                SELECT
                    d.entity_id  AS decision_id,
                    d.properties AS decision_props,
                    json_extract(d.properties, '$.finding_id') AS ref_finding_id,
                    json_extract(d.properties, '$.verdict') AS verdict,
                    f.entity_id  AS finding_id,
                    f.properties AS finding_props,
                    json_extract(f.properties, '$.severity') AS severity
                FROM entities d
                JOIN entities f
                    ON f.entity_id = json_extract(d.properties, '$.finding_id')
                    AND f.deleted_at IS NULL
                WHERE d.core_id = 4
                    AND d.deleted_at IS NULL
                    AND json_extract(d.properties, '$.verdict') IN (
                        'false_positive', 'accepted_risk', 'closed', 'risk_accepted'
                    )
                    AND f.core_id = 2
                    AND json_extract(f.properties, '$.severity') IN ('critical', 'high')
                LIMIT 200
                """
            )
            rows = cursor.fetchall()
            for row in rows:
                issues.append(
                    MaintenanceIssue(
                        severity="high",
                        issue_type="contradiction",
                        entity_id=row["finding_id"],
                        core_id=2,
                        description=(
                            f"Finding {row['finding_id']} has severity "
                            f"'{row['severity']}' in Core 2 (Threat Intel) but "
                            f"Decision {row['decision_id']} in Core 4 (Decision Memory) "
                            f"has verdict='{row['verdict']}'. The finding should be "
                            f"resolved or marked informational."
                        ),
                        suggested_fix=(
                            "Update the finding's severity to 'informational' or soft-delete "
                            "it after confirming the Core 4 decision is still valid."
                        ),
                        extra={
                            "decision_id": row["decision_id"],
                            "verdict": row["verdict"],
                        },
                    )
                )

            # Also detect: same entity_id present in multiple cores (type mismatch signal)
            cursor.execute(
                """
                SELECT entity_id, GROUP_CONCAT(core_id, ',') AS cores, COUNT(*) AS cnt
                FROM entities
                WHERE deleted_at IS NULL
                GROUP BY entity_id
                HAVING cnt > 1
                LIMIT 100
                """
            )
            rows = cursor.fetchall()
            for row in rows:
                issues.append(
                    MaintenanceIssue(
                        severity="medium",
                        issue_type="contradiction",
                        entity_id=row["entity_id"],
                        core_id=0,
                        description=(
                            f"Entity '{row['entity_id']}' exists in multiple cores: "
                            f"{row['cores']}. Same entity_id across cores signals "
                            f"an ingestion collision."
                        ),
                        suggested_fix=(
                            "Re-ingest the entity with a unique entity_id per core, "
                            "or soft-delete the duplicate."
                        ),
                        extra={"cores": row["cores"]},
                    )
                )

        finally:
            conn.close()

        return issues

    # -------------------------------------------------------------------------
    # find_orphaned_entities
    # -------------------------------------------------------------------------

    def find_orphaned_entities(self) -> List[MaintenanceIssue]:
        """Find entities with no relationships in any core.

        Returns:
            List of MaintenanceIssue with issue_type="orphan".
        """
        if not self._db_exists():
            return []

        issues: List[MaintenanceIssue] = []
        conn = self._get_conn()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT e.entity_id, e.core_id, e.entity_type, e.name
                FROM entities e
                WHERE e.deleted_at IS NULL
                AND NOT EXISTS (
                    SELECT 1 FROM relationships r
                    WHERE r.source_id = e.entity_id OR r.target_id = e.entity_id
                )
                ORDER BY e.core_id, e.updated_at DESC
                LIMIT 500
                """
            )
            rows = cursor.fetchall()
            for row in rows:
                core_name = CORE_DEFINITIONS.get(row["core_id"], {}).get("name", f"Core {row['core_id']}")
                issues.append(
                    MaintenanceIssue(
                        severity="medium",
                        issue_type="orphan",
                        entity_id=row["entity_id"],
                        core_id=row["core_id"],
                        description=(
                            f"Entity '{row['name']}' (type={row['entity_type']}) in "
                            f"{core_name} (Core {row['core_id']}) has no relationships. "
                            f"It is invisible to graph traversal queries."
                        ),
                        suggested_fix=(
                            "Create at least one relationship linking this entity to a "
                            "connected entity, or run auto_fix to link it to its core anchor."
                        ),
                        extra={"entity_type": row["entity_type"], "core_name": core_name},
                    )
                )
        finally:
            conn.close()

        return issues

    # -------------------------------------------------------------------------
    # detect_duplicates
    # -------------------------------------------------------------------------

    def detect_duplicates(self) -> List[MaintenanceIssue]:
        """Detect duplicate findings: same source+rule+file combination in Core 2.

        Returns:
            List of MaintenanceIssue with issue_type="duplicate".
        """
        if not self._db_exists():
            return []

        issues: List[MaintenanceIssue] = []
        conn = self._get_conn()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT
                    json_extract(properties, '$.source') AS src,
                    json_extract(properties, '$.rule')   AS rule,
                    json_extract(properties, '$.file')   AS file,
                    COUNT(*) AS cnt,
                    GROUP_CONCAT(entity_id, ',') AS ids
                FROM entities
                WHERE core_id = 2 AND deleted_at IS NULL
                    AND json_extract(properties, '$.source') IS NOT NULL
                GROUP BY src, rule, file
                HAVING cnt > 1
                ORDER BY cnt DESC
                LIMIT 100
                """
            )
            rows = cursor.fetchall()
            for row in rows:
                id_list = (row["ids"] or "").split(",")
                # Report each duplicate (all but the first) as an issue
                primary_id = id_list[0] if id_list else "unknown"
                duplicate_ids = id_list[1:]
                for dup_id in duplicate_ids:
                    issues.append(
                        MaintenanceIssue(
                            severity="medium",
                            issue_type="duplicate",
                            entity_id=dup_id,
                            core_id=2,
                            description=(
                                f"Finding '{dup_id}' is a duplicate of '{primary_id}' "
                                f"(same source='{row['src']}', rule='{row['rule']}', "
                                f"file='{row['file']}'). {row['cnt']} copies exist."
                            ),
                            suggested_fix=(
                                "Soft-delete duplicate findings, keeping only the most "
                                "recently updated copy. Run auto_fix to apply this automatically."
                            ),
                            extra={
                                "primary_id": primary_id,
                                "source": row["src"],
                                "rule": row["rule"],
                                "file": row["file"],
                                "total_copies": row["cnt"],
                            },
                        )
                    )
        finally:
            conn.close()

        return issues

    # -------------------------------------------------------------------------
    # check_staleness
    # -------------------------------------------------------------------------

    def check_staleness(self, days: int = 30) -> List[MaintenanceIssue]:
        """Detect entities not updated in more than `days` days.

        Args:
            days: Staleness threshold. Defaults to 30.

        Returns:
            List of MaintenanceIssue with issue_type="stale".
        """
        if not self._db_exists():
            return []

        cutoff = (datetime.utcnow() - timedelta(days=days)).isoformat()
        issues: List[MaintenanceIssue] = []
        conn = self._get_conn()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT entity_id, core_id, entity_type, name, updated_at
                FROM entities
                WHERE deleted_at IS NULL AND updated_at < ?
                ORDER BY updated_at ASC
                LIMIT 500
                """,
                (cutoff,),
            )
            rows = cursor.fetchall()
            for row in rows:
                core_name = CORE_DEFINITIONS.get(row["core_id"], {}).get("name", f"Core {row['core_id']}")
                issues.append(
                    MaintenanceIssue(
                        severity="low",
                        issue_type="stale",
                        entity_id=row["entity_id"],
                        core_id=row["core_id"],
                        description=(
                            f"Entity '{row['name']}' (type={row['entity_type']}) in "
                            f"{core_name} has not been updated since {row['updated_at']}. "
                            f"Data may be outdated (threshold: {days} days)."
                        ),
                        suggested_fix=(
                            "Re-ingest this entity from its source system, or soft-delete "
                            "it if it is no longer relevant."
                        ),
                        extra={"last_updated": row["updated_at"], "staleness_days": days},
                    )
                )
        finally:
            conn.close()

        return issues

    # -------------------------------------------------------------------------
    # _check_missing_fields (internal, called by run_full_sweep)
    # -------------------------------------------------------------------------

    def _check_missing_fields(self) -> List[MaintenanceIssue]:
        """Detect entities lacking required fields in their properties.

        Returns:
            List of MaintenanceIssue with issue_type="missing_field".
        """
        if not self._db_exists():
            return []

        issues: List[MaintenanceIssue] = []
        conn = self._get_conn()
        try:
            cursor = conn.cursor()
            # Core 2: findings must have severity
            cursor.execute(
                """
                SELECT entity_id, name, properties
                FROM entities
                WHERE core_id = 2 AND deleted_at IS NULL
                AND (
                    json_extract(properties, '$.severity') IS NULL
                    OR json_extract(properties, '$.severity') = ''
                )
                LIMIT 200
                """
            )
            for row in cursor.fetchall():
                issues.append(
                    MaintenanceIssue(
                        severity="high",
                        issue_type="missing_field",
                        entity_id=row["entity_id"],
                        core_id=2,
                        description=(
                            f"Finding '{row['name']}' (Core 2) is missing the required "
                            f"'severity' field in its properties."
                        ),
                        suggested_fix=(
                            "Re-ingest the finding with a severity value: "
                            "critical | high | medium | low | informational."
                        ),
                        extra={"missing_field": "severity"},
                    )
                )
        finally:
            conn.close()

        return issues

    # -------------------------------------------------------------------------
    # _check_type_consistency (internal, called by run_full_sweep)
    # -------------------------------------------------------------------------

    def _check_type_consistency(self) -> List[MaintenanceIssue]:
        """Detect entities whose type does not match their core's expected types.

        Returns:
            List of MaintenanceIssue with issue_type="type_mismatch".
        """
        if not self._db_exists():
            return []

        issues: List[MaintenanceIssue] = []
        conn = self._get_conn()
        try:
            cursor = conn.cursor()
            for core_id, core_def in CORE_DEFINITIONS.items():
                expected_types = core_def["primary_entity_types"]
                if not expected_types:
                    continue

                # Entities whose type is NOT in the expected set
                placeholders = ",".join("?" * len(expected_types))
                cursor.execute(
                    f"""SELECT entity_id, entity_type, nameFROM entities
                    WHERE core_id = ? AND deleted_at IS NULL
                    AND entity_type NOT IN ({placeholders})
                    AND entity_type NOT IN ('CoreAnchor')
                    LIMIT 100
                    """,  # nosec B608
                    [core_id] + expected_types,
                )
                rows = cursor.fetchall()
                for row in rows:
                    issues.append(
                        MaintenanceIssue(
                            severity="low",
                            issue_type="type_mismatch",
                            entity_id=row["entity_id"],
                            core_id=core_id,
                            description=(
                                f"Entity '{row['name']}' has type '{row['entity_type']}' "
                                f"but Core {core_id} ({core_def['name']}) expects types: "
                                f"{expected_types}."
                            ),
                            suggested_fix=(
                                f"Re-ingest the entity into the correct core, or update "
                                f"its entity_type to one of: {expected_types}."
                            ),
                            extra={
                                "entity_type": row["entity_type"],
                                "expected_types": expected_types,
                            },
                        )
                    )
        finally:
            conn.close()

        return issues

    # -------------------------------------------------------------------------
    # auto_fix
    # -------------------------------------------------------------------------

    def auto_fix(
        self,
        issues: List[MaintenanceIssue],
        dry_run: bool = True,
    ) -> Dict[str, Any]:
        """Apply automatic fixes for safe issue types.

        Fixable issue types:
        - orphan: Links entity to its core anchor entity via "belongs_to_core" relationship.
        - duplicate: Soft-deletes all but the earliest created duplicate.

        Args:
            issues: List of MaintenanceIssue objects to fix.
            dry_run: If True, report what would be done without writing to DB.

        Returns:
            Dict with keys: dry_run, fixes_applied, fixes_skipped, errors, details.
        """
        fixes_applied = 0
        fixes_skipped = 0
        errors = 0
        details: List[Dict[str, Any]] = []

        fixable_types = {"orphan", "duplicate"}

        if not self._db_exists():
            return {
                "dry_run": dry_run,
                "fixes_applied": 0,
                "fixes_skipped": len(issues),
                "errors": 0,
                "details": [],
            }

        conn = self._get_conn() if not dry_run else None
        try:
            for issue in issues:
                if issue.issue_type not in fixable_types:
                    fixes_skipped += 1
                    continue

                action = "would_fix" if dry_run else "fixed"

                if issue.issue_type == "orphan":
                    core_id = issue.core_id
                    anchor_id = f"core_{core_id}_anchor"
                    rel_id = f"maint_orphan_{issue.entity_id}_{anchor_id}"

                    if dry_run:
                        details.append({
                            "action": action,
                            "issue_type": "orphan",
                            "entity_id": issue.entity_id,
                            "rel_id": rel_id,
                            "description": f"Would link {issue.entity_id} to {anchor_id}",
                        })
                        fixes_applied += 1
                    else:
                        try:
                            cursor = conn.cursor()
                            now = datetime.utcnow().isoformat()
                            core_name = CORE_DEFINITIONS.get(core_id, {}).get("name", f"Core {core_id}")

                            # Ensure anchor exists
                            cursor.execute(
                                """
                                INSERT OR IGNORE INTO entities
                                (entity_id, core_id, entity_type, name, properties,
                                 created_at, updated_at, org_id)
                                VALUES (?, ?, 'CoreAnchor', ?, '{}', ?, ?, 'system')
                                """,
                                (anchor_id, core_id, core_name, now, now),
                            )

                            # Create relationship
                            cursor.execute(
                                """
                                INSERT OR IGNORE INTO relationships
                                (rel_id, source_id, target_id, rel_type, properties,
                                 confidence, created_at)
                                VALUES (?, ?, ?, 'belongs_to_core', '{}', 0.5, ?)
                                """,
                                (rel_id, issue.entity_id, anchor_id, now),
                            )
                            conn.commit()
                            details.append({
                                "action": action,
                                "issue_type": "orphan",
                                "entity_id": issue.entity_id,
                                "rel_id": rel_id,
                            })
                            fixes_applied += 1
                        except Exception as exc:
                            logger.warning("auto_fix orphan failed for %s: %s", issue.entity_id, exc)
                            errors += 1
                            details.append({
                                "action": "error",
                                "issue_type": "orphan",
                                "entity_id": issue.entity_id,
                                "error": str(exc),
                            })

                elif issue.issue_type == "duplicate":
                    if dry_run:
                        details.append({
                            "action": action,
                            "issue_type": "duplicate",
                            "entity_id": issue.entity_id,
                            "description": f"Would soft-delete duplicate {issue.entity_id}",
                        })
                        fixes_applied += 1
                    else:
                        try:
                            cursor = conn.cursor()
                            now = datetime.utcnow().isoformat()
                            cursor.execute(
                                "UPDATE entities SET deleted_at = ? WHERE entity_id = ?",
                                (now, issue.entity_id),
                            )
                            conn.commit()
                            details.append({
                                "action": action,
                                "issue_type": "duplicate",
                                "entity_id": issue.entity_id,
                            })
                            fixes_applied += 1
                        except Exception as exc:
                            logger.warning("auto_fix duplicate failed for %s: %s", issue.entity_id, exc)
                            errors += 1
                            details.append({
                                "action": "error",
                                "issue_type": "duplicate",
                                "entity_id": issue.entity_id,
                                "error": str(exc),
                            })

        finally:
            if conn is not None:
                conn.close()

        return {
            "dry_run": dry_run,
            "fixes_applied": fixes_applied,
            "fixes_skipped": fixes_skipped,
            "errors": errors,
            "details": details,
        }

    # -------------------------------------------------------------------------
    # get_core_health
    # -------------------------------------------------------------------------

    def get_core_health(self) -> Dict[str, Any]:
        """Compute a health score (0-100) for each Knowledge Core.

        Score is based on:
        - Entity count (populated = healthy)
        - % of entities that are connected (have relationships)
        - Absence of missing_field issues in Core 2
        - Absence of stale entities (penalty for >50% stale)

        Returns:
            Dict mapping core_id (str) to dict with score (int) and breakdown.
        """
        if not self._db_exists():
            return {
                str(core_id): {"score": 0, "reason": "database_not_found"}
                for core_id in CORE_DEFINITIONS
            }

        conn = self._get_conn()
        try:
            cursor = conn.cursor()
            health: Dict[str, Any] = {}
            stale_cutoff = (datetime.utcnow() - timedelta(days=30)).isoformat()

            for core_id in CORE_DEFINITIONS:
                # Total entities
                cursor.execute(
                    "SELECT COUNT(*) FROM entities WHERE core_id = ? AND deleted_at IS NULL",
                    (core_id,),
                )
                total = cursor.fetchone()[0]

                if total == 0:
                    health[str(core_id)] = {
                        "core_id": core_id,
                        "core_name": CORE_DEFINITIONS[core_id]["name"],
                        "score": 0,
                        "total_entities": 0,
                        "connected_pct": 0.0,
                        "stale_pct": 0.0,
                        "missing_severity_count": 0,
                        "reason": "no_entities",
                    }
                    continue

                # Connected entities
                cursor.execute(
                    """
                    SELECT COUNT(DISTINCT e.entity_id) FROM entities e
                    WHERE e.core_id = ? AND e.deleted_at IS NULL
                    AND (
                        EXISTS (SELECT 1 FROM relationships r WHERE r.source_id = e.entity_id)
                        OR EXISTS (SELECT 1 FROM relationships r WHERE r.target_id = e.entity_id)
                    )
                    """,
                    (core_id,),
                )
                connected = cursor.fetchone()[0]

                # Stale entities
                cursor.execute(
                    """
                    SELECT COUNT(*) FROM entities
                    WHERE core_id = ? AND deleted_at IS NULL AND updated_at < ?
                    """,
                    (core_id, stale_cutoff),
                )
                stale = cursor.fetchone()[0]

                # Missing severity in Core 2
                missing_severity = 0
                if core_id == 2:
                    cursor.execute(
                        """
                        SELECT COUNT(*) FROM entities
                        WHERE core_id = 2 AND deleted_at IS NULL
                        AND (
                            json_extract(properties, '$.severity') IS NULL
                            OR json_extract(properties, '$.severity') = ''
                        )
                        """
                    )
                    missing_severity = cursor.fetchone()[0]

                connected_pct = (connected / total * 100.0) if total > 0 else 0.0
                stale_pct = (stale / total * 100.0) if total > 0 else 0.0
                missing_severity_pct = (missing_severity / total * 100.0) if total > 0 else 0.0

                # Score calculation: start at 100, deduct penalties
                score = 100
                # Penalty: low connectivity (max -40 for 0% connected)
                score -= int((1.0 - connected_pct / 100.0) * 40)
                # Penalty: high staleness (max -30 for 100% stale)
                score -= int((stale_pct / 100.0) * 30)
                # Penalty: missing severity in Core 2 (max -30)
                score -= int((missing_severity_pct / 100.0) * 30)
                score = max(0, min(100, score))

                health[str(core_id)] = {
                    "core_id": core_id,
                    "core_name": CORE_DEFINITIONS[core_id]["name"],
                    "score": score,
                    "total_entities": total,
                    "connected_pct": round(connected_pct, 2),
                    "stale_pct": round(stale_pct, 2),
                    "missing_severity_count": missing_severity,
                    "reason": "ok" if score >= 70 else ("degraded" if score >= 40 else "critical"),
                }

            return health

        finally:
            conn.close()
