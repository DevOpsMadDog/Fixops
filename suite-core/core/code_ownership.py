"""
Code Ownership Mapper — assigns code owners to files and security findings.

Provides CODEOWNERS-style glob-pattern matching, SQLite-backed owner registry,
finding auto-assignment, and coverage/workload analytics.

Usage:
    ownership = CodeOwnership()
    ownership.add_owner(Owner(email="alice@example.com", name="Alice", team="platform", ...))
    ownership.add_rule("src/core/**", "alice@example.com", priority=10)
    owner = ownership.resolve_owner("src/core/brain_pipeline.py")
"""

from __future__ import annotations

import fnmatch
import json
import logging
import re
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# DB path
# ---------------------------------------------------------------------------
_DB_PATH = Path(__file__).parent / "code_ownership.db"


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class Owner(BaseModel):
    """A code owner — a person or team responsible for one or more file paths."""

    email: str = Field(..., description="Unique identifier / contact email")
    name: str = Field(..., description="Human-readable display name")
    team: str = Field(..., description="Team or squad name")
    repos: List[str] = Field(default_factory=list, description="Repos this owner is responsible for")
    file_patterns: List[str] = Field(
        default_factory=list,
        description="Glob patterns for files this owner is responsible for",
    )
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class OwnershipRule(BaseModel):
    """A CODEOWNERS-style rule: glob pattern → owner email with priority."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    pattern: str = Field(..., description="Glob pattern (e.g. 'src/core/**')")
    owner_email: str = Field(..., description="Email of the assigned owner")
    priority: int = Field(
        default=0,
        description="Higher priority rules win when multiple patterns match",
    )
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class AssignedFinding(BaseModel):
    """A security finding with an assigned owner."""

    finding_id: str
    owner_email: Optional[str] = None
    owner_name: Optional[str] = None
    owner_team: Optional[str] = None
    file_path: Optional[str] = None
    assigned_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _glob_match(pattern: str, path: str) -> bool:
    """Match *path* against a CODEOWNERS-style glob *pattern*.

    Supports ``**`` for multi-segment matching (converted to ``*`` for
    ``fnmatch``).  Both leading ``/`` (repo-root-relative) and trailing ``/``
    (directory) are stripped before matching.
    """
    # Normalise separators
    path = path.replace("\\", "/").lstrip("/")
    pattern = pattern.replace("\\", "/").lstrip("/").rstrip("/")

    # If the pattern ends with /** (or has ** anywhere), expand to cover both
    # the directory itself and everything under it.
    # Convert ** → * for fnmatch (fnmatch doesn't understand **)
    fn_pattern = re.sub(r"\*\*", "*", pattern)

    if fnmatch.fnmatch(path, fn_pattern):
        return True

    # Also try matching just the basename for simple wildcard patterns
    basename = Path(path).name
    if fnmatch.fnmatch(basename, fn_pattern):
        return True

    return False


def _extract_file_path(finding: Dict[str, Any]) -> Optional[str]:
    """Extract a file path from a finding dict."""
    for field in ("file_path", "file", "path", "location", "filename", "source_path"):
        val = finding.get(field)
        if val and isinstance(val, str):
            return val.strip()
    return None


# ---------------------------------------------------------------------------
# Core class
# ---------------------------------------------------------------------------

class CodeOwnership:
    """SQLite-backed code ownership registry with CODEOWNERS-style resolution.

    Methods
    -------
    add_owner             — register a code owner
    add_rule              — add a glob-pattern ownership rule
    resolve_owner         — find owner for a file path
    resolve_finding_owner — find owner for a security finding dict
    import_codeowners     — parse CODEOWNERS file format
    get_ownership_coverage — % of files with owners
    get_unowned_files     — files without owners
    get_owner_workload    — findings count per owner
    auto_assign_findings  — bulk assign findings to owners
    """

    def __init__(self, db_path: Optional[Path] = None) -> None:
        self._db_path = db_path or _DB_PATH
        self._init_db()

    # ------------------------------------------------------------------
    # DB helpers
    # ------------------------------------------------------------------

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._get_conn() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS owners (
                    email       TEXT PRIMARY KEY,
                    name        TEXT NOT NULL,
                    team        TEXT NOT NULL DEFAULT '',
                    repos       TEXT NOT NULL DEFAULT '[]',
                    file_patterns TEXT NOT NULL DEFAULT '[]',
                    created_at  TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS ownership_rules (
                    id          TEXT PRIMARY KEY,
                    pattern     TEXT NOT NULL,
                    owner_email TEXT NOT NULL,
                    priority    INTEGER NOT NULL DEFAULT 0,
                    created_at  TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_rules_owner ON ownership_rules(owner_email);
                CREATE INDEX IF NOT EXISTS idx_rules_priority ON ownership_rules(priority DESC);

                CREATE TABLE IF NOT EXISTS finding_assignments (
                    finding_id  TEXT NOT NULL,
                    org_id      TEXT NOT NULL DEFAULT 'default',
                    owner_email TEXT,
                    file_path   TEXT,
                    assigned_at TEXT NOT NULL,
                    PRIMARY KEY (finding_id, org_id)
                );
                CREATE INDEX IF NOT EXISTS idx_assign_org ON finding_assignments(org_id);
                CREATE INDEX IF NOT EXISTS idx_assign_owner ON finding_assignments(owner_email);
                """
            )

    # ------------------------------------------------------------------
    # Owner management
    # ------------------------------------------------------------------

    def add_owner(self, owner: Owner) -> Owner:
        """Register (or upsert) a code owner."""
        with self._get_conn() as conn:
            conn.execute(
                """
                INSERT INTO owners (email, name, team, repos, file_patterns, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(email) DO UPDATE SET
                    name          = excluded.name,
                    team          = excluded.team,
                    repos         = excluded.repos,
                    file_patterns = excluded.file_patterns
                """,
                (
                    owner.email,
                    owner.name,
                    owner.team,
                    json.dumps(owner.repos),
                    json.dumps(owner.file_patterns),
                    owner.created_at,
                ),
            )
        logger.debug("Registered owner %s (%s)", owner.email, owner.name)
        return owner

    def get_owner(self, email: str) -> Optional[Owner]:
        """Fetch a single owner by email."""
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM owners WHERE email = ?", (email,)
            ).fetchone()
        if row is None:
            return None
        return self._row_to_owner(row)

    def list_owners(self) -> List[Owner]:
        """Return all registered owners."""
        with self._get_conn() as conn:
            rows = conn.execute("SELECT * FROM owners ORDER BY email").fetchall()
        return [self._row_to_owner(r) for r in rows]

    def delete_owner(self, email: str) -> bool:
        """Remove an owner. Returns True if deleted."""
        with self._get_conn() as conn:
            cur = conn.execute("DELETE FROM owners WHERE email = ?", (email,))
        return cur.rowcount > 0

    @staticmethod
    def _row_to_owner(row: sqlite3.Row) -> Owner:
        return Owner(
            email=row["email"],
            name=row["name"],
            team=row["team"],
            repos=json.loads(row["repos"]),
            file_patterns=json.loads(row["file_patterns"]),
            created_at=row["created_at"],
        )

    # ------------------------------------------------------------------
    # Rule management
    # ------------------------------------------------------------------

    def add_rule(self, pattern: str, owner_email: str, priority: int = 0) -> OwnershipRule:
        """Add a CODEOWNERS-style glob rule."""
        rule = OwnershipRule(
            pattern=pattern,
            owner_email=owner_email,
            priority=priority,
        )
        with self._get_conn() as conn:
            conn.execute(
                """
                INSERT INTO ownership_rules (id, pattern, owner_email, priority, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (rule.id, rule.pattern, rule.owner_email, rule.priority, rule.created_at),
            )
        logger.debug("Added rule '%s' → %s (priority %d)", pattern, owner_email, priority)
        return rule

    def list_rules(self) -> List[OwnershipRule]:
        """Return all rules ordered by priority descending."""
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM ownership_rules ORDER BY priority DESC, created_at ASC"
            ).fetchall()
        return [
            OwnershipRule(
                id=r["id"],
                pattern=r["pattern"],
                owner_email=r["owner_email"],
                priority=r["priority"],
                created_at=r["created_at"],
            )
            for r in rows
        ]

    def delete_rule(self, rule_id: str) -> bool:
        """Remove a rule by ID. Returns True if deleted."""
        with self._get_conn() as conn:
            cur = conn.execute("DELETE FROM ownership_rules WHERE id = ?", (rule_id,))
        return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Resolution
    # ------------------------------------------------------------------

    def resolve_owner(self, file_path: str) -> Optional[Owner]:
        """Find the best owner for *file_path* using glob rules.

        Rules are evaluated from highest priority to lowest.  The first match
        wins.  If no rule matches, returns None.
        """
        rules = self.list_rules()  # already ordered by priority DESC
        for rule in rules:
            if _glob_match(rule.pattern, file_path):
                owner = self.get_owner(rule.owner_email)
                if owner:
                    return owner
                logger.warning(
                    "Rule '%s' references unknown owner %s",
                    rule.pattern,
                    rule.owner_email,
                )
        return None

    def resolve_finding_owner(self, finding: Dict[str, Any]) -> Optional[Owner]:
        """Find the best owner for a security finding.

        Resolution order:
        1. file_path field → glob-rule lookup
        2. owner_email field → direct owner lookup
        3. None
        """
        file_path = _extract_file_path(finding)
        if file_path:
            owner = self.resolve_owner(file_path)
            if owner:
                return owner

        # Fallback: direct email reference in the finding
        direct_email = finding.get("owner_email") or finding.get("assigned_to")
        if direct_email:
            return self.get_owner(str(direct_email))

        return None

    # ------------------------------------------------------------------
    # CODEOWNERS import
    # ------------------------------------------------------------------

    def import_codeowners(self, content: str) -> int:
        """Parse a CODEOWNERS file and load rules.

        Format (GitHub/GitLab compatible)::

            # comment
            src/core/**   @alice @bob
            *.py          @platform-team

        GitHub uses ``@username``; we accept bare emails too.
        Priority is assigned by line order (later lines = lower priority,
        mirroring CODEOWNERS semantics where later rules override earlier).

        Returns the number of rules imported.
        """
        lines = content.splitlines()
        total = len([l for l in lines if l.strip() and not l.strip().startswith("#")])
        priority_base = total  # first non-comment line gets highest priority

        imported = 0
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            parts = line.split()
            if len(parts) < 2:
                continue

            pattern = parts[0]
            # Strip @ prefixes from GitHub handles; treat as email/identifier
            emails = [p.lstrip("@") for p in parts[1:]]

            for email in emails:
                self.add_rule(pattern, email, priority=priority_base)

            priority_base -= 1
            imported += 1

        logger.info("Imported %d CODEOWNERS rules", imported)
        return imported

    # ------------------------------------------------------------------
    # Coverage & analytics
    # ------------------------------------------------------------------

    def get_ownership_coverage(self, org_id: str, file_paths: List[str]) -> Dict[str, Any]:
        """Calculate what percentage of *file_paths* have an owner.

        Parameters
        ----------
        org_id:
            Organisation scope (informational, not used for filtering rules).
        file_paths:
            List of repo-relative file paths to evaluate.
        """
        if not file_paths:
            return {
                "org_id": org_id,
                "total_files": 0,
                "owned_files": 0,
                "unowned_files": 0,
                "coverage_pct": 0.0,
            }

        owned = 0
        for fp in file_paths:
            if self.resolve_owner(fp) is not None:
                owned += 1

        unowned = len(file_paths) - owned
        coverage_pct = round((owned / len(file_paths)) * 100, 2)

        return {
            "org_id": org_id,
            "total_files": len(file_paths),
            "owned_files": owned,
            "unowned_files": unowned,
            "coverage_pct": coverage_pct,
        }

    def get_unowned_files(self, org_id: str, file_paths: List[str]) -> List[str]:
        """Return the subset of *file_paths* that have no owner."""
        return [fp for fp in file_paths if self.resolve_owner(fp) is None]

    def get_owner_workload(self, org_id: str) -> List[Dict[str, Any]]:
        """Return findings-per-owner counts for *org_id*."""
        with self._get_conn() as conn:
            rows = conn.execute(
                """
                SELECT fa.owner_email, COUNT(*) AS finding_count
                FROM finding_assignments fa
                WHERE fa.org_id = ?
                GROUP BY fa.owner_email
                ORDER BY finding_count DESC
                """,
                (org_id,),
            ).fetchall()

        result: List[Dict[str, Any]] = []
        for row in rows:
            email = row["owner_email"]
            owner = self.get_owner(email) if email else None
            result.append(
                {
                    "owner_email": email,
                    "owner_name": owner.name if owner else None,
                    "owner_team": owner.team if owner else None,
                    "finding_count": row["finding_count"],
                    "org_id": org_id,
                }
            )
        return result

    # ------------------------------------------------------------------
    # Auto-assignment
    # ------------------------------------------------------------------

    def auto_assign_findings(
        self, findings: List[Dict[str, Any]], org_id: str = "default"
    ) -> List[AssignedFinding]:
        """Bulk-assign each finding to its best owner and persist the assignment.

        Returns the list of AssignedFinding objects (one per finding).
        Findings without a resolvable owner get owner_email=None.
        """
        now = datetime.now(timezone.utc).isoformat()
        assignments: List[AssignedFinding] = []

        with self._get_conn() as conn:
            for finding in findings:
                finding_id = str(
                    finding.get("id") or finding.get("finding_id") or uuid.uuid4()
                )
                file_path = _extract_file_path(finding)
                owner = self.resolve_finding_owner(finding)

                assigned = AssignedFinding(
                    finding_id=finding_id,
                    owner_email=owner.email if owner else None,
                    owner_name=owner.name if owner else None,
                    owner_team=owner.team if owner else None,
                    file_path=file_path,
                    assigned_at=now,
                )
                assignments.append(assigned)

                conn.execute(
                    """
                    INSERT INTO finding_assignments
                        (finding_id, org_id, owner_email, file_path, assigned_at)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(finding_id, org_id) DO UPDATE SET
                        owner_email = excluded.owner_email,
                        file_path   = excluded.file_path,
                        assigned_at = excluded.assigned_at
                    """,
                    (finding_id, org_id, assigned.owner_email, file_path, now),
                )

        logger.info(
            "Auto-assigned %d findings for org=%s (%d with owners)",
            len(findings),
            org_id,
            sum(1 for a in assignments if a.owner_email),
        )
        return assignments


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------
_instance: Optional[CodeOwnership] = None


def get_code_ownership(db_path: Optional[Path] = None) -> CodeOwnership:
    """Return the module-level singleton CodeOwnership instance."""
    global _instance
    if _instance is None:
        _instance = CodeOwnership(db_path=db_path)
    return _instance
