"""
Developer Self-Service Security Portal for ALDECI.

Provides developers with a scoped view of security findings for their repos,
along with fix suggestions, security scores, and learning resources.

Persona coverage: P05 (Developer), P06 (AppSec Engineer), P08 (DevOps)
Compliance: SOC2 CC6.1
"""

from __future__ import annotations

import json
import logging
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except ImportError:  # pragma: no cover - bus optional
    _get_tg_bus = None

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class RepoSecurityScore(BaseModel):
    """Security posture score for a single repository."""

    repo_name: str
    score: float = Field(ge=0.0, le=100.0, description="Security score 0-100")
    grade: str = Field(description="Letter grade A-F")
    finding_count: int
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    last_scan: Optional[str] = None
    trend: str = Field(
        default="stable",
        description="One of: improving, stable, degrading",
    )


class FixSuggestion(BaseModel):
    """Actionable fix suggestion for a security finding."""

    finding_id: str
    title: str
    description: str
    code_snippet: Optional[str] = None
    upgrade_command: Optional[str] = None
    reference_url: str
    difficulty: str = Field(description="One of: easy, medium, hard")
    estimated_time_minutes: int


class LearningResource(BaseModel):
    """Educational resource linked to a finding type."""

    title: str
    url: str
    category: str = Field(description="One of: OWASP, CWE, best-practice")
    finding_types: List[str]


# ---------------------------------------------------------------------------
# Fix-generation templates
# ---------------------------------------------------------------------------

_FIX_TEMPLATES: Dict[str, Dict[str, Any]] = {
    "sql_injection": {
        "title": "Use parameterised queries to prevent SQL Injection",
        "description": (
            "SQL Injection occurs when user-supplied data is concatenated directly "
            "into SQL statements. Use parameterised queries or an ORM to separate "
            "data from code."
        ),
        "snippets": {
            "python": (
                "# BAD\ncursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")\n\n"
                "# GOOD\ncursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))"
            ),
            "java": (
                "// GOOD\nPreparedStatement ps = conn.prepareStatement(\n"
                "    \"SELECT * FROM users WHERE id = ?\");\nps.setInt(1, userId);"
            ),
        },
        "reference_url": "https://owasp.org/www-community/attacks/SQL_Injection",
        "difficulty": "easy",
        "estimated_time_minutes": 30,
    },
    "xss": {
        "title": "Encode output to prevent Cross-Site Scripting (XSS)",
        "description": (
            "XSS allows attackers to inject client-side scripts. Always encode "
            "user-controlled data before rendering in HTML."
        ),
        "snippets": {
            "javascript": (
                "// BAD\ndocument.getElementById('out').innerHTML = userInput;\n\n"
                "// GOOD\ndocument.getElementById('out').textContent = userInput;"
            ),
            "python": (
                "# Using markupsafe\nfrom markupsafe import escape\nsafe = escape(user_input)"
            ),
        },
        "reference_url": "https://owasp.org/www-community/attacks/xss/",
        "difficulty": "easy",
        "estimated_time_minutes": 20,
    },
    "outdated_dependency": {
        "title": "Upgrade vulnerable dependency to a patched version",
        "description": (
            "The dependency in use has a known vulnerability. Upgrading to the "
            "latest patched version resolves the issue."
        ),
        "snippets": {
            "python": "# Run:\npip install --upgrade <package>",
            "javascript": "# Run:\nnpm update <package>",
        },
        "reference_url": "https://nvd.nist.gov/",
        "difficulty": "easy",
        "estimated_time_minutes": 15,
    },
    "hardcoded_secret": {
        "title": "Remove hardcoded credentials and use environment variables",
        "description": (
            "Hardcoded secrets in source code can be exposed via version control. "
            "Move secrets to environment variables or a secrets manager."
        ),
        "snippets": {
            "python": (
                "# BAD\npassword = 'supersecret'\n\n"
                "# GOOD\nimport os\npassword = os.environ['DB_PASSWORD']"
            ),
            "javascript": (
                "// BAD\nconst apiKey = 'sk-abc123';\n\n"
                "// GOOD\nconst apiKey = process.env.API_KEY;"
            ),
        },
        "reference_url": "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
        "difficulty": "easy",
        "estimated_time_minutes": 20,
    },
    "insecure_deserialization": {
        "title": "Avoid deserializing untrusted data with unsafe libraries",
        "description": (
            "Deserializing attacker-controlled data with unsafe libraries (pickle, "
            "yaml.load) can lead to remote code execution. Use safe alternatives."
        ),
        "snippets": {
            "python": (
                "# BAD\nimport pickle\nobj = pickle.loads(user_data)\n\n"
                "# GOOD\nimport json\nobj = json.loads(user_data)"
            ),
        },
        "reference_url": "https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data",
        "difficulty": "medium",
        "estimated_time_minutes": 60,
    },
    "missing_auth": {
        "title": "Add authentication and authorisation to the endpoint",
        "description": (
            "The endpoint is publicly accessible without authentication. Apply an "
            "auth dependency to restrict access to authorised users."
        ),
        "snippets": {
            "python": (
                "# FastAPI\nfrom fastapi import Depends\n"
                "from apps.api.auth_deps import api_key_auth\n\n"
                "@router.get('/secure', dependencies=[Depends(api_key_auth)])\nasync def secure_route(): ..."
            ),
        },
        "reference_url": "https://owasp.org/www-project-top-ten/2021/A01_2021-Broken_Access_Control",
        "difficulty": "medium",
        "estimated_time_minutes": 45,
    },
    "weak_crypto": {
        "title": "Replace weak cryptographic algorithm with a strong alternative",
        "description": (
            "MD5/SHA-1 are cryptographically broken for security purposes. "
            "Use SHA-256 or stronger for hashing, and AES-256 for encryption."
        ),
        "snippets": {
            "python": (
                "# BAD\nimport hashlib\nhash = hashlib.md5(data).hexdigest()\n\n"
                "# GOOD\nhash = hashlib.sha256(data).hexdigest()"
            ),
        },
        "reference_url": "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html",
        "difficulty": "easy",
        "estimated_time_minutes": 15,
    },
    "default": {
        "title": "Remediate the identified security finding",
        "description": (
            "Review the finding details and apply the recommended remediation steps. "
            "Consult the linked reference for guidance."
        ),
        "snippets": {},
        "reference_url": "https://owasp.org/www-project-top-ten/",
        "difficulty": "medium",
        "estimated_time_minutes": 60,
    },
}

# ---------------------------------------------------------------------------
# Learning resources database
# ---------------------------------------------------------------------------

_LEARNING_DB: Dict[str, List[Dict[str, Any]]] = {
    "sql_injection": [
        {
            "title": "OWASP SQL Injection Prevention Cheat Sheet",
            "url": "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
            "category": "OWASP",
        },
        {
            "title": "CWE-89: SQL Injection",
            "url": "https://cwe.mitre.org/data/definitions/89.html",
            "category": "CWE",
        },
    ],
    "xss": [
        {
            "title": "OWASP XSS Prevention Cheat Sheet",
            "url": "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
            "category": "OWASP",
        },
        {
            "title": "CWE-79: Cross-site Scripting",
            "url": "https://cwe.mitre.org/data/definitions/79.html",
            "category": "CWE",
        },
    ],
    "outdated_dependency": [
        {
            "title": "OWASP A06:2021 – Vulnerable and Outdated Components",
            "url": "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
            "category": "OWASP",
        },
        {
            "title": "Dependency Management Best Practices",
            "url": "https://snyk.io/learn/open-source-security/dependency-management/",
            "category": "best-practice",
        },
    ],
    "hardcoded_secret": [
        {
            "title": "OWASP Secrets Management Cheat Sheet",
            "url": "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
            "category": "OWASP",
        },
        {
            "title": "CWE-798: Use of Hard-coded Credentials",
            "url": "https://cwe.mitre.org/data/definitions/798.html",
            "category": "CWE",
        },
    ],
    "insecure_deserialization": [
        {
            "title": "OWASP Deserialization Cheat Sheet",
            "url": "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html",
            "category": "OWASP",
        },
        {
            "title": "CWE-502: Deserialization of Untrusted Data",
            "url": "https://cwe.mitre.org/data/definitions/502.html",
            "category": "CWE",
        },
    ],
    "missing_auth": [
        {
            "title": "OWASP A01:2021 – Broken Access Control",
            "url": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
            "category": "OWASP",
        },
        {
            "title": "CWE-862: Missing Authorization",
            "url": "https://cwe.mitre.org/data/definitions/862.html",
            "category": "CWE",
        },
    ],
    "weak_crypto": [
        {
            "title": "OWASP Cryptographic Storage Cheat Sheet",
            "url": "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html",
            "category": "OWASP",
        },
        {
            "title": "CWE-327: Use of a Broken or Risky Cryptographic Algorithm",
            "url": "https://cwe.mitre.org/data/definitions/327.html",
            "category": "CWE",
        },
    ],
    "default": [
        {
            "title": "OWASP Top 10",
            "url": "https://owasp.org/www-project-top-ten/",
            "category": "OWASP",
        },
        {
            "title": "Secure Coding Practices Quick Reference",
            "url": "https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/",
            "category": "best-practice",
        },
    ],
}

# ---------------------------------------------------------------------------
# Score / grade helpers
# ---------------------------------------------------------------------------

_SEVERITY_WEIGHTS = {"critical": 20.0, "high": 10.0, "medium": 4.0, "low": 1.0}


def _grade_from_score(score: float) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 65:
        return "C"
    if score >= 50:
        return "D"
    return "F"


# ---------------------------------------------------------------------------
# DeveloperPortal class
# ---------------------------------------------------------------------------


class DeveloperPortal:
    """SQLite-backed developer self-service security portal.

    Scopes findings to repos the developer owns, provides fix suggestions,
    security scores, learning resources, and gamification (leaderboard).
    """

    def __init__(self, db_path: str = "data/developer_portal.db") -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_tables()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_tables(self) -> None:
        with self._get_conn() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS repo_owners (
                    id          TEXT PRIMARY KEY,
                    repo_name   TEXT NOT NULL,
                    dev_email   TEXT NOT NULL,
                    org_id      TEXT NOT NULL,
                    registered_at TEXT NOT NULL,
                    UNIQUE(repo_name, dev_email, org_id)
                );

                CREATE TABLE IF NOT EXISTS dev_findings (
                    id          TEXT PRIMARY KEY,
                    repo_name   TEXT NOT NULL,
                    org_id      TEXT NOT NULL,
                    title       TEXT NOT NULL,
                    severity    TEXT NOT NULL,
                    status      TEXT NOT NULL DEFAULT 'open',
                    finding_type TEXT,
                    file_path   TEXT,
                    language    TEXT,
                    cve_id      TEXT,
                    description TEXT,
                    source      TEXT,
                    metadata    TEXT,
                    created_at  TEXT NOT NULL,
                    resolved_at TEXT
                );

                CREATE TABLE IF NOT EXISTS fix_events (
                    id          TEXT PRIMARY KEY,
                    finding_id  TEXT NOT NULL,
                    dev_email   TEXT NOT NULL,
                    org_id      TEXT NOT NULL,
                    fixed_at    TEXT NOT NULL,
                    time_to_fix_minutes INTEGER
                );

                CREATE INDEX IF NOT EXISTS idx_repo_owners_email ON repo_owners(dev_email, org_id);
                CREATE INDEX IF NOT EXISTS idx_repo_owners_repo  ON repo_owners(repo_name, org_id);
                CREATE INDEX IF NOT EXISTS idx_dev_findings_repo ON dev_findings(repo_name, org_id);
                CREATE INDEX IF NOT EXISTS idx_fix_events_dev    ON fix_events(dev_email, org_id);
                """
            )

    # ------------------------------------------------------------------
    # Repo ownership
    # ------------------------------------------------------------------

    def register_repo_owner(
        self,
        repo_name: str,
        developer_email: str,
        org_id: str,
    ) -> None:
        """Map a developer to a repository within an org."""
        with self._get_conn() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO repo_owners (id, repo_name, dev_email, org_id, registered_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    str(uuid.uuid4()),
                    repo_name,
                    developer_email,
                    org_id,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
        logger.info(
            "Registered repo owner: %s -> %s (org=%s)", developer_email, repo_name, org_id
        )
        self._emit_event(
            "developer_portal.repo_owner.registered",
            {"repo_name": repo_name, "developer_email": developer_email, "org_id": org_id},
        )

    def _get_owned_repos(self, developer_email: str, org_id: str) -> List[str]:
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT repo_name FROM repo_owners WHERE dev_email = ? AND org_id = ?",
                (developer_email, org_id),
            ).fetchall()
        return [row["repo_name"] for row in rows]

    # ------------------------------------------------------------------
    # Finding ingestion (internal helper used by tests / pipeline)
    # ------------------------------------------------------------------

    def add_finding(
        self,
        repo_name: str,
        org_id: str,
        title: str,
        severity: str,
        finding_type: str = "default",
        *,
        finding_id: Optional[str] = None,
        file_path: Optional[str] = None,
        language: Optional[str] = None,
        cve_id: Optional[str] = None,
        description: str = "",
        source: str = "scanner",
        status: str = "open",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        fid = finding_id or str(uuid.uuid4())
        with self._get_conn() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO dev_findings
                    (id, repo_name, org_id, title, severity, status, finding_type,
                     file_path, language, cve_id, description, source, metadata, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    fid,
                    repo_name,
                    org_id,
                    title,
                    severity.lower(),
                    status,
                    finding_type,
                    file_path,
                    language,
                    cve_id,
                    description,
                    source,
                    json.dumps(metadata or {}),
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
        return fid

    def mark_finding_resolved(
        self,
        finding_id: str,
        developer_email: str,
        org_id: str,
        time_to_fix_minutes: Optional[int] = None,
    ) -> None:
        """Mark a finding as resolved and record a fix event for stats."""
        now = datetime.now(timezone.utc).isoformat()
        with self._get_conn() as conn:
            conn.execute(
                "UPDATE dev_findings SET status = 'resolved', resolved_at = ? WHERE id = ?",
                (now, finding_id),
            )
            conn.execute(
                """
                INSERT INTO fix_events (id, finding_id, dev_email, org_id, fixed_at, time_to_fix_minutes)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    str(uuid.uuid4()),
                    finding_id,
                    developer_email,
                    org_id,
                    now,
                    time_to_fix_minutes,
                ),
            )

    # ------------------------------------------------------------------
    # Findings queries
    # ------------------------------------------------------------------

    def get_my_findings(
        self,
        developer_email: str,
        org_id: str,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return findings scoped to repos owned by the developer."""
        owned = self._get_owned_repos(developer_email, org_id)
        if not owned:
            return []

        placeholders = ",".join("?" * len(owned))
        params: List[Any] = [*owned, org_id]
        query = (
            f"SELECT * FROM dev_findings WHERE repo_name IN ({placeholders}) AND org_id = ?"  # nosec B608
        )
        if status:
            query += " AND status = ?"
            params.append(status)
        query += " ORDER BY created_at DESC"

        with self._get_conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]

    # ------------------------------------------------------------------
    # Repo scoring
    # ------------------------------------------------------------------

    def _calculate_repo_score(self, findings: List[Dict[str, Any]]) -> float:
        """Score 0-100 based on open findings; more/severe findings = lower score."""
        if not findings:
            return 100.0
        open_findings = [f for f in findings if f.get("status") != "resolved"]
        penalty = sum(
            _SEVERITY_WEIGHTS.get(f.get("severity", "low"), 1.0) for f in open_findings
        )
        score = max(0.0, 100.0 - penalty)
        return round(score, 1)

    def get_repo_score(self, repo_name: str, org_id: str) -> RepoSecurityScore:
        """Compute and return a security score for a repository."""
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM dev_findings WHERE repo_name = ? AND org_id = ?",
                (repo_name, org_id),
            ).fetchall()
        findings = [dict(r) for r in rows]
        open_findings = [f for f in findings if f.get("status") != "resolved"]

        counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in open_findings:
            sev = f.get("severity", "low")
            if sev in counts:
                counts[sev] += 1

        score = self._calculate_repo_score(findings)
        last_scan: Optional[str] = None
        if findings:
            last_scan = max(f.get("created_at", "") for f in findings)

        return RepoSecurityScore(
            repo_name=repo_name,
            score=score,
            grade=_grade_from_score(score),
            finding_count=len(open_findings),
            critical=counts["critical"],
            high=counts["high"],
            medium=counts["medium"],
            low=counts["low"],
            last_scan=last_scan,
            trend="stable",
        )

    def get_all_repo_scores(self, org_id: str) -> List[RepoSecurityScore]:
        """Return security scores for every repo in the org."""
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT DISTINCT repo_name FROM dev_findings WHERE org_id = ?",
                (org_id,),
            ).fetchall()
        repos = [row["repo_name"] for row in rows]
        return [self.get_repo_score(repo, org_id) for repo in repos]

    # ------------------------------------------------------------------
    # Fix suggestions
    # ------------------------------------------------------------------

    def _generate_fix_snippet(self, finding_type: str, language: str) -> str:
        """Return a code fix template for the given finding type and language."""
        template = _FIX_TEMPLATES.get(finding_type, _FIX_TEMPLATES["default"])
        snippets: Dict[str, str] = template.get("snippets", {})
        if language and language in snippets:
            return snippets[language]
        # Fallback: return first available snippet
        if snippets:
            return next(iter(snippets.values()))
        return ""

    def get_fix_suggestion(
        self,
        finding_id: str,
        language: Optional[str] = None,
    ) -> FixSuggestion:
        """Generate a fix suggestion for the given finding."""
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM dev_findings WHERE id = ?", (finding_id,)
            ).fetchone()

        finding_type = "default"
        lang = language or "python"
        if row:
            finding_type = row["finding_type"] or "default"
            lang = language or row["language"] or "python"

        template = _FIX_TEMPLATES.get(finding_type, _FIX_TEMPLATES["default"])
        snippet = self._generate_fix_snippet(finding_type, lang)

        upgrade_command: Optional[str] = None
        if finding_type == "outdated_dependency":
            snippets = template.get("snippets", {})
            upgrade_command = snippets.get(lang, snippets.get("python", ""))

        return FixSuggestion(
            finding_id=finding_id,
            title=template["title"],
            description=template["description"],
            code_snippet=snippet or None,
            upgrade_command=upgrade_command,
            reference_url=template["reference_url"],
            difficulty=template["difficulty"],
            estimated_time_minutes=template["estimated_time_minutes"],
        )

    def get_fix_suggestions_batch(
        self,
        finding_ids: List[str],
        language: Optional[str] = None,
    ) -> List[FixSuggestion]:
        """Return fix suggestions for a list of finding IDs."""
        return [self.get_fix_suggestion(fid, language) for fid in finding_ids]

    # ------------------------------------------------------------------
    # Upgrade recommendations
    # ------------------------------------------------------------------

    def get_upgrade_recommendations(
        self, repo_name: str, org_id: str
    ) -> List[Dict[str, Any]]:
        """Return findings of type outdated_dependency for a repo."""
        with self._get_conn() as conn:
            rows = conn.execute(
                """
                SELECT id, title, severity, cve_id, metadata
                FROM dev_findings
                WHERE repo_name = ? AND org_id = ? AND finding_type = 'outdated_dependency'
                  AND status != 'resolved'
                ORDER BY
                    CASE severity
                        WHEN 'critical' THEN 1
                        WHEN 'high'     THEN 2
                        WHEN 'medium'   THEN 3
                        ELSE 4
                    END
                """,
                (repo_name, org_id),
            ).fetchall()

        results = []
        for row in rows:
            meta: Dict[str, Any] = {}
            try:
                meta = json.loads(row["metadata"] or "{}")
            except (json.JSONDecodeError, TypeError):
                pass
            results.append(
                {
                    "finding_id": row["id"],
                    "title": row["title"],
                    "severity": row["severity"],
                    "cve_id": row["cve_id"],
                    "package": meta.get("package"),
                    "current_version": meta.get("current_version"),
                    "fixed_version": meta.get("fixed_version"),
                    "upgrade_command": meta.get("upgrade_command"),
                }
            )
        return results

    # ------------------------------------------------------------------
    # Learning resources
    # ------------------------------------------------------------------

    def _get_learning_db(self) -> Dict[str, List[Dict[str, Any]]]:
        """Return the built-in mapping of finding types to learning resources."""
        return _LEARNING_DB

    def get_learning_resources(self, finding_type: str) -> List[LearningResource]:
        """Return educational resources for the given finding type."""
        db = self._get_learning_db()
        raw = db.get(finding_type, db.get("default", []))
        return [
            LearningResource(
                title=item["title"],
                url=item["url"],
                category=item["category"],
                finding_types=[finding_type],
            )
            for item in raw
        ]

    # ------------------------------------------------------------------
    # Developer stats
    # ------------------------------------------------------------------

    def get_developer_stats(
        self, developer_email: str, org_id: str
    ) -> Dict[str, Any]:
        """Return per-developer statistics."""
        owned = self._get_owned_repos(developer_email, org_id)

        with self._get_conn() as conn:
            fix_rows = conn.execute(
                "SELECT time_to_fix_minutes FROM fix_events WHERE dev_email = ? AND org_id = ?",
                (developer_email, org_id),
            ).fetchall()

        fixes = [r["time_to_fix_minutes"] for r in fix_rows if r["time_to_fix_minutes"] is not None]
        avg_fix_time = round(sum(fixes) / len(fixes), 1) if fixes else None

        # Count open findings across owned repos
        open_count = 0
        if owned:
            placeholders = ",".join("?" * len(owned))
            with self._get_conn() as conn:
                row = conn.execute(
                    f"SELECT COUNT(*) AS c FROM dev_findings "  # nosec B608
                    f"WHERE repo_name IN ({placeholders}) AND org_id = ? AND status != 'resolved'",
                    [*owned, org_id],
                ).fetchone()
            open_count = row["c"] if row else 0

        return {
            "developer_email": developer_email,
            "org_id": org_id,
            "repos_owned": len(owned),
            "findings_fixed": len(fix_rows),
            "open_findings": open_count,
            "avg_fix_time_minutes": avg_fix_time,
        }

    # ------------------------------------------------------------------
    # Leaderboard
    # ------------------------------------------------------------------

    def get_leaderboard(self, org_id: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Return top developers ranked by number of findings fixed."""
        with self._get_conn() as conn:
            rows = conn.execute(
                """
                SELECT dev_email,
                       COUNT(*) AS fixes,
                       AVG(time_to_fix_minutes) AS avg_minutes
                FROM fix_events
                WHERE org_id = ?
                GROUP BY dev_email
                ORDER BY fixes DESC
                LIMIT ?
                """,
                (org_id, limit),
            ).fetchall()

        return [
            {
                "rank": idx + 1,
                "developer_email": row["dev_email"],
                "findings_fixed": row["fixes"],
                "avg_fix_time_minutes": (
                    round(row["avg_minutes"], 1) if row["avg_minutes"] is not None else None
                ),
            }
            for idx, row in enumerate(rows)
        ]

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

