"""
ALdeci Developer Risk Profiler -- Per-developer vulnerability risk scoring.

Tracks which developers (code authors/committers) introduce the most
vulnerabilities, their fix rates, and builds risk scores per developer.
Used for PR risk analysis: "this PR is by a high-risk developer who
introduced 5 critical vulns last month".

Privacy: raw emails are NEVER stored. developer_id = SHA256(email.lower()).
Only the email domain is retained for org-level analytics.

Usage:
    from core.developer_risk_profiler import DeveloperRiskProfiler

    profiler = DeveloperRiskProfiler()
    profiler.record_contribution(
        commit_sha="abc123",
        author_email="dev@company.com",
        files_changed=["src/auth.py"],
        lines_added=42,
        lines_deleted=10,
        findings_introduced=["FIND-001"],
    )
    profile = profiler.get_profile("dev@company.com")
    # profile.risk_score -> 34.7
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Set

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_ENGINE_VERSION = "1.0.0"
_DEFAULT_DB_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "data", "developer_profiles.db"
)

# Risk score weights (must sum to 1.0)
_W_INTRO_RATE = 0.35   # vulnerability introduction rate
_W_SEVERITY = 0.20     # severity distribution
_W_FIX_RATE = 0.18     # fix rate (low = higher risk)
_W_RECENCY = 0.12      # recent introductions weighted more
_W_MATERIALITY = 0.15  # material/breaking change ratio

# Severity multipliers for weighted severity score
_SEVERITY_WEIGHTS: Dict[str, float] = {
    "critical": 1.0,
    "high": 0.7,
    "medium": 0.4,
    "low": 0.15,
    "info": 0.05,
}

# Input limits
_MAX_FILES_PER_COMMIT = 5_000
_MAX_FINDINGS_PER_COMMIT = 10_000
_MAX_BULK_FINDINGS = 100_000
_MAX_COMMIT_SHA_LEN = 128
_MAX_EMAIL_LEN = 320
_MAX_DISPLAY_NAME_LEN = 256
_MAX_FINDING_ID_LEN = 256


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------


@dataclass
class DeveloperProfile:
    """Aggregated risk profile for a single developer."""

    developer_id: str           # SHA256(email.lower())
    email_domain: str           # e.g. "company.com"
    display_name: str           # initials or pseudonym
    first_seen: str             # ISO-8601
    last_seen: str              # ISO-8601
    total_commits: int = 0
    total_findings_introduced: int = 0
    findings_by_severity: Dict[str, int] = field(default_factory=dict)
    findings_fixed: int = 0
    avg_fix_time_hours: float = 0.0
    risk_score: float = 0.0     # 0-100
    risk_trend: str = "stable"  # improving | stable | degrading
    languages: Set[str] = field(default_factory=set)
    repos: Set[str] = field(default_factory=set)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["languages"] = sorted(self.languages)
        d["repos"] = sorted(self.repos)
        return d


@dataclass
class DeveloperContribution:
    """A single commit by a developer."""

    commit_sha: str
    developer_id: str
    timestamp: str              # ISO-8601
    files_changed: List[str] = field(default_factory=list)
    lines_added: int = 0
    lines_deleted: int = 0
    findings_introduced: List[str] = field(default_factory=list)
    security_relevant: bool = False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _hash_email(email: str) -> str:
    """SHA256 hash of lowercased email. Never store raw email."""
    return hashlib.sha256(email.strip().lower().encode("utf-8")).hexdigest()


def _extract_domain(email: str) -> str:
    """Extract domain from email, or 'unknown' if malformed."""
    email = email.strip().lower()
    if "@" in email:
        return email.rsplit("@", 1)[1]
    return "unknown"


def _make_initials(email: str) -> str:
    """Derive initials from the local part of an email."""
    local = email.strip().lower().split("@")[0]
    parts = local.replace(".", " ").replace("_", " ").replace("-", " ").split()
    if not parts:
        return "??"
    if len(parts) == 1:
        return parts[0][:2].upper()
    return (parts[0][0] + parts[-1][0]).upper()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_security_file(path: str) -> bool:
    """Heuristic: is this file security-relevant?"""
    lower = path.lower()
    keywords = (
        "auth", "login", "password", "crypt", "secur", "token",
        "session", "oauth", "saml", "jwt", "cert", "key", "secret",
        "permission", "acl", "rbac", "csrf", "xss", "sql",
    )
    return any(kw in lower for kw in keywords)


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class DeveloperRiskProfiler:
    """Tracks developer risk profiles backed by SQLite."""

    def __init__(self, db_path: Optional[str] = None):
        self._db_path = db_path or _DEFAULT_DB_PATH
        os.makedirs(os.path.dirname(os.path.abspath(self._db_path)), exist_ok=True)
        self._local = threading.local()
        self._write_lock = threading.Lock()
        self._init_db()

    # -- connection management -----------------------------------------------

    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(self._db_path)
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn.execute("PRAGMA foreign_keys=ON")
            self._local.conn.row_factory = sqlite3.Row
        return self._local.conn

    def _init_db(self) -> None:
        conn = self._conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS developer_profiles (
                developer_id        TEXT PRIMARY KEY,
                email_domain        TEXT NOT NULL,
                display_name        TEXT NOT NULL DEFAULT '??',
                first_seen          TEXT NOT NULL,
                last_seen           TEXT NOT NULL,
                total_commits       INTEGER NOT NULL DEFAULT 0,
                total_findings_introduced INTEGER NOT NULL DEFAULT 0,
                findings_by_severity_json TEXT NOT NULL DEFAULT '{}',
                findings_fixed      INTEGER NOT NULL DEFAULT 0,
                avg_fix_time_hours  REAL NOT NULL DEFAULT 0.0,
                risk_score          REAL NOT NULL DEFAULT 0.0,
                risk_trend          TEXT NOT NULL DEFAULT 'stable',
                languages_json      TEXT NOT NULL DEFAULT '[]',
                repos_json          TEXT NOT NULL DEFAULT '[]'
            );

            CREATE TABLE IF NOT EXISTS developer_contributions (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                commit_sha          TEXT NOT NULL,
                developer_id        TEXT NOT NULL,
                timestamp           TEXT NOT NULL,
                files_changed_json  TEXT NOT NULL DEFAULT '[]',
                lines_added         INTEGER NOT NULL DEFAULT 0,
                lines_deleted       INTEGER NOT NULL DEFAULT 0,
                findings_introduced_json TEXT NOT NULL DEFAULT '[]',
                security_relevant   INTEGER NOT NULL DEFAULT 0,
                material_changes_count INTEGER NOT NULL DEFAULT 0,
                breaking_changes_count INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (developer_id) REFERENCES developer_profiles(developer_id)
            );

            CREATE TABLE IF NOT EXISTS developer_findings (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                developer_id        TEXT NOT NULL,
                finding_id          TEXT NOT NULL,
                severity            TEXT NOT NULL DEFAULT 'medium',
                introduced_at       TEXT NOT NULL,
                fixed_at            TEXT,
                commit_sha          TEXT,
                FOREIGN KEY (developer_id) REFERENCES developer_profiles(developer_id)
            );

            CREATE TABLE IF NOT EXISTS risk_score_history (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                developer_id        TEXT NOT NULL,
                risk_score          REAL NOT NULL,
                recorded_at         TEXT NOT NULL,
                FOREIGN KEY (developer_id) REFERENCES developer_profiles(developer_id)
            );

            CREATE INDEX IF NOT EXISTS idx_contrib_dev
                ON developer_contributions(developer_id);
            CREATE INDEX IF NOT EXISTS idx_contrib_sha
                ON developer_contributions(commit_sha);
            CREATE INDEX IF NOT EXISTS idx_contrib_ts
                ON developer_contributions(timestamp);
            CREATE INDEX IF NOT EXISTS idx_findings_dev
                ON developer_findings(developer_id);
            CREATE INDEX IF NOT EXISTS idx_findings_fid
                ON developer_findings(finding_id);
            CREATE INDEX IF NOT EXISTS idx_findings_sev
                ON developer_findings(severity);
            CREATE INDEX IF NOT EXISTS idx_history_dev
                ON risk_score_history(developer_id);
            CREATE INDEX IF NOT EXISTS idx_history_ts
                ON risk_score_history(recorded_at);
        """)
        conn.commit()

    def close(self) -> None:
        if hasattr(self._local, "conn") and self._local.conn:
            self._local.conn.close()
            self._local.conn = None

    # -- input validation ----------------------------------------------------

    @staticmethod
    def _validate_email(email: str) -> str:
        if not email or not isinstance(email, str):
            raise ValueError("author_email is required")
        email = email.strip()
        if len(email) > _MAX_EMAIL_LEN:
            raise ValueError("email exceeds maximum length")
        if "@" not in email:
            raise ValueError("invalid email format")
        return email

    @staticmethod
    def _validate_sha(sha: str) -> str:
        if not sha or not isinstance(sha, str):
            raise ValueError("commit_sha is required")
        sha = sha.strip()
        if len(sha) > _MAX_COMMIT_SHA_LEN:
            raise ValueError("commit_sha exceeds maximum length")
        return sha

    # -- write operations (thread-safe) --------------------------------------

    def _ensure_profile(self, developer_id: str, email: str) -> None:
        """Create profile row if it does not exist."""
        conn = self._conn()
        existing = conn.execute(
            "SELECT 1 FROM developer_profiles WHERE developer_id = ?",
            (developer_id,),
        ).fetchone()
        if existing:
            return
        now = _now_iso()
        conn.execute(
            """INSERT INTO developer_profiles
               (developer_id, email_domain, display_name, first_seen, last_seen)
               VALUES (?, ?, ?, ?, ?)""",
            (developer_id, _extract_domain(email), _make_initials(email), now, now),
        )

    def record_contribution(
        self,
        commit_sha: str,
        author_email: str,
        files_changed: Sequence[str],
        lines_added: int = 0,
        lines_deleted: int = 0,
        findings_introduced: Optional[Sequence[str]] = None,
        material_changes_count: int = 0,
        breaking_changes_count: int = 0,
    ) -> str:
        """Record a commit and any findings it introduced. Returns developer_id.

        Args:
            material_changes_count: Number of MATERIAL-classified changes in this commit.
            breaking_changes_count: Number of BREAKING-classified changes in this commit.
        """
        commit_sha = self._validate_sha(commit_sha)
        author_email = self._validate_email(author_email)
        findings_introduced = list(findings_introduced or [])
        files_list = list(files_changed or [])

        if len(files_list) > _MAX_FILES_PER_COMMIT:
            files_list = files_list[:_MAX_FILES_PER_COMMIT]
        if len(findings_introduced) > _MAX_FINDINGS_PER_COMMIT:
            findings_introduced = findings_introduced[:_MAX_FINDINGS_PER_COMMIT]

        developer_id = _hash_email(author_email)
        now = _now_iso()
        sec_relevant = any(_is_security_file(f) for f in files_list)

        with self._write_lock:
            conn = self._conn()
            self._ensure_profile(developer_id, author_email)

            # Insert contribution
            conn.execute(
                """INSERT INTO developer_contributions
                   (commit_sha, developer_id, timestamp, files_changed_json,
                    lines_added, lines_deleted, findings_introduced_json,
                    security_relevant, material_changes_count, breaking_changes_count)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    commit_sha,
                    developer_id,
                    now,
                    json.dumps(files_list),
                    max(0, int(lines_added)),
                    max(0, int(lines_deleted)),
                    json.dumps(findings_introduced),
                    1 if sec_relevant else 0,
                    max(0, int(material_changes_count)),
                    max(0, int(breaking_changes_count)),
                ),
            )

            # Insert findings
            for fid in findings_introduced:
                if not fid or len(str(fid)) > _MAX_FINDING_ID_LEN:
                    continue
                conn.execute(
                    """INSERT INTO developer_findings
                       (developer_id, finding_id, severity, introduced_at, commit_sha)
                       VALUES (?, ?, ?, ?, ?)""",
                    (developer_id, str(fid), "medium", now, commit_sha),
                )

            # Update profile counters
            conn.execute(
                """UPDATE developer_profiles SET
                       total_commits = total_commits + 1,
                       total_findings_introduced = total_findings_introduced + ?,
                       last_seen = ?
                   WHERE developer_id = ?""",
                (len(findings_introduced), now, developer_id),
            )
            conn.commit()

        return developer_id

    def record_fix(
        self,
        developer_email: str,
        finding_id: str,
        fixed_at: Optional[str] = None,
    ) -> bool:
        """Record when a developer fixes a finding. Returns True if updated."""
        developer_email = self._validate_email(developer_email)
        developer_id = _hash_email(developer_email)
        if not finding_id or len(str(finding_id)) > _MAX_FINDING_ID_LEN:
            raise ValueError("invalid finding_id")
        fixed_at = fixed_at or _now_iso()

        with self._write_lock:
            conn = self._conn()
            # Find the unfixed finding row
            row = conn.execute(
                """SELECT id, introduced_at FROM developer_findings
                   WHERE developer_id = ? AND finding_id = ? AND fixed_at IS NULL
                   LIMIT 1""",
                (developer_id, str(finding_id)),
            ).fetchone()
            if not row:
                return False

            conn.execute(
                "UPDATE developer_findings SET fixed_at = ? WHERE id = ?",
                (fixed_at, row["id"]),
            )
            conn.execute(
                """UPDATE developer_profiles SET findings_fixed = findings_fixed + 1
                   WHERE developer_id = ?""",
                (developer_id,),
            )
            conn.commit()

        # Recompute average fix time
        self._recompute_avg_fix_time(developer_id)
        return True

    def _recompute_avg_fix_time(self, developer_id: str) -> None:
        """Recompute average fix time in hours for a developer."""
        conn = self._conn()
        rows = conn.execute(
            """SELECT introduced_at, fixed_at FROM developer_findings
               WHERE developer_id = ? AND fixed_at IS NOT NULL""",
            (developer_id,),
        ).fetchall()
        if not rows:
            return

        total_hours = 0.0
        count = 0
        for r in rows:
            try:
                intro = datetime.fromisoformat(r["introduced_at"])
                fixed = datetime.fromisoformat(r["fixed_at"])
                delta_h = max(0.0, (fixed - intro).total_seconds() / 3600.0)
                total_hours += delta_h
                count += 1
            except (ValueError, TypeError):
                continue

        if count > 0:
            avg = total_hours / count
            with self._write_lock:
                conn.execute(
                    "UPDATE developer_profiles SET avg_fix_time_hours = ? WHERE developer_id = ?",
                    (round(avg, 2), developer_id),
                )
                conn.commit()

    # -- risk scoring --------------------------------------------------------

    def compute_risk_score(self, developer_email: str) -> float:
        """
        Multi-factor risk scoring (0-100).

        Weights:
          40% -- vulnerability introduction rate (findings per commit)
          25% -- severity distribution (more criticals = higher risk)
          20% -- fix rate (low fix rate = higher risk)
          15% -- recency (recent introductions weighted more)
        """
        developer_email = self._validate_email(developer_email)
        developer_id = _hash_email(developer_email)
        conn = self._conn()

        profile_row = conn.execute(
            "SELECT * FROM developer_profiles WHERE developer_id = ?",
            (developer_id,),
        ).fetchone()
        if not profile_row:
            return 0.0

        total_commits = profile_row["total_commits"] or 0
        total_introduced = profile_row["total_findings_introduced"] or 0
        findings_fixed = profile_row["findings_fixed"] or 0

        # ---- Factor 1: Introduction rate (findings per commit) ----
        if total_commits == 0:
            intro_rate_score = 0.0
        else:
            rate = total_introduced / total_commits
            # Normalize: 0 findings/commit -> 0, 1+ findings/commit -> 100
            intro_rate_score = min(100.0, rate * 100.0)

        # ---- Factor 2: Severity distribution ----
        findings_rows = conn.execute(
            "SELECT severity FROM developer_findings WHERE developer_id = ?",
            (developer_id,),
        ).fetchall()

        if not findings_rows:
            severity_score = 0.0
        else:
            weighted_sum = 0.0
            for fr in findings_rows:
                sev = (fr["severity"] or "medium").lower()
                weighted_sum += _SEVERITY_WEIGHTS.get(sev, 0.4)
            # Average severity weight normalized to 0-100
            avg_weight = weighted_sum / len(findings_rows)
            severity_score = min(100.0, avg_weight * 100.0)

        # ---- Factor 3: Fix rate ----
        if total_introduced == 0:
            fix_rate_score = 0.0  # no findings = no risk from fix rate
        else:
            fix_ratio = findings_fixed / total_introduced
            # Higher fix ratio -> lower risk. Invert: (1 - fix_ratio) * 100
            fix_rate_score = max(0.0, (1.0 - fix_ratio) * 100.0)

        # ---- Factor 4: Recency ----
        # Count findings introduced in last 30 days vs older
        recent_rows = conn.execute(
            """SELECT COUNT(*) as cnt FROM developer_findings
               WHERE developer_id = ?
               AND introduced_at >= datetime('now', '-30 days')""",
            (developer_id,),
        ).fetchone()
        recent_count = recent_rows["cnt"] if recent_rows else 0

        if total_introduced == 0:
            recency_score = 0.0
        else:
            recency_ratio = recent_count / total_introduced
            # More recent introductions -> higher risk
            recency_score = min(100.0, recency_ratio * 100.0)

        # ---- Factor 5: Material change ratio ----
        # Developers who frequently make BREAKING/MATERIAL security changes
        # without corresponding findings are low risk (security-conscious).
        # Those who make breaking changes AND introduce findings are high risk.
        material_row = conn.execute(
            """SELECT
                   COALESCE(SUM(material_changes_count), 0) as total_material,
                   COALESCE(SUM(breaking_changes_count), 0) as total_breaking
               FROM developer_contributions
               WHERE developer_id = ?""",
            (developer_id,),
        ).fetchone()
        total_material = material_row["total_material"] if material_row else 0
        total_breaking = material_row["total_breaking"] if material_row else 0

        if total_commits == 0 or (total_material + total_breaking) == 0:
            materiality_score = 0.0
        else:
            # Ratio of breaking+material changes to total commits
            mat_ratio = (total_material + total_breaking * 2) / total_commits
            # Higher ratio + findings = dangerous; cap at 100
            if total_introduced > 0:
                # Amplify: developer makes security-relevant changes AND introduces vulns
                materiality_score = min(100.0, mat_ratio * 50.0 * (1 + total_introduced / total_commits))
            else:
                # Makes security changes but doesn't introduce vulns — lower risk
                materiality_score = min(30.0, mat_ratio * 15.0)

        # ---- Weighted combination ----
        risk = (
            _W_INTRO_RATE * intro_rate_score
            + _W_SEVERITY * severity_score
            + _W_FIX_RATE * fix_rate_score
            + _W_RECENCY * recency_score
            + _W_MATERIALITY * materiality_score
        )
        risk = round(min(100.0, max(0.0, risk)), 1)

        # Persist score and update trend
        self._update_risk_score(developer_id, risk)
        return risk

    def _update_risk_score(self, developer_id: str, new_score: float) -> None:
        """Persist risk score, update trend, and record history."""
        conn = self._conn()
        now = _now_iso()

        # Determine trend from history
        history = conn.execute(
            """SELECT risk_score FROM risk_score_history
               WHERE developer_id = ?
               ORDER BY recorded_at DESC LIMIT 5""",
            (developer_id,),
        ).fetchall()

        trend = "stable"
        if len(history) >= 2:
            old_avg = sum(r["risk_score"] for r in history) / len(history)
            delta = new_score - old_avg
            if delta > 3.0:
                trend = "degrading"
            elif delta < -3.0:
                trend = "improving"

        # Update severity breakdown
        sev_rows = conn.execute(
            """SELECT severity, COUNT(*) as cnt FROM developer_findings
               WHERE developer_id = ? GROUP BY severity""",
            (developer_id,),
        ).fetchall()
        sev_dict = {r["severity"]: r["cnt"] for r in sev_rows}

        with self._write_lock:
            conn.execute(
                """UPDATE developer_profiles SET
                       risk_score = ?,
                       risk_trend = ?,
                       findings_by_severity_json = ?
                   WHERE developer_id = ?""",
                (new_score, trend, json.dumps(sev_dict), developer_id),
            )
            conn.execute(
                """INSERT INTO risk_score_history
                   (developer_id, risk_score, recorded_at)
                   VALUES (?, ?, ?)""",
                (developer_id, new_score, now),
            )
            conn.commit()

    # -- read operations -----------------------------------------------------

    def get_profile(self, developer_email: str) -> Optional[DeveloperProfile]:
        """Return full developer profile with current risk score."""
        developer_email = self._validate_email(developer_email)
        developer_id = _hash_email(developer_email)

        # Recompute risk score on read for freshness
        self.compute_risk_score(developer_email)

        conn = self._conn()
        row = conn.execute(
            "SELECT * FROM developer_profiles WHERE developer_id = ?",
            (developer_id,),
        ).fetchone()
        if not row:
            return None

        return DeveloperProfile(
            developer_id=row["developer_id"],
            email_domain=row["email_domain"],
            display_name=row["display_name"],
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            total_commits=row["total_commits"],
            total_findings_introduced=row["total_findings_introduced"],
            findings_by_severity=json.loads(row["findings_by_severity_json"] or "{}"),
            findings_fixed=row["findings_fixed"],
            avg_fix_time_hours=row["avg_fix_time_hours"],
            risk_score=row["risk_score"],
            risk_trend=row["risk_trend"],
            languages=set(json.loads(row["languages_json"] or "[]")),
            repos=set(json.loads(row["repos_json"] or "[]")),
        )

    def get_pr_risk_context(
        self,
        author_email: str,
        files_changed: Sequence[str],
    ) -> Dict[str, Any]:
        """
        Given a PR author and changed files, return risk context for the PR.

        Returns:
            {
                "developer_risk_score": float,
                "developer_risk_trend": str,
                "total_past_findings": int,
                "severity_breakdown": dict,
                "fix_rate_percent": float,
                "security_files_touched": list,
                "historical_findings_in_same_files": int,
                "pr_risk_level": "low" | "medium" | "high" | "critical",
                "recommendation": str,
            }
        """
        author_email = self._validate_email(author_email)
        developer_id = _hash_email(author_email)
        files_list = list(files_changed or [])

        conn = self._conn()
        profile = self.get_profile(author_email)

        # Default context for unknown developers
        if profile is None:
            return {
                "developer_risk_score": 0.0,
                "developer_risk_trend": "stable",
                "total_past_findings": 0,
                "severity_breakdown": {},
                "fix_rate_percent": 100.0,
                "security_files_touched": [f for f in files_list if _is_security_file(f)],
                "historical_findings_in_same_files": 0,
                "pr_risk_level": "low",
                "recommendation": "New developer -- no historical risk data available.",
            }

        # Count findings historically associated with the same files
        historical_in_files = 0
        if files_list:
            for f in files_list[:200]:  # cap iteration
                rows = conn.execute(
                    """SELECT COUNT(*) as cnt FROM developer_contributions
                       WHERE developer_id = ?
                       AND files_changed_json LIKE ?
                       AND findings_introduced_json != '[]'""",
                    (developer_id, f"%{json.dumps(f)[1:-1]}%"),
                ).fetchone()
                historical_in_files += rows["cnt"] if rows else 0

        fix_rate = 0.0
        if profile.total_findings_introduced > 0:
            fix_rate = round(
                (profile.findings_fixed / profile.total_findings_introduced) * 100.0, 1
            )

        sec_files = [f for f in files_list if _is_security_file(f)]

        # Fetch material change history for this developer
        material_row = conn.execute(
            """SELECT
                   COALESCE(SUM(material_changes_count), 0) as total_material,
                   COALESCE(SUM(breaking_changes_count), 0) as total_breaking
               FROM developer_contributions
               WHERE developer_id = ?""",
            (developer_id,),
        ).fetchone()
        total_material = material_row["total_material"] if material_row else 0
        total_breaking = material_row["total_breaking"] if material_row else 0

        # Determine PR risk level — material changes amplify risk
        score = profile.risk_score
        has_sec_files = len(sec_files) > 0
        has_breaking_history = total_breaking > 2
        if score >= 70 or (score >= 50 and has_sec_files) or (score >= 40 and has_breaking_history):
            pr_level = "critical"
        elif score >= 45 or (score >= 30 and has_sec_files) or (score >= 25 and has_breaking_history):
            pr_level = "high"
        elif score >= 20:
            pr_level = "medium"
        else:
            pr_level = "low"

        recommendations = {
            "critical": "Mandatory security review required. Developer has high vulnerability introduction rate.",
            "high": "Security-focused code review recommended. Check for common vulnerability patterns.",
            "medium": "Standard code review with attention to security-sensitive changes.",
            "low": "Standard code review process.",
        }
        if has_breaking_history and pr_level in ("critical", "high"):
            recommendations[pr_level] += (
                f" Developer has {total_breaking} historical BREAKING changes — "
                "extra scrutiny on auth/crypto/API surface modifications."
            )

        return {
            "developer_risk_score": profile.risk_score,
            "developer_risk_trend": profile.risk_trend,
            "total_past_findings": profile.total_findings_introduced,
            "severity_breakdown": profile.findings_by_severity,
            "fix_rate_percent": fix_rate,
            "security_files_touched": sec_files,
            "historical_findings_in_same_files": historical_in_files,
            "material_changes_total": total_material,
            "breaking_changes_total": total_breaking,
            "pr_risk_level": pr_level,
            "recommendation": recommendations[pr_level],
        }

    def get_team_leaderboard(
        self,
        org_id: Optional[str] = None,
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        """Ranked list of developers by risk score (highest risk first)."""
        limit = max(1, min(limit, 500))
        conn = self._conn()

        if org_id:
            rows = conn.execute(
                """SELECT * FROM developer_profiles
                   WHERE email_domain = ?
                   ORDER BY risk_score DESC LIMIT ?""",
                (org_id, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM developer_profiles ORDER BY risk_score DESC LIMIT ?",
                (limit,),
            ).fetchall()

        result = []
        for r in rows:
            result.append({
                "developer_id": r["developer_id"],
                "display_name": r["display_name"],
                "email_domain": r["email_domain"],
                "risk_score": r["risk_score"],
                "risk_trend": r["risk_trend"],
                "total_commits": r["total_commits"],
                "total_findings_introduced": r["total_findings_introduced"],
                "findings_fixed": r["findings_fixed"],
                "fix_rate_percent": round(
                    (r["findings_fixed"] / r["total_findings_introduced"] * 100.0)
                    if r["total_findings_introduced"] > 0
                    else 100.0,
                    1,
                ),
            })
        return result

    def get_risk_trend(
        self,
        developer_email: str,
        days: int = 90,
    ) -> List[Dict[str, Any]]:
        """Risk score history over time for a developer."""
        developer_email = self._validate_email(developer_email)
        developer_id = _hash_email(developer_email)
        days = max(1, min(days, 365))

        conn = self._conn()
        rows = conn.execute(
            """SELECT risk_score, recorded_at FROM risk_score_history
               WHERE developer_id = ?
               AND recorded_at >= datetime('now', ?)
               ORDER BY recorded_at ASC""",
            (developer_id, f"-{days} days"),
        ).fetchall()

        return [
            {"risk_score": r["risk_score"], "recorded_at": r["recorded_at"]}
            for r in rows
        ]

    def bulk_ingest_from_findings(
        self,
        findings: Sequence[Dict[str, Any]],
        org_id: str = "default",
    ) -> Dict[str, Any]:
        """
        Ingest existing findings to build historical profiles.

        Each finding dict should have:
          - author_email: str (required)
          - finding_id: str (required)
          - severity: str (optional, default "medium")
          - introduced_at: str ISO (optional)
          - fixed_at: str ISO or None (optional)
          - commit_sha: str (optional)
          - files: list[str] (optional)
        """
        if not findings:
            return {"ingested": 0, "skipped": 0, "developers_affected": 0}

        findings_list = list(findings)
        if len(findings_list) > _MAX_BULK_FINDINGS:
            logger.warning(
                "Bulk ingest capped at %d findings (received %d)",
                _MAX_BULK_FINDINGS,
                len(findings_list),
            )
            findings_list = findings_list[:_MAX_BULK_FINDINGS]

        ingested = 0
        skipped = 0
        dev_ids: Set[str] = set()

        with self._write_lock:
            conn = self._conn()
            for f in findings_list:
                try:
                    email = f.get("author_email", "")
                    finding_id = f.get("finding_id", "")
                    if not email or "@" not in email or not finding_id:
                        skipped += 1
                        continue

                    email = email.strip()[:_MAX_EMAIL_LEN]
                    finding_id = str(finding_id)[:_MAX_FINDING_ID_LEN]
                    developer_id = _hash_email(email)
                    severity = (f.get("severity") or "medium").lower()
                    if severity not in _SEVERITY_WEIGHTS:
                        severity = "medium"
                    introduced_at = f.get("introduced_at") or _now_iso()
                    fixed_at = f.get("fixed_at")
                    commit_sha = (f.get("commit_sha") or "")[:_MAX_COMMIT_SHA_LEN]

                    self._ensure_profile(developer_id, email)

                    # Check for duplicate finding
                    existing = conn.execute(
                        """SELECT 1 FROM developer_findings
                           WHERE developer_id = ? AND finding_id = ? LIMIT 1""",
                        (developer_id, finding_id),
                    ).fetchone()
                    if existing:
                        skipped += 1
                        continue

                    conn.execute(
                        """INSERT INTO developer_findings
                           (developer_id, finding_id, severity, introduced_at,
                            fixed_at, commit_sha)
                           VALUES (?, ?, ?, ?, ?, ?)""",
                        (developer_id, finding_id, severity, introduced_at,
                         fixed_at, commit_sha),
                    )

                    # Update counters
                    conn.execute(
                        """UPDATE developer_profiles SET
                               total_findings_introduced = total_findings_introduced + 1,
                               findings_fixed = findings_fixed + ?
                           WHERE developer_id = ?""",
                        (1 if fixed_at else 0, developer_id),
                    )

                    dev_ids.add(developer_id)
                    ingested += 1

                except (ValueError, TypeError, KeyError) as exc:
                    logger.debug(
                        "Skipping finding during bulk ingest: %s",
                        type(exc).__name__,
                    )
                    skipped += 1
                    continue

            conn.commit()

        # Recompute avg fix time for affected developers
        for did in dev_ids:
            self._recompute_avg_fix_time(did)

        return {
            "ingested": ingested,
            "skipped": skipped,
            "developers_affected": len(dev_ids),
        }

    # -- stats ---------------------------------------------------------------

    def get_stats(self) -> Dict[str, Any]:
        """Global statistics for the profiler."""
        conn = self._conn()
        profiles = conn.execute(
            "SELECT COUNT(*) as cnt FROM developer_profiles"
        ).fetchone()
        contributions = conn.execute(
            "SELECT COUNT(*) as cnt FROM developer_contributions"
        ).fetchone()
        findings = conn.execute(
            "SELECT COUNT(*) as cnt FROM developer_findings"
        ).fetchone()
        avg_score = conn.execute(
            "SELECT AVG(risk_score) as avg FROM developer_profiles"
        ).fetchone()

        return {
            "total_developers": profiles["cnt"] if profiles else 0,
            "total_contributions": contributions["cnt"] if contributions else 0,
            "total_findings_tracked": findings["cnt"] if findings else 0,
            "avg_risk_score": round(avg_score["avg"] or 0.0, 1) if avg_score else 0.0,
            "engine_version": _ENGINE_VERSION,
        }
