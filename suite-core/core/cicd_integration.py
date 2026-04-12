"""CI/CD Pipeline Security Integration for ALDECI/FixOps.

Provides a policy gate engine that evaluates security findings from the brain
pipeline and blocks/warns/passes CI/CD pipelines based on configured rules.

Designed to integrate with GitHub Actions and GitLab CI via the REST API.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Default DB path (overridden in tests via constructor)
# ---------------------------------------------------------------------------
_DEFAULT_DB_PATH = Path(__file__).parent.parent.parent / "data" / "cicd_integration.db"


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class PolicyAction(str, Enum):
    """Outcome of evaluating findings against a policy."""

    PASS = "pass"
    WARN = "warn"
    BLOCK = "block"


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class PolicyRule(BaseModel):
    """Single rule within a CI/CD policy."""

    name: str = Field(..., description="Human-readable rule name")
    severity_threshold: str = Field(
        "critical",
        description="Block if any finding >= this severity (critical|high|medium|low)",
    )
    max_critical: int = Field(0, ge=0, description="Max allowed critical findings before blocking")
    max_high: int = Field(5, ge=0, description="Max allowed high findings before blocking")
    categories: List[str] = Field(
        default_factory=list,
        description="Only apply rule to these finding categories (empty = all)",
    )
    enabled: bool = Field(True, description="Whether this rule is active")


class ScanResult(BaseModel):
    """Result of evaluating a CI scan against a policy."""

    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    repo: str = Field(..., description="Repository slug (owner/name)")
    branch: str = Field("main", description="Branch name")
    commit_sha: str = Field("", description="Full commit SHA")
    findings_count: int = Field(0, ge=0)
    critical: int = Field(0, ge=0)
    high: int = Field(0, ge=0)
    medium: int = Field(0, ge=0)
    low: int = Field(0, ge=0)
    policy_action: PolicyAction = Field(PolicyAction.PASS)
    details: List[Dict[str, Any]] = Field(default_factory=list)
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    duration_ms: int = Field(0, ge=0)


class PRComment(BaseModel):
    """PR comment payload for posting scan results to a pull request."""

    repo: str = Field(..., description="Repository slug (owner/name)")
    pr_number: int = Field(..., ge=1)
    body: str = Field(..., description="Markdown comment body")
    badge_url: str = Field("", description="URL to the badge SVG")


# ---------------------------------------------------------------------------
# Policy Gate Engine
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

_BADGE_COLORS = {
    PolicyAction.PASS: "#4c1",      # green
    PolicyAction.WARN: "#fe7d37",   # orange
    PolicyAction.BLOCK: "#e05d44",  # red
}

_BADGE_LABELS = {
    PolicyAction.PASS: "passing",
    PolicyAction.WARN: "warning",
    PolicyAction.BLOCK: "failing",
}


class CICDPolicyEngine:
    """SQLite-backed CI/CD policy gate engine.

    Stores policies and scan history in a local SQLite database.  All public
    methods are synchronous and thread-safe via ``check_same_thread=False``.
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        resolved = Path(db_path) if db_path else _DEFAULT_DB_PATH
        resolved.parent.mkdir(parents=True, exist_ok=True)
        self._db_path = str(resolved)
        self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()
        logger.info("CICDPolicyEngine initialised at %s", self._db_path)

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_schema(self) -> None:
        with self._conn:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS policies (
                    policy_id   TEXT PRIMARY KEY,
                    org_id      TEXT NOT NULL DEFAULT '',
                    rules_json  TEXT NOT NULL,
                    created_at  TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS scan_history (
                    scan_id        TEXT PRIMARY KEY,
                    repo           TEXT NOT NULL,
                    branch         TEXT NOT NULL DEFAULT 'main',
                    commit_sha     TEXT NOT NULL DEFAULT '',
                    findings_count INTEGER NOT NULL DEFAULT 0,
                    critical       INTEGER NOT NULL DEFAULT 0,
                    high           INTEGER NOT NULL DEFAULT 0,
                    medium         INTEGER NOT NULL DEFAULT 0,
                    low            INTEGER NOT NULL DEFAULT 0,
                    policy_action  TEXT NOT NULL,
                    details_json   TEXT NOT NULL DEFAULT '[]',
                    scanned_at     TEXT NOT NULL,
                    duration_ms    INTEGER NOT NULL DEFAULT 0
                );

                CREATE INDEX IF NOT EXISTS idx_scan_repo_branch
                    ON scan_history (repo, branch, scanned_at DESC);
                """
            )

    # ------------------------------------------------------------------
    # Policy CRUD
    # ------------------------------------------------------------------

    def create_policy(
        self,
        rules: List[PolicyRule],
        org_id: str = "",
    ) -> str:
        """Persist a new policy and return its generated policy_id."""
        policy_id = str(uuid.uuid4())
        rules_json = json.dumps([r.model_dump() for r in rules])
        created_at = datetime.now(timezone.utc).isoformat()
        with self._conn:
            self._conn.execute(
                "INSERT INTO policies (policy_id, org_id, rules_json, created_at) VALUES (?, ?, ?, ?)",
                (policy_id, org_id, rules_json, created_at),
            )
        logger.debug("Created policy %s for org %s with %d rules", policy_id, org_id, len(rules))
        return policy_id

    def get_policy(self, policy_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a policy by ID, or None if not found."""
        row = self._conn.execute(
            "SELECT * FROM policies WHERE policy_id = ?", (policy_id,)
        ).fetchone()
        if not row:
            return None
        return {
            "policy_id": row["policy_id"],
            "org_id": row["org_id"],
            "rules": json.loads(row["rules_json"]),
            "created_at": row["created_at"],
        }

    def list_policies(self, org_id: str = "") -> List[Dict[str, Any]]:
        """List all policies, optionally filtered by org_id."""
        if org_id:
            rows = self._conn.execute(
                "SELECT * FROM policies WHERE org_id = ? ORDER BY created_at DESC", (org_id,)
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM policies ORDER BY created_at DESC"
            ).fetchall()
        return [
            {
                "policy_id": r["policy_id"],
                "org_id": r["org_id"],
                "rules": json.loads(r["rules_json"]),
                "created_at": r["created_at"],
            }
            for r in rows
        ]

    # ------------------------------------------------------------------
    # Scan evaluation
    # ------------------------------------------------------------------

    def evaluate_scan(
        self,
        findings: List[Dict[str, Any]],
        policy_id: str,
        repo: str = "",
        branch: str = "main",
        commit_sha: str = "",
        duration_ms: int = 0,
    ) -> ScanResult:
        """Evaluate *findings* against the stored policy and return a ScanResult.

        Each finding dict should contain at minimum:
            ``severity`` (str): critical | high | medium | low | info
            ``category`` (str, optional): finding category

        The most restrictive applicable rule wins.
        """
        policy = self.get_policy(policy_id)
        if policy is None:
            raise ValueError(f"Policy {policy_id!r} not found")

        rules = [PolicyRule(**r) for r in policy["rules"]]

        # Count severities
        counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            sev = str(f.get("severity", "low")).lower()
            if sev in counts:
                counts[sev] += 1

        action = PolicyAction.PASS
        triggered_rules: List[str] = []

        for rule in rules:
            if not rule.enabled:
                continue

            # Filter findings by category if the rule specifies any
            relevant = findings
            if rule.categories:
                relevant = [
                    f for f in findings
                    if str(f.get("category", "")).lower() in [c.lower() for c in rule.categories]
                ]

            rel_counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for f in relevant:
                sev = str(f.get("severity", "low")).lower()
                if sev in rel_counts:
                    rel_counts[sev] += 1

            rule_action = self._apply_rule(rule, rel_counts)
            if _action_weight(rule_action) > _action_weight(action):
                action = rule_action
            if rule_action != PolicyAction.PASS:
                triggered_rules.append(rule.name)

        result = ScanResult(
            repo=repo,
            branch=branch,
            commit_sha=commit_sha,
            findings_count=len(findings),
            critical=counts["critical"],
            high=counts["high"],
            medium=counts["medium"],
            low=counts["low"],
            policy_action=action,
            details=[{"triggered_rules": triggered_rules, "findings_summary": counts}],
            duration_ms=duration_ms,
        )

        # Persist to history
        self._save_scan(result)
        return result

    def _apply_rule(
        self, rule: PolicyRule, counts: Dict[str, int]
    ) -> PolicyAction:
        """Return the PolicyAction implied by a single rule given severity counts."""
        threshold_weight = _SEVERITY_ORDER.get(rule.severity_threshold.lower(), 4)

        # Check if any finding meets or exceeds the severity threshold
        for sev, weight in _SEVERITY_ORDER.items():
            if weight >= threshold_weight and counts.get(sev, 0) > 0:
                return PolicyAction.BLOCK

        # Check explicit max counts
        if counts.get("critical", 0) > rule.max_critical:
            return PolicyAction.BLOCK
        if counts.get("high", 0) > rule.max_high:
            return PolicyAction.WARN

        return PolicyAction.PASS

    def _save_scan(self, result: ScanResult) -> None:
        with self._conn:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO scan_history
                    (scan_id, repo, branch, commit_sha, findings_count,
                     critical, high, medium, low, policy_action,
                     details_json, scanned_at, duration_ms)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    result.scan_id,
                    result.repo,
                    result.branch,
                    result.commit_sha,
                    result.findings_count,
                    result.critical,
                    result.high,
                    result.medium,
                    result.low,
                    result.policy_action.value,
                    json.dumps(result.details),
                    result.scanned_at.isoformat(),
                    result.duration_ms,
                ),
            )

    # ------------------------------------------------------------------
    # History
    # ------------------------------------------------------------------

    def get_scan_history(
        self,
        repo: str,
        branch: str = "",
        limit: int = 50,
    ) -> List[ScanResult]:
        """Return recent scan results for a repo, newest first."""
        if branch:
            rows = self._conn.execute(
                """
                SELECT * FROM scan_history
                WHERE repo = ? AND branch = ?
                ORDER BY scanned_at DESC
                LIMIT ?
                """,
                (repo, branch, limit),
            ).fetchall()
        else:
            rows = self._conn.execute(
                """
                SELECT * FROM scan_history
                WHERE repo = ?
                ORDER BY scanned_at DESC
                LIMIT ?
                """,
                (repo, limit),
            ).fetchall()

        results = []
        for r in rows:
            results.append(
                ScanResult(
                    scan_id=r["scan_id"],
                    repo=r["repo"],
                    branch=r["branch"],
                    commit_sha=r["commit_sha"],
                    findings_count=r["findings_count"],
                    critical=r["critical"],
                    high=r["high"],
                    medium=r["medium"],
                    low=r["low"],
                    policy_action=PolicyAction(r["policy_action"]),
                    details=json.loads(r["details_json"]),
                    scanned_at=datetime.fromisoformat(r["scanned_at"]),
                    duration_ms=r["duration_ms"],
                )
            )
        return results

    # ------------------------------------------------------------------
    # PR comment & badge
    # ------------------------------------------------------------------

    def generate_pr_comment(self, scan_result: ScanResult) -> str:
        """Generate a markdown PR comment summarising the scan result."""
        action = scan_result.policy_action
        icon = {"pass": "✅", "warn": "⚠️", "block": "🚫"}.get(action.value, "ℹ️")
        headline = {
            "pass": "Security scan **passed**",
            "warn": "Security scan completed with **warnings**",
            "block": "Security scan **failed** — merge blocked",
        }.get(action.value, "Security scan complete")

        triggered = []
        for d in scan_result.details:
            triggered.extend(d.get("triggered_rules", []))

        lines = [
            f"## {icon} ALDECI Security Scan — {headline}",
            "",
            f"**Repo:** `{scan_result.repo}` | "
            f"**Branch:** `{scan_result.branch}` | "
            f"**Commit:** `{scan_result.commit_sha[:8] or 'N/A'}`",
            "",
            "### Findings Summary",
            "",
            "| Severity | Count |",
            "|----------|-------|",
            f"| 🔴 Critical | {scan_result.critical} |",
            f"| 🟠 High     | {scan_result.high} |",
            f"| 🟡 Medium   | {scan_result.medium} |",
            f"| 🟢 Low      | {scan_result.low} |",
            f"| **Total**   | **{scan_result.findings_count}** |",
            "",
        ]

        if triggered:
            lines += [
                "### Triggered Rules",
                "",
                *[f"- `{r}`" for r in triggered],
                "",
            ]

        lines += [
            f"*Scan completed in {scan_result.duration_ms}ms · "
            f"Powered by [ALDECI](https://github.com/DevOpsMadDog/Fixops)*",
        ]

        return "\n".join(lines)

    def generate_badge(self, scan_result: ScanResult) -> Dict[str, Any]:
        """Return SVG badge data as a dict (color, label, message)."""
        action = scan_result.policy_action
        color = _BADGE_COLORS[action]
        label = _BADGE_LABELS[action]
        message = f"{scan_result.findings_count} findings"

        # Minimal Shields.io-compatible badge SVG
        svg = (
            f'<svg xmlns="http://www.w3.org/2000/svg" width="150" height="20">'
            f'<rect width="80" height="20" fill="#555"/>'
            f'<rect x="80" width="70" height="20" fill="{color}"/>'
            f'<text x="40" y="14" fill="#fff" font-family="Verdana" font-size="11"'
            f' text-anchor="middle">security</text>'
            f'<text x="115" y="14" fill="#fff" font-family="Verdana" font-size="11"'
            f' text-anchor="middle">{label}</text>'
            f'</svg>'
        )

        return {
            "action": action.value,
            "label": label,
            "message": message,
            "color": color,
            "svg": svg,
            "repo": scan_result.repo,
            "branch": scan_result.branch,
        }

    def close(self) -> None:
        """Close the underlying SQLite connection."""
        self._conn.close()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _action_weight(action: PolicyAction) -> int:
    return {"pass": 0, "warn": 1, "block": 2}[action.value]
