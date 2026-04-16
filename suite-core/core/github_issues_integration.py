"""GitHub Issues Integration for ALDECI.

Real GitHub API integration using the authenticated `gh` CLI.
Creates, updates, syncs, and queries GitHub Issues as an ALM/ticketing
system for security findings.

All API calls use subprocess + `gh` CLI (already authenticated via
`gh auth login`). No mock data — real issues on DevOpsMadDog/Fixops.

Usage::

    from core.github_issues_integration import get_github_issues_client

    client = get_github_issues_client()
    issue = client.create_issue_from_finding(finding)
    metrics = client.get_metrics()

Environment variables:
    GITHUB_ISSUES_REPO     — owner/repo  (default: DevOpsMadDog/Fixops)
    GITHUB_ISSUES_ASSIGNEE — default assignee login (optional)
    GH_BIN                 — override path to the `gh` binary
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import sqlite3
import subprocess  # nosec B404
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DEFAULT_REPO = "DevOpsMadDog/Fixops"
_ALDECI_LABEL = "aldeci"

_SEVERITY_LABELS = {"critical", "high", "medium", "low", "informational"}
_TYPE_LABELS = {"sast", "dast", "sca", "iac", "secret", "cloud", "network"}

_ISSUE_TITLE_PREFIX = "[ALDECI-{severity}]"

# Labels that must exist in the repo before we can create issues with them.
# They are created lazily on first use.
_REQUIRED_LABELS: Dict[str, Dict[str, str]] = {
    # core tag
    "aldeci": {"color": "0075ca", "description": "Created by ALDECI security platform"},
    # severity
    "critical": {"color": "d73a4a", "description": "Critical severity finding"},
    "high": {"color": "e4e669", "description": "High severity finding"},
    "medium": {"color": "fbca04", "description": "Medium severity finding"},
    "low": {"color": "0e8a16", "description": "Low severity finding"},
    "informational": {"color": "cfd3d7", "description": "Informational finding"},
    # type
    "sast": {"color": "b60205", "description": "Static Application Security Testing"},
    "dast": {"color": "e4e669", "description": "Dynamic Application Security Testing"},
    "sca": {"color": "0075ca", "description": "Software Composition Analysis"},
    "iac": {"color": "bfd4f2", "description": "Infrastructure as Code"},
    "secret": {"color": "d93f0b", "description": "Exposed secret / credential"},
    "cloud": {"color": "1d76db", "description": "Cloud security misconfiguration"},
    "network": {"color": "006b75", "description": "Network / perimeter finding"},
}

# ---------------------------------------------------------------------------
# DB path (SQLite — tracks issue links + metrics)
# ---------------------------------------------------------------------------

_DB_DIR = Path(__file__).resolve().parent.parent / "data"
_DB_PATH = _DB_DIR / "github_issues.db"


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    """Minimal finding representation for issue creation."""

    finding_id: str
    title: str
    severity: str  # critical | high | medium | low | informational
    finding_type: str = "sast"  # sast | dast | sca | iac | secret | cloud | network
    description: str = ""
    cwe: Optional[str] = None          # e.g. "CWE-79"
    cvss: Optional[float] = None       # e.g. 9.8
    affected_file: Optional[str] = None
    affected_line: Optional[int] = None
    remediation: Optional[str] = None
    scanner: Optional[str] = None
    cve_id: Optional[str] = None
    status: str = "open"               # open | resolved | in_progress | accepted_risk
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GitHubIssue:
    """GitHub issue as returned by `gh issue list/view`."""

    number: int
    title: str
    state: str          # open | closed
    url: str
    labels: List[str]
    assignees: List[str]
    created_at: str
    updated_at: str
    closed_at: Optional[str] = None
    body: Optional[str] = None


@dataclass
class IssueLink:
    """Maps a finding_id to a GitHub issue number."""

    finding_id: str
    issue_number: int
    repo: str
    created_at: str
    last_synced_at: str
    finding_status: str
    issue_state: str


@dataclass
class SyncResult:
    """Result of a single create/update/sync operation."""

    success: bool
    action: str          # created | updated | closed | reopened | skipped | error
    finding_id: str
    issue_number: Optional[int] = None
    issue_url: Optional[str] = None
    detail: str = ""
    error: Optional[str] = None


@dataclass
class IssueMetrics:
    """Aggregate metrics for ALDECI-created issues."""

    total_created: int = 0
    total_open: int = 0
    total_closed: int = 0
    avg_time_to_close_hours: float = 0.0
    by_severity: Dict[str, int] = field(default_factory=dict)
    by_type: Dict[str, int] = field(default_factory=dict)
    by_state: Dict[str, int] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# gh CLI wrapper
# ---------------------------------------------------------------------------


def _find_gh() -> str:
    """Return path to the `gh` binary. Raises RuntimeError if not found."""
    override = os.getenv("GH_BIN", "").strip()
    if override:
        return override

    # shutil.which searches $PATH
    found = shutil.which("gh")
    if found:
        return found

    # Common install locations not always on PATH
    candidates = [
        "/usr/local/bin/gh",
        "/opt/homebrew/bin/gh",
        "/home/linuxbrew/.linuxbrew/bin/gh",
        str(Path.home() / ".local" / "bin" / "gh"),
        str(Path.home() / "bin" / "gh"),
    ]
    for candidate in candidates:
        if Path(candidate).is_file():
            return candidate

    raise RuntimeError(
        "GitHub CLI (`gh`) not found. Install from https://cli.github.com/ "
        "and authenticate with `gh auth login`."
    )


def _run_gh(
    args: List[str],
    *,
    repo: Optional[str] = None,
    timeout: int = 30,
    input_text: Optional[str] = None,
) -> Tuple[bool, Any]:
    """Run a `gh` CLI command and return (success, parsed_json_or_text).

    Args:
        args: Command arguments after ``gh`` (e.g. ``["issue", "create", ...]``).
        repo: If provided, prepend ``--repo <repo>`` after the subcommand.
        timeout: Seconds before the subprocess is killed.
        input_text: Optional stdin content.

    Returns:
        ``(True, parsed)`` on success (parsed is dict/list/str).
        ``(False, error_str)`` on failure.
    """
    gh = _find_gh()

    # Insert --repo after the first subcommand group (e.g. "issue create")
    cmd: List[str] = [gh] + args
    if repo:
        # Find a good insertion point — after the noun (issue/pr/label/release)
        # gh <noun> <verb> --repo <repo> ...
        insert_at = min(3, len(cmd))
        cmd = cmd[:insert_at] + ["--repo", repo] + cmd[insert_at:]

    logger.debug("gh cmd: %s", " ".join(cmd))

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_text,
        )
    except subprocess.TimeoutExpired:
        return False, f"gh command timed out after {timeout}s"
    except FileNotFoundError as exc:
        return False, f"gh binary not found: {exc}"

    if result.returncode != 0:
        err = (result.stderr or result.stdout or "").strip()
        logger.warning("gh failed (rc=%d): %s", result.returncode, err)
        return False, err

    output = result.stdout.strip()
    if not output:
        return True, None

    # Try to parse as JSON
    try:
        return True, json.loads(output)
    except json.JSONDecodeError:
        return True, output


# ---------------------------------------------------------------------------
# SQLite store for issue links + event log
# ---------------------------------------------------------------------------


class _IssueStore:
    """Thread-safe SQLite store for issue links and sync events."""

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._lock = threading.Lock()
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._migrate()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _migrate(self) -> None:
        with self._lock, self._conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS issue_links (
                    finding_id      TEXT PRIMARY KEY,
                    issue_number    INTEGER NOT NULL,
                    repo            TEXT NOT NULL,
                    created_at      TEXT NOT NULL,
                    last_synced_at  TEXT NOT NULL,
                    finding_status  TEXT NOT NULL DEFAULT 'open',
                    issue_state     TEXT NOT NULL DEFAULT 'open'
                );

                CREATE TABLE IF NOT EXISTS sync_events (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    finding_id      TEXT NOT NULL,
                    issue_number    INTEGER,
                    action          TEXT NOT NULL,
                    success         INTEGER NOT NULL,
                    detail          TEXT,
                    error           TEXT,
                    occurred_at     TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS issue_metrics (
                    issue_number    INTEGER NOT NULL,
                    repo            TEXT NOT NULL,
                    severity        TEXT,
                    finding_type    TEXT,
                    created_at      TEXT NOT NULL,
                    closed_at       TEXT,
                    PRIMARY KEY (issue_number, repo)
                );
            """)

    # ── Link CRUD ─────────────────────────────────────────────────────────

    def upsert_link(
        self,
        finding_id: str,
        issue_number: int,
        repo: str,
        finding_status: str = "open",
        issue_state: str = "open",
    ) -> None:
        now = _utcnow()
        with self._lock, self._conn() as conn:
            conn.execute(
                """
                INSERT INTO issue_links
                    (finding_id, issue_number, repo, created_at, last_synced_at,
                     finding_status, issue_state)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(finding_id) DO UPDATE SET
                    last_synced_at = excluded.last_synced_at,
                    finding_status = excluded.finding_status,
                    issue_state    = excluded.issue_state
                """,
                (finding_id, issue_number, repo, now, now, finding_status, issue_state),
            )

    def get_link(self, finding_id: str) -> Optional[IssueLink]:
        with self._lock, self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM issue_links WHERE finding_id = ?", (finding_id,)
            ).fetchone()
        if row is None:
            return None
        return IssueLink(**dict(row))

    def get_all_links(self) -> List[IssueLink]:
        with self._lock, self._conn() as conn:
            rows = conn.execute("SELECT * FROM issue_links").fetchall()
        return [IssueLink(**dict(r)) for r in rows]

    # ── Event log ─────────────────────────────────────────────────────────

    def log_event(
        self,
        finding_id: str,
        action: str,
        success: bool,
        issue_number: Optional[int] = None,
        detail: str = "",
        error: Optional[str] = None,
    ) -> None:
        with self._lock, self._conn() as conn:
            conn.execute(
                """
                INSERT INTO sync_events
                    (finding_id, issue_number, action, success, detail, error, occurred_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (finding_id, issue_number, action, int(success), detail, error, _utcnow()),
            )

    # ── Metrics data ──────────────────────────────────────────────────────

    def upsert_metric(
        self,
        issue_number: int,
        repo: str,
        severity: str,
        finding_type: str,
        created_at: str,
        closed_at: Optional[str] = None,
    ) -> None:
        with self._lock, self._conn() as conn:
            conn.execute(
                """
                INSERT INTO issue_metrics
                    (issue_number, repo, severity, finding_type, created_at, closed_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(issue_number, repo) DO UPDATE SET
                    closed_at = excluded.closed_at
                """,
                (issue_number, repo, severity, finding_type, created_at, closed_at),
            )

    def get_metrics_raw(self, repo: str) -> List[sqlite3.Row]:
        with self._lock, self._conn() as conn:
            return conn.execute(
                "SELECT * FROM issue_metrics WHERE repo = ?", (repo,)
            ).fetchall()

    def count_events(self) -> int:
        with self._lock, self._conn() as conn:
            return conn.execute("SELECT COUNT(*) FROM sync_events").fetchone()[0]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_severity(sev: str) -> str:
    sev = sev.lower().strip()
    if sev in _SEVERITY_LABELS:
        return sev
    mapping = {
        "crit": "critical",
        "warn": "medium",
        "info": "informational",
        "none": "informational",
    }
    return mapping.get(sev, "low")


def _normalize_type(t: str) -> str:
    t = t.lower().strip()
    return t if t in _TYPE_LABELS else "sast"


def _build_issue_title(finding: Finding) -> str:
    sev = _normalize_severity(finding.severity).upper()
    return f"[ALDECI-{sev}] {finding.title}"


def _build_issue_body(finding: Finding) -> str:
    lines: List[str] = [
        "## ALDECI Security Finding",
        "",
        f"**Finding ID:** `{finding.finding_id}`",
        f"**Severity:** `{_normalize_severity(finding.severity).upper()}`",
        f"**Type:** `{_normalize_type(finding.finding_type).upper()}`",
        f"**Scanner:** `{finding.scanner or 'N/A'}`",
        f"**Status:** `{finding.status}`",
        "",
    ]

    if finding.description:
        lines += ["## Description", "", finding.description, ""]

    # Technical details table
    lines += ["## Technical Details", "", "| Field | Value |", "|---|---|"]
    if finding.cwe:
        lines.append(f"| CWE | [{finding.cwe}](https://cwe.mitre.org/data/definitions/{finding.cwe.replace('CWE-', '')}.html) |")
    if finding.cve_id:
        lines.append(f"| CVE | [{finding.cve_id}](https://nvd.nist.gov/vuln/detail/{finding.cve_id}) |")
    if finding.cvss is not None:
        lines.append(f"| CVSS Score | `{finding.cvss}` |")
    if finding.affected_file:
        loc = finding.affected_file
        if finding.affected_line:
            loc += f":{finding.affected_line}"
        lines.append(f"| Affected File | `{loc}` |")
    lines.append("")

    if finding.remediation:
        lines += ["## Remediation", "", finding.remediation, ""]

    if finding.extra:
        lines += ["## Additional Context", ""]
        for k, v in finding.extra.items():
            lines.append(f"- **{k}:** {v}")
        lines.append("")

    lines += [
        "---",
        f"*Created by ALDECI at {_utcnow()} · [Fixops Platform](https://github.com/DevOpsMadDog/Fixops)*",
    ]

    return "\n".join(lines)


def _parse_gh_issue(raw: Dict[str, Any]) -> GitHubIssue:
    """Parse a raw gh JSON issue dict into a GitHubIssue dataclass."""
    labels = [lbl.get("name", "") for lbl in raw.get("labels", [])]
    assignees = [a.get("login", "") for a in raw.get("assignees", [])]
    return GitHubIssue(
        number=raw["number"],
        title=raw.get("title", ""),
        state=raw.get("state", "open").lower(),
        url=raw.get("url", raw.get("html_url", "")),
        labels=labels,
        assignees=assignees,
        created_at=raw.get("createdAt", raw.get("created_at", "")),
        updated_at=raw.get("updatedAt", raw.get("updated_at", "")),
        closed_at=raw.get("closedAt", raw.get("closed_at")),
        body=raw.get("body"),
    )


# ---------------------------------------------------------------------------
# Main client
# ---------------------------------------------------------------------------


class GitHubIssuesClient:
    """GitHub Issues integration client.

    Uses the authenticated `gh` CLI for all API calls. Thread-safe.
    """

    def __init__(
        self,
        repo: Optional[str] = None,
        default_assignee: Optional[str] = None,
        db_path: Optional[Path] = None,
    ) -> None:
        self._repo = repo or os.getenv("GITHUB_ISSUES_REPO", _DEFAULT_REPO)
        self._assignee = default_assignee or os.getenv("GITHUB_ISSUES_ASSIGNEE", "")
        self._store = _IssueStore(db_path or _DB_PATH)
        self._labels_ensured: bool = False
        self._labels_lock = threading.Lock()

    # ── Label management ──────────────────────────────────────────────────

    def _ensure_labels(self) -> None:
        """Create required labels if they don't exist yet (lazy, once per process)."""
        with self._labels_lock:
            if self._labels_ensured:
                return
            self._labels_ensured = True  # set early to avoid thundering herd

        # Fetch existing labels
        ok, existing = _run_gh(
            ["label", "list", "--json", "name", "--limit", "100"],
            repo=self._repo,
        )
        if not ok or not isinstance(existing, list):
            logger.warning("Could not fetch existing labels: %s", existing)
            return

        existing_names = {item.get("name", "") for item in existing}

        for name, meta in _REQUIRED_LABELS.items():
            if name in existing_names:
                continue
            ok, _ = _run_gh(
                [
                    "label", "create", name,
                    "--color", meta["color"],
                    "--description", meta["description"],
                    "--force",
                ],
                repo=self._repo,
            )
            if ok:
                logger.info("Created GitHub label: %s", name)
            else:
                logger.warning("Failed to create label %s", name)

    # ── Create issue from finding ─────────────────────────────────────────

    def create_issue_from_finding(
        self,
        finding: Finding,
        *,
        assignee: Optional[str] = None,
        extra_labels: Optional[List[str]] = None,
    ) -> SyncResult:
        """Create a GitHub Issue from an ALDECI finding.

        Deduplicates: if an issue already exists for this finding_id,
        returns the existing link without creating a duplicate.

        Args:
            finding: The ALDECI finding to file.
            assignee: Override default assignee.
            extra_labels: Additional labels beyond severity + type.

        Returns:
            SyncResult with action "created" or "skipped" (already exists).
        """
        # Dedup check
        existing_link = self._store.get_link(finding.finding_id)
        if existing_link is not None:
            logger.info(
                "Issue already exists for finding %s → #%d",
                finding.finding_id,
                existing_link.issue_number,
            )
            return SyncResult(
                success=True,
                action="skipped",
                finding_id=finding.finding_id,
                issue_number=existing_link.issue_number,
                detail="Issue already exists — use update_issue() to add comments",
            )

        self._ensure_labels()

        sev = _normalize_severity(finding.severity)
        ftype = _normalize_type(finding.finding_type)
        title = _build_issue_title(finding)
        body = _build_issue_body(finding)

        labels = [_ALDECI_LABEL, sev, ftype]
        if extra_labels:
            labels.extend(extra_labels)
        labels_str = ",".join(dict.fromkeys(labels))  # dedup, preserve order

        cmd = [
            "issue", "create",
            "--title", title,
            "--body", body,
            "--label", labels_str,
        ]

        effective_assignee = assignee or self._assignee
        if effective_assignee:
            cmd += ["--assignee", effective_assignee]

        ok, result = _run_gh(cmd, repo=self._repo)

        if not ok:
            self._store.log_event(
                finding.finding_id, "create", False,
                error=str(result),
            )
            return SyncResult(
                success=False,
                action="error",
                finding_id=finding.finding_id,
                error=str(result),
            )

        # `gh issue create` returns the URL as plain text (or JSON with --json)
        issue_url = str(result).strip() if result else ""
        issue_number: Optional[int] = None

        # Extract number from URL: .../issues/123
        url_match = re.search(r"/issues/(\d+)", issue_url)
        if url_match:
            issue_number = int(url_match.group(1))

        self._store.upsert_link(
            finding.finding_id,
            issue_number or 0,
            self._repo,
            finding_status=finding.status,
            issue_state="open",
        )
        self._store.log_event(
            finding.finding_id, "created", True,
            issue_number=issue_number,
            detail=f"URL: {issue_url}",
        )
        # Record in metrics table
        if issue_number:
            self._store.upsert_metric(
                issue_number, self._repo, sev, ftype, _utcnow()
            )

        logger.info("Created GitHub issue #%s for finding %s", issue_number, finding.finding_id)
        return SyncResult(
            success=True,
            action="created",
            finding_id=finding.finding_id,
            issue_number=issue_number,
            issue_url=issue_url,
            detail=f"Created issue #{issue_number}",
        )

    # ── List issues ───────────────────────────────────────────────────────

    def list_issues(
        self,
        state: str = "open",
        limit: int = 50,
        label: Optional[str] = None,
    ) -> List[GitHubIssue]:
        """List ALDECI-created GitHub Issues.

        Args:
            state: "open", "closed", or "all".
            limit: Max number of issues to return.
            label: Filter by additional label (default: "aldeci").

        Returns:
            List of GitHubIssue objects.
        """
        filter_label = label or _ALDECI_LABEL
        ok, data = _run_gh(
            [
                "issue", "list",
                "--label", filter_label,
                "--state", state,
                "--limit", str(limit),
                "--json", "number,title,state,labels,assignees,createdAt,updatedAt,closedAt,url",
            ],
            repo=self._repo,
        )

        if not ok or not isinstance(data, list):
            logger.warning("Failed to list issues: %s", data)
            return []

        issues = []
        for raw in data:
            try:
                issues.append(_parse_gh_issue(raw))
            except (KeyError, TypeError) as exc:
                logger.warning("Failed to parse issue: %s — %s", raw, exc)

        return issues

    # ── Update issue (add comment) ────────────────────────────────────────

    def update_issue(
        self,
        finding_id: str,
        comment: str,
        *,
        issue_number: Optional[int] = None,
    ) -> SyncResult:
        """Add a comment to the GitHub issue linked to this finding.

        Args:
            finding_id: ALDECI finding identifier.
            comment: Markdown comment body.
            issue_number: Override — use if link is not stored locally.

        Returns:
            SyncResult with action "updated".
        """
        num = issue_number
        if num is None:
            link = self._store.get_link(finding_id)
            if link is None:
                return SyncResult(
                    success=False,
                    action="error",
                    finding_id=finding_id,
                    error="No issue link found for this finding_id. Create first.",
                )
            num = link.issue_number

        ok, result = _run_gh(
            ["issue", "comment", str(num), "--body", comment],
            repo=self._repo,
        )

        if not ok:
            self._store.log_event(finding_id, "comment", False, num, error=str(result))
            return SyncResult(
                success=False,
                action="error",
                finding_id=finding_id,
                issue_number=num,
                error=str(result),
            )

        self._store.log_event(finding_id, "updated", True, num, detail="Comment added")
        return SyncResult(
            success=True,
            action="updated",
            finding_id=finding_id,
            issue_number=num,
            detail="Comment added to issue",
        )

    # ── Search for existing issue (dedup) ─────────────────────────────────

    def search_issue(self, finding_title: str) -> Optional[GitHubIssue]:
        """Search GitHub Issues by finding title pattern to avoid duplicates.

        Args:
            finding_title: The finding title substring to search for.

        Returns:
            First matching GitHubIssue or None.
        """
        # Escape special chars for gh search
        safe_title = finding_title.replace('"', "'")[:100]
        ok, data = _run_gh(
            [
                "issue", "list",
                "--search", safe_title,
                "--label", _ALDECI_LABEL,
                "--state", "all",
                "--limit", "5",
                "--json", "number,title,state,labels,assignees,createdAt,updatedAt,closedAt,url",
            ],
            repo=self._repo,
        )

        if not ok or not isinstance(data, list) or not data:
            return None

        for raw in data:
            try:
                issue = _parse_gh_issue(raw)
                if finding_title.lower() in issue.title.lower():
                    return issue
            except (KeyError, TypeError):
                continue

        return None

    # ── Bidirectional sync ────────────────────────────────────────────────

    def sync_finding_to_github(self, finding: Finding) -> SyncResult:
        """Push finding status to GitHub — close or reopen issue as needed.

        - finding.status == "resolved" / "closed" / "fixed"  → close issue
        - finding.status == "open" / "in_progress"           → reopen issue
        - Otherwise: add a status comment.

        Args:
            finding: The ALDECI finding with current status.

        Returns:
            SyncResult describing what happened.
        """
        link = self._store.get_link(finding.finding_id)
        if link is None:
            # No issue yet — create one
            return self.create_issue_from_finding(finding)

        num = link.issue_number
        finding_status = finding.status.lower()

        if finding_status in ("resolved", "closed", "fixed", "wontfix"):
            # Close the issue
            ok, result = _run_gh(
                ["issue", "close", str(num), "--comment",
                 f"Closed by ALDECI: finding status changed to `{finding.status}`."],
                repo=self._repo,
            )
            action = "closed"
        elif finding_status in ("open", "in_progress", "reopened"):
            if link.issue_state == "open":
                # Already open — just add a comment
                return self.update_issue(
                    finding.finding_id,
                    f"Status updated to `{finding.status}` by ALDECI.",
                    issue_number=num,
                )
            ok, result = _run_gh(
                ["issue", "reopen", str(num), "--comment",
                 f"Reopened by ALDECI: finding status changed to `{finding.status}`."],
                repo=self._repo,
            )
            action = "reopened"
        else:
            # Unknown status — add comment
            return self.update_issue(
                finding.finding_id,
                f"Finding status changed to `{finding.status}` in ALDECI.",
                issue_number=num,
            )

        if not ok:
            self._store.log_event(finding.finding_id, action, False, num, error=str(result))
            return SyncResult(
                success=False,
                action="error",
                finding_id=finding.finding_id,
                issue_number=num,
                error=str(result),
            )

        new_state = "closed" if action == "closed" else "open"
        self._store.upsert_link(
            finding.finding_id, num, self._repo,
            finding_status=finding.status,
            issue_state=new_state,
        )
        self._store.log_event(finding.finding_id, action, True, num,
                              detail=f"Issue #{num} {action}")

        # Update metrics with closed_at if closing
        if action == "closed":
            self._store.upsert_metric(
                num, self._repo,
                _normalize_severity(finding.severity),
                _normalize_type(finding.finding_type),
                link.created_at,
                _utcnow(),
            )

        return SyncResult(
            success=True,
            action=action,
            finding_id=finding.finding_id,
            issue_number=num,
            detail=f"Issue #{num} {action}",
        )

    def sync_github_to_findings(self) -> List[Dict[str, Any]]:
        """Pull closed GitHub Issues and return findings to mark as resolved.

        Queries all ALDECI issues that are closed on GitHub, checks which ones
        are still "open" in local tracking, and returns a list of finding IDs
        that should be marked resolved.

        Returns:
            List of dicts: [{finding_id, issue_number, action}]
        """
        closed_issues = self.list_issues(state="closed", limit=200)
        closed_numbers = {issue.number: issue for issue in closed_issues}

        results: List[Dict[str, Any]] = []
        for link in self._store.get_all_links():
            if link.issue_state == "open" and link.issue_number in closed_numbers:
                # GitHub closed it — mark as resolved in ALDECI
                issue = closed_numbers[link.issue_number]
                self._store.upsert_link(
                    link.finding_id, link.issue_number, link.repo,
                    finding_status="resolved",
                    issue_state="closed",
                )
                self._store.log_event(
                    link.finding_id, "synced_from_github", True,
                    link.issue_number,
                    detail="Marked resolved because GitHub issue was closed",
                )
                results.append({
                    "finding_id": link.finding_id,
                    "issue_number": link.issue_number,
                    "action": "marked_resolved",
                    "closed_at": issue.closed_at,
                })

        return results

    # ── Bulk sync ─────────────────────────────────────────────────────────

    def sync_all_findings(
        self,
        findings: List[Finding],
        *,
        dry_run: bool = False,
    ) -> List[SyncResult]:
        """Sync a list of findings — create issues for new ones, update existing.

        Args:
            findings: List of ALDECI findings to sync.
            dry_run: If True, log what would happen without making API calls.

        Returns:
            List of SyncResult, one per finding.
        """
        results: List[SyncResult] = []
        for finding in findings:
            if dry_run:
                link = self._store.get_link(finding.finding_id)
                action = "would_create" if link is None else "would_update"
                results.append(SyncResult(
                    success=True,
                    action=action,
                    finding_id=finding.finding_id,
                    issue_number=link.issue_number if link else None,
                    detail="dry_run=True, no API call made",
                ))
                continue
            result = self.sync_finding_to_github(finding)
            results.append(result)
            # Respect GitHub's secondary rate limit: 1 issue creation per second
            time.sleep(0.5)

        return results

    # ── Metrics ───────────────────────────────────────────────────────────

    def get_metrics(self) -> IssueMetrics:
        """Compute aggregate metrics from stored data + live GitHub query.

        Returns:
            IssueMetrics dataclass.
        """
        rows = self._store.get_metrics_raw(self._repo)

        total = len(rows)
        open_count = 0
        closed_count = 0
        by_severity: Dict[str, int] = {}
        by_type: Dict[str, int] = {}
        close_durations: List[float] = []

        for row in rows:
            sev = row["severity"] or "unknown"
            ftype = row["finding_type"] or "unknown"
            by_severity[sev] = by_severity.get(sev, 0) + 1
            by_type[ftype] = by_type.get(ftype, 0) + 1

            if row["closed_at"]:
                closed_count += 1
                try:
                    created = datetime.fromisoformat(row["created_at"])
                    closed = datetime.fromisoformat(row["closed_at"])
                    duration_hours = (closed - created).total_seconds() / 3600
                    close_durations.append(duration_hours)
                except (ValueError, TypeError):
                    pass
            else:
                open_count += 1

        avg_close = sum(close_durations) / len(close_durations) if close_durations else 0.0

        return IssueMetrics(
            total_created=total,
            total_open=open_count,
            total_closed=closed_count,
            avg_time_to_close_hours=round(avg_close, 2),
            by_severity=by_severity,
            by_type=by_type,
            by_state={"open": open_count, "closed": closed_count},
        )

    # ── Convenience: check gh auth ────────────────────────────────────────

    def check_auth(self) -> Dict[str, Any]:
        """Check if gh CLI is available and authenticated.

        Returns:
            Dict with keys: available, authenticated, username, error.
        """
        try:
            gh_bin = _find_gh()
        except RuntimeError as exc:
            return {"available": False, "authenticated": False, "error": str(exc)}

        ok, result = _run_gh(["auth", "status"])
        if not ok:
            return {
                "available": True,
                "authenticated": False,
                "gh_bin": gh_bin,
                "error": str(result),
            }

        # Try to get username
        ok2, whoami = _run_gh(["api", "user", "--jq", ".login"])
        username = str(whoami).strip() if ok2 and whoami else "unknown"

        return {
            "available": True,
            "authenticated": True,
            "gh_bin": gh_bin,
            "username": username,
            "repo": self._repo,
        }


# ---------------------------------------------------------------------------
# Singleton factory
# ---------------------------------------------------------------------------

_client_instance: Optional[GitHubIssuesClient] = None
_client_lock = threading.Lock()


def get_github_issues_client() -> GitHubIssuesClient:
    """Return the process-level singleton GitHubIssuesClient."""
    global _client_instance
    if _client_instance is None:
        with _client_lock:
            if _client_instance is None:
                _client_instance = GitHubIssuesClient()
    return _client_instance
