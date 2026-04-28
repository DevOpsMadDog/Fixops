"""
Changelog Auto-Generator — ALDECI Beast Mode.

Parses git commits (conventional + beast-mode format) and generates
formatted changelogs with semantic versioning support.

Supported formats:
- Conventional commits: feat(scope): description
- Beast Mode commits: beast-mode(type): description

Output formats: MARKDOWN, JSON, HTML

Compliance: supports release management traceability for SOC2 CC8.1
"""

from __future__ import annotations

import json
import logging
import re
import subprocess  # nosec B404
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)


# ============================================================================
# ENUMS
# ============================================================================


class ChangeType(Enum):
    """Semantic categories for changelog entries."""

    FEATURE = "feature"
    FIX = "fix"
    DOCS = "docs"
    REFACTOR = "refactor"
    TEST = "test"
    SECURITY = "security"
    PERFORMANCE = "performance"
    BREAKING = "breaking"
    OTHER = "other"


class OutputFormat(Enum):
    """Supported changelog output formats."""

    MARKDOWN = "markdown"
    JSON = "json"
    HTML = "html"


# ============================================================================
# MODELS
# ============================================================================


class ChangeEntry(BaseModel):
    """A single changelog entry parsed from a git commit."""

    type: ChangeType
    description: str
    commit_sha: str = ""
    author: str = ""
    date: str = ""
    scope: Optional[str] = None
    breaking: bool = False


class ChangelogVersion(BaseModel):
    """A versioned group of changelog entries."""

    version: str
    date: str = Field(default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%d"))
    entries: List[ChangeEntry] = Field(default_factory=list)
    summary: str = ""


# ============================================================================
# MAPPING TABLES
# ============================================================================

# Conventional commit type → ChangeType
_CONVENTIONAL_MAP: Dict[str, ChangeType] = {
    "feat": ChangeType.FEATURE,
    "feature": ChangeType.FEATURE,
    "fix": ChangeType.FIX,
    "bugfix": ChangeType.FIX,
    "hotfix": ChangeType.FIX,
    "docs": ChangeType.DOCS,
    "doc": ChangeType.DOCS,
    "refactor": ChangeType.REFACTOR,
    "refact": ChangeType.REFACTOR,
    "test": ChangeType.TEST,
    "tests": ChangeType.TEST,
    "security": ChangeType.SECURITY,
    "sec": ChangeType.SECURITY,
    "perf": ChangeType.PERFORMANCE,
    "performance": ChangeType.PERFORMANCE,
    "breaking": ChangeType.BREAKING,
    "chore": ChangeType.OTHER,
    "style": ChangeType.OTHER,
    "ci": ChangeType.OTHER,
    "build": ChangeType.OTHER,
    "revert": ChangeType.FIX,
}

# Beast Mode type keywords → ChangeType
_BEAST_MODE_MAP: Dict[str, ChangeType] = {
    "feat": ChangeType.FEATURE,
    "feature": ChangeType.FEATURE,
    "fix": ChangeType.FIX,
    "bugfix": ChangeType.FIX,
    "docs": ChangeType.DOCS,
    "doc": ChangeType.DOCS,
    "refactor": ChangeType.REFACTOR,
    "test": ChangeType.TEST,
    "tests": ChangeType.TEST,
    "security": ChangeType.SECURITY,
    "perf": ChangeType.PERFORMANCE,
    "performance": ChangeType.PERFORMANCE,
    "breaking": ChangeType.BREAKING,
    "docker": ChangeType.FEATURE,
    "dashboard": ChangeType.FEATURE,
    "trustgraph": ChangeType.FEATURE,
    "pipeline": ChangeType.FEATURE,
    "connector": ChangeType.FEATURE,
    "api": ChangeType.FEATURE,
    "ui": ChangeType.FEATURE,
    "wip": ChangeType.OTHER,
    "status": ChangeType.OTHER,
    "chore": ChangeType.OTHER,
}

# Human-readable section headings
_SECTION_HEADINGS: Dict[ChangeType, str] = {
    ChangeType.BREAKING: "Breaking Changes",
    ChangeType.FEATURE: "New Features",
    ChangeType.FIX: "Bug Fixes",
    ChangeType.SECURITY: "Security",
    ChangeType.PERFORMANCE: "Performance",
    ChangeType.REFACTOR: "Refactoring",
    ChangeType.DOCS: "Documentation",
    ChangeType.TEST: "Tests",
    ChangeType.OTHER: "Other Changes",
}

# Section display order (most important first)
_SECTION_ORDER: List[ChangeType] = [
    ChangeType.BREAKING,
    ChangeType.FEATURE,
    ChangeType.FIX,
    ChangeType.SECURITY,
    ChangeType.PERFORMANCE,
    ChangeType.REFACTOR,
    ChangeType.DOCS,
    ChangeType.TEST,
    ChangeType.OTHER,
]

# Regex patterns
_CONVENTIONAL_RE = re.compile(
    r"^(?P<type>[a-z]+)(?:\((?P<scope>[^)]+)\))?(?P<breaking>!)?\s*:\s*(?P<desc>.+)$",
    re.IGNORECASE,
)
_BEAST_MODE_RE = re.compile(
    r"^beast-mode\((?P<type>[^)]+)\)\s*:\s*(?P<desc>.+)$",
    re.IGNORECASE,
)
# Commit log line: SHA<TAB>author<TAB>date<TAB>message
_GIT_LOG_RE = re.compile(
    r"^(?P<sha>[0-9a-zA-Z]{7,40})\t(?P<author>[^\t]*)\t(?P<date>[^\t]*)\t(?P<msg>.+)$"
)


# ============================================================================
# MAIN CLASS
# ============================================================================


class ChangelogGenerator:
    """
    Parses git commits and generates structured changelogs.

    Supports:
    - Conventional commit format (feat, fix, docs, ...)
    - Beast Mode format (beast-mode(type): description)
    - Semantic version suggestion (major / minor / patch)
    - Markdown, JSON, and HTML output
    """

    def __init__(self, repo_path: str = ".") -> None:
        self.repo_path = repo_path

    # ------------------------------------------------------------------
    # Parsing
    # ------------------------------------------------------------------

    def _parse_conventional_commit(self, message: str) -> Optional[ChangeEntry]:
        """Parse a conventional commit message into a ChangeEntry."""
        line = message.strip().splitlines()[0] if message.strip() else ""
        m = _CONVENTIONAL_RE.match(line)
        if not m:
            return None
        raw_type = m.group("type").lower()
        change_type = _CONVENTIONAL_MAP.get(raw_type)
        if change_type is None:
            return None
        breaking = bool(m.group("breaking")) or "BREAKING CHANGE" in message
        if breaking:
            change_type = ChangeType.BREAKING
        return ChangeEntry(
            type=change_type,
            description=m.group("desc").strip(),
            scope=m.group("scope"),
            breaking=breaking,
        )

    def _parse_beast_mode_commit(self, message: str) -> Optional[ChangeEntry]:
        """Parse a beast-mode commit message into a ChangeEntry."""
        line = message.strip().splitlines()[0] if message.strip() else ""
        m = _BEAST_MODE_RE.match(line)
        if not m:
            return None
        raw_type = m.group("type").lower()
        change_type = _BEAST_MODE_MAP.get(raw_type, ChangeType.OTHER)
        return ChangeEntry(
            type=change_type,
            description=m.group("desc").strip(),
            scope=raw_type,
            breaking=False,
        )

    def _parse_single_line(
        self, sha: str, author: str, date: str, message: str
    ) -> Optional[ChangeEntry]:
        """Try beast-mode first, then conventional, then skip."""
        entry = self._parse_beast_mode_commit(message)
        if entry is None:
            entry = self._parse_conventional_commit(message)
        if entry is not None:
            entry.commit_sha = sha
            entry.author = author
            entry.date = date
        return entry

    def parse_commits(self, commits_text: str) -> List[ChangeEntry]:
        """
        Parse a block of commit log text into ChangeEntry objects.

        Accepts two formats:
        1. Tabular: ``<sha>\\t<author>\\t<date>\\t<message>`` (one per line)
        2. Plain: one commit message per line (no metadata)
        """
        entries: List[ChangeEntry] = []
        for raw_line in commits_text.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            tab_m = _GIT_LOG_RE.match(line)
            if tab_m:
                entry = self._parse_single_line(
                    sha=tab_m.group("sha"),
                    author=tab_m.group("author"),
                    date=tab_m.group("date"),
                    message=tab_m.group("msg"),
                )
            else:
                entry = self._parse_single_line("", "", "", line)
            if entry is not None:
                entries.append(entry)
        return entries

    # ------------------------------------------------------------------
    # Grouping
    # ------------------------------------------------------------------

    def group_by_type(self, entries: List[ChangeEntry]) -> Dict[ChangeType, List[ChangeEntry]]:
        """Group entries by ChangeType, preserving section order."""
        groups: Dict[ChangeType, List[ChangeEntry]] = {ct: [] for ct in _SECTION_ORDER}
        for entry in entries:
            groups.setdefault(entry.type, []).append(entry)
        # Remove empty sections
        return {k: v for k, v in groups.items() if v}

    # ------------------------------------------------------------------
    # Version suggestion
    # ------------------------------------------------------------------

    def suggest_version(self, entries: List[ChangeEntry], current_version: str = "0.0.0") -> str:
        """
        Suggest next semver based on change types.

        Rules:
        - Any BREAKING entry → major bump
        - Any FEATURE entry → minor bump
        - Otherwise → patch bump
        """
        parts = current_version.lstrip("v").split(".")
        try:
            major, minor, patch = int(parts[0]), int(parts[1]), int(parts[2])
        except (IndexError, ValueError):
            major, minor, patch = 0, 0, 0

        types = {e.type for e in entries}
        if ChangeType.BREAKING in types or any(e.breaking for e in entries):
            return f"{major + 1}.0.0"
        if ChangeType.FEATURE in types:
            return f"{major}.{minor + 1}.0"
        return f"{major}.{minor}.{patch + 1}"

    # ------------------------------------------------------------------
    # Output: Markdown
    # ------------------------------------------------------------------

    def generate_markdown(self, entries: List[ChangeEntry], version: str) -> str:
        """Render changelog as Markdown."""
        groups = self.group_by_type(entries)
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        lines: List[str] = [f"## [{version}] — {today}", ""]
        for change_type in _SECTION_ORDER:
            section = groups.get(change_type, [])
            if not section:
                continue
            heading = _SECTION_HEADINGS[change_type]
            lines.append(f"### {heading}")
            lines.append("")
            for entry in section:
                prefix = f"**[{entry.scope}]** " if entry.scope else ""
                breaking_tag = " _(breaking)_" if entry.breaking else ""
                sha_ref = f" ([`{entry.commit_sha[:7]}`])" if entry.commit_sha else ""
                lines.append(f"- {prefix}{entry.description}{breaking_tag}{sha_ref}")
            lines.append("")
        return "\n".join(lines).rstrip() + "\n"

    # ------------------------------------------------------------------
    # Output: JSON
    # ------------------------------------------------------------------

    def generate_json(self, entries: List[ChangeEntry], version: str) -> str:
        """Render changelog as JSON."""
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        groups = self.group_by_type(entries)
        payload: Dict[str, Any] = {
            "version": version,
            "date": today,
            "sections": {},
            "total_entries": len(entries),
        }
        for change_type in _SECTION_ORDER:
            section = groups.get(change_type, [])
            if not section:
                continue
            heading = _SECTION_HEADINGS[change_type]
            payload["sections"][heading] = [
                {
                    "description": e.description,
                    "scope": e.scope,
                    "breaking": e.breaking,
                    "commit_sha": e.commit_sha,
                    "author": e.author,
                    "date": e.date,
                }
                for e in section
            ]
        return json.dumps(payload, indent=2)

    # ------------------------------------------------------------------
    # Output: HTML
    # ------------------------------------------------------------------

    def generate_html(self, entries: List[ChangeEntry], version: str) -> str:
        """Render changelog as HTML."""
        groups = self.group_by_type(entries)
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        parts: List[str] = [
            "<!DOCTYPE html>",
            "<html lang='en'>",
            "<head><meta charset='UTF-8'>"
            f"<title>Changelog {version}</title></head>",
            "<body>",
            f"<h2>Changelog — {version} ({today})</h2>",
        ]
        for change_type in _SECTION_ORDER:
            section = groups.get(change_type, [])
            if not section:
                continue
            heading = _SECTION_HEADINGS[change_type]
            parts.append(f"<h3>{heading}</h3>")
            parts.append("<ul>")
            for entry in section:
                scope_html = f"<strong>[{entry.scope}]</strong> " if entry.scope else ""
                breaking_html = " <em>(breaking)</em>" if entry.breaking else ""
                sha_html = (
                    f" <code>{entry.commit_sha[:7]}</code>" if entry.commit_sha else ""
                )
                parts.append(
                    f"<li>{scope_html}{entry.description}{breaking_html}{sha_html}</li>"
                )
            parts.append("</ul>")
        parts += ["</body>", "</html>"]
        return "\n".join(parts) + "\n"

    # ------------------------------------------------------------------
    # Unified entry point
    # ------------------------------------------------------------------

    def generate_changelog(
        self,
        entries: List[ChangeEntry],
        version: str,
        format: OutputFormat = OutputFormat.MARKDOWN,
    ) -> str:
        """Generate changelog in the requested format."""
        if format == OutputFormat.MARKDOWN:
            return self.generate_markdown(entries, version)
        if format == OutputFormat.JSON:
            return self.generate_json(entries, version)
        if format == OutputFormat.HTML:
            return self.generate_html(entries, version)
        raise ValueError(f"Unknown output format: {format}")

    # ------------------------------------------------------------------
    # Release notes (concise)
    # ------------------------------------------------------------------

    def generate_release_notes(self, version: str, entries: List[ChangeEntry]) -> str:
        """Generate a concise release notes summary (Markdown)."""
        groups = self.group_by_type(entries)
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        lines: List[str] = [f"# Release {version} ({today})", ""]
        # Highlight breaking changes prominently
        breaking = groups.get(ChangeType.BREAKING, [])
        if breaking:
            lines.append("> **BREAKING CHANGES** — review before upgrading")
            lines.append("")
            for e in breaking:
                lines.append(f"- {e.description}")
            lines.append("")
        # Summary counts
        counts: List[str] = []
        for ct, label in [
            (ChangeType.FEATURE, "feature"),
            (ChangeType.FIX, "fix"),
            (ChangeType.SECURITY, "security update"),
        ]:
            n = len(groups.get(ct, []))
            if n:
                counts.append(f"{n} {label}{'s' if n > 1 else ''}")
        if counts:
            lines.append("This release includes " + ", ".join(counts) + ".")
            lines.append("")
        # Top highlights (first 5 features + fixes)
        highlights: List[ChangeEntry] = (
            groups.get(ChangeType.FEATURE, [])[:3]
            + groups.get(ChangeType.FIX, [])[:2]
            + groups.get(ChangeType.SECURITY, [])[:2]
        )
        if highlights:
            lines.append("## Highlights")
            lines.append("")
            for e in highlights:
                lines.append(f"- {e.description}")
            lines.append("")
        return "\n".join(lines).rstrip() + "\n"

    # ------------------------------------------------------------------
    # Git integration
    # ------------------------------------------------------------------

    def get_unreleased(self, since_tag: str = "") -> List[ChangeEntry]:
        """
        Return ChangeEntry list for commits since the given tag (or all commits
        if since_tag is empty or not found).

        Uses ``git log`` with a tabular format:
        ``%h\\t%an\\t%ci\\t%s``
        """
        fmt = "%h\t%an\t%ci\t%s"
        cmd: List[str]
        if since_tag:
            cmd = ["git", "log", f"{since_tag}..HEAD", f"--pretty=format:{fmt}"]
        else:
            cmd = ["git", "log", f"--pretty=format:{fmt}"]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=self.repo_path,
                timeout=15,
            )
            if result.returncode != 0:
                _logger.warning(
                    "git log failed",
                    returncode=result.returncode,
                    stderr=result.stderr,
                )
                return []
            return self.parse_commits(result.stdout)
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            _logger.warning("git log error", error=str(exc))
            return []
