"""
Changelog API endpoints — ALDECI Beast Mode.

Exposes changelog generation, version suggestion, and release notes
via REST API backed by ChangelogGenerator.

Endpoints:
  GET  /api/v1/changelog/recent          — last 50 commits grouped by scope
  POST /api/v1/changelog/generate        — generate from commit list
  GET  /api/v1/changelog/unreleased      — changes since last tag
  POST /api/v1/changelog/suggest-version — suggest next semver
  POST /api/v1/changelog/release-notes   — concise release notes
  GET  /api/v1/changelog/formats         — available output formats
"""

from __future__ import annotations

import subprocess
from typing import Any, Dict, List

from core.changelog_generator import (
    ChangeEntry,
    ChangelogGenerator,
    ChangeType,
    OutputFormat,
)
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/v1/changelog", tags=["changelog"])
_generator = ChangelogGenerator()


# ============================================================================
# REQUEST / RESPONSE MODELS
# ============================================================================


class GenerateRequest(BaseModel):
    """Request body for /generate."""

    commits: str = Field(
        ...,
        description=(
            "Raw commit log text. Each line may be plain commit messages or "
            "tabular format: <sha>\\t<author>\\t<date>\\t<message>"
        ),
    )
    version: str = Field("1.0.0", description="Version label for this changelog")
    format: OutputFormat = Field(OutputFormat.MARKDOWN, description="Output format")


class GenerateResponse(BaseModel):
    """Response for /generate."""

    version: str
    format: str
    content: str
    entry_count: int


class SuggestVersionRequest(BaseModel):
    """Request body for /suggest-version."""

    commits: str = Field(..., description="Raw commit log text")
    current_version: str = Field("0.0.0", description="Current semver string")


class SuggestVersionResponse(BaseModel):
    """Response for /suggest-version."""

    current_version: str
    suggested_version: str
    bump_type: str
    entry_count: int


class ReleaseNotesRequest(BaseModel):
    """Request body for /release-notes."""

    commits: str = Field(..., description="Raw commit log text")
    version: str = Field("1.0.0", description="Version label")


class ReleaseNotesResponse(BaseModel):
    """Response for /release-notes."""

    version: str
    notes: str


class UnreleasedResponse(BaseModel):
    """Response for /unreleased."""

    since_tag: str
    entry_count: int
    entries: List[Dict[str, Any]]
    suggested_version: str


class RecentCommitResponse(BaseModel):
    """Single commit in recent changelog."""

    sha: str = Field(..., description="Git commit SHA (7-char)")
    scope: str = Field(..., description="Scope (feat/fix/perf/ui/qa/etc)")
    message: str = Field(..., description="Commit message after scope")
    timestamp: str = Field(..., description="ISO 8601 timestamp")


class RecentChangelogResponse(BaseModel):
    """Response for /recent."""

    limit: int = Field(..., description="Number of commits fetched")
    total_count: int = Field(..., description="Total commits in repo")
    commits: List[RecentCommitResponse] = Field(..., description="Commits grouped by scope")
    scopes: Dict[str, int] = Field(..., description="Count by scope")


# ============================================================================
# HELPERS
# ============================================================================


def _detect_bump_type(entries: List[ChangeEntry]) -> str:
    """Return the semver bump type string for a list of entries."""
    types = {e.type for e in entries}
    if ChangeType.BREAKING in types or any(e.breaking for e in entries):
        return "major"
    if ChangeType.FEATURE in types:
        return "minor"
    return "patch"


def _entries_to_dicts(entries: List[ChangeEntry]) -> List[Dict[str, Any]]:
    return [
        {
            "type": e.type.value,
            "description": e.description,
            "commit_sha": e.commit_sha,
            "author": e.author,
            "date": e.date,
            "scope": e.scope,
            "breaking": e.breaking,
        }
        for e in entries
    ]


# ============================================================================
# ENDPOINTS
# ============================================================================


@router.get("/recent", response_model=RecentChangelogResponse, summary="Get recent commits grouped by scope")
def get_recent_changelog(limit: int = Query(50, ge=1, le=500, description="Max commits to fetch")) -> RecentChangelogResponse:
    """
    Fetch the last N commits from git log and group by scope.

    Parses beast-mode(<scope>): <msg> format and extracts scope + message.
    Returns commits in reverse chronological order (newest first).
    """
    try:
        # Get commit log with format: <hash>|<author>|<date>|<message>
        result = subprocess.run(
            ["git", "log", f"--max-count={limit}", "--format=%h|%an|%ai|%s"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            raise HTTPException(status_code=500, detail="Failed to fetch git log")

        lines = result.stdout.strip().split("\n")
        if not lines or lines[0] == "":
            return RecentChangelogResponse(limit=limit, total_count=0, commits=[], scopes={})

        commits_list: List[RecentCommitResponse] = []
        scope_counts: Dict[str, int] = {}

        for line in lines:
            if not line.strip():
                continue
            parts = line.split("|", 3)
            if len(parts) < 4:
                continue

            sha, author, timestamp, msg = parts
            # Extract scope from beast-mode(scope): msg or conventional scope: msg
            scope = "other"
            message = msg

            if msg.startswith("beast-mode(") and ")" in msg:
                # beast-mode(feat): msg → scope=feat, message=msg
                close_paren = msg.index(")")
                scope = msg[11:close_paren]  # Extract between ( and )
                message = msg[close_paren+2:].strip() if close_paren+2 < len(msg) else message
            elif ":" in msg:
                # conventional: feat: msg → scope=feat
                potential_scope = msg.split(":", 1)[0]
                if potential_scope and not " " in potential_scope and potential_scope.lower() in [
                    "feat", "fix", "perf", "ui", "qa", "refactor", "docs", "chore", "style", "test"
                ]:
                    scope = potential_scope.lower()
                    message = msg.split(":", 1)[1].strip()

            scope_counts[scope] = scope_counts.get(scope, 0) + 1
            commits_list.append(
                RecentCommitResponse(
                    sha=sha,
                    scope=scope,
                    message=message,
                    timestamp=timestamp,
                )
            )

        # Get total commit count
        count_result = subprocess.run(
            ["git", "rev-list", "--count", "HEAD"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        total_count = int(count_result.stdout.strip()) if count_result.returncode == 0 else len(commits_list)

        return RecentChangelogResponse(
            limit=limit,
            total_count=total_count,
            commits=commits_list,
            scopes=scope_counts,
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=500, detail="Git operation timed out")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching changelog: {str(e)}")


@router.post("/generate", response_model=GenerateResponse, summary="Generate changelog from commits")
def generate_changelog(body: GenerateRequest) -> GenerateResponse:
    """
    Parse the provided commit log text and return a formatted changelog.

    Accepts conventional commits (``feat:``, ``fix:``, ...) and beast-mode
    commits (``beast-mode(type): ...``).
    """
    entries = _generator.parse_commits(body.commits)
    if not entries:
        raise HTTPException(
            status_code=422,
            detail="No parseable commits found in the provided text.",
        )
    content = _generator.generate_changelog(entries, body.version, body.format)
    return GenerateResponse(
        version=body.version,
        format=body.format.value,
        content=content,
        entry_count=len(entries),
    )


@router.get("/unreleased", response_model=UnreleasedResponse, summary="Changes since last tag")
def get_unreleased(
    since_tag: str = Query(default="", description="Git tag to diff from (empty = all commits)"),
    current_version: str = Query(default="0.0.0", description="Current version for bump suggestion"),
) -> UnreleasedResponse:
    """
    Return all unreleased commits since the given tag, with a suggested
    next version based on change types.
    """
    entries = _generator.get_unreleased(since_tag=since_tag)
    suggested = _generator.suggest_version(entries, current_version)
    return UnreleasedResponse(
        since_tag=since_tag,
        entry_count=len(entries),
        entries=_entries_to_dicts(entries),
        suggested_version=suggested,
    )


@router.post("/suggest-version", response_model=SuggestVersionResponse, summary="Suggest next semver")
def suggest_version(body: SuggestVersionRequest) -> SuggestVersionResponse:
    """
    Parse commits and suggest the appropriate next semantic version.

    Rules:
    - Breaking change → major bump
    - New feature → minor bump
    - Bug fix / other → patch bump
    """
    entries = _generator.parse_commits(body.commits)
    suggested = _generator.suggest_version(entries, body.current_version)
    bump = _detect_bump_type(entries)
    return SuggestVersionResponse(
        current_version=body.current_version,
        suggested_version=suggested,
        bump_type=bump,
        entry_count=len(entries),
    )


@router.post("/release-notes", response_model=ReleaseNotesResponse, summary="Generate release notes")
def release_notes(body: ReleaseNotesRequest) -> ReleaseNotesResponse:
    """
    Generate concise, human-readable release notes from a commit list.

    The notes highlight breaking changes, summarise feature/fix counts,
    and list the top highlights.
    """
    entries = _generator.parse_commits(body.commits)
    if not entries:
        raise HTTPException(
            status_code=422,
            detail="No parseable commits found in the provided text.",
        )
    notes = _generator.generate_release_notes(body.version, entries)
    return ReleaseNotesResponse(version=body.version, notes=notes)


@router.get("/formats", summary="List available output formats")
def list_formats() -> Dict[str, Any]:
    """Return all supported changelog output formats."""
    return {
        "formats": [f.value for f in OutputFormat],
        "default": OutputFormat.MARKDOWN.value,
        "descriptions": {
            OutputFormat.MARKDOWN.value: "GitHub-flavoured Markdown",
            OutputFormat.JSON.value: "Structured JSON for programmatic use",
            OutputFormat.HTML.value: "Standalone HTML page",
        },
    }
