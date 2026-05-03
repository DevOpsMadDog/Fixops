"""ALDECI GitHub REST v3 API Router.

Direct pass-through to the **GitHub REST v3 API** (api.github.com or a
GitHub Enterprise Server installation).

Distinct from the existing GitHub-related routers:
  * ``github_security_router``   — Advanced Security ingestion + Brain Pipeline
  * ``github_app_router``        — GitHub App webhook handler
  * ``github_app_autofix_router`` — auto-fix PR submitter
  * ``github_issues_router``     — issue auto-creation flow

This router is the *generic* REST v3 pass-through used by personas and
analytics that need raw GitHub data.

Endpoints (mounted at ``/api/v1/github-api``)
---------------------------------------------
GET  /                                                              — capability summary
GET  /user/repos                                                    — list authenticated user's repos
GET  /repos/{owner}/{repo}                                          — single repo
GET  /repos/{owner}/{repo}/pulls                                    — list pull requests
GET  /repos/{owner}/{repo}/security-advisories                      — repo security advisories
GET  /repos/{owner}/{repo}/dependabot/alerts                        — Dependabot alerts
GET  /repos/{owner}/{repo}/code-scanning/alerts                     — code-scanning alerts
GET  /search/repositories                                           — repo search
GET  /search/code                                                   — code search

When ``GITHUB_TOKEN`` is unset the capability summary reports
``status="unavailable"`` and lookup endpoints respond with HTTP 503.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/github-api",
    tags=["github-api"],
)


# ---------------------------------------------------------------------------
# Lazy engine accessor (test seam)
# ---------------------------------------------------------------------------


def _get_engine():
    from core.github_api_engine import get_github_api_engine
    return get_github_api_engine()


# ---------------------------------------------------------------------------
# Pydantic models — extra="allow" so future GitHub fields don't break us
# ---------------------------------------------------------------------------


class CapabilitySummary(BaseModel):
    service: str
    endpoints: List[str]
    github_token_present: bool
    base_url: str
    status: str = Field(..., description="ok | empty | unavailable")


class _GHModel(BaseModel):
    model_config = ConfigDict(extra="allow")


class RepoOwner(_GHModel):
    login: Optional[str] = None
    id: Optional[int] = None
    type: Optional[str] = None


class RepoLicense(_GHModel):
    key: Optional[str] = None
    name: Optional[str] = None
    spdx_id: Optional[str] = None
    url: Optional[str] = None


class Repo(_GHModel):
    id: Optional[int] = None
    name: Optional[str] = None
    full_name: Optional[str] = None
    private: Optional[bool] = None
    owner: Optional[RepoOwner] = None
    html_url: Optional[str] = None
    description: Optional[str] = None
    fork: Optional[bool] = None
    url: Optional[str] = None
    default_branch: Optional[str] = None
    archived: Optional[bool] = None
    disabled: Optional[bool] = None
    pushed_at: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    language: Optional[str] = None
    forks_count: Optional[int] = None
    stargazers_count: Optional[int] = None
    watchers_count: Optional[int] = None
    open_issues_count: Optional[int] = None
    license: Optional[RepoLicense] = None
    topics: List[str] = []


class PRUser(_GHModel):
    login: Optional[str] = None


class PRRefRepo(_GHModel):
    pass


class PRRef(_GHModel):
    ref: Optional[str] = None
    sha: Optional[str] = None
    repo: Optional[PRRefRepo] = None


class PRLabel(_GHModel):
    name: Optional[str] = None
    color: Optional[str] = None
    description: Optional[str] = None


class PullRequest(_GHModel):
    id: Optional[int] = None
    number: Optional[int] = None
    state: Optional[str] = None
    title: Optional[str] = None
    body: Optional[str] = None
    user: Optional[PRUser] = None
    head: Optional[PRRef] = None
    base: Optional[PRRef] = None
    draft: Optional[bool] = None
    merged: Optional[bool] = None
    merged_at: Optional[str] = None
    merged_by: Optional[PRUser] = None
    mergeable: Optional[bool] = None
    mergeable_state: Optional[str] = None
    comments: Optional[int] = None
    review_comments: Optional[int] = None
    commits: Optional[int] = None
    additions: Optional[int] = None
    deletions: Optional[int] = None
    changed_files: Optional[int] = None
    labels: List[PRLabel] = []


class CVSS(_GHModel):
    score: Optional[float] = None
    vector_string: Optional[str] = None


class CWE(_GHModel):
    cwe_id: Optional[str] = None
    name: Optional[str] = None


class Identifier(_GHModel):
    type: Optional[str] = None
    value: Optional[str] = None


class SecurityAdvisory(_GHModel):
    ghsa_id: Optional[str] = None
    summary: Optional[str] = None
    severity: Optional[str] = None
    cve_id: Optional[str] = None
    cvss: Optional[CVSS] = None
    cwes: List[CWE] = []
    identifiers: List[Identifier] = []
    references: List[Dict[str, Any]] = []
    state: Optional[str] = None
    published_at: Optional[str] = None
    updated_at: Optional[str] = None


class DependabotPackage(_GHModel):
    ecosystem: Optional[str] = None
    name: Optional[str] = None


class DependabotDependency(_GHModel):
    package: Optional[DependabotPackage] = None
    manifest_path: Optional[str] = None
    scope: Optional[str] = None


class DependabotSecurityAdvisory(_GHModel):
    ghsa_id: Optional[str] = None
    cve_id: Optional[str] = None
    summary: Optional[str] = None
    severity: Optional[str] = None
    cwes: List[CWE] = []
    references: List[Dict[str, Any]] = []


class DependabotPatched(_GHModel):
    identifier: Optional[str] = None


class DependabotSecurityVulnerability(_GHModel):
    package: Optional[DependabotPackage] = None
    severity: Optional[str] = None
    vulnerable_version_range: Optional[str] = None
    first_patched_version: Optional[DependabotPatched] = None


class DependabotDismisser(_GHModel):
    login: Optional[str] = None


class DependabotAlert(_GHModel):
    number: Optional[int] = None
    state: Optional[str] = None
    dependency: Optional[DependabotDependency] = None
    security_advisory: Optional[DependabotSecurityAdvisory] = None
    security_vulnerability: Optional[DependabotSecurityVulnerability] = None
    url: Optional[str] = None
    html_url: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    dismissed_at: Optional[str] = None
    dismissed_by: Optional[DependabotDismisser] = None
    dismissed_reason: Optional[str] = None
    fixed_at: Optional[str] = None


class CodeScanRule(_GHModel):
    id: Optional[str] = None
    severity: Optional[str] = None
    description: Optional[str] = None
    name: Optional[str] = None
    tags: List[str] = []
    full_description: Optional[str] = None
    security_severity_level: Optional[str] = None


class CodeScanTool(_GHModel):
    name: Optional[str] = None
    guid: Optional[str] = None
    version: Optional[str] = None


class CodeScanLocation(_GHModel):
    path: Optional[str] = None
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    start_column: Optional[int] = None
    end_column: Optional[int] = None


class CodeScanInstance(_GHModel):
    ref: Optional[str] = None
    analysis_key: Optional[str] = None
    environment: Optional[str] = None
    state: Optional[str] = None
    commit_sha: Optional[str] = None
    message: Optional[Dict[str, Any]] = None
    location: Optional[CodeScanLocation] = None
    html_url: Optional[str] = None
    classifications: List[str] = []


class CodeScanDismisser(_GHModel):
    login: Optional[str] = None


class CodeScanAlert(_GHModel):
    number: Optional[int] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    url: Optional[str] = None
    html_url: Optional[str] = None
    state: Optional[str] = None
    dismissed_by: Optional[CodeScanDismisser] = None
    dismissed_at: Optional[str] = None
    dismissed_reason: Optional[str] = None
    dismissed_comment: Optional[str] = None
    rule: Optional[CodeScanRule] = None
    tool: Optional[CodeScanTool] = None
    most_recent_instance: Optional[CodeScanInstance] = None
    instances_url: Optional[str] = None


class RepoSearchResult(_GHModel):
    total_count: int = 0
    incomplete_results: bool = False
    items: List[Repo] = []


class CodeSearchRepoSummary(_GHModel):
    pass


class CodeSearchItem(_GHModel):
    name: Optional[str] = None
    path: Optional[str] = None
    sha: Optional[str] = None
    url: Optional[str] = None
    git_url: Optional[str] = None
    html_url: Optional[str] = None
    repository: Optional[CodeSearchRepoSummary] = None


class CodeSearchResult(_GHModel):
    total_count: int = 0
    incomplete_results: bool = False
    items: List[CodeSearchItem] = []


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _raise_unavailable() -> None:
    raise HTTPException(
        status_code=503,
        detail={
            "error": "github_api_unavailable",
            "message": "GITHUB_TOKEN environment variable is not configured",
        },
    )


def _map_github_error(exc: Exception) -> HTTPException:
    """Translate a GitHubAPIHTTPError (or unavailable) into an HTTPException."""
    from core.github_api_engine import GitHubAPIHTTPError, GitHubAPIUnavailable

    if isinstance(exc, GitHubAPIUnavailable):
        return HTTPException(
            status_code=503,
            detail={
                "error": "github_api_unavailable",
                "message": str(exc),
            },
        )
    if isinstance(exc, GitHubAPIHTTPError):
        passthrough = {400, 401, 403, 404, 409, 422, 429}
        status = exc.status_code if exc.status_code in passthrough else 502
        return HTTPException(
            status_code=status,
            detail={
                "error": "github_api_upstream_error",
                "upstream_status": exc.status_code,
                "message": str(exc),
                "payload": exc.payload,
            },
        )
    return HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/",
    response_model=CapabilitySummary,
    summary="GitHub REST v3 capability summary",
)
def capability_summary() -> CapabilitySummary:
    """Return service identity, exposed endpoints, configured base URL,
    token-present flag, and overall status (ok | empty | unavailable)."""
    engine = _get_engine()
    return CapabilitySummary(**engine.capability_summary())


@router.get(
    "/user/repos",
    response_model=List[Repo],
    summary="List repositories for the authenticated user",
)
def list_user_repos(
    affiliation: Optional[str] = Query(
        None, description="Comma-separated: owner,collaborator,organization_member"
    ),
    visibility: Optional[str] = Query(
        None, description="all | public | private"
    ),
    sort: Optional[str] = Query(
        None, description="created | updated | pushed | full_name"
    ),
    direction: Optional[str] = Query(None, description="asc | desc"),
    per_page: Optional[int] = Query(None, ge=1, le=100),
    page: Optional[int] = Query(None, ge=1),
) -> List[Repo]:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        body = engine.list_user_repos(
            affiliation=affiliation,
            visibility=visibility,
            sort=sort,
            direction=direction,
            per_page=per_page,
            page=page,
        )
    except Exception as exc:
        raise _map_github_error(exc) from exc
    return [Repo(**item) for item in body if isinstance(item, dict)]


@router.get(
    "/repos/{owner}/{repo}",
    response_model=Repo,
    summary="Get a single repository by owner + name",
)
def get_repo(owner: str, repo: str) -> Repo:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        body = engine.get_repo(owner, repo)
    except Exception as exc:
        raise _map_github_error(exc) from exc
    return Repo(**body)


@router.get(
    "/repos/{owner}/{repo}/pulls",
    response_model=List[PullRequest],
    summary="List pull requests for a repository",
)
def list_pulls(
    owner: str,
    repo: str,
    state: Optional[str] = Query(None, description="open | closed | all"),
    head: Optional[str] = Query(None, description="user:branch"),
    base: Optional[str] = Query(None, description="branch name"),
    sort: Optional[str] = Query(
        None, description="created | updated | popularity | long-running"
    ),
    direction: Optional[str] = Query(None, description="asc | desc"),
    per_page: Optional[int] = Query(None, ge=1, le=100),
    page: Optional[int] = Query(None, ge=1),
) -> List[PullRequest]:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        body = engine.list_pulls(
            owner,
            repo,
            state=state,
            head=head,
            base=base,
            sort=sort,
            direction=direction,
            per_page=per_page,
            page=page,
        )
    except Exception as exc:
        raise _map_github_error(exc) from exc
    return [PullRequest(**item) for item in body if isinstance(item, dict)]


@router.get(
    "/repos/{owner}/{repo}/security-advisories",
    response_model=List[SecurityAdvisory],
    summary="List repository security advisories",
)
def list_security_advisories(
    owner: str,
    repo: str,
    state: Optional[str] = Query(
        None, description="published | withdrawn | triage | draft | closed"
    ),
) -> List[SecurityAdvisory]:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        body = engine.list_security_advisories(owner, repo, state=state)
    except Exception as exc:
        raise _map_github_error(exc) from exc
    return [SecurityAdvisory(**item) for item in body if isinstance(item, dict)]


@router.get(
    "/repos/{owner}/{repo}/dependabot/alerts",
    response_model=List[DependabotAlert],
    summary="List Dependabot alerts for a repository",
)
def list_dependabot_alerts(
    owner: str,
    repo: str,
    state: Optional[str] = Query(
        None, description="auto_dismissed | dismissed | fixed | open"
    ),
    severity: Optional[str] = Query(
        None, description="critical | high | medium | low"
    ),
) -> List[DependabotAlert]:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        body = engine.list_dependabot_alerts(
            owner, repo, state=state, severity=severity
        )
    except Exception as exc:
        raise _map_github_error(exc) from exc
    return [DependabotAlert(**item) for item in body if isinstance(item, dict)]


@router.get(
    "/repos/{owner}/{repo}/code-scanning/alerts",
    response_model=List[CodeScanAlert],
    summary="List code-scanning alerts for a repository",
)
def list_code_scanning_alerts(
    owner: str,
    repo: str,
    state: Optional[str] = Query(
        None, description="open | closed | fixed | dismissed"
    ),
    severity: Optional[str] = Query(
        None,
        description="critical | high | medium | low | warning | note | error",
    ),
    tool_name: Optional[str] = Query(None, description="Tool name filter"),
) -> List[CodeScanAlert]:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        body = engine.list_code_scanning_alerts(
            owner,
            repo,
            state=state,
            severity=severity,
            tool_name=tool_name,
        )
    except Exception as exc:
        raise _map_github_error(exc) from exc
    return [CodeScanAlert(**item) for item in body if isinstance(item, dict)]


@router.get(
    "/search/repositories",
    response_model=RepoSearchResult,
    summary="Search public repositories",
)
def search_repositories(
    q: str = Query(..., description="GitHub search query string"),
    sort: Optional[str] = Query(
        None, description="stars | forks | help-wanted-issues | updated"
    ),
    order: Optional[str] = Query(None, description="asc | desc"),
    per_page: Optional[int] = Query(None, ge=1, le=100),
) -> RepoSearchResult:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        body = engine.search_repositories(
            q, sort=sort, order=order, per_page=per_page
        )
    except Exception as exc:
        raise _map_github_error(exc) from exc
    return RepoSearchResult(
        total_count=int(body.get("total_count", 0) or 0),
        incomplete_results=bool(body.get("incomplete_results", False)),
        items=[
            Repo(**item)
            for item in body.get("items", [])
            if isinstance(item, dict)
        ],
    )


@router.get(
    "/search/code",
    response_model=CodeSearchResult,
    summary="Search code across repositories",
)
def search_code(
    q: str = Query(..., description="GitHub code search query string"),
    sort: Optional[str] = Query(None, description="indexed"),
    order: Optional[str] = Query(None, description="asc | desc"),
    per_page: Optional[int] = Query(None, ge=1, le=100),
) -> CodeSearchResult:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        body = engine.search_code(
            q, sort=sort, order=order, per_page=per_page
        )
    except Exception as exc:
        raise _map_github_error(exc) from exc
    return CodeSearchResult(
        total_count=int(body.get("total_count", 0) or 0),
        incomplete_results=bool(body.get("incomplete_results", False)),
        items=[
            CodeSearchItem(**item)
            for item in body.get("items", [])
            if isinstance(item, dict)
        ],
    )
