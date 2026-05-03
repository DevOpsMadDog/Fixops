"""Router-level HTTP tests for the generic GitHub REST v3 pass-through API.

Covers /api/v1/github-api/* via FastAPI TestClient with a stub httpx.Client
so no real GitHub call is made.

Tests:
1.  GET /                                              — capability summary (unavailable when env unset)
2.  GET /                                              — capability summary (ok when env set)
3.  GET /                                              — capability summary uses GHE base URL when GITHUB_API_URL set
4.  GET /user/repos                                    — Bearer token + Accept + API-version headers attached
5.  GET /user/repos                                    — query params (affiliation, visibility, sort, direction, per_page) forwarded
6.  GET /repos/{owner}/{repo}                          — single repo
7.  GET /repos/{owner}/{repo}/pulls                    — list PRs with state filter
8.  GET /repos/{owner}/{repo}/security-advisories      — list advisories
9.  GET /repos/{owner}/{repo}/dependabot/alerts        — list dependabot with severity
10. GET /repos/{owner}/{repo}/code-scanning/alerts     — list code-scanning with tool_name
11. GET /search/repositories                           — search wraps total_count + items
12. GET /search/code                                   — search code wraps total_count + items
13. lookup endpoint returns 503 when env unset
14. upstream 404 surfaces as 404 with payload echo
15. upstream 500 collapses to 502 Bad Gateway
16. monkeypatched env (GITHUB_TOKEN + GITHUB_API_URL) re-reads via reset_github_api_engine
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

# Ensure suite paths are importable regardless of cwd
for _p in ["suite-core", "suite-api"]:
    _abs = str(Path(__file__).parent.parent / _p)
    if _abs not in sys.path:
        sys.path.insert(0, _abs)

import apps.api.github_api_router as _router_mod
from apps.api.github_api_router import router
from core.github_api_engine import (
    GitHubAPIEngine,
    get_github_api_engine,
    reset_github_api_engine,
)


# ---------------------------------------------------------------------------
# Stub httpx.Client
# ---------------------------------------------------------------------------


class _StubResponse:
    def __init__(
        self,
        status_code: int,
        json_payload: Any = None,
        text: str = "",
        headers: Optional[Dict[str, str]] = None,
    ) -> None:
        self.status_code = status_code
        self._json = json_payload
        self.text = text
        self.headers = headers or {}
        if json_payload is not None:
            self.content = b"{}"
        elif text:
            self.content = text.encode("utf-8") if isinstance(text, str) else text
        else:
            self.content = b""

    def json(self) -> Any:
        if self._json is None:
            raise ValueError("no json")
        return self._json


class StubHTTPXClient:
    """Captures requests and returns scripted responses keyed by (method, path-suffix)."""

    def __init__(
        self,
        base: str = "https://api.github.com/",
        routes: Optional[Dict[str, _StubResponse]] = None,
    ) -> None:
        self.base = base
        self.routes: Dict[str, _StubResponse] = routes or {}
        self.calls: List[Dict[str, Any]] = []

    def set(self, method: str, suffix: str, response: _StubResponse) -> None:
        self.routes[f"{method.upper()} {suffix}"] = response

    def request(
        self,
        method: str,
        url: str,
        json: Any = None,  # noqa: A002 - mirror httpx signature
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        auth: Any = None,
    ) -> _StubResponse:
        suffix = url[len(self.base):] if url.startswith(self.base) else url
        key = f"{method.upper()} {suffix}"
        self.calls.append(
            {
                "method": method.upper(),
                "url": url,
                "suffix": suffix,
                "json": json,
                "params": params,
                "headers": headers,
                "auth": auth,
            }
        )
        if key in self.routes:
            return self.routes[key]
        return _StubResponse(200, {})

    def close(self) -> None:  # pragma: no cover
        pass


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_singleton():
    """Each test gets a fresh engine singleton."""
    reset_github_api_engine()
    yield
    reset_github_api_engine()


def _build_app(engine: GitHubAPIEngine) -> TestClient:
    """Mount the router with engine injection."""
    _router_mod._get_engine = lambda: engine  # type: ignore[attr-defined]
    app = FastAPI()
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=True)


@pytest.fixture
def stub() -> StubHTTPXClient:
    return StubHTTPXClient()


@pytest.fixture
def configured_engine(stub: StubHTTPXClient) -> GitHubAPIEngine:
    return GitHubAPIEngine(
        token="ghp_TESTONLY_xyz123",
        base_url="https://api.github.com",
        client=stub,  # type: ignore[arg-type]
    )


@pytest.fixture
def unavailable_engine() -> GitHubAPIEngine:
    return GitHubAPIEngine(token="", client=httpx.Client())


# ---------------------------------------------------------------------------
# 1. Capability summary — unavailable
# ---------------------------------------------------------------------------


def test_capability_summary_unavailable(unavailable_engine: GitHubAPIEngine) -> None:
    client = _build_app(unavailable_engine)
    resp = client.get("/api/v1/github-api/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["service"] == "GitHub REST v3"
    assert body["github_token_present"] is False
    assert body["status"] == "unavailable"
    assert body["base_url"] == "https://api.github.com"
    # All 8 documented endpoints surface in summary
    for ep in [
        "/user/repos",
        "/repos/{owner}/{repo}",
        "/repos/{owner}/{repo}/pulls",
        "/repos/{owner}/{repo}/security-advisories",
        "/repos/{owner}/{repo}/dependabot/alerts",
        "/repos/{owner}/{repo}/code-scanning/alerts",
        "/search/repositories",
        "/search/code",
    ]:
        assert ep in body["endpoints"]


# ---------------------------------------------------------------------------
# 2. Capability summary — ok when configured
# ---------------------------------------------------------------------------


def test_capability_summary_ok(configured_engine: GitHubAPIEngine) -> None:
    client = _build_app(configured_engine)
    resp = client.get("/api/v1/github-api/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["github_token_present"] is True
    assert body["status"] == "ok"


# ---------------------------------------------------------------------------
# 3. Capability summary — GitHub Enterprise base URL
# ---------------------------------------------------------------------------


def test_capability_summary_enterprise_base_url() -> None:
    engine = GitHubAPIEngine(
        token="ghp_ent",
        base_url="https://github.acme.io/api/v3",
        client=httpx.Client(),
    )
    client = _build_app(engine)
    resp = client.get("/api/v1/github-api/")
    assert resp.status_code == 200
    assert resp.json()["base_url"] == "https://github.acme.io/api/v3"


# ---------------------------------------------------------------------------
# 4. List user repos — Bearer + Accept + API-version headers
# ---------------------------------------------------------------------------


def test_list_user_repos_headers_attached(
    configured_engine: GitHubAPIEngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "GET",
        "user/repos",
        _StubResponse(
            200,
            [
                {
                    "id": 1296269,
                    "name": "Hello-World",
                    "full_name": "octocat/Hello-World",
                    "private": False,
                    "owner": {
                        "login": "octocat",
                        "id": 1,
                        "type": "User",
                    },
                    "html_url": "https://github.com/octocat/Hello-World",
                    "description": "This your first repo!",
                    "fork": False,
                    "url": "https://api.github.com/repos/octocat/Hello-World",
                    "default_branch": "main",
                    "archived": False,
                    "disabled": False,
                    "pushed_at": "2026-05-04T12:00:00Z",
                    "created_at": "2011-01-26T19:01:12Z",
                    "updated_at": "2026-05-04T12:00:00Z",
                    "language": "Python",
                    "forks_count": 9,
                    "stargazers_count": 80,
                    "watchers_count": 80,
                    "open_issues_count": 0,
                    "license": {
                        "key": "mit",
                        "name": "MIT License",
                        "spdx_id": "MIT",
                        "url": "https://api.github.com/licenses/mit",
                    },
                    "topics": ["aldeci", "fixops"],
                }
            ],
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get("/api/v1/github-api/user/repos")
    assert resp.status_code == 200
    body = resp.json()
    assert isinstance(body, list)
    assert len(body) == 1
    item = body[0]
    assert item["full_name"] == "octocat/Hello-World"
    assert item["owner"]["login"] == "octocat"
    assert item["license"]["spdx_id"] == "MIT"
    assert item["topics"] == ["aldeci", "fixops"]
    # Header assertions
    sent = stub.calls[0]["headers"]
    assert sent.get("Authorization") == "Bearer ghp_TESTONLY_xyz123"
    assert sent.get("Accept") == "application/vnd.github+json"
    assert sent.get("X-GitHub-Api-Version") == "2022-11-28"


# ---------------------------------------------------------------------------
# 5. List user repos — query params forwarded
# ---------------------------------------------------------------------------


def test_list_user_repos_forwards_query_params(
    configured_engine: GitHubAPIEngine, stub: StubHTTPXClient
) -> None:
    stub.set("GET", "user/repos", _StubResponse(200, []))
    client = _build_app(configured_engine)
    resp = client.get(
        "/api/v1/github-api/user/repos"
        "?affiliation=owner,collaborator,organization_member"
        "&visibility=all&sort=updated&direction=desc&per_page=50&page=2"
    )
    assert resp.status_code == 200
    sent = stub.calls[0]["params"]
    assert sent == {
        "affiliation": "owner,collaborator,organization_member",
        "visibility": "all",
        "sort": "updated",
        "direction": "desc",
        "per_page": 50,
        "page": 2,
    }


# ---------------------------------------------------------------------------
# 6. Single repo
# ---------------------------------------------------------------------------


def test_get_single_repo(
    configured_engine: GitHubAPIEngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "GET",
        "repos/octocat/Hello-World",
        _StubResponse(
            200,
            {
                "id": 1296269,
                "name": "Hello-World",
                "full_name": "octocat/Hello-World",
                "private": False,
                "owner": {"login": "octocat", "id": 1, "type": "User"},
                "default_branch": "main",
                "language": "Python",
                "stargazers_count": 80,
                "topics": [],
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get("/api/v1/github-api/repos/octocat/Hello-World")
    assert resp.status_code == 200
    body = resp.json()
    assert body["full_name"] == "octocat/Hello-World"
    assert body["default_branch"] == "main"
    assert body["language"] == "Python"


# ---------------------------------------------------------------------------
# 7. Pull requests with state filter
# ---------------------------------------------------------------------------


def test_list_pulls_state_filter(
    configured_engine: GitHubAPIEngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "GET",
        "repos/octocat/Hello-World/pulls",
        _StubResponse(
            200,
            [
                {
                    "id": 1,
                    "number": 1347,
                    "state": "open",
                    "title": "Amazing new feature",
                    "body": "Please pull these awesome changes in!",
                    "user": {"login": "octocat"},
                    "head": {
                        "ref": "feature/new-thing",
                        "sha": "6dcb09b5b57875f334f61aebed695e2e4193db5e",
                    },
                    "base": {
                        "ref": "main",
                        "sha": "0123456789abcdef0123456789abcdef01234567",
                    },
                    "draft": False,
                    "merged": False,
                    "mergeable": True,
                    "mergeable_state": "clean",
                    "comments": 10,
                    "review_comments": 0,
                    "commits": 3,
                    "additions": 100,
                    "deletions": 3,
                    "changed_files": 5,
                    "labels": [
                        {
                            "name": "bug",
                            "color": "d73a4a",
                            "description": "Something isn't working",
                        }
                    ],
                }
            ],
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get(
        "/api/v1/github-api/repos/octocat/Hello-World/pulls"
        "?state=open&base=main&sort=updated&direction=desc&per_page=10"
    )
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 1
    pr = body[0]
    assert pr["number"] == 1347
    assert pr["state"] == "open"
    assert pr["head"]["ref"] == "feature/new-thing"
    assert pr["labels"][0]["name"] == "bug"
    sent = stub.calls[0]["params"]
    assert sent == {
        "state": "open",
        "base": "main",
        "sort": "updated",
        "direction": "desc",
        "per_page": 10,
    }


# ---------------------------------------------------------------------------
# 8. Security advisories
# ---------------------------------------------------------------------------


def test_list_security_advisories(
    configured_engine: GitHubAPIEngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "GET",
        "repos/octocat/Hello-World/security-advisories",
        _StubResponse(
            200,
            [
                {
                    "ghsa_id": "GHSA-xxxx-xxxx-xxxx",
                    "summary": "SQL injection in search",
                    "severity": "high",
                    "cve_id": "CVE-2026-12345",
                    "cvss": {
                        "score": 8.1,
                        "vector_string": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    },
                    "cwes": [{"cwe_id": "CWE-89", "name": "SQL Injection"}],
                    "identifiers": [
                        {"type": "GHSA", "value": "GHSA-xxxx-xxxx-xxxx"},
                        {"type": "CVE", "value": "CVE-2026-12345"},
                    ],
                    "references": [{"url": "https://example.com/advisory"}],
                    "state": "published",
                    "published_at": "2026-04-30T00:00:00Z",
                    "updated_at": "2026-05-01T00:00:00Z",
                }
            ],
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get(
        "/api/v1/github-api/repos/octocat/Hello-World/security-advisories"
        "?state=published"
    )
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 1
    adv = body[0]
    assert adv["ghsa_id"] == "GHSA-xxxx-xxxx-xxxx"
    assert adv["severity"] == "high"
    assert adv["cvss"]["score"] == 8.1
    assert adv["cwes"][0]["cwe_id"] == "CWE-89"
    assert stub.calls[0]["params"] == {"state": "published"}


# ---------------------------------------------------------------------------
# 9. Dependabot alerts
# ---------------------------------------------------------------------------


def test_list_dependabot_alerts(
    configured_engine: GitHubAPIEngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "GET",
        "repos/octocat/Hello-World/dependabot/alerts",
        _StubResponse(
            200,
            [
                {
                    "number": 7,
                    "state": "open",
                    "dependency": {
                        "package": {"ecosystem": "pip", "name": "django"},
                        "manifest_path": "requirements.txt",
                        "scope": "runtime",
                    },
                    "security_advisory": {
                        "ghsa_id": "GHSA-aaaa-bbbb-cccc",
                        "cve_id": "CVE-2026-99999",
                        "summary": "Django vuln",
                        "severity": "critical",
                        "cwes": [{"cwe_id": "CWE-79", "name": "XSS"}],
                        "references": [],
                    },
                    "security_vulnerability": {
                        "package": {"ecosystem": "pip", "name": "django"},
                        "severity": "critical",
                        "vulnerable_version_range": "< 4.2.13",
                        "first_patched_version": {"identifier": "4.2.13"},
                    },
                    "url": "https://api.github.com/repos/octocat/Hello-World/dependabot/alerts/7",
                    "html_url": "https://github.com/octocat/Hello-World/security/dependabot/7",
                    "created_at": "2026-05-01T00:00:00Z",
                    "updated_at": "2026-05-02T00:00:00Z",
                }
            ],
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get(
        "/api/v1/github-api/repos/octocat/Hello-World/dependabot/alerts"
        "?state=open&severity=critical"
    )
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 1
    alert = body[0]
    assert alert["number"] == 7
    assert alert["state"] == "open"
    assert alert["dependency"]["package"]["name"] == "django"
    assert alert["security_advisory"]["severity"] == "critical"
    assert alert["security_vulnerability"]["first_patched_version"]["identifier"] == "4.2.13"
    assert stub.calls[0]["params"] == {"state": "open", "severity": "critical"}


# ---------------------------------------------------------------------------
# 10. Code-scanning alerts
# ---------------------------------------------------------------------------


def test_list_code_scanning_alerts(
    configured_engine: GitHubAPIEngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "GET",
        "repos/octocat/Hello-World/code-scanning/alerts",
        _StubResponse(
            200,
            [
                {
                    "number": 42,
                    "created_at": "2026-04-01T00:00:00Z",
                    "updated_at": "2026-04-02T00:00:00Z",
                    "url": "https://api.github.com/repos/octocat/Hello-World/code-scanning/alerts/42",
                    "html_url": "https://github.com/octocat/Hello-World/security/code-scanning/42",
                    "state": "open",
                    "rule": {
                        "id": "py/sql-injection",
                        "severity": "error",
                        "description": "SQL query built from user-controlled input",
                        "name": "SQL injection",
                        "tags": ["security", "external/cwe/cwe-89"],
                        "full_description": "...",
                        "security_severity_level": "high",
                    },
                    "tool": {
                        "name": "CodeQL",
                        "guid": None,
                        "version": "2.16.1",
                    },
                    "most_recent_instance": {
                        "ref": "refs/heads/main",
                        "analysis_key": ".github/workflows/codeql.yml:analyze",
                        "environment": "production",
                        "state": "open",
                        "commit_sha": "deadbeef",
                        "message": {"text": "SQL injection here"},
                        "location": {
                            "path": "src/db.py",
                            "start_line": 42,
                            "end_line": 42,
                            "start_column": 1,
                            "end_column": 80,
                        },
                        "html_url": "https://github.com/octocat/Hello-World/blob/main/src/db.py#L42",
                        "classifications": ["source"],
                    },
                    "instances_url": "https://api.github.com/repos/octocat/Hello-World/code-scanning/alerts/42/instances",
                }
            ],
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get(
        "/api/v1/github-api/repos/octocat/Hello-World/code-scanning/alerts"
        "?state=open&severity=high&tool_name=CodeQL"
    )
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 1
    alert = body[0]
    assert alert["number"] == 42
    assert alert["rule"]["name"] == "SQL injection"
    assert alert["tool"]["name"] == "CodeQL"
    assert alert["most_recent_instance"]["location"]["path"] == "src/db.py"
    assert alert["most_recent_instance"]["location"]["start_line"] == 42
    assert stub.calls[0]["params"] == {
        "state": "open",
        "severity": "high",
        "tool_name": "CodeQL",
    }


# ---------------------------------------------------------------------------
# 11. Search repositories
# ---------------------------------------------------------------------------


def test_search_repositories(
    configured_engine: GitHubAPIEngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "GET",
        "search/repositories",
        _StubResponse(
            200,
            {
                "total_count": 1,
                "incomplete_results": False,
                "items": [
                    {
                        "id": 1,
                        "name": "aldeci",
                        "full_name": "DevOpsMadDog/aldeci",
                        "private": False,
                        "owner": {"login": "DevOpsMadDog", "id": 99, "type": "User"},
                        "html_url": "https://github.com/DevOpsMadDog/aldeci",
                        "stargazers_count": 1234,
                        "language": "Python",
                        "topics": ["security", "aspm"],
                    }
                ],
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get(
        "/api/v1/github-api/search/repositories?q=aldeci&sort=stars&order=desc"
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["total_count"] == 1
    assert body["incomplete_results"] is False
    assert len(body["items"]) == 1
    assert body["items"][0]["full_name"] == "DevOpsMadDog/aldeci"
    sent = stub.calls[0]["params"]
    assert sent == {"q": "aldeci", "sort": "stars", "order": "desc"}


# ---------------------------------------------------------------------------
# 12. Search code
# ---------------------------------------------------------------------------


def test_search_code(
    configured_engine: GitHubAPIEngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "GET",
        "search/code",
        _StubResponse(
            200,
            {
                "total_count": 2,
                "incomplete_results": False,
                "items": [
                    {
                        "name": "auth.py",
                        "path": "src/auth.py",
                        "sha": "deadbeef",
                        "url": "https://api.github.com/.../auth.py",
                        "git_url": "git://github.com/.../auth.py",
                        "html_url": "https://github.com/.../auth.py",
                        "repository": {"full_name": "octocat/Hello-World"},
                    },
                    {
                        "name": "auth_test.py",
                        "path": "tests/auth_test.py",
                        "sha": "c0ffee",
                        "url": "https://api.github.com/.../auth_test.py",
                        "git_url": "git://github.com/.../auth_test.py",
                        "html_url": "https://github.com/.../auth_test.py",
                        "repository": {"full_name": "octocat/Hello-World"},
                    },
                ],
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get(
        "/api/v1/github-api/search/code?q=jwt+in:file+language:python"
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["total_count"] == 2
    assert len(body["items"]) == 2
    assert body["items"][0]["name"] == "auth.py"
    assert body["items"][0]["path"] == "src/auth.py"
    assert stub.calls[0]["params"] == {"q": "jwt in:file language:python"}


# ---------------------------------------------------------------------------
# 13. Lookup endpoint returns 503 when unavailable
# ---------------------------------------------------------------------------


def test_lookup_endpoint_503_when_unavailable(
    unavailable_engine: GitHubAPIEngine,
) -> None:
    client = _build_app(unavailable_engine)
    resp = client.get("/api/v1/github-api/repos/octocat/Hello-World")
    assert resp.status_code == 503
    body = resp.json()
    assert body["detail"]["error"] == "github_api_unavailable"


# ---------------------------------------------------------------------------
# 14. Upstream 404 surfaces as 404 with payload echo
# ---------------------------------------------------------------------------


def test_upstream_404_surfaces(
    configured_engine: GitHubAPIEngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "GET",
        "repos/missing/repo",
        _StubResponse(
            404,
            {
                "message": "Not Found",
                "documentation_url": "https://docs.github.com/rest",
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get("/api/v1/github-api/repos/missing/repo")
    assert resp.status_code == 404
    body = resp.json()
    assert body["detail"]["error"] == "github_api_upstream_error"
    assert body["detail"]["upstream_status"] == 404
    assert body["detail"]["payload"]["message"] == "Not Found"


# ---------------------------------------------------------------------------
# 15. Upstream 500 collapses to 502 Bad Gateway
# ---------------------------------------------------------------------------


def test_upstream_500_collapses_to_502(
    configured_engine: GitHubAPIEngine, stub: StubHTTPXClient
) -> None:
    stub.set(
        "GET",
        "repos/octocat/Hello-World",
        _StubResponse(500, {"message": "Server Error"}),
    )
    client = _build_app(configured_engine)
    resp = client.get("/api/v1/github-api/repos/octocat/Hello-World")
    assert resp.status_code == 502
    body = resp.json()
    assert body["detail"]["error"] == "github_api_upstream_error"
    assert body["detail"]["upstream_status"] == 500


# ---------------------------------------------------------------------------
# 16. monkeypatched env (token + GHE base URL) takes effect after reset
# ---------------------------------------------------------------------------


def test_env_monkeypatch_takes_effect(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_envtoken")
    monkeypatch.setenv("GITHUB_API_URL", "https://github.acme.io/api/v3")
    reset_github_api_engine()
    engine = get_github_api_engine()
    assert engine.token_present is True
    assert engine.base_url == "https://github.acme.io/api/v3"
    assert engine.status() == "ok"
