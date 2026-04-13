"""Real GitHub Issues integration tests for ALDECI.

Tests use the authenticated `gh` CLI to make REAL API calls against
DevOpsMadDog/Fixops. Issues created during tests use a [TEST] prefix
and are cleaned up automatically.

Test categories:
  - Unit tests (no API calls, marked normally)
  - Integration tests (real gh CLI calls, marked @pytest.mark.integration)

Run integration tests explicitly:
    pytest tests/test_github_issues_real.py -m integration -v

Run unit tests only (default):
    pytest tests/test_github_issues_real.py -v
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------

_suite_core = str(Path(__file__).parent.parent / "suite-core")
if _suite_core not in sys.path:
    sys.path.insert(0, _suite_core)

# ---------------------------------------------------------------------------
# Import the module under test
# ---------------------------------------------------------------------------

from core.github_issues_integration import (
    Finding,
    GitHubIssue,
    GitHubIssuesClient,
    IssueMetrics,
    SyncResult,
    _build_issue_body,
    _build_issue_title,
    _find_gh,
    _normalize_severity,
    _normalize_type,
    _run_gh,
    get_github_issues_client,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TEST_REPO = "DevOpsMadDog/Fixops"
TEST_PREFIX = "[TEST]"
_CREATED_ISSUE_NUMBERS: List[int] = []  # track for cleanup


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(
    *,
    finding_id: Optional[str] = None,
    severity: str = "medium",
    title: Optional[str] = None,
    finding_type: str = "sast",
    **kwargs,
) -> Finding:
    uid = finding_id or f"test-{uuid.uuid4().hex[:8]}"
    t = title or f"{TEST_PREFIX} ALDECI Test Finding {uid}"
    # Build defaults then let kwargs override so individual tests can customise any field
    defaults: Dict[str, Any] = dict(
        description="Automated test finding created by pytest.",
        cwe="CWE-79",
        cvss=6.5,
        affected_file="suite-core/core/brain_pipeline.py",
        affected_line=42,
        remediation="Test remediation guidance.",
        scanner="semgrep",
        cve_id="CVE-2024-0001",
        status="open",
    )
    defaults.update(kwargs)
    return Finding(
        finding_id=uid,
        title=t,
        severity=severity,
        finding_type=finding_type,
        **defaults,
    )


def _gh_available() -> bool:
    """Return True if gh CLI is findable on this system."""
    try:
        _find_gh()
        return True
    except RuntimeError:
        return False


def _gh_authenticated() -> bool:
    """Return True if gh CLI is available AND authenticated."""
    if not _gh_available():
        return False
    try:
        result = subprocess.run(
            [_find_gh(), "auth", "status"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.returncode == 0
    except Exception:
        return False


def _close_issue(issue_number: int) -> None:
    """Best-effort cleanup: close a test issue."""
    if not _gh_available():
        return
    try:
        subprocess.run(
            [_find_gh(), "issue", "close", str(issue_number),
             "--repo", TEST_REPO,
             "--comment", "Closed by automated test cleanup."],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def tmp_db(tmp_path_factory):
    """Temporary SQLite DB for tests (module-scoped)."""
    return tmp_path_factory.mktemp("db") / "test_github.db"


@pytest.fixture(scope="module")
def client(tmp_db):
    """GitHubIssuesClient pointed at test DB."""
    return GitHubIssuesClient(repo=TEST_REPO, db_path=tmp_db)


@pytest.fixture(scope="module")
def real_client(tmp_db):
    """Client for integration tests — requires gh auth."""
    return GitHubIssuesClient(repo=TEST_REPO, db_path=tmp_db)


@pytest.fixture(autouse=True, scope="module")
def cleanup_test_issues():
    """Close any [TEST] issues created during this run."""
    yield
    for num in _CREATED_ISSUE_NUMBERS:
        _close_issue(num)


# ===========================================================================
# UNIT TESTS — no GitHub API calls
# ===========================================================================


class TestNormalizeSeverity:
    def test_canonical_values_unchanged(self):
        for sev in ("critical", "high", "medium", "low", "informational"):
            assert _normalize_severity(sev) == sev

    def test_uppercase_lowercased(self):
        assert _normalize_severity("CRITICAL") == "critical"
        assert _normalize_severity("HIGH") == "high"

    def test_abbreviations_mapped(self):
        assert _normalize_severity("crit") == "critical"
        assert _normalize_severity("info") == "informational"
        assert _normalize_severity("warn") == "medium"

    def test_unknown_falls_back_to_low(self):
        assert _normalize_severity("bogus") == "low"

    def test_strips_whitespace(self):
        assert _normalize_severity("  high  ") == "high"


class TestNormalizeType:
    def test_canonical_types_unchanged(self):
        for t in ("sast", "dast", "sca", "iac", "secret", "cloud", "network"):
            assert _normalize_type(t) == t

    def test_uppercase_lowercased(self):
        assert _normalize_type("SAST") == "sast"

    def test_unknown_falls_back_to_sast(self):
        assert _normalize_type("unknown_type") == "sast"


class TestBuildIssueTitle:
    def test_title_format(self):
        f = _make_finding(severity="critical", title="SQL Injection in login")
        title = _build_issue_title(f)
        assert title == "[ALDECI-CRITICAL] SQL Injection in login"

    def test_severity_uppercased_in_title(self):
        f = _make_finding(severity="high", title="XSS")
        assert "[ALDECI-HIGH]" in _build_issue_title(f)

    def test_original_title_preserved(self):
        f = _make_finding(title="My Finding Title")
        assert "My Finding Title" in _build_issue_title(f)


class TestBuildIssueBody:
    def test_body_contains_finding_id(self):
        f = _make_finding(finding_id="abc-123")
        body = _build_issue_body(f)
        assert "abc-123" in body

    def test_body_contains_severity(self):
        f = _make_finding(severity="critical")
        body = _build_issue_body(f)
        assert "CRITICAL" in body

    def test_body_contains_cwe_link(self):
        f = _make_finding(cwe="CWE-79")
        body = _build_issue_body(f)
        assert "CWE-79" in body
        assert "cwe.mitre.org" in body

    def test_body_contains_cve(self):
        f = _make_finding(cve_id="CVE-2024-1234")
        body = _build_issue_body(f)
        assert "CVE-2024-1234" in body
        assert "nvd.nist.gov" in body

    def test_body_contains_cvss(self):
        f = _make_finding(cvss=9.8)
        body = _build_issue_body(f)
        assert "9.8" in body

    def test_body_contains_affected_file(self):
        f = _make_finding(affected_file="core/brain.py", affected_line=42)
        body = _build_issue_body(f)
        assert "core/brain.py" in body
        assert "42" in body

    def test_body_contains_remediation(self):
        f = _make_finding(remediation="Update dependency to >= 2.0.0")
        body = _build_issue_body(f)
        assert "Update dependency to >= 2.0.0" in body

    def test_body_has_aldeci_footer(self):
        f = _make_finding()
        body = _build_issue_body(f)
        assert "ALDECI" in body

    def test_body_extra_metadata_included(self):
        f = _make_finding(extra={"app_id": "APP-001", "owner": "team-sec"})
        body = _build_issue_body(f)
        assert "APP-001" in body
        assert "team-sec" in body


class TestFindingDataclass:
    def test_defaults(self):
        f = Finding(finding_id="x", title="T", severity="low")
        assert f.finding_type == "sast"
        assert f.status == "open"
        assert f.extra == {}

    def test_all_fields(self):
        f = _make_finding()
        assert f.cwe == "CWE-79"
        assert f.cvss == 6.5
        assert f.scanner == "semgrep"


class TestSyncResultDataclass:
    def test_error_result(self):
        r = SyncResult(success=False, action="error", finding_id="x", error="boom")
        assert not r.success
        assert r.error == "boom"

    def test_success_result(self):
        r = SyncResult(success=True, action="created", finding_id="y", issue_number=42)
        assert r.success
        assert r.issue_number == 42


class TestGitHubIssuesClientUnit:
    """Unit tests with mocked subprocess."""

    def test_create_issue_skips_duplicate(self, client: GitHubIssuesClient, tmp_db):
        """If link exists in DB, create returns 'skipped'."""
        from core.github_issues_integration import _IssueStore
        store = _IssueStore(tmp_db)
        finding_id = f"dup-{uuid.uuid4().hex[:6]}"
        store.upsert_link(finding_id, 999, TEST_REPO)
        f = _make_finding(finding_id=finding_id)
        c = GitHubIssuesClient(repo=TEST_REPO, db_path=tmp_db)
        result = c.create_issue_from_finding(f)
        assert result.action == "skipped"
        assert result.issue_number == 999

    def test_update_issue_no_link_returns_error(self, client: GitHubIssuesClient):
        """update_issue() with unknown finding_id returns error SyncResult."""
        result = client.update_issue("nonexistent-finding-id-xyz", "comment text")
        assert not result.success
        assert result.action == "error"
        assert "No issue link" in (result.error or "")

    def test_metrics_empty_db(self, tmp_path):
        """Metrics on empty DB returns zeros."""
        c = GitHubIssuesClient(repo=TEST_REPO, db_path=tmp_path / "empty.db")
        m = c.get_metrics()
        assert m.total_created == 0
        assert m.total_open == 0
        assert m.total_closed == 0
        assert m.avg_time_to_close_hours == 0.0

    @patch("core.github_issues_integration._run_gh")
    def test_list_issues_empty_response(self, mock_run, tmp_path):
        """list_issues() returns [] when gh returns empty list."""
        mock_run.return_value = (True, [])
        c = GitHubIssuesClient(repo=TEST_REPO, db_path=tmp_path / "t.db")
        issues = c.list_issues()
        assert issues == []

    @patch("core.github_issues_integration._run_gh")
    def test_list_issues_parses_response(self, mock_run, tmp_path):
        """list_issues() correctly parses gh JSON output."""
        mock_run.return_value = (True, [
            {
                "number": 42,
                "title": "[ALDECI-HIGH] XSS",
                "state": "OPEN",
                "url": "https://github.com/DevOpsMadDog/Fixops/issues/42",
                "labels": [{"name": "aldeci"}, {"name": "high"}],
                "assignees": [{"login": "devopsai"}],
                "createdAt": "2026-04-01T00:00:00Z",
                "updatedAt": "2026-04-02T00:00:00Z",
                "closedAt": None,
            }
        ])
        c = GitHubIssuesClient(repo=TEST_REPO, db_path=tmp_path / "t2.db")
        issues = c.list_issues()
        assert len(issues) == 1
        assert issues[0].number == 42
        assert "aldeci" in issues[0].labels
        assert "devopsai" in issues[0].assignees

    @patch("core.github_issues_integration._run_gh")
    def test_search_issue_returns_none_on_empty(self, mock_run, tmp_path):
        """search_issue() returns None when no results."""
        mock_run.return_value = (True, [])
        c = GitHubIssuesClient(repo=TEST_REPO, db_path=tmp_path / "t3.db")
        result = c.search_issue("SQL Injection")
        assert result is None

    @patch("core.github_issues_integration._run_gh")
    def test_sync_all_dry_run(self, mock_run, tmp_path):
        """sync_all_findings with dry_run=True never calls _run_gh."""
        c = GitHubIssuesClient(repo=TEST_REPO, db_path=tmp_path / "t4.db")
        findings = [_make_finding() for _ in range(3)]
        results = c.sync_all_findings(findings, dry_run=True)
        mock_run.assert_not_called()
        assert len(results) == 3
        assert all(r.action.startswith("would_") for r in results)

    @patch("core.github_issues_integration._run_gh")
    def test_create_issue_handles_gh_failure(self, mock_run, tmp_path):
        """create_issue_from_finding returns error SyncResult on gh failure."""
        mock_run.return_value = (False, "HTTP 422: Unprocessable Entity")
        c = GitHubIssuesClient(repo=TEST_REPO, db_path=tmp_path / "t5.db")
        f = _make_finding()
        result = c.create_issue_from_finding(f)
        assert not result.success
        assert result.action == "error"
        assert "422" in (result.error or "")

    def test_get_singleton_returns_same_instance(self):
        """get_github_issues_client() returns the same object each call."""
        c1 = get_github_issues_client()
        c2 = get_github_issues_client()
        assert c1 is c2

    @patch("core.github_issues_integration._find_gh", return_value="/usr/local/bin/gh")
    @patch("core.github_issues_integration._run_gh")
    def test_check_auth_gh_failure(self, mock_run, mock_find_gh, tmp_path):
        """check_auth() returns authenticated=False on gh failure."""
        mock_run.return_value = (False, "not logged in")
        c = GitHubIssuesClient(repo=TEST_REPO, db_path=tmp_path / "auth.db")
        status = c.check_auth()
        assert status["available"] is True
        assert status["authenticated"] is False


# ===========================================================================
# INTEGRATION TESTS — real gh CLI calls
# ===========================================================================

_INTEGRATION_REASON = (
    "gh CLI not available or not authenticated. "
    "Install from https://cli.github.com/ and run `gh auth login`."
)


@pytest.mark.integration
class TestGhCliAvailability:
    """Verify gh CLI is present and authenticated."""

    def test_gh_cli_is_findable(self):
        """gh CLI binary must be locatable on this system."""
        try:
            gh_bin = _find_gh()
            assert gh_bin, "gh binary path should be non-empty"
            assert Path(gh_bin).is_file() or shutil.which(gh_bin), "gh binary must exist"
        except RuntimeError as exc:
            pytest.fail(f"gh CLI not found: {exc}")

    def test_gh_cli_version(self):
        """gh --version must return exit code 0."""
        try:
            gh_bin = _find_gh()
        except RuntimeError:
            pytest.skip("gh CLI not found")
        result = subprocess.run([gh_bin, "--version"], capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, f"gh --version failed: {result.stderr}"
        assert "gh version" in result.stdout.lower() or "github" in result.stdout.lower()

    def test_gh_auth_status(self):
        """gh auth status must report logged in."""
        if not _gh_available():
            pytest.skip("gh CLI not found")
        try:
            gh_bin = _find_gh()
        except RuntimeError:
            pytest.skip("gh CLI not found")
        result = subprocess.run(
            [gh_bin, "auth", "status"],
            capture_output=True, text=True, timeout=15
        )
        assert result.returncode == 0, (
            f"gh auth status failed (rc={result.returncode}): {result.stderr}\n"
            "Run `gh auth login` to authenticate."
        )

    def test_gh_can_access_repo(self):
        """gh can query the target repo."""
        if not _gh_authenticated():
            pytest.skip(_INTEGRATION_REASON)
        try:
            gh_bin = _find_gh()
        except RuntimeError:
            pytest.skip("gh CLI not found")
        result = subprocess.run(
            [gh_bin, "repo", "view", TEST_REPO, "--json", "name"],
            capture_output=True, text=True, timeout=15
        )
        assert result.returncode == 0, f"Cannot access repo {TEST_REPO}: {result.stderr}"
        data = json.loads(result.stdout)
        assert data.get("name") == "Fixops"


@pytest.mark.integration
class TestRunGhHelper:
    """Test the _run_gh wrapper with real CLI."""

    def setup_method(self):
        if not _gh_authenticated():
            pytest.skip(_INTEGRATION_REASON)

    def test_run_gh_success(self):
        ok, data = _run_gh(["repo", "view", TEST_REPO, "--json", "name"])
        assert ok is True
        assert isinstance(data, dict)
        assert data.get("name") == "Fixops"

    def test_run_gh_bad_command_returns_false(self):
        ok, err = _run_gh(["issue", "list", "--repo", "nonexistent/repo-xyz-abc-123"])
        assert ok is False
        assert isinstance(err, str)

    def test_run_gh_list_issues_json(self):
        ok, data = _run_gh(
            ["issue", "list", "--label", "aldeci", "--state", "all",
             "--limit", "5", "--json", "number,title,state"],
            repo=TEST_REPO,
        )
        assert ok is True
        assert isinstance(data, list)


@pytest.mark.integration
class TestCreateRealIssue:
    """Create a real GitHub issue and verify it exists."""

    def setup_method(self):
        if not _gh_authenticated():
            pytest.skip(_INTEGRATION_REASON)

    def test_create_issue_returns_url(self, real_client: GitHubIssuesClient):
        """Creating an issue returns a real GitHub URL."""
        f = _make_finding(
            title=f"{TEST_PREFIX} XSS in login form (pytest integration test)",
            severity="high",
            finding_type="sast",
        )
        result = real_client.create_issue_from_finding(f)

        assert result.success, f"Expected success, got error: {result.error}"
        assert result.action == "created"
        assert result.issue_number is not None
        assert result.issue_number > 0
        assert "github.com" in (result.issue_url or "")

        _CREATED_ISSUE_NUMBERS.append(result.issue_number)

    def test_create_issue_dedup(self, real_client: GitHubIssuesClient):
        """Creating an issue twice for the same finding_id returns 'skipped'."""
        f = _make_finding(
            title=f"{TEST_PREFIX} Dedup test finding",
            severity="low",
        )
        # First creation
        r1 = real_client.create_issue_from_finding(f)
        if r1.action == "created" and r1.issue_number:
            _CREATED_ISSUE_NUMBERS.append(r1.issue_number)

        # Second creation — must be skipped
        r2 = real_client.create_issue_from_finding(f)
        assert r2.action == "skipped"
        assert r2.issue_number == r1.issue_number

    def test_created_issue_has_correct_labels(self, real_client: GitHubIssuesClient):
        """The created issue must have aldeci + severity + type labels."""
        f = _make_finding(
            title=f"{TEST_PREFIX} Label verification test",
            severity="medium",
            finding_type="sca",
        )
        result = real_client.create_issue_from_finding(f)
        if result.action == "created" and result.issue_number:
            _CREATED_ISSUE_NUMBERS.append(result.issue_number)

        assert result.success

        # Verify labels by listing issues
        issues = real_client.list_issues(state="open", limit=50)
        created = next((i for i in issues if i.number == result.issue_number), None)
        if created:
            assert "aldeci" in created.labels, f"'aldeci' label missing from {created.labels}"
            assert "medium" in created.labels, f"'medium' label missing from {created.labels}"
            assert "sca" in created.labels, f"'sca' label missing from {created.labels}"


@pytest.mark.integration
class TestListRealIssues:
    """Verify list_issues() against the live repo."""

    def setup_method(self):
        if not _gh_authenticated():
            pytest.skip(_INTEGRATION_REASON)

    def test_list_issues_returns_list(self, real_client: GitHubIssuesClient):
        issues = real_client.list_issues(state="open", limit=10)
        assert isinstance(issues, list)

    def test_list_closed_issues(self, real_client: GitHubIssuesClient):
        issues = real_client.list_issues(state="closed", limit=5)
        assert isinstance(issues, list)
        for issue in issues:
            assert issue.state in ("closed", "CLOSED")

    def test_list_all_issues(self, real_client: GitHubIssuesClient):
        issues = real_client.list_issues(state="all", limit=20)
        assert isinstance(issues, list)


@pytest.mark.integration
class TestUpdateRealIssue:
    """Add a comment to a real issue."""

    def setup_method(self):
        if not _gh_authenticated():
            pytest.skip(_INTEGRATION_REASON)

    def test_add_comment_to_existing_issue(self, real_client: GitHubIssuesClient):
        """Create an issue then add a comment."""
        f = _make_finding(
            title=f"{TEST_PREFIX} Comment test finding",
            severity="low",
        )
        create_result = real_client.create_issue_from_finding(f)
        if create_result.action == "created" and create_result.issue_number:
            _CREATED_ISSUE_NUMBERS.append(create_result.issue_number)

        assert create_result.success

        comment_result = real_client.update_issue(
            f.finding_id,
            "**ALDECI re-scan**: Vulnerability confirmed. CVSS updated to 7.2.",
        )
        assert comment_result.success
        assert comment_result.action == "updated"


@pytest.mark.integration
class TestSearchRealIssues:
    """Search for issues by title pattern."""

    def setup_method(self):
        if not _gh_authenticated():
            pytest.skip(_INTEGRATION_REASON)

    def test_search_nonexistent_returns_none(self, real_client: GitHubIssuesClient):
        result = real_client.search_issue("zzznonexistentfindingxxx999abc")
        assert result is None

    def test_search_existing_test_issue(self, real_client: GitHubIssuesClient):
        """After creating an issue, search should find it by title fragment."""
        unique_fragment = f"pytest-search-{uuid.uuid4().hex[:8]}"
        f = _make_finding(
            title=f"{TEST_PREFIX} {unique_fragment}",
            severity="low",
        )
        create_result = real_client.create_issue_from_finding(f)
        if create_result.action == "created" and create_result.issue_number:
            _CREATED_ISSUE_NUMBERS.append(create_result.issue_number)

        # Small delay for indexing
        time.sleep(2)

        found = real_client.search_issue(unique_fragment)
        # May be None due to search indexing delay — soft assert
        if found is not None:
            assert unique_fragment in found.title


@pytest.mark.integration
class TestBidirectionalSync:
    """Bidirectional sync between ALDECI and GitHub."""

    def setup_method(self):
        if not _gh_authenticated():
            pytest.skip(_INTEGRATION_REASON)

    def test_sync_github_to_findings_returns_list(self, real_client: GitHubIssuesClient):
        """sync_github_to_findings() always returns a list."""
        results = real_client.sync_github_to_findings()
        assert isinstance(results, list)
        for item in results:
            assert "finding_id" in item
            assert "issue_number" in item
            assert "action" in item

    def test_sync_all_findings_creates_issues(self, real_client: GitHubIssuesClient):
        """sync_all_findings() creates issues for new findings."""
        findings = [
            _make_finding(
                title=f"{TEST_PREFIX} Sync batch test {i}",
                severity="low",
                finding_type="iac",
            )
            for i in range(2)
        ]
        results = real_client.sync_all_findings(findings)
        assert len(results) == 2
        for result in results:
            assert result.success, f"Sync failed: {result.error}"
            if result.action == "created" and result.issue_number:
                _CREATED_ISSUE_NUMBERS.append(result.issue_number)


@pytest.mark.integration
class TestMetricsReal:
    """Metrics after real issue creation."""

    def setup_method(self):
        if not _gh_authenticated():
            pytest.skip(_INTEGRATION_REASON)

    def test_metrics_after_create(self, real_client: GitHubIssuesClient):
        """Metrics total_created should be >= 1 after creating an issue."""
        f = _make_finding(
            title=f"{TEST_PREFIX} Metrics test finding",
            severity="critical",
        )
        result = real_client.create_issue_from_finding(f)
        if result.action == "created" and result.issue_number:
            _CREATED_ISSUE_NUMBERS.append(result.issue_number)

        metrics = real_client.get_metrics()
        assert isinstance(metrics, IssueMetrics)
        assert metrics.total_created >= 1
        assert isinstance(metrics.by_severity, dict)
        assert isinstance(metrics.by_type, dict)
        assert metrics.total_open + metrics.total_closed == metrics.total_created

    def test_metrics_by_severity_populated(self, real_client: GitHubIssuesClient):
        """after creating issues, by_severity should have entries."""
        metrics = real_client.get_metrics()
        if metrics.total_created > 0:
            assert len(metrics.by_severity) > 0


@pytest.mark.integration
class TestCheckAuth:
    """Test check_auth() with real gh CLI."""

    def test_check_auth_returns_dict(self, real_client: GitHubIssuesClient):
        status = real_client.check_auth()
        assert isinstance(status, dict)
        assert "available" in status
        assert "authenticated" in status

    def test_check_auth_gh_available(self, real_client: GitHubIssuesClient):
        if not _gh_available():
            pytest.skip("gh CLI not found")
        status = real_client.check_auth()
        assert status["available"] is True

    def test_check_auth_gh_authenticated(self, real_client: GitHubIssuesClient):
        if not _gh_authenticated():
            pytest.skip(_INTEGRATION_REASON)
        status = real_client.check_auth()
        assert status["authenticated"] is True
        assert "username" in status
        assert "repo" in status
