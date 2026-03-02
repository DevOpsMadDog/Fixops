"""Comprehensive tests for FixOps PR Generator (suite-core/automation/pr_generator.py).

Covers:
- GitHub full flow: get ref → create branch → commit → PR
- GitLab full flow: create branch → commit → MR
- Error handling: missing token, branch creation failure, commit failure
- Edge cases: existing branch, no changes, empty repo
"""

from __future__ import annotations

from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

from automation.pr_generator import PRGenerator, PRResult


# ── Fixtures ──────────────────────────────────────────────────────────────


@pytest.fixture
def github_gen() -> PRGenerator:
    return PRGenerator({"scm_provider": "github", "github_token": "ghp_test123"})


@pytest.fixture
def gitlab_gen() -> PRGenerator:
    return PRGenerator({"scm_provider": "gitlab", "gitlab_token": "glpat-test123"})


# ── PRResult tests ────────────────────────────────────────────────────────


class TestPRResult:
    def test_default_values(self):
        r = PRResult()
        assert r.success is False
        assert r.pr_url is None
        assert r.pr_number is None
        assert r.branch_name == ""
        assert r.commits == []
        assert r.files_changed == []
        assert r.error is None
        assert isinstance(r.timestamp, datetime)

    def test_with_values(self):
        r = PRResult(
            pr_url="https://github.com/owner/repo/pull/42",
            pr_number=42,
            branch_name="fixops/fix-123",
            commits=["abc123"],
            files_changed=["src/app.py"],
            success=True,
        )
        assert r.success
        assert r.pr_number == 42


# ── PRGenerator init tests ────────────────────────────────────────────────


class TestPRGeneratorInit:
    def test_default_provider(self):
        gen = PRGenerator()
        assert gen.scm_provider == "github"

    def test_custom_provider(self):
        gen = PRGenerator({"scm_provider": "gitlab"})
        assert gen.scm_provider == "gitlab"

    def test_unsupported_provider(self):
        gen = PRGenerator({"scm_provider": "bitbucket"})
        result = gen.create_pr("owner/repo", "title", "body", "branch")
        assert not result.success
        assert "Unsupported" in (result.error or "")


# ── GitHub flow tests ─────────────────────────────────────────────────────


class TestGitHubPRFlow:
    def test_missing_token(self):
        gen = PRGenerator({"scm_provider": "github"})
        result = gen.create_pr("owner/repo", "fix it", "desc", "branch")
        assert not result.success
        assert "token" in (result.error or "").lower()

    @patch("automation.pr_generator._requests")
    def test_full_flow_success(self, mock_requests, github_gen):
        """Full GitHub flow: resolve base → create branch → commit file → PR."""
        # Mock GET ref/heads/main → 200 with SHA
        ref_resp = MagicMock(status_code=200)
        ref_resp.json.return_value = {"object": {"sha": "abc123base"}}

        # Mock POST create branch → 201
        branch_resp = MagicMock(status_code=201)

        # Mock GET contents (file doesn't exist) → 404
        contents_check = MagicMock(status_code=404)

        # Mock PUT contents (commit) → 201
        commit_resp = MagicMock(status_code=201)
        commit_resp.json.return_value = {"commit": {"sha": "commit456"}}

        # Mock POST pulls → 201
        pr_resp = MagicMock(status_code=201)
        pr_resp.json.return_value = {
            "html_url": "https://github.com/owner/repo/pull/99",
            "number": 99,
        }

        # Wire up calls in order
        mock_requests.get.side_effect = [ref_resp, contents_check]
        mock_requests.post.side_effect = [branch_resp, pr_resp]
        mock_requests.put.return_value = commit_resp

        result = github_gen.create_pr(
            "owner/repo",
            "Fix CVE-2024-001",
            "Automated fix",
            "fixops/fix-001",
            "main",
            {"src/app.py": "import safe\n"},
        )

        assert result.success
        assert result.pr_url == "https://github.com/owner/repo/pull/99"
        assert result.pr_number == 99
        assert result.branch_name == "fixops/fix-001"
        assert "commit456" in result.commits
        assert "src/app.py" in result.files_changed

    @patch("automation.pr_generator._requests")
    def test_base_ref_not_found(self, mock_requests, github_gen):
        """Should fail gracefully when base branch doesn't exist."""
        ref_resp = MagicMock(status_code=404)
        mock_requests.get.return_value = ref_resp

        result = github_gen.create_pr(
            "owner/repo", "title", "body", "branch", "nonexistent-base"
        )
        assert not result.success
        assert "base branch" in (result.error or "").lower()

    @patch("automation.pr_generator._requests")
    def test_branch_creation_failure(self, mock_requests, github_gen):
        """Should fail when branch creation returns non-success."""
        ref_resp = MagicMock(status_code=200)
        ref_resp.json.return_value = {"object": {"sha": "basesha"}}
        branch_resp = MagicMock(status_code=500, text="Internal Server Error")

        mock_requests.get.return_value = ref_resp
        mock_requests.post.return_value = branch_resp

        result = github_gen.create_pr(
            "owner/repo", "title", "body", "branch", "main"
        )
        assert not result.success
        assert "branch" in (result.error or "").lower()

    @patch("automation.pr_generator._requests")
    def test_branch_already_exists(self, mock_requests, github_gen):
        """Should succeed when branch already exists (422)."""
        ref_resp = MagicMock(status_code=200)
        ref_resp.json.return_value = {"object": {"sha": "basesha"}}
        branch_resp = MagicMock(status_code=422, text="Reference already exists")
        pr_resp = MagicMock(status_code=201)
        pr_resp.json.return_value = {
            "html_url": "https://github.com/owner/repo/pull/1",
            "number": 1,
        }

        mock_requests.get.return_value = ref_resp
        mock_requests.post.side_effect = [branch_resp, pr_resp]

        result = github_gen.create_pr(
            "owner/repo", "title", "body", "existing-branch", "main"
        )
        assert result.success

    @patch("automation.pr_generator._requests")
    def test_no_changes(self, mock_requests, github_gen):
        """Should create PR even with no file changes."""
        ref_resp = MagicMock(status_code=200)
        ref_resp.json.return_value = {"object": {"sha": "basesha"}}
        branch_resp = MagicMock(status_code=201)
        pr_resp = MagicMock(status_code=201)
        pr_resp.json.return_value = {
            "html_url": "https://github.com/owner/repo/pull/2",
            "number": 2,
        }

        mock_requests.get.return_value = ref_resp
        mock_requests.post.side_effect = [branch_resp, pr_resp]

        result = github_gen.create_pr(
            "owner/repo", "title", "body", "branch", "main", changes=None
        )
        assert result.success
        assert result.files_changed == []

    @patch("automation.pr_generator._requests")
    def test_commit_failure_skips_file(self, mock_requests, github_gen):
        """Should skip files that fail to commit but still create PR."""
        ref_resp = MagicMock(status_code=200)
        ref_resp.json.return_value = {"object": {"sha": "basesha"}}
        branch_resp = MagicMock(status_code=201)
        contents_check = MagicMock(status_code=404)
        commit_fail = MagicMock(status_code=500, text="Internal error")
        pr_resp = MagicMock(status_code=201)
        pr_resp.json.return_value = {"html_url": "url", "number": 3}

        mock_requests.get.side_effect = [ref_resp, contents_check]
        mock_requests.put.return_value = commit_fail
        mock_requests.post.side_effect = [branch_resp, pr_resp]

        result = github_gen.create_pr(
            "owner/repo", "title", "body", "branch", "main",
            changes={"bad.py": "content"},
        )
        assert result.success
        assert result.files_changed == []

    @patch("automation.pr_generator._requests")
    def test_pr_creation_failure(self, mock_requests, github_gen):
        """Should report failure when PR creation fails."""
        ref_resp = MagicMock(status_code=200)
        ref_resp.json.return_value = {"object": {"sha": "basesha"}}
        branch_resp = MagicMock(status_code=201)
        pr_resp = MagicMock(status_code=422, text="Validation Failed")

        mock_requests.get.return_value = ref_resp
        mock_requests.post.side_effect = [branch_resp, pr_resp]

        result = github_gen.create_pr(
            "owner/repo", "title", "body", "branch", "main"
        )
        assert not result.success
        assert "422" in (result.error or "")

    @patch("automation.pr_generator._requests")
    def test_update_existing_file(self, mock_requests, github_gen):
        """Should use file SHA when updating existing files."""
        ref_resp = MagicMock(status_code=200)
        ref_resp.json.return_value = {"object": {"sha": "basesha"}}
        branch_resp = MagicMock(status_code=201)
        # File exists — returns SHA
        contents_check = MagicMock(status_code=200)
        contents_check.json.return_value = {"sha": "existing_file_sha"}
        commit_resp = MagicMock(status_code=200)
        commit_resp.json.return_value = {"commit": {"sha": "comm789"}}
        pr_resp = MagicMock(status_code=201)
        pr_resp.json.return_value = {"html_url": "url", "number": 5}

        mock_requests.get.side_effect = [ref_resp, contents_check]
        mock_requests.put.return_value = commit_resp
        mock_requests.post.side_effect = [branch_resp, pr_resp]

        result = github_gen.create_pr(
            "owner/repo", "title", "body", "branch", "main",
            changes={"existing.py": "new content"},
        )
        assert result.success
        # Verify PUT payload included existing sha
        put_call = mock_requests.put.call_args
        assert put_call is not None
        payload = put_call.kwargs.get("json") or put_call[1].get("json")
        assert payload.get("sha") == "existing_file_sha"


# ── GitLab flow tests ─────────────────────────────────────────────────────


class TestGitLabMRFlow:
    def test_missing_token(self):
        gen = PRGenerator({"scm_provider": "gitlab"})
        result = gen.create_pr("owner/repo", "fix", "desc", "branch")
        assert not result.success
        assert "token" in (result.error or "").lower()

    @patch("automation.pr_generator._requests")
    def test_full_flow_success(self, mock_requests, gitlab_gen):
        """Full GitLab flow: create branch → commit files → MR."""
        # Branch creation
        branch_resp = MagicMock(status_code=201)
        # HEAD check for file existence → 404 (new file)
        head_resp = MagicMock(status_code=404)
        # Commit
        commit_resp = MagicMock(status_code=201)
        commit_resp.json.return_value = {"id": "glcommit001"}
        # MR creation
        mr_resp = MagicMock(status_code=201)
        mr_resp.json.return_value = {
            "web_url": "https://gitlab.com/owner/repo/-/merge_requests/10",
            "iid": 10,
        }

        mock_requests.post.side_effect = [branch_resp, commit_resp, mr_resp]
        mock_requests.head.return_value = head_resp

        result = gitlab_gen.create_pr(
            "owner/repo",
            "Fix vulnerability",
            "Auto fix",
            "fixops/fix-gl",
            "main",
            {"src/fix.py": "safe code"},
        )

        assert result.success
        assert result.pr_number == 10
        assert "merge_requests" in (result.pr_url or "")
        assert "glcommit001" in result.commits

    @patch("automation.pr_generator._requests")
    def test_branch_already_exists(self, mock_requests, gitlab_gen):
        """Should handle 400 'already exists' gracefully."""
        branch_resp = MagicMock(status_code=400)
        branch_resp.text = "Branch already exists"
        head_resp = MagicMock(status_code=200)  # file exists
        commit_resp = MagicMock(status_code=201)
        commit_resp.json.return_value = {"id": "gl002"}
        mr_resp = MagicMock(status_code=201)
        mr_resp.json.return_value = {"web_url": "url", "iid": 11}

        mock_requests.post.side_effect = [branch_resp, commit_resp, mr_resp]
        mock_requests.head.return_value = head_resp

        result = gitlab_gen.create_pr(
            "owner/repo", "title", "body", "branch", "main",
            changes={"file.py": "content"},
        )
        assert result.success

    @patch("automation.pr_generator._requests")
    def test_branch_creation_error(self, mock_requests, gitlab_gen):
        """Should fail on branch creation error."""
        branch_resp = MagicMock(status_code=500)
        branch_resp.text = "Server error"

        mock_requests.post.return_value = branch_resp

        result = gitlab_gen.create_pr(
            "owner/repo", "title", "body", "branch", "main"
        )
        assert not result.success
        assert "branch" in (result.error or "").lower()

    @patch("automation.pr_generator._requests")
    def test_commit_failure(self, mock_requests, gitlab_gen):
        """Should fail when commit fails."""
        branch_resp = MagicMock(status_code=201)
        head_resp = MagicMock(status_code=404)
        commit_resp = MagicMock(status_code=400)
        commit_resp.text = "Bad request"

        mock_requests.post.side_effect = [branch_resp, commit_resp]
        mock_requests.head.return_value = head_resp

        result = gitlab_gen.create_pr(
            "owner/repo", "title", "body", "branch", "main",
            changes={"file.py": "content"},
        )
        assert not result.success
        assert "commit" in (result.error or "").lower()


# ── Dependency update PR tests ────────────────────────────────────────────


class TestDependencyUpdatePR:
    def test_generate_pr_description(self, github_gen):
        """Should generate proper description."""

        class FakeUpdate:
            package_name = "lodash"
            current_version = "4.17.20"
            new_version = "4.17.21"
            has_security_vulnerability = True
            cve_ids = ["CVE-2021-23337"]

        desc = github_gen._generate_pr_description([FakeUpdate()])
        assert "lodash" in desc
        assert "CVE-2021-23337" in desc
        assert "Security Updates" in desc

    @patch("automation.pr_generator._requests")
    def test_generate_pr_for_deps(self, mock_requests, github_gen):
        """Should create PR for dependency updates."""

        class FakeUpdate:
            package_name = "axios"
            current_version = "0.21.0"
            new_version = "0.21.1"
            has_security_vulnerability = True
            cve_ids = ["CVE-2021-3749"]

        ref_resp = MagicMock(status_code=200)
        ref_resp.json.return_value = {"object": {"sha": "base"}}
        branch_resp = MagicMock(status_code=201)
        pr_resp = MagicMock(status_code=201)
        pr_resp.json.return_value = {"html_url": "url", "number": 20}

        mock_requests.get.return_value = ref_resp
        mock_requests.post.side_effect = [branch_resp, pr_resp]

        result = github_gen.generate_pr_for_dependency_updates(
            "owner/repo", [FakeUpdate()]
        )
        assert result.success
        assert result.branch_name.startswith("fixops/dependency-updates-")
