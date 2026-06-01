"""Tests for code_repo_agent input validation (Fix 2: GitPython RCE prevention).

Verifies that _validate_repo_url and _validate_repo_branch reject all known
dangerous inputs and accept well-formed safe inputs.
"""
import pytest
import sys
import os

# Ensure suite-core is on path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))

from agents.design_time.code_repo_agent import _validate_repo_url, _validate_repo_branch


# ---------------------------------------------------------------------------
# _validate_repo_url — dangerous inputs that MUST be rejected
# ---------------------------------------------------------------------------

class TestRepoUrlRejected:
    """All of these must raise ValueError."""

    def test_ext_transport_rce(self):
        """ext:: transport executes arbitrary shell commands via gitpython."""
        with pytest.raises(ValueError, match="disallowed transport"):
            _validate_repo_url("ext::sh -c 'id>/tmp/pwned'")

    def test_ext_transport_uppercase(self):
        with pytest.raises(ValueError, match="disallowed transport"):
            _validate_repo_url("EXT::sh -c 'id'")

    def test_ext_transport_upload_pack(self):
        """Classic gitpython RCE vector."""
        with pytest.raises(ValueError, match="disallowed transport"):
            _validate_repo_url("ext::git-upload-pack '/path/to/repo'")

    def test_file_double_colon(self):
        with pytest.raises(ValueError, match="disallowed transport"):
            _validate_repo_url("file::/etc/passwd")

    def test_file_triple_slash(self):
        with pytest.raises(ValueError, match="disallowed transport"):
            _validate_repo_url("file:///etc/passwd")

    def test_file_triple_slash_absolute(self):
        with pytest.raises(ValueError, match="disallowed transport"):
            _validate_repo_url("file:///home/user/repos/secret")

    def test_git_protocol(self):
        """git:// is unauthenticated; not needed and not allowed."""
        with pytest.raises(ValueError, match="disallowed transport"):
            _validate_repo_url("git://github.com/org/repo.git")

    def test_ssh_protocol(self):
        with pytest.raises(ValueError, match="disallowed transport"):
            _validate_repo_url("ssh://git@github.com/org/repo.git")

    def test_leading_dash_option_injection(self):
        """--upload-pack= option injection."""
        with pytest.raises(ValueError, match="must not start with"):
            _validate_repo_url("--upload-pack=id https://github.com/org/repo")

    def test_empty_url(self):
        with pytest.raises(ValueError, match="must not be empty"):
            _validate_repo_url("")

    def test_plain_path(self):
        """Bare local path is not a valid remote URL."""
        with pytest.raises(ValueError):
            _validate_repo_url("/home/user/myrepo")

    def test_relative_path(self):
        with pytest.raises(ValueError):
            _validate_repo_url("../../../etc/passwd")

    def test_shell_metachar_in_url(self):
        """Shell metacharacters must be rejected."""
        with pytest.raises(ValueError):
            _validate_repo_url("https://github.com/org/repo;rm -rf /")

    def test_newline_in_url(self):
        with pytest.raises(ValueError):
            _validate_repo_url("https://github.com/org/repo\nrm -rf /")

    def test_null_byte(self):
        with pytest.raises(ValueError):
            _validate_repo_url("https://github.com/org/repo\x00evil")


# ---------------------------------------------------------------------------
# _validate_repo_url — safe inputs that MUST be accepted
# ---------------------------------------------------------------------------

class TestRepoUrlAccepted:
    """All of these must NOT raise."""

    def test_https_github(self):
        _validate_repo_url("https://github.com/org/repo.git")

    def test_https_no_dot_git(self):
        _validate_repo_url("https://github.com/org/repo")

    def test_https_trailing_slash(self):
        _validate_repo_url("https://github.com/org/repo/")

    def test_https_gitlab(self):
        _validate_repo_url("https://gitlab.com/namespace/project.git")

    def test_https_with_port(self):
        _validate_repo_url("https://git.internal.example.com:8443/org/repo.git")

    def test_https_with_credentials(self):
        """Token-auth URL (credentials embedded)."""
        _validate_repo_url("https://token:x-oauth-basic@github.com/org/repo.git")

    def test_http_fallback(self):
        """http:// is allowed (some internal mirrors don't have TLS)."""
        _validate_repo_url("http://git.internal.corp/org/repo.git")

    def test_https_deep_path(self):
        _validate_repo_url("https://github.com/very/deep/nested/path/repo.git")


# ---------------------------------------------------------------------------
# _validate_repo_branch — dangerous inputs that MUST be rejected
# ---------------------------------------------------------------------------

class TestRepoBranchRejected:
    """All of these must raise ValueError."""

    def test_empty_branch(self):
        with pytest.raises(ValueError, match="must not be empty"):
            _validate_repo_branch("")

    def test_leading_dash_flag_injection(self):
        """A branch starting with - would be treated as a git option."""
        with pytest.raises(ValueError, match="must not start with"):
            _validate_repo_branch("-f")

    def test_double_dash_option(self):
        with pytest.raises(ValueError, match="must not start with"):
            _validate_repo_branch("--force")

    def test_shell_semicolon(self):
        with pytest.raises(ValueError):
            _validate_repo_branch("main;rm -rf /")

    def test_shell_backtick(self):
        with pytest.raises(ValueError):
            _validate_repo_branch("main`id`")

    def test_shell_dollar(self):
        with pytest.raises(ValueError):
            _validate_repo_branch("main$(id)")

    def test_space_in_branch(self):
        with pytest.raises(ValueError):
            _validate_repo_branch("feature branch")

    def test_newline(self):
        with pytest.raises(ValueError):
            _validate_repo_branch("main\nevil")

    def test_null_byte(self):
        with pytest.raises(ValueError):
            _validate_repo_branch("main\x00evil")

    def test_too_long(self):
        with pytest.raises(ValueError):
            _validate_repo_branch("a" * 201)


# ---------------------------------------------------------------------------
# _validate_repo_branch — safe inputs that MUST be accepted
# ---------------------------------------------------------------------------

class TestRepoBranchAccepted:
    """All of these must NOT raise."""

    def test_main(self):
        _validate_repo_branch("main")

    def test_master(self):
        _validate_repo_branch("master")

    def test_feature_slash(self):
        _validate_repo_branch("feature/my-feature")

    def test_release_tag(self):
        _validate_repo_branch("release/1.2.3")

    def test_hotfix(self):
        _validate_repo_branch("hotfix/fix-auth-bug")

    def test_numeric(self):
        _validate_repo_branch("v2.0.0")

    def test_underscore(self):
        _validate_repo_branch("my_branch_name")

    def test_dotted(self):
        _validate_repo_branch("refs/heads/main")

    def test_max_length(self):
        _validate_repo_branch("a" * 200)


# ---------------------------------------------------------------------------
# CodeRepoAgent construction: bad inputs raise at __init__ time
# ---------------------------------------------------------------------------

class TestCodeRepoAgentConstructionValidation:
    """Confirm the agent rejects bad inputs at construction, not at clone time."""

    def _make_config(self):
        from agents.core.agent_framework import AgentConfig, AgentType
        return AgentConfig(
            agent_id="test-agent",
            agent_type=AgentType.DESIGN_TIME,
            name="Test Agent",
        )

    def test_bad_url_raises_at_construction(self):
        from agents.design_time.code_repo_agent import CodeRepoAgent
        with pytest.raises(ValueError):
            CodeRepoAgent(
                config=self._make_config(),
                fixops_api_url="http://localhost:8000",
                fixops_api_key="test",
                repo_url="ext::sh -c 'id'",
                repo_branch="main",
            )

    def test_bad_branch_raises_at_construction(self):
        from agents.design_time.code_repo_agent import CodeRepoAgent
        with pytest.raises(ValueError):
            CodeRepoAgent(
                config=self._make_config(),
                fixops_api_url="http://localhost:8000",
                fixops_api_key="test",
                repo_url="https://github.com/org/repo.git",
                repo_branch="--force",
            )

    def test_good_inputs_construct_ok(self):
        from agents.design_time.code_repo_agent import CodeRepoAgent
        agent = CodeRepoAgent(
            config=self._make_config(),
            fixops_api_url="http://localhost:8000",
            fixops_api_key="test",
            repo_url="https://github.com/org/repo.git",
            repo_branch="main",
        )
        assert agent.repo_url == "https://github.com/org/repo.git"
        assert agent.repo_branch == "main"
