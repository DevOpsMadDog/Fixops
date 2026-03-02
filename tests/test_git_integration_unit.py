"""Comprehensive unit tests for suite-evidence-risk/risk/reachability/git_integration.py.

Tests cover:
- GitRepository dataclass validation and URL normalization
- RepositoryMetadata dataclass
- GitRepositoryAnalyzer: init, caching, clone logic, metadata extraction, cleanup

Pillar: V5 (MPTE Verification) — Git integration enables code reachability analysis
"""

import os
import subprocess
import tempfile
from pathlib import Path

import pytest

from risk.reachability.git_integration import (
    GitRepository,
    GitRepositoryAnalyzer,
    RepositoryMetadata,
)


# ── GitRepository dataclass ─────────────────────────────────────────


class TestGitRepository:
    """Tests for GitRepository dataclass."""

    def test_create_with_https_url(self):
        repo = GitRepository(url="https://github.com/org/repo.git")
        assert repo.url == "https://github.com/org/repo.git"
        assert repo.branch == "main"
        assert repo.commit is None
        assert repo.local_path is None
        assert repo.auth_token is None

    def test_create_with_ssh_url(self):
        repo = GitRepository(url="git@github.com:org/repo.git")
        assert repo.url == "git@github.com:org/repo.git"

    def test_create_with_git_protocol(self):
        repo = GitRepository(url="git://github.com/org/repo.git")
        assert repo.url == "git://github.com/org/repo.git"

    def test_create_with_file_url(self):
        repo = GitRepository(url="file:///tmp/my-repo")
        assert repo.url == "file:///tmp/my-repo"

    def test_short_github_url_normalized(self):
        repo = GitRepository(url="org/repo")
        assert "github.com" in repo.url

    def test_empty_url_raises(self):
        with pytest.raises(ValueError, match="Repository URL is required"):
            GitRepository(url="")

    def test_custom_branch(self):
        repo = GitRepository(url="https://github.com/org/repo.git", branch="develop")
        assert repo.branch == "develop"

    def test_with_commit(self):
        repo = GitRepository(
            url="https://github.com/org/repo.git", commit="abc123def456"
        )
        assert repo.commit == "abc123def456"

    def test_with_auth_token(self):
        repo = GitRepository(
            url="https://github.com/org/repo.git",
            auth_token="ghp_token123",
        )
        assert repo.auth_token == "ghp_token123"

    def test_with_auth_username_password(self):
        repo = GitRepository(
            url="https://github.com/org/repo.git",
            auth_username="user",
            auth_password="pass",
        )
        assert repo.auth_username == "user"
        assert repo.auth_password == "pass"

    def test_http_url_preserved(self):
        repo = GitRepository(url="http://internal.example.com/repo.git")
        assert repo.url == "http://internal.example.com/repo.git"


# ── RepositoryMetadata dataclass ────────────────────────────────────


class TestRepositoryMetadata:
    """Tests for RepositoryMetadata dataclass."""

    def test_create(self):
        meta = RepositoryMetadata(
            url="https://github.com/org/repo.git",
            branch="main",
            commit="abc123",
            commit_message="Initial commit",
            commit_author="Author Name",
            commit_date="2026-01-01 00:00:00 +0000",
            file_count=100,
            language_distribution={"Python": 50, "JavaScript": 30},
            total_lines=5000,
        )
        assert meta.url == "https://github.com/org/repo.git"
        assert meta.branch == "main"
        assert meta.commit == "abc123"
        assert meta.file_count == 100
        assert meta.total_lines == 5000
        assert meta.language_distribution["Python"] == 50

    def test_empty_language_distribution(self):
        meta = RepositoryMetadata(
            url="u",
            branch="b",
            commit="c",
            commit_message="m",
            commit_author="a",
            commit_date="d",
            file_count=0,
            language_distribution={},
            total_lines=0,
        )
        assert meta.language_distribution == {}
        assert meta.file_count == 0


# ── GitRepositoryAnalyzer ───────────────────────────────────────────


class TestGitRepositoryAnalyzerInit:
    """Tests for GitRepositoryAnalyzer initialization."""

    def test_default_init(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            analyzer = GitRepositoryAnalyzer(workspace_dir=Path(tmpdir))
            assert analyzer.workspace_dir == Path(tmpdir)
            assert analyzer.cache_dir == Path(tmpdir) / "cache"
            assert analyzer.max_repo_size_mb == 500
            assert analyzer.clone_timeout_seconds == 300
            assert analyzer.cleanup_after_analysis is False
            assert analyzer.enable_caching is True

    def test_custom_config(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config = {
                "max_repo_size_mb": 100,
                "clone_timeout_seconds": 60,
                "cleanup_after_analysis": True,
                "enable_caching": False,
            }
            analyzer = GitRepositoryAnalyzer(
                workspace_dir=Path(tmpdir),
                config=config,
            )
            assert analyzer.max_repo_size_mb == 100
            assert analyzer.clone_timeout_seconds == 60
            assert analyzer.cleanup_after_analysis is True
            assert analyzer.enable_caching is False

    def test_creates_directories(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ws = Path(tmpdir) / "new_workspace"
            GitRepositoryAnalyzer(workspace_dir=ws)
            assert ws.exists()
            assert (ws / "cache").exists()

    def test_custom_cache_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = Path(tmpdir) / "custom_cache"
            analyzer = GitRepositoryAnalyzer(
                workspace_dir=Path(tmpdir),
                cache_dir=cache,
            )
            assert analyzer.cache_dir == cache
            assert cache.exists()


class TestGitRepositoryAnalyzerClone:
    """Tests for clone functionality."""

    def test_clone_local_file_url(self):
        """Test cloning from a file:// URL (local repository)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a real git repo
            repo_path = Path(tmpdir) / "local_repo"
            repo_path.mkdir()
            subprocess.run(
                ["git", "init"],
                cwd=repo_path,
                capture_output=True,
                check=True,
            )
            # Create a file and commit
            (repo_path / "README.md").write_text("# Test")
            subprocess.run(
                ["git", "add", "."],
                cwd=repo_path,
                capture_output=True,
                check=True,
            )
            subprocess.run(
                ["git", "commit", "-m", "init"],
                cwd=repo_path,
                capture_output=True,
                check=True,
                env={**os.environ, "GIT_AUTHOR_NAME": "Test", "GIT_AUTHOR_EMAIL": "t@t.com",
                     "GIT_COMMITTER_NAME": "Test", "GIT_COMMITTER_EMAIL": "t@t.com"},
            )

            analyzer = GitRepositoryAnalyzer(
                workspace_dir=Path(tmpdir) / "workspace"
            )
            repo = GitRepository(url=f"file://{repo_path}")
            cloned_path = analyzer.clone_repository(repo)
            assert cloned_path == repo_path
            assert (cloned_path / ".git").exists()

    def test_clone_local_nonexistent_raises(self):
        """Test that cloning a non-existent local path raises."""
        with tempfile.TemporaryDirectory() as tmpdir:
            analyzer = GitRepositoryAnalyzer(
                workspace_dir=Path(tmpdir) / "workspace"
            )
            repo = GitRepository(url="file:///nonexistent/path")
            with pytest.raises(RuntimeError, match="does not exist"):
                analyzer.clone_repository(repo)

    def test_clone_local_not_git_repo_raises(self):
        """Test that a local path without .git raises."""
        with tempfile.TemporaryDirectory() as tmpdir:
            not_a_repo = Path(tmpdir) / "not_a_repo"
            not_a_repo.mkdir()
            analyzer = GitRepositoryAnalyzer(
                workspace_dir=Path(tmpdir) / "workspace"
            )
            repo = GitRepository(url=f"file://{not_a_repo}")
            with pytest.raises(RuntimeError, match="Not a Git repository"):
                analyzer.clone_repository(repo)

    def test_clone_caching(self):
        """Test that cached repos are reused."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a local git repo
            repo_path = Path(tmpdir) / "local_repo"
            repo_path.mkdir()
            subprocess.run(
                ["git", "init"],
                cwd=repo_path,
                capture_output=True,
                check=True,
            )
            (repo_path / "README.md").write_text("# Test")
            subprocess.run(
                ["git", "add", "."],
                cwd=repo_path,
                capture_output=True,
                check=True,
            )
            subprocess.run(
                ["git", "commit", "-m", "init"],
                cwd=repo_path,
                capture_output=True,
                check=True,
                env={**os.environ, "GIT_AUTHOR_NAME": "Test", "GIT_AUTHOR_EMAIL": "t@t.com",
                     "GIT_COMMITTER_NAME": "Test", "GIT_COMMITTER_EMAIL": "t@t.com"},
            )

            analyzer = GitRepositoryAnalyzer(
                workspace_dir=Path(tmpdir) / "workspace"
            )
            repo = GitRepository(url=f"file://{repo_path}")
            # Clone twice - second should use cache
            path1 = analyzer.clone_repository(repo)
            path2 = analyzer.clone_repository(repo)
            # file:// URLs return directly, so same path
            assert path1 == path2


class TestGitRepositoryAnalyzerMetadata:
    """Tests for metadata extraction from real git repos."""

    def test_get_metadata(self):
        """Test metadata extraction from the current repo."""
        # Use the actual Fixops repo we're in
        repo_path = Path("/Users/devops.ai/developement/fixops/Fixops")
        if not (repo_path / ".git").exists():
            pytest.skip("Not in a git repo")

        analyzer = GitRepositoryAnalyzer()
        meta = analyzer.get_repository_metadata(repo_path)
        assert isinstance(meta, RepositoryMetadata)
        assert len(meta.commit) >= 7  # Git short hash minimum
        assert meta.file_count > 0
        assert meta.total_lines > 0
        assert "Python" in meta.language_distribution

    def test_get_metadata_not_git_repo(self):
        """Test that non-git directory raises."""
        with tempfile.TemporaryDirectory() as tmpdir:
            analyzer = GitRepositoryAnalyzer()
            with pytest.raises(ValueError, match="Not a Git repository"):
                analyzer.get_repository_metadata(Path(tmpdir))


class TestAnalyzeRepositoryStructure:
    """Tests for _analyze_repository_structure."""

    def test_analyze_structure(self):
        """Test repository structure analysis."""
        with tempfile.TemporaryDirectory() as tmpdir:
            repo_path = Path(tmpdir)
            # Create some test files
            (repo_path / "main.py").write_text("# Python file\nprint('hello')\n")
            (repo_path / "app.js").write_text("// JS file\nconsole.log('hi');\n")
            (repo_path / "README.md").write_text("# Readme\n")
            # Create .git to be ignored
            (repo_path / ".git").mkdir()
            (repo_path / ".git" / "config").write_text("git config")

            analyzer = GitRepositoryAnalyzer()
            file_count, lang_dist, total_lines = analyzer._analyze_repository_structure(
                repo_path
            )
            assert file_count >= 2  # At least py and js
            assert "Python" in lang_dist
            assert "JavaScript" in lang_dist
            assert total_lines >= 4

    def test_analyze_structure_with_subdirs(self):
        """Test structure analysis with nested directories."""
        with tempfile.TemporaryDirectory() as tmpdir:
            repo_path = Path(tmpdir)
            src = repo_path / "src"
            src.mkdir()
            (src / "app.py").write_text("x = 1\n")
            (src / "helper.py").write_text("y = 2\nz = 3\n")
            # node_modules should be ignored
            nm = repo_path / "node_modules"
            nm.mkdir()
            (nm / "pkg.js").write_text("ignored")

            analyzer = GitRepositoryAnalyzer()
            file_count, lang_dist, total_lines = analyzer._analyze_repository_structure(
                repo_path
            )
            assert lang_dist.get("Python", 0) == 2
            assert total_lines >= 3

    def test_analyze_empty_directory(self):
        """Test with empty directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            analyzer = GitRepositoryAnalyzer()
            file_count, lang_dist, total_lines = analyzer._analyze_repository_structure(
                Path(tmpdir)
            )
            assert file_count == 0
            assert total_lines == 0


class TestGenerateCacheKey:
    """Tests for _generate_cache_key."""

    def test_different_urls_different_keys(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            analyzer = GitRepositoryAnalyzer(workspace_dir=Path(tmpdir))
            repo1 = GitRepository(url="https://github.com/org/repo1.git")
            repo2 = GitRepository(url="https://github.com/org/repo2.git")
            key1 = analyzer._generate_cache_key(repo1)
            key2 = analyzer._generate_cache_key(repo2)
            assert key1 != key2

    def test_same_url_same_key(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            analyzer = GitRepositoryAnalyzer(workspace_dir=Path(tmpdir))
            repo1 = GitRepository(url="https://github.com/org/repo.git")
            repo2 = GitRepository(url="https://github.com/org/repo.git")
            assert analyzer._generate_cache_key(repo1) == analyzer._generate_cache_key(repo2)

    def test_different_branches_different_keys(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            analyzer = GitRepositoryAnalyzer(workspace_dir=Path(tmpdir))
            repo1 = GitRepository(url="https://github.com/org/repo.git", branch="main")
            repo2 = GitRepository(url="https://github.com/org/repo.git", branch="develop")
            key1 = analyzer._generate_cache_key(repo1)
            key2 = analyzer._generate_cache_key(repo2)
            assert key1 != key2


class TestLanguageDetection:
    """Tests for language extension mapping in structure analysis."""

    def test_all_supported_languages(self):
        """Test that all supported language extensions are detected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            repo_path = Path(tmpdir)
            extensions = {
                ".py": "Python",
                ".js": "JavaScript",
                ".ts": "TypeScript",
                ".java": "Java",
                ".go": "Go",
                ".rs": "Rust",
                ".cpp": "C++",
                ".c": "C",
                ".cs": "C#",
                ".rb": "Ruby",
                ".php": "PHP",
                ".swift": "Swift",
                ".kt": "Kotlin",
                ".scala": "Scala",
            }
            for ext, lang in extensions.items():
                (repo_path / f"test{ext}").write_text(f"// {lang} file\n")

            analyzer = GitRepositoryAnalyzer()
            _, lang_dist, _ = analyzer._analyze_repository_structure(repo_path)
            for ext, lang in extensions.items():
                assert lang in lang_dist, f"Missing language: {lang} for extension {ext}"
                assert lang_dist[lang] >= 1

    def test_unsupported_extensions_counted_as_files(self):
        """Test that unsupported extensions count as files but not languages."""
        with tempfile.TemporaryDirectory() as tmpdir:
            repo_path = Path(tmpdir)
            (repo_path / "data.csv").write_text("a,b,c\n")
            (repo_path / "config.yaml").write_text("key: value\n")

            analyzer = GitRepositoryAnalyzer()
            file_count, lang_dist, total_lines = analyzer._analyze_repository_structure(
                repo_path
            )
            assert file_count == 2
            assert total_lines == 0  # Non-lang files don't count lines
