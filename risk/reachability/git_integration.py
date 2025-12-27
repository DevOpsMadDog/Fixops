"""Git repository integration for reachability analysis."""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Mapping, Optional
from urllib.parse import urlparse, urlunparse

logger = logging.getLogger(__name__)


@dataclass
class GitRepository:
    """Represents a Git repository for analysis."""

    url: str
    branch: str = "main"
    commit: Optional[str] = None
    local_path: Optional[Path] = None
    auth_token: Optional[str] = None
    auth_username: Optional[str] = None
    auth_password: Optional[str] = None

    def __post_init__(self):
        """Validate repository URL."""
        if not self.url:
            raise ValueError("Repository URL is required")

        # Normalize URL - but preserve file:// URLs for local repos
        if not self.url.startswith(
            ("http://", "https://", "git@", "git://", "file://")
        ):
            # Assume it's a GitHub-style URL
            if "/" in self.url and "@" not in self.url:
                self.url = f"https://github.com/{self.url}.git"
            else:
                self.url = f"https://github.com/{self.url}"


@dataclass
class RepositoryMetadata:
    """Metadata about a cloned repository."""

    url: str
    branch: str
    commit: str
    commit_message: str
    commit_author: str
    commit_date: str
    file_count: int
    language_distribution: Dict[str, int]
    total_lines: int


class GitRepositoryAnalyzer:
    """Enterprise-grade Git repository analyzer for reachability analysis."""

    def __init__(
        self,
        workspace_dir: Optional[Path] = None,
        cache_dir: Optional[Path] = None,
        config: Optional[Mapping[str, Any]] = None,
    ):
        """Initialize Git repository analyzer.

        Parameters
        ----------
        workspace_dir
            Directory for cloning repositories. If None, uses temp directory.
        cache_dir
            Directory for caching cloned repositories. If None, uses workspace_dir.
        config
            Configuration options for Git operations.
        """
        self.config = config or {}
        self.workspace_dir = (
            workspace_dir or Path(tempfile.gettempdir()) / "fixops_repos"
        )
        self.cache_dir = cache_dir or self.workspace_dir / "cache"
        self.workspace_dir.mkdir(parents=True, exist_ok=True)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        self.max_repo_size_mb = self.config.get("max_repo_size_mb", 500)
        self.clone_timeout_seconds = self.config.get("clone_timeout_seconds", 300)
        self.cleanup_after_analysis = self.config.get("cleanup_after_analysis", False)
        self.enable_caching = self.config.get("enable_caching", True)

        # Track cloned repositories
        self._cloned_repos: Dict[str, Path] = {}

    def clone_repository(
        self,
        repository: GitRepository,
        force_refresh: bool = False,
    ) -> Path:
        """Clone a Git repository for analysis.

        Parameters
        ----------
        repository
            Repository configuration.
        force_refresh
            If True, re-clone even if cached.

        Returns
        -------
        Path
            Path to cloned repository.
        """
        # Handle file:// URLs - these are local paths, no cloning needed
        if repository.url.startswith("file://"):
            # Use urlparse for proper file:// URL parsing instead of fragile string replace
            # This correctly handles file://localhost/path and file:///path formats
            parsed_url = urlparse(repository.url)
            local_path = Path(parsed_url.path)
            if not local_path.exists():
                raise RuntimeError(
                    f"Local repository path does not exist: {local_path}"
                )
            if not (local_path / ".git").exists():
                raise RuntimeError(f"Not a Git repository: {local_path}")
            logger.info(f"Using local repository: {local_path}")
            self._cloned_repos[repository.url] = local_path
            return local_path

        # Generate cache key
        cache_key = self._generate_cache_key(repository)
        cached_path = self.cache_dir / cache_key

        # Check cache
        if (
            self.enable_caching
            and not force_refresh
            and cached_path.exists()
            and (cached_path / ".git").exists()
        ):
            logger.info(f"Using cached repository: {cached_path}")
            self._cloned_repos[repository.url] = cached_path
            return cached_path

        # Clone to temporary location first
        temp_path = self.workspace_dir / f"temp_{cache_key}"

        try:
            # Prepare clone command
            clone_url = self._prepare_clone_url(repository)

            # Clone repository
            logger.info(
                f"Cloning repository: {repository.url} (branch: {repository.branch})"
            )

            clone_cmd = [
                "git",
                "clone",
                "--depth",
                "1",  # Shallow clone for speed
                "--branch",
                repository.branch,
                clone_url,
                str(temp_path),
            ]

            # Add authentication if provided
            env = os.environ.copy()
            if repository.auth_token:
                parsed_url = urlparse(repository.url)
                hostname = parsed_url.hostname or ""
                # Use exact hostname matching to prevent URL injection attacks
                if hostname == "github.com" or hostname.endswith(".github.com"):
                    creds = repository.auth_token
                elif hostname == "gitlab.com" or hostname.endswith(".gitlab.com"):
                    creds = f"oauth2:{repository.auth_token}"
                else:
                    # For unsupported hosts, don't inject credentials
                    creds = None

                if creds:
                    # Reconstruct URL with credentials while preserving path
                    new_netloc = f"{creds}@{parsed_url.netloc}"
                    clone_cmd[6] = urlunparse(parsed_url._replace(netloc=new_netloc))

            # Execute clone
            result = subprocess.run(
                clone_cmd,
                capture_output=True,
                text=True,
                timeout=self.clone_timeout_seconds,
                env=env,
            )

            if result.returncode != 0:
                raise RuntimeError(
                    f"Git clone failed: {result.stderr}\nCommand: {' '.join(clone_cmd)}"
                )

            # Check repository size
            repo_size_mb = self._get_directory_size(temp_path) / (1024 * 1024)
            if repo_size_mb > self.max_repo_size_mb:
                raise ValueError(
                    f"Repository size ({repo_size_mb:.1f} MB) exceeds limit "
                    f"({self.max_repo_size_mb} MB)"
                )

            # Checkout specific commit if provided
            if repository.commit:
                logger.info(f"Checking out commit: {repository.commit}")
                subprocess.run(
                    ["git", "checkout", repository.commit],
                    cwd=temp_path,
                    check=True,
                    capture_output=True,
                )

            # Move to cache if enabled
            if self.enable_caching:
                if cached_path.exists():
                    shutil.rmtree(cached_path)
                shutil.move(str(temp_path), str(cached_path))
                final_path = cached_path
            else:
                final_path = temp_path

            self._cloned_repos[repository.url] = final_path
            logger.info(f"Repository cloned successfully: {final_path}")

            return final_path

        except subprocess.TimeoutExpired:
            if temp_path.exists():
                shutil.rmtree(temp_path, ignore_errors=True)
            raise RuntimeError(
                f"Git clone timed out after {self.clone_timeout_seconds} seconds"
            )
        except Exception as e:
            if temp_path.exists():
                shutil.rmtree(temp_path, ignore_errors=True)
            logger.error(f"Failed to clone repository: {e}")
            raise

    def get_repository_metadata(self, repo_path: Path) -> RepositoryMetadata:
        """Extract metadata from a cloned repository.

        Parameters
        ----------
        repo_path
            Path to cloned repository.

        Returns
        -------
        RepositoryMetadata
            Repository metadata.
        """
        if not (repo_path / ".git").exists():
            raise ValueError(f"Not a Git repository: {repo_path}")

        # Get commit info
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()

        commit_message = subprocess.run(
            ["git", "log", "-1", "--pretty=%s"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()

        commit_author = subprocess.run(
            ["git", "log", "-1", "--pretty=%an"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()

        commit_date = subprocess.run(
            ["git", "log", "-1", "--pretty=%ai"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()

        # Get branch
        branch = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()

        # Get remote URL
        try:
            remote_url = subprocess.run(
                ["git", "config", "--get", "remote.origin.url"],
                cwd=repo_path,
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
        except subprocess.CalledProcessError:
            remote_url = "unknown"

        # Analyze file distribution
        file_count, language_dist, total_lines = self._analyze_repository_structure(
            repo_path
        )

        return RepositoryMetadata(
            url=remote_url,
            branch=branch,
            commit=commit,
            commit_message=commit_message,
            commit_author=commit_author,
            commit_date=commit_date,
            file_count=file_count,
            language_distribution=language_dist,
            total_lines=total_lines,
        )

    def _analyze_repository_structure(
        self, repo_path: Path
    ) -> tuple[int, Dict[str, int], int]:
        """Analyze repository structure and language distribution."""
        file_count = 0
        language_dist: Dict[str, int] = {}
        total_lines = 0

        # Language extensions mapping
        lang_extensions = {
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

        # Ignore patterns
        ignore_patterns = {
            ".git",
            "node_modules",
            "vendor",
            "__pycache__",
            ".venv",
            "venv",
            "target",
            "build",
            "dist",
            ".gradle",
        }

        for root, dirs, files in os.walk(repo_path):
            # Filter ignored directories
            dirs[:] = [d for d in dirs if d not in ignore_patterns]

            for file in files:
                file_path = Path(root) / file
                rel_path = file_path.relative_to(repo_path)

                # Skip ignored files
                if any(part in ignore_patterns for part in rel_path.parts):
                    continue

                file_count += 1
                ext = file_path.suffix.lower()

                if ext in lang_extensions:
                    lang = lang_extensions[ext]
                    language_dist[lang] = language_dist.get(lang, 0) + 1

                # Count lines (for supported languages)
                if ext in lang_extensions:
                    try:
                        with open(file_path, "rb") as f:
                            lines = sum(1 for _ in f)
                            total_lines += lines
                    except Exception:
                        pass

        return file_count, language_dist, total_lines

    def _generate_cache_key(self, repository: GitRepository) -> str:
        """Generate cache key for repository."""
        import hashlib

        key_parts = [
            repository.url,
            repository.branch,
            repository.commit or "HEAD",
        ]
        key_string = "|".join(key_parts)
        return hashlib.sha256(key_string.encode()).hexdigest()[:16]

    def _prepare_clone_url(self, repository: GitRepository) -> str:
        """Prepare clone URL with authentication if needed.

        Uses proper URL parsing to prevent injection attacks and preserve
        the full URL path, query string, and fragment.
        """
        parsed = urlparse(repository.url)
        hostname = parsed.hostname or ""

        # Handle token-based authentication
        if repository.auth_token:
            # Use exact hostname matching to prevent URL injection attacks
            if hostname == "github.com" or hostname.endswith(".github.com"):
                creds = repository.auth_token
            elif hostname == "gitlab.com" or hostname.endswith(".gitlab.com"):
                creds = f"oauth2:{repository.auth_token}"
            else:
                # For unsupported hosts, return URL without credentials
                return repository.url

            # Reconstruct URL with credentials while preserving path
            new_netloc = f"{creds}@{parsed.netloc}"
            return urlunparse(parsed._replace(netloc=new_netloc))

        # Handle username/password authentication
        elif repository.auth_username and repository.auth_password:
            # Reconstruct URL with credentials while preserving path
            auth_string = f"{repository.auth_username}:{repository.auth_password}"
            new_netloc = f"{auth_string}@{parsed.netloc}"
            return urlunparse(parsed._replace(netloc=new_netloc))

        return repository.url

    def _get_directory_size(self, path: Path) -> int:
        """Calculate total size of directory in bytes."""
        total = 0
        try:
            for entry in os.scandir(path):
                if entry.is_file():
                    total += entry.stat().st_size
                elif entry.is_dir() and entry.name != ".git":
                    total += self._get_directory_size(Path(entry.path))
        except (OSError, PermissionError):
            pass
        return total

    def cleanup_repository(self, repository: GitRepository) -> None:
        """Clean up cloned repository."""
        if repository.url in self._cloned_repos:
            repo_path = self._cloned_repos[repository.url]

            # Only cleanup if not cached or if cleanup is forced
            if not self.enable_caching or self.cleanup_after_analysis:
                if repo_path.exists():
                    logger.info(f"Cleaning up repository: {repo_path}")
                    shutil.rmtree(repo_path, ignore_errors=True)

            del self._cloned_repos[repository.url]

    def cleanup_all(self) -> None:
        """Clean up all cloned repositories."""
        for repo_url in list(self._cloned_repos.keys()):
            repo_path = self._cloned_repos[repo_url]
            if repo_path.exists() and not self.enable_caching:
                shutil.rmtree(repo_path, ignore_errors=True)
        self._cloned_repos.clear()

    def get_cloned_path(self, repository: GitRepository) -> Optional[Path]:
        """Get path to cloned repository if already cloned."""
        return self._cloned_repos.get(repository.url)
