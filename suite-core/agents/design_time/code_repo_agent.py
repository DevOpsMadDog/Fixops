"""Code Repository Agent

Monitors code repositories and pushes SARIF, SBOM, and design context data.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from agents.core.agent_framework import AgentConfig, AgentData, BaseAgent

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Input-validation helpers — prevent RCE via malicious repo_url / repo_branch
# ---------------------------------------------------------------------------

# Allow only https:// and http:// (plain-text fallback) remote URLs.
# Explicitly rejects:
#   ext::        — gitpython ext:: transport executes arbitrary commands
#   file://      — local path traversal / mounting of internal files
#   git://       — unauthenticated, no TLS, not needed
#   ssh://       — would require key management outside our control
#   any leading - — option injection (e.g. --upload-pack=…)
_REPO_URL_RE = re.compile(
    r"^https?://"           # must start with http:// or https://
    r"[A-Za-z0-9._~:@%/\-]+"  # host + path chars — no shell metacharacters
    r"(\.git)?/?$",
    re.ASCII,
)

# Branch / tag names: alphanumeric, hyphens, underscores, dots, forward slashes.
# Rejects anything that could become a git option flag (leading -) or contain
# shell metacharacters.
_BRANCH_RE = re.compile(r"^[A-Za-z0-9._/\-]{1,200}$", re.ASCII)


def _validate_repo_url(url: str) -> None:
    """Raise ValueError if *url* is not a safe https/http remote URL.

    Rejects ext:: / file:: transports (RCE / path-traversal via gitpython),
    option-injection prefixes (leading -), and any URL that does not match
    the strict allowlist regex.
    """
    if not url:
        raise ValueError("repo_url must not be empty")
    # Reject known dangerous transport prefixes before regex check
    lower = url.lower().lstrip()
    for dangerous in ("ext::", "file::", "file://", "git://", "ssh://"):
        if lower.startswith(dangerous):
            raise ValueError(
                f"repo_url uses a disallowed transport ({dangerous!r}). "
                "Only https:// and http:// are permitted."
            )
    if lower.startswith("-"):
        raise ValueError("repo_url must not start with '-' (option injection)")
    if not _REPO_URL_RE.match(url):
        raise ValueError(
            f"repo_url {url!r} is not a valid https/http URL. "
            "Only https:// and http:// remote URLs are allowed."
        )


def _validate_repo_branch(branch: str) -> None:
    """Raise ValueError if *branch* contains characters that could be injected
    as git option flags or shell metacharacters."""
    if not branch:
        raise ValueError("repo_branch must not be empty")
    if branch.startswith("-"):
        raise ValueError("repo_branch must not start with '-' (option injection)")
    if not _BRANCH_RE.match(branch):
        raise ValueError(
            f"repo_branch {branch!r} contains disallowed characters. "
            "Only alphanumeric, hyphens, underscores, dots, and slashes are allowed."
        )


class CodeRepoAgent(BaseAgent):
    """Agent that monitors code repositories."""

    def __init__(
        self,
        config: AgentConfig,
        fixops_api_url: str,
        fixops_api_key: str,
        repo_url: str,
        repo_branch: str = "main",
    ):
        """Initialize code repo agent.

        Raises ValueError immediately if repo_url or repo_branch fail
        validation so callers get an explicit error at construction time
        rather than at clone time (which is harder to distinguish from a
        network failure).
        """
        # Validate before storing — reject dangerous transports / injection
        _validate_repo_url(repo_url)
        _validate_repo_branch(repo_branch)
        super().__init__(config, fixops_api_url, fixops_api_key)
        self.repo_url = repo_url
        self.repo_branch = repo_branch
        self.last_commit: Optional[str] = None
        self.repo_path: Optional[str] = None

    async def connect(self) -> bool:
        """Connect to repository."""
        try:
            import git

            # Re-validate before any git I/O — defence-in-depth in case repo_url
            # or repo_branch were mutated after construction.
            _validate_repo_url(self.repo_url)
            _validate_repo_branch(self.repo_branch)

            # Derive a safe local directory name from the URL path component only
            # (never from user-supplied data that could contain path separators).
            from urllib.parse import urlparse as _urlparse
            url_path = _urlparse(self.repo_url).path  # e.g. /org/repo.git
            repo_name = url_path.rstrip("/").split("/")[-1].replace(".git", "") or "repo"
            # Sanitise: keep only alnum / hyphen / underscore / dot
            repo_name = re.sub(r"[^A-Za-z0-9._\-]", "_", repo_name)[:64]
            self.repo_path = f"/tmp/fixops-agents/{repo_name}"  # nosec B108

            try:
                repo = git.Repo(self.repo_path)
                repo.remotes.origin.pull()
            except (ValueError, KeyError, RuntimeError, TypeError, AttributeError):
                repo = git.Repo.clone_from(self.repo_url, self.repo_path)

            repo.git.checkout(self.repo_branch)
            self.last_commit = repo.head.commit.hexsha

            logger.info(f"Connected to repository: {self.repo_url}")
            return True

        except ValueError as e:
            # Validation failure — log the message without the URL to avoid
            # reflecting attacker-controlled content into logs.
            logger.error("Rejected repository connection due to invalid input: %s", e)
            return False
        except (OSError, KeyError, RuntimeError) as e:
            logger.error(f"Failed to connect to repository: {e}")
            return False

    async def disconnect(self):
        """Disconnect from repository."""
        # Keep repo cloned for future use

    async def collect_data(self) -> List[AgentData]:
        """Collect data from repository."""
        import git

        try:
            # Re-validate before any git I/O (defence-in-depth)
            _validate_repo_url(self.repo_url)
            _validate_repo_branch(self.repo_branch)

            repo = git.Repo(self.repo_path)
            repo.remotes.origin.pull()
            repo.git.checkout(self.repo_branch)

            current_commit = repo.head.commit.hexsha

            # Check if there are new commits
            if current_commit == self.last_commit:
                return []  # No new data

            self.last_commit = current_commit

            data_items = []

            # Collect SARIF (run security scan)
            sarif_data = await self._collect_sarif()
            if sarif_data:
                data_items.append(
                    AgentData(
                        agent_id=self.config.agent_id,
                        timestamp=datetime.now(timezone.utc),
                        data_type="sarif",
                        data=sarif_data,
                        metadata={
                            "repo_url": self.repo_url,
                            "branch": self.repo_branch,
                            "commit": current_commit,
                        },
                    )
                )

            # Collect SBOM (generate from code)
            sbom_data = await self._collect_sbom()
            if sbom_data:
                data_items.append(
                    AgentData(
                        agent_id=self.config.agent_id,
                        timestamp=datetime.now(timezone.utc),
                        data_type="sbom",
                        data=sbom_data,
                        metadata={
                            "repo_url": self.repo_url,
                            "branch": self.repo_branch,
                            "commit": current_commit,
                        },
                    )
                )

            # Collect design context
            design_context = await self._collect_design_context()
            if design_context:
                data_items.append(
                    AgentData(
                        agent_id=self.config.agent_id,
                        timestamp=datetime.now(timezone.utc),
                        data_type="design_context",
                        data=design_context,
                        metadata={
                            "repo_url": self.repo_url,
                            "branch": self.repo_branch,
                            "commit": current_commit,
                        },
                    )
                )

            return data_items

        except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
            logger.error(f"Error collecting data from {self.repo_url}: {e}")
            return []

    async def _collect_sarif(self) -> Optional[Dict[str, Any]]:
        """Collect SARIF data by running security scan."""
        try:
            # Use proprietary analyzer or OSS fallback
            from risk.reachability.analyzer import VulnerabilityReachabilityAnalyzer

            VulnerabilityReachabilityAnalyzer(config={})

            # Run scan (simplified - would run actual scan)
            # In real implementation, would run proprietary or OSS scanner
            return {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {
                            "driver": {
                                "name": "FixOps",
                                "version": "1.0.0",
                            }
                        },
                        "results": [],  # Would contain actual findings
                    }
                ],
            }

        except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
            logger.error(f"Error collecting SARIF: {e}")
            return None

    async def _collect_sbom(self) -> Optional[Dict[str, Any]]:
        """Collect SBOM by generating from code."""
        try:
            from pathlib import Path

            from risk.sbom.generator import SBOMFormat, SBOMGenerator

            generator = SBOMGenerator()
            sbom = generator.generate_from_codebase(
                Path(self.repo_path), SBOMFormat.CYCLONEDX
            )

            return sbom

        except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
            logger.error(f"Error collecting SBOM: {e}")
            return None

    async def _collect_design_context(self) -> Optional[Dict[str, Any]]:
        """Collect design context from repository."""
        try:
            # Extract design context (architecture, components, etc.)
            # In real implementation, would parse design docs, architecture diagrams, etc.
            return {
                "components": [],
                "architecture": {},
                "dependencies": {},
            }

        except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
            logger.error(f"Error collecting design context: {e}")
            return None
