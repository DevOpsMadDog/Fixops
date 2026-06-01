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
        """Collect SARIF data by running a real security scan via semgrep or bandit.

        Falls back to None (not an empty-results skeleton) when no scanner is
        available so callers can distinguish "no scan ran" from "scan ran and
        found nothing".
        """
        import subprocess
        import json as _json
        from pathlib import Path as _Path

        if not self.repo_path or not _Path(self.repo_path).is_dir():
            logger.warning("_collect_sarif: repo_path not set or missing, skipping scan")
            return None

        # Try semgrep first (OWASP rulesets available), then bandit for Python.
        for cmd, tool_name in [
            (
                ["semgrep", "--config", "p/owasp-top-ten", "--json",
                 "--quiet", "--no-git-ignore", self.repo_path],
                "semgrep",
            ),
            (
                ["bandit", "-r", self.repo_path, "-f", "sarif", "-q"],
                "bandit",
            ),
        ]:
            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
                if proc.returncode in (0, 1) and proc.stdout.strip():
                    try:
                        data = _json.loads(proc.stdout)
                        # semgrep --json wraps results; bandit -f sarif emits SARIF directly
                        if tool_name == "semgrep" and "results" in data:
                            # Convert semgrep JSON to minimal SARIF envelope
                            return {
                                "version": "2.1.0",
                                "runs": [{
                                    "tool": {"driver": {"name": "semgrep", "version": "auto"}},
                                    "results": [
                                        {
                                            "ruleId": r.get("check_id", "unknown"),
                                            "message": {"text": r.get("extra", {}).get("message", "")},
                                            "locations": [{
                                                "physicalLocation": {
                                                    "artifactLocation": {"uri": r.get("path", "")},
                                                    "region": {
                                                        "startLine": r.get("start", {}).get("line", 0),
                                                        "endLine": r.get("end", {}).get("line", 0),
                                                    },
                                                }
                                            }],
                                            "level": r.get("extra", {}).get("severity", "warning").lower(),
                                        }
                                        for r in data.get("results", [])
                                    ],
                                }],
                            }
                        # bandit/other SARIF output — validate it has the SARIF version key
                        if isinstance(data, dict) and "runs" in data:
                            return data
                    except (_json.JSONDecodeError, KeyError, TypeError) as parse_err:
                        logger.warning(f"_collect_sarif: {tool_name} output parse error: {parse_err}")
                        continue
            except FileNotFoundError:
                continue  # scanner not installed — try next
            except subprocess.TimeoutExpired:
                logger.warning(f"_collect_sarif: {tool_name} timed out after 120s")
                continue
            except (OSError, ValueError, KeyError, RuntimeError) as e:
                logger.error(f"_collect_sarif: {tool_name} error: {e}")
                continue

        logger.warning(
            "_collect_sarif: no scanner (semgrep/bandit) available — returning None. "
            "Install semgrep or bandit to enable design-time SARIF capture."
        )
        return None

    async def _collect_sbom(self) -> Optional[Dict[str, Any]]:
        """Collect a real CycloneDX SBOM by running ``syft`` on the repo path.

        Requires syft >= 0.80 installed in PATH (or at /opt/homebrew/bin/syft).
        Returns the parsed CycloneDX JSON dict on success, or honest ``None``
        with a warning log when syft is absent or the scan fails.  Never returns
        fabricated component data.
        """
        import json as _json
        import shutil
        import subprocess
        from pathlib import Path

        if not self.repo_path or not Path(self.repo_path).is_dir():
            logger.warning("_collect_sbom: repo_path not set or not a directory — skipping")
            return None

        # Locate syft — prefer PATH, then common Homebrew location.
        syft_bin = shutil.which("syft") or "/opt/homebrew/bin/syft"
        if not shutil.which(syft_bin) and not Path(syft_bin).is_file():
            logger.warning(
                "_collect_sbom: syft not found in PATH or /opt/homebrew/bin/syft — "
                "install syft to enable SBOM capture (https://github.com/anchore/syft)"
            )
            return None

        cmd = [syft_bin, self.repo_path, "-o", "cyclonedx-json", "--quiet"]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
            if proc.returncode != 0:
                logger.warning(
                    "_collect_sbom: syft exited %d for %s: %s",
                    proc.returncode,
                    self.repo_path,
                    proc.stderr[:500],
                )
                return None

            sbom = _json.loads(proc.stdout)
            component_count = len(sbom.get("components", []))
            logger.info(
                "_collect_sbom: syft produced real CycloneDX SBOM with %d components for %s",
                component_count,
                self.repo_path,
            )
            return sbom

        except subprocess.TimeoutExpired:
            logger.warning("_collect_sbom: syft timed out after 120s for %s", self.repo_path)
            return None
        except (_json.JSONDecodeError, OSError, ValueError) as exc:
            logger.error("_collect_sbom: failed to parse syft output: %s", exc)
            return None

    async def _collect_design_context(self) -> Optional[Dict[str, Any]]:
        """Collect design context from the repository.

        Extracts real structural signals from the repo:
        - Component list derived from top-level directories
        - Dependency manifest filenames present
        - IaC / config file presence flags

        Returns None when repo_path is not set rather than returning an empty
        skeleton that looks like a successful scan.
        """
        from pathlib import Path as _Path
        import os as _os

        if not self.repo_path or not _Path(self.repo_path).is_dir():
            logger.warning("_collect_design_context: repo_path not set or missing")
            return None

        try:
            repo_root = _Path(self.repo_path)

            # Top-level directories as component candidates
            components = sorted(
                p.name for p in repo_root.iterdir()
                if p.is_dir() and not p.name.startswith(".")
            )

            # Dependency manifest presence
            dep_manifests = []
            for fname in (
                "requirements.txt", "requirements-dev.txt", "pyproject.toml",
                "package.json", "go.mod", "pom.xml", "Gemfile", "Cargo.toml",
            ):
                if (repo_root / fname).exists():
                    dep_manifests.append(fname)

            # IaC presence
            iac_signals = {}
            for label, patterns in {
                "terraform": ["*.tf", "*.tfvars"],
                "kubernetes": ["*.yaml", "*.yml"],
                "docker": ["Dockerfile", "docker-compose.yml", "docker-compose.yaml"],
                "github_actions": [".github/workflows"],
            }.items():
                for pat in patterns:
                    if pat.startswith("."):
                        iac_signals[label] = (repo_root / pat).exists()
                    else:
                        iac_signals[label] = any(repo_root.rglob(pat))
                    if iac_signals.get(label):
                        break

            # Rough language detection from extensions
            ext_counts: dict = {}
            for fp in repo_root.rglob("*"):
                if fp.is_file() and fp.suffix:
                    ext_counts[fp.suffix] = ext_counts.get(fp.suffix, 0) + 1
            top_exts = sorted(ext_counts.items(), key=lambda x: x[1], reverse=True)[:5]

            return {
                "components": components,
                "dependency_manifests": dep_manifests,
                "iac_signals": iac_signals,
                "top_extensions": [{"ext": e, "count": c} for e, c in top_exts],
                "architecture": {},  # populated by future diagram-parser integration
            }

        except (OSError, ValueError, KeyError, RuntimeError) as e:
            logger.error(f"_collect_design_context: error scanning {self.repo_path}: {e}")
            return None
