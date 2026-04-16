"""FixOps PR Generator - Automated pull request generation.

Enterprise-grade PR generator with full git operations:
- Creates branches from base (via SCM API)
- Commits file changes (via SCM API — no local git clone needed)
- Creates pull requests / merge requests
- Supports GitHub and GitLab

Uses the SCM provider's Content/Repository API to create branches and
commit files remotely, avoiding the need for a local git checkout.
"""

from __future__ import annotations

import base64
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import requests as _requests
from requests import RequestException

logger = logging.getLogger(__name__)

_GITHUB_API = "https://api.github.com"
_GITLAB_API = "https://gitlab.com/api/v4"


@dataclass
class PRResult:
    """PR generation result."""

    pr_url: Optional[str] = None
    pr_number: Optional[int] = None
    branch_name: str = ""
    commits: List[str] = field(default_factory=list)
    files_changed: List[str] = field(default_factory=list)
    success: bool = False
    error: Optional[str] = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class PRGenerator:
    """FixOps PR Generator - Automated pull request generation.

    Full lifecycle: create branch → commit files → open PR/MR.
    All operations use the SCM API (no local git needed).
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.scm_provider = self.config.get("scm_provider", "github")
        self._github_api = self.config.get("github_api_url", _GITHUB_API).rstrip("/")
        self._gitlab_api = self.config.get("gitlab_api_url", _GITLAB_API).rstrip("/")
        self._timeout = float(self.config.get("timeout", 30))

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def create_pr(
        self,
        repository: str,
        title: str,
        description: str,
        branch: str,
        base: str = "main",
        changes: Optional[Dict[str, str]] = None,
    ) -> PRResult:
        """Create pull request with changes.

        Full workflow:
        1. Resolve base branch SHA
        2. Create feature branch from base
        3. Commit all file changes to feature branch
        4. Open PR/MR from feature → base
        """
        if self.scm_provider == "github":
            return self._create_github_pr(
                repository, title, description, branch, base, changes
            )
        elif self.scm_provider == "gitlab":
            return self._create_gitlab_mr(
                repository, title, description, branch, base, changes
            )
        else:
            return PRResult(
                success=False, error=f"Unsupported SCM provider: {self.scm_provider}"
            )

    # ==================================================================
    # GitHub — full create-branch → commit → PR flow
    # ==================================================================

    def _github_headers(self) -> Dict[str, str]:
        token = self.config.get("github_token", "")
        return {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def _github_get_ref_sha(self, repo: str, ref: str) -> Optional[str]:
        """Get the SHA of a git reference (branch/tag)."""
        url = f"{self._github_api}/repos/{repo}/git/ref/heads/{ref}"
        resp = _requests.get(url, headers=self._github_headers(), timeout=self._timeout)  # nosemgrep: dynamic-urllib-use-detected
        if resp.status_code == 200:
            return resp.json()["object"]["sha"]
        logger.warning("GitHub: could not resolve ref %s/%s: %s", repo, ref, resp.status_code)
        return None

    def _github_create_branch(self, repo: str, branch: str, sha: str) -> bool:
        """Create a new branch pointing at *sha*."""
        url = f"{self._github_api}/repos/{repo}/git/refs"
        payload = {"ref": f"refs/heads/{branch}", "sha": sha}
        resp = _requests.post(  # nosemgrep: dynamic-urllib-use-detected
            url, headers=self._github_headers(), json=payload, timeout=self._timeout
        )
        if resp.status_code in (201, 200):
            logger.info("GitHub: created branch %s on %s", branch, repo)
            return True
        # 422 = branch already exists — treat as success
        if resp.status_code == 422:
            logger.info("GitHub: branch %s already exists on %s", branch, repo)
            return True
        logger.error(
            "GitHub: failed to create branch %s: %s %s",
            branch, resp.status_code, resp.text[:200],
        )
        return False

    def _github_commit_file(
        self, repo: str, branch: str, path: str, content: str, message: str
    ) -> Optional[str]:
        """Create or update a single file on *branch* via the Contents API.

        Returns the commit SHA on success, None on failure.
        """
        url = f"{self._github_api}/repos/{repo}/contents/{path}"
        headers = self._github_headers()

        # Check if file already exists on the branch (need its sha for update)
        existing_sha: Optional[str] = None
        check = _requests.get(  # nosemgrep: dynamic-urllib-use-detected
            url, headers=headers, params={"ref": branch}, timeout=self._timeout
        )
        if check.status_code == 200:
            existing_sha = check.json().get("sha")

        payload: Dict[str, Any] = {
            "message": message,
            "content": base64.b64encode(content.encode("utf-8")).decode("ascii"),
            "branch": branch,
        }
        if existing_sha:
            payload["sha"] = existing_sha

        resp = _requests.put(url, headers=headers, json=payload, timeout=self._timeout)  # nosemgrep: dynamic-urllib-use-detected
        if resp.status_code in (200, 201):
            commit_sha = resp.json().get("commit", {}).get("sha")
            logger.info("GitHub: committed %s on %s (%s)", path, branch, commit_sha)
            return commit_sha
        logger.error(
            "GitHub: failed to commit %s: %s %s",
            path, resp.status_code, resp.text[:200],
        )
        return None

    def _create_github_pr(
        self,
        repository: str,
        title: str,
        description: str,
        branch: str,
        base: str,
        changes: Optional[Dict[str, str]],
    ) -> PRResult:
        """Create GitHub pull request with full git operations."""
        api_token = self.config.get("github_token")
        if not api_token:
            return PRResult(success=False, error="GitHub token not configured")

        commits: List[str] = []
        files_changed: List[str] = []

        try:
            # Step 1: Resolve base branch SHA
            base_sha = self._github_get_ref_sha(repository, base)
            if not base_sha:
                return PRResult(
                    success=False,
                    error=f"Could not resolve base branch '{base}' on {repository}",
                )

            # Step 2: Create feature branch
            if not self._github_create_branch(repository, branch, base_sha):
                return PRResult(
                    success=False,
                    error=f"Failed to create branch '{branch}' on {repository}",
                )

            # Step 3: Commit each changed file
            if changes:
                for file_path, content in changes.items():
                    commit_msg = f"fix: {title} — update {file_path}\n\nAutomated by FixOps AutoFix Engine"
                    sha = self._github_commit_file(
                        repository, branch, file_path, content, commit_msg
                    )
                    if sha:
                        commits.append(sha)
                        files_changed.append(file_path)
                    else:
                        logger.warning("Skipping file %s — commit failed", file_path)

            # Step 4: Create the PR
            pr_payload = {
                "title": title,
                "body": description,
                "head": branch,
                "base": base,
            }
            resp = _requests.post(  # nosemgrep: dynamic-urllib-use-detected
                f"{self._github_api}/repos/{repository}/pulls",
                headers=self._github_headers(),
                json=pr_payload,
                timeout=self._timeout,
            )

            if resp.status_code == 201:
                data = resp.json()
                return PRResult(
                    pr_url=data.get("html_url"),
                    pr_number=data.get("number"),
                    branch_name=branch,
                    commits=commits,
                    files_changed=files_changed,
                    success=True,
                )
            else:
                return PRResult(
                    success=False,
                    branch_name=branch,
                    commits=commits,
                    files_changed=files_changed,
                    error=f"PR creation failed: {resp.status_code} — {resp.text[:300]}",
                )

        except RequestException as exc:
            logger.error("GitHub PR flow failed: %s", exc)
            return PRResult(success=False, error=str(exc))

    # ==================================================================
    # GitLab — full create-branch → commit → MR flow
    # ==================================================================

    def _gitlab_headers(self) -> Dict[str, str]:
        return {"PRIVATE-TOKEN": self.config.get("gitlab_token", "")}

    def _gitlab_project_url(self, repository: str) -> str:
        project_id = repository.replace("/", "%2F")
        return f"{self._gitlab_api}/projects/{project_id}"

    def _gitlab_create_branch(self, repository: str, branch: str, base: str) -> bool:
        """Create a branch on GitLab."""
        url = f"{self._gitlab_project_url(repository)}/repository/branches"
        payload = {"branch": branch, "ref": base}
        resp = _requests.post(  # nosemgrep: dynamic-urllib-use-detected
            url, headers=self._gitlab_headers(), json=payload, timeout=self._timeout
        )
        if resp.status_code in (200, 201):
            logger.info("GitLab: created branch %s", branch)
            return True
        if resp.status_code == 400 and "already exists" in resp.text.lower():
            logger.info("GitLab: branch %s already exists", branch)
            return True
        logger.error(
            "GitLab: failed to create branch %s: %s %s",
            branch, resp.status_code, resp.text[:200],
        )
        return False

    def _gitlab_commit_files(
        self,
        repository: str,
        branch: str,
        changes: Dict[str, str],
        commit_message: str,
    ) -> Optional[str]:
        """Commit multiple files in a single commit via the Commits API."""
        url = f"{self._gitlab_project_url(repository)}/repository/commits"
        actions = []
        for file_path, content in changes.items():
            # Check if file exists to decide create vs update
            check_url = (
                f"{self._gitlab_project_url(repository)}"
                f"/repository/files/{file_path.replace('/', '%2F')}"
            )
            exists = _requests.head(
                check_url,
                headers=self._gitlab_headers(),
                params={"ref": branch},
                timeout=self._timeout,
            )
            action = "update" if exists.status_code == 200 else "create"
            actions.append(
                {"action": action, "file_path": file_path, "content": content}
            )

        payload = {
            "branch": branch,
            "commit_message": commit_message,
            "actions": actions,
        }
        resp = _requests.post(  # nosemgrep: dynamic-urllib-use-detected
            url, headers=self._gitlab_headers(), json=payload, timeout=self._timeout
        )
        if resp.status_code in (200, 201):
            sha = resp.json().get("id")
            logger.info("GitLab: committed %d files (%s)", len(actions), sha)
            return sha
        logger.error(
            "GitLab: commit failed: %s %s", resp.status_code, resp.text[:200]
        )
        return None

    def _create_gitlab_mr(
        self,
        repository: str,
        title: str,
        description: str,
        branch: str,
        base: str,
        changes: Optional[Dict[str, str]],
    ) -> PRResult:
        """Create GitLab merge request with full git operations."""
        api_token = self.config.get("gitlab_token")
        if not api_token:
            return PRResult(success=False, error="GitLab token not configured")

        commits: List[str] = []
        files_changed: List[str] = list(changes.keys()) if changes else []

        try:
            # Step 1: Create feature branch from base
            if not self._gitlab_create_branch(repository, branch, base):
                return PRResult(
                    success=False,
                    error=f"Failed to create branch '{branch}' on {repository}",
                )

            # Step 2: Commit all files in a single commit
            if changes:
                commit_msg = f"fix: {title}\n\nAutomated by FixOps AutoFix Engine"
                sha = self._gitlab_commit_files(
                    repository, branch, changes, commit_msg
                )
                if sha:
                    commits.append(sha)
                else:
                    return PRResult(
                        success=False,
                        branch_name=branch,
                        error="Failed to commit files to branch",
                    )

            # Step 3: Create MR
            mr_payload = {
                "title": title,
                "description": description,
                "source_branch": branch,
                "target_branch": base,
                "remove_source_branch": True,
            }
            resp = _requests.post(  # nosemgrep: dynamic-urllib-use-detected
                f"{self._gitlab_project_url(repository)}/merge_requests",
                headers=self._gitlab_headers(),
                json=mr_payload,
                timeout=self._timeout,
            )

            if resp.status_code == 201:
                data = resp.json()
                return PRResult(
                    pr_url=data.get("web_url"),
                    pr_number=data.get("iid"),
                    branch_name=branch,
                    commits=commits,
                    files_changed=files_changed,
                    success=True,
                )
            else:
                return PRResult(
                    success=False,
                    branch_name=branch,
                    commits=commits,
                    files_changed=files_changed,
                    error=f"MR creation failed: {resp.status_code} — {resp.text[:300]}",
                )

        except RequestException as exc:
            logger.error("GitLab MR flow failed: %s", exc)
            return PRResult(success=False, error=str(exc))

    def generate_pr_for_dependency_updates(
        self,
        repository: str,
        updates: List[Any],  # List[DependencyUpdate]
        base: str = "main",
    ) -> PRResult:
        """Generate PR for dependency updates."""

        # Generate title and description
        security_count = sum(1 for u in updates if u.has_security_vulnerability)

        if security_count > 0:
            title = f"Security: Update {len(updates)} dependencies ({security_count} security)"
        else:
            title = f"Update {len(updates)} dependencies"

        description = self._generate_pr_description(updates)

        # Generate branch name
        branch = (
            f"fixops/dependency-updates-{datetime.now(timezone.utc).strftime('%Y%m%d')}"
        )

        return self.create_pr(
            repository=repository,
            title=title,
            description=description,
            branch=branch,
            base=base,
        )

    def _generate_pr_description(self, updates: List[Any]) -> str:
        """Generate PR description for dependency updates."""
        lines = ["## Dependency Updates", ""]

        security_updates = [u for u in updates if u.has_security_vulnerability]
        if security_updates:
            lines.append("### Security Updates")
            for update in security_updates:
                lines.append(
                    f"- **{update.package_name}**: {update.current_version} → {update.new_version}"
                )
                if update.cve_ids:
                    lines.append(f"  - CVEs: {', '.join(update.cve_ids)}")
            lines.append("")

        regular_updates = [u for u in updates if not u.has_security_vulnerability]
        if regular_updates:
            lines.append("### Regular Updates")
            for update in regular_updates:
                lines.append(
                    f"- **{update.package_name}**: {update.current_version} → {update.new_version}"
                )
            lines.append("")

        lines.append("---")
        lines.append("*Automated by FixOps*")

        return "\n".join(lines)
