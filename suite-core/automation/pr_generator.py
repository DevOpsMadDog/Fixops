"""FixOps PR Generator - Automated pull request generation."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


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
    """FixOps PR Generator - Automated pull request generation."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize PR generator."""
        self.config = config or {}
        self.scm_provider = self.config.get(
            "scm_provider", "github"
        )  # github, gitlab, bitbucket

    def create_pr(
        self,
        repository: str,
        title: str,
        description: str,
        branch: str,
        base: str = "main",
        changes: Optional[Dict[str, str]] = None,  # file_path -> new_content
    ) -> PRResult:
        """Create pull request with changes."""
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

    def _create_github_pr(
        self,
        repository: str,
        title: str,
        description: str,
        branch: str,
        base: str,
        changes: Optional[Dict[str, str]],
    ) -> PRResult:
        """Create GitHub pull request."""
        import requests

        api_token = self.config.get("github_token")
        if not api_token:
            return PRResult(success=False, error="GitHub token not configured")

        # In production, would:
        # 1. Create branch
        # 2. Commit changes
        # 3. Push branch
        # 4. Create PR

        try:
            headers = {
                "Authorization": f"token {api_token}",
                "Accept": "application/vnd.github.v3+json",
            }

            # Create PR
            payload = {
                "title": title,
                "body": description,
                "head": branch,
                "base": base,
            }

            response = requests.post(
                f"https://api.github.com/repos/{repository}/pulls",
                headers=headers,
                json=payload,
                timeout=30,
            )

            if response.status_code == 201:
                result = response.json()
                return PRResult(
                    pr_url=result.get("html_url"),
                    pr_number=result.get("number"),
                    branch_name=branch,
                    files_changed=list(changes.keys()) if changes else [],
                    success=True,
                )
            else:
                return PRResult(
                    success=False,
                    error=f"Failed to create PR: {response.status_code}",
                )

        except Exception as e:
            logger.error(f"Failed to create GitHub PR: {e}")
            return PRResult(success=False, error=str(e))

    def _create_gitlab_mr(
        self,
        repository: str,
        title: str,
        description: str,
        branch: str,
        base: str,
        changes: Optional[Dict[str, str]],
    ) -> PRResult:
        """Create GitLab merge request."""
        import requests

        api_token = self.config.get("gitlab_token")
        if not api_token:
            return PRResult(success=False, error="GitLab token not configured")

        try:
            headers = {"PRIVATE-TOKEN": api_token}

            # Create merge request
            payload = {
                "title": title,
                "description": description,
                "source_branch": branch,
                "target_branch": base,
            }

            # GitLab uses project ID, not repo name
            project_id = repository.replace("/", "%2F")

            response = requests.post(
                f"https://gitlab.com/api/v4/projects/{project_id}/merge_requests",
                headers=headers,
                json=payload,
                timeout=30,
            )

            if response.status_code == 201:
                result = response.json()
                return PRResult(
                    pr_url=result.get("web_url"),
                    pr_number=result.get("iid"),
                    branch_name=branch,
                    files_changed=list(changes.keys()) if changes else [],
                    success=True,
                )
            else:
                return PRResult(
                    success=False,
                    error=f"Failed to create MR: {response.status_code}",
                )

        except Exception as e:
            logger.error(f"Failed to create GitLab MR: {e}")
            return PRResult(success=False, error=str(e))

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
