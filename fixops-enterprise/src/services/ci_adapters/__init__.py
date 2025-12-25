"""CI adapter compatibility shims that route to the top-level integrations package."""

from __future__ import annotations

from integrations.github.adapter import GitHubCIAdapter  # noqa: F401
from integrations.gitlab.adapter import GitLabCIAdapter  # noqa: F401
from integrations.jenkins.adapter import JenkinsCIAdapter  # noqa: F401
from integrations.sonarqube.adapter import SonarQubeAdapter  # noqa: F401

__all__ = ["GitHubCIAdapter", "GitLabCIAdapter", "JenkinsCIAdapter", "SonarQubeAdapter"]
