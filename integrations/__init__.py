"""Integration modules for FixOps.

Provides adapters for CI/CD platforms, vulnerability scanners, and ticketing systems.
"""

from integrations.github.adapter import GitHubCIAdapter
from integrations.gitlab.adapter import GitLabCIAdapter
from integrations.azure_devops.adapter import AzureDevOpsAdapter
from integrations.jenkins.adapter import JenkinsCIAdapter
from integrations.sonarqube.adapter import SonarQubeAdapter
from integrations.snyk.adapter import SnykAdapter
from integrations.defectdojo.adapter import DefectDojoAdapter

__all__ = [
    "GitHubCIAdapter",
    "GitLabCIAdapter",
    "AzureDevOpsAdapter",
    "JenkinsCIAdapter",
    "SonarQubeAdapter",
    "SnykAdapter",
    "DefectDojoAdapter",
]
