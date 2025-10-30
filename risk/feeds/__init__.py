"""Data feed helpers for risk scoring."""

from __future__ import annotations

from pathlib import Path

from .base import (
    FeedMetadata,
    FeedRegistry,
    ThreatIntelligenceFeed,
    VulnerabilityRecord,
)
from .ecosystems import (
    AlpineSecDBFeed,
    DebianSecurityFeed,
    GoVulnDBFeed,
    MavenSecurityFeed,
    NPMSecurityFeed,
    NuGetSecurityFeed,
    PyPISecurityFeed,
    RubySecFeed,
    RustSecFeed,
    UbuntuSecurityFeed,
)
from .exploits import (
    AbuseCHMalwareBazaarFeed,
    AbuseCHThreatFoxFeed,
    AbuseCHURLHausFeed,
    AlienVaultOTXFeed,
    ExploitDBFeed,
    Rapid7AttackerKBFeed,
    VulnersFeed,
)
from .github import GitHubSecurityAdvisoriesFeed
from .nvd import NVDFeed
from .osv import OSVFeed
from .vendors import (
    AppleSecurityFeed,
    AWSSecurityFeed,
    AzureSecurityFeed,
    CiscoSecurityFeed,
    DockerSecurityFeed,
    KubernetesSecurityFeed,
    MicrosoftSecurityFeed,
    OracleSecurityFeed,
    VMwareSecurityFeed,
)

FEEDS_DIR = Path("data/feeds")

__all__ = [
    "FEEDS_DIR",
    "VulnerabilityRecord",
    "FeedMetadata",
    "ThreatIntelligenceFeed",
    "FeedRegistry",
    "OSVFeed",
    "NVDFeed",
    "GitHubSecurityAdvisoriesFeed",
    "MicrosoftSecurityFeed",
    "AppleSecurityFeed",
    "AWSSecurityFeed",
    "AzureSecurityFeed",
    "OracleSecurityFeed",
    "CiscoSecurityFeed",
    "VMwareSecurityFeed",
    "DockerSecurityFeed",
    "KubernetesSecurityFeed",
    "NPMSecurityFeed",
    "PyPISecurityFeed",
    "RubySecFeed",
    "RustSecFeed",
    "GoVulnDBFeed",
    "MavenSecurityFeed",
    "NuGetSecurityFeed",
    "DebianSecurityFeed",
    "UbuntuSecurityFeed",
    "AlpineSecDBFeed",
    "ExploitDBFeed",
    "VulnersFeed",
    "AlienVaultOTXFeed",
    "AbuseCHURLHausFeed",
    "AbuseCHMalwareBazaarFeed",
    "AbuseCHThreatFoxFeed",
    "Rapid7AttackerKBFeed",
]
