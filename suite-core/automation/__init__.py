"""FixOps Automation Engine

Automated dependency updates, PR generation, and remediation.
"""

from automation.dependency_updater import DependencyUpdater, UpdateResult
from automation.pr_generator import PRGenerator, PRResult
from automation.remediation import (
    CWEFixRegistry,
    CWEFixTemplate,
    RemediationEngine,
    RemediationResult,
    RemediationStatus,
    RemediationStrategy,
)

__all__ = [
    "DependencyUpdater",
    "UpdateResult",
    "PRGenerator",
    "PRResult",
    "CWEFixRegistry",
    "CWEFixTemplate",
    "RemediationEngine",
    "RemediationResult",
    "RemediationStatus",
    "RemediationStrategy",
]
