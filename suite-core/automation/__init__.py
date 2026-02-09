"""FixOps Automation Engine

Automated dependency updates, PR generation, and remediation.
"""

from automation.dependency_updater import DependencyUpdater, UpdateResult
from automation.pr_generator import PRGenerator, PRResult
from automation.remediation import RemediationEngine, RemediationResult

__all__ = [
    "DependencyUpdater",
    "UpdateResult",
    "PRGenerator",
    "PRResult",
    "RemediationEngine",
    "RemediationResult",
]
