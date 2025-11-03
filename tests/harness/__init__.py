"""
E2E Test Harness for FixOps

This package provides utilities for ruthless end-to-end testing of FixOps
with real CLI and API calls (no mocks or stubs).
"""

from tests.harness.cli_runner import CLIRunner
from tests.harness.evidence_validator import EvidenceValidator
from tests.harness.fixture_manager import FixtureManager
from tests.harness.flag_config_manager import FlagConfigManager
from tests.harness.server_manager import ServerManager

__all__ = [
    "ServerManager",
    "CLIRunner",
    "FixtureManager",
    "FlagConfigManager",
    "EvidenceValidator",
]
