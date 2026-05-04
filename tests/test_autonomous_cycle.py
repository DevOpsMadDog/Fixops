"""Focused autonomous-cycle validation entrypoint.

This wrapper maps the autonomous-cycle suite onto maintained, high-signal
validation coverage so the focused validation command exercises current
behavior instead of missing legacy filenames.

When run in isolation (e.g. ``pytest tests/test_autonomous_cycle.py``), the
``tests.e2e.conftest`` plugin is registered explicitly so that E2E fixtures
are available.  When collected as part of the full ``tests/`` tree, pytest
discovers the conftest automatically, so we skip the explicit registration
to avoid the "Plugin already registered" error.

The fixtures from ``tests/e2e/conftest.py`` are re-exported here so that
re-imported test classes can resolve them regardless of conftest scoping.
"""

import sys
import pytest

# Only register the e2e conftest when it has NOT already been loaded by
# pytest's automatic conftest discovery (i.e. when running this file in
# isolation rather than as part of the full tests/ collection).
if "tests.e2e.conftest" not in sys.modules:
    pytest_plugins = ["tests.e2e.conftest"]

from tests.e2e.test_bn_lr_hybrid import TestBNLRHybrid as _TestBNLRHybrid
from tests.e2e.test_branding_namespace import TestBrandingNamespace as _TestBrandingNamespace
from tests.test_ai_consensus import *  # noqa: F401,F403

# Re-export the e2e fixtures at this module's scope so that re-imported test
# classes can resolve them when running in isolation.  These mirror the
# definitions in tests/e2e/conftest.py exactly.
from tests.harness import (
    CLIRunner,
    EvidenceValidator,
    FixtureManager,
    FlagConfigManager,
    ServerManager,
)


@pytest.fixture
def fixture_manager():
    """Provide a FixtureManager with automatic cleanup."""
    manager = FixtureManager()
    manager.create_temp_dir()
    yield manager
    manager.cleanup()


@pytest.fixture
def flag_config_manager(fixture_manager):
    """Provide a FlagConfigManager with automatic cleanup."""
    manager = FlagConfigManager(temp_dir=fixture_manager.temp_dir)
    yield manager
    manager.cleanup()


@pytest.fixture
def cli_runner(fixture_manager):
    """Provide a CLIRunner configured for testing."""
    return CLIRunner(cwd=fixture_manager.temp_dir)


@pytest.fixture
def evidence_validator():
    """Provide an EvidenceValidator."""
    return EvidenceValidator()


@pytest.fixture
def server_manager():
    """Provide a ServerManager with automatic cleanup."""
    manager = ServerManager()
    yield manager
    manager.stop()


@pytest.fixture
def test_fixtures(fixture_manager):
    """Generate test fixtures for pipeline testing."""
    design = fixture_manager.generate_design_csv(
        components=[
            {
                "component": "payment-service",
                "owner": "app-team",
                "criticality": "high",
                "notes": "Handles card processing",
            },
            {
                "component": "notification-service",
                "owner": "platform",
                "criticality": "medium",
                "notes": "Sends emails",
            },
        ]
    )

    sbom = fixture_manager.generate_sbom_json(
        components=[
            {
                "type": "library",
                "name": "payment-service",
                "version": "1.0.0",
                "purl": "pkg:pypi/payment-service@1.0.0",
                "licenses": [{"license": {"id": "MIT"}}],
            },
            {
                "type": "application",
                "name": "notification-service",
                "version": "2.0.0",
                "purl": "pkg:npm/notification-service@2.0.0",
                "licenses": [{"license": {"id": "Apache-2.0"}}],
            },
        ]
    )

    cve = fixture_manager.generate_cve_json(
        vulnerabilities=[
            {
                "cveID": "CVE-2024-0001",
                "title": "Example vulnerability in payment-service",
                "knownExploited": True,
                "severity": "high",
            }
        ]
    )

    sarif = fixture_manager.generate_sarif_json(
        results=[
            {
                "ruleId": "TEST001",
                "level": "error",
                "message": {"text": "SQL injection risk"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": "services/payment-service/app.py"
                            },
                            "region": {"startLine": 42},
                        }
                    }
                ],
            }
        ]
    )

    return {
        "design": design,
        "sbom": sbom,
        "cve": cve,
        "sarif": sarif,
    }


@pytest.mark.timeout(120)
class TestBNLRHybrid(_TestBNLRHybrid):
    pass


@pytest.mark.timeout(120)
class TestBrandingNamespace(_TestBrandingNamespace):
    pass
