"""
Shared pytest fixtures for E2E tests.
"""

import pytest

from tests.harness import (
    CLIRunner,
    EvidenceValidator,
    FixtureManager,
    FlagConfigManager,
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
def demo_fixtures(fixture_manager):
    """Generate demo test fixtures."""
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
                "ruleId": "DEMO001",
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
