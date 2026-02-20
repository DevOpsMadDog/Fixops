"""Tests for CI adapter integrations.

These tests depend on modules that have not yet been implemented:
- core.services.enterprise.ci_adapters (GitHubCIAdapter, JenkinsCIAdapter)
- core.services.enterprise.signing
- core.services.enterprise.evidence (EvidenceStore)

The SonarQubeAdapter is tested separately in test_sonarqube_adapter.py
once the adapter's async API is wired to DecisionEngine.make_decision().
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.skip(
    reason=(
        "Depends on unimplemented modules: ci_adapters "
        "(GitHubCIAdapter, JenkinsCIAdapter), signing, evidence (EvidenceStore)"
    )
)


def test_github_webhook_comment(signing_env: None) -> None:
    pass


def test_jenkins_signed_response(signing_env: None) -> None:
    pass


def test_sonarqube_ingest_top_factors(signing_env: None) -> None:
    pass
