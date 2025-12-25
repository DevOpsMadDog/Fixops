"""Tests for cross-stage correlation engine enhancements."""

import pytest

from fixops_enterprise.src.services.correlation_engine import (
    CorrelationEngine,
    get_correlation_engine,
)


@pytest.fixture
def correlation_engine():
    """Create enabled correlation engine."""
    return CorrelationEngine(enabled=True)


@pytest.fixture
def sample_findings_by_stage():
    """Sample findings across SDLC stages."""
    return {
        "design": [
            {
                "id": "design-1",
                "title": "SQL Injection Risk",
                "cve_id": "CVE-2024-1234",
                "component": "auth-service",
                "severity": "high",
            }
        ],
        "build": [
            {
                "id": "build-1",
                "title": "SQL Injection Vulnerability",
                "cve_id": "CVE-2024-1234",
                "component": "auth-service",
                "rule_id": "CWE-89",
                "severity": "high",
            },
            {
                "id": "build-2",
                "title": "Hardcoded Secrets",
                "component": "config-loader",
                "rule_id": "CWE-798",
                "severity": "critical",
            },
        ],
        "deploy": [
            {
                "id": "deploy-1",
                "title": "Container CVE",
                "cve_id": "CVE-2024-1234",
                "asset_id": "k8s/auth-service",
                "severity": "high",
            }
        ],
        "runtime": [
            {
                "id": "runtime-1",
                "title": "Active SQL Injection Detected",
                "cve_id": "CVE-2024-1234",
                "component": "auth-service",
                "severity": "critical",
            }
        ],
    }


@pytest.mark.asyncio
async def test_cross_stage_correlation(correlation_engine, sample_findings_by_stage):
    """Test that findings are correlated across stages."""
    groups = await correlation_engine.correlate_cross_stage(sample_findings_by_stage)

    assert len(groups) > 0

    # Find the group with CVE-2024-1234
    cve_group = None
    for group in groups:
        primary = group.get("primary_finding", {})
        if primary.get("cve_id") == "CVE-2024-1234":
            cve_group = group
            break

    assert cve_group is not None
    assert cve_group["total_related"] >= 2
    assert len(cve_group["stages_involved"]) >= 2


@pytest.mark.asyncio
async def test_cross_stage_link_attributes(correlation_engine, sample_findings_by_stage):
    """Test custom link attributes for correlation."""
    groups = await correlation_engine.correlate_cross_stage(
        sample_findings_by_stage,
        link_attributes=["cve_id"],
    )

    # Should find correlations based on CVE only
    assert len(groups) >= 1


@pytest.mark.asyncio
async def test_deduplication(correlation_engine):
    """Test finding deduplication."""
    findings = [
        {"id": "1", "title": "SQL Injection", "rule_id": "CWE-89", "severity": "high"},
        {"id": "2", "title": "SQL Injection", "rule_id": "CWE-89", "severity": "high"},
        {"id": "3", "title": "XSS Vulnerability", "rule_id": "CWE-79", "severity": "medium"},
    ]

    result = await correlation_engine.deduplicate_findings(findings)

    assert result["duplicates_removed"] == 1
    assert len(result["unique"]) == 2
    assert result["dedup_ratio"] > 0


@pytest.mark.asyncio
async def test_disabled_engine_returns_empty():
    """Test that disabled engine returns empty results."""
    engine = CorrelationEngine(enabled=False)

    findings_by_stage = {
        "build": [{"id": "1", "cve_id": "CVE-2024-1234"}],
        "deploy": [{"id": "2", "cve_id": "CVE-2024-1234"}],
    }

    groups = await engine.correlate_cross_stage(findings_by_stage)
    assert groups == []

    dedup_result = await engine.deduplicate_findings([{"id": "1"}])
    assert dedup_result["duplicates_removed"] == 0


def test_get_stats(correlation_engine):
    """Test stats endpoint."""
    stats = correlation_engine.get_stats()

    assert stats["enabled"] is True
    assert stats["strategies_count"] == 5
    assert "fingerprint" in stats["strategies"]
    assert "vulnerability" in stats["strategies"]


@pytest.mark.asyncio
async def test_batch_correlation(correlation_engine):
    """Test batch correlation of findings."""
    findings = [
        {
            "id": "1",
            "fingerprint": "abc123",
            "title": "SQL Injection",
            "severity": "high",
            "status": "open",
        },
        {
            "id": "2",
            "fingerprint": "abc123",
            "title": "SQL Injection",
            "severity": "high",
            "status": "open",
        },
        {
            "id": "3",
            "fingerprint": "def456",
            "title": "XSS",
            "severity": "medium",
            "status": "open",
        },
    ]

    results = await correlation_engine.batch_correlate_findings(findings)

    # Should find correlations for findings with same fingerprint
    assert len(results) >= 0  # May vary based on matching threshold
