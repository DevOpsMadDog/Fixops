"""Comprehensive tests for the correlation engine."""

from __future__ import annotations

import pytest
import pytest_asyncio
from src.services.correlation_engine import CorrelationEngine, CorrelationResult


@pytest.mark.asyncio
async def test_correlation_engine_initialization():
    """Test that correlation engine initializes correctly."""
    engine = CorrelationEngine(enabled=True)
    assert engine is not None
    assert engine.enabled is True


@pytest.mark.asyncio
async def test_correlation_with_empty_findings():
    """Test correlation with empty findings list."""
    engine = CorrelationEngine(enabled=True)
    result = await engine.batch_correlate_findings([])
    assert len(result) == 0


@pytest.mark.asyncio
async def test_fingerprint_correlation():
    """Test fingerprint-based correlation."""
    engine = CorrelationEngine(enabled=True)
    findings = [
        {
            "id": "finding-1",
            "rule_id": "SQL-001",
            "message": "SQL injection",
            "file": "/app/api/users.py",
            "line": 42,
            "severity": "high",
            "fingerprint": "abc123",
            "status": "open"
        },
        {
            "id": "finding-2",
            "rule_id": "SQL-001",
            "message": "SQL injection",
            "file": "/app/api/users.py",
            "line": 45,
            "severity": "high",
            "fingerprint": "abc123",
            "status": "open"
        },
    ]

    # Finding 1 should correlate with Finding 2
    result = await engine.correlate_finding(findings[0], findings)
    assert result is not None
    assert result.finding_id == "finding-1"
    assert "finding-2" in result.correlated_findings
    assert result.correlation_type == "exact_fingerprint"


@pytest.mark.asyncio
async def test_cross_stage_correlation():
    """Test cross-stage correlation (Design -> Runtime)."""
    engine = CorrelationEngine(enabled=True)
    
    findings = [
        # Runtime Finding
        {
            "id": "runtime-1",
            "stage": "runtime",
            "cve_id": "CVE-2023-1234",
            "component_name": "lib-foo",
            "severity": "critical",
            "status": "open"
        },
        # Build Finding (SAST/SCA)
        {
            "id": "build-1",
            "stage": "build",
            "cve_id": "CVE-2023-1234",
            "component_name": "lib-foo",
            "severity": "critical",
            "status": "open"
        }
    ]

    # Check runtime finding correlation
    result = await engine.correlate_finding(findings[0], findings)
    
    assert result is not None
    assert result.finding_id == "runtime-1"
    assert "build-1" in result.correlated_findings
    assert result.correlation_type == "cross_stage_trace"
    assert result.root_cause == "sdlc_lifecycle_trace"
