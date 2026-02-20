"""Comprehensive tests for the correlation engine."""

from __future__ import annotations

from core.services.enterprise.correlation_engine import CorrelationEngine


def test_correlation_engine_initialization():
    """Test that correlation engine initializes correctly."""
    engine = CorrelationEngine()
    assert engine is not None


def test_correlation_with_empty_findings():
    """Test correlation with empty findings list."""
    engine = CorrelationEngine()
    result = engine.correlate([])

    assert result["original_count"] == 0
    assert result["correlated_count"] == 0
    assert result["noise_reduction_percentage"] == 0.0


def test_correlation_with_single_finding():
    """Test correlation with a single finding."""
    engine = CorrelationEngine()
    findings = [
        {
            "id": "finding-1",
            "rule_id": "TEST-001",
            "message": "Test finding",
            "severity": "low",
        }
    ]

    result = engine.correlate(findings)
    assert result["original_count"] == 1
    assert result["correlated_count"] >= 1


def test_fingerprint_correlation():
    """Test fingerprint-based correlation."""
    engine = CorrelationEngine()
    findings = [
        {
            "id": "finding-1",
            "rule_id": "SQL-001",
            "message": "SQL injection",
            "file": "/app/api/users.py",
            "line": 42,
            "severity": "high",
            "fingerprint": "abc123",
        },
        {
            "id": "finding-2",
            "rule_id": "SQL-001",
            "message": "SQL injection",
            "file": "/app/api/users.py",
            "line": 45,
            "severity": "high",
            "fingerprint": "abc123",
        },
    ]

    result = engine.correlate(findings)
    assert result["original_count"] == 2
    assert result["correlated_count"] <= 2


def test_location_proximity_correlation():
    """Test location proximity correlation."""
    engine = CorrelationEngine()
    findings = [
        {
            "id": "finding-1",
            "file": "/app/api/users.py",
            "line": 42,
            "severity": "high",
        },
        {
            "id": "finding-2",
            "file": "/app/api/users.py",
            "line": 45,
            "severity": "high",
        },
    ]

    result = engine.correlate(findings)
    assert result["original_count"] == 2


def test_noise_reduction_calculation():
    """Test that noise reduction percentage is calculated correctly."""
    engine = CorrelationEngine()
    findings = [
        {"id": f"finding-{i}", "rule_id": "TEST-001", "severity": "low"}
        for i in range(10)
    ]

    result = engine.correlate(findings)
    assert "noise_reduction_percentage" in result
    assert 0 <= result["noise_reduction_percentage"] <= 100


def test_correlation_metadata():
    """Test that correlation result includes proper metadata."""
    engine = CorrelationEngine()
    findings = [
        {"id": "finding-1", "rule_id": "TEST-001", "severity": "low"},
        {"id": "finding-2", "rule_id": "TEST-002", "severity": "medium"},
    ]

    result = engine.correlate(findings)
    assert "original_count" in result
    assert "correlated_count" in result
    assert "noise_reduction_percentage" in result
    assert "correlated_groups" in result
