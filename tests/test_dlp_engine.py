"""
Tests for the DLP Engine — PII, PCI, credential detection and redaction.

22+ tests covering:
- Basic scan_text contract
- Credit card, SSN, email, AWS key detection
- Clean text (zero findings)
- Risk level values
- Redaction behaviour
- Storage/retrieval
- Filtering by risk level
- Stats aggregation
- Custom patterns
- Privacy guarantee (no raw match values stored)
"""

import sys
sys.path.insert(0, "suite-core")

import pytest
import tempfile
from pathlib import Path

from core.dlp_engine import DLPEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine(tmp_path):
    """DLPEngine backed by a temporary SQLite database."""
    return DLPEngine(db_path=str(tmp_path / "dlp_test.db"))


# ---------------------------------------------------------------------------
# 1. Basic scan_text contract
# ---------------------------------------------------------------------------

def test_scan_text_returns_dict(engine):
    result = engine.scan_text("hello world")
    assert isinstance(result, dict)


def test_scan_text_has_scan_id(engine):
    result = engine.scan_text("hello world")
    assert "scan_id" in result
    assert isinstance(result["scan_id"], str)
    assert len(result["scan_id"]) > 0


def test_scan_text_has_required_keys(engine):
    result = engine.scan_text("hello world")
    for key in ("scan_id", "total_findings", "findings", "categories_found", "risk_level"):
        assert key in result, f"Missing key: {key}"


# ---------------------------------------------------------------------------
# 2. Pattern detection
# ---------------------------------------------------------------------------

def test_scan_text_detects_credit_card(engine):
    result = engine.scan_text("Card number: 4111111111111111 please charge it")
    pattern_names = [f["pattern_name"] for f in result["findings"]]
    assert "credit_card" in pattern_names


def test_scan_text_detects_ssn(engine):
    result = engine.scan_text("SSN: 123-45-6789")
    pattern_names = [f["pattern_name"] for f in result["findings"]]
    assert "ssn" in pattern_names


def test_scan_text_detects_email(engine):
    result = engine.scan_text("Contact us at alice@example.com for support")
    pattern_names = [f["pattern_name"] for f in result["findings"]]
    assert "email_address" in pattern_names


def test_scan_text_detects_aws_key(engine):
    # AKIAIOSFODNN7EXAMPLE is the canonical AWS example key
    result = engine.scan_text("export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE")
    pattern_names = [f["pattern_name"] for f in result["findings"]]
    assert "aws_access_key" in pattern_names


def test_scan_text_detects_private_key_header(engine):
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA..."
    result = engine.scan_text(text)
    pattern_names = [f["pattern_name"] for f in result["findings"]]
    assert "private_key" in pattern_names


# ---------------------------------------------------------------------------
# 3. Clean text → zero findings
# ---------------------------------------------------------------------------

def test_scan_text_clean_text_zero_findings(engine):
    result = engine.scan_text("The quick brown fox jumps over the lazy dog.")
    assert result["total_findings"] == 0
    assert result["findings"] == []


def test_scan_text_clean_text_risk_low(engine):
    result = engine.scan_text("The quick brown fox jumps over the lazy dog.")
    assert result["risk_level"] == "low"


# ---------------------------------------------------------------------------
# 4. Risk level values
# ---------------------------------------------------------------------------

def test_scan_text_risk_level_valid_values(engine):
    valid = {"low", "medium", "high", "critical"}
    result = engine.scan_text("email@test.com and 4111111111111111")
    assert result["risk_level"] in valid


def test_scan_text_critical_card_gives_critical_risk(engine):
    result = engine.scan_text("4111111111111111")
    assert result["risk_level"] == "critical"


# ---------------------------------------------------------------------------
# 5. Findings structure — privacy guarantee
# ---------------------------------------------------------------------------

def test_findings_never_contain_raw_match(engine):
    """Raw matched values must NOT appear in findings."""
    raw_card = "4111111111111111"
    result = engine.scan_text(f"Charge {raw_card} now")
    for finding in result["findings"]:
        # redacted_sample should NOT equal the full raw value
        assert finding.get("redacted_sample") != raw_card


def test_findings_have_required_keys(engine):
    result = engine.scan_text("alice@example.com")
    assert result["total_findings"] > 0
    for f in result["findings"]:
        for key in ("pattern_name", "severity", "category", "match_count", "redacted_sample"):
            assert key in f, f"Finding missing key: {key}"


def test_findings_match_count_positive(engine):
    result = engine.scan_text("alice@example.com bob@example.org")
    emails = [f for f in result["findings"] if f["pattern_name"] == "email_address"]
    assert emails[0]["match_count"] >= 1


# ---------------------------------------------------------------------------
# 6. Redaction
# ---------------------------------------------------------------------------

def test_redact_text_removes_sensitive_values(engine):
    text = "My email is alice@example.com"
    redacted = engine.redact_text(text)
    assert "alice@example.com" not in redacted


def test_redact_text_contains_redacted_placeholder(engine):
    text = "My email is alice@example.com"
    redacted = engine.redact_text(text)
    assert "[REDACTED" in redacted


def test_redact_text_clean_text_unchanged_structure(engine):
    text = "Nothing sensitive here at all."
    redacted = engine.redact_text(text)
    # No REDACTED placeholders should appear for clean text
    assert "[REDACTED" not in redacted


# ---------------------------------------------------------------------------
# 7. Storage and retrieval
# ---------------------------------------------------------------------------

def test_get_scan_result_retrieves_stored_result(engine):
    result = engine.scan_text("alice@example.com", context="test-ctx")
    scan_id = result["scan_id"]
    retrieved = engine.get_scan_result(scan_id)
    assert retrieved is not None
    assert retrieved["scan_id"] == scan_id


def test_get_scan_result_returns_none_for_unknown(engine):
    assert engine.get_scan_result("nonexistent-id-12345") is None


def test_list_scan_results_returns_list(engine):
    engine.scan_text("alice@example.com")
    results = engine.list_scan_results()
    assert isinstance(results, list)
    assert len(results) >= 1


def test_list_scan_results_risk_level_filter(engine):
    # Generate a critical scan and a clean (low-risk) scan
    engine.scan_text("4111111111111111", org_id="filter-org")
    engine.scan_text("nothing sensitive", org_id="filter-org")
    critical_results = engine.list_scan_results(org_id="filter-org", risk_level="critical")
    for r in critical_results:
        assert r["risk_level"] == "critical"


# ---------------------------------------------------------------------------
# 8. Stats
# ---------------------------------------------------------------------------

def test_get_stats_returns_numeric_dict(engine):
    engine.scan_text("alice@example.com 4111111111111111")
    stats = engine.get_stats()
    assert isinstance(stats, dict)
    assert isinstance(stats["total_scans"], int)
    assert isinstance(stats["total_findings"], int)
    assert isinstance(stats["by_category"], dict)
    assert isinstance(stats["by_severity"], dict)
    assert isinstance(stats["critical_scans"], int)


def test_get_stats_counts_increase(engine):
    stats_before = engine.get_stats(org_id="stats-org")
    engine.scan_text("alice@example.com", org_id="stats-org")
    stats_after = engine.get_stats(org_id="stats-org")
    assert stats_after["total_scans"] > stats_before["total_scans"]


# ---------------------------------------------------------------------------
# 9. Custom patterns
# ---------------------------------------------------------------------------

def test_add_custom_pattern_returns_dict(engine):
    result = engine.add_custom_pattern(
        name="internal_id",
        pattern=r"\bINT-\d{6}\b",
        severity="high",
        category="internal",
    )
    assert isinstance(result, dict)
    assert result["name"] == "internal_id"


def test_custom_pattern_detected_after_add(engine):
    engine.add_custom_pattern(
        name="ticket_id",
        pattern=r"\bTICKET-\d{4}\b",
        severity="medium",
        category="internal",
        org_id="custom-org",
    )
    result = engine.scan_text("Reference TICKET-1234 for this issue", org_id="custom-org")
    pattern_names = [f["pattern_name"] for f in result["findings"]]
    assert "ticket_id" in pattern_names


# ---------------------------------------------------------------------------
# 10. File scanning
# ---------------------------------------------------------------------------

def test_scan_file_returns_same_shape_as_scan_text(engine, tmp_path):
    f = tmp_path / "sample.txt"
    f.write_text("Contact alice@example.com for details")
    result = engine.scan_file(str(f))
    for key in ("scan_id", "total_findings", "findings", "categories_found", "risk_level"):
        assert key in result


def test_scan_file_raises_for_missing_file(engine):
    with pytest.raises(ValueError):
        engine.scan_file("/nonexistent/path/secret.txt")
