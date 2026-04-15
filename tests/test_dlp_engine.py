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


# ---------------------------------------------------------------------------
# 11. Policy CRUD
# ---------------------------------------------------------------------------

def test_create_policy_returns_dict(engine):
    pol = engine.create_policy("org1", {
        "policy_name": "Credit Card Policy",
        "data_types": ["credit_card"],
        "channels": ["email"],
        "action": "block",
        "severity": "critical",
    })
    assert isinstance(pol, dict)
    assert pol["policy_name"] == "Credit Card Policy"
    assert "id" in pol


def test_create_policy_has_uuid_id(engine):
    pol = engine.create_policy("org1", {
        "policy_name": "SSN Policy",
        "data_types": ["ssn"],
        "channels": ["web"],
        "action": "alert",
        "severity": "high",
    })
    import uuid
    uuid.UUID(pol["id"])  # raises if not valid UUID


def test_create_policy_defaults(engine):
    pol = engine.create_policy("org1", {"policy_name": "Minimal Policy"})
    assert pol["action"] == "alert"
    assert pol["severity"] == "medium"
    assert pol["enabled"] is True
    assert pol["hit_count"] == 0


def test_create_policy_requires_name(engine):
    with pytest.raises((ValueError, Exception)):
        engine.create_policy("org1", {})


def test_list_policies_returns_created(engine):
    engine.create_policy("org2", {"policy_name": "P1", "data_types": ["email"]})
    engine.create_policy("org2", {"policy_name": "P2", "data_types": ["ssn"]})
    policies = engine.list_policies("org2")
    assert len(policies) >= 2
    names = [p["policy_name"] for p in policies]
    assert "P1" in names
    assert "P2" in names


def test_list_policies_enabled_filter(engine):
    engine.create_policy("org3", {"policy_name": "Enabled", "enabled": True})
    engine.create_policy("org3", {"policy_name": "Disabled", "enabled": False})
    enabled = engine.list_policies("org3", enabled=True)
    for p in enabled:
        assert p["enabled"] is True


def test_get_policy_returns_correct_record(engine):
    pol = engine.create_policy("org4", {"policy_name": "GetTest", "data_types": ["phone"]})
    retrieved = engine.get_policy("org4", pol["id"])
    assert retrieved is not None
    assert retrieved["id"] == pol["id"]
    assert retrieved["policy_name"] == "GetTest"


def test_get_policy_wrong_org_returns_none(engine):
    pol = engine.create_policy("org5", {"policy_name": "Isolated"})
    result = engine.get_policy("other_org", pol["id"])
    assert result is None


# ---------------------------------------------------------------------------
# 12. Incident Detection
# ---------------------------------------------------------------------------

def test_detect_incident_no_matching_policy_returns_none(engine):
    result = engine.detect_incident("orgX", {
        "data_type": "credit_card",
        "channel": "email",
        "content": "4111111111111111",
    })
    assert result is None


def test_detect_incident_matching_policy_creates_incident(engine):
    engine.create_policy("orgD", {
        "policy_name": "CC Block",
        "data_types": ["credit_card"],
        "channels": ["email"],
        "action": "block",
        "severity": "critical",
    })
    incident = engine.detect_incident("orgD", {
        "data_type": "credit_card",
        "channel": "email",
        "content": "4111111111111111",
        "user_email": "alice@example.com",
    })
    assert incident is not None
    assert "id" in incident
    assert incident["action_taken"] == "blocked"
    assert incident["severity"] == "critical"
    assert incident["status"] == "new"


def test_detect_incident_increments_policy_hit_count(engine):
    pol = engine.create_policy("orgE", {
        "policy_name": "Hit Counter",
        "data_types": ["ssn"],
        "channels": ["web"],
        "action": "alert",
        "severity": "high",
    })
    engine.detect_incident("orgE", {"data_type": "ssn", "channel": "web"})
    engine.detect_incident("orgE", {"data_type": "ssn", "channel": "web"})
    updated = engine.get_policy("orgE", pol["id"])
    assert updated["hit_count"] >= 2


def test_detect_incident_pii_is_masked(engine):
    engine.create_policy("orgF", {
        "policy_name": "Email Mask",
        "data_types": ["email"],
        "channels": ["web"],
        "action": "alert",
        "severity": "medium",
    })
    incident = engine.detect_incident("orgF", {
        "data_type": "email",
        "channel": "web",
        "content": "alice@example.com",
    })
    assert incident is not None
    assert "alice@example.com" not in incident["detected_pattern"]
    assert "alice@example.com" not in incident["content_preview"]


def test_detect_incident_channel_mismatch_no_fire(engine):
    engine.create_policy("orgG", {
        "policy_name": "Email Only",
        "data_types": ["credit_card"],
        "channels": ["email"],
        "action": "block",
        "severity": "critical",
    })
    result = engine.detect_incident("orgG", {
        "data_type": "credit_card",
        "channel": "usb",  # wrong channel
        "content": "4111111111111111",
    })
    assert result is None


# ---------------------------------------------------------------------------
# 13. PII Masking
# ---------------------------------------------------------------------------

def test_mask_pii_credit_card(engine):
    masked = engine._mask_pii("4111111111111111", "credit_card")
    assert "4111111111111111" not in masked
    assert "****" in masked


def test_mask_pii_ssn(engine):
    masked = engine._mask_pii("123-45-6789", "ssn")
    assert "123-45" not in masked
    assert "***" in masked


def test_mask_pii_email(engine):
    masked = engine._mask_pii("alice@example.com", "email")
    assert "alice" not in masked or "***" in masked


def test_mask_pii_ip_address(engine):
    masked = engine._mask_pii("192.168.1.100", "ip_address")
    assert "100" not in masked or "*" in masked


# ---------------------------------------------------------------------------
# 14. Incident Management
# ---------------------------------------------------------------------------

def test_list_incidents_returns_list(engine):
    engine.create_policy("orgH", {
        "policy_name": "List Test",
        "data_types": ["phone"],
        "channels": ["usb"],
        "action": "quarantine",
        "severity": "high",
    })
    engine.detect_incident("orgH", {"data_type": "phone", "channel": "usb"})
    incidents = engine.list_incidents("orgH")
    assert isinstance(incidents, list)
    assert len(incidents) >= 1


def test_list_incidents_severity_filter(engine):
    engine.create_policy("orgI", {
        "policy_name": "Critical Policy",
        "data_types": ["passport"],
        "channels": ["print"],
        "action": "block",
        "severity": "critical",
    })
    engine.detect_incident("orgI", {"data_type": "passport", "channel": "print"})
    critical_incidents = engine.list_incidents("orgI", severity="critical")
    for inc in critical_incidents:
        assert inc["severity"] == "critical"


def test_update_incident_status(engine):
    engine.create_policy("orgJ", {
        "policy_name": "Status Test",
        "data_types": ["iban"],
        "channels": ["cloud_upload"],
        "action": "alert",
        "severity": "high",
    })
    incident = engine.detect_incident("orgJ", {
        "data_type": "iban",
        "channel": "cloud_upload",
    })
    assert incident is not None
    updated = engine.update_incident_status("orgJ", incident["id"], "investigating")
    assert updated is True
    incidents = engine.list_incidents("orgJ", status="investigating")
    assert any(i["id"] == incident["id"] for i in incidents)


def test_update_incident_status_invalid_raises(engine):
    with pytest.raises(ValueError):
        engine.update_incident_status("orgJ", "fake-id", "invalid_status")


# ---------------------------------------------------------------------------
# 15. Exceptions
# ---------------------------------------------------------------------------

def test_create_exception_returns_dict(engine):
    exc_rec = engine.create_exception("orgK", {
        "user_id": "user-123",
        "policy_id": "pol-456",
        "reason": "Approved for quarterly reporting",
        "approved_by": "ciso@example.com",
    })
    assert isinstance(exc_rec, dict)
    assert exc_rec["user_id"] == "user-123"
    assert "id" in exc_rec


def test_create_exception_requires_user_id(engine):
    with pytest.raises(ValueError):
        engine.create_exception("orgK", {"reason": "No user"})


def test_list_exceptions_returns_created(engine):
    engine.create_exception("orgL", {"user_id": "u1", "reason": "R1"})
    engine.create_exception("orgL", {"user_id": "u2", "reason": "R2"})
    exceptions = engine.list_exceptions("orgL")
    assert len(exceptions) >= 2


# ---------------------------------------------------------------------------
# 16. Stats and Daily Trends
# ---------------------------------------------------------------------------

def test_get_dlp_stats_returns_dict(engine):
    stats = engine.get_dlp_stats("orgM")
    assert isinstance(stats, dict)
    assert "total_incidents" in stats
    assert "by_severity" in stats
    assert "by_channel" in stats
    assert "by_data_type" in stats
    assert "block_rate" in stats
    assert "false_positive_rate" in stats
    assert "top_users" in stats
    assert "top_policies" in stats


def test_get_dlp_stats_counts_incidents(engine):
    engine.create_policy("orgN", {
        "policy_name": "Stats Policy",
        "data_types": ["medical"],
        "channels": ["clipboard"],
        "action": "alert",
        "severity": "high",
    })
    engine.detect_incident("orgN", {"data_type": "medical", "channel": "clipboard"})
    stats = engine.get_dlp_stats("orgN")
    assert stats["total_incidents"] >= 1


def test_get_daily_trends_returns_list(engine):
    trends = engine.get_daily_trends("orgO", days=30)
    assert isinstance(trends, list)


# ---------------------------------------------------------------------------
# 17. Org Isolation
# ---------------------------------------------------------------------------

def test_org_isolation_policies(engine):
    engine.create_policy("orgP", {"policy_name": "Org P Policy", "data_types": ["ssn"]})
    engine.create_policy("orgQ", {"policy_name": "Org Q Policy", "data_types": ["email"]})
    p_policies = engine.list_policies("orgP")
    q_policies = engine.list_policies("orgQ")
    p_names = [p["policy_name"] for p in p_policies]
    q_names = [p["policy_name"] for p in q_policies]
    assert "Org P Policy" in p_names
    assert "Org Q Policy" not in p_names
    assert "Org Q Policy" in q_names
    assert "Org P Policy" not in q_names


def test_org_isolation_incidents(engine):
    engine.create_policy("orgR", {
        "policy_name": "R Policy",
        "data_types": ["credit_card"],
        "channels": ["email"],
        "action": "block",
        "severity": "critical",
    })
    engine.detect_incident("orgR", {"data_type": "credit_card", "channel": "email"})
    # orgS has no policies, so no incidents
    incidents_s = engine.list_incidents("orgS")
    assert len(incidents_s) == 0
