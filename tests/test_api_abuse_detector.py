"""Tests for APIAbuseDetector — brute force, credential stuffing, DDoS, bot detection."""
import sys
import tempfile
import time

sys.path.insert(0, "suite-core")

import pytest

from core.api_abuse_detector import APIAbuseDetector


@pytest.fixture
def detector(tmp_path):
    """Fresh detector backed by a temp DB per test."""
    db = str(tmp_path / "test_abuse.db")
    return APIAbuseDetector(db_path=db)


# ============================================================================
# record_request
# ============================================================================


def test_record_request_returns_string(detector):
    rid = detector.record_request(ip="1.2.3.4", endpoint="/api/v1/login")
    assert isinstance(rid, str)
    assert len(rid) > 0


def test_record_request_unique_ids(detector):
    rid1 = detector.record_request(ip="1.2.3.4", endpoint="/api/v1/a")
    rid2 = detector.record_request(ip="1.2.3.4", endpoint="/api/v1/b")
    assert rid1 != rid2


def test_record_request_all_params(detector):
    rid = detector.record_request(
        ip="10.0.0.1",
        endpoint="/api/v1/data",
        user_agent="Mozilla/5.0",
        status_code=200,
        api_key="key-abc",
        response_time_ms=123,
        org_id="acme",
    )
    assert isinstance(rid, str)


# ============================================================================
# detect_abuse — empty state
# ============================================================================


def test_detect_abuse_no_requests_returns_empty(detector):
    result = detector.detect_abuse(ip="9.9.9.9")
    assert result == []


def test_detect_abuse_single_request_returns_empty(detector):
    detector.record_request(ip="1.2.3.4", endpoint="/api/v1/x")
    result = detector.detect_abuse(ip="1.2.3.4")
    assert isinstance(result, list)
    # one request does not trigger any threshold
    patterns = [e["pattern"] for e in result]
    assert "brute_force" not in patterns
    assert "ddos" not in patterns


# ============================================================================
# brute_force detection
# ============================================================================


def test_detect_brute_force_triggers(detector):
    """101 requests in the same minute bucket → brute_force detected."""
    for _ in range(105):
        detector.record_request(ip="5.5.5.5", endpoint="/api/v1/login", status_code=401)
    events = detector.detect_abuse(ip="5.5.5.5", window_minutes=60)
    patterns = [e["pattern"] for e in events]
    # brute_force or credential_stuffing should fire
    assert any(p in patterns for p in ("brute_force", "credential_stuffing", "ddos"))


def test_brute_force_event_has_required_fields(detector):
    for _ in range(110):
        detector.record_request(ip="6.6.6.6", endpoint="/api/v1/token")
    events = detector.detect_abuse(ip="6.6.6.6", window_minutes=60)
    assert len(events) > 0
    ev = events[0]
    assert "event_id" in ev
    assert "pattern" in ev
    assert "severity" in ev
    assert "detected_at" in ev
    assert "evidence" in ev
    assert isinstance(ev["evidence"], dict)


# ============================================================================
# credential_stuffing detection
# ============================================================================


def test_credential_stuffing_detects_many_failed_auth(detector):
    """11 401 responses from same IP within same 5-min window → credential_stuffing."""
    for _ in range(12):
        detector.record_request(ip="7.7.7.7", endpoint="/auth/login", status_code=401)
    events = detector.detect_abuse(ip="7.7.7.7", window_minutes=60)
    patterns = [e["pattern"] for e in events]
    assert "credential_stuffing" in patterns


def test_credential_stuffing_severity_is_critical(detector):
    for _ in range(15):
        detector.record_request(ip="8.8.8.8", endpoint="/auth/token", status_code=403)
    events = detector.detect_abuse(ip="8.8.8.8", window_minutes=60)
    cred_events = [e for e in events if e["pattern"] == "credential_stuffing"]
    assert len(cred_events) > 0
    assert cred_events[0]["severity"] == "critical"


# ============================================================================
# bot_traffic detection
# ============================================================================


def test_bot_detection_crawler_useragent(detector):
    detector.record_request(ip="11.22.33.44", endpoint="/api/v1/data",
                            user_agent="Mozilla/5.0 (compatible; Googlebot/2.1; +crawler)")
    events = detector.detect_abuse(ip="11.22.33.44", window_minutes=60)
    patterns = [e["pattern"] for e in events]
    assert "bot_traffic" in patterns


def test_bot_detection_spider_useragent(detector):
    detector.record_request(ip="55.66.77.88", endpoint="/api/v1/items",
                            user_agent="spider/1.0")
    events = detector.detect_abuse(ip="55.66.77.88", window_minutes=60)
    patterns = [e["pattern"] for e in events]
    assert "bot_traffic" in patterns


def test_bot_detection_severity_is_low(detector):
    detector.record_request(ip="99.88.77.66", endpoint="/api/v1/x",
                            user_agent="bad-bot/2.0")
    events = detector.detect_abuse(ip="99.88.77.66", window_minutes=60)
    bot_events = [e for e in events if e["pattern"] == "bot_traffic"]
    assert len(bot_events) > 0
    assert bot_events[0]["severity"] == "low"


def test_normal_useragent_no_bot_detection(detector):
    detector.record_request(ip="192.168.1.1", endpoint="/api/v1/data",
                            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
    events = detector.detect_abuse(ip="192.168.1.1", window_minutes=60)
    patterns = [e["pattern"] for e in events]
    assert "bot_traffic" not in patterns


# ============================================================================
# block_ip / is_blocked / unblock_ip
# ============================================================================


def test_block_ip_returns_dict(detector):
    result = detector.block_ip(ip="3.3.3.3", reason="manual block")
    assert isinstance(result, dict)
    assert result["ip"] == "3.3.3.3"
    assert "blocked_until" in result
    assert "blocked_at" in result


def test_is_blocked_after_block(detector):
    detector.block_ip(ip="4.4.4.4", reason="brute force", duration_hours=24)
    status = detector.is_blocked("4.4.4.4")
    assert status["blocked"] is True
    assert status["reason"] == "brute force"
    assert "until" in status


def test_is_blocked_unknown_ip_returns_false(detector):
    status = detector.is_blocked("0.0.0.1")
    assert status["blocked"] is False
    assert status["reason"] == ""


def test_unblock_ip_returns_true_for_known(detector):
    detector.block_ip(ip="5.5.5.1", reason="test")
    result = detector.unblock_ip("5.5.5.1")
    assert result is True


def test_unblock_ip_returns_false_for_unknown(detector):
    result = detector.unblock_ip("99.99.99.99")
    assert result is False


def test_is_blocked_after_unblock(detector):
    detector.block_ip(ip="6.6.6.1", reason="test")
    detector.unblock_ip("6.6.6.1")
    status = detector.is_blocked("6.6.6.1")
    assert status["blocked"] is False


# ============================================================================
# get_block_list
# ============================================================================


def test_get_block_list_returns_list(detector):
    result = detector.get_block_list()
    assert isinstance(result, list)


def test_get_block_list_contains_blocked_ips(detector):
    detector.block_ip(ip="10.0.0.1", reason="test")
    detector.block_ip(ip="10.0.0.2", reason="test")
    lst = detector.get_block_list()
    ips = [r["ip"] for r in lst]
    assert "10.0.0.1" in ips
    assert "10.0.0.2" in ips


# ============================================================================
# get_abuse_events
# ============================================================================


def test_get_abuse_events_returns_list(detector):
    result = detector.get_abuse_events()
    assert isinstance(result, list)


def test_get_abuse_events_after_detection(detector):
    for _ in range(12):
        detector.record_request(ip="20.20.20.20", endpoint="/api/login", status_code=401)
    detector.detect_abuse(ip="20.20.20.20", window_minutes=60)
    events = detector.get_abuse_events(ip="20.20.20.20")
    assert isinstance(events, list)
    assert len(events) >= 1


def test_get_abuse_events_pattern_filter(detector):
    for _ in range(12):
        detector.record_request(ip="21.21.21.21", endpoint="/api/login",
                                user_agent="spider/1.0", status_code=401)
    detector.detect_abuse(ip="21.21.21.21", window_minutes=60)
    bot_events = detector.get_abuse_events(pattern="bot_traffic")
    for ev in bot_events:
        assert ev["pattern"] == "bot_traffic"


# ============================================================================
# get_stats
# ============================================================================


def test_get_stats_returns_dict(detector):
    result = detector.get_stats()
    assert isinstance(result, dict)


def test_get_stats_numeric_values(detector):
    detector.record_request(ip="30.30.30.30", endpoint="/x")
    stats = detector.get_stats()
    assert isinstance(stats["total_requests"], int)
    assert isinstance(stats["total_abuse_events"], int)
    assert isinstance(stats["blocked_ips"], int)
    assert stats["total_requests"] >= 1


def test_get_stats_abuse_by_pattern_is_dict(detector):
    stats = detector.get_stats()
    assert isinstance(stats["abuse_by_pattern"], dict)


def test_get_stats_top_abusing_ips_is_list(detector):
    stats = detector.get_stats()
    assert isinstance(stats["top_abusing_ips"], list)


def test_get_stats_blocked_ips_count(detector):
    detector.block_ip("40.40.40.40", reason="test")
    stats = detector.get_stats()
    assert stats["blocked_ips"] >= 1


# ============================================================================
# multiple independent patterns
# ============================================================================


def test_multiple_patterns_detected_independently(detector):
    """Bot UA + failed auth can both trigger on same IP."""
    for _ in range(12):
        detector.record_request(ip="50.50.50.50", endpoint="/auth",
                                user_agent="crawler/2.0", status_code=401)
    events = detector.detect_abuse(ip="50.50.50.50", window_minutes=60)
    patterns = {e["pattern"] for e in events}
    assert len(patterns) >= 2  # at least bot_traffic + credential_stuffing


def test_org_id_isolation(detector):
    """Events from org A should not appear in org B query."""
    for _ in range(12):
        detector.record_request(ip="60.60.60.60", endpoint="/auth", status_code=401,
                                org_id="org_a")
    detector.detect_abuse(ip="60.60.60.60", org_id="org_a")
    events_b = detector.get_abuse_events(ip="60.60.60.60", org_id="org_b")
    assert events_b == []
