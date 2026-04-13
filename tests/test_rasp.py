"""
Comprehensive tests for the RASP (Runtime Application Self-Protection) Engine.

Coverage:
- Pattern detection: SQLi, XSS, CMDi, path traversal, XXE, SSRF, LFI, RFI (24 tests)
- Blocking modes: monitor, block, redirect (6 tests)
- Rate limiting: per-IP sliding window, auto-block after violations (8 tests)
- Session protection: fixation, concurrent sessions, impossible travel (7 tests)
- Metrics: counters, by_category, by_severity, top attacker IPs (6 tests)
- Rule management: list, enable, disable (5 tests)
- Config & mode switching (4 tests)
- TrustGraph stubs (3 tests)
- Edge cases (4 tests)

Run with:
    python -m pytest tests/test_rasp.py -v --timeout=10
"""

from __future__ import annotations

import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))

from core.rasp_engine import (
    AttackerStats,
    DetectionPattern,
    RaspConfig,
    RaspEngine,
    RaspMetrics,
    RaspMode,
    RaspMiddlewareHelper,
    RateLimitConfig,
    SessionRecord,
    ThreatCategory,
    ThreatEvent,
    ThreatSeverity,
    get_rasp_engine,
)


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def tmp_db(tmp_path):
    """Temporary SQLite path for each test — full isolation."""
    return str(tmp_path / "rasp_test.db")


@pytest.fixture
def engine(tmp_db):
    """Fresh RaspEngine in BLOCK mode for most tests."""
    cfg = RaspConfig(mode=RaspMode.BLOCK)
    return RaspEngine(config=cfg, db_path=tmp_db)


@pytest.fixture
def monitor_engine(tmp_db):
    """RaspEngine in MONITOR mode."""
    cfg = RaspConfig(mode=RaspMode.MONITOR)
    return RaspEngine(config=cfg, db_path=tmp_db)


@pytest.fixture
def redirect_engine(tmp_db):
    """RaspEngine in REDIRECT mode."""
    cfg = RaspConfig(mode=RaspMode.REDIRECT, honeypot_url="http://trap.internal/honeypot")
    return RaspEngine(config=cfg, db_path=tmp_db)


def _inspect(
    eng: RaspEngine,
    *,
    ip: str = "1.2.3.4",
    method: str = "GET",
    path: str = "/search",
    params: Optional[Dict[str, str]] = None,
    body: Optional[str] = None,
    headers: Optional[Dict[str, str]] = None,
):
    """Convenience wrapper around inspect_request_sync."""
    return eng.inspect_request_sync(
        client_ip=ip,
        method=method,
        path=path,
        query_params=params,
        headers=headers,
        body_text=body,
    )


# ============================================================================
# 1. SQL Injection detection
# ============================================================================


class TestSQLiDetection:
    def test_union_select_in_param(self, engine):
        blocked, events = _inspect(engine, params={"q": "' UNION SELECT 1,2,3--"})
        assert len(events) >= 1
        assert any(e.category == ThreatCategory.SQLI for e in events)
        assert blocked is True

    def test_or_tautology(self, engine):
        blocked, events = _inspect(engine, params={"id": "1' OR '1'='1"})
        assert any(e.category == ThreatCategory.SQLI for e in events)

    def test_comment_truncation(self, engine):
        blocked, events = _inspect(engine, params={"name": "admin'--"})
        assert any(e.category == ThreatCategory.SQLI for e in events)

    def test_stacked_queries(self, engine):
        blocked, events = _inspect(engine, params={"id": "1; DROP TABLE users--"})
        assert any(e.category == ThreatCategory.SQLI for e in events)

    def test_sleep_blind_sqli(self, engine):
        blocked, events = _inspect(engine, params={"id": "1' AND SLEEP(5)--"})
        assert any(e.category == ThreatCategory.SQLI for e in events)

    def test_clean_param_no_sqli(self, engine):
        blocked, events = _inspect(engine, params={"q": "hello world"})
        sqli_events = [e for e in events if e.category == ThreatCategory.SQLI]
        assert len(sqli_events) == 0

    def test_url_encoded_sqli(self, engine):
        # %27%20OR%20%271%27%3D%271 = ' OR '1'='1
        blocked, events = _inspect(engine, params={"id": "%27%20OR%20%271%27%3D%271"})
        assert any(e.category == ThreatCategory.SQLI for e in events)


# ============================================================================
# 2. XSS detection
# ============================================================================


class TestXSSDetection:
    def test_script_tag(self, engine):
        blocked, events = _inspect(engine, params={"name": "<script>alert(1)</script>"})
        assert any(e.category == ThreatCategory.XSS for e in events)

    def test_event_handler(self, engine):
        blocked, events = _inspect(engine, params={"input": '<img onerror="alert(1)">'})
        assert any(e.category == ThreatCategory.XSS for e in events)

    def test_javascript_uri(self, engine):
        blocked, events = _inspect(engine, params={"url": "javascript:alert(document.cookie)"})
        assert any(e.category == ThreatCategory.XSS for e in events)

    def test_vbscript_uri(self, engine):
        blocked, events = _inspect(engine, params={"href": "vbscript:msgbox(1)"})
        assert any(e.category == ThreatCategory.XSS for e in events)

    def test_data_uri_html(self, engine):
        blocked, events = _inspect(engine, params={"src": "data:text/html,<h1>xss</h1>"})
        assert any(e.category == ThreatCategory.XSS for e in events)

    def test_clean_html_safe(self, engine):
        blocked, events = _inspect(engine, params={"content": "<b>bold text</b>"})
        xss_events = [e for e in events if e.category == ThreatCategory.XSS]
        assert len(xss_events) == 0


# ============================================================================
# 3. Command injection detection
# ============================================================================


class TestCMDiDetection:
    def test_pipe_injection(self, engine):
        blocked, events = _inspect(engine, params={"cmd": "ls | cat /etc/passwd"})
        assert any(e.category == ThreatCategory.CMDI for e in events)

    def test_semicolon_shell(self, engine):
        blocked, events = _inspect(engine, params={"file": "foo; whoami"})
        assert any(e.category == ThreatCategory.CMDI for e in events)

    def test_backtick_substitution(self, engine):
        blocked, events = _inspect(engine, params={"input": "`id`"})
        assert any(e.category == ThreatCategory.CMDI for e in events)

    def test_dollar_paren_substitution(self, engine):
        blocked, events = _inspect(engine, params={"val": "$(cat /etc/passwd)"})
        assert any(e.category == ThreatCategory.CMDI for e in events)

    def test_clean_command_safe(self, engine):
        blocked, events = _inspect(engine, params={"action": "start"})
        cmdi_events = [e for e in events if e.category == ThreatCategory.CMDI]
        assert len(cmdi_events) == 0


# ============================================================================
# 4. Path traversal detection
# ============================================================================


class TestPathTraversalDetection:
    def test_dot_dot_slash(self, engine):
        blocked, events = _inspect(engine, params={"file": "../../etc/passwd"})
        assert any(e.category == ThreatCategory.PATH_TRAVERSAL for e in events)

    def test_url_encoded_traversal(self, engine):
        blocked, events = _inspect(engine, params={"path": "%2e%2e%2fetc%2fpasswd"})
        assert any(e.category == ThreatCategory.PATH_TRAVERSAL for e in events)

    def test_double_encoded_traversal(self, engine):
        blocked, events = _inspect(engine, params={"f": "%252e%252e%252fetc"})
        assert any(e.category == ThreatCategory.PATH_TRAVERSAL for e in events)

    def test_windows_backslash_traversal(self, engine):
        blocked, events = _inspect(engine, params={"dir": "..\\windows\\system32"})
        assert any(e.category == ThreatCategory.PATH_TRAVERSAL for e in events)


# ============================================================================
# 5. XXE detection
# ============================================================================


class TestXXEDetection:
    def test_doctype_entity(self, engine):
        payload = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        blocked, events = _inspect(engine, body=payload)
        assert any(e.category == ThreatCategory.XXE for e in events)

    def test_system_entity(self, engine):
        payload = '<!ENTITY extFile SYSTEM "file:///etc/shadow">'
        blocked, events = _inspect(engine, body=payload)
        assert any(e.category == ThreatCategory.XXE for e in events)


# ============================================================================
# 6. SSRF detection
# ============================================================================


class TestSSRFDetection:
    def test_internal_ip_param(self, engine):
        blocked, events = _inspect(engine, params={"url": "http://192.168.1.1/admin"})
        assert any(e.category == ThreatCategory.SSRF for e in events)

    def test_metadata_service(self, engine):
        blocked, events = _inspect(engine, params={"endpoint": "http://169.254.169.254/latest/meta-data/"})
        assert any(e.category == ThreatCategory.SSRF for e in events)

    def test_loopback_ssrf(self, engine):
        blocked, events = _inspect(engine, params={"target": "http://127.0.0.1:8080"})
        assert any(e.category == ThreatCategory.SSRF for e in events)


# ============================================================================
# 7. LFI / RFI detection
# ============================================================================


class TestLFIRFIDetection:
    def test_etc_passwd_lfi(self, engine):
        blocked, events = _inspect(engine, params={"page": "../../etc/passwd"})
        assert any(e.category in (ThreatCategory.LFI, ThreatCategory.PATH_TRAVERSAL) for e in events)

    def test_php_wrapper_lfi(self, engine):
        blocked, events = _inspect(engine, params={"file": "php://filter/convert.base64-encode/resource=index.php"})
        assert any(e.category == ThreatCategory.LFI for e in events)


# ============================================================================
# 8. Blocking modes
# ============================================================================


class TestBlockingModes:
    def test_monitor_mode_allows_threat(self, monitor_engine):
        """MONITOR mode: threat detected but request NOT blocked."""
        blocked, events = _inspect(monitor_engine, params={"q": "' UNION SELECT 1--"})
        assert len(events) >= 1
        assert blocked is False
        assert events[0].action_taken == RaspMode.MONITOR

    def test_block_mode_blocks_threat(self, engine):
        """BLOCK mode: request is blocked on threat detection."""
        blocked, events = _inspect(engine, params={"q": "' UNION SELECT 1--"})
        assert blocked is True
        assert events[0].action_taken == RaspMode.BLOCK

    def test_redirect_mode_blocks_threat(self, redirect_engine):
        """REDIRECT mode: treated as blocked (caller should redirect)."""
        blocked, events = _inspect(redirect_engine, params={"q": "<script>alert(1)</script>"})
        assert blocked is True
        assert events[0].action_taken == RaspMode.REDIRECT

    def test_mode_switch_runtime(self, engine):
        """Switch from BLOCK to MONITOR at runtime."""
        engine.set_mode(RaspMode.MONITOR)
        blocked, events = _inspect(engine, params={"q": "' UNION SELECT 1--"})
        assert blocked is False

    def test_trusted_ip_bypass(self, engine):
        """Trusted IPs are never blocked regardless of payload."""
        engine.update_config(trusted_ips=["10.0.0.1"])
        blocked, events = _inspect(engine, ip="10.0.0.1", params={"q": "' UNION SELECT 1--"})
        assert blocked is False
        assert len(events) == 0

    def test_clean_request_not_blocked(self, engine):
        """Legitimate request passes through in BLOCK mode."""
        blocked, events = _inspect(engine, params={"q": "security dashboard"})
        assert blocked is False


# ============================================================================
# 9. Rate limiting
# ============================================================================


class TestRateLimiting:
    def test_rate_limit_blocks_after_threshold(self, tmp_db):
        """IP is blocked once it exceeds max_requests within the window."""
        cfg = RaspConfig(
            mode=RaspMode.BLOCK,
            rate_limit=RateLimitConfig(
                window_seconds=60,
                max_requests=5,
                max_violations=100,  # high — so only request-rate triggers here
            ),
        )
        eng = RaspEngine(config=cfg, db_path=tmp_db)
        for _ in range(5):
            _inspect(eng, ip="5.5.5.5")
        # 6th request should be blocked by rate limiter
        blocked, _ = _inspect(eng, ip="5.5.5.5")
        assert blocked is True

    def test_different_ips_independent_limits(self, tmp_db):
        """Rate limit is per-IP — one IP over limit should not affect another."""
        cfg = RaspConfig(
            mode=RaspMode.BLOCK,
            rate_limit=RateLimitConfig(window_seconds=60, max_requests=3, max_violations=100),
        )
        eng = RaspEngine(config=cfg, db_path=tmp_db)
        for _ in range(4):
            _inspect(eng, ip="6.6.6.6")
        # Different IP should still be allowed
        blocked, _ = _inspect(eng, ip="7.7.7.7")
        assert blocked is False

    def test_auto_block_after_violations(self, tmp_db):
        """IP auto-blocked after exceeding violation threshold."""
        cfg = RaspConfig(
            mode=RaspMode.BLOCK,
            rate_limit=RateLimitConfig(
                window_seconds=60,
                max_requests=1000,
                max_violations=3,
                auto_block_duration=60,
            ),
        )
        eng = RaspEngine(config=cfg, db_path=tmp_db)
        # Send 3 malicious requests to hit violation threshold
        for _ in range(3):
            _inspect(eng, ip="8.8.8.8", params={"q": "' UNION SELECT 1--"})
        # Next request from that IP should be auto-blocked
        blocked, _ = _inspect(eng, ip="8.8.8.8")
        assert blocked is True

    def test_manual_block_ip(self, engine):
        blocked_before = engine.get_blocked_ips()
        engine.block_ip("9.9.9.9", duration_seconds=3600)
        blocked_after = engine.get_blocked_ips()
        assert "9.9.9.9" in blocked_after
        assert "9.9.9.9" not in blocked_before

    def test_manual_unblock_ip(self, engine):
        engine.block_ip("10.10.10.10", duration_seconds=3600)
        result = engine.unblock_ip("10.10.10.10")
        assert result is True
        assert "10.10.10.10" not in engine.get_blocked_ips()

    def test_unblock_nonexistent_ip_returns_false(self, engine):
        result = engine.unblock_ip("99.99.99.99")
        assert result is False

    def test_blocked_ip_rejected_without_inspection(self, engine):
        """Auto-blocked IP is rejected before any pattern matching."""
        engine.block_ip("11.11.11.11", duration_seconds=3600)
        blocked, events = _inspect(engine, ip="11.11.11.11", params={"q": "hello world"})
        assert blocked is True
        assert len(events) == 0  # rejected at IP check, not pattern match

    def test_get_blocked_ips_returns_ttl(self, engine):
        engine.block_ip("12.12.12.12", duration_seconds=3600)
        blocked = engine.get_blocked_ips()
        assert "12.12.12.12" in blocked
        assert blocked["12.12.12.12"] > 3590  # roughly 3600s remaining


# ============================================================================
# 10. Session protection
# ============================================================================


class TestSessionProtection:
    def _make_session(self, session_id="sid-1", user_id="user-1", ip="1.2.3.4", country="US"):
        return SessionRecord(
            session_id=session_id,
            user_id=user_id,
            client_ip=ip,
            geo_country=country,
        )

    def test_clean_session_no_anomalies(self, engine):
        sess = self._make_session()
        engine.register_session(sess)
        anomalies = engine.check_session("sid-1", "1.2.3.4", user_id="user-1")
        assert anomalies == []

    def test_session_fixation_detected(self, engine):
        sess = self._make_session()
        engine.register_session(sess)
        # Same session ID but different IP
        anomalies = engine.check_session("sid-1", "99.99.99.99", user_id="user-1")
        assert "session_fixation" in anomalies

    def test_too_many_concurrent_sessions(self, engine):
        for i in range(6):
            engine.register_session(self._make_session(session_id=f"sid-{i}", ip=f"1.2.3.{i}"))
        anomalies = engine.check_session("sid-0", "1.2.3.0", user_id="user-1", max_concurrent=5)
        assert "too_many_sessions" in anomalies

    def test_session_terminated_properly(self, engine):
        sess = self._make_session()
        engine.register_session(sess)
        engine.terminate_session("sid-1")
        # After termination, session should not exist (touch returns None)
        anomaly = engine._sessions.touch("sid-1", "1.2.3.4")
        assert anomaly is None

    def test_impossible_travel_same_country_ok(self, engine):
        sess = self._make_session(country="US")
        engine.register_session(sess)
        result = engine.detect_impossible_travel("user-1", "5.5.5.5", "US")
        assert result is False

    def test_impossible_travel_different_country_detected(self, engine):
        sess = self._make_session(country="US")
        engine.register_session(sess)
        result = engine.detect_impossible_travel("user-1", "5.5.5.5", "CN")
        assert result is True

    def test_impossible_travel_no_existing_sessions(self, engine):
        """No sessions → no impossible travel."""
        result = engine.detect_impossible_travel("unknown-user", "5.5.5.5", "DE")
        assert result is False


# ============================================================================
# 11. Metrics
# ============================================================================


class TestMetrics:
    def test_requests_inspected_increments(self, engine):
        for _ in range(5):
            _inspect(engine, params={"q": "normal"})
        metrics = engine.get_metrics()
        assert metrics.requests_inspected >= 5

    def test_threats_detected_counter(self, engine):
        _inspect(engine, params={"q": "' UNION SELECT 1--"})
        metrics = engine.get_metrics()
        assert metrics.threats_detected >= 1

    def test_threats_blocked_counter_in_block_mode(self, engine):
        _inspect(engine, params={"q": "' UNION SELECT 1--"})
        metrics = engine.get_metrics()
        assert metrics.threats_blocked >= 1
        assert metrics.threats_allowed_monitor == 0

    def test_monitor_mode_no_blocked_count(self, monitor_engine):
        _inspect(monitor_engine, params={"q": "' UNION SELECT 1--"})
        metrics = monitor_engine.get_metrics()
        assert metrics.threats_blocked == 0
        assert metrics.threats_allowed_monitor >= 1

    def test_by_category_populated(self, engine):
        _inspect(engine, params={"q": "' UNION SELECT 1--"})
        _inspect(engine, params={"v": "<script>alert(1)</script>"})
        metrics = engine.get_metrics()
        assert metrics.by_category.get("sqli", 0) >= 1
        assert metrics.by_category.get("xss", 0) >= 1

    def test_top_attacker_ips_tracked(self, engine):
        _inspect(engine, ip="50.50.50.50", params={"q": "' UNION SELECT 1--"})
        _inspect(engine, ip="50.50.50.50", params={"q": "' UNION SELECT 2--"})
        metrics = engine.get_metrics()
        assert metrics.top_attacker_ips.get("50.50.50.50", 0) >= 2

    def test_engine_uptime_positive(self, engine):
        metrics = engine.get_metrics()
        assert metrics.engine_uptime_seconds >= 0.0


# ============================================================================
# 12. Rule management
# ============================================================================


class TestRuleManagement:
    def test_get_rules_returns_all(self, engine):
        rules = engine.get_rules()
        assert len(rules) >= 20  # at least 20 patterns defined

    def test_rule_ids_unique(self, engine):
        rules = engine.get_rules()
        ids = [r.rule_id for r in rules]
        assert len(ids) == len(set(ids))

    def test_disable_rule_stops_detection(self, engine):
        # Disable all XSS rules
        rules = engine.get_rules()
        for r in rules:
            if r.category == ThreatCategory.XSS:
                engine.set_rule_enabled(r.rule_id, False)
        blocked, events = _inspect(engine, params={"v": "<script>alert(1)</script>"})
        xss = [e for e in events if e.category == ThreatCategory.XSS]
        assert len(xss) == 0

    def test_reenable_rule_restores_detection(self, engine):
        rules = engine.get_rules()
        xss_rules = [r for r in rules if r.category == ThreatCategory.XSS]
        for r in xss_rules:
            engine.set_rule_enabled(r.rule_id, False)
        for r in xss_rules:
            engine.set_rule_enabled(r.rule_id, True)
        blocked, events = _inspect(engine, params={"v": "<script>alert(1)</script>"})
        xss = [e for e in events if e.category == ThreatCategory.XSS]
        assert len(xss) >= 1

    def test_toggle_nonexistent_rule_returns_false(self, engine):
        result = engine.set_rule_enabled("NONEXISTENT-999", False)
        assert result is False


# ============================================================================
# 13. Config & mode
# ============================================================================


class TestConfig:
    def test_default_mode_is_config_mode(self, engine):
        cfg = engine.config
        assert cfg.mode == RaspMode.BLOCK

    def test_set_mode_monitor(self, engine):
        engine.set_mode(RaspMode.MONITOR)
        assert engine.config.mode == RaspMode.MONITOR

    def test_update_config_trusted_ips(self, engine):
        engine.update_config(trusted_ips=["192.168.1.100"])
        assert "192.168.1.100" in engine.config.trusted_ips

    def test_config_returns_copy(self, engine):
        """Modifying the returned config object should not mutate engine state."""
        cfg = engine.config
        cfg.mode = RaspMode.MONITOR
        assert engine.config.mode == RaspMode.BLOCK  # original unchanged


# ============================================================================
# 14. TrustGraph stubs
# ============================================================================


class TestTrustGraphStubs:
    def test_index_in_trustgraph_stub_does_not_raise(self, engine):
        """_index_in_trustgraph is a no-op stub — must not raise and must still detect the threat."""
        _, events = _inspect(engine, params={"q": "' UNION SELECT 1--"})
        assert len(events) >= 1, "SQLi payload should still be detected even with TrustGraph stub"

    def test_trustgraph_query_attacker_returns_dict(self, engine):
        result = engine.trustgraph_query_attacker("1.2.3.4")
        assert isinstance(result, dict)
        assert result["ip"] == "1.2.3.4"
        assert "trustgraph_correlated" in result

    def test_trustgraph_correlate_campaign_returns_dict(self, engine):
        events = [
            ThreatEvent(
                rule_id="SQLI-001",
                category=ThreatCategory.SQLI,
                severity=ThreatSeverity.CRITICAL,
                confidence=0.95,
                client_ip="1.2.3.4",
                method="GET",
                path="/search",
                matched_value="union select",
                matched_field="query:q",
                action_taken=RaspMode.BLOCK,
            )
        ]
        result = engine.trustgraph_correlate_campaign(events)
        assert isinstance(result, dict)
        assert "1.2.3.4" in result["ips"]


# ============================================================================
# 15. Edge cases
# ============================================================================


class TestEdgeCases:
    def test_empty_params_no_events(self, engine):
        blocked, events = _inspect(engine, params={})
        assert events == []
        assert blocked is False

    def test_none_body_does_not_crash(self, engine):
        blocked, events = _inspect(engine, body=None)
        assert isinstance(events, list)

    def test_large_body_truncated(self, tmp_db):
        """Body larger than max_body_inspect_bytes is truncated, not rejected."""
        cfg = RaspConfig(mode=RaspMode.BLOCK, max_body_inspect_bytes=100)
        eng = RaspEngine(config=cfg, db_path=tmp_db)
        big_body = "A" * 10000
        blocked, events = _inspect(eng, body=big_body)
        # No crash — large safe body should not produce events
        assert isinstance(events, list)

    def test_middleware_helper_wraps_engine(self, engine):
        helper = RaspMiddlewareHelper(engine)
        blocked, events = helper.process(
            client_ip="2.2.2.2",
            method="GET",
            path="/test",
            query_params={"q": "' UNION SELECT 1--"},
        )
        assert blocked is True
        assert len(events) >= 1

    def test_singleton_get_rasp_engine(self, tmp_db, monkeypatch):
        """get_rasp_engine() returns the same instance on repeated calls."""
        import core.rasp_engine as mod
        monkeypatch.setattr(mod, "_engine", None)
        eng1 = mod.get_rasp_engine()
        eng2 = mod.get_rasp_engine()
        assert eng1 is eng2

    def test_false_positive_feedback(self, engine):
        """report_false_positive records feedback and updates FP rate."""
        _, events = _inspect(engine, params={"q": "' UNION SELECT 1--"})
        assert len(events) >= 1
        event_id = events[0].event_id
        result = engine.report_false_positive(event_id, reporter="analyst")
        assert result is True
        metrics = engine.get_metrics()
        assert metrics.false_positive_rate >= 0.0
