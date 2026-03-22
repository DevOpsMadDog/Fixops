"""Unit tests for ALdeci SIEM Integration Engine.

Tests data models, format encoders (CEF/LEEF/JSON), engine target management,
event forwarding, filtering, and singleton access.
"""

import json
from unittest.mock import patch, MagicMock

import pytest

from integrations.siem_engine import (
    SIEMEngine,
    SIEMEvent,
    SIEMTarget,
    SIEMSeverity,
    SIEMTransport,
    SIEMOutputFormat,
    ForwardResult,
    format_cef,
    format_leef,
    format_json,
    _sanitize_cef,
    get_siem_engine,
)


# ── Enum Tests ──────────────────────────────────────────────────────


class TestSIEMSeverity:
    def test_cef_severity_mapping(self):
        assert SIEMSeverity.CRITICAL.to_cef_severity() == 10
        assert SIEMSeverity.HIGH.to_cef_severity() == 8
        assert SIEMSeverity.MEDIUM.to_cef_severity() == 5
        assert SIEMSeverity.LOW.to_cef_severity() == 3
        assert SIEMSeverity.INFO.to_cef_severity() == 1

    def test_syslog_severity_mapping(self):
        assert SIEMSeverity.CRITICAL.to_syslog_severity() == 2
        assert SIEMSeverity.INFO.to_syslog_severity() == 6


class TestEnums:
    def test_transport_values(self):
        assert SIEMTransport.SYSLOG_TCP.value == "syslog_tcp"
        assert SIEMTransport.SPLUNK_HEC.value == "splunk_hec"
        assert SIEMTransport.WEBHOOK.value == "webhook"

    def test_output_format_values(self):
        assert SIEMOutputFormat.CEF.value == "cef"
        assert SIEMOutputFormat.LEEF.value == "leef"
        assert SIEMOutputFormat.JSON.value == "json"


# ── Data Model Tests ────────────────────────────────────────────────


class TestSIEMTarget:
    def test_defaults(self):
        t = SIEMTarget(name="test")
        assert t.name == "test"
        assert t.transport == SIEMTransport.SYSLOG_TCP
        assert t.output_format == SIEMOutputFormat.CEF
        assert t.enabled is True
        assert t.target_id.startswith("siem-")

    def test_to_dict(self):
        t = SIEMTarget(name="splunk", transport=SIEMTransport.SPLUNK_HEC)
        d = t.to_dict()
        assert d["name"] == "splunk"
        assert d["transport"] == "splunk_hec"
        assert "target_id" in d


class TestSIEMEvent:
    def test_defaults(self):
        e = SIEMEvent(event_type="scan.completed", message="Done")
        assert e.event_type == "scan.completed"
        assert e.severity == SIEMSeverity.INFO
        assert e.event_id.startswith("evt-")

    def test_to_dict(self):
        e = SIEMEvent(event_type="finding.new", severity=SIEMSeverity.HIGH, cve_id="CVE-2024-1234")
        d = e.to_dict()
        assert d["severity"] == "high"
        assert d["cve_id"] == "CVE-2024-1234"


class TestForwardResult:
    def test_defaults(self):
        r = ForwardResult(target_id="t1")
        assert r.success is False
        assert r.bytes_sent == 0

    def test_to_dict(self):
        r = ForwardResult(target_id="t1", success=True, bytes_sent=256, duration_ms=1.234)
        d = r.to_dict()
        assert d["success"] is True
        assert d["duration_ms"] == 1.23


# ── Format Encoder Tests ────────────────────────────────────────────


class TestCEFFormat:
    def test_basic_cef(self):
        e = SIEMEvent(event_type="scan.completed", severity=SIEMSeverity.HIGH, message="5 findings")
        result = format_cef(e)
        assert result.startswith("CEF:0|ALdeci|CTEM+|1.0|")
        assert "|8|" in result  # severity 8 for HIGH
        assert "msg=5 findings" in result

    def test_cef_with_all_fields(self):
        e = SIEMEvent(
            event_type="finding.new", severity=SIEMSeverity.CRITICAL,
            src_ip="10.0.0.1", dst_ip="10.0.0.2", user_id="admin",
            app_id="APP-001", finding_id="F-123", cve_id="CVE-2024-1234",
            outcome="detected", message="SQL injection found",
        )
        result = format_cef(e)
        assert "src=10.0.0.1" in result
        assert "dst=10.0.0.2" in result
        assert "duser=admin" in result
        assert "cs1=APP-001" in result
        assert "cs3=CVE-2024-1234" in result

    def test_sanitize_cef(self):
        assert _sanitize_cef("a|b") == "a\\|b"
        assert _sanitize_cef("a=b") == "a\\=b"
        assert _sanitize_cef("a\\b") == "a\\\\b"


class TestLEEFFormat:
    def test_basic_leef(self):
        e = SIEMEvent(event_type="vuln.detected", severity=SIEMSeverity.MEDIUM, message="XSS found")
        result = format_leef(e)
        assert result.startswith("LEEF:2.0|ALdeci|CTEM+|1.0|")
        assert "cat=vuln.detected" in result
        assert "msg=XSS found" in result

    def test_leef_tab_separated(self):
        e = SIEMEvent(event_type="test", message="m")
        result = format_leef(e)
        parts = result.split("|")
        assert len(parts) == 6  # LEEF:2.0, Vendor, Product, Version, EventID, KVPairs
        kv = parts[5]
        assert "\t" in kv


# ── Engine Tests ────────────────────────────────────────────────────


class TestSIEMEngine:
    def setup_method(self):
        self.engine = SIEMEngine()

    def test_add_target(self):
        t = SIEMTarget(name="test-syslog")
        result = self.engine.add_target(t)
        assert result.name == "test-syslog"
        assert len(self.engine.list_targets()) == 1

    def test_remove_target(self):
        t = SIEMTarget(name="remove-me")
        self.engine.add_target(t)
        assert self.engine.remove_target(t.target_id) is True
        assert len(self.engine.list_targets()) == 0

    def test_remove_nonexistent(self):
        assert self.engine.remove_target("nope") is False

    def test_get_target(self):
        t = SIEMTarget(name="find-me")
        self.engine.add_target(t)
        found = self.engine.get_target(t.target_id)
        assert found is not None
        assert found.name == "find-me"

    def test_get_target_not_found(self):
        assert self.engine.get_target("nope") is None

    def test_forward_event_no_targets(self):
        e = SIEMEvent(event_type="test", message="hello")
        results = self.engine.forward_event(e)
        assert len(results) == 0

    def test_forward_event_disabled_target(self):
        t = SIEMTarget(name="disabled", enabled=False)
        self.engine.add_target(t)
        e = SIEMEvent(event_type="test", message="hello")
        results = self.engine.forward_event(e)
        assert len(results) == 0

    def test_forward_event_filter(self):
        t = SIEMTarget(name="filtered", event_filters=["scan.completed"])
        self.engine.add_target(t)
        # Event type doesn't match filter
        e = SIEMEvent(event_type="finding.new", message="no match")
        results = self.engine.forward_event(e)
        assert len(results) == 0

    def test_forward_event_filter_match(self):
        t = SIEMTarget(name="filtered", event_filters=["scan.completed"],
                       transport=SIEMTransport.SYSLOG_UDP)
        self.engine.add_target(t)
        e = SIEMEvent(event_type="scan.completed", message="match")
        # Will fail to connect but should attempt
        results = self.engine.forward_event(e)
        assert len(results) == 1

    def test_stats(self):
        stats = self.engine.get_stats()
        assert stats["events_forwarded"] == 0
        assert stats["active_targets"] == 0

    def test_recent_events(self):
        events = self.engine.get_recent_events()
        assert events == []

    def test_ring_buffer(self):
        """Test that event log doesn't grow beyond max size."""
        t = SIEMTarget(name="test", transport=SIEMTransport.SYSLOG_UDP)
        self.engine.add_target(t)
        self.engine._max_log_size = 5
        for i in range(10):
            e = SIEMEvent(event_type=f"test-{i}", message=f"msg-{i}")
            self.engine.forward_event(e)
        assert len(self.engine._event_log) == 5

    def test_test_target_not_found(self):
        result = self.engine.test_target("nonexistent")
        assert result.success is False
        assert "not found" in result.error.lower()

    @patch("integrations.siem_engine.socket.socket")
    def test_send_syslog_tcp_success(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        t = SIEMTarget(name="tcp", transport=SIEMTransport.SYSLOG_TCP)
        self.engine.add_target(t)
        e = SIEMEvent(event_type="test", severity=SIEMSeverity.HIGH, message="tcp test")
        results = self.engine.forward_event(e)
        assert len(results) == 1
        assert results[0].success is True
        assert results[0].bytes_sent > 0
        mock_sock.connect.assert_called_once()
        mock_sock.sendall.assert_called_once()

    @patch("integrations.siem_engine.socket.socket")
    def test_send_syslog_udp_success(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        t = SIEMTarget(name="udp", transport=SIEMTransport.SYSLOG_UDP)
        self.engine.add_target(t)
        e = SIEMEvent(event_type="test", message="udp test")
        results = self.engine.forward_event(e)
        assert len(results) == 1
        assert results[0].success is True
        mock_sock.sendto.assert_called_once()


class TestSingleton:
    def test_get_siem_engine(self):
        import integrations.siem_engine as mod
        mod._engine = None
        e1 = get_siem_engine()
        e2 = get_siem_engine()
        assert e1 is e2
        mod._engine = None  # cleanup



class TestJSONFormat:
    def test_json_valid(self):
        e = SIEMEvent(event_type="scan", message="done")
        result = format_json(e)
        parsed = json.loads(result)
        assert parsed["event_type"] == "scan"
        assert parsed["message"] == "done"

