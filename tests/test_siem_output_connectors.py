"""Tests for SIEM Output Connectors — Splunk HEC + Microsoft Sentinel.

Covers:
- SplunkHECConnector: config, event formatting, batch, health, stats
- SentinelConnector: config, event mapping, severity mapping, health, stats
- SIEMOutputEngine: target CRUD, delivery tracking, statistics
- siem_output_router: all endpoints via FastAPI TestClient
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest

# Ensure suite paths are importable
_repo = Path(__file__).resolve().parents[1]
for _sub in ("suite-core", "suite-api", "suite-integrations"):
    _p = str(_repo / _sub)
    if _p not in sys.path:
        sys.path.insert(0, _p)


# ============================================================================
# Splunk HEC Connector Tests
# ============================================================================


class TestSplunkHECConfig:
    """Tests for SplunkHECConfig dataclass."""

    def test_default_config(self):
        from siem_connectors.splunk_hec_connector import SplunkHECConfig

        cfg = SplunkHECConfig()
        assert cfg.url == ""
        assert cfg.token == ""
        assert cfg.index == "aldeci"
        assert cfg.source == "aldeci-ctem"
        assert cfg.sourcetype == "aldeci:security"
        assert cfg.batch_size == 50
        assert cfg.max_retries == 3
        assert cfg.verify_ssl is True

    def test_token_hashed(self):
        from siem_connectors.splunk_hec_connector import SplunkHECConfig
        import hashlib

        cfg = SplunkHECConfig(token="my-secret-token")
        expected = hashlib.sha256(b"my-secret-token").hexdigest()
        assert cfg._token_hash == expected

    def test_to_safe_dict_no_raw_token(self):
        from siem_connectors.splunk_hec_connector import SplunkHECConfig

        cfg = SplunkHECConfig(
            url="https://splunk.example.com:8088",
            token="secret-hec-token",
            index="main",
        )
        safe = cfg.to_safe_dict()
        assert "token" not in safe or safe.get("token") is None
        assert "token_hash" in safe
        assert safe["url"] == "https://splunk.example.com:8088"
        assert safe["index"] == "main"

    def test_custom_config(self):
        from siem_connectors.splunk_hec_connector import SplunkHECConfig

        cfg = SplunkHECConfig(
            url="https://splunk:8088",
            token="tok",
            index="security",
            source="aldeci",
            sourcetype="json",
            host="myhost",
            verify_ssl=False,
            batch_size=100,
            max_retries=5,
            base_delay_s=2.0,
            timeout_s=60.0,
        )
        assert cfg.batch_size == 100
        assert cfg.max_retries == 5
        assert cfg.verify_ssl is False
        assert cfg.host == "myhost"


class TestSplunkHECConnector:
    """Tests for SplunkHECConnector class."""

    def test_format_event_basic(self):
        from siem_connectors.splunk_hec_connector import (
            SplunkHECConfig,
            SplunkHECConnector,
        )

        connector = SplunkHECConnector(SplunkHECConfig(index="test", host="myhost"))
        event = {
            "event_type": "finding",
            "severity": "high",
            "message": "SQL injection detected",
            "timestamp": "2026-04-22T10:00:00+00:00",
        }
        formatted = connector.format_event(event)
        assert formatted["index"] == "test"
        assert formatted["host"] == "myhost"
        assert formatted["event"]["severity_num"] == 2  # high = 2
        assert formatted["event"]["message"] == "SQL injection detected"
        assert "time" in formatted
        assert isinstance(formatted["time"], float)

    def test_format_event_default_severity(self):
        from siem_connectors.splunk_hec_connector import (
            SplunkHECConfig,
            SplunkHECConnector,
        )

        connector = SplunkHECConnector(SplunkHECConfig())
        event = {"event_type": "test"}
        formatted = connector.format_event(event)
        assert formatted["event"]["severity_num"] == 5  # info = 5

    def test_format_event_severity_mapping(self):
        from siem_connectors.splunk_hec_connector import (
            SplunkHECConfig,
            SplunkHECConnector,
        )

        connector = SplunkHECConnector(SplunkHECConfig())
        for sev, expected_num in [("critical", 1), ("high", 2), ("medium", 3), ("low", 4), ("info", 5)]:
            event = {"severity": sev}
            formatted = connector.format_event(event)
            assert formatted["event"]["severity_num"] == expected_num, f"Failed for {sev}"

    def test_format_batch_ndjson(self):
        from siem_connectors.splunk_hec_connector import (
            SplunkHECConfig,
            SplunkHECConnector,
        )

        connector = SplunkHECConnector(SplunkHECConfig())
        events = [
            {"event_type": "alert", "severity": "high", "timestamp": "2026-04-22T10:00:00+00:00"},
            {"event_type": "finding", "severity": "low", "timestamp": "2026-04-22T10:01:00+00:00"},
        ]
        batch = connector.format_batch(events)
        lines = batch.strip().split("\n")
        assert len(lines) == 2
        for line in lines:
            parsed = json.loads(line)
            assert "event" in parsed
            assert "time" in parsed

    def test_send_events_empty(self):
        from siem_connectors.splunk_hec_connector import (
            SplunkHECConfig,
            SplunkHECConnector,
        )

        connector = SplunkHECConnector(SplunkHECConfig())
        results = connector.send_events([])
        assert results == []

    def test_send_events_no_httpx(self):
        from siem_connectors.splunk_hec_connector import (
            SplunkHECConfig,
            SplunkHECConnector,
        )
        import siem_connectors.splunk_hec_connector as mod

        original = mod._HTTPX_AVAILABLE
        mod._HTTPX_AVAILABLE = False
        try:
            connector = SplunkHECConnector(SplunkHECConfig())
            results = connector.send_events([{"event_type": "test"}])
            assert len(results) == 1
            assert results[0].success is False
            assert "httpx" in results[0].error.lower()
        finally:
            mod._HTTPX_AVAILABLE = original

    def test_send_events_batching(self):
        from siem_connectors.splunk_hec_connector import (
            SplunkHECConfig,
            SplunkHECConnector,
        )

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = '{"text":"Success","code":0}'

        with patch("siem_connectors.splunk_hec_connector.httpx") as mock_httpx:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.post.return_value = mock_response
            mock_httpx.Client.return_value = mock_client

            config = SplunkHECConfig(
                url="https://splunk:8088",
                token="test-token",
                batch_size=2,
            )
            connector = SplunkHECConnector(config)
            events = [{"event_type": f"e{i}"} for i in range(5)]
            results = connector.send_events(events)

            # 5 events / batch_size=2 = 3 batches
            assert len(results) == 3
            assert all(r.success for r in results)

    def test_send_events_retry_on_500(self):
        from siem_connectors.splunk_hec_connector import (
            SplunkHECConfig,
            SplunkHECConnector,
        )

        responses = [
            MagicMock(status_code=500, text="Internal Server Error"),
            MagicMock(status_code=200, text='{"text":"Success","code":0}'),
        ]
        call_count = [0]

        def mock_post(*args, **kwargs):
            idx = min(call_count[0], len(responses) - 1)
            call_count[0] += 1
            return responses[idx]

        with patch("siem_connectors.splunk_hec_connector.httpx") as mock_httpx:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.post.side_effect = mock_post
            mock_httpx.Client.return_value = mock_client

            config = SplunkHECConfig(
                url="https://splunk:8088",
                token="test-token",
                base_delay_s=0.01,  # fast for tests
                max_retries=2,
            )
            connector = SplunkHECConnector(config)
            results = connector.send_events([{"event_type": "test"}])

            assert len(results) == 1
            assert results[0].success is True
            assert results[0].retries_used == 1

    def test_check_health_no_httpx(self):
        from siem_connectors.splunk_hec_connector import (
            SplunkHECConfig,
            SplunkHECConnector,
        )
        import siem_connectors.splunk_hec_connector as mod

        original = mod._HTTPX_AVAILABLE
        mod._HTTPX_AVAILABLE = False
        try:
            connector = SplunkHECConnector(SplunkHECConfig())
            health = connector.check_health()
            assert health["healthy"] is False
        finally:
            mod._HTTPX_AVAILABLE = original

    def test_get_stats(self):
        from siem_connectors.splunk_hec_connector import (
            SplunkHECConfig,
            SplunkHECConnector,
        )

        connector = SplunkHECConnector(SplunkHECConfig(url="https://splunk:8088"))
        stats = connector.get_stats()
        assert "total_sent" in stats
        assert "total_failed" in stats
        assert "config" in stats
        assert stats["config"]["url"] == "https://splunk:8088"

    def test_delivery_result_to_dict(self):
        from siem_connectors.splunk_hec_connector import SplunkDeliveryResult

        result = SplunkDeliveryResult(
            events_sent=10,
            events_failed=2,
            success=True,
            status_code=200,
            duration_ms=123.456789,
            retries_used=1,
        )
        d = result.to_dict()
        assert d["events_sent"] == 10
        assert d["events_failed"] == 2
        assert d["success"] is True
        assert d["duration_ms"] == 123.46
        assert d["retries_used"] == 1


# ============================================================================
# Microsoft Sentinel Connector Tests
# ============================================================================


class TestSentinelConfig:
    """Tests for SentinelConfig dataclass."""

    def test_default_config(self):
        from siem_connectors.sentinel_connector import SentinelConfig

        cfg = SentinelConfig()
        assert cfg.tenant_id == ""
        assert cfg.client_id == ""
        assert cfg.stream_name == "Custom-ALDECISecurityEvents_CL"
        assert cfg.log_type == "ALDECISecurityEvents"
        assert cfg.max_retries == 3
        assert cfg.batch_size == 100

    def test_secret_hashed(self):
        from siem_connectors.sentinel_connector import SentinelConfig
        import hashlib

        cfg = SentinelConfig(client_secret="my-azure-secret")
        expected = hashlib.sha256(b"my-azure-secret").hexdigest()
        assert cfg._secret_hash == expected

    def test_to_safe_dict_no_secret(self):
        from siem_connectors.sentinel_connector import SentinelConfig

        cfg = SentinelConfig(
            tenant_id="t-123",
            client_id="c-456",
            client_secret="supersecret",
            dcr_endpoint="https://dcr.eastus.ingest.monitor.azure.com",
        )
        safe = cfg.to_safe_dict()
        assert "client_secret" not in safe
        assert "secret_hash" in safe
        assert safe["tenant_id"] == "t-123"
        assert safe["dcr_endpoint"] == "https://dcr.eastus.ingest.monitor.azure.com"


class TestSentinelConnector:
    """Tests for SentinelConnector class."""

    def test_map_event_severity_mapping(self):
        from siem_connectors.sentinel_connector import (
            SentinelConfig,
            SentinelConnector,
        )

        connector = SentinelConnector(SentinelConfig())
        for aldeci_sev, sentinel_sev in [
            ("critical", "High"),
            ("high", "High"),
            ("medium", "Medium"),
            ("low", "Low"),
            ("info", "Informational"),
        ]:
            event = {"severity": aldeci_sev, "event_type": "test"}
            mapped = connector.map_event(event)
            assert mapped["ALDECI_Severity"] == sentinel_sev, f"Failed for {aldeci_sev}"

    def test_map_event_status_mapping(self):
        from siem_connectors.sentinel_connector import (
            SentinelConfig,
            SentinelConnector,
        )

        connector = SentinelConnector(SentinelConfig())
        for aldeci_status, sentinel_status in [
            ("open", "New"),
            ("acknowledged", "InProgress"),
            ("in_progress", "InProgress"),
            ("resolved", "Closed"),
            ("closed", "Closed"),
        ]:
            event = {"status": aldeci_status}
            mapped = connector.map_event(event)
            assert mapped["ALDECI_Status"] == sentinel_status, f"Failed for {aldeci_status}"

    def test_map_event_all_fields(self):
        from siem_connectors.sentinel_connector import (
            SentinelConfig,
            SentinelConnector,
        )

        connector = SentinelConnector(SentinelConfig())
        event = {
            "event_id": "evt-123",
            "event_type": "finding",
            "severity": "high",
            "status": "open",
            "source": "scanner",
            "message": "XSS found",
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "user_id": "user-1",
            "finding_id": "find-1",
            "cve_id": "CVE-2024-1234",
            "action": "detect",
            "outcome": "alert",
            "org_id": "org-1",
            "metadata": {"scanner": "zap"},
            "timestamp": "2026-04-22T12:00:00+00:00",
        }
        mapped = connector.map_event(event)
        assert mapped["ALDECI_EventId"] == "evt-123"
        assert mapped["ALDECI_EventType"] == "finding"
        assert mapped["ALDECI_Severity"] == "High"
        assert mapped["ALDECI_Status"] == "New"
        assert mapped["ALDECI_SrcIP"] == "10.0.0.1"
        assert mapped["ALDECI_CVE"] == "CVE-2024-1234"
        assert mapped["ALDECI_OrgId"] == "org-1"
        assert mapped["TimeGenerated"] == "2026-04-22T12:00:00+00:00"
        meta = json.loads(mapped["ALDECI_Metadata"])
        assert meta["scanner"] == "zap"

    def test_send_events_empty(self):
        from siem_connectors.sentinel_connector import (
            SentinelConfig,
            SentinelConnector,
        )

        connector = SentinelConnector(SentinelConfig())
        results = connector.send_events([])
        assert results == []

    def test_send_events_no_httpx(self):
        from siem_connectors.sentinel_connector import (
            SentinelConfig,
            SentinelConnector,
        )
        import siem_connectors.sentinel_connector as mod

        original = mod._HTTPX_AVAILABLE
        mod._HTTPX_AVAILABLE = False
        try:
            connector = SentinelConnector(SentinelConfig())
            results = connector.send_events([{"event_type": "test"}])
            assert len(results) == 1
            assert results[0].success is False
            assert "httpx" in results[0].error.lower()
        finally:
            mod._HTTPX_AVAILABLE = original

    def test_check_health_no_httpx(self):
        from siem_connectors.sentinel_connector import (
            SentinelConfig,
            SentinelConnector,
        )
        import siem_connectors.sentinel_connector as mod

        original = mod._HTTPX_AVAILABLE
        mod._HTTPX_AVAILABLE = False
        try:
            connector = SentinelConnector(SentinelConfig())
            health = connector.check_health()
            assert health["healthy"] is False
        finally:
            mod._HTTPX_AVAILABLE = original

    def test_get_stats(self):
        from siem_connectors.sentinel_connector import (
            SentinelConfig,
            SentinelConnector,
        )

        connector = SentinelConnector(SentinelConfig(tenant_id="t-1", client_id="c-1"))
        stats = connector.get_stats()
        assert "total_sent" in stats
        assert "config" in stats
        assert stats["config"]["tenant_id"] == "t-1"

    def test_delivery_result_to_dict(self):
        from siem_connectors.sentinel_connector import SentinelDeliveryResult

        result = SentinelDeliveryResult(
            events_sent=5,
            success=True,
            status_code=204,
            duration_ms=99.999,
        )
        d = result.to_dict()
        assert d["events_sent"] == 5
        assert d["success"] is True
        assert d["status_code"] == 204
        assert d["duration_ms"] == 100.0

    def test_send_events_batch_with_retry(self):
        from siem_connectors.sentinel_connector import (
            SentinelConfig,
            SentinelConnector,
        )

        # Mock token acquisition + batch send
        connector = SentinelConnector(SentinelConfig(
            tenant_id="t",
            client_id="c",
            client_secret="s",
            dcr_endpoint="https://dcr.example.com",
            dcr_rule_id="dcr-123",
            base_delay_s=0.01,
        ))

        # Simulate: first call returns 503, second returns 204
        responses = [
            MagicMock(status_code=503, text="Service Unavailable"),
            MagicMock(status_code=204, text=""),
        ]
        call_count = [0]

        def mock_post(*args, **kwargs):
            idx = min(call_count[0], len(responses) - 1)
            call_count[0] += 1
            return responses[idx]

        connector._access_token = "fake-token"
        connector._token_expires_at = time.time() + 3600

        with patch("siem_connectors.sentinel_connector.httpx") as mock_httpx:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.post.side_effect = mock_post
            mock_httpx.Client.return_value = mock_client

            results = connector.send_events([{"event_type": "test"}])
            assert len(results) == 1
            assert results[0].success is True
            assert results[0].retries_used == 1


# ============================================================================
# SIEM Output Engine Tests
# ============================================================================


class TestSIEMOutputEngine:
    """Tests for the SQLite-backed SIEMOutputEngine."""

    @pytest.fixture(autouse=True)
    def setup_engine(self, tmp_path):
        from core.siem_output_engine import SIEMOutputEngine

        self.db_path = str(tmp_path / "test_siem_output.db")
        self.engine = SIEMOutputEngine(db_path=self.db_path)
        self.org_id = "test-org"

    def test_configure_target_splunk(self):
        result = self.engine.configure_target(
            org_id=self.org_id,
            name="Splunk Production",
            siem_type="splunk_hec",
            config={"url": "https://splunk:8088", "token": "hec-token", "index": "main"},
        )
        assert result["name"] == "Splunk Production"
        assert result["siem_type"] == "splunk_hec"
        assert result["status"] == "active"
        assert result["target_id"].startswith("siem-out-")

    def test_configure_target_sentinel(self):
        result = self.engine.configure_target(
            org_id=self.org_id,
            name="Sentinel US East",
            siem_type="sentinel",
            config={
                "tenant_id": "t-1",
                "client_id": "c-1",
                "client_secret": "sec",
                "dcr_endpoint": "https://dcr.eastus.azure.com",
            },
        )
        assert result["siem_type"] == "sentinel"
        assert result["status"] == "active"

    def test_configure_target_invalid_type(self):
        with pytest.raises(ValueError, match="Invalid siem_type"):
            self.engine.configure_target(
                org_id=self.org_id,
                name="Bad",
                siem_type="elasticsearch",
                config={},
            )

    def test_get_targets(self):
        self.engine.configure_target(self.org_id, "Splunk", "splunk_hec", {"url": "http://a"})
        self.engine.configure_target(self.org_id, "Sentinel", "sentinel", {"tenant_id": "t"})
        targets = self.engine.get_targets(self.org_id)
        assert len(targets) == 2
        names = {t["name"] for t in targets}
        assert "Splunk" in names
        assert "Sentinel" in names

    def test_get_targets_strips_secrets(self):
        self.engine.configure_target(
            self.org_id, "S1", "splunk_hec",
            {"url": "http://a", "token": "secret-tok"},
        )
        targets = self.engine.get_targets(self.org_id)
        assert len(targets) == 1
        assert "token" not in targets[0]["config"]
        assert "token_hash" in targets[0]["config"]

    def test_get_target_by_id(self):
        result = self.engine.configure_target(self.org_id, "S1", "splunk_hec", {})
        target = self.engine.get_target(self.org_id, result["target_id"])
        assert target is not None
        assert target["name"] == "S1"

    def test_get_target_not_found(self):
        target = self.engine.get_target(self.org_id, "nonexistent")
        assert target is None

    def test_get_target_org_isolation(self):
        result = self.engine.configure_target("org-a", "SA", "splunk_hec", {})
        # Different org cannot see it
        target = self.engine.get_target("org-b", result["target_id"])
        assert target is None

    def test_update_target_status(self):
        result = self.engine.configure_target(self.org_id, "S1", "splunk_hec", {})
        updated = self.engine.update_target_status(self.org_id, result["target_id"], "inactive")
        assert updated["status"] == "inactive"

    def test_update_target_status_invalid(self):
        result = self.engine.configure_target(self.org_id, "S1", "splunk_hec", {})
        with pytest.raises(ValueError, match="Invalid status"):
            self.engine.update_target_status(self.org_id, result["target_id"], "broken")

    def test_update_target_status_not_found(self):
        updated = self.engine.update_target_status(self.org_id, "nonexistent", "active")
        assert updated is None

    def test_delete_target(self):
        result = self.engine.configure_target(self.org_id, "S1", "splunk_hec", {})
        assert self.engine.delete_target(self.org_id, result["target_id"]) is True
        assert self.engine.get_target(self.org_id, result["target_id"]) is None

    def test_delete_target_not_found(self):
        assert self.engine.delete_target(self.org_id, "nonexistent") is False

    def test_record_delivery_success(self):
        result = self.engine.configure_target(self.org_id, "S1", "splunk_hec", {})
        tid = result["target_id"]
        delivery = self.engine.record_delivery(
            org_id=self.org_id,
            target_id=tid,
            batch_size=10,
            events_sent=10,
            events_failed=0,
            success=True,
            status_code=200,
            duration_ms=50.5,
        )
        assert delivery["success"] is True
        assert delivery["events_sent"] == 10

    def test_record_delivery_failure(self):
        result = self.engine.configure_target(self.org_id, "S1", "splunk_hec", {})
        tid = result["target_id"]
        delivery = self.engine.record_delivery(
            org_id=self.org_id,
            target_id=tid,
            batch_size=5,
            events_sent=0,
            events_failed=5,
            success=False,
            status_code=500,
            error="Internal Server Error",
            duration_ms=100.0,
            retries_used=3,
        )
        assert delivery["success"] is False
        assert delivery["events_failed"] == 5

    def test_get_stats(self):
        result = self.engine.configure_target(self.org_id, "S1", "splunk_hec", {})
        tid = result["target_id"]
        self.engine.record_delivery(self.org_id, tid, 10, 10, 0, True, 200, "", 50.0)
        self.engine.record_delivery(self.org_id, tid, 5, 0, 5, False, 500, "err", 100.0)
        stats = self.engine.get_stats(self.org_id, tid)
        assert stats["totals"]["total_sent"] == 10
        assert stats["totals"]["total_failed"] == 5
        assert stats["totals"]["total_batches"] == 2
        assert stats["totals"]["success_rate_pct"] > 0

    def test_get_stats_all_targets(self):
        r1 = self.engine.configure_target(self.org_id, "S1", "splunk_hec", {})
        r2 = self.engine.configure_target(self.org_id, "S2", "sentinel", {})
        self.engine.record_delivery(self.org_id, r1["target_id"], 10, 10, 0, True, 200)
        self.engine.record_delivery(self.org_id, r2["target_id"], 5, 5, 0, True, 204)
        stats = self.engine.get_stats(self.org_id)
        assert stats["totals"]["total_sent"] == 15
        assert len(stats["targets"]) == 2

    def test_get_delivery_history(self):
        result = self.engine.configure_target(self.org_id, "S1", "splunk_hec", {})
        tid = result["target_id"]
        for i in range(5):
            self.engine.record_delivery(self.org_id, tid, 1, 1, 0, True, 200, "", float(i))
        history = self.engine.get_delivery_history(self.org_id, tid, limit=3)
        assert len(history) == 3

    def test_stats_empty(self):
        stats = self.engine.get_stats(self.org_id)
        assert stats["totals"]["total_sent"] == 0
        assert stats["totals"]["total_failed"] == 0

    def test_success_rate_calculation(self):
        result = self.engine.configure_target(self.org_id, "S1", "splunk_hec", {})
        tid = result["target_id"]
        # 8 success + 2 failure = 80% success rate
        for _ in range(8):
            self.engine.record_delivery(self.org_id, tid, 1, 1, 0, True, 200)
        for _ in range(2):
            self.engine.record_delivery(self.org_id, tid, 1, 0, 1, False, 500, "err")
        stats = self.engine.get_stats(self.org_id, tid)
        assert stats["totals"]["success_rate_pct"] == 80.0


# ============================================================================
# SIEM Output Router Tests
# ============================================================================


class TestSIEMOutputRouter:
    """Tests for the SIEM Output FastAPI router."""

    @pytest.fixture(autouse=True)
    def setup_client(self, tmp_path):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from apps.api.siem_output_router import router, _get_engine
        from core.siem_output_engine import SIEMOutputEngine

        # Override engine with temp DB
        db_path = str(tmp_path / "test_router.db")
        self._engine = SIEMOutputEngine(db_path=db_path)

        app = FastAPI()
        app.include_router(router)

        # Patch the engine getter
        import apps.api.siem_output_router as mod
        mod._engine = self._engine

        self.client = TestClient(app)

    def test_configure_splunk_target(self):
        resp = self.client.post("/api/v1/siem-output/configure", json={
            "org_id": "org-1",
            "name": "Splunk Prod",
            "siem_type": "splunk_hec",
            "config": {"url": "https://splunk:8088", "token": "tok"},
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "configured"
        assert data["target"]["siem_type"] == "splunk_hec"

    def test_configure_sentinel_target(self):
        resp = self.client.post("/api/v1/siem-output/configure", json={
            "org_id": "org-1",
            "name": "Sentinel East",
            "siem_type": "sentinel",
            "config": {
                "tenant_id": "t-1",
                "client_id": "c-1",
                "client_secret": "secret",
                "dcr_endpoint": "https://dcr.azure.com",
            },
        })
        assert resp.status_code == 200
        assert resp.json()["target"]["siem_type"] == "sentinel"

    def test_configure_invalid_type(self):
        resp = self.client.post("/api/v1/siem-output/configure", json={
            "name": "Bad",
            "siem_type": "elasticsearch",
            "config": {},
        })
        assert resp.status_code == 400

    def test_list_targets(self):
        self.client.post("/api/v1/siem-output/configure", json={
            "org_id": "org-1",
            "name": "S1",
            "siem_type": "splunk_hec",
            "config": {},
        })
        resp = self.client.get("/api/v1/siem-output/targets?org_id=org-1")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 1

    def test_get_target(self):
        create = self.client.post("/api/v1/siem-output/configure", json={
            "org_id": "org-1",
            "name": "S1",
            "siem_type": "splunk_hec",
            "config": {},
        })
        tid = create.json()["target"]["target_id"]
        resp = self.client.get(f"/api/v1/siem-output/targets/{tid}?org_id=org-1")
        assert resp.status_code == 200
        assert resp.json()["name"] == "S1"

    def test_get_target_not_found(self):
        resp = self.client.get("/api/v1/siem-output/targets/nonexistent?org_id=org-1")
        assert resp.status_code == 404

    def test_update_target_status(self):
        create = self.client.post("/api/v1/siem-output/configure", json={
            "org_id": "org-1",
            "name": "S1",
            "siem_type": "splunk_hec",
            "config": {},
        })
        tid = create.json()["target"]["target_id"]
        resp = self.client.put(
            f"/api/v1/siem-output/targets/{tid}/status?org_id=org-1",
            json={"status": "inactive"},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "inactive"

    def test_update_target_status_invalid(self):
        create = self.client.post("/api/v1/siem-output/configure", json={
            "org_id": "org-1",
            "name": "S1",
            "siem_type": "splunk_hec",
            "config": {},
        })
        tid = create.json()["target"]["target_id"]
        resp = self.client.put(
            f"/api/v1/siem-output/targets/{tid}/status?org_id=org-1",
            json={"status": "broken"},
        )
        assert resp.status_code == 400

    def test_delete_target(self):
        create = self.client.post("/api/v1/siem-output/configure", json={
            "org_id": "org-1",
            "name": "S1",
            "siem_type": "splunk_hec",
            "config": {},
        })
        tid = create.json()["target"]["target_id"]
        resp = self.client.delete(f"/api/v1/siem-output/targets/{tid}?org_id=org-1")
        assert resp.status_code == 200
        assert resp.json()["status"] == "deleted"

    def test_delete_target_not_found(self):
        resp = self.client.delete("/api/v1/siem-output/targets/nonexistent?org_id=org-1")
        assert resp.status_code == 404

    def test_get_all_status(self):
        self.client.post("/api/v1/siem-output/configure", json={
            "org_id": "org-1",
            "name": "S1",
            "siem_type": "splunk_hec",
            "config": {"url": "https://splunk:8088"},
        })
        resp = self.client.get("/api/v1/siem-output/status?org_id=org-1")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 1
        assert "health" in data["targets"][0]

    def test_get_target_status_endpoint(self):
        create = self.client.post("/api/v1/siem-output/configure", json={
            "org_id": "org-1",
            "name": "S1",
            "siem_type": "splunk_hec",
            "config": {},
        })
        tid = create.json()["target"]["target_id"]
        resp = self.client.get(f"/api/v1/siem-output/status/{tid}?org_id=org-1")
        assert resp.status_code == 200
        assert "health" in resp.json()

    def test_get_stats(self):
        resp = self.client.get("/api/v1/siem-output/stats?org_id=org-1")
        assert resp.status_code == 200
        assert "totals" in resp.json()

    def test_get_target_stats(self):
        create = self.client.post("/api/v1/siem-output/configure", json={
            "org_id": "org-1",
            "name": "S1",
            "siem_type": "splunk_hec",
            "config": {},
        })
        tid = create.json()["target"]["target_id"]
        resp = self.client.get(f"/api/v1/siem-output/stats/{tid}?org_id=org-1")
        assert resp.status_code == 200

    def test_get_delivery_history(self):
        create = self.client.post("/api/v1/siem-output/configure", json={
            "org_id": "org-1",
            "name": "S1",
            "siem_type": "splunk_hec",
            "config": {},
        })
        tid = create.json()["target"]["target_id"]
        resp = self.client.get(f"/api/v1/siem-output/history/{tid}?org_id=org-1")
        assert resp.status_code == 200
        assert "history" in resp.json()

    def test_test_no_targets(self):
        resp = self.client.post("/api/v1/siem-output/test", json={
            "org_id": "org-1",
        })
        assert resp.status_code == 404

    def test_test_specific_target_not_found(self):
        resp = self.client.post("/api/v1/siem-output/test", json={
            "org_id": "org-1",
            "target_id": "nonexistent",
        })
        assert resp.status_code == 404
