"""
Integration test — ALdeci webhook consumer forwarders.

Boots all three forwarders on random free ports (no port conflicts),
fires 3 canonical ALdeci events at each forwarder, and asserts:
  - Correct HTTP response code from each forwarder
  - Correct transformation output (via mock-target capture)
  - Splunk HEC envelope structure (time, host, sourcetype, index, event)
  - ECS document structure (@timestamp, event.*, vulnerability.*, file.*)
  - Slack Block Kit structure (blocks, header, actions button)
  - Slack alerter skips low-severity events correctly

All forwarders run in mock mode (no real Splunk/Elastic/Slack required).

Run:
  python -m pytest examples/webhook_consumer/test_consumer.py -v
"""
from __future__ import annotations

import json
import os
import socket
import sys
import threading
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone
from http.server import HTTPServer
from typing import Any, Dict, List, Optional
from unittest.mock import patch

import pytest

# Make sure forwarder modules are importable when run from repo root
_CONSUMER_DIR = os.path.dirname(os.path.abspath(__file__))
if _CONSUMER_DIR not in sys.path:
    sys.path.insert(0, _CONSUMER_DIR)

import splunk_hec_forwarder as _splunk_mod
import elastic_forwarder as _elastic_mod
import slack_alerter as _slack_mod


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _free_port() -> int:
    """Find a free TCP port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


def _start_server(handler_class: type, port: int) -> HTTPServer:
    """Start an HTTPServer in a daemon thread. Returns the server."""
    server = HTTPServer(("127.0.0.1", port), handler_class)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    # Wait until port is open
    for _ in range(50):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                break
        except OSError:
            time.sleep(0.05)
    return server


def _post(url: str, payload: Dict[str, Any], headers: Optional[Dict[str, str]] = None) -> tuple:
    """POST JSON to url. Returns (status_code, response_body_dict)."""
    body = json.dumps(payload).encode("utf-8")
    h = {"Content-Type": "application/json"}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, data=body, headers=h, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, {}


def _get(url: str) -> tuple:
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, {}


# ---------------------------------------------------------------------------
# Canonical ALdeci test events
# ---------------------------------------------------------------------------

_FINDING_CREATED_PAYLOAD: Dict[str, Any] = {
    "finding_id": "F-2026-0001",
    "event_type": "finding.created",
    "title": "SQL Injection in /api/v1/login",
    "severity": "critical",
    "affected_asset": "src/auth/login.py",
    "source": "semgrep",
    "org_id": "acme-corp",
    "cve_id": "CVE-2023-1234",
    "cvss_score": 9.8,
    "description": "Unsanitised user input passed directly to SQL query.",
    "detected_at": "2026-04-26T10:00:00+00:00",
    "webhook_id": "wh-test-001",
    "delivered_at": "2026-04-26T10:00:01+00:00",
}

_DECISION_MADE_PAYLOAD: Dict[str, Any] = {
    "finding_id": "F-2026-0002",
    "event_type": "decision.made",
    "title": "Prioritise CVE-2023-5678 for immediate patching",
    "severity": "high",
    "affected_asset": "requirements.txt",
    "source": "brain-pipeline",
    "org_id": "acme-corp",
    "decision": "PATCH_NOW",
    "confidence": 0.95,
    "recommendation": "Upgrade requests library to >= 2.32.0",
    "detected_at": "2026-04-26T11:00:00+00:00",
}

_THREAT_DETECTED_PAYLOAD: Dict[str, Any] = {
    "finding_id": "F-2026-0003",
    "event_type": "threat.detected",
    "title": "APT29 TTP observed in network traffic",
    "severity": "critical",
    "affected_asset": "network/egress-gateway",
    "source": "mpte",
    "org_id": "acme-corp",
    "threat_actor": "APT29",
    "ioc": "185.220.101.0/24",
    "mitre_technique": "T1071.001",
    "detected_at": "2026-04-26T12:00:00+00:00",
}

_LOW_SEVERITY_PAYLOAD: Dict[str, Any] = {
    "finding_id": "F-2026-0004",
    "event_type": "decision.made",
    "title": "Minor dependency version drift detected",
    "severity": "low",
    "affected_asset": "package.json",
    "source": "sca",
    "org_id": "acme-corp",
    "detected_at": "2026-04-26T13:00:00+00:00",
}


# ---------------------------------------------------------------------------
# Captured transform storage (injected via mock)
# ---------------------------------------------------------------------------

class _CaptureList:
    """Thread-safe list for capturing transformed payloads."""
    def __init__(self) -> None:
        self._items: List[Any] = []
        self._lock = threading.Lock()

    def append(self, item: Any) -> None:
        with self._lock:
            self._items.append(item)

    def __len__(self) -> int:
        with self._lock:
            return len(self._items)

    def __getitem__(self, idx: int) -> Any:
        with self._lock:
            return self._items[idx]

    def clear(self) -> None:
        with self._lock:
            self._items.clear()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def splunk_captured() -> _CaptureList:
    return _CaptureList()


@pytest.fixture(scope="module")
def elastic_captured() -> _CaptureList:
    return _CaptureList()


@pytest.fixture(scope="module")
def slack_captured() -> _CaptureList:
    return _CaptureList()


@pytest.fixture(scope="module")
def splunk_server(splunk_captured: _CaptureList):
    """Start Splunk HEC forwarder in mock mode, capturing transformed events."""
    port = _free_port()

    original_post = _splunk_mod._post_to_splunk

    def capturing_post(hec_event: Dict[str, Any]):
        splunk_captured.append(hec_event)
        return 200, None

    with patch.object(_splunk_mod, "_post_to_splunk", side_effect=capturing_post):
        server = _start_server(_splunk_mod.ALdeciWebhookHandler, port)
        yield port, server
        server.shutdown()


@pytest.fixture(scope="module")
def elastic_server(elastic_captured: _CaptureList):
    """Start Elastic ECS forwarder in mock mode, capturing transformed events."""
    port = _free_port()

    def capturing_index(doc: Dict[str, Any]):
        elastic_captured.append(doc)
        return 200, None

    with patch.object(_elastic_mod, "_index_to_elastic", side_effect=capturing_index):
        server = _start_server(_elastic_mod.ALdeciWebhookHandler, port)
        yield port, server
        server.shutdown()


@pytest.fixture(scope="module")
def slack_server(slack_captured: _CaptureList):
    """Start Slack alerter in mock mode, capturing Block Kit messages."""
    port = _free_port()

    def capturing_slack(message: Dict[str, Any]):
        slack_captured.append(message)
        return 200, None

    # Override the alert event/severity sets to include all our test events
    with patch.object(_slack_mod, "_ALERT_EVENTS", {"decision.made", "threat.detected", "finding.critical", "finding.created"}), \
         patch.object(_slack_mod, "_ALERT_SEVERITIES", {"high", "critical"}), \
         patch.object(_slack_mod, "_post_to_slack", side_effect=capturing_slack):
        server = _start_server(_slack_mod.ALdeciWebhookHandler, port)
        yield port, server
        server.shutdown()


# ---------------------------------------------------------------------------
# Health check tests
# ---------------------------------------------------------------------------


class TestHealthEndpoints:
    def test_splunk_health(self, splunk_server):
        port, _ = splunk_server
        code, body = _get(f"http://127.0.0.1:{port}/health")
        assert code == 200
        assert body["status"] == "healthy"
        assert body["forwarder"] == "splunk-hec"

    def test_elastic_health(self, elastic_server):
        port, _ = elastic_server
        code, body = _get(f"http://127.0.0.1:{port}/health")
        assert code == 200
        assert body["status"] == "healthy"
        assert body["forwarder"] == "elastic-ecs"

    def test_slack_health(self, slack_server):
        port, _ = slack_server
        code, body = _get(f"http://127.0.0.1:{port}/health")
        assert code == 200
        assert body["status"] == "healthy"
        assert body["forwarder"] == "slack-alerter"


# ---------------------------------------------------------------------------
# Splunk HEC forwarder tests
# ---------------------------------------------------------------------------


class TestSplunkHECForwarder:
    """
    3 test events sent to Splunk forwarder.
    Asserts HEC envelope structure per:
      https://docs.splunk.com/Documentation/Splunk/latest/Data/FormateventsforHTTPEventCollector
    """

    def _send(self, port: int, payload: Dict[str, Any], event_type: str = "") -> tuple:
        headers: Dict[str, str] = {}
        if event_type:
            headers["X-ALdeci-Event"] = event_type
        return _post(f"http://127.0.0.1:{port}/webhook", payload, headers)

    def test_finding_created_http_200(self, splunk_server):
        port, _ = splunk_server
        code, body = self._send(port, _FINDING_CREATED_PAYLOAD, "finding.created")
        assert code == 200, f"Expected 200, got {code}: {body}"
        assert body["status"] == "forwarded"

    def test_decision_made_http_200(self, splunk_server):
        port, _ = splunk_server
        code, body = self._send(port, _DECISION_MADE_PAYLOAD, "decision.made")
        assert code == 200
        assert body["status"] == "forwarded"

    def test_threat_detected_http_200(self, splunk_server):
        port, _ = splunk_server
        code, body = self._send(port, _THREAT_DETECTED_PAYLOAD, "threat.detected")
        assert code == 200
        assert body["status"] == "forwarded"

    def test_hec_envelope_has_required_fields(self, splunk_server, splunk_captured):
        # Wait for captures
        for _ in range(20):
            if len(splunk_captured) >= 3:
                break
            time.sleep(0.05)
        assert len(splunk_captured) >= 3, f"Expected 3 captures, got {len(splunk_captured)}"

        for i in range(3):
            hec = splunk_captured[i]
            # Splunk HEC required fields
            assert "time" in hec, f"HEC event {i} missing 'time'"
            assert "host" in hec, f"HEC event {i} missing 'host'"
            assert "sourcetype" in hec, f"HEC event {i} missing 'sourcetype'"
            assert "index" in hec, f"HEC event {i} missing 'index'"
            assert "event" in hec, f"HEC event {i} missing 'event'"
            assert isinstance(hec["time"], float), "'time' must be epoch float"
            assert isinstance(hec["event"], dict), "'event' must be a dict"

    def test_hec_event_body_fields(self, splunk_captured):
        # First event is finding.created
        event_body = splunk_captured[0]["event"]
        assert event_body.get("aldeci_event_type") == "finding.created"
        assert event_body.get("finding_id") == "F-2026-0001"
        assert event_body.get("severity") == "critical"
        assert event_body.get("affected_asset") == "src/auth/login.py"
        assert event_body.get("source_scanner") == "semgrep"
        assert event_body.get("cve_id") == "CVE-2023-1234"
        assert event_body.get("cvss_score") == 9.8

    def test_hec_sourcetype_and_index(self, splunk_captured):
        hec = splunk_captured[0]
        assert hec["sourcetype"] == "aldeci:finding"
        assert hec["index"] == "aldeci_security"

    def test_hec_timestamp_is_epoch(self, splunk_captured):
        hec = splunk_captured[0]
        ts = hec["time"]
        # 2026-04-26T10:00:00 UTC in epoch seconds
        expected_epoch = datetime(2026, 4, 26, 10, 0, 0, tzinfo=timezone.utc).timestamp()
        assert abs(ts - expected_epoch) < 1.0, f"Epoch mismatch: {ts} vs {expected_epoch}"

    def test_hec_severity_mapping(self, splunk_captured):
        # critical → "critical", high → "high"
        assert splunk_captured[0]["event"]["severity"] == "critical"
        assert splunk_captured[1]["event"]["severity"] == "high"

    def test_invalid_json_returns_400(self, splunk_server):
        port, _ = splunk_server
        body = b"not valid json"
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/webhook",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            urllib.request.urlopen(req, timeout=5)
        except urllib.error.HTTPError as exc:
            assert exc.code == 400
        else:
            pytest.fail("Expected 400 for invalid JSON")


# ---------------------------------------------------------------------------
# Elastic ECS forwarder tests
# ---------------------------------------------------------------------------


class TestElasticECSForwarder:
    """
    3 test events sent to Elastic forwarder.
    Asserts ECS document structure per:
      https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html
    """

    def _send(self, port: int, payload: Dict[str, Any], event_type: str = "") -> tuple:
        headers: Dict[str, str] = {}
        if event_type:
            headers["X-ALdeci-Event"] = event_type
        return _post(f"http://127.0.0.1:{port}/webhook", payload, headers)

    def test_finding_created_http_200(self, elastic_server):
        port, _ = elastic_server
        code, body = self._send(port, _FINDING_CREATED_PAYLOAD, "finding.created")
        assert code == 200
        assert body["status"] == "indexed"

    def test_decision_made_http_200(self, elastic_server):
        port, _ = elastic_server
        code, body = self._send(port, _DECISION_MADE_PAYLOAD, "decision.made")
        assert code == 200

    def test_threat_detected_http_200(self, elastic_server):
        port, _ = elastic_server
        code, body = self._send(port, _THREAT_DETECTED_PAYLOAD, "threat.detected")
        assert code == 200

    def test_ecs_required_top_level_fields(self, elastic_server, elastic_captured):
        for _ in range(20):
            if len(elastic_captured) >= 3:
                break
            time.sleep(0.05)
        assert len(elastic_captured) >= 3

        for i in range(3):
            doc = elastic_captured[i]
            assert "@timestamp" in doc, f"ECS doc {i} missing '@timestamp'"
            assert "event" in doc, f"ECS doc {i} missing 'event'"
            assert "log" in doc, f"ECS doc {i} missing 'log'"
            assert "observer" in doc, f"ECS doc {i} missing 'observer'"
            assert "tags" in doc, f"ECS doc {i} missing 'tags'"
            assert "labels" in doc, f"ECS doc {i} missing 'labels'"

    def test_ecs_event_fields(self, elastic_captured):
        doc = elastic_captured[0]
        evt = doc["event"]
        assert evt.get("kind") == "event"
        assert "vulnerability" in evt.get("category", [])
        assert evt.get("provider") == "aldeci"
        assert evt.get("dataset") == "aldeci.finding"
        assert evt.get("action") == "finding.created"
        assert evt.get("id") == "F-2026-0001"

    def test_ecs_vulnerability_fields(self, elastic_captured):
        doc = elastic_captured[0]
        vuln = doc.get("vulnerability", {})
        assert vuln.get("id") == "CVE-2023-1234"
        assert vuln.get("severity") == "critical"
        score = vuln.get("score", {})
        assert score.get("base") == 9.8

    def test_ecs_file_field(self, elastic_captured):
        doc = elastic_captured[0]
        f = doc.get("file", {})
        assert "src/auth/login.py" in f.get("path", "")
        assert f.get("name") == "login.py"

    def test_ecs_observer_field(self, elastic_captured):
        doc = elastic_captured[0]
        obs = doc.get("observer", {})
        assert obs.get("name") == "semgrep"
        assert obs.get("type") == "scanner"
        assert obs.get("vendor") == "ALdeci"

    def test_ecs_timestamp_format(self, elastic_captured):
        doc = elastic_captured[0]
        ts = doc["@timestamp"]
        # Must be valid ISO-8601
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        assert dt.year == 2026

    def test_ecs_decision_event_category(self, elastic_captured):
        # Second event is decision.made → category should be "process"
        doc = elastic_captured[1]
        evt = doc["event"]
        assert "process" in evt.get("category", [])

    def test_ecs_threat_event_category(self, elastic_captured):
        # Third event is threat.detected → category should be "threat"
        doc = elastic_captured[2]
        evt = doc["event"]
        assert "threat" in evt.get("category", [])

    def test_ecs_aldeci_labels(self, elastic_captured):
        doc = elastic_captured[0]
        labels = doc.get("labels", {})
        assert labels.get("aldeci_event_type") == "finding.created"
        assert labels.get("aldeci_finding_id") == "F-2026-0001"
        assert labels.get("aldeci_org_id") == "acme-corp"


# ---------------------------------------------------------------------------
# Slack alerter tests
# ---------------------------------------------------------------------------


class TestSlackAlerter:
    """
    Tests for Slack Block Kit alerter.
    Asserts:
      - HIGH/CRITICAL decision.made/threat events fire Slack messages
      - LOW severity events are skipped (200 + skipped)
      - Block Kit structure: header, section, actions blocks
      - Deep-link button present for events with finding_id
    """

    def _send(self, port: int, payload: Dict[str, Any], event_type: str = "") -> tuple:
        headers: Dict[str, str] = {}
        if event_type:
            headers["X-ALdeci-Event"] = event_type
        return _post(f"http://127.0.0.1:{port}/webhook", payload, headers)

    def test_decision_made_high_fires_alert(self, slack_server):
        port, _ = slack_server
        code, body = self._send(port, _DECISION_MADE_PAYLOAD, "decision.made")
        assert code == 200
        assert body["status"] == "alerted"

    def test_threat_detected_critical_fires_alert(self, slack_server):
        port, _ = slack_server
        code, body = self._send(port, _THREAT_DETECTED_PAYLOAD, "threat.detected")
        assert code == 200
        assert body["status"] == "alerted"

    def test_finding_created_critical_fires_alert(self, slack_server):
        port, _ = slack_server
        code, body = self._send(port, _FINDING_CREATED_PAYLOAD, "finding.created")
        assert code == 200
        assert body["status"] == "alerted"

    def test_low_severity_skipped(self, slack_server):
        port, _ = slack_server
        code, body = self._send(port, _LOW_SEVERITY_PAYLOAD, "decision.made")
        assert code == 200
        assert body["status"] == "skipped"
        assert body["reason"] == "severity_below_threshold"

    def test_slack_captures_three_messages(self, slack_server, slack_captured):
        for _ in range(20):
            if len(slack_captured) >= 3:
                break
            time.sleep(0.05)
        assert len(slack_captured) >= 3, f"Expected >= 3 Slack captures, got {len(slack_captured)}"

    def test_block_kit_has_blocks(self, slack_captured):
        msg = slack_captured[0]
        assert "blocks" in msg, "Slack message missing 'blocks'"
        assert isinstance(msg["blocks"], list)
        assert len(msg["blocks"]) >= 3, f"Expected >= 3 blocks, got {len(msg['blocks'])}"

    def test_block_kit_header_block(self, slack_captured):
        msg = slack_captured[0]
        header = msg["blocks"][0]
        assert header["type"] == "header"
        assert "text" in header
        # Header text must contain severity
        assert "HIGH" in header["text"]["text"] or "CRITICAL" in header["text"]["text"]

    def test_block_kit_actions_button(self, slack_captured):
        # First captured event (decision.made or finding.created) has finding_id
        # so it should have an actions block with a button
        msg = slack_captured[0]
        block_types = [b["type"] for b in msg["blocks"]]
        assert "actions" in block_types, f"No actions block found. Block types: {block_types}"
        actions_block = next(b for b in msg["blocks"] if b["type"] == "actions")
        elements = actions_block.get("elements", [])
        assert len(elements) >= 1
        btn = elements[0]
        assert btn["type"] == "button"
        assert "url" in btn
        assert "finding_id" in btn["url"] or "findings" in btn["url"]

    def test_block_kit_fallback_text(self, slack_captured):
        msg = slack_captured[0]
        assert "text" in msg
        assert len(msg["text"]) > 0

    def test_block_kit_colour_attachment(self, slack_captured):
        msg = slack_captured[0]
        attachments = msg.get("attachments", [])
        assert len(attachments) >= 1
        colour = attachments[0].get("color", "")
        # HIGH = #FF6600, CRITICAL = #FF0000
        assert colour in ("#FF0000", "#FF6600"), f"Unexpected colour: {colour}"


# ---------------------------------------------------------------------------
# Transform unit tests (no server needed)
# ---------------------------------------------------------------------------


class TestTransformFunctions:
    """Unit tests for the transform functions — no HTTP overhead."""

    def test_splunk_transform_basic(self):
        hec = _splunk_mod.transform_to_hec("finding.created", _FINDING_CREATED_PAYLOAD)
        assert hec["sourcetype"] == "aldeci:finding"
        assert hec["index"] == "aldeci_security"
        assert isinstance(hec["time"], float)
        assert hec["event"]["finding_id"] == "F-2026-0001"

    def test_splunk_transform_strips_none(self):
        minimal = {"finding_id": "X", "title": "T", "severity": "low", "org_id": "o"}
        hec = _splunk_mod.transform_to_hec("finding.created", minimal)
        # None values should not appear in event body
        assert None not in hec["event"].values()

    def test_splunk_transform_missing_timestamp(self):
        payload = {k: v for k, v in _FINDING_CREATED_PAYLOAD.items() if k != "detected_at"}
        hec = _splunk_mod.transform_to_hec("finding.created", payload)
        # Should default to current time
        assert isinstance(hec["time"], float)
        assert hec["time"] > 0

    def test_elastic_transform_ecs_fields(self):
        doc = _elastic_mod.transform_to_ecs("finding.created", _FINDING_CREATED_PAYLOAD)
        assert "@timestamp" in doc
        assert doc["event"]["kind"] == "event"
        assert doc["vulnerability"]["id"] == "CVE-2023-1234"

    def test_elastic_transform_decision_category(self):
        doc = _elastic_mod.transform_to_ecs("decision.made", _DECISION_MADE_PAYLOAD)
        assert "process" in doc["event"]["category"]

    def test_elastic_transform_threat_category(self):
        doc = _elastic_mod.transform_to_ecs("threat.detected", _THREAT_DETECTED_PAYLOAD)
        assert "threat" in doc["event"]["category"]

    def test_elastic_transform_compliance_category(self):
        payload = {**_FINDING_CREATED_PAYLOAD, "event_type": "compliance.violation"}
        doc = _elastic_mod.transform_to_ecs("compliance.violation", payload)
        assert "compliance" in doc["event"]["category"]

    def test_elastic_transform_strips_none(self):
        minimal = {"finding_id": "X", "title": "T", "severity": "medium", "org_id": "o"}
        doc = _elastic_mod.transform_to_ecs("finding.created", minimal)
        assert "@timestamp" in doc
        assert doc["event"]["id"] == "X"

    def test_slack_build_message_critical(self):
        msg = _slack_mod.build_slack_message("finding.created", _FINDING_CREATED_PAYLOAD)
        assert "blocks" in msg
        assert "text" in msg
        # Header should contain CRITICAL
        header_text = msg["blocks"][0]["text"]["text"]
        assert "CRITICAL" in header_text

    def test_slack_build_message_has_cve_link(self):
        msg = _slack_mod.build_slack_message("finding.created", _FINDING_CREATED_PAYLOAD)
        # Find section blocks with CVE field
        all_text = json.dumps(msg)
        assert "CVE-2023-1234" in all_text
        assert "nvd.nist.gov" in all_text

    def test_slack_build_message_high_button_style(self):
        msg = _slack_mod.build_slack_message("decision.made", _DECISION_MADE_PAYLOAD)
        actions = next((b for b in msg["blocks"] if b["type"] == "actions"), None)
        assert actions is not None
        btn = actions["elements"][0]
        assert btn["style"] == "danger"  # HIGH severity = danger style

    def test_slack_build_message_recommendation(self):
        msg = _slack_mod.build_slack_message("decision.made", _DECISION_MADE_PAYLOAD)
        all_text = json.dumps(msg)
        assert "Upgrade requests library" in all_text

    def test_slack_build_message_mitre_technique(self):
        msg = _slack_mod.build_slack_message("threat.detected", _THREAT_DETECTED_PAYLOAD)
        all_text = json.dumps(msg)
        assert "T1071.001" in all_text


# ---------------------------------------------------------------------------
# HMAC verification tests
# ---------------------------------------------------------------------------


class TestHMACVerification:
    """Verify that signature checking works correctly when secret is set."""

    def test_splunk_invalid_signature_rejected(self, splunk_server):
        port, _ = splunk_server
        with patch.object(_splunk_mod, "ALDECI_WEBHOOK_SECRET", "test-secret"):
            body = json.dumps(_FINDING_CREATED_PAYLOAD).encode("utf-8")
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/webhook",
                data=body,
                headers={
                    "Content-Type": "application/json",
                    "X-ALdeci-Signature": "sha256=invalidsig",
                },
                method="POST",
            )
            try:
                urllib.request.urlopen(req, timeout=5)
                pytest.fail("Expected 401")
            except urllib.error.HTTPError as exc:
                assert exc.code == 401

    def test_elastic_invalid_signature_rejected(self, elastic_server):
        port, _ = elastic_server
        with patch.object(_elastic_mod, "ALDECI_WEBHOOK_SECRET", "test-secret"):
            body = json.dumps(_FINDING_CREATED_PAYLOAD).encode("utf-8")
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/webhook",
                data=body,
                headers={
                    "Content-Type": "application/json",
                    "X-ALdeci-Signature": "sha256=badsig",
                },
                method="POST",
            )
            try:
                urllib.request.urlopen(req, timeout=5)
                pytest.fail("Expected 401")
            except urllib.error.HTTPError as exc:
                assert exc.code == 401

    def test_valid_signature_accepted(self, splunk_server):
        import hashlib
        import hmac as _hmac

        port, _ = splunk_server
        secret = "test-secret-for-valid-test"
        body = json.dumps(_FINDING_CREATED_PAYLOAD).encode("utf-8")
        sig = "sha256=" + _hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()

        with patch.object(_splunk_mod, "ALDECI_WEBHOOK_SECRET", secret):
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/webhook",
                data=body,
                headers={
                    "Content-Type": "application/json",
                    "X-ALdeci-Signature": sig,
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                assert resp.status == 200
