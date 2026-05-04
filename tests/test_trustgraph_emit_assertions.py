"""
TrustGraph emit-site assertions — batches 11/12/13 (14 engines).

Pattern: inject a fake _get_tg_bus into the engine module so the real
trustgraph is never needed, call the produce method with minimal args,
assert emit() was called with the expected event_type.

Engines tested (14 total):
  bandit_scan_engine        → scan.completed    via queue_scan()
  prowler_scan_engine       → scan.completed    via queue_scan()
  opensearch_detection_engine → asset.discovered via create_detector()
  falcon_edr_engine         → threat.detected   via get_detect_summaries()
  sentinelone_edr_engine    → threat.detected   via list_threats()
  pagerduty_incident_engine → incident.created  via create_incident()
  harbor_registry_engine    → scan.completed    via trigger_scan()
  cyberark_pam_engine       → asset.discovered  via retrieve_password()
  misp_integration_engine   → threat.detected   via list_events()
  qualys_engine             → scan.completed    via launch_scan()
  checkmarx_engine          → scan.completed    via create_scan()
  sonarqube_engine          → threat.detected   via issues_search()
  jira_cloud_engine         → incident.created  via create_issue()
  elastic_security_engine   → threat.detected   via search_signals()
"""

from __future__ import annotations

import types
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_fake_bus():
    """Return a (bus_mock, get_bus_fn) pair — get_bus_fn() returns bus_mock."""
    bus = MagicMock()
    bus.emit = MagicMock()

    def get_bus():
        return bus

    return bus, get_bus


# ---------------------------------------------------------------------------
# 1. BanditScanEngine — scan.completed via queue_scan()
# ---------------------------------------------------------------------------

def test_bandit_emits_scan_completed(tmp_path):
    import core.bandit_scan_engine as mod

    bus, get_bus = _make_fake_bus()
    with patch.object(mod, "_get_tg_bus", get_bus):
        engine = mod.BanditScanEngine(db_path=str(tmp_path / "bandit.db"))
        engine.queue_scan(target_path="/tmp/src")

    bus.emit.assert_called_once()
    event_type = bus.emit.call_args[0][0]
    assert event_type == "scan.completed", f"expected scan.completed, got {event_type!r}"


# ---------------------------------------------------------------------------
# 2. ProwlerScanEngine — scan.completed via queue_scan()
# ---------------------------------------------------------------------------

def test_prowler_emits_scan_completed(tmp_path):
    import core.prowler_scan_engine as mod

    bus, get_bus = _make_fake_bus()
    with patch.object(mod, "_get_tg_bus", get_bus):
        engine = mod.ProwlerScanEngine(db_path=str(tmp_path / "prowler.db"))
        engine.queue_scan(provider="aws", region="us-east-1")

    bus.emit.assert_called_once()
    event_type = bus.emit.call_args[0][0]
    assert event_type == "scan.completed", f"expected scan.completed, got {event_type!r}"


# ---------------------------------------------------------------------------
# 3. OpenSearchDetectionEngine — asset.discovered via create_detector()
#    Requires a live OpenSearch endpoint — we inject a stub httpx.Client.
# ---------------------------------------------------------------------------

def test_opensearch_emits_asset_discovered():
    import httpx
    import core.opensearch_detection_engine as mod

    fake_response = MagicMock()
    fake_response.status_code = 200  # real int — engine does >= 400 check
    fake_response.json.return_value = {"_id": "det-001"}

    stub_client = MagicMock(spec=httpx.Client)
    # OpenSearch engine calls client.request(method, url, ...)
    stub_client.request.return_value = fake_response

    bus, get_bus = _make_fake_bus()
    with patch.object(mod, "_get_tg_bus", get_bus):
        engine = mod.OpenSearchDetectionEngine(
            base_url="http://localhost:9200",
            username="admin",
            password="admin",
            client=stub_client,
        )
        engine.create_detector({"name": "test-detector", "indices": ["logs-*"]})

    bus.emit.assert_called_once()
    event_type = bus.emit.call_args[0][0]
    assert event_type == "asset.discovered", f"expected asset.discovered, got {event_type!r}"


# ---------------------------------------------------------------------------
# 4. FalconEDREngine — threat.detected via get_detect_summaries()
#    Emits per-detection; we need at least one detection_id in the response.
# ---------------------------------------------------------------------------

def test_falcon_emits_threat_detected():
    import httpx
    import core.falcon_edr_engine as mod

    summaries_resp = MagicMock()
    summaries_resp.status_code = 200
    summaries_resp.json.return_value = {
        "resources": [
            {
                "detection_id": "ldt:abc123",
                "max_severity": 80,
                "max_severity_displayname": "High",
                "status": "new",
                "behaviors": [],
                "hostinfo": {},
                "device": {"hostname": "host1", "platform_name": "Windows", "os_version": "10"},
            }
        ]
    }

    stub_client = MagicMock(spec=httpx.Client)
    stub_client.post.return_value = summaries_resp

    bus, get_bus = _make_fake_bus()
    with patch.object(mod, "_get_tg_bus", get_bus):
        engine = mod.FalconEDREngine(
            client_id="cid",
            client_secret="csec",
            client=stub_client,
        )
        # Patch _ensure_token so no OAuth round-trip
        engine._token = "tok"
        engine._token_expires_at = 1e18
        engine.get_detect_summaries(["ldt:abc123"])

    bus.emit.assert_called()
    first_call_event = bus.emit.call_args_list[0][0][0]
    assert first_call_event == "threat.detected", f"expected threat.detected, got {first_call_event!r}"


# ---------------------------------------------------------------------------
# 5. SentinelOneEDREngine — threat.detected via list_threats()
# ---------------------------------------------------------------------------

def test_sentinelone_emits_threat_detected():
    import httpx
    import core.sentinelone_edr_engine as mod

    threat_resp = MagicMock()
    threat_resp.status_code = 200
    threat_resp.json.return_value = {
        "data": [
            {
                "id": "thr-001",
                "threatInfo": {
                    "confidenceLevel": "malicious",
                    "classification": "Trojan",
                    "mitigationStatus": "mitigated",
                },
            }
        ],
        "pagination": {"nextCursor": None},
    }

    stub_client = MagicMock(spec=httpx.Client)
    stub_client.get.return_value = threat_resp

    bus, get_bus = _make_fake_bus()
    with patch.object(mod, "_get_tg_bus", get_bus):
        engine = mod.SentinelOneEDREngine(
            url="https://s1.example.com",
            api_token="tok",
            client=stub_client,
        )
        engine.list_threats()

    bus.emit.assert_called()
    event_type = bus.emit.call_args_list[0][0][0]
    assert event_type == "threat.detected", f"expected threat.detected, got {event_type!r}"


# ---------------------------------------------------------------------------
# 6. PagerDutyIncidentEngine — incident.created via create_incident()
# ---------------------------------------------------------------------------

def test_pagerduty_emits_incident_created():
    import httpx
    import core.pagerduty_incident_engine as mod

    pd_resp = MagicMock()
    pd_resp.status_code = 201
    pd_resp.json.return_value = {
        "incident": {
            "id": "PD123",
            "incident_number": 42,
            "title": "Test incident",
            "urgency": "high",
            "status": "triggered",
        }
    }

    stub_client = MagicMock(spec=httpx.Client)
    stub_client.post.return_value = pd_resp

    body = {
        "incident": {
            "type": "incident",
            "title": "Test incident",
            "service": {"id": "SVC1", "type": "service_reference"},
        }
    }

    bus, get_bus = _make_fake_bus()
    with patch.object(mod, "_get_tg_bus", get_bus):
        engine = mod.PagerDutyIncidentEngine(
            api_token="tok",
            from_email="ops@example.com",
            client=stub_client,
        )
        engine.create_incident(body)

    bus.emit.assert_called_once()
    event_type = bus.emit.call_args[0][0]
    assert event_type == "incident.created", f"expected incident.created, got {event_type!r}"


# ---------------------------------------------------------------------------
# 7. HarborRegistryEngine — scan.completed via trigger_scan()
# ---------------------------------------------------------------------------

def test_harbor_emits_scan_completed():
    import httpx
    import core.harbor_registry_engine as mod

    scan_resp = MagicMock()
    scan_resp.status_code = 202  # real int — harbor does 200<=sc<300 check
    scan_resp.json.return_value = {}

    stub_client = MagicMock(spec=httpx.Client)
    # HarborRegistryEngine calls client.request(method, url, ...)
    stub_client.request.return_value = scan_resp

    bus, get_bus = _make_fake_bus()
    with patch.object(mod, "_get_tg_bus", get_bus):
        engine = mod.HarborRegistryEngine(
            harbor_url="https://harbor.example.com",
            harbor_username="admin",
            harbor_password="pass",
            client=stub_client,
        )
        engine.trigger_scan(
            project_name="library",
            repository_name="nginx",
            digest="sha256:abc123",
        )

    bus.emit.assert_called_once()
    event_type = bus.emit.call_args[0][0]
    assert event_type == "scan.completed", f"expected scan.completed, got {event_type!r}"


# ---------------------------------------------------------------------------
# 8. CyberArkPAMEngine — asset.discovered via retrieve_password()
#    Requires CyberArk auth round-trip — inject stub client.
# ---------------------------------------------------------------------------

def test_cyberark_emits_asset_discovered():
    import httpx
    import core.cyberark_pam_engine as mod

    auth_resp = MagicMock()
    auth_resp.status_code = 200
    auth_resp.text = '"session-token-abc"'
    auth_resp.json.return_value = "session-token-abc"

    pw_resp = MagicMock()
    pw_resp.status_code = 200
    pw_resp.text = '"s3cr3t"'

    stub_client = MagicMock(spec=httpx.Client)
    # First POST = Logon, second POST = retrieve password
    stub_client.post.side_effect = [auth_resp, pw_resp]

    bus, get_bus = _make_fake_bus()
    with patch.object(mod, "_get_tg_bus", get_bus):
        engine = mod.CyberArkPAMEngine(
            cyberark_url="https://cyberark.example.com",
            cyberark_username="admin",
            cyberark_password="pass",
            client=stub_client,
        )
        # Seed a cached token so _ensure_available passes without Logon call
        engine._cached_token = "session-token-abc"
        import time
        engine._token_acquired_at = time.time()
        engine.retrieve_password(account_id="acct-001", reason="audit")

    bus.emit.assert_called_once()
    event_type = bus.emit.call_args[0][0]
    assert event_type == "asset.discovered", f"expected asset.discovered, got {event_type!r}"


# ---------------------------------------------------------------------------
# 9. MISPIntegrationEngine — threat.detected via list_events()
# ---------------------------------------------------------------------------

def test_misp_emits_threat_detected():
    import httpx
    import core.misp_integration_engine as mod

    events_resp = MagicMock()
    events_resp.status_code = 200  # real int
    events_resp.json.return_value = [
        {"Event": {"id": "1", "info": "APT28 campaign", "date": "2026-05-01"}}
    ]

    stub_client = MagicMock(spec=httpx.Client)
    # MISPIntegrationEngine calls client.request(method, url, ...)
    stub_client.request.return_value = events_resp

    bus, get_bus = _make_fake_bus()
    with patch.object(mod, "_get_tg_bus", get_bus):
        engine = mod.MISPIntegrationEngine(
            misp_url="https://misp.example.com",
            auth_key="key123",
            client=stub_client,
        )
        engine.list_events()

    bus.emit.assert_called_once()
    event_type = bus.emit.call_args[0][0]
    assert event_type == "threat.detected", f"expected threat.detected, got {event_type!r}"


# ---------------------------------------------------------------------------
# 10. QualysEngine — scan.completed via launch_scan()
# ---------------------------------------------------------------------------

def test_qualys_emits_scan_completed():
    import httpx
    import core.qualys_engine as mod

    scan_resp = MagicMock()
    scan_resp.status_code = 200  # real int — engine does >= 400 check
    scan_resp.text = "<SIMPLE_RETURN><RESPONSE><CODE>2001</CODE></RESPONSE></SIMPLE_RETURN>"
    scan_resp.json.return_value = {"SIMPLE_RETURN": {"RESPONSE": {"CODE": "2001"}}}

    stub_client = MagicMock(spec=httpx.Client)
    # QualysEngine uses client.post for action=launch, client.get for others
    stub_client.post.return_value = scan_resp
    stub_client.get.return_value = scan_resp

    bus, get_bus = _make_fake_bus()
    with patch.object(mod, "_get_tg_bus", get_bus):
        engine = mod.QualysEngine(
            username="user",
            password="pass",
            api_base="https://qualysapi.example.com",
            client=stub_client,
        )
        engine.launch_scan(
            scan_title="Test Scan",
            ip="192.168.1.1",
            option_title="Basic",
        )

    bus.emit.assert_called_once()
    event_type = bus.emit.call_args[0][0]
    assert event_type == "scan.completed", f"expected scan.completed, got {event_type!r}"


# ---------------------------------------------------------------------------
# 11. CheckmarxEngine — scan.completed via create_scan()
# ---------------------------------------------------------------------------

def test_checkmarx_emits_scan_completed():
    import httpx
    import core.checkmarx_engine as mod

    scan_resp = MagicMock()
    scan_resp.status_code = 201
    scan_resp.json.return_value = {"id": "scan-xyz"}

    stub_client = MagicMock(spec=httpx.Client)
    stub_client.post.return_value = scan_resp

    body = {"project": {"id": "proj-001"}, "engineConfiguration": {"id": 1}}

    bus, get_bus = _make_fake_bus()
    with patch.object(mod, "_get_tg_bus", get_bus):
        engine = mod.CheckmarxEngine(
            base_url="https://cx.example.com",
            client_id="cid",
            client_secret="csec",
            tenant="mytenant",
            client=stub_client,
        )
        # Pre-seed token so no auth round-trip
        engine._token = "tok"
        engine._token_expires_at = 1e18
        engine.create_scan(body)

    bus.emit.assert_called_once()
    event_type = bus.emit.call_args[0][0]
    assert event_type == "scan.completed", f"expected scan.completed, got {event_type!r}"


# ---------------------------------------------------------------------------
# 12. SonarQubeEngine — threat.detected via issues_search()
# ---------------------------------------------------------------------------

def test_sonarqube_emits_threat_detected():
    import httpx
    import core.sonarqube_engine as mod

    issues_resp = MagicMock()
    issues_resp.status_code = 200
    issues_resp.json.return_value = {
        "issues": [{"key": "issue1", "rule": "java:S1234", "severity": "MAJOR"}],
        "paging": {"pageIndex": 1, "pageSize": 100, "total": 1},
    }

    stub_client = MagicMock(spec=httpx.Client)
    stub_client.get.return_value = issues_resp

    bus, get_bus = _make_fake_bus()
    with patch.object(mod, "_get_tg_bus", get_bus):
        engine = mod.SonarQubeEngine(
            base_url="https://sonar.example.com",
            token="tok123",
            client=stub_client,
        )
        engine.issues_search(componentKeys="my-project")

    bus.emit.assert_called_once()
    event_type = bus.emit.call_args[0][0]
    assert event_type == "threat.detected", f"expected threat.detected, got {event_type!r}"


# ---------------------------------------------------------------------------
# 13. JiraCloudEngine — incident.created via create_issue()
# ---------------------------------------------------------------------------

def test_jira_emits_incident_created():
    import httpx
    import core.jira_cloud_engine as mod

    issue_resp = MagicMock()
    issue_resp.status_code = 201  # real int
    issue_resp.json.return_value = {"id": "10000", "key": "SEC-1", "self": "https://..."}

    stub_client = MagicMock(spec=httpx.Client)
    # JiraCloudEngine calls client.request(method, url, ...)
    stub_client.request.return_value = issue_resp

    fields = {
        "project": {"key": "SEC"},
        "summary": "CVE-2024-0001 needs remediation",
        "issuetype": {"name": "Bug"},
        "priority": {"name": "High"},
    }

    bus, get_bus = _make_fake_bus()
    with patch.object(mod, "_get_tg_bus", get_bus):
        engine = mod.JiraCloudEngine(
            jira_url="https://myorg.atlassian.net",
            jira_auth="user@example.com:api-token",
            client=stub_client,
        )
        engine.create_issue(fields)

    bus.emit.assert_called_once()
    event_type = bus.emit.call_args[0][0]
    assert event_type == "incident.created", f"expected incident.created, got {event_type!r}"


# ---------------------------------------------------------------------------
# 14. ElasticSecurityEngine — threat.detected via search_signals()
# ---------------------------------------------------------------------------

def test_elastic_emits_threat_detected():
    import httpx
    import core.elastic_security_engine as mod

    signals_resp = MagicMock()
    signals_resp.status_code = 200  # real int — engine does >= 400 check
    signals_resp.json.return_value = {
        "hits": {
            "hits": [
                {"_id": "sig1", "_source": {"signal": {"rule": {"name": "Suspicious"}}}}
            ],
            "total": {"value": 1},
        }
    }

    stub_client = MagicMock(spec=httpx.Client)
    # ElasticSecurityEngine calls client.request(method, url, ...)
    stub_client.request.return_value = signals_resp

    bus, get_bus = _make_fake_bus()
    with patch.object(mod, "_get_tg_bus", get_bus):
        engine = mod.ElasticSecurityEngine(
            base_url="https://elastic.example.com",
            api_key="apikey123",
            client=stub_client,
        )
        engine.search_signals({"query": {"match_all": {}}})

    bus.emit.assert_called_once()
    event_type = bus.emit.call_args[0][0]
    assert event_type == "threat.detected", f"expected threat.detected, got {event_type!r}"
