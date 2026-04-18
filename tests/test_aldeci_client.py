"""Tests for ALDECIClient SDK — all HTTP calls mocked via unittest.mock.

Covers:
  - Constructor defaults and environment variable fallback
  - _request error handling (4xx / 5xx -> ALDECIError)
  - All major domain methods (health, SBOM, SOC, compliance, intelligence, risk, posture)
  - Query parameter serialisation
  - Request body serialisation
"""

from __future__ import annotations

import json
import os
import urllib.error
from io import BytesIO
from unittest.mock import MagicMock, call, patch

import pytest

from core.aldeci_client import ALDECIClient, ALDECIError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mock_response(payload, status: int = 200):
    """Return a context-manager mock that yields a readable HTTP response."""
    body = json.dumps(payload).encode()
    mock_resp = MagicMock()
    mock_resp.read.return_value = body
    mock_resp.status = status
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    return mock_resp


def _http_error(code: int, body=None):
    body_bytes = json.dumps(body or {"detail": "error"}).encode()
    return urllib.error.HTTPError(
        url="http://localhost:8000/api/v1/test",
        code=code,
        msg="Error",
        hdrs=None,
        fp=BytesIO(body_bytes),
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def client():
    return ALDECIClient(base_url="http://localhost:8000", api_key="test-key")


@pytest.fixture
def client_no_key():
    return ALDECIClient(base_url="http://localhost:8000", api_key="")


# ---------------------------------------------------------------------------
# 1. Constructor & environment variable fallback
# ---------------------------------------------------------------------------

def test_constructor_explicit_values():
    c = ALDECIClient(base_url="http://myserver:9000", api_key="secret")
    assert c.base_url == "http://myserver:9000"
    assert c._api_key == "secret"


def test_constructor_strips_trailing_slash():
    c = ALDECIClient(base_url="http://myserver:9000/", api_key="k")
    assert c.base_url == "http://myserver:9000"


def test_constructor_env_fallback(monkeypatch):
    monkeypatch.setenv("ALDECI_BASE_URL", "http://envserver:8888")
    monkeypatch.setenv("ALDECI_API_KEY", "env-key")
    c = ALDECIClient()
    assert c.base_url == "http://envserver:8888"
    assert c._api_key == "env-key"


def test_constructor_explicit_overrides_env(monkeypatch):
    monkeypatch.setenv("ALDECI_BASE_URL", "http://envserver:8888")
    monkeypatch.setenv("ALDECI_API_KEY", "env-key")
    c = ALDECIClient(base_url="http://explicit:1234", api_key="explicit-key")
    assert c.base_url == "http://explicit:1234"
    assert c._api_key == "explicit-key"


def test_constructor_default_timeout():
    c = ALDECIClient()
    assert c._timeout == 30


# ---------------------------------------------------------------------------
# 2. _headers — API key injection
# ---------------------------------------------------------------------------

def test_headers_includes_api_key(client):
    h = client._headers()
    assert h["X-API-Key"] == "test-key"
    assert h["Content-Type"] == "application/json"
    assert h["Accept"] == "application/json"


def test_headers_no_api_key_omits_header(client_no_key):
    h = client_no_key._headers()
    assert "X-API-Key" not in h


# ---------------------------------------------------------------------------
# 3. Error handling — ALDECIError raised on 4xx / 5xx
# ---------------------------------------------------------------------------

def test_request_raises_on_404(client):
    with patch("urllib.request.urlopen", side_effect=_http_error(404, {"detail": "not found"})):
        with pytest.raises(ALDECIError) as exc_info:
            client._get("/api/v1/missing")
    assert exc_info.value.status_code == 404
    assert "not found" in exc_info.value.detail


def test_request_raises_on_403(client):
    with patch("urllib.request.urlopen", side_effect=_http_error(403, {"detail": "forbidden"})):
        with pytest.raises(ALDECIError) as exc_info:
            client._get("/api/v1/protected")
    assert exc_info.value.status_code == 403


def test_request_raises_on_500(client):
    with patch("urllib.request.urlopen", side_effect=_http_error(500, {"detail": "server error"})):
        with pytest.raises(ALDECIError) as exc_info:
            client._get("/api/v1/crash")
    assert exc_info.value.status_code == 500


def test_aldeci_error_str_representation():
    err = ALDECIError(401, "Unauthorized")
    assert "401" in str(err)
    assert "Unauthorized" in str(err)


# ---------------------------------------------------------------------------
# 4. Health endpoints
# ---------------------------------------------------------------------------

def test_health(client):
    payload = {"status": "ok"}
    with patch("urllib.request.urlopen", return_value=_mock_response(payload)):
        result = client.health()
    assert result == payload


def test_platform_health(client):
    payload = {"api": "ok", "db": "ok"}
    with patch("urllib.request.urlopen", return_value=_mock_response(payload)):
        result = client.platform_health()
    assert result["api"] == "ok"


def test_deployment_health(client):
    payload = {"services": {"api": "healthy"}}
    with patch("urllib.request.urlopen", return_value=_mock_response(payload)):
        result = client.deployment_health()
    assert "services" in result


# ---------------------------------------------------------------------------
# 5. SBOM Export
# ---------------------------------------------------------------------------

def test_sbom_export_cyclonedx(client):
    payload = {"bomFormat": "CycloneDX", "specVersion": "1.4", "components": []}
    with patch("urllib.request.urlopen", return_value=_mock_response(payload)) as mock_open:
        result = client.sbom_export_cyclonedx("my-service", org_id="acme")
    assert result["bomFormat"] == "CycloneDX"
    # Verify POST body was sent
    req_obj = mock_open.call_args[0][0]
    body = json.loads(req_obj.data)
    assert body["project_name"] == "my-service"
    assert body["org_id"] == "acme"


def test_sbom_export_spdx(client):
    payload = {"spdxVersion": "SPDX-2.3", "packages": []}
    with patch("urllib.request.urlopen", return_value=_mock_response(payload)):
        result = client.sbom_export_spdx("frontend", org_id="acme")
    assert result["spdxVersion"] == "SPDX-2.3"


def test_sbom_projects(client):
    payload = [{"project_name": "backend", "component_count": 42}]
    with patch("urllib.request.urlopen", return_value=_mock_response(payload)):
        result = client.sbom_projects(org_id="acme")
    assert isinstance(result, list)
    assert result[0]["project_name"] == "backend"


# ---------------------------------------------------------------------------
# 6. SOC — Alert Triage
# ---------------------------------------------------------------------------

def test_alert_queue(client):
    payload = [{"alert_id": "a1", "priority": "p1"}, {"alert_id": "a2", "priority": "p2"}]
    with patch("urllib.request.urlopen", return_value=_mock_response(payload)):
        result = client.alert_queue(org_id="acme")
    assert len(result) == 2
    assert result[0]["priority"] == "p1"


def test_alerts_with_status_filter(client):
    payload = [{"alert_id": "a1", "status": "open"}]
    with patch("urllib.request.urlopen", return_value=_mock_response(payload)) as mock_open:
        result = client.alerts(org_id="acme", status="open")
    url = mock_open.call_args[0][0].full_url
    assert "status=open" in url
    assert "org_id=acme" in url


def test_alert_stats(client):
    payload = {"total": 100, "p1": 5, "p2": 20}
    with patch("urllib.request.urlopen", return_value=_mock_response(payload)):
        result = client.alert_stats(org_id="acme")
    assert result["total"] == 100


# ---------------------------------------------------------------------------
# 7. SOC — Incident Orchestration
# ---------------------------------------------------------------------------

def test_incidents(client):
    payload = [{"incident_id": "i1", "severity": "critical"}]
    with patch("urllib.request.urlopen", return_value=_mock_response(payload)):
        result = client.incidents(org_id="acme", severity="critical")
    assert result[0]["severity"] == "critical"


def test_incident_metrics(client):
    payload = {"mttr_hours": 4.2, "mttc_hours": 1.1}
    with patch("urllib.request.urlopen", return_value=_mock_response(payload)):
        result = client.incident_metrics(org_id="acme")
    assert "mttr_hours" in result


def test_create_incident(client):
    payload = {"incident_id": "new-1", "title": "Ransomware detected"}
    with patch("urllib.request.urlopen", return_value=_mock_response(payload)) as mock_open:
        result = client.create_incident("Ransomware detected", "critical", org_id="acme")
    assert result["incident_id"] == "new-1"
    body = json.loads(mock_open.call_args[0][0].data)
    assert body["title"] == "Ransomware detected"
    assert body["severity"] == "critical"
    assert body["org_id"] == "acme"


# ---------------------------------------------------------------------------
# 8. Compliance
# ---------------------------------------------------------------------------

def test_compliance_scan_results(client):
    payload = [{"check_id": "CIS-1.1", "status": "pass"}]
    with patch("urllib.request.urlopen", return_value=_mock_response(payload)):
        result = client.compliance_scan_results(org_id="acme")
    assert result[0]["check_id"] == "CIS-1.1"


def test_compliance_stats(client):
    payload = {"pass_count": 80, "fail_count": 20, "pass_rate": 0.8}
    with patch("urllib.request.urlopen", return_value=_mock_response(payload)):
        result = client.compliance_stats(org_id="acme")
    assert result["pass_rate"] == 0.8


def test_evidence_collect_all(client):
    payload = {"status": "queued", "collected": 5}
    with patch("urllib.request.urlopen", return_value=_mock_response(payload)) as mock_open:
        result = client.evidence_collect_all(org_id="acme")
    assert result["status"] == "queued"
    body = json.loads(mock_open.call_args[0][0].data)
    assert body["org_id"] == "acme"


# ---------------------------------------------------------------------------
# 9. Intelligence — GraphRAG & Copilot
# ---------------------------------------------------------------------------

def test_graph_query(client):
    payload = {"nodes": [{"id": "n1"}], "edges": [], "context": "threat context"}
    with patch("urllib.request.urlopen", return_value=_mock_response(payload)) as mock_open:
        result = client.graph_query("threat_context", org_id="acme", max_hops=3)
    assert "nodes" in result
    body = json.loads(mock_open.call_args[0][0].data)
    assert body["template"] == "threat_context"
    assert body["max_hops"] == 3


def test_graph_semantic_search(client):
    payload = {"results": [{"text": "lateral movement", "score": 0.9}]}
    with patch("urllib.request.urlopen", return_value=_mock_response(payload)):
        result = client.graph_semantic_search("privilege escalation")
    assert result["results"][0]["score"] == 0.9


def test_graph_health(client):
    payload = {"status": "healthy", "cores": {"security": 95}}
    with patch("urllib.request.urlopen", return_value=_mock_response(payload)):
        result = client.graph_health()
    assert result["status"] == "healthy"


def test_copilot_chat(client):
    payload = {"answer": "You have 3 critical incidents.", "confidence": 0.92}
    with patch("urllib.request.urlopen", return_value=_mock_response(payload)) as mock_open:
        result = client.copilot_chat("What are my top incidents?", org_id="acme")
    assert "answer" in result
    body = json.loads(mock_open.call_args[0][0].data)
    assert body["message"] == "What are my top incidents?"
    assert body["org_id"] == "acme"


def test_copilot_agents(client):
    payload = [{"name": "security-analyst", "capabilities": ["threat-intel"]}]
    with patch("urllib.request.urlopen", return_value=_mock_response(payload)):
        result = client.copilot_agents()
    assert isinstance(result, list)
    assert result[0]["name"] == "security-analyst"


# ---------------------------------------------------------------------------
# 10. Risk
# ---------------------------------------------------------------------------

def test_risk_org_score(client):
    payload = {"score": 72, "grade": "C", "domains": {}}
    with patch("urllib.request.urlopen", return_value=_mock_response(payload)):
        result = client.risk_org_score(org_id="acme")
    assert result["grade"] == "C"


def test_risk_heatmap(client):
    payload = {"cells": [{"likelihood": 3, "impact": 4, "count": 2}]}
    with patch("urllib.request.urlopen", return_value=_mock_response(payload)):
        result = client.risk_heatmap(org_id="acme")
    assert "cells" in result


def test_risk_overview_aggregates_calls(client):
    """risk_overview() calls three sub-endpoints and merges results."""
    top = [{"entity": "db-01", "score": 90}]
    stats = {"total": 50}
    org_score = {"score": 72, "grade": "C"}

    responses = [
        _mock_response(top),
        _mock_response(stats),
        _mock_response(org_score),
    ]
    with patch("urllib.request.urlopen", side_effect=responses):
        result = client.risk_overview(org_id="acme")

    assert "top_risks" in result
    assert "stats" in result
    assert "org_score" in result
    assert result["org_score"]["grade"] == "C"


# ---------------------------------------------------------------------------
# 11. Security Posture
# ---------------------------------------------------------------------------

def test_posture_score(client):
    payload = {"score": 85, "grade": "B", "components": {}}
    with patch("urllib.request.urlopen", return_value=_mock_response(payload)):
        result = client.posture_score(org_id="acme")
    assert result["score"] == 85


def test_posture_history(client):
    payload = [{"score": 80, "timestamp": "2026-04-15"}, {"score": 85, "timestamp": "2026-04-16"}]
    with patch("urllib.request.urlopen", return_value=_mock_response(payload)) as mock_open:
        result = client.posture_history(org_id="acme", limit=90)
    assert len(result) == 2
    url = mock_open.call_args[0][0].full_url
    assert "limit=90" in url


# ---------------------------------------------------------------------------
# 12. Vulnerability Intelligence
# ---------------------------------------------------------------------------

def test_vulnerabilities_with_severity_filter(client):
    payload = [{"cve_id": "CVE-2024-1234", "severity": "critical", "cvss": 9.8}]
    with patch("urllib.request.urlopen", return_value=_mock_response(payload)) as mock_open:
        result = client.vulnerabilities(org_id="acme", severity="critical")
    assert result[0]["cvss"] == 9.8
    url = mock_open.call_args[0][0].full_url
    assert "severity=critical" in url


def test_vulnerability_stats(client):
    payload = {"critical": 5, "high": 20, "medium": 50}
    with patch("urllib.request.urlopen", return_value=_mock_response(payload)):
        result = client.vulnerability_stats(org_id="acme")
    assert result["critical"] == 5


# ---------------------------------------------------------------------------
# 13. Supply Chain
# ---------------------------------------------------------------------------

def test_supply_chain_risks(client):
    payload = [{"risk_id": "sc-1", "severity": "high", "vendor": "lodash"}]
    with patch("urllib.request.urlopen", return_value=_mock_response(payload)):
        result = client.supply_chain_risks(org_id="acme")
    assert result[0]["vendor"] == "lodash"


# ---------------------------------------------------------------------------
# 14. Attack Surface
# ---------------------------------------------------------------------------

def test_attack_surface_summary(client):
    payload = {"exposure_score": 42, "open_exposures": 17}
    with patch("urllib.request.urlopen", return_value=_mock_response(payload)):
        result = client.attack_surface_summary(org_id="acme")
    assert result["exposure_score"] == 42


# ---------------------------------------------------------------------------
# 15. Assets
# ---------------------------------------------------------------------------

def test_assets_with_type_filter(client):
    payload = [{"asset_id": "srv-01", "type": "server"}]
    with patch("urllib.request.urlopen", return_value=_mock_response(payload)) as mock_open:
        result = client.assets(org_id="acme", asset_type="server")
    assert result[0]["type"] == "server"
    url = mock_open.call_args[0][0].full_url
    assert "asset_type=server" in url


# ---------------------------------------------------------------------------
# 16. KPI
# ---------------------------------------------------------------------------

def test_kpi_summary(client):
    payload = {"mttd_hours": 2.5, "mttr_hours": 8.0, "grade": "A"}
    with patch("urllib.request.urlopen", return_value=_mock_response(payload)):
        result = client.kpi_summary(org_id="acme")
    assert result["grade"] == "A"


# ---------------------------------------------------------------------------
# 17. Connectors
# ---------------------------------------------------------------------------

def test_connectors_health(client):
    payload = {"splunk": "ok", "jira": "degraded"}
    with patch("urllib.request.urlopen", return_value=_mock_response(payload)):
        result = client.connectors_health()
    assert result["splunk"] == "ok"


def test_list_connectors(client):
    payload = [{"name": "splunk", "type": "siem", "status": "active"}]
    with patch("urllib.request.urlopen", return_value=_mock_response(payload)):
        result = client.list_connectors(org_id="acme")
    assert result[0]["name"] == "splunk"


# ---------------------------------------------------------------------------
# 18. Threat Intelligence
# ---------------------------------------------------------------------------

def test_threat_indicators_with_type(client):
    payload = [{"indicator": "1.2.3.4", "ioc_type": "ip", "confidence": 0.9}]
    with patch("urllib.request.urlopen", return_value=_mock_response(payload)) as mock_open:
        result = client.threat_indicators(org_id="acme", ioc_type="ip")
    assert result[0]["ioc_type"] == "ip"
    url = mock_open.call_args[0][0].full_url
    assert "ioc_type=ip" in url


def test_threat_intel_stats(client):
    payload = {"total_iocs": 1500, "active": 800}
    with patch("urllib.request.urlopen", return_value=_mock_response(payload)):
        result = client.threat_intel_stats(org_id="acme")
    assert result["total_iocs"] == 1500


# ---------------------------------------------------------------------------
# 19. None params are excluded from query string
# ---------------------------------------------------------------------------

def test_none_params_excluded(client):
    """Params with None values must not appear in the query string."""
    payload = []
    with patch("urllib.request.urlopen", return_value=_mock_response(payload)) as mock_open:
        client.alerts(org_id="acme", status=None)
    url = mock_open.call_args[0][0].full_url
    assert "status" not in url
    assert "org_id=acme" in url


# ---------------------------------------------------------------------------
# 20. Empty response body handled gracefully
# ---------------------------------------------------------------------------

def test_empty_response_body(client):
    mock_resp = MagicMock()
    mock_resp.read.return_value = b""
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    with patch("urllib.request.urlopen", return_value=mock_resp):
        result = client._get("/api/v1/noop")
    assert result == {}
