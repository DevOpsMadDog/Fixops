"""Tests for tenable_io_router — ALDECI.

Spins up a minimal FastAPI app with the Tenable.io router mounted. Each test
gets an isolated engine singleton with a stub httpx.Client.

NO MOCKS rule:
  * Live endpoints return HTTP 503 when access/secret keys are unset.
  * Capability summary reports ``status="unavailable"`` with no creds.
  * Happy paths inject a stub httpx.Client (not a hardcoded engine payload)
    so we still exercise the real networking + parsing code paths.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

import pytest

from tests.conftest import API_TOKEN

from fastapi import FastAPI
from fastapi.testclient import TestClient

HEADERS = {"X-API-Key": API_TOKEN}


# ---------------------------------------------------------------------------
# httpx stubs
# ---------------------------------------------------------------------------


class _StubResponse:
    """Minimal stand-in for httpx.Response with .json() + .status_code."""

    def __init__(self, status_code: int, payload: Any, text: str = ""):
        self.status_code = status_code
        self._payload = payload
        self.text = text or json.dumps(payload)

    def json(self) -> Any:
        return self._payload


class _StubClient:
    """Records calls and returns a queued response per URL suffix."""

    def __init__(self, responses: Dict[str, Any]):
        self._responses = responses
        self.calls: List[Dict[str, Any]] = []

    def _match(self, url: str) -> Any:
        # longest-prefix-first to disambiguate /scans/{id}/hosts/{id} from /scans/{id}
        for path in sorted(self._responses.keys(), key=len, reverse=True):
            if path in url:
                return self._responses[path]
        return _StubResponse(404, {"error": "not found"}, text="not found")

    def get(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
    ):  # noqa: D401
        self.calls.append(
            {
                "method": "GET",
                "url": url,
                "headers": headers or {},
                "params": params or {},
            }
        )
        return self._match(url)

    def post(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
    ):  # noqa: D401, A002
        self.calls.append(
            {
                "method": "POST",
                "url": url,
                "headers": headers or {},
                "params": params or {},
                "json": json or {},
            }
        )
        return self._match(url)

    def close(self) -> None:
        pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_app(
    *,
    access_key: Optional[str],
    secret_key: Optional[str],
    stub_responses: Dict[str, Any],
):
    """Construct an isolated app+engine bound to a stub client."""
    from core import tenable_io_engine as engine_mod

    engine_mod.reset_tenable_io_engine()

    stub_client = _StubClient(stub_responses)
    engine_mod.get_tenable_io_engine(
        access_key=access_key,
        secret_key=secret_key,
        client=stub_client,
    )

    from apps.api.tenable_io_router import router

    app = FastAPI()
    app.include_router(router)
    return app, stub_client


def _reset():
    from core import tenable_io_engine as engine_mod

    engine_mod.reset_tenable_io_engine()


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


def test_capability_summary_unavailable_when_no_credentials(monkeypatch):
    monkeypatch.delenv("TENABLE_ACCESS_KEY", raising=False)
    monkeypatch.delenv("TENABLE_SECRET_KEY", raising=False)
    app, _ = _build_app(access_key=None, secret_key=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/tenable-io/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "Tenable.io"
    assert "/scans" in body["endpoints"]
    assert "/scans/{scan_id}" in body["endpoints"]
    assert "/scans/{scan_id}/hosts/{host_id}" in body["endpoints"]
    assert "/agents" in body["endpoints"]
    assert "/policies" in body["endpoints"]
    assert "/workbenches/vulnerabilities" in body["endpoints"]
    assert body["tenable_access_key_present"] is False
    assert body["tenable_secret_key_present"] is False
    assert body["status"] == "unavailable"
    _reset()


def test_capability_summary_ok_when_both_keys_present(monkeypatch):
    monkeypatch.setenv("TENABLE_ACCESS_KEY", "ak")
    monkeypatch.setenv("TENABLE_SECRET_KEY", "sk")
    app, _ = _build_app(
        access_key="ak", secret_key="sk", stub_responses={}
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/tenable-io/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["tenable_access_key_present"] is True
    assert body["tenable_secret_key_present"] is True
    assert body["status"] == "ok"
    _reset()


def test_capability_summary_unavailable_when_only_one_key_set(monkeypatch):
    monkeypatch.setenv("TENABLE_ACCESS_KEY", "ak")
    monkeypatch.delenv("TENABLE_SECRET_KEY", raising=False)
    app, _ = _build_app(
        access_key="ak", secret_key=None, stub_responses={}
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/tenable-io/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["tenable_access_key_present"] is True
    assert body["tenable_secret_key_present"] is False
    assert body["status"] == "unavailable"
    _reset()


# ---------------------------------------------------------------------------
# 503 paths when no credentials
# ---------------------------------------------------------------------------


def test_scans_returns_503_when_no_credentials(monkeypatch):
    monkeypatch.delenv("TENABLE_ACCESS_KEY", raising=False)
    monkeypatch.delenv("TENABLE_SECRET_KEY", raising=False)
    app, _ = _build_app(access_key=None, secret_key=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/tenable-io/scans", headers=HEADERS)
    assert r.status_code == 503, r.text
    detail = r.json()["detail"]
    assert "TENABLE_ACCESS_KEY" in detail or "TENABLE_SECRET_KEY" in detail
    _reset()


def test_scan_detail_returns_503_when_no_credentials(monkeypatch):
    monkeypatch.delenv("TENABLE_ACCESS_KEY", raising=False)
    monkeypatch.delenv("TENABLE_SECRET_KEY", raising=False)
    app, _ = _build_app(access_key=None, secret_key=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/tenable-io/scans/42", headers=HEADERS)
    assert r.status_code == 503, r.text
    _reset()


def test_host_detail_returns_503_when_no_credentials(monkeypatch):
    monkeypatch.delenv("TENABLE_ACCESS_KEY", raising=False)
    monkeypatch.delenv("TENABLE_SECRET_KEY", raising=False)
    app, _ = _build_app(access_key=None, secret_key=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/tenable-io/scans/42/hosts/7", headers=HEADERS)
    assert r.status_code == 503, r.text
    _reset()


def test_agents_returns_503_when_no_credentials(monkeypatch):
    monkeypatch.delenv("TENABLE_ACCESS_KEY", raising=False)
    monkeypatch.delenv("TENABLE_SECRET_KEY", raising=False)
    app, _ = _build_app(access_key=None, secret_key=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/tenable-io/agents?limit=10&offset=0", headers=HEADERS
    )
    assert r.status_code == 503, r.text
    _reset()


def test_policies_returns_503_when_no_credentials(monkeypatch):
    monkeypatch.delenv("TENABLE_ACCESS_KEY", raising=False)
    monkeypatch.delenv("TENABLE_SECRET_KEY", raising=False)
    app, _ = _build_app(access_key=None, secret_key=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/tenable-io/policies", headers=HEADERS)
    assert r.status_code == 503, r.text
    _reset()


def test_workbench_returns_503_when_no_credentials(monkeypatch):
    monkeypatch.delenv("TENABLE_ACCESS_KEY", raising=False)
    monkeypatch.delenv("TENABLE_SECRET_KEY", raising=False)
    app, _ = _build_app(access_key=None, secret_key=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/tenable-io/workbenches/vulnerabilities",
        json={"date_range": 30, "severity": [3, 4]},
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text
    _reset()


# ---------------------------------------------------------------------------
# Happy paths — stubbed httpx client
# ---------------------------------------------------------------------------


def test_scans_happy_path_normalizes(monkeypatch):
    monkeypatch.setenv("TENABLE_ACCESS_KEY", "ak")
    monkeypatch.setenv("TENABLE_SECRET_KEY", "sk")
    raw = {
        "scans": [
            {
                "id": 42,
                "uuid": "scan-uuid-1",
                "name": "Weekly DC Scan",
                "type": "remote",
                "status": "completed",
                "owner": "secops@example.com",
                "creation_date": 1700000000,
                "last_modification_date": 1700100000,
                "starttime": "20260501T010000",
                "schedule_uuid": "sched-uuid-1",
                "has_triggers": False,
                "scan_uuid": "scan-uuid-1",
            },
            {
                "id": 43,
                "uuid": "scan-uuid-2",
                "name": "Adhoc Web Scan",
                "type": "remote",
                "status": "running",
                "owner": "appsec@example.com",
                "creation_date": 1700200000,
                "last_modification_date": 1700300000,
            },
        ]
    }
    app, stub = _build_app(
        access_key="ak",
        secret_key="sk",
        stub_responses={"/scans": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/tenable-io/scans", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["scans"]) == 2
    assert body["scans"][0]["id"] == 42
    assert body["scans"][0]["name"] == "Weekly DC Scan"
    assert body["scans"][0]["status"] == "completed"
    assert body["scans"][1]["scan_uuid"] == "scan-uuid-2"  # falls back to uuid
    # X-ApiKeys header was set
    assert (
        stub.calls[0]["headers"]["X-ApiKeys"]
        == "accessKey=ak; secretKey=sk"
    )
    _reset()


def test_scan_detail_happy_path_normalizes(monkeypatch):
    monkeypatch.setenv("TENABLE_ACCESS_KEY", "ak")
    monkeypatch.setenv("TENABLE_SECRET_KEY", "sk")
    raw = {
        "info": {
            "name": "Weekly DC Scan",
            "status": "completed",
            "scan_start": 1700000000,
            "scan_end": 1700001000,
            "targets": "10.0.0.0/24",
            "hostcount": 12,
            "severity_processed": 234,
            "hosts_processed": 12,
            "scan_type": "remote",
        },
        "hosts": [
            {
                "host_id": 7,
                "hostname": "db-01.internal",
                "score": 1234,
                "critical": 2,
                "high": 5,
                "medium": 11,
                "low": 4,
                "info": 33,
            }
        ],
        "vulnerabilities": [
            {
                "count": 7,
                "severity": 4,
                "plugin_id": 156123,
                "plugin_name": "Apache Log4j RCE",
                "plugin_family": "Web Servers",
            }
        ],
    }
    app, stub = _build_app(
        access_key="ak",
        secret_key="sk",
        stub_responses={"/scans/42": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/tenable-io/scans/42?history_id=99", headers=HEADERS
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["info"]["name"] == "Weekly DC Scan"
    assert body["info"]["hostcount"] == 12
    assert len(body["hosts"]) == 1
    assert body["hosts"][0]["host_id"] == 7
    assert body["hosts"][0]["critical"] == 2
    assert len(body["vulnerabilities"]) == 1
    assert body["vulnerabilities"][0]["plugin_id"] == 156123
    # history_id forwarded
    assert stub.calls[0]["params"]["history_id"] == 99
    _reset()


def test_host_detail_happy_path_normalizes(monkeypatch):
    monkeypatch.setenv("TENABLE_ACCESS_KEY", "ak")
    monkeypatch.setenv("TENABLE_SECRET_KEY", "sk")
    raw = {
        "info": {
            "host_start": "Sat May  3 02:00:00 2026",
            "host_end": "Sat May  3 02:14:00 2026",
            "host_fqdn": "db-01.internal.example.com",
            "host_ip": "10.0.0.7",
            "mac-address": "00:11:22:33:44:55",
            "operating-system": ["Ubuntu Linux 22.04"],
        },
        "vulnerabilities": [
            {
                "vuln_index": 0,
                "plugin_id": 156123,
                "plugin_name": "Apache Log4j RCE",
                "severity": 4,
                "count": 1,
                "cve": ["CVE-2021-44228", "CVE-2021-45046"],
            },
            {
                "vuln_index": 1,
                "plugin_id": 19506,
                "plugin_name": "Nessus Scan Information",
                "severity": 0,
                "count": 1,
                "cve": "CVE-2024-9999",
            },
        ],
        "compliance": [
            {"check_id": "cis-1.1.1", "severity": 3, "count": 1}
        ],
    }
    app, _ = _build_app(
        access_key="ak",
        secret_key="sk",
        stub_responses={"/scans/42/hosts/7": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/tenable-io/scans/42/hosts/7", headers=HEADERS
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["info"]["host_fqdn"] == "db-01.internal.example.com"
    assert body["info"]["mac_address"] == "00:11:22:33:44:55"
    assert "Ubuntu Linux 22.04" in body["info"]["operating_system"]
    assert len(body["vulnerabilities"]) == 2
    assert body["vulnerabilities"][0]["cve"] == [
        "CVE-2021-44228",
        "CVE-2021-45046",
    ]
    # scalar cve coerced to list
    assert body["vulnerabilities"][1]["cve"] == ["CVE-2024-9999"]
    assert len(body["compliance"]) == 1
    assert body["compliance"][0]["check_id"] == "cis-1.1.1"
    _reset()


def test_agents_happy_path_normalizes(monkeypatch):
    monkeypatch.setenv("TENABLE_ACCESS_KEY", "ak")
    monkeypatch.setenv("TENABLE_SECRET_KEY", "sk")
    raw = {
        "agents": [
            {
                "id": 1,
                "uuid": "agent-uuid-1",
                "name": "host-01",
                "platform": "LINUX",
                "distro": "ubuntu-22.04",
                "ip": "10.0.0.10",
                "last_scanned": 1700000000,
                "plugin_feed_id": "202604261200",
                "core_version": "10.5.3",
                "status": "on",
                "network_uuid": "net-default",
            }
        ]
    }
    app, stub = _build_app(
        access_key="ak",
        secret_key="sk",
        stub_responses={"/scanners/null/agents": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/tenable-io/agents?limit=25&offset=50", headers=HEADERS
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["agents"]) == 1
    assert body["agents"][0]["name"] == "host-01"
    assert body["agents"][0]["status"] == "on"
    # query forwarding
    assert stub.calls[0]["params"]["limit"] == 25
    assert stub.calls[0]["params"]["offset"] == 50
    _reset()


def test_policies_happy_path_normalizes(monkeypatch):
    monkeypatch.setenv("TENABLE_ACCESS_KEY", "ak")
    monkeypatch.setenv("TENABLE_SECRET_KEY", "sk")
    raw = {
        "policies": [
            {
                "id": 11,
                "template_uuid": "tmpl-basic",
                "name": "Basic Network Scan",
                "description": "Default Tenable scan template",
                "owner": "secops@example.com",
                "visibility": "private",
                "shared": 0,
                "user_permissions": 128,
                "last_modification_date": 1700000000,
            }
        ]
    }
    app, _ = _build_app(
        access_key="ak",
        secret_key="sk",
        stub_responses={"/policies": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/tenable-io/policies", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["policies"]) == 1
    assert body["policies"][0]["name"] == "Basic Network Scan"
    assert body["policies"][0]["template_uuid"] == "tmpl-basic"
    _reset()


def test_workbench_happy_path_normalizes(monkeypatch):
    monkeypatch.setenv("TENABLE_ACCESS_KEY", "ak")
    monkeypatch.setenv("TENABLE_SECRET_KEY", "sk")
    raw = {
        "vulnerabilities": [
            {
                "count": 23,
                "plugin_id": 156123,
                "severity": 4,
                "plugin_name": "Apache Log4j RCE",
                "plugin_family": "Web Servers",
                "vpr_score": {
                    "score": 9.3,
                    "drivers": {
                        "exploit_code_maturity": "FUNCTIONAL",
                        "threat_intensity_last28": "VERY_HIGH",
                    },
                },
            }
        ]
    }
    app, stub = _build_app(
        access_key="ak",
        secret_key="sk",
        stub_responses={
            "/workbenches/vulnerabilities": _StubResponse(200, raw)
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/tenable-io/workbenches/vulnerabilities",
        json={
            "date_range": 30,
            "severity": [3, 4],
            "vpr_score": {"gte": 7.0},
        },
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["vulnerabilities"]) == 1
    v = body["vulnerabilities"][0]
    assert v["plugin_id"] == 156123
    assert v["vpr_score"]["score"] == 9.3
    assert v["vpr_score"]["drivers"]["exploit_code_maturity"] == "FUNCTIONAL"
    # date_range was forwarded as upstream query param
    assert stub.calls[0]["params"]["date_range"] == 30
    _reset()


# ---------------------------------------------------------------------------
# Upstream error paths
# ---------------------------------------------------------------------------


def test_scans_returns_503_on_upstream_429(monkeypatch):
    monkeypatch.setenv("TENABLE_ACCESS_KEY", "ak")
    monkeypatch.setenv("TENABLE_SECRET_KEY", "sk")
    app, _ = _build_app(
        access_key="ak",
        secret_key="sk",
        stub_responses={
            "/scans": _StubResponse(
                429, {"error": "rate limit"}, text="rate limit"
            )
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/tenable-io/scans", headers=HEADERS)
    assert r.status_code == 503, r.text
    detail = r.json()["detail"]
    assert "rate-limit" in detail.lower() or "429" in detail
    _reset()


def test_scan_detail_returns_503_on_upstream_401(monkeypatch):
    monkeypatch.setenv("TENABLE_ACCESS_KEY", "bad")
    monkeypatch.setenv("TENABLE_SECRET_KEY", "bad")
    app, _ = _build_app(
        access_key="bad",
        secret_key="bad",
        stub_responses={
            "/scans/42": _StubResponse(
                401, {"error": "unauthorized"}, text="unauthorized"
            )
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/tenable-io/scans/42", headers=HEADERS)
    assert r.status_code == 503, r.text
    detail = r.json()["detail"]
    assert "401" in detail or "credential" in detail.lower()
    _reset()


def test_agents_validation_rejects_bad_limit(monkeypatch):
    monkeypatch.setenv("TENABLE_ACCESS_KEY", "ak")
    monkeypatch.setenv("TENABLE_SECRET_KEY", "sk")
    app, _ = _build_app(
        access_key="ak", secret_key="sk", stub_responses={}
    )
    client = TestClient(app, raise_server_exceptions=True)

    # FastAPI Query(ge=1) rejects 0 with 422 before engine ever runs
    r = client.get(
        "/api/v1/tenable-io/agents?limit=0&offset=0", headers=HEADERS
    )
    assert r.status_code == 422, r.text
    _reset()
