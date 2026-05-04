"""Tests for qualys_router - ALDECI.

Spins up a minimal FastAPI app with the Qualys router mounted. Each test
gets an isolated engine singleton with a stub httpx.Client.

NO MOCKS rule:
  * Live endpoints return HTTP 503 when env vars are unset.
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
    """Minimal stand-in for httpx.Response with .json() + .status_code + .text."""

    def __init__(
        self,
        status_code: int,
        payload: Any,
        text: Optional[str] = None,
        json_decodes: bool = True,
    ):
        self.status_code = status_code
        self._payload = payload
        self._json_decodes = json_decodes
        if text is not None:
            self.text = text
        else:
            try:
                self.text = json.dumps(payload)
            except (TypeError, ValueError):
                self.text = str(payload)

    def json(self) -> Any:
        if not self._json_decodes:
            raise ValueError("not json")
        return self._payload


class _StubClient:
    """Records calls and returns a queued response per URL suffix."""

    def __init__(self, responses: Dict[str, Any]):
        self._responses = responses
        self.calls: List[Dict[str, Any]] = []

    def _match(self, url: str) -> Any:
        # longest-prefix-first to disambiguate nested paths
        for path in sorted(self._responses.keys(), key=len, reverse=True):
            if path in url:
                return self._responses[path]
        return _StubResponse(404, {"error": "not found"}, text="not found")

    def get(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        auth: Any = None,
    ):  # noqa: D401
        self.calls.append(
            {
                "method": "GET",
                "url": url,
                "headers": headers or {},
                "params": params or {},
                "auth": auth,
            }
        )
        return self._match(url)

    def post(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        auth: Any = None,
    ):  # noqa: D401
        self.calls.append(
            {
                "method": "POST",
                "url": url,
                "headers": headers or {},
                "params": params or {},
                "data": data or {},
                "auth": auth,
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
    username: Optional[str],
    password: Optional[str],
    api_base: Optional[str],
    stub_responses: Dict[str, Any],
):
    """Construct an isolated app+engine bound to a stub client."""
    from core import qualys_engine as engine_mod

    engine_mod.reset_qualys_engine()

    stub_client = _StubClient(stub_responses)
    engine_mod.get_qualys_engine(
        username=username,
        password=password,
        api_base=api_base,
        client=stub_client,
    )

    from apps.api.qualys_router import router

    app = FastAPI()
    app.include_router(router)
    return app, stub_client


def _reset():
    from core import qualys_engine as engine_mod

    engine_mod.reset_qualys_engine()


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


def test_capability_summary_unavailable_when_no_credentials(monkeypatch):
    monkeypatch.delenv("QUALYS_USERNAME", raising=False)
    monkeypatch.delenv("QUALYS_PASSWORD", raising=False)
    monkeypatch.delenv("QUALYS_API_BASE", raising=False)
    app, _ = _build_app(
        username=None, password=None, api_base=None, stub_responses={}
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/qualys/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "Qualys VMDR"
    assert "/api/2.0/fo/asset/host/?action=list" in body["endpoints"]
    assert (
        "/api/2.0/fo/asset/host/vm/detection/?action=list"
        in body["endpoints"]
    )
    assert "/api/2.0/fo/scan/?action=list" in body["endpoints"]
    assert "/api/2.0/fo/scan/?action=launch" in body["endpoints"]
    assert "/api/2.0/fo/compliance/policy/?action=list" in body["endpoints"]
    assert "/api/2.0/fo/report/?action=list" in body["endpoints"]
    assert body["qualys_username_present"] is False
    assert body["qualys_password_present"] is False
    assert body["qualys_api_base_present"] is False
    assert body["status"] == "unavailable"
    _reset()


def test_capability_summary_ok_when_all_env_present(monkeypatch):
    monkeypatch.setenv("QUALYS_USERNAME", "u")
    monkeypatch.setenv("QUALYS_PASSWORD", "p")
    monkeypatch.setenv("QUALYS_API_BASE", "https://qualysapi.qualys.com")
    app, _ = _build_app(
        username="u",
        password="p",
        api_base="https://qualysapi.qualys.com",
        stub_responses={},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/qualys/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["qualys_username_present"] is True
    assert body["qualys_password_present"] is True
    assert body["qualys_api_base_present"] is True
    assert body["status"] == "ok"
    _reset()


def test_capability_summary_unavailable_when_only_user_set(monkeypatch):
    monkeypatch.setenv("QUALYS_USERNAME", "u")
    monkeypatch.delenv("QUALYS_PASSWORD", raising=False)
    monkeypatch.delenv("QUALYS_API_BASE", raising=False)
    app, _ = _build_app(
        username="u", password=None, api_base=None, stub_responses={}
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/qualys/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["qualys_username_present"] is True
    assert body["qualys_password_present"] is False
    assert body["qualys_api_base_present"] is False
    assert body["status"] == "unavailable"
    _reset()


# ---------------------------------------------------------------------------
# 503 paths when env vars are unset
# ---------------------------------------------------------------------------


def test_hosts_returns_503_when_no_credentials(monkeypatch):
    monkeypatch.delenv("QUALYS_USERNAME", raising=False)
    monkeypatch.delenv("QUALYS_PASSWORD", raising=False)
    monkeypatch.delenv("QUALYS_API_BASE", raising=False)
    app, _ = _build_app(
        username=None, password=None, api_base=None, stub_responses={}
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/qualys/api/2.0/fo/asset/host/?action=list",
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text
    detail = r.json()["detail"]
    assert "QUALYS_" in detail
    _reset()


def test_detections_returns_503_when_no_credentials(monkeypatch):
    monkeypatch.delenv("QUALYS_USERNAME", raising=False)
    monkeypatch.delenv("QUALYS_PASSWORD", raising=False)
    monkeypatch.delenv("QUALYS_API_BASE", raising=False)
    app, _ = _build_app(
        username=None, password=None, api_base=None, stub_responses={}
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/qualys/api/2.0/fo/asset/host/vm/detection/?action=list",
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text
    _reset()


def test_scans_returns_503_when_no_credentials(monkeypatch):
    monkeypatch.delenv("QUALYS_USERNAME", raising=False)
    monkeypatch.delenv("QUALYS_PASSWORD", raising=False)
    monkeypatch.delenv("QUALYS_API_BASE", raising=False)
    app, _ = _build_app(
        username=None, password=None, api_base=None, stub_responses={}
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/qualys/api/2.0/fo/scan/?action=list", headers=HEADERS
    )
    assert r.status_code == 503, r.text
    _reset()


def test_launch_scan_returns_503_when_no_credentials(monkeypatch):
    monkeypatch.delenv("QUALYS_USERNAME", raising=False)
    monkeypatch.delenv("QUALYS_PASSWORD", raising=False)
    monkeypatch.delenv("QUALYS_API_BASE", raising=False)
    app, _ = _build_app(
        username=None, password=None, api_base=None, stub_responses={}
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/qualys/api/2.0/fo/scan/?action=launch",
        json={
            "scan_title": "weekly",
            "ip": "10.0.0.0/24",
            "option_id": 1,
        },
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text
    _reset()


def test_policies_returns_503_when_no_credentials(monkeypatch):
    monkeypatch.delenv("QUALYS_USERNAME", raising=False)
    monkeypatch.delenv("QUALYS_PASSWORD", raising=False)
    monkeypatch.delenv("QUALYS_API_BASE", raising=False)
    app, _ = _build_app(
        username=None, password=None, api_base=None, stub_responses={}
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/qualys/api/2.0/fo/compliance/policy/?action=list",
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text
    _reset()


def test_reports_returns_503_when_no_credentials(monkeypatch):
    monkeypatch.delenv("QUALYS_USERNAME", raising=False)
    monkeypatch.delenv("QUALYS_PASSWORD", raising=False)
    monkeypatch.delenv("QUALYS_API_BASE", raising=False)
    app, _ = _build_app(
        username=None, password=None, api_base=None, stub_responses={}
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/qualys/api/2.0/fo/report/?action=list", headers=HEADERS
    )
    assert r.status_code == 503, r.text
    _reset()


# ---------------------------------------------------------------------------
# Happy paths - stubbed httpx client
# ---------------------------------------------------------------------------


def test_hosts_happy_path_returns_payload(monkeypatch):
    monkeypatch.setenv("QUALYS_USERNAME", "u")
    monkeypatch.setenv("QUALYS_PASSWORD", "p")
    monkeypatch.setenv("QUALYS_API_BASE", "https://qualysapi.qualys.com")
    raw = {
        "HOST_LIST_OUTPUT": {
            "RESPONSE": {
                "HOST_LIST": {
                    "HOST": [
                        {
                            "ID": 12345,
                            "IP": "10.0.0.7",
                            "DNS": "db-01.internal",
                            "OS": "Ubuntu Linux 22.04",
                            "TRACKING_METHOD": "IP",
                        }
                    ]
                }
            }
        }
    }
    app, stub = _build_app(
        username="u",
        password="p",
        api_base="https://qualysapi.qualys.com",
        stub_responses={"/api/2.0/fo/asset/host/": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/qualys/api/2.0/fo/asset/host/?action=list&truncation_limit=50",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["payload"] == raw
    # Qualys-required header was set
    assert (
        stub.calls[0]["headers"]["X-Requested-With"]
        == "ALDECI Qualys Connector"
    )
    # action + truncation_limit forwarded upstream
    assert stub.calls[0]["params"]["action"] == "list"
    assert stub.calls[0]["params"]["truncation_limit"] == 50
    # auth supplied
    assert stub.calls[0]["auth"] is not None
    _reset()


def test_detections_happy_path_returns_payload(monkeypatch):
    monkeypatch.setenv("QUALYS_USERNAME", "u")
    monkeypatch.setenv("QUALYS_PASSWORD", "p")
    monkeypatch.setenv("QUALYS_API_BASE", "https://qualysapi.qualys.com")
    raw = {
        "HOST_LIST_VM_DETECTION_OUTPUT": {
            "RESPONSE": {
                "HOST_LIST": {
                    "HOST": [
                        {
                            "ID": 12345,
                            "DETECTION_LIST": {
                                "DETECTION": [
                                    {
                                        "QID": 38170,
                                        "TYPE": "Confirmed",
                                        "SEVERITY": 5,
                                        "STATUS": "Active",
                                        "QDS": {"@severity": "Critical", "#text": 95},
                                    }
                                ]
                            },
                        }
                    ]
                }
            }
        }
    }
    app, stub = _build_app(
        username="u",
        password="p",
        api_base="https://qualysapi.qualys.com",
        stub_responses={
            "/api/2.0/fo/asset/host/vm/detection/": _StubResponse(200, raw)
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/qualys/api/2.0/fo/asset/host/vm/detection/?action=list&severities=4,5",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["payload"] == raw
    assert stub.calls[0]["params"]["severities"] == "4,5"
    assert stub.calls[0]["params"]["output_format"] == "JSON"
    _reset()


def test_scans_happy_path_returns_payload(monkeypatch):
    monkeypatch.setenv("QUALYS_USERNAME", "u")
    monkeypatch.setenv("QUALYS_PASSWORD", "p")
    monkeypatch.setenv("QUALYS_API_BASE", "https://qualysapi.qualys.com")
    raw = {
        "SCAN_LIST_OUTPUT": {
            "RESPONSE": {
                "SCAN_LIST": {
                    "SCAN": [
                        {
                            "REF": "scan/1700000000.12345",
                            "TYPE": "On-Demand",
                            "TITLE": "Weekly DC Scan",
                            "USER_LOGIN": "secops_qa",
                            "STATE": "Finished",
                        }
                    ]
                }
            }
        }
    }
    app, stub = _build_app(
        username="u",
        password="p",
        api_base="https://qualysapi.qualys.com",
        stub_responses={"/api/2.0/fo/scan/": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/qualys/api/2.0/fo/scan/?action=list&state=Finished",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["payload"] == raw
    assert stub.calls[0]["params"]["state"] == "Finished"
    _reset()


def test_launch_scan_happy_path_returns_payload(monkeypatch):
    monkeypatch.setenv("QUALYS_USERNAME", "u")
    monkeypatch.setenv("QUALYS_PASSWORD", "p")
    monkeypatch.setenv("QUALYS_API_BASE", "https://qualysapi.qualys.com")
    raw = {
        "SIMPLE_RETURN": {
            "RESPONSE": {
                "TEXT": "New scan launched",
                "ITEM_LIST": {
                    "ITEM": [
                        {"KEY": "ID", "VALUE": "5678"},
                        {
                            "KEY": "REFERENCE",
                            "VALUE": "scan/1714900000.5678",
                        },
                    ]
                },
            }
        }
    }
    app, stub = _build_app(
        username="u",
        password="p",
        api_base="https://qualysapi.qualys.com",
        stub_responses={"/api/2.0/fo/scan/": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/qualys/api/2.0/fo/scan/?action=launch",
        json={
            "scan_title": "weekly DC",
            "ip": "10.0.0.0/24",
            "option_id": 1,
            "iscanner_name": "scanner-01",
        },
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["payload"] == raw
    assert stub.calls[0]["method"] == "POST"
    assert stub.calls[0]["params"]["action"] == "launch"
    assert stub.calls[0]["data"]["scan_title"] == "weekly DC"
    assert stub.calls[0]["data"]["ip"] == "10.0.0.0/24"
    assert stub.calls[0]["data"]["option_id"] == 1
    _reset()


def test_policies_happy_path_returns_payload(monkeypatch):
    monkeypatch.setenv("QUALYS_USERNAME", "u")
    monkeypatch.setenv("QUALYS_PASSWORD", "p")
    monkeypatch.setenv("QUALYS_API_BASE", "https://qualysapi.qualys.com")
    raw = {
        "POLICY_LIST_OUTPUT": {
            "RESPONSE": {
                "POLICY_LIST": {
                    "POLICY": [
                        {
                            "ID": 100,
                            "TITLE": "CIS Benchmark for Ubuntu 22.04",
                            "STATUS": "Active",
                        }
                    ]
                }
            }
        }
    }
    app, _ = _build_app(
        username="u",
        password="p",
        api_base="https://qualysapi.qualys.com",
        stub_responses={
            "/api/2.0/fo/compliance/policy/": _StubResponse(200, raw)
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/qualys/api/2.0/fo/compliance/policy/?action=list",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["payload"] == raw
    _reset()


def test_reports_happy_path_returns_payload(monkeypatch):
    monkeypatch.setenv("QUALYS_USERNAME", "u")
    monkeypatch.setenv("QUALYS_PASSWORD", "p")
    monkeypatch.setenv("QUALYS_API_BASE", "https://qualysapi.qualys.com")
    raw = {
        "REPORT_LIST_OUTPUT": {
            "RESPONSE": {
                "REPORT_LIST": {
                    "REPORT": [
                        {
                            "ID": 7777,
                            "TITLE": "Q2 Vulnerability Roll-up",
                            "TYPE": "Scan",
                            "STATUS": {"STATE": "Finished"},
                        }
                    ]
                }
            }
        }
    }
    app, _ = _build_app(
        username="u",
        password="p",
        api_base="https://qualysapi.qualys.com",
        stub_responses={"/api/2.0/fo/report/": _StubResponse(200, raw)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/qualys/api/2.0/fo/report/?action=list",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["payload"] == raw
    _reset()


# ---------------------------------------------------------------------------
# XML fallback envelope
# ---------------------------------------------------------------------------


def test_hosts_returns_xml_envelope_when_upstream_returns_xml(monkeypatch):
    monkeypatch.setenv("QUALYS_USERNAME", "u")
    monkeypatch.setenv("QUALYS_PASSWORD", "p")
    monkeypatch.setenv("QUALYS_API_BASE", "https://qualysapi.qualys.com")
    xml_text = "<?xml version=\"1.0\"?><HOST_LIST_OUTPUT/>"
    app, _ = _build_app(
        username="u",
        password="p",
        api_base="https://qualysapi.qualys.com",
        stub_responses={
            "/api/2.0/fo/asset/host/": _StubResponse(
                200, None, text=xml_text, json_decodes=False
            )
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/qualys/api/2.0/fo/asset/host/?action=list",
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["payload"] == {"xml": xml_text}
    _reset()


# ---------------------------------------------------------------------------
# Upstream error paths
# ---------------------------------------------------------------------------


def test_hosts_returns_503_on_upstream_429(monkeypatch):
    monkeypatch.setenv("QUALYS_USERNAME", "u")
    monkeypatch.setenv("QUALYS_PASSWORD", "p")
    monkeypatch.setenv("QUALYS_API_BASE", "https://qualysapi.qualys.com")
    app, _ = _build_app(
        username="u",
        password="p",
        api_base="https://qualysapi.qualys.com",
        stub_responses={
            "/api/2.0/fo/asset/host/": _StubResponse(
                429, {"error": "rate limit"}, text="rate limit"
            )
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/qualys/api/2.0/fo/asset/host/?action=list",
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text
    detail = r.json()["detail"]
    assert "rate-limit" in detail.lower() or "429" in detail
    _reset()


def test_scans_returns_503_on_upstream_401(monkeypatch):
    monkeypatch.setenv("QUALYS_USERNAME", "bad")
    monkeypatch.setenv("QUALYS_PASSWORD", "bad")
    monkeypatch.setenv("QUALYS_API_BASE", "https://qualysapi.qualys.com")
    app, _ = _build_app(
        username="bad",
        password="bad",
        api_base="https://qualysapi.qualys.com",
        stub_responses={
            "/api/2.0/fo/scan/": _StubResponse(
                401, {"error": "unauthorized"}, text="unauthorized"
            )
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/qualys/api/2.0/fo/scan/?action=list", headers=HEADERS
    )
    assert r.status_code == 503, r.text
    detail = r.json()["detail"]
    assert "401" in detail or "credential" in detail.lower()
    _reset()


def test_scans_returns_503_on_upstream_409_concurrency(monkeypatch):
    monkeypatch.setenv("QUALYS_USERNAME", "u")
    monkeypatch.setenv("QUALYS_PASSWORD", "p")
    monkeypatch.setenv("QUALYS_API_BASE", "https://qualysapi.qualys.com")
    app, _ = _build_app(
        username="u",
        password="p",
        api_base="https://qualysapi.qualys.com",
        stub_responses={
            "/api/2.0/fo/scan/": _StubResponse(
                409, {"error": "concurrent"}, text="concurrent"
            )
        },
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/qualys/api/2.0/fo/scan/?action=list", headers=HEADERS
    )
    assert r.status_code == 503, r.text
    detail = r.json()["detail"]
    assert "409" in detail or "concurrency" in detail.lower()
    _reset()


def test_launch_scan_returns_422_on_missing_required_target(monkeypatch):
    monkeypatch.setenv("QUALYS_USERNAME", "u")
    monkeypatch.setenv("QUALYS_PASSWORD", "p")
    monkeypatch.setenv("QUALYS_API_BASE", "https://qualysapi.qualys.com")
    app, _ = _build_app(
        username="u",
        password="p",
        api_base="https://qualysapi.qualys.com",
        stub_responses={},
    )
    client = TestClient(app, raise_server_exceptions=True)

    # No ip / asset_groups / asset_group_ids -> engine raises ValueError -> 422
    r = client.post(
        "/api/v1/qualys/api/2.0/fo/scan/?action=launch",
        json={"scan_title": "no-target", "option_id": 1},
        headers=HEADERS,
    )
    assert r.status_code == 422, r.text
    _reset()


def test_action_param_must_be_list_for_get(monkeypatch):
    monkeypatch.setenv("QUALYS_USERNAME", "u")
    monkeypatch.setenv("QUALYS_PASSWORD", "p")
    monkeypatch.setenv("QUALYS_API_BASE", "https://qualysapi.qualys.com")
    app, _ = _build_app(
        username="u",
        password="p",
        api_base="https://qualysapi.qualys.com",
        stub_responses={},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/qualys/api/2.0/fo/scan/?action=launch", headers=HEADERS
    )
    assert r.status_code == 422, r.text
    _reset()


def test_launch_action_must_be_launch_for_post(monkeypatch):
    monkeypatch.setenv("QUALYS_USERNAME", "u")
    monkeypatch.setenv("QUALYS_PASSWORD", "p")
    monkeypatch.setenv("QUALYS_API_BASE", "https://qualysapi.qualys.com")
    app, _ = _build_app(
        username="u",
        password="p",
        api_base="https://qualysapi.qualys.com",
        stub_responses={},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/qualys/api/2.0/fo/scan/?action=list",
        json={"scan_title": "x", "ip": "1.1.1.1", "option_id": 1},
        headers=HEADERS,
    )
    assert r.status_code == 422, r.text
    _reset()
