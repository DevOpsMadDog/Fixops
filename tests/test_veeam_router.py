"""Tests for veeam_router — ALDECI.

Spins up a minimal FastAPI app with the Veeam router mounted. Each test gets
an isolated httpx stub client and resets the engine singleton so state doesn't
bleed between tests.

NO MOCKS rule:
  * GET /, GET /api/v1/{backupSessions, jobs, backups, restorePoints,
    managedServers}, POST /api/oauth2/token return HTTP 503 when creds are
    unset.
  * Capability summary reports ``status="unavailable"`` when creds are missing.
  * Happy paths inject a stub httpx.Client (not a hardcoded engine payload)
    so we still exercise the real auth + parsing code paths.
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
    def __init__(self, status_code: int, payload: Any, text: str = ""):
        self.status_code = status_code
        self._payload = payload
        self.text = text or (json.dumps(payload) if payload is not None else "")

    def json(self) -> Any:
        if self._payload is None:
            raise ValueError("no json body")
        return self._payload


class _StubClient:
    """Records calls and returns a queued response per URL suffix."""

    def __init__(self, responses: Dict[str, Any]):
        self._responses = responses
        self.calls: List[Dict[str, Any]] = []

    def _resolve(self, url: str) -> _StubResponse:
        # Longest-suffix match wins so /api/v1/jobs/jb-1/start beats /api/v1/jobs.
        best: Optional[_StubResponse] = None
        best_len = -1
        for path, resp in self._responses.items():
            if path in url and len(path) > best_len:
                best = resp
                best_len = len(path)
        if best is None:
            return _StubResponse(404, {"error": "not found"}, text="not found")
        return best

    def get(self, url: str, headers: Optional[Dict[str, str]] = None):
        self.calls.append(
            {"method": "GET", "url": url, "headers": dict(headers or {})}
        )
        return self._resolve(url)

    def post(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        content: Optional[bytes] = None,
    ):
        self.calls.append(
            {
                "method": "POST",
                "url": url,
                "headers": dict(headers or {}),
                "content": content,
            }
        )
        return self._resolve(url)

    def put(self, *args, **kwargs):  # not used today
        return self.post(*args, **kwargs)

    def close(self) -> None:
        pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_app(
    *,
    creds: Optional[Dict[str, str]],
    stub_responses: Dict[str, Any],
):
    """Construct an isolated app+engine."""
    from core import veeam_engine as engine_mod

    engine_mod.reset_veeam_engine()

    stub_client = _StubClient(stub_responses)
    if creds is None:
        engine_mod.get_veeam_engine(client=stub_client)
    else:
        engine_mod.get_veeam_engine(
            base_url=creds.get("base_url"),
            username=creds.get("username"),
            password=creds.get("password"),
            client=stub_client,
        )

    from apps.api.veeam_router import router

    app = FastAPI()
    app.include_router(router)
    return app, stub_client


def _reset():
    from core import veeam_engine as engine_mod

    engine_mod.reset_veeam_engine()


@pytest.fixture(autouse=True)
def _wipe_env(monkeypatch):
    """Ensure env-var creds don't leak in from the host."""
    for var in ("VEEAM_BASE_URL", "VEEAM_USERNAME", "VEEAM_PASSWORD"):
        monkeypatch.delenv(var, raising=False)
    _reset()
    yield
    _reset()


_OK_CREDS = {
    "base_url": "https://veeam.example.com:9398",
    "username": "veeam-admin",
    "password": "veeam-pa55w0rd!",
}

_TOKEN_PATH = "/api/oauth2/token"
_TOKEN_RESP_OK = _StubResponse(
    200,
    {
        "access_token": "tok-abc-123",
        "refresh_token": "ref-abc-123",
        "expires_in": 900,
        "token_type": "Bearer",
    },
)


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


def test_capability_summary_unavailable_when_no_creds():
    app, _ = _build_app(creds=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/veeam/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "Veeam Backup Enterprise Manager"
    assert body["endpoints"] == [
        "/api/oauth2/token",
        "/api/v1/backupSessions",
        "/api/v1/jobs",
        "/api/v1/backups",
        "/api/v1/restorePoints",
        "/api/v1/managedServers",
    ]
    assert body["veeam_base_url_present"] is False
    assert body["veeam_username_present"] is False
    assert body["veeam_password_present"] is False
    assert body["status"] == "unavailable"


def test_capability_summary_ok_when_creds_present():
    app, _ = _build_app(creds=_OK_CREDS, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/veeam/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["veeam_base_url_present"] is True
    assert body["veeam_username_present"] is True
    assert body["veeam_password_present"] is True
    assert body["status"] == "ok"


# ---------------------------------------------------------------------------
# 503 paths when creds missing
# ---------------------------------------------------------------------------


def test_backup_sessions_503_when_creds_missing():
    app, _ = _build_app(creds=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)
    r = client.get("/api/v1/veeam/api/v1/backupSessions", headers=HEADERS)
    assert r.status_code == 503, r.text
    assert "VEEAM" in r.json()["detail"]


def test_jobs_503_when_creds_missing():
    app, _ = _build_app(creds=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)
    r = client.get("/api/v1/veeam/api/v1/jobs", headers=HEADERS)
    assert r.status_code == 503, r.text


def test_managed_servers_503_when_creds_missing():
    app, _ = _build_app(creds=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)
    r = client.get("/api/v1/veeam/api/v1/managedServers", headers=HEADERS)
    assert r.status_code == 503, r.text


def test_oauth_token_503_when_creds_missing():
    app, _ = _build_app(creds=None, stub_responses={})
    client = TestClient(app, raise_server_exceptions=True)
    # No engine creds, no explicit username/password in form -> 503
    r = client.post(
        "/api/v1/veeam/api/oauth2/token",
        data={"grant_type": "password"},
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text


# ---------------------------------------------------------------------------
# Validation 422
# ---------------------------------------------------------------------------


def test_oauth_token_unsupported_grant_type_422():
    app, _ = _build_app(creds=_OK_CREDS, stub_responses={})
    client = TestClient(app, raise_server_exceptions=False)
    r = client.post(
        "/api/v1/veeam/api/oauth2/token",
        data={"grant_type": "client_credentials"},
        headers=HEADERS,
    )
    assert r.status_code == 422, r.text


def test_restore_points_missing_backup_uid_422():
    app, _ = _build_app(creds=_OK_CREDS, stub_responses={})
    client = TestClient(app, raise_server_exceptions=False)
    r = client.get("/api/v1/veeam/api/v1/restorePoints", headers=HEADERS)
    # FastAPI rejects with 422 due to missing required BackupUid query param
    assert r.status_code == 422, r.text


# ---------------------------------------------------------------------------
# Happy paths — stubbed httpx client
# ---------------------------------------------------------------------------


def test_oauth_token_password_grant_happy_path():
    app, stub = _build_app(
        creds=_OK_CREDS,
        stub_responses={_TOKEN_PATH: _TOKEN_RESP_OK},
    )
    client = TestClient(app, raise_server_exceptions=True)
    r = client.post(
        "/api/v1/veeam/api/oauth2/token",
        data={"grant_type": "password"},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["access_token"] == "tok-abc-123"
    assert body["refresh_token"] == "ref-abc-123"
    assert body["expires_in"] == 900
    assert body["token_type"] == "Bearer"
    # Verify the form-encoded body went out with grant_type=password.
    assert len(stub.calls) == 1
    sent = stub.calls[0]
    assert sent["method"] == "POST"
    assert _TOKEN_PATH in sent["url"]
    assert b"grant_type=password" in (sent["content"] or b"")
    assert b"username=veeam-admin" in (sent["content"] or b"")


def test_backup_sessions_happy_path_normalizes():
    raw = {
        "Sessions": [
            {
                "Id": "ses-1",
                "Name": "Daily-VM-Backup",
                "JobName": "Daily-VM-Backup",
                "JobUid": "job-uid-1",
                "JobType": "Backup",
                "JobObjectName": "vm-prod-01",
                "BackupRepositoryUid": "repo-1",
                "CreationTimeUTC": "2026-05-04T01:00:00Z",
                "EndTimeUTC": "2026-05-04T01:23:45Z",
                "State": "Stopped",
                "Result": "Success",
                "Reason": "",
                "Progress": 100,
                "BackedUpSize": 12345678,
                "ProcessingRate": 50000000,
                "RestoredSize": 0,
                "ProcessedObjects": 12,
                "TotalObjects": 12,
            },
            {
                "Id": "ses-2",
                "Name": "Daily-DB-Backup",
                "JobName": "Daily-DB-Backup",
                "JobUid": "job-uid-2",
                "JobType": "Backup",
                "JobObjectName": "vm-db-01",
                "BackupRepositoryUid": "repo-1",
                "CreationTimeUTC": "2026-05-04T02:00:00Z",
                "EndTimeUTC": "",
                "State": "Working",
                "Result": "None",
                "Reason": "",
                "Progress": 47,
                "BackedUpSize": 4500000,
                "ProcessingRate": 60000000,
                "RestoredSize": 0,
                "ProcessedObjects": 3,
                "TotalObjects": 7,
            },
        ],
        "Total": 2,
        "Skip": 0,
        "Take": 100,
    }
    app, stub = _build_app(
        creds=_OK_CREDS,
        stub_responses={
            _TOKEN_PATH: _TOKEN_RESP_OK,
            "/api/v1/backupSessions": _StubResponse(200, raw),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)
    r = client.get(
        "/api/v1/veeam/api/v1/backupSessions",
        params={"Skip": 0, "Take": 100},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    wrap = body["SessionListResponse"]
    assert wrap["Total"] == 2
    assert len(wrap["Sessions"]) == 2
    assert wrap["Sessions"][0]["Id"] == "ses-1"
    assert wrap["Sessions"][0]["State"] == "Stopped"
    assert wrap["Sessions"][0]["Result"] == "Success"
    assert wrap["Sessions"][0]["Progress"] == 100
    assert wrap["Sessions"][1]["State"] == "Working"
    assert wrap["Sessions"][1]["Progress"] == 47

    # Confirm bearer auth was applied to the data call.
    bearer_calls = [
        c for c in stub.calls if c["headers"].get("Authorization", "").startswith("Bearer ")
    ]
    assert len(bearer_calls) >= 1
    assert bearer_calls[0]["headers"]["Authorization"] == "Bearer tok-abc-123"


def test_jobs_happy_path_normalizes():
    raw = {
        "Jobs": [
            {
                "Id": "job-1",
                "Name": "Daily-VM-Backup",
                "Description": "Daily VM backup at 01:00 UTC",
                "JobType": "Backup",
                "ScheduleEnabled": True,
                "ScheduleSettings": {
                    "StartDate": "2026-05-04T01:00:00Z",
                    "RunPeriodically": "Daily",
                    "RetryCount": 3,
                    "RetryTimeout": 600,
                    "BackupWindow": "01:00-04:00",
                },
                "NextRun": "2026-05-05T01:00:00Z",
                "LastRun": "2026-05-04T01:00:00Z",
                "ProcessedObjects": 12,
                "TotalObjects": 12,
                "BackedUpSize": 12345678,
                "EndTimeUTC": "2026-05-04T01:23:45Z",
                "State": "Stopped",
                "Result": "Success",
                "Reason": "",
                "RepositoryName": "Repo-Prod",
                "RepositoryUid": "repo-1",
            }
        ]
    }
    app, _ = _build_app(
        creds=_OK_CREDS,
        stub_responses={
            _TOKEN_PATH: _TOKEN_RESP_OK,
            "/api/v1/jobs": _StubResponse(200, raw),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)
    r = client.get("/api/v1/veeam/api/v1/jobs", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    jobs = body["JobListResponse"]["Jobs"]
    assert len(jobs) == 1
    assert jobs[0]["Id"] == "job-1"
    assert jobs[0]["ScheduleEnabled"] is True
    assert jobs[0]["ScheduleSettings"]["RetryCount"] == 3
    assert jobs[0]["State"] == "Stopped"
    assert jobs[0]["Result"] == "Success"


def test_start_job_returns_202_with_task():
    raw = {"Task": {"Id": "task-1", "State": "Running"}}
    app, _ = _build_app(
        creds=_OK_CREDS,
        stub_responses={
            _TOKEN_PATH: _TOKEN_RESP_OK,
            "/api/v1/jobs/job-1/start": _StubResponse(202, raw),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)
    r = client.post("/api/v1/veeam/api/v1/jobs/job-1/start", headers=HEADERS)
    assert r.status_code == 202, r.text
    body = r.json()
    assert body["Task"]["Id"] == "task-1"
    assert body["Task"]["State"] == "Running"


def test_backups_happy_path_normalizes():
    raw = {
        "Backups": [
            {
                "Id": "bk-1",
                "Name": "Daily-VM-Backup",
                "JobUid": "job-uid-1",
                "JobName": "Daily-VM-Backup",
                "JobType": "Backup",
                "CreationTimeUTC": "2026-05-04T01:00:00Z",
                "BackupSize": 12345678,
                "DataSize": 9876543,
                "BackupTypes": ["Full", "Incremental"],
                "JobObjectName": "vm-prod-01",
                "RestorePoints": 7,
                "OldestRestorePoint": "2026-04-28T01:00:00Z",
                "MostRecentRestorePoint": "2026-05-04T01:00:00Z",
                "RepositoryName": "Repo-Prod",
                "RepositoryUid": "repo-1",
            }
        ]
    }
    app, _ = _build_app(
        creds=_OK_CREDS,
        stub_responses={
            _TOKEN_PATH: _TOKEN_RESP_OK,
            "/api/v1/backups": _StubResponse(200, raw),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)
    r = client.get("/api/v1/veeam/api/v1/backups", headers=HEADERS)
    assert r.status_code == 200, r.text
    backups = r.json()["BackupListResponse"]["Backups"]
    assert len(backups) == 1
    assert backups[0]["Id"] == "bk-1"
    assert backups[0]["BackupTypes"] == ["Full", "Incremental"]
    assert backups[0]["RestorePoints"] == 7
    assert backups[0]["BackupSize"] == 12345678


def test_restore_points_happy_path_normalizes():
    raw = {
        "RestorePoints": [
            {
                "Id": "rp-1",
                "Name": "vm-prod-01@2026-05-04T01:00",
                "BackupUid": "bk-1",
                "BackupName": "Daily-VM-Backup",
                "JobObjectName": "vm-prod-01",
                "BackupType": "Incremental",
                "CreationTimeUTC": "2026-05-04T01:00:00Z",
                "FilesCount": 14523,
                "BackupSize": 234567,
                "RetentionTimestamp": "2026-06-04T01:00:00Z",
                "BackupChainUid": "chain-1",
                "IsCorrupted": False,
                "IsConsistent": True,
            }
        ]
    }
    app, _ = _build_app(
        creds=_OK_CREDS,
        stub_responses={
            _TOKEN_PATH: _TOKEN_RESP_OK,
            "/api/v1/restorePoints": _StubResponse(200, raw),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)
    r = client.get(
        "/api/v1/veeam/api/v1/restorePoints",
        params={"BackupUid": "bk-1"},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    rps = r.json()["RestorePointListResponse"]["RestorePoints"]
    assert len(rps) == 1
    assert rps[0]["Id"] == "rp-1"
    assert rps[0]["IsCorrupted"] is False
    assert rps[0]["IsConsistent"] is True
    assert rps[0]["FilesCount"] == 14523


def test_managed_servers_happy_path_normalizes():
    raw = {
        "ManagedServers": [
            {
                "Id": "srv-1",
                "Name": "veeam-prod-01",
                "Description": "Production Veeam Backup Server",
                "Type": "VBRServer",
                "Version": "12.1.0.2131",
                "Status": "Online",
                "Port": 9392,
            }
        ]
    }
    app, _ = _build_app(
        creds=_OK_CREDS,
        stub_responses={
            _TOKEN_PATH: _TOKEN_RESP_OK,
            "/api/v1/managedServers": _StubResponse(200, raw),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)
    r = client.get("/api/v1/veeam/api/v1/managedServers", headers=HEADERS)
    assert r.status_code == 200, r.text
    srvs = r.json()["ManagedServerListResponse"]["ManagedServers"]
    assert len(srvs) == 1
    assert srvs[0]["Id"] == "srv-1"
    assert srvs[0]["Status"] == "Online"
    assert srvs[0]["Port"] == 9392


def test_token_refresh_on_401():
    """First data call gets 401 -> engine refreshes token -> retry succeeds."""
    raw_jobs = {"Jobs": [{"Id": "job-1", "Name": "J", "JobType": "Backup"}]}
    # We need different responses on first vs second hit to /api/v1/jobs.
    # Build a tiny call counter via a custom client.
    sessions_responses: List[_StubResponse] = [
        _StubResponse(401, None, text="unauthorized"),
        _StubResponse(200, raw_jobs),
    ]

    class _RefreshClient(_StubClient):
        def get(self, url, headers=None):
            self.calls.append({"method": "GET", "url": url, "headers": dict(headers or {})})
            if "/api/v1/jobs" in url and sessions_responses:
                return sessions_responses.pop(0)
            return self._resolve(url)

    from core import veeam_engine as engine_mod
    engine_mod.reset_veeam_engine()
    stub = _RefreshClient({_TOKEN_PATH: _TOKEN_RESP_OK})
    engine_mod.get_veeam_engine(
        base_url=_OK_CREDS["base_url"],
        username=_OK_CREDS["username"],
        password=_OK_CREDS["password"],
        client=stub,
    )
    from apps.api.veeam_router import router
    app = FastAPI()
    app.include_router(router)
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/veeam/api/v1/jobs", headers=HEADERS)
    assert r.status_code == 200, r.text
    # Token endpoint must have been hit twice (initial + refresh after 401).
    token_calls = [c for c in stub.calls if _TOKEN_PATH in c["url"]]
    assert len(token_calls) == 2
    engine_mod.reset_veeam_engine()


def test_get_single_job_happy_path():
    raw = {
        "Id": "job-1",
        "Name": "Daily-VM-Backup",
        "JobType": "Backup",
        "ScheduleEnabled": True,
        "State": "Stopped",
        "Result": "Success",
    }
    app, _ = _build_app(
        creds=_OK_CREDS,
        stub_responses={
            _TOKEN_PATH: _TOKEN_RESP_OK,
            "/api/v1/jobs/job-1": _StubResponse(200, raw),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)
    r = client.get("/api/v1/veeam/api/v1/jobs/job-1", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["Id"] == "job-1"
    assert body["Result"] == "Success"
