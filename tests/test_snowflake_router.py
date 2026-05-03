"""Tests for the Snowflake SQL API router (NO MOCKS, real httpx code path).

Each test installs a stub ``httpx.Client`` so the engine's REAL request
construction + JWT-bearer wiring + JSON parsing is exercised end-to-end —
only the network is intercepted.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

# Use the same API token wiring the rest of the test suite uses
from tests.conftest import API_TOKEN

HEADERS = {"X-API-Key": API_TOKEN}


# ---------------------------------------------------------------- RSA key

# Pre-generated 2048-bit RSA private key used only for these tests. JWT signing
# is exercised end-to-end so the engine code path is real.
@pytest.fixture(scope="module")
def rsa_private_pem() -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return pem.decode("utf-8")


# ---------------------------------------------------------------- httpx stub


class _StubResponse:
    def __init__(self, status_code: int, payload: Any, text: str = ""):
        self.status_code = status_code
        self._payload = payload
        self.text = text or json.dumps(payload)
        self.content = self.text.encode("utf-8") if self.text else b""

    def json(self) -> Any:
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload


class _StubClient:
    """Minimal httpx.Client substitute matching by URL substring + method."""

    def __init__(self, responses: Dict[str, _StubResponse]):
        # responses keyed by "<METHOD> <substring>", e.g. "POST /api/v2/statements"
        self._responses = responses
        self.calls: List[Dict[str, Any]] = []

    def _match(self, method: str, url: str) -> _StubResponse:
        for key, resp in self._responses.items():
            if not key.startswith(method + " "):
                continue
            if key.split(" ", 1)[1] in url:
                return resp
        # Some tests want a default JSON 200
        return _StubResponse(404, {"error": "not stubbed"}, text="not stubbed")

    def _record(self, method: str, url: str, **kw) -> None:
        self.calls.append({"method": method, "url": url, **kw})

    def get(self, url, headers=None, params=None):
        self._record("GET", url, headers=headers or {}, params=params or {})
        return self._match("GET", url)

    def post(self, url, headers=None, json=None, params=None):
        self._record("POST", url, headers=headers or {}, json=json, params=params or {})
        return self._match("POST", url)

    def request(self, method, url, headers=None, json=None, params=None):
        self._record(method, url, headers=headers or {}, json=json, params=params or {})
        return self._match(method, url)

    def close(self) -> None:
        pass


# ---------------------------------------------------------------- builders


def _build_app(
    *,
    account: Optional[str],
    user: Optional[str],
    private_key_pem: Optional[str],
    stub_responses: Optional[Dict[str, _StubResponse]] = None,
):
    from core import snowflake_engine as eng_mod

    eng_mod.reset_snowflake_engine()
    stub = _StubClient(stub_responses or {})
    eng_mod.get_snowflake_engine(
        account=account,
        user=user,
        private_key_pem=private_key_pem,
        client=stub,
        force_refresh=True,
    )

    from apps.api.snowflake_router import router

    app = FastAPI()
    app.include_router(router)
    return app, stub


def _reset() -> None:
    from core import snowflake_engine as eng_mod
    eng_mod.reset_snowflake_engine()


# ============================================================ capability


def test_capability_summary_unavailable_when_no_creds(monkeypatch):
    monkeypatch.delenv("SNOWFLAKE_ACCOUNT", raising=False)
    monkeypatch.delenv("SNOWFLAKE_USER", raising=False)
    monkeypatch.delenv("SNOWFLAKE_PRIVATE_KEY", raising=False)
    app, _ = _build_app(account="", user="", private_key_pem="")
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/snowflake/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "Snowflake SQL API"
    for ep in [
        "/api/v2/statements",
        "/api/v2/databases",
        "/api/v2/users",
        "/api/v2/warehouses",
        "/api/v2/roles",
    ]:
        assert ep in body["endpoints"], f"missing endpoint {ep}"
    assert body["snowflake_account_present"] is False
    assert body["snowflake_user_present"] is False
    assert body["snowflake_private_key_present"] is False
    assert body["status"] == "unavailable"
    _reset()


def test_capability_summary_ok_when_creds_present(monkeypatch, rsa_private_pem):
    monkeypatch.setenv("SNOWFLAKE_ACCOUNT", "ab12345.us-east-1")
    monkeypatch.setenv("SNOWFLAKE_USER", "ALDECI_SVC")
    monkeypatch.setenv("SNOWFLAKE_PRIVATE_KEY", rsa_private_pem)
    app, _ = _build_app(
        account="ab12345.us-east-1",
        user="ALDECI_SVC",
        private_key_pem=rsa_private_pem,
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/snowflake/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["snowflake_account_present"] is True
    assert body["snowflake_user_present"] is True
    assert body["snowflake_private_key_present"] is True
    assert body["status"] == "ok"
    _reset()


# ============================================================ 503 paths


def test_statements_post_returns_503_when_no_creds(monkeypatch):
    monkeypatch.delenv("SNOWFLAKE_ACCOUNT", raising=False)
    monkeypatch.delenv("SNOWFLAKE_USER", raising=False)
    monkeypatch.delenv("SNOWFLAKE_PRIVATE_KEY", raising=False)
    app, _ = _build_app(account="", user="", private_key_pem="")
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/snowflake/api/v2/statements",
        headers=HEADERS,
        json={"statement": "SELECT 1"},
    )
    assert r.status_code == 503, r.text
    assert r.json()["detail"]["error"] == "snowflake_unavailable"
    _reset()


def test_show_endpoints_return_503_when_no_creds(monkeypatch):
    monkeypatch.delenv("SNOWFLAKE_ACCOUNT", raising=False)
    monkeypatch.delenv("SNOWFLAKE_USER", raising=False)
    monkeypatch.delenv("SNOWFLAKE_PRIVATE_KEY", raising=False)
    app, _ = _build_app(account="", user="", private_key_pem="")
    client = TestClient(app, raise_server_exceptions=True)

    for path in (
        "/api/v2/databases",
        "/api/v2/users",
        "/api/v2/warehouses",
        "/api/v2/roles",
        "/api/v2/databases/MYDB/schemas",
        "/api/v2/statements/abc-123",
    ):
        r = client.get(f"/api/v1/snowflake{path}", headers=HEADERS)
        assert r.status_code == 503, f"{path}: {r.text}"

    r = client.delete("/api/v1/snowflake/api/v2/statements/abc-123", headers=HEADERS)
    assert r.status_code == 503, r.text
    _reset()


# ============================================================ statements


def test_submit_statement_round_trip_via_stub(rsa_private_pem, monkeypatch):
    monkeypatch.setenv("SNOWFLAKE_ACCOUNT", "ab12345.us-east-1")
    monkeypatch.setenv("SNOWFLAKE_USER", "ALDECI_SVC")
    monkeypatch.setenv("SNOWFLAKE_PRIVATE_KEY", rsa_private_pem)

    upstream = {
        "statementHandle": "01ab-1234-5678",
        "code": "090001",
        "sqlState": "00000",
        "message": "Statement executed successfully.",
        "statementStatusUrl": "/api/v2/statements/01ab-1234-5678",
        "resultSetMetaData": {
            "numRows": 1,
            "format": "json",
            "partitionInfo": [{"rowCount": 1, "uncompressedSize": 16}],
            "rowType": [
                {"name": "ID", "type": "FIXED", "scale": 0, "precision": 38, "nullable": False},
                {"name": "NAME", "type": "TEXT", "scale": None, "precision": None, "nullable": True},
            ],
        },
        "data": [["42", "ALDECI"]],
    }
    app, stub = _build_app(
        account="ab12345.us-east-1",
        user="ALDECI_SVC",
        private_key_pem=rsa_private_pem,
        stub_responses={"POST /api/v2/statements": _StubResponse(200, upstream)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/snowflake/api/v2/statements",
        headers=HEADERS,
        json={
            "statement": "SELECT id, name FROM users LIMIT 1",
            "warehouse": "ANALYTICS_WH",
            "role": "READER",
            "database": "PROD",
            "schema": "PUBLIC",
            "parameters": {"BINARY_OUTPUT_FORMAT": "BASE64"},
            "timeout": 30,
            "resultSetMetaData": {"format": "jsonv2"},
            "asyncExec": False,
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["statementHandle"] == "01ab-1234-5678"
    assert body["sqlState"] == "00000"
    assert body["resultSetMetaData"]["numRows"] == 1
    assert body["resultSetMetaData"]["format"] == "json"
    assert len(body["resultSetMetaData"]["rowType"]) == 2
    assert body["resultSetMetaData"]["rowType"][0]["name"] == "ID"
    assert body["data"] == [["42", "ALDECI"]]

    # Verify upstream call shape: bearer JWT + body coercion
    assert stub.calls, "expected at least one upstream call"
    sent = stub.calls[0]
    assert sent["method"] == "POST"
    assert sent["url"].startswith("https://ab12345.us-east-1.snowflakecomputing.com")
    assert sent["url"].endswith("/api/v2/statements")
    auth = sent["headers"].get("Authorization", "")
    assert auth.startswith("Bearer "), f"expected JWT bearer, got {auth!r}"
    assert sent["headers"].get("X-Snowflake-Authorization-Token-Type") == "KEYPAIR_JWT"
    body_sent = sent["json"]
    assert body_sent["statement"] == "SELECT id, name FROM users LIMIT 1"
    assert body_sent["warehouse"] == "ANALYTICS_WH"
    assert body_sent["role"] == "READER"
    assert body_sent["database"] == "PROD"
    assert body_sent["schema"] == "PUBLIC"
    assert body_sent["parameters"] == {"BINARY_OUTPUT_FORMAT": "BASE64"}
    assert body_sent["timeout"] == 30
    assert body_sent["resultSetMetaData"] == {"format": "jsonv2"}
    _reset()


def test_get_statement_with_partition(rsa_private_pem, monkeypatch):
    monkeypatch.setenv("SNOWFLAKE_ACCOUNT", "ab12345.us-east-1")
    monkeypatch.setenv("SNOWFLAKE_USER", "ALDECI_SVC")
    monkeypatch.setenv("SNOWFLAKE_PRIVATE_KEY", rsa_private_pem)
    upstream = {
        "statementHandle": "abc-handle",
        "code": "090001",
        "sqlState": "00000",
        "message": "ok",
        "resultSetMetaData": {
            "numRows": 0,
            "format": "json",
            "partitionInfo": [],
            "rowType": [],
        },
        "data": [],
    }
    app, stub = _build_app(
        account="ab12345.us-east-1",
        user="ALDECI_SVC",
        private_key_pem=rsa_private_pem,
        stub_responses={"GET /api/v2/statements/abc-handle": _StubResponse(200, upstream)},
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/snowflake/api/v2/statements/abc-handle",
        headers=HEADERS,
        params={"partition": 2},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["statementHandle"] == "abc-handle"
    assert stub.calls
    assert stub.calls[0]["params"].get("partition") == 2
    _reset()


def test_cancel_statement_returns_204(rsa_private_pem, monkeypatch):
    monkeypatch.setenv("SNOWFLAKE_ACCOUNT", "ab12345.us-east-1")
    monkeypatch.setenv("SNOWFLAKE_USER", "ALDECI_SVC")
    monkeypatch.setenv("SNOWFLAKE_PRIVATE_KEY", rsa_private_pem)
    app, stub = _build_app(
        account="ab12345.us-east-1",
        user="ALDECI_SVC",
        private_key_pem=rsa_private_pem,
        stub_responses={
            "POST /api/v2/statements/abc-handle/cancel": _StubResponse(200, {}, text=""),
        },
    )
    client = TestClient(app, raise_server_exceptions=True)
    r = client.delete("/api/v1/snowflake/api/v2/statements/abc-handle", headers=HEADERS)
    assert r.status_code == 204, r.text
    assert stub.calls
    cancel_call = stub.calls[-1]
    assert cancel_call["method"] in ("POST", "DELETE")
    assert "/api/v2/statements/abc-handle/cancel" in cancel_call["url"]
    _reset()


# ============================================================ SHOW wrappers


def _show_databases_payload() -> Dict[str, Any]:
    return {
        "statementHandle": "h1",
        "code": "090001",
        "sqlState": "00000",
        "message": "ok",
        "resultSetMetaData": {
            "numRows": 2,
            "format": "json",
            "partitionInfo": [],
            "rowType": [
                {"name": "created_on", "type": "TIMESTAMP_LTZ", "scale": 0, "precision": 0, "nullable": True},
                {"name": "name", "type": "TEXT", "scale": None, "precision": None, "nullable": False},
                {"name": "kind", "type": "TEXT", "scale": None, "precision": None, "nullable": True},
                {"name": "retention_time", "type": "FIXED", "scale": 0, "precision": 38, "nullable": True},
                {"name": "comment", "type": "TEXT", "scale": None, "precision": None, "nullable": True},
                {"name": "owner", "type": "TEXT", "scale": None, "precision": None, "nullable": True},
                {"name": "options", "type": "TEXT", "scale": None, "precision": None, "nullable": True},
            ],
        },
        "data": [
            ["2026-01-01 00:00:00", "PROD", "STANDARD", "1", "Production DB", "SYSADMIN", ""],
            ["2026-01-02 00:00:00", "STAGING", "TRANSIENT", "0", "Staging DB", "SYSADMIN", ""],
        ],
    }


def test_list_databases_via_stub(rsa_private_pem, monkeypatch):
    monkeypatch.setenv("SNOWFLAKE_ACCOUNT", "ab12345.us-east-1")
    monkeypatch.setenv("SNOWFLAKE_USER", "ALDECI_SVC")
    monkeypatch.setenv("SNOWFLAKE_PRIVATE_KEY", rsa_private_pem)
    app, stub = _build_app(
        account="ab12345.us-east-1",
        user="ALDECI_SVC",
        private_key_pem=rsa_private_pem,
        stub_responses={"POST /api/v2/statements": _StubResponse(200, _show_databases_payload())},
    )
    client = TestClient(app, raise_server_exceptions=True)
    r = client.get("/api/v1/snowflake/api/v2/databases", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert "databases" in body
    assert len(body["databases"]) == 2
    names = {d["name"] for d in body["databases"]}
    assert names == {"PROD", "STAGING"}
    kinds = {d["kind"] for d in body["databases"]}
    assert "STANDARD" in kinds and "TRANSIENT" in kinds
    # Confirm upstream got SHOW DATABASES
    assert stub.calls
    assert "SHOW DATABASES" in stub.calls[0]["json"]["statement"]
    _reset()


def test_list_schemas_uses_db_name(rsa_private_pem, monkeypatch):
    monkeypatch.setenv("SNOWFLAKE_ACCOUNT", "ab12345.us-east-1")
    monkeypatch.setenv("SNOWFLAKE_USER", "ALDECI_SVC")
    monkeypatch.setenv("SNOWFLAKE_PRIVATE_KEY", rsa_private_pem)
    upstream = {
        "statementHandle": "h2",
        "code": "090001",
        "sqlState": "00000",
        "message": "ok",
        "resultSetMetaData": {
            "numRows": 1,
            "format": "json",
            "partitionInfo": [],
            "rowType": [
                {"name": "created_on", "type": "TIMESTAMP_LTZ", "scale": 0, "precision": 0, "nullable": True},
                {"name": "name", "type": "TEXT", "scale": None, "precision": None, "nullable": False},
                {"name": "database_name", "type": "TEXT", "scale": None, "precision": None, "nullable": True},
                {"name": "owner", "type": "TEXT", "scale": None, "precision": None, "nullable": True},
                {"name": "retention_time", "type": "FIXED", "scale": 0, "precision": 38, "nullable": True},
                {"name": "options", "type": "TEXT", "scale": None, "precision": None, "nullable": True},
                {"name": "comment", "type": "TEXT", "scale": None, "precision": None, "nullable": True},
            ],
        },
        "data": [
            ["2026-01-01 00:00:00", "PUBLIC", "MYDB", "SYSADMIN", "1", "", ""],
        ],
    }
    app, stub = _build_app(
        account="ab12345.us-east-1",
        user="ALDECI_SVC",
        private_key_pem=rsa_private_pem,
        stub_responses={"POST /api/v2/statements": _StubResponse(200, upstream)},
    )
    client = TestClient(app, raise_server_exceptions=True)
    r = client.get("/api/v1/snowflake/api/v2/databases/MYDB/schemas", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["schemas"][0]["name"] == "PUBLIC"
    assert body["schemas"][0]["database_name"] == "MYDB"
    assert "SHOW SCHEMAS IN DATABASE" in stub.calls[0]["json"]["statement"]
    assert "MYDB" in stub.calls[0]["json"]["statement"]
    _reset()


def test_list_warehouses_and_roles(rsa_private_pem, monkeypatch):
    monkeypatch.setenv("SNOWFLAKE_ACCOUNT", "ab12345.us-east-1")
    monkeypatch.setenv("SNOWFLAKE_USER", "ALDECI_SVC")
    monkeypatch.setenv("SNOWFLAKE_PRIVATE_KEY", rsa_private_pem)
    wh = {
        "statementHandle": "h3",
        "code": "090001",
        "sqlState": "00000",
        "message": "ok",
        "resultSetMetaData": {
            "numRows": 1,
            "format": "json",
            "partitionInfo": [],
            "rowType": [
                {"name": "name", "type": "TEXT", "scale": None, "precision": None, "nullable": False},
                {"name": "state", "type": "TEXT", "scale": None, "precision": None, "nullable": True},
                {"name": "type", "type": "TEXT", "scale": None, "precision": None, "nullable": True},
                {"name": "size", "type": "TEXT", "scale": None, "precision": None, "nullable": True},
                {"name": "min_cluster_count", "type": "FIXED", "scale": 0, "precision": 38, "nullable": True},
                {"name": "max_cluster_count", "type": "FIXED", "scale": 0, "precision": 38, "nullable": True},
                {"name": "scaling_policy", "type": "TEXT", "scale": None, "precision": None, "nullable": True},
                {"name": "auto_resume", "type": "TEXT", "scale": None, "precision": None, "nullable": True},
                {"name": "auto_suspend", "type": "FIXED", "scale": 0, "precision": 38, "nullable": True},
                {"name": "is_default", "type": "TEXT", "scale": None, "precision": None, "nullable": True},
                {"name": "is_current", "type": "TEXT", "scale": None, "precision": None, "nullable": True},
            ],
        },
        "data": [
            ["ANALYTICS_WH", "STARTED", "STANDARD", "X-SMALL", "1", "1", "STANDARD", "true", "300", "false", "true"],
        ],
    }
    app, stub = _build_app(
        account="ab12345.us-east-1",
        user="ALDECI_SVC",
        private_key_pem=rsa_private_pem,
        stub_responses={"POST /api/v2/statements": _StubResponse(200, wh)},
    )
    client = TestClient(app, raise_server_exceptions=True)
    r = client.get("/api/v1/snowflake/api/v2/warehouses", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["warehouses"][0]["name"] == "ANALYTICS_WH"
    assert body["warehouses"][0]["state"] == "STARTED"
    assert body["warehouses"][0]["size"] == "X-SMALL"
    assert body["warehouses"][0]["auto_resume"] is True
    assert body["warehouses"][0]["auto_suspend"] == 300
    assert body["warehouses"][0]["scaling_policy"] == "STANDARD"
    assert "SHOW WAREHOUSES" in stub.calls[0]["json"]["statement"]
    _reset()


def test_list_users(rsa_private_pem, monkeypatch):
    monkeypatch.setenv("SNOWFLAKE_ACCOUNT", "ab12345.us-east-1")
    monkeypatch.setenv("SNOWFLAKE_USER", "ALDECI_SVC")
    monkeypatch.setenv("SNOWFLAKE_PRIVATE_KEY", rsa_private_pem)
    upstream = {
        "statementHandle": "h4",
        "code": "090001",
        "sqlState": "00000",
        "message": "ok",
        "resultSetMetaData": {
            "numRows": 1,
            "format": "json",
            "partitionInfo": [],
            "rowType": [
                {"name": "name", "type": "TEXT", "scale": None, "precision": None, "nullable": False},
                {"name": "default_role", "type": "TEXT", "scale": None, "precision": None, "nullable": True},
                {"name": "default_warehouse", "type": "TEXT", "scale": None, "precision": None, "nullable": True},
                {"name": "default_namespace", "type": "TEXT", "scale": None, "precision": None, "nullable": True},
                {"name": "login_name", "type": "TEXT", "scale": None, "precision": None, "nullable": True},
                {"name": "display_name", "type": "TEXT", "scale": None, "precision": None, "nullable": True},
                {"name": "email", "type": "TEXT", "scale": None, "precision": None, "nullable": True},
                {"name": "type", "type": "TEXT", "scale": None, "precision": None, "nullable": True},
                {"name": "disabled", "type": "TEXT", "scale": None, "precision": None, "nullable": True},
                {"name": "must_change_password", "type": "TEXT", "scale": None, "precision": None, "nullable": True},
                {"name": "snowflake_lock", "type": "TEXT", "scale": None, "precision": None, "nullable": True},
                {"name": "password_last_set_time", "type": "TIMESTAMP_LTZ", "scale": 0, "precision": 0, "nullable": True},
                {"name": "expires_at_time", "type": "TIMESTAMP_LTZ", "scale": 0, "precision": 0, "nullable": True},
                {"name": "created_on", "type": "TIMESTAMP_LTZ", "scale": 0, "precision": 0, "nullable": True},
                {"name": "last_success_login", "type": "TIMESTAMP_LTZ", "scale": 0, "precision": 0, "nullable": True},
                {"name": "locked_until_time", "type": "TIMESTAMP_LTZ", "scale": 0, "precision": 0, "nullable": True},
            ],
        },
        "data": [
            [
                "ALICE",
                "ANALYST",
                "ANALYTICS_WH",
                "PROD.PUBLIC",
                "alice@example.com",
                "Alice Anderson",
                "alice@example.com",
                "PERSON",
                "false",
                "false",
                "false",
                "2026-01-01 00:00:00",
                None,
                "2026-01-01 00:00:00",
                "2026-05-01 00:00:00",
                None,
            ],
        ],
    }
    app, _ = _build_app(
        account="ab12345.us-east-1",
        user="ALDECI_SVC",
        private_key_pem=rsa_private_pem,
        stub_responses={"POST /api/v2/statements": _StubResponse(200, upstream)},
    )
    client = TestClient(app, raise_server_exceptions=True)
    r = client.get("/api/v1/snowflake/api/v2/users", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["users"][0]["name"] == "ALICE"
    assert body["users"][0]["email"] == "alice@example.com"
    assert body["users"][0]["disabled"] is False
    assert body["users"][0]["default_role"] == "ANALYST"
    _reset()


def test_list_roles(rsa_private_pem, monkeypatch):
    monkeypatch.setenv("SNOWFLAKE_ACCOUNT", "ab12345.us-east-1")
    monkeypatch.setenv("SNOWFLAKE_USER", "ALDECI_SVC")
    monkeypatch.setenv("SNOWFLAKE_PRIVATE_KEY", rsa_private_pem)
    upstream = {
        "statementHandle": "h5",
        "code": "090001",
        "sqlState": "00000",
        "message": "ok",
        "resultSetMetaData": {
            "numRows": 2,
            "format": "json",
            "partitionInfo": [],
            "rowType": [
                {"name": "created_on", "type": "TIMESTAMP_LTZ", "scale": 0, "precision": 0, "nullable": True},
                {"name": "name", "type": "TEXT", "scale": None, "precision": None, "nullable": False},
                {"name": "is_default", "type": "TEXT", "scale": None, "precision": None, "nullable": True},
                {"name": "is_current", "type": "TEXT", "scale": None, "precision": None, "nullable": True},
                {"name": "is_inherited", "type": "TEXT", "scale": None, "precision": None, "nullable": True},
                {"name": "assigned_to_users", "type": "FIXED", "scale": 0, "precision": 38, "nullable": True},
                {"name": "granted_to_roles", "type": "FIXED", "scale": 0, "precision": 38, "nullable": True},
                {"name": "granted_to_users", "type": "FIXED", "scale": 0, "precision": 38, "nullable": True},
                {"name": "granted_roles", "type": "FIXED", "scale": 0, "precision": 38, "nullable": True},
                {"name": "owner", "type": "TEXT", "scale": None, "precision": None, "nullable": True},
                {"name": "comment", "type": "TEXT", "scale": None, "precision": None, "nullable": True},
            ],
        },
        "data": [
            ["2026-01-01 00:00:00", "SYSADMIN", "false", "false", "false", "1", "1", "1", "5", "ACCOUNTADMIN", "Sys"],
            ["2026-01-01 00:00:00", "ANALYST", "false", "true", "true", "3", "0", "3", "0", "SECURITYADMIN", "Read"],
        ],
    }
    app, _ = _build_app(
        account="ab12345.us-east-1",
        user="ALDECI_SVC",
        private_key_pem=rsa_private_pem,
        stub_responses={"POST /api/v2/statements": _StubResponse(200, upstream)},
    )
    client = TestClient(app, raise_server_exceptions=True)
    r = client.get("/api/v1/snowflake/api/v2/roles", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert {role["name"] for role in body["roles"]} == {"SYSADMIN", "ANALYST"}
    analyst = next(r for r in body["roles"] if r["name"] == "ANALYST")
    assert analyst["is_current"] is True
    assert analyst["granted_to_users"] == 3
    _reset()


# ============================================================ upstream errors


def test_statement_upstream_400_passes_through(rsa_private_pem, monkeypatch):
    monkeypatch.setenv("SNOWFLAKE_ACCOUNT", "ab12345.us-east-1")
    monkeypatch.setenv("SNOWFLAKE_USER", "ALDECI_SVC")
    monkeypatch.setenv("SNOWFLAKE_PRIVATE_KEY", rsa_private_pem)
    upstream_err = {
        "code": "002003",
        "sqlState": "42S02",
        "message": "Object 'NOSUCHTABLE' does not exist or not authorized.",
    }
    app, _ = _build_app(
        account="ab12345.us-east-1",
        user="ALDECI_SVC",
        private_key_pem=rsa_private_pem,
        stub_responses={"POST /api/v2/statements": _StubResponse(400, upstream_err)},
    )
    client = TestClient(app, raise_server_exceptions=True)
    r = client.post(
        "/api/v1/snowflake/api/v2/statements",
        headers=HEADERS,
        json={"statement": "SELECT * FROM NOSUCHTABLE"},
    )
    assert r.status_code == 400, r.text
    detail = r.json()["detail"]
    assert detail["error"] == "snowflake_upstream_error"
    assert detail["upstream_status"] == 400
    assert detail["payload"]["sqlState"] == "42S02"
    _reset()
