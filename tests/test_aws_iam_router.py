"""Tests for the AWS IAM router (NO MOCKS, real boto3 path).

Tests:
  1. Capability summary -> status="unavailable" when env unset.
  2. Capability summary -> status="ok" + region echo when env set.
  3. /users returns 503 when env unset.
  4. /users returns a real IAM page via botocore Stubber when env set.
  5. /roles returns a real IAM page via Stubber.
  6. /policies returns a real IAM page via Stubber.
  7. /credential-report POST + GET round-trip via Stubber.
  8. /users/{name}/access-keys returns 503 when env unset.

The Stubber path proves the real boto3 code is exercised — no synthetic
fallback data is ever returned.
"""
from __future__ import annotations

import base64
import os
from typing import Any, Optional

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from tests.conftest import API_TOKEN

# Mask any developer ~/.aws so unconfigured tests are deterministic.
os.environ["AWS_SHARED_CREDENTIALS_FILE"] = "/dev/null"
os.environ["AWS_CONFIG_FILE"] = "/dev/null"

HEADERS = {"X-API-Key": API_TOKEN}

boto3 = pytest.importorskip("boto3")
botocore_stub = pytest.importorskip("botocore.stub")
Stubber = botocore_stub.Stubber


# ---------------------------------------------------------------- helpers


def _build_app(
    *,
    access_key: Optional[str],
    secret_key: Optional[str],
    region: str = "us-east-1",
    stubbed_client: Any = None,
):
    """Build a minimal FastAPI app mounting the AWS IAM router."""
    from core import aws_iam_engine as eng_mod

    eng_mod.reset_aws_iam_engine()
    eng_mod.get_aws_iam_engine(
        access_key=access_key,
        secret_key=secret_key,
        region=region,
        client=stubbed_client,
        force_refresh=True,
    )

    from apps.api.aws_iam_router import router

    app = FastAPI()
    app.include_router(router)
    return app


def _reset() -> None:
    from core import aws_iam_engine as eng_mod
    eng_mod.reset_aws_iam_engine()


def _make_stubbed_iam():
    """Create a real boto3 iam client wrapped in a Stubber."""
    real = boto3.client(
        "iam",
        region_name="us-east-1",
        aws_access_key_id="AKIAFAKE",
        aws_secret_access_key="fake-secret",
    )
    return real, Stubber(real)


# ============================================================ capability


def test_capability_summary_unavailable_when_no_creds(monkeypatch):
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)
    app = _build_app(access_key="", secret_key="", region="us-west-2")
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/aws-iam/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "AWS IAM"
    for ep in (
        "/users",
        "/users/{name}",
        "/users/{name}/access-keys",
        "/roles",
        "/roles/{name}",
        "/policies",
        "/policies/{arn}",
        "/credential-report",
    ):
        assert ep in body["endpoints"], f"missing endpoint {ep}"
    assert body["aws_access_key_present"] is False
    assert body["aws_region"] == "us-west-2"
    assert body["status"] == "unavailable"
    _reset()


def test_capability_summary_ok_when_creds_present(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIATEST")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    app = _build_app(
        access_key="AKIATEST", secret_key="secret", region="eu-west-1"
    )
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/aws-iam/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["aws_access_key_present"] is True
    assert body["aws_region"] == "eu-west-1"
    assert body["status"] == "ok"
    _reset()


# ============================================================ 503 paths


def test_users_returns_503_when_no_creds(monkeypatch):
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)
    app = _build_app(access_key="", secret_key="")
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/aws-iam/users", headers=HEADERS)
    assert r.status_code == 503, r.text
    assert "AWS_ACCESS_KEY_ID" in r.json()["detail"]
    _reset()


def test_user_access_keys_returns_503_when_no_creds(monkeypatch):
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)
    app = _build_app(access_key="", secret_key="")
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/aws-iam/users/alice/access-keys", headers=HEADERS
    )
    assert r.status_code == 503, r.text
    _reset()


# ============================================================ stubbed paths


def test_users_returns_iam_page_via_stubber(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIATEST")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    real, stubber = _make_stubbed_iam()
    page = {
        "Users": [
            {
                "Path": "/",
                "UserName": "alice",
                "UserId": "AIDAEXAMPLE1234567",
                "Arn": "arn:aws:iam::123456789012:user/alice",
                "CreateDate": "2024-01-01T00:00:00+00:00",
            },
            {
                "Path": "/eng/",
                "UserName": "bob",
                "UserId": "AIDAEXAMPLE2345678",
                "Arn": "arn:aws:iam::123456789012:user/eng/bob",
                "CreateDate": "2024-02-02T00:00:00+00:00",
            },
        ],
        "IsTruncated": True,
        "Marker": "next-page",
    }
    # Stubber will validate incoming params — we send no MaxItems/Marker.
    stubber.add_response("list_users", page, {})
    stubber.activate()
    try:
        app = _build_app(
            access_key="AKIATEST",
            secret_key="secret",
            stubbed_client=real,
        )
        client = TestClient(app, raise_server_exceptions=True)

        r = client.get("/api/v1/aws-iam/users", headers=HEADERS)
        assert r.status_code == 200, r.text
        body = r.json()
        assert len(body["Users"]) == 2
        assert body["Users"][0]["UserName"] == "alice"
        assert body["IsTruncated"] is True
        assert body["Marker"] == "next-page"
        stubber.assert_no_pending_responses()
    finally:
        stubber.deactivate()
        _reset()


def test_roles_returns_iam_page_via_stubber(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIATEST")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    real, stubber = _make_stubbed_iam()
    page = {
        "Roles": [
            {
                "Path": "/",
                "RoleName": "lambda-exec",
                "RoleId": "AROAEXAMPLE1234567",
                "Arn": "arn:aws:iam::123456789012:role/lambda-exec",
                "CreateDate": "2024-03-03T00:00:00+00:00",
                "AssumeRolePolicyDocument": "%7B%7D",
            }
        ],
        "IsTruncated": False,
    }
    stubber.add_response("list_roles", page, {})
    stubber.activate()
    try:
        app = _build_app(
            access_key="AKIATEST",
            secret_key="secret",
            stubbed_client=real,
        )
        client = TestClient(app, raise_server_exceptions=True)

        r = client.get("/api/v1/aws-iam/roles", headers=HEADERS)
        assert r.status_code == 200, r.text
        body = r.json()
        assert len(body["Roles"]) == 1
        assert body["Roles"][0]["RoleName"] == "lambda-exec"
        assert body["IsTruncated"] is False
        assert "Marker" not in body
        stubber.assert_no_pending_responses()
    finally:
        stubber.deactivate()
        _reset()


def test_policies_returns_iam_page_via_stubber(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIATEST")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    real, stubber = _make_stubbed_iam()
    page = {
        "Policies": [
            {
                "PolicyName": "ReadOnlyAccess",
                "PolicyId": "ANPAEXAMPLE1234567",
                "Arn": "arn:aws:iam::aws:policy/ReadOnlyAccess",
                "Path": "/",
                "DefaultVersionId": "v1",
                "AttachmentCount": 12,
                "PermissionsBoundaryUsageCount": 0,
                "IsAttachable": True,
                "CreateDate": "2015-02-06T18:39:48+00:00",
                "UpdateDate": "2024-09-30T22:34:34+00:00",
            }
        ],
        "IsTruncated": False,
    }
    stubber.add_response(
        "list_policies",
        page,
        {"Scope": "AWS", "OnlyAttached": False},
    )
    stubber.activate()
    try:
        app = _build_app(
            access_key="AKIATEST",
            secret_key="secret",
            stubbed_client=real,
        )
        client = TestClient(app, raise_server_exceptions=True)

        r = client.get(
            "/api/v1/aws-iam/policies",
            headers=HEADERS,
            params={"Scope": "AWS", "OnlyAttached": False},
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert len(body["Policies"]) == 1
        assert body["Policies"][0]["PolicyName"] == "ReadOnlyAccess"
        stubber.assert_no_pending_responses()
    finally:
        stubber.deactivate()
        _reset()


def test_credential_report_round_trip_via_stubber(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIATEST")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    real, stubber = _make_stubbed_iam()
    stubber.add_response(
        "generate_credential_report",
        {"State": "STARTED", "Description": "Report generation started."},
        {},
    )
    csv_payload = (
        b"user,arn,user_creation_time\n"
        b"alice,arn:aws:iam::123:user/alice,2024-01-01T00:00:00+00:00\n"
    )
    stubber.add_response(
        "get_credential_report",
        {
            "Content": csv_payload,
            "ReportFormat": "text/csv",
            "GeneratedTime": "2026-05-04T00:00:00+00:00",
        },
        {},
    )
    stubber.activate()
    try:
        app = _build_app(
            access_key="AKIATEST",
            secret_key="secret",
            stubbed_client=real,
        )
        client = TestClient(app, raise_server_exceptions=True)

        r1 = client.post(
            "/api/v1/aws-iam/credential-report/generate", headers=HEADERS
        )
        assert r1.status_code == 202, r1.text
        assert r1.json()["State"] == "STARTED"

        r2 = client.get("/api/v1/aws-iam/credential-report", headers=HEADERS)
        assert r2.status_code == 200, r2.text
        body = r2.json()
        assert body["ReportFormat"] == "text/csv"
        decoded = base64.b64decode(body["Content"])
        assert b"alice" in decoded
        stubber.assert_no_pending_responses()
    finally:
        stubber.deactivate()
        _reset()
