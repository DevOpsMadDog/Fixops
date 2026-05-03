"""Tests for the Amazon Inspector v2 router (NO MOCKS, real boto3 path).

Six tests:
  1. Capability summary returns ``status="unavailable"`` when env unset.
  2. Capability summary returns ``status="ok"`` + region echo when env set.
  3. /findings returns 503 when env unset.
  4. /findings returns a real findings page via botocore Stubber when env set.
  5. /coverage + /configuration + /usage return 503 when env unset.
  6. /findings/{arn} round-trips via Stubber when configured.
  7. /coverage + /configuration + /usage exercise real boto3 path via Stubber.
  8. Invalid filterCriteria JSON returns 422.

The Stubber path proves the real boto3 code is exercised — no synthetic
fallback data is ever returned.
"""
from __future__ import annotations

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
    """Build a minimal FastAPI app mounting the Amazon Inspector v2 router."""
    from core import amazon_inspector_engine as eng_mod

    eng_mod.reset_amazon_inspector_engine()
    eng_mod.get_amazon_inspector_engine(
        access_key=access_key,
        secret_key=secret_key,
        region=region,
        client=stubbed_client,
        force_refresh=True,
    )

    from apps.api.amazon_inspector_router import router

    app = FastAPI()
    app.include_router(router)
    return app


def _reset() -> None:
    from core import amazon_inspector_engine as eng_mod
    eng_mod.reset_amazon_inspector_engine()


def _make_stubbed_boto():
    """Create a real boto3 inspector2 client wrapped in a Stubber."""
    real_boto = boto3.client(
        "inspector2",
        region_name="us-east-1",
        aws_access_key_id="AKIAFAKE",
        aws_secret_access_key="fake-secret",
    )
    return real_boto, Stubber(real_boto)


def _finding(arn_id: str = "f-1", severity: str = "HIGH") -> dict:
    """Build a minimal Inspector2 finding accepted by ListFindings shape."""
    return {
        "awsAccountId": "123456789012",
        "findingArn": (
            f"arn:aws:inspector2:us-east-1:123456789012:finding/{arn_id}"
        ),
        "title": f"Test finding {arn_id}",
        "description": "Stubber-injected Inspector2 finding.",
        "type": "PACKAGE_VULNERABILITY",
        "severity": severity,
        "status": "ACTIVE",
        "fixAvailable": "YES",
        "inspectorScore": 7.5,
        "remediation": {
            "recommendation": {
                "text": "Upgrade openssl",
                "Url": "https://example.com/cve",
            }
        },
        "resources": [
            {
                "id": "i-1234567890abcdef0",
                "type": "AWS_EC2_INSTANCE",
                "partition": "aws",
                "region": "us-east-1",
            }
        ],
        "firstObservedAt": "2026-04-01T00:00:00Z",
        "lastObservedAt": "2026-05-01T00:00:00Z",
    }


# ============================================================ capability


def test_capability_summary_unavailable_when_no_creds(monkeypatch):
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)
    app = _build_app(access_key="", secret_key="", region="us-west-2")
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/amazon-inspector/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "Amazon Inspector v2"
    for ep in [
        "/findings",
        "/findings/{id}",
        "/coverage",
        "/configuration",
        "/usage",
    ]:
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

    r = client.get("/api/v1/amazon-inspector/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["aws_access_key_present"] is True
    assert body["aws_region"] == "eu-west-1"
    assert body["status"] == "ok"
    _reset()


# ============================================================ 503 paths


def test_findings_returns_503_when_no_creds(monkeypatch):
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)
    app = _build_app(access_key="", secret_key="")
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/amazon-inspector/findings", headers=HEADERS)
    assert r.status_code == 503, r.text
    assert "AWS_ACCESS_KEY_ID" in r.json()["detail"]
    _reset()


def test_coverage_configuration_usage_503_when_no_creds(monkeypatch):
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)
    app = _build_app(access_key="", secret_key="")
    client = TestClient(app, raise_server_exceptions=True)

    for path in ("/coverage", "/configuration", "/usage"):
        r = client.get(f"/api/v1/amazon-inspector{path}", headers=HEADERS)
        assert r.status_code == 503, f"{path}: {r.text}"
    _reset()


# ============================================================ real boto3 path


def test_findings_returns_page_via_stubber(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIATEST")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    real_boto, stubber = _make_stubbed_boto()
    page = [_finding("crit-1", "CRITICAL"), _finding("hi-1", "HIGH")]
    stubber.add_response(
        "list_findings",
        {"findings": page, "nextToken": "page-2"},
        {},
    )
    stubber.activate()
    try:
        app = _build_app(
            access_key="AKIATEST",
            secret_key="secret",
            stubbed_client=real_boto,
        )
        client = TestClient(app, raise_server_exceptions=True)

        r = client.get("/api/v1/amazon-inspector/findings", headers=HEADERS)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["nextToken"] == "page-2"
        assert len(body["findings"]) == 2
        ids = [f["findingArn"].rsplit("/", 1)[-1] for f in body["findings"]]
        assert ids == ["crit-1", "hi-1"]
        assert body["findings"][0]["severity"] == "CRITICAL"
        stubber.assert_no_pending_responses()
    finally:
        stubber.deactivate()
        _reset()


def test_findings_invalid_filter_returns_422(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIATEST")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    app = _build_app(access_key="AKIATEST", secret_key="secret")
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/amazon-inspector/findings",
        headers=HEADERS,
        params={"filterCriteria": "not-json{"},
    )
    assert r.status_code == 422, r.text
    assert "filterCriteria" in r.json()["detail"]
    _reset()


def test_get_finding_round_trip_via_stubber(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIATEST")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    real_boto, stubber = _make_stubbed_boto()
    arn = "arn:aws:inspector2:us-east-1:123456789012:finding/abc-123"
    detail = {
        "findingArn": arn,
        "cisaData": {
            "action": "Apply update",
            "dateAdded": "2026-04-01",
            "dateDue": "2026-05-01",
        },
        "epssScore": 0.42,
    }
    stubber.add_response(
        "batch_get_finding_details",
        {"findingDetails": [detail], "errors": []},
        {"findingArns": [arn]},
    )
    stubber.activate()
    try:
        app = _build_app(
            access_key="AKIATEST",
            secret_key="secret",
            stubbed_client=real_boto,
        )
        client = TestClient(app, raise_server_exceptions=True)

        r = client.get(
            f"/api/v1/amazon-inspector/findings/{arn}", headers=HEADERS
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["findingArn"] == arn
        assert len(body["findingDetails"]) == 1
        assert body["findingDetails"][0]["epssScore"] == 0.42
        assert body["errors"] == []
        stubber.assert_no_pending_responses()
    finally:
        stubber.deactivate()
        _reset()


def test_coverage_returns_payload_via_stubber(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIATEST")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    real_boto, stubber = _make_stubbed_boto()
    coverage_page = {
        "coveredResources": [
            {
                "accountId": "123456789012",
                "resourceId": "i-1234567890abcdef0",
                "resourceType": "AWS_EC2_INSTANCE",
                "scanType": "PACKAGE",
                "scanStatus": {
                    "statusCode": "ACTIVE",
                    "reason": "SUCCESSFUL",
                },
            }
        ],
        "nextToken": "cov-page-2",
    }
    stubber.add_response("list_coverage", coverage_page, {})
    stubber.activate()
    try:
        app = _build_app(
            access_key="AKIATEST",
            secret_key="secret",
            stubbed_client=real_boto,
        )
        client = TestClient(app, raise_server_exceptions=True)

        r = client.get("/api/v1/amazon-inspector/coverage", headers=HEADERS)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["nextToken"] == "cov-page-2"
        assert len(body["coveredResources"]) == 1
        assert body["coveredResources"][0]["resourceType"] == "AWS_EC2_INSTANCE"
        stubber.assert_no_pending_responses()
    finally:
        stubber.deactivate()
        _reset()


def test_configuration_returns_payload_via_stubber(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIATEST")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    real_boto, stubber = _make_stubbed_boto()
    cfg_resp = {
        "ec2Configuration": {
            "scanModeState": {
                "scanMode": "EC2_SSM_AGENT_BASED",
                "scanModeStatus": "SUCCESS",
            },
        },
        "ecrConfiguration": {
            "rescanDurationState": {
                "rescanDuration": "DAYS_30",
                "pullDateRescanDuration": "DAYS_14",
                "status": "SUCCESS",
                "updatedAt": "2026-05-01T00:00:00Z",
            },
        },
    }
    stubber.add_response("get_configuration", cfg_resp, {})
    stubber.activate()
    try:
        app = _build_app(
            access_key="AKIATEST",
            secret_key="secret",
            stubbed_client=real_boto,
        )
        client = TestClient(app, raise_server_exceptions=True)

        r = client.get("/api/v1/amazon-inspector/configuration", headers=HEADERS)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["ec2Configuration"]["scanModeState"]["scanMode"] == "EC2_SSM_AGENT_BASED"
        assert body["ecrConfiguration"]["rescanDurationState"]["rescanDuration"] == "DAYS_30"
        stubber.assert_no_pending_responses()
    finally:
        stubber.deactivate()
        _reset()


def test_usage_returns_payload_via_stubber(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIATEST")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    real_boto, stubber = _make_stubbed_boto()
    usage_resp = {
        "totals": [
            {
                "accountId": "123456789012",
                "usage": [
                    {
                        "type": "EC2_INSTANCE_HOURS",
                        "total": 720.0,
                        "currency": "USD",
                        "estimatedMonthlyCost": 18.5,
                    }
                ],
            }
        ],
        "nextToken": "usage-page-2",
    }
    stubber.add_response(
        "list_usage_totals",
        usage_resp,
        {"accountIds": ["123456789012"]},
    )
    stubber.activate()
    try:
        app = _build_app(
            access_key="AKIATEST",
            secret_key="secret",
            stubbed_client=real_boto,
        )
        client = TestClient(app, raise_server_exceptions=True)

        r = client.get(
            "/api/v1/amazon-inspector/usage",
            headers=HEADERS,
            params={"accountIds": "123456789012"},
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["nextToken"] == "usage-page-2"
        assert len(body["usageTotals"]) == 1
        usage = body["usageTotals"][0]["usage"][0]
        assert usage["type"] == "EC2_INSTANCE_HOURS"
        assert usage["total"] == 720.0
        stubber.assert_no_pending_responses()
    finally:
        stubber.deactivate()
        _reset()
