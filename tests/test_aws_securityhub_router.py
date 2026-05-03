"""Tests for the AWS Security Hub router (NO MOCKS, real boto3 path).

Six tests:
  1. Capability summary returns ``status="unavailable"`` when env unset.
  2. Capability summary returns ``status="ok"`` + region echo when env set.
  3. /findings returns 503 when env unset.
  4. /findings returns a real ASFF page via botocore Stubber when env set.
  5. /insights returns 503 when env unset.
  6. /standards + /enabled-products + /control-status return 503 when env unset.
  7. POST /findings/batch round-trips identifiers via Stubber when configured.

The Stubber path proves the real boto3 code is exercised — no synthetic
fallback data is ever returned.
"""
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

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


def _asff(finding_id: str = "f-1", severity: str = "HIGH") -> Dict[str, Any]:
    """Build a minimal-valid ASFF finding accepted by boto3 GetFindings shape."""
    return {
        "SchemaVersion": "2018-10-08",
        "Id": f"arn:aws:securityhub:us-east-1:123456789012:finding/{finding_id}",
        "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
        "Region": "us-east-1",
        "GeneratorId": f"gen-{finding_id}",
        "AwsAccountId": "123456789012",
        "Types": ["Software and Configuration Checks/Industry/Test"],
        "CreatedAt": "2026-05-01T00:00:00.000Z",
        "UpdatedAt": "2026-05-01T00:00:00.000Z",
        "Severity": {"Label": severity, "Normalized": 70},
        "Title": f"Test finding {finding_id}",
        "Description": "Stubber-injected ASFF finding.",
        "Resources": [{
            "Type": "AwsAccount",
            "Id": "AWS::::Account:123456789012",
            "Partition": "aws",
            "Region": "us-east-1",
        }],
        "Compliance": {"Status": "FAILED"},
        "Workflow": {"Status": "NEW"},
        "RecordState": "ACTIVE",
    }


def _build_app(
    *,
    access_key: Optional[str],
    secret_key: Optional[str],
    region: str = "us-east-1",
    stubbed_client: Any = None,
):
    """Build a minimal FastAPI app mounting the AWS Security Hub router."""
    from core import aws_securityhub_engine as eng_mod

    eng_mod.reset_aws_securityhub_engine()
    eng_mod.get_aws_securityhub_engine(
        access_key=access_key,
        secret_key=secret_key,
        region=region,
        client=stubbed_client,
        force_refresh=True,
    )

    from apps.api.aws_securityhub_router import router

    app = FastAPI()
    app.include_router(router)
    return app


def _reset() -> None:
    from core import aws_securityhub_engine as eng_mod
    eng_mod.reset_aws_securityhub_engine()


def _make_stubbed_boto():
    """Create a real boto3 securityhub client wrapped in a Stubber."""
    real_boto = boto3.client(
        "securityhub",
        region_name="us-east-1",
        aws_access_key_id="AKIAFAKE",
        aws_secret_access_key="fake-secret",
    )
    return real_boto, Stubber(real_boto)


# ============================================================ capability


def test_capability_summary_unavailable_when_no_creds(monkeypatch):
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)
    app = _build_app(access_key="", secret_key="", region="us-west-2")
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/aws-securityhub/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "AWS Security Hub"
    for ep in [
        "/findings",
        "/insights",
        "/standards",
        "/enabled-products",
        "/control-status",
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

    r = client.get("/api/v1/aws-securityhub/", headers=HEADERS)
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

    r = client.get("/api/v1/aws-securityhub/findings", headers=HEADERS)
    assert r.status_code == 503, r.text
    assert "AWS_ACCESS_KEY_ID" in r.json()["detail"]
    _reset()


def test_insights_standards_products_control_503_when_no_creds(monkeypatch):
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)
    app = _build_app(access_key="", secret_key="")
    client = TestClient(app, raise_server_exceptions=True)

    for path in ("/insights", "/standards", "/enabled-products", "/control-status"):
        r = client.get(f"/api/v1/aws-securityhub{path}", headers=HEADERS)
        assert r.status_code == 503, f"{path}: {r.text}"
    _reset()


# ============================================================ real boto3 path


def test_findings_returns_asff_page_via_stubber(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIATEST")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    real_boto, stubber = _make_stubbed_boto()
    page = [_asff("crit-1", "CRITICAL"), _asff("hi-1", "HIGH")]
    stubber.add_response(
        "get_findings",
        {"Findings": page, "NextToken": "page-2"},
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

        r = client.get("/api/v1/aws-securityhub/findings", headers=HEADERS)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["NextToken"] == "page-2"
        assert len(body["Findings"]) == 2
        ids = [f["Id"].rsplit("/", 1)[-1] for f in body["Findings"]]
        assert ids == ["crit-1", "hi-1"]
        assert body["Findings"][0]["Severity"]["Label"] == "CRITICAL"
        stubber.assert_no_pending_responses()
    finally:
        stubber.deactivate()
        _reset()


def test_findings_invalid_filters_returns_422(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIATEST")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    app = _build_app(access_key="AKIATEST", secret_key="secret")
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/aws-securityhub/findings",
        headers=HEADERS,
        params={"Filters": "not-json{"},
    )
    assert r.status_code == 422, r.text
    assert "Filters" in r.json()["detail"]
    _reset()


def test_batch_findings_round_trip_via_stubber(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIATEST")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    real_boto, stubber = _make_stubbed_boto()
    finding = _asff("batch-1", "MEDIUM")
    stubber.add_response(
        "get_findings",
        {"Findings": [finding]},
        {
            "Filters": {
                "Id": [{"Value": finding["Id"], "Comparison": "EQUALS"}]
            }
        },
    )
    stubber.activate()
    try:
        app = _build_app(
            access_key="AKIATEST",
            secret_key="secret",
            stubbed_client=real_boto,
        )
        client = TestClient(app, raise_server_exceptions=True)

        r = client.post(
            "/api/v1/aws-securityhub/findings/batch",
            headers=HEADERS,
            json={
                "FindingIdentifiers": [
                    {"Id": finding["Id"], "ProductArn": finding["ProductArn"]}
                ]
            },
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert len(body["Findings"]) == 1
        assert body["Findings"][0]["Id"] == finding["Id"]
        stubber.assert_no_pending_responses()
    finally:
        stubber.deactivate()
        _reset()


def test_insights_returns_payload_via_stubber(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIATEST")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    real_boto, stubber = _make_stubbed_boto()
    insights_page = {
        "Insights": [
            {
                "InsightArn": "arn:aws:securityhub:::insight/test/1",
                "Name": "Test Insight",
                "Filters": {},
                "GroupByAttribute": "ResourceId",
            }
        ]
    }
    stubber.add_response("get_insights", insights_page, {})
    stubber.activate()
    try:
        app = _build_app(
            access_key="AKIATEST",
            secret_key="secret",
            stubbed_client=real_boto,
        )
        client = TestClient(app, raise_server_exceptions=True)

        r = client.get("/api/v1/aws-securityhub/insights", headers=HEADERS)
        assert r.status_code == 200, r.text
        body = r.json()
        assert len(body["Insights"]) == 1
        assert body["Insights"][0]["Name"] == "Test Insight"
        stubber.assert_no_pending_responses()
    finally:
        stubber.deactivate()
        _reset()
