"""Tests for the AWS WAFv2 router (NO MOCKS, real boto3 path).

Tests:
  1. Capability summary -> status="unavailable" when env unset.
  2. Capability summary -> status="ok" + region echo when env set.
  3. /web-acls returns 503 when env unset.
  4. /web-acls returns a real WAFv2 page via botocore Stubber when env set.
  5. /web-acls/{Scope}/{Id}/{Name} returns a Web ACL via Stubber.
  6. /rule-groups returns a Rule Groups page via Stubber.
  7. /ip-sets returns an IPSets page via Stubber.
  8. /managed-rule-groups returns a managed-rule-groups page via Stubber.
  9. POST /sampled-requests round-trip via Stubber.
 10. Invalid Scope on /web-acls returns 422.
 11. POST /sampled-requests with missing fields returns 400.

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
    """Build a minimal FastAPI app mounting the AWS WAF router."""
    from core import aws_waf_engine as eng_mod

    eng_mod.reset_aws_waf_engine()
    eng_mod.get_aws_waf_engine(
        access_key=access_key,
        secret_key=secret_key,
        region=region,
        client=stubbed_client,
        force_refresh=True,
    )

    from apps.api.aws_waf_router import router

    app = FastAPI()
    app.include_router(router)
    return app


def _reset() -> None:
    from core import aws_waf_engine as eng_mod
    eng_mod.reset_aws_waf_engine()


def _make_stubbed_wafv2():
    """Create a real boto3 wafv2 client wrapped in a Stubber."""
    real = boto3.client(
        "wafv2",
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

    r = client.get("/api/v1/aws-waf/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "AWS WAFv2"
    for ep in (
        "/web-acls",
        "/web-acls/{Scope}/{Id}/{Name}",
        "/rule-groups",
        "/ip-sets",
        "/regex-pattern-sets",
        "/sampled-requests",
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

    r = client.get("/api/v1/aws-waf/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["aws_access_key_present"] is True
    assert body["aws_region"] == "eu-west-1"
    assert body["status"] == "ok"
    _reset()


# ============================================================ 503 paths


def test_web_acls_returns_503_when_no_creds(monkeypatch):
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)
    app = _build_app(access_key="", secret_key="")
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/aws-waf/web-acls",
        headers=HEADERS,
        params={"Scope": "REGIONAL"},
    )
    assert r.status_code == 503, r.text
    assert "AWS_ACCESS_KEY_ID" in r.json()["detail"]
    _reset()


def test_invalid_scope_on_web_acls_returns_422(monkeypatch):
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)
    app = _build_app(access_key="", secret_key="")
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get(
        "/api/v1/aws-waf/web-acls",
        headers=HEADERS,
        params={"Scope": "GLOBAL"},
    )
    assert r.status_code == 422, r.text
    _reset()


# ============================================================ stubbed paths


def test_web_acls_returns_wafv2_page_via_stubber(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIATEST")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    real, stubber = _make_stubbed_wafv2()
    page = {
        "WebACLs": [
            {
                "Name": "prod-waf",
                "Id": "abc-123-def",
                "Description": "Production WAF",
                "LockToken": "tok-1",
                "ARN": (
                    "arn:aws:wafv2:us-east-1:123456789012:regional/"
                    "webacl/prod-waf/abc-123-def"
                ),
            },
            {
                "Name": "staging-waf",
                "Id": "ghi-456-jkl",
                "Description": "Staging WAF",
                "LockToken": "tok-2",
                "ARN": (
                    "arn:aws:wafv2:us-east-1:123456789012:regional/"
                    "webacl/staging-waf/ghi-456-jkl"
                ),
            },
        ],
        "NextMarker": "next-page-token",
    }
    stubber.add_response("list_web_acls", page, {"Scope": "REGIONAL"})
    stubber.activate()
    try:
        app = _build_app(
            access_key="AKIATEST",
            secret_key="secret",
            stubbed_client=real,
        )
        client = TestClient(app, raise_server_exceptions=True)

        r = client.get(
            "/api/v1/aws-waf/web-acls",
            headers=HEADERS,
            params={"Scope": "REGIONAL"},
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert len(body["WebACLs"]) == 2
        assert body["WebACLs"][0]["Name"] == "prod-waf"
        assert body["NextMarker"] == "next-page-token"
        stubber.assert_no_pending_responses()
    finally:
        stubber.deactivate()
        _reset()


def test_get_web_acl_via_stubber(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIATEST")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    real, stubber = _make_stubbed_wafv2()
    page = {
        "WebACL": {
            "Name": "prod-waf",
            "Id": "abc-123-def",
            "ARN": (
                "arn:aws:wafv2:us-east-1:123456789012:regional/"
                "webacl/prod-waf/abc-123-def"
            ),
            "DefaultAction": {"Allow": {}},
            "Description": "Prod WAF",
            "Rules": [
                {
                    "Name": "BlockSqli",
                    "Priority": 0,
                    "Statement": {
                        "SqliMatchStatement": {
                            "FieldToMatch": {"Body": {}},
                            "TextTransformations": [
                                {"Priority": 0, "Type": "NONE"}
                            ],
                        }
                    },
                    "Action": {"Block": {}},
                    "VisibilityConfig": {
                        "SampledRequestsEnabled": True,
                        "CloudWatchMetricsEnabled": True,
                        "MetricName": "BlockSqli",
                    },
                }
            ],
            "VisibilityConfig": {
                "SampledRequestsEnabled": True,
                "CloudWatchMetricsEnabled": True,
                "MetricName": "prod-waf",
            },
            "Capacity": 25,
            "ManagedByFirewallManager": False,
            "LabelNamespace": "awswaf:123456789012:webacl:prod-waf:",
        },
        "LockToken": "lock-token-xyz",
        "ApplicationIntegrationURL": (
            "https://wafintegration.amazonaws.com/?token=abc"
        ),
    }
    stubber.add_response(
        "get_web_acl",
        page,
        {"Scope": "REGIONAL", "Id": "abc-123-def", "Name": "prod-waf"},
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
            "/api/v1/aws-waf/web-acls/REGIONAL/abc-123-def/prod-waf",
            headers=HEADERS,
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["WebACL"]["Name"] == "prod-waf"
        assert body["WebACL"]["Capacity"] == 25
        assert body["WebACL"]["Rules"][0]["Name"] == "BlockSqli"
        assert body["LockToken"] == "lock-token-xyz"
        assert "ApplicationIntegrationURL" in body
        stubber.assert_no_pending_responses()
    finally:
        stubber.deactivate()
        _reset()


def test_rule_groups_via_stubber(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIATEST")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    real, stubber = _make_stubbed_wafv2()
    page = {
        "RuleGroups": [
            {
                "Name": "block-bad-bots",
                "Id": "rg-001",
                "Description": "Bot blocker",
                "LockToken": "rg-tok-1",
                "ARN": (
                    "arn:aws:wafv2:us-east-1:123456789012:regional/"
                    "rulegroup/block-bad-bots/rg-001"
                ),
            }
        ],
    }
    stubber.add_response("list_rule_groups", page, {"Scope": "REGIONAL"})
    stubber.activate()
    try:
        app = _build_app(
            access_key="AKIATEST",
            secret_key="secret",
            stubbed_client=real,
        )
        client = TestClient(app, raise_server_exceptions=True)

        r = client.get(
            "/api/v1/aws-waf/rule-groups",
            headers=HEADERS,
            params={"Scope": "REGIONAL"},
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert len(body["RuleGroups"]) == 1
        assert body["RuleGroups"][0]["Name"] == "block-bad-bots"
        assert "NextMarker" not in body
        stubber.assert_no_pending_responses()
    finally:
        stubber.deactivate()
        _reset()


def test_ip_sets_via_stubber(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIATEST")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    real, stubber = _make_stubbed_wafv2()
    page = {
        "IPSets": [
            {
                "Name": "blocked-ips",
                "Id": "ipset-001",
                "Description": "manually-blocked IPs",
                "LockToken": "ipset-tok-1",
                "ARN": (
                    "arn:aws:wafv2:us-east-1:123456789012:regional/"
                    "ipset/blocked-ips/ipset-001"
                ),
            }
        ],
    }
    stubber.add_response("list_ip_sets", page, {"Scope": "REGIONAL"})
    stubber.activate()
    try:
        app = _build_app(
            access_key="AKIATEST",
            secret_key="secret",
            stubbed_client=real,
        )
        client = TestClient(app, raise_server_exceptions=True)

        r = client.get(
            "/api/v1/aws-waf/ip-sets",
            headers=HEADERS,
            params={"Scope": "REGIONAL"},
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert len(body["IPSets"]) == 1
        assert body["IPSets"][0]["Name"] == "blocked-ips"
        stubber.assert_no_pending_responses()
    finally:
        stubber.deactivate()
        _reset()


def test_managed_rule_groups_via_stubber(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIATEST")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    real, stubber = _make_stubbed_wafv2()
    page = {
        "ManagedRuleGroups": [
            {
                "VendorName": "AWS",
                "Name": "AWSManagedRulesCommonRuleSet",
                "Description": "AWS Common Rule Set",
                "VersioningSupported": True,
            },
            {
                "VendorName": "AWS",
                "Name": "AWSManagedRulesSQLiRuleSet",
                "Description": "AWS SQLi rules",
                "VersioningSupported": True,
            },
        ],
        "NextMarker": "next-mrg",
    }
    stubber.add_response(
        "list_available_managed_rule_groups", page, {"Scope": "CLOUDFRONT"}
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
            "/api/v1/aws-waf/managed-rule-groups",
            headers=HEADERS,
            params={"Scope": "CLOUDFRONT"},
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert len(body["ManagedRuleGroups"]) == 2
        assert body["ManagedRuleGroups"][0]["VendorName"] == "AWS"
        assert body["NextMarker"] == "next-mrg"
        stubber.assert_no_pending_responses()
    finally:
        stubber.deactivate()
        _reset()


def test_sampled_requests_round_trip_via_stubber(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIATEST")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    real, stubber = _make_stubbed_wafv2()
    expected_params = {
        "WebAclArn": (
            "arn:aws:wafv2:us-east-1:123456789012:regional/"
            "webacl/prod-waf/abc-123-def"
        ),
        "RuleMetricName": "BlockSqli",
        "Scope": "REGIONAL",
        "TimeWindow": {
            "StartTime": "2026-05-04T00:00:00+00:00",
            "EndTime": "2026-05-04T01:00:00+00:00",
        },
        "MaxItems": 50,
    }
    page = {
        "SampledRequests": [
            {
                "Request": {
                    "ClientIP": "203.0.113.42",
                    "Country": "US",
                    "URI": "/login",
                    "Method": "POST",
                    "HTTPVersion": "HTTP/2.0",
                    "Headers": [
                        {"Name": "User-Agent", "Value": "curl/7.85"},
                    ],
                },
                "Weight": 1,
                "Timestamp": "2026-05-04T00:30:00+00:00",
                "Action": "BLOCK",
                "RuleNameWithinRuleGroup": "BlockSqli",
            }
        ],
        "PopulationSize": 1234,
        "TimeWindow": {
            "StartTime": "2026-05-04T00:00:00+00:00",
            "EndTime": "2026-05-04T01:00:00+00:00",
        },
    }
    stubber.add_response("get_sampled_requests", page, expected_params)
    stubber.activate()
    try:
        app = _build_app(
            access_key="AKIATEST",
            secret_key="secret",
            stubbed_client=real,
        )
        client = TestClient(app, raise_server_exceptions=True)

        body = {
            "WebAclArn": expected_params["WebAclArn"],
            "RuleMetricName": "BlockSqli",
            "Scope": "REGIONAL",
            "TimeWindow": {
                "StartTime": "2026-05-04T00:00:00+00:00",
                "EndTime": "2026-05-04T01:00:00+00:00",
            },
            "MaxItems": 50,
        }
        r = client.post(
            "/api/v1/aws-waf/sampled-requests", headers=HEADERS, json=body
        )
        assert r.status_code == 200, r.text
        out = r.json()
        assert out["PopulationSize"] == 1234
        assert len(out["SampledRequests"]) == 1
        assert out["SampledRequests"][0]["Action"] == "BLOCK"
        assert out["SampledRequests"][0]["Request"]["ClientIP"] == "203.0.113.42"
        stubber.assert_no_pending_responses()
    finally:
        stubber.deactivate()
        _reset()


def test_sampled_requests_missing_fields_returns_400(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIATEST")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    app = _build_app(access_key="AKIATEST", secret_key="secret")
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/aws-waf/sampled-requests",
        headers=HEADERS,
        json={"WebAclArn": "arn:aws:wafv2:..."},
    )
    assert r.status_code == 400, r.text
    _reset()
