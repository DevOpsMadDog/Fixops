"""Tests for the AWS S3 router (NO MOCKS, real boto3 path via Stubber).

Coverage:
  1.  Capability summary returns ``status="unavailable"`` when env unset.
  2.  Capability summary returns ``status="ok"`` + region echo when env set.
  3.  /buckets returns 503 when env unset.
  4.  /buckets returns a real ListBuckets response via botocore Stubber.
  5.  /buckets/{name}/policy returns 404 NoSuchBucketPolicy via Stubber.
  6.  /buckets/{name}/encryption returns 200 with SSE rules via Stubber.
  7.  /buckets/{name}/encryption returns 404 when SSE not configured.
  8.  /buckets/{name}/acl returns 200 with Owner+Grants via Stubber.
  9.  /buckets/{name}/public-access-block returns 200 (configured) and 404
      (unset) via Stubber.
  10. /buckets/{name}/versioning returns 200 with MFADelete via Stubber.
  11. /buckets/{name}/logging returns 200 with TargetBucket via Stubber.
  12. /buckets/{name}/lifecycle returns 200 with rules and 404 when unset.

The Stubber path proves the real boto3 code is exercised — no synthetic
fallback data is ever returned.
"""
from __future__ import annotations

import os
from typing import Any, Optional

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

# Mask any developer ~/.aws so unconfigured tests are deterministic.
os.environ["AWS_SHARED_CREDENTIALS_FILE"] = "/dev/null"
os.environ["AWS_CONFIG_FILE"] = "/dev/null"

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
    """Build a minimal FastAPI app mounting the AWS S3 router."""
    from core import aws_s3_engine as eng_mod

    eng_mod.reset_aws_s3_engine()
    eng_mod.get_aws_s3_engine(
        access_key=access_key,
        secret_key=secret_key,
        region=region,
        client=stubbed_client,
        force_refresh=True,
    )

    from apps.api.aws_s3_router import router

    app = FastAPI()
    app.include_router(router)
    return app


def _reset() -> None:
    from core import aws_s3_engine as eng_mod
    eng_mod.reset_aws_s3_engine()


def _make_stubbed_boto():
    """Create a real boto3 s3 client wrapped in a Stubber."""
    real_boto = boto3.client(
        "s3",
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

    r = client.get("/api/v1/aws-s3/")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "AWS S3"
    expected_eps = {
        "/buckets",
        "/buckets/{name}/policy",
        "/buckets/{name}/encryption",
        "/buckets/{name}/acl",
        "/buckets/{name}/public-access-block",
        "/buckets/{name}/versioning",
        "/buckets/{name}/logging",
        "/buckets/{name}/lifecycle",
    }
    for ep in expected_eps:
        assert ep in body["endpoints"], f"missing endpoint {ep}"
    assert body["aws_access_key_present"] is False
    assert body["aws_region"] == "us-west-2"
    assert body["status"] == "unavailable"
    _reset()


def test_capability_summary_ok_when_creds_present(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIATEST")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    app = _build_app(access_key="AKIATEST", secret_key="secret", region="eu-west-1")
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/aws-s3/")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["aws_access_key_present"] is True
    assert body["aws_region"] == "eu-west-1"
    assert body["status"] == "ok"
    _reset()


# ============================================================ 503 paths


def test_buckets_returns_503_when_no_creds(monkeypatch):
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)
    app = _build_app(access_key="", secret_key="")
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/aws-s3/buckets")
    assert r.status_code == 503, r.text
    assert "AWS_ACCESS_KEY_ID" in r.json()["detail"]
    _reset()


# ============================================================ ListBuckets


def test_list_buckets_via_stubber(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIATEST")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    real_boto, stubber = _make_stubbed_boto()
    stubber.add_response(
        "list_buckets",
        {
            "Buckets": [
                {"Name": "logs-prod", "CreationDate": "2024-01-01T00:00:00Z"},
                {"Name": "data-prod", "CreationDate": "2024-02-01T00:00:00Z"},
            ],
            "Owner": {"DisplayName": "ops", "ID": "abc123"},
        },
        {},
    )
    stubber.activate()
    try:
        app = _build_app(
            access_key="AKIATEST", secret_key="secret", stubbed_client=real_boto
        )
        client = TestClient(app, raise_server_exceptions=True)

        r = client.get("/api/v1/aws-s3/buckets")
        assert r.status_code == 200, r.text
        body = r.json()
        names = [b["Name"] for b in body["Buckets"]]
        assert names == ["logs-prod", "data-prod"]
        assert body["Owner"]["DisplayName"] == "ops"
        assert body["Owner"]["ID"] == "abc123"
        stubber.assert_no_pending_responses()
    finally:
        stubber.deactivate()
        _reset()


# ============================================================ bucket policy 404


def test_get_bucket_policy_404_via_stubber(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIATEST")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    real_boto, stubber = _make_stubbed_boto()
    stubber.add_client_error(
        "get_bucket_policy",
        service_error_code="NoSuchBucketPolicy",
        service_message="The bucket policy does not exist",
        http_status_code=404,
        expected_params={"Bucket": "logs-prod"},
    )
    stubber.activate()
    try:
        app = _build_app(
            access_key="AKIATEST", secret_key="secret", stubbed_client=real_boto
        )
        client = TestClient(app, raise_server_exceptions=True)

        r = client.get("/api/v1/aws-s3/buckets/logs-prod/policy")
        assert r.status_code == 404, r.text
        body = r.json()
        assert body["detail"]["code"] == "NoSuchBucketPolicy"
        assert "logs-prod" in body["detail"]["resource"]
        stubber.assert_no_pending_responses()
    finally:
        stubber.deactivate()
        _reset()


# ============================================================ encryption 200/404


def test_get_bucket_encryption_via_stubber(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIATEST")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    real_boto, stubber = _make_stubbed_boto()
    sse_payload = {
        "ServerSideEncryptionConfiguration": {
            "Rules": [
                {
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "aws:kms",
                        "KMSMasterKeyID": "arn:aws:kms:us-east-1:111:key/abc",
                    },
                    "BucketKeyEnabled": True,
                }
            ]
        }
    }
    stubber.add_response(
        "get_bucket_encryption", sse_payload, {"Bucket": "data-prod"}
    )
    stubber.activate()
    try:
        app = _build_app(
            access_key="AKIATEST", secret_key="secret", stubbed_client=real_boto
        )
        client = TestClient(app, raise_server_exceptions=True)

        r = client.get("/api/v1/aws-s3/buckets/data-prod/encryption")
        assert r.status_code == 200, r.text
        body = r.json()
        rule = body["ServerSideEncryptionConfiguration"]["Rules"][0]
        assert rule["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"] == "aws:kms"
        assert rule["BucketKeyEnabled"] is True
        stubber.assert_no_pending_responses()
    finally:
        stubber.deactivate()
        _reset()


def test_get_bucket_encryption_404_via_stubber(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIATEST")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    real_boto, stubber = _make_stubbed_boto()
    stubber.add_client_error(
        "get_bucket_encryption",
        service_error_code="ServerSideEncryptionConfigurationNotFoundError",
        service_message="The server side encryption configuration was not found",
        http_status_code=404,
        expected_params={"Bucket": "no-sse"},
    )
    stubber.activate()
    try:
        app = _build_app(
            access_key="AKIATEST", secret_key="secret", stubbed_client=real_boto
        )
        client = TestClient(app, raise_server_exceptions=True)

        r = client.get("/api/v1/aws-s3/buckets/no-sse/encryption")
        assert r.status_code == 404, r.text
        body = r.json()
        assert body["detail"]["code"] == "ServerSideEncryptionConfigurationNotFoundError"
        stubber.assert_no_pending_responses()
    finally:
        stubber.deactivate()
        _reset()


# ============================================================ acl


def test_get_bucket_acl_via_stubber(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIATEST")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    real_boto, stubber = _make_stubbed_boto()
    acl_payload = {
        "Owner": {"DisplayName": "ops", "ID": "abc123"},
        "Grants": [
            {
                "Grantee": {
                    "Type": "CanonicalUser",
                    "DisplayName": "ops",
                    "ID": "abc123",
                },
                "Permission": "FULL_CONTROL",
            }
        ],
    }
    stubber.add_response("get_bucket_acl", acl_payload, {"Bucket": "logs-prod"})
    stubber.activate()
    try:
        app = _build_app(
            access_key="AKIATEST", secret_key="secret", stubbed_client=real_boto
        )
        client = TestClient(app, raise_server_exceptions=True)

        r = client.get("/api/v1/aws-s3/buckets/logs-prod/acl")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["Owner"]["ID"] == "abc123"
        assert body["Grants"][0]["Permission"] == "FULL_CONTROL"
        assert body["Grants"][0]["Grantee"]["Type"] == "CanonicalUser"
        stubber.assert_no_pending_responses()
    finally:
        stubber.deactivate()
        _reset()


# ====================================================== public-access-block


def test_get_public_access_block_200_and_404(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIATEST")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")

    # 200 path
    real_boto, stubber = _make_stubbed_boto()
    pab = {
        "PublicAccessBlockConfiguration": {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        }
    }
    stubber.add_response(
        "get_public_access_block", pab, {"Bucket": "locked-down"}
    )
    stubber.add_client_error(
        "get_public_access_block",
        service_error_code="NoSuchPublicAccessBlockConfiguration",
        service_message="The public access block configuration was not found",
        http_status_code=404,
        expected_params={"Bucket": "wide-open"},
    )
    stubber.activate()
    try:
        app = _build_app(
            access_key="AKIATEST", secret_key="secret", stubbed_client=real_boto
        )
        client = TestClient(app, raise_server_exceptions=True)

        r = client.get("/api/v1/aws-s3/buckets/locked-down/public-access-block")
        assert r.status_code == 200, r.text
        cfg = r.json()["PublicAccessBlockConfiguration"]
        assert cfg["BlockPublicAcls"] is True
        assert cfg["RestrictPublicBuckets"] is True

        r2 = client.get("/api/v1/aws-s3/buckets/wide-open/public-access-block")
        assert r2.status_code == 404, r2.text
        assert (
            r2.json()["detail"]["code"]
            == "NoSuchPublicAccessBlockConfiguration"
        )
        stubber.assert_no_pending_responses()
    finally:
        stubber.deactivate()
        _reset()


# ============================================================ versioning


def test_get_bucket_versioning_via_stubber(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIATEST")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    real_boto, stubber = _make_stubbed_boto()
    stubber.add_response(
        "get_bucket_versioning",
        {"Status": "Enabled", "MFADelete": "Disabled"},
        {"Bucket": "data-prod"},
    )
    stubber.activate()
    try:
        app = _build_app(
            access_key="AKIATEST", secret_key="secret", stubbed_client=real_boto
        )
        client = TestClient(app, raise_server_exceptions=True)

        r = client.get("/api/v1/aws-s3/buckets/data-prod/versioning")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["Status"] == "Enabled"
        assert body["MFADelete"] == "Disabled"
        stubber.assert_no_pending_responses()
    finally:
        stubber.deactivate()
        _reset()


# ============================================================ logging


def test_get_bucket_logging_via_stubber(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIATEST")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    real_boto, stubber = _make_stubbed_boto()
    stubber.add_response(
        "get_bucket_logging",
        {
            "LoggingEnabled": {
                "TargetBucket": "audit-logs",
                "TargetPrefix": "data-prod/",
                "TargetGrants": [],
            }
        },
        {"Bucket": "data-prod"},
    )
    stubber.activate()
    try:
        app = _build_app(
            access_key="AKIATEST", secret_key="secret", stubbed_client=real_boto
        )
        client = TestClient(app, raise_server_exceptions=True)

        r = client.get("/api/v1/aws-s3/buckets/data-prod/logging")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["LoggingEnabled"]["TargetBucket"] == "audit-logs"
        assert body["LoggingEnabled"]["TargetPrefix"] == "data-prod/"
        stubber.assert_no_pending_responses()
    finally:
        stubber.deactivate()
        _reset()


# ============================================================ lifecycle 200/404


def test_get_bucket_lifecycle_200_and_404(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIATEST")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    real_boto, stubber = _make_stubbed_boto()
    rules_payload = {
        "Rules": [
            {
                "ID": "expire-old-logs",
                "Filter": {"Prefix": "logs/"},
                "Status": "Enabled",
                "Expiration": {"Days": 365, "ExpiredObjectDeleteMarker": False},
                "Transitions": [{"Days": 30, "StorageClass": "GLACIER"}],
            }
        ]
    }
    stubber.add_response(
        "get_bucket_lifecycle_configuration",
        rules_payload,
        {"Bucket": "data-prod"},
    )
    stubber.add_client_error(
        "get_bucket_lifecycle_configuration",
        service_error_code="NoSuchLifecycleConfiguration",
        service_message="The lifecycle configuration does not exist",
        http_status_code=404,
        expected_params={"Bucket": "no-lifecycle"},
    )
    stubber.activate()
    try:
        app = _build_app(
            access_key="AKIATEST", secret_key="secret", stubbed_client=real_boto
        )
        client = TestClient(app, raise_server_exceptions=True)

        r = client.get("/api/v1/aws-s3/buckets/data-prod/lifecycle")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["Rules"][0]["ID"] == "expire-old-logs"
        assert body["Rules"][0]["Status"] == "Enabled"
        assert body["Rules"][0]["Transitions"][0]["StorageClass"] == "GLACIER"

        r2 = client.get("/api/v1/aws-s3/buckets/no-lifecycle/lifecycle")
        assert r2.status_code == 404, r2.text
        assert r2.json()["detail"]["code"] == "NoSuchLifecycleConfiguration"
        stubber.assert_no_pending_responses()
    finally:
        stubber.deactivate()
        _reset()
