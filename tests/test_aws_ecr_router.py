"""Tests for the AWS ECR router (NO MOCKS, real boto3 path via Stubber).

Coverage:
  1.  Capability summary returns ``status="unavailable"`` when env unset.
  2.  Capability summary returns ``status="ok"`` + region echo when env set.
  3.  /repositories returns 503 when env unset.
  4.  /repositories returns a real DescribeRepositories response via Stubber.
  5.  /repositories/{name}/images returns ListImages via Stubber.
  6.  POST /repositories/{name}/images/batch-describe returns DescribeImages
      via Stubber.
  7.  /repositories/{name}/images/{image_id}/scan-findings returns full
      Inspector enhanced findings via Stubber (sha256 digest path).
  8.  /repositories/{name}/scan-findings 404 on ScanNotFoundException
      (image-tag path).
  9.  /repositories/{name}/lifecycle-policy 200 + 404 on
      LifecyclePolicyNotFoundException.
  10. /repositories/{name}/policy 200 + 404 on RepositoryPolicyNotFoundException.
  11. /registry-scanning-config returns ENHANCED + continuous-scan rules.

Stubber path proves the real boto3 code is exercised.
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
    """Build a minimal FastAPI app mounting the AWS ECR router."""
    from core import aws_ecr_engine as eng_mod

    eng_mod.reset_aws_ecr_engine()
    eng_mod.get_aws_ecr_engine(
        access_key=access_key,
        secret_key=secret_key,
        region=region,
        client=stubbed_client,
        force_refresh=True,
    )

    from apps.api.aws_ecr_router import router

    app = FastAPI()
    app.include_router(router)
    return app


def _reset() -> None:
    from core import aws_ecr_engine as eng_mod
    eng_mod.reset_aws_ecr_engine()


def _make_stubbed_boto():
    """Create a real boto3 ecr client wrapped in a Stubber."""
    real_boto = boto3.client(
        "ecr",
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

    r = client.get("/api/v1/aws-ecr/")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "AWS ECR"
    expected_eps = {
        "/repositories",
        "/repositories/{name}/images",
        "/repositories/{name}/scan-findings",
        "/repositories/{name}/lifecycle-policy",
        "/repositories/{name}/policy",
        "/registry-scanning-config",
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

    r = client.get("/api/v1/aws-ecr/")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["aws_access_key_present"] is True
    assert body["aws_region"] == "eu-west-1"
    assert body["status"] == "ok"
    _reset()


# ============================================================ 503 paths


def test_repositories_returns_503_when_no_creds(monkeypatch):
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)
    app = _build_app(access_key="", secret_key="")
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/aws-ecr/repositories")
    assert r.status_code == 503, r.text
    assert "AWS_ACCESS_KEY_ID" in r.json()["detail"]
    _reset()


# ============================================================ DescribeRepositories


def test_describe_repositories_via_stubber(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIATEST")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    real_boto, stubber = _make_stubbed_boto()
    stubber.add_response(
        "describe_repositories",
        {
            "repositories": [
                {
                    "repositoryArn": "arn:aws:ecr:us-east-1:111122223333:repository/api",
                    "registryId": "111122223333",
                    "repositoryName": "api",
                    "repositoryUri": "111122223333.dkr.ecr.us-east-1.amazonaws.com/api",
                    "createdAt": "2024-01-01T00:00:00Z",
                    "imageTagMutability": "IMMUTABLE",
                    "imageScanningConfiguration": {"scanOnPush": True},
                    "encryptionConfiguration": {"encryptionType": "KMS", "kmsKey": "arn:aws:kms:us-east-1:111:key/abc"},
                },
                {
                    "repositoryArn": "arn:aws:ecr:us-east-1:111122223333:repository/web",
                    "registryId": "111122223333",
                    "repositoryName": "web",
                    "repositoryUri": "111122223333.dkr.ecr.us-east-1.amazonaws.com/web",
                    "createdAt": "2024-02-01T00:00:00Z",
                    "imageTagMutability": "MUTABLE",
                    "imageScanningConfiguration": {"scanOnPush": False},
                    "encryptionConfiguration": {"encryptionType": "AES256"},
                },
            ],
            "nextToken": "next-page-token",
        },
        {"maxResults": 50},
    )
    stubber.activate()
    try:
        app = _build_app(
            access_key="AKIATEST", secret_key="secret", stubbed_client=real_boto
        )
        client = TestClient(app, raise_server_exceptions=True)

        r = client.get("/api/v1/aws-ecr/repositories?maxResults=50")
        assert r.status_code == 200, r.text
        body = r.json()
        names = [b["repositoryName"] for b in body["repositories"]]
        assert names == ["api", "web"]
        assert body["repositories"][0]["imageTagMutability"] == "IMMUTABLE"
        assert body["repositories"][0]["imageScanningConfiguration"]["scanOnPush"] is True
        assert body["repositories"][0]["encryptionConfiguration"]["encryptionType"] == "KMS"
        assert body["nextToken"] == "next-page-token"
        stubber.assert_no_pending_responses()
    finally:
        stubber.deactivate()
        _reset()


# ============================================================ ListImages


def test_list_images_via_stubber(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIATEST")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    real_boto, stubber = _make_stubbed_boto()
    stubber.add_response(
        "list_images",
        {
            "imageIds": [
                {"imageDigest": "sha256:aaaa", "imageTag": "v1.0.0"},
                {"imageDigest": "sha256:bbbb", "imageTag": "v1.0.1"},
                {"imageDigest": "sha256:cccc"},
            ],
        },
        {"repositoryName": "api"},
    )
    stubber.activate()
    try:
        app = _build_app(
            access_key="AKIATEST", secret_key="secret", stubbed_client=real_boto
        )
        client = TestClient(app, raise_server_exceptions=True)

        r = client.get("/api/v1/aws-ecr/repositories/api/images")
        assert r.status_code == 200, r.text
        body = r.json()
        assert len(body["imageIds"]) == 3
        assert body["imageIds"][0]["imageTag"] == "v1.0.0"
        assert body["imageIds"][2]["imageDigest"] == "sha256:cccc"
        assert body["imageIds"][2].get("imageTag") is None
        stubber.assert_no_pending_responses()
    finally:
        stubber.deactivate()
        _reset()


# ============================================================ BatchDescribeImages


def test_batch_describe_images_via_stubber(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIATEST")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    real_boto, stubber = _make_stubbed_boto()
    stubber.add_response(
        "describe_images",
        {
            "imageDetails": [
                {
                    "registryId": "111122223333",
                    "repositoryName": "api",
                    "imageDigest": "sha256:aaaa",
                    "imageTags": ["v1.0.0", "latest"],
                    "imageSizeInBytes": 12345678,
                    "imagePushedAt": "2024-01-15T00:00:00Z",
                    "imageScanStatus": {
                        "status": "COMPLETE",
                        "description": "Scan complete",
                    },
                    "imageScanFindingsSummary": {
                        "imageScanCompletedAt": "2024-01-15T01:00:00Z",
                        "vulnerabilitySourceUpdatedAt": "2024-01-15T00:00:00Z",
                        "findingSeverityCounts": {"CRITICAL": 1, "HIGH": 5, "MEDIUM": 10},
                    },
                    "imageManifestMediaType": "application/vnd.docker.distribution.manifest.v2+json",
                    "artifactMediaType": "application/vnd.docker.container.image.v1+json",
                }
            ],
        },
        {
            "repositoryName": "api",
            "imageIds": [
                {"imageDigest": "sha256:aaaa"},
                {"imageTag": "missing"},
            ],
        },
    )
    stubber.activate()
    try:
        app = _build_app(
            access_key="AKIATEST", secret_key="secret", stubbed_client=real_boto
        )
        client = TestClient(app, raise_server_exceptions=True)

        r = client.post(
            "/api/v1/aws-ecr/repositories/api/images/batch-describe",
            json={
                "imageIds": [
                    {"imageDigest": "sha256:aaaa"},
                    {"imageTag": "missing"},
                ]
            },
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert len(body["imageDetails"]) == 1
        detail = body["imageDetails"][0]
        assert detail["repositoryName"] == "api"
        assert detail["imageScanStatus"]["status"] == "COMPLETE"
        assert detail["imageScanFindingsSummary"]["findingSeverityCounts"]["CRITICAL"] == 1
        assert "v1.0.0" in detail["imageTags"]
        assert body["failures"] == []  # boto3 describe_images shape does not include failures
        stubber.assert_no_pending_responses()
    finally:
        stubber.deactivate()
        _reset()


def test_batch_describe_images_422_on_empty_image_ids(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIATEST")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    app = _build_app(access_key="AKIATEST", secret_key="secret")
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/aws-ecr/repositories/api/images/batch-describe",
        json={"imageIds": []},
    )
    assert r.status_code == 422, r.text
    _reset()


# ============================================================ scan-findings


def test_describe_image_scan_findings_via_stubber(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIATEST")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    real_boto, stubber = _make_stubbed_boto()
    findings_payload = {
        "registryId": "111122223333",
        "repositoryName": "api",
        "imageId": {"imageDigest": "sha256:aaaa", "imageTag": "v1.0.0"},
        "imageScanStatus": {"status": "ACTIVE", "description": "Findings active"},
        "imageScanFindings": {
            "imageScanCompletedAt": "2024-01-15T01:00:00Z",
            "vulnerabilitySourceUpdatedAt": "2024-01-15T00:00:00Z",
            "findings": [
                {
                    "name": "CVE-2024-12345",
                    "description": "Critical RCE in libfoo",
                    "uri": "https://nvd.nist.gov/vuln/detail/CVE-2024-12345",
                    "severity": "CRITICAL",
                    "attributes": [
                        {"key": "package_name", "value": "libfoo"},
                        {"key": "package_version", "value": "1.2.3"},
                    ],
                }
            ],
            "findingSeverityCounts": {"CRITICAL": 1},
            "enhancedFindings": [
                {
                    "awsAccountId": "111122223333",
                    "description": "Enhanced Inspector finding",
                    "findingArn": "arn:aws:inspector2:us-east-1:111:finding/abc",
                    "firstObservedAt": "2024-01-15T01:00:00Z",
                    "lastObservedAt": "2024-01-16T01:00:00Z",
                    "packageVulnerabilityDetails": {
                        "vulnerabilityId": "CVE-2024-12345",
                        "source": "NVD",
                        "vendorSeverity": "CRITICAL",
                        "vulnerablePackages": [
                            {"name": "libfoo", "version": "1.2.3"}
                        ],
                    },
                    "remediation": {
                        "recommendation": {
                            "url": "https://example.com/fix",
                            "text": "Upgrade to 1.2.4",
                        }
                    },
                    "resources": [
                        {"id": "sha256:aaaa", "type": "AWS_ECR_CONTAINER_IMAGE"}
                    ],
                    "score": 9.8,
                    "severity": "CRITICAL",
                    "status": "ACTIVE",
                    "title": "CVE-2024-12345 in libfoo",
                    "type": "PACKAGE_VULNERABILITY",
                    "updatedAt": "2024-01-16T01:00:00Z",
                }
            ],
        },
    }
    stubber.add_response(
        "describe_image_scan_findings",
        findings_payload,
        {
            "repositoryName": "api",
            "imageId": {"imageDigest": "sha256:aaaa"},
        },
    )
    stubber.activate()
    try:
        app = _build_app(
            access_key="AKIATEST", secret_key="secret", stubbed_client=real_boto
        )
        client = TestClient(app, raise_server_exceptions=True)

        r = client.get(
            "/api/v1/aws-ecr/repositories/api/images/sha256:aaaa/scan-findings"
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["imageScanStatus"]["status"] == "ACTIVE"
        assert body["imageScanFindings"]["findings"][0]["severity"] == "CRITICAL"
        assert body["imageScanFindings"]["findings"][0]["name"] == "CVE-2024-12345"
        enhanced = body["imageScanFindings"]["enhancedFindings"][0]
        assert enhanced["packageVulnerabilityDetails"]["vulnerabilityId"] == "CVE-2024-12345"
        assert enhanced["score"] == 9.8
        assert enhanced["remediation"]["recommendation"]["text"] == "Upgrade to 1.2.4"
        stubber.assert_no_pending_responses()
    finally:
        stubber.deactivate()
        _reset()


def test_describe_image_scan_findings_404_on_scan_not_found(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIATEST")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    real_boto, stubber = _make_stubbed_boto()
    stubber.add_client_error(
        "describe_image_scan_findings",
        service_error_code="ScanNotFoundException",
        service_message="Scan results not found",
        http_status_code=404,
        expected_params={
            "repositoryName": "api",
            "imageId": {"imageTag": "unscanned"},
        },
    )
    stubber.activate()
    try:
        app = _build_app(
            access_key="AKIATEST", secret_key="secret", stubbed_client=real_boto
        )
        client = TestClient(app, raise_server_exceptions=True)

        r = client.get(
            "/api/v1/aws-ecr/repositories/api/images/unscanned/scan-findings"
        )
        assert r.status_code == 404, r.text
        body = r.json()
        assert body["detail"]["code"] == "ScanNotFoundException"
        assert "api/unscanned" in body["detail"]["resource"]
        stubber.assert_no_pending_responses()
    finally:
        stubber.deactivate()
        _reset()


# ============================================================ lifecycle-policy 200/404


def test_get_lifecycle_policy_200_and_404(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIATEST")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    real_boto, stubber = _make_stubbed_boto()
    stubber.add_response(
        "get_lifecycle_policy",
        {
            "registryId": "111122223333",
            "repositoryName": "api",
            "lifecyclePolicyText": '{"rules":[{"rulePriority":1,"description":"Expire untagged images older than 30 days for the api repository on every push","selection":{"tagStatus":"untagged","countType":"sinceImagePushed","countUnit":"days","countNumber":30},"action":{"type":"expire"}}]}',
            "lastEvaluatedAt": "2024-02-01T00:00:00Z",
        },
        {"repositoryName": "api"},
    )
    stubber.add_client_error(
        "get_lifecycle_policy",
        service_error_code="LifecyclePolicyNotFoundException",
        service_message="Lifecycle policy does not exist for the repository",
        http_status_code=404,
        expected_params={"repositoryName": "no-policy-repo"},
    )
    stubber.activate()
    try:
        app = _build_app(
            access_key="AKIATEST", secret_key="secret", stubbed_client=real_boto
        )
        client = TestClient(app, raise_server_exceptions=True)

        r = client.get("/api/v1/aws-ecr/repositories/api/lifecycle-policy")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["repositoryName"] == "api"
        assert "rulePriority" in body["lifecyclePolicyText"]

        r2 = client.get("/api/v1/aws-ecr/repositories/no-policy-repo/lifecycle-policy")
        assert r2.status_code == 404, r2.text
        assert r2.json()["detail"]["code"] == "LifecyclePolicyNotFoundException"
        stubber.assert_no_pending_responses()
    finally:
        stubber.deactivate()
        _reset()


# ============================================================ repo policy 200/404


def test_get_repository_policy_200_and_404(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIATEST")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    real_boto, stubber = _make_stubbed_boto()
    stubber.add_response(
        "get_repository_policy",
        {
            "registryId": "111122223333",
            "repositoryName": "api",
            "policyText": '{"Version":"2012-10-17","Statement":[]}',
        },
        {"repositoryName": "api"},
    )
    stubber.add_client_error(
        "get_repository_policy",
        service_error_code="RepositoryPolicyNotFoundException",
        service_message="Repository policy does not exist for the repository",
        http_status_code=404,
        expected_params={"repositoryName": "no-policy-repo"},
    )
    stubber.activate()
    try:
        app = _build_app(
            access_key="AKIATEST", secret_key="secret", stubbed_client=real_boto
        )
        client = TestClient(app, raise_server_exceptions=True)

        r = client.get("/api/v1/aws-ecr/repositories/api/policy")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["repositoryName"] == "api"
        assert "Version" in body["policyText"]

        r2 = client.get("/api/v1/aws-ecr/repositories/no-policy-repo/policy")
        assert r2.status_code == 404, r2.text
        assert r2.json()["detail"]["code"] == "RepositoryPolicyNotFoundException"
        stubber.assert_no_pending_responses()
    finally:
        stubber.deactivate()
        _reset()


# ============================================================ registry-scanning-config


def test_get_registry_scanning_config_via_stubber(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIATEST")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    real_boto, stubber = _make_stubbed_boto()
    stubber.add_response(
        "get_registry_scanning_configuration",
        {
            "registryId": "111122223333",
            "scanningConfiguration": {
                "scanType": "ENHANCED",
                "rules": [
                    {
                        "scanFrequency": "CONTINUOUS_SCAN",
                        "repositoryFilters": [
                            {"filter": "*", "filterType": "WILDCARD"}
                        ],
                    }
                ],
            },
        },
        {},
    )
    stubber.activate()
    try:
        app = _build_app(
            access_key="AKIATEST", secret_key="secret", stubbed_client=real_boto
        )
        client = TestClient(app, raise_server_exceptions=True)

        r = client.get("/api/v1/aws-ecr/registry-scanning-config")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["scanType"] == "ENHANCED"
        assert body["rules"][0]["scanFrequency"] == "CONTINUOUS_SCAN"
        assert body["rules"][0]["repositoryFilters"][0]["filterType"] == "WILDCARD"
        stubber.assert_no_pending_responses()
    finally:
        stubber.deactivate()
        _reset()
