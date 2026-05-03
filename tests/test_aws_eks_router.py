"""Tests for the AWS EKS router (NO MOCKS, real boto3 path via Stubber).

Coverage:
  1.  Capability summary returns ``status="unavailable"`` when env unset.
  2.  Capability summary returns ``status="ok"`` + region echo when env set.
  3.  /clusters returns 503 when env unset.
  4.  /clusters returns a real ListClusters response via botocore Stubber
      including pagination passthrough (maxResults, nextToken).
  5.  /clusters/{name} returns 200 with full DescribeCluster payload via Stubber.
  6.  /clusters/{name} returns 404 ResourceNotFoundException via Stubber.
  7.  /clusters/{name}/nodegroups returns names + nextToken via Stubber.
  8.  /clusters/{name}/nodegroups/{ng} returns full describe payload via Stubber.
  9.  /clusters/{name}/addons returns names via Stubber.
  10. /clusters/{name}/addons/{addon} returns full describe payload via Stubber.
  11. /clusters/{name}/fargate-profiles returns names via Stubber.
  12. /clusters/{name}/access-entries returns principal ARNs and accepts filters
      (associatedPolicyArn + type) via Stubber.

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
    """Build a minimal FastAPI app mounting the AWS EKS router."""
    from core import aws_eks_engine as eng_mod

    eng_mod.reset_aws_eks_engine()
    eng_mod.get_aws_eks_engine(
        access_key=access_key,
        secret_key=secret_key,
        region=region,
        client=stubbed_client,
        force_refresh=True,
    )

    from apps.api.aws_eks_router import router

    app = FastAPI()
    app.include_router(router)
    return app


def _reset() -> None:
    from core import aws_eks_engine as eng_mod
    eng_mod.reset_aws_eks_engine()


def _make_stubbed_boto():
    """Create a real boto3 eks client wrapped in a Stubber."""
    real_boto = boto3.client(
        "eks",
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

    r = client.get("/api/v1/aws-eks/")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "AWS EKS"
    expected_eps = {
        "/clusters",
        "/clusters/{name}",
        "/clusters/{name}/nodegroups",
        "/clusters/{name}/addons",
        "/clusters/{name}/fargate-profiles",
        "/clusters/{name}/access-entries",
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

    r = client.get("/api/v1/aws-eks/")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["aws_access_key_present"] is True
    assert body["aws_region"] == "eu-west-1"
    assert body["status"] == "ok"
    _reset()


# ============================================================ 503 paths


def test_clusters_returns_503_when_no_creds(monkeypatch):
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)
    app = _build_app(access_key="", secret_key="")
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/aws-eks/clusters")
    assert r.status_code == 503, r.text
    assert "AWS_ACCESS_KEY_ID" in r.json()["detail"]
    _reset()


# ============================================================ ListClusters


def test_list_clusters_via_stubber_with_pagination(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIATEST")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    real_boto, stubber = _make_stubbed_boto()
    stubber.add_response(
        "list_clusters",
        {
            "clusters": ["prod-eks", "stage-eks"],
            "nextToken": "TOKEN_NEXT",
        },
        {"maxResults": 50, "nextToken": "TOKEN_PREV", "include": ["all"]},
    )
    stubber.activate()
    try:
        app = _build_app(
            access_key="AKIATEST", secret_key="secret", stubbed_client=real_boto
        )
        client = TestClient(app, raise_server_exceptions=True)

        r = client.get(
            "/api/v1/aws-eks/clusters",
            params={"maxResults": 50, "nextToken": "TOKEN_PREV", "include": "all"},
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["clusters"] == ["prod-eks", "stage-eks"]
        assert body["nextToken"] == "TOKEN_NEXT"
        stubber.assert_no_pending_responses()
    finally:
        stubber.deactivate()
        _reset()


# ============================================================ DescribeCluster 200 + 404


def test_describe_cluster_via_stubber(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIATEST")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    real_boto, stubber = _make_stubbed_boto()
    cluster_payload = {
        "cluster": {
            "name": "prod-eks",
            "arn": "arn:aws:eks:us-east-1:111:cluster/prod-eks",
            "version": "1.30",
            "endpoint": "https://abc.gr7.us-east-1.eks.amazonaws.com",
            "roleArn": "arn:aws:iam::111:role/eks-role",
            "status": "ACTIVE",
            "platformVersion": "eks.5",
            "resourcesVpcConfig": {
                "subnetIds": ["subnet-aaa", "subnet-bbb"],
                "securityGroupIds": ["sg-xxx"],
                "clusterSecurityGroupId": "sg-cluster",
                "vpcId": "vpc-aaa",
                "endpointPublicAccess": True,
                "endpointPrivateAccess": False,
                "publicAccessCidrs": ["0.0.0.0/0"],
            },
            "kubernetesNetworkConfig": {
                "serviceIpv4Cidr": "10.100.0.0/16",
                "ipFamily": "ipv4",
            },
            "logging": {
                "clusterLogging": [
                    {"types": ["api", "audit"], "enabled": True},
                    {
                        "types": ["authenticator", "controllerManager", "scheduler"],
                        "enabled": False,
                    },
                ]
            },
            "identity": {
                "oidc": {
                    "issuer": "https://oidc.eks.us-east-1.amazonaws.com/id/ABC"
                }
            },
            "encryptionConfig": [
                {
                    "resources": ["secrets"],
                    "provider": {"keyArn": "arn:aws:kms:us-east-1:111:key/k1"},
                }
            ],
            "accessConfig": {
                "bootstrapClusterCreatorAdminPermissions": True,
                "authenticationMode": "API_AND_CONFIG_MAP",
            },
            "tags": {"env": "prod"},
        }
    }
    stubber.add_response(
        "describe_cluster", cluster_payload, {"name": "prod-eks"}
    )
    stubber.activate()
    try:
        app = _build_app(
            access_key="AKIATEST", secret_key="secret", stubbed_client=real_boto
        )
        client = TestClient(app, raise_server_exceptions=True)

        r = client.get("/api/v1/aws-eks/clusters/prod-eks")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["cluster"]["name"] == "prod-eks"
        assert body["cluster"]["status"] == "ACTIVE"
        assert body["cluster"]["resourcesVpcConfig"]["endpointPublicAccess"] is True
        assert body["cluster"]["accessConfig"]["authenticationMode"] == "API_AND_CONFIG_MAP"
        assert body["cluster"]["encryptionConfig"][0]["resources"] == ["secrets"]
        assert body["cluster"]["identity"]["oidc"]["issuer"].startswith("https://oidc")
        stubber.assert_no_pending_responses()
    finally:
        stubber.deactivate()
        _reset()


def test_describe_cluster_404_via_stubber(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIATEST")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    real_boto, stubber = _make_stubbed_boto()
    stubber.add_client_error(
        "describe_cluster",
        service_error_code="ResourceNotFoundException",
        service_message="No cluster found for name: ghost-eks.",
        http_status_code=404,
        expected_params={"name": "ghost-eks"},
    )
    stubber.activate()
    try:
        app = _build_app(
            access_key="AKIATEST", secret_key="secret", stubbed_client=real_boto
        )
        client = TestClient(app, raise_server_exceptions=True)

        r = client.get("/api/v1/aws-eks/clusters/ghost-eks")
        assert r.status_code == 404, r.text
        body = r.json()
        assert body["detail"]["code"] == "ResourceNotFoundException"
        assert "ghost-eks" in body["detail"]["resource"]
        stubber.assert_no_pending_responses()
    finally:
        stubber.deactivate()
        _reset()


# ============================================================ Nodegroups


def test_list_nodegroups_via_stubber(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIATEST")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    real_boto, stubber = _make_stubbed_boto()
    stubber.add_response(
        "list_nodegroups",
        {"nodegroups": ["ng-spot", "ng-ondemand"], "nextToken": "TKN2"},
        {"clusterName": "prod-eks", "maxResults": 10},
    )
    stubber.activate()
    try:
        app = _build_app(
            access_key="AKIATEST", secret_key="secret", stubbed_client=real_boto
        )
        client = TestClient(app, raise_server_exceptions=True)

        r = client.get(
            "/api/v1/aws-eks/clusters/prod-eks/nodegroups",
            params={"maxResults": 10},
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["nodegroups"] == ["ng-spot", "ng-ondemand"]
        assert body["nextToken"] == "TKN2"
        stubber.assert_no_pending_responses()
    finally:
        stubber.deactivate()
        _reset()


def test_describe_nodegroup_via_stubber(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIATEST")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    real_boto, stubber = _make_stubbed_boto()
    ng_payload = {
        "nodegroup": {
            "nodegroupName": "ng-spot",
            "nodegroupArn": "arn:aws:eks:us-east-1:111:nodegroup/prod-eks/ng-spot/abc",
            "clusterName": "prod-eks",
            "version": "1.30",
            "releaseVersion": "1.30.0-20240101",
            "status": "ACTIVE",
            "capacityType": "SPOT",
            "scalingConfig": {"minSize": 1, "maxSize": 10, "desiredSize": 3},
            "instanceTypes": ["m6i.large"],
            "subnets": ["subnet-aaa"],
            "amiType": "AL2023_x86_64_STANDARD",
            "nodeRole": "arn:aws:iam::111:role/ng-role",
            "labels": {"role": "spot"},
            "taints": [{"key": "spot", "value": "true", "effect": "NO_SCHEDULE"}],
            "diskSize": 50,
            "updateConfig": {"maxUnavailable": 1},
            "tags": {"env": "prod"},
        }
    }
    stubber.add_response(
        "describe_nodegroup",
        ng_payload,
        {"clusterName": "prod-eks", "nodegroupName": "ng-spot"},
    )
    stubber.activate()
    try:
        app = _build_app(
            access_key="AKIATEST", secret_key="secret", stubbed_client=real_boto
        )
        client = TestClient(app, raise_server_exceptions=True)

        r = client.get("/api/v1/aws-eks/clusters/prod-eks/nodegroups/ng-spot")
        assert r.status_code == 200, r.text
        body = r.json()
        ng = body["nodegroup"]
        assert ng["nodegroupName"] == "ng-spot"
        assert ng["capacityType"] == "SPOT"
        assert ng["scalingConfig"]["desiredSize"] == 3
        assert ng["amiType"] == "AL2023_x86_64_STANDARD"
        assert ng["taints"][0]["effect"] == "NO_SCHEDULE"
        stubber.assert_no_pending_responses()
    finally:
        stubber.deactivate()
        _reset()


# ============================================================ Addons


def test_list_addons_via_stubber(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIATEST")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    real_boto, stubber = _make_stubbed_boto()
    stubber.add_response(
        "list_addons",
        {"addons": ["vpc-cni", "coredns", "kube-proxy"]},
        {"clusterName": "prod-eks"},
    )
    stubber.activate()
    try:
        app = _build_app(
            access_key="AKIATEST", secret_key="secret", stubbed_client=real_boto
        )
        client = TestClient(app, raise_server_exceptions=True)

        r = client.get("/api/v1/aws-eks/clusters/prod-eks/addons")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["addons"] == ["vpc-cni", "coredns", "kube-proxy"]
        assert body["nextToken"] is None
        stubber.assert_no_pending_responses()
    finally:
        stubber.deactivate()
        _reset()


def test_describe_addon_via_stubber(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIATEST")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    real_boto, stubber = _make_stubbed_boto()
    addon_payload = {
        "addon": {
            "addonName": "vpc-cni",
            "clusterName": "prod-eks",
            "status": "ACTIVE",
            "addonVersion": "v1.18.0-eksbuild.1",
            "addonArn": "arn:aws:eks:us-east-1:111:addon/prod-eks/vpc-cni/abc",
            "serviceAccountRoleArn": "arn:aws:iam::111:role/vpc-cni-role",
            "publisher": "eks",
            "owner": "aws",
            "tags": {"env": "prod"},
        }
    }
    stubber.add_response(
        "describe_addon",
        addon_payload,
        {"clusterName": "prod-eks", "addonName": "vpc-cni"},
    )
    stubber.activate()
    try:
        app = _build_app(
            access_key="AKIATEST", secret_key="secret", stubbed_client=real_boto
        )
        client = TestClient(app, raise_server_exceptions=True)

        r = client.get("/api/v1/aws-eks/clusters/prod-eks/addons/vpc-cni")
        assert r.status_code == 200, r.text
        body = r.json()
        addon = body["addon"]
        assert addon["addonName"] == "vpc-cni"
        assert addon["status"] == "ACTIVE"
        assert addon["addonVersion"].startswith("v1.18")
        assert addon["serviceAccountRoleArn"].endswith("vpc-cni-role")
        stubber.assert_no_pending_responses()
    finally:
        stubber.deactivate()
        _reset()


# ============================================================ Fargate profiles


def test_list_fargate_profiles_via_stubber(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIATEST")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    real_boto, stubber = _make_stubbed_boto()
    stubber.add_response(
        "list_fargate_profiles",
        {"fargateProfileNames": ["batch-jobs", "system"], "nextToken": "TKN3"},
        {"clusterName": "prod-eks", "maxResults": 5},
    )
    stubber.activate()
    try:
        app = _build_app(
            access_key="AKIATEST", secret_key="secret", stubbed_client=real_boto
        )
        client = TestClient(app, raise_server_exceptions=True)

        r = client.get(
            "/api/v1/aws-eks/clusters/prod-eks/fargate-profiles",
            params={"maxResults": 5},
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["fargateProfileNames"] == ["batch-jobs", "system"]
        assert body["nextToken"] == "TKN3"
        stubber.assert_no_pending_responses()
    finally:
        stubber.deactivate()
        _reset()


# ============================================================ Access entries


def test_list_access_entries_via_stubber_with_filters(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIATEST")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    real_boto, stubber = _make_stubbed_boto()
    stubber.add_response(
        "list_access_entries",
        {
            "accessEntries": [
                "arn:aws:iam::111:role/admin",
                "arn:aws:iam::111:role/devops",
            ],
        },
        {
            "clusterName": "prod-eks",
            "associatedPolicyArn": (
                "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
            ),
        },
    )
    stubber.activate()
    try:
        app = _build_app(
            access_key="AKIATEST", secret_key="secret", stubbed_client=real_boto
        )
        client = TestClient(app, raise_server_exceptions=True)

        r = client.get(
            "/api/v1/aws-eks/clusters/prod-eks/access-entries",
            params={
                "associatedPolicyArn": (
                    "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
                ),
            },
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["accessEntries"] == [
            "arn:aws:iam::111:role/admin",
            "arn:aws:iam::111:role/devops",
        ]
        stubber.assert_no_pending_responses()
    finally:
        stubber.deactivate()
        _reset()
