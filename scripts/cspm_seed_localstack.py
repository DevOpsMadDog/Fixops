#!/usr/bin/env python3
"""Seed LocalStack with intentionally misconfigured AWS resources for CSPM tests.

Creates real (LocalStack-backed) misconfigurations that Prowler/Checkov/CloudSploit
will flag. Each resource is tagged with ``Tenant=<org_id>`` so per-tenant
attribution works.

Usage:
    python scripts/cspm_seed_localstack.py --endpoint http://localhost:4566 \
        --tenant juice-shop-corp --tenant nodegoat-corp [...]

Resources created per tenant:
    1. Public S3 bucket (no public-access block, public-read ACL)
    2. IAM user with attached Administrator-equivalent inline policy (admin*)
    3. EC2 security group with 0.0.0.0/0:22 ingress
    4. RDS instance without storage encryption
    5. KMS key with rotation disabled
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import uuid
from typing import List

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

logger = logging.getLogger("cspm_seed")
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")


def _client(service: str, endpoint: str, region: str = "us-east-1"):
    return boto3.client(
        service,
        endpoint_url=endpoint,
        region_name=region,
        aws_access_key_id="test",
        aws_secret_access_key="test",
        config=Config(retries={"max_attempts": 1}, connect_timeout=10, read_timeout=60),
    )


def seed_public_s3(endpoint: str, tenant: str) -> dict:
    s3 = _client("s3", endpoint)
    name = f"cspm-public-{tenant}-{uuid.uuid4().hex[:8]}".lower()
    try:
        s3.create_bucket(Bucket=name)
        # Misconfig: public bucket policy (skips slow ACL path on LocalStack).
        try:
            policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "PublicRead",
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": ["s3:GetObject"],
                        "Resource": [f"arn:aws:s3:::{name}/*"],
                    }
                ],
            }
            s3.put_bucket_policy(Bucket=name, Policy=json.dumps(policy))
        except ClientError as exc:
            logger.warning("put_bucket_policy failed for %s: %s", name, exc)
        try:
            s3.put_bucket_tagging(
                Bucket=name,
                Tagging={"TagSet": [{"Key": "Tenant", "Value": tenant}, {"Key": "CSPMSeed", "Value": "true"}]},
            )
        except ClientError as exc:
            logger.warning("put_bucket_tagging failed for %s: %s", name, exc)
        return {"resource_type": "s3_bucket", "id": name, "tenant": tenant, "issue": "public bucket policy"}
    except ClientError as exc:
        logger.error("seed_public_s3 failed (%s): %s", tenant, exc)
        return {"resource_type": "s3_bucket", "id": name, "tenant": tenant, "error": str(exc)}


def seed_admin_iam_user(endpoint: str, tenant: str) -> dict:
    iam = _client("iam", endpoint)
    user = f"cspm-admin-{tenant}-{uuid.uuid4().hex[:6]}".lower()
    try:
        iam.create_user(UserName=user, Tags=[{"Key": "Tenant", "Value": tenant}])
        # Misconfig: inline policy granting *:*.
        iam.put_user_policy(
            UserName=user,
            PolicyName="AdminAll",
            PolicyDocument=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {"Effect": "Allow", "Action": "*", "Resource": "*"}
                    ],
                }
            ),
        )
        return {"resource_type": "iam_user", "id": user, "tenant": tenant, "issue": "wildcard admin policy"}
    except ClientError as exc:
        logger.error("seed_admin_iam_user failed (%s): %s", tenant, exc)
        return {"resource_type": "iam_user", "id": user, "tenant": tenant, "error": str(exc)}


def seed_open_security_group(endpoint: str, tenant: str) -> dict:
    ec2 = _client("ec2", endpoint)
    name = f"cspm-open-sg-{tenant}-{uuid.uuid4().hex[:6]}".lower()
    try:
        # Need a VPC; LocalStack default VPC suffices.
        vpcs = ec2.describe_vpcs().get("Vpcs", [])
        vpc_id = vpcs[0]["VpcId"] if vpcs else ec2.create_vpc(CidrBlock="10.99.0.0/16")["Vpc"]["VpcId"]
        sg = ec2.create_security_group(
            GroupName=name,
            Description="CSPM seeded open SSH",
            VpcId=vpc_id,
        )
        sg_id = sg["GroupId"]
        # Misconfig: 0.0.0.0/0 on port 22.
        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
        )
        ec2.create_tags(Resources=[sg_id], Tags=[{"Key": "Tenant", "Value": tenant}])
        return {"resource_type": "security_group", "id": sg_id, "tenant": tenant, "issue": "0.0.0.0/0:22 ingress"}
    except ClientError as exc:
        logger.error("seed_open_security_group failed (%s): %s", tenant, exc)
        return {"resource_type": "security_group", "id": name, "tenant": tenant, "error": str(exc)}


def seed_unencrypted_rds(endpoint: str, tenant: str) -> dict:
    rds = _client("rds", endpoint)
    db_id = f"cspm-rds-{tenant}-{uuid.uuid4().hex[:6]}".lower()
    try:
        rds.create_db_instance(
            DBInstanceIdentifier=db_id,
            DBInstanceClass="db.t3.micro",
            Engine="postgres",
            AllocatedStorage=20,
            MasterUsername="admin",
            MasterUserPassword="ChangeMe123!",
            StorageEncrypted=False,  # Misconfig
            Tags=[{"Key": "Tenant", "Value": tenant}],
        )
        return {"resource_type": "rds_instance", "id": db_id, "tenant": tenant, "issue": "storage not encrypted"}
    except ClientError as exc:
        logger.error("seed_unencrypted_rds failed (%s): %s", tenant, exc)
        return {"resource_type": "rds_instance", "id": db_id, "tenant": tenant, "error": str(exc)}


def seed_kms_no_rotation(endpoint: str, tenant: str) -> dict:
    kms = _client("kms", endpoint)
    try:
        key = kms.create_key(
            Description=f"CSPM seeded key for {tenant}",
            Tags=[{"TagKey": "Tenant", "TagValue": tenant}],
        )
        kid = key["KeyMetadata"]["KeyId"]
        # Misconfig: explicitly disable rotation (default is also disabled).
        try:
            kms.disable_key_rotation(KeyId=kid)
        except ClientError:
            pass
        return {"resource_type": "kms_key", "id": kid, "tenant": tenant, "issue": "key rotation disabled"}
    except ClientError as exc:
        logger.error("seed_kms_no_rotation failed (%s): %s", tenant, exc)
        return {"resource_type": "kms_key", "id": "unknown", "tenant": tenant, "error": str(exc)}


def seed_tenant(endpoint: str, tenant: str) -> List[dict]:
    return [
        seed_public_s3(endpoint, tenant),
        seed_admin_iam_user(endpoint, tenant),
        seed_open_security_group(endpoint, tenant),
        seed_unencrypted_rds(endpoint, tenant),
        seed_kms_no_rotation(endpoint, tenant),
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--endpoint", default="http://localhost:4566")
    parser.add_argument(
        "--tenant",
        action="append",
        default=[],
        help="Tenant org_id (repeatable). Example: --tenant juice-shop-corp",
    )
    parser.add_argument("--out", default="scripts/cspm_seed_manifest.json")
    args = parser.parse_args()

    tenants = args.tenant or ["default"]
    manifest = {"endpoint": args.endpoint, "tenants": {}}
    for tenant in tenants:
        logger.info("Seeding tenant %s ...", tenant)
        manifest["tenants"][tenant] = seed_tenant(args.endpoint, tenant)

    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2, default=str)
    logger.info("Manifest written to %s", args.out)
    print(json.dumps({"tenants": list(manifest["tenants"].keys()), "manifest_path": args.out}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
