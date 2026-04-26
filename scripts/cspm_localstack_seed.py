#!/usr/bin/env python3
"""Seed real AWS resources into LocalStack for CSPM scanning.

This script uses boto3 against the LocalStack endpoint (default
http://localhost:4566) to create *real* (LocalStack-real) AWS resources
that ALDECI's CSPM scanner can then enumerate. We never insert directly
into ALDECI databases — we use the actual AWS API surface.

Resources created (mix of compliant + intentionally-misconfigured):
  - S3 buckets:
      * fixops-cspm-public-<n>      (public read ACL — finding)
      * fixops-cspm-encrypted-<n>   (compliant)
  - IAM users + inline policies:
      * fixops-admin-<n>            (Action='*' Resource='*' — finding)
      * fixops-readonly-<n>         (compliant)

Idempotent: re-running adds suffixes; existing resources are skipped.

Usage:
  python3 scripts/cspm_localstack_seed.py [--endpoint http://localhost:4566]
                                          [--buckets 3] [--users 2]
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from typing import Any, Dict, List

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger("cspm_localstack_seed")


def _client(service: str, endpoint: str):
    import boto3
    return boto3.client(
        service,
        endpoint_url=endpoint,
        aws_access_key_id="test",
        aws_secret_access_key="test",
        region_name="us-east-1",
    )


def seed_s3(endpoint: str, count: int) -> List[Dict[str, Any]]:
    s3 = _client("s3", endpoint)
    out: List[Dict[str, Any]] = []
    timestamp = int(time.time())
    for i in range(count):
        # Public bucket (intentional misconfiguration)
        public_bucket = f"fixops-cspm-public-{timestamp}-{i}"
        try:
            s3.create_bucket(Bucket=public_bucket)
            s3.put_bucket_acl(Bucket=public_bucket, ACL="public-read")
            s3.put_object(
                Bucket=public_bucket, Key="readme.txt", Body=b"public test object"
            )
            out.append({"bucket": public_bucket, "public": True})
            log.info("  S3: created public bucket %s", public_bucket)
        except Exception as exc:  # noqa: BLE001
            log.warning("  S3: failed %s: %s", public_bucket, exc)

        # Compliant encrypted bucket
        encrypted_bucket = f"fixops-cspm-encrypted-{timestamp}-{i}"
        try:
            s3.create_bucket(Bucket=encrypted_bucket)
            s3.put_bucket_encryption(
                Bucket=encrypted_bucket,
                ServerSideEncryptionConfiguration={
                    "Rules": [
                        {
                            "ApplyServerSideEncryptionByDefault": {
                                "SSEAlgorithm": "AES256"
                            }
                        }
                    ]
                },
            )
            out.append({"bucket": encrypted_bucket, "encrypted": True})
            log.info("  S3: created encrypted bucket %s", encrypted_bucket)
        except Exception as exc:  # noqa: BLE001
            log.warning("  S3: failed %s: %s", encrypted_bucket, exc)
    return out


def seed_iam(endpoint: str, count: int) -> List[Dict[str, Any]]:
    iam = _client("iam", endpoint)
    out: List[Dict[str, Any]] = []
    timestamp = int(time.time())

    for i in range(count):
        admin_user = f"fixops-admin-{timestamp}-{i}"
        try:
            iam.create_user(UserName=admin_user)
            iam.put_user_policy(
                UserName=admin_user,
                PolicyName="AdminWildcard",
                PolicyDocument=json.dumps(
                    {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "*",
                                "Resource": "*",
                            }
                        ],
                    }
                ),
            )
            out.append({"user": admin_user, "admin": True})
            log.info("  IAM: created admin user %s (wildcard policy)", admin_user)
        except Exception as exc:  # noqa: BLE001
            log.warning("  IAM: failed %s: %s", admin_user, exc)

        readonly_user = f"fixops-readonly-{timestamp}-{i}"
        try:
            iam.create_user(UserName=readonly_user)
            iam.put_user_policy(
                UserName=readonly_user,
                PolicyName="ReadOnlyS3",
                PolicyDocument=json.dumps(
                    {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": ["s3:GetObject", "s3:ListBucket"],
                                "Resource": "*",
                            }
                        ],
                    }
                ),
            )
            out.append({"user": readonly_user, "readonly": True})
            log.info("  IAM: created readonly user %s", readonly_user)
        except Exception as exc:  # noqa: BLE001
            log.warning("  IAM: failed %s: %s", readonly_user, exc)
    return out


def main(argv: List[str] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument(
        "--endpoint",
        default=os.environ.get("FIXOPS_AWS_ENDPOINT", "http://localhost:4566"),
        help="LocalStack endpoint URL",
    )
    p.add_argument("--buckets", type=int, default=2, help="S3 bucket pairs to create")
    p.add_argument("--users", type=int, default=2, help="IAM user pairs to create")
    p.add_argument("--skip-s3", action="store_true")
    p.add_argument("--skip-iam", action="store_true")
    args = p.parse_args(argv)

    log.info("CSPM LocalStack seeder → endpoint=%s", args.endpoint)

    summary: Dict[str, Any] = {"endpoint": args.endpoint}
    if not args.skip_s3:
        log.info("Seeding S3 (%d pairs)…", args.buckets)
        summary["s3"] = seed_s3(args.endpoint, args.buckets)
    if not args.skip_iam:
        log.info("Seeding IAM (%d pairs)…", args.users)
        summary["iam"] = seed_iam(args.endpoint, args.users)

    log.info(
        "DONE: created %d S3 resources, %d IAM resources",
        len(summary.get("s3", [])),
        len(summary.get("iam", [])),
    )
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
