"""Tests for Prowler Output Normalizer — ALDECI.

Covers: JSON parsing (v3 + v4), CSV parsing, severity mapping, status filtering,
CIS benchmark mapping, compliance framework detection, edge cases.
"""
from __future__ import annotations

import json
import os
import sys
import pytest

_repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _sub in ("suite-core", "suite-api", "suite-feeds", "suite-attack",
             "suite-evidence-risk", "suite-integrations"):
    _p = os.path.join(_repo, _sub)
    if _p not in sys.path:
        sys.path.insert(0, _p)

from core.prowler_normalizer import (
    ProwlerNormalizer,
    normalize_prowler_output,
    _map_compliance_frameworks,
)


# ---------------------------------------------------------------------------
# JSON normalization — Prowler v4 format
# ---------------------------------------------------------------------------

class TestJsonNormalizationV4:
    def test_single_fail_finding(self):
        raw = json.dumps([{
            "CheckID": "s3_bucket_public_access",
            "CheckTitle": "S3 Bucket has public access enabled",
            "Status": "FAIL",
            "Severity": "critical",
            "Provider": "aws",
            "AccountId": "123456789012",
            "Region": "us-east-1",
            "ServiceName": "s3",
            "ResourceId": "my-bucket",
            "ResourceArn": "arn:aws:s3:::my-bucket",
            "ResourceType": "AWS::S3::Bucket",
            "StatusExtended": "Bucket my-bucket has public read access",
            "Risk": "Data exposure",
            "Remediation": {
                "Recommendation": {
                    "Text": "Block all public access",
                    "Url": "https://docs.aws.amazon.com/s3"
                }
            },
        }])
        normalizer = ProwlerNormalizer(provider="aws")
        findings = normalizer.normalize_json(raw)
        assert len(findings) == 1
        f = findings[0]
        assert f["check_id"] == "s3_bucket_public_access"
        assert f["severity"] == "critical"
        assert f["provider"] == "aws"
        assert f["resource_id"] == "my-bucket"
        assert f["remediation"] == "Block all public access"
        assert f["remediation_url"] == "https://docs.aws.amazon.com/s3"

    def test_pass_findings_skipped(self):
        raw = json.dumps([
            {"CheckID": "iam_check_1", "Status": "PASS", "Severity": "high"},
            {"CheckID": "iam_check_2", "Status": "FAIL", "Severity": "high"},
        ])
        normalizer = ProwlerNormalizer(provider="aws")
        findings = normalizer.normalize_json(raw)
        assert len(findings) == 1
        assert findings[0]["check_id"] == "iam_check_2"

    def test_single_dict_input(self):
        raw = json.dumps({
            "CheckID": "ec2_check_1",
            "Status": "FAIL",
            "Severity": "medium",
            "Provider": "aws",
        })
        normalizer = ProwlerNormalizer(provider="aws")
        findings = normalizer.normalize_json(raw)
        assert len(findings) == 1

    def test_severity_mapping(self):
        for prowler_sev, expected in [
            ("critical", "critical"),
            ("high", "high"),
            ("medium", "medium"),
            ("low", "low"),
            ("informational", "informational"),
            ("info", "informational"),
        ]:
            raw = json.dumps([{
                "CheckID": "test_check",
                "Status": "FAIL",
                "Severity": prowler_sev,
            }])
            normalizer = ProwlerNormalizer(provider="aws")
            findings = normalizer.normalize_json(raw)
            assert findings[0]["severity"] == expected

    def test_unknown_severity_defaults_to_medium(self):
        raw = json.dumps([{
            "CheckID": "test_check",
            "Status": "FAIL",
            "Severity": "extreme",
        }])
        normalizer = ProwlerNormalizer(provider="aws")
        findings = normalizer.normalize_json(raw)
        assert findings[0]["severity"] == "medium"


# ---------------------------------------------------------------------------
# JSON normalization — Prowler v3 format (lowercase keys)
# ---------------------------------------------------------------------------

class TestJsonNormalizationV3:
    def test_v3_lowercase_keys(self):
        raw = json.dumps([{
            "check_id": "s3_check_v3",
            "check_title": "S3 v3 check",
            "status": "FAIL",
            "severity": "high",
            "provider": "aws",
            "account_id": "123456",
            "region": "eu-west-1",
            "service_name": "s3",
            "resource_id": "bucket-v3",
            "resource_arn": "arn:aws:s3:::bucket-v3",
            "resource_type": "bucket",
            "status_extended": "Public access",
            "risk": "Data leak",
            "remediation": "Fix it",
        }])
        normalizer = ProwlerNormalizer(provider="aws")
        findings = normalizer.normalize_json(raw)
        assert len(findings) == 1
        f = findings[0]
        assert f["check_id"] == "s3_check_v3"
        assert f["region"] == "eu-west-1"
        assert f["remediation"] == "Fix it"


# ---------------------------------------------------------------------------
# CSV normalization
# ---------------------------------------------------------------------------

class TestCsvNormalization:
    def test_csv_parsing(self):
        csv_data = (
            "CHECK_ID,CHECK_TITLE,STATUS,SEVERITY,PROVIDER,ACCOUNT_ID,REGION,SERVICE_NAME,RESOURCE_ID\n"
            "s3_check_1,S3 Public Bucket,FAIL,critical,aws,123456,us-east-1,s3,my-bucket\n"
            "iam_check_1,IAM Root MFA,PASS,high,aws,123456,us-east-1,iam,root\n"
            "ec2_check_1,EC2 Open Port,FAIL,high,aws,123456,us-west-2,ec2,i-12345\n"
        )
        normalizer = ProwlerNormalizer(provider="aws")
        findings = normalizer.normalize_csv(csv_data)
        assert len(findings) == 2  # PASS skipped
        assert findings[0]["check_id"] == "s3_check_1"
        assert findings[0]["severity"] == "critical"
        assert findings[1]["check_id"] == "ec2_check_1"

    def test_csv_empty(self):
        normalizer = ProwlerNormalizer(provider="aws")
        findings = normalizer.normalize_csv("")
        assert findings == []


# ---------------------------------------------------------------------------
# Compliance framework mapping
# ---------------------------------------------------------------------------

class TestComplianceMapping:
    def test_iam_maps_to_cis_nist_pci(self):
        frameworks = _map_compliance_frameworks("iam_root_mfa")
        assert "CIS" in frameworks
        assert "NIST-800-53" in frameworks
        assert "PCI-DSS" in frameworks

    def test_s3_maps_to_cis_nist_soc2(self):
        frameworks = _map_compliance_frameworks("s3_bucket_public")
        assert "CIS" in frameworks
        assert "NIST-800-53" in frameworks
        assert "SOC2" in frameworks

    def test_kms_maps_to_hipaa(self):
        frameworks = _map_compliance_frameworks("kms_key_rotation")
        assert "HIPAA" in frameworks

    def test_unknown_prefix_defaults_to_cis(self):
        frameworks = _map_compliance_frameworks("unknown_check_xyz")
        assert frameworks == ["CIS"]

    def test_cloudtrail_maps_to_pci(self):
        frameworks = _map_compliance_frameworks("cloudtrail_enabled")
        assert "PCI-DSS" in frameworks


# ---------------------------------------------------------------------------
# Convenience function
# ---------------------------------------------------------------------------

class TestConvenienceFunction:
    def test_normalize_json(self):
        raw = json.dumps([{
            "CheckID": "test_1",
            "Status": "FAIL",
            "Severity": "high",
        }])
        findings = normalize_prowler_output(raw, provider="aws", format="json")
        assert len(findings) == 1

    def test_normalize_csv(self):
        csv_data = "CHECK_ID,STATUS,SEVERITY\ntest_1,FAIL,medium\n"
        findings = normalize_prowler_output(csv_data, provider="azure", format="csv")
        assert len(findings) == 1
        assert findings[0]["provider"] == "azure"


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_invalid_json(self):
        normalizer = ProwlerNormalizer(provider="aws")
        findings = normalizer.normalize_json("not valid json")
        assert findings == []

    def test_non_list_non_dict_json(self):
        normalizer = ProwlerNormalizer(provider="aws")
        findings = normalizer.normalize_json('"just a string"')
        assert findings == []

    def test_empty_list_json(self):
        normalizer = ProwlerNormalizer(provider="aws")
        findings = normalizer.normalize_json("[]")
        assert findings == []

    def test_warning_status_is_kept(self):
        raw = json.dumps([{
            "CheckID": "test_warn",
            "Status": "WARNING",
            "Severity": "medium",
        }])
        normalizer = ProwlerNormalizer(provider="aws")
        findings = normalizer.normalize_json(raw)
        assert len(findings) == 1  # WARNING is treated as a finding

    def test_raw_json_preserved(self):
        item = {"CheckID": "test_raw", "Status": "FAIL", "Severity": "low", "extra_field": "data"}
        raw = json.dumps([item])
        normalizer = ProwlerNormalizer(provider="aws")
        findings = normalizer.normalize_json(raw)
        raw_preserved = json.loads(findings[0]["raw_json"])
        assert raw_preserved["extra_field"] == "data"

    def test_compliance_frameworks_as_json_string(self):
        raw = json.dumps([{
            "CheckID": "s3_test",
            "Status": "FAIL",
            "Severity": "high",
        }])
        normalizer = ProwlerNormalizer(provider="aws")
        findings = normalizer.normalize_json(raw)
        frameworks = json.loads(findings[0]["compliance_frameworks"])
        assert isinstance(frameworks, list)
        assert "CIS" in frameworks
