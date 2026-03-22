"""Unit tests for ALdeci CSPM Engine — Cloud Security Posture Management.

Tests Terraform and CloudFormation scanning, provider detection,
finding generation, severity/category classification, and compliance scoring.
Covers V7 (scanner engine) pillar.
"""

import json
import pytest

from core.cspm_engine import (
    CSPMEngine,
    CloudProvider,
    CspmCategory,
    CspmFinding,
    CspmScanResult,
    CspmSeverity,
    ALL_RULES,
    AWS_RULES,
    AZURE_RULES,
    GCP_RULES,
    get_cspm_engine,
)


# ── Fixtures ────────────────────────────────────────────────────────


@pytest.fixture
def engine():
    return CSPMEngine()


@pytest.fixture
def tf_aws_secure():
    """Terraform config with no misconfigurations."""
    return '''
provider "aws" {
  region = "us-east-1"
}

resource "aws_s3_bucket" "secure" {
  bucket = "my-secure-bucket"
  acl    = "private"
}

resource "aws_ebs_volume" "vol" {
  availability_zone = "us-east-1a"
  size              = 40
  encrypted         = true
}

resource "aws_cloudtrail" "trail" {
  name           = "main-trail"
  s3_bucket_name = "trail-bucket"
}
'''


@pytest.fixture
def tf_aws_insecure():
    """Terraform config with multiple misconfigurations."""
    return '''
provider "aws" {
  region = "us-east-1"
}

resource "aws_s3_bucket" "public" {
  bucket = "public-bucket"
  acl    = "public-read"
}

resource "aws_security_group" "open" {
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_ebs_volume" "unencrypted" {
  availability_zone = "us-east-1a"
  size              = 40
}

resource "aws_db_instance" "public_rds" {
  publicly_accessible = true
  engine              = "mysql"
}

resource "aws_iam_policy" "admin" {
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "*",
    "Resource": "*"
  }]
}
POLICY
}
'''


@pytest.fixture
def tf_azure():
    """Azure Terraform config."""
    return '''
provider "azurerm" {
  features {}
}

resource "azurerm_storage_account" "example" {
  name = "storageacct"
}
'''


@pytest.fixture
def tf_gcp():
    """GCP Terraform config."""
    return '''
provider "google" {
  project = "my-project"
}

resource "google_compute_instance" "default" {
  name = "vm-instance"
}
'''


@pytest.fixture
def cf_clean():
    """CloudFormation template with no issues."""
    return json.dumps({
        "Resources": {
            "SecureBucket": {
                "Type": "AWS::S3::Bucket",
                "Properties": {
                    "BucketName": "secure-bucket",
                    "AccessControl": "Private",
                },
            },
            "SecureRDS": {
                "Type": "AWS::RDS::DBInstance",
                "Properties": {
                    "Engine": "mysql",
                    "PubliclyAccessible": False,
                },
            },
        }
    })


@pytest.fixture
def cf_insecure():
    """CloudFormation template with misconfigurations."""
    return json.dumps({
        "Resources": {
            "PublicBucket": {
                "Type": "AWS::S3::Bucket",
                "Properties": {
                    "BucketName": "public-bucket",
                    "AccessControl": "PublicRead",
                },
            },
            "OpenSG": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {
                    "SecurityGroupIngress": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 22,
                            "ToPort": 22,
                            "CidrIp": "0.0.0.0/0",
                        }
                    ]
                },
            },
            "PublicRDS": {
                "Type": "AWS::RDS::DBInstance",
                "Properties": {
                    "Engine": "mysql",
                    "PubliclyAccessible": True,
                },
            },
        }
    })


# ── Data Model Tests ────────────────────────────────────────────────


class TestEnums:
    def test_cloud_provider_values(self):
        assert CloudProvider.AWS.value == "aws"
        assert CloudProvider.AZURE.value == "azure"
        assert CloudProvider.GCP.value == "gcp"
        assert CloudProvider.MULTI.value == "multi"

    def test_cspm_severity_values(self):
        assert CspmSeverity.CRITICAL.value == "critical"
        assert CspmSeverity.HIGH.value == "high"
        assert CspmSeverity.MEDIUM.value == "medium"
        assert CspmSeverity.LOW.value == "low"
        assert CspmSeverity.INFO.value == "info"

    def test_cspm_category_values(self):
        assert CspmCategory.IAM.value == "iam"
        assert CspmCategory.STORAGE.value == "storage"
        assert CspmCategory.NETWORK.value == "network"
        assert CspmCategory.ENCRYPTION.value == "encryption"
        assert CspmCategory.LOGGING.value == "logging"
        assert CspmCategory.COMPUTE.value == "compute"
        assert CspmCategory.DATABASE.value == "database"
        assert CspmCategory.CONTAINER.value == "container"
        assert CspmCategory.SERVERLESS.value == "serverless"


class TestCspmFinding:
    def test_to_dict(self):
        f = CspmFinding(
            finding_id="CSPM-test",
            title="Test Finding",
            severity=CspmSeverity.HIGH,
            category=CspmCategory.STORAGE,
            provider=CloudProvider.AWS,
            resource_type="s3",
            resource_id="my-bucket",
            region="us-east-1",
            cis_benchmark="CIS-AWS-2.1.5",
            description="Test",
            recommendation="Fix it",
            compliance_frameworks=["SOC2-CC6.1"],
        )
        d = f.to_dict()
        assert d["finding_id"] == "CSPM-test"
        assert d["severity"] == "high"
        assert d["category"] == "storage"
        assert d["provider"] == "aws"
        assert d["resource_type"] == "s3"
        assert d["resource_id"] == "my-bucket"
        assert d["region"] == "us-east-1"
        assert d["cis_benchmark"] == "CIS-AWS-2.1.5"
        assert d["compliance_frameworks"] == ["SOC2-CC6.1"]
        assert "timestamp" in d
        assert d["confidence"] == 0.9  # default

    def test_default_values(self):
        f = CspmFinding(
            finding_id="test",
            title="t",
            severity=CspmSeverity.LOW,
            category=CspmCategory.IAM,
            provider=CloudProvider.GCP,
            resource_type="iam",
            resource_id="r1",
        )
        assert f.region == ""
        assert f.cis_benchmark == ""
        assert f.compliance_frameworks == []
        assert f.confidence == 0.9


class TestCspmScanResult:
    def test_to_dict(self):
        result = CspmScanResult(
            scan_id="cspm-123",
            provider="aws",
            resources_scanned=10,
            total_findings=2,
            findings=[],
            by_severity={"critical": 1, "high": 1},
            by_category={"storage": 1, "network": 1},
            compliance_score=80.0,
            duration_ms=42.5,
        )
        d = result.to_dict()
        assert d["scan_id"] == "cspm-123"
        assert d["provider"] == "aws"
        assert d["resources_scanned"] == 10
        assert d["total_findings"] == 2
        assert d["compliance_score"] == 80.0
        assert "timestamp" in d


# ── Rules Inventory Tests ───────────────────────────────────────────


class TestRules:
    def test_aws_rules_count(self):
        assert len(AWS_RULES) == 40

    def test_azure_rules_count(self):
        assert len(AZURE_RULES) == 25

    def test_gcp_rules_count(self):
        assert len(GCP_RULES) == 20

    def test_all_rules_mapping(self):
        assert CloudProvider.AWS in ALL_RULES
        assert CloudProvider.AZURE in ALL_RULES
        assert CloudProvider.GCP in ALL_RULES

    def test_rule_structure(self):
        for rules in [AWS_RULES, AZURE_RULES, GCP_RULES]:
            for rule in rules:
                assert len(rule) == 8
                rid, title, sev, cwe, cat, desc, rec, frameworks = rule
                assert isinstance(rid, str)
                assert isinstance(title, str)
                assert sev in ("critical", "high", "medium", "low", "info")
                assert cwe.startswith("CWE-")
                assert isinstance(frameworks, list)

    def test_aws_rules_have_compliance(self):
        for rule in AWS_RULES:
            assert len(rule[7]) > 0, f"Rule {rule[0]} has no compliance frameworks"


# ── Provider Detection Tests ────────────────────────────────────────


class TestProviderDetection:
    def test_detect_aws(self, engine):
        assert engine._detect_provider_tf('provider "aws" {}') == CloudProvider.AWS

    def test_detect_aws_resource(self, engine):
        assert engine._detect_provider_tf('resource "aws_s3_bucket" "b" {}') == CloudProvider.AWS

    def test_detect_azure(self, engine):
        assert engine._detect_provider_tf('provider "azurerm" { features {} }') == CloudProvider.AZURE

    def test_detect_azure_resource(self, engine):
        assert engine._detect_provider_tf('resource "azurerm_storage_account" "a" {}') == CloudProvider.AZURE

    def test_detect_gcp(self, engine):
        assert engine._detect_provider_tf('provider "google" { project = "p" }') == CloudProvider.GCP

    def test_detect_gcp_resource(self, engine):
        assert engine._detect_provider_tf('resource "google_compute_instance" "i" {}') == CloudProvider.GCP

    def test_default_aws(self, engine):
        assert engine._detect_provider_tf("something else") == CloudProvider.AWS


# ── Terraform Scanning Tests ────────────────────────────────────────


class TestScanTerraform:
    def test_secure_config(self, engine, tf_aws_secure):
        result = engine.scan_terraform(tf_aws_secure)
        assert isinstance(result, CspmScanResult)
        assert result.total_findings == 0
        assert result.compliance_score == 100.0
        assert result.provider == "aws"
        assert result.resources_scanned >= 3

    def test_insecure_config_finds_issues(self, engine, tf_aws_insecure):
        result = engine.scan_terraform(tf_aws_insecure)
        assert result.total_findings >= 4
        titles = [f.title for f in result.findings]
        # Should find S3 public, SG open, EBS unencrypted, RDS public, IAM wildcard, no CloudTrail
        assert any("Public" in t or "public" in t.lower() for t in titles)

    def test_insecure_severities(self, engine, tf_aws_insecure):
        result = engine.scan_terraform(tf_aws_insecure)
        assert "critical" in result.by_severity or "high" in result.by_severity

    def test_insecure_categories(self, engine, tf_aws_insecure):
        result = engine.scan_terraform(tf_aws_insecure)
        categories = set(result.by_category.keys())
        assert len(categories) >= 2

    def test_compliance_score_decreases(self, engine, tf_aws_insecure):
        result = engine.scan_terraform(tf_aws_insecure)
        assert result.compliance_score < 100.0

    def test_scan_id_format(self, engine, tf_aws_secure):
        result = engine.scan_terraform(tf_aws_secure)
        assert result.scan_id.startswith("cspm-")

    def test_duration_measured(self, engine, tf_aws_secure):
        result = engine.scan_terraform(tf_aws_secure)
        assert result.duration_ms >= 0

    def test_azure_provider_detected(self, engine, tf_azure):
        result = engine.scan_terraform(tf_azure)
        assert result.provider == "azure"

    def test_gcp_provider_detected(self, engine, tf_gcp):
        result = engine.scan_terraform(tf_gcp)
        assert result.provider == "gcp"

    def test_s3_public_read(self, engine):
        tf = '''
resource "aws_s3_bucket" "b" {
  acl = "public-read"
}
'''
        result = engine.scan_terraform(tf)
        assert result.total_findings >= 1
        sev = [f.severity for f in result.findings]
        assert CspmSeverity.CRITICAL in sev

    def test_security_group_open(self, engine):
        tf = '''
resource "aws_security_group" "sg" {
  ingress {
    cidr_blocks = ["0.0.0.0/0"]
  }
}
'''
        result = engine.scan_terraform(tf)
        found_network = any(f.category == CspmCategory.NETWORK for f in result.findings)
        assert found_network

    def test_unencrypted_ebs(self, engine):
        tf = '''
resource "aws_ebs_volume" "vol" {
  availability_zone = "us-east-1a"
  size = 40
}
'''
        result = engine.scan_terraform(tf)
        found_enc = any(f.category == CspmCategory.ENCRYPTION for f in result.findings)
        assert found_enc

    def test_rds_public(self, engine):
        tf = '''
resource "aws_db_instance" "db" {
  publicly_accessible = true
}
'''
        result = engine.scan_terraform(tf)
        found_db = any(f.category == CspmCategory.DATABASE for f in result.findings)
        assert found_db

    def test_iam_wildcard(self, engine):
        tf = '''
resource "aws_iam_policy" "admin" {
  policy = <<POLICY
{"Statement": [{"Action": "*", "Resource": "*"}]}
POLICY
}
'''
        result = engine.scan_terraform(tf)
        found_iam = any(f.category == CspmCategory.IAM for f in result.findings)
        assert found_iam

    def test_no_cloudtrail(self, engine):
        tf = '''
provider "aws" {}
resource "aws_s3_bucket" "b" {
  acl = "private"
}
'''
        result = engine.scan_terraform(tf)
        found_log = any(f.category == CspmCategory.LOGGING for f in result.findings)
        assert found_log

    def test_empty_tf(self, engine):
        result = engine.scan_terraform("")
        assert isinstance(result, CspmScanResult)
        assert result.resources_scanned >= 1  # max(0, 1)

    def test_finding_to_dict(self, engine, tf_aws_insecure):
        result = engine.scan_terraform(tf_aws_insecure)
        for f in result.findings:
            d = f.to_dict()
            assert "finding_id" in d
            assert "severity" in d
            assert "category" in d
            assert "provider" in d

    def test_result_to_dict(self, engine, tf_aws_insecure):
        result = engine.scan_terraform(tf_aws_insecure)
        d = result.to_dict()
        assert "scan_id" in d
        assert "findings" in d
        assert isinstance(d["findings"], list)


# ── CloudFormation Scanning Tests ───────────────────────────────────


class TestScanCloudFormation:
    def test_clean_template(self, engine, cf_clean):
        result = engine.scan_cloudformation(cf_clean)
        assert isinstance(result, CspmScanResult)
        assert result.total_findings == 0
        assert result.provider == "aws"
        assert result.resources_scanned == 2

    def test_insecure_template(self, engine, cf_insecure):
        result = engine.scan_cloudformation(cf_insecure)
        assert result.total_findings >= 2
        titles = [f.title for f in result.findings]
        assert any("S3" in t or "Public" in t for t in titles)

    def test_cf_s3_public(self, engine):
        cf = json.dumps({
            "Resources": {
                "Bucket": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": {"AccessControl": "PublicRead"},
                }
            }
        })
        result = engine.scan_cloudformation(cf)
        assert result.total_findings >= 1

    def test_cf_sg_open(self, engine):
        cf = json.dumps({
            "Resources": {
                "SG": {
                    "Type": "AWS::EC2::SecurityGroup",
                    "Properties": {
                        "SecurityGroupIngress": [
                            {"CidrIp": "0.0.0.0/0", "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22}
                        ]
                    },
                }
            }
        })
        result = engine.scan_cloudformation(cf)
        assert result.total_findings >= 1
        assert any(f.category == CspmCategory.NETWORK for f in result.findings)

    def test_cf_rds_public(self, engine):
        cf = json.dumps({
            "Resources": {
                "DB": {
                    "Type": "AWS::RDS::DBInstance",
                    "Properties": {"PubliclyAccessible": True, "Engine": "mysql"},
                }
            }
        })
        result = engine.scan_cloudformation(cf)
        assert result.total_findings >= 1
        assert any(f.category == CspmCategory.DATABASE for f in result.findings)

    def test_invalid_json(self, engine):
        result = engine.scan_cloudformation("not valid json {{{")
        assert isinstance(result, CspmScanResult)
        assert result.total_findings == 0
        assert result.resources_scanned == 0

    def test_empty_resources(self, engine):
        cf = json.dumps({"Resources": {}})
        result = engine.scan_cloudformation(cf)
        assert result.total_findings == 0

    def test_compliance_score(self, engine, cf_insecure):
        result = engine.scan_cloudformation(cf_insecure)
        assert 0 <= result.compliance_score <= 100

    def test_scan_id_format(self, engine, cf_clean):
        result = engine.scan_cloudformation(cf_clean)
        assert result.scan_id.startswith("cspm-")


# ── Make Finding Tests ──────────────────────────────────────────────


class TestMakeFinding:
    def test_creates_valid_finding(self, engine):
        rule = AWS_RULES[0]  # S3 Public Access
        finding = engine._make_finding(rule, CloudProvider.AWS, "my-bucket")
        assert isinstance(finding, CspmFinding)
        assert finding.severity == CspmSeverity.CRITICAL
        assert finding.provider == CloudProvider.AWS
        assert finding.resource_id == "my-bucket"
        assert finding.finding_id.startswith("CSPM-")
        assert len(finding.compliance_frameworks) > 0

    def test_azure_finding(self, engine):
        rule = AZURE_RULES[0]
        finding = engine._make_finding(rule, CloudProvider.AZURE, "storageacct")
        assert finding.provider == CloudProvider.AZURE

    def test_gcp_finding(self, engine):
        rule = GCP_RULES[0]
        finding = engine._make_finding(rule, CloudProvider.GCP, "bucket-1")
        assert finding.provider == CloudProvider.GCP


# ── Summarize Tests ─────────────────────────────────────────────────


class TestSummarize:
    def test_empty_findings(self):
        by_sev, by_cat = CSPMEngine._summarize([])
        assert by_sev == {}
        assert by_cat == {}

    def test_counts_severities(self, engine):
        findings = [
            engine._make_finding(AWS_RULES[0], CloudProvider.AWS, "r1"),  # critical
            engine._make_finding(AWS_RULES[0], CloudProvider.AWS, "r2"),  # critical
            engine._make_finding(AWS_RULES[2], CloudProvider.AWS, "r3"),  # high
        ]
        by_sev, by_cat = CSPMEngine._summarize(findings)
        assert by_sev.get("critical", 0) == 2
        assert by_sev.get("high", 0) == 1


# ── Singleton Tests ─────────────────────────────────────────────────


class TestSingleton:
    def test_get_cspm_engine_returns_engine(self):
        e = get_cspm_engine()
        assert isinstance(e, CSPMEngine)

    def test_get_cspm_engine_singleton(self):
        e1 = get_cspm_engine()
        e2 = get_cspm_engine()
        assert e1 is e2


# ── SDK Availability Tests ──────────────────────────────────────────


class TestSDKDetection:
    def test_init_doesnt_crash(self):
        """Engine should initialize even without cloud SDKs."""
        engine = CSPMEngine()
        assert isinstance(engine, CSPMEngine)

    def test_sdk_flags_are_bools(self):
        engine = CSPMEngine()
        assert isinstance(engine._boto3_available, bool)
        assert isinstance(engine._azure_available, bool)
        assert isinstance(engine._gcp_available, bool)
