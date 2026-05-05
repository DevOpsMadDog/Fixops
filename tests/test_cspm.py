"""Tests for the CSPM Engine (Cloud Security Posture Management).

Covers:
- CloudResource model validation
- CIS Benchmark rule evaluation (AWS, Azure, GCP)
- Scan engine: scan_resource, run_scan
- Finding CRUD: list, get, suppress, resolve
- Drift detection
- Remediation playbook generation
- Risk and posture scoring
- Compliance mapping
- Benchmark status
- Resource inventory CRUD
- Baseline management
- Singleton factory

Run with:
    python -m pytest tests/test_cspm.py -x --tb=short --timeout=10 -q
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict

import pytest

# Make suite-core importable without installing the package
sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))

# All tests in this file are skipped: they were written against a posture-management
# API (CloudResource, CISBenchmarkRule, etc.) that was replaced by an IaC/HCL
# scanner API. See docs/test_collection_triage_2026-05-05.md for the rewrite plan.
pytestmark = pytest.mark.skip(
    reason="API changed — cspm_engine.py is now an IaC scanner; "
    "tests written against removed posture-management API; "
    "rewrite needed (see docs/test_collection_triage_2026-05-05.md)"
)

# NOTE: test_cspm.py was written against a posture-management API that was replaced
# by an IaC/HCL scanner API at an earlier commit. All symbols below except
# CloudProvider, CSPMEngine, and get_cspm_engine no longer exist in cspm_engine.py.
# Every test class is skipped until the tests are rewritten against the current API.
# See docs/test_collection_triage_2026-05-05.md for the rewrite plan.

from core.cspm_engine import (
    CloudProvider,
    CSPMEngine,
    get_cspm_engine,
)

# Stub out removed symbols so fixtures/class bodies still parse without NameError.
class _RemovedSymbol:
    """Placeholder for a symbol removed from cspm_engine.py."""
    pass

CISBenchmarkRule = _RemovedSymbol
CloudResource = _RemovedSymbol
ComplianceFramework = _RemovedSymbol
CSPMFinding = _RemovedSymbol
DriftEvent = _RemovedSymbol
FindingStatus = _RemovedSymbol
OrgPosture = _RemovedSymbol
RemediationPlaybook = _RemovedSymbol
ResourceType = _RemovedSymbol
ScanResult = _RemovedSymbol
Severity = _RemovedSymbol
_CIS_RULES: list = []
_RULES_BY_ID: dict = {}

def _build_playbook(*a, **kw):  # type: ignore[no-untyped-def]
    raise NotImplementedError("API removed")

def _compliance_score(*a, **kw):  # type: ignore[no-untyped-def]
    raise NotImplementedError("API removed")

def _detect_drift(*a, **kw):  # type: ignore[no-untyped-def]
    raise NotImplementedError("API removed")

def _evaluate_rule(*a, **kw):  # type: ignore[no-untyped-def]
    raise NotImplementedError("API removed")

def _get_applicable_rules(*a, **kw):  # type: ignore[no-untyped-def]
    raise NotImplementedError("API removed")

def _posture_score(*a, **kw):  # type: ignore[no-untyped-def]
    raise NotImplementedError("API removed")

def _score_from_findings(*a, **kw):  # type: ignore[no-untyped-def]
    raise NotImplementedError("API removed")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine(tmp_path):
    """CSPMEngine backed by a temp SQLite DB."""
    return CSPMEngine(db_path=str(tmp_path / "cspm_test.db"))


@pytest.fixture
def aws_s3_public(engine) -> CloudResource:
    res = CloudResource(
        provider=CloudProvider.AWS,
        resource_type=ResourceType.S3_BUCKET,
        name="my-public-bucket",
        account_id="123456789",
        org_id="test-org",
        is_public=True,
        is_encrypted=False,
        metadata={"mfa_delete_enabled": False, "access_logging_enabled": False},
    )
    engine.register_resource(res)
    return res


@pytest.fixture
def aws_s3_compliant(engine) -> CloudResource:
    res = CloudResource(
        provider=CloudProvider.AWS,
        resource_type=ResourceType.S3_BUCKET,
        name="my-private-bucket",
        account_id="123456789",
        org_id="test-org",
        is_public=False,
        is_encrypted=True,
        metadata={"mfa_delete_enabled": True, "access_logging_enabled": True},
    )
    engine.register_resource(res)
    return res


@pytest.fixture
def aws_sg_open_ssh(engine) -> CloudResource:
    res = CloudResource(
        provider=CloudProvider.AWS,
        resource_type=ResourceType.SECURITY_GROUP,
        name="sg-open",
        account_id="123456789",
        org_id="test-org",
        metadata={"allows_ssh_from_internet": True, "allows_rdp_from_internet": True,
                  "default_sg_has_rules": True},
    )
    engine.register_resource(res)
    return res


@pytest.fixture
def aws_ec2_insecure(engine) -> CloudResource:
    res = CloudResource(
        provider=CloudProvider.AWS,
        resource_type=ResourceType.EC2_INSTANCE,
        name="i-bad",
        account_id="123456789",
        org_id="test-org",
        is_public=True,
        is_encrypted=False,
        metadata={"imdsv2_required": False, "ssm_managed": False},
    )
    engine.register_resource(res)
    return res


@pytest.fixture
def aws_rds_bad(engine) -> CloudResource:
    res = CloudResource(
        provider=CloudProvider.AWS,
        resource_type=ResourceType.RDS_INSTANCE,
        name="db-prod",
        account_id="123456789",
        org_id="test-org",
        is_public=True,
        is_encrypted=False,
        metadata={"backup_retention_days": 0, "auto_minor_version_upgrade": False},
    )
    engine.register_resource(res)
    return res


@pytest.fixture
def azure_storage_bad(engine) -> CloudResource:
    res = CloudResource(
        provider=CloudProvider.AZURE,
        resource_type=ResourceType.STORAGE_ACCOUNT,
        name="storageacc",
        account_id="sub-001",
        org_id="test-org",
        is_public=True,
        metadata={"https_only": False, "customer_managed_key": False, "soft_delete_enabled": False},
    )
    engine.register_resource(res)
    return res


@pytest.fixture
def gcp_gcs_bad(engine) -> CloudResource:
    res = CloudResource(
        provider=CloudProvider.GCP,
        resource_type=ResourceType.GCS_BUCKET,
        name="gcs-bucket",
        account_id="project-xyz",
        org_id="test-org",
        is_public=True,
        metadata={"uniform_bucket_access": False, "customer_managed_key": False},
    )
    engine.register_resource(res)
    return res


# ---------------------------------------------------------------------------
# 1. Model validation
# ---------------------------------------------------------------------------

class TestCloudResourceModel:
    def test_id_auto_generated(self):
        res = CloudResource(
            provider=CloudProvider.AWS,
            resource_type=ResourceType.S3_BUCKET,
            name="bucket",
        )
        assert res.id.startswith("res-")

    def test_default_values(self):
        res = CloudResource(
            provider=CloudProvider.GCP,
            resource_type=ResourceType.GCS_BUCKET,
            name="test",
        )
        assert res.is_encrypted is True
        assert res.is_public is False
        assert res.org_id == "default"
        assert res.region == "global"

    def test_metadata_dict(self):
        res = CloudResource(
            provider=CloudProvider.AZURE,
            resource_type=ResourceType.STORAGE_ACCOUNT,
            name="s",
            metadata={"https_only": True},
        )
        assert res.metadata["https_only"] is True

    def test_tags(self):
        res = CloudResource(
            provider=CloudProvider.AWS,
            resource_type=ResourceType.EC2_INSTANCE,
            name="i-1",
            tags={"env": "prod", "team": "security"},
        )
        assert res.tags["env"] == "prod"

    def test_model_dump_roundtrip(self):
        res = CloudResource(
            provider=CloudProvider.AWS,
            resource_type=ResourceType.VPC,
            name="vpc-1",
        )
        dumped = res.model_dump_json()
        restored = CloudResource.model_validate_json(dumped)
        assert restored.id == res.id
        assert restored.provider == CloudProvider.AWS


# ---------------------------------------------------------------------------
# 2. CIS Rule catalogue
# ---------------------------------------------------------------------------

class TestCISRuleCatalogue:
    def test_minimum_rule_count(self):
        assert len(_CIS_RULES) >= 50

    def test_all_providers_covered(self):
        providers = {r.provider for r in _CIS_RULES}
        assert CloudProvider.AWS in providers
        assert CloudProvider.AZURE in providers
        assert CloudProvider.GCP in providers

    def test_rules_by_id_lookup(self):
        assert "aws-s3-2.1" in _RULES_BY_ID
        assert "aws-net-3.1" in _RULES_BY_ID
        assert "azure-stor-2.1" in _RULES_BY_ID
        assert "gcp-gcs-2.1" in _RULES_BY_ID

    def test_rules_have_compliance_mapping(self):
        for rule in _CIS_RULES:
            assert isinstance(rule.compliance_mapping, dict)

    def test_critical_rules_exist(self):
        critical = [r for r in _CIS_RULES if r.severity == Severity.CRITICAL]
        assert len(critical) >= 5

    def test_remediation_cli_populated(self):
        rule = _RULES_BY_ID["aws-s3-2.1"]
        assert rule.remediation_cli is not None
        assert "aws s3api" in rule.remediation_cli

    def test_terraform_block_on_s3(self):
        rule = _RULES_BY_ID["aws-s3-2.1"]
        assert rule.remediation_terraform is not None
        assert "aws_s3_bucket" in rule.remediation_terraform


# ---------------------------------------------------------------------------
# 3. Rule evaluation — AWS IAM
# ---------------------------------------------------------------------------

class TestAWSIAMRules:
    def test_root_account_passes_when_not_root(self):
        res = CloudResource(provider=CloudProvider.AWS, resource_type=ResourceType.IAM_USER,
                            name="alice", metadata={"is_root": False})
        rule = _RULES_BY_ID["aws-iam-1.1"]
        assert _evaluate_rule(rule, res) is True

    def test_root_account_fails_when_root(self):
        res = CloudResource(provider=CloudProvider.AWS, resource_type=ResourceType.IAM_USER,
                            name="root", metadata={"is_root": True})
        rule = _RULES_BY_ID["aws-iam-1.1"]
        assert _evaluate_rule(rule, res) is False

    def test_mfa_root_passes_with_mfa(self):
        res = CloudResource(provider=CloudProvider.AWS, resource_type=ResourceType.IAM_USER,
                            name="root", metadata={"is_root": True, "mfa_enabled": True})
        assert _evaluate_rule(_RULES_BY_ID["aws-iam-1.2"], res) is True

    def test_mfa_root_fails_without_mfa(self):
        res = CloudResource(provider=CloudProvider.AWS, resource_type=ResourceType.IAM_USER,
                            name="root", metadata={"is_root": True, "mfa_enabled": False})
        assert _evaluate_rule(_RULES_BY_ID["aws-iam-1.2"], res) is False

    def test_key_rotation_passes_within_90_days(self):
        res = CloudResource(provider=CloudProvider.AWS, resource_type=ResourceType.IAM_USER,
                            name="bob", metadata={"access_key_age_days": 45})
        assert _evaluate_rule(_RULES_BY_ID["aws-iam-1.4"], res) is True

    def test_key_rotation_fails_over_90_days(self):
        res = CloudResource(provider=CloudProvider.AWS, resource_type=ResourceType.IAM_USER,
                            name="bob", metadata={"access_key_age_days": 120})
        assert _evaluate_rule(_RULES_BY_ID["aws-iam-1.4"], res) is False

    def test_password_policy_passes_14_chars(self):
        res = CloudResource(provider=CloudProvider.AWS, resource_type=ResourceType.IAM_POLICY,
                            name="policy", metadata={"min_password_length": 16})
        assert _evaluate_rule(_RULES_BY_ID["aws-iam-1.5"], res) is True

    def test_password_policy_fails_short(self):
        res = CloudResource(provider=CloudProvider.AWS, resource_type=ResourceType.IAM_POLICY,
                            name="policy", metadata={"min_password_length": 8})
        assert _evaluate_rule(_RULES_BY_ID["aws-iam-1.5"], res) is False


# ---------------------------------------------------------------------------
# 4. Rule evaluation — AWS S3
# ---------------------------------------------------------------------------

class TestAWSS3Rules:
    def test_public_bucket_fails(self):
        res = CloudResource(provider=CloudProvider.AWS, resource_type=ResourceType.S3_BUCKET,
                            name="pub", is_public=True)
        assert _evaluate_rule(_RULES_BY_ID["aws-s3-2.1"], res) is False

    def test_private_bucket_passes(self):
        res = CloudResource(provider=CloudProvider.AWS, resource_type=ResourceType.S3_BUCKET,
                            name="priv", is_public=False)
        assert _evaluate_rule(_RULES_BY_ID["aws-s3-2.1"], res) is True

    def test_unencrypted_bucket_fails(self):
        res = CloudResource(provider=CloudProvider.AWS, resource_type=ResourceType.S3_BUCKET,
                            name="s3", is_encrypted=False)
        assert _evaluate_rule(_RULES_BY_ID["aws-s3-2.2"], res) is False

    def test_mfa_delete_passes(self):
        res = CloudResource(provider=CloudProvider.AWS, resource_type=ResourceType.S3_BUCKET,
                            name="s3", metadata={"mfa_delete_enabled": True})
        assert _evaluate_rule(_RULES_BY_ID["aws-s3-2.3"], res) is True

    def test_access_logging_passes(self):
        res = CloudResource(provider=CloudProvider.AWS, resource_type=ResourceType.S3_BUCKET,
                            name="s3", metadata={"access_logging_enabled": True})
        assert _evaluate_rule(_RULES_BY_ID["aws-s3-2.4"], res) is True


# ---------------------------------------------------------------------------
# 5. Rule evaluation — AWS Network
# ---------------------------------------------------------------------------

class TestAWSNetworkRules:
    def test_open_ssh_fails(self):
        res = CloudResource(provider=CloudProvider.AWS, resource_type=ResourceType.SECURITY_GROUP,
                            name="sg", metadata={"allows_ssh_from_internet": True})
        assert _evaluate_rule(_RULES_BY_ID["aws-net-3.1"], res) is False

    def test_closed_ssh_passes(self):
        res = CloudResource(provider=CloudProvider.AWS, resource_type=ResourceType.SECURITY_GROUP,
                            name="sg", metadata={"allows_ssh_from_internet": False})
        assert _evaluate_rule(_RULES_BY_ID["aws-net-3.1"], res) is True

    def test_open_rdp_fails(self):
        res = CloudResource(provider=CloudProvider.AWS, resource_type=ResourceType.SECURITY_GROUP,
                            name="sg", metadata={"allows_rdp_from_internet": True})
        assert _evaluate_rule(_RULES_BY_ID["aws-net-3.2"], res) is False

    def test_vpc_flow_logs_passes(self):
        res = CloudResource(provider=CloudProvider.AWS, resource_type=ResourceType.VPC,
                            name="vpc", metadata={"flow_logs_enabled": True})
        assert _evaluate_rule(_RULES_BY_ID["aws-net-3.3"], res) is True

    def test_vpc_flow_logs_fails(self):
        res = CloudResource(provider=CloudProvider.AWS, resource_type=ResourceType.VPC,
                            name="vpc", metadata={"flow_logs_enabled": False})
        assert _evaluate_rule(_RULES_BY_ID["aws-net-3.3"], res) is False


# ---------------------------------------------------------------------------
# 6. Rule evaluation — AWS Compute
# ---------------------------------------------------------------------------

class TestAWSComputeRules:
    def test_imdsv2_required_passes(self):
        res = CloudResource(provider=CloudProvider.AWS, resource_type=ResourceType.EC2_INSTANCE,
                            name="i-1", metadata={"imdsv2_required": True})
        assert _evaluate_rule(_RULES_BY_ID["aws-ec2-4.1"], res) is True

    def test_imdsv2_not_required_fails(self):
        res = CloudResource(provider=CloudProvider.AWS, resource_type=ResourceType.EC2_INSTANCE,
                            name="i-1", metadata={"imdsv2_required": False})
        assert _evaluate_rule(_RULES_BY_ID["aws-ec2-4.1"], res) is False

    def test_public_ec2_fails(self):
        res = CloudResource(provider=CloudProvider.AWS, resource_type=ResourceType.EC2_INSTANCE,
                            name="i-1", is_public=True)
        assert _evaluate_rule(_RULES_BY_ID["aws-ec2-4.2"], res) is False

    def test_ebs_encryption_fails(self):
        res = CloudResource(provider=CloudProvider.AWS, resource_type=ResourceType.EC2_INSTANCE,
                            name="i-1", is_encrypted=False)
        assert _evaluate_rule(_RULES_BY_ID["aws-ec2-4.3"], res) is False


# ---------------------------------------------------------------------------
# 7. Rule evaluation — Azure
# ---------------------------------------------------------------------------

class TestAzureRules:
    def test_azure_mfa_fails_without_mfa(self):
        res = CloudResource(provider=CloudProvider.AZURE, resource_type=ResourceType.IAM_USER,
                            name="admin", metadata={"mfa_enabled": False})
        assert _evaluate_rule(_RULES_BY_ID["azure-iam-1.1"], res) is False

    def test_azure_storage_public_fails(self):
        res = CloudResource(provider=CloudProvider.AZURE, resource_type=ResourceType.STORAGE_ACCOUNT,
                            name="acc", is_public=True)
        assert _evaluate_rule(_RULES_BY_ID["azure-stor-2.1"], res) is False

    def test_azure_https_only_passes(self):
        res = CloudResource(provider=CloudProvider.AZURE, resource_type=ResourceType.STORAGE_ACCOUNT,
                            name="acc", metadata={"https_only": True})
        assert _evaluate_rule(_RULES_BY_ID["azure-stor-2.2"], res) is True

    def test_azure_open_ssh_fails(self):
        res = CloudResource(provider=CloudProvider.AZURE, resource_type=ResourceType.NETWORK_ACL,
                            name="nsg", metadata={"allows_ssh_from_internet": True})
        assert _evaluate_rule(_RULES_BY_ID["azure-net-3.1"], res) is False

    def test_azure_log_retention_passes(self):
        res = CloudResource(provider=CloudProvider.AZURE, resource_type=ResourceType.AZURE_MONITOR,
                            name="monitor", metadata={"log_retention_days": 400})
        assert _evaluate_rule(_RULES_BY_ID["azure-log-6.2"], res) is True

    def test_azure_log_retention_fails_short(self):
        res = CloudResource(provider=CloudProvider.AZURE, resource_type=ResourceType.AZURE_MONITOR,
                            name="monitor", metadata={"log_retention_days": 90})
        assert _evaluate_rule(_RULES_BY_ID["azure-log-6.2"], res) is False


# ---------------------------------------------------------------------------
# 8. Rule evaluation — GCP
# ---------------------------------------------------------------------------

class TestGCPRules:
    def test_gcp_public_bucket_fails(self):
        res = CloudResource(provider=CloudProvider.GCP, resource_type=ResourceType.GCS_BUCKET,
                            name="bucket", is_public=True)
        assert _evaluate_rule(_RULES_BY_ID["gcp-gcs-2.1"], res) is False

    def test_gcp_private_bucket_passes(self):
        res = CloudResource(provider=CloudProvider.GCP, resource_type=ResourceType.GCS_BUCKET,
                            name="bucket", is_public=False)
        assert _evaluate_rule(_RULES_BY_ID["gcp-gcs-2.1"], res) is True

    def test_gcp_service_account_key_age_passes(self):
        res = CloudResource(provider=CloudProvider.GCP, resource_type=ResourceType.IAM_USER,
                            name="sa", metadata={"key_age_days": 30})
        assert _evaluate_rule(_RULES_BY_ID["gcp-iam-1.1"], res) is True

    def test_gcp_service_account_key_age_fails(self):
        res = CloudResource(provider=CloudProvider.GCP, resource_type=ResourceType.IAM_USER,
                            name="sa", metadata={"key_age_days": 100})
        assert _evaluate_rule(_RULES_BY_ID["gcp-iam-1.1"], res) is False

    def test_gcp_firewall_ssh_fails(self):
        res = CloudResource(provider=CloudProvider.GCP, resource_type=ResourceType.SECURITY_GROUP,
                            name="fw", metadata={"allows_ssh_from_internet": True})
        assert _evaluate_rule(_RULES_BY_ID["gcp-net-3.1"], res) is False

    def test_gcp_flow_logs_passes(self):
        res = CloudResource(provider=CloudProvider.GCP, resource_type=ResourceType.VPC,
                            name="vpc", metadata={"flow_logs_enabled": True})
        assert _evaluate_rule(_RULES_BY_ID["gcp-net-3.2"], res) is True

    def test_gcp_shielded_vm_passes(self):
        res = CloudResource(provider=CloudProvider.GCP, resource_type=ResourceType.COMPUTE_INSTANCE,
                            name="vm", metadata={"shielded_vm_enabled": True})
        assert _evaluate_rule(_RULES_BY_ID["gcp-compute-4.2"], res) is True


# ---------------------------------------------------------------------------
# 9. scan_resource
# ---------------------------------------------------------------------------

class TestScanResource:
    def test_public_s3_generates_findings(self, engine, aws_s3_public):
        findings = engine.scan_resource(aws_s3_public)
        rule_ids = [f.rule_id for f in findings]
        assert "aws-s3-2.1" in rule_ids
        assert "aws-s3-2.2" in rule_ids

    def test_compliant_s3_generates_no_public_finding(self, engine, aws_s3_compliant):
        findings = engine.scan_resource(aws_s3_compliant)
        rule_ids = [f.rule_id for f in findings]
        assert "aws-s3-2.1" not in rule_ids
        assert "aws-s3-2.2" not in rule_ids

    def test_open_sg_generates_critical_findings(self, engine, aws_sg_open_ssh):
        findings = engine.scan_resource(aws_sg_open_ssh)
        rule_ids = [f.rule_id for f in findings]
        assert "aws-net-3.1" in rule_ids
        assert "aws-net-3.2" in rule_ids

    def test_findings_stored_in_db(self, engine, aws_s3_public):
        engine.scan_resource(aws_s3_public)
        stored = engine.list_findings("test-org")
        assert len(stored) >= 1

    def test_finding_has_correct_severity(self, engine, aws_s3_public):
        findings = engine.scan_resource(aws_s3_public)
        public_finding = next(f for f in findings if f.rule_id == "aws-s3-2.1")
        assert public_finding.severity == Severity.CRITICAL

    def test_finding_has_remediation(self, engine, aws_s3_public):
        findings = engine.scan_resource(aws_s3_public)
        public_finding = next(f for f in findings if f.rule_id == "aws-s3-2.1")
        assert public_finding.remediation_summary
        assert public_finding.remediation_cli


# ---------------------------------------------------------------------------
# 10. run_scan
# ---------------------------------------------------------------------------

class TestRunScan:
    def test_scan_returns_scan_result(self, engine, aws_s3_public):
        result = engine.run_scan(org_id="test-org")
        assert isinstance(result, ScanResult)

    def test_scan_counts_resources(self, engine, aws_s3_public, aws_sg_open_ssh):
        result = engine.run_scan(org_id="test-org")
        assert result.resources_scanned == 2

    def test_scan_posture_score_is_low_for_bad_resources(self, engine, aws_s3_public, aws_ec2_insecure):
        result = engine.run_scan(org_id="test-org")
        assert result.posture.overall_score < 80

    def test_scan_with_rule_id_filter(self, engine, aws_s3_public):
        result = engine.run_scan(org_id="test-org", rule_ids=["aws-s3-2.1"])
        rule_ids = [f.rule_id for f in engine.list_findings("test-org")]
        # Filter applied — only the specified rule should generate findings
        assert "aws-s3-2.1" in rule_ids

    def test_scan_saves_result(self, engine, aws_s3_public):
        engine.run_scan(org_id="test-org")
        scans = engine.list_scans(org_id="test-org")
        assert len(scans) >= 1


# ---------------------------------------------------------------------------
# 11. Finding management
# ---------------------------------------------------------------------------

class TestFindingManagement:
    def test_list_findings_empty_initially(self, engine):
        assert engine.list_findings("new-org") == []

    def test_get_finding_by_id(self, engine, aws_s3_public):
        findings = engine.scan_resource(aws_s3_public)
        fid = findings[0].id
        retrieved = engine.get_finding(fid)
        assert retrieved is not None
        assert retrieved.id == fid

    def test_get_nonexistent_finding_returns_none(self, engine):
        assert engine.get_finding("does-not-exist") is None

    def test_suppress_finding(self, engine, aws_s3_public):
        findings = engine.scan_resource(aws_s3_public)
        fid = findings[0].id
        suppressed = engine.suppress_finding(fid, reason="Accepted risk")
        assert suppressed.status == FindingStatus.SUPPRESSED
        assert suppressed.suppression_reason == "Accepted risk"

    def test_resolve_finding(self, engine, aws_s3_public):
        findings = engine.scan_resource(aws_s3_public)
        fid = findings[0].id
        resolved = engine.resolve_finding(fid)
        assert resolved.status == FindingStatus.RESOLVED
        assert resolved.resolved_at is not None

    def test_filter_findings_by_status(self, engine, aws_s3_public):
        findings = engine.scan_resource(aws_s3_public)
        engine.suppress_finding(findings[0].id, "test")
        open_findings = engine.list_findings("test-org", status=FindingStatus.OPEN)
        suppressed = engine.list_findings("test-org", status=FindingStatus.SUPPRESSED)
        assert all(f.status == FindingStatus.OPEN for f in open_findings)
        assert all(f.status == FindingStatus.SUPPRESSED for f in suppressed)

    def test_filter_findings_by_severity(self, engine, aws_s3_public):
        engine.scan_resource(aws_s3_public)
        critical = engine.list_findings("test-org", severity=Severity.CRITICAL)
        assert all(f.severity == Severity.CRITICAL for f in critical)


# ---------------------------------------------------------------------------
# 12. Resource inventory
# ---------------------------------------------------------------------------

class TestResourceInventory:
    def test_register_and_list(self, engine):
        res = CloudResource(provider=CloudProvider.AWS, resource_type=ResourceType.VPC,
                            name="vpc-1", org_id="org1")
        engine.register_resource(res)
        resources = engine.list_resources("org1")
        assert len(resources) == 1
        assert resources[0].name == "vpc-1"

    def test_get_resource(self, engine):
        res = CloudResource(provider=CloudProvider.AWS, resource_type=ResourceType.VPC,
                            name="vpc-2", org_id="org1")
        engine.register_resource(res)
        fetched = engine.get_resource(res.id)
        assert fetched is not None
        assert fetched.id == res.id

    def test_get_nonexistent_resource(self, engine):
        assert engine.get_resource("no-such-id") is None

    def test_delete_resource(self, engine):
        res = CloudResource(provider=CloudProvider.AWS, resource_type=ResourceType.VPC,
                            name="vpc-del", org_id="org1")
        engine.register_resource(res)
        deleted = engine.delete_resource(res.id)
        assert deleted is True
        assert engine.get_resource(res.id) is None

    def test_delete_nonexistent_returns_false(self, engine):
        assert engine.delete_resource("no-such") is False

    def test_org_isolation(self, engine):
        res1 = CloudResource(provider=CloudProvider.AWS, resource_type=ResourceType.VPC,
                             name="vpc-a", org_id="org-a")
        res2 = CloudResource(provider=CloudProvider.AWS, resource_type=ResourceType.VPC,
                             name="vpc-b", org_id="org-b")
        engine.register_resource(res1)
        engine.register_resource(res2)
        assert len(engine.list_resources("org-a")) == 1
        assert len(engine.list_resources("org-b")) == 1


# ---------------------------------------------------------------------------
# 13. Drift detection
# ---------------------------------------------------------------------------

class TestDriftDetection:
    def _make_resource(self, **kwargs) -> CloudResource:
        defaults: Dict[str, Any] = {
            "provider": CloudProvider.AWS,
            "resource_type": ResourceType.S3_BUCKET,
            "name": "bucket",
            "account_id": "acct",
            "org_id": "org",
            "is_public": False,
            "is_encrypted": True,
            "metadata": {},
        }
        defaults.update(kwargs)
        return CloudResource(**defaults)

    def test_no_drift_identical(self):
        baseline = self._make_resource()
        current = self._make_resource(id=baseline.id)
        events = _detect_drift(current, baseline, "org")
        assert events == []

    def test_detects_new_public_resource(self):
        baseline = self._make_resource(is_public=False)
        current = self._make_resource(id=baseline.id, is_public=True)
        events = _detect_drift(current, baseline, "org")
        types = [e.drift_type for e in events]
        assert "new_public_resource" in types

    def test_public_drift_is_critical(self):
        baseline = self._make_resource(is_public=False)
        current = self._make_resource(id=baseline.id, is_public=True)
        events = _detect_drift(current, baseline, "org")
        pub_event = next(e for e in events if e.drift_type == "new_public_resource")
        assert pub_event.severity == Severity.CRITICAL

    def test_detects_encryption_removal(self):
        baseline = self._make_resource(is_encrypted=True)
        current = self._make_resource(id=baseline.id, is_encrypted=False)
        events = _detect_drift(current, baseline, "org")
        types = [e.drift_type for e in events]
        assert "encryption_removed" in types

    def test_detects_security_control_disabled(self):
        baseline = self._make_resource(metadata={"flow_logs_enabled": True})
        current = self._make_resource(id=baseline.id, metadata={"flow_logs_enabled": False})
        events = _detect_drift(current, baseline, "org")
        types = [e.drift_type for e in events]
        assert "security_control_disabled" in types

    def test_detects_tag_change(self):
        baseline = self._make_resource()
        baseline.tags = {"env": "prod"}
        current = self._make_resource(id=baseline.id)
        current.tags = {"env": "staging"}
        events = _detect_drift(current, baseline, "org")
        types = [e.drift_type for e in events]
        assert "tags_changed" in types

    def test_engine_drift_stored(self, engine):
        res = CloudResource(provider=CloudProvider.AWS, resource_type=ResourceType.S3_BUCKET,
                            name="b", org_id="driftorg", is_public=False, is_encrypted=True)
        engine.register_resource(res)
        engine.save_baseline("driftorg")
        # Mutate resource to be public
        res2 = CloudResource(id=res.id, provider=CloudProvider.AWS,
                             resource_type=ResourceType.S3_BUCKET, name="b",
                             org_id="driftorg", is_public=True, is_encrypted=True)
        engine.register_resource(res2)
        engine.run_scan(org_id="driftorg")
        drift = engine.list_drift("driftorg")
        assert len(drift) >= 1


# ---------------------------------------------------------------------------
# 14. Remediation playbook
# ---------------------------------------------------------------------------

class TestRemediationPlaybook:
    def test_playbook_generated_for_finding(self, engine, aws_s3_public):
        findings = engine.scan_resource(aws_s3_public)
        fid = next(f.id for f in findings if f.rule_id == "aws-s3-2.1")
        playbook = engine.get_remediation(fid)
        assert isinstance(playbook, RemediationPlaybook)

    def test_playbook_has_steps(self, engine, aws_s3_public):
        findings = engine.scan_resource(aws_s3_public)
        fid = findings[0].id
        playbook = engine.get_remediation(fid)
        assert len(playbook.steps) >= 3

    def test_playbook_cli_commands_populated(self, engine, aws_s3_public):
        findings = engine.scan_resource(aws_s3_public)
        fid = next(f.id for f in findings if f.rule_id == "aws-s3-2.1")
        playbook = engine.get_remediation(fid)
        assert len(playbook.cli_commands) >= 1

    def test_playbook_terraform_for_s3(self, engine, aws_s3_public):
        findings = engine.scan_resource(aws_s3_public)
        fid = next(f.id for f in findings if f.rule_id == "aws-s3-2.1")
        playbook = engine.get_remediation(fid)
        assert len(playbook.terraform_blocks) >= 1

    def test_playbook_nonexistent_finding(self, engine):
        assert engine.get_remediation("no-such") is None

    def test_playbook_risk_level_critical(self, engine, aws_s3_public):
        findings = engine.scan_resource(aws_s3_public)
        fid = next(f.id for f in findings if f.rule_id == "aws-s3-2.1")
        playbook = engine.get_remediation(fid)
        assert playbook.risk_level == "high"

    def test_playbook_rds_requires_downtime(self, engine, aws_rds_bad):
        findings = engine.scan_resource(aws_rds_bad)
        fid = next(f.id for f in findings if f.rule_id == "aws-rds-5.2")
        playbook = engine.get_remediation(fid)
        assert playbook.requires_downtime is True


# ---------------------------------------------------------------------------
# 15. Posture scoring
# ---------------------------------------------------------------------------

class TestPostureScoring:
    def test_score_zero_findings(self):
        assert _score_from_findings(0, 0, 0, 0, 0) == 0.0

    def test_risk_score_all_critical(self):
        score = _score_from_findings(10, 10, 0, 0, 0)
        assert score == 100.0

    def test_posture_score_inverts_risk(self):
        assert _posture_score(0.0) == 100.0
        assert _posture_score(100.0) == 0.0
        assert _posture_score(60.0) == 40.0

    def test_get_posture_empty_org(self, engine):
        posture = engine.get_posture("empty-org")
        assert posture.overall_score == 100.0
        assert posture.total_resources == 0

    def test_get_posture_with_findings(self, engine, aws_s3_public, aws_ec2_insecure):
        engine.run_scan("test-org")
        posture = engine.get_posture("test-org")
        assert posture.total_findings > 0
        assert posture.overall_score < 100.0

    def test_posture_has_account_breakdown(self, engine, aws_s3_public):
        engine.run_scan("test-org")
        posture = engine.get_posture("test-org")
        assert len(posture.accounts) >= 1

    def test_posture_compliance_scores_populated(self, engine, aws_s3_public):
        engine.run_scan("test-org")
        posture = engine.get_posture("test-org")
        assert "soc2" in posture.compliance_scores
        assert "pci_dss" in posture.compliance_scores
        assert "hipaa" in posture.compliance_scores


# ---------------------------------------------------------------------------
# 16. Compliance scoring
# ---------------------------------------------------------------------------

class TestComplianceScoring:
    def test_compliance_score_no_findings(self):
        assert _compliance_score([], ComplianceFramework.SOC2) == 100.0

    def test_compliance_score_decreases_with_violations(self, engine, aws_s3_public):
        findings = engine.scan_resource(aws_s3_public)
        score = _compliance_score(findings, ComplianceFramework.SOC2)
        assert score < 100.0

    def test_compliance_map_has_all_frameworks(self, engine):
        cmap = engine.get_compliance_map()
        fw_keys = set(cmap["frameworks"].keys())
        for fw in ComplianceFramework:
            assert fw.value in fw_keys

    def test_compliance_map_has_rules(self, engine):
        cmap = engine.get_compliance_map()
        assert cmap["total_rules"] > 0
        assert len(cmap["frameworks"]["soc2"]) > 0


# ---------------------------------------------------------------------------
# 17. Benchmark status
# ---------------------------------------------------------------------------

class TestBenchmarkStatus:
    def test_benchmark_status_structure(self, engine):
        status = engine.get_benchmark_status("empty-org")
        assert "total_rules" in status
        assert "total_passing" in status
        assert "total_failing" in status
        assert "by_provider" in status

    def test_benchmark_all_passing_when_no_findings(self, engine):
        status = engine.get_benchmark_status("no-findings-org")
        assert status["total_failing"] == 0

    def test_benchmark_failing_when_findings_exist(self, engine, aws_s3_public):
        engine.scan_resource(aws_s3_public)
        status = engine.get_benchmark_status("test-org")
        assert status["total_failing"] > 0

    def test_benchmark_providers_covered(self, engine):
        status = engine.get_benchmark_status("empty-org")
        providers = set(status["by_provider"].keys())
        assert "aws" in providers
        assert "azure" in providers
        assert "gcp" in providers


# ---------------------------------------------------------------------------
# 18. Baseline management
# ---------------------------------------------------------------------------

class TestBaseline:
    def test_save_baseline_returns_count(self, engine):
        res = CloudResource(provider=CloudProvider.AWS, resource_type=ResourceType.VPC,
                            name="vpc", org_id="baseorg")
        engine.register_resource(res)
        count = engine.save_baseline("baseorg")
        assert count == 1

    def test_save_baseline_empty_org(self, engine):
        count = engine.save_baseline("no-resources-org")
        assert count == 0


# ---------------------------------------------------------------------------
# 19. Singleton
# ---------------------------------------------------------------------------

class TestSingleton:
    def test_get_cspm_engine_returns_same_instance(self, tmp_path):
        # Reset singleton for test isolation by using a unique db path
        from core import cspm_engine as _mod
        original = _mod._engine_instance
        _mod._engine_instance = None
        try:
            e1 = get_cspm_engine(str(tmp_path / "singleton.db"))
            e2 = get_cspm_engine(str(tmp_path / "singleton.db"))
            assert e1 is e2
        finally:
            _mod._engine_instance = original
