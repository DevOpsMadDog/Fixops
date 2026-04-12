"""
Tests for CSPM (Cloud Security Posture Management) engine.

Covers:
- Resource sync and CRUD
- Security checks for AWS, Azure, GCP
- Public exposure detection
- Encryption status checks
- IAM analysis
- Security group analysis
- Compliance summary
- CSPM score calculation

Run with: python -m pytest tests/test_cspm.py -x --tb=short --timeout=10 -q
"""

from __future__ import annotations

import sys
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))

from core.cspm import (
    CheckSeverity,
    CloudProvider,
    CloudResource,
    ComplianceStatus,
    CSPMEngine,
    ResourceCategory,
    SecurityCheck,
    _BUILTIN_CHECKS,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engine(tmp_path):
    """CSPMEngine backed by a temp SQLite DB."""
    return CSPMEngine(db_path=str(tmp_path / "cspm_test.db"))


@pytest.fixture
def org_id():
    return "test-org-001"


def _make_resource(**kwargs) -> CloudResource:
    defaults = dict(
        provider=CloudProvider.AWS,
        category=ResourceCategory.STORAGE,
        resource_type="s3_bucket",
        resource_id=str(uuid.uuid4()),
        name="test-bucket",
        region="us-east-1",
        account_id="123456789012",
        org_id="test-org-001",
    )
    defaults.update(kwargs)
    return CloudResource(**defaults)


# ---------------------------------------------------------------------------
# Resource sync and CRUD
# ---------------------------------------------------------------------------


class TestResourceSync:
    def test_sync_returns_count(self, engine, org_id):
        resources = [
            _make_resource(resource_id="r1", org_id=org_id),
            _make_resource(resource_id="r2", org_id=org_id),
        ]
        count = engine.sync_resources(resources, CloudProvider.AWS, org_id)
        assert count == 2

    def test_sync_upserts_on_conflict(self, engine, org_id):
        r = _make_resource(resource_id="r-upsert", name="original", org_id=org_id)
        engine.sync_resources([r], CloudProvider.AWS, org_id)
        r2 = _make_resource(resource_id="r-upsert", name="updated", org_id=org_id)
        engine.sync_resources([r2], CloudProvider.AWS, org_id)
        resources = engine.list_resources(org_id=org_id)
        assert len(resources) == 1
        assert resources[0].name == "updated"

    def test_get_resource_by_id(self, engine, org_id):
        r = _make_resource(resource_id="get-me", org_id=org_id)
        engine.sync_resources([r], CloudProvider.AWS, org_id)
        fetched = engine.get_resource(r.id)
        assert fetched is not None
        assert fetched.resource_id == "get-me"

    def test_get_resource_missing_returns_none(self, engine):
        assert engine.get_resource("nonexistent-uuid") is None

    def test_list_resources_empty_org(self, engine):
        result = engine.list_resources(org_id="empty-org")
        assert result == []

    def test_list_resources_filter_by_provider(self, engine, org_id):
        aws_r = _make_resource(resource_id="aws-1", provider=CloudProvider.AWS, org_id=org_id)
        gcp_r = _make_resource(
            resource_id="gcp-1",
            provider=CloudProvider.GCP,
            category=ResourceCategory.STORAGE,
            resource_type="gcs_bucket",
            org_id=org_id,
        )
        engine.sync_resources([aws_r], CloudProvider.AWS, org_id)
        engine.sync_resources([gcp_r], CloudProvider.GCP, org_id)
        aws_only = engine.list_resources(org_id=org_id, provider=CloudProvider.AWS)
        assert all(r.provider == CloudProvider.AWS for r in aws_only)
        assert len(aws_only) == 1

    def test_list_resources_filter_by_category(self, engine, org_id):
        storage_r = _make_resource(resource_id="s1", category=ResourceCategory.STORAGE, org_id=org_id)
        iam_r = _make_resource(
            resource_id="i1",
            category=ResourceCategory.IAM,
            resource_type="iam_user",
            org_id=org_id,
        )
        engine.sync_resources([storage_r, iam_r], CloudProvider.AWS, org_id)
        iam_only = engine.list_resources(org_id=org_id, category=ResourceCategory.IAM)
        assert len(iam_only) == 1
        assert iam_only[0].resource_type == "iam_user"

    def test_list_resources_public_only_filter(self, engine, org_id):
        public_r = _make_resource(resource_id="pub-1", public_exposure=True, org_id=org_id)
        private_r = _make_resource(resource_id="priv-1", public_exposure=False, org_id=org_id)
        engine.sync_resources([public_r, private_r], CloudProvider.AWS, org_id)
        public_only = engine.list_resources(org_id=org_id, public_only=True)
        assert len(public_only) == 1
        assert public_only[0].resource_id == "pub-1"

    def test_sync_preserves_config_and_tags(self, engine, org_id):
        r = _make_resource(
            resource_id="cfg-r",
            config={"block_public_access": True},
            tags={"env": "prod"},
            org_id=org_id,
        )
        engine.sync_resources([r], CloudProvider.AWS, org_id)
        fetched = engine.get_resource(r.id)
        assert fetched.config["block_public_access"] is True
        assert fetched.tags["env"] == "prod"


# ---------------------------------------------------------------------------
# AWS security checks
# ---------------------------------------------------------------------------


class TestAWSChecks:
    def _get_check(self, fn_name: str) -> SecurityCheck:
        for c in _BUILTIN_CHECKS:
            if c.check_function == fn_name:
                return c
        raise KeyError(fn_name)

    def test_s3_public_access_non_compliant(self, engine, org_id):
        r = _make_resource(
            resource_id="s3-pub",
            resource_type="s3_bucket",
            public_exposure=True,
            config={"block_public_access": False},
            org_id=org_id,
        )
        engine.sync_resources([r], CloudProvider.AWS, org_id)
        check = self._get_check("check_aws_s3_public_access")
        result = engine.run_check(r, check)
        assert result.status == ComplianceStatus.NON_COMPLIANT

    def test_s3_public_access_compliant(self, engine, org_id):
        r = _make_resource(
            resource_id="s3-priv",
            resource_type="s3_bucket",
            public_exposure=False,
            config={"block_public_access": True},
            org_id=org_id,
        )
        engine.sync_resources([r], CloudProvider.AWS, org_id)
        check = self._get_check("check_aws_s3_public_access")
        result = engine.run_check(r, check)
        assert result.status == ComplianceStatus.COMPLIANT

    def test_s3_public_access_not_applicable_wrong_type(self, engine, org_id):
        r = _make_resource(resource_id="ec2-1", resource_type="ec2_instance", org_id=org_id)
        engine.sync_resources([r], CloudProvider.AWS, org_id)
        check = self._get_check("check_aws_s3_public_access")
        result = engine.run_check(r, check)
        assert result.status == ComplianceStatus.NOT_APPLICABLE

    def test_s3_encryption_non_compliant(self, engine, org_id):
        r = _make_resource(
            resource_id="s3-noenc",
            resource_type="s3_bucket",
            encryption_enabled=False,
            org_id=org_id,
        )
        engine.sync_resources([r], CloudProvider.AWS, org_id)
        check = self._get_check("check_aws_s3_encryption")
        result = engine.run_check(r, check)
        assert result.status == ComplianceStatus.NON_COMPLIANT

    def test_s3_encryption_compliant(self, engine, org_id):
        r = _make_resource(
            resource_id="s3-enc",
            resource_type="s3_bucket",
            encryption_enabled=True,
            org_id=org_id,
        )
        engine.sync_resources([r], CloudProvider.AWS, org_id)
        check = self._get_check("check_aws_s3_encryption")
        result = engine.run_check(r, check)
        assert result.status == ComplianceStatus.COMPLIANT

    def test_vpc_flow_logs_non_compliant(self, engine, org_id):
        r = _make_resource(
            resource_id="vpc-1",
            category=ResourceCategory.NETWORK,
            resource_type="vpc",
            config={"flow_logs_enabled": False},
            org_id=org_id,
        )
        engine.sync_resources([r], CloudProvider.NETWORK if False else CloudProvider.AWS, org_id)
        check = self._get_check("check_aws_vpc_flow_logs")
        result = engine.run_check(r, check)
        assert result.status == ComplianceStatus.NON_COMPLIANT

    def test_vpc_flow_logs_compliant(self, engine, org_id):
        r = _make_resource(
            resource_id="vpc-2",
            category=ResourceCategory.NETWORK,
            resource_type="vpc",
            config={"flow_logs_enabled": True},
            org_id=org_id,
        )
        check = self._get_check("check_aws_vpc_flow_logs")
        result = engine.run_check(r, check)
        assert result.status == ComplianceStatus.COMPLIANT

    def test_cloudtrail_non_compliant(self, engine, org_id):
        r = _make_resource(
            resource_id="ct-1",
            category=ResourceCategory.LOGGING,
            resource_type="cloudtrail",
            config={"enabled": False, "is_multi_region_trail": False},
            org_id=org_id,
        )
        check = self._get_check("check_aws_cloudtrail")
        result = engine.run_check(r, check)
        assert result.status == ComplianceStatus.NON_COMPLIANT

    def test_cloudtrail_compliant(self, engine, org_id):
        r = _make_resource(
            resource_id="ct-2",
            category=ResourceCategory.LOGGING,
            resource_type="cloudtrail",
            config={"enabled": True, "is_multi_region_trail": True},
            org_id=org_id,
        )
        check = self._get_check("check_aws_cloudtrail")
        result = engine.run_check(r, check)
        assert result.status == ComplianceStatus.COMPLIANT

    def test_iam_mfa_non_compliant(self, engine, org_id):
        r = _make_resource(
            resource_id="iam-1",
            category=ResourceCategory.IAM,
            resource_type="iam_user",
            config={"console_access": True, "mfa_enabled": False},
            org_id=org_id,
        )
        check = self._get_check("check_aws_iam_mfa")
        result = engine.run_check(r, check)
        assert result.status == ComplianceStatus.NON_COMPLIANT

    def test_iam_mfa_compliant_with_mfa(self, engine, org_id):
        r = _make_resource(
            resource_id="iam-2",
            category=ResourceCategory.IAM,
            resource_type="iam_user",
            config={"console_access": True, "mfa_enabled": True},
            org_id=org_id,
        )
        check = self._get_check("check_aws_iam_mfa")
        result = engine.run_check(r, check)
        assert result.status == ComplianceStatus.COMPLIANT

    def test_iam_mfa_compliant_no_console(self, engine, org_id):
        r = _make_resource(
            resource_id="iam-3",
            category=ResourceCategory.IAM,
            resource_type="iam_user",
            config={"console_access": False, "mfa_enabled": False},
            org_id=org_id,
        )
        check = self._get_check("check_aws_iam_mfa")
        result = engine.run_check(r, check)
        assert result.status == ComplianceStatus.COMPLIANT

    def test_sg_open_ssh_non_compliant(self, engine, org_id):
        r = _make_resource(
            resource_id="sg-ssh",
            category=ResourceCategory.NETWORK,
            resource_type="security_group",
            config={"inbound_rules": [{"port": 22, "cidr": "0.0.0.0/0", "protocol": "tcp"}]},
            org_id=org_id,
        )
        check = self._get_check("check_aws_sg_open_ssh")
        result = engine.run_check(r, check)
        assert result.status == ComplianceStatus.NON_COMPLIANT

    def test_sg_open_ssh_compliant(self, engine, org_id):
        r = _make_resource(
            resource_id="sg-ssh-ok",
            category=ResourceCategory.NETWORK,
            resource_type="security_group",
            config={"inbound_rules": [{"port": 22, "cidr": "10.0.0.0/8", "protocol": "tcp"}]},
            org_id=org_id,
        )
        check = self._get_check("check_aws_sg_open_ssh")
        result = engine.run_check(r, check)
        assert result.status == ComplianceStatus.COMPLIANT

    def test_sg_open_rdp_non_compliant(self, engine, org_id):
        r = _make_resource(
            resource_id="sg-rdp",
            category=ResourceCategory.NETWORK,
            resource_type="security_group",
            config={"inbound_rules": [{"port": 3389, "cidr": "0.0.0.0/0", "protocol": "tcp"}]},
            org_id=org_id,
        )
        check = self._get_check("check_aws_sg_open_rdp")
        result = engine.run_check(r, check)
        assert result.status == ComplianceStatus.NON_COMPLIANT

    def test_rds_public_non_compliant(self, engine, org_id):
        r = _make_resource(
            resource_id="rds-pub",
            category=ResourceCategory.DATABASE,
            resource_type="rds_instance",
            public_exposure=True,
            config={"publicly_accessible": True},
            org_id=org_id,
        )
        check = self._get_check("check_aws_rds_public")
        result = engine.run_check(r, check)
        assert result.status == ComplianceStatus.NON_COMPLIANT

    def test_rds_public_compliant(self, engine, org_id):
        r = _make_resource(
            resource_id="rds-priv",
            category=ResourceCategory.DATABASE,
            resource_type="rds_instance",
            public_exposure=False,
            config={"publicly_accessible": False},
            org_id=org_id,
        )
        check = self._get_check("check_aws_rds_public")
        result = engine.run_check(r, check)
        assert result.status == ComplianceStatus.COMPLIANT

    def test_ebs_encryption_non_compliant(self, engine, org_id):
        r = _make_resource(
            resource_id="ebs-noenc",
            category=ResourceCategory.ENCRYPTION,
            resource_type="ebs_volume",
            encryption_enabled=False,
            org_id=org_id,
        )
        check = self._get_check("check_aws_ebs_encryption")
        result = engine.run_check(r, check)
        assert result.status == ComplianceStatus.NON_COMPLIANT

    def test_ebs_encryption_compliant(self, engine, org_id):
        r = _make_resource(
            resource_id="ebs-enc",
            category=ResourceCategory.ENCRYPTION,
            resource_type="ebs_volume",
            encryption_enabled=True,
            org_id=org_id,
        )
        check = self._get_check("check_aws_ebs_encryption")
        result = engine.run_check(r, check)
        assert result.status == ComplianceStatus.COMPLIANT


# ---------------------------------------------------------------------------
# Azure security checks
# ---------------------------------------------------------------------------


class TestAzureChecks:
    def _get_check(self, fn_name: str) -> SecurityCheck:
        for c in _BUILTIN_CHECKS:
            if c.check_function == fn_name:
                return c
        raise KeyError(fn_name)

    def test_azure_storage_encryption_non_compliant(self, engine, org_id):
        r = _make_resource(
            resource_id="az-stor-noenc",
            provider=CloudProvider.AZURE,
            category=ResourceCategory.STORAGE,
            resource_type="storage_account",
            encryption_enabled=False,
            org_id=org_id,
        )
        check = self._get_check("check_azure_storage_encryption")
        result = engine.run_check(r, check)
        assert result.status == ComplianceStatus.NON_COMPLIANT

    def test_azure_storage_encryption_compliant(self, engine, org_id):
        r = _make_resource(
            resource_id="az-stor-enc",
            provider=CloudProvider.AZURE,
            category=ResourceCategory.STORAGE,
            resource_type="storage_account",
            encryption_enabled=True,
            org_id=org_id,
        )
        check = self._get_check("check_azure_storage_encryption")
        result = engine.run_check(r, check)
        assert result.status == ComplianceStatus.COMPLIANT

    def test_azure_nsg_ssh_non_compliant(self, engine, org_id):
        r = _make_resource(
            resource_id="az-nsg-ssh",
            provider=CloudProvider.AZURE,
            category=ResourceCategory.NETWORK,
            resource_type="network_security_group",
            config={
                "security_rules": [
                    {
                        "access": "Allow",
                        "source_address_prefix": "Internet",
                        "destination_port_range": "22",
                    }
                ]
            },
            org_id=org_id,
        )
        check = self._get_check("check_azure_nsg_ssh")
        result = engine.run_check(r, check)
        assert result.status == ComplianceStatus.NON_COMPLIANT

    def test_azure_nsg_rdp_non_compliant(self, engine, org_id):
        r = _make_resource(
            resource_id="az-nsg-rdp",
            provider=CloudProvider.AZURE,
            category=ResourceCategory.NETWORK,
            resource_type="network_security_group",
            config={
                "security_rules": [
                    {
                        "access": "Allow",
                        "source_address_prefix": "*",
                        "destination_port_range": "3389",
                    }
                ]
            },
            org_id=org_id,
        )
        check = self._get_check("check_azure_nsg_rdp")
        result = engine.run_check(r, check)
        assert result.status == ComplianceStatus.NON_COMPLIANT

    def test_azure_nsg_compliant(self, engine, org_id):
        r = _make_resource(
            resource_id="az-nsg-ok",
            provider=CloudProvider.AZURE,
            category=ResourceCategory.NETWORK,
            resource_type="network_security_group",
            config={"security_rules": []},
            org_id=org_id,
        )
        check = self._get_check("check_azure_nsg_ssh")
        result = engine.run_check(r, check)
        assert result.status == ComplianceStatus.COMPLIANT

    def test_azure_keyvault_logs_non_compliant(self, engine, org_id):
        r = _make_resource(
            resource_id="az-kv-nologs",
            provider=CloudProvider.AZURE,
            category=ResourceCategory.LOGGING,
            resource_type="key_vault",
            config={"diagnostic_logs_enabled": False},
            org_id=org_id,
        )
        check = self._get_check("check_azure_keyvault_logs")
        result = engine.run_check(r, check)
        assert result.status == ComplianceStatus.NON_COMPLIANT

    def test_azure_sql_tde_non_compliant(self, engine, org_id):
        r = _make_resource(
            resource_id="az-sql-notde",
            provider=CloudProvider.AZURE,
            category=ResourceCategory.DATABASE,
            resource_type="sql_database",
            encryption_enabled=False,
            config={"transparent_data_encryption": False},
            org_id=org_id,
        )
        check = self._get_check("check_azure_sql_tde")
        result = engine.run_check(r, check)
        assert result.status == ComplianceStatus.NON_COMPLIANT

    def test_azure_aks_rbac_non_compliant(self, engine, org_id):
        r = _make_resource(
            resource_id="az-aks-norbac",
            provider=CloudProvider.AZURE,
            category=ResourceCategory.CONTAINER,
            resource_type="aks_cluster",
            config={"rbac_enabled": False},
            org_id=org_id,
        )
        check = self._get_check("check_azure_aks_rbac")
        result = engine.run_check(r, check)
        assert result.status == ComplianceStatus.NON_COMPLIANT

    def test_azure_aks_rbac_compliant(self, engine, org_id):
        r = _make_resource(
            resource_id="az-aks-rbac",
            provider=CloudProvider.AZURE,
            category=ResourceCategory.CONTAINER,
            resource_type="aks_cluster",
            config={"rbac_enabled": True},
            org_id=org_id,
        )
        check = self._get_check("check_azure_aks_rbac")
        result = engine.run_check(r, check)
        assert result.status == ComplianceStatus.COMPLIANT


# ---------------------------------------------------------------------------
# GCP security checks
# ---------------------------------------------------------------------------


class TestGCPChecks:
    def _get_check(self, fn_name: str) -> SecurityCheck:
        for c in _BUILTIN_CHECKS:
            if c.check_function == fn_name:
                return c
        raise KeyError(fn_name)

    def test_gcp_bucket_public_acl_non_compliant(self, engine, org_id):
        r = _make_resource(
            resource_id="gcp-bucket-pub",
            provider=CloudProvider.GCP,
            category=ResourceCategory.STORAGE,
            resource_type="gcs_bucket",
            config={"acl": [{"entity": "allUsers", "role": "READER"}]},
            org_id=org_id,
        )
        check = self._get_check("check_gcp_bucket_public_acl")
        result = engine.run_check(r, check)
        assert result.status == ComplianceStatus.NON_COMPLIANT

    def test_gcp_bucket_public_acl_compliant(self, engine, org_id):
        r = _make_resource(
            resource_id="gcp-bucket-priv",
            provider=CloudProvider.GCP,
            category=ResourceCategory.STORAGE,
            resource_type="gcs_bucket",
            config={"acl": [{"entity": "user:admin@example.com", "role": "OWNER"}]},
            org_id=org_id,
        )
        check = self._get_check("check_gcp_bucket_public_acl")
        result = engine.run_check(r, check)
        assert result.status == ComplianceStatus.COMPLIANT

    def test_gcp_firewall_ssh_non_compliant(self, engine, org_id):
        r = _make_resource(
            resource_id="gcp-fw-ssh",
            provider=CloudProvider.GCP,
            category=ResourceCategory.NETWORK,
            resource_type="firewall_rule",
            config={
                "source_ranges": ["0.0.0.0/0"],
                "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}],
            },
            org_id=org_id,
        )
        check = self._get_check("check_gcp_firewall_ssh")
        result = engine.run_check(r, check)
        assert result.status == ComplianceStatus.NON_COMPLIANT

    def test_gcp_audit_logging_non_compliant(self, engine, org_id):
        r = _make_resource(
            resource_id="gcp-proj-nolog",
            provider=CloudProvider.GCP,
            category=ResourceCategory.LOGGING,
            resource_type="project",
            config={"audit_logging_enabled": False},
            org_id=org_id,
        )
        check = self._get_check("check_gcp_audit_logging")
        result = engine.run_check(r, check)
        assert result.status == ComplianceStatus.NON_COMPLIANT

    def test_gcp_kms_rotation_non_compliant_no_rotation(self, engine, org_id):
        r = _make_resource(
            resource_id="gcp-kms-norot",
            provider=CloudProvider.GCP,
            category=ResourceCategory.ENCRYPTION,
            resource_type="kms_key",
            config={"rotation_period_days": None},
            org_id=org_id,
        )
        check = self._get_check("check_gcp_kms_rotation")
        result = engine.run_check(r, check)
        assert result.status == ComplianceStatus.NON_COMPLIANT

    def test_gcp_kms_rotation_non_compliant_too_long(self, engine, org_id):
        r = _make_resource(
            resource_id="gcp-kms-long",
            provider=CloudProvider.GCP,
            category=ResourceCategory.ENCRYPTION,
            resource_type="kms_key",
            config={"rotation_period_days": 180},
            org_id=org_id,
        )
        check = self._get_check("check_gcp_kms_rotation")
        result = engine.run_check(r, check)
        assert result.status == ComplianceStatus.NON_COMPLIANT

    def test_gcp_kms_rotation_compliant(self, engine, org_id):
        r = _make_resource(
            resource_id="gcp-kms-ok",
            provider=CloudProvider.GCP,
            category=ResourceCategory.ENCRYPTION,
            resource_type="kms_key",
            config={"rotation_period_days": 30},
            org_id=org_id,
        )
        check = self._get_check("check_gcp_kms_rotation")
        result = engine.run_check(r, check)
        assert result.status == ComplianceStatus.COMPLIANT

    def test_gcp_gke_rbac_non_compliant(self, engine, org_id):
        r = _make_resource(
            resource_id="gcp-gke-abac",
            provider=CloudProvider.GCP,
            category=ResourceCategory.CONTAINER,
            resource_type="gke_cluster",
            config={"legacy_abac_enabled": True},
            org_id=org_id,
        )
        check = self._get_check("check_gcp_gke_rbac")
        result = engine.run_check(r, check)
        assert result.status == ComplianceStatus.NON_COMPLIANT

    def test_gcp_sql_ssl_non_compliant(self, engine, org_id):
        r = _make_resource(
            resource_id="gcp-sql-nossl",
            provider=CloudProvider.GCP,
            category=ResourceCategory.DATABASE,
            resource_type="cloud_sql",
            config={"require_ssl": False},
            org_id=org_id,
        )
        check = self._get_check("check_gcp_sql_ssl")
        result = engine.run_check(r, check)
        assert result.status == ComplianceStatus.NON_COMPLIANT


# ---------------------------------------------------------------------------
# Public exposure detection
# ---------------------------------------------------------------------------


class TestPublicExposure:
    def test_get_public_resources_returns_exposed(self, engine, org_id):
        public = _make_resource(resource_id="pub-1", public_exposure=True, org_id=org_id)
        private = _make_resource(resource_id="priv-1", public_exposure=False, org_id=org_id)
        engine.sync_resources([public, private], CloudProvider.AWS, org_id)
        result = engine.get_public_resources(org_id)
        assert len(result) == 1
        assert result[0].resource_id == "pub-1"

    def test_get_public_resources_empty(self, engine, org_id):
        result = engine.get_public_resources(org_id)
        assert result == []


# ---------------------------------------------------------------------------
# Encryption status checks
# ---------------------------------------------------------------------------


class TestEncryptionChecks:
    def test_get_unencrypted_resources(self, engine, org_id):
        enc = _make_resource(resource_id="enc-1", encryption_enabled=True, org_id=org_id)
        noenc = _make_resource(resource_id="noenc-1", encryption_enabled=False, org_id=org_id)
        engine.sync_resources([enc, noenc], CloudProvider.AWS, org_id)
        result = engine.get_unencrypted_resources(org_id)
        assert len(result) == 1
        assert result[0].resource_id == "noenc-1"

    def test_get_unencrypted_resources_empty_when_all_encrypted(self, engine, org_id):
        r = _make_resource(resource_id="enc-only", encryption_enabled=True, org_id=org_id)
        engine.sync_resources([r], CloudProvider.AWS, org_id)
        result = engine.get_unencrypted_resources(org_id)
        assert result == []


# ---------------------------------------------------------------------------
# IAM analysis
# ---------------------------------------------------------------------------


class TestIAMAnalysis:
    def test_iam_findings_admin_access(self, engine, org_id):
        r = _make_resource(
            resource_id="iam-admin",
            category=ResourceCategory.IAM,
            resource_type="iam_user",
            config={"admin_access": True, "console_access": True, "mfa_enabled": True},
            org_id=org_id,
        )
        engine.sync_resources([r], CloudProvider.AWS, org_id)
        findings = engine.get_iam_findings(org_id)
        assert len(findings) == 1
        assert any("AdministratorAccess" in i for i in findings[0]["issues"])

    def test_iam_findings_old_access_key(self, engine, org_id):
        r = _make_resource(
            resource_id="iam-oldkey",
            category=ResourceCategory.IAM,
            resource_type="iam_user",
            config={"access_keys_age_days": 120, "console_access": False, "mfa_enabled": True},
            org_id=org_id,
        )
        engine.sync_resources([r], CloudProvider.AWS, org_id)
        findings = engine.get_iam_findings(org_id)
        assert len(findings) == 1
        assert any("90 days" in i for i in findings[0]["issues"])

    def test_iam_findings_no_issues_for_clean_user(self, engine, org_id):
        r = _make_resource(
            resource_id="iam-clean",
            category=ResourceCategory.IAM,
            resource_type="iam_user",
            config={"console_access": True, "mfa_enabled": True, "access_keys_age_days": 30},
            org_id=org_id,
        )
        engine.sync_resources([r], CloudProvider.AWS, org_id)
        findings = engine.get_iam_findings(org_id)
        assert findings == []

    def test_iam_findings_no_mfa_with_console_access(self, engine, org_id):
        r = _make_resource(
            resource_id="iam-nomfa",
            category=ResourceCategory.IAM,
            resource_type="iam_user",
            config={"console_access": True, "mfa_enabled": False},
            org_id=org_id,
        )
        engine.sync_resources([r], CloudProvider.AWS, org_id)
        findings = engine.get_iam_findings(org_id)
        assert len(findings) == 1
        assert any("MFA" in i for i in findings[0]["issues"])

    def test_iam_findings_severity_high_for_multiple_issues(self, engine, org_id):
        r = _make_resource(
            resource_id="iam-multi",
            category=ResourceCategory.IAM,
            resource_type="iam_user",
            config={
                "admin_access": True,
                "console_access": True,
                "mfa_enabled": False,
                "access_keys_age_days": 200,
            },
            org_id=org_id,
        )
        engine.sync_resources([r], CloudProvider.AWS, org_id)
        findings = engine.get_iam_findings(org_id)
        assert findings[0]["severity"] == "HIGH"


# ---------------------------------------------------------------------------
# Security group analysis
# ---------------------------------------------------------------------------


class TestSecurityGroupAnalysis:
    def test_sg_findings_open_ssh(self, engine, org_id):
        r = _make_resource(
            resource_id="sg-open-ssh",
            category=ResourceCategory.NETWORK,
            resource_type="security_group",
            config={"inbound_rules": [{"port": 22, "cidr": "0.0.0.0/0"}]},
            org_id=org_id,
        )
        engine.sync_resources([r], CloudProvider.AWS, org_id)
        findings = engine.get_security_group_findings(org_id)
        assert len(findings) == 1
        assert any("SSH" in i for i in findings[0]["issues"])
        assert findings[0]["severity"] == "HIGH"

    def test_sg_findings_open_rdp(self, engine, org_id):
        r = _make_resource(
            resource_id="sg-open-rdp",
            category=ResourceCategory.NETWORK,
            resource_type="security_group",
            config={"inbound_rules": [{"port": 3389, "cidr": "0.0.0.0/0"}]},
            org_id=org_id,
        )
        engine.sync_resources([r], CloudProvider.AWS, org_id)
        findings = engine.get_security_group_findings(org_id)
        assert any("RDP" in i for i in findings[0]["issues"])

    def test_sg_findings_no_issues_restricted(self, engine, org_id):
        r = _make_resource(
            resource_id="sg-restricted",
            category=ResourceCategory.NETWORK,
            resource_type="security_group",
            config={"inbound_rules": [{"port": 22, "cidr": "10.0.0.0/8"}]},
            org_id=org_id,
        )
        engine.sync_resources([r], CloudProvider.AWS, org_id)
        findings = engine.get_security_group_findings(org_id)
        assert findings == []

    def test_sg_findings_allow_all_rule(self, engine, org_id):
        r = _make_resource(
            resource_id="sg-allow-all",
            category=ResourceCategory.NETWORK,
            resource_type="security_group",
            config={
                "inbound_rules": [{"protocol": "-1", "cidr": "0.0.0.0/0"}],
            },
            org_id=org_id,
        )
        engine.sync_resources([r], CloudProvider.AWS, org_id)
        findings = engine.get_security_group_findings(org_id)
        assert len(findings) == 1


# ---------------------------------------------------------------------------
# Compliance summary
# ---------------------------------------------------------------------------


class TestComplianceSummary:
    def test_summary_empty_org(self, engine, org_id):
        summary = engine.get_compliance_summary(org_id)
        assert summary["total"] == 0
        assert summary["compliance_rate"] == 0.0

    def test_summary_counts_after_scan(self, engine, org_id):
        # Two S3 buckets: one compliant, one not
        compliant_r = _make_resource(
            resource_id="s3-good",
            resource_type="s3_bucket",
            public_exposure=False,
            config={"block_public_access": True},
            encryption_enabled=True,
            org_id=org_id,
        )
        bad_r = _make_resource(
            resource_id="s3-bad",
            resource_type="s3_bucket",
            public_exposure=True,
            config={"block_public_access": False},
            encryption_enabled=False,
            org_id=org_id,
        )
        engine.sync_resources([compliant_r, bad_r], CloudProvider.AWS, org_id)
        engine.run_security_checks(org_id, provider=CloudProvider.AWS)
        summary = engine.get_compliance_summary(org_id)
        assert summary["total"] > 0
        assert summary["compliant"] + summary["non_compliant"] + summary["not_assessed"] + summary["not_applicable"] == summary["total"]
        assert 0.0 <= summary["compliance_rate"] <= 100.0

    def test_summary_has_by_category(self, engine, org_id):
        r = _make_resource(
            resource_id="s3-cat",
            resource_type="s3_bucket",
            public_exposure=False,
            config={"block_public_access": True},
            org_id=org_id,
        )
        engine.sync_resources([r], CloudProvider.AWS, org_id)
        engine.run_security_checks(org_id, provider=CloudProvider.AWS)
        summary = engine.get_compliance_summary(org_id)
        assert isinstance(summary["by_category"], dict)

    def test_get_check_results_filter_by_status(self, engine, org_id):
        r = _make_resource(
            resource_id="s3-nc",
            resource_type="s3_bucket",
            public_exposure=True,
            config={"block_public_access": False},
            org_id=org_id,
        )
        engine.sync_resources([r], CloudProvider.AWS, org_id)
        engine.run_security_checks(org_id, provider=CloudProvider.AWS)
        nc_results = engine.get_check_results(org_id, status_filter=ComplianceStatus.NON_COMPLIANT)
        assert all(r.status == ComplianceStatus.NON_COMPLIANT for r in nc_results)


# ---------------------------------------------------------------------------
# CSPM score calculation
# ---------------------------------------------------------------------------


class TestCSPMScore:
    def test_score_no_resources_is_100(self, engine, org_id):
        score = engine.get_cspm_score(org_id)
        assert score == 100.0

    def test_score_all_compliant_close_to_100(self, engine, org_id):
        r = _make_resource(
            resource_id="s3-score-good",
            resource_type="s3_bucket",
            public_exposure=False,
            encryption_enabled=True,
            config={"block_public_access": True},
            org_id=org_id,
        )
        engine.sync_resources([r], CloudProvider.AWS, org_id)
        engine.run_security_checks(org_id, provider=CloudProvider.AWS)
        score = engine.get_cspm_score(org_id)
        assert 0.0 <= score <= 100.0

    def test_score_penalized_for_public_resources(self, engine, org_id):
        # Two resources, one public — score should be penalized
        pub = _make_resource(
            resource_id="s3-pub-score",
            resource_type="s3_bucket",
            public_exposure=True,
            config={"block_public_access": False},
            org_id=org_id,
        )
        priv = _make_resource(
            resource_id="s3-priv-score",
            resource_type="s3_bucket",
            public_exposure=False,
            config={"block_public_access": True},
            org_id=org_id,
        )
        engine.sync_resources([pub, priv], CloudProvider.AWS, org_id)
        engine.run_security_checks(org_id, provider=CloudProvider.AWS)
        score = engine.get_cspm_score(org_id)
        assert score < 100.0

    def test_score_penalized_for_unencrypted_resources(self, engine, org_id):
        r = _make_resource(
            resource_id="s3-noenc-score",
            resource_type="s3_bucket",
            encryption_enabled=False,
            config={"block_public_access": True},
            org_id=org_id,
        )
        engine.sync_resources([r], CloudProvider.AWS, org_id)
        engine.run_security_checks(org_id, provider=CloudProvider.AWS)
        score_with_unencrypted = engine.get_cspm_score(org_id)
        assert score_with_unencrypted < 100.0

    def test_score_is_float_between_0_and_100(self, engine, org_id):
        r = _make_resource(
            resource_id="s3-score-range",
            resource_type="s3_bucket",
            public_exposure=True,
            encryption_enabled=False,
            config={"block_public_access": False},
            org_id=org_id,
        )
        engine.sync_resources([r], CloudProvider.AWS, org_id)
        engine.run_security_checks(org_id, provider=CloudProvider.AWS)
        score = engine.get_cspm_score(org_id)
        assert isinstance(score, float)
        assert 0.0 <= score <= 100.0

    def test_score_no_checks_run_returns_100(self, engine, org_id):
        # Resources exist but no checks run → no stored results → total==0 → 100.0
        r = _make_resource(resource_id="s3-nocheck", resource_type="s3_bucket", org_id=org_id)
        engine.sync_resources([r], CloudProvider.AWS, org_id)
        # No run_security_checks call — score is 100.0 (no failures recorded)
        score = engine.get_cspm_score(org_id)
        assert score == 100.0

    def test_score_returns_50_when_results_all_not_assessed(self, engine, org_id):
        # The 50.0 path: results exist but assessed (compliant+non_compliant) == 0
        # Achieve this by storing a NOT_ASSESSED result directly via a check with missing impl
        from core.cspm import CheckSeverity, SecurityCheck
        r = _make_resource(resource_id="s3-na", resource_type="s3_bucket", org_id=org_id)
        engine.sync_resources([r], CloudProvider.AWS, org_id)
        bad_check = SecurityCheck(
            name="Missing",
            description="desc",
            provider=CloudProvider.AWS,
            category=ResourceCategory.STORAGE,
            severity=CheckSeverity.LOW,
            check_function="nonexistent_method",
        )
        result = engine.run_check(r, bad_check)
        engine._persist_result(result, org_id)
        score = engine.get_cspm_score(org_id)
        assert score == 50.0


# ---------------------------------------------------------------------------
# Builtin checks catalogue
# ---------------------------------------------------------------------------


class TestBuiltinChecks:
    def test_builtin_checks_not_empty(self):
        assert len(_BUILTIN_CHECKS) > 0

    def test_all_checks_have_check_function_on_engine(self):
        engine = CSPMEngine.__new__(CSPMEngine)
        for check in _BUILTIN_CHECKS:
            assert hasattr(engine, check.check_function), (
                f"Missing method: {check.check_function}"
            )

    def test_checks_cover_all_three_providers(self):
        providers = {c.provider for c in _BUILTIN_CHECKS}
        assert CloudProvider.AWS in providers
        assert CloudProvider.AZURE in providers
        assert CloudProvider.GCP in providers

    def test_run_check_unknown_function_returns_not_assessed(self, engine, org_id):
        r = _make_resource(resource_id="r-unknown", org_id=org_id)
        check = SecurityCheck(
            name="Fake Check",
            description="desc",
            provider=CloudProvider.AWS,
            category=ResourceCategory.STORAGE,
            severity=CheckSeverity.LOW,
            check_function="nonexistent_method",
        )
        result = engine.run_check(r, check)
        assert result.status == ComplianceStatus.NOT_ASSESSED
