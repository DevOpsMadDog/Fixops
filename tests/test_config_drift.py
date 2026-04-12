"""
Tests for ConfigDriftDetector — baseline rules, config comparison,
resource checking, batch, history, resolution, summary, defaults.
"""

from __future__ import annotations

import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

# Ensure suite paths are available
os.environ.setdefault("FIXOPS_MODE", "dev")

from core.config_drift import (
    BaselineRule,
    CloudProvider,
    ConfigDriftDetector,
    DriftResult,
    DriftSeverity,
    DriftSummary,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_db(tmp_path):
    """Temporary SQLite database path."""
    return str(tmp_path / "test_drift.db")


@pytest.fixture
def detector(tmp_db):
    """Fresh ConfigDriftDetector backed by a temp DB."""
    return ConfigDriftDetector(db_path=tmp_db)


@pytest.fixture
def s3_rule():
    return BaselineRule(
        id="test-s3-public",
        name="S3 Block Public Access",
        description="S3 must block public access.",
        provider=CloudProvider.AWS,
        resource_type="s3_bucket",
        expected_config={
            "block_public_acls": True,
            "block_public_policy": True,
        },
        severity=DriftSeverity.CRITICAL,
        cis_benchmark="CIS AWS 2.1.5",
        remediation="Enable S3 block public access settings.",
    )


@pytest.fixture
def sg_rule():
    return BaselineRule(
        id="test-sg-ssh",
        name="No Unrestricted SSH",
        description="Security groups must not allow SSH from any.",
        provider=CloudProvider.AWS,
        resource_type="security_group",
        expected_config={"allow_ssh_from_any": False},
        severity=DriftSeverity.HIGH,
        cis_benchmark="CIS AWS 5.2",
        remediation="Remove SSH rule from security group.",
    )


# ---------------------------------------------------------------------------
# Baseline rule CRUD
# ---------------------------------------------------------------------------


def test_add_and_list_baseline_rule(detector, s3_rule):
    result = detector.add_baseline_rule(s3_rule)
    assert result.id == s3_rule.id
    assert result.name == s3_rule.name

    rules = detector.list_baseline_rules()
    assert len(rules) == 1
    assert rules[0].id == s3_rule.id


def test_list_baseline_rules_filter_provider(detector, s3_rule, sg_rule):
    azure_rule = BaselineRule(
        id="azure-test",
        name="Azure Test",
        description="desc",
        provider=CloudProvider.AZURE,
        resource_type="storage_account",
        expected_config={"encryption_enabled": True},
        severity=DriftSeverity.HIGH,
        cis_benchmark=None,
        remediation="Enable encryption.",
    )
    detector.add_baseline_rule(s3_rule)
    detector.add_baseline_rule(sg_rule)
    detector.add_baseline_rule(azure_rule)

    aws_rules = detector.list_baseline_rules(provider=CloudProvider.AWS)
    assert len(aws_rules) == 2

    azure_rules = detector.list_baseline_rules(provider=CloudProvider.AZURE)
    assert len(azure_rules) == 1
    assert azure_rules[0].id == "azure-test"


def test_list_baseline_rules_filter_resource_type(detector, s3_rule, sg_rule):
    detector.add_baseline_rule(s3_rule)
    detector.add_baseline_rule(sg_rule)

    s3_rules = detector.list_baseline_rules(resource_type="s3_bucket")
    assert len(s3_rules) == 1
    assert s3_rules[0].id == s3_rule.id


def test_delete_baseline_rule(detector, s3_rule):
    detector.add_baseline_rule(s3_rule)
    assert len(detector.list_baseline_rules()) == 1

    detector.delete_baseline_rule(s3_rule.id)
    assert len(detector.list_baseline_rules()) == 0


def test_list_returns_empty_when_no_rules(detector):
    assert detector.list_baseline_rules() == []


def test_rule_preserves_cis_benchmark(detector, s3_rule):
    detector.add_baseline_rule(s3_rule)
    rules = detector.list_baseline_rules()
    assert rules[0].cis_benchmark == "CIS AWS 2.1.5"


def test_rule_optional_cis_benchmark_none(detector):
    rule = BaselineRule(
        name="No CIS",
        description="desc",
        provider=CloudProvider.GCP,
        resource_type="gcs_bucket",
        expected_config={"public_access": False},
        severity=DriftSeverity.LOW,
        remediation="Fix it.",
    )
    detector.add_baseline_rule(rule)
    rules = detector.list_baseline_rules()
    assert rules[0].cis_benchmark is None


# ---------------------------------------------------------------------------
# Config comparison
# ---------------------------------------------------------------------------


def test_compare_configs_no_drift(detector):
    expected = {"block_public_acls": True, "encryption": True}
    actual = {"block_public_acls": True, "encryption": True}
    drifted = detector._compare_configs(expected, actual)
    assert drifted == []


def test_compare_configs_single_field_drift(detector):
    expected = {"block_public_acls": True}
    actual = {"block_public_acls": False}
    drifted = detector._compare_configs(expected, actual)
    assert "block_public_acls" in drifted


def test_compare_configs_missing_field(detector):
    expected = {"encryption": True, "logging": True}
    actual = {"encryption": True}
    drifted = detector._compare_configs(expected, actual)
    assert "logging" in drifted


def test_compare_configs_nested_drift(detector):
    expected = {"settings": {"encryption": True, "versioning": True}}
    actual = {"settings": {"encryption": True, "versioning": False}}
    drifted = detector._compare_configs(expected, actual)
    assert "settings.versioning" in drifted


def test_compare_configs_nested_no_drift(detector):
    expected = {"settings": {"encryption": True}}
    actual = {"settings": {"encryption": True, "extra": "ignored"}}
    drifted = detector._compare_configs(expected, actual)
    assert drifted == []


def test_compare_configs_multiple_drifts(detector):
    expected = {"a": 1, "b": 2, "c": 3}
    actual = {"a": 1, "b": 9, "c": 9}
    drifted = detector._compare_configs(expected, actual)
    assert set(drifted) == {"b", "c"}


# ---------------------------------------------------------------------------
# Resource checking
# ---------------------------------------------------------------------------


def test_check_resource_compliant(detector, s3_rule):
    detector.add_baseline_rule(s3_rule)
    results = detector.check_resource(
        resource_id="bucket-1",
        resource_type="s3_bucket",
        actual_config={"block_public_acls": True, "block_public_policy": True},
        provider=CloudProvider.AWS,
        org_id="org-test",
    )
    assert results == []


def test_check_resource_drifted(detector, s3_rule):
    detector.add_baseline_rule(s3_rule)
    results = detector.check_resource(
        resource_id="bucket-1",
        resource_type="s3_bucket",
        actual_config={"block_public_acls": False, "block_public_policy": False},
        provider=CloudProvider.AWS,
        org_id="org-test",
    )
    assert len(results) == 1
    drift = results[0]
    assert drift.resource_id == "bucket-1"
    assert drift.severity == DriftSeverity.CRITICAL
    assert "block_public_acls" in drift.drifted_fields
    assert drift.resolved_at is None
    assert drift.org_id == "org-test"


def test_check_resource_multiple_rules_match(detector, s3_rule):
    rule2 = BaselineRule(
        id="test-s3-enc",
        name="S3 Encryption",
        description="Must encrypt.",
        provider=CloudProvider.AWS,
        resource_type="s3_bucket",
        expected_config={"encryption_enabled": True},
        severity=DriftSeverity.HIGH,
        remediation="Enable encryption.",
    )
    detector.add_baseline_rule(s3_rule)
    detector.add_baseline_rule(rule2)
    results = detector.check_resource(
        resource_id="bucket-1",
        resource_type="s3_bucket",
        actual_config={
            "block_public_acls": False,
            "block_public_policy": True,
            "encryption_enabled": False,
        },
        provider=CloudProvider.AWS,
        org_id="org-test",
    )
    assert len(results) == 2


def test_check_resource_no_matching_rules(detector, sg_rule):
    detector.add_baseline_rule(sg_rule)
    results = detector.check_resource(
        resource_id="bucket-1",
        resource_type="s3_bucket",
        actual_config={"block_public_acls": False},
        provider=CloudProvider.AWS,
        org_id="org-test",
    )
    assert results == []


# ---------------------------------------------------------------------------
# Batch checking
# ---------------------------------------------------------------------------


def test_check_batch(detector, s3_rule, sg_rule):
    detector.add_baseline_rule(s3_rule)
    detector.add_baseline_rule(sg_rule)

    resources = [
        {
            "resource_id": "bucket-1",
            "resource_type": "s3_bucket",
            "actual_config": {"block_public_acls": False, "block_public_policy": False},
            "provider": "AWS",
        },
        {
            "resource_id": "sg-1",
            "resource_type": "security_group",
            "actual_config": {"allow_ssh_from_any": True},
            "provider": "AWS",
        },
    ]
    results = detector.check_batch(resources=resources, org_id="org-test")
    assert len(results) == 2
    resource_ids = {r.resource_id for r in results}
    assert "bucket-1" in resource_ids
    assert "sg-1" in resource_ids


def test_check_batch_empty(detector):
    results = detector.check_batch(resources=[], org_id="org-test")
    assert results == []


# ---------------------------------------------------------------------------
# Drift history and resolution
# ---------------------------------------------------------------------------


def test_get_drift_history(detector, s3_rule):
    detector.add_baseline_rule(s3_rule)
    detector.check_resource(
        resource_id="bucket-1",
        resource_type="s3_bucket",
        actual_config={"block_public_acls": False, "block_public_policy": False},
        provider=CloudProvider.AWS,
        org_id="org-test",
    )
    history = detector.get_drift_history(org_id="org-test")
    assert len(history) == 1
    assert history[0].resource_id == "bucket-1"


def test_get_drift_history_filter_resource(detector, s3_rule):
    detector.add_baseline_rule(s3_rule)
    detector.check_resource(
        resource_id="bucket-1",
        resource_type="s3_bucket",
        actual_config={"block_public_acls": False, "block_public_policy": False},
        provider=CloudProvider.AWS,
        org_id="org-test",
    )
    detector.check_resource(
        resource_id="bucket-2",
        resource_type="s3_bucket",
        actual_config={"block_public_acls": False, "block_public_policy": False},
        provider=CloudProvider.AWS,
        org_id="org-test",
    )
    history = detector.get_drift_history(org_id="org-test", resource_id="bucket-1")
    assert all(h.resource_id == "bucket-1" for h in history)


def test_resolve_drift(detector, s3_rule):
    detector.add_baseline_rule(s3_rule)
    results = detector.check_resource(
        resource_id="bucket-1",
        resource_type="s3_bucket",
        actual_config={"block_public_acls": False, "block_public_policy": False},
        provider=CloudProvider.AWS,
        org_id="org-test",
    )
    drift_id = results[0].id
    detector.resolve_drift(drift_id)

    active = detector.get_active_drifts(org_id="org-test")
    assert all(d.id != drift_id for d in active)

    history = detector.get_drift_history(org_id="org-test")
    resolved = next(h for h in history if h.id == drift_id)
    assert resolved.resolved_at is not None


def test_get_active_drifts_filter_severity(detector, s3_rule, sg_rule):
    detector.add_baseline_rule(s3_rule)  # CRITICAL
    detector.add_baseline_rule(sg_rule)  # HIGH
    detector.check_resource(
        resource_id="bucket-1",
        resource_type="s3_bucket",
        actual_config={"block_public_acls": False, "block_public_policy": False},
        provider=CloudProvider.AWS,
        org_id="org-test",
    )
    detector.check_resource(
        resource_id="sg-1",
        resource_type="security_group",
        actual_config={"allow_ssh_from_any": True},
        provider=CloudProvider.AWS,
        org_id="org-test",
    )
    critical = detector.get_active_drifts(org_id="org-test", severity_filter=DriftSeverity.CRITICAL)
    assert all(d.severity == DriftSeverity.CRITICAL for d in critical)
    assert len(critical) >= 1


# ---------------------------------------------------------------------------
# Summary calculation
# ---------------------------------------------------------------------------


def test_get_drift_summary_empty(detector):
    summary = detector.get_drift_summary(org_id="org-test")
    assert summary.total_resources == 0
    assert summary.compliant == 0
    assert summary.drifted == 0
    assert summary.compliance_rate == 100.0


def test_get_drift_summary_with_drifts(detector, s3_rule, sg_rule):
    detector.add_baseline_rule(s3_rule)
    detector.add_baseline_rule(sg_rule)
    detector.check_resource(
        resource_id="bucket-1",
        resource_type="s3_bucket",
        actual_config={"block_public_acls": False, "block_public_policy": False},
        provider=CloudProvider.AWS,
        org_id="org-test",
    )
    detector.check_resource(
        resource_id="sg-1",
        resource_type="security_group",
        actual_config={"allow_ssh_from_any": True},
        provider=CloudProvider.AWS,
        org_id="org-test",
    )
    summary = detector.get_drift_summary(org_id="org-test")
    assert summary.drifted == 2
    assert summary.total_resources == 2
    assert summary.compliance_rate == 0.0
    assert summary.by_severity[DriftSeverity.CRITICAL.value] >= 1
    assert summary.by_severity[DriftSeverity.HIGH.value] >= 1


def test_get_drift_trend(detector, s3_rule):
    detector.add_baseline_rule(s3_rule)
    detector.check_resource(
        resource_id="bucket-1",
        resource_type="s3_bucket",
        actual_config={"block_public_acls": False, "block_public_policy": False},
        provider=CloudProvider.AWS,
        org_id="org-test",
    )
    trend = detector.get_drift_trend(org_id="org-test", days=30)
    assert isinstance(trend, list)
    assert len(trend) >= 1
    assert "date" in trend[0]
    assert "count" in trend[0]


# ---------------------------------------------------------------------------
# Default CIS baselines
# ---------------------------------------------------------------------------


def test_get_default_baselines_not_empty(detector):
    defaults = detector.get_default_baselines()
    assert len(defaults) >= 12


def test_get_default_baselines_has_aws_rules(detector):
    defaults = detector.get_default_baselines()
    aws_rules = [r for r in defaults if r.provider == CloudProvider.AWS]
    assert len(aws_rules) >= 5


def test_get_default_baselines_has_azure_rules(detector):
    defaults = detector.get_default_baselines()
    azure_rules = [r for r in defaults if r.provider == CloudProvider.AZURE]
    assert len(azure_rules) >= 3


def test_get_default_baselines_has_gcp_rules(detector):
    defaults = detector.get_default_baselines()
    gcp_rules = [r for r in defaults if r.provider == CloudProvider.GCP]
    assert len(gcp_rules) >= 3


def test_default_baselines_have_cis_benchmarks(detector):
    defaults = detector.get_default_baselines()
    with_cis = [r for r in defaults if r.cis_benchmark]
    assert len(with_cis) >= 10


def test_get_remediation(detector, s3_rule):
    detector.add_baseline_rule(s3_rule)
    results = detector.check_resource(
        resource_id="bucket-1",
        resource_type="s3_bucket",
        actual_config={"block_public_acls": False, "block_public_policy": False},
        provider=CloudProvider.AWS,
        org_id="org-test",
    )
    drift_id = results[0].id
    remediation = detector.get_remediation(drift_id)
    assert isinstance(remediation, str)
    assert len(remediation) > 0


def test_get_remediation_unknown_id(detector):
    result = detector.get_remediation("nonexistent-id")
    assert "not found" in result.lower()
