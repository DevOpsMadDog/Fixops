"""Tests for suite-core/core/data_classification.py — Data Classification Engine.

Tests cover:
- ClassificationLevel / DataCategory enums
- ClassifiedAsset Pydantic model
- DataClassificationEngine: classify_asset, auto_classify, get_asset_classification,
  list_classified_assets, get_handling_instructions, upgrade_classification,
  downgrade_classification, get_classification_stats, audit_classification_changes
- Built-in PII/PHI/PCI/credentials pattern detection
- SQLite persistence (via tmp_path fixture)
- Edge cases: not found, invalid upgrades/downgrades, missing approvals

Usage:
    pytest tests/test_data_classification.py -v --timeout=10
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Ensure suite-core is importable
_suite_core = str(Path(__file__).parent.parent / "suite-core")
if _suite_core not in sys.path:
    sys.path.insert(0, _suite_core)

from core.data_classification import (
    AutoClassifyResult,
    ClassificationChange,
    ClassificationLevel,
    ClassifiedAsset,
    DataCategory,
    DataClassificationEngine,
    _HANDLING_INSTRUCTIONS,
    _LEVEL_ORDER,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine(tmp_path):
    """Fresh engine backed by a temp SQLite DB."""
    db = str(tmp_path / "classification_test.db")
    return DataClassificationEngine(db_path=db)


@pytest.fixture
def sample_asset():
    return ClassifiedAsset(
        id="ca-test0001",
        name="User PII export",
        path="/data/exports/users.csv",
        classification_level=ClassificationLevel.CUI,
        categories=[DataCategory.PII],
        owner="alice@example.com",
        org_id="org-1",
    )


# ---------------------------------------------------------------------------
# Enum tests
# ---------------------------------------------------------------------------

class TestClassificationLevel:
    def test_all_levels_present(self):
        levels = {l.value for l in ClassificationLevel}
        assert levels == {"UNCLASSIFIED", "CUI", "CONFIDENTIAL", "SECRET", "TOP_SECRET"}

    def test_level_ordering(self):
        assert _LEVEL_ORDER[ClassificationLevel.UNCLASSIFIED] < _LEVEL_ORDER[ClassificationLevel.CUI]
        assert _LEVEL_ORDER[ClassificationLevel.CUI] < _LEVEL_ORDER[ClassificationLevel.CONFIDENTIAL]
        assert _LEVEL_ORDER[ClassificationLevel.CONFIDENTIAL] < _LEVEL_ORDER[ClassificationLevel.SECRET]
        assert _LEVEL_ORDER[ClassificationLevel.SECRET] < _LEVEL_ORDER[ClassificationLevel.TOP_SECRET]

    def test_str_enum(self):
        assert ClassificationLevel.SECRET == "SECRET"


class TestDataCategory:
    def test_all_categories_present(self):
        cats = {c.value for c in DataCategory}
        assert "PII" in cats
        assert "PHI" in cats
        assert "PCI" in cats
        assert "FINANCIAL" in cats
        assert "CREDENTIALS" in cats
        assert "SOURCE_CODE" in cats
        assert "CONFIGURATION" in cats
        assert "TELEMETRY" in cats

    def test_str_enum(self):
        assert DataCategory.PII == "PII"


# ---------------------------------------------------------------------------
# Model tests
# ---------------------------------------------------------------------------

class TestClassifiedAsset:
    def test_defaults(self):
        asset = ClassifiedAsset(name="test", org_id="org-x")
        assert asset.classification_level == ClassificationLevel.UNCLASSIFIED
        assert asset.categories == []
        assert asset.encryption_required is False
        assert asset.retention_days == 365
        assert asset.id.startswith("ca-")

    def test_full_construction(self, sample_asset):
        assert sample_asset.name == "User PII export"
        assert sample_asset.classification_level == ClassificationLevel.CUI
        assert DataCategory.PII in sample_asset.categories
        assert sample_asset.owner == "alice@example.com"


# ---------------------------------------------------------------------------
# classify_asset
# ---------------------------------------------------------------------------

class TestClassifyAsset:
    def test_classify_new_asset(self, engine, sample_asset):
        result = engine.classify_asset(sample_asset)
        assert result.id == sample_asset.id
        assert result.classification_level == ClassificationLevel.CUI

    def test_auto_sets_handling_instructions(self, engine):
        asset = ClassifiedAsset(
            name="secrets file",
            classification_level=ClassificationLevel.SECRET,
            org_id="org-1",
        )
        result = engine.classify_asset(asset)
        assert result.handling_instructions is not None
        assert "SCIF" in result.handling_instructions

    def test_auto_sets_encryption_for_secret(self, engine):
        asset = ClassifiedAsset(
            name="top secret doc",
            classification_level=ClassificationLevel.SECRET,
            org_id="org-1",
        )
        result = engine.classify_asset(asset)
        assert result.encryption_required is True

    def test_auto_sets_encryption_for_top_secret(self, engine):
        asset = ClassifiedAsset(
            name="ts doc",
            classification_level=ClassificationLevel.TOP_SECRET,
            org_id="org-1",
        )
        result = engine.classify_asset(asset)
        assert result.encryption_required is True

    def test_unclassified_no_encryption(self, engine):
        asset = ClassifiedAsset(
            name="public doc",
            classification_level=ClassificationLevel.UNCLASSIFIED,
            org_id="org-1",
        )
        result = engine.classify_asset(asset)
        assert result.encryption_required is False

    def test_classify_persists(self, engine, sample_asset):
        engine.classify_asset(sample_asset)
        retrieved = engine.get_asset_classification(sample_asset.id)
        assert retrieved is not None
        assert retrieved.name == sample_asset.name

    def test_classify_records_audit_change(self, engine, sample_asset):
        engine.classify_asset(sample_asset)
        changes = engine.audit_classification_changes(asset_id=sample_asset.id)
        assert len(changes) >= 1
        assert changes[0].action in ("classify", "update")

    def test_update_existing_asset(self, engine, sample_asset):
        engine.classify_asset(sample_asset)
        sample_asset.classification_level = ClassificationLevel.CONFIDENTIAL
        result = engine.classify_asset(sample_asset)
        assert result.classification_level == ClassificationLevel.CONFIDENTIAL


# ---------------------------------------------------------------------------
# auto_classify — PII patterns
# ---------------------------------------------------------------------------

class TestAutoClassifyPII:
    def test_detects_ssn(self, engine):
        result = engine.auto_classify(
            "Patient SSN: 123-45-6789",
            asset_id="a-ssn",
            apply=False,
        )
        assert DataCategory.PII in result.detected_categories
        assert "ssn" in result.matches.get("PII", []) or any(
            "123-45-6789" in m for m in result.matches.get("PII", [])
        )

    def test_detects_email(self, engine):
        result = engine.auto_classify(
            "Contact: john.doe@example.com for more info",
            asset_id="a-email",
            apply=False,
        )
        assert DataCategory.PII in result.detected_categories

    def test_detects_phone(self, engine):
        result = engine.auto_classify(
            "Call us at 555-867-5309",
            asset_id="a-phone",
            apply=False,
        )
        assert DataCategory.PII in result.detected_categories

    def test_no_pii_clean_content(self, engine):
        result = engine.auto_classify(
            "The quick brown fox jumps over the lazy dog.",
            asset_id="a-clean",
            apply=False,
        )
        assert DataCategory.PII not in result.detected_categories


# ---------------------------------------------------------------------------
# auto_classify — PHI patterns
# ---------------------------------------------------------------------------

class TestAutoClassifyPHI:
    def test_detects_medical_record(self, engine):
        result = engine.auto_classify(
            "MRN: MR-00192837 admitted 2023-01-01",
            asset_id="a-mrn",
            apply=False,
        )
        assert DataCategory.PHI in result.detected_categories

    def test_detects_patient_keyword(self, engine):
        result = engine.auto_classify(
            "patient John Smith was treated for hypertension",
            asset_id="a-patient",
            apply=False,
        )
        assert DataCategory.PHI in result.detected_categories

    def test_phi_recommends_confidential_or_higher(self, engine):
        result = engine.auto_classify(
            "MRN: MR-12345 patient John",
            asset_id="a-phi-level",
            apply=False,
        )
        assert DataCategory.PHI in result.detected_categories
        assert _LEVEL_ORDER[result.recommended_level] >= _LEVEL_ORDER[ClassificationLevel.CONFIDENTIAL]


# ---------------------------------------------------------------------------
# auto_classify — PCI patterns
# ---------------------------------------------------------------------------

class TestAutoClassifyPCI:
    def test_detects_visa(self, engine):
        result = engine.auto_classify(
            "Card: 4111-1111-1111-1111 exp 12/26",
            asset_id="a-visa",
            apply=False,
        )
        assert DataCategory.PCI in result.detected_categories

    def test_detects_mastercard(self, engine):
        result = engine.auto_classify(
            "Payment method: 5500 0000 0000 0004",
            asset_id="a-mc",
            apply=False,
        )
        assert DataCategory.PCI in result.detected_categories

    def test_pci_recommends_confidential_or_higher(self, engine):
        result = engine.auto_classify(
            "Visa: 4111111111111111",
            asset_id="a-pci-level",
            apply=False,
        )
        assert _LEVEL_ORDER[result.recommended_level] >= _LEVEL_ORDER[ClassificationLevel.CONFIDENTIAL]


# ---------------------------------------------------------------------------
# auto_classify — Credentials patterns
# ---------------------------------------------------------------------------

class TestAutoClassifyCredentials:
    def test_detects_private_key(self, engine):
        result = engine.auto_classify(
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...",
            asset_id="a-privkey",
            apply=False,
        )
        assert DataCategory.CREDENTIALS in result.detected_categories

    def test_detects_aws_key(self, engine):
        result = engine.auto_classify(
            "AWS Access Key: AKIAIOSFODNN7EXAMPLE",
            asset_id="a-aws",
            apply=False,
        )
        assert DataCategory.CREDENTIALS in result.detected_categories

    def test_credentials_recommend_secret(self, engine):
        result = engine.auto_classify(
            "AKIAIOSFODNN7EXAMPLE is the key",
            asset_id="a-cred-level",
            apply=False,
        )
        assert _LEVEL_ORDER[result.recommended_level] >= _LEVEL_ORDER[ClassificationLevel.SECRET]


# ---------------------------------------------------------------------------
# auto_classify — apply=True
# ---------------------------------------------------------------------------

class TestAutoClassifyApply:
    def test_apply_creates_asset(self, engine):
        result = engine.auto_classify(
            "SSN: 123-45-6789",
            asset_id="a-apply-new",
            org_id="org-apply",
            apply=True,
        )
        assert result.applied is True
        stored = engine.get_asset_classification("a-apply-new")
        assert stored is not None
        assert DataCategory.PII in stored.categories

    def test_apply_merges_with_existing(self, engine):
        # Create an existing CUI asset
        existing = ClassifiedAsset(
            id="a-merge",
            name="merge test",
            classification_level=ClassificationLevel.CUI,
            categories=[DataCategory.CONFIGURATION],
            org_id="org-merge",
        )
        engine.classify_asset(existing)

        # Auto-classify with credentials content — should upgrade
        result = engine.auto_classify(
            "AKIAIOSFODNN7EXAMPLE secret key",
            asset_id="a-merge",
            org_id="org-merge",
            apply=True,
        )
        assert result.applied is True
        stored = engine.get_asset_classification("a-merge")
        assert _LEVEL_ORDER[stored.classification_level] >= _LEVEL_ORDER[ClassificationLevel.SECRET]


# ---------------------------------------------------------------------------
# get_asset_classification
# ---------------------------------------------------------------------------

class TestGetAssetClassification:
    def test_returns_none_for_unknown(self, engine):
        assert engine.get_asset_classification("nonexistent-id") is None

    def test_returns_correct_asset(self, engine, sample_asset):
        engine.classify_asset(sample_asset)
        result = engine.get_asset_classification(sample_asset.id)
        assert result.id == sample_asset.id
        assert result.classification_level == ClassificationLevel.CUI


# ---------------------------------------------------------------------------
# list_classified_assets
# ---------------------------------------------------------------------------

class TestListClassifiedAssets:
    def test_list_all(self, engine):
        for i in range(3):
            engine.classify_asset(ClassifiedAsset(
                id=f"list-{i}",
                name=f"asset {i}",
                classification_level=ClassificationLevel.CUI,
                org_id="org-list",
            ))
        assets = engine.list_classified_assets("org-list")
        assert len(assets) == 3

    def test_filter_by_level(self, engine):
        engine.classify_asset(ClassifiedAsset(
            id="filt-cui", name="cui asset",
            classification_level=ClassificationLevel.CUI,
            org_id="org-filt",
        ))
        engine.classify_asset(ClassifiedAsset(
            id="filt-secret", name="secret asset",
            classification_level=ClassificationLevel.SECRET,
            org_id="org-filt",
        ))
        results = engine.list_classified_assets("org-filt", level=ClassificationLevel.SECRET)
        assert len(results) == 1
        assert results[0].id == "filt-secret"

    def test_filter_by_category(self, engine):
        engine.classify_asset(ClassifiedAsset(
            id="cat-pii", name="pii doc",
            classification_level=ClassificationLevel.CUI,
            categories=[DataCategory.PII],
            org_id="org-cat",
        ))
        engine.classify_asset(ClassifiedAsset(
            id="cat-phi", name="phi doc",
            classification_level=ClassificationLevel.CONFIDENTIAL,
            categories=[DataCategory.PHI],
            org_id="org-cat",
        ))
        results = engine.list_classified_assets("org-cat", category=DataCategory.PHI)
        assert len(results) == 1
        assert results[0].id == "cat-phi"

    def test_org_isolation(self, engine):
        engine.classify_asset(ClassifiedAsset(
            id="iso-1", name="org-a asset", org_id="org-a"))
        engine.classify_asset(ClassifiedAsset(
            id="iso-2", name="org-b asset", org_id="org-b"))
        results = engine.list_classified_assets("org-a")
        assert all(a.org_id == "org-a" for a in results)


# ---------------------------------------------------------------------------
# get_handling_instructions
# ---------------------------------------------------------------------------

class TestHandlingInstructions:
    def test_all_levels_have_instructions(self, engine):
        for level in ClassificationLevel:
            instructions = engine.get_handling_instructions(level)
            assert isinstance(instructions, str)
            assert len(instructions) > 10

    def test_top_secret_mentions_scif(self, engine):
        instructions = engine.get_handling_instructions(ClassificationLevel.TOP_SECRET)
        assert "SCIF" in instructions or "air-gap" in instructions.lower() or "Air-gap" in instructions

    def test_unclassified_is_permissive(self, engine):
        instructions = engine.get_handling_instructions(ClassificationLevel.UNCLASSIFIED)
        assert "No special handling" in instructions or "standard" in instructions.lower()


# ---------------------------------------------------------------------------
# upgrade_classification
# ---------------------------------------------------------------------------

class TestUpgradeClassification:
    def test_upgrade_succeeds(self, engine, sample_asset):
        engine.classify_asset(sample_asset)
        result = engine.upgrade_classification(
            sample_asset.id,
            ClassificationLevel.SECRET,
            changed_by="admin",
            reason="new sensitivity discovered",
        )
        assert result.classification_level == ClassificationLevel.SECRET
        assert result.encryption_required is True

    def test_upgrade_records_audit(self, engine, sample_asset):
        engine.classify_asset(sample_asset)
        engine.upgrade_classification(
            sample_asset.id, ClassificationLevel.SECRET, changed_by="admin"
        )
        changes = engine.audit_classification_changes(asset_id=sample_asset.id)
        upgrade_changes = [c for c in changes if c.action == "upgrade"]
        assert len(upgrade_changes) == 1
        assert upgrade_changes[0].previous_level == ClassificationLevel.CUI
        assert upgrade_changes[0].new_level == ClassificationLevel.SECRET

    def test_upgrade_to_same_level_raises(self, engine, sample_asset):
        engine.classify_asset(sample_asset)
        with pytest.raises(ValueError, match="higher level"):
            engine.upgrade_classification(
                sample_asset.id, ClassificationLevel.CUI
            )

    def test_upgrade_to_lower_level_raises(self, engine, sample_asset):
        engine.classify_asset(sample_asset)
        with pytest.raises(ValueError, match="higher level"):
            engine.upgrade_classification(
                sample_asset.id, ClassificationLevel.UNCLASSIFIED
            )

    def test_upgrade_nonexistent_asset_raises(self, engine):
        with pytest.raises(ValueError, match="Asset not found"):
            engine.upgrade_classification("nonexistent", ClassificationLevel.SECRET)


# ---------------------------------------------------------------------------
# downgrade_classification
# ---------------------------------------------------------------------------

class TestDowngradeClassification:
    def test_downgrade_succeeds(self, engine):
        asset = ClassifiedAsset(
            id="dg-test", name="downgrade test",
            classification_level=ClassificationLevel.SECRET,
            org_id="org-dg",
        )
        engine.classify_asset(asset)
        result = engine.downgrade_classification(
            "dg-test",
            ClassificationLevel.CUI,
            changed_by="security-officer",
            approval_id="APPR-001",
            reason="data no longer sensitive after scrubbing",
        )
        assert result.classification_level == ClassificationLevel.CUI

    def test_downgrade_records_audit_with_approval(self, engine):
        asset = ClassifiedAsset(
            id="dg-audit", name="audit downgrade",
            classification_level=ClassificationLevel.CONFIDENTIAL,
            org_id="org-dg",
        )
        engine.classify_asset(asset)
        engine.downgrade_classification(
            "dg-audit", ClassificationLevel.UNCLASSIFIED,
            changed_by="officer", approval_id="APPR-999", reason="cleared for release"
        )
        changes = engine.audit_classification_changes(asset_id="dg-audit")
        dg_changes = [c for c in changes if c.action == "downgrade"]
        assert len(dg_changes) == 1
        assert dg_changes[0].approval_id == "APPR-999"

    def test_downgrade_to_higher_level_raises(self, engine):
        asset = ClassifiedAsset(
            id="dg-bad", name="bad downgrade",
            classification_level=ClassificationLevel.CUI,
            org_id="org-dg",
        )
        engine.classify_asset(asset)
        with pytest.raises(ValueError, match="lower level"):
            engine.downgrade_classification(
                "dg-bad", ClassificationLevel.SECRET,
                changed_by="officer", approval_id="APPR-X", reason="test"
            )

    def test_downgrade_without_approval_raises(self, engine):
        asset = ClassifiedAsset(
            id="dg-noappr", name="no approval",
            classification_level=ClassificationLevel.SECRET,
            org_id="org-dg",
        )
        engine.classify_asset(asset)
        with pytest.raises(ValueError, match="approval_id"):
            engine.downgrade_classification(
                "dg-noappr", ClassificationLevel.CUI,
                changed_by="officer", approval_id="", reason="some reason"
            )

    def test_downgrade_without_reason_raises(self, engine):
        asset = ClassifiedAsset(
            id="dg-norsn", name="no reason",
            classification_level=ClassificationLevel.SECRET,
            org_id="org-dg",
        )
        engine.classify_asset(asset)
        with pytest.raises(ValueError, match="approval_id"):
            engine.downgrade_classification(
                "dg-norsn", ClassificationLevel.CUI,
                changed_by="officer", approval_id="APPR-Y", reason=""
            )

    def test_downgrade_nonexistent_raises(self, engine):
        with pytest.raises(ValueError, match="Asset not found"):
            engine.downgrade_classification(
                "nonexistent", ClassificationLevel.UNCLASSIFIED,
                changed_by="officer", approval_id="APPR-Z", reason="test"
            )


# ---------------------------------------------------------------------------
# get_classification_stats
# ---------------------------------------------------------------------------

class TestClassificationStats:
    def test_stats_empty_org(self, engine):
        stats = engine.get_classification_stats("org-empty")
        assert stats["total_assets"] == 0
        assert stats["by_level"] == {}

    def test_stats_counts_correctly(self, engine):
        for i in range(2):
            engine.classify_asset(ClassifiedAsset(
                id=f"stat-cui-{i}", name=f"cui {i}",
                classification_level=ClassificationLevel.CUI,
                categories=[DataCategory.PII],
                org_id="org-stats",
            ))
        engine.classify_asset(ClassifiedAsset(
            id="stat-secret", name="secret",
            classification_level=ClassificationLevel.SECRET,
            categories=[DataCategory.CREDENTIALS],
            org_id="org-stats",
        ))
        stats = engine.get_classification_stats("org-stats")
        assert stats["total_assets"] == 3
        assert stats["by_level"].get("CUI") == 2
        assert stats["by_level"].get("SECRET") == 1

    def test_stats_by_category(self, engine):
        engine.classify_asset(ClassifiedAsset(
            id="sc-1", name="pii asset",
            classification_level=ClassificationLevel.CUI,
            categories=[DataCategory.PII, DataCategory.PHI],
            org_id="org-cat-stats",
        ))
        stats = engine.get_classification_stats("org-cat-stats")
        assert stats["by_category"].get("PII") == 1
        assert stats["by_category"].get("PHI") == 1

    def test_stats_encrypted_count(self, engine):
        engine.classify_asset(ClassifiedAsset(
            id="enc-1", name="enc asset",
            classification_level=ClassificationLevel.SECRET,
            org_id="org-enc",
        ))
        stats = engine.get_classification_stats("org-enc")
        assert stats["encrypted_count"] >= 1


# ---------------------------------------------------------------------------
# audit_classification_changes
# ---------------------------------------------------------------------------

class TestAuditClassificationChanges:
    def test_returns_all_changes(self, engine, sample_asset):
        engine.classify_asset(sample_asset)
        engine.upgrade_classification(sample_asset.id, ClassificationLevel.CONFIDENTIAL)
        changes = engine.audit_classification_changes()
        assert len(changes) >= 2

    def test_filter_by_asset_id(self, engine, sample_asset):
        engine.classify_asset(sample_asset)
        other = ClassifiedAsset(id="other-asset", name="other", org_id="org-1")
        engine.classify_asset(other)
        changes = engine.audit_classification_changes(asset_id=sample_asset.id)
        assert all(c.asset_id == sample_asset.id for c in changes)

    def test_filter_by_action(self, engine, sample_asset):
        engine.classify_asset(sample_asset)
        engine.upgrade_classification(sample_asset.id, ClassificationLevel.SECRET)
        upgrade_changes = engine.audit_classification_changes(action="upgrade")
        assert all(c.action == "upgrade" for c in upgrade_changes)
        assert len(upgrade_changes) >= 1

    def test_limit_respected(self, engine):
        for i in range(10):
            engine.classify_asset(ClassifiedAsset(
                id=f"lim-{i}", name=f"asset {i}", org_id="org-lim"
            ))
        changes = engine.audit_classification_changes(limit=3)
        assert len(changes) <= 3

    def test_change_model_fields(self, engine, sample_asset):
        engine.classify_asset(sample_asset)
        changes = engine.audit_classification_changes(asset_id=sample_asset.id)
        assert len(changes) >= 1
        change = changes[0]
        assert isinstance(change, ClassificationChange)
        assert change.asset_id == sample_asset.id
        assert change.new_level == ClassificationLevel.CUI
        assert change.timestamp is not None
