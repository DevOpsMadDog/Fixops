"""Tests for Marketplace service — file persistence, items, purchases, contributors."""
import json
import os
import uuid
from unittest.mock import patch

import pytest


class TestMarketplaceEnums:
    """Test marketplace enum types and data models."""

    def test_qa_status_values(self):
        from core.services.enterprise.marketplace import QAStatus
        assert QAStatus.passed.value == "passed"
        assert QAStatus.warning.value == "warning"
        assert QAStatus.failed.value == "failed"

    def test_content_type_values(self):
        from core.services.enterprise.marketplace import ContentType
        assert ContentType.policy_template.value == "policy_template"
        assert ContentType.compliance_testset.value == "compliance_testset"
        assert ContentType.mitigation_playbook.value == "mitigation_playbook"
        assert ContentType.attack_scenario.value == "attack_scenario"
        assert ContentType.pipeline_gate.value == "pipeline_gate"

    def test_pricing_model_values(self):
        from core.services.enterprise.marketplace import PricingModel
        assert PricingModel.free.value == "free"
        assert PricingModel.one_time.value == "one_time"
        assert PricingModel.subscription.value == "subscription"


class TestContributorProfile:
    def test_create_default(self):
        from core.services.enterprise.marketplace import ContributorProfile
        cp = ContributorProfile(author="test-author", organization="test-org")
        assert cp.author == "test-author"
        assert cp.organization == "test-org"
        assert cp.submissions == 0
        assert cp.validated_submissions == 0
        assert cp.reputation_score == 0.0

    def test_to_dict(self):
        from core.services.enterprise.marketplace import ContributorProfile
        cp = ContributorProfile(
            author="alice", organization="acme",
            submissions=5, validated_submissions=3,
            adoption_events=10, total_rating=20.0,
            rating_count=4, average_rating=5.0,
            reputation_score=0.85,
        )
        d = cp.to_dict()
        assert d["author"] == "alice"
        assert d["submissions"] == 5
        assert d["reputation_score"] == 0.85

    def test_from_dict(self):
        from core.services.enterprise.marketplace import ContributorProfile
        data = {
            "author": "bob",
            "organization": "widgets",
            "submissions": 3,
            "validated_submissions": 2,
            "adoption_events": 7,
            "total_rating": 14.5,
            "rating_count": 3,
            "average_rating": 4.83,
            "reputation_score": 0.72,
            "last_submission_at": "2024-01-01T00:00:00Z",
        }
        cp = ContributorProfile.from_dict(data)
        assert cp.author == "bob"
        assert cp.submissions == 3
        assert cp.last_submission_at == "2024-01-01T00:00:00Z"

    def test_from_dict_defaults(self):
        from core.services.enterprise.marketplace import ContributorProfile
        cp = ContributorProfile.from_dict({})
        assert cp.author == "unknown"
        assert cp.organization == "unknown"
        assert cp.submissions == 0

    def test_roundtrip(self):
        from core.services.enterprise.marketplace import ContributorProfile
        original = ContributorProfile(
            author="test", organization="org",
            submissions=10, validated_submissions=8,
        )
        d = original.to_dict()
        restored = ContributorProfile.from_dict(d)
        assert restored.author == original.author
        assert restored.submissions == original.submissions


class TestMarketplaceItemModel:
    def test_create_with_defaults(self):
        from core.services.enterprise.marketplace import (
            MarketplaceItemModel, ContentType, PricingModel,
        )
        item = MarketplaceItemModel(
            id="test-123",
            name="Test Policy",
            content_type=ContentType.policy_template,
        )
        assert item.id == "test-123"
        assert item.name == "Test Policy"
        assert item.pricing_model == PricingModel.free
        assert item.price == 0.0
        assert item.rating == 4.6

    def test_create_paid_item(self):
        from core.services.enterprise.marketplace import (
            MarketplaceItemModel, ContentType, PricingModel,
        )
        item = MarketplaceItemModel(
            id="paid-001",
            name="Premium Playbook",
            content_type=ContentType.mitigation_playbook,
            pricing_model=PricingModel.one_time,
            price=99.99,
            tags=["premium", "remediation"],
        )
        assert item.pricing_model == PricingModel.one_time
        assert item.price == 99.99
        assert "premium" in item.tags


class TestMarketplaceItem:
    def test_create_dataclass(self):
        from core.services.enterprise.marketplace import (
            MarketplaceItem, ContentType, PricingModel,
        )
        item = MarketplaceItem(
            id=str(uuid.uuid4()),
            name="Test Item",
            description="A test item",
            content_type=ContentType.attack_scenario,
            compliance_frameworks=["mitre_attack"],
            ssdlc_stages=["test"],
            pricing_model=PricingModel.free,
        )
        assert item.name == "Test Item"
        assert item.downloads == 0
        assert item.rating == 4.6
        assert item.version == "1.0.0"


class TestMarketplaceService:
    @pytest.fixture
    def temp_marketplace_dir(self, tmp_path):
        """Use a temporary directory for marketplace data."""
        marketplace_dir = tmp_path / "marketplace"
        marketplace_dir.mkdir()
        with patch.dict(os.environ, {"FIXOPS_MARKETPLACE_DIR": str(marketplace_dir)}):
            # Need to reload the module to pick up new env var
            import core.services.enterprise.marketplace as mp_module
            original_data_dir = mp_module.DATA_DIR
            original_items = mp_module.ITEMS_FILE
            original_purchases = mp_module.PURCHASES_FILE
            original_contributors = mp_module.CONTRIBUTORS_FILE
            mp_module.DATA_DIR = marketplace_dir
            mp_module.ITEMS_FILE = marketplace_dir / "items.json"
            mp_module.PURCHASES_FILE = marketplace_dir / "purchases.json"
            mp_module.CONTRIBUTORS_FILE = marketplace_dir / "contributors.json"
            yield marketplace_dir
            # Restore
            mp_module.DATA_DIR = original_data_dir
            mp_module.ITEMS_FILE = original_items
            mp_module.PURCHASES_FILE = original_purchases
            mp_module.CONTRIBUTORS_FILE = original_contributors

    def test_init_seeds_items(self, temp_marketplace_dir):
        from core.services.enterprise.marketplace import MarketplaceService
        svc = MarketplaceService(secret="test-secret")
        assert len(svc._items) > 0

    def test_init_persists_data(self, temp_marketplace_dir):
        from core.services.enterprise.marketplace import MarketplaceService
        MarketplaceService(secret="test-secret")
        items_file = temp_marketplace_dir / "items.json"
        assert items_file.exists()
        data = json.loads(items_file.read_text())
        assert len(data) > 0

    def test_default_secret(self, temp_marketplace_dir):
        from core.services.enterprise.marketplace import MarketplaceService
        svc = MarketplaceService()
        assert svc._secret == b"fixops-secret"

    def test_custom_secret(self, temp_marketplace_dir):
        from core.services.enterprise.marketplace import MarketplaceService
        svc = MarketplaceService(secret="my-custom-secret")
        assert svc._secret == b"my-custom-secret"
