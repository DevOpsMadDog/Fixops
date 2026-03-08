"""Tests for PolicyDB — policy management database."""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

import pytest
from core.policy_models import Policy, PolicyStatus


# ---------------------------------------------------------------------------
# Model tests
# ---------------------------------------------------------------------------
class TestPolicyModels:
    def test_policy_status_enum(self):
        assert PolicyStatus.ACTIVE == "active"
        assert PolicyStatus.DRAFT == "draft"
        assert PolicyStatus.ARCHIVED == "archived"

    def test_policy_to_dict(self):
        policy = Policy(
            id="p-1",
            name="Critical Vuln SLA",
            description="SLA for critical vulnerabilities",
            policy_type="sla",
            status=PolicyStatus.ACTIVE,
            rules={"max_days": 7, "severity": "critical"},
            created_by="admin",
        )
        d = policy.to_dict()
        assert d["id"] == "p-1"
        assert d["name"] == "Critical Vuln SLA"
        assert d["policy_type"] == "sla"
        assert d["status"] == "active"
        assert d["rules"]["max_days"] == 7


# ---------------------------------------------------------------------------
# PolicyDB tests
# ---------------------------------------------------------------------------
class TestPolicyDB:
    @pytest.fixture
    def db(self, tmp_path):
        from core.policy_db import PolicyDB
        return PolicyDB(db_path=str(tmp_path / "test_policies.db"))

    @pytest.fixture
    def sample_policy(self, db):
        policy = Policy(
            id="",
            name="Test Policy",
            description="A test policy",
            policy_type="security",
            status=PolicyStatus.ACTIVE,
            rules={"min_score": 7.0},
            created_by="test",
        )
        return db.create_policy(policy)

    def test_create_policy(self, db):
        policy = Policy(
            id="",
            name="New Policy",
            description="Brand new",
            policy_type="compliance",
            status=PolicyStatus.DRAFT,
            rules={"framework": "SOC2"},
        )
        created = db.create_policy(policy)
        assert created.id != ""
        assert created.name == "New Policy"

    def test_get_policy(self, db, sample_policy):
        policy = db.get_policy(sample_policy.id)
        assert policy is not None
        assert policy.name == "Test Policy"
        assert policy.rules["min_score"] == 7.0

    def test_get_policy_not_found(self, db):
        assert db.get_policy("nonexistent") is None

    def test_list_policies(self, db, sample_policy):
        policies = db.list_policies()
        assert len(policies) >= 1

    def test_list_policies_by_type(self, db):
        db.create_policy(Policy(
            id="", name="Sec Policy", description="Security",
            policy_type="security", status=PolicyStatus.ACTIVE,
        ))
        db.create_policy(Policy(
            id="", name="Comp Policy", description="Compliance",
            policy_type="compliance", status=PolicyStatus.ACTIVE,
        ))
        sec_policies = db.list_policies(policy_type="security")
        assert len(sec_policies) >= 1
        assert all(p.policy_type == "security" for p in sec_policies)

    def test_update_policy(self, db, sample_policy):
        sample_policy.name = "Updated Policy"
        sample_policy.status = PolicyStatus.ARCHIVED
        updated = db.update_policy(sample_policy)
        assert updated.name == "Updated Policy"
        from_db = db.get_policy(sample_policy.id)
        assert from_db.status == PolicyStatus.ARCHIVED

    def test_delete_policy(self, db, sample_policy):
        result = db.delete_policy(sample_policy.id)
        assert result is True
        assert db.get_policy(sample_policy.id) is None

    def test_list_policies_pagination(self, db):
        for i in range(5):
            db.create_policy(Policy(
                id="", name=f"Policy {i}", description=f"Desc {i}",
                policy_type="sla", status=PolicyStatus.ACTIVE,
            ))
        page1 = db.list_policies(limit=3)
        page2 = db.list_policies(limit=3, offset=3)
        assert len(page1) == 3
        assert len(page2) == 2
