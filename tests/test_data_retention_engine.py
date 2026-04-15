"""Tests for DataRetentionEngine.

Covers: init, policy CRUD, dataset registration, legal hold toggle,
schedule/complete deletion, deletion audit trail, stats structure,
org isolation.

Total: 28 tests
"""

from __future__ import annotations

import os
import pytest
from core.data_retention_engine import DataRetentionEngine


@pytest.fixture
def engine(tmp_path):
    return DataRetentionEngine(db_path=str(tmp_path / "test.db"))


# ---------------------------------------------------------------------------
# 1. Initialisation
# ---------------------------------------------------------------------------


def test_init_creates_db(tmp_path):
    db = str(tmp_path / "dr_init.db")
    DataRetentionEngine(db_path=db)
    assert os.path.exists(db)


def test_init_idempotent(tmp_path):
    db = str(tmp_path / "dr_idem.db")
    DataRetentionEngine(db_path=db)
    DataRetentionEngine(db_path=db)  # no error on second init


# ---------------------------------------------------------------------------
# 2. Policy CRUD
# ---------------------------------------------------------------------------


def test_create_policy_returns_dict(engine):
    pol = engine.create_policy("org1", {
        "policy_name": "GDPR Logs",
        "data_category": "logs",
        "retention_days": 90,
        "action_on_expiry": "delete",
        "legal_hold": False,
        "regulation": "GDPR",
    })
    assert pol["policy_id"]
    assert pol["policy_name"] == "GDPR Logs"
    assert pol["retention_days"] == 90
    assert pol["regulation"] == "GDPR"
    assert pol["data_category"] == "logs"
    assert pol["legal_hold"] is False


def test_create_policy_defaults(engine):
    pol = engine.create_policy("org1", {"policy_name": "Minimal"})
    assert pol["data_category"] == "logs"
    assert pol["retention_days"] == 365
    assert pol["action_on_expiry"] == "delete"
    assert pol["regulation"] == "custom"


def test_create_policy_invalid_category_defaults(engine):
    pol = engine.create_policy("org1", {"policy_name": "X", "data_category": "bogus"})
    assert pol["data_category"] == "logs"


def test_create_policy_invalid_action_defaults(engine):
    pol = engine.create_policy("org1", {"policy_name": "X", "action_on_expiry": "shred"})
    assert pol["action_on_expiry"] == "delete"


def test_create_policy_invalid_regulation_defaults(engine):
    pol = engine.create_policy("org1", {"policy_name": "X", "regulation": "FAKE"})
    assert pol["regulation"] == "custom"


def test_list_policies_empty(engine):
    assert engine.list_policies("no-org") == []


def test_list_policies_returns_all(engine):
    engine.create_policy("org1", {"policy_name": "P1", "regulation": "GDPR"})
    engine.create_policy("org1", {"policy_name": "P2", "regulation": "HIPAA"})
    pols = engine.list_policies("org1")
    assert len(pols) == 2


def test_list_policies_filter_regulation(engine):
    engine.create_policy("org1", {"policy_name": "P1", "regulation": "GDPR"})
    engine.create_policy("org1", {"policy_name": "P2", "regulation": "CCPA"})
    gdpr = engine.list_policies("org1", regulation="GDPR")
    assert len(gdpr) == 1
    assert gdpr[0]["regulation"] == "GDPR"


def test_get_policy_returns_none_for_missing(engine):
    assert engine.get_policy("org1", "nonexistent") is None


def test_get_policy_returns_policy(engine):
    pol = engine.create_policy("org1", {"policy_name": "PII Retention"})
    fetched = engine.get_policy("org1", pol["policy_id"])
    assert fetched["policy_name"] == "PII Retention"


# ---------------------------------------------------------------------------
# 3. Dataset Registration
# ---------------------------------------------------------------------------


def _make_policy(engine, org="org1", regulation="GDPR", days=30):
    return engine.create_policy(org, {
        "policy_name": "Test Policy",
        "retention_days": days,
        "regulation": regulation,
    })


def test_register_dataset_returns_dict(engine):
    pol = _make_policy(engine)
    ds = engine.register_dataset("org1", {
        "dataset_name": "Customer PII",
        "policy_id": pol["policy_id"],
        "location": "s3://bucket/pii",
        "size_bytes": 1024,
        "record_count": 500,
        "data_owner": "data-team",
    })
    assert ds["dataset_id"]
    assert ds["dataset_name"] == "Customer PII"
    assert ds["size_bytes"] == 1024
    assert ds["record_count"] == 500
    assert ds["status"] == "active"
    assert ds["legal_hold"] is False


def test_register_dataset_has_expiry_date(engine):
    pol = _make_policy(engine, days=365)
    ds = engine.register_dataset("org1", {
        "dataset_name": "Logs",
        "policy_id": pol["policy_id"],
    })
    assert ds["expiry_date"]  # non-empty string


def test_list_datasets_empty(engine):
    assert engine.list_datasets("no-org") == []


def test_list_datasets_filter_by_policy(engine):
    pol1 = _make_policy(engine)
    pol2 = _make_policy(engine)
    engine.register_dataset("org1", {"dataset_name": "D1", "policy_id": pol1["policy_id"]})
    engine.register_dataset("org1", {"dataset_name": "D2", "policy_id": pol2["policy_id"]})
    result = engine.list_datasets("org1", policy_id=pol1["policy_id"])
    assert len(result) == 1
    assert result[0]["dataset_name"] == "D1"


# ---------------------------------------------------------------------------
# 4. Legal Hold
# ---------------------------------------------------------------------------


def test_mark_legal_hold(engine):
    pol = _make_policy(engine)
    ds = engine.register_dataset("org1", {"dataset_name": "PII", "policy_id": pol["policy_id"]})
    updated = engine.mark_legal_hold("org1", ds["dataset_id"], "legal-team", "Litigation hold")
    assert updated["legal_hold"] is True
    assert updated["held_by"] == "legal-team"
    assert updated["hold_reason"] == "Litigation hold"


def test_release_legal_hold(engine):
    pol = _make_policy(engine)
    ds = engine.register_dataset("org1", {"dataset_name": "PII", "policy_id": pol["policy_id"]})
    engine.mark_legal_hold("org1", ds["dataset_id"], "legal-team", "reason")
    released = engine.release_legal_hold("org1", ds["dataset_id"], "legal-team")
    assert released["legal_hold"] is False
    assert released["held_by"] == ""


# ---------------------------------------------------------------------------
# 5. Deletion Lifecycle
# ---------------------------------------------------------------------------


def test_schedule_deletion(engine):
    pol = _make_policy(engine)
    ds = engine.register_dataset("org1", {"dataset_name": "Old Logs", "policy_id": pol["policy_id"]})
    updated = engine.schedule_deletion("org1", ds["dataset_id"], "admin", "Monthly cleanup")
    assert updated["status"] == "scheduled_for_deletion"
    assert updated["scheduled_by"] == "admin"


def test_complete_deletion(engine):
    pol = _make_policy(engine)
    ds = engine.register_dataset("org1", {"dataset_name": "Old Logs", "policy_id": pol["policy_id"]})
    engine.schedule_deletion("org1", ds["dataset_id"], "admin", "")
    deleted = engine.complete_deletion("org1", ds["dataset_id"], "admin")
    assert deleted["status"] == "deleted"
    assert deleted["deleted_by"] == "admin"
    assert deleted["deleted_at"]


def test_deletion_audit_trail_recorded(engine):
    pol = _make_policy(engine)
    ds = engine.register_dataset("org1", {"dataset_name": "AuditTest", "policy_id": pol["policy_id"]})
    engine.schedule_deletion("org1", ds["dataset_id"], "alice", "notes")
    engine.complete_deletion("org1", ds["dataset_id"], "bob")
    audit = engine.get_deletion_audit("org1")
    assert len(audit) >= 2
    actions = [a["action"] for a in audit]
    assert "scheduled_for_deletion" in actions
    assert "deleted" in actions


def test_deletion_audit_empty_for_new_org(engine):
    assert engine.get_deletion_audit("fresh-org") == []


# ---------------------------------------------------------------------------
# 6. Stats
# ---------------------------------------------------------------------------


def test_stats_structure(engine):
    stats = engine.get_retention_stats("org1")
    assert "total_policies" in stats
    assert "by_regulation" in stats
    assert "total_datasets" in stats
    assert "expired_count" in stats
    assert "legal_hold_count" in stats
    assert "scheduled_for_deletion" in stats
    assert "compliance_score" in stats


def test_stats_compliance_score_range(engine):
    stats = engine.get_retention_stats("org1")
    assert 0 <= stats["compliance_score"] <= 100


def test_stats_legal_hold_count(engine):
    pol = _make_policy(engine)
    ds = engine.register_dataset("org1", {"dataset_name": "H", "policy_id": pol["policy_id"]})
    engine.mark_legal_hold("org1", ds["dataset_id"], "legal", "hold")
    stats = engine.get_retention_stats("org1")
    assert stats["legal_hold_count"] == 1


def test_stats_scheduled_for_deletion(engine):
    pol = _make_policy(engine)
    ds = engine.register_dataset("org1", {"dataset_name": "S", "policy_id": pol["policy_id"]})
    engine.schedule_deletion("org1", ds["dataset_id"], "admin", "")
    stats = engine.get_retention_stats("org1")
    assert stats["scheduled_for_deletion"] == 1


# ---------------------------------------------------------------------------
# 7. Org Isolation
# ---------------------------------------------------------------------------


def test_org_isolation_policies(engine):
    engine.create_policy("org-A", {"policy_name": "Pol-A"})
    engine.create_policy("org-B", {"policy_name": "Pol-B"})
    assert len(engine.list_policies("org-A")) == 1
    assert len(engine.list_policies("org-B")) == 1


def test_org_isolation_datasets(engine):
    pol_a = engine.create_policy("org-A", {"policy_name": "PA"})
    pol_b = engine.create_policy("org-B", {"policy_name": "PB"})
    engine.register_dataset("org-A", {"dataset_name": "DA", "policy_id": pol_a["policy_id"]})
    engine.register_dataset("org-B", {"dataset_name": "DB", "policy_id": pol_b["policy_id"]})
    assert len(engine.list_datasets("org-A")) == 1
    assert len(engine.list_datasets("org-B")) == 1
