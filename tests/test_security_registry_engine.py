"""Tests for SecurityRegistryEngine — ALDECI."""

from __future__ import annotations

import pytest

from core.security_registry_engine import SecurityRegistryEngine


@pytest.fixture
def engine(tmp_path):
    return SecurityRegistryEngine(db_path=str(tmp_path / "security_registry.db"))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _artifact(engine, org_id="org1", **kwargs):
    data = dict(artifact_name="Password Policy v2", artifact_type="policy")
    data.update(kwargs)
    return engine.register_artifact(org_id, data)


def _review(engine, artifact_id, org_id="org1", **kwargs):
    data = dict(reviewer="alice", review_outcome="approved")
    data.update(kwargs)
    return engine.record_review(org_id, artifact_id, data)


# ---------------------------------------------------------------------------
# register_artifact — validation
# ---------------------------------------------------------------------------

def test_register_artifact_missing_name_raises(engine):
    with pytest.raises(ValueError, match="artifact_name"):
        engine.register_artifact("org1", {"artifact_type": "policy"})


def test_register_artifact_empty_name_raises(engine):
    with pytest.raises(ValueError, match="artifact_name"):
        engine.register_artifact("org1", {"artifact_name": "  ", "artifact_type": "policy"})


def test_register_artifact_invalid_type_raises(engine):
    with pytest.raises(ValueError, match="artifact_type"):
        engine.register_artifact("org1", {"artifact_name": "A", "artifact_type": "unknown"})


# ---------------------------------------------------------------------------
# register_artifact — all valid types and statuses
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("artifact_type", [
    "policy", "standard", "procedure", "guideline",
    "control", "framework", "tool", "runbook",
])
def test_register_artifact_all_types(engine, artifact_type):
    a = _artifact(engine, artifact_type=artifact_type)
    assert a["artifact_type"] == artifact_type
    assert a["org_id"] == "org1"
    assert "id" in a
    assert "created_at" in a


def test_register_artifact_default_status_is_draft(engine):
    a = _artifact(engine)
    assert a["artifact_status"] == "draft"


def test_register_artifact_default_version(engine):
    a = _artifact(engine)
    assert a["version"] == "1.0"


def test_register_artifact_invalid_status_falls_back_to_draft(engine):
    a = _artifact(engine, artifact_status="bad_status")
    assert a["artifact_status"] == "draft"


def test_register_artifact_tag_list_as_list(engine):
    a = _artifact(engine, tag_list=["iso27001", "nist", "gdpr"])
    assert isinstance(a["tag_list"], list)
    assert "iso27001" in a["tag_list"]
    assert "nist" in a["tag_list"]


def test_register_artifact_tag_list_empty(engine):
    a = _artifact(engine)
    assert a["tag_list"] == []


def test_register_artifact_with_all_fields(engine):
    a = _artifact(
        engine,
        version="2.1",
        artifact_status="active",
        description="Company password policy",
        owner="CISO",
        reviewer="compliance-team",
        download_url="https://docs.example.com/policy.pdf",
        tag_list=["security", "compliance"],
    )
    assert a["version"] == "2.1"
    assert a["artifact_status"] == "active"
    assert a["description"] == "Company password policy"
    assert a["owner"] == "CISO"
    assert a["download_url"] == "https://docs.example.com/policy.pdf"
    assert "security" in a["tag_list"]


# ---------------------------------------------------------------------------
# list_artifacts
# ---------------------------------------------------------------------------

def test_list_artifacts_empty(engine):
    assert engine.list_artifacts("org1") == []


def test_list_artifacts_org_isolation(engine):
    _artifact(engine, org_id="org1")
    _artifact(engine, org_id="org2")
    assert len(engine.list_artifacts("org1")) == 1
    assert len(engine.list_artifacts("org2")) == 1


def test_list_artifacts_filter_type(engine):
    _artifact(engine, artifact_type="policy")
    _artifact(engine, artifact_name="NIST Framework", artifact_type="framework")
    results = engine.list_artifacts("org1", artifact_type="framework")
    assert len(results) == 1
    assert results[0]["artifact_type"] == "framework"


def test_list_artifacts_filter_status(engine):
    _artifact(engine, artifact_status="draft")
    _artifact(engine, artifact_name="Active Policy", artifact_status="active")
    results = engine.list_artifacts("org1", artifact_status="active")
    assert len(results) == 1
    assert results[0]["artifact_status"] == "active"


def test_list_artifacts_tags_as_list(engine):
    _artifact(engine, tag_list=["tag1", "tag2"])
    results = engine.list_artifacts("org1")
    assert isinstance(results[0]["tag_list"], list)


# ---------------------------------------------------------------------------
# get_artifact
# ---------------------------------------------------------------------------

def test_get_artifact_found(engine):
    a = _artifact(engine)
    fetched = engine.get_artifact("org1", a["id"])
    assert fetched is not None
    assert fetched["id"] == a["id"]
    assert fetched["artifact_name"] == "Password Policy v2"


def test_get_artifact_not_found(engine):
    assert engine.get_artifact("org1", "nonexistent") is None


def test_get_artifact_wrong_org(engine):
    a = _artifact(engine, org_id="org1")
    assert engine.get_artifact("org2", a["id"]) is None


def test_get_artifact_tags_as_list(engine):
    a = _artifact(engine, tag_list=["alpha", "beta"])
    fetched = engine.get_artifact("org1", a["id"])
    assert isinstance(fetched["tag_list"], list)
    assert "alpha" in fetched["tag_list"]


# ---------------------------------------------------------------------------
# update_artifact_status
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("new_status", [
    "draft", "active", "deprecated", "under_review", "archived",
])
def test_update_artifact_status_all_valid(engine, new_status):
    a = _artifact(engine)
    updated = engine.update_artifact_status("org1", a["id"], new_status)
    assert updated["artifact_status"] == new_status


def test_update_artifact_status_invalid_raises(engine):
    a = _artifact(engine)
    with pytest.raises(ValueError, match="artifact_status"):
        engine.update_artifact_status("org1", a["id"], "invalid_status")


def test_update_artifact_status_not_found_raises(engine):
    with pytest.raises(KeyError):
        engine.update_artifact_status("org1", "nonexistent", "active")


def test_update_artifact_status_wrong_org_raises(engine):
    a = _artifact(engine, org_id="org1")
    with pytest.raises(KeyError):
        engine.update_artifact_status("org2", a["id"], "active")


# ---------------------------------------------------------------------------
# record_review
# ---------------------------------------------------------------------------

def test_record_review_approved_sets_active(engine):
    a = _artifact(engine)
    assert engine.get_artifact("org1", a["id"])["artifact_status"] == "draft"
    _review(engine, a["id"], review_outcome="approved")
    assert engine.get_artifact("org1", a["id"])["artifact_status"] == "active"


def test_record_review_rejected_does_not_change_status(engine):
    a = _artifact(engine)
    _review(engine, a["id"], review_outcome="rejected")
    assert engine.get_artifact("org1", a["id"])["artifact_status"] == "draft"


def test_record_review_invalid_outcome_raises(engine):
    a = _artifact(engine)
    with pytest.raises(ValueError, match="review_outcome"):
        engine.record_review("org1", a["id"], {"reviewer": "alice", "review_outcome": "bad"})


def test_record_review_missing_reviewer_raises(engine):
    a = _artifact(engine)
    with pytest.raises(ValueError, match="reviewer"):
        engine.record_review("org1", a["id"], {"reviewer": "", "review_outcome": "approved"})


@pytest.mark.parametrize("outcome", [
    "approved", "rejected", "approved_with_changes", "deferred",
])
def test_record_review_all_outcomes(engine, outcome):
    a = _artifact(engine)
    r = engine.record_review("org1", a["id"], {"reviewer": "bob", "review_outcome": outcome})
    assert r["review_outcome"] == outcome
    assert r["reviewer"] == "bob"
    assert "id" in r
    assert "created_at" in r


def test_record_review_updates_artifact_reviewer(engine):
    a = _artifact(engine)
    _review(engine, a["id"], reviewer="carol", review_outcome="approved")
    updated = engine.get_artifact("org1", a["id"])
    assert updated["reviewer"] == "carol"


def test_record_review_with_next_review_date(engine):
    a = _artifact(engine)
    r = engine.record_review(
        "org1", a["id"],
        {"reviewer": "alice", "review_outcome": "approved",
         "next_review_date": "2027-01-01T00:00:00+00:00"},
    )
    assert r["next_review_date"] == "2027-01-01T00:00:00+00:00"


# ---------------------------------------------------------------------------
# list_reviews
# ---------------------------------------------------------------------------

def test_list_reviews_empty(engine):
    assert engine.list_reviews("org1") == []


def test_list_reviews_org_isolation(engine):
    a1 = _artifact(engine, org_id="org1")
    a2 = _artifact(engine, org_id="org2")
    _review(engine, a1["id"], org_id="org1")
    _review(engine, a2["id"], org_id="org2")
    assert len(engine.list_reviews("org1")) == 1
    assert len(engine.list_reviews("org2")) == 1


def test_list_reviews_filter_artifact_id(engine):
    a1 = _artifact(engine, artifact_name="Policy A")
    a2 = _artifact(engine, artifact_name="Policy B")
    _review(engine, a1["id"])
    _review(engine, a2["id"])
    results = engine.list_reviews("org1", artifact_id=a1["id"])
    assert len(results) == 1
    assert results[0]["artifact_id"] == a1["id"]


def test_list_reviews_filter_outcome(engine):
    a = _artifact(engine)
    _review(engine, a["id"], review_outcome="approved")
    _review(engine, a["id"], review_outcome="rejected")
    results = engine.list_reviews("org1", review_outcome="rejected")
    assert len(results) == 1
    assert results[0]["review_outcome"] == "rejected"


# ---------------------------------------------------------------------------
# add_reference
# ---------------------------------------------------------------------------

def test_add_reference_success(engine):
    a1 = _artifact(engine, artifact_name="Policy A")
    a2 = _artifact(engine, artifact_name="Policy B")
    ref = engine.add_reference("org1", a1["id"], {"referenced_artifact_id": a2["id"]})
    assert ref["artifact_id"] == a1["id"]
    assert ref["referenced_artifact_id"] == a2["id"]
    assert ref["reference_type"] == "related"
    assert "id" in ref
    assert "created_at" in ref


def test_add_reference_missing_referenced_id_raises(engine):
    a = _artifact(engine)
    with pytest.raises(ValueError, match="referenced_artifact_id"):
        engine.add_reference("org1", a["id"], {"referenced_artifact_id": ""})


def test_add_reference_source_not_found_raises(engine):
    a2 = _artifact(engine)
    with pytest.raises(KeyError):
        engine.add_reference("org1", "bad-id", {"referenced_artifact_id": a2["id"]})


def test_add_reference_target_not_found_raises(engine):
    a1 = _artifact(engine)
    with pytest.raises(KeyError):
        engine.add_reference("org1", a1["id"], {"referenced_artifact_id": "bad-id"})


def test_add_reference_cross_org_raises(engine):
    a1 = _artifact(engine, org_id="org1")
    a2 = _artifact(engine, org_id="org2")
    # Source is org1, but referenced is org2 — should not find it under org1
    with pytest.raises(KeyError):
        engine.add_reference("org1", a1["id"], {"referenced_artifact_id": a2["id"]})


def test_add_reference_with_custom_type_notes(engine):
    a1 = _artifact(engine, artifact_name="Policy A")
    a2 = _artifact(engine, artifact_name="Standard B")
    ref = engine.add_reference(
        "org1", a1["id"],
        {"referenced_artifact_id": a2["id"], "reference_type": "implements", "notes": "See section 4"},
    )
    assert ref["reference_type"] == "implements"
    assert ref["notes"] == "See section 4"


# ---------------------------------------------------------------------------
# list_references
# ---------------------------------------------------------------------------

def test_list_references_empty(engine):
    a = _artifact(engine)
    assert engine.list_references("org1", a["id"]) == []


def test_list_references_returns_refs(engine):
    a1 = _artifact(engine, artifact_name="A")
    a2 = _artifact(engine, artifact_name="B")
    a3 = _artifact(engine, artifact_name="C")
    engine.add_reference("org1", a1["id"], {"referenced_artifact_id": a2["id"]})
    engine.add_reference("org1", a1["id"], {"referenced_artifact_id": a3["id"]})
    refs = engine.list_references("org1", a1["id"])
    assert len(refs) == 2


# ---------------------------------------------------------------------------
# get_registry_stats
# ---------------------------------------------------------------------------

def test_get_registry_stats_empty(engine):
    stats = engine.get_registry_stats("org1")
    assert stats["total_artifacts"] == 0
    assert stats["active_artifacts"] == 0
    assert stats["deprecated_artifacts"] == 0
    assert stats["by_type"] == {}
    assert stats["by_status"] == {}
    assert stats["pending_review"] == 0
    assert stats["total_reviews"] == 0
    assert stats["approval_rate"] == 0.0


def test_get_registry_stats_counts(engine):
    a1 = _artifact(engine, artifact_type="policy")
    a2 = _artifact(engine, artifact_name="Std", artifact_type="standard")
    a3 = _artifact(engine, artifact_name="Tool", artifact_type="tool", artifact_status="deprecated")
    _review(engine, a1["id"], review_outcome="approved")
    _review(engine, a2["id"], review_outcome="rejected")

    stats = engine.get_registry_stats("org1")
    assert stats["total_artifacts"] == 3
    assert stats["active_artifacts"] == 1  # a1 approved → active
    assert stats["deprecated_artifacts"] == 1
    assert stats["by_type"]["policy"] == 1
    assert stats["by_type"]["standard"] == 1
    assert stats["by_type"]["tool"] == 1
    assert stats["total_reviews"] == 2


def test_get_registry_stats_approval_rate(engine):
    a1 = _artifact(engine, artifact_name="P1")
    a2 = _artifact(engine, artifact_name="P2")
    _review(engine, a1["id"], review_outcome="approved")
    _review(engine, a2["id"], review_outcome="approved")

    stats = engine.get_registry_stats("org1")
    assert stats["approval_rate"] == 100.0


def test_get_registry_stats_approval_rate_partial(engine):
    a1 = _artifact(engine, artifact_name="P1")
    a2 = _artifact(engine, artifact_name="P2")
    _review(engine, a1["id"], review_outcome="approved")
    _review(engine, a2["id"], review_outcome="rejected")

    stats = engine.get_registry_stats("org1")
    assert stats["approval_rate"] == 50.0


def test_get_registry_stats_org_isolation(engine):
    _artifact(engine, org_id="org1")
    _artifact(engine, org_id="org2")
    stats1 = engine.get_registry_stats("org1")
    stats2 = engine.get_registry_stats("org2")
    assert stats1["total_artifacts"] == 1
    assert stats2["total_artifacts"] == 1


def test_get_registry_stats_by_status(engine):
    _artifact(engine, artifact_status="active")
    _artifact(engine, artifact_name="P2", artifact_status="draft")
    _artifact(engine, artifact_name="P3", artifact_status="under_review")
    stats = engine.get_registry_stats("org1")
    assert stats["by_status"]["active"] == 1
    assert stats["by_status"]["draft"] == 1
    assert stats["by_status"]["under_review"] == 1
