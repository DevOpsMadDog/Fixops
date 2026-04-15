"""Tests for ThreatModelGenerator engine — 25+ tests."""

from __future__ import annotations

import tempfile
import os
import pytest
from core.threat_model_generator import ThreatModelGenerator


@pytest.fixture
def engine(tmp_path):
    db = str(tmp_path / "test_tmg.db")
    return ThreatModelGenerator(db_path=db)


ORG = "org-test"
OTHER_ORG = "org-other"


# ---------------------------------------------------------------------------
# create_model
# ---------------------------------------------------------------------------

def test_create_model_returns_dict(engine):
    result = engine.create_model(ORG, {"name": "MyModel", "system_type": "web_app"})
    assert result["model_id"]
    assert result["org_id"] == ORG
    assert result["name"] == "MyModel"
    assert result["system_type"] == "web_app"
    assert result["status"] == "draft"


def test_create_model_defaults(engine):
    result = engine.create_model(ORG, {"name": "DefaultModel"})
    assert result["methodology"] == "STRIDE"
    assert result["data_classification"] == "internal"
    assert isinstance(result["trust_boundaries"], list)
    assert isinstance(result["components"], list)


def test_create_model_with_json_fields(engine):
    result = engine.create_model(ORG, {
        "name": "Full",
        "trust_boundaries": ["internet", "dmz"],
        "components": ["frontend", "api", "db"],
    })
    assert result["trust_boundaries"] == ["internet", "dmz"]
    assert result["components"] == ["frontend", "api", "db"]


def test_create_model_has_timestamps(engine):
    result = engine.create_model(ORG, {"name": "TimestampModel"})
    assert result["created_at"]
    assert result["updated_at"]


# ---------------------------------------------------------------------------
# list_models
# ---------------------------------------------------------------------------

def test_list_models_empty(engine):
    assert engine.list_models(ORG) == []


def test_list_models_returns_created(engine):
    engine.create_model(ORG, {"name": "M1"})
    engine.create_model(ORG, {"name": "M2"})
    results = engine.list_models(ORG)
    assert len(results) == 2


def test_list_models_org_isolation(engine):
    engine.create_model(ORG, {"name": "OrgModel"})
    engine.create_model(OTHER_ORG, {"name": "OtherOrgModel"})
    assert len(engine.list_models(ORG)) == 1
    assert len(engine.list_models(OTHER_ORG)) == 1


def test_list_models_filter_status(engine):
    engine.create_model(ORG, {"name": "Draft", "status": "draft"})
    engine.create_model(ORG, {"name": "Approved", "status": "approved"})
    drafts = engine.list_models(ORG, status="draft")
    assert all(m["status"] == "draft" for m in drafts)
    assert len(drafts) == 1


def test_list_models_filter_methodology(engine):
    engine.create_model(ORG, {"name": "STRIDE Model", "methodology": "STRIDE"})
    engine.create_model(ORG, {"name": "PASTA Model", "methodology": "PASTA"})
    stride = engine.list_models(ORG, methodology="STRIDE")
    assert len(stride) == 1
    assert stride[0]["methodology"] == "STRIDE"


# ---------------------------------------------------------------------------
# get_model
# ---------------------------------------------------------------------------

def test_get_model_returns_record(engine):
    created = engine.create_model(ORG, {"name": "GetTest"})
    fetched = engine.get_model(ORG, created["model_id"])
    assert fetched is not None
    assert fetched["model_id"] == created["model_id"]


def test_get_model_includes_threats_count(engine):
    m = engine.create_model(ORG, {"name": "WithThreats", "system_type": "api"})
    engine.auto_generate_threats(ORG, m["model_id"])
    fetched = engine.get_model(ORG, m["model_id"])
    assert fetched["threats_count"] > 0


def test_get_model_not_found(engine):
    assert engine.get_model(ORG, "nonexistent-id") is None


def test_get_model_org_isolation(engine):
    m = engine.create_model(ORG, {"name": "IsolationTest"})
    assert engine.get_model(OTHER_ORG, m["model_id"]) is None


# ---------------------------------------------------------------------------
# auto_generate_threats
# ---------------------------------------------------------------------------

def test_auto_generate_web_app(engine):
    m = engine.create_model(ORG, {"name": "WebApp", "system_type": "web_app"})
    threats = engine.auto_generate_threats(ORG, m["model_id"])
    assert len(threats) == 8
    assert all(t["org_id"] == ORG for t in threats)
    assert all(t["model_id"] == m["model_id"] for t in threats)


def test_auto_generate_api(engine):
    m = engine.create_model(ORG, {"name": "API", "system_type": "api"})
    threats = engine.auto_generate_threats(ORG, m["model_id"])
    assert len(threats) == 8
    categories = {t["stride_category"] for t in threats}
    assert len(categories) > 1  # multiple STRIDE categories


def test_auto_generate_cloud_infra(engine):
    m = engine.create_model(ORG, {"name": "Cloud", "system_type": "cloud_infra"})
    threats = engine.auto_generate_threats(ORG, m["model_id"])
    assert len(threats) == 9  # cloud_infra has 9 threats
    titles = [t["title"] for t in threats]
    assert any("IAM" in t for t in titles)


def test_auto_generate_microservice(engine):
    m = engine.create_model(ORG, {"name": "MSvc", "system_type": "microservice"})
    threats = engine.auto_generate_threats(ORG, m["model_id"])
    assert len(threats) == 8


def test_auto_generate_mobile(engine):
    m = engine.create_model(ORG, {"name": "Mobile", "system_type": "mobile"})
    threats = engine.auto_generate_threats(ORG, m["model_id"])
    assert len(threats) == 8


def test_auto_generate_iot(engine):
    m = engine.create_model(ORG, {"name": "IoT", "system_type": "iot"})
    threats = engine.auto_generate_threats(ORG, m["model_id"])
    assert len(threats) == 8


def test_auto_generate_data_pipeline(engine):
    m = engine.create_model(ORG, {"name": "Pipeline", "system_type": "data_pipeline"})
    threats = engine.auto_generate_threats(ORG, m["model_id"])
    assert len(threats) == 8


def test_auto_generate_threats_have_mitigations_list(engine):
    m = engine.create_model(ORG, {"name": "MitCheck", "system_type": "web_app"})
    threats = engine.auto_generate_threats(ORG, m["model_id"])
    assert all(isinstance(t["mitigations"], list) for t in threats)


def test_auto_generate_model_not_found(engine):
    with pytest.raises(ValueError):
        engine.auto_generate_threats(ORG, "nonexistent-model-id")


# ---------------------------------------------------------------------------
# add_threat / list_threats / update_threat_status
# ---------------------------------------------------------------------------

def test_add_threat_manual(engine):
    m = engine.create_model(ORG, {"name": "ManualThreats"})
    t = engine.add_threat(ORG, m["model_id"], {
        "stride_category": "Spoofing",
        "title": "MITM Attack",
        "likelihood": "high",
        "impact": "high",
        "risk_rating": "critical",
    })
    assert t["threat_id"]
    assert t["title"] == "MITM Attack"
    assert t["stride_category"] == "Spoofing"


def test_list_threats_returns_threats(engine):
    m = engine.create_model(ORG, {"name": "ListThreats", "system_type": "api"})
    engine.auto_generate_threats(ORG, m["model_id"])
    threats = engine.list_threats(ORG, m["model_id"])
    assert len(threats) > 0


def test_list_threats_filter_stride_category(engine):
    m = engine.create_model(ORG, {"name": "FilterThreats", "system_type": "web_app"})
    engine.auto_generate_threats(ORG, m["model_id"])
    spoofing = engine.list_threats(ORG, m["model_id"], stride_category="Spoofing")
    assert all(t["stride_category"] == "Spoofing" for t in spoofing)


def test_update_threat_status(engine):
    m = engine.create_model(ORG, {"name": "StatusUpdate"})
    t = engine.add_threat(ORG, m["model_id"], {"title": "T1", "stride_category": "Tampering"})
    ok = engine.update_threat_status(ORG, t["threat_id"], "mitigated")
    assert ok is True


def test_update_threat_status_not_found(engine):
    ok = engine.update_threat_status(ORG, "nonexistent", "mitigated")
    assert ok is False


# ---------------------------------------------------------------------------
# add_mitigation / list_mitigations
# ---------------------------------------------------------------------------

def test_add_mitigation(engine):
    m = engine.create_model(ORG, {"name": "MitTest"})
    t = engine.add_threat(ORG, m["model_id"], {"title": "Threat1", "stride_category": "Tampering"})
    mit = engine.add_mitigation(ORG, t["threat_id"], {
        "title": "Enable WAF",
        "mitigation_type": "preventive",
        "effort": "low",
        "owner": "security-team",
    })
    assert mit["mitigation_id"]
    assert mit["title"] == "Enable WAF"


def test_list_mitigations(engine):
    m = engine.create_model(ORG, {"name": "ListMit"})
    t = engine.add_threat(ORG, m["model_id"], {"title": "T", "stride_category": "Spoofing"})
    engine.add_mitigation(ORG, t["threat_id"], {"title": "Mit A"})
    engine.add_mitigation(ORG, t["threat_id"], {"title": "Mit B"})
    mits = engine.list_mitigations(ORG, t["threat_id"])
    assert len(mits) == 2


# ---------------------------------------------------------------------------
# add_review
# ---------------------------------------------------------------------------

def test_add_review_approved_updates_status(engine):
    m = engine.create_model(ORG, {"name": "ReviewTest"})
    review = engine.add_review(ORG, m["model_id"], {
        "reviewer": "ciso@example.com",
        "verdict": "approved",
        "comments": "LGTM",
    })
    assert review["verdict"] == "approved"
    updated = engine.get_model(ORG, m["model_id"])
    assert updated["status"] == "approved"


def test_add_review_rejected_resets_to_draft(engine):
    m = engine.create_model(ORG, {"name": "RejectTest", "status": "review"})
    engine.add_review(ORG, m["model_id"], {"reviewer": "ciso", "verdict": "rejected"})
    updated = engine.get_model(ORG, m["model_id"])
    assert updated["status"] == "draft"


def test_add_review_needs_revision(engine):
    m = engine.create_model(ORG, {"name": "RevisionTest"})
    review = engine.add_review(ORG, m["model_id"], {
        "reviewer": "reviewer@example.com",
        "verdict": "needs_revision",
        "comments": "Add more components",
    })
    assert review["review_id"]
    assert review["verdict"] == "needs_revision"


# ---------------------------------------------------------------------------
# get_model_stats
# ---------------------------------------------------------------------------

def test_get_model_stats_empty(engine):
    stats = engine.get_model_stats(ORG)
    assert stats["total_models"] == 0
    assert stats["total_threats"] == 0
    assert stats["open_threats"] == 0
    assert stats["critical_risks"] == 0
    assert stats["mitigations_count"] == 0
    assert isinstance(stats["by_stride"], dict)


def test_get_model_stats_with_data(engine):
    m = engine.create_model(ORG, {"name": "Stats Model", "system_type": "web_app"})
    engine.auto_generate_threats(ORG, m["model_id"])
    engine.add_review(ORG, m["model_id"], {"reviewer": "ciso", "verdict": "approved"})

    stats = engine.get_model_stats(ORG)
    assert stats["total_models"] == 1
    assert stats["approved_models"] == 1
    assert stats["total_threats"] == 8
    assert stats["open_threats"] == 8
    assert stats["critical_risks"] >= 1
    assert len(stats["by_stride"]) > 0


def test_get_model_stats_org_isolation(engine):
    engine.create_model(ORG, {"name": "Org Model"})
    engine.create_model(OTHER_ORG, {"name": "Other Org Model"})
    stats_org = engine.get_model_stats(ORG)
    stats_other = engine.get_model_stats(OTHER_ORG)
    assert stats_org["total_models"] == 1
    assert stats_other["total_models"] == 1
