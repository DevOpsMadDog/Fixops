"""Tests for IdentityRiskEngine — wave 23."""

import pytest
from core.identity_risk_engine import IdentityRiskEngine


@pytest.fixture
def engine(tmp_path):
    return IdentityRiskEngine(db_path=str(tmp_path / "identity_risk.db"))


# ---------------------------------------------------------------------------
# register_identity
# ---------------------------------------------------------------------------

def test_register_identity_minimal(engine):
    ident = engine.register_identity("org1", {"identity_type": "human"})
    assert ident["identity_type"] == "human"
    assert ident["risk_score"] == 0.0
    assert ident["risk_level"] == "low"
    assert ident["mfa_enabled"] is False
    assert ident["status"] == "active"
    assert "id" in ident
    assert "created_at" in ident


def test_register_identity_all_types(engine):
    types = ["human", "service_account", "machine", "federated", "guest", "privileged"]
    for idx, itype in enumerate(types):
        ident = engine.register_identity("org1", {"identity_type": itype, "username": f"u{idx}"})
        assert ident["identity_type"] == itype


def test_register_identity_invalid_type_raises(engine):
    with pytest.raises(ValueError, match="identity_type"):
        engine.register_identity("org1", {"identity_type": "robot"})


def test_register_identity_invalid_status_raises(engine):
    with pytest.raises(ValueError, match="status"):
        engine.register_identity("org1", {"identity_type": "human", "status": "ghost"})


def test_register_identity_mfa_enabled(engine):
    ident = engine.register_identity("org1", {"identity_type": "human", "mfa_enabled": True})
    assert ident["mfa_enabled"] is True


def test_register_identity_risk_score_clamped(engine):
    ident = engine.register_identity("org1", {"identity_type": "human", "risk_score": 150.0})
    assert ident["risk_score"] == 100.0
    ident2 = engine.register_identity("org1", {"identity_type": "human", "risk_score": -5.0})
    assert ident2["risk_score"] == 0.0


def test_register_identity_risk_level_from_score(engine):
    cases = [(85.0, "critical"), (65.0, "high"), (40.0, "medium"), (10.0, "low")]
    for score, expected_level in cases:
        ident = engine.register_identity("org1", {"identity_type": "human", "risk_score": score})
        assert ident["risk_level"] == expected_level, f"score={score}"


def test_register_identity_all_statuses(engine):
    for idx, st in enumerate(["active", "inactive", "suspended", "terminated"]):
        ident = engine.register_identity("org1", {"identity_type": "human", "status": st, "username": f"u{idx}"})
        assert ident["status"] == st


# ---------------------------------------------------------------------------
# list_identities
# ---------------------------------------------------------------------------

def test_list_identities_empty(engine):
    assert engine.list_identities("org1") == []


def test_list_identities_filter_by_type(engine):
    engine.register_identity("org1", {"identity_type": "human"})
    engine.register_identity("org1", {"identity_type": "machine"})
    machines = engine.list_identities("org1", identity_type="machine")
    assert len(machines) == 1
    assert machines[0]["identity_type"] == "machine"


def test_list_identities_filter_by_risk_level(engine):
    engine.register_identity("org1", {"identity_type": "human", "risk_score": 90.0})
    engine.register_identity("org1", {"identity_type": "human", "risk_score": 10.0})
    critical = engine.list_identities("org1", risk_level="critical")
    assert len(critical) == 1
    assert critical[0]["risk_level"] == "critical"


def test_list_identities_filter_by_status(engine):
    engine.register_identity("org1", {"identity_type": "human", "status": "active"})
    engine.register_identity("org1", {"identity_type": "human", "status": "suspended"})
    suspended = engine.list_identities("org1", status="suspended")
    assert len(suspended) == 1
    assert suspended[0]["status"] == "suspended"


def test_list_identities_org_isolation(engine):
    engine.register_identity("org1", {"identity_type": "human"})
    assert engine.list_identities("org2") == []


# ---------------------------------------------------------------------------
# get_identity
# ---------------------------------------------------------------------------

def test_get_identity_found(engine):
    created = engine.register_identity("org1", {"identity_type": "human", "username": "alice"})
    fetched = engine.get_identity("org1", created["id"])
    assert fetched is not None
    assert fetched["id"] == created["id"]
    assert fetched["username"] == "alice"


def test_get_identity_not_found_returns_none(engine):
    assert engine.get_identity("org1", "nonexistent-id") is None


def test_get_identity_org_isolation(engine):
    created = engine.register_identity("org1", {"identity_type": "human"})
    assert engine.get_identity("org2", created["id"]) is None


# ---------------------------------------------------------------------------
# update_risk_score
# ---------------------------------------------------------------------------

def test_update_risk_score_changes_level(engine):
    ident = engine.register_identity("org1", {"identity_type": "human", "risk_score": 10.0})
    updated = engine.update_risk_score("org1", ident["id"], 85.0)
    assert updated["risk_score"] == 85.0
    assert updated["risk_level"] == "critical"


def test_update_risk_score_clamps_to_100(engine):
    ident = engine.register_identity("org1", {"identity_type": "human"})
    updated = engine.update_risk_score("org1", ident["id"], 999.0)
    assert updated["risk_score"] == 100.0


def test_update_risk_score_clamps_to_0(engine):
    ident = engine.register_identity("org1", {"identity_type": "human", "risk_score": 50.0})
    updated = engine.update_risk_score("org1", ident["id"], -10.0)
    assert updated["risk_score"] == 0.0
    assert updated["risk_level"] == "low"


def test_update_risk_score_not_found_raises(engine):
    with pytest.raises(KeyError):
        engine.update_risk_score("org1", "ghost-id", 50.0)


def test_update_risk_score_boundary_levels(engine):
    ident = engine.register_identity("org1", {"identity_type": "human"})
    assert engine.update_risk_score("org1", ident["id"], 80.0)["risk_level"] == "critical"
    assert engine.update_risk_score("org1", ident["id"], 60.0)["risk_level"] == "high"
    assert engine.update_risk_score("org1", ident["id"], 30.0)["risk_level"] == "medium"
    assert engine.update_risk_score("org1", ident["id"], 29.9)["risk_level"] == "low"


# ---------------------------------------------------------------------------
# record_risk_factor
# ---------------------------------------------------------------------------

def test_record_risk_factor_basic(engine):
    ident = engine.register_identity("org1", {"identity_type": "human"})
    factor = engine.record_risk_factor("org1", {
        "identity_id": ident["id"],
        "factor_type": "stale_credentials",
        "severity": "high",
        "score_impact": 20.0,
        "description": "Credentials not rotated in 90 days",
    })
    assert factor["factor_type"] == "stale_credentials"
    assert factor["severity"] == "high"
    assert factor["score_impact"] == 20.0
    assert factor["status"] == "active"
    assert "id" in factor


def test_record_risk_factor_all_types(engine):
    types = [
        "stale_credentials", "excess_privileges", "mfa_bypass", "suspicious_location",
        "after_hours_access", "failed_auth_spike", "data_access_anomaly",
        "lateral_movement", "account_sharing", "password_reuse",
    ]
    for ft in types:
        factor = engine.record_risk_factor("org1", {"identity_id": "i1", "factor_type": ft})
        assert factor["factor_type"] == ft


def test_record_risk_factor_invalid_type_raises(engine):
    with pytest.raises(ValueError, match="factor_type"):
        engine.record_risk_factor("org1", {"identity_id": "i1", "factor_type": "bad_type"})


def test_record_risk_factor_invalid_severity_raises(engine):
    with pytest.raises(ValueError, match="severity"):
        engine.record_risk_factor("org1", {
            "identity_id": "i1", "factor_type": "stale_credentials", "severity": "extreme"
        })


def test_record_risk_factor_score_impact_clamped(engine):
    factor = engine.record_risk_factor("org1", {
        "identity_id": "i1", "factor_type": "mfa_bypass", "score_impact": 999.0
    })
    assert factor["score_impact"] == 50.0

    factor2 = engine.record_risk_factor("org1", {
        "identity_id": "i1", "factor_type": "mfa_bypass", "score_impact": -5.0
    })
    assert factor2["score_impact"] == 0.0


# ---------------------------------------------------------------------------
# list_risk_factors
# ---------------------------------------------------------------------------

def test_list_risk_factors_empty(engine):
    assert engine.list_risk_factors("org1") == []


def test_list_risk_factors_filter_by_identity(engine):
    engine.record_risk_factor("org1", {"identity_id": "id-A", "factor_type": "mfa_bypass"})
    engine.record_risk_factor("org1", {"identity_id": "id-B", "factor_type": "stale_credentials"})
    factors = engine.list_risk_factors("org1", identity_id="id-A")
    assert len(factors) == 1
    assert factors[0]["identity_id"] == "id-A"


def test_list_risk_factors_filter_by_severity(engine):
    engine.record_risk_factor("org1", {"identity_id": "i1", "factor_type": "mfa_bypass", "severity": "critical"})
    engine.record_risk_factor("org1", {"identity_id": "i1", "factor_type": "stale_credentials", "severity": "low"})
    critical = engine.list_risk_factors("org1", severity="critical")
    assert len(critical) == 1


def test_list_risk_factors_filter_by_status(engine):
    f = engine.record_risk_factor("org1", {"identity_id": "i1", "factor_type": "mfa_bypass"})
    engine.mitigate_factor("org1", f["id"])
    active = engine.list_risk_factors("org1", status="active")
    assert len(active) == 0
    mitigated = engine.list_risk_factors("org1", status="mitigated")
    assert len(mitigated) == 1


# ---------------------------------------------------------------------------
# mitigate_factor
# ---------------------------------------------------------------------------

def test_mitigate_factor_sets_status(engine):
    factor = engine.record_risk_factor("org1", {"identity_id": "i1", "factor_type": "mfa_bypass"})
    result = engine.mitigate_factor("org1", factor["id"])
    assert result["status"] == "mitigated"


def test_mitigate_factor_not_found_raises(engine):
    with pytest.raises(KeyError):
        engine.mitigate_factor("org1", "ghost-factor-id")


def test_mitigate_factor_org_isolation(engine):
    factor = engine.record_risk_factor("org1", {"identity_id": "i1", "factor_type": "mfa_bypass"})
    with pytest.raises(KeyError):
        engine.mitigate_factor("org2", factor["id"])


# ---------------------------------------------------------------------------
# record_access_review
# ---------------------------------------------------------------------------

def test_record_access_review_basic(engine):
    review = engine.record_access_review("org1", {
        "identity_id": "id-alice",
        "reviewer": "bob@example.com",
        "decision": "approved",
        "resource": "s3://prod-bucket",
        "access_level": "read",
        "review_reason": "Quarterly access review",
    })
    assert review["decision"] == "approved"
    assert review["reviewer"] == "bob@example.com"
    assert review["identity_id"] == "id-alice"
    assert "id" in review


def test_record_access_review_all_decisions(engine):
    for decision in ["approved", "revoked", "modified", "deferred"]:
        review = engine.record_access_review("org1", {
            "identity_id": "id-x", "reviewer": "rev", "decision": decision
        })
        assert review["decision"] == decision


def test_record_access_review_missing_identity_id_raises(engine):
    with pytest.raises(ValueError, match="identity_id"):
        engine.record_access_review("org1", {"reviewer": "bob", "decision": "approved"})


def test_record_access_review_missing_reviewer_raises(engine):
    with pytest.raises(ValueError, match="reviewer"):
        engine.record_access_review("org1", {"identity_id": "id-x", "decision": "approved"})


def test_record_access_review_invalid_decision_raises(engine):
    with pytest.raises(ValueError, match="decision"):
        engine.record_access_review("org1", {
            "identity_id": "id-x", "reviewer": "rev", "decision": "ignored"
        })


# ---------------------------------------------------------------------------
# list_access_reviews
# ---------------------------------------------------------------------------

def test_list_access_reviews_empty(engine):
    assert engine.list_access_reviews("org1") == []


def test_list_access_reviews_filter_by_identity(engine):
    engine.record_access_review("org1", {"identity_id": "id-A", "reviewer": "r", "decision": "approved"})
    engine.record_access_review("org1", {"identity_id": "id-B", "reviewer": "r", "decision": "revoked"})
    reviews = engine.list_access_reviews("org1", identity_id="id-A")
    assert len(reviews) == 1
    assert reviews[0]["identity_id"] == "id-A"


def test_list_access_reviews_filter_by_decision(engine):
    engine.record_access_review("org1", {"identity_id": "id-A", "reviewer": "r", "decision": "approved"})
    engine.record_access_review("org1", {"identity_id": "id-B", "reviewer": "r", "decision": "revoked"})
    revoked = engine.list_access_reviews("org1", decision="revoked")
    assert len(revoked) == 1
    assert revoked[0]["decision"] == "revoked"


def test_list_access_reviews_org_isolation(engine):
    engine.record_access_review("org1", {"identity_id": "id-A", "reviewer": "r", "decision": "approved"})
    assert engine.list_access_reviews("org2") == []


# ---------------------------------------------------------------------------
# get_identity_risk_stats
# ---------------------------------------------------------------------------

def test_get_identity_risk_stats_empty(engine):
    stats = engine.get_identity_risk_stats("org1")
    assert stats["total_identities"] == 0
    assert stats["high_risk_identities"] == 0
    assert stats["mfa_enabled_count"] == 0
    assert stats["active_risk_factors"] == 0
    assert stats["critical_factors"] == 0
    assert stats["avg_risk_score"] == 0.0


def test_get_identity_risk_stats_counts(engine):
    id1 = engine.register_identity("org1", {"identity_type": "human", "risk_score": 90.0, "mfa_enabled": True})
    id2 = engine.register_identity("org1", {"identity_type": "service_account", "risk_score": 10.0})
    id3 = engine.register_identity("org1", {"identity_type": "machine", "risk_score": 65.0})

    engine.record_risk_factor("org1", {"identity_id": id1["id"], "factor_type": "mfa_bypass", "severity": "critical"})
    engine.record_risk_factor("org1", {"identity_id": id2["id"], "factor_type": "stale_credentials", "severity": "low"})

    stats = engine.get_identity_risk_stats("org1")
    assert stats["total_identities"] == 3
    assert stats["high_risk_identities"] == 2  # scores 90 and 65
    assert stats["mfa_enabled_count"] == 1
    assert stats["active_risk_factors"] == 2
    assert stats["critical_factors"] == 1
    assert stats["avg_risk_score"] > 0
    assert "human" in stats["by_identity_type"]
    assert "service_account" in stats["by_identity_type"]
    assert "critical" in stats["by_risk_level"]


def test_get_identity_risk_stats_org_isolation(engine):
    engine.register_identity("org1", {"identity_type": "human", "risk_score": 90.0})
    stats = engine.get_identity_risk_stats("org2")
    assert stats["total_identities"] == 0


def test_get_identity_risk_stats_by_risk_level(engine):
    engine.register_identity("org1", {"identity_type": "human", "risk_score": 85.0})
    engine.register_identity("org1", {"identity_type": "human", "risk_score": 85.0})
    engine.register_identity("org1", {"identity_type": "human", "risk_score": 5.0})
    stats = engine.get_identity_risk_stats("org1")
    assert stats["by_risk_level"].get("critical", 0) == 2
    assert stats["by_risk_level"].get("low", 0) == 1
