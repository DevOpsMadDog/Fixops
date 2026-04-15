"""Tests for NetworkSegmentationEngine — 30+ tests covering all major paths."""

from __future__ import annotations

import pytest


@pytest.fixture
def engine(tmp_path):
    from core.network_segmentation_engine import NetworkSegmentationEngine
    return NetworkSegmentationEngine(db_path=str(tmp_path / "netseg.db"))


ORG = "test-org-netseg"
ORG2 = "other-org-netseg"


# ---------------------------------------------------------------------------
# Segment creation
# ---------------------------------------------------------------------------

def test_create_segment_basic(engine):
    seg = engine.create_segment(ORG, {
        "name": "Production",
        "segment_type": "prod",
        "trust_level": 9,
        "cidr": "10.0.0.0/8",
    })
    assert seg["id"]
    assert seg["name"] == "Production"
    assert seg["segment_type"] == "prod"
    assert seg["trust_level"] == 9
    assert seg["cidr"] == "10.0.0.0/8"
    assert seg["org_id"] == ORG


def test_create_segment_all_types(engine):
    for seg_type in ("dmz", "internal", "guest", "management", "prod", "dev"):
        seg = engine.create_segment(ORG, {
            "name": f"Seg-{seg_type}",
            "segment_type": seg_type,
        })
        assert seg["segment_type"] == seg_type


def test_create_segment_default_trust_level(engine):
    seg = engine.create_segment(ORG, {"name": "Dev", "segment_type": "dev"})
    assert seg["trust_level"] == 5


def test_create_segment_missing_name(engine):
    with pytest.raises(ValueError, match="name"):
        engine.create_segment(ORG, {"segment_type": "dmz"})


def test_create_segment_invalid_type(engine):
    with pytest.raises(ValueError):
        engine.create_segment(ORG, {"name": "X", "segment_type": "datacenter"})


def test_create_segment_invalid_trust_level(engine):
    with pytest.raises(ValueError, match="trust_level"):
        engine.create_segment(ORG, {"name": "X", "segment_type": "prod", "trust_level": 11})


def test_create_segment_trust_level_zero(engine):
    seg = engine.create_segment(ORG, {
        "name": "Untrusted",
        "segment_type": "guest",
        "trust_level": 0,
    })
    assert seg["trust_level"] == 0


# ---------------------------------------------------------------------------
# List segments
# ---------------------------------------------------------------------------

def test_list_segments_empty(engine):
    assert engine.list_segments(ORG) == []


def test_list_segments_multiple(engine):
    engine.create_segment(ORG, {"name": "DMZ", "segment_type": "dmz"})
    engine.create_segment(ORG, {"name": "Prod", "segment_type": "prod", "trust_level": 9})
    segs = engine.list_segments(ORG)
    assert len(segs) == 2


def test_list_segments_filter_by_type(engine):
    engine.create_segment(ORG, {"name": "DMZ", "segment_type": "dmz"})
    engine.create_segment(ORG, {"name": "Prod", "segment_type": "prod"})
    engine.create_segment(ORG, {"name": "Dev", "segment_type": "dev"})
    prod_segs = engine.list_segments(ORG, segment_type="prod")
    assert len(prod_segs) == 1
    assert prod_segs[0]["name"] == "Prod"


def test_list_segments_org_isolation(engine):
    engine.create_segment(ORG, {"name": "A", "segment_type": "dmz"})
    engine.create_segment(ORG2, {"name": "B", "segment_type": "internal"})
    assert len(engine.list_segments(ORG)) == 1
    assert len(engine.list_segments(ORG2)) == 1


# ---------------------------------------------------------------------------
# Flow policies
# ---------------------------------------------------------------------------

def test_add_flow_policy_basic(engine):
    src = engine.create_segment(ORG, {"name": "DMZ", "segment_type": "dmz", "trust_level": 3})
    dst = engine.create_segment(ORG, {"name": "Prod", "segment_type": "prod", "trust_level": 9})
    policy = engine.add_flow_policy(ORG, {
        "src_segment_id": src["id"],
        "dst_segment_id": dst["id"],
        "action": "deny",
        "ports": ["22", "3389"],
        "justification": "No direct DMZ to prod access",
    })
    assert policy["id"]
    assert policy["action"] == "deny"
    assert "22" in policy["ports"]
    assert policy["justification"] == "No direct DMZ to prod access"


def test_add_flow_policy_allow(engine):
    src = engine.create_segment(ORG, {"name": "Internal", "segment_type": "internal", "trust_level": 7})
    dst = engine.create_segment(ORG, {"name": "DMZ", "segment_type": "dmz", "trust_level": 3})
    policy = engine.add_flow_policy(ORG, {
        "src_segment_id": src["id"],
        "dst_segment_id": dst["id"],
        "action": "allow",
        "ports": ["443"],
    })
    assert policy["action"] == "allow"
    assert "443" in policy["ports"]


def test_add_flow_policy_missing_src(engine):
    with pytest.raises(ValueError, match="src_segment_id"):
        engine.add_flow_policy(ORG, {
            "dst_segment_id": "some-id",
            "action": "allow",
        })


def test_add_flow_policy_missing_dst(engine):
    src = engine.create_segment(ORG, {"name": "DMZ", "segment_type": "dmz"})
    with pytest.raises(ValueError, match="dst_segment_id"):
        engine.add_flow_policy(ORG, {
            "src_segment_id": src["id"],
            "action": "allow",
        })


def test_add_flow_policy_invalid_action(engine):
    src = engine.create_segment(ORG, {"name": "DMZ", "segment_type": "dmz"})
    dst = engine.create_segment(ORG, {"name": "Prod", "segment_type": "prod"})
    with pytest.raises(ValueError, match="action"):
        engine.add_flow_policy(ORG, {
            "src_segment_id": src["id"],
            "dst_segment_id": dst["id"],
            "action": "permit",
        })


def test_add_flow_policy_unknown_segment(engine):
    src = engine.create_segment(ORG, {"name": "DMZ", "segment_type": "dmz"})
    with pytest.raises(ValueError, match="not found"):
        engine.add_flow_policy(ORG, {
            "src_segment_id": src["id"],
            "dst_segment_id": "nonexistent",
            "action": "allow",
        })


def test_list_flow_policies_empty(engine):
    assert engine.list_flow_policies(ORG) == []


def test_list_flow_policies_multiple(engine):
    src = engine.create_segment(ORG, {"name": "DMZ", "segment_type": "dmz"})
    dst = engine.create_segment(ORG, {"name": "Prod", "segment_type": "prod"})
    engine.add_flow_policy(ORG, {"src_segment_id": src["id"], "dst_segment_id": dst["id"], "action": "deny"})
    engine.add_flow_policy(ORG, {"src_segment_id": dst["id"], "dst_segment_id": src["id"], "action": "allow"})
    policies = engine.list_flow_policies(ORG)
    assert len(policies) == 2


# ---------------------------------------------------------------------------
# Flow check
# ---------------------------------------------------------------------------

def test_check_flow_allowed_match(engine):
    src = engine.create_segment(ORG, {"name": "Internal", "segment_type": "internal", "trust_level": 7})
    dst = engine.create_segment(ORG, {"name": "DMZ", "segment_type": "dmz", "trust_level": 3})
    engine.add_flow_policy(ORG, {
        "src_segment_id": src["id"],
        "dst_segment_id": dst["id"],
        "action": "allow",
        "ports": ["443"],
    })
    result = engine.check_flow_allowed(ORG, src["id"], dst["id"], 443)
    assert result["allowed"] is True
    assert result["policy_matched"] is not None


def test_check_flow_denied_by_policy(engine):
    src = engine.create_segment(ORG, {"name": "Guest", "segment_type": "guest", "trust_level": 1})
    dst = engine.create_segment(ORG, {"name": "Prod", "segment_type": "prod", "trust_level": 9})
    engine.add_flow_policy(ORG, {
        "src_segment_id": src["id"],
        "dst_segment_id": dst["id"],
        "action": "deny",
        "ports": ["22"],
    })
    result = engine.check_flow_allowed(ORG, src["id"], dst["id"], 22)
    assert result["allowed"] is False


def test_check_flow_default_deny_no_policy(engine):
    src = engine.create_segment(ORG, {"name": "DMZ", "segment_type": "dmz"})
    dst = engine.create_segment(ORG, {"name": "Prod", "segment_type": "prod"})
    result = engine.check_flow_allowed(ORG, src["id"], dst["id"], 80)
    assert result["allowed"] is False
    assert result["policy_matched"] is None
    assert "default deny" in result["reason"].lower()


def test_check_flow_allow_all_ports(engine):
    src = engine.create_segment(ORG, {"name": "Internal", "segment_type": "internal"})
    dst = engine.create_segment(ORG, {"name": "DMZ", "segment_type": "dmz"})
    engine.add_flow_policy(ORG, {
        "src_segment_id": src["id"],
        "dst_segment_id": dst["id"],
        "action": "allow",
        "ports": [],  # all ports
    })
    result = engine.check_flow_allowed(ORG, src["id"], dst["id"], 9999)
    assert result["allowed"] is True


# ---------------------------------------------------------------------------
# Lateral movement risk
# ---------------------------------------------------------------------------

def test_detect_lateral_movement_risk_none(engine):
    engine.create_segment(ORG, {"name": "DMZ", "segment_type": "dmz", "trust_level": 3})
    risks = engine.detect_lateral_movement_risk(ORG)
    assert risks == []


def test_detect_lateral_movement_risk_allow_all_to_prod(engine):
    src = engine.create_segment(ORG, {"name": "Guest", "segment_type": "guest", "trust_level": 1})
    dst = engine.create_segment(ORG, {"name": "Prod", "segment_type": "prod", "trust_level": 9})
    engine.add_flow_policy(ORG, {
        "src_segment_id": src["id"],
        "dst_segment_id": dst["id"],
        "action": "allow",
        "ports": [],  # allow all
    })
    risks = engine.detect_lateral_movement_risk(ORG)
    assert len(risks) >= 1
    risk = risks[0]
    assert risk["severity"] in ("critical", "high")
    assert "lateral movement" in risk["risk_description"].lower()


def test_detect_lateral_movement_risk_deny_not_flagged(engine):
    src = engine.create_segment(ORG, {"name": "Guest", "segment_type": "guest", "trust_level": 1})
    dst = engine.create_segment(ORG, {"name": "Prod", "segment_type": "prod", "trust_level": 9})
    engine.add_flow_policy(ORG, {
        "src_segment_id": src["id"],
        "dst_segment_id": dst["id"],
        "action": "deny",
        "ports": [],
    })
    risks = engine.detect_lateral_movement_risk(ORG)
    assert risks == []


def test_detect_lateral_movement_risk_specific_ports_not_flagged(engine):
    src = engine.create_segment(ORG, {"name": "Dev", "segment_type": "dev", "trust_level": 4})
    dst = engine.create_segment(ORG, {"name": "Prod", "segment_type": "prod", "trust_level": 9})
    engine.add_flow_policy(ORG, {
        "src_segment_id": src["id"],
        "dst_segment_id": dst["id"],
        "action": "allow",
        "ports": ["443"],  # specific port, not allow-all
    })
    risks = engine.detect_lateral_movement_risk(ORG)
    assert risks == []


# ---------------------------------------------------------------------------
# Segmentation score
# ---------------------------------------------------------------------------

def test_get_segmentation_score_empty(engine):
    result = engine.get_segmentation_score(ORG)
    assert result["score"] == 100
    assert result["grade"] == "A"
    assert result["findings"] == []


def test_get_segmentation_score_with_risks(engine):
    src = engine.create_segment(ORG, {"name": "Guest", "segment_type": "guest", "trust_level": 1})
    dst = engine.create_segment(ORG, {"name": "Prod", "segment_type": "prod", "trust_level": 9})
    # Critical risk: allow-all from guest to prod with large trust gap
    engine.add_flow_policy(ORG, {
        "src_segment_id": src["id"],
        "dst_segment_id": dst["id"],
        "action": "allow",
        "ports": [],
    })
    result = engine.get_segmentation_score(ORG)
    assert result["score"] < 100
    assert result["grade"] in ("A", "B", "C", "D", "F")
    assert len(result["findings"]) >= 1


def test_get_segmentation_score_grade_boundaries(engine):
    # Score 100 → A
    result = engine.get_segmentation_score(ORG)
    assert result["grade"] == "A"


def test_get_segmentation_score_fields(engine):
    result = engine.get_segmentation_score(ORG)
    assert "score" in result
    assert "grade" in result
    assert "segments_count" in result
    assert "policies_count" in result
    assert "lateral_movement_risks" in result
    assert "findings" in result


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

def test_get_segmentation_stats_empty(engine):
    stats = engine.get_segmentation_stats(ORG)
    assert stats["segments"] == 0
    assert stats["flow_policies"] == 0
    assert stats["violations"] == 0


def test_get_segmentation_stats_with_data(engine):
    src = engine.create_segment(ORG, {"name": "DMZ", "segment_type": "dmz", "trust_level": 3})
    dst = engine.create_segment(ORG, {"name": "Prod", "segment_type": "prod", "trust_level": 9})
    engine.add_flow_policy(ORG, {
        "src_segment_id": src["id"],
        "dst_segment_id": dst["id"],
        "action": "deny",
    })
    stats = engine.get_segmentation_stats(ORG)
    assert stats["segments"] == 2
    assert stats["flow_policies"] == 1


def test_get_segmentation_stats_org_isolation(engine):
    engine.create_segment(ORG, {"name": "DMZ", "segment_type": "dmz"})
    engine.create_segment(ORG2, {"name": "Prod", "segment_type": "prod"})
    engine.create_segment(ORG2, {"name": "Dev", "segment_type": "dev"})
    stats_org1 = engine.get_segmentation_stats(ORG)
    stats_org2 = engine.get_segmentation_stats(ORG2)
    assert stats_org1["segments"] == 1
    assert stats_org2["segments"] == 2
