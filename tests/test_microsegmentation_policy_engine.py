"""Tests for MicrosegmentationPolicyEngine — 30+ tests covering all major paths."""

from __future__ import annotations

import pytest


@pytest.fixture
def engine(tmp_path):
    from core.microsegmentation_policy_engine import MicrosegmentationPolicyEngine
    return MicrosegmentationPolicyEngine(db_path=str(tmp_path / "msp.db"))


ORG = "test-org-msp"
ORG2 = "other-org-msp"


# ---------------------------------------------------------------------------
# Segment creation
# ---------------------------------------------------------------------------

def test_create_segment_basic(engine):
    seg = engine.create_segment(ORG, {
        "name": "Prod DB",
        "segment_type": "database",
        "cidr_range": "10.1.0.0/24",
    })
    assert seg["id"]
    assert seg["name"] == "Prod DB"
    assert seg["segment_type"] == "database"
    assert seg["cidr_range"] == "10.1.0.0/24"
    assert seg["org_id"] == ORG
    assert seg["enforcement_mode"] == "monitoring"
    assert seg["policy_count"] == 0
    assert seg["violation_count"] == 0


def test_create_segment_all_types(engine):
    for stype in ("workload", "application", "database", "dmz", "iot", "management", "production", "development"):
        seg = engine.create_segment(ORG, {"name": f"Seg-{stype}", "segment_type": stype})
        assert seg["segment_type"] == stype


def test_create_segment_all_enforcement_modes(engine):
    for mode in ("enforcing", "monitoring", "disabled"):
        seg = engine.create_segment(ORG, {
            "name": f"Seg-{mode}",
            "segment_type": "workload",
            "enforcement_mode": mode,
        })
        assert seg["enforcement_mode"] == mode


def test_create_segment_missing_name(engine):
    with pytest.raises(ValueError, match="name"):
        engine.create_segment(ORG, {"segment_type": "workload"})


def test_create_segment_empty_name(engine):
    with pytest.raises(ValueError, match="name"):
        engine.create_segment(ORG, {"name": "", "segment_type": "workload"})


def test_create_segment_invalid_type(engine):
    with pytest.raises(ValueError):
        engine.create_segment(ORG, {"name": "X", "segment_type": "datacenter"})


def test_create_segment_invalid_enforcement_mode(engine):
    with pytest.raises(ValueError):
        engine.create_segment(ORG, {"name": "X", "segment_type": "workload", "enforcement_mode": "strict"})


# ---------------------------------------------------------------------------
# Segment list / get
# ---------------------------------------------------------------------------

def test_list_segments_empty(engine):
    assert engine.list_segments(ORG) == []


def test_list_segments_multiple(engine):
    engine.create_segment(ORG, {"name": "A", "segment_type": "workload"})
    engine.create_segment(ORG, {"name": "B", "segment_type": "database"})
    segs = engine.list_segments(ORG)
    assert len(segs) == 2


def test_list_segments_filter_by_type(engine):
    engine.create_segment(ORG, {"name": "WL1", "segment_type": "workload"})
    engine.create_segment(ORG, {"name": "DB1", "segment_type": "database"})
    wls = engine.list_segments(ORG, segment_type="workload")
    assert len(wls) == 1
    assert wls[0]["segment_type"] == "workload"


def test_list_segments_filter_by_enforcement_mode(engine):
    engine.create_segment(ORG, {"name": "E1", "segment_type": "workload", "enforcement_mode": "enforcing"})
    engine.create_segment(ORG, {"name": "M1", "segment_type": "workload", "enforcement_mode": "monitoring"})
    enforcing = engine.list_segments(ORG, enforcement_mode="enforcing")
    assert len(enforcing) == 1
    assert enforcing[0]["enforcement_mode"] == "enforcing"


def test_list_segments_org_isolation(engine):
    engine.create_segment(ORG, {"name": "A", "segment_type": "workload"})
    assert engine.list_segments(ORG2) == []


def test_get_segment_found(engine):
    seg = engine.create_segment(ORG, {"name": "Found", "segment_type": "dmz"})
    result = engine.get_segment(ORG, seg["id"])
    assert result is not None
    assert result["id"] == seg["id"]
    assert result["name"] == "Found"


def test_get_segment_not_found(engine):
    assert engine.get_segment(ORG, "nonexistent-id") is None


def test_get_segment_wrong_org(engine):
    seg = engine.create_segment(ORG, {"name": "Secret", "segment_type": "management"})
    assert engine.get_segment(ORG2, seg["id"]) is None


# ---------------------------------------------------------------------------
# Policy creation and policy_count increment
# ---------------------------------------------------------------------------

def test_create_policy_basic(engine):
    src = engine.create_segment(ORG, {"name": "Src", "segment_type": "workload"})
    dst = engine.create_segment(ORG, {"name": "Dst", "segment_type": "database"})
    policy = engine.create_policy(ORG, {
        "src_segment_id": src["id"],
        "dst_segment_id": dst["id"],
        "policy_action": "allow",
        "protocol": "tcp",
        "port_range": "5432",
    })
    assert policy["id"]
    assert policy["src_segment_id"] == src["id"]
    assert policy["dst_segment_id"] == dst["id"]
    assert policy["policy_action"] == "allow"
    assert policy["protocol"] == "tcp"
    assert policy["enabled"] == 1
    assert policy["match_count"] == 0


def test_create_policy_increments_policy_count_both_segments(engine):
    src = engine.create_segment(ORG, {"name": "Src", "segment_type": "workload"})
    dst = engine.create_segment(ORG, {"name": "Dst", "segment_type": "database"})
    assert engine.get_segment(ORG, src["id"])["policy_count"] == 0
    assert engine.get_segment(ORG, dst["id"])["policy_count"] == 0

    engine.create_policy(ORG, {
        "src_segment_id": src["id"],
        "dst_segment_id": dst["id"],
        "policy_action": "deny",
        "protocol": "any",
    })

    assert engine.get_segment(ORG, src["id"])["policy_count"] == 1
    assert engine.get_segment(ORG, dst["id"])["policy_count"] == 1


def test_create_policy_multiple_increments(engine):
    src = engine.create_segment(ORG, {"name": "Src", "segment_type": "workload"})
    dst = engine.create_segment(ORG, {"name": "Dst", "segment_type": "database"})
    for _ in range(3):
        engine.create_policy(ORG, {
            "src_segment_id": src["id"],
            "dst_segment_id": dst["id"],
            "policy_action": "allow",
            "protocol": "tcp",
        })
    assert engine.get_segment(ORG, src["id"])["policy_count"] == 3
    assert engine.get_segment(ORG, dst["id"])["policy_count"] == 3


def test_create_policy_all_actions(engine):
    src = engine.create_segment(ORG, {"name": "S", "segment_type": "workload"})
    dst = engine.create_segment(ORG, {"name": "D", "segment_type": "workload"})
    for action in ("allow", "deny", "inspect", "log", "rate_limit"):
        p = engine.create_policy(ORG, {
            "src_segment_id": src["id"],
            "dst_segment_id": dst["id"],
            "policy_action": action,
            "protocol": "tcp",
        })
        assert p["policy_action"] == action


def test_create_policy_all_protocols(engine):
    src = engine.create_segment(ORG, {"name": "S", "segment_type": "workload"})
    dst = engine.create_segment(ORG, {"name": "D", "segment_type": "workload"})
    for proto in ("tcp", "udp", "icmp", "any", "http", "https", "dns", "smtp"):
        p = engine.create_policy(ORG, {
            "src_segment_id": src["id"],
            "dst_segment_id": dst["id"],
            "policy_action": "allow",
            "protocol": proto,
        })
        assert p["protocol"] == proto


def test_create_policy_missing_src(engine):
    dst = engine.create_segment(ORG, {"name": "Dst", "segment_type": "database"})
    with pytest.raises(ValueError, match="src_segment_id"):
        engine.create_policy(ORG, {"dst_segment_id": dst["id"], "policy_action": "allow", "protocol": "tcp"})


def test_create_policy_missing_dst(engine):
    src = engine.create_segment(ORG, {"name": "Src", "segment_type": "workload"})
    with pytest.raises(ValueError, match="dst_segment_id"):
        engine.create_policy(ORG, {"src_segment_id": src["id"], "policy_action": "allow", "protocol": "tcp"})


def test_create_policy_invalid_action(engine):
    src = engine.create_segment(ORG, {"name": "S", "segment_type": "workload"})
    dst = engine.create_segment(ORG, {"name": "D", "segment_type": "workload"})
    with pytest.raises(ValueError):
        engine.create_policy(ORG, {
            "src_segment_id": src["id"],
            "dst_segment_id": dst["id"],
            "policy_action": "block",
            "protocol": "tcp",
        })


def test_create_policy_invalid_protocol(engine):
    src = engine.create_segment(ORG, {"name": "S", "segment_type": "workload"})
    dst = engine.create_segment(ORG, {"name": "D", "segment_type": "workload"})
    with pytest.raises(ValueError):
        engine.create_policy(ORG, {
            "src_segment_id": src["id"],
            "dst_segment_id": dst["id"],
            "policy_action": "allow",
            "protocol": "ftp",
        })


def test_list_policies_filter(engine):
    src = engine.create_segment(ORG, {"name": "S", "segment_type": "workload"})
    dst = engine.create_segment(ORG, {"name": "D", "segment_type": "database"})
    engine.create_policy(ORG, {"src_segment_id": src["id"], "dst_segment_id": dst["id"], "policy_action": "allow", "protocol": "tcp"})
    engine.create_policy(ORG, {"src_segment_id": src["id"], "dst_segment_id": dst["id"], "policy_action": "deny", "protocol": "udp"})

    allows = engine.list_policies(ORG, policy_action="allow")
    assert len(allows) == 1
    assert allows[0]["policy_action"] == "allow"

    src_filtered = engine.list_policies(ORG, src_segment_id=src["id"])
    assert len(src_filtered) == 2


# ---------------------------------------------------------------------------
# Violations and violation_count increment
# ---------------------------------------------------------------------------

def test_record_violation_basic(engine):
    seg = engine.create_segment(ORG, {"name": "Web", "segment_type": "application"})
    v = engine.record_violation(ORG, {
        "segment_id": seg["id"],
        "src_ip": "192.168.1.100",
        "dst_ip": "10.0.0.5",
        "protocol": "tcp",
        "port": 443,
        "violation_type": "blocked_traffic",
        "severity": "high",
    })
    assert v["id"]
    assert v["segment_id"] == seg["id"]
    assert v["violation_type"] == "blocked_traffic"
    assert v["severity"] == "high"
    assert v["port"] == 443


def test_record_violation_increments_violation_count(engine):
    seg = engine.create_segment(ORG, {"name": "Prod", "segment_type": "production"})
    assert engine.get_segment(ORG, seg["id"])["violation_count"] == 0
    engine.record_violation(ORG, {"segment_id": seg["id"], "violation_type": "blocked_traffic", "severity": "medium"})
    assert engine.get_segment(ORG, seg["id"])["violation_count"] == 1
    engine.record_violation(ORG, {"segment_id": seg["id"], "violation_type": "policy_mismatch", "severity": "high"})
    assert engine.get_segment(ORG, seg["id"])["violation_count"] == 2


def test_record_violation_all_types(engine):
    seg = engine.create_segment(ORG, {"name": "IoT", "segment_type": "iot"})
    for vtype in ("blocked_traffic", "policy_mismatch", "unauthorized_lateral", "data_exfil_attempt"):
        v = engine.record_violation(ORG, {
            "segment_id": seg["id"],
            "violation_type": vtype,
            "severity": "medium",
        })
        assert v["violation_type"] == vtype


def test_record_violation_missing_segment_id(engine):
    with pytest.raises(ValueError, match="segment_id"):
        engine.record_violation(ORG, {"violation_type": "blocked_traffic", "severity": "low"})


def test_list_violations_filter_by_segment(engine):
    seg1 = engine.create_segment(ORG, {"name": "S1", "segment_type": "workload"})
    seg2 = engine.create_segment(ORG, {"name": "S2", "segment_type": "database"})
    engine.record_violation(ORG, {"segment_id": seg1["id"], "violation_type": "blocked_traffic", "severity": "low"})
    engine.record_violation(ORG, {"segment_id": seg2["id"], "violation_type": "policy_mismatch", "severity": "high"})

    v1 = engine.list_violations(ORG, segment_id=seg1["id"])
    assert len(v1) == 1
    assert v1[0]["segment_id"] == seg1["id"]


def test_list_violations_filter_by_severity(engine):
    seg = engine.create_segment(ORG, {"name": "S", "segment_type": "workload"})
    engine.record_violation(ORG, {"segment_id": seg["id"], "violation_type": "blocked_traffic", "severity": "critical"})
    engine.record_violation(ORG, {"segment_id": seg["id"], "violation_type": "blocked_traffic", "severity": "low"})

    crits = engine.list_violations(ORG, severity="critical")
    assert len(crits) == 1
    assert crits[0]["severity"] == "critical"


# ---------------------------------------------------------------------------
# Stats — high_violation_segments detection
# ---------------------------------------------------------------------------

def test_get_segmentation_stats_empty(engine):
    stats = engine.get_segmentation_stats(ORG)
    assert stats["total_segments"] == 0
    assert stats["total_policies"] == 0
    assert stats["total_violations"] == 0
    assert stats["enforcing_segments"] == 0
    assert stats["high_violation_segments"] == []


def test_get_segmentation_stats_counts(engine):
    src = engine.create_segment(ORG, {"name": "S", "segment_type": "workload", "enforcement_mode": "enforcing"})
    dst = engine.create_segment(ORG, {"name": "D", "segment_type": "database", "enforcement_mode": "monitoring"})
    engine.create_policy(ORG, {"src_segment_id": src["id"], "dst_segment_id": dst["id"], "policy_action": "allow", "protocol": "tcp"})
    engine.record_violation(ORG, {"segment_id": src["id"], "violation_type": "blocked_traffic", "severity": "medium"})

    stats = engine.get_segmentation_stats(ORG)
    assert stats["total_segments"] == 2
    assert stats["total_policies"] == 1
    assert stats["total_violations"] == 1
    assert stats["enforcing_segments"] == 1


def test_get_segmentation_stats_by_segment_type(engine):
    engine.create_segment(ORG, {"name": "W1", "segment_type": "workload"})
    engine.create_segment(ORG, {"name": "W2", "segment_type": "workload"})
    engine.create_segment(ORG, {"name": "D1", "segment_type": "database"})
    stats = engine.get_segmentation_stats(ORG)
    assert stats["by_segment_type"]["workload"] == 2
    assert stats["by_segment_type"]["database"] == 1


def test_high_violation_segments_threshold(engine):
    seg = engine.create_segment(ORG, {"name": "Hot", "segment_type": "production"})
    # Add exactly 5 violations — should NOT appear (threshold is > 5)
    for _ in range(5):
        engine.record_violation(ORG, {"segment_id": seg["id"], "violation_type": "blocked_traffic", "severity": "medium"})
    stats = engine.get_segmentation_stats(ORG)
    assert len(stats["high_violation_segments"]) == 0

    # Add one more — now violation_count = 6, should appear
    engine.record_violation(ORG, {"segment_id": seg["id"], "violation_type": "policy_mismatch", "severity": "high"})
    stats = engine.get_segmentation_stats(ORG)
    assert len(stats["high_violation_segments"]) == 1
    assert stats["high_violation_segments"][0]["id"] == seg["id"]
    assert stats["high_violation_segments"][0]["violation_count"] == 6


def test_stats_org_isolation(engine):
    seg = engine.create_segment(ORG, {"name": "S", "segment_type": "workload"})
    engine.record_violation(ORG, {"segment_id": seg["id"], "violation_type": "blocked_traffic", "severity": "low"})
    stats = engine.get_segmentation_stats(ORG2)
    assert stats["total_segments"] == 0
    assert stats["total_violations"] == 0
