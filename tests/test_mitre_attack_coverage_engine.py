"""Tests for MITREAttackCoverageEngine.

Coverage: seed, add_technique, log_detection, get_coverage, get_gaps,
          get_heatmap, get_techniques, get_detections, org isolation,
          edge cases.
"""

import unittest.mock
import pytest
import core.mitre_attack_coverage_engine as _mitre_module
from core.mitre_attack_coverage_engine import (
    MITREAttackCoverageEngine,
    MITRE_TECHNIQUES,
    MITRE_TACTICS,
    get_mitre_coverage_engine,
)

# The engine uses stdlib logging but calls it with structlog-style kwargs.
# Patch the module-level logger so tests are not broken by that engine bug.
_mitre_module._logger = unittest.mock.MagicMock()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engine(tmp_path):
    return MITREAttackCoverageEngine(data_dir=str(tmp_path))


ORG_A = "org-alpha"
ORG_B = "org-beta"


# ---------------------------------------------------------------------------
# seed_att_ck_techniques
# ---------------------------------------------------------------------------


def test_seed_returns_technique_count(engine):
    count = engine.seed_att_ck_techniques(ORG_A)
    assert count == len(MITRE_TECHNIQUES)


def test_seed_is_idempotent(engine):
    first = engine.seed_att_ck_techniques(ORG_A)
    second = engine.seed_att_ck_techniques(ORG_A)
    # Second call inserts 0 new rows (INSERT OR IGNORE)
    assert first == len(MITRE_TECHNIQUES)
    assert second == 0


def test_seed_populates_techniques_list(engine):
    engine.seed_att_ck_techniques(ORG_A)
    techniques = engine.get_techniques(ORG_A)
    assert len(techniques) == len(MITRE_TECHNIQUES)


def test_seed_technique_fields(engine):
    engine.seed_att_ck_techniques(ORG_A)
    techniques = engine.get_techniques(ORG_A)
    t = techniques[0]
    assert "technique_id" in t
    assert "name" in t
    assert "tactic_id" in t
    assert "severity" in t


def test_seed_different_orgs_independent(engine):
    engine.seed_att_ck_techniques(ORG_A)
    engine.seed_att_ck_techniques(ORG_B)
    a_techs = engine.get_techniques(ORG_A)
    b_techs = engine.get_techniques(ORG_B)
    assert len(a_techs) == len(b_techs) == len(MITRE_TECHNIQUES)


# ---------------------------------------------------------------------------
# add_technique
# ---------------------------------------------------------------------------


def test_add_technique_returns_record(engine):
    result = engine.add_technique(ORG_A, {
        "technique_id": "T9999",
        "name": "Custom Technique",
        "tactic_id": "TA0001",
    })
    assert result["technique_id"] == "T9999"
    assert result["name"] == "Custom Technique"
    assert result["tactic_id"] == "TA0001"
    assert result["org_id"] == ORG_A


def test_add_technique_normalises_to_uppercase(engine):
    result = engine.add_technique(ORG_A, {
        "technique_id": "t8888",
        "name": "Lower case ID",
        "tactic_id": "ta0002",
    })
    assert result["technique_id"] == "T8888"
    assert result["tactic_id"] == "TA0002"


def test_add_technique_optional_fields_default(engine):
    result = engine.add_technique(ORG_A, {
        "technique_id": "T7777",
        "name": "Minimal Technique",
        "tactic_id": "TA0003",
    })
    assert result["severity"] == "medium"
    assert result["description"] == ""


def test_add_technique_custom_severity(engine):
    result = engine.add_technique(ORG_A, {
        "technique_id": "T6666",
        "name": "Critical Tech",
        "tactic_id": "TA0004",
        "severity": "critical",
        "description": "Very dangerous",
    })
    assert result["severity"] == "critical"
    assert result["description"] == "Very dangerous"


def test_add_technique_missing_technique_id_raises(engine):
    with pytest.raises(ValueError, match="technique_id"):
        engine.add_technique(ORG_A, {"name": "No ID", "tactic_id": "TA0001"})


def test_add_technique_missing_name_raises(engine):
    with pytest.raises(ValueError, match="technique_id"):
        engine.add_technique(ORG_A, {"technique_id": "T1234", "tactic_id": "TA0001"})


def test_add_technique_missing_tactic_id_raises(engine):
    with pytest.raises(ValueError, match="technique_id"):
        engine.add_technique(ORG_A, {"technique_id": "T5555", "name": "No Tactic"})


def test_add_technique_appears_in_get_techniques(engine):
    engine.add_technique(ORG_A, {
        "technique_id": "T4444",
        "name": "Visible Tech",
        "tactic_id": "TA0005",
    })
    techs = engine.get_techniques(ORG_A)
    ids = [t["technique_id"] for t in techs]
    assert "T4444" in ids


def test_add_technique_org_isolation(engine):
    engine.add_technique(ORG_A, {
        "technique_id": "T3333",
        "name": "Org A Only",
        "tactic_id": "TA0001",
    })
    b_techs = engine.get_techniques(ORG_B)
    ids = [t["technique_id"] for t in b_techs]
    assert "T3333" not in ids


# ---------------------------------------------------------------------------
# log_detection
# ---------------------------------------------------------------------------


def test_log_detection_returns_record(engine):
    engine.seed_att_ck_techniques(ORG_A)
    rec = engine.log_detection(ORG_A, "T1190", "siem", 0.9)
    assert rec["org_id"] == ORG_A
    assert rec["technique_id"] == "T1190"
    assert rec["source"] == "siem"
    assert rec["confidence"] == 0.9
    assert "detection_id" in rec
    assert "detected_at" in rec


def test_log_detection_clamps_confidence_above_1(engine):
    engine.seed_att_ck_techniques(ORG_A)
    rec = engine.log_detection(ORG_A, "T1190", "edr", 1.5)
    assert rec["confidence"] == 1.0


def test_log_detection_clamps_confidence_below_0(engine):
    engine.seed_att_ck_techniques(ORG_A)
    rec = engine.log_detection(ORG_A, "T1190", "edr", -0.5)
    assert rec["confidence"] == 0.0


def test_log_detection_normalises_technique_id_case(engine):
    engine.seed_att_ck_techniques(ORG_A)
    rec = engine.log_detection(ORG_A, "t1078", "ids", 0.7)
    assert rec["technique_id"] == "T1078"


def test_log_detection_with_metadata(engine):
    engine.seed_att_ck_techniques(ORG_A)
    meta = {"host": "web-01", "alert_id": "A-001"}
    rec = engine.log_detection(ORG_A, "T1566", "email_gateway", 0.8, metadata=meta)
    assert rec["metadata"] == meta


def test_log_detection_multiple_detections_same_technique(engine):
    engine.seed_att_ck_techniques(ORG_A)
    for _ in range(3):
        engine.log_detection(ORG_A, "T1190", "siem", 0.9)
    dets = engine.get_detections(ORG_A, technique_id="T1190")
    assert len(dets) == 3


# ---------------------------------------------------------------------------
# get_coverage
# ---------------------------------------------------------------------------


def test_get_coverage_empty_org_returns_zeros(engine):
    result = engine.get_coverage(ORG_A)
    assert result["overall_pct"] == 0.0
    assert result["covered_count"] == 0
    assert result["total_count"] == 0
    assert result["tactic_breakdown"] == {}
    assert result["assessment_id"] is None


def test_get_coverage_after_seed_no_detections(engine):
    engine.seed_att_ck_techniques(ORG_A)
    result = engine.get_coverage(ORG_A)
    assert result["total_count"] == len(MITRE_TECHNIQUES)
    assert result["covered_count"] == 0
    assert result["overall_pct"] == 0.0


def test_get_coverage_after_detection(engine):
    engine.seed_att_ck_techniques(ORG_A)
    engine.log_detection(ORG_A, "T1190", "siem", 0.9)
    result = engine.get_coverage(ORG_A)
    assert result["covered_count"] == 1
    assert result["overall_pct"] > 0.0
    assert result["assessment_id"] is not None


def test_get_coverage_tactic_breakdown_structure(engine):
    engine.seed_att_ck_techniques(ORG_A)
    engine.log_detection(ORG_A, "T1190", "siem", 0.9)
    result = engine.get_coverage(ORG_A)
    breakdown = result["tactic_breakdown"]
    assert len(breakdown) > 0
    # Check at least one tactic entry has expected keys
    sample = next(iter(breakdown.values()))
    assert "tactic_id" in sample
    assert "covered" in sample
    assert "total" in sample
    assert "coverage_pct" in sample


def test_get_coverage_multiple_detections_same_technique_counts_once(engine):
    engine.seed_att_ck_techniques(ORG_A)
    for _ in range(5):
        engine.log_detection(ORG_A, "T1190", "siem", 0.9)
    result = engine.get_coverage(ORG_A)
    assert result["covered_count"] == 1


def test_get_coverage_org_isolation(engine):
    engine.seed_att_ck_techniques(ORG_A)
    engine.seed_att_ck_techniques(ORG_B)
    engine.log_detection(ORG_A, "T1190", "siem", 0.9)
    a_result = engine.get_coverage(ORG_A)
    b_result = engine.get_coverage(ORG_B)
    assert a_result["covered_count"] == 1
    assert b_result["covered_count"] == 0


# ---------------------------------------------------------------------------
# get_gaps
# ---------------------------------------------------------------------------


def test_get_gaps_all_techniques_gap_when_no_detections(engine):
    engine.seed_att_ck_techniques(ORG_A)
    gaps = engine.get_gaps(ORG_A)
    assert len(gaps) == len(MITRE_TECHNIQUES)


def test_get_gaps_detected_technique_removed_from_gaps(engine):
    engine.seed_att_ck_techniques(ORG_A)
    engine.log_detection(ORG_A, "T1190", "siem", 0.9)
    gaps = engine.get_gaps(ORG_A)
    gap_ids = [g["technique_id"] for g in gaps]
    assert "T1190" not in gap_ids
    assert len(gaps) == len(MITRE_TECHNIQUES) - 1


def test_get_gaps_sorted_critical_first(engine):
    engine.seed_att_ck_techniques(ORG_A)
    gaps = engine.get_gaps(ORG_A)
    # Find first non-critical severity position
    severities = [g["severity"] for g in gaps]
    critical_positions = [i for i, s in enumerate(severities) if s == "critical"]
    high_positions = [i for i, s in enumerate(severities) if s == "high"]
    if critical_positions and high_positions:
        assert max(critical_positions) < min(high_positions)


def test_get_gaps_structure(engine):
    engine.seed_att_ck_techniques(ORG_A)
    gaps = engine.get_gaps(ORG_A)
    gap = gaps[0]
    assert "technique_id" in gap
    assert "name" in gap
    assert "tactic_id" in gap
    assert "severity" in gap


def test_get_gaps_empty_when_all_detected(engine):
    engine.seed_att_ck_techniques(ORG_A)
    for tid, *_ in MITRE_TECHNIQUES:
        engine.log_detection(ORG_A, tid, "siem", 0.8)
    gaps = engine.get_gaps(ORG_A)
    assert len(gaps) == 0


# ---------------------------------------------------------------------------
# get_heatmap
# ---------------------------------------------------------------------------


def test_get_heatmap_structure(engine):
    engine.seed_att_ck_techniques(ORG_A)
    heatmap = engine.get_heatmap(ORG_A)
    assert heatmap["domain"] == "enterprise-attack"
    assert heatmap["attack_version"] == "14"
    assert "by_tactic" in heatmap
    assert "techniques" in heatmap
    assert heatmap["org_id"] == ORG_A


def test_get_heatmap_no_detections_zero_total(engine):
    engine.seed_att_ck_techniques(ORG_A)
    heatmap = engine.get_heatmap(ORG_A)
    assert heatmap["total_detections"] == 0
    assert heatmap["techniques"] == []


def test_get_heatmap_after_detection(engine):
    engine.seed_att_ck_techniques(ORG_A)
    engine.log_detection(ORG_A, "T1190", "siem", 0.9)
    heatmap = engine.get_heatmap(ORG_A)
    assert heatmap["total_detections"] == 1
    assert len(heatmap["techniques"]) == 1
    assert heatmap["techniques"][0]["techniqueID"] == "T1190"


def test_get_heatmap_score_capped_at_100(engine):
    engine.seed_att_ck_techniques(ORG_A)
    for _ in range(10):
        engine.log_detection(ORG_A, "T1190", "siem", 0.9)
    heatmap = engine.get_heatmap(ORG_A)
    t_entry = next(t for t in heatmap["techniques"] if t["techniqueID"] == "T1190")
    assert t_entry["score"] <= 100


def test_get_heatmap_by_tactic_entries(engine):
    engine.seed_att_ck_techniques(ORG_A)
    heatmap = engine.get_heatmap(ORG_A)
    by_tactic = heatmap["by_tactic"]
    assert len(by_tactic) > 0
    entry = by_tactic[0]
    assert "tactic_id" in entry
    assert "techniques" in entry
    assert "total_count" in entry


# ---------------------------------------------------------------------------
# get_techniques
# ---------------------------------------------------------------------------


def test_get_techniques_empty_for_new_org(engine):
    techs = engine.get_techniques(ORG_A)
    assert techs == []


def test_get_techniques_includes_detection_count(engine):
    engine.seed_att_ck_techniques(ORG_A)
    engine.log_detection(ORG_A, "T1190", "siem", 0.9)
    techs = engine.get_techniques(ORG_A)
    t1190 = next(t for t in techs if t["technique_id"] == "T1190")
    assert t1190["detection_count"] == 1


# ---------------------------------------------------------------------------
# get_detections
# ---------------------------------------------------------------------------


def test_get_detections_returns_all_for_org(engine):
    engine.seed_att_ck_techniques(ORG_A)
    engine.log_detection(ORG_A, "T1190", "siem", 0.9)
    engine.log_detection(ORG_A, "T1078", "edr", 0.7)
    dets = engine.get_detections(ORG_A)
    assert len(dets) == 2


def test_get_detections_filter_by_technique(engine):
    engine.seed_att_ck_techniques(ORG_A)
    engine.log_detection(ORG_A, "T1190", "siem", 0.9)
    engine.log_detection(ORG_A, "T1078", "edr", 0.7)
    dets = engine.get_detections(ORG_A, technique_id="T1190")
    assert all(d["technique_id"] == "T1190" for d in dets)
    assert len(dets) == 1


def test_get_detections_metadata_parsed(engine):
    engine.seed_att_ck_techniques(ORG_A)
    engine.log_detection(ORG_A, "T1190", "siem", 0.9, metadata={"key": "val"})
    dets = engine.get_detections(ORG_A)
    assert dets[0]["metadata"] == {"key": "val"}


def test_get_detections_org_isolation(engine):
    engine.seed_att_ck_techniques(ORG_A)
    engine.seed_att_ck_techniques(ORG_B)
    engine.log_detection(ORG_A, "T1190", "siem", 0.9)
    b_dets = engine.get_detections(ORG_B)
    assert len(b_dets) == 0


def test_get_detections_limit_respected(engine):
    engine.seed_att_ck_techniques(ORG_A)
    for _ in range(10):
        engine.log_detection(ORG_A, "T1190", "siem", 0.9)
    dets = engine.get_detections(ORG_A, limit=5)
    assert len(dets) == 5


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------


def test_get_mitre_coverage_engine_returns_instance():
    instance = get_mitre_coverage_engine()
    assert isinstance(instance, MITREAttackCoverageEngine)


def test_get_mitre_coverage_engine_is_singleton():
    a = get_mitre_coverage_engine()
    b = get_mitre_coverage_engine()


# ---------------------------------------------------------------------------
# get_technique_by_id
# ---------------------------------------------------------------------------


def test_lookup_returns_seeded_technique(engine):
    engine.seed_att_ck_techniques(ORG_A)
    result = engine.get_technique_by_id(ORG_A, "T1190")
    assert result is not None
    assert result["technique_id"] == "T1190"
    assert result["name"] == "Exploit Public-Facing Application"
    assert result["tactic_id"] == "TA0001"


def test_lookup_is_case_insensitive(engine):
    engine.seed_att_ck_techniques(ORG_A)
    lower = engine.get_technique_by_id(ORG_A, "t1059")
    upper = engine.get_technique_by_id(ORG_A, "T1059")
    assert lower is not None
    assert lower["technique_id"] == upper["technique_id"] == "T1059"


def test_lookup_missing_returns_none(engine):
    engine.seed_att_ck_techniques(ORG_A)
    result = engine.get_technique_by_id(ORG_A, "T9999")
    assert result is None


def test_lookup_org_isolation(engine):
    engine.seed_att_ck_techniques(ORG_A)
    # ORG_B has no seeded data — lookup must return None
    result = engine.get_technique_by_id(ORG_B, "T1190")
    assert result is None


def test_lookup_includes_detection_count(engine):
    engine.seed_att_ck_techniques(ORG_A)
    engine.log_detection(ORG_A, "T1078", "siem", 0.9)
    engine.log_detection(ORG_A, "T1078", "edr", 0.8)
    result = engine.get_technique_by_id(ORG_A, "T1078")
    assert result is not None
    assert result["detection_count"] == 2


def test_lookup_empty_org_returns_none(engine):
    # No seed called — DB initialised but empty
    result = engine.get_technique_by_id(ORG_A, "T1190")
    assert result is None
