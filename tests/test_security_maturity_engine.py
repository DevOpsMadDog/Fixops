"""Tests for SecurityMaturityEngine — 32 tests covering:
- DB init and schema
- Assessment lifecycle (create, list, get, complete)
- Framework-specific domain auto-creation (NIST CSF, CIS Controls, ISO 27001)
- Domain scoring and level computation
- Controls (add, list, implementation status scoring)
- Targets and gap analysis
- Roadmap generation
- Stats aggregation
- Org isolation
"""

from __future__ import annotations

import os
import tempfile
import pytest

from core.security_maturity_engine import SecurityMaturityEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine(tmp_path):
    db_path = str(tmp_path / "test_maturity.db")
    return SecurityMaturityEngine(db_path)


@pytest.fixture
def org():
    return "test-org-maturity"


@pytest.fixture
def org2():
    return "other-org-maturity"


# ---------------------------------------------------------------------------
# DB init
# ---------------------------------------------------------------------------

def test_engine_init(engine):
    """Engine initialises without error."""
    assert engine is not None
    assert engine.db_path.endswith(".db")


def test_db_tables_created(engine):
    """All four tables are created."""
    import sqlite3
    conn = sqlite3.connect(engine.db_path)
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    conn.close()
    assert "maturity_assessments" in tables
    assert "maturity_domains" in tables
    assert "maturity_controls" in tables
    assert "maturity_targets" in tables


# ---------------------------------------------------------------------------
# Assessment creation
# ---------------------------------------------------------------------------

def test_create_assessment_nist_csf(engine, org):
    a = engine.create_assessment(org, {"name": "NIST CSF Assessment", "framework": "nist_csf"})
    assert a["id"]
    assert a["name"] == "NIST CSF Assessment"
    assert a["framework"] == "nist_csf"
    assert a["status"] == "draft"
    assert a["overall_level"] == 1


def test_create_assessment_auto_creates_nist_domains(engine, org):
    a = engine.create_assessment(org, {"name": "NIST", "framework": "nist_csf"})
    full = engine.get_assessment(org, a["id"])
    domain_names = {d["domain_name"] for d in full["domains"]}
    assert "identify" in domain_names
    assert "protect" in domain_names
    assert "detect" in domain_names
    assert "respond" in domain_names
    assert "recover" in domain_names
    assert len(full["domains"]) == 5


def test_create_assessment_cis_controls_domains(engine, org):
    a = engine.create_assessment(org, {"name": "CIS", "framework": "cis_controls"})
    full = engine.get_assessment(org, a["id"])
    domain_names = {d["domain_name"] for d in full["domains"]}
    assert "ig1" in domain_names
    assert "ig2" in domain_names
    assert "ig3" in domain_names
    assert len(full["domains"]) == 3


def test_create_assessment_iso27001_domains(engine, org):
    a = engine.create_assessment(org, {"name": "ISO 27001", "framework": "iso27001"})
    full = engine.get_assessment(org, a["id"])
    assert len(full["domains"]) == 14  # A.5 through A.18


def test_create_assessment_custom_no_domains(engine, org):
    a = engine.create_assessment(org, {"name": "Custom", "framework": "custom"})
    full = engine.get_assessment(org, a["id"])
    assert full["domains"] == []


def test_create_assessment_invalid_framework(engine, org):
    with pytest.raises(ValueError, match="Invalid framework"):
        engine.create_assessment(org, {"name": "Bad", "framework": "unknown_fw"})


def test_create_assessment_missing_name(engine, org):
    with pytest.raises(ValueError, match="name is required"):
        engine.create_assessment(org, {"framework": "nist_csf"})


# ---------------------------------------------------------------------------
# List assessments
# ---------------------------------------------------------------------------

def test_list_assessments_empty(engine, org):
    assert engine.list_assessments(org) == []


def test_list_assessments_returns_all(engine, org):
    engine.create_assessment(org, {"name": "A1", "framework": "nist_csf"})
    engine.create_assessment(org, {"name": "A2", "framework": "cis_controls"})
    results = engine.list_assessments(org)
    assert len(results) == 2


def test_list_assessments_filter_status(engine, org):
    engine.create_assessment(org, {"name": "Draft", "framework": "nist_csf"})
    drafts = engine.list_assessments(org, status="draft")
    assert len(drafts) == 1
    completed = engine.list_assessments(org, status="completed")
    assert len(completed) == 0


# ---------------------------------------------------------------------------
# Domain scoring and level computation
# ---------------------------------------------------------------------------

def test_compute_level_boundaries(engine):
    assert engine._compute_level(0) == 1
    assert engine._compute_level(19.9) == 1
    assert engine._compute_level(20) == 2
    assert engine._compute_level(39.9) == 2
    assert engine._compute_level(40) == 3
    assert engine._compute_level(59.9) == 3
    assert engine._compute_level(60) == 4
    assert engine._compute_level(79.9) == 4
    assert engine._compute_level(80) == 5
    assert engine._compute_level(100) == 5


def test_add_domain_score_updates_level(engine, org):
    a = engine.create_assessment(org, {"name": "Score Test", "framework": "nist_csf"})
    full = engine.get_assessment(org, a["id"])
    domain_id = full["domains"][0]["id"]
    result = engine.add_domain_score(org, domain_id, {"score": 65.0, "evidence": "Docs reviewed"})
    assert result is not None
    assert result["score"] == 65.0
    assert result["level"] == 4


def test_add_domain_score_clamps_to_100(engine, org):
    a = engine.create_assessment(org, {"name": "Clamp Test", "framework": "nist_csf"})
    full = engine.get_assessment(org, a["id"])
    domain_id = full["domains"][0]["id"]
    result = engine.add_domain_score(org, domain_id, {"score": 150.0})
    assert result["score"] == 100.0
    assert result["level"] == 5


def test_add_domain_score_not_found(engine, org):
    result = engine.add_domain_score(org, "nonexistent-domain", {"score": 50.0})
    assert result is None


# ---------------------------------------------------------------------------
# Controls
# ---------------------------------------------------------------------------

def test_add_control_to_domain(engine, org):
    a = engine.create_assessment(org, {"name": "Controls Test", "framework": "nist_csf"})
    full = engine.get_assessment(org, a["id"])
    domain_id = full["domains"][0]["id"]
    ctrl = engine.add_control(org, domain_id, {
        "control_name": "MFA Enforcement",
        "implementation_status": "implemented",
        "control_id": "PR.AC-7",
    })
    assert ctrl["id"]
    assert ctrl["control_name"] == "MFA Enforcement"
    assert ctrl["implementation_status"] == "implemented"
    assert ctrl["score"] == 75.0  # implemented maps to 75.0


def test_add_control_not_implemented_score(engine, org):
    a = engine.create_assessment(org, {"name": "C2", "framework": "nist_csf"})
    full = engine.get_assessment(org, a["id"])
    domain_id = full["domains"][0]["id"]
    ctrl = engine.add_control(org, domain_id, {
        "control_name": "Logging",
        "implementation_status": "not_implemented",
    })
    assert ctrl["score"] == 0.0


def test_add_control_optimized_score(engine, org):
    a = engine.create_assessment(org, {"name": "C3", "framework": "nist_csf"})
    full = engine.get_assessment(org, a["id"])
    domain_id = full["domains"][0]["id"]
    ctrl = engine.add_control(org, domain_id, {
        "control_name": "SIEM",
        "implementation_status": "optimized",
    })
    assert ctrl["score"] == 100.0


def test_add_control_invalid_status(engine, org):
    a = engine.create_assessment(org, {"name": "C4", "framework": "nist_csf"})
    full = engine.get_assessment(org, a["id"])
    domain_id = full["domains"][0]["id"]
    with pytest.raises(ValueError, match="Invalid implementation_status"):
        engine.add_control(org, domain_id, {
            "control_name": "Bad",
            "implementation_status": "unknown_status",
        })


def test_list_controls(engine, org):
    a = engine.create_assessment(org, {"name": "C5", "framework": "nist_csf"})
    full = engine.get_assessment(org, a["id"])
    domain_id = full["domains"][0]["id"]
    engine.add_control(org, domain_id, {"control_name": "Ctrl1", "implementation_status": "partial"})
    engine.add_control(org, domain_id, {"control_name": "Ctrl2", "implementation_status": "implemented"})
    controls = engine.list_controls(org, domain_id)
    assert len(controls) == 2


# ---------------------------------------------------------------------------
# Complete assessment
# ---------------------------------------------------------------------------

def test_complete_assessment_computes_avg_score(engine, org):
    a = engine.create_assessment(org, {"name": "Complete Test", "framework": "nist_csf"})
    full = engine.get_assessment(org, a["id"])
    # Score all 5 domains
    for i, domain in enumerate(full["domains"]):
        engine.add_domain_score(org, domain["id"], {"score": float((i + 1) * 20)})
    # Avg = (20+40+60+80+100)/5 = 60 → level 4
    completed = engine.complete_assessment(org, a["id"])
    assert completed["status"] == "completed"
    assert completed["overall_score"] == 60.0
    assert completed["overall_level"] == 4
    assert completed["completed_date"] is not None


def test_complete_assessment_not_found(engine, org):
    result = engine.complete_assessment(org, "nonexistent-id")
    assert result is None


# ---------------------------------------------------------------------------
# Targets
# ---------------------------------------------------------------------------

def test_set_target(engine, org):
    t = engine.set_target(org, {
        "domain_name": "identify",
        "current_level": 2,
        "target_level": 4,
        "effort_estimate": "high",
        "target_date": "2026-12-31",
    })
    assert t["id"]
    assert t["domain_name"] == "identify"
    assert t["current_level"] == 2
    assert t["target_level"] == 4
    assert t["effort_estimate"] == "high"


def test_set_target_missing_domain(engine, org):
    with pytest.raises(ValueError, match="domain_name is required"):
        engine.set_target(org, {"current_level": 1, "target_level": 3})


def test_set_target_invalid_effort(engine, org):
    with pytest.raises(ValueError, match="Invalid effort_estimate"):
        engine.set_target(org, {
            "domain_name": "protect",
            "effort_estimate": "extreme",
        })


def test_list_targets_includes_gap(engine, org):
    engine.set_target(org, {"domain_name": "detect", "current_level": 1, "target_level": 4})
    targets = engine.list_targets(org)
    assert len(targets) >= 1
    t = next(t for t in targets if t["domain_name"] == "detect")
    assert t["gap"] == 3


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

def test_get_maturity_stats_empty(engine, org):
    stats = engine.get_maturity_stats(org)
    assert stats["assessments_completed"] == 0
    assert stats["avg_maturity_score"] == 0.0
    assert stats["domains_at_target"] == 0
    assert stats["domains_below_target"] == 0


def test_get_maturity_stats_after_completion(engine, org):
    a = engine.create_assessment(org, {"name": "Stats Test", "framework": "nist_csf"})
    full = engine.get_assessment(org, a["id"])
    for domain in full["domains"]:
        engine.add_domain_score(org, domain["id"], {"score": 80.0})
    engine.complete_assessment(org, a["id"])
    stats = engine.get_maturity_stats(org)
    assert stats["assessments_completed"] == 1
    assert stats["avg_maturity_score"] == 80.0
    assert "nist_csf" in stats["by_framework"]


# ---------------------------------------------------------------------------
# Roadmap
# ---------------------------------------------------------------------------

def test_get_roadmap_ordered_by_gap(engine, org):
    engine.set_target(org, {"domain_name": "recover", "current_level": 1, "target_level": 3})
    engine.set_target(org, {"domain_name": "respond", "current_level": 2, "target_level": 5})
    roadmap = engine.get_roadmap(org)
    # respond gap=3 > recover gap=2, so respond should come first
    assert len(roadmap) >= 2
    gaps = [r["gap"] for r in roadmap]
    assert gaps == sorted(gaps, reverse=True)


def test_roadmap_excludes_at_target(engine, org):
    engine.set_target(org, {"domain_name": "identify", "current_level": 4, "target_level": 4})
    roadmap = engine.get_roadmap(org)
    names = [r["domain_name"] for r in roadmap]
    assert "identify" not in names


# ---------------------------------------------------------------------------
# Org isolation
# ---------------------------------------------------------------------------

def test_org_isolation(engine, org, org2):
    engine.create_assessment(org, {"name": "Org1 Assessment", "framework": "nist_csf"})
    engine.create_assessment(org2, {"name": "Org2 Assessment", "framework": "cis_controls"})
    org1_results = engine.list_assessments(org)
    org2_results = engine.list_assessments(org2)
    assert len(org1_results) == 1
    assert org1_results[0]["name"] == "Org1 Assessment"
    assert len(org2_results) == 1
    assert org2_results[0]["name"] == "Org2 Assessment"
