"""Tests for AttackChainEngine — ALDECI Wave 18."""

from __future__ import annotations

import pytest

from core.attack_chain_engine import AttackChainEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine(tmp_path):
    return AttackChainEngine(db_path=str(tmp_path / "attack_chain.db"))


@pytest.fixture
def chain(engine):
    return engine.create_chain("org1", {
        "chain_name": "APT29 Intrusion",
        "threat_actor": "APT29",
        "kill_chain_phase": "reconnaissance",
        "confidence": 75.0,
        "iocs": ["1.2.3.4", "evil.com"],
    })


# ---------------------------------------------------------------------------
# create_chain
# ---------------------------------------------------------------------------

def test_create_chain_basic(engine):
    result = engine.create_chain("org1", {"chain_name": "Test Chain"})
    assert result["chain_name"] == "Test Chain"
    assert result["status"] == "active"
    assert result["confidence"] == 50.0
    assert result["kill_chain_phase"] == "reconnaissance"
    assert isinstance(result["iocs"], list)


def test_create_chain_missing_name_raises(engine):
    with pytest.raises(ValueError, match="chain_name is required"):
        engine.create_chain("org1", {})


def test_create_chain_empty_name_raises(engine):
    with pytest.raises(ValueError):
        engine.create_chain("org1", {"chain_name": "   "})


def test_create_chain_invalid_phase_raises(engine):
    with pytest.raises(ValueError, match="kill_chain_phase"):
        engine.create_chain("org1", {"chain_name": "Bad", "kill_chain_phase": "unknown_phase"})


def test_create_chain_all_kill_chain_phases(engine):
    phases = [
        "reconnaissance", "weaponization", "delivery", "exploitation",
        "installation", "c2", "actions_on_objectives",
    ]
    for phase in phases:
        result = engine.create_chain("org1", {
            "chain_name": f"Chain {phase}",
            "kill_chain_phase": phase,
        })
        assert result["kill_chain_phase"] == phase


def test_create_chain_with_iocs(engine):
    result = engine.create_chain("org1", {
        "chain_name": "IOC Chain",
        "iocs": ["192.168.1.1", "malware.exe"],
    })
    assert result["iocs"] == ["192.168.1.1", "malware.exe"]


# ---------------------------------------------------------------------------
# list_chains
# ---------------------------------------------------------------------------

def test_list_chains_returns_all(engine, chain):
    engine.create_chain("org1", {"chain_name": "Second Chain"})
    results = engine.list_chains("org1")
    assert len(results) == 2


def test_list_chains_filter_by_status(engine):
    engine.create_chain("org1", {"chain_name": "Active"})
    c2 = engine.create_chain("org1", {"chain_name": "Contained"})
    engine.update_chain_status("org1", c2["id"], "contained")
    active = engine.list_chains("org1", status="active")
    assert all(c["status"] == "active" for c in active)
    contained = engine.list_chains("org1", status="contained")
    assert all(c["status"] == "contained" for c in contained)


def test_list_chains_filter_by_phase(engine):
    engine.create_chain("org1", {"chain_name": "Recon Chain", "kill_chain_phase": "reconnaissance"})
    engine.create_chain("org1", {"chain_name": "Delivery Chain", "kill_chain_phase": "delivery"})
    recon = engine.list_chains("org1", kill_chain_phase="reconnaissance")
    assert all(c["kill_chain_phase"] == "reconnaissance" for c in recon)


# ---------------------------------------------------------------------------
# get_chain
# ---------------------------------------------------------------------------

def test_get_chain_found(engine, chain):
    result = engine.get_chain("org1", chain["id"])
    assert result["id"] == chain["id"]


def test_get_chain_wrong_org_returns_none(engine, chain):
    assert engine.get_chain("org_other", chain["id"]) is None


def test_get_chain_not_found_returns_none(engine):
    assert engine.get_chain("org1", "nonexistent-id") is None


# ---------------------------------------------------------------------------
# update_chain_status
# ---------------------------------------------------------------------------

def test_update_chain_status_valid(engine, chain):
    result = engine.update_chain_status("org1", chain["id"], "contained")
    assert result["status"] == "contained"


def test_update_chain_status_full_lifecycle(engine, chain):
    for status in ["contained", "eradicated", "recovered"]:
        result = engine.update_chain_status("org1", chain["id"], status)
        assert result["status"] == status


def test_update_chain_status_invalid_raises(engine, chain):
    with pytest.raises(ValueError, match="status"):
        engine.update_chain_status("org1", chain["id"], "deleted")


def test_update_chain_status_not_found_raises(engine):
    with pytest.raises(KeyError):
        engine.update_chain_status("org1", "bad-id", "contained")


def test_update_chain_status_updates_updated_at(engine, chain):
    original_updated_at = chain["updated_at"]
    result = engine.update_chain_status("org1", chain["id"], "contained")
    assert result["updated_at"] >= original_updated_at


# ---------------------------------------------------------------------------
# add_chain_step
# ---------------------------------------------------------------------------

def test_add_chain_step_basic(engine, chain):
    step = engine.add_chain_step("org1", chain["id"], {
        "technique_name": "Spearphishing",
        "tactic": "initial-access",
    })
    assert step["technique_name"] == "Spearphishing"
    assert step["tactic"] == "initial-access"
    assert step["outcome"] == "unknown"
    assert step["step_number"] == 1


def test_add_chain_step_auto_increments(engine, chain):
    s1 = engine.add_chain_step("org1", chain["id"], {"technique_name": "Step1", "tactic": "t1"})
    s2 = engine.add_chain_step("org1", chain["id"], {"technique_name": "Step2", "tactic": "t2"})
    s3 = engine.add_chain_step("org1", chain["id"], {"technique_name": "Step3", "tactic": "t3"})
    assert s1["step_number"] == 1
    assert s2["step_number"] == 2
    assert s3["step_number"] == 3


def test_add_chain_step_explicit_step_number(engine, chain):
    step = engine.add_chain_step("org1", chain["id"], {
        "technique_name": "Jump", "tactic": "lateral-movement", "step_number": 10,
    })
    assert step["step_number"] == 10


def test_add_chain_step_invalid_chain_raises(engine):
    with pytest.raises(KeyError):
        engine.add_chain_step("org1", "bad-chain-id", {
            "technique_name": "T", "tactic": "t",
        })


def test_add_chain_step_missing_technique_raises(engine, chain):
    with pytest.raises(ValueError, match="technique_name"):
        engine.add_chain_step("org1", chain["id"], {"tactic": "t"})


def test_add_chain_step_missing_tactic_raises(engine, chain):
    with pytest.raises(ValueError, match="tactic"):
        engine.add_chain_step("org1", chain["id"], {"technique_name": "T"})


def test_add_chain_step_with_evidence(engine, chain):
    step = engine.add_chain_step("org1", chain["id"], {
        "technique_name": "T", "tactic": "t",
        "evidence": ["log_entry_1", "pcap_file"],
    })
    assert step["evidence"] == ["log_entry_1", "pcap_file"]


# ---------------------------------------------------------------------------
# list_chain_steps
# ---------------------------------------------------------------------------

def test_list_chain_steps_ordered_by_step_number(engine, chain):
    engine.add_chain_step("org1", chain["id"], {"technique_name": "A", "tactic": "t", "step_number": 3})
    engine.add_chain_step("org1", chain["id"], {"technique_name": "B", "tactic": "t", "step_number": 1})
    engine.add_chain_step("org1", chain["id"], {"technique_name": "C", "tactic": "t", "step_number": 2})
    steps = engine.list_chain_steps("org1", chain["id"])
    assert [s["step_number"] for s in steps] == [1, 2, 3]


def test_list_chain_steps_empty(engine, chain):
    assert engine.list_chain_steps("org1", chain["id"]) == []


# ---------------------------------------------------------------------------
# link_chains
# ---------------------------------------------------------------------------

def test_link_chains_basic(engine):
    c1 = engine.create_chain("org1", {"chain_name": "C1"})
    c2 = engine.create_chain("org1", {"chain_name": "C2"})
    link = engine.link_chains("org1", {
        "source_chain_id": c1["id"],
        "target_chain_id": c2["id"],
        "link_type": "lateral_movement",
    })
    assert link["link_type"] == "lateral_movement"
    assert link["source_chain_id"] == c1["id"]
    assert link["target_chain_id"] == c2["id"]


def test_link_chains_all_link_types(engine):
    c1 = engine.create_chain("org1", {"chain_name": "C1"})
    c2 = engine.create_chain("org1", {"chain_name": "C2"})
    for lt in ["lateral_movement", "persistence", "escalation"]:
        link = engine.link_chains("org1", {
            "source_chain_id": c1["id"],
            "target_chain_id": c2["id"],
            "link_type": lt,
        })
        assert link["link_type"] == lt


def test_link_chains_invalid_source_raises(engine):
    c2 = engine.create_chain("org1", {"chain_name": "C2"})
    with pytest.raises(KeyError):
        engine.link_chains("org1", {
            "source_chain_id": "bad-id",
            "target_chain_id": c2["id"],
            "link_type": "lateral_movement",
        })


def test_link_chains_invalid_target_raises(engine):
    c1 = engine.create_chain("org1", {"chain_name": "C1"})
    with pytest.raises(KeyError):
        engine.link_chains("org1", {
            "source_chain_id": c1["id"],
            "target_chain_id": "bad-id",
            "link_type": "lateral_movement",
        })


def test_link_chains_wrong_org_raises(engine):
    c1 = engine.create_chain("org1", {"chain_name": "C1"})
    c2 = engine.create_chain("org1", {"chain_name": "C2"})
    with pytest.raises(KeyError):
        engine.link_chains("org_other", {
            "source_chain_id": c1["id"],
            "target_chain_id": c2["id"],
            "link_type": "lateral_movement",
        })


# ---------------------------------------------------------------------------
# get_chain_links
# ---------------------------------------------------------------------------

def test_get_chain_links_as_source_and_target(engine):
    c1 = engine.create_chain("org1", {"chain_name": "C1"})
    c2 = engine.create_chain("org1", {"chain_name": "C2"})
    c3 = engine.create_chain("org1", {"chain_name": "C3"})
    engine.link_chains("org1", {
        "source_chain_id": c1["id"], "target_chain_id": c2["id"], "link_type": "lateral_movement"
    })
    engine.link_chains("org1", {
        "source_chain_id": c3["id"], "target_chain_id": c1["id"], "link_type": "persistence"
    })
    links = engine.get_chain_links("org1", c1["id"])
    assert len(links) == 2


# ---------------------------------------------------------------------------
# get_attack_stats
# ---------------------------------------------------------------------------

def test_get_attack_stats_empty(engine):
    stats = engine.get_attack_stats("org1")
    assert stats["total_chains"] == 0
    assert stats["active_chains"] == 0
    assert stats["total_steps"] == 0
    assert stats["avg_steps_per_chain"] == 0.0


def test_get_attack_stats_counts(engine):
    c1 = engine.create_chain("org1", {
        "chain_name": "C1", "kill_chain_phase": "delivery",
    })
    c2 = engine.create_chain("org1", {
        "chain_name": "C2", "kill_chain_phase": "exploitation",
    })
    engine.update_chain_status("org1", c2["id"], "contained")
    engine.add_chain_step("org1", c1["id"], {"technique_name": "T1", "tactic": "t"})
    engine.add_chain_step("org1", c1["id"], {"technique_name": "T2", "tactic": "t"})
    engine.add_chain_step("org1", c2["id"], {"technique_name": "T3", "tactic": "t"})

    stats = engine.get_attack_stats("org1")
    assert stats["total_chains"] == 2
    assert stats["active_chains"] == 1
    assert stats["by_status"]["active"] == 1
    assert stats["by_status"]["contained"] == 1
    assert stats["by_phase"]["delivery"] == 1
    assert stats["by_phase"]["exploitation"] == 1
    assert stats["total_steps"] == 3
    assert stats["avg_steps_per_chain"] == pytest.approx(1.5)


# ---------------------------------------------------------------------------
# Org isolation
# ---------------------------------------------------------------------------

def test_org_isolation(engine):
    engine.create_chain("org1", {"chain_name": "Org1 Chain"})
    engine.create_chain("org2", {"chain_name": "Org2 Chain"})
    assert len(engine.list_chains("org1")) == 1
    assert len(engine.list_chains("org2")) == 1
    stats1 = engine.get_attack_stats("org1")
    stats2 = engine.get_attack_stats("org2")
    assert stats1["total_chains"] == 1
    assert stats2["total_chains"] == 1
