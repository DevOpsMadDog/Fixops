"""Tests for DigitalForensicsEngine — Digital Forensics case management.

Run with: python -m pytest tests/test_digital_forensics_engine.py -v --timeout=10
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))

from core.digital_forensics_engine import DigitalForensicsEngine


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def engine(tmp_path):
    """Create a DigitalForensicsEngine with a temporary database."""
    db_path = str(tmp_path / "forensics_test.db")
    return DigitalForensicsEngine(db_path=db_path)


@pytest.fixture
def org_id():
    return "org-test-001"


@pytest.fixture
def org2_id():
    return "org-other-999"


@pytest.fixture
def open_case(engine, org_id):
    return engine.create_case(org_id, {
        "title": "Ransomware Incident Q1",
        "case_type": "ransom",
        "priority": "critical",
        "assigned_analyst": "alice@aldeci.io",
        "related_incident_id": "INC-2026-001",
    })


@pytest.fixture
def evidence_item(engine, org_id, open_case):
    return engine.add_evidence(org_id, open_case["case_id"], {
        "evidence_type": "memory_dump",
        "filename": "memdump_srv01.raw",
        "size_bytes": 8589934592,
        "hash_md5": "d41d8cd98f00b204e9800998ecf8427e",
        "hash_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "collected_by": "alice@aldeci.io",
        "storage_location": "s3://forensics-bucket/cases/INC-2026-001/",
    })


# ============================================================================
# Initialization
# ============================================================================


def test_engine_init_creates_db(tmp_path):
    db_path = str(tmp_path / "new_forensics.db")
    engine = DigitalForensicsEngine(db_path=db_path)
    assert Path(db_path).exists()


def test_engine_init_creates_tables(tmp_path):
    import sqlite3
    db_path = str(tmp_path / "schema_test.db")
    DigitalForensicsEngine(db_path=db_path)
    conn = sqlite3.connect(db_path)
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    conn.close()
    assert "forensic_cases" in tables
    assert "evidence_items" in tables
    assert "analysis_results" in tables
    assert "chain_of_custody" in tables


# ============================================================================
# Case CRUD
# ============================================================================


def test_create_case_returns_dict(engine, org_id):
    result = engine.create_case(org_id, {"title": "Test Case", "case_type": "malware"})
    assert isinstance(result, dict)


def test_create_case_has_required_fields(engine, org_id):
    result = engine.create_case(org_id, {"title": "Test", "case_type": "insider"})
    for field in ("case_id", "org_id", "title", "case_type", "status", "priority", "created_at"):
        assert field in result, f"Missing field: {field}"


def test_create_case_defaults(engine, org_id):
    result = engine.create_case(org_id, {"title": "Minimal"})
    assert result["status"] == "open"
    assert result["priority"] == "medium"
    assert result["case_type"] == "malware"


def test_create_case_invalid_type_falls_back(engine, org_id):
    result = engine.create_case(org_id, {"title": "X", "case_type": "invalid_type"})
    assert result["case_type"] == "malware"


def test_list_cases_returns_list(engine, org_id, open_case):
    result = engine.list_cases(org_id)
    assert isinstance(result, list)
    assert len(result) >= 1


def test_list_cases_status_filter(engine, org_id):
    engine.create_case(org_id, {"title": "A", "status": "open"})
    engine.create_case(org_id, {"title": "B", "status": "closed"})
    open_cases = engine.list_cases(org_id, status="open")
    assert all(c["status"] == "open" for c in open_cases)


def test_get_case_returns_correct_record(engine, org_id, open_case):
    result = engine.get_case(org_id, open_case["case_id"])
    assert result is not None
    assert result["case_id"] == open_case["case_id"]
    assert result["title"] == "Ransomware Incident Q1"


def test_get_case_missing_returns_none(engine, org_id):
    result = engine.get_case(org_id, "nonexistent-case-id")
    assert result is None


# ============================================================================
# Evidence Management
# ============================================================================


def test_add_evidence_returns_dict(engine, org_id, open_case):
    result = engine.add_evidence(org_id, open_case["case_id"], {
        "evidence_type": "pcap",
        "filename": "capture.pcap",
        "collected_by": "bob",
    })
    assert isinstance(result, dict)
    assert "evidence_id" in result


def test_add_evidence_has_all_fields(engine, org_id, open_case, evidence_item):
    for field in ("evidence_id", "org_id", "case_id", "evidence_type",
                  "filename", "size_bytes", "hash_md5", "hash_sha256",
                  "collected_by", "collected_at", "storage_location"):
        assert field in evidence_item, f"Missing field: {field}"


def test_list_evidence_returns_items(engine, org_id, open_case, evidence_item):
    items = engine.list_evidence(org_id, open_case["case_id"])
    assert isinstance(items, list)
    assert len(items) >= 1
    assert any(e["evidence_id"] == evidence_item["evidence_id"] for e in items)


def test_add_evidence_invalid_type_falls_back(engine, org_id, open_case):
    result = engine.add_evidence(org_id, open_case["case_id"], {
        "evidence_type": "banana",
        "filename": "x.bin",
    })
    assert result["evidence_type"] == "log_file"


# ============================================================================
# Analysis Results
# ============================================================================


def test_add_analysis_result_returns_dict(engine, org_id, open_case, evidence_item):
    result = engine.add_analysis_result(org_id, open_case["case_id"], {
        "evidence_id": evidence_item["evidence_id"],
        "analysis_type": "memory",
        "findings": ["Mimikatz detected in lsass memory", "Credential dumping artifacts"],
        "iocs_extracted": ["185.220.101.45", "xmrig.exe"],
        "tool_used": "Volatility3",
        "analyst": "alice@aldeci.io",
    })
    assert isinstance(result, dict)
    assert "result_id" in result


def test_analysis_result_findings_are_list(engine, org_id, open_case):
    result = engine.add_analysis_result(org_id, open_case["case_id"], {
        "analysis_type": "static",
        "findings": ["Packed binary", "Suspicious imports"],
        "iocs_extracted": ["evil.com"],
    })
    assert isinstance(result["findings"], list)
    assert isinstance(result["iocs_extracted"], list)


def test_list_analysis_results_deserializes_json(engine, org_id, open_case):
    engine.add_analysis_result(org_id, open_case["case_id"], {
        "analysis_type": "network",
        "findings": ["C2 beacon traffic", "DNS tunneling"],
        "iocs_extracted": ["192.168.1.100"],
    })
    results = engine.list_analysis_results(org_id, open_case["case_id"])
    assert len(results) >= 1
    assert isinstance(results[0]["findings"], list)
    assert isinstance(results[0]["iocs_extracted"], list)


def test_analysis_invalid_type_falls_back(engine, org_id, open_case):
    result = engine.add_analysis_result(org_id, open_case["case_id"], {
        "analysis_type": "quantum",
        "findings": [],
    })
    assert result["analysis_type"] == "static"


# ============================================================================
# Chain of Custody
# ============================================================================


def test_log_chain_of_custody_returns_dict(engine, org_id, evidence_item):
    result = engine.log_chain_of_custody(
        org_id=org_id,
        evidence_id=evidence_item["evidence_id"],
        action="transferred",
        actor="bob@aldeci.io",
        notes="Transferred to lab analyst",
    )
    assert isinstance(result, dict)
    assert "custody_id" in result
    assert result["action"] == "transferred"


def test_get_chain_of_custody_includes_auto_entry(engine, org_id, evidence_item):
    """Adding evidence auto-logs a 'collected' custody entry."""
    entries = engine.get_chain_of_custody(org_id, evidence_item["evidence_id"])
    assert len(entries) >= 1
    actions = [e["action"] for e in entries]
    assert "collected" in actions


def test_chain_of_custody_ordered_ascending(engine, org_id, evidence_item):
    engine.log_chain_of_custody(org_id, evidence_item["evidence_id"], "analyzed", "alice", "")
    engine.log_chain_of_custody(org_id, evidence_item["evidence_id"], "archived", "bob", "")
    entries = engine.get_chain_of_custody(org_id, evidence_item["evidence_id"])
    timestamps = [e["timestamp"] for e in entries]
    assert timestamps == sorted(timestamps)


# ============================================================================
# Stats
# ============================================================================


def test_get_forensics_stats_returns_dict(engine, org_id):
    stats = engine.get_forensics_stats(org_id)
    assert isinstance(stats, dict)
    for key in ("open_cases", "evidence_items", "analyses_completed", "avg_case_duration_days"):
        assert key in stats


def test_forensics_stats_open_cases_count(engine, org_id):
    engine.create_case(org_id, {"title": "Case1", "status": "open"})
    engine.create_case(org_id, {"title": "Case2", "status": "active"})
    stats = engine.get_forensics_stats(org_id)
    assert stats["open_cases"] >= 2


def test_forensics_stats_evidence_count(engine, org_id, open_case, evidence_item):
    stats = engine.get_forensics_stats(org_id)
    assert stats["evidence_items"] >= 1


def test_forensics_stats_analyses_count(engine, org_id, open_case):
    engine.add_analysis_result(org_id, open_case["case_id"], {
        "analysis_type": "timeline",
        "findings": ["Lateral movement detected"],
    })
    stats = engine.get_forensics_stats(org_id)
    assert stats["analyses_completed"] >= 1


def test_forensics_stats_avg_duration_no_closed_cases(engine, org_id):
    stats = engine.get_forensics_stats(org_id)
    assert stats["avg_case_duration_days"] == 0.0


# ============================================================================
# Org Isolation
# ============================================================================


def test_cases_isolated_by_org(engine, org_id, org2_id):
    engine.create_case(org_id, {"title": "Org1 Case"})
    engine.create_case(org2_id, {"title": "Org2 Case"})

    org1_cases = engine.list_cases(org_id)
    org2_cases = engine.list_cases(org2_id)

    org1_titles = [c["title"] for c in org1_cases]
    org2_titles = [c["title"] for c in org2_cases]

    assert "Org1 Case" in org1_titles
    assert "Org2 Case" not in org1_titles
    assert "Org2 Case" in org2_titles
    assert "Org1 Case" not in org2_titles


def test_evidence_isolated_by_org(engine, org_id, org2_id):
    case1 = engine.create_case(org_id, {"title": "Org1 Case"})
    case2 = engine.create_case(org2_id, {"title": "Org2 Case"})

    engine.add_evidence(org_id, case1["case_id"], {"filename": "org1.pcap"})
    engine.add_evidence(org2_id, case2["case_id"], {"filename": "org2.pcap"})

    org1_evidence = engine.list_evidence(org_id, case1["case_id"])
    org2_evidence = engine.list_evidence(org2_id, case2["case_id"])

    assert all(e["org_id"] == org_id for e in org1_evidence)
    assert all(e["org_id"] == org2_id for e in org2_evidence)


def test_stats_isolated_by_org(engine, org_id, org2_id):
    engine.create_case(org_id, {"title": "A"})
    engine.create_case(org_id, {"title": "B"})
    # org2 has no cases

    stats1 = engine.get_forensics_stats(org_id)
    stats2 = engine.get_forensics_stats(org2_id)

    assert stats1["open_cases"] >= 2
    assert stats2["open_cases"] == 0
