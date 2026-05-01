"""Test that /api/v1/hunting-playbooks/playbooks surfaces real SigmaHQ data.

Verifies the empty-endpoint fix: when the org has not authored any playbooks,
list_playbooks() falls back to the imported SigmaHQ rule catalog (real public
data from github.com/SigmaHQ/sigma, no mocks). Fixture builds a tiny SigmaHQ
PersistentDict-shape table with 3 real-shaped rule rows and points the engine
at it.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from core.threat_hunting_playbook_engine import ThreatHuntingPlaybookEngine


def _build_sigma_db(path: Path, rules: list[dict]) -> None:
    """Materialise a real-shaped SigmaHQ PersistentDict snapshot."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(str(path)) as c:
        c.execute(
            "CREATE TABLE IF NOT EXISTS sigmahq_rules (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
        )
        for rule in rules:
            c.execute(
                "INSERT OR REPLACE INTO sigmahq_rules (key, value) VALUES (?, ?)",
                (rule["id"], json.dumps(rule)),
            )
        c.commit()


@pytest.fixture
def engine(tmp_path):
    return ThreatHuntingPlaybookEngine(db_path=str(tmp_path / "thp.db"))


def test_no_org_playbooks_no_sigma_returns_empty_with_hint(engine, tmp_path):
    res = engine.list_playbooks_with_sigma_fallback(
        "fresh-org",
        sigma_db_path=str(tmp_path / "missing.db"),
    )
    assert res["playbooks"] == []
    assert res["total"] == 0
    assert res["source"] == "empty"
    assert "import-sigma" in res["hint"]


def test_no_org_playbooks_table_missing_returns_empty(engine, tmp_path):
    """Sigma DB exists but has no sigmahq_rules table -> structured empty."""
    db = tmp_path / "state.db"
    with sqlite3.connect(str(db)) as c:
        c.execute("CREATE TABLE other (k TEXT)")
        c.commit()
    res = engine.list_playbooks_with_sigma_fallback(
        "fresh-org-2", sigma_db_path=str(db)
    )
    assert res["source"] == "empty"
    assert res["total"] == 0


def test_empty_org_falls_back_to_sigmahq_rules(engine, tmp_path):
    sigma_db = tmp_path / "state.db"
    _build_sigma_db(sigma_db, [
        {
            "id": "f0a8b6c0-1111-4444-8888-deadbeefcafe",
            "title": "Suspicious PowerShell Encoded Command",
            "status": "stable",
            "description": "Detects use of PowerShell -EncodedCommand for obfuscated payload execution.",
            "tags": ["attack.t1059.001", "attack.execution", "windows.process_creation"],
            "attack_techniques": ["t1059.001"],
            "logsource": {"product": "windows", "category": "process_creation"},
            "platform": "windows",
            "level": "high",
            "imported_at": "2024-05-01T00:00:00Z",
        },
        {
            "id": "1a2b3c4d-5555-6666-7777-abcdef012345",
            "title": "Mimikatz LSASS Memory Access",
            "description": "Detects LSASS memory access patterns characteristic of Mimikatz.",
            "tags": ["attack.t1003.001", "attack.credential-access", "windows.defender"],
            "attack_techniques": ["t1003.001"],
            "logsource": {"product": "windows", "service": "security"},
            "platform": "windows",
            "level": "critical",
        },
        {
            "id": "9999aaaa-bbbb-cccc-dddd-eeeeffff0000",
            "title": "DNS Tunnel Detection",
            "description": "Anomalously long DNS queries — possible C2 tunnel.",
            "tags": ["network.dns", "anomaly"],
            "attack_techniques": [],
            "logsource": {"category": "dns"},
            "platform": "network",
            "level": "medium",
        },
    ])

    res = engine.list_playbooks_with_sigma_fallback(
        "fresh-org-3", sigma_db_path=str(sigma_db)
    )
    assert res["source"] == "sigmahq-derived"
    assert res["total"] == 3
    assert res["sigma_total"] == 3

    by_name = {p["playbook_name"]: p for p in res["playbooks"]}
    pwsh = by_name["Suspicious PowerShell Encoded Command"]
    # attack_techniques present -> ttp hunt_type
    assert pwsh["hunt_type"] == "ttp"
    assert pwsh["mitre_technique"] == "T1059.001"
    assert pwsh["data_sources"] == ["windows", "process_creation"]
    assert pwsh["tools"] == ["sigma"]
    assert pwsh["source"] == "sigmahq"
    # No attack_techniques -> behavioral
    dns = by_name["DNS Tunnel Detection"]
    assert dns["hunt_type"] == "behavioral"
    assert dns["mitre_technique"] == ""


def test_sigma_fallback_hunt_type_filter_applies(engine, tmp_path):
    sigma_db = tmp_path / "sigma_filt.db"
    _build_sigma_db(sigma_db, [
        {"id": "id1", "title": "TTP rule", "tags": ["attack.t1059"],
         "attack_techniques": ["t1059"], "logsource": {}, "level": "high"},
        {"id": "id2", "title": "Behavioral rule", "tags": ["anomaly"],
         "attack_techniques": [], "logsource": {}, "level": "low"},
    ])
    res = engine.list_playbooks_with_sigma_fallback(
        "filt-org", hunt_type="ttp", sigma_db_path=str(sigma_db)
    )
    assert res["total"] == 1
    assert res["playbooks"][0]["playbook_name"] == "TTP rule"


def test_org_authored_playbooks_take_precedence(engine, tmp_path):
    sigma_db = tmp_path / "sigma_pre.db"
    _build_sigma_db(sigma_db, [
        {"id": "id1", "title": "Sigma rule", "tags": ["attack.t1059"],
         "attack_techniques": ["t1059"], "logsource": {}, "level": "high"},
    ])
    engine.create_playbook(
        org_id="tier-org",
        playbook_name="Custom Lateral Movement Hunt",
        hunt_type="hypothesis",
        threat_category="lateral-movement",
    )
    res = engine.list_playbooks_with_sigma_fallback(
        "tier-org", sigma_db_path=str(sigma_db)
    )
    assert res["source"] == "org_authored"
    assert res["total"] == 1
    assert res["playbooks"][0]["playbook_name"] == "Custom Lateral Movement Hunt"


def test_sigma_fallback_skips_malformed_rule_values(engine, tmp_path):
    """A bad JSON row in the side-DB doesn't crash the listing."""
    sigma_db = tmp_path / "sigma_bad.db"
    sigma_db.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(str(sigma_db)) as c:
        c.execute(
            "CREATE TABLE sigmahq_rules (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
        )
        c.execute("INSERT INTO sigmahq_rules VALUES ('good', ?)",
                  (json.dumps({"id": "good", "title": "Real rule",
                               "tags": ["attack.t1059"], "attack_techniques": ["t1059"],
                               "logsource": {}, "level": "high"}),))
        c.execute("INSERT INTO sigmahq_rules VALUES ('bad', 'not-json{{{')")
        c.execute("INSERT INTO sigmahq_rules VALUES ('list', '[1,2,3]')")  # not a dict
        c.commit()
    res = engine.list_playbooks_with_sigma_fallback(
        "bad-org", sigma_db_path=str(sigma_db)
    )
    assert res["source"] == "sigmahq-derived"
    assert res["total"] == 1
    assert res["sigma_total"] == 3
    assert res["playbooks"][0]["playbook_name"] == "Real rule"
