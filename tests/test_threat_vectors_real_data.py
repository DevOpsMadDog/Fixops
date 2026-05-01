"""Test that /api/v1/threat-vectors/vectors surfaces real MITRE ATT&CK data.

Verifies the empty-endpoint fix: when the org has not recorded any vectors,
list_vectors() falls back to the imported MITRE ATT&CK technique catalog
(real public-source data, no mocks). Fixture builds a tiny MITRE side-DB
with 4 real-shaped technique rows and points the engine at it.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from core.threat_vector_analysis_engine import ThreatVectorAnalysisEngine


def _build_mitre_db(path: Path, techniques: list[dict]) -> None:
    """Materialise a real-shaped MITRE ATT&CK SQLite snapshot."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(str(path)) as c:
        c.execute(
            """CREATE TABLE IF NOT EXISTS techniques (
                technique_id TEXT PRIMARY KEY,
                name         TEXT NOT NULL,
                description  TEXT,
                tactic_ids   TEXT,
                platforms    TEXT,
                tactic_type  TEXT,
                data_sources TEXT,
                is_subtechnique INTEGER DEFAULT 0,
                parent_id    TEXT,
                stix_id      TEXT,
                imported_at  TEXT NOT NULL
            )"""
        )
        for t in techniques:
            c.execute(
                """INSERT OR REPLACE INTO techniques
                   (technique_id, name, description, tactic_ids, platforms,
                    tactic_type, data_sources, is_subtechnique, parent_id,
                    stix_id, imported_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    t["technique_id"], t["name"], t.get("description", ""),
                    json.dumps(t.get("tactic_ids", [])),
                    json.dumps(t.get("platforms", [])),
                    "", "[]",
                    int(t.get("is_subtechnique", False)),
                    t.get("parent_id"),
                    t.get("stix_id", ""),
                    "2024-01-01T00:00:00Z",
                ),
            )
        c.commit()


@pytest.fixture
def engine(tmp_path):
    return ThreatVectorAnalysisEngine(db_path=str(tmp_path / "tva.db"))


def test_no_org_vectors_no_mitre_returns_empty_with_hint(engine, tmp_path):
    res = engine.list_vectors_with_mitre_fallback(
        "fresh", mitre_db_path=str(tmp_path / "missing.db")
    )
    assert res["vectors"] == []
    assert res["total"] == 0
    assert res["source"] == "empty"
    assert "import-mitre" in res["hint"]


def test_empty_org_falls_back_to_mitre_techniques(engine, tmp_path):
    mitre_db = tmp_path / "mitre.db"
    _build_mitre_db(mitre_db, [
        {"technique_id": "T1059", "name": "Command and Scripting Interpreter",
         "description": "Adversaries may abuse command and script interpreters.",
         "tactic_ids": ["execution"], "platforms": ["Windows", "Linux"]},
        {"technique_id": "T1486", "name": "Data Encrypted for Impact",
         "description": "Adversaries may encrypt data on target systems.",
         "tactic_ids": ["impact"], "platforms": ["Windows"]},
        {"technique_id": "T1003", "name": "OS Credential Dumping",
         "description": "Adversaries may attempt to dump credentials.",
         "tactic_ids": ["credential-access"], "platforms": ["Windows"]},
        # subtechnique should be filtered out
        {"technique_id": "T1003.001", "name": "LSASS Memory",
         "tactic_ids": ["credential-access"], "is_subtechnique": True,
         "parent_id": "T1003"},
    ])

    res = engine.list_vectors_with_mitre_fallback("fresh-2", mitre_db_path=str(mitre_db))
    assert res["source"] == "mitre-attack-derived"
    assert res["total"] == 3  # subtechnique excluded
    assert res["mitre_total"] == 3  # query already filters subtechniques

    by_id = {v["source_technique_id"]: v for v in res["vectors"]}
    assert "T1486" in by_id
    # impact tactic -> critical severity
    assert by_id["T1486"]["severity"] == "critical"
    # execution tactic -> high
    assert by_id["T1059"]["severity"] == "high"
    # credential-access -> high + vector_type credential_stuffing
    assert by_id["T1003"]["severity"] == "high"
    assert by_id["T1003"]["vector_type"] == "credential_stuffing"
    # platform passthrough
    assert "Windows" in by_id["T1003"]["source_platforms"]
    # real-source attribution everywhere
    for v in res["vectors"]:
        assert v["source"] == "mitre-attack"


def test_mitre_fallback_severity_filter_applies(engine, tmp_path):
    mitre_db = tmp_path / "mitre_filt.db"
    _build_mitre_db(mitre_db, [
        {"technique_id": "T1486", "name": "Data Encrypted for Impact",
         "tactic_ids": ["impact"]},
        {"technique_id": "T1059", "name": "Command and Scripting Interpreter",
         "tactic_ids": ["execution"]},
    ])
    res = engine.list_vectors_with_mitre_fallback(
        "filt-org", severity="critical", mitre_db_path=str(mitre_db)
    )
    assert res["total"] == 1
    assert res["vectors"][0]["source_technique_id"] == "T1486"


def test_org_recorded_vectors_take_precedence(engine, tmp_path):
    mitre_db = tmp_path / "mitre_pre.db"
    _build_mitre_db(mitre_db, [
        {"technique_id": "T1059", "name": "Command and Scripting Interpreter",
         "tactic_ids": ["execution"]},
    ])
    engine.record_vector(
        "tier-org",
        {"name": "Custom Phishing Vector", "vector_type": "email", "severity": "high"},
    )
    res = engine.list_vectors_with_mitre_fallback("tier-org", mitre_db_path=str(mitre_db))
    assert res["source"] == "org_recorded"
    assert res["total"] == 1
    assert res["vectors"][0]["name"] == "Custom Phishing Vector"
