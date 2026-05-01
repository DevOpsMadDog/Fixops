"""Test that GET /api/v1/compliance-mapping/controls?framework=mitre_d3fend
surfaces the real MITRE D3FEND ontology when the org has none registered.

Verifies the empty-endpoint fix (Backlog 8 / type-b last remaining):
when the org has zero D3FEND controls, the listing falls back to the
imported MITRE D3FEND catalogue (real public-source JSON-LD parsed by
feeds.d3fend.importer, no mocks). Each test materialises a tiny D3FEND
side-DB with real-shaped rows and points the engine at it.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from core.compliance_mapping_engine import ComplianceMappingEngine


_TABLE = "d3fend_techniques"


def _build_d3fend_db(
    path: Path,
    techniques: list[tuple[str, str, str, str | None, str, list[str]]],
) -> None:
    """Materialise a D3FEND-shaped SQLite snapshot.

    techniques = [
        (control_id, control_name, description, parent_id, top_category,
         attack_techniques), ...
    ]
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as c:
        c.execute(
            f"""
            CREATE TABLE IF NOT EXISTS {_TABLE} (
                control_id        TEXT PRIMARY KEY,
                control_name      TEXT NOT NULL,
                description       TEXT NOT NULL DEFAULT '',
                parent_id         TEXT,
                top_category      TEXT NOT NULL,
                attack_techniques TEXT NOT NULL DEFAULT '[]',
                ref_links         TEXT NOT NULL DEFAULT '[]',
                source_iri        TEXT NOT NULL DEFAULT '',
                imported_at       TEXT NOT NULL
            )
            """
        )
        for cid, name, desc, parent, top, atks in techniques:
            c.execute(
                f"""INSERT OR REPLACE INTO {_TABLE}
                    (control_id, control_name, description, parent_id,
                     top_category, attack_techniques, ref_links,
                     source_iri, imported_at)
                    VALUES (?,?,?,?,?,?,'[]',?, '2024-01-01T00:00:00Z')""",
                (
                    cid, name, desc, parent, top, json.dumps(atks),
                    f"https://d3fend.mitre.org/ontologies/d3fend.owl#{cid}",
                ),
            )
        c.commit()


@pytest.fixture
def engine(tmp_path):
    db_path = tmp_path / "compliance_mapping.db"
    return ComplianceMappingEngine(db_path=str(db_path))


@pytest.fixture
def d3fend_db(tmp_path):
    """A real-shaped D3FEND side-DB with the canonical six top categories
    plus two leaf techniques mapped to ATT&CK."""
    p = tmp_path / "d3fend.db"
    _build_d3fend_db(p, [
        ("D3-HARDEN", "Harden",
         "Reduce the attack surface of a system",
         None, "D3-HARDEN", []),
        ("D3-DETECT", "Detect",
         "Identify adversary access to or unauthorized activity on networks",
         None, "D3-DETECT", []),
        ("D3-ISOLATE", "Isolate",
         "Create logical or physical barriers in a system",
         None, "D3-ISOLATE", []),
        ("D3-DECEIVE", "Deceive",
         "Advertise, entice, allow adversaries to engage in deceptive operations",
         None, "D3-DECEIVE", []),
        ("D3-EVICT", "Evict",
         "Remove an adversary from a network",
         None, "D3-EVICT", []),
        ("D3-RESTORE", "Restore",
         "Return the system to a known-good state after compromise",
         None, "D3-RESTORE", []),
        # Leaf techniques mapped to real ATT&CK technique IDs:
        ("D3-PFV", "Platform Filesystem Verification",
         "Cryptographically verifies that platform files have not been tampered with",
         "D3-HARDEN", "D3-HARDEN", ["T1027", "T1059.001"]),
        ("D3-IRA", "Identifier Reputation Analysis",
         "Analyzing the reputation of an identifier",
         "D3-DETECT", "D3-DETECT", ["T1071.004"]),
    ])
    return p


def test_empty_org_with_no_d3fend_db_returns_org_rows_only(engine, tmp_path):
    """When neither org-controls nor D3FEND side-DB exist -> empty list,
    no error, no fallback projection."""
    res = engine.list_controls_with_d3fend_fallback(
        "fresh-org-no-d3fend",
        framework="mitre_d3fend",
        d3fend_db_path=str(tmp_path / "no_such.db"),
    )
    assert res == []


def test_empty_org_falls_back_to_d3fend_techniques(engine, d3fend_db):
    """Empty org + populated D3FEND side-DB -> derived ontology rows are
    projected. Real-shaped, with provenance fields and ATT&CK mappings."""
    res = engine.list_controls_with_d3fend_fallback(
        "fresh-org-with-d3fend",
        framework="mitre_d3fend",
        d3fend_db_path=str(d3fend_db),
    )
    # 6 top categories + 2 leaf techniques = 8 derived rows
    assert len(res) == 8
    cids = {r["control_id"] for r in res}
    assert "D3-HARDEN" in cids
    assert "D3-PFV" in cids
    assert "D3-IRA" in cids

    # Each derived row carries provenance + correct shape.
    by_cid = {r["control_id"]: r for r in res}
    pfv = by_cid["D3-PFV"]
    assert pfv["framework"] == "mitre_d3fend"
    assert pfv["control_status"] == "not_implemented"
    assert pfv["source"] == "mitre-d3fend"
    assert pfv["source_iri"].startswith("https://d3fend.mitre.org/")
    assert pfv["top_category"] == "D3-HARDEN"
    assert pfv["parent_id"] == "D3-HARDEN"
    assert pfv["attack_techniques"] == ["T1027", "T1059.001"]
    assert pfv["evidence_count"] == 0


def test_org_registered_d3fend_takes_precedence_over_fallback(engine, d3fend_db):
    """When the org has registered its own D3FEND control, the fallback is
    bypassed entirely (no duplication, no derived rows appended)."""
    engine.add_control("tiered-org", {
        "control_id": "MY-D3-CUSTOM",
        "framework": "mitre_d3fend",
        "control_name": "Custom hardening playbook",
        "description": "Internal hardening procedure",
        "control_status": "implemented",
    })
    res = engine.list_controls_with_d3fend_fallback(
        "tiered-org",
        framework="mitre_d3fend",
        d3fend_db_path=str(d3fend_db),
    )
    # Only the org's single control is returned — no D3FEND derivation
    assert len(res) == 1
    assert res[0]["control_id"] == "MY-D3-CUSTOM"
    assert res[0]["control_status"] == "implemented"
    # No provenance from the side-DB
    assert "source" not in res[0] or res[0].get("source") != "mitre-d3fend"


def test_non_d3fend_framework_filter_bypasses_fallback(engine, d3fend_db):
    """When the caller filters for a different framework, the D3FEND
    fallback is skipped — derived rows would falsely satisfy the filter."""
    res = engine.list_controls_with_d3fend_fallback(
        "fresh-org-other-fw",
        framework="nist_csf_2_0",
        d3fend_db_path=str(d3fend_db),
    )
    assert res == []  # org has no NIST controls and D3FEND-derived rows excluded


def test_no_framework_filter_returns_org_plus_d3fend(engine, d3fend_db):
    """No framework filter + empty org -> D3FEND derivation appended after
    any (zero) org rows. Org rows for OTHER frameworks are preserved."""
    engine.add_control("mixed-org", {
        "control_id": "AC-2",
        "framework": "nist_800_53",
        "control_name": "Account Management",
        "control_status": "partial",
    })
    res = engine.list_controls_with_d3fend_fallback(
        "mixed-org",
        d3fend_db_path=str(d3fend_db),
    )
    # 1 NIST org-row + 8 derived D3FEND rows
    assert len(res) == 9
    # NIST row preserved + first
    nist_rows = [r for r in res if r.get("framework") == "nist_800_53"]
    assert len(nist_rows) == 1
    assert nist_rows[0]["control_id"] == "AC-2"
    # D3FEND derived rows present and badged with provenance
    d3_rows = [r for r in res if r.get("framework") == "mitre_d3fend"]
    assert len(d3_rows) == 8
    assert all(r.get("source") == "mitre-d3fend" for r in d3_rows)


def test_status_filter_non_default_bypasses_fallback(engine, d3fend_db):
    """Caller asking for `control_status=implemented` on D3FEND would
    be misled by derived rows (always not_implemented) — fallback is
    skipped."""
    res = engine.list_controls_with_d3fend_fallback(
        "fresh-org-impl",
        framework="mitre_d3fend",
        control_status="implemented",
        d3fend_db_path=str(d3fend_db),
    )
    assert res == []
