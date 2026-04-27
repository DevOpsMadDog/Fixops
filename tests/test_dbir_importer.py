"""Tests for DBIR / VCDB incident importer.

Tests:
1. Parse a 5-incident fixture set
2. Action-pattern extraction (malware/hacking/error/social/misuse/physical/environmental)
3. Actor classification (external/internal/partner)
4. List endpoint returns incidents after import
5. Filter by action_pattern=hacking
6. Idempotent re-import (same incident_ids = same total, no duplicates)
"""

from __future__ import annotations

import io
import json
import os
import sys
import tarfile
import types
from typing import Any, Dict, List

import pytest

# ---------------------------------------------------------------------------
# Ensure suite-feeds is importable
# ---------------------------------------------------------------------------

_SUITE_FEEDS = os.path.join(os.path.dirname(__file__), "..", "suite-feeds")
if _SUITE_FEEDS not in sys.path:
    sys.path.insert(0, _SUITE_FEEDS)


# ---------------------------------------------------------------------------
# Fixtures: 5 representative VERIS incidents
# ---------------------------------------------------------------------------

_INCIDENTS: List[Dict[str, Any]] = [
    {
        "incident_id": "11111111-1111-1111-1111-111111111111",
        "summary": "Web app SQL injection led to credential theft.",
        "action": {
            "hacking": {
                "variety": ["SQLi"],
                "vector": ["Web application"],
            }
        },
        "actor": {
            "external": {
                "motive": ["Financial"],
                "variety": ["Organized crime"],
            }
        },
        "asset": {"assets": [{"variety": "S - Web application"}]},
        "attribute": {"confidentiality": {"data_disclosure": "Yes"}},
        "discovery_method": {"external": {"variety": ["Notification by law enforcement"]}},
        "victim": {
            "industry": "522110",
            "employee_count": "1001 to 10000",
            "country": ["US"],
        },
        "timeline": {"incident": {"year": 2024, "month": 5}},
    },
    {
        "incident_id": "22222222-2222-2222-2222-222222222222",
        "summary": "Ransomware deployed via phishing.",
        "action": {
            "malware": {"variety": ["Ransomware"]},
            "social": {"variety": ["Phishing"]},
        },
        "actor": {"external": {"variety": ["Organized crime"]}},
        "asset": {"assets": [{"variety": "S - File server"}]},
        "attribute": {"availability": {"variety": ["Loss"]}},
        "discovery_method": {"internal": {"variety": ["Reported by employee"]}},
        "victim": {
            "industry": "621111",
            "employee_count": "101 to 1000",
            "country": ["US"],
        },
        "timeline": {"incident": {"year": 2024, "month": 7}},
    },
    {
        "incident_id": "33333333-3333-3333-3333-333333333333",
        "summary": "Misconfigured S3 bucket exposed PII.",
        "action": {"error": {"variety": ["Misconfiguration"]}},
        "actor": {"internal": {"variety": ["End-user"]}},
        "asset": {"assets": [{"variety": "S - Database"}]},
        "attribute": {"confidentiality": {"data_disclosure": "Potentially"}},
        "discovery_method": {"external": {"variety": ["Researcher"]}},
        "victim": {
            "industry": "511130",
            "employee_count": "11 to 100",
            "country": ["US"],
        },
        "timeline": {"incident": {"year": 2023, "month": 11}},
    },
    {
        "incident_id": "44444444-4444-4444-4444-444444444444",
        "summary": "Disgruntled contractor abused privileged access.",
        "action": {"misuse": {"variety": ["Privilege abuse"]}},
        "actor": {"partner": {"variety": ["Contractor"]}},
        "asset": {"assets": [{"variety": "S - Mainframe"}]},
        "attribute": {"integrity": {"variety": ["Alter behavior"]}},
        "discovery_method": {"internal": {"variety": ["Audit"]}},
        "victim": {
            "industry": 921110,
            "employee_count": "10001 to 25000",
            "country": ["GB"],
        },
        "timeline": {"incident": {"year": 2023, "month": 3}},
    },
    {
        "incident_id": "55555555-5555-5555-5555-555555555555",
        "summary": "Stolen laptop containing patient records.",
        "action": {"physical": {"variety": ["Theft"]}},
        "actor": {"external": {"variety": ["Unaffiliated"]}},
        "asset": {"assets": [{"variety": "U - Laptop"}]},
        "attribute": {"confidentiality": {"data_disclosure": "Unknown"}},
        "discovery_method": {"internal": {"variety": ["Reported by employee"]}},
        "victim": {
            "industry": ["622110"],
            "employee_count": "1 to 10",
            "country": "US",
        },
        "timeline": {"incident": {"year": 2024, "month": 1}},
    },
]


def _build_tar_bytes(
    incidents: List[Dict[str, Any]],
    prefix: str = "VCDB-master",
) -> bytes:
    """Build an in-memory tar.gz containing data/json/validated/<id>.json files."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for inc in incidents:
            content = json.dumps(inc).encode("utf-8")
            name = f"{prefix}/data/json/validated/{inc['incident_id']}.json"
            info = tarfile.TarInfo(name=name)
            info.size = len(content)
            tf.addfile(info, io.BytesIO(content))

        # Include a non-validated file that should be skipped
        noise = json.dumps({"incident_id": "ignore-me"}).encode("utf-8")
        info = tarfile.TarInfo(name=f"{prefix}/data/json/raw/should-skip.json")
        info.size = len(noise)
        tf.addfile(info, io.BytesIO(noise))
    buf.seek(0)
    return buf.read()


# ---------------------------------------------------------------------------
# Patch the store with an in-memory dict so tests don't touch disk
# ---------------------------------------------------------------------------

class _InMemoryStore(dict):
    def persist(self, key):  # noqa: D401
        pass


@pytest.fixture(autouse=True)
def _mock_store(monkeypatch):
    from feeds.dbir import importer as imp
    store = _InMemoryStore()
    monkeypatch.setattr(imp, "_store", store)
    yield store
    monkeypatch.setattr(imp, "_store", None)


# ---------------------------------------------------------------------------
# Test 1: Parse a 5-incident fixture set
# ---------------------------------------------------------------------------

def test_parse_five_incidents():
    from feeds.dbir.importer import import_incidents_from_archive

    tar_bytes = _build_tar_bytes(_INCIDENTS)
    result = import_incidents_from_archive(tar_bytes)

    assert result["incidents"] == 5, f"Expected 5 incidents, got {result['incidents']}"
    assert "by_action_pattern" in result
    assert "by_actor" in result
    assert "by_industry_naics" in result


# ---------------------------------------------------------------------------
# Test 2: Action-pattern extraction
# ---------------------------------------------------------------------------

def test_action_pattern_extraction():
    from feeds.dbir.importer import parse_incident

    # Incident 0 — hacking
    p0 = parse_incident(_INCIDENTS[0])
    assert p0 is not None
    assert "hacking" in p0["action_patterns"]
    assert p0["primary_action_pattern"] == "hacking"

    # Incident 1 — malware + social (multiple patterns)
    p1 = parse_incident(_INCIDENTS[1])
    assert p1 is not None
    assert set(p1["action_patterns"]) == {"malware", "social"}

    # Incident 2 — error
    p2 = parse_incident(_INCIDENTS[2])
    assert p2 is not None
    assert p2["primary_action_pattern"] == "error"

    # Incident 3 — misuse, Incident 4 — physical
    p3 = parse_incident(_INCIDENTS[3])
    p4 = parse_incident(_INCIDENTS[4])
    assert p3 is not None and p3["primary_action_pattern"] == "misuse"
    assert p4 is not None and p4["primary_action_pattern"] == "physical"


# ---------------------------------------------------------------------------
# Test 3: Actor classification (external/internal/partner)
# ---------------------------------------------------------------------------

def test_actor_classification():
    from feeds.dbir.importer import parse_incident

    p0 = parse_incident(_INCIDENTS[0])
    p2 = parse_incident(_INCIDENTS[2])
    p3 = parse_incident(_INCIDENTS[3])

    assert p0 is not None and "external" in p0["actors"]
    assert p2 is not None and "internal" in p2["actors"]
    assert p3 is not None and "partner" in p3["actors"]


# ---------------------------------------------------------------------------
# Test 4: List endpoint returns incidents after import
# ---------------------------------------------------------------------------

def test_list_after_import():
    from feeds.dbir.importer import import_incidents_from_archive, list_incidents

    tar_bytes = _build_tar_bytes(_INCIDENTS)
    import_incidents_from_archive(tar_bytes)

    incidents = list_incidents()
    assert len(incidents) == 5
    ids = {i["incident_id"] for i in incidents}
    for inc in _INCIDENTS:
        assert inc["incident_id"] in ids


# ---------------------------------------------------------------------------
# Test 5: Filter by action_pattern=hacking
# ---------------------------------------------------------------------------

def test_filter_by_action_pattern_hacking():
    from feeds.dbir.importer import import_incidents_from_archive, list_incidents

    tar_bytes = _build_tar_bytes(_INCIDENTS)
    import_incidents_from_archive(tar_bytes)

    hacking = list_incidents(action_pattern="hacking")
    assert len(hacking) == 1
    assert hacking[0]["incident_id"] == "11111111-1111-1111-1111-111111111111"
    assert "hacking" in hacking[0]["action_patterns"]

    # Filter by social — should hit incident 1 (combo)
    social = list_incidents(action_pattern="social")
    assert len(social) == 1
    assert social[0]["incident_id"] == "22222222-2222-2222-2222-222222222222"


# ---------------------------------------------------------------------------
# Test 6: Idempotent re-import
# ---------------------------------------------------------------------------

def test_idempotent_reimport():
    from feeds.dbir.importer import import_incidents_from_archive, list_incidents

    tar_bytes = _build_tar_bytes(_INCIDENTS)
    r1 = import_incidents_from_archive(tar_bytes)
    r2 = import_incidents_from_archive(tar_bytes)

    assert r1["incidents"] == 5
    assert r2["incidents"] == 5

    incidents = list_incidents()
    assert len(incidents) == 5  # no duplicates
