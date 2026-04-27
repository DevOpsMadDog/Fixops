"""Tests for AlienVault OTX (Open Threat Exchange) pulses + indicators importer.

Tests:
1. Parse 5-pulse fixture JSON
2. Indicator-type extraction (IPv4 / domain / SHA256 / CVE)
3. ATT&CK technique cross-link extraction
4. List pulses endpoint pagination
5. Filter indicators by type=domain
6. Idempotent re-import (same payload twice = same totals, no duplicates)
"""

from __future__ import annotations

import os
import sys
from typing import Any, Dict, List

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

# ---------------------------------------------------------------------------
# Path setup — suite-feeds + suite-api must be importable
# ---------------------------------------------------------------------------

_HERE = os.path.dirname(__file__)
for rel in ("..", "../suite-feeds", "../suite-api", "../suite-core"):
    p = os.path.abspath(os.path.join(_HERE, rel))
    if p not in sys.path:
        sys.path.insert(0, p)


# ---------------------------------------------------------------------------
# Fixtures: 5 representative OTX pulses covering all indicator types of
# interest (IPv4, IPv6, domain, hostname, URL, email, file hashes, CVE).
# ---------------------------------------------------------------------------

_PULSES: List[Dict[str, Any]] = [
    {
        "id": "pulse-aaaaaaaaaaaaaaaaaaaaaaaa",
        "name": "APT29 — SolarWinds-style supply-chain operation",
        "description": "Tracking C2 infrastructure linked to APT29.",
        "author_name": "alienvault",
        "created": "2024-03-01T10:00:00",
        "modified": "2024-03-02T12:00:00",
        "references": ["https://example.org/apt29-report"],
        "tags": ["APT29", "Cozy Bear", "supply-chain"],
        "malware_families": [{"display_name": "Sunburst"}],
        "attack_ids": [
            {"id": "T1059", "display_name": "Command and Scripting Interpreter"},
            {"id": "T1071.001", "display_name": "Web Protocols"},
        ],
        "industries": ["Government", "Defense"],
        "targeted_countries": ["US"],
        "tlp": "white",
        "adversary": "APT29",
        "public": True,
        "indicators": [
            {"id": 1001, "type": "IPv4", "indicator": "203.0.113.42", "created": "2024-03-01T10:00:00"},
            {"id": 1002, "type": "domain", "indicator": "evil-c2.example", "created": "2024-03-01T10:01:00"},
            {"id": 1003, "type": "FileHash-SHA256",
             "indicator": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
             "created": "2024-03-01T10:02:00"},
            {"id": 1004, "type": "CVE", "indicator": "CVE-2020-1472", "created": "2024-03-01T10:03:00"},
        ],
    },
    {
        "id": "pulse-bbbbbbbbbbbbbbbbbbbbbbbb",
        "name": "Emotet phishing wave",
        "description": "Recent Emotet phishing infrastructure.",
        "author_name": "researcher42",
        "created": "2024-03-15T08:00:00",
        "modified": "2024-03-15T08:30:00",
        "references": [],
        "tags": ["emotet", "phishing"],
        "malware_families": [{"display_name": "Emotet"}],
        "attack_ids": [{"id": "T1566.001", "display_name": "Spearphishing Attachment"}],
        "industries": [],
        "targeted_countries": ["US", "DE"],
        "tlp": "amber",
        "public": True,
        "indicators": [
            {"id": 2001, "type": "URL", "indicator": "http://emotet-drop.example/payload.exe", "created": "2024-03-15T08:00:00"},
            {"id": 2002, "type": "domain", "indicator": "emotet-drop.example", "created": "2024-03-15T08:00:00"},
            {"id": 2003, "type": "email", "indicator": "invoice@emotet-spoof.example", "created": "2024-03-15T08:00:00"},
            {"id": 2004, "type": "FileHash-MD5", "indicator": "098f6bcd4621d373cade4e832627b4f6", "created": "2024-03-15T08:01:00"},
        ],
    },
    {
        "id": "pulse-cccccccccccccccccccccccc",
        "name": "Log4Shell exploitation IPs",
        "description": "Mass-scanning hosts probing for CVE-2021-44228.",
        "author_name": "alienvault",
        "created": "2024-02-10T00:00:00",
        "modified": "2024-02-10T00:05:00",
        "references": ["https://logging.apache.org/log4j/2.x/security.html"],
        "tags": ["log4shell", "scanning"],
        "malware_families": [],
        "attack_ids": [{"id": "T1190", "display_name": "Exploit Public-Facing Application"}],
        "indicators": [
            {"id": 3001, "type": "IPv4", "indicator": "198.51.100.7", "created": "2024-02-10T00:00:00"},
            {"id": 3002, "type": "IPv6", "indicator": "2001:db8::dead:beef", "created": "2024-02-10T00:00:00"},
            {"id": 3003, "type": "CVE", "indicator": "CVE-2021-44228", "created": "2024-02-10T00:00:00"},
        ],
    },
    {
        "id": "pulse-dddddddddddddddddddddddd",
        "name": "Ransomware payload hashes",
        "description": "SHA256s of recent ransomware variants.",
        "author_name": "vendor-xyz",
        "created": "2024-01-05T00:00:00",
        "modified": "2024-01-05T00:00:00",
        "tags": ["ransomware"],
        "malware_families": [{"display_name": "LockBit"}],
        "attack_ids": [],  # no ATT&CK link
        "indicators": [
            {"id": 4001, "type": "FileHash-SHA1", "indicator": "da39a3ee5e6b4b0d3255bfef95601890afd80709", "created": "2024-01-05T00:00:00"},
            {"id": 4002, "type": "FileHash-SHA256",
             "indicator": "deadbeef" * 8, "created": "2024-01-05T00:00:00"},
        ],
    },
    {
        "id": "pulse-eeeeeeeeeeeeeeeeeeeeeeee",
        "name": "Generic IOC bundle",
        "description": "Mixed OSINT indicators.",
        "author_name": "community",
        "created": "2024-04-01T00:00:00",
        "modified": "2024-04-01T00:00:00",
        "tags": ["osint"],
        "malware_families": [],
        "attack_ids": [{"id": "T1041", "display_name": "Exfiltration Over C2"}],
        "indicators": [
            {"id": 5001, "type": "hostname", "indicator": "host.malicious.example", "created": "2024-04-01T00:00:00"},
            {"id": 5002, "type": "domain", "indicator": "malicious.example", "created": "2024-04-01T00:00:00"},
            {"id": 5003, "type": "IPv4", "indicator": "192.0.2.99", "created": "2024-04-01T00:00:00"},
        ],
    },
]


# ---------------------------------------------------------------------------
# In-memory store substitute (no disk writes)
# ---------------------------------------------------------------------------

class _InMemoryStore(dict):
    def persist(self, key):  # noqa: D401
        pass


@pytest.fixture(autouse=True)
def _mock_stores(monkeypatch):
    """Patch both pulses + indicators stores with fresh in-memory dicts."""
    from feeds.otx import importer as imp
    pulses = _InMemoryStore()
    indicators = _InMemoryStore()
    monkeypatch.setattr(imp, "_pulses_store", pulses)
    monkeypatch.setattr(imp, "_indicators_store", indicators)
    yield (pulses, indicators)
    monkeypatch.setattr(imp, "_pulses_store", None)
    monkeypatch.setattr(imp, "_indicators_store", None)


# ---------------------------------------------------------------------------
# Test 1: Parse 5-pulse fixture JSON
# ---------------------------------------------------------------------------

def test_parse_five_pulses():
    from feeds.otx.importer import import_pulses

    result = import_pulses(_PULSES)

    assert result["pulses"] == 5, f"Expected 5 pulses, got {result}"
    # 4 + 4 + 3 + 2 + 3 = 16 indicators
    assert result["indicators"] == 16, f"Expected 16 indicators, got {result}"
    assert "by_indicator_type" in result
    assert isinstance(result["by_indicator_type"], dict)
    assert result["by_indicator_type"]  # non-empty


# ---------------------------------------------------------------------------
# Test 2: Indicator-type extraction (IPv4 / domain / SHA256 / CVE)
# ---------------------------------------------------------------------------

def test_indicator_type_extraction():
    from feeds.otx.importer import import_pulses

    result = import_pulses(_PULSES)
    by_type = result["by_indicator_type"]

    # 3 IPv4 (203.0.113.42, 198.51.100.7, 192.0.2.99)
    assert by_type.get("IPv4") == 3, f"IPv4 count wrong: {by_type}"
    # 3 domains (evil-c2.example, emotet-drop.example, malicious.example)
    assert by_type.get("domain") == 3, f"domain count wrong: {by_type}"
    # 2 SHA256 (pulse 0 + pulse 3)
    assert by_type.get("FileHash-SHA256") == 2, f"SHA256 count wrong: {by_type}"
    # 2 CVE (CVE-2020-1472, CVE-2021-44228)
    assert by_type.get("CVE") == 2, f"CVE count wrong: {by_type}"
    # IPv6 + URL + email + hostname + SHA1 + MD5 also present
    assert by_type.get("IPv6") == 1
    assert by_type.get("URL") == 1
    assert by_type.get("email") == 1
    assert by_type.get("hostname") == 1
    assert by_type.get("FileHash-SHA1") == 1
    assert by_type.get("FileHash-MD5") == 1


# ---------------------------------------------------------------------------
# Test 3: ATT&CK technique cross-link extraction
# ---------------------------------------------------------------------------

def test_attack_id_extraction():
    from feeds.otx.importer import import_pulses, list_pulses

    result = import_pulses(_PULSES)

    # 4 of the 5 pulses carry attack_ids (the ransomware-hashes pulse has [])
    assert result["with_attack_id"] == 4, f"with_attack_id wrong: {result}"

    # APT29 pulse: T1059 + T1071.001
    pulses = list_pulses(pulse_id="pulse-aaaaaaaaaaaaaaaaaaaaaaaa")
    assert len(pulses) == 1
    apt29 = pulses[0]
    assert "T1059" in apt29["attack_ids"]
    assert "T1071.001" in apt29["attack_ids"]

    # Log4Shell pulse: T1190
    pulses = list_pulses(pulse_id="pulse-cccccccccccccccccccccccc")
    assert pulses and "T1190" in pulses[0]["attack_ids"]

    # Ransomware-hashes pulse: empty attack_ids
    pulses = list_pulses(pulse_id="pulse-dddddddddddddddddddddddd")
    assert pulses and pulses[0]["attack_ids"] == []


# ---------------------------------------------------------------------------
# Test 4: List pulses endpoint pagination
# ---------------------------------------------------------------------------

def test_list_pulses_pagination(monkeypatch):
    """Drive the FastAPI endpoint and exercise limit/offset pagination."""
    from feeds.otx.importer import import_pulses
    from apps.api import otx_router

    import_pulses(_PULSES)

    # Bypass api_key_auth in the test app
    async def _no_auth():
        return None

    app = FastAPI()
    app.dependency_overrides[otx_router.api_key_auth] = _no_auth
    app.include_router(otx_router.router)
    client = TestClient(app)

    # Page 1, limit 2 → 2 pulses
    r1 = client.get("/api/v1/otx/pulses?limit=2&offset=0")
    assert r1.status_code == 200, r1.text
    body1 = r1.json()
    assert body1["total"] == 2
    assert len(body1["pulses"]) == 2

    # Page 2, limit 2 → 2 more
    r2 = client.get("/api/v1/otx/pulses?limit=2&offset=2")
    assert r2.status_code == 200
    body2 = r2.json()
    assert len(body2["pulses"]) == 2

    # Page 3, limit 2 → 1 remaining
    r3 = client.get("/api/v1/otx/pulses?limit=2&offset=4")
    assert r3.status_code == 200
    body3 = r3.json()
    assert len(body3["pulses"]) == 1

    # Across all pages, every fixture id appears exactly once
    seen_ids = (
        {p["id"] for p in body1["pulses"]}
        | {p["id"] for p in body2["pulses"]}
        | {p["id"] for p in body3["pulses"]}
    )
    expected_ids = {p["id"] for p in _PULSES}
    assert seen_ids == expected_ids


# ---------------------------------------------------------------------------
# Test 5: Filter indicators by type=domain
# ---------------------------------------------------------------------------

def test_filter_indicators_by_type_domain():
    from feeds.otx.importer import import_pulses, list_indicators

    import_pulses(_PULSES)

    domains = list_indicators(indicator_type="domain")
    assert len(domains) == 3, f"Expected 3 domain indicators, got {len(domains)}"
    values = {d["indicator"] for d in domains}
    assert values == {"evil-c2.example", "emotet-drop.example", "malicious.example"}
    for d in domains:
        assert d["type"] == "domain"

    # Filter by pulse_id narrows the set
    domains_apt = list_indicators(
        pulse_id="pulse-aaaaaaaaaaaaaaaaaaaaaaaa",
        indicator_type="domain",
    )
    assert len(domains_apt) == 1
    assert domains_apt[0]["indicator"] == "evil-c2.example"


# ---------------------------------------------------------------------------
# Test 6: Idempotent re-import
# ---------------------------------------------------------------------------

def test_idempotent_reimport():
    from feeds.otx.importer import (
        import_pulses,
        list_pulses,
        list_indicators,
        get_store_stats,
    )

    r1 = import_pulses(_PULSES)
    r2 = import_pulses(_PULSES)

    assert r1["pulses"] == 5
    assert r2["pulses"] == 5
    assert r1["indicators"] == 16
    assert r2["indicators"] == 16

    # Stores hold one entry per unique key — no duplicates
    pulses = list_pulses(limit=1000)
    indicators = list_indicators(limit=10_000)
    stats = get_store_stats()

    assert len(pulses) == 5
    assert len(indicators) == 16
    assert stats["total_pulses"] == 5
    assert stats["total_indicators"] == 16
    assert stats["with_attack_id"] == 4
