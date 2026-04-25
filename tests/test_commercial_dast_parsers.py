"""Tests for commercial DAST format parsers (Veracode DAST + Invicti + Acunetix).

Covers:
  - Severity normalization (vendor-specific → ALDECI canonical)
  - Single-record parsers (parse_veracode_flaw / _invicti_ / _acunetix_)
  - Embedded-sample fallback ingestion (air-gap mode)
  - Live-dump ingestion with custom payloads
  - Error handling (malformed, missing fields, wrong types)
  - Mirror to SecurityFindingsEngine with correct source_tool tags
  - Dedup behaviour via correlation_key
"""
from __future__ import annotations

import os
import tempfile

import pytest


@pytest.fixture
def isolated_engine(monkeypatch):
    """Provide a SecurityFindingsEngine pointed at a fresh temp DB.

    We swap the singleton cached inside ``commercial_dast_parsers`` for a
    fresh instance per test so dedup / lifecycle counts stay deterministic.
    """
    from core.security_findings_engine import SecurityFindingsEngine
    from connectors import commercial_dast_parsers as cdp

    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    engine = SecurityFindingsEngine(db_path=tmp.name)
    cdp.set_engine_for_tests(engine)
    yield engine
    cdp.reset_engine_singleton_for_tests()
    try:
        os.unlink(tmp.name)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Severity normalization
# ---------------------------------------------------------------------------

def test_veracode_severity_int_to_canonical():
    from connectors.commercial_dast_parsers import _normalize_veracode_severity
    assert _normalize_veracode_severity(5) == "critical"
    assert _normalize_veracode_severity(4) == "high"
    assert _normalize_veracode_severity(3) == "medium"
    assert _normalize_veracode_severity(2) == "low"
    assert _normalize_veracode_severity(1) == "informational"
    assert _normalize_veracode_severity(0) == "informational"


def test_veracode_severity_string_int():
    from connectors.commercial_dast_parsers import _normalize_veracode_severity
    assert _normalize_veracode_severity("5") == "critical"
    assert _normalize_veracode_severity("garbage") == "informational"
    assert _normalize_veracode_severity(None) == "medium"


def test_invicti_severity_canonical():
    from connectors.commercial_dast_parsers import _normalize_invicti_severity
    assert _normalize_invicti_severity("Critical") == "critical"
    assert _normalize_invicti_severity("HIGH") == "high"
    assert _normalize_invicti_severity("Important") == "high"
    assert _normalize_invicti_severity("Medium") == "medium"
    assert _normalize_invicti_severity("Low") == "low"
    assert _normalize_invicti_severity("Best Practice") == "informational"
    assert _normalize_invicti_severity("nonsense") == "medium"
    assert _normalize_invicti_severity(None) == "medium"


def test_acunetix_severity_canonical():
    from connectors.commercial_dast_parsers import _normalize_acunetix_severity
    assert _normalize_acunetix_severity("high") == "high"
    assert _normalize_acunetix_severity("MEDIUM") == "medium"
    assert _normalize_acunetix_severity(3) == "high"
    assert _normalize_acunetix_severity(2) == "medium"
    assert _normalize_acunetix_severity(1) == "low"
    assert _normalize_acunetix_severity(0) == "informational"
    assert _normalize_acunetix_severity("info") == "informational"
    assert _normalize_acunetix_severity(None) == "medium"


# ---------------------------------------------------------------------------
# Embedded sample shape
# ---------------------------------------------------------------------------

def test_embedded_samples_have_at_least_5_records():
    from connectors.commercial_dast_parsers import (
        VERACODE_DAST_SAMPLE, INVICTI_SAMPLE, ACUNETIX_SAMPLE,
    )
    assert len(VERACODE_DAST_SAMPLE["_embed"]["flaws"]) >= 5
    assert len(INVICTI_SAMPLE["Vulnerabilities"]) >= 5
    assert len(ACUNETIX_SAMPLE["vulnerabilities"]) >= 5


def test_embedded_samples_have_required_fields():
    from connectors.commercial_dast_parsers import (
        VERACODE_DAST_SAMPLE, INVICTI_SAMPLE, ACUNETIX_SAMPLE,
    )
    for f in VERACODE_DAST_SAMPLE["_embed"]["flaws"]:
        assert {"issue_id", "severity", "category_name", "url", "source_file"}.issubset(f)
    for v in INVICTI_SAMPLE["Vulnerabilities"]:
        assert {"Severity", "Type", "Url", "Poc", "RawRequest", "RawResponse"}.issubset(v)
    for v in ACUNETIX_SAMPLE["vulnerabilities"]:
        assert {"severity", "name", "location", "parameter", "request"}.issubset(v)


# ---------------------------------------------------------------------------
# Single-record parsers
# ---------------------------------------------------------------------------

def test_parse_veracode_flaw_basic():
    from connectors.commercial_dast_parsers import parse_veracode_flaw, VERACODE_DAST_SAMPLE
    raw = VERACODE_DAST_SAMPLE["_embed"]["flaws"][0]
    out = parse_veracode_flaw(raw)
    assert out["severity"] == "critical"
    assert out["category"] == "SQL Injection"
    assert out["asset_id"].startswith("https://")
    assert "veracode-dast" in out["correlation_key"]
    assert out["cvss_score"] >= 9.0


def test_parse_veracode_flaw_rejects_non_dict():
    from connectors.commercial_dast_parsers import parse_veracode_flaw
    with pytest.raises(ValueError):
        parse_veracode_flaw("not-a-dict")  # type: ignore[arg-type]


def test_parse_invicti_vulnerability_basic():
    from connectors.commercial_dast_parsers import parse_invicti_vulnerability, INVICTI_SAMPLE
    raw = INVICTI_SAMPLE["Vulnerabilities"][0]
    out = parse_invicti_vulnerability(raw)
    assert out["severity"] == "critical"
    assert "SqlInjection" in out["title"]
    assert out["parameter"] == "id"
    assert out["raw_request"].startswith("GET")
    assert "invicti" in out["correlation_key"]


def test_parse_invicti_handles_lowercase_keys():
    from connectors.commercial_dast_parsers import parse_invicti_vulnerability
    raw = {
        "id": "x",
        "severity": "high",
        "type": "XSS",
        "url": "https://t.example/p",
        "parameter": "q",
        "method": "GET",
        "poc": "<script>",
        "rawRequest": "GET /p?q=<script> HTTP/1.1",
        "rawResponse": "HTTP/1.1 200",
        "description": "x",
        "remediation": "encode",
        "cwe": "79",
    }
    out = parse_invicti_vulnerability(raw)
    assert out["severity"] == "high"
    assert out["vuln_type"] == "XSS"
    assert out["cwe"] == "79"


def test_parse_acunetix_vulnerability_basic():
    from connectors.commercial_dast_parsers import parse_acunetix_vulnerability, ACUNETIX_SAMPLE
    raw = ACUNETIX_SAMPLE["vulnerabilities"][0]
    out = parse_acunetix_vulnerability(raw)
    assert out["severity"] == "high"
    assert "SQL Injection" in out["title"]
    assert out["parameter"] == "session"
    assert out["cvss_score"] == pytest.approx(9.1)
    assert "acunetix" in out["correlation_key"]


def test_parse_acunetix_handles_int_severity():
    from connectors.commercial_dast_parsers import parse_acunetix_vulnerability
    raw = {
        "vuln_id": "z", "severity": 3, "name": "X", "location": "/",
        "parameter": "p", "request": "GET / HTTP/1.1", "details": "d",
        "cwe_list": ["CWE-79"], "cvss3": {"base_score": 7.7},
    }
    out = parse_acunetix_vulnerability(raw)
    assert out["severity"] == "high"
    assert out["cvss_score"] == pytest.approx(7.7)


def test_parse_acunetix_handles_garbage_cvss():
    from connectors.commercial_dast_parsers import parse_acunetix_vulnerability
    raw = {
        "vuln_id": "g", "severity": "medium", "name": "X", "location": "/",
        "parameter": "", "request": "", "details": "", "cwe_list": [],
        "cvss3": {"base_score": "garbage"},
    }
    out = parse_acunetix_vulnerability(raw)
    assert out["cvss_score"] == 5.0


# ---------------------------------------------------------------------------
# Iterators tolerate variant shapes
# ---------------------------------------------------------------------------

def test_iterators_handle_list_input():
    from connectors.commercial_dast_parsers import (
        _iter_veracode_flaws, _iter_invicti_vulns, _iter_acunetix_vulns,
    )
    assert list(_iter_veracode_flaws([{"issue_id": 1}, "skip-me"])) == [{"issue_id": 1}]
    assert list(_iter_invicti_vulns([{"Id": "x"}])) == [{"Id": "x"}]
    assert list(_iter_acunetix_vulns([{"vuln_id": "y"}])) == [{"vuln_id": "y"}]


def test_iterators_handle_none_and_garbage():
    from connectors.commercial_dast_parsers import (
        _iter_veracode_flaws, _iter_invicti_vulns, _iter_acunetix_vulns,
    )
    assert list(_iter_veracode_flaws(None)) == []
    assert list(_iter_invicti_vulns(None)) == []
    assert list(_iter_acunetix_vulns(None)) == []
    assert list(_iter_veracode_flaws("garbage")) == []  # type: ignore[arg-type]
    assert list(_iter_invicti_vulns(123)) == []  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Ingestion — fallback mode (air-gap)
# ---------------------------------------------------------------------------

def test_ingest_veracode_fallback_when_empty(isolated_engine):
    from connectors.commercial_dast_parsers import ingest_veracode_dast_dump
    result = ingest_veracode_dast_dump(dump=None, org_id="acme")
    assert result.used_fallback is True
    assert result.records_seen >= 5
    assert result.records_ingested == result.records_seen
    assert result.errors == []
    findings = isolated_engine.list_findings(org_id="acme", source_tool="dast_via_veracode")
    assert len(findings) >= 5


def test_ingest_invicti_fallback_when_empty(isolated_engine):
    from connectors.commercial_dast_parsers import ingest_invicti_dump
    result = ingest_invicti_dump(dump=None, org_id="acme")
    assert result.used_fallback is True
    assert result.records_seen >= 5
    assert result.records_ingested == result.records_seen
    findings = isolated_engine.list_findings(org_id="acme", source_tool="dast_via_invicti")
    assert len(findings) >= 5
    assert all(f["source_tool"] == "dast_via_invicti" for f in findings)


def test_ingest_acunetix_fallback_when_empty(isolated_engine):
    from connectors.commercial_dast_parsers import ingest_acunetix_dump
    result = ingest_acunetix_dump(dump=None, org_id="acme")
    assert result.used_fallback is True
    assert result.records_seen >= 5
    findings = isolated_engine.list_findings(org_id="acme", source_tool="dast_via_acunetix")
    assert len(findings) >= 5


def test_ingest_use_fallback_disabled_returns_zero(isolated_engine):
    from connectors.commercial_dast_parsers import (
        ingest_veracode_dast_dump, ingest_invicti_dump, ingest_acunetix_dump,
    )
    for fn in (ingest_veracode_dast_dump, ingest_invicti_dump, ingest_acunetix_dump):
        r = fn(dump=None, org_id="x", use_fallback_if_empty=False)
        assert r.records_seen == 0
        assert r.records_ingested == 0
        assert r.used_fallback is False


# ---------------------------------------------------------------------------
# Ingestion — custom dumps
# ---------------------------------------------------------------------------

def test_ingest_veracode_with_custom_dump(isolated_engine):
    from connectors.commercial_dast_parsers import ingest_veracode_dast_dump
    custom = {"_embed": {"flaws": [
        {"issue_id": 1, "severity": 5, "category_name": "Custom SQLi",
         "url": "https://x/y", "source_file": "/x.py", "line": 1,
         "description": "d", "remediation": "r", "cwe_id": "89"},
    ]}}
    r = ingest_veracode_dast_dump(dump=custom, org_id="acme")
    assert r.records_seen == 1
    assert r.records_ingested == 1
    assert r.used_fallback is False
    findings = isolated_engine.list_findings(org_id="acme")
    assert any("Custom SQLi" in f["title"] for f in findings)


def test_ingest_invicti_with_custom_dump_attaches_evidence(isolated_engine):
    from connectors.commercial_dast_parsers import ingest_invicti_dump
    custom = {"Vulnerabilities": [
        {"Id": "C-1", "Severity": "Critical", "Type": "SQLi",
         "Url": "https://x", "Parameter": "p", "Method": "GET",
         "Poc": "p=' OR 1=1--", "RawRequest": "GET / HTTP/1.1",
         "RawResponse": "HTTP/1.1 200", "Description": "d",
         "RemedialActions": "r", "Cwe": "89"},
    ]}
    r = ingest_invicti_dump(dump=custom, org_id="acme")
    assert r.records_ingested == 1
    found = isolated_engine.get_finding(r.findings[0]["id"], "acme")
    assert found is not None
    # Evidence should include PoC entry
    assert any("PoC" in (e["content"] or "") for e in found.get("evidence", []))


def test_ingest_acunetix_with_custom_dump_attaches_evidence(isolated_engine):
    from connectors.commercial_dast_parsers import ingest_acunetix_dump
    custom = {"vulnerabilities": [
        {"vuln_id": "A-1", "severity": "high", "name": "SQLi",
         "location": "/p", "affects_url": "https://x/p",
         "parameter": "q", "request": "GET /p?q=' HTTP/1.1",
         "details": "d", "cwe_list": ["CWE-89"],
         "cvss3": {"base_score": 9.1}},
    ]}
    r = ingest_acunetix_dump(dump=custom, org_id="acme")
    assert r.records_ingested == 1
    found = isolated_engine.get_finding(r.findings[0]["id"], "acme")
    assert any(e["evidence_type"] == "network-capture" for e in found.get("evidence", []))


# ---------------------------------------------------------------------------
# Source-tool tagging
# ---------------------------------------------------------------------------

def test_source_tool_tags_are_distinct(isolated_engine):
    from connectors.commercial_dast_parsers import (
        ingest_veracode_dast_dump, ingest_invicti_dump, ingest_acunetix_dump,
    )
    ingest_veracode_dast_dump(dump=None, org_id="acme")
    ingest_invicti_dump(dump=None, org_id="acme")
    ingest_acunetix_dump(dump=None, org_id="acme")
    summary = isolated_engine.get_findings_summary("acme")
    by_tool = summary["by_source_tool"]
    assert by_tool.get("dast_via_veracode", 0) >= 5
    assert by_tool.get("dast_via_invicti", 0) >= 5
    assert by_tool.get("dast_via_acunetix", 0) >= 5


# ---------------------------------------------------------------------------
# Dedup via correlation_key
# ---------------------------------------------------------------------------

def test_dedup_repeat_ingest_increments_occurrence(isolated_engine):
    from connectors.commercial_dast_parsers import ingest_veracode_dast_dump
    r1 = ingest_veracode_dast_dump(dump=None, org_id="acme")
    r2 = ingest_veracode_dast_dump(dump=None, org_id="acme")
    assert r1.records_ingested == r2.records_ingested
    findings = isolated_engine.list_findings(org_id="acme", source_tool="dast_via_veracode")
    # Same number of unique rows (dedup'd) but occurrence_count >= 2 on each
    assert all(f["occurrence_count"] >= 2 for f in findings)


def test_dedup_invicti(isolated_engine):
    from connectors.commercial_dast_parsers import ingest_invicti_dump
    ingest_invicti_dump(dump=None, org_id="acme")
    ingest_invicti_dump(dump=None, org_id="acme")
    findings = isolated_engine.list_findings(org_id="acme", source_tool="dast_via_invicti")
    assert all(f["occurrence_count"] >= 2 for f in findings)


def test_dedup_acunetix(isolated_engine):
    from connectors.commercial_dast_parsers import ingest_acunetix_dump
    ingest_acunetix_dump(dump=None, org_id="acme")
    ingest_acunetix_dump(dump=None, org_id="acme")
    findings = isolated_engine.list_findings(org_id="acme", source_tool="dast_via_acunetix")
    assert all(f["occurrence_count"] >= 2 for f in findings)


# ---------------------------------------------------------------------------
# Org isolation
# ---------------------------------------------------------------------------

def test_org_isolation(isolated_engine):
    from connectors.commercial_dast_parsers import ingest_veracode_dast_dump
    ingest_veracode_dast_dump(dump=None, org_id="acme")
    ingest_veracode_dast_dump(dump=None, org_id="globex")
    acme = isolated_engine.list_findings(org_id="acme")
    globex = isolated_engine.list_findings(org_id="globex")
    assert len(acme) >= 5
    assert len(globex) >= 5
    acme_ids = {f["id"] for f in acme}
    globex_ids = {f["id"] for f in globex}
    assert acme_ids.isdisjoint(globex_ids)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def test_ingest_rejects_blank_org_id(isolated_engine):
    from connectors.commercial_dast_parsers import (
        ingest_veracode_dast_dump, ingest_invicti_dump, ingest_acunetix_dump,
    )
    for fn in (ingest_veracode_dast_dump, ingest_invicti_dump, ingest_acunetix_dump):
        with pytest.raises(ValueError):
            fn(dump=None, org_id="")
        with pytest.raises(ValueError):
            fn(dump=None, org_id="   ")


def test_ingest_skips_malformed_records_without_crashing(isolated_engine):
    from connectors.commercial_dast_parsers import ingest_invicti_dump
    bad = {"Vulnerabilities": [
        {"Severity": "High", "Type": "OK", "Url": "https://ok"},
        "not-a-dict",  # malformed → skipped silently by iterator
        {"Severity": "Critical", "Type": "OK2", "Url": "https://ok2"},
    ]}
    r = ingest_invicti_dump(dump=bad, org_id="acme")
    # Iterator filters non-dict values; both dicts ingest OK.
    assert r.records_seen == 2
    assert r.records_ingested == 2


# ---------------------------------------------------------------------------
# IngestionResult shape
# ---------------------------------------------------------------------------

def test_ingestion_result_to_dict():
    from connectors.commercial_dast_parsers import IngestionResult
    res = IngestionResult(vendor="veracode", source_tool="dast_via_veracode", org_id="x")
    res.records_seen = 3
    res.records_ingested = 2
    res.findings = [{"id": "1", "title": "t", "severity": "high", "asset_id": "a",
                     "source_tool": "dast_via_veracode", "occurrence_count": 1}]
    res.errors = ["e"]
    out = res.to_dict()
    assert out["vendor"] == "veracode"
    assert out["records_seen"] == 3
    assert len(out["findings"]) == 1
