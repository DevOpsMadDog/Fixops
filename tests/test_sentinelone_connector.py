"""Tests for SentinelOne Singularity XDR connector.

Covers:
  - Severity mapping (confidence + classification + analyst verdict)
  - MITRE technique extraction
  - Single Threat / list / wrapper / raw JSON / bytes / single-dict inputs
  - Multi-tenant org_id isolation
  - SecurityFindingsEngine round-trip (record, dedup, evidence)
  - Correlation engine mirror (when wired)
  - Embedded 10-sample fallback
  - Router contract (FastAPI TestClient)
"""

from __future__ import annotations

import json
import os

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from connectors.sentinelone_connector import (
    SentinelOneConnector,
    _S1_FALLBACK_THREATS,
    _coerce_dump,
    _correlation_key,
    _extract_mitre,
    _map_severity,
    _normalize_threat,
    get_sentinelone_connector,
)
from core.security_findings_engine import SecurityFindingsEngine

try:
    from core.security_event_correlation_engine import SecurityEventCorrelationEngine
    _HAVE_CORR = True
except (ImportError, RuntimeError):  # pragma: no cover
    SecurityEventCorrelationEngine = None  # type: ignore
    _HAVE_CORR = False


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def isolated_dbs(tmp_path, monkeypatch):
    """Isolate per-domain SQLite DBs into a tmp dir."""
    monkeypatch.setenv("ALDECI_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("FIXOPS_DATA_DIR", str(tmp_path))
    yield tmp_path


@pytest.fixture
def findings(isolated_dbs, tmp_path):
    return SecurityFindingsEngine(db_path=str(tmp_path / "s1_findings.db"))


@pytest.fixture
def connector(findings):
    corr = SecurityEventCorrelationEngine() if _HAVE_CORR else None
    return SentinelOneConnector(findings_engine=findings, correlation_engine=corr)


@pytest.fixture
def fastapi_client(isolated_dbs, monkeypatch, findings):
    """Mount only the SentinelOne router and override auth + singleton."""
    # Disable auth to keep tests focused on the connector contract
    monkeypatch.setenv("FIXOPS_DISABLE_AUTH", "1")
    monkeypatch.setenv("FIXOPS_ALLOW_NO_AUTH", "1")
    # Force the singleton to use the isolated findings engine
    import connectors.sentinelone_connector as s1mod
    s1mod._singleton = SentinelOneConnector(
        findings_engine=findings,
        correlation_engine=SecurityEventCorrelationEngine() if _HAVE_CORR else None,
    )

    from apps.api.sentinelone_connector_router import router

    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------
def test_severity_explicit_critical_wins():
    info = {"severity": "Critical", "confidenceLevel": "suspicious"}
    assert _map_severity(info) == "critical"


def test_severity_explicit_low_passthrough():
    info = {"severity": "Low", "confidenceLevel": "malicious"}
    assert _map_severity(info) == "low"


def test_severity_malicious_default_high():
    info = {"confidenceLevel": "malicious", "classification": "Malware"}
    assert _map_severity(info) == "high"


def test_severity_suspicious_default_medium():
    info = {"confidenceLevel": "suspicious", "classification": "Generic.Suspicious"}
    assert _map_severity(info) == "medium"


def test_severity_ransomware_bumps_critical():
    info = {"confidenceLevel": "malicious", "classification": "Ransomware"}
    assert _map_severity(info) == "critical"


def test_severity_pua_drops_to_low():
    info = {"confidenceLevel": "malicious", "classification": "PUA"}
    assert _map_severity(info) == "low"


def test_severity_false_positive_clamps_to_low():
    info = {
        "confidenceLevel": "malicious",
        "classification": "Trojan",
        "analystVerdict": "false_positive",
    }
    assert _map_severity(info) == "low"


def test_severity_unknown_confidence_defaults_medium():
    info = {"confidenceLevel": "weird"}
    assert _map_severity(info) == "medium"


# ---------------------------------------------------------------------------
# MITRE extraction
# ---------------------------------------------------------------------------
def test_mitre_extraction_from_sample():
    raw = _S1_FALLBACK_THREATS[2]  # PowerShell sample
    techs = _extract_mitre(raw["indicators"])
    assert "T1059.001" in techs
    assert "T1027" in techs


def test_mitre_extraction_empty_indicators():
    assert _extract_mitre([]) == []


def test_mitre_extraction_dedup():
    raw = [
        {"tactics": [{"techniques": [{"name": "T1059"}]}]},
        {"tactics": [{"techniques": [{"name": "T1059"}]}]},
    ]
    assert _extract_mitre(raw) == ["T1059"]


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------
def test_normalize_first_sample_wannacry():
    norm = _normalize_threat(_S1_FALLBACK_THREATS[0])
    assert norm["severity"] == "critical"  # Ransomware bump
    assert norm["classification"] == "Ransomware"
    assert norm["asset_id"] == "DESKTOP-WIN10-01"
    assert norm["asset_type"] == "endpoint"
    assert norm["mitigation_status"] == "mitigated"
    assert norm["file_hash"].startswith("ed01ebfbc9eb")
    assert "T1486" in norm["mitre_techniques"]
    assert "WannaCry" in norm["title"]


def test_normalize_pua_sample():
    norm = _normalize_threat(_S1_FALLBACK_THREATS[7])  # AdwareToolbar
    assert norm["severity"] == "low"
    assert norm["analyst_verdict"] == "false_positive"


def test_normalize_missing_threat_info_safe():
    norm = _normalize_threat({"id": "x"})
    assert norm["severity"] == "medium"
    assert norm["asset_id"] == "unknown-endpoint"


def test_normalize_rejects_non_mapping():
    with pytest.raises(ValueError):
        _normalize_threat([])  # type: ignore[arg-type]


def test_normalize_correlation_key_stable():
    norm1 = _normalize_threat(_S1_FALLBACK_THREATS[0])
    norm2 = _normalize_threat(_S1_FALLBACK_THREATS[0])
    assert norm1["correlation_key"] == norm2["correlation_key"]
    assert norm1["correlation_key"].startswith("sentinelone|")


# ---------------------------------------------------------------------------
# Coerce dump
# ---------------------------------------------------------------------------
def test_coerce_dump_wrapper():
    out = _coerce_dump({"data": _S1_FALLBACK_THREATS, "pagination": {}})
    assert len(out) == len(_S1_FALLBACK_THREATS)


def test_coerce_dump_list():
    out = _coerce_dump(_S1_FALLBACK_THREATS[:3])
    assert len(out) == 3


def test_coerce_dump_single_threat_dict():
    out = _coerce_dump(_S1_FALLBACK_THREATS[0])
    assert len(out) == 1
    assert out[0]["id"] == _S1_FALLBACK_THREATS[0]["id"]


def test_coerce_dump_json_string():
    text = json.dumps({"data": _S1_FALLBACK_THREATS[:2]})
    out = _coerce_dump(text)
    assert len(out) == 2


def test_coerce_dump_bytes():
    text = json.dumps({"data": _S1_FALLBACK_THREATS[:1]}).encode("utf-8")
    out = _coerce_dump(text)
    assert len(out) == 1


def test_coerce_dump_invalid_json_raises():
    with pytest.raises(ValueError):
        _coerce_dump("not-json{")


def test_coerce_dump_unsupported_type_raises():
    with pytest.raises(ValueError):
        _coerce_dump(12345)  # type: ignore[arg-type]


def test_coerce_dump_dict_missing_data_raises():
    with pytest.raises(ValueError):
        _coerce_dump({"pagination": {}})


# ---------------------------------------------------------------------------
# End-to-end ingest with SecurityFindingsEngine
# ---------------------------------------------------------------------------
def test_ingest_full_fallback_records_findings(connector):
    res = connector.ingest_fallback(org_id="acme", max_events=10)
    assert res["threats_seen"] == 10
    assert res["findings_recorded"] == 10
    assert res["mode"] == "fallback"
    assert res["source_tool"] == "sentinelone"
    assert res["severity_breakdown"]["critical"] >= 1
    # 6 mitigated + 2 not_mitigated + 1 marked_as_benign + 1 mitigated → at least 2 statuses
    assert len(res["mitigation_breakdown"]) >= 2


def test_ingest_dedup_via_correlation_key(connector, findings):
    # Ingest same dump twice — second pass increments occurrence_count
    connector.ingest_fallback(org_id="acme", max_events=3)
    connector.ingest_fallback(org_id="acme", max_events=3)
    rows = findings.list_findings(org_id="acme", source_tool="sentinelone")
    assert len(rows) == 3  # dedup'd, not 6
    assert all(r["occurrence_count"] >= 2 for r in rows)


def test_ingest_multi_tenant_isolation(connector, findings):
    connector.ingest_fallback(org_id="orgA", max_events=2)
    connector.ingest_fallback(org_id="orgB", max_events=4)
    a = findings.list_findings(org_id="orgA", source_tool="sentinelone")
    b = findings.list_findings(org_id="orgB", source_tool="sentinelone")
    assert len(a) == 2
    assert len(b) == 4
    # No leakage
    a_ids = {r["id"] for r in a}
    b_ids = {r["id"] for r in b}
    assert a_ids.isdisjoint(b_ids)


def test_ingest_attaches_evidence(connector, findings):
    res = connector.ingest_fallback(org_id="acme", max_events=1)
    fid = res["recorded_finding_ids"][0]
    full = findings.get_finding(fid, org_id="acme")
    assert full is not None
    assert full["evidence"], "expected raw S1 Threat to be attached as evidence"
    assert full["evidence"][0]["evidence_type"] == "report"
    # Evidence content should round-trip as JSON
    payload = json.loads(full["evidence"][0]["content"])
    assert "threatInfo" in payload


def test_ingest_blank_org_rejected(connector):
    with pytest.raises(ValueError):
        connector.ingest_s1_dump(_S1_FALLBACK_THREATS[:1], org_id="")


def test_ingest_none_org_rejected(connector):
    with pytest.raises(ValueError):
        connector.ingest_s1_dump(_S1_FALLBACK_THREATS[:1], org_id=None)  # type: ignore[arg-type]


def test_ingest_records_severity_for_each_threat(connector):
    res = connector.ingest_fallback(org_id="acme", max_events=10)
    total = sum(res["severity_breakdown"].values())
    assert total == res["findings_recorded"]


def test_ingest_partial_invalid_input_continues(connector, findings):
    payload = [
        _S1_FALLBACK_THREATS[0],
        "this is not a threat dict",  # invalid: skipped during _coerce_dump filtering
        _S1_FALLBACK_THREATS[1],
    ]
    res = connector.ingest_s1_dump(payload, org_id="acme")
    # Coerce filters the str out, so only 2 threats are seen
    assert res["threats_seen"] == 2
    assert res["findings_recorded"] == 2


def test_ingest_returns_scan_id_when_omitted(connector):
    res = connector.ingest_fallback(org_id="acme", max_events=1)
    assert res["scan_id"]
    assert res["scan_id"].startswith("s1-scan-")


def test_ingest_respects_explicit_scan_id(connector):
    res = connector.ingest_s1_dump(
        _S1_FALLBACK_THREATS[:2], org_id="acme", scan_id="my-explicit-scan",
    )
    assert res["scan_id"] == "my-explicit-scan"


def test_ingest_raw_json_string(connector, findings):
    text = json.dumps({"data": _S1_FALLBACK_THREATS[:3]})
    res = connector.ingest_s1_dump(text, org_id="acme")
    assert res["findings_recorded"] == 3


def test_ingest_invalid_json_raises_value_error(connector):
    with pytest.raises(ValueError):
        connector.ingest_s1_dump("not json", org_id="acme")


def test_singleton_accessor_returns_same_instance():
    a = get_sentinelone_connector()
    b = get_sentinelone_connector()
    assert a is b


def test_constructor_rejects_no_findings_engine():
    with pytest.raises(ValueError):
        SentinelOneConnector(findings_engine=None)


# ---------------------------------------------------------------------------
# Router contract (FastAPI TestClient)
# ---------------------------------------------------------------------------
def test_router_health(fastapi_client):
    r = fastapi_client.get("/api/v1/connectors/sentinelone/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["service"] == "sentinelone-connector"
    assert body["fallback_samples"] == 10


def test_router_status_alias(fastapi_client):
    r = fastapi_client.get("/api/v1/connectors/sentinelone/status")
    assert r.status_code == 200
    assert r.json()["service"] == "sentinelone-connector"


def test_router_sample(fastapi_client):
    r = fastapi_client.get("/api/v1/connectors/sentinelone/sample?limit=3")
    assert r.status_code == 200
    body = r.json()
    assert body["count"] == 3
    assert len(body["data"]) == 3
    assert "threatInfo" in body["data"][0]


def test_router_ingest_with_wrapper(fastapi_client):
    r = fastapi_client.post(
        "/api/v1/connectors/sentinelone/ingest",
        json={
            "org_id": "router-org",
            "payload": {"data": _S1_FALLBACK_THREATS[:5]},
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["findings_recorded"] == 5
    assert body["org_id"] == "router-org"


def test_router_ingest_with_list(fastapi_client):
    r = fastapi_client.post(
        "/api/v1/connectors/sentinelone/ingest",
        json={
            "org_id": "router-org-2",
            "payload": _S1_FALLBACK_THREATS[:2],
        },
    )
    assert r.status_code == 200
    assert r.json()["findings_recorded"] == 2


def test_router_ingest_sample_endpoint(fastapi_client):
    r = fastapi_client.post(
        "/api/v1/connectors/sentinelone/ingest/sample",
        json={"org_id": "sample-org", "max_events": 5},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["mode"] == "fallback"
    assert body["findings_recorded"] == 5


def test_router_ingest_raw_json(fastapi_client):
    raw = json.dumps({"data": _S1_FALLBACK_THREATS[:2]})
    r = fastapi_client.post(
        "/api/v1/connectors/sentinelone/ingest/raw",
        json={"org_id": "raw-org", "raw_json": raw},
    )
    assert r.status_code == 200
    assert r.json()["findings_recorded"] == 2


def test_router_ingest_rejects_bad_payload(fastapi_client):
    # `payload` field is required → 422 from pydantic
    r = fastapi_client.post(
        "/api/v1/connectors/sentinelone/ingest",
        json={"org_id": "x"},
    )
    assert r.status_code == 422


def test_router_ingest_raw_invalid_returns_400(fastapi_client):
    r = fastapi_client.post(
        "/api/v1/connectors/sentinelone/ingest/raw",
        json={"org_id": "x", "raw_json": "not-json"},
    )
    assert r.status_code == 400


# ---------------------------------------------------------------------------
# Embedded fallback shape sanity (regression guard)
# ---------------------------------------------------------------------------
def test_fallback_has_ten_threats():
    assert len(_S1_FALLBACK_THREATS) == 10


def test_fallback_each_has_required_envelope():
    for t in _S1_FALLBACK_THREATS:
        assert "id" in t
        assert "threatInfo" in t
        assert "agentDetectionInfo" in t
        ti = t["threatInfo"]
        assert "classification" in ti
        assert "confidenceLevel" in ti
        assert "mitigationStatus" in ti


def test_fallback_unique_threat_ids():
    ids = [t["id"] for t in _S1_FALLBACK_THREATS]
    assert len(ids) == len(set(ids))
