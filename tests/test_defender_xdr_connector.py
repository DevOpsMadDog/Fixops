"""Tests for Microsoft Defender XDR (Sentinel-XDR) connector.

These tests do NOT touch a live Microsoft Graph Security API. They exercise
the JSON-format adapter and the SecurityFindingsEngine mirror using:
  - The 10 embedded fallback alerts (REAL Microsoft Graph schema)
  - On-the-fly synthetic alerts to cover edge cases

Coverage:
  - Pure normalization helpers (severity/category/evidence extraction)
  - Single-alert ingest path
  - Bulk-dump ingest (file + fallback)
  - Multi-tenant org_id isolation
  - Malformed/edge-case input survives without crashes
  - Router request models & responses (FastAPI TestClient)
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from connectors.defender_xdr_connector import (
    DefenderXDRConnector,
    _DEFENDER_FALLBACK_ALERTS,
    _DEFENDER_SEVERITY_MAP,
    _DEFENDER_CATEGORY_MAP,
    _evidence_type,
    _extract_primary_asset,
    _normalize_alert,
    _normalize_category,
    _normalize_severity,
    _suggest_remediation,
    get_defender_xdr_connector,
)
from core.security_findings_engine import SecurityFindingsEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def isolated_dbs(tmp_path, monkeypatch):
    """Point all per-domain SQLite DBs at an isolated tmp dir."""
    monkeypatch.setenv("ALDECI_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("FIXOPS_DATA_DIR", str(tmp_path))
    yield tmp_path


@pytest.fixture
def findings(isolated_dbs, tmp_path):
    db = str(tmp_path / "sf.db")
    return SecurityFindingsEngine(db_path=db)


@pytest.fixture
def connector(findings):
    return DefenderXDRConnector(findings_engine=findings)


# ---------------------------------------------------------------------------
# 1. Severity normalization
# ---------------------------------------------------------------------------
def test_severity_map_covers_all_defender_levels():
    """All 6 Defender severity strings are mapped."""
    for sev in ("informational", "low", "medium", "high", "critical", "unknown"):
        assert sev in _DEFENDER_SEVERITY_MAP


def test_severity_normalize_high():
    assert _normalize_severity("High") == "high"


def test_severity_normalize_uppercase():
    assert _normalize_severity("MEDIUM") == "medium"


def test_severity_normalize_unknown_string_defaults_medium():
    assert _normalize_severity("alien-severity-XYZ") == "medium"


def test_severity_normalize_non_string_defaults_medium():
    assert _normalize_severity(None) == "medium"
    assert _normalize_severity(42) == "medium"
    assert _normalize_severity({"x": 1}) == "medium"


def test_severity_normalize_unknown_maps_low():
    """Defender 'unknown' severity maps to ALDECI 'low' (defensive)."""
    assert _normalize_severity("unknown") == "low"


# ---------------------------------------------------------------------------
# 2. Category normalization
# ---------------------------------------------------------------------------
def test_category_map_covers_core_mitre_tactics():
    """Map covers the 12 core MITRE ATT&CK tactics + special Defender categories."""
    expected = {
        "initialaccess", "execution", "persistence", "privilegeescalation",
        "defenseevasion", "credentialaccess", "discovery", "lateralmovement",
        "collection", "commandandcontrol", "exfiltration", "impact",
        "malware", "ransomware",
    }
    for tactic in expected:
        assert tactic in _DEFENDER_CATEGORY_MAP


def test_category_normalize_credential_access_maps_secret_exposure():
    assert _normalize_category("CredentialAccess") == "secret-exposure"


def test_category_normalize_ransomware_maps_malware():
    assert _normalize_category("Ransomware") == "malware"


def test_category_normalize_exfiltration_maps_data_leak():
    assert _normalize_category("Exfiltration") == "data-leak"


def test_category_normalize_handles_dashes_underscores_and_spaces():
    """Defender variants like 'lateral_movement' / 'lateral-movement' / 'Lateral Movement' all map."""
    assert _normalize_category("lateral_movement") == "anomaly"
    assert _normalize_category("lateral-movement") == "anomaly"
    assert _normalize_category("Lateral Movement") == "anomaly"


def test_category_normalize_unknown_defaults_anomaly():
    assert _normalize_category("AlienCategoryXYZ") == "anomaly"


def test_category_normalize_non_string_defaults_anomaly():
    assert _normalize_category(None) == "anomaly"
    assert _normalize_category(42) == "anomaly"


# ---------------------------------------------------------------------------
# 3. Evidence type detection
# ---------------------------------------------------------------------------
def test_evidence_type_device_via_odata():
    item = {"@odata.type": "#microsoft.graph.security.deviceEvidence"}
    assert _evidence_type(item) == "device"


def test_evidence_type_process_via_odata():
    item = {"@odata.type": "#microsoft.graph.security.processEvidence"}
    assert _evidence_type(item) == "process"


def test_evidence_type_file_via_odata():
    assert _evidence_type({"@odata.type": "#microsoft.graph.security.fileEvidence"}) == "file"


def test_evidence_type_user_via_odata():
    assert _evidence_type({"@odata.type": "#microsoft.graph.security.userEvidence"}) == "user"


def test_evidence_type_ip_via_odata():
    assert _evidence_type({"@odata.type": "#microsoft.graph.security.ipEvidence"}) == "ip"


def test_evidence_type_url_via_odata():
    assert _evidence_type({"@odata.type": "#microsoft.graph.security.urlEvidence"}) == "url"


def test_evidence_type_duck_typed_device():
    """When @odata.type is missing, fall back to duck typing."""
    assert _evidence_type({"deviceDnsName": "foo"}) == "device"


def test_evidence_type_duck_typed_process():
    assert _evidence_type({"processCommandLine": "x.exe"}) == "process"


def test_evidence_type_duck_typed_file_via_sha256():
    assert _evidence_type({"sha256": "abc"}) == "file"


def test_evidence_type_unknown_returns_unknown():
    assert _evidence_type({"weirdkey": 1}) == "unknown"


# ---------------------------------------------------------------------------
# 4. Primary asset extraction (priority order)
# ---------------------------------------------------------------------------
def test_extract_primary_asset_prefers_device_over_process():
    evidence = [
        {"@odata.type": "#microsoft.graph.security.processEvidence", "processId": 1},
        {"@odata.type": "#microsoft.graph.security.deviceEvidence", "deviceDnsName": "host1"},
    ]
    out = _extract_primary_asset(evidence)
    assert out == {"asset_id": "host1", "asset_type": "host"}


def test_extract_primary_asset_falls_back_to_process_then_file():
    evidence_proc = [
        {"@odata.type": "#microsoft.graph.security.processEvidence",
         "imageFile": {"fileName": "evil.exe"}},
    ]
    out = _extract_primary_asset(evidence_proc)
    assert out["asset_type"] == "process"
    assert out["asset_id"] == "evil.exe"


def test_extract_primary_asset_user_via_userprincipalname():
    evidence = [
        {"@odata.type": "#microsoft.graph.security.userEvidence",
         "userAccount": {"userPrincipalName": "alice@x.com"}},
    ]
    out = _extract_primary_asset(evidence)
    assert out == {"asset_id": "alice@x.com", "asset_type": "user"}


def test_extract_primary_asset_ip_when_only_ip():
    evidence = [{"@odata.type": "#microsoft.graph.security.ipEvidence", "ipAddress": "1.2.3.4"}]
    assert _extract_primary_asset(evidence) == {"asset_id": "1.2.3.4", "asset_type": "ip"}


def test_extract_primary_asset_handles_empty_evidence():
    assert _extract_primary_asset([]) == {"asset_id": "", "asset_type": ""}


def test_extract_primary_asset_handles_none_evidence():
    assert _extract_primary_asset(None) == {"asset_id": "", "asset_type": ""}


def test_extract_primary_asset_skips_non_dict_items():
    evidence = ["junk", 42, None, {"@odata.type": "#microsoft.graph.security.deviceEvidence",
                                    "deviceDnsName": "real-host"}]
    assert _extract_primary_asset(evidence)["asset_id"] == "real-host"


# ---------------------------------------------------------------------------
# 5. Embedded fallback alerts
# ---------------------------------------------------------------------------
def test_fallback_has_exactly_10_alerts():
    """Spec: 10 sample Defender alerts."""
    assert len(_DEFENDER_FALLBACK_ALERTS) == 10


def test_fallback_alerts_all_have_required_fields():
    required = {"alertId", "title", "category", "severity", "createdDateTime"}
    for a in _DEFENDER_FALLBACK_ALERTS:
        assert required.issubset(a.keys()), f"missing keys in {a.get('alertId')}"


def test_fallback_alerts_carry_real_mitre_techniques():
    """Each fallback carries at least one MITRE ATT&CK technique ID."""
    for a in _DEFENDER_FALLBACK_ALERTS:
        techniques = a.get("mitreTechniques") or []
        assert techniques, f"alert {a['alertId']} missing mitreTechniques"
        for t in techniques:
            assert t.startswith("T") and any(c.isdigit() for c in t)


def test_fallback_alerts_have_evidence_array():
    """Real Defender alerts always carry an evidence array."""
    for a in _DEFENDER_FALLBACK_ALERTS:
        assert isinstance(a.get("evidence"), list)


# ---------------------------------------------------------------------------
# 6. Single-alert normalization (end-to-end)
# ---------------------------------------------------------------------------
def test_normalize_alert_powershell_high():
    """First fallback (PowerShell EncodedCommand) → ALDECI high anomaly."""
    raw = _DEFENDER_FALLBACK_ALERTS[0]
    out = _normalize_alert(raw)
    assert out["severity"] == "high"
    assert out["finding_type"] == "anomaly"           # Execution
    assert out["source_tool"] == "defender_xdr"
    assert out["asset_type"] == "host"                # device wins over process
    assert "WIN-SRV-01" in out["asset_id"]
    assert "T1059.001" in out["description"]
    assert out["correlation_key"].startswith("defender_xdr|")
    assert out["cvss_score"] == 7.8                   # high → 7.8


def test_normalize_alert_ransomware_maps_malware():
    """Ransomware category → malware finding_type."""
    rans = next(a for a in _DEFENDER_FALLBACK_ALERTS if a["category"] == "Ransomware")
    out = _normalize_alert(rans)
    assert out["finding_type"] == "malware"
    assert out["severity"] == "high"
    assert out["asset_type"] == "host"
    assert "URGENT" in out["remediation"]             # high severity → URGENT prefix


def test_normalize_alert_credential_access_maps_secret_exposure():
    cred = next(a for a in _DEFENDER_FALLBACK_ALERTS if a["category"] == "CredentialAccess")
    out = _normalize_alert(cred)
    assert out["finding_type"] == "secret-exposure"


def test_normalize_alert_lateral_movement_extracts_user_when_user_only():
    """When evidence has a user but no device, primary asset is user."""
    raw = {
        "alertId":  "x1",
        "title":    "Lateral via PtH",
        "category": "LateralMovement",
        "severity": "medium",
        "mitreTechniques": ["T1550.002"],
        "evidence": [
            {"@odata.type": "#microsoft.graph.security.userEvidence",
             "userAccount": {"accountName": "victim"}},
        ],
    }
    out = _normalize_alert(raw)
    assert out["asset_type"] == "user"
    assert out["asset_id"] == "victim"


def test_normalize_alert_correlation_key_uses_alert_id():
    raw = _DEFENDER_FALLBACK_ALERTS[2]
    out = _normalize_alert(raw)
    assert out["correlation_key"] == f"defender_xdr|{raw['alertId']}"


def test_normalize_alert_truncates_long_title():
    raw = {"alertId": "x", "title": "X" * 500, "category": "Execution",
           "severity": "low", "mitreTechniques": []}
    out = _normalize_alert(raw)
    assert len(out["title"]) <= 255


def test_normalize_alert_handles_missing_optional_fields():
    """Bare-bones alert with only required fields still normalizes cleanly."""
    raw = {"alertId": "minimal-1", "severity": "low"}
    out = _normalize_alert(raw)
    assert out["severity"] == "low"
    assert out["source_tool"] == "defender_xdr"
    assert out["finding_type"] == "anomaly"  # missing category defaults
    assert out["asset_id"] == "unknown"


def test_normalize_alert_rejects_non_dict():
    with pytest.raises(ValueError):
        _normalize_alert("not-a-dict")
    with pytest.raises(ValueError):
        _normalize_alert(None)


# ---------------------------------------------------------------------------
# 7. Remediation suggestion
# ---------------------------------------------------------------------------
def test_suggest_remediation_prefixes_urgent_for_critical():
    out = _suggest_remediation("malware", "critical")
    assert out.startswith("URGENT:")


def test_suggest_remediation_no_urgent_for_low():
    out = _suggest_remediation("anomaly", "low")
    assert not out.startswith("URGENT:")


def test_suggest_remediation_includes_secret_rotation_for_secret_exposure():
    out = _suggest_remediation("secret-exposure", "high")
    assert "Rotate" in out


# ---------------------------------------------------------------------------
# 8. Connector — single-alert ingest
# ---------------------------------------------------------------------------
def test_connector_requires_findings_engine():
    with pytest.raises(ValueError):
        DefenderXDRConnector(findings_engine=None)


def test_ingest_alert_records_finding(connector, findings):
    raw = _DEFENDER_FALLBACK_ALERTS[0]
    rec = connector.ingest_alert(org_id="acme", alert=raw)
    assert rec["id"]
    assert rec["source_tool"] == "defender_xdr"
    # And it shows up in the findings list:
    listed = findings.list_findings(org_id="acme")
    assert any(f["id"] == rec["id"] for f in listed)


def test_ingest_alert_rejects_empty_org_id(connector):
    with pytest.raises(ValueError):
        connector.ingest_alert(org_id="", alert={"alertId": "x", "severity": "low"})


# ---------------------------------------------------------------------------
# 9. Bulk-dump ingest — fallback
# ---------------------------------------------------------------------------
def test_ingest_dump_fallback_records_all_10(connector):
    res = connector.ingest_defender_dump(org_id="acme", force_fallback=True, max_alerts=10)
    assert res["mode"] == "fallback"
    assert res["alerts_processed"] == 10
    assert res["findings_recorded"] == 10
    assert res["skipped"] == 0
    assert res["source_tool"] == "defender_xdr"
    assert sum(res["severity_counts"].values()) == 10


def test_ingest_dump_respects_max_alerts(connector):
    res = connector.ingest_defender_dump(org_id="acme", force_fallback=True, max_alerts=3)
    assert res["alerts_processed"] == 3
    assert res["findings_recorded"] == 3


def test_ingest_dump_rejects_invalid_max_alerts(connector):
    with pytest.raises(ValueError):
        connector.ingest_defender_dump(org_id="acme", max_alerts=0)


def test_ingest_dump_rejects_empty_org_id(connector):
    with pytest.raises(ValueError):
        connector.ingest_defender_dump(org_id="", force_fallback=True)


# ---------------------------------------------------------------------------
# 10. Bulk-dump ingest — file (live mode)
# ---------------------------------------------------------------------------
def test_ingest_dump_from_json_list_file(connector, tmp_path):
    """Dump as a plain JSON list ingests cleanly."""
    p = tmp_path / "dump.json"
    p.write_text(json.dumps(_DEFENDER_FALLBACK_ALERTS[:5]))
    res = connector.ingest_defender_dump(org_id="acme", dump_file=str(p), max_alerts=10)
    assert res["mode"] == "live"
    assert res["alerts_processed"] == 5
    assert res["findings_recorded"] == 5


def test_ingest_dump_from_graph_value_wrapper(connector, tmp_path):
    """Microsoft Graph wraps the response as {"value": [...]} — connector must accept it."""
    p = tmp_path / "graph.json"
    p.write_text(json.dumps({"value": _DEFENDER_FALLBACK_ALERTS[:4],
                             "@odata.context": "https://graph.microsoft.com/v1.0/$metadata"}))
    res = connector.ingest_defender_dump(org_id="acme", dump_file=str(p))
    assert res["mode"] == "live"
    assert res["findings_recorded"] == 4


def test_ingest_dump_missing_file_falls_back(connector, tmp_path):
    res = connector.ingest_defender_dump(
        org_id="acme",
        dump_file=str(tmp_path / "does-not-exist.json"),
    )
    assert res["mode"] == "fallback"
    assert res["findings_recorded"] == 10


def test_ingest_dump_invalid_json_falls_back(connector, tmp_path):
    p = tmp_path / "garbage.json"
    p.write_text("{not json{{{")
    res = connector.ingest_defender_dump(org_id="acme", dump_file=str(p))
    assert res["mode"] == "fallback"


def test_ingest_dump_unexpected_json_shape_falls_back(connector, tmp_path):
    """JSON that's neither list nor {value:[...]} → falls back."""
    p = tmp_path / "weird.json"
    p.write_text(json.dumps({"unexpected": "shape"}))
    res = connector.ingest_defender_dump(org_id="acme", dump_file=str(p))
    assert res["mode"] == "fallback"


# ---------------------------------------------------------------------------
# 11. Multi-tenant isolation
# ---------------------------------------------------------------------------
def test_multi_tenant_findings_are_isolated(connector, findings):
    connector.ingest_defender_dump(org_id="tenant-a", force_fallback=True, max_alerts=3)
    connector.ingest_defender_dump(org_id="tenant-b", force_fallback=True, max_alerts=5)
    a = findings.list_findings(org_id="tenant-a")
    b = findings.list_findings(org_id="tenant-b")
    assert len(a) == 3
    assert len(b) == 5
    # No cross-contamination of finding IDs
    assert {x["id"] for x in a}.isdisjoint({x["id"] for x in b})


# ---------------------------------------------------------------------------
# 12. parse_alerts (no DB write)
# ---------------------------------------------------------------------------
def test_parse_alerts_returns_list_of_normalized(connector):
    out = connector.parse_alerts(_DEFENDER_FALLBACK_ALERTS)
    assert len(out) == 10
    assert all(o["source_tool"] == "defender_xdr" for o in out)


def test_parse_alerts_skips_malformed_silently(connector):
    """Malformed alerts are skipped, valid ones still parsed (never raises)."""
    mixed = [
        _DEFENDER_FALLBACK_ALERTS[0],
        "not-a-dict",                          # skipped
        None,                                   # skipped
        _DEFENDER_FALLBACK_ALERTS[1],
    ]
    out = connector.parse_alerts(mixed)
    assert len(out) == 2


def test_parse_alert_single_returns_normalized(connector):
    out = connector.parse_alert(_DEFENDER_FALLBACK_ALERTS[0])
    assert out["severity"] == "high"
    assert out["source_tool"] == "defender_xdr"


# ---------------------------------------------------------------------------
# 13. Singleton accessor
# ---------------------------------------------------------------------------
def test_singleton_accessor_returns_same_instance(isolated_dbs):
    a = get_defender_xdr_connector()
    b = get_defender_xdr_connector()
    assert a is b


# ---------------------------------------------------------------------------
# 14. Router smoke tests (FastAPI)
# ---------------------------------------------------------------------------
def test_router_health_returns_ok(isolated_dbs, monkeypatch):
    """Health endpoint advertises the connector wiring."""
    # Bypass api_key auth in isolated test
    from apps.api import auth_deps as _auth
    monkeypatch.setattr(_auth, "api_key_auth", lambda: "test")

    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from apps.api.defender_xdr_connector_router import router

    app = FastAPI()
    app.include_router(router)
    # Override the dependency
    app.dependency_overrides[_auth.api_key_auth] = lambda: "test"
    with TestClient(app) as client:
        r = client.get("/api/v1/connectors/defender-xdr/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["source_tool"] == "defender_xdr"
    assert body["fallback_alert_count"] == 10


def test_router_status_alias(isolated_dbs, monkeypatch):
    """Demo-001 contract: /status mirrors /health."""
    from apps.api import auth_deps as _auth
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from apps.api.defender_xdr_connector_router import router

    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[_auth.api_key_auth] = lambda: "test"
    with TestClient(app) as client:
        r = client.get("/api/v1/connectors/defender-xdr/status")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_router_ingest_fallback(isolated_dbs, monkeypatch):
    """POST /ingest with force_fallback=true ingests embedded samples."""
    from apps.api import auth_deps as _auth
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from apps.api.defender_xdr_connector_router import router

    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[_auth.api_key_auth] = lambda: "test"
    with TestClient(app) as client:
        r = client.post(
            "/api/v1/connectors/defender-xdr/ingest",
            json={"org_id": "router-test", "force_fallback": True, "max_alerts": 4},
        )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["mode"] == "fallback"
    assert body["findings_recorded"] == 4
    assert body["source_tool"] == "defender_xdr"


def test_router_ingest_alert_single(isolated_dbs, monkeypatch):
    """POST /ingest/alert ingests a single alert and returns the recorded finding."""
    from apps.api import auth_deps as _auth
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from apps.api.defender_xdr_connector_router import router

    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[_auth.api_key_auth] = lambda: "test"
    payload = {
        "org_id": "single-router",
        "alert":  _DEFENDER_FALLBACK_ALERTS[0],
    }
    with TestClient(app) as client:
        r = client.post("/api/v1/connectors/defender-xdr/ingest/alert", json=payload)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "ok"
    assert body["finding"]["source_tool"] == "defender_xdr"


def test_router_parse_does_not_write(isolated_dbs, monkeypatch):
    """POST /parse normalizes alerts but does not persist."""
    from apps.api import auth_deps as _auth
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from apps.api.defender_xdr_connector_router import router

    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[_auth.api_key_auth] = lambda: "test"
    payload = {"alerts": list(_DEFENDER_FALLBACK_ALERTS[:3])}
    with TestClient(app) as client:
        r = client.post("/api/v1/connectors/defender-xdr/parse", json=payload)
    assert r.status_code == 200
    body = r.json()
    assert body["input_count"] == 3
    assert body["parsed_count"] == 3
    assert body["skipped_count"] == 0
    assert all(a["source_tool"] == "defender_xdr" for a in body["alerts"])


def test_router_ingest_validation_rejects_empty_org(isolated_dbs, monkeypatch):
    """Pydantic validation: org_id min_length=1 enforced at the router boundary."""
    from apps.api import auth_deps as _auth
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from apps.api.defender_xdr_connector_router import router

    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[_auth.api_key_auth] = lambda: "test"
    with TestClient(app) as client:
        r = client.post(
            "/api/v1/connectors/defender-xdr/ingest",
            json={"org_id": "", "force_fallback": True},
        )
    assert r.status_code == 422
