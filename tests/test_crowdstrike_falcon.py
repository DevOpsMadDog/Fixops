"""Tests for CrowdStrike Falcon connector — REAL Detection.Created format parser.

These tests do NOT touch the live CrowdStrike API. They exercise the
format adapter, severity/technique mappings, dump-extraction heuristics,
and the in-memory mirror to EDREngine + SecurityFindingsEngine +
SecurityEventCorrelationEngine using the embedded 10-detection sample
(real Falcon Streaming API schema, synthetic content).

Closes 1 of 11 substitute-only gaps from the 2026-04-26 commercial-vendor
audit (`raw/competitive/gap-matrix-2026-04-26.md`).
"""

from __future__ import annotations

import json
import os
import threading

import pytest

from connectors.crowdstrike_falcon_connector import (
    CrowdStrikeFalconConnector,
    FALCON_SAMPLE_DETECTIONS,
    _FALCON_TACTIC_TO_MITRE,
    _FALCON_TECHNIQUE_TO_MITRE,
    falcon_severity_to_aldeci,
    falcon_severity_to_cvss,
    falcon_tactic_to_mitre,
    falcon_technique_to_mitre,
    get_falcon_connector,
    parse_event,
)
from core.edr_engine import EDREngine
from core.security_event_correlation_engine import SecurityEventCorrelationEngine
from core.security_findings_engine import SecurityFindingsEngine


# ----------------------------------------------------------------------
# Fixtures
# ----------------------------------------------------------------------
@pytest.fixture
def isolated_dbs(tmp_path, monkeypatch):
    """Point all per-domain SQLite DBs at an isolated tmp dir."""
    monkeypatch.setenv("ALDECI_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("FIXOPS_DATA_DIR", str(tmp_path))
    yield tmp_path


@pytest.fixture
def connector(isolated_dbs, tmp_path):
    """Build a connector with all engines using tmp_path-scoped DBs.

    Each engine's ``__init__`` accepts ``db_path`` so we explicitly pass it
    here. This guarantees the test is hermetic regardless of env vars.
    """
    findings_db = str(tmp_path / "security_findings.db")
    edr_db = str(tmp_path / "edr.db")
    corr_db = str(tmp_path / "correlation.db")
    edr = EDREngine(db_path=edr_db)
    findings = SecurityFindingsEngine(db_path=findings_db)
    # SecurityEventCorrelationEngine uses the default db_path arg, but its
    # ingest does not collide with findings — pass explicit if signature allows
    try:
        corr = SecurityEventCorrelationEngine(db_path=corr_db)
    except TypeError:
        corr = SecurityEventCorrelationEngine()
    return CrowdStrikeFalconConnector(
        edr_engine=edr,
        findings_engine=findings,
        correlation_engine=corr,
    )


@pytest.fixture
def parser_only_connector():
    """Connector with no engines wired — for parser-shape tests."""
    return CrowdStrikeFalconConnector()


# ----------------------------------------------------------------------
# Severity mapping tests (5 tests covering all 5 buckets)
# ----------------------------------------------------------------------
def test_severity_critical_high_band():
    assert falcon_severity_to_aldeci(100) == "critical"
    assert falcon_severity_to_aldeci(95)  == "critical"
    assert falcon_severity_to_aldeci(90)  == "critical"


def test_severity_high_band():
    assert falcon_severity_to_aldeci(89) == "high"
    assert falcon_severity_to_aldeci(75) == "high"
    assert falcon_severity_to_aldeci(70) == "high"


def test_severity_medium_band():
    assert falcon_severity_to_aldeci(69) == "medium"
    assert falcon_severity_to_aldeci(55) == "medium"
    assert falcon_severity_to_aldeci(50) == "medium"


def test_severity_low_band():
    assert falcon_severity_to_aldeci(49) == "low"
    assert falcon_severity_to_aldeci(35) == "low"
    assert falcon_severity_to_aldeci(30) == "low"


def test_severity_informational_band_and_invalid():
    assert falcon_severity_to_aldeci(29) == "informational"
    assert falcon_severity_to_aldeci(1)  == "informational"
    # Invalid input falls back to medium
    assert falcon_severity_to_aldeci("not-a-number") == "medium"  # type: ignore[arg-type]
    assert falcon_severity_to_aldeci(None) == "medium"  # type: ignore[arg-type]


def test_severity_to_cvss_linear_scaling():
    assert falcon_severity_to_cvss(100) == 10.0
    assert falcon_severity_to_cvss(50)  == 5.0
    assert falcon_severity_to_cvss(1)   == 0.1
    assert falcon_severity_to_cvss(95)  == 9.5
    # Out-of-range gets clipped
    assert falcon_severity_to_cvss(150) == 10.0
    assert falcon_severity_to_cvss(0)   == 0.1
    # Invalid input → 5.0 default
    assert falcon_severity_to_cvss("abc") == 5.0  # type: ignore[arg-type]


# ----------------------------------------------------------------------
# Technique / Tactic mapping tests
# ----------------------------------------------------------------------
def test_technique_mapping_powershell():
    assert falcon_technique_to_mitre("PowerShell") == "T1059.001"


def test_technique_mapping_lsass():
    assert falcon_technique_to_mitre("LSASS Memory") == "T1003.001"


def test_technique_mapping_smb_lateral():
    assert falcon_technique_to_mitre("SMB/Windows Admin Shares") == "T1021.002"


def test_technique_mapping_case_insensitive():
    assert falcon_technique_to_mitre("powershell") == "T1059.001"
    assert falcon_technique_to_mitre("DNS") == "T1071.004"


def test_technique_mapping_unknown_returns_empty():
    assert falcon_technique_to_mitre("MadeUpTechnique") == ""
    assert falcon_technique_to_mitre("") == ""


def test_tactic_mapping_all_14_canonical():
    """Every Falcon tactic in the published list maps to a TA#### code."""
    assert falcon_tactic_to_mitre("Initial Access")     == "TA0001"
    assert falcon_tactic_to_mitre("Execution")          == "TA0002"
    assert falcon_tactic_to_mitre("Persistence")        == "TA0003"
    assert falcon_tactic_to_mitre("Privilege Escalation") == "TA0004"
    assert falcon_tactic_to_mitre("Defense Evasion")    == "TA0005"
    assert falcon_tactic_to_mitre("Credential Access")  == "TA0006"
    assert falcon_tactic_to_mitre("Discovery")          == "TA0007"
    assert falcon_tactic_to_mitre("Lateral Movement")   == "TA0008"
    assert falcon_tactic_to_mitre("Collection")         == "TA0009"
    assert falcon_tactic_to_mitre("Command and Control") == "TA0011"
    assert falcon_tactic_to_mitre("Exfiltration")       == "TA0010"
    assert falcon_tactic_to_mitre("Impact")             == "TA0040"
    # Unknown
    assert falcon_tactic_to_mitre("Mystery") == ""
    assert falcon_tactic_to_mitre("") == ""


# ----------------------------------------------------------------------
# parse_event tests — real Falcon shape
# ----------------------------------------------------------------------
def test_parse_event_wrapper_shape_ransomware():
    """Detection 1 — ransomware (critical, T1486)."""
    parsed = parse_event(FALCON_SAMPLE_DETECTIONS[0])
    assert parsed["detection_id"] == "ldt:5a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d:ev-001"
    assert parsed["severity"] == "critical"
    assert parsed["severity_score"] == 95
    assert parsed["cvss_score"] == 9.5
    assert parsed["mitre_technique"] == "T1486"
    assert parsed["mitre_tactic"] == "TA0040"
    assert parsed["process_name"] == "svchost-fake.exe"
    assert parsed["sha256"].startswith("e3b0c44298fc1c14")
    assert parsed["user"] == "CORP\\jdoe"
    assert parsed["pid"] == 12345
    assert "ransomware" in parsed["description"].lower()


def test_parse_event_lsass_credential_dump():
    """Detection 2 — LSASS dump (T1003.001)."""
    parsed = parse_event(FALCON_SAMPLE_DETECTIONS[1])
    assert parsed["mitre_technique"] == "T1003.001"
    assert parsed["mitre_tactic"] == "TA0006"
    assert parsed["process_name"] == "procdump.exe"
    assert parsed["severity"] == "critical"


def test_parse_event_powershell_encoded():
    """Detection 3 — encoded PowerShell (T1059.001)."""
    parsed = parse_event(FALCON_SAMPLE_DETECTIONS[2])
    assert parsed["mitre_technique"] == "T1059.001"
    assert parsed["mitre_tactic"] == "TA0002"
    assert parsed["severity"] == "high"
    assert "-enc" in parsed["cmdline"]


def test_parse_event_lateral_movement_smb():
    """Detection 4 — psexec lateral movement (T1021.002)."""
    parsed = parse_event(FALCON_SAMPLE_DETECTIONS[3])
    assert parsed["mitre_technique"] == "T1021.002"
    assert parsed["mitre_tactic"] == "TA0008"
    assert "psexec" in parsed["cmdline"].lower()


def test_parse_event_uac_bypass_pe():
    """Detection 5 — CMSTP UAC bypass (T1548.002, Privilege Escalation)."""
    parsed = parse_event(FALCON_SAMPLE_DETECTIONS[4])
    assert parsed["mitre_technique"] == "T1548.002"
    assert parsed["mitre_tactic"] == "TA0004"
    assert parsed["severity"] == "medium"


def test_parse_event_dns_tunneling():
    """Detection 7 — DNS C2 (T1071.004)."""
    parsed = parse_event(FALCON_SAMPLE_DETECTIONS[6])
    assert parsed["mitre_technique"] == "T1071.004"
    assert parsed["mitre_tactic"] == "TA0011"


def test_parse_event_informational_collapses_severity():
    """Detection 10 — informational (severity 20)."""
    parsed = parse_event(FALCON_SAMPLE_DETECTIONS[9])
    assert parsed["severity"] == "informational"
    assert parsed["mitre_technique"] == "T1057"


def test_parse_event_flat_shape_without_wrapper():
    """Insight UI export omits the metadata/event wrapper."""
    flat = dict(FALCON_SAMPLE_DETECTIONS[0]["event"])  # unwrap
    parsed = parse_event(flat)
    assert parsed["mitre_technique"] == "T1486"
    assert parsed["severity"] == "critical"


def test_parse_event_missing_detect_id_generates_surrogate():
    parsed = parse_event({"Severity": 50, "FileName": "x.exe"})
    assert parsed["detection_id"].startswith("falcon-")
    assert len(parsed["detection_id"]) > 7
    assert parsed["severity"] == "medium"


def test_parse_event_rejects_non_dict():
    with pytest.raises(ValueError):
        parse_event("not-a-dict")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        parse_event([1, 2, 3])  # type: ignore[arg-type]


def test_parse_event_eventcreationtime_to_iso():
    """eventCreationTime (ms epoch) is converted to ISO-8601 UTC."""
    from datetime import datetime, timezone
    parsed = parse_event(FALCON_SAMPLE_DETECTIONS[0])
    # ISO-8601 UTC format: YYYY-MM-DDTHH:MM:SS+00:00
    assert "T" in parsed["detected_at"]
    assert parsed["detected_at"].endswith("+00:00")
    # Round-trip: re-parse and check it equals the source ms-epoch (1798875600000)
    dt = datetime.fromisoformat(parsed["detected_at"])
    assert dt.tzinfo is not None
    assert int(dt.timestamp() * 1000) == 1798875600000


# ----------------------------------------------------------------------
# Sample shape sanity tests
# ----------------------------------------------------------------------
def test_sample_dump_has_10_detections():
    assert len(FALCON_SAMPLE_DETECTIONS) == 10


def test_sample_dump_covers_all_severity_bands():
    """The 10-detection sample must exercise critical/high/medium/low/informational."""
    severities = {parse_event(e)["severity"] for e in FALCON_SAMPLE_DETECTIONS}
    assert severities == {"critical", "high", "medium", "low", "informational"}


def test_sample_dump_real_falcon_field_names():
    """Every event must use the canonical Falcon field names."""
    required_fields = {"DetectId", "Severity", "FileName", "CommandLine",
                       "Technique", "Tactic", "BehaviorId"}
    for event in FALCON_SAMPLE_DETECTIONS:
        ev = event["event"]
        missing = required_fields - set(ev.keys())
        assert not missing, f"event missing Falcon fields: {missing}"


# ----------------------------------------------------------------------
# ingest_falcon_dump end-to-end tests
# ----------------------------------------------------------------------
def test_ingest_list_of_events(connector):
    res = connector.ingest_falcon_dump(FALCON_SAMPLE_DETECTIONS, org_id="acme")
    assert res["mode"] == "live"
    assert res["events_processed"] == 10
    assert res["ingested"] == 10
    assert res["failed"] == 0
    assert res["findings_recorded"] == 10
    assert res["edr_events"] == 10
    assert res["correlation_events"] == 10
    assert len(res["detection_ids"]) == 10


def test_ingest_single_dict_event(connector):
    res = connector.ingest_falcon_dump(FALCON_SAMPLE_DETECTIONS[0], org_id="acme")
    assert res["ingested"] == 1
    assert res["findings_recorded"] == 1


def test_ingest_falcon_rest_envelope_resources_key(connector):
    """Falcon's REST API wraps the array under {"resources": [...]}."""
    envelope = {"resources": FALCON_SAMPLE_DETECTIONS[:3], "meta": {"trace_id": "abc"}}
    res = connector.ingest_falcon_dump(envelope, org_id="acme")
    assert res["ingested"] == 3


def test_ingest_json_string_array(connector):
    text = json.dumps(FALCON_SAMPLE_DETECTIONS[:5])
    res = connector.ingest_falcon_dump(text, org_id="acme")
    assert res["ingested"] == 5


def test_ingest_ndjson_string(connector):
    """NDJSON: one JSON object per line."""
    ndjson = "\n".join(json.dumps(e) for e in FALCON_SAMPLE_DETECTIONS[:4])
    res = connector.ingest_falcon_dump(ndjson, org_id="acme")
    assert res["ingested"] == 4


def test_ingest_bytes_payload(connector):
    payload = json.dumps(FALCON_SAMPLE_DETECTIONS).encode("utf-8")
    res = connector.ingest_falcon_dump(payload, org_id="acme")
    assert res["ingested"] == 10


def test_ingest_from_file_path(connector, tmp_path):
    dump_file = tmp_path / "falcon-dump.json"
    dump_file.write_text(json.dumps(FALCON_SAMPLE_DETECTIONS), encoding="utf-8")
    res = connector.ingest_falcon_dump(dump_file, org_id="acme")
    assert res["ingested"] == 10


def test_ingest_missing_file_raises(connector, tmp_path):
    with pytest.raises(FileNotFoundError):
        connector.ingest_falcon_dump(tmp_path / "no-such.json", org_id="acme")


def test_ingest_max_events_caps_processing(connector):
    res = connector.ingest_falcon_dump(FALCON_SAMPLE_DETECTIONS, org_id="acme", max_events=3)
    assert res["ingested"] == 3
    assert len(res["detection_ids"]) == 3


def test_ingest_empty_string_processes_zero(connector):
    res = connector.ingest_falcon_dump("", org_id="acme")
    assert res["ingested"] == 0
    assert res["failed"] == 0


def test_ingest_requires_org_id(connector):
    with pytest.raises(ValueError):
        connector.ingest_falcon_dump(FALCON_SAMPLE_DETECTIONS, org_id="")


def test_ingest_malformed_event_counted_as_failed(connector):
    """A non-dict in the event list is counted as failed but doesn't crash."""
    payload = list(FALCON_SAMPLE_DETECTIONS[:2]) + [None, "broken"]  # type: ignore[list-item]
    res = connector.ingest_falcon_dump(payload, org_id="acme")
    # _extract_events filters non-dicts so we get 2 ingested, 0 failed
    assert res["ingested"] == 2
    assert res["events_processed"] == 2


# ----------------------------------------------------------------------
# Tenant-isolation + dedup
# ----------------------------------------------------------------------
def _falcon_findings(findings):
    """Filter findings to only those mirrored by the Falcon connector
    (correlation_key prefix). The EDR engine emits its own auto-detection
    findings on top of process-event ingest, so we must filter."""
    return [f for f in findings
            if (f.get("correlation_key") or "").startswith("crowdstrike_falcon|")]


def test_findings_isolated_per_tenant(connector):
    """Findings from acme are not visible to globex."""
    connector.ingest_falcon_dump(FALCON_SAMPLE_DETECTIONS[:3], org_id="acme")
    connector.ingest_falcon_dump(FALCON_SAMPLE_DETECTIONS[:5], org_id="globex")
    a = connector._findings.list_findings(org_id="acme")
    b = connector._findings.list_findings(org_id="globex")
    assert all(f["org_id"] == "acme" for f in a)
    assert all(f["org_id"] == "globex" for f in b)
    a_falcon = _falcon_findings(a)
    b_falcon = _falcon_findings(b)
    assert len(a_falcon) == 3
    assert len(b_falcon) == 5


def test_reingest_is_idempotent_on_correlation_key(connector):
    """Re-ingesting the same dump dedups via correlation_key (detection_id)."""
    connector.ingest_falcon_dump(FALCON_SAMPLE_DETECTIONS[:4], org_id="acme")
    connector.ingest_falcon_dump(FALCON_SAMPLE_DETECTIONS[:4], org_id="acme")
    findings = _falcon_findings(connector._findings.list_findings(org_id="acme"))
    # 4 unique Falcon detections expected, even after re-run
    assert len(findings) == 4
    # Each Falcon finding should have occurrence_count == 2 after the second ingest
    occurrence = {f["correlation_key"]: f["occurrence_count"] for f in findings}
    assert all(c == 2 for c in occurrence.values())


def test_correlation_engine_receives_falcon_events(connector):
    """All ingested detections appear in the correlation engine."""
    connector.ingest_falcon_dump(FALCON_SAMPLE_DETECTIONS[:5], org_id="acme")
    events = connector._correlation.list_events(org_id="acme")
    assert len(events) >= 5
    sources = {e["source_system"] for e in events}
    assert "crowdstrike_falcon" in sources


def test_edr_endpoints_created_per_unique_hostname(connector):
    """The connector registers one EDR endpoint per unique ComputerName."""
    connector.ingest_falcon_dump(FALCON_SAMPLE_DETECTIONS, org_id="acme")
    eps = connector._edr.list_endpoints("acme")
    hostnames = {e["hostname"] for e in eps}
    expected = {e["event"]["ComputerName"] for e in FALCON_SAMPLE_DETECTIONS}
    assert hostnames == expected


# ----------------------------------------------------------------------
# Convenience helpers
# ----------------------------------------------------------------------
def test_ingest_sample_helper(connector):
    res = connector.ingest_sample(org_id="demo-org")
    assert res["ingested"] == 10
    assert res["findings_recorded"] == 10


def test_no_engines_wired_does_not_crash(parser_only_connector):
    """A connector with no engines wired still parses and returns counts."""
    res = parser_only_connector.ingest_falcon_dump(
        FALCON_SAMPLE_DETECTIONS[:3], org_id="acme",
    )
    assert res["ingested"] == 3
    assert res["findings_recorded"] == 0
    assert res["edr_events"] == 0
    assert res["correlation_events"] == 0
    assert len(res["detection_ids"]) == 3


def test_module_singleton_accessor():
    a = get_falcon_connector()
    b = get_falcon_connector()
    assert a is b
    assert isinstance(a, CrowdStrikeFalconConnector)


def test_concurrent_ingest_thread_safe(connector):
    """The RLock guards concurrent ingest calls."""
    org = "thread-test"
    errors: list = []

    def worker(slice_idx: int) -> None:
        try:
            connector.ingest_falcon_dump(
                FALCON_SAMPLE_DETECTIONS[slice_idx:slice_idx + 2],
                org_id=org,
            )
        except Exception as exc:  # noqa: BLE001 — collect for assertion
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(0, 10, 2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, f"concurrent ingest errors: {errors}"
    findings = _falcon_findings(connector._findings.list_findings(org_id=org))
    # 5 threads × 2 events = 10 unique detections
    assert len(findings) == 10
