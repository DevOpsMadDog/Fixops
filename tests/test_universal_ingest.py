"""Tests for GAP-034 (universal ingest) + GAP-035 (Chronicle/Datadog adapters)."""

from __future__ import annotations

import os
import tempfile

import pytest

from core.security_data_pipeline_engine import SecurityDataPipelineEngine
from core.siem_integration_engine import (
    SIEM_ADAPTERS,
    ChronicleAdapter,
    DatadogAdapter,
    forward_to_siem,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def engine(tmp_path):
    db = tmp_path / "sdp.db"
    return SecurityDataPipelineEngine(db_path=str(db))


# ---------------------------------------------------------------------------
# 1. Source registration
# ---------------------------------------------------------------------------


def test_register_source_returns_id_and_echoes_mapping(engine):
    mapping = {"severity": "$.level", "asset": "$.host.name"}
    res = engine.register_source("acme", "cloudtrail", mapping)
    assert res["source_name"] == "cloudtrail"
    assert res["org_id"] == "acme"
    assert res["schema_mapping"] == mapping
    assert res["enabled"] is True
    assert res["id"]


def test_register_source_idempotent_on_same_name(engine):
    engine.register_source("acme", "cloudtrail", {"sev": "$.s"})
    updated = engine.register_source("acme", "cloudtrail", {"sev": "$.severity"})
    sources = engine.list_sources("acme")
    assert len(sources) == 1
    assert sources[0]["schema_mapping"] == {"sev": "$.severity"}
    # id stays stable on update
    assert updated["id"] == sources[0]["id"]


def test_register_source_empty_name_raises(engine):
    with pytest.raises(ValueError):
        engine.register_source("acme", "", {"x": "$.y"})


def test_register_source_non_dict_mapping_raises(engine):
    with pytest.raises(ValueError):
        engine.register_source("acme", "s1", ["not", "a", "dict"])  # type: ignore[arg-type]


def test_register_source_disabled_flag_persists(engine):
    engine.register_source("acme", "s1", {"a": "$.b"}, enabled=False)
    sources = engine.list_sources("acme")
    assert sources[0]["enabled"] is False


# ---------------------------------------------------------------------------
# 2. list_sources + org isolation
# ---------------------------------------------------------------------------


def test_list_sources_empty_org_returns_empty(engine):
    assert engine.list_sources("nobody") == []


def test_list_sources_isolates_by_org(engine):
    engine.register_source("tenant-a", "s1", {"x": "$.x"})
    engine.register_source("tenant-b", "s1", {"y": "$.y"})
    a = engine.list_sources("tenant-a")
    b = engine.list_sources("tenant-b")
    assert len(a) == 1 and a[0]["schema_mapping"] == {"x": "$.x"}
    assert len(b) == 1 and b[0]["schema_mapping"] == {"y": "$.y"}


# ---------------------------------------------------------------------------
# 3. JSONPath mapping correctness — 3 sample schemas
# ---------------------------------------------------------------------------


def test_jsonpath_mapping_cloudtrail_schema(engine):
    mapping = {
        "severity": "$.detail.severity",
        "user": "$.detail.userIdentity.userName",
        "source_ip": "$.detail.sourceIPAddress",
    }
    engine.register_source("acme", "cloudtrail", mapping)

    raw = {
        "detail": {
            "severity": "high",
            "userIdentity": {"userName": "alice"},
            "sourceIPAddress": "10.0.0.1",
        }
    }
    rec = engine.ingest_record("acme", "cloudtrail", raw)
    assert rec["target_fields"] == {
        "severity": "high",
        "user": "alice",
        "source_ip": "10.0.0.1",
    }


def test_jsonpath_mapping_crowdstrike_schema(engine):
    mapping = {
        "host": "$.device.hostname",
        "sha256": "$.file.hashes.sha256",
        "action": "$.action_taken",
    }
    engine.register_source("acme", "crowdstrike", mapping)
    raw = {
        "device": {"hostname": "srv-01"},
        "file": {"hashes": {"sha256": "abc123"}},
        "action_taken": "quarantine",
    }
    rec = engine.ingest_record("acme", "crowdstrike", raw)
    assert rec["target_fields"] == {
        "host": "srv-01",
        "sha256": "abc123",
        "action": "quarantine",
    }


def test_jsonpath_mapping_k8s_audit_schema_with_array(engine):
    mapping = {
        "verb": "$.verb",
        "first_group": "$.user.groups[0]",
        "resource": "$.objectRef.resource",
    }
    engine.register_source("acme", "k8s-audit", mapping)
    raw = {
        "verb": "create",
        "user": {"groups": ["system:masters", "admins"]},
        "objectRef": {"resource": "pods"},
    }
    rec = engine.ingest_record("acme", "k8s-audit", raw)
    assert rec["target_fields"] == {
        "verb": "create",
        "first_group": "system:masters",
        "resource": "pods",
    }


def test_jsonpath_missing_path_yields_none(engine):
    engine.register_source("acme", "s1", {"a": "$.does.not.exist"})
    rec = engine.ingest_record("acme", "s1", {"foo": "bar"})
    assert rec["target_fields"] == {"a": None}


def test_jsonpath_bracket_quoted_key(engine):
    engine.register_source("acme", "s1", {"weird": "$['weird key'].v"})
    rec = engine.ingest_record("acme", "s1", {"weird key": {"v": 42}})
    assert rec["target_fields"] == {"weird": 42}


def test_jsonpath_root_without_dollar(engine):
    engine.register_source("acme", "s1", {"a": "foo.bar"})
    rec = engine.ingest_record("acme", "s1", {"foo": {"bar": "baz"}})
    assert rec["target_fields"] == {"a": "baz"}


# ---------------------------------------------------------------------------
# 4. ingest_record persistence + errors
# ---------------------------------------------------------------------------


def test_ingest_record_persists_and_counts(engine):
    engine.register_source("acme", "s1", {"x": "$.y"})
    engine.ingest_record("acme", "s1", {"y": 1})
    engine.ingest_record("acme", "s1", {"y": 2})
    assert engine.count_records("acme") == 2
    assert engine.count_records("acme", "s1") == 2
    assert engine.count_records("other") == 0


def test_ingest_record_unknown_source_raises(engine):
    with pytest.raises(ValueError):
        engine.ingest_record("acme", "never-registered", {"y": 1})


def test_ingest_record_raw_record_must_be_dict(engine):
    engine.register_source("acme", "s1", {"x": "$.y"})
    with pytest.raises(ValueError):
        engine.ingest_record("acme", "s1", "not a dict")  # type: ignore[arg-type]


def test_ingest_record_returns_id_and_timestamp(engine):
    engine.register_source("acme", "s1", {"x": "$.y"})
    rec = engine.ingest_record("acme", "s1", {"y": 9})
    assert rec["id"]
    assert rec["ingested_at"]
    assert rec["source"] == "s1"


# ---------------------------------------------------------------------------
# 5. SIEM adapter registry — Chronicle + Datadog
# ---------------------------------------------------------------------------


def test_siem_registry_has_chronicle_and_datadog():
    assert "chronicle" in SIEM_ADAPTERS
    assert "datadog" in SIEM_ADAPTERS


def test_siem_registry_retains_legacy_adapters():
    for name in ("splunk", "qradar", "elastic", "sentinel"):
        assert name in SIEM_ADAPTERS


def test_chronicle_adapter_forward_event_success():
    adapter = ChronicleAdapter()
    result = adapter.forward_event({"event_id": "e-1", "severity": "high"})
    assert result["adapter"] == "chronicle"
    assert result["success"] is True
    assert result["status"] == "forwarded"
    assert result["event_id"] == "e-1"
    assert "chronicle.googleapis.com" in result["endpoint"]


def test_datadog_adapter_forward_event_success():
    adapter = DatadogAdapter()
    result = adapter.forward_event({"event_id": "e-2", "message": "x"})
    assert result["adapter"] == "datadog"
    assert result["success"] is True
    assert "datadoghq.com" in result["endpoint"]


def test_siem_adapter_rejects_non_dict_event():
    adapter = ChronicleAdapter()
    assert adapter.forward_event(None)["success"] is False  # type: ignore[arg-type]
    assert adapter.forward_event("raw string")["success"] is False  # type: ignore[arg-type]


def test_forward_to_siem_unknown_adapter_returns_failure():
    res = forward_to_siem("nosuch", {"event_id": "e"})
    assert res["success"] is False
    assert "unknown adapter" in res["error"]


def test_forward_to_siem_chronicle_convenience():
    res = forward_to_siem("Chronicle", {"event_id": "e-3"})
    assert res["adapter"] == "chronicle"
    assert res["success"] is True


def test_forward_to_siem_datadog_convenience():
    res = forward_to_siem("datadog", {"event_id": "e-4"})
    assert res["adapter"] == "datadog"
    assert res["success"] is True


def test_siem_output_engine_registry_mirrors_integration():
    from core.siem_output_engine import SIEM_ADAPTERS as OUT_ADAPTERS

    assert "chronicle" in OUT_ADAPTERS
    assert "datadog" in OUT_ADAPTERS
