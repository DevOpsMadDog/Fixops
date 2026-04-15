"""Tests for ContainerRuntimeSecurityEngine — ~35 tests."""

from __future__ import annotations

import pytest
from pathlib import Path

from core.container_runtime_security_engine import ContainerRuntimeSecurityEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine(tmp_path):
    return ContainerRuntimeSecurityEngine(db_path=str(tmp_path / "crs.db"))


@pytest.fixture
def container(engine):
    return engine.register_container("org1", {
        "container_id": "c1",
        "image_name": "nginx",
        "image_tag": "1.25",
        "namespace": "production",
        "cluster": "k8s-prod",
    })


# ---------------------------------------------------------------------------
# register_container
# ---------------------------------------------------------------------------

class TestRegisterContainer:
    def test_basic_registration(self, engine):
        c = engine.register_container("org1", {"container_id": "c1", "image_name": "nginx"})
        assert c["container_id"] == "c1"
        assert c["image_name"] == "nginx"
        assert c["security_score"] == 100
        assert c["runtime_status"] == "running"
        assert c["privileged"] == 0
        assert c["host_network"] == 0

    def test_missing_container_id_raises(self, engine):
        with pytest.raises(ValueError, match="container_id"):
            engine.register_container("org1", {"image_name": "nginx"})

    def test_missing_image_name_raises(self, engine):
        with pytest.raises(ValueError, match="image_name"):
            engine.register_container("org1", {"container_id": "c1"})

    def test_invalid_runtime_status_raises(self, engine):
        with pytest.raises(ValueError, match="runtime_status"):
            engine.register_container("org1", {
                "container_id": "c1", "image_name": "nginx", "runtime_status": "unknown"
            })

    def test_valid_runtime_statuses(self, engine):
        for status in ["running", "stopped", "paused", "crashed"]:
            c = engine.register_container("org1", {
                "container_id": f"c_{status}",
                "image_name": "nginx",
                "runtime_status": status,
            })
            assert c["runtime_status"] == status

    def test_privileged_flag(self, engine):
        c = engine.register_container("org1", {
            "container_id": "c_priv", "image_name": "nginx", "privileged": True
        })
        assert c["privileged"] == 1

    def test_host_network_flag(self, engine):
        c = engine.register_container("org1", {
            "container_id": "c_hn", "image_name": "nginx", "host_network": True
        })
        assert c["host_network"] == 1

    def test_custom_security_score(self, engine):
        c = engine.register_container("org1", {
            "container_id": "c_score", "image_name": "nginx", "security_score": 75
        })
        assert c["security_score"] == 75


# ---------------------------------------------------------------------------
# list_containers / get_container
# ---------------------------------------------------------------------------

class TestListAndGetContainers:
    def test_list_all(self, engine, container):
        result = engine.list_containers("org1")
        assert len(result) == 1
        assert result[0]["container_id"] == "c1"

    def test_filter_by_namespace(self, engine):
        engine.register_container("org1", {"container_id": "c_prod", "image_name": "nginx", "namespace": "production"})
        engine.register_container("org1", {"container_id": "c_dev", "image_name": "nginx", "namespace": "dev"})
        result = engine.list_containers("org1", namespace="production")
        assert all(r["namespace"] == "production" for r in result)

    def test_filter_by_runtime_status(self, engine):
        engine.register_container("org1", {"container_id": "c_run", "image_name": "nginx", "runtime_status": "running"})
        engine.register_container("org1", {"container_id": "c_stop", "image_name": "nginx", "runtime_status": "stopped"})
        result = engine.list_containers("org1", runtime_status="running")
        assert all(r["runtime_status"] == "running" for r in result)

    def test_get_container_by_container_id(self, engine, container):
        result = engine.get_container("org1", "c1")
        assert result is not None
        assert result["container_id"] == "c1"

    def test_get_container_wrong_org_returns_none(self, engine, container):
        result = engine.get_container("org2", "c1")
        assert result is None

    def test_get_container_not_found_returns_none(self, engine):
        result = engine.get_container("org1", "nonexistent")
        assert result is None

    def test_org_isolation_in_list(self, engine):
        engine.register_container("org1", {"container_id": "c_a", "image_name": "nginx"})
        engine.register_container("org2", {"container_id": "c_b", "image_name": "redis"})
        result = engine.list_containers("org1")
        assert all(r["org_id"] == "org1" for r in result)


# ---------------------------------------------------------------------------
# update_container_status
# ---------------------------------------------------------------------------

class TestUpdateContainerStatus:
    def test_update_status(self, engine, container):
        result = engine.update_container_status("org1", "c1", "stopped")
        assert result["runtime_status"] == "stopped"

    def test_update_status_invalid_raises(self, engine, container):
        with pytest.raises(ValueError):
            engine.update_container_status("org1", "c1", "invalid")

    def test_update_status_not_found_raises(self, engine):
        with pytest.raises(KeyError):
            engine.update_container_status("org1", "nonexistent", "stopped")


# ---------------------------------------------------------------------------
# record_runtime_event
# ---------------------------------------------------------------------------

class TestRecordRuntimeEvent:
    def test_basic_event(self, engine, container):
        evt = engine.record_runtime_event("org1", {
            "container_id": "c1",
            "event_type": "exec_command",
            "severity": "high",
        })
        assert evt["status"] == "detected"
        assert evt["event_type"] == "exec_command"

    def test_invalid_event_type_raises(self, engine, container):
        with pytest.raises(ValueError, match="event_type"):
            engine.record_runtime_event("org1", {
                "container_id": "c1", "event_type": "invalid", "severity": "low"
            })

    def test_invalid_severity_raises(self, engine, container):
        with pytest.raises(ValueError, match="severity"):
            engine.record_runtime_event("org1", {
                "container_id": "c1", "event_type": "exec_command", "severity": "extreme"
            })

    def test_nonexistent_container_raises(self, engine):
        with pytest.raises(ValueError, match="not found"):
            engine.record_runtime_event("org1", {
                "container_id": "ghost", "event_type": "exec_command", "severity": "low"
            })

    def test_critical_decrements_score_by_20(self, engine, container):
        engine.record_runtime_event("org1", {
            "container_id": "c1", "event_type": "privilege_escalation", "severity": "critical"
        })
        updated = engine.get_container("org1", "c1")
        assert updated["security_score"] == 80

    def test_high_decrements_score_by_15(self, engine, container):
        engine.record_runtime_event("org1", {
            "container_id": "c1", "event_type": "exec_command", "severity": "high"
        })
        updated = engine.get_container("org1", "c1")
        assert updated["security_score"] == 85

    def test_medium_decrements_score_by_10(self, engine, container):
        engine.record_runtime_event("org1", {
            "container_id": "c1", "event_type": "file_write", "severity": "medium"
        })
        updated = engine.get_container("org1", "c1")
        assert updated["security_score"] == 90

    def test_low_decrements_score_by_5(self, engine, container):
        engine.record_runtime_event("org1", {
            "container_id": "c1", "event_type": "network_connection", "severity": "low"
        })
        updated = engine.get_container("org1", "c1")
        assert updated["security_score"] == 95

    def test_security_score_clamps_at_zero(self, engine):
        # Start with a low score container
        engine.register_container("org1", {
            "container_id": "c_low", "image_name": "nginx", "security_score": 5
        })
        engine.record_runtime_event("org1", {
            "container_id": "c_low", "event_type": "crypto_mining", "severity": "critical"
        })
        updated = engine.get_container("org1", "c_low")
        assert updated["security_score"] == 0

    def test_multiple_events_accumulate(self, engine, container):
        engine.record_runtime_event("org1", {
            "container_id": "c1", "event_type": "exec_command", "severity": "high"  # -15
        })
        engine.record_runtime_event("org1", {
            "container_id": "c1", "event_type": "file_write", "severity": "medium"  # -10
        })
        updated = engine.get_container("org1", "c1")
        assert updated["security_score"] == 75

    def test_all_event_types_valid(self, engine, container):
        valid_types = [
            "exec_command", "network_connection", "file_write", "privilege_escalation",
            "unexpected_process", "port_scan", "crypto_mining"
        ]
        for et in valid_types:
            evt = engine.record_runtime_event("org1", {
                "container_id": "c1", "event_type": et, "severity": "low"
            })
            assert evt["event_type"] == et


# ---------------------------------------------------------------------------
# list_events / update_event_status
# ---------------------------------------------------------------------------

class TestEventsListAndStatus:
    def test_list_events(self, engine, container):
        engine.record_runtime_event("org1", {
            "container_id": "c1", "event_type": "exec_command", "severity": "high"
        })
        events = engine.list_events("org1")
        assert len(events) == 1

    def test_filter_by_event_type(self, engine, container):
        engine.record_runtime_event("org1", {"container_id": "c1", "event_type": "exec_command", "severity": "low"})
        engine.record_runtime_event("org1", {"container_id": "c1", "event_type": "file_write", "severity": "low"})
        result = engine.list_events("org1", event_type="exec_command")
        assert all(r["event_type"] == "exec_command" for r in result)

    def test_filter_by_severity(self, engine, container):
        engine.record_runtime_event("org1", {"container_id": "c1", "event_type": "exec_command", "severity": "critical"})
        engine.record_runtime_event("org1", {"container_id": "c1", "event_type": "file_write", "severity": "low"})
        result = engine.list_events("org1", severity="critical")
        assert all(r["severity"] == "critical" for r in result)

    def test_filter_by_status(self, engine, container):
        evt = engine.record_runtime_event("org1", {
            "container_id": "c1", "event_type": "exec_command", "severity": "low"
        })
        engine.update_event_status("org1", evt["id"], "mitigated")
        detected = engine.list_events("org1", status="detected")
        assert all(r["status"] == "detected" for r in detected)

    def test_update_event_status(self, engine, container):
        evt = engine.record_runtime_event("org1", {
            "container_id": "c1", "event_type": "exec_command", "severity": "low"
        })
        updated = engine.update_event_status("org1", evt["id"], "investigated")
        assert updated["status"] == "investigated"

    def test_update_event_status_wrong_org_raises(self, engine, container):
        evt = engine.record_runtime_event("org1", {
            "container_id": "c1", "event_type": "exec_command", "severity": "low"
        })
        with pytest.raises(KeyError):
            engine.update_event_status("org2", evt["id"], "mitigated")

    def test_update_event_status_invalid_raises(self, engine, container):
        evt = engine.record_runtime_event("org1", {
            "container_id": "c1", "event_type": "exec_command", "severity": "low"
        })
        with pytest.raises(ValueError):
            engine.update_event_status("org1", evt["id"], "invalid_status")


# ---------------------------------------------------------------------------
# create_policy / list_policies
# ---------------------------------------------------------------------------

class TestPolicies:
    def test_create_policy(self, engine):
        policy = engine.create_policy("org1", {
            "policy_name": "Block Privileged",
            "policy_type": "block_privileged",
            "enforcement": "enforce",
        })
        assert policy["policy_name"] == "Block Privileged"
        assert policy["enforcement"] == "enforce"

    def test_missing_policy_name_raises(self, engine):
        with pytest.raises(ValueError, match="policy_name"):
            engine.create_policy("org1", {"policy_type": "block_privileged"})

    def test_invalid_policy_type_raises(self, engine):
        with pytest.raises(ValueError, match="policy_type"):
            engine.create_policy("org1", {"policy_name": "P", "policy_type": "invalid"})

    def test_invalid_enforcement_raises(self, engine):
        with pytest.raises(ValueError, match="enforcement"):
            engine.create_policy("org1", {
                "policy_name": "P", "policy_type": "block_privileged", "enforcement": "strict"
            })

    def test_list_policies(self, engine):
        engine.create_policy("org1", {"policy_name": "P1", "policy_type": "block_privileged", "enforcement": "audit"})
        engine.create_policy("org1", {"policy_name": "P2", "policy_type": "restrict_exec", "enforcement": "enforce"})
        result = engine.list_policies("org1")
        assert len(result) == 2

    def test_filter_by_enforcement(self, engine):
        engine.create_policy("org1", {"policy_name": "P1", "policy_type": "block_privileged", "enforcement": "audit"})
        engine.create_policy("org1", {"policy_name": "P2", "policy_type": "restrict_exec", "enforcement": "enforce"})
        result = engine.list_policies("org1", enforcement="audit")
        assert all(r["enforcement"] == "audit" for r in result)

    def test_policy_org_isolation(self, engine):
        engine.create_policy("org1", {"policy_name": "P1", "policy_type": "block_privileged"})
        engine.create_policy("org2", {"policy_name": "P2", "policy_type": "restrict_exec"})
        assert len(engine.list_policies("org1")) == 1
        assert len(engine.list_policies("org2")) == 1


# ---------------------------------------------------------------------------
# get_runtime_stats
# ---------------------------------------------------------------------------

class TestRuntimeStats:
    def test_empty_stats(self, engine):
        stats = engine.get_runtime_stats("org1")
        assert stats["total_containers"] == 0
        assert stats["running_containers"] == 0
        assert stats["total_events"] == 0
        assert stats["active_events"] == 0
        assert stats["critical_events"] == 0
        assert stats["avg_security_score"] == 0.0
        assert stats["by_event_type"] == {}

    def test_running_containers_count(self, engine):
        engine.register_container("org1", {"container_id": "c1", "image_name": "nginx", "runtime_status": "running"})
        engine.register_container("org1", {"container_id": "c2", "image_name": "redis", "runtime_status": "stopped"})
        stats = engine.get_runtime_stats("org1")
        assert stats["total_containers"] == 2
        assert stats["running_containers"] == 1

    def test_avg_security_score(self, engine):
        engine.register_container("org1", {"container_id": "c1", "image_name": "nginx", "security_score": 80})
        engine.register_container("org1", {"container_id": "c2", "image_name": "redis", "security_score": 60})
        stats = engine.get_runtime_stats("org1")
        assert stats["avg_security_score"] == 70.0

    def test_by_event_type_breakdown(self, engine, container):
        engine.record_runtime_event("org1", {"container_id": "c1", "event_type": "exec_command", "severity": "low"})
        engine.record_runtime_event("org1", {"container_id": "c1", "event_type": "exec_command", "severity": "low"})
        engine.record_runtime_event("org1", {"container_id": "c1", "event_type": "file_write", "severity": "low"})
        stats = engine.get_runtime_stats("org1")
        assert stats["by_event_type"]["exec_command"] == 2
        assert stats["by_event_type"]["file_write"] == 1

    def test_critical_events_count(self, engine, container):
        engine.record_runtime_event("org1", {"container_id": "c1", "event_type": "crypto_mining", "severity": "critical"})
        engine.record_runtime_event("org1", {"container_id": "c1", "event_type": "exec_command", "severity": "low"})
        stats = engine.get_runtime_stats("org1")
        assert stats["critical_events"] == 1

    def test_active_events_count(self, engine, container):
        evt = engine.record_runtime_event("org1", {"container_id": "c1", "event_type": "exec_command", "severity": "low"})
        engine.update_event_status("org1", evt["id"], "mitigated")
        engine.record_runtime_event("org1", {"container_id": "c1", "event_type": "file_write", "severity": "low"})
        stats = engine.get_runtime_stats("org1")
        assert stats["active_events"] == 1

    def test_stats_org_isolation(self, engine):
        engine.register_container("org1", {"container_id": "c1", "image_name": "nginx"})
        engine.register_container("org2", {"container_id": "c2", "image_name": "redis"})
        stats1 = engine.get_runtime_stats("org1")
        assert stats1["total_containers"] == 1
