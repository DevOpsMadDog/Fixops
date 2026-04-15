"""Tests for ContainerSecurityPostureEngine — ALDECI."""

from __future__ import annotations

import pytest

from core.container_security_posture_engine import ContainerSecurityPostureEngine


@pytest.fixture
def engine(tmp_path):
    return ContainerSecurityPostureEngine(db_path=str(tmp_path / "csp.db"))


# ---------------------------------------------------------------------------
# register_cluster — validation
# ---------------------------------------------------------------------------

def test_register_cluster_minimal(engine):
    c = engine.register_cluster("org1", {"name": "prod-cluster"})
    assert c["id"]
    assert c["org_id"] == "org1"
    assert c["name"] == "prod-cluster"
    assert c["runtime"] == "docker"
    assert c["posture_score"] == 100.0
    assert c["status"] == "active"
    assert c["created_at"]


def test_register_cluster_all_fields(engine):
    c = engine.register_cluster("org1", {
        "name": "k8s-prod",
        "runtime": "containerd",
        "version": "1.28.0",
        "node_count": 10,
        "namespace_count": 5,
    })
    assert c["runtime"] == "containerd"
    assert c["node_count"] == 10
    assert c["namespace_count"] == 5


def test_register_cluster_missing_name_raises(engine):
    with pytest.raises(ValueError, match="name"):
        engine.register_cluster("org1", {"runtime": "docker"})


def test_register_cluster_empty_name_raises(engine):
    with pytest.raises(ValueError, match="name"):
        engine.register_cluster("org1", {"name": "   "})


def test_register_cluster_invalid_runtime_raises(engine):
    with pytest.raises(ValueError, match="runtime"):
        engine.register_cluster("org1", {"name": "c1", "runtime": "lxd"})


@pytest.mark.parametrize("rt", ["docker", "containerd", "cri-o", "podman"])
def test_register_cluster_all_valid_runtimes(engine, rt):
    c = engine.register_cluster("org1", {"name": f"cluster-{rt}", "runtime": rt})
    assert c["runtime"] == rt


# ---------------------------------------------------------------------------
# list_clusters / get_cluster
# ---------------------------------------------------------------------------

def test_list_clusters_empty(engine):
    assert engine.list_clusters("org1") == []


def test_list_clusters_org_isolation(engine):
    engine.register_cluster("org1", {"name": "C1"})
    engine.register_cluster("org2", {"name": "C2"})
    assert len(engine.list_clusters("org1")) == 1
    assert len(engine.list_clusters("org2")) == 1


def test_list_clusters_filter_runtime(engine):
    engine.register_cluster("org1", {"name": "C1", "runtime": "docker"})
    engine.register_cluster("org1", {"name": "C2", "runtime": "containerd"})
    result = engine.list_clusters("org1", runtime="docker")
    assert len(result) == 1
    assert result[0]["runtime"] == "docker"


def test_get_cluster_exists(engine):
    c = engine.register_cluster("org1", {"name": "C1"})
    fetched = engine.get_cluster("org1", c["id"])
    assert fetched["id"] == c["id"]


def test_get_cluster_not_found_returns_none(engine):
    assert engine.get_cluster("org1", "nonexistent") is None


def test_get_cluster_wrong_org_returns_none(engine):
    c = engine.register_cluster("org1", {"name": "C1"})
    assert engine.get_cluster("org2", c["id"]) is None


# ---------------------------------------------------------------------------
# record_finding — validation & posture score deduction
# ---------------------------------------------------------------------------

def test_record_finding_missing_cluster_id_raises(engine):
    with pytest.raises(ValueError, match="cluster_id"):
        engine.record_finding("org1", {"finding_type": "misconfiguration", "severity": "high"})


def test_record_finding_invalid_finding_type_raises(engine):
    c = engine.register_cluster("org1", {"name": "C1"})
    with pytest.raises(ValueError, match="finding_type"):
        engine.record_finding("org1", {"cluster_id": c["id"], "finding_type": "bad_type", "severity": "high"})


def test_record_finding_invalid_severity_raises(engine):
    c = engine.register_cluster("org1", {"name": "C1"})
    with pytest.raises(ValueError, match="severity"):
        engine.record_finding("org1", {"cluster_id": c["id"], "finding_type": "misconfiguration", "severity": "extreme"})


@pytest.mark.parametrize("ft", [
    "image_vuln", "misconfiguration", "secret_exposure",
    "privilege_escalation", "network_policy", "runtime_anomaly"
])
def test_record_finding_all_valid_types(engine, ft):
    c = engine.register_cluster("org1", {"name": "C1"})
    f = engine.record_finding("org1", {
        "cluster_id": c["id"],
        "finding_type": ft,
        "severity": "medium",
    })
    assert f["finding_type"] == ft
    assert f["status"] == "open"


def test_record_finding_critical_decrements_score_by_8(engine):
    c = engine.register_cluster("org1", {"name": "C1"})
    engine.record_finding("org1", {
        "cluster_id": c["id"],
        "finding_type": "misconfiguration",
        "severity": "critical",
    })
    updated = engine.get_cluster("org1", c["id"])
    assert updated["posture_score"] == 92.0


def test_record_finding_high_decrements_by_4(engine):
    c = engine.register_cluster("org1", {"name": "C1"})
    engine.record_finding("org1", {"cluster_id": c["id"], "finding_type": "image_vuln", "severity": "high"})
    updated = engine.get_cluster("org1", c["id"])
    assert updated["posture_score"] == 96.0


def test_record_finding_medium_decrements_by_2(engine):
    c = engine.register_cluster("org1", {"name": "C1"})
    engine.record_finding("org1", {"cluster_id": c["id"], "finding_type": "misconfiguration", "severity": "medium"})
    updated = engine.get_cluster("org1", c["id"])
    assert updated["posture_score"] == 98.0


def test_record_finding_low_decrements_by_1(engine):
    c = engine.register_cluster("org1", {"name": "C1"})
    engine.record_finding("org1", {"cluster_id": c["id"], "finding_type": "network_policy", "severity": "low"})
    updated = engine.get_cluster("org1", c["id"])
    assert updated["posture_score"] == 99.0


def test_record_finding_info_no_score_change(engine):
    c = engine.register_cluster("org1", {"name": "C1"})
    engine.record_finding("org1", {"cluster_id": c["id"], "finding_type": "misconfiguration", "severity": "info"})
    updated = engine.get_cluster("org1", c["id"])
    assert updated["posture_score"] == 100.0


def test_record_finding_score_floored_at_zero(engine):
    c = engine.register_cluster("org1", {"name": "C1"})
    # 13 critical findings = -104 → clamped to 0
    for _ in range(13):
        engine.record_finding("org1", {
            "cluster_id": c["id"],
            "finding_type": "misconfiguration",
            "severity": "critical",
        })
    updated = engine.get_cluster("org1", c["id"])
    assert updated["posture_score"] == 0.0


def test_record_finding_cumulative_deductions(engine):
    c = engine.register_cluster("org1", {"name": "C1"})
    engine.record_finding("org1", {"cluster_id": c["id"], "finding_type": "image_vuln", "severity": "critical"})  # -8 → 92
    engine.record_finding("org1", {"cluster_id": c["id"], "finding_type": "misconfiguration", "severity": "high"})  # -4 → 88
    engine.record_finding("org1", {"cluster_id": c["id"], "finding_type": "network_policy", "severity": "medium"})  # -2 → 86
    updated = engine.get_cluster("org1", c["id"])
    assert updated["posture_score"] == 86.0


# ---------------------------------------------------------------------------
# list_findings
# ---------------------------------------------------------------------------

def test_list_findings_empty(engine):
    assert engine.list_findings("org1") == []


def test_list_findings_filter_cluster_id(engine):
    c1 = engine.register_cluster("org1", {"name": "C1"})
    c2 = engine.register_cluster("org1", {"name": "C2"})
    engine.record_finding("org1", {"cluster_id": c1["id"], "finding_type": "misconfiguration", "severity": "high"})
    engine.record_finding("org1", {"cluster_id": c2["id"], "finding_type": "image_vuln", "severity": "low"})
    result = engine.list_findings("org1", cluster_id=c1["id"])
    assert len(result) == 1


def test_list_findings_filter_finding_type(engine):
    c = engine.register_cluster("org1", {"name": "C1"})
    engine.record_finding("org1", {"cluster_id": c["id"], "finding_type": "misconfiguration", "severity": "high"})
    engine.record_finding("org1", {"cluster_id": c["id"], "finding_type": "image_vuln", "severity": "low"})
    result = engine.list_findings("org1", finding_type="image_vuln")
    assert len(result) == 1


def test_list_findings_filter_severity(engine):
    c = engine.register_cluster("org1", {"name": "C1"})
    engine.record_finding("org1", {"cluster_id": c["id"], "finding_type": "misconfiguration", "severity": "critical"})
    engine.record_finding("org1", {"cluster_id": c["id"], "finding_type": "network_policy", "severity": "low"})
    result = engine.list_findings("org1", severity="critical")
    assert len(result) == 1


def test_list_findings_filter_status(engine):
    c = engine.register_cluster("org1", {"name": "C1"})
    f = engine.record_finding("org1", {"cluster_id": c["id"], "finding_type": "misconfiguration", "severity": "high"})
    engine.resolve_finding("org1", f["id"], "Fixed in manifest")
    result_open = engine.list_findings("org1", status="open")
    result_resolved = engine.list_findings("org1", status="resolved")
    assert len(result_open) == 0
    assert len(result_resolved) == 1


# ---------------------------------------------------------------------------
# resolve_finding
# ---------------------------------------------------------------------------

def test_resolve_finding_sets_resolved_status(engine):
    c = engine.register_cluster("org1", {"name": "C1"})
    f = engine.record_finding("org1", {"cluster_id": c["id"], "finding_type": "image_vuln", "severity": "high"})
    resolved = engine.resolve_finding("org1", f["id"], "Patched base image")
    assert resolved["status"] == "resolved"
    assert resolved["resolved_at"]
    assert resolved["resolution"] == "Patched base image"


def test_resolve_finding_restores_posture_score(engine):
    c = engine.register_cluster("org1", {"name": "C1"})
    f = engine.record_finding("org1", {"cluster_id": c["id"], "finding_type": "misconfiguration", "severity": "critical"})
    # score should be 92 now
    mid = engine.get_cluster("org1", c["id"])
    assert mid["posture_score"] == 92.0

    engine.resolve_finding("org1", f["id"], "Fixed")
    restored = engine.get_cluster("org1", c["id"])
    assert restored["posture_score"] == 100.0


def test_resolve_finding_score_capped_at_100(engine):
    c = engine.register_cluster("org1", {"name": "C1"})
    # Record and immediately resolve low-severity — score stays at 100
    f = engine.record_finding("org1", {"cluster_id": c["id"], "finding_type": "network_policy", "severity": "low"})
    engine.resolve_finding("org1", f["id"], "OK")
    restored = engine.get_cluster("org1", c["id"])
    assert restored["posture_score"] == 100.0


def test_resolve_finding_not_found_raises(engine):
    with pytest.raises(KeyError):
        engine.resolve_finding("org1", "nonexistent", "N/A")


def test_resolve_finding_wrong_org_raises(engine):
    c = engine.register_cluster("org1", {"name": "C1"})
    f = engine.record_finding("org1", {"cluster_id": c["id"], "finding_type": "image_vuln", "severity": "high"})
    with pytest.raises(KeyError):
        engine.resolve_finding("org2", f["id"], "N/A")


def test_resolve_info_finding_score_unchanged(engine):
    c = engine.register_cluster("org1", {"name": "C1"})
    f = engine.record_finding("org1", {"cluster_id": c["id"], "finding_type": "misconfiguration", "severity": "info"})
    engine.resolve_finding("org1", f["id"], "No change needed")
    updated = engine.get_cluster("org1", c["id"])
    assert updated["posture_score"] == 100.0


# ---------------------------------------------------------------------------
# get_posture_stats
# ---------------------------------------------------------------------------

def test_get_posture_stats_empty(engine):
    stats = engine.get_posture_stats("org1")
    assert stats["total_clusters"] == 0
    assert stats["avg_posture_score"] == 0.0
    assert stats["total_findings"] == 0
    assert stats["open_findings"] == 0
    assert stats["critical_findings"] == 0
    assert stats["clusters_at_risk"] == 0


def test_get_posture_stats_counts(engine):
    c = engine.register_cluster("org1", {"name": "C1"})
    engine.record_finding("org1", {"cluster_id": c["id"], "finding_type": "misconfiguration", "severity": "critical"})
    engine.record_finding("org1", {"cluster_id": c["id"], "finding_type": "image_vuln", "severity": "high"})
    stats = engine.get_posture_stats("org1")
    assert stats["total_clusters"] == 1
    assert stats["total_findings"] == 2
    assert stats["open_findings"] == 2
    assert stats["critical_findings"] == 1


def test_get_posture_stats_by_finding_type(engine):
    c = engine.register_cluster("org1", {"name": "C1"})
    engine.record_finding("org1", {"cluster_id": c["id"], "finding_type": "misconfiguration", "severity": "medium"})
    engine.record_finding("org1", {"cluster_id": c["id"], "finding_type": "misconfiguration", "severity": "low"})
    engine.record_finding("org1", {"cluster_id": c["id"], "finding_type": "image_vuln", "severity": "high"})
    stats = engine.get_posture_stats("org1")
    assert stats["by_finding_type"]["misconfiguration"] == 2
    assert stats["by_finding_type"]["image_vuln"] == 1


def test_get_posture_stats_clusters_at_risk(engine):
    c = engine.register_cluster("org1", {"name": "C1"})
    # Need score < 70: 4 critical findings = -32 → 68
    for _ in range(4):
        engine.record_finding("org1", {
            "cluster_id": c["id"],
            "finding_type": "misconfiguration",
            "severity": "critical",
        })
    stats = engine.get_posture_stats("org1")
    assert stats["clusters_at_risk"] == 1


def test_get_posture_stats_avg_posture_score(engine):
    c1 = engine.register_cluster("org1", {"name": "C1"})
    c2 = engine.register_cluster("org1", {"name": "C2"})
    # c1: score stays 100, c2: -8 = 92 → avg = 96
    engine.record_finding("org1", {"cluster_id": c2["id"], "finding_type": "misconfiguration", "severity": "critical"})
    stats = engine.get_posture_stats("org1")
    assert stats["avg_posture_score"] == 96.0


def test_get_posture_stats_open_findings_decrements_on_resolve(engine):
    c = engine.register_cluster("org1", {"name": "C1"})
    f = engine.record_finding("org1", {"cluster_id": c["id"], "finding_type": "image_vuln", "severity": "high"})
    stats_before = engine.get_posture_stats("org1")
    assert stats_before["open_findings"] == 1

    engine.resolve_finding("org1", f["id"], "Fixed")
    stats_after = engine.get_posture_stats("org1")
    assert stats_after["open_findings"] == 0


def test_get_posture_stats_org_isolation(engine):
    c1 = engine.register_cluster("org1", {"name": "C1"})
    c2 = engine.register_cluster("org2", {"name": "C2"})
    engine.record_finding("org1", {"cluster_id": c1["id"], "finding_type": "misconfiguration", "severity": "critical"})
    stats1 = engine.get_posture_stats("org1")
    stats2 = engine.get_posture_stats("org2")
    assert stats1["total_findings"] == 1
    assert stats2["total_findings"] == 0
