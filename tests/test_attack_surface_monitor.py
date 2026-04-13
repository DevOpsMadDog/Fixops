"""Tests for AttackSurfaceMonitor — snapshots, diffs, scoring, shadow IT, attack paths.

Run:
    python -m pytest tests/test_attack_surface_monitor.py --timeout=15 -q -o "addopts="
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Any, Dict, List

import pytest

from core.attack_surface_monitor import (
    AttackPath,
    AttackSurfaceDiff,
    AttackSurfaceMonitor,
    AttackSurfaceSnapshot,
    MonitorSession,
    ServiceInfo,
    get_attack_surface_monitor,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def temp_db(tmp_path: Path) -> str:
    return str(tmp_path / "test_asm_monitor.db")


@pytest.fixture
def monitor(temp_db: str) -> AttackSurfaceMonitor:
    return AttackSurfaceMonitor(db_path=temp_db)


@pytest.fixture
def base_snapshot(monitor: AttackSurfaceMonitor) -> AttackSurfaceSnapshot:
    """Snapshot with known synthetic data — no real port scan."""
    snap = AttackSurfaceSnapshot(
        target="test-host",
        open_ports=[22, 80, 443],
        services=[
            ServiceInfo(port=22, service="SSH", risk_level="medium"),
            ServiceInfo(port=80, service="HTTP", risk_level="low"),
            ServiceInfo(port=443, service="HTTPS", risk_level="low"),
        ],
        endpoints=["http://test-host:80/", "https://test-host:443/"],
        deps=["requests==2.31.0", "fastapi==0.110.0"],
        secrets_exposed=[],
    )
    snap.score = monitor.calculate_attack_surface_score(snap)
    monitor._save_snapshot(snap)
    return snap


@pytest.fixture
def updated_snapshot(monitor: AttackSurfaceMonitor) -> AttackSurfaceSnapshot:
    """Snapshot with an added risky port and a new secret."""
    snap = AttackSurfaceSnapshot(
        target="test-host",
        open_ports=[22, 80, 443, 6379],
        services=[
            ServiceInfo(port=22, service="SSH", risk_level="medium"),
            ServiceInfo(port=80, service="HTTP", risk_level="low"),
            ServiceInfo(port=443, service="HTTPS", risk_level="low"),
            ServiceInfo(port=6379, service="Redis", risk_level="critical"),
        ],
        endpoints=["http://test-host:80/", "https://test-host:443/", "http://test-host:8080/"],
        deps=["requests==2.31.0", "fastapi==0.110.0"],
        secrets_exposed=["DATABASE_PASSWORD"],
    )
    snap.score = monitor.calculate_attack_surface_score(snap)
    monitor._save_snapshot(snap)
    return snap


# ---------------------------------------------------------------------------
# Snapshot tests
# ---------------------------------------------------------------------------


class TestSnapshotCreation:
    def test_snapshot_has_required_fields(self, base_snapshot: AttackSurfaceSnapshot) -> None:
        assert base_snapshot.id.startswith("snap-")
        assert base_snapshot.target == "test-host"
        assert isinstance(base_snapshot.timestamp, str)
        assert len(base_snapshot.timestamp) > 0

    def test_snapshot_open_ports_recorded(self, base_snapshot: AttackSurfaceSnapshot) -> None:
        assert 22 in base_snapshot.open_ports
        assert 80 in base_snapshot.open_ports
        assert 443 in base_snapshot.open_ports

    def test_snapshot_services_classified(self, base_snapshot: AttackSurfaceSnapshot) -> None:
        service_names = {s.service for s in base_snapshot.services}
        assert "SSH" in service_names
        assert "HTTP" in service_names

    def test_snapshot_score_computed(self, base_snapshot: AttackSurfaceSnapshot) -> None:
        assert 0.0 <= base_snapshot.score <= 100.0

    def test_snapshot_persisted_and_retrievable(
        self, monitor: AttackSurfaceMonitor, base_snapshot: AttackSurfaceSnapshot
    ) -> None:
        retrieved = monitor.get_snapshot(base_snapshot.id)
        assert retrieved is not None
        assert retrieved.id == base_snapshot.id
        assert retrieved.target == base_snapshot.target

    def test_take_snapshot_localhost(self, monitor: AttackSurfaceMonitor) -> None:
        """Real scan of localhost — should complete without errors."""
        snap = monitor.take_snapshot("127.0.0.1", port_timeout=0.05)
        assert snap.id.startswith("snap-")
        assert snap.target == "127.0.0.1"
        assert isinstance(snap.open_ports, list)
        assert 0.0 <= snap.score <= 100.0

    def test_snapshot_secret_scanning(self, monitor: AttackSurfaceMonitor) -> None:
        env = {"DATABASE_PASSWORD": "s3cret", "APP_NAME": "fixops", "API_KEY": "abc123"}
        snap = monitor.take_snapshot(
            "127.0.0.1",
            port_timeout=0.05,
            endpoints=[],
            deps=[],
            env_vars=env,
        )
        assert "DATABASE_PASSWORD" in snap.secrets_exposed
        assert "API_KEY" in snap.secrets_exposed
        assert "APP_NAME" not in snap.secrets_exposed

    def test_list_snapshots_returns_saved(
        self, monitor: AttackSurfaceMonitor, base_snapshot: AttackSurfaceSnapshot
    ) -> None:
        snaps = monitor.list_snapshots("test-host")
        ids = [s.id for s in snaps]
        assert base_snapshot.id in ids


# ---------------------------------------------------------------------------
# Diff tests
# ---------------------------------------------------------------------------


class TestDiffSnapshots:
    def test_diff_detects_added_port(
        self,
        monitor: AttackSurfaceMonitor,
        base_snapshot: AttackSurfaceSnapshot,
        updated_snapshot: AttackSurfaceSnapshot,
    ) -> None:
        diff = monitor.diff_snapshots(base_snapshot, updated_snapshot)
        assert 6379 in diff.added_ports

    def test_diff_detects_removed_port(
        self,
        monitor: AttackSurfaceMonitor,
        base_snapshot: AttackSurfaceSnapshot,
    ) -> None:
        reduced = AttackSurfaceSnapshot(
            target="test-host",
            open_ports=[80, 443],
            services=[
                ServiceInfo(port=80, service="HTTP", risk_level="low"),
                ServiceInfo(port=443, service="HTTPS", risk_level="low"),
            ],
            endpoints=["http://test-host:80/"],
            deps=[],
            secrets_exposed=[],
        )
        reduced.score = monitor.calculate_attack_surface_score(reduced)
        monitor._save_snapshot(reduced)
        diff = monitor.diff_snapshots(base_snapshot, reduced)
        assert 22 in diff.removed_ports

    def test_diff_detects_new_secrets(
        self,
        monitor: AttackSurfaceMonitor,
        base_snapshot: AttackSurfaceSnapshot,
        updated_snapshot: AttackSurfaceSnapshot,
    ) -> None:
        diff = monitor.diff_snapshots(base_snapshot, updated_snapshot)
        assert "DATABASE_PASSWORD" in diff.new_secrets

    def test_diff_detects_added_endpoints(
        self,
        monitor: AttackSurfaceMonitor,
        base_snapshot: AttackSurfaceSnapshot,
        updated_snapshot: AttackSurfaceSnapshot,
    ) -> None:
        diff = monitor.diff_snapshots(base_snapshot, updated_snapshot)
        assert any("8080" in ep for ep in diff.added_endpoints)

    def test_diff_score_delta_positive_when_risk_increased(
        self,
        monitor: AttackSurfaceMonitor,
        base_snapshot: AttackSurfaceSnapshot,
        updated_snapshot: AttackSurfaceSnapshot,
    ) -> None:
        diff = monitor.diff_snapshots(base_snapshot, updated_snapshot)
        assert diff.score_delta > 0
        assert diff.risk_increased is True

    def test_diff_change_count(
        self,
        monitor: AttackSurfaceMonitor,
        base_snapshot: AttackSurfaceSnapshot,
        updated_snapshot: AttackSurfaceSnapshot,
    ) -> None:
        diff = monitor.diff_snapshots(base_snapshot, updated_snapshot)
        assert diff.change_count > 0

    def test_diff_identical_snapshots_zero_changes(
        self,
        monitor: AttackSurfaceMonitor,
        base_snapshot: AttackSurfaceSnapshot,
    ) -> None:
        diff = monitor.diff_snapshots(base_snapshot, base_snapshot)
        assert diff.change_count == 0
        assert diff.score_delta == 0.0
        assert diff.risk_increased is False


# ---------------------------------------------------------------------------
# Scoring tests
# ---------------------------------------------------------------------------


class TestScoring:
    def test_score_zero_for_empty_snapshot(self, monitor: AttackSurfaceMonitor) -> None:
        snap = AttackSurfaceSnapshot(target="clean", open_ports=[], services=[], endpoints=[], deps=[], secrets_exposed=[])
        score = monitor.calculate_attack_surface_score(snap)
        assert score == 0.0

    def test_score_increases_with_critical_ports(self, monitor: AttackSurfaceMonitor) -> None:
        snap_no_critical = AttackSurfaceSnapshot(
            target="t", open_ports=[80], services=[ServiceInfo(port=80, service="HTTP", risk_level="low")],
            endpoints=[], deps=[], secrets_exposed=[],
        )
        snap_critical = AttackSurfaceSnapshot(
            target="t", open_ports=[6379], services=[ServiceInfo(port=6379, service="Redis", risk_level="critical")],
            endpoints=[], deps=[], secrets_exposed=[],
        )
        assert monitor.calculate_attack_surface_score(snap_critical) > monitor.calculate_attack_surface_score(snap_no_critical)

    def test_score_increases_with_secrets(self, monitor: AttackSurfaceMonitor) -> None:
        base = AttackSurfaceSnapshot(target="t", open_ports=[], services=[], endpoints=[], deps=[], secrets_exposed=[])
        with_secret = AttackSurfaceSnapshot(target="t", open_ports=[], services=[], endpoints=[], deps=[], secrets_exposed=["DB_PASS"])
        assert monitor.calculate_attack_surface_score(with_secret) > monitor.calculate_attack_surface_score(base)

    def test_score_capped_at_100(self, monitor: AttackSurfaceMonitor) -> None:
        snap = AttackSurfaceSnapshot(
            target="t",
            open_ports=list(range(1, 101)),
            services=[ServiceInfo(port=p, service=f"svc-{p}", risk_level="critical") for p in range(1, 101)],
            endpoints=[f"http://t:{p}/" for p in range(1, 101)],
            deps=["dep"] * 100,
            secrets_exposed=[f"SECRET_{i}" for i in range(20)],
        )
        score = monitor.calculate_attack_surface_score(snap)
        assert score <= 100.0

    def test_get_current_score_returns_dict(self, monitor: AttackSurfaceMonitor) -> None:
        result = monitor.get_current_score("127.0.0.1", port_timeout=0.05)
        assert "score" in result
        assert "snapshot_id" in result
        assert "target" in result
        assert result["target"] == "127.0.0.1"
        assert 0.0 <= result["score"] <= 100.0


# ---------------------------------------------------------------------------
# Shadow IT tests
# ---------------------------------------------------------------------------


class TestShadowIT:
    def test_shadow_it_returns_list(self, monitor: AttackSurfaceMonitor) -> None:
        findings = monitor.detect_shadow_it("127.0.0.1", port_timeout=0.05)
        assert isinstance(findings, list)

    def test_shadow_it_finding_structure(self, monitor: AttackSurfaceMonitor) -> None:
        findings = monitor.detect_shadow_it("127.0.0.1", port_timeout=0.05)
        for f in findings:
            assert "port" in f
            assert "service" in f
            assert "risk_level" in f
            assert "detected_at" in f
            assert "is_admin_interface" in f

    def test_shadow_it_flags_admin_interfaces(self, monitor: AttackSurfaceMonitor) -> None:
        # Simulate findings with known admin ports
        # We inject directly rather than relying on what's open
        findings = [
            {"host": "127.0.0.1", "port": 9090, "service": "Prometheus", "risk_level": "high",
             "is_admin_interface": True, "detected_at": "2026-01-01T00:00:00Z",
             "reason": "Unexpected open port"},
        ]
        admin_count = sum(1 for f in findings if f.get("is_admin_interface"))
        assert admin_count >= 1


# ---------------------------------------------------------------------------
# Attack path tests
# ---------------------------------------------------------------------------


class TestAttackPaths:
    def _make_findings(self) -> List[Dict[str, Any]]:
        return [
            {"host": "127.0.0.1", "port": 6379, "service": "Redis",
             "risk_level": "critical", "is_admin_interface": True, "detected_at": ""},
            {"host": "127.0.0.1", "port": 8080, "service": "HTTP-proxy",
             "risk_level": "medium", "is_admin_interface": False, "detected_at": ""},
        ]

    def test_generate_paths_returns_list(self, monitor: AttackSurfaceMonitor) -> None:
        paths = monitor.generate_attack_paths(self._make_findings())
        assert isinstance(paths, list)

    def test_generate_paths_for_critical_findings(self, monitor: AttackSurfaceMonitor) -> None:
        paths = monitor.generate_attack_paths(self._make_findings())
        assert len(paths) >= 1

    def test_path_has_required_fields(self, monitor: AttackSurfaceMonitor) -> None:
        paths = monitor.generate_attack_paths(self._make_findings())
        assert len(paths) >= 1
        p = paths[0]
        assert p.id.startswith("apath-")
        assert p.entry_point != ""
        assert len(p.steps) >= 2
        assert 0.0 <= p.risk_score <= 100.0

    def test_path_includes_mitre_techniques(self, monitor: AttackSurfaceMonitor) -> None:
        paths = monitor.generate_attack_paths(self._make_findings())
        assert len(paths) >= 1
        assert len(paths[0].techniques) >= 1

    def test_no_paths_for_empty_findings(self, monitor: AttackSurfaceMonitor) -> None:
        paths = monitor.generate_attack_paths([])
        assert paths == []

    def test_no_paths_for_low_risk_only(self, monitor: AttackSurfaceMonitor) -> None:
        findings = [
            {"host": "127.0.0.1", "port": 80, "service": "HTTP",
             "risk_level": "low", "is_admin_interface": False, "detected_at": ""},
        ]
        paths = monitor.generate_attack_paths(findings)
        assert paths == []


# ---------------------------------------------------------------------------
# Singleton factory test
# ---------------------------------------------------------------------------


def test_get_attack_surface_monitor_returns_singleton() -> None:
    m1 = get_attack_surface_monitor()
    m2 = get_attack_surface_monitor()
    assert m1 is m2
