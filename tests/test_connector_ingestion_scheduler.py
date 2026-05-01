"""Unit tests for ConnectorIngestionScheduler."""
from __future__ import annotations

import threading
import time
from unittest.mock import MagicMock, patch

import pytest

from core.connector_ingestion_scheduler import (
    ConnectorIngestionScheduler,
    _thehive_severity_to_str,
    _wazuh_level_to_severity,
)


# ---------------------------------------------------------------------------
# 1. Each connector failing must NOT crash collect_all_findings
# ---------------------------------------------------------------------------

def test_collect_handles_each_connector_failure():
    sched = ConnectorIngestionScheduler(org_id="acme", interval_s=60)
    boom = MagicMock(side_effect=RuntimeError("connector down"))
    # Patch all 10 collectors to raise
    targets = [
        "_collect_trivy", "_collect_semgrep", "_collect_snyk",
        "_collect_github_security", "_collect_aws_hub",
        "_collect_azure_defender", "_collect_gcp_scc",
        "_collect_wazuh", "_collect_thehive", "_collect_feed_fusion",
    ]
    for name in targets:
        setattr(sched, name, boom)
    result = sched.collect_all_findings()
    assert result == [], "must return [] when every collector raises"
    assert boom.call_count == len(targets)


# ---------------------------------------------------------------------------
# 2. Aggregation: 3 collectors returning 5/3/2 findings -> 10 total
# ---------------------------------------------------------------------------

def test_collect_aggregates_results():
    sched = ConnectorIngestionScheduler(org_id="acme", interval_s=60)
    sched._collect_trivy = MagicMock(return_value=[{"id": f"t{i}"} for i in range(5)])
    sched._collect_semgrep = MagicMock(return_value=[{"id": f"s{i}"} for i in range(3)])
    sched._collect_snyk = MagicMock(return_value=[{"id": f"k{i}"} for i in range(2)])
    # Force the rest to noop
    for name in (
        "_collect_github_security", "_collect_aws_hub",
        "_collect_azure_defender", "_collect_gcp_scc",
        "_collect_wazuh", "_collect_thehive", "_collect_feed_fusion",
    ):
        setattr(sched, name, MagicMock(return_value=[]))
    result = sched.collect_all_findings()
    assert len(result) == 10


# ---------------------------------------------------------------------------
# 3. _tick_once should call pipeline.run when findings present
# ---------------------------------------------------------------------------

def test_run_loop_calls_pipeline_when_findings():
    sched = ConnectorIngestionScheduler(org_id="acme", interval_s=60)
    fake_findings = [{"id": "x"}, {"id": "y"}]
    sched.collect_all_findings = MagicMock(return_value=fake_findings)
    fake_pipeline = MagicMock()
    sched._pipeline = fake_pipeline
    sched._tick_once()
    assert fake_pipeline.run.call_count == 1
    args, _ = fake_pipeline.run.call_args
    pi = args[0]
    assert pi.org_id == "acme"
    assert pi.findings == fake_findings


# ---------------------------------------------------------------------------
# 4. _tick_once should NOT call pipeline.run when collect returns []
# ---------------------------------------------------------------------------

def test_run_loop_skips_pipeline_when_empty():
    sched = ConnectorIngestionScheduler(org_id="acme", interval_s=60)
    sched.collect_all_findings = MagicMock(return_value=[])
    fake_pipeline = MagicMock()
    sched._pipeline = fake_pipeline
    sched._tick_once()
    fake_pipeline.run.assert_not_called()


# ---------------------------------------------------------------------------
# 5. stop() event terminates the loop quickly
# ---------------------------------------------------------------------------

def test_stop_event_terminates_loop():
    sched = ConnectorIngestionScheduler(org_id="acme", interval_s=5)
    sched.collect_all_findings = MagicMock(return_value=[])
    sched._pipeline = MagicMock()
    sched.start()
    assert sched._thread.is_alive()
    sched.stop()
    sched._thread.join(timeout=6)
    assert not sched._thread.is_alive(), "thread did not exit after stop()"


# ---------------------------------------------------------------------------
# 6. Wazuh severity mapping (parametric)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("level,expected", [
    (15, "critical"),
    (12, "critical"),
    (11, "high"),
    (8, "high"),
    (7, "medium"),
    (4, "medium"),
    (3, "low"),
    (0, "low"),
    (None, "low"),
    ("nope", "low"),
])
def test_wazuh_severity_mapping(level, expected):
    assert _wazuh_level_to_severity(level) == expected


# ---------------------------------------------------------------------------
# Bonus: TheHive severity mapping
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("sev,expected", [
    (1, "low"),
    (2, "medium"),
    (3, "high"),
    (4, "critical"),
    (None, "medium"),
    ("nope", "medium"),
])
def test_thehive_severity_mapping(sev, expected):
    assert _thehive_severity_to_str(sev) == expected
