"""Tests for CloudCostOptimizationEngine.detect_spend_anomalies.

Covers: empty org, Z-score spike detection, low-utilization overspend,
severity classification, org isolation, summary counts.

Z-score math notes:
  - With 5 equal-low costs + 1 spike => z_spike = 2.236 (>= 2.0 threshold)
  - With 10 equal-low costs + 1 spike => z_spike > 3.0 (>= critical 2.0*1.5=3.0)
  - With only 2 tools => Z-score path is skipped entirely
"""

from __future__ import annotations

import pytest

from core.cloud_cost_optimization_engine import CloudCostOptimizationEngine


@pytest.fixture
def engine(tmp_path):
    return CloudCostOptimizationEngine(db_path=str(tmp_path / "anomaly_test.db"))


@pytest.fixture
def org():
    return "org-anomaly-001"


# ---------------------------------------------------------------------------
# Empty org
# ---------------------------------------------------------------------------

class TestDetectSpendAnomaliesEmpty:
    def test_empty_org_returns_no_anomalies(self, engine, org):
        result = engine.detect_spend_anomalies(org)
        assert result["anomalies"] == []
        assert result["summary"]["z_score_spikes"] == 0
        assert result["summary"]["low_util_overspend"] == 0
        assert result["summary"]["total_anomaly_spend"] == 0.0
        assert result["org_mean_monthly_cost"] == 0.0
        assert result["detected_at"]


# ---------------------------------------------------------------------------
# Z-score spike detection
# ---------------------------------------------------------------------------

class TestZScoreSpikeDetection:
    def test_spike_flagged_above_threshold(self, engine, org):
        # 5 cheap tools + 1 spike => z_spike = 2.236 >= 2.0 threshold
        for i in range(5):
            engine.register_tool(org, f"Cheap{i}", monthly_cost=10.0)
        engine.register_tool(org, "Spike", monthly_cost=5000.0)
        result = engine.detect_spend_anomalies(org, z_threshold=2.0)
        spike_names = [a["tool_name"] for a in result["anomalies"] if a["reason"] == "z_score_spike"]
        assert "Spike" in spike_names
        assert result["summary"]["z_score_spikes"] >= 1

    def test_spike_severity_critical_at_1_5x_threshold(self, engine, org):
        # 10 cheap tools + 1 spike => z_spike > 3.0 = 2.0 * 1.5 => critical
        for i in range(10):
            engine.register_tool(org, f"Low{i}", monthly_cost=10.0)
        engine.register_tool(org, "HugeSpike", monthly_cost=5000.0)
        result = engine.detect_spend_anomalies(org, z_threshold=2.0)
        critical = [a for a in result["anomalies"] if a["severity"] == "critical" and a["reason"] == "z_score_spike"]
        assert any(a["tool_name"] == "HugeSpike" for a in critical)

    def test_no_spike_when_fewer_than_3_tools(self, engine, org):
        # With only 2 tools the Z-score path is skipped — no z_score_spike anomalies
        engine.register_tool(org, "A", monthly_cost=100.0)
        engine.register_tool(org, "B", monthly_cost=9000.0)
        result = engine.detect_spend_anomalies(org, z_threshold=2.0)
        z_spikes = [a for a in result["anomalies"] if a["reason"] == "z_score_spike"]
        assert z_spikes == []


# ---------------------------------------------------------------------------
# Low-utilization overspend
# ---------------------------------------------------------------------------

class TestLowUtilizationOverspend:
    def test_low_util_tool_flagged(self, engine, org):
        t = engine.register_tool(org, "Ghost", monthly_cost=800.0)
        engine.update_utilization(t["id"], org, 10.0)
        result = engine.detect_spend_anomalies(org, low_utilization_threshold=20.0)
        lu = [a for a in result["anomalies"] if a["reason"] == "low_util_overspend"]
        assert any(a["tool_name"] == "Ghost" for a in lu)
        assert result["summary"]["low_util_overspend"] >= 1

    def test_well_utilized_tool_not_flagged(self, engine, org):
        t = engine.register_tool(org, "Active", monthly_cost=800.0)
        engine.update_utilization(t["id"], org, 85.0)
        result = engine.detect_spend_anomalies(org, low_utilization_threshold=20.0)
        lu_names = [a["tool_name"] for a in result["anomalies"] if a["reason"] == "low_util_overspend"]
        assert "Active" not in lu_names

    def test_zero_cost_tool_not_flagged_as_low_util(self, engine, org):
        # Free tools with 0 utilization are not an overspend anomaly
        t = engine.register_tool(org, "FreeTool", monthly_cost=0.0)
        engine.update_utilization(t["id"], org, 0.0)
        result = engine.detect_spend_anomalies(org, low_utilization_threshold=20.0)
        lu_names = [a["tool_name"] for a in result["anomalies"] if a["reason"] == "low_util_overspend"]
        assert "FreeTool" not in lu_names


# ---------------------------------------------------------------------------
# Summary and org isolation
# ---------------------------------------------------------------------------

class TestSummaryAndIsolation:
    def test_total_anomaly_spend_sum(self, engine, org):
        t1 = engine.register_tool(org, "Ghost1", monthly_cost=300.0)
        t2 = engine.register_tool(org, "Ghost2", monthly_cost=700.0)
        engine.update_utilization(t1["id"], org, 5.0)
        engine.update_utilization(t2["id"], org, 5.0)
        result = engine.detect_spend_anomalies(org, low_utilization_threshold=20.0)
        # Both tools have low utilization and non-zero cost => both flagged
        assert result["summary"]["total_anomaly_spend"] == pytest.approx(1000.0, rel=1e-3)

    def test_org_isolation(self, engine, org):
        org2 = "org-anomaly-002"
        t = engine.register_tool(org, "Ghost", monthly_cost=999.0)
        engine.update_utilization(t["id"], org, 2.0)
        result = engine.detect_spend_anomalies(org2, low_utilization_threshold=20.0)
        assert result["anomalies"] == []
        assert result["org_mean_monthly_cost"] == 0.0
