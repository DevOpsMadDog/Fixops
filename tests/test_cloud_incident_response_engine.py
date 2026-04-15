"""Tests for CloudIncidentResponseEngine.

Covers:
- create_incident: valid, invalid provider/type/severity, JSON list fields
- contain_incident: status=contained, contained_at set, containment_time_mins computed, not found, org isolation
- resolve_incident: status=resolved, resolved_at set, resolution_time_mins computed, root_cause stored
- add_containment_action: valid, invalid action_type, automated flag
- complete_action: status=completed, executed_at set, result stored, not found, org isolation
- create_playbook: valid, invalid provider/type, steps as list, execution_count=0
- execute_playbook: execution_count++, not found, org isolation
- list_playbooks: org isolation
- get_incident: returns actions + matching playbooks
- list_incidents: filter by status and cloud_provider, org isolation
- get_ir_metrics: total, by_status, by_provider, avg_containment_mins, avg_resolution_mins, open_critical
- Multi-tenant isolation throughout
"""
from __future__ import annotations

import os
import time

import pytest

os.environ.setdefault("FIXOPS_MODE", "dev")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")

from core.cloud_incident_response_engine import CloudIncidentResponseEngine

ORG = "org-cir-test"
ORG2 = "org-cir-other"


@pytest.fixture
def engine(tmp_path):
    return CloudIncidentResponseEngine(db_path=str(tmp_path / "cir.db"))


def _incident(overrides=None):
    base = {
        "incident_name": "S3 Breach",
        "cloud_provider": "aws",
        "incident_type": "data-breach",
        "severity": "high",
    }
    if overrides:
        base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# create_incident
# ---------------------------------------------------------------------------

class TestCreateIncident:
    def test_returns_dict_with_id(self, engine):
        inc = engine.create_incident(ORG, **_incident())
        assert "id" in inc and len(inc["id"]) == 36

    def test_status_is_detected(self, engine):
        inc = engine.create_incident(ORG, **_incident())
        assert inc["status"] == "detected"

    def test_blast_radius_unknown(self, engine):
        inc = engine.create_incident(ORG, **_incident())
        assert inc["blast_radius"] == "unknown"

    def test_affected_services_stored_as_list(self, engine):
        inc = engine.create_incident(ORG, **_incident(), affected_services=["s3", "ec2"])
        assert inc["affected_services"] == ["s3", "ec2"]

    def test_affected_regions_stored_as_list(self, engine):
        inc = engine.create_incident(ORG, **_incident(), affected_regions=["us-east-1"])
        assert inc["affected_regions"] == ["us-east-1"]

    def test_invalid_provider_raises(self, engine):
        with pytest.raises(ValueError, match="cloud_provider"):
            engine.create_incident(ORG, "Test", cloud_provider="bogus", incident_type="data-breach", severity="high")

    def test_invalid_incident_type_raises(self, engine):
        with pytest.raises(ValueError, match="incident_type"):
            engine.create_incident(ORG, "Test", cloud_provider="aws", incident_type="unknown-type", severity="high")

    def test_invalid_severity_raises(self, engine):
        with pytest.raises(ValueError, match="severity"):
            engine.create_incident(ORG, "Test", cloud_provider="aws", incident_type="ddos", severity="extreme")

    def test_detected_at_set(self, engine):
        inc = engine.create_incident(ORG, **_incident())
        assert inc["detected_at"] != ""

    def test_org_id_stored(self, engine):
        inc = engine.create_incident(ORG, **_incident())
        assert inc["org_id"] == ORG


# ---------------------------------------------------------------------------
# contain_incident
# ---------------------------------------------------------------------------

class TestContainIncident:
    def test_status_becomes_contained(self, engine):
        inc = engine.create_incident(ORG, **_incident())
        result = engine.contain_incident(inc["id"], ORG)
        assert result["status"] == "contained"

    def test_contained_at_set(self, engine):
        inc = engine.create_incident(ORG, **_incident())
        result = engine.contain_incident(inc["id"], ORG)
        assert result["contained_at"] != ""

    def test_blast_radius_stored(self, engine):
        inc = engine.create_incident(ORG, **_incident())
        result = engine.contain_incident(inc["id"], ORG, blast_radius="3 accounts")
        assert result["blast_radius"] == "3 accounts"

    def test_containment_time_mins_nonnegative(self, engine):
        inc = engine.create_incident(ORG, **_incident())
        result = engine.contain_incident(inc["id"], ORG)
        # julianday computation — may be 0.0 when same-second but should be >= 0
        assert result["containment_time_mins"] >= 0.0

    def test_not_found_raises(self, engine):
        with pytest.raises(KeyError):
            engine.contain_incident("nonexistent", ORG)

    def test_org_isolation(self, engine):
        inc = engine.create_incident(ORG, **_incident())
        with pytest.raises(KeyError):
            engine.contain_incident(inc["id"], ORG2)


# ---------------------------------------------------------------------------
# resolve_incident
# ---------------------------------------------------------------------------

class TestResolveIncident:
    def test_status_becomes_resolved(self, engine):
        inc = engine.create_incident(ORG, **_incident())
        result = engine.resolve_incident(inc["id"], ORG, root_cause="misconfigured bucket policy")
        assert result["status"] == "resolved"

    def test_resolved_at_set(self, engine):
        inc = engine.create_incident(ORG, **_incident())
        result = engine.resolve_incident(inc["id"], ORG)
        assert result["resolved_at"] != ""

    def test_root_cause_stored(self, engine):
        inc = engine.create_incident(ORG, **_incident())
        result = engine.resolve_incident(inc["id"], ORG, root_cause="exposed credentials")
        assert result["root_cause"] == "exposed credentials"

    def test_resolution_time_mins_nonnegative(self, engine):
        inc = engine.create_incident(ORG, **_incident())
        result = engine.resolve_incident(inc["id"], ORG)
        assert result["resolution_time_mins"] >= 0.0

    def test_not_found_raises(self, engine):
        with pytest.raises(KeyError):
            engine.resolve_incident("nonexistent", ORG)

    def test_org_isolation(self, engine):
        inc = engine.create_incident(ORG, **_incident())
        with pytest.raises(KeyError):
            engine.resolve_incident(inc["id"], ORG2)


# ---------------------------------------------------------------------------
# add_containment_action + complete_action
# ---------------------------------------------------------------------------

class TestContainmentActions:
    def test_add_returns_pending(self, engine):
        inc = engine.create_incident(ORG, **_incident())
        action = engine.add_containment_action(inc["id"], ORG, action_type="isolate")
        assert action["status"] == "pending"

    def test_automated_flag_true(self, engine):
        inc = engine.create_incident(ORG, **_incident())
        action = engine.add_containment_action(inc["id"], ORG, action_type="block-ip", automated=True)
        assert action["automated"] == 1

    def test_automated_flag_false(self, engine):
        inc = engine.create_incident(ORG, **_incident())
        action = engine.add_containment_action(inc["id"], ORG, action_type="alert", automated=False)
        assert action["automated"] == 0

    def test_invalid_action_type_raises(self, engine):
        inc = engine.create_incident(ORG, **_incident())
        with pytest.raises(ValueError, match="action_type"):
            engine.add_containment_action(inc["id"], ORG, action_type="nuke")

    def test_complete_action_status(self, engine):
        inc = engine.create_incident(ORG, **_incident())
        action = engine.add_containment_action(inc["id"], ORG, action_type="snapshot")
        completed = engine.complete_action(action["id"], ORG, result="snapshot taken")
        assert completed["status"] == "completed"

    def test_complete_action_executed_at_set(self, engine):
        inc = engine.create_incident(ORG, **_incident())
        action = engine.add_containment_action(inc["id"], ORG, action_type="revoke-access")
        completed = engine.complete_action(action["id"], ORG)
        assert completed["executed_at"] != ""

    def test_complete_action_result_stored(self, engine):
        inc = engine.create_incident(ORG, **_incident())
        action = engine.add_containment_action(inc["id"], ORG, action_type="disable-account")
        completed = engine.complete_action(action["id"], ORG, result="account disabled")
        assert completed["result"] == "account disabled"

    def test_complete_action_not_found(self, engine):
        with pytest.raises(KeyError):
            engine.complete_action("nonexistent", ORG)

    def test_complete_action_org_isolation(self, engine):
        inc = engine.create_incident(ORG, **_incident())
        action = engine.add_containment_action(inc["id"], ORG, action_type="quarantine")
        with pytest.raises(KeyError):
            engine.complete_action(action["id"], ORG2)


# ---------------------------------------------------------------------------
# create_playbook + execute_playbook
# ---------------------------------------------------------------------------

class TestPlaybooks:
    def test_create_returns_dict(self, engine):
        pb = engine.create_playbook(ORG, "AWS Breach PB", "aws", "data-breach", steps=["step1", "step2"])
        assert "id" in pb and len(pb["id"]) == 36

    def test_execution_count_starts_at_zero(self, engine):
        pb = engine.create_playbook(ORG, "Ransomware PB", "azure", "ransomware")
        assert pb["execution_count"] == 0

    def test_steps_stored_as_list(self, engine):
        pb = engine.create_playbook(ORG, "DDoS PB", "gcp", "ddos", steps=["isolate", "alert"])
        assert pb["steps"] == ["isolate", "alert"]

    def test_invalid_provider_raises(self, engine):
        with pytest.raises(ValueError, match="cloud_provider"):
            engine.create_playbook(ORG, "Bad PB", "badcloud", "data-breach")

    def test_invalid_incident_type_raises(self, engine):
        with pytest.raises(ValueError, match="incident_type"):
            engine.create_playbook(ORG, "Bad PB", "aws", "unknown-type")

    def test_execute_increments_count(self, engine):
        pb = engine.create_playbook(ORG, "Exec PB", "aws", "account-compromise")
        result = engine.execute_playbook(pb["id"], ORG)
        assert result["execution_count"] == 1

    def test_execute_twice_increments_twice(self, engine):
        pb = engine.create_playbook(ORG, "Multi Exec PB", "aws", "insider")
        engine.execute_playbook(pb["id"], ORG)
        result = engine.execute_playbook(pb["id"], ORG)
        assert result["execution_count"] == 2

    def test_execute_not_found_raises(self, engine):
        with pytest.raises(KeyError):
            engine.execute_playbook("nonexistent", ORG)

    def test_execute_org_isolation(self, engine):
        pb = engine.create_playbook(ORG, "Iso PB", "aws", "misconfiguration")
        with pytest.raises(KeyError):
            engine.execute_playbook(pb["id"], ORG2)

    def test_list_playbooks_org_isolation(self, engine):
        engine.create_playbook(ORG, "PB1", "aws", "data-breach")
        engine.create_playbook(ORG2, "PB2", "azure", "ransomware")
        pbs = engine.list_playbooks(ORG)
        assert len(pbs) == 1
        assert pbs[0]["org_id"] == ORG


# ---------------------------------------------------------------------------
# get_incident
# ---------------------------------------------------------------------------

class TestGetIncident:
    def test_returns_incident_with_actions(self, engine):
        inc = engine.create_incident(ORG, **_incident())
        engine.add_containment_action(inc["id"], ORG, action_type="isolate")
        engine.add_containment_action(inc["id"], ORG, action_type="alert")
        result = engine.get_incident(inc["id"], ORG)
        assert len(result["actions"]) == 2

    def test_returns_matching_playbooks(self, engine):
        inc = engine.create_incident(ORG, **_incident({"cloud_provider": "aws", "incident_type": "data-breach"}))
        engine.create_playbook(ORG, "AWS Breach PB", "aws", "data-breach")
        engine.create_playbook(ORG, "AWS Other PB", "aws", "ransomware")  # different type
        result = engine.get_incident(inc["id"], ORG)
        assert len(result["playbooks"]) == 1
        assert result["playbooks"][0]["incident_type"] == "data-breach"

    def test_not_found_raises(self, engine):
        with pytest.raises(KeyError):
            engine.get_incident("nonexistent", ORG)

    def test_org_isolation(self, engine):
        inc = engine.create_incident(ORG, **_incident())
        with pytest.raises(KeyError):
            engine.get_incident(inc["id"], ORG2)


# ---------------------------------------------------------------------------
# list_incidents
# ---------------------------------------------------------------------------

class TestListIncidents:
    def test_filter_by_status(self, engine):
        inc1 = engine.create_incident(ORG, **_incident({"incident_name": "Inc1"}))
        inc2 = engine.create_incident(ORG, **_incident({"incident_name": "Inc2"}))
        engine.contain_incident(inc1["id"], ORG)
        detected = engine.list_incidents(ORG, status="detected")
        assert len(detected) == 1
        assert detected[0]["id"] == inc2["id"]

    def test_filter_by_provider(self, engine):
        engine.create_incident(ORG, **_incident({"cloud_provider": "aws"}))
        engine.create_incident(ORG, **_incident({"cloud_provider": "azure"}))
        aws_incs = engine.list_incidents(ORG, cloud_provider="aws")
        assert len(aws_incs) == 1

    def test_org_isolation(self, engine):
        engine.create_incident(ORG, **_incident({"incident_name": "Org1 Inc"}))
        engine.create_incident(ORG2, **_incident({"incident_name": "Org2 Inc"}))
        results = engine.list_incidents(ORG)
        assert len(results) == 1
        assert results[0]["org_id"] == ORG


# ---------------------------------------------------------------------------
# get_ir_metrics
# ---------------------------------------------------------------------------

class TestIRMetrics:
    def test_empty_org_returns_zeros(self, engine):
        metrics = engine.get_ir_metrics("org-empty-metrics")
        assert metrics["total_incidents"] == 0
        assert metrics["avg_containment_mins"] == 0.0
        assert metrics["avg_resolution_mins"] == 0.0
        assert metrics["open_critical"] == 0

    def test_total_incidents(self, engine):
        for i in range(3):
            engine.create_incident(ORG, **_incident({"incident_name": f"Inc{i}"}))
        metrics = engine.get_ir_metrics(ORG)
        assert metrics["total_incidents"] == 3

    def test_by_status(self, engine):
        inc1 = engine.create_incident(ORG, **_incident({"incident_name": "I1"}))
        inc2 = engine.create_incident(ORG, **_incident({"incident_name": "I2"}))
        engine.contain_incident(inc1["id"], ORG)
        metrics = engine.get_ir_metrics(ORG)
        assert metrics["by_status"]["contained"] == 1
        assert metrics["by_status"]["detected"] == 1

    def test_by_provider(self, engine):
        engine.create_incident(ORG, **_incident({"cloud_provider": "aws", "incident_name": "A1"}))
        engine.create_incident(ORG, **_incident({"cloud_provider": "aws", "incident_name": "A2"}))
        engine.create_incident(ORG, **_incident({"cloud_provider": "azure", "incident_name": "Az1"}))
        metrics = engine.get_ir_metrics(ORG)
        assert metrics["by_provider"]["aws"] == 2
        assert metrics["by_provider"]["azure"] == 1

    def test_open_critical(self, engine):
        crit1 = engine.create_incident(ORG, **_incident({"severity": "critical", "incident_name": "C1"}))
        crit2 = engine.create_incident(ORG, **_incident({"severity": "critical", "incident_name": "C2"}))
        engine.resolve_incident(crit2["id"], ORG)
        metrics = engine.get_ir_metrics(ORG)
        assert metrics["open_critical"] == 1

    def test_metrics_org_isolation(self, engine):
        engine.create_incident(ORG, **_incident({"incident_name": "Org1 Inc"}))
        engine.create_incident(ORG2, **_incident({"incident_name": "Org2 Inc"}))
        metrics1 = engine.get_ir_metrics(ORG)
        metrics2 = engine.get_ir_metrics(ORG2)
        assert metrics1["total_incidents"] == 1
        assert metrics2["total_incidents"] == 1

    def test_avg_containment_mins_nonnegative(self, engine):
        inc = engine.create_incident(ORG, **_incident())
        engine.contain_incident(inc["id"], ORG)
        metrics = engine.get_ir_metrics(ORG)
        assert metrics["avg_containment_mins"] >= 0.0

    def test_avg_resolution_mins_nonnegative(self, engine):
        inc = engine.create_incident(ORG, **_incident())
        engine.resolve_incident(inc["id"], ORG)
        metrics = engine.get_ir_metrics(ORG)
        assert metrics["avg_resolution_mins"] >= 0.0
