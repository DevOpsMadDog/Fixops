"""Unit tests for core.exposure_case — V3 Decision Intelligence Exposure Case model.

Tests the ExposureCaseManager that collapses noisy scanner findings into
actionable Exposure Cases with full lifecycle management (OPEN -> CLOSED).
"""

import os
import tempfile
import pytest
from unittest.mock import patch


class TestCaseStatus:
    """Test CaseStatus enum."""

    def test_all_statuses(self):
        from core.exposure_case import CaseStatus
        assert CaseStatus.OPEN.value == "open"
        assert CaseStatus.TRIAGING.value == "triaging"
        assert CaseStatus.FIXING.value == "fixing"
        assert CaseStatus.RESOLVED.value == "resolved"
        assert CaseStatus.CLOSED.value == "closed"
        assert CaseStatus.ACCEPTED_RISK.value == "accepted_risk"
        assert CaseStatus.FALSE_POSITIVE.value == "false_positive"

    def test_status_is_string_enum(self):
        from core.exposure_case import CaseStatus
        assert isinstance(CaseStatus.OPEN, str)
        assert CaseStatus.OPEN == "open"

    def test_status_count(self):
        from core.exposure_case import CaseStatus
        assert len(CaseStatus) == 7


class TestCasePriority:
    """Test CasePriority enum."""

    def test_all_priorities(self):
        from core.exposure_case import CasePriority
        assert CasePriority.CRITICAL.value == "critical"
        assert CasePriority.HIGH.value == "high"
        assert CasePriority.MEDIUM.value == "medium"
        assert CasePriority.LOW.value == "low"
        assert CasePriority.INFO.value == "info"

    def test_priority_count(self):
        from core.exposure_case import CasePriority
        assert len(CasePriority) == 5


class TestValidTransitions:
    """Test lifecycle state machine transitions."""

    def test_open_transitions(self):
        from core.exposure_case import CaseStatus, VALID_TRANSITIONS
        allowed = VALID_TRANSITIONS[CaseStatus.OPEN]
        assert CaseStatus.TRIAGING in allowed
        assert CaseStatus.ACCEPTED_RISK in allowed
        assert CaseStatus.FALSE_POSITIVE in allowed

    def test_triaging_transitions(self):
        from core.exposure_case import CaseStatus, VALID_TRANSITIONS
        allowed = VALID_TRANSITIONS[CaseStatus.TRIAGING]
        assert CaseStatus.FIXING in allowed
        assert CaseStatus.OPEN in allowed

    def test_fixing_transitions(self):
        from core.exposure_case import CaseStatus, VALID_TRANSITIONS
        allowed = VALID_TRANSITIONS[CaseStatus.FIXING]
        assert CaseStatus.RESOLVED in allowed

    def test_resolved_transitions(self):
        from core.exposure_case import CaseStatus, VALID_TRANSITIONS
        allowed = VALID_TRANSITIONS[CaseStatus.RESOLVED]
        assert CaseStatus.CLOSED in allowed
        assert CaseStatus.OPEN in allowed

    def test_closed_can_reopen(self):
        from core.exposure_case import CaseStatus, VALID_TRANSITIONS
        allowed = VALID_TRANSITIONS[CaseStatus.CLOSED]
        assert CaseStatus.OPEN in allowed


class TestExposureCase:
    """Test ExposureCase dataclass."""

    def test_creation_basic(self):
        from core.exposure_case import ExposureCase
        case = ExposureCase(case_id="EC-001", title="SQL Injection in Login")
        assert case.case_id == "EC-001"
        assert case.title == "SQL Injection in Login"
        assert case.status.value == "open"
        assert case.priority.value == "medium"

    def test_auto_generated_id(self):
        from core.exposure_case import ExposureCase
        case = ExposureCase(case_id="", title="Test")
        assert case.case_id.startswith("EC-")
        assert len(case.case_id) == 15  # EC- + 12 hex chars

    def test_auto_timestamps(self):
        from core.exposure_case import ExposureCase
        case = ExposureCase(case_id="EC-001", title="Test")
        assert case.created_at != ""
        assert case.updated_at != ""
        assert "T" in case.created_at

    def test_defaults(self):
        from core.exposure_case import ExposureCase
        case = ExposureCase(case_id="EC-001", title="Test")
        assert case.description == ""
        assert case.org_id == ""
        assert case.root_cve is None
        assert case.root_cwe is None
        assert case.affected_assets == []
        assert case.cluster_ids == []
        assert case.finding_count == 0
        assert case.risk_score == 0.0
        assert case.epss_score is None
        assert case.in_kev is False
        assert case.blast_radius == 0
        assert case.assigned_to is None
        assert case.tags == []
        assert case.metadata == {}

    def test_to_dict(self):
        from core.exposure_case import CasePriority, CaseStatus, ExposureCase
        case = ExposureCase(
            case_id="EC-001",
            title="Test",
            status=CaseStatus.TRIAGING,
            priority=CasePriority.HIGH,
            risk_score=8.5,
            tags=["urgent"],
        )
        d = case.to_dict()
        assert d["case_id"] == "EC-001"
        assert d["status"] == "triaging"
        assert d["priority"] == "high"
        assert d["risk_score"] == 8.5
        assert d["tags"] == ["urgent"]


class TestSeverityToPriority:
    """Test severity_to_priority mapper."""

    def test_critical(self):
        from core.exposure_case import CasePriority, severity_to_priority
        assert severity_to_priority("critical") == CasePriority.CRITICAL

    def test_high(self):
        from core.exposure_case import CasePriority, severity_to_priority
        assert severity_to_priority("high") == CasePriority.HIGH

    def test_medium(self):
        from core.exposure_case import CasePriority, severity_to_priority
        assert severity_to_priority("medium") == CasePriority.MEDIUM

    def test_low(self):
        from core.exposure_case import CasePriority, severity_to_priority
        assert severity_to_priority("low") == CasePriority.LOW

    def test_info(self):
        from core.exposure_case import CasePriority, severity_to_priority
        assert severity_to_priority("info") == CasePriority.INFO

    def test_informational(self):
        from core.exposure_case import CasePriority, severity_to_priority
        assert severity_to_priority("informational") == CasePriority.INFO

    def test_unknown_defaults_to_medium(self):
        from core.exposure_case import CasePriority, severity_to_priority
        assert severity_to_priority("bogus") == CasePriority.MEDIUM

    def test_none_defaults_to_medium(self):
        from core.exposure_case import CasePriority, severity_to_priority
        assert severity_to_priority(None) == CasePriority.MEDIUM

    def test_case_insensitive(self):
        from core.exposure_case import CasePriority, severity_to_priority
        assert severity_to_priority("CRITICAL") == CasePriority.CRITICAL
        assert severity_to_priority("High") == CasePriority.HIGH

    def test_whitespace_stripped(self):
        from core.exposure_case import CasePriority, severity_to_priority
        assert severity_to_priority("  high  ") == CasePriority.HIGH


class TestExposureCaseManager:
    """Test ExposureCaseManager with real SQLite DB."""

    def setup_method(self):
        from core.exposure_case import ExposureCaseManager
        ExposureCaseManager.reset_instance()
        self._tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db_path = self._tmp.name
        self._tmp.close()

    def teardown_method(self):
        from core.exposure_case import ExposureCaseManager
        ExposureCaseManager.reset_instance()
        try:
            os.unlink(self.db_path)
        except Exception:
            pass
        for ext in ["-wal", "-shm"]:
            try:
                os.unlink(self.db_path + ext)
            except Exception:
                pass

    def _manager(self):
        from core.exposure_case import ExposureCaseManager
        return ExposureCaseManager(db_path=self.db_path)

    def _make_case(self, **kwargs):
        from core.exposure_case import ExposureCase
        defaults = {"case_id": "EC-TEST-001", "title": "Test SQL Injection"}
        defaults.update(kwargs)
        return ExposureCase(**defaults)

    @patch("core.exposure_case.ExposureCaseManager._persist_to_brain")
    @patch("core.exposure_case.ExposureCaseManager._emit_event")
    def test_create_case(self, mock_emit, mock_brain):
        mgr = self._manager()
        case = self._make_case()
        created = mgr.create_case(case)
        assert created.case_id == "EC-TEST-001"
        assert created.title == "Test SQL Injection"

    @patch("core.exposure_case.ExposureCaseManager._persist_to_brain")
    @patch("core.exposure_case.ExposureCaseManager._emit_event")
    def test_get_case(self, mock_emit, mock_brain):
        mgr = self._manager()
        case = self._make_case()
        mgr.create_case(case)
        retrieved = mgr.get_case("EC-TEST-001")
        assert retrieved is not None
        assert retrieved.title == "Test SQL Injection"

    def test_get_case_not_found(self):
        mgr = self._manager()
        assert mgr.get_case("nonexistent") is None

    @patch("core.exposure_case.ExposureCaseManager._persist_to_brain")
    @patch("core.exposure_case.ExposureCaseManager._emit_event")
    def test_list_cases(self, mock_emit, mock_brain):
        mgr = self._manager()
        for i in range(5):
            mgr.create_case(self._make_case(case_id=f"EC-{i:03d}", title=f"Case {i}"))
        result = mgr.list_cases()
        assert result["total"] == 5
        assert len(result["cases"]) == 5

    @patch("core.exposure_case.ExposureCaseManager._persist_to_brain")
    @patch("core.exposure_case.ExposureCaseManager._emit_event")
    def test_list_cases_with_filters(self, mock_emit, mock_brain):
        from core.exposure_case import CasePriority
        mgr = self._manager()
        mgr.create_case(self._make_case(case_id="EC-001", priority=CasePriority.CRITICAL))
        mgr.create_case(self._make_case(case_id="EC-002", priority=CasePriority.LOW))
        result = mgr.list_cases(priority="critical")
        assert result["total"] == 1

    @patch("core.exposure_case.ExposureCaseManager._persist_to_brain")
    @patch("core.exposure_case.ExposureCaseManager._emit_event")
    def test_transition_valid(self, mock_emit, mock_brain):
        from core.exposure_case import CaseStatus
        mgr = self._manager()
        mgr.create_case(self._make_case())
        case = mgr.transition("EC-TEST-001", CaseStatus.TRIAGING)
        assert case.status == CaseStatus.TRIAGING

    @patch("core.exposure_case.ExposureCaseManager._persist_to_brain")
    @patch("core.exposure_case.ExposureCaseManager._emit_event")
    def test_transition_invalid(self, mock_emit, mock_brain):
        from core.exposure_case import CaseStatus
        mgr = self._manager()
        mgr.create_case(self._make_case())
        with pytest.raises(ValueError, match="Invalid transition"):
            mgr.transition("EC-TEST-001", CaseStatus.CLOSED)

    @patch("core.exposure_case.ExposureCaseManager._persist_to_brain")
    @patch("core.exposure_case.ExposureCaseManager._emit_event")
    def test_transition_not_found(self, mock_emit, mock_brain):
        from core.exposure_case import CaseStatus
        mgr = self._manager()
        with pytest.raises(ValueError, match="not found"):
            mgr.transition("nonexistent", CaseStatus.TRIAGING)

    @patch("core.exposure_case.ExposureCaseManager._persist_to_brain")
    @patch("core.exposure_case.ExposureCaseManager._emit_event")
    def test_transition_resolved_sets_timestamp(self, mock_emit, mock_brain):
        from core.exposure_case import CaseStatus
        mgr = self._manager()
        mgr.create_case(self._make_case())
        mgr.transition("EC-TEST-001", CaseStatus.TRIAGING)
        mgr.transition("EC-TEST-001", CaseStatus.FIXING)
        case = mgr.transition("EC-TEST-001", CaseStatus.RESOLVED)
        assert case.resolved_at is not None

    @patch("core.exposure_case.ExposureCaseManager._persist_to_brain")
    @patch("core.exposure_case.ExposureCaseManager._emit_event")
    def test_update_case(self, mock_emit, mock_brain):
        mgr = self._manager()
        mgr.create_case(self._make_case())
        updated = mgr.update_case("EC-TEST-001", {
            "title": "Updated Title",
            "assigned_to": "dev-team",
            "risk_score": 9.5,
        })
        assert updated.title == "Updated Title"
        assert updated.assigned_to == "dev-team"
        assert updated.risk_score == 9.5

    @patch("core.exposure_case.ExposureCaseManager._persist_to_brain")
    @patch("core.exposure_case.ExposureCaseManager._emit_event")
    def test_update_case_not_found(self, mock_emit, mock_brain):
        mgr = self._manager()
        with pytest.raises(ValueError, match="not found"):
            mgr.update_case("nonexistent", {"title": "X"})

    @patch("core.exposure_case.ExposureCaseManager._persist_to_brain")
    @patch("core.exposure_case.ExposureCaseManager._emit_event")
    def test_update_case_ignores_protected_fields(self, mock_emit, mock_brain):
        mgr = self._manager()
        mgr.create_case(self._make_case())
        updated = mgr.update_case("EC-TEST-001", {
            "status": "closed",  # Should be ignored
            "case_id": "EC-HACKED",  # Should be ignored
        })
        assert updated.case_id == "EC-TEST-001"
        assert updated.status.value == "open"

    @patch("core.exposure_case.ExposureCaseManager._persist_to_brain")
    @patch("core.exposure_case.ExposureCaseManager._emit_event")
    def test_find_case_by_cluster(self, mock_emit, mock_brain):
        mgr = self._manager()
        mgr.create_case(self._make_case(cluster_ids=["cluster-A", "cluster-B"]))
        found = mgr.find_case_by_cluster("cluster-A")
        assert found is not None
        assert found.case_id == "EC-TEST-001"

    @patch("core.exposure_case.ExposureCaseManager._persist_to_brain")
    @patch("core.exposure_case.ExposureCaseManager._emit_event")
    def test_find_case_by_cluster_not_found(self, mock_emit, mock_brain):
        mgr = self._manager()
        mgr.create_case(self._make_case(cluster_ids=["cluster-A"]))
        found = mgr.find_case_by_cluster("nonexistent-cluster")
        assert found is None

    @patch("core.exposure_case.ExposureCaseManager._persist_to_brain")
    @patch("core.exposure_case.ExposureCaseManager._emit_event")
    def test_stats_empty(self, mock_emit, mock_brain):
        mgr = self._manager()
        stats = mgr.stats()
        assert stats["total_cases"] == 0
        assert stats["kev_cases"] == 0

    @patch("core.exposure_case.ExposureCaseManager._persist_to_brain")
    @patch("core.exposure_case.ExposureCaseManager._emit_event")
    def test_stats_with_cases(self, mock_emit, mock_brain):
        from core.exposure_case import CasePriority
        mgr = self._manager()
        mgr.create_case(self._make_case(case_id="EC-001", priority=CasePriority.CRITICAL, in_kev=True, risk_score=9.0))
        mgr.create_case(self._make_case(case_id="EC-002", priority=CasePriority.LOW, risk_score=2.0))
        stats = mgr.stats()
        assert stats["total_cases"] == 2
        assert stats["kev_cases"] == 1
        assert stats["avg_risk_score"] > 0
        assert "critical" in stats["by_priority"]

    @patch("core.exposure_case.ExposureCaseManager._persist_to_brain")
    @patch("core.exposure_case.ExposureCaseManager._emit_event")
    def test_purge_empty_cases_dry_run(self, mock_emit, mock_brain):
        mgr = self._manager()
        mgr.create_case(self._make_case(case_id="EC-EMPTY"))
        result = mgr.purge_empty_cases(dry_run=True)
        assert result["purged"] == 1
        assert result["dry_run"] is True
        # Still exists
        assert mgr.get_case("EC-EMPTY") is not None

    @patch("core.exposure_case.ExposureCaseManager._persist_to_brain")
    @patch("core.exposure_case.ExposureCaseManager._emit_event")
    def test_purge_empty_cases_real(self, mock_emit, mock_brain):
        mgr = self._manager()
        mgr.create_case(self._make_case(case_id="EC-EMPTY"))
        result = mgr.purge_empty_cases(dry_run=False)
        assert result["purged"] == 1
        assert mgr.get_case("EC-EMPTY") is None

    @patch("core.exposure_case.ExposureCaseManager._persist_to_brain")
    @patch("core.exposure_case.ExposureCaseManager._emit_event")
    def test_add_clusters(self, mock_emit, mock_brain):
        mgr = self._manager()
        mgr.create_case(self._make_case(cluster_ids=["c1"]))
        updated = mgr.add_clusters("EC-TEST-001", ["c2", "c3"], finding_count_delta=5)
        assert "c2" in updated.cluster_ids
        assert "c3" in updated.cluster_ids
        assert updated.finding_count == 5

    @patch("core.exposure_case.ExposureCaseManager._persist_to_brain")
    @patch("core.exposure_case.ExposureCaseManager._emit_event")
    def test_add_clusters_no_duplicates(self, mock_emit, mock_brain):
        mgr = self._manager()
        mgr.create_case(self._make_case(cluster_ids=["c1"]))
        updated = mgr.add_clusters("EC-TEST-001", ["c1"])  # Already exists
        assert updated.cluster_ids == ["c1"]

    @patch("core.exposure_case.ExposureCaseManager._persist_to_brain")
    @patch("core.exposure_case.ExposureCaseManager._emit_event")
    def test_full_lifecycle(self, mock_emit, mock_brain):
        """Test full OPEN -> TRIAGING -> FIXING -> RESOLVED -> CLOSED lifecycle."""
        from core.exposure_case import CaseStatus
        mgr = self._manager()
        mgr.create_case(self._make_case())
        mgr.transition("EC-TEST-001", CaseStatus.TRIAGING)
        mgr.transition("EC-TEST-001", CaseStatus.FIXING)
        mgr.transition("EC-TEST-001", CaseStatus.RESOLVED)
        case = mgr.transition("EC-TEST-001", CaseStatus.CLOSED)
        assert case.status == CaseStatus.CLOSED
        assert case.resolved_at is not None
        assert case.closed_at is not None

    def test_close_connection(self):
        mgr = self._manager()
        mgr.close()
        # Should not raise even if called twice
        mgr.close()
