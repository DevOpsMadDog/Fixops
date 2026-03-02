"""Unit tests for core.mpte_models — V5 MPTE Verification data models.

Tests PenTestRequest, PenTestResult, PenTestConfig and their associated enums
which form the data foundation of the MPTE micro-pentest verification system.
"""

from datetime import datetime


class TestPenTestStatus:
    """Test PenTestStatus enum."""

    def test_all_statuses_exist(self):
        from core.mpte_models import PenTestStatus
        assert PenTestStatus.PENDING.value == "pending"
        assert PenTestStatus.RUNNING.value == "running"
        assert PenTestStatus.COMPLETED.value == "completed"
        assert PenTestStatus.FAILED.value == "failed"
        assert PenTestStatus.CANCELLED.value == "cancelled"

    def test_status_count(self):
        from core.mpte_models import PenTestStatus
        assert len(PenTestStatus) == 5


class TestExploitabilityLevel:
    """Test ExploitabilityLevel enum."""

    def test_all_levels_exist(self):
        from core.mpte_models import ExploitabilityLevel
        assert ExploitabilityLevel.CONFIRMED_EXPLOITABLE.value == "confirmed_exploitable"
        assert ExploitabilityLevel.LIKELY_EXPLOITABLE.value == "likely_exploitable"
        assert ExploitabilityLevel.UNEXPLOITABLE.value == "unexploitable"
        assert ExploitabilityLevel.BLOCKED.value == "blocked"
        assert ExploitabilityLevel.INCONCLUSIVE.value == "inconclusive"
        assert ExploitabilityLevel.UNKNOWN.value == "unknown"

    def test_level_count(self):
        from core.mpte_models import ExploitabilityLevel
        assert len(ExploitabilityLevel) == 6  # 5 original + UNKNOWN added by backend-hardener


class TestPenTestPriority:
    """Test PenTestPriority enum."""

    def test_all_priorities_exist(self):
        from core.mpte_models import PenTestPriority
        assert PenTestPriority.CRITICAL.value == "critical"
        assert PenTestPriority.HIGH.value == "high"
        assert PenTestPriority.MEDIUM.value == "medium"
        assert PenTestPriority.LOW.value == "low"

    def test_priority_count(self):
        from core.mpte_models import PenTestPriority
        assert len(PenTestPriority) == 4


class TestPenTestRequest:
    """Test PenTestRequest dataclass."""

    def _make_request(self, **kwargs):
        from core.mpte_models import PenTestPriority, PenTestRequest
        defaults = {
            "id": "req-001",
            "finding_id": "f-123",
            "target_url": "https://example.com/api/login",
            "vulnerability_type": "sql_injection",
            "test_case": "Check for SQLi in login form",
            "priority": PenTestPriority.HIGH,
        }
        defaults.update(kwargs)
        return PenTestRequest(**defaults)

    def test_creation_with_defaults(self):
        from core.mpte_models import PenTestStatus
        req = self._make_request()
        assert req.id == "req-001"
        assert req.finding_id == "f-123"
        assert req.target_url == "https://example.com/api/login"
        assert req.vulnerability_type == "sql_injection"
        assert req.status == PenTestStatus.PENDING
        assert req.started_at is None
        assert req.completed_at is None
        assert req.mpte_job_id is None
        assert req.metadata == {}

    def test_creation_with_custom_status(self):
        from core.mpte_models import PenTestStatus
        req = self._make_request(status=PenTestStatus.RUNNING)
        assert req.status == PenTestStatus.RUNNING

    def test_created_at_auto_set(self):
        req = self._make_request()
        assert isinstance(req.created_at, datetime)

    def test_to_dict(self):
        req = self._make_request()
        d = req.to_dict()
        assert d["id"] == "req-001"
        assert d["finding_id"] == "f-123"
        assert d["target_url"] == "https://example.com/api/login"
        assert d["vulnerability_type"] == "sql_injection"
        assert d["test_case"] == "Check for SQLi in login form"
        assert d["priority"] == "high"
        assert d["status"] == "pending"
        assert d["started_at"] is None
        assert d["completed_at"] is None
        assert d["mpte_job_id"] is None
        assert d["metadata"] == {}

    def test_to_dict_with_timestamps(self):
        now = datetime.utcnow()
        req = self._make_request(started_at=now, completed_at=now)
        d = req.to_dict()
        assert d["started_at"] is not None
        assert d["completed_at"] is not None

    def test_to_dict_created_at_is_iso(self):
        req = self._make_request()
        d = req.to_dict()
        assert "T" in d["created_at"]


class TestPenTestResult:
    """Test PenTestResult dataclass."""

    def _make_result(self, **kwargs):
        from core.mpte_models import ExploitabilityLevel, PenTestResult
        defaults = {
            "id": "res-001",
            "request_id": "req-001",
            "finding_id": "f-123",
            "exploitability": ExploitabilityLevel.CONFIRMED_EXPLOITABLE,
            "exploit_successful": True,
            "evidence": "SQL injection confirmed via UNION-based attack",
        }
        defaults.update(kwargs)
        return PenTestResult(**defaults)

    def test_creation_with_defaults(self):
        result = self._make_result()
        assert result.id == "res-001"
        assert result.request_id == "req-001"
        assert result.exploit_successful is True
        assert result.steps_taken == []
        assert result.artifacts == []
        assert result.confidence_score == 0.0
        assert result.execution_time_seconds == 0.0
        assert result.metadata == {}

    def test_creation_with_steps(self):
        steps = ["Enumerate endpoints", "Inject payload", "Extract data"]
        result = self._make_result(steps_taken=steps)
        assert len(result.steps_taken) == 3
        assert "Inject payload" in result.steps_taken

    def test_creation_with_confidence(self):
        result = self._make_result(confidence_score=0.95)
        assert result.confidence_score == 0.95

    def test_to_dict(self):
        result = self._make_result(
            steps_taken=["step1"],
            artifacts=["screenshot.png"],
            confidence_score=0.88,
            execution_time_seconds=12.5,
        )
        d = result.to_dict()
        assert d["id"] == "res-001"
        assert d["exploitability"] == "confirmed_exploitable"
        assert d["exploit_successful"] is True
        assert d["confidence_score"] == 0.88
        assert d["execution_time_seconds"] == 12.5
        assert d["steps_taken"] == ["step1"]
        assert d["artifacts"] == ["screenshot.png"]

    def test_unexploitable_result(self):
        from core.mpte_models import ExploitabilityLevel
        result = self._make_result(
            exploitability=ExploitabilityLevel.UNEXPLOITABLE,
            exploit_successful=False,
            evidence="WAF blocked all injection attempts",
        )
        d = result.to_dict()
        assert d["exploitability"] == "unexploitable"
        assert d["exploit_successful"] is False

    def test_inconclusive_result(self):
        from core.mpte_models import ExploitabilityLevel
        result = self._make_result(
            exploitability=ExploitabilityLevel.INCONCLUSIVE,
            exploit_successful=False,
            evidence="Target was unreachable during test window",
        )
        assert result.exploitability == ExploitabilityLevel.INCONCLUSIVE


class TestPenTestConfig:
    """Test PenTestConfig dataclass."""

    def _make_config(self, **kwargs):
        from core.mpte_models import PenTestConfig
        defaults = {
            "id": "cfg-001",
            "name": "production-mpte",
            "mpte_url": "https://mpte:8443",
        }
        defaults.update(kwargs)
        return PenTestConfig(**defaults)

    def test_creation_with_defaults(self):
        cfg = self._make_config()
        assert cfg.id == "cfg-001"
        assert cfg.name == "production-mpte"
        assert cfg.mpte_url == "https://mpte:8443"
        assert cfg.api_key is None
        assert cfg.enabled is True
        assert cfg.max_concurrent_tests == 5
        assert cfg.timeout_seconds == 300
        assert cfg.auto_trigger is False
        assert cfg.target_environments == []
        assert cfg.metadata == {}

    def test_creation_with_api_key(self):
        cfg = self._make_config(api_key="secret-key-123")
        assert cfg.api_key == "secret-key-123"

    def test_to_dict_masks_api_key(self):
        cfg = self._make_config(api_key="secret-key-123")
        d = cfg.to_dict()
        assert d["api_key"] == "***"

    def test_to_dict_no_api_key(self):
        cfg = self._make_config()
        d = cfg.to_dict()
        assert d["api_key"] is None

    def test_to_dict_fields(self):
        cfg = self._make_config(
            enabled=False,
            max_concurrent_tests=10,
            timeout_seconds=600,
            auto_trigger=True,
            target_environments=["staging", "qa"],
        )
        d = cfg.to_dict()
        assert d["id"] == "cfg-001"
        assert d["name"] == "production-mpte"
        assert d["mpte_url"] == "https://mpte:8443"
        assert d["enabled"] is False
        assert d["max_concurrent_tests"] == 10
        assert d["timeout_seconds"] == 600
        assert d["auto_trigger"] is True
        assert d["target_environments"] == ["staging", "qa"]

    def test_created_at_auto_set(self):
        cfg = self._make_config()
        assert isinstance(cfg.created_at, datetime)
        assert isinstance(cfg.updated_at, datetime)

    def test_to_dict_timestamps_are_iso(self):
        cfg = self._make_config()
        d = cfg.to_dict()
        assert "T" in d["created_at"]
        assert "T" in d["updated_at"]

    def test_metadata_in_dict(self):
        cfg = self._make_config(metadata={"region": "us-east-1"})
        d = cfg.to_dict()
        assert d["metadata"]["region"] == "us-east-1"
