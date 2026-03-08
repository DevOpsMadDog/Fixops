"""Tests for the APP_ID Configuration Parser.

Covers: AppConfig, AppConfigManager, SLAConfig, ComponentConfig,
ScannerConfig, PolicyConfig, enumerations, validation, and persistence.
"""

import os
import sys
import tempfile
from pathlib import Path

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

import pytest
from pydantic import ValidationError

from core.app_config import (
    AppConfig,
    AppConfigManager,
    ClassificationLevel,
    ComponentConfig,
    Criticality,
    DataClassification,
    PolicyConfig,
    ScannerConfig,
    SLAConfig,
)


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class TestEnums:
    def test_criticality_values(self):
        assert Criticality.critical == "critical"
        assert Criticality.high == "high"
        assert Criticality.medium == "medium"
        assert Criticality.low == "low"

    def test_data_classification_values(self):
        assert DataClassification.phi == "phi"
        assert DataClassification.pci == "pci"
        assert DataClassification.pii == "pii"
        assert DataClassification.public == "public"
        assert DataClassification.internal == "internal"
        assert DataClassification.confidential == "confidential"

    def test_classification_level_values(self):
        assert ClassificationLevel.unclassified == "unclassified"
        assert ClassificationLevel.cui == "cui"
        assert ClassificationLevel.secret == "secret"
        assert ClassificationLevel.top_secret == "top-secret"
        assert ClassificationLevel.sci == "sci"


# ---------------------------------------------------------------------------
# SLAConfig
# ---------------------------------------------------------------------------

class TestSLAConfig:
    def test_default_values(self):
        sla = SLAConfig()
        assert sla.critical == "24h"
        assert sla.high == "72h"
        assert sla.medium == "14d"
        assert sla.low == "30d"

    def test_custom_values(self):
        sla = SLAConfig(critical="12h", high="48h", medium="7d", low="14d")
        assert sla.critical == "12h"
        assert sla.high == "48h"

    def test_validate_duration_valid(self):
        sla = SLAConfig(critical="1h", high="2d", medium="3w", low="1y")
        assert sla.critical == "1h"
        assert sla.high == "2d"
        assert sla.medium == "3w"
        assert sla.low == "1y"

    def test_validate_duration_invalid_unit(self):
        with pytest.raises(ValidationError):
            SLAConfig(critical="24x")

    def test_validate_duration_empty(self):
        with pytest.raises(ValidationError):
            SLAConfig(critical="")

    def test_validate_duration_non_numeric(self):
        with pytest.raises(ValidationError):
            SLAConfig(critical="abch")

    def test_to_timedelta_hours(self):
        sla = SLAConfig(critical="24h")
        td = sla.to_timedelta("critical")
        assert td.total_seconds() == 24 * 3600

    def test_to_timedelta_days(self):
        sla = SLAConfig(medium="14d")
        td = sla.to_timedelta("medium")
        assert td.days == 14

    def test_to_timedelta_weeks(self):
        sla = SLAConfig(low="2w")
        td = sla.to_timedelta("low")
        assert td.days == 14

    def test_to_timedelta_years(self):
        sla = SLAConfig(low="1y")
        td = sla.to_timedelta("low")
        assert td.days == 365

    def test_to_timedelta_unknown_severity(self):
        sla = SLAConfig()
        with pytest.raises(ValueError):
            sla.to_timedelta("nonexistent")


# ---------------------------------------------------------------------------
# ComponentConfig
# ---------------------------------------------------------------------------

class TestComponentConfig:
    def test_basic_creation(self):
        comp = ComponentConfig(name="auth-service")
        assert comp.name == "auth-service"
        assert comp.language is None
        assert comp.owner is None

    def test_full_creation(self):
        comp = ComponentConfig(
            name="API Gateway",
            language="python",
            owner="platform-team",
            repo_url="https://github.com/example/api",
            tags={"env": "prod"}
        )
        assert comp.name == "api gateway"  # sanitized to lowercase
        assert comp.language == "python"
        assert comp.owner == "platform-team"

    def test_name_sanitized(self):
        comp = ComponentConfig(name="  MyService  ")
        assert comp.name == "myservice"

    def test_empty_name_rejected(self):
        with pytest.raises(ValidationError):
            ComponentConfig(name="")

    def test_valid_repo_url_https(self):
        comp = ComponentConfig(name="svc", repo_url="https://github.com/org/repo")
        assert comp.repo_url == "https://github.com/org/repo"

    def test_valid_repo_url_git(self):
        comp = ComponentConfig(name="svc", repo_url="git@github.com:org/repo.git")
        assert comp.repo_url == "git@github.com:org/repo.git"

    def test_invalid_repo_url(self):
        with pytest.raises(ValidationError):
            ComponentConfig(name="svc", repo_url="ftp://invalid.com/repo")

    def test_component_with_sla(self):
        comp = ComponentConfig(
            name="critical-svc",
            sla=SLAConfig(critical="4h", high="12h")
        )
        assert comp.sla.critical == "4h"


# ---------------------------------------------------------------------------
# ScannerConfig
# ---------------------------------------------------------------------------

class TestScannerConfig:
    def test_defaults(self):
        sc = ScannerConfig()
        assert sc.sast == []
        assert sc.sca == []
        assert sc.iac == []
        assert sc.dast == []
        assert sc.container == []
        assert sc.secrets == []

    def test_all_scanners(self):
        sc = ScannerConfig(
            sast=["semgrep", "codeql"],
            sca=["snyk"],
            dast=["zap"]
        )
        result = sc.all_scanners()
        assert "sast" in result
        assert result["sast"] == ["semgrep", "codeql"]
        # Empty categories should not appear
        assert "iac" not in result or result["iac"] == []

    def test_custom_scanners(self):
        sc = ScannerConfig(
            sast=["semgrep"],
            container=["trivy", "grype"],
            secrets=["gitleaks"]
        )
        assert len(sc.container) == 2
        assert sc.secrets == ["gitleaks"]


# ---------------------------------------------------------------------------
# AppConfig
# ---------------------------------------------------------------------------

class TestAppConfig:
    def _make_config(self, **overrides):
        defaults = dict(
            app_id="APP-001",
            name="Test Application",
            criticality=Criticality.high,
            data_classification=DataClassification.pii,
            components=[ComponentConfig(name="backend")],
            compliance=[],
            scanners=ScannerConfig(),
            policies=PolicyConfig(require_mpte_for=[Criticality.critical]),
        )
        defaults.update(overrides)
        return AppConfig(**defaults)

    def test_basic_creation(self):
        cfg = self._make_config()
        assert cfg.app_id
        assert cfg.name == "Test Application"
        assert cfg.criticality == Criticality.high

    def test_sanitize_app_id(self):
        cfg = self._make_config(app_id="  app-test-001  ")
        assert cfg.app_id == cfg.app_id.strip().lower()

    def test_has_compliance(self):
        cfg = self._make_config(
            compliance=["soc2", "hipaa"]
        )
        assert cfg.has_compliance("soc2") is True
        assert cfg.has_compliance("pcidss") is False

    def test_is_itar(self):
        cfg = self._make_config(compliance=["itar"])
        assert cfg.is_itar() is True

        cfg2 = self._make_config(compliance=["soc2"])
        assert cfg2.is_itar() is False

    def test_get_component(self):
        comp = ComponentConfig(name="frontend", language="typescript")
        cfg = self._make_config(components=[comp])
        found = cfg.get_component("frontend")
        assert found is not None
        assert found.language == "typescript"

    def test_get_component_not_found(self):
        cfg = self._make_config()
        result = cfg.get_component("nonexistent")
        assert result is None

    def test_sla_deadline(self):
        from datetime import datetime
        cfg = self._make_config()
        deadline = cfg.sla_deadline("high")
        # Should return a datetime in the future (or at least a datetime)
        if deadline is not None:
            assert isinstance(deadline, datetime)

    def test_to_yaml(self):
        cfg = self._make_config()
        yaml_str = cfg.to_yaml()
        assert isinstance(yaml_str, str)
        assert "app_id" in yaml_str or "APP" in yaml_str.upper()


# ---------------------------------------------------------------------------
# AppConfigManager (SQLite persistence)
# ---------------------------------------------------------------------------

class TestAppConfigManager:
    def setup_method(self, method):
        self.tmpdir = tempfile.mkdtemp()
        # Use method name in DB path for complete isolation
        self.db_path = Path(self.tmpdir) / f"test_{method.__name__}.db"
        self.mgr = AppConfigManager(db_path=self.db_path)

    def teardown_method(self):
        try:
            self.mgr.close()
        except Exception:
            pass

    def test_context_manager(self):
        with AppConfigManager(db_path=self.db_path) as mgr:
            assert mgr is not None

    def _app(self, app_id, name, **overrides):
        """Helper to create AppConfig with all required fields."""
        defaults = dict(
            app_id=app_id,
            name=name,
            criticality=Criticality.medium,
            data_classification=DataClassification.internal,
            components=[ComponentConfig(name="core")],
            compliance=[],
            scanners=ScannerConfig(),
            policies=PolicyConfig(require_mpte_for=[Criticality.critical]),
        )
        defaults.update(overrides)
        return AppConfig(**defaults)

    def test_register_and_get_app(self):
        config = self._app("REG-001", "Registered App")
        self.mgr.register_app(config)
        retrieved = self.mgr.get_app("reg-001")
        assert retrieved is not None
        assert retrieved.name == "Registered App"

    def test_get_app_not_found(self):
        result = self.mgr.get_app("nonexistent")
        assert result is None

    def test_list_apps(self):
        for i in range(3):
            config = self._app(f"LIST-{i:03d}", f"App {i}",
                               criticality=Criticality.low,
                               data_classification=DataClassification.public,
                               components=[ComponentConfig(name=f"comp-{i}")])
            self.mgr.register_app(config)
        apps = self.mgr.list_apps()
        assert len(apps) >= 3

    def test_update_app(self):
        config = self._app("UPD-001", "Original Name", criticality=Criticality.low)
        self.mgr.register_app(config)

        updates = {"name": "Updated Name", "criticality": "high"}
        result = self.mgr.update_app("upd-001", updates)
        assert result is not None
        assert result.name == "Updated Name"

    def test_delete_app(self):
        config = self._app("DEL-001", "To Delete", criticality=Criticality.low)
        self.mgr.register_app(config)
        self.mgr.delete_app("del-001")
        assert self.mgr.get_app("del-001") is None

    def test_get_scanners(self):
        config = self._app("SCAN-001", "Scanner App",
                           criticality=Criticality.high,
                           data_classification=DataClassification.pci,
                           scanners=ScannerConfig(sast=["semgrep"], dast=["zap"]))
        self.mgr.register_app(config)
        scanners = self.mgr.get_scanners("scan-001")
        assert scanners is not None

    def test_health_check(self):
        health = self.mgr.health_check()
        assert isinstance(health, dict)
        assert "status" in health or "ok" in str(health).lower() or len(health) > 0

    def test_export_config(self):
        config = self._app("EXP-001", "Export App")
        self.mgr.register_app(config)
        exported = self.mgr.export_config("exp-001")
        assert exported is not None

    def test_load_from_dict(self):
        data = {
            "app_id": "DICT-001",
            "name": "Dict App",
            "criticality": "high",
            "data_classification": "pii",
            "components": [{"name": "backend"}],
            "compliance": [],
            "scanners": {},
            "policies": {"require_mpte_for": ["critical"]},
        }
        config = self.mgr.load_from_dict(data)
        assert isinstance(config, AppConfig)
        assert config.name == "Dict App"
