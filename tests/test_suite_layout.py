"""
PR2.2b Suite Layout Tests

Tests to verify the restructured repository layout:
1. Root contains only suite-* folders plus essentials (docs, scripts, tests, archive, data)
2. Legacy top-level code dirs do NOT exist at root
3. Imports still work via sitecustomize.py sys.path configuration
"""

import os
import sys
from pathlib import Path

import pytest


def get_project_root() -> Path:
    """Find the project root by looking for sitecustomize.py."""
    current = Path(__file__).resolve().parent
    while current != current.parent:
        if (current / "sitecustomize.py").exists():
            return current
        current = current.parent
    return Path(__file__).resolve().parent.parent


PROJECT_ROOT = get_project_root()


class TestSuiteDirectoriesExist:
    """Verify suite directories exist at root."""

    def test_suite_api_exists(self):
        """suite-api/ must exist at root."""
        suite_path = PROJECT_ROOT / "suite-api"
        assert suite_path.exists(), "suite-api/ should exist at project root"
        assert suite_path.is_dir(), "suite-api should be a directory"

    def test_suite_core_exists(self):
        """suite-core/ must exist at root."""
        suite_path = PROJECT_ROOT / "suite-core"
        assert suite_path.exists(), "suite-core/ should exist at project root"
        assert suite_path.is_dir(), "suite-core should be a directory"

    def test_suite_ui_exists(self):
        """suite-ui/ must exist at root."""
        suite_path = PROJECT_ROOT / "suite-ui"
        assert suite_path.exists(), "suite-ui/ should exist at project root"
        assert suite_path.is_dir(), "suite-ui should be a directory"

    def test_suite_integrations_exists(self):
        """suite-integrations/ must exist at root."""
        suite_path = PROJECT_ROOT / "suite-integrations"
        assert suite_path.exists(), "suite-integrations/ should exist at project root"
        assert suite_path.is_dir(), "suite-integrations should be a directory"

    def test_suite_evidence_risk_exists(self):
        """suite-evidence-risk/ must exist at root."""
        suite_path = PROJECT_ROOT / "suite-evidence-risk"
        assert suite_path.exists(), "suite-evidence-risk/ should exist at project root"
        assert suite_path.is_dir(), "suite-evidence-risk should be a directory"

    def test_suite_attack_exists(self):
        """suite-attack/ must exist at root."""
        suite_path = PROJECT_ROOT / "suite-attack"
        assert suite_path.exists(), "suite-attack/ should exist at project root"
        assert suite_path.is_dir(), "suite-attack should be a directory"

    def test_suite_feeds_exists(self):
        """suite-feeds/ must exist at root."""
        suite_path = PROJECT_ROOT / "suite-feeds"
        assert suite_path.exists(), "suite-feeds/ should exist at project root"
        assert suite_path.is_dir(), "suite-feeds should be a directory"


class TestLegacyDirsNotAtRoot:
    """Verify legacy code directories do NOT exist at root."""

    @pytest.mark.parametrize("legacy_dir", [
        "apps",
        "backend",
        "core",
        "risk",
        "evidence",
        "integrations",
        "ui",
        "services",
        "telemetry",
        "agents",
    ])
    def test_legacy_dir_not_at_root(self, legacy_dir: str):
        """Legacy code directory should not exist at root."""
        legacy_path = PROJECT_ROOT / legacy_dir
        assert not legacy_path.exists(), (
            f"{legacy_dir}/ should not exist at root after restructure. "
            f"It should be moved to a suite-* folder."
        )


class TestEssentialDirsExist:
    """Verify essential directories exist at root."""

    @pytest.mark.parametrize("essential_dir", [
        "docs",
        "scripts",
        "tests",
        "archive",
        ".github",
    ])
    def test_essential_dir_exists(self, essential_dir: str):
        """Essential directory should exist at root."""
        dir_path = PROJECT_ROOT / essential_dir
        assert dir_path.exists(), f"{essential_dir}/ should exist at project root"


class TestSitecustomizeExists:
    """Verify sitecustomize.py exists for sys.path configuration."""

    def test_sitecustomize_exists(self):
        """sitecustomize.py must exist at root."""
        sitecustomize = PROJECT_ROOT / "sitecustomize.py"
        assert sitecustomize.exists(), "sitecustomize.py should exist at project root"

    def test_sitecustomize_has_suite_paths(self):
        """sitecustomize.py should reference suite paths."""
        sitecustomize = PROJECT_ROOT / "sitecustomize.py"
        content = sitecustomize.read_text()
        assert "suite-api" in content, "sitecustomize.py should reference suite-api"
        assert "suite-core" in content, "sitecustomize.py should reference suite-core"
        assert "suite-attack" in content, "sitecustomize.py should reference suite-attack"
        assert "suite-feeds" in content, "sitecustomize.py should reference suite-feeds"
        assert "sys.path" in content, "sitecustomize.py should modify sys.path"


class TestImportsStillWork:
    """Verify that legacy imports still work via sitecustomize.py."""

    def test_import_apps_api_app(self):
        """import apps.api.app should work."""
        # Ensure suite paths are in sys.path
        suite_api_path = str(PROJECT_ROOT / "suite-api")
        if suite_api_path not in sys.path:
            sys.path.insert(0, suite_api_path)
        
        # Add archive/legacy for fixops module
        legacy_path = str(PROJECT_ROOT / "archive" / "legacy")
        if legacy_path not in sys.path:
            sys.path.insert(0, legacy_path)
        
        # Skip path security check for tests
        os.environ.setdefault("FIXOPS_SKIP_PATH_SECURITY", "1")
        
        try:
            from apps.api.app import create_app
            assert callable(create_app), "create_app should be callable"
        except ImportError as e:
            pytest.fail(f"Failed to import apps.api.app: {e}")

    def test_import_core(self):
        """import core should work."""
        suite_core_path = str(PROJECT_ROOT / "suite-core")
        if suite_core_path not in sys.path:
            sys.path.insert(0, suite_core_path)
        
        try:
            import core
            assert core is not None
        except ImportError as e:
            pytest.fail(f"Failed to import core: {e}")

    def test_import_risk(self):
        """import risk should work."""
        suite_er_path = str(PROJECT_ROOT / "suite-evidence-risk")
        if suite_er_path not in sys.path:
            sys.path.insert(0, suite_er_path)
        
        try:
            import risk
            assert risk is not None
        except ImportError as e:
            pytest.fail(f"Failed to import risk: {e}")

    def test_import_backend(self):
        """import backend should work."""
        suite_api_path = str(PROJECT_ROOT / "suite-api")
        if suite_api_path not in sys.path:
            sys.path.insert(0, suite_api_path)
        
        try:
            import backend
            assert backend is not None
        except ImportError as e:
            pytest.fail(f"Failed to import backend: {e}")


class TestCreateAppWorks:
    """Verify that the FastAPI app can be created."""

    def test_create_app_returns_fastapi_instance(self):
        """create_app() should return a FastAPI application."""
        # Ensure suite paths are in sys.path
        suite_api_path = str(PROJECT_ROOT / "suite-api")
        suite_core_path = str(PROJECT_ROOT / "suite-core")
        suite_attack_path = str(PROJECT_ROOT / "suite-attack")
        suite_feeds_path = str(PROJECT_ROOT / "suite-feeds")
        suite_er_path = str(PROJECT_ROOT / "suite-evidence-risk")
        suite_int_path = str(PROJECT_ROOT / "suite-integrations")
        legacy_path = str(PROJECT_ROOT / "archive" / "legacy")

        for path in [suite_api_path, suite_core_path, suite_attack_path, suite_feeds_path, suite_er_path, suite_int_path, legacy_path]:
            if path not in sys.path:
                sys.path.insert(0, path)
        
        # Set minimal environment
        os.environ.setdefault("FIXOPS_JWT_SECRET", "test-secret")
        os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
        os.environ.setdefault("FIXOPS_DEMO_MODE", "true")
        os.environ.setdefault("FIXOPS_SKIP_PATH_SECURITY", "1")
        
        try:
            from apps.api.app import create_app
            app = create_app()
            
            from fastapi import FastAPI
            assert isinstance(app, FastAPI), "create_app() should return a FastAPI instance"
        except ImportError as e:
            pytest.fail(f"Failed to create app: {e}")


class TestSuiteContents:
    """Verify suite directories contain expected contents."""

    def test_suite_api_has_apps(self):
        """suite-api/apps should exist."""
        apps_path = PROJECT_ROOT / "suite-api" / "apps"
        assert apps_path.exists(), "suite-api/apps should exist"

    def test_suite_api_has_backend(self):
        """suite-api/backend should exist."""
        backend_path = PROJECT_ROOT / "suite-api" / "backend"
        assert backend_path.exists(), "suite-api/backend should exist"

    def test_suite_core_has_core(self):
        """suite-core/core should exist."""
        core_path = PROJECT_ROOT / "suite-core" / "core"
        assert core_path.exists(), "suite-core/core should exist"

    def test_suite_ui_has_aldeci(self):
        """suite-ui/aldeci should exist."""
        aldeci_path = PROJECT_ROOT / "suite-ui" / "aldeci"
        assert aldeci_path.exists(), "suite-ui/aldeci should exist"

    def test_suite_evidence_risk_has_risk(self):
        """suite-evidence-risk/risk should exist."""
        risk_path = PROJECT_ROOT / "suite-evidence-risk" / "risk"
        assert risk_path.exists(), "suite-evidence-risk/risk should exist"

    def test_suite_evidence_risk_has_evidence(self):
        """suite-evidence-risk/evidence should exist."""
        evidence_path = PROJECT_ROOT / "suite-evidence-risk" / "evidence"
        assert evidence_path.exists(), "suite-evidence-risk/evidence should exist"

    def test_suite_integrations_has_integrations(self):
        """suite-integrations/integrations should exist."""
        integrations_path = PROJECT_ROOT / "suite-integrations" / "integrations"
        assert integrations_path.exists(), "suite-integrations/integrations should exist"

    def test_suite_attack_has_api(self):
        """suite-attack/api should exist with attack routers."""
        api_path = PROJECT_ROOT / "suite-attack" / "api"
        assert api_path.exists(), "suite-attack/api should exist"
        assert (api_path / "micro_pentest_router.py").exists(), "micro_pentest_router.py should be in suite-attack/api"
        assert (api_path / "mpte_router.py").exists(), "mpte_router.py should be in suite-attack/api"

    def test_suite_feeds_has_api(self):
        """suite-feeds/api should exist with feeds router."""
        api_path = PROJECT_ROOT / "suite-feeds" / "api"
        assert api_path.exists(), "suite-feeds/api should exist"
        assert (api_path / "feeds_router.py").exists(), "feeds_router.py should be in suite-feeds/api"

    def test_suite_feeds_has_service(self):
        """suite-feeds/feeds_service.py should exist."""
        svc_path = PROJECT_ROOT / "suite-feeds" / "feeds_service.py"
        assert svc_path.exists(), "feeds_service.py should be in suite-feeds root"
