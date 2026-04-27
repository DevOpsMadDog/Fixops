"""
PR1 Tests: Validate suite-ui/aldeci-ui-new is the official UI and web/ MFEs are deprecated.

These tests ensure:
1. suite-ui/aldeci-ui-new exists and has required files
2. web/ no longer exists (moved to archive)
3. Backend CORS allows Vite dev server
"""

from pathlib import Path


# Get project root (assumes tests are run from project root or tests/ directory)
def get_project_root() -> Path:
    """Find the project root by looking for key markers."""
    current = Path(__file__).resolve().parent
    while current != current.parent:
        # Look for suite-api/apps/api/app.py (new structure) or apps/api/app.py (legacy)
        if (current / "suite-api" / "apps" / "api" / "app.py").exists():
            return current
        if (current / "apps" / "api" / "app.py").exists():
            return current
        current = current.parent
    # Fallback to parent of tests/
    return Path(__file__).resolve().parent.parent


PROJECT_ROOT = get_project_root()


class TestUIAldeciNewIsOfficialUI:
    """Verify suite-ui/aldeci-ui-new is the official frontend."""

    def test_ui_aldeci_new_directory_exists(self):
        """suite-ui/aldeci-ui-new directory must exist."""
        ui_path = PROJECT_ROOT / "suite-ui" / "aldeci-ui-new"
        assert ui_path.exists(), f"suite-ui/aldeci-ui-new directory should exist at {ui_path}"
        assert ui_path.is_dir(), "suite-ui/aldeci-ui-new should be a directory"

    def test_ui_aldeci_new_has_package_json(self):
        """suite-ui/aldeci-ui-new must have package.json."""
        pkg_json = PROJECT_ROOT / "suite-ui" / "aldeci-ui-new" / "package.json"
        assert pkg_json.exists(), "suite-ui/aldeci-ui-new should have package.json"

    def test_ui_aldeci_new_has_vite_config(self):
        """suite-ui/aldeci-ui-new must be a Vite project."""
        vite_config_ts = PROJECT_ROOT / "suite-ui" / "aldeci-ui-new" / "vite.config.ts"
        vite_config_js = PROJECT_ROOT / "suite-ui" / "aldeci-ui-new" / "vite.config.js"
        assert vite_config_ts.exists() or vite_config_js.exists(), (
            "suite-ui/aldeci-ui-new should have vite.config.ts or vite.config.js"
        )

    def test_ui_aldeci_new_has_src_directory(self):
        """suite-ui/aldeci-ui-new must have src/ directory."""
        src_dir = PROJECT_ROOT / "suite-ui" / "aldeci-ui-new" / "src"
        assert src_dir.exists(), "suite-ui/aldeci-ui-new should have src/ directory"
        assert src_dir.is_dir(), "src should be a directory"


class TestLegacyMFEsDeprecated:
    """Verify web/ MFEs are deprecated and moved to archive."""

    def test_web_directory_does_not_exist(self):
        """web/ directory should not exist at project root."""
        web_path = PROJECT_ROOT / "web"
        assert not web_path.exists(), (
            f"web/ directory should not exist at {web_path}. "
            "It should be moved to archive/web_mfe_legacy/"
        )


class TestBackendCORS:
    """Verify backend CORS allows Vite dev server."""

    def test_cors_source_includes_vite_port(self):
        """suite-api/apps/api/app.py should allow localhost:5173 in CORS."""
        app_py = PROJECT_ROOT / "suite-api" / "apps" / "api" / "app.py"
        content = app_py.read_text()
        assert (
            "localhost:5173" in content
        ), "Backend CORS should allow Vite dev server on port 5173"
        assert (
            "127.0.0.1:5173" in content
        ), "Backend CORS should allow Vite dev server on 127.0.0.1:5173"
