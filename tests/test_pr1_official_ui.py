"""
PR1 Tests: Validate suite-ui/aldeci is the official UI and web/ MFEs are deprecated.

These tests ensure:
1. suite-ui/aldeci exists and has required files
2. web/ no longer exists (moved to archive)
3. .env.example is present
4. CORS allows Vite dev server
"""

import os
from pathlib import Path

import pytest


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


class TestUIAldeciIsOfficialUI:
    """Verify suite-ui/aldeci is the official frontend."""

    def test_ui_aldeci_directory_exists(self):
        """suite-ui/aldeci directory must exist."""
        ui_path = PROJECT_ROOT / "suite-ui" / "aldeci"
        assert ui_path.exists(), f"suite-ui/aldeci directory should exist at {ui_path}"
        assert ui_path.is_dir(), "suite-ui/aldeci should be a directory"

    def test_ui_aldeci_has_package_json(self):
        """suite-ui/aldeci must have package.json."""
        pkg_json = PROJECT_ROOT / "suite-ui" / "aldeci" / "package.json"
        assert pkg_json.exists(), "suite-ui/aldeci should have package.json"

    def test_ui_aldeci_has_vite_config(self):
        """suite-ui/aldeci must be a Vite project."""
        vite_config = PROJECT_ROOT / "suite-ui" / "aldeci" / "vite.config.ts"
        assert vite_config.exists(), "suite-ui/aldeci should have vite.config.ts"

    def test_ui_aldeci_has_src_directory(self):
        """suite-ui/aldeci must have src/ directory."""
        src_dir = PROJECT_ROOT / "suite-ui" / "aldeci" / "src"
        assert src_dir.exists(), "suite-ui/aldeci should have src/ directory"
        assert src_dir.is_dir(), "src should be a directory"

    def test_ui_aldeci_has_env_example(self):
        """suite-ui/aldeci must have .env.example for configuration."""
        env_example = PROJECT_ROOT / "suite-ui" / "aldeci" / ".env.example"
        assert env_example.exists(), "suite-ui/aldeci should have .env.example"

    def test_ui_aldeci_env_example_has_vite_api_url(self):
        """suite-ui/aldeci/.env.example must define VITE_API_URL."""
        env_example = PROJECT_ROOT / "suite-ui" / "aldeci" / ".env.example"
        content = env_example.read_text()
        assert "VITE_API_URL" in content, ".env.example should define VITE_API_URL"

    def test_ui_aldeci_has_screen_api_mapping(self):
        """suite-ui/aldeci must have SCREEN_API_MAPPING.md."""
        mapping_file = PROJECT_ROOT / "suite-ui" / "aldeci" / "SCREEN_API_MAPPING.md"
        assert mapping_file.exists(), "suite-ui/aldeci should have SCREEN_API_MAPPING.md"


class TestLegacyMFEsDeprecated:
    """Verify web/ MFEs are deprecated and moved to archive."""

    def test_web_directory_does_not_exist(self):
        """web/ directory should not exist at project root."""
        web_path = PROJECT_ROOT / "web"
        assert not web_path.exists(), (
            f"web/ directory should not exist at {web_path}. "
            "It should be moved to archive/web_mfe_legacy/"
        )

    def test_legacy_mfe_in_archive(self):
        """Legacy MFEs should be in archive/web_mfe_legacy/."""
        archive_path = PROJECT_ROOT / "archive" / "web_mfe_legacy"
        assert archive_path.exists(), (
            "Legacy MFEs should be archived at archive/web_mfe_legacy/"
        )
        assert archive_path.is_dir(), "archive/web_mfe_legacy should be a directory"

    def test_legacy_ui_documentation_exists(self):
        """docs/legacy-ui.md should document the deprecation."""
        legacy_doc = PROJECT_ROOT / "docs" / "legacy-ui.md"
        assert legacy_doc.exists(), "docs/legacy-ui.md should document MFE deprecation"

    def test_legacy_ui_doc_mentions_deprecation(self):
        """docs/legacy-ui.md should mention deprecation."""
        legacy_doc = PROJECT_ROOT / "docs" / "legacy-ui.md"
        content = legacy_doc.read_text()
        assert "deprecated" in content.lower(), (
            "docs/legacy-ui.md should mention deprecation"
        )
        assert "archive/web_mfe_legacy" in content, (
            "docs/legacy-ui.md should reference archive location"
        )


class TestReadmeUpdated:
    """Verify README.md points to suite-ui/aldeci as official UI."""

    def test_readme_mentions_ui_aldeci(self):
        """README should mention suite-ui/aldeci."""
        readme = PROJECT_ROOT / "README.md"
        content = readme.read_text()
        assert "suite-ui/aldeci" in content, "README should mention suite-ui/aldeci"

    def test_readme_mentions_vite(self):
        """README should mention Vite for ui/aldeci."""
        readme = PROJECT_ROOT / "README.md"
        content = readme.read_text()
        assert "npm run dev" in content, "README should include npm run dev command"

    def test_readme_mentions_legacy_deprecation(self):
        """README should note web/ deprecation."""
        readme = PROJECT_ROOT / "README.md"
        content = readme.read_text()
        assert "legacy" in content.lower() or "deprecated" in content.lower(), (
            "README should mention legacy/deprecated MFEs"
        )


class TestBackendCORS:
    """Verify backend CORS allows Vite dev server."""

    def test_cors_source_includes_vite_port(self):
        """suite-api/apps/api/app.py should allow localhost:5173 in CORS."""
        app_py = PROJECT_ROOT / "suite-api" / "apps" / "api" / "app.py"
        content = app_py.read_text()
        assert "localhost:5173" in content, (
            "Backend CORS should allow Vite dev server on port 5173"
        )
        assert "127.0.0.1:5173" in content, (
            "Backend CORS should allow Vite dev server on 127.0.0.1:5173"
        )
