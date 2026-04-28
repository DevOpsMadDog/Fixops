"""
Tests that SDK packages are properly scaffolded and buildable.
Verifies: Python aldeci-client + TypeScript @aldeci/client package metadata and importability.
"""

import importlib
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
PYTHON_SDK_ROOT = REPO_ROOT / "sdks" / "python"
TS_SDK_ROOT = REPO_ROOT / "sdks" / "typescript"


# ---------------------------------------------------------------------------
# Python SDK tests
# ---------------------------------------------------------------------------


class TestPythonSDKPackageMetadata:
    """Verify Python SDK package files exist with correct metadata."""

    def test_pyproject_toml_exists(self):
        assert (PYTHON_SDK_ROOT / "pyproject.toml").exists(), "pyproject.toml missing"

    def test_pyproject_toml_name_is_aldeci_client(self):
        try:
            import tomllib  # Python 3.11+
        except ImportError:
            import tomli as tomllib  # type: ignore[no-redef]

        with open(PYTHON_SDK_ROOT / "pyproject.toml", "rb") as f:
            data = tomllib.load(f)
        name = data["tool"]["poetry"]["name"]
        assert name == "aldeci-client", f"Expected 'aldeci-client', got '{name}'"

    def test_setup_cfg_exists(self):
        assert (PYTHON_SDK_ROOT / "setup.cfg").exists(), "setup.cfg missing"

    def test_setup_cfg_name_is_aldeci_client(self):
        import configparser

        cfg = configparser.ConfigParser()
        cfg.read(PYTHON_SDK_ROOT / "setup.cfg")
        name = cfg["metadata"]["name"]
        assert name == "aldeci-client", f"Expected 'aldeci-client', got '{name}'"

    def test_aldeci_client_package_dir_exists(self):
        assert (PYTHON_SDK_ROOT / "aldeci_client").is_dir(), "aldeci_client/ directory missing"

    def test_aldeci_client_has_init(self):
        assert (PYTHON_SDK_ROOT / "aldeci_client" / "__init__.py").exists()

    def test_aldeci_client_has_client_module(self):
        assert (PYTHON_SDK_ROOT / "aldeci_client" / "client.py").exists()

    def test_aldeci_client_has_models(self):
        models_dir = PYTHON_SDK_ROOT / "aldeci_client" / "models"
        assert models_dir.is_dir(), "aldeci_client/models/ directory missing"
        assert any(models_dir.glob("*.py")), "No model files found in aldeci_client/models/"

    def test_aldeci_client_has_api(self):
        api_dir = PYTHON_SDK_ROOT / "aldeci_client" / "api"
        assert api_dir.is_dir(), "aldeci_client/api/ directory missing"

    def test_readme_exists(self):
        assert (PYTHON_SDK_ROOT / "README.md").exists()

    def test_readme_mentions_aldeci_client(self):
        readme = (PYTHON_SDK_ROOT / "README.md").read_text()
        assert "aldeci-client" in readme
        assert "aldeci_client" in readme


class TestPythonSDKImportable:
    """Verify the Python SDK can be imported (requires pip install -e sdks/python)."""

    def test_aldeci_client_importable(self):
        try:
            mod = importlib.import_module("aldeci_client")
            assert mod is not None
        except ImportError as e:
            pytest.skip(f"aldeci_client not installed: {e}")

    def test_aldeci_client_exports_authenticated_client(self):
        try:
            from aldeci_client import AuthenticatedClient

            assert AuthenticatedClient is not None
        except ImportError as e:
            pytest.skip(f"aldeci_client not installed: {e}")

    def test_aldeci_client_exports_client(self):
        try:
            from aldeci_client import Client

            assert Client is not None
        except ImportError as e:
            pytest.skip(f"aldeci_client not installed: {e}")

    def test_aldeci_client_can_instantiate_client(self):
        try:
            from aldeci_client import Client

            c = Client(base_url="http://localhost:8000")
            assert c is not None
        except ImportError as e:
            pytest.skip(f"aldeci_client not installed: {e}")


# ---------------------------------------------------------------------------
# TypeScript SDK tests
# ---------------------------------------------------------------------------


class TestTypeScriptSDKPackageMetadata:
    """Verify TypeScript SDK package files exist with correct metadata."""

    def test_package_json_exists(self):
        assert (TS_SDK_ROOT / "package.json").exists(), "package.json missing"

    def test_package_json_name_is_aldeci_client(self):
        with open(TS_SDK_ROOT / "package.json") as f:
            pkg = json.load(f)
        assert pkg["name"] == "@aldeci/client", f"Expected '@aldeci/client', got '{pkg['name']}'"

    def test_package_json_has_version(self):
        with open(TS_SDK_ROOT / "package.json") as f:
            pkg = json.load(f)
        assert "version" in pkg and pkg["version"], "version missing from package.json"

    def test_tsconfig_exists(self):
        assert (TS_SDK_ROOT / "tsconfig.json").exists(), "tsconfig.json missing"

    def test_tsconfig_targets_src(self):
        with open(TS_SDK_ROOT / "tsconfig.json") as f:
            cfg = json.load(f)
        assert "src/**/*" in cfg.get("include", []), "tsconfig.json should include src/**/*"

    def test_src_directory_exists(self):
        assert (TS_SDK_ROOT / "src").is_dir(), "src/ directory missing"

    def test_src_has_index(self):
        assert (TS_SDK_ROOT / "src" / "index.ts").exists(), "src/index.ts missing"

    def test_src_has_models(self):
        models_dir = TS_SDK_ROOT / "src" / "models"
        assert models_dir.is_dir(), "src/models/ missing"
        assert any(models_dir.glob("*.ts")), "No .ts files in src/models/"

    def test_src_has_services(self):
        services_dir = TS_SDK_ROOT / "src" / "services"
        assert services_dir.is_dir(), "src/services/ missing"
        assert any(services_dir.glob("*.ts")), "No .ts files in src/services/"

    def test_readme_exists(self):
        assert (TS_SDK_ROOT / "README.md").exists()

    def test_readme_mentions_aldeci_client(self):
        readme = (TS_SDK_ROOT / "README.md").read_text()
        assert "@aldeci/client" in readme


class TestTypeScriptSDKBuilt:
    """Verify the TypeScript SDK has been compiled (dist/ with .d.ts files)."""

    def test_dist_directory_exists(self):
        dist = TS_SDK_ROOT / "dist"
        assert dist.is_dir(), (
            "dist/ not found — run: cd sdks/typescript && npm install && npm run build"
        )

    def test_dist_has_declaration_files(self):
        dist = TS_SDK_ROOT / "dist"
        if not dist.is_dir():
            pytest.skip("dist/ not built yet")
        dts_files = list(dist.rglob("*.d.ts"))
        assert len(dts_files) > 0, "No .d.ts declaration files found in dist/"

    def test_dist_has_js_files(self):
        dist = TS_SDK_ROOT / "dist"
        if not dist.is_dir():
            pytest.skip("dist/ not built yet")
        js_files = list(dist.rglob("*.js"))
        assert len(js_files) > 0, "No .js files found in dist/"
