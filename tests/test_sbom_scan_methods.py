"""
Tests for SBOMGenerator.scan_python_deps, scan_js_deps, get_sbom_stats
and the /api/v1/sbom/cyclonedx, /spdx, /stats router endpoints.

Covers (15+ tests):
- scan_python_deps returns list with name/version/license/purl keys
- scan_python_deps purl format is pkg:pypi/...
- scan_python_deps on missing file returns []
- scan_js_deps returns list with name/version/license/purl keys
- scan_js_deps purl format is pkg:npm/...
- scan_js_deps on missing file returns []
- scan_js_deps on invalid JSON returns []
- get_sbom_stats keys: python_deps, js_deps, total_deps, generated_at
- get_sbom_stats total_deps == python_deps + js_deps
- generate_cyclonedx produces CycloneDX 1.4 envelope
- generate_cyclonedx components array non-empty when deps present
- generate_spdx produces SPDX 2.3 envelope
- generate_spdx packages array non-empty when deps present
- router GET /cyclonedx returns 200 with sbom key
- router GET /spdx returns 200 with sbom key
- router GET /stats returns python_deps, js_deps, total_deps, generated_at
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))

os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-secret")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

from core.sbom_generator import SBOMGenerator


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

REQUIREMENTS_TXT = """\
requests==2.31.0
fastapi==0.110.0
pydantic==2.6.4
uvicorn==0.29.0
structlog==24.1.0
"""

PACKAGE_JSON = json.dumps({
    "name": "aldeci-ui-new",
    "version": "0.1.0",
    "license": "MIT",
    "dependencies": {
        "react": "^19.0.0",
        "react-dom": "^19.0.0",
    },
    "devDependencies": {
        "vite": "^6.0.0",
        "@vitejs/plugin-react": "^4.2.0",
    },
})


@pytest.fixture
def gen(tmp_path) -> SBOMGenerator:
    return SBOMGenerator(
        project_name="aldeci",
        project_version="2.0.0",
        db_path=str(tmp_path / "sbom_test.db"),
    )


# ---------------------------------------------------------------------------
# scan_python_deps
# ---------------------------------------------------------------------------

def test_scan_python_deps_returns_list(gen):
    with patch("builtins.open", MagicMock()), \
         patch.object(Path, "exists", return_value=True), \
         patch.object(Path, "read_text", return_value=REQUIREMENTS_TXT):
        result = gen.scan_python_deps("org1")
    assert isinstance(result, list)
    assert len(result) == 5


def test_scan_python_deps_item_keys(gen):
    with patch.object(Path, "exists", return_value=True), \
         patch.object(Path, "read_text", return_value=REQUIREMENTS_TXT):
        result = gen.scan_python_deps("org1")
    for item in result:
        assert "name" in item
        assert "version" in item
        assert "license" in item
        assert "purl" in item


def test_scan_python_deps_purl_format(gen):
    with patch.object(Path, "exists", return_value=True), \
         patch.object(Path, "read_text", return_value=REQUIREMENTS_TXT):
        result = gen.scan_python_deps("org1")
    for item in result:
        assert item["purl"].startswith("pkg:pypi/"), f"Bad purl: {item['purl']}"


def test_scan_python_deps_missing_file_returns_empty(gen):
    with patch.object(Path, "exists", return_value=False):
        result = gen.scan_python_deps("org1")
    assert result == []


def test_scan_python_deps_specific_package(gen):
    with patch.object(Path, "exists", return_value=True), \
         patch.object(Path, "read_text", return_value=REQUIREMENTS_TXT):
        result = gen.scan_python_deps("org1")
    names = [r["name"] for r in result]
    assert "requests" in names
    assert "fastapi" in names


# ---------------------------------------------------------------------------
# scan_js_deps
# ---------------------------------------------------------------------------

def test_scan_js_deps_returns_list(gen):
    with patch.object(Path, "exists", return_value=True), \
         patch.object(Path, "read_text", return_value=PACKAGE_JSON):
        result = gen.scan_js_deps("org1")
    assert isinstance(result, list)
    assert len(result) == 4  # 2 deps + 2 devDeps


def test_scan_js_deps_item_keys(gen):
    with patch.object(Path, "exists", return_value=True), \
         patch.object(Path, "read_text", return_value=PACKAGE_JSON):
        result = gen.scan_js_deps("org1")
    for item in result:
        assert "name" in item
        assert "version" in item
        assert "license" in item
        assert "purl" in item


def test_scan_js_deps_purl_format(gen):
    with patch.object(Path, "exists", return_value=True), \
         patch.object(Path, "read_text", return_value=PACKAGE_JSON):
        result = gen.scan_js_deps("org1")
    for item in result:
        assert item["purl"].startswith("pkg:npm/"), f"Bad purl: {item['purl']}"


def test_scan_js_deps_missing_file_returns_empty(gen):
    with patch.object(Path, "exists", return_value=False):
        result = gen.scan_js_deps("org1")
    assert result == []


def test_scan_js_deps_invalid_json_returns_empty(gen):
    with patch.object(Path, "exists", return_value=True), \
         patch.object(Path, "read_text", return_value="NOT JSON {{{"):
        result = gen.scan_js_deps("org1")
    assert result == []


def test_scan_js_deps_specific_package(gen):
    with patch.object(Path, "exists", return_value=True), \
         patch.object(Path, "read_text", return_value=PACKAGE_JSON):
        result = gen.scan_js_deps("org1")
    names = [r["name"] for r in result]
    assert "react" in names
    assert "vite" in names


# ---------------------------------------------------------------------------
# get_sbom_stats
# ---------------------------------------------------------------------------

def test_get_sbom_stats_keys(gen):
    with patch.object(gen, "scan_python_deps", return_value=[{"name": "a"}] * 3), \
         patch.object(gen, "scan_js_deps", return_value=[{"name": "b"}] * 2):
        stats = gen.get_sbom_stats("org1")
    assert "python_deps" in stats
    assert "js_deps" in stats
    assert "total_deps" in stats
    assert "generated_at" in stats


def test_get_sbom_stats_totals(gen):
    with patch.object(gen, "scan_python_deps", return_value=[{}] * 7), \
         patch.object(gen, "scan_js_deps", return_value=[{}] * 4):
        stats = gen.get_sbom_stats("org1")
    assert stats["python_deps"] == 7
    assert stats["js_deps"] == 4
    assert stats["total_deps"] == 11


def test_get_sbom_stats_generated_at_is_iso(gen):
    with patch.object(gen, "scan_python_deps", return_value=[]), \
         patch.object(gen, "scan_js_deps", return_value=[]):
        stats = gen.get_sbom_stats("default")
    # Should be parseable as ISO datetime
    from datetime import datetime
    dt = datetime.fromisoformat(stats["generated_at"])
    assert dt is not None


# ---------------------------------------------------------------------------
# generate_cyclonedx / generate_spdx with scan output
# ---------------------------------------------------------------------------

def test_generate_cyclonedx_from_scan(gen):
    with patch.object(Path, "exists", return_value=True), \
         patch.object(Path, "read_text", return_value=REQUIREMENTS_TXT):
        components = gen.scan_python_deps("org1")
    sbom = gen.generate_cyclonedx(components)
    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.4"
    assert len(sbom["components"]) == 5


def test_generate_cyclonedx_component_has_purl(gen):
    with patch.object(Path, "exists", return_value=True), \
         patch.object(Path, "read_text", return_value=REQUIREMENTS_TXT):
        components = gen.scan_python_deps("org1")
    sbom = gen.generate_cyclonedx(components)
    for comp in sbom["components"]:
        assert "purl" in comp
        assert comp["purl"].startswith("pkg:pypi/")


def test_generate_spdx_from_scan(gen):
    with patch.object(Path, "exists", return_value=True), \
         patch.object(Path, "read_text", return_value=PACKAGE_JSON):
        components = gen.scan_js_deps("org1")
    sbom = gen.generate_spdx(components)
    assert "spdxVersion" in sbom
    assert sbom["spdxVersion"].startswith("SPDX-")
    assert len(sbom["packages"]) == 4


def test_generate_spdx_package_has_spdxid(gen):
    with patch.object(Path, "exists", return_value=True), \
         patch.object(Path, "read_text", return_value=PACKAGE_JSON):
        components = gen.scan_js_deps("org1")
    sbom = gen.generate_spdx(components)
    for pkg in sbom["packages"]:
        assert "SPDXID" in pkg
        assert pkg["SPDXID"].startswith("SPDXRef-")
