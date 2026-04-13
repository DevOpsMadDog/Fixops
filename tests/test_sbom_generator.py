"""
Tests for suite-core/core/sbom_generator.py

Covers:
- requirements.txt parsing (various formats)
- package.json parsing (deps, devDeps, peerDeps)
- CycloneDX 1.4 envelope structure
- pip list SBOM generation (mocked subprocess)
- OSV batch query (mocked HTTP)
- OSV scan for SBOM (mocked)
- map_osv_to_findings schema
- generate_from_requirements FileNotFoundError
- generate_from_package_json FileNotFoundError / invalid JSON
- purl generation
- empty manifest handling
- OSV network failure graceful fallback
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))

os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-secret")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

from core.sbom_generator import (
    SBOMGenerator,
    _make_purl,
    _parse_requirements_txt,
    _parse_package_json_deps,
    _cyclonedx_envelope,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def gen() -> SBOMGenerator:
    return SBOMGenerator(project_name="test-project", project_version="1.2.3")


@pytest.fixture
def tmp_requirements(tmp_path) -> Path:
    content = (
        "requests==2.28.2\n"
        "# comment line\n"
        "flask>=2.0\n"
        "numpy==1.24.0  # inline comment\n"
        "-r other.txt\n"
        "pydantic[email]==1.10.7\n"
    )
    p = tmp_path / "requirements.txt"
    p.write_text(content)
    return p


@pytest.fixture
def tmp_package_json(tmp_path) -> Path:
    data = {
        "name": "my-app",
        "version": "2.0.0",
        "dependencies": {"lodash": "^4.17.21", "express": "4.18.2"},
        "devDependencies": {"jest": "^29.0.0"},
        "peerDependencies": {"react": ">=18.0.0"},
    }
    p = tmp_path / "package.json"
    p.write_text(json.dumps(data))
    return p


# ---------------------------------------------------------------------------
# Internal helper tests
# ---------------------------------------------------------------------------


def test_parse_requirements_txt_basic():
    text = "requests==2.28.2\nflask>=2.0\nnumpy"
    pairs = _parse_requirements_txt(text)
    names = [p[0] for p in pairs]
    assert "requests" in names
    assert "flask" in names
    assert "numpy" in names


def test_parse_requirements_txt_skips_comments_and_options():
    text = "# comment\n-r other.txt\n--index-url http://x\nrequests==1.0"
    pairs = _parse_requirements_txt(text)
    assert len(pairs) == 1
    assert pairs[0][0] == "requests"


def test_parse_requirements_txt_extracts_pinned_version():
    pairs = _parse_requirements_txt("pydantic==1.10.7")
    assert pairs[0] == ("pydantic", "1.10.7")


def test_parse_requirements_txt_extras_stripped():
    pairs = _parse_requirements_txt("pydantic[email]==1.10.7")
    assert pairs[0][0] == "pydantic"
    assert pairs[0][1] == "1.10.7"


def test_parse_package_json_deps_all_sections():
    data = {
        "dependencies": {"lodash": "^4.17.21"},
        "devDependencies": {"jest": "29.0.0"},
        "peerDependencies": {"react": ">=18.0.0"},
    }
    pairs = _parse_package_json_deps(data)
    names = [p[0] for p in pairs]
    assert "lodash" in names
    assert "jest" in names
    assert "react" in names


def test_make_purl_with_version():
    purl = _make_purl("pypi", "requests", "2.28.2")
    assert purl == "pkg:pypi/requests@2.28.2"


def test_make_purl_without_version():
    purl = _make_purl("npm", "lodash", "")
    assert purl == "pkg:npm/lodash"


# ---------------------------------------------------------------------------
# generate_from_requirements
# ---------------------------------------------------------------------------


def test_generate_from_requirements_structure(gen, tmp_requirements):
    sbom = gen.generate_from_requirements(str(tmp_requirements))
    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.4"
    assert "serialNumber" in sbom
    assert "metadata" in sbom
    assert "components" in sbom


def test_generate_from_requirements_components(gen, tmp_requirements):
    sbom = gen.generate_from_requirements(str(tmp_requirements))
    names = [c["name"] for c in sbom["components"]]
    assert "requests" in names
    assert "flask" in names
    assert "numpy" in names
    assert "pydantic" in names


def test_generate_from_requirements_purl_format(gen, tmp_requirements):
    sbom = gen.generate_from_requirements(str(tmp_requirements))
    requests_comp = next(c for c in sbom["components"] if c["name"] == "requests")
    assert requests_comp["purl"].startswith("pkg:pypi/requests")


def test_generate_from_requirements_file_not_found(gen):
    with pytest.raises(FileNotFoundError):
        gen.generate_from_requirements("/nonexistent/requirements.txt")


def test_generate_from_requirements_empty_file(gen, tmp_path):
    p = tmp_path / "requirements.txt"
    p.write_text("# only comments\n")
    sbom = gen.generate_from_requirements(str(p))
    assert sbom["components"] == []


# ---------------------------------------------------------------------------
# generate_from_package_json
# ---------------------------------------------------------------------------


def test_generate_from_package_json_structure(gen, tmp_package_json):
    sbom = gen.generate_from_package_json(str(tmp_package_json))
    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.4"
    assert sbom["metadata"]["component"]["name"] == "my-app"


def test_generate_from_package_json_components(gen, tmp_package_json):
    sbom = gen.generate_from_package_json(str(tmp_package_json))
    names = [c["name"] for c in sbom["components"]]
    assert "lodash" in names
    assert "express" in names
    assert "jest" in names
    assert "react" in names


def test_generate_from_package_json_file_not_found(gen):
    with pytest.raises(FileNotFoundError):
        gen.generate_from_package_json("/nonexistent/package.json")


def test_generate_from_package_json_invalid_json(gen, tmp_path):
    p = tmp_path / "package.json"
    p.write_text("not-json{{{")
    with pytest.raises((json.JSONDecodeError, ValueError)):
        gen.generate_from_package_json(str(p))


# ---------------------------------------------------------------------------
# generate_from_installed_pip (mocked)
# ---------------------------------------------------------------------------


def test_generate_from_installed_pip_success(gen):
    fake_packages = [{"name": "requests", "version": "2.28.2"}, {"name": "flask", "version": "2.3.0"}]
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = json.dumps(fake_packages)
    with patch("subprocess.run", return_value=mock_result):
        sbom = gen.generate_from_installed_pip()
    names = [c["name"] for c in sbom["components"]]
    assert "requests" in names
    assert "flask" in names


def test_generate_from_installed_pip_subprocess_failure(gen):
    mock_result = MagicMock()
    mock_result.returncode = 1
    mock_result.stderr = "pip error"
    mock_result.stdout = ""
    with patch("subprocess.run", return_value=mock_result):
        with pytest.raises(RuntimeError, match="pip list failed"):
            gen.generate_from_installed_pip()


# ---------------------------------------------------------------------------
# OSV query (mocked HTTP)
# ---------------------------------------------------------------------------


_FAKE_OSV_RESPONSE = {
    "results": [
        {
            "vulns": [
                {
                    "id": "PYSEC-2023-001",
                    "aliases": ["CVE-2023-12345"],
                    "summary": "Remote code execution in requests",
                    "details": "A vulnerability in requests allows RCE.",
                    "severity": [{"type": "CVSS_V3", "score": "9.8"}],
                    "affected": [{"ranges": [{"events": [{"fixed": "2.29.0"}]}]}],
                    "references": [{"url": "https://example.com/advisory"}],
                    "published": "2023-01-01T00:00:00Z",
                    "modified": "2023-01-02T00:00:00Z",
                }
            ]
        },
        {"vulns": []},
    ]
}


def test_query_osv_returns_findings(gen):
    packages = [
        {"name": "requests", "version": "2.28.0", "ecosystem": "PyPI"},
        {"name": "flask", "version": "2.3.0", "ecosystem": "PyPI"},
    ]
    with patch("core.sbom_generator._http_post_json", return_value=_FAKE_OSV_RESPONSE):
        results = gen.query_osv(packages)
    assert len(results) == 1
    assert results[0]["id"] == "PYSEC-2023-001"
    assert results[0]["affected_package"]["name"] == "requests"


def test_query_osv_network_error_returns_empty(gen):
    from urllib.error import URLError
    packages = [{"name": "requests", "version": "2.28.0", "ecosystem": "PyPI"}]
    with patch("core.sbom_generator._http_post_json", side_effect=URLError("timeout")):
        results = gen.query_osv(packages)
    assert results == []


def test_query_osv_empty_packages(gen):
    results = gen.query_osv([])
    assert results == []


def test_scan_osv_for_sbom(gen, tmp_requirements):
    sbom = gen.generate_from_requirements(str(tmp_requirements))
    with patch("core.sbom_generator._http_post_json", return_value={"results": []}):
        results = gen.scan_osv_for_sbom(sbom)
    assert isinstance(results, list)


# ---------------------------------------------------------------------------
# map_osv_to_findings schema
# ---------------------------------------------------------------------------


def test_map_osv_to_findings_schema(gen):
    raw = [
        {
            "id": "PYSEC-2023-001",
            "aliases": ["CVE-2023-12345"],
            "summary": "RCE vuln",
            "details": "Details here.",
            "severity": [{"type": "CVSS_V3", "score": "9.8"}],
            "affected": [{"ranges": [{"events": [{"fixed": "2.29.0"}]}]}],
            "references": [{"url": "https://example.com"}],
            "published": "2023-01-01T00:00:00Z",
            "modified": "2023-01-02T00:00:00Z",
            "affected_package": {"name": "requests", "version": "2.28.0"},
        }
    ]
    findings = gen.map_osv_to_findings(raw)
    assert len(findings) == 1
    f = findings[0]
    assert f["severity"] == "CRITICAL"
    assert f["cve_ids"] == ["CVE-2023-12345"]
    assert f["affected_package"] == "requests"
    assert f["affected_version"] == "2.28.0"
    assert "2.29.0" in f["fix_versions"]
    assert f["source"] == "osv.dev"
    assert "id" in f


def test_map_osv_to_findings_empty(gen):
    assert gen.map_osv_to_findings([]) == []


# ---------------------------------------------------------------------------
# Instance-method parse_requirements_txt
# ---------------------------------------------------------------------------


def test_instance_parse_requirements_txt_two_components(tmp_path):
    g = SBOMGenerator(db_path=str(tmp_path / "sbom.db"))
    comps = g.parse_requirements_txt("requests==2.28.0\nflask>=2.0.0")
    assert len(comps) == 2
    names = [c["name"] for c in comps]
    assert "requests" in names
    assert "flask" in names


def test_instance_parse_requirements_txt_empty_string(tmp_path):
    g = SBOMGenerator(db_path=str(tmp_path / "sbom.db"))
    comps = g.parse_requirements_txt("")
    assert comps == []


def test_instance_parse_requirements_txt_skips_comments(tmp_path):
    g = SBOMGenerator(db_path=str(tmp_path / "sbom.db"))
    comps = g.parse_requirements_txt("# comment\nrequests==1.0")
    assert len(comps) == 1
    assert comps[0]["name"] == "requests"


def test_instance_parse_requirements_txt_purl_format(tmp_path):
    g = SBOMGenerator(db_path=str(tmp_path / "sbom.db"))
    comps = g.parse_requirements_txt("requests==2.28.0")
    assert comps[0]["purl"] == "pkg:pypi/requests@2.28.0"


# ---------------------------------------------------------------------------
# Instance-method parse_package_json
# ---------------------------------------------------------------------------


def test_instance_parse_package_json_with_dependencies(tmp_path):
    g = SBOMGenerator(db_path=str(tmp_path / "sbom.db"))
    content = json.dumps({"dependencies": {"lodash": "^4.17.21"}, "devDependencies": {"jest": "29.0.0"}})
    comps = g.parse_package_json(content)
    names = [c["name"] for c in comps]
    assert "lodash" in names
    assert "jest" in names


def test_instance_parse_package_json_empty_dependencies(tmp_path):
    g = SBOMGenerator(db_path=str(tmp_path / "sbom.db"))
    comps = g.parse_package_json(json.dumps({}))
    assert comps == []


# ---------------------------------------------------------------------------
# parse_go_mod
# ---------------------------------------------------------------------------


def test_parse_go_mod_require_block(tmp_path):
    g = SBOMGenerator(db_path=str(tmp_path / "sbom.db"))
    content = "module example.com/myapp\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.0\n\tgolang.org/x/net v0.10.0\n)\n"
    comps = g.parse_go_mod(content)
    names = [c["name"] for c in comps]
    assert "github.com/gin-gonic/gin" in names
    assert "golang.org/x/net" in names


def test_parse_go_mod_purl_format(tmp_path):
    g = SBOMGenerator(db_path=str(tmp_path / "sbom.db"))
    content = "require (\n\tgithub.com/pkg/errors v0.9.1\n)\n"
    comps = g.parse_go_mod(content)
    assert comps[0]["purl"].startswith("pkg:golang/")


# ---------------------------------------------------------------------------
# generate_cyclonedx
# ---------------------------------------------------------------------------


def test_generate_cyclonedx_returns_bomformat(tmp_path):
    g = SBOMGenerator(db_path=str(tmp_path / "sbom.db"))
    comps = g.parse_requirements_txt("requests==2.28.0")
    sbom = g.generate_cyclonedx(comps)
    assert sbom["bomFormat"] == "CycloneDX"


def test_generate_cyclonedx_components_list(tmp_path):
    g = SBOMGenerator(db_path=str(tmp_path / "sbom.db"))
    comps = g.parse_requirements_txt("requests==2.28.0\nflask>=2.0")
    sbom = g.generate_cyclonedx(comps)
    assert len(sbom["components"]) == 2


# ---------------------------------------------------------------------------
# generate_spdx
# ---------------------------------------------------------------------------


def test_generate_spdx_returns_spdxversion(tmp_path):
    g = SBOMGenerator(db_path=str(tmp_path / "sbom.db"))
    comps = g.parse_requirements_txt("requests==2.28.0")
    sbom = g.generate_spdx(comps)
    assert "spdxVersion" in sbom
    assert sbom["spdxVersion"].startswith("SPDX-")


# ---------------------------------------------------------------------------
# store_sbom / get_sbom / list_sboms
# ---------------------------------------------------------------------------


def test_store_sbom_returns_nonempty_id(tmp_path):
    g = SBOMGenerator(db_path=str(tmp_path / "sbom.db"))
    comps = g.parse_requirements_txt("requests==2.28.0")
    sbom = g.generate_cyclonedx(comps)
    sbom_id = g.store_sbom(sbom, "cyclonedx", "myproject")
    assert sbom_id and isinstance(sbom_id, str)


def test_get_sbom_retrieves_stored(tmp_path):
    g = SBOMGenerator(db_path=str(tmp_path / "sbom.db"))
    comps = g.parse_requirements_txt("flask==2.0.0")
    sbom = g.generate_cyclonedx(comps)
    sbom_id = g.store_sbom(sbom, "cyclonedx", "myproject")
    retrieved = g.get_sbom(sbom_id)
    assert retrieved is not None
    assert retrieved["bomFormat"] == "CycloneDX"


def test_get_sbom_unknown_id_returns_none(tmp_path):
    g = SBOMGenerator(db_path=str(tmp_path / "sbom.db"))
    result = g.get_sbom("nonexistent-id-xyz")
    assert result is None


def test_list_sboms_returns_list(tmp_path):
    g = SBOMGenerator(db_path=str(tmp_path / "sbom.db"))
    result = g.list_sboms()
    assert isinstance(result, list)


def test_list_sboms_after_store(tmp_path):
    g = SBOMGenerator(db_path=str(tmp_path / "sbom.db"))
    comps = g.parse_requirements_txt("numpy==1.24.0")
    sbom = g.generate_cyclonedx(comps)
    g.store_sbom(sbom, "cyclonedx", "project-a", "org-1")
    records = g.list_sboms("org-1")
    assert len(records) == 1
    assert records[0]["target"] == "project-a"


# ---------------------------------------------------------------------------
# diff_sboms
# ---------------------------------------------------------------------------


def test_diff_sboms_identical_returns_empty(tmp_path):
    g = SBOMGenerator(db_path=str(tmp_path / "sbom.db"))
    comps = g.parse_requirements_txt("requests==2.28.0")
    sbom = g.generate_cyclonedx(comps)
    id_a = g.store_sbom(sbom, "cyclonedx", "proj")
    id_b = g.store_sbom(sbom, "cyclonedx", "proj")
    diff = g.diff_sboms(id_a, id_b)
    assert diff["added"] == []
    assert diff["removed"] == []
    assert diff["changed"] == []


def test_diff_sboms_added_component(tmp_path):
    g = SBOMGenerator(db_path=str(tmp_path / "sbom.db"))
    sbom_a = g.generate_cyclonedx(g.parse_requirements_txt("requests==2.28.0"))
    sbom_b = g.generate_cyclonedx(g.parse_requirements_txt("requests==2.28.0\nflask==2.0.0"))
    id_a = g.store_sbom(sbom_a, "cyclonedx", "proj")
    id_b = g.store_sbom(sbom_b, "cyclonedx", "proj")
    diff = g.diff_sboms(id_a, id_b)
    assert len(diff["added"]) == 1
    assert diff["added"][0]["name"] == "flask"
