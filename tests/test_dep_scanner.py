"""Tests for the Dependency Vulnerability Scanner.

Covers:
- DepVulnerability Pydantic model (creation, field validation)
- _parse_version and _version_lt helpers
- _parse_requirements_line helper
- DependencyScanner.scan_requirements()
- DependencyScanner.scan_package_json()
- DependencyScanner.scan_installed()
- DependencyScanner.get_outdated()
- DependencyScanner.get_vulnerable()
- DependencyScanner.generate_upgrade_plan()
- FastAPI router endpoints (6 endpoints)

All external calls (pip subprocess) are mocked.
No network access required.
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

# ---------------------------------------------------------------------------
# Path setup — ensure suite-core is importable
# ---------------------------------------------------------------------------
_REPO_ROOT = Path(__file__).resolve().parents[1]
_SUITE_CORE = str(_REPO_ROOT / "suite-core")
if _SUITE_CORE not in sys.path:
    sys.path.insert(0, _SUITE_CORE)

os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")

from core.dep_scanner import (
    KNOWN_VULNS,
    DepVulnerability,
    DependencyScanner,
    _normalize_pkg_name,
    _parse_requirements_line,
    _parse_version,
    _version_lt,
)


# ===========================================================================
# Fixtures
# ===========================================================================


@pytest.fixture
def scanner() -> DependencyScanner:
    return DependencyScanner()


@pytest.fixture
def tmp_requirements(tmp_path: Path) -> Path:
    """Write a sample requirements.txt with known-vulnerable packages."""
    content = (
        "requests==2.28.1\n"
        "cryptography==41.0.3\n"
        "pyjwt==2.3.0\n"
        "urllib3==1.26.4\n"
        "# this is a comment\n"
        "-r other.txt\n"
        "flask>=2.2.0\n"
        "jinja2==3.1.2\n"
        "pillow==9.0.0\n"
        "somelib  # no version\n"
    )
    f = tmp_path / "requirements.txt"
    f.write_text(content)
    return f


@pytest.fixture
def tmp_package_json(tmp_path: Path) -> Path:
    """Write a sample package.json with known-vulnerable packages."""
    data = {
        "name": "aldeci-ui",
        "version": "1.0.0",
        "dependencies": {
            "axios": "^1.5.0",
            "lodash": "4.17.20",
            "express": "4.18.0",
        },
        "devDependencies": {
            "vite": "^5.0.11",
            "semver": "^7.5.1",
        },
    }
    f = tmp_path / "package.json"
    f.write_text(json.dumps(data))
    return f


@pytest.fixture
def empty_requirements(tmp_path: Path) -> Path:
    f = tmp_path / "empty.txt"
    f.write_text("# empty\n")
    return f


@pytest.fixture
def clean_requirements(tmp_path: Path) -> Path:
    """requirements.txt with no known-vulnerable packages."""
    f = tmp_path / "clean.txt"
    f.write_text("nonexistentpackage==99.0.0\nanothersafelib==1.2.3\n")
    return f


# ===========================================================================
# DepVulnerability model tests
# ===========================================================================


class TestDepVulnerabilityModel:
    def test_creation_all_fields(self):
        v = DepVulnerability(
            package="requests",
            installed_version="2.28.1",
            fixed_version="2.31.0",
            cve_id="CVE-2023-32681",
            severity="high",
            description="Test description",
            advisory_url="https://example.com/advisory",
        )
        assert v.package == "requests"
        assert v.installed_version == "2.28.1"
        assert v.fixed_version == "2.31.0"
        assert v.cve_id == "CVE-2023-32681"
        assert v.severity == "high"
        assert v.description == "Test description"
        assert v.advisory_url == "https://example.com/advisory"

    def test_model_dict(self):
        v = DepVulnerability(
            package="flask",
            installed_version="2.1.0",
            fixed_version="2.3.2",
            cve_id="CVE-2023-30861",
            severity="high",
            description="desc",
            advisory_url="https://example.com",
        )
        d = v.model_dump()
        assert set(d.keys()) == {
            "package",
            "installed_version",
            "fixed_version",
            "cve_id",
            "severity",
            "description",
            "advisory_url",
        }

    def test_extra_fields_ignored(self):
        v = DepVulnerability(
            package="x",
            installed_version="1.0",
            fixed_version="2.0",
            cve_id="CVE-0",
            severity="low",
            description="d",
            advisory_url="https://x.com",
            extra_unknown_field="ignored",  # type: ignore[call-arg]
        )
        assert not hasattr(v, "extra_unknown_field")

    def test_severity_values(self):
        for sev in ("critical", "high", "medium", "low", "info"):
            v = DepVulnerability(
                package="p",
                installed_version="1.0",
                fixed_version="2.0",
                cve_id="CVE-0",
                severity=sev,
                description="d",
                advisory_url="https://x.com",
            )
            assert v.severity == sev


# ===========================================================================
# Version parsing helpers
# ===========================================================================


class TestParseVersion:
    def test_simple(self):
        assert _parse_version("2.31.0") == (2, 31, 0)

    def test_two_part(self):
        assert _parse_version("6.0") == (6, 0)

    def test_date_style(self):
        assert _parse_version("2023.7.22") == (2023, 7, 22)

    def test_with_prerelease(self):
        result = _parse_version("1.0.0b1")
        assert result[0] == 1

    def test_zero_fallback(self):
        result = _parse_version("nover")
        assert result == (0,)

    def test_with_plus(self):
        assert _parse_version("1.2.3+local") == (1, 2, 3)

    def test_epoch(self):
        result = _parse_version("1!2.3.4")
        assert result == (2, 3, 4)


class TestVersionLt:
    def test_less_than(self):
        assert _version_lt((2, 28, 1), (2, 31, 0)) is True

    def test_equal(self):
        assert _version_lt((2, 31, 0), (2, 31, 0)) is False

    def test_greater(self):
        assert _version_lt((3, 0, 0), (2, 31, 0)) is False

    def test_different_lengths(self):
        assert _version_lt((2,), (2, 1)) is True
        assert _version_lt((2, 1), (2,)) is False

    def test_patch_level(self):
        assert _version_lt((41, 0, 3), (41, 0, 4)) is True
        assert _version_lt((41, 0, 4), (41, 0, 4)) is False


# ===========================================================================
# _parse_requirements_line tests
# ===========================================================================


class TestParseRequirementsLine:
    def test_eq_op(self):
        result = _parse_requirements_line("requests==2.28.1")
        assert result is not None
        assert result[1] == "2.28.1"

    def test_ge_op(self):
        result = _parse_requirements_line("flask>=2.2.0")
        assert result is not None
        assert result[1] == "2.2.0"

    def test_comment_line(self):
        assert _parse_requirements_line("# comment") is None

    def test_blank_line(self):
        assert _parse_requirements_line("   ") is None

    def test_option_line(self):
        assert _parse_requirements_line("-r other.txt") is None

    def test_no_version(self):
        result = _parse_requirements_line("somelib")
        assert result is not None
        assert result[1] == "0.0.0"

    def test_inline_comment_stripped(self):
        result = _parse_requirements_line("requests==2.28.1  # security update")
        assert result is not None
        assert result[1] == "2.28.1"

    def test_name_normalized(self):
        result = _parse_requirements_line("PyYAML==6.0")
        assert result is not None
        name, ver = result
        assert name == "pyyaml"


# ===========================================================================
# DependencyScanner.scan_requirements tests
# ===========================================================================


class TestScanRequirements:
    def test_returns_list(self, scanner: DependencyScanner, tmp_requirements: Path):
        result = scanner.scan_requirements(str(tmp_requirements))
        assert isinstance(result, list)

    def test_finds_requests_vuln(self, scanner: DependencyScanner, tmp_requirements: Path):
        vulns = scanner.scan_requirements(str(tmp_requirements))
        pkgs = [v.package for v in vulns]
        assert "requests" in pkgs

    def test_finds_cryptography_vuln(self, scanner: DependencyScanner, tmp_requirements: Path):
        vulns = scanner.scan_requirements(str(tmp_requirements))
        pkgs = [v.package for v in vulns]
        assert "cryptography" in pkgs

    def test_finds_pyjwt_vuln(self, scanner: DependencyScanner, tmp_requirements: Path):
        vulns = scanner.scan_requirements(str(tmp_requirements))
        pkgs = [v.package for v in vulns]
        assert "pyjwt" in pkgs

    def test_all_items_are_dep_vuln(self, scanner: DependencyScanner, tmp_requirements: Path):
        vulns = scanner.scan_requirements(str(tmp_requirements))
        for v in vulns:
            assert isinstance(v, DepVulnerability)

    def test_severity_in_known_values(self, scanner: DependencyScanner, tmp_requirements: Path):
        vulns = scanner.scan_requirements(str(tmp_requirements))
        valid = {"critical", "high", "medium", "low", "info"}
        for v in vulns:
            assert v.severity in valid

    def test_missing_file_returns_empty(self, scanner: DependencyScanner):
        result = scanner.scan_requirements("/nonexistent/requirements.txt")
        assert result == []

    def test_empty_file_returns_empty(self, scanner: DependencyScanner, empty_requirements: Path):
        result = scanner.scan_requirements(str(empty_requirements))
        assert result == []

    def test_clean_file_returns_empty(self, scanner: DependencyScanner, clean_requirements: Path):
        result = scanner.scan_requirements(str(clean_requirements))
        assert result == []

    def test_cve_id_format(self, scanner: DependencyScanner, tmp_requirements: Path):
        vulns = scanner.scan_requirements(str(tmp_requirements))
        for v in vulns:
            assert v.cve_id.startswith("CVE-")

    def test_advisory_url_is_https(self, scanner: DependencyScanner, tmp_requirements: Path):
        vulns = scanner.scan_requirements(str(tmp_requirements))
        for v in vulns:
            assert v.advisory_url.startswith("https://")


# ===========================================================================
# DependencyScanner.scan_package_json tests
# ===========================================================================


class TestScanPackageJson:
    def test_returns_list(self, scanner: DependencyScanner, tmp_package_json: Path):
        result = scanner.scan_package_json(str(tmp_package_json))
        assert isinstance(result, list)

    def test_finds_lodash_vuln(self, scanner: DependencyScanner, tmp_package_json: Path):
        vulns = scanner.scan_package_json(str(tmp_package_json))
        pkgs = [v.package for v in vulns]
        assert "lodash" in pkgs

    def test_finds_axios_vuln(self, scanner: DependencyScanner, tmp_package_json: Path):
        vulns = scanner.scan_package_json(str(tmp_package_json))
        pkgs = [v.package for v in vulns]
        assert "axios" in pkgs

    def test_finds_semver_vuln(self, scanner: DependencyScanner, tmp_package_json: Path):
        vulns = scanner.scan_package_json(str(tmp_package_json))
        pkgs = [v.package for v in vulns]
        assert "semver" in pkgs

    def test_all_items_are_dep_vuln(self, scanner: DependencyScanner, tmp_package_json: Path):
        vulns = scanner.scan_package_json(str(tmp_package_json))
        for v in vulns:
            assert isinstance(v, DepVulnerability)

    def test_missing_file_returns_empty(self, scanner: DependencyScanner):
        result = scanner.scan_package_json("/nonexistent/package.json")
        assert result == []

    def test_invalid_json_returns_empty(self, scanner: DependencyScanner, tmp_path: Path):
        f = tmp_path / "bad.json"
        f.write_text("not json {{{")
        result = scanner.scan_package_json(str(f))
        assert result == []

    def test_empty_json_returns_empty(self, scanner: DependencyScanner, tmp_path: Path):
        f = tmp_path / "empty.json"
        f.write_text("{}")
        result = scanner.scan_package_json(str(f))
        assert result == []

    def test_caret_version_stripped(self, scanner: DependencyScanner, tmp_path: Path):
        """Caret versions like ^1.5.0 should be stripped to 1.5.0."""
        data = {"dependencies": {"axios": "^1.5.0"}}
        f = tmp_path / "pkg.json"
        f.write_text(json.dumps(data))
        vulns = scanner.scan_package_json(str(f))
        pkgs = [v.package for v in vulns]
        assert "axios" in pkgs


# ===========================================================================
# DependencyScanner.scan_installed tests
# ===========================================================================


class TestScanInstalled:
    def _make_freeze_output(self) -> str:
        return (
            "requests==2.28.1\n"
            "cryptography==38.0.1\n"
            "urllib3==1.26.4\n"
            "pyjwt==2.3.0\n"
            "safepkg==99.0.0\n"
        )

    def test_returns_list_with_mock(self, scanner: DependencyScanner):
        freeze_out = self._make_freeze_output()
        mock_result = MagicMock()
        mock_result.stdout = freeze_out
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result):
            result = scanner.scan_installed()
        assert isinstance(result, list)

    def test_finds_vulns_in_installed(self, scanner: DependencyScanner):
        freeze_out = self._make_freeze_output()
        mock_result = MagicMock()
        mock_result.stdout = freeze_out
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result):
            vulns = scanner.scan_installed()
        pkgs = [v.package for v in vulns]
        assert "requests" in pkgs
        assert "cryptography" in pkgs

    def test_subprocess_failure_returns_empty(self, scanner: DependencyScanner):
        with patch("subprocess.run", side_effect=Exception("pip broken")):
            result = scanner.scan_installed()
        assert result == []

    def test_all_items_are_dep_vuln(self, scanner: DependencyScanner):
        freeze_out = self._make_freeze_output()
        mock_result = MagicMock()
        mock_result.stdout = freeze_out

        with patch("subprocess.run", return_value=mock_result):
            vulns = scanner.scan_installed()
        for v in vulns:
            assert isinstance(v, DepVulnerability)


# ===========================================================================
# DependencyScanner.get_outdated tests
# ===========================================================================


class TestGetOutdated:
    def _pip_outdated_json(self) -> str:
        return json.dumps([
            {"name": "requests", "version": "2.28.1", "latest_version": "2.31.0", "latest_filetype": "wheel"},
            {"name": "cryptography", "version": "38.0.1", "latest_version": "42.0.5", "latest_filetype": "wheel"},
        ])

    def test_returns_list(self, scanner: DependencyScanner):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = self._pip_outdated_json()

        with patch("subprocess.run", return_value=mock_result):
            result = scanner.get_outdated()
        assert isinstance(result, list)

    def test_contains_package_fields(self, scanner: DependencyScanner):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = self._pip_outdated_json()

        with patch("subprocess.run", return_value=mock_result):
            result = scanner.get_outdated()

        assert len(result) == 2
        assert result[0]["package"] == "requests"
        assert result[0]["latest_version"] == "2.31.0"

    def test_subprocess_failure_returns_empty(self, scanner: DependencyScanner):
        with patch("subprocess.run", side_effect=Exception("timeout")):
            result = scanner.get_outdated()
        assert result == []

    def test_nonzero_returncode_returns_empty(self, scanner: DependencyScanner):
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            result = scanner.get_outdated()
        assert result == []


# ===========================================================================
# DependencyScanner.get_vulnerable tests
# ===========================================================================


class TestGetVulnerable:
    def test_delegates_to_scan_installed(self, scanner: DependencyScanner):
        """get_vulnerable should return the same as scan_installed."""
        mock_result = MagicMock()
        mock_result.stdout = "requests==2.28.1\n"

        with patch("subprocess.run", return_value=mock_result):
            v1 = scanner.get_vulnerable()
            v2 = scanner.scan_installed()

        # Both should find the same packages
        assert [v.package for v in v1] == [v.package for v in v2]

    def test_returns_only_vulnerable(self, scanner: DependencyScanner):
        mock_result = MagicMock()
        mock_result.stdout = "safepkg==99.0.0\nrequests==2.28.1\n"

        with patch("subprocess.run", return_value=mock_result):
            vulns = scanner.get_vulnerable()
        pkgs = [v.package for v in vulns]
        assert "requests" in pkgs
        # safepkg has no entry in the vuln db
        assert "safepkg" not in pkgs


# ===========================================================================
# DependencyScanner.generate_upgrade_plan tests
# ===========================================================================


class TestGenerateUpgradePlan:
    def _freeze(self) -> MagicMock:
        m = MagicMock()
        m.stdout = (
            "requests==2.28.1\n"
            "cryptography==38.0.1\n"
            "pyjwt==2.3.0\n"
            "pillow==8.3.1\n"
        )
        return m

    def test_returns_dict(self, scanner: DependencyScanner):
        with patch("subprocess.run", return_value=self._freeze()):
            plan = scanner.generate_upgrade_plan()
        assert isinstance(plan, dict)

    def test_required_keys(self, scanner: DependencyScanner):
        with patch("subprocess.run", return_value=self._freeze()):
            plan = scanner.generate_upgrade_plan()
        for key in ("generated_at", "total_vulnerabilities", "critical", "high", "medium", "low", "upgrade_commands", "summary"):
            assert key in plan, f"Missing key: {key}"

    def test_total_vulnerabilities_is_int(self, scanner: DependencyScanner):
        with patch("subprocess.run", return_value=self._freeze()):
            plan = scanner.generate_upgrade_plan()
        assert isinstance(plan["total_vulnerabilities"], int)

    def test_upgrade_commands_are_pip_install(self, scanner: DependencyScanner):
        with patch("subprocess.run", return_value=self._freeze()):
            plan = scanner.generate_upgrade_plan()
        for cmd in plan["upgrade_commands"]:
            assert cmd.startswith("pip install")

    def test_no_duplicate_upgrades(self, scanner: DependencyScanner):
        with patch("subprocess.run", return_value=self._freeze()):
            plan = scanner.generate_upgrade_plan()
        cmds = plan["upgrade_commands"]
        assert len(cmds) == len(set(cmds))

    def test_generated_at_is_iso(self, scanner: DependencyScanner):
        with patch("subprocess.run", return_value=self._freeze()):
            plan = scanner.generate_upgrade_plan()
        from datetime import datetime
        # Should not raise
        datetime.fromisoformat(plan["generated_at"].replace("Z", "+00:00"))

    def test_critical_pillow_present(self, scanner: DependencyScanner):
        with patch("subprocess.run", return_value=self._freeze()):
            plan = scanner.generate_upgrade_plan()
        critical_pkgs = [e["package"] for e in plan["critical"]]
        assert "pillow" in critical_pkgs


# ===========================================================================
# Known vulnerability DB sanity checks
# ===========================================================================


class TestKnownVulnsDB:
    def test_db_has_entries(self):
        # At least 50 packages keys in the DB
        assert len(KNOWN_VULNS) >= 50, f"Only {len(KNOWN_VULNS)} package keys in DB"

    def test_all_entries_have_cve(self):
        for pkg, entries in KNOWN_VULNS.items():
            for entry in entries:
                _, _, cve_id, _, _, _ = entry
                assert cve_id.startswith("CVE-"), f"Bad CVE in {pkg}: {cve_id}"

    def test_all_entries_have_valid_severity(self):
        valid = {"critical", "high", "medium", "low", "info"}
        for pkg, entries in KNOWN_VULNS.items():
            for entry in entries:
                _, _, _, severity, _, _ = entry
                assert severity in valid, f"Bad severity in {pkg}: {severity}"

    def test_all_entries_have_advisory_url(self):
        for pkg, entries in KNOWN_VULNS.items():
            for entry in entries:
                _, _, _, _, _, url = entry
                assert url.startswith("https://"), f"Bad URL in {pkg}: {url}"

    def test_requests_in_db(self):
        assert "requests" in KNOWN_VULNS

    def test_cryptography_in_db(self):
        assert "cryptography" in KNOWN_VULNS

    def test_lodash_in_db(self):
        assert "lodash" in KNOWN_VULNS

    def test_entry_count(self):
        total = sum(len(v) for v in KNOWN_VULNS.values())
        assert total >= 50


# ===========================================================================
# FastAPI router tests
# ===========================================================================


@pytest.fixture
def api_client(tmp_requirements: Path, tmp_package_json: Path):
    """Create a FastAPI TestClient with the dep_scanner router mounted."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    # Router import must happen after sys.path is set
    from apps.api.dep_scanner_router import router

    app = FastAPI()
    app.include_router(router)
    return TestClient(app), tmp_requirements, tmp_package_json


# Add suite-api to path for router import
_SUITE_API = str(_REPO_ROOT / "suite-api")
if _SUITE_API not in sys.path:
    sys.path.insert(0, _SUITE_API)


class TestDepScannerRouter:
    def test_scan_requirements_endpoint(self, api_client):
        client, req_file, _ = api_client
        mock_result = MagicMock()
        mock_result.stdout = ""
        with patch("subprocess.run", return_value=mock_result):
            resp = client.post(
                "/api/v1/dep-scanner/scan-requirements",
                json={"file_path": str(req_file)},
            )
        assert resp.status_code == 200
        data = resp.json()
        assert "vulnerabilities" in data
        assert "total" in data
        assert data["file_path"] == str(req_file)

    def test_scan_requirements_returns_vulns(self, api_client):
        client, req_file, _ = api_client
        resp = client.post(
            "/api/v1/dep-scanner/scan-requirements",
            json={"file_path": str(req_file)},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 1

    def test_scan_requirements_missing_file(self, api_client):
        client, _, _ = api_client
        resp = client.post(
            "/api/v1/dep-scanner/scan-requirements",
            json={"file_path": "/nonexistent/file.txt"},
        )
        assert resp.status_code == 404

    def test_scan_requirements_path_traversal(self, api_client):
        client, _, _ = api_client
        resp = client.post(
            "/api/v1/dep-scanner/scan-requirements",
            json={"file_path": "../../etc/passwd"},
        )
        assert resp.status_code == 400

    def test_scan_package_json_endpoint(self, api_client):
        client, _, pkg_file = api_client
        resp = client.post(
            "/api/v1/dep-scanner/scan-package-json",
            json={"file_path": str(pkg_file)},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "vulnerabilities" in data
        assert data["total"] >= 1

    def test_scan_package_json_missing_file(self, api_client):
        client, _, _ = api_client
        resp = client.post(
            "/api/v1/dep-scanner/scan-package-json",
            json={"file_path": "/nonexistent/package.json"},
        )
        assert resp.status_code == 404

    def test_scan_installed_endpoint(self, api_client):
        client, _, _ = api_client
        mock_result = MagicMock()
        mock_result.stdout = "requests==2.28.1\n"
        mock_result.returncode = 0
        with patch("subprocess.run", return_value=mock_result):
            resp = client.get("/api/v1/dep-scanner/scan-installed")
        assert resp.status_code == 200
        data = resp.json()
        assert "vulnerabilities" in data
        assert data["total"] >= 1

    def test_outdated_endpoint(self, api_client):
        client, _, _ = api_client
        outdated_json = json.dumps([
            {"name": "requests", "version": "2.28.1", "latest_version": "2.31.0", "latest_filetype": "wheel"},
        ])
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = outdated_json
        with patch("subprocess.run", return_value=mock_result):
            resp = client.get("/api/v1/dep-scanner/outdated")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["package"] == "requests"

    def test_vulnerable_endpoint(self, api_client):
        client, _, _ = api_client
        mock_result = MagicMock()
        mock_result.stdout = "cryptography==38.0.1\n"
        with patch("subprocess.run", return_value=mock_result):
            resp = client.get("/api/v1/dep-scanner/vulnerable")
        assert resp.status_code == 200
        data = resp.json()
        assert "vulnerabilities" in data
        assert data["total"] >= 1

    def test_upgrade_plan_endpoint(self, api_client):
        client, _, _ = api_client
        mock_result = MagicMock()
        mock_result.stdout = "requests==2.28.1\ncryptography==38.0.1\n"
        with patch("subprocess.run", return_value=mock_result):
            resp = client.get("/api/v1/dep-scanner/upgrade-plan")
        assert resp.status_code == 200
        data = resp.json()
        assert "generated_at" in data
        assert "total_vulnerabilities" in data
        assert "upgrade_commands" in data
        assert "summary" in data
        assert isinstance(data["upgrade_commands"], list)
