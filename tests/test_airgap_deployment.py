"""Tests for suite-core/core/airgap_deployment.py — Air-Gap Deployment Hardening.

Covers all 8 hardening components:
  1. OfflineCVEDatabase — NVD mirror + search
  2. OfflineSBOMGenerator — CycloneDX SBOM from local manifests
  3. SneakernetManager — encrypted+signed update packages
  4. LocalTrustGraphConfig — local-only TrustGraph enforcement
  5. NetworkIsolationVerifier — active egress checks
  6. TelemetryKillSwitch — telemetry disable + verify
  7. DeploymentValidator — pre-deployment checklist
  8. ClassificationEnforcer — classification level enforcement

Usage:
    pytest tests/test_airgap_deployment.py -v --timeout=10
"""

from __future__ import annotations

import gzip
import json
import os
import struct
import sys
import threading
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest

# Add suite-core to path
suite_core_path = str(Path(__file__).parent.parent / "suite-core")
if suite_core_path not in sys.path:
    sys.path.insert(0, suite_core_path)

from core.airgap_deployment import (
    AirGapDeploymentHardening,
    ClassificationEnforcer,
    ClassificationLevel,
    ClassificationPolicy,
    CLASSIFICATION_POLICIES,
    CVERecord,
    DeploymentCheckItem,
    DeploymentValidationReport,
    DeploymentValidator,
    LocalTrustGraphConfig,
    NetworkCheckResult,
    NetworkIsolationVerifier,
    OfflineCVEDatabase,
    OfflineSBOMGenerator,
    SBOMComponent,
    SBOMDocument,
    SNEAKERNET_MAGIC,
    SneakernetManifest,
    SneakernetManager,
    TelemetryKillSwitch,
    TelemetryStatus,
    _sha256_bytes,
    _utcnow,
)
from core.fips_encryption import AirGapMode, FIPSEncryption


# ===========================================================================
# Fixtures
# ===========================================================================


@pytest.fixture(autouse=True)
def reset_airgap_mode():
    """Always start tests with AirGapMode disabled."""
    AirGapMode.disable()
    yield
    AirGapMode.disable()


@pytest.fixture
def tmp_data(tmp_path):
    """Temporary data root for all airgap components."""
    return tmp_path


@pytest.fixture
def cve_db(tmp_path):
    return OfflineCVEDatabase(db_path=tmp_path / "cve_db" / "nvd.sqlite3")


@pytest.fixture
def sbom_gen(tmp_path):
    return OfflineSBOMGenerator(output_dir=tmp_path / "sbom")


@pytest.fixture
def sneakernet(tmp_path):
    return SneakernetManager(base_dir=tmp_path / "sneakernet")


@pytest.fixture
def aes_key():
    """32-byte AES-256 key for sneakernet tests."""
    import os as _os
    return _os.urandom(32)


@pytest.fixture
def tg_config(tmp_path):
    return LocalTrustGraphConfig(config_path=tmp_path / "tg" / "config.json")


@pytest.fixture
def telemetry(tmp_path):
    return TelemetryKillSwitch(kill_file=tmp_path / "telemetry.disabled")


@pytest.fixture
def sample_nvd_feed(tmp_path) -> Path:
    """Write a minimal gzip NVD feed and return its path."""
    items = [
        {
            "cve_id": "CVE-2024-1234",
            "description": "Buffer overflow in libssl",
            "severity": "HIGH",
            "cvss_score": 8.1,
            "cvss_version": "3.1",
            "published": "2024-03-01T00:00:00",
            "modified": "2024-03-10T00:00:00",
            "products": ["cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*"],
            "references": [],
            "cwe_ids": ["CWE-122"],
        },
        {
            "cve_id": "CVE-2025-9999",
            "description": "SQL injection in Django admin",
            "severity": "CRITICAL",
            "cvss_score": 9.8,
            "cvss_version": "3.1",
            "published": "2025-01-15T00:00:00",
            "modified": "2025-01-20T00:00:00",
            "products": ["cpe:2.3:a:djangoproject:django:4.2:*:*:*:*:*:*:*"],
            "references": [],
            "cwe_ids": ["CWE-89"],
        },
    ]
    feed_path = tmp_path / "nvdcve-2024.json.gz"
    with gzip.open(feed_path, "wt", encoding="utf-8") as fh:
        json.dump(items, fh)
    return feed_path


@pytest.fixture
def sample_payload_file(tmp_path) -> Path:
    """A small file to package in sneakernet tests."""
    p = tmp_path / "data.txt"
    p.write_text("ALDECI air-gap test payload")
    return p


# ===========================================================================
# 1. CVERecord model
# ===========================================================================


class TestCVERecord:
    def test_valid_cve_id(self):
        r = CVERecord(cve_id="CVE-2024-1234")
        assert r.cve_id == "CVE-2024-1234"

    def test_cve_id_uppercased(self):
        r = CVERecord(cve_id="cve-2024-1234")
        assert r.cve_id == "CVE-2024-1234"

    def test_invalid_cve_id_raises(self):
        with pytest.raises(Exception):
            CVERecord(cve_id="NOTACVE")

    def test_cvss_score_bounds(self):
        r = CVERecord(cve_id="CVE-2024-0001", cvss_score=9.9)
        assert r.cvss_score == 9.9

    def test_cvss_score_out_of_range_raises(self):
        with pytest.raises(Exception):
            CVERecord(cve_id="CVE-2024-0001", cvss_score=11.0)

    def test_defaults(self):
        r = CVERecord(cve_id="CVE-2024-5678")
        assert r.severity == "UNKNOWN"
        assert r.cvss_score == 0.0
        assert r.products == []


# ===========================================================================
# 2. OfflineCVEDatabase
# ===========================================================================


class TestOfflineCVEDatabase:
    def test_init_creates_db(self, cve_db, tmp_path):
        assert (tmp_path / "cve_db" / "nvd.sqlite3").exists()

    def test_import_nvd_feed_returns_count(self, cve_db, sample_nvd_feed):
        count = cve_db.import_nvd_feed(str(sample_nvd_feed), year=2024)
        assert count == 2

    def test_import_missing_feed_raises(self, cve_db):
        with pytest.raises(FileNotFoundError):
            cve_db.import_nvd_feed("/nonexistent/feed.json.gz")

    def test_search_returns_results(self, cve_db, sample_nvd_feed):
        cve_db.import_nvd_feed(str(sample_nvd_feed), year=2024)
        results = cve_db.search()
        assert len(results) == 2

    def test_search_by_severity(self, cve_db, sample_nvd_feed):
        cve_db.import_nvd_feed(str(sample_nvd_feed), year=2024)
        results = cve_db.search(severity="CRITICAL")
        assert all(r.severity == "CRITICAL" for r in results)
        assert len(results) == 1

    def test_search_by_min_score(self, cve_db, sample_nvd_feed):
        cve_db.import_nvd_feed(str(sample_nvd_feed), year=2024)
        results = cve_db.search(min_score=9.0)
        assert all(r.cvss_score >= 9.0 for r in results)

    def test_search_by_product(self, cve_db, sample_nvd_feed):
        cve_db.import_nvd_feed(str(sample_nvd_feed), year=2024)
        results = cve_db.search(product="openssl")
        assert len(results) >= 1

    def test_get_by_id_found(self, cve_db, sample_nvd_feed):
        cve_db.import_nvd_feed(str(sample_nvd_feed), year=2024)
        record = cve_db.get_by_id("CVE-2024-1234")
        assert record is not None
        assert record.cve_id == "CVE-2024-1234"

    def test_get_by_id_not_found(self, cve_db):
        result = cve_db.get_by_id("CVE-9999-0000")
        assert result is None

    def test_get_stats(self, cve_db, sample_nvd_feed):
        cve_db.import_nvd_feed(str(sample_nvd_feed), year=2024)
        stats = cve_db.get_stats()
        assert stats["total"] == 2
        assert "by_severity" in stats

    def test_generate_feed_stubs(self, cve_db, tmp_path):
        stub_dir = tmp_path / "stubs"
        paths = cve_db.generate_feed_stubs(output_dir=stub_dir)
        assert len(paths) == 3  # 2024, 2025, 2026
        for p in paths:
            assert Path(p).exists()
            assert Path(p).suffix == ".gz"

    def test_stubs_can_be_imported(self, cve_db, tmp_path):
        stub_dir = tmp_path / "stubs"
        paths = cve_db.generate_feed_stubs(output_dir=stub_dir)
        total = 0
        for p in paths:
            # extract year from filename
            year = int(Path(p).stem.replace(".json", "").split("-")[-1])
            count = cve_db.import_nvd_feed(p, year=year)
            total += count
        assert total > 0

    def test_search_with_year_filter(self, cve_db, sample_nvd_feed):
        cve_db.import_nvd_feed(str(sample_nvd_feed), year=2024)
        results = cve_db.search(year=2025)
        assert all("2025" in r.published for r in results)

    def test_search_limit(self, cve_db, sample_nvd_feed):
        cve_db.import_nvd_feed(str(sample_nvd_feed), year=2024)
        results = cve_db.search(limit=1)
        assert len(results) <= 1


# ===========================================================================
# 3. OfflineSBOMGenerator
# ===========================================================================


class TestOfflineSBOMGenerator:
    def test_generate_empty_project(self, sbom_gen, tmp_path):
        project = tmp_path / "myproject"
        project.mkdir()
        doc = sbom_gen.generate(str(project))
        assert isinstance(doc, SBOMDocument)
        assert doc.bom_format == "CycloneDX"
        assert doc.spec_version == "1.4"

    def test_generate_python_requirements(self, sbom_gen, tmp_path):
        project = tmp_path / "pyproj"
        project.mkdir()
        (project / "requirements.txt").write_text(
            "requests==2.31.0\nfastapi>=0.100.0\npydantic~=2.0\n"
        )
        doc = sbom_gen.generate(str(project))
        names = [c.name for c in doc.components]
        assert "requests" in names
        assert "fastapi" in names

    def test_generate_node_package_json(self, sbom_gen, tmp_path):
        project = tmp_path / "nodeproj"
        project.mkdir()
        (project / "package.json").write_text(json.dumps({
            "dependencies": {"express": "^4.18.2", "lodash": "^4.17.21"},
            "devDependencies": {"jest": "^29.0.0"},
        }))
        doc = sbom_gen.generate(str(project))
        names = [c.name for c in doc.components]
        assert "express" in names
        assert "jest" in names

    def test_generate_go_mod(self, sbom_gen, tmp_path):
        project = tmp_path / "goproj"
        project.mkdir()
        (project / "go.mod").write_text(
            "module example.com/myapp\n\ngo 1.21\n\nrequire (\n"
            "\tgithub.com/gin-gonic/gin v1.9.1\n"
            "\tgithub.com/stretchr/testify v1.8.4\n)\n"
        )
        doc = sbom_gen.generate(str(project))
        names = [c.name for c in doc.components]
        assert any("gin" in n for n in names)

    def test_generate_java_pom(self, sbom_gen, tmp_path):
        project = tmp_path / "javaproj"
        project.mkdir()
        pom = """<project>
  <dependencies>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
      <version>6.0.0</version>
    </dependency>
  </dependencies>
</project>"""
        (project / "pom.xml").write_text(pom)
        doc = sbom_gen.generate(str(project))
        names = [c.name for c in doc.components]
        assert any("spring" in n for n in names)

    def test_write_json_creates_file(self, sbom_gen, tmp_path):
        project = tmp_path / "proj"
        project.mkdir()
        doc = sbom_gen.generate(str(project))
        out_path = sbom_gen.write_json(doc)
        assert Path(out_path).exists()
        data = json.loads(Path(out_path).read_text())
        assert data["bom_format"] == "CycloneDX"

    def test_sbom_component_purl_ecosystem(self, sbom_gen, tmp_path):
        project = tmp_path / "pypkg"
        project.mkdir()
        (project / "requirements.txt").write_text("numpy==1.26.0\n")
        doc = sbom_gen.generate(str(project))
        numpy_comp = next((c for c in doc.components if c.name == "numpy"), None)
        assert numpy_comp is not None
        assert numpy_comp.ecosystem == "python"
        assert "pkg:pypi/numpy" in numpy_comp.purl

    def test_missing_project_raises(self, sbom_gen):
        with pytest.raises(FileNotFoundError):
            sbom_gen.generate("/nonexistent/project")


# ===========================================================================
# 4. SneakernetManager
# ===========================================================================


class TestSneakernetManager:
    def test_export_creates_package(self, sneakernet, aes_key, sample_payload_file):
        out = sneakernet.export_package(
            payload_files=[str(sample_payload_file)],
            package_type="cve_db",
            version="2025.01.1",
            key=aes_key,
        )
        assert Path(out).exists()
        assert Path(out).stat().st_size > 0

    def test_package_has_magic_header(self, sneakernet, aes_key, sample_payload_file):
        out = sneakernet.export_package(
            payload_files=[str(sample_payload_file)],
            package_type="cve_db",
            version="2025.01.1",
            key=aes_key,
        )
        data = Path(out).read_bytes()
        assert data[:8] == SNEAKERNET_MAGIC

    def test_export_missing_file_raises(self, sneakernet, aes_key):
        with pytest.raises(FileNotFoundError):
            sneakernet.export_package(
                payload_files=["/nonexistent/file.txt"],
                package_type="cve_db",
                version="1.0.0",
                key=aes_key,
            )

    def test_import_roundtrip(self, sneakernet, aes_key, sample_payload_file, tmp_path):
        out = sneakernet.export_package(
            payload_files=[str(sample_payload_file)],
            package_type="sbom",
            version="2025.02.0",
            key=aes_key,
        )
        extract_dir = str(tmp_path / "extracted")
        manifest, files = sneakernet.import_package(out, aes_key, extract_dir=extract_dir)
        assert manifest.package_type == "sbom"
        assert manifest.version == "2025.02.0"
        assert len(files) >= 1
        assert Path(files[0]).exists()
        assert Path(files[0]).read_text() == "ALDECI air-gap test payload"

    def test_import_wrong_key_raises(self, sneakernet, aes_key, sample_payload_file, tmp_path):
        import os
        out = sneakernet.export_package(
            payload_files=[str(sample_payload_file)],
            package_type="cve_db",
            version="1.0.0",
            key=aes_key,
        )
        wrong_key = os.urandom(32)
        with pytest.raises((ValueError, Exception)):
            sneakernet.import_package(out, wrong_key)

    def test_import_tampered_package_raises(self, sneakernet, aes_key, sample_payload_file):
        out = sneakernet.export_package(
            payload_files=[str(sample_payload_file)],
            package_type="cve_db",
            version="1.0.0",
            key=aes_key,
        )
        data = bytearray(Path(out).read_bytes())
        data[-10] ^= 0xFF  # corrupt last bytes
        Path(out).write_bytes(bytes(data))
        with pytest.raises(ValueError):
            sneakernet.import_package(out, aes_key)

    def test_import_missing_package_raises(self, sneakernet, aes_key):
        with pytest.raises(FileNotFoundError):
            sneakernet.import_package("/nonexistent/pkg.snk", aes_key)

    def test_import_invalid_magic_raises(self, sneakernet, aes_key, tmp_path):
        bad_pkg = tmp_path / "bad.snk"
        bad_pkg.write_bytes(b"INVALIDHDR" + b"\x00" * 50)
        with pytest.raises(ValueError, match="magic"):
            sneakernet.import_package(str(bad_pkg), aes_key)

    def test_version_tracking(self, sneakernet, aes_key, sample_payload_file):
        sneakernet.export_package(
            payload_files=[str(sample_payload_file)],
            package_type="signatures",
            version="1.0.0",
            key=aes_key,
        )
        sneakernet.export_package(
            payload_files=[str(sample_payload_file)],
            package_type="signatures",
            version="2.0.0",
            key=aes_key,
        )
        versions = sneakernet.list_versions()
        assert "signatures" in versions
        assert len(versions["signatures"]) == 2

    def test_rollback_version(self, sneakernet, aes_key, sample_payload_file):
        sneakernet.export_package(
            payload_files=[str(sample_payload_file)],
            package_type="cve_db",
            version="1.0.0",
            key=aes_key,
        )
        sneakernet.export_package(
            payload_files=[str(sample_payload_file)],
            package_type="cve_db",
            version="2.0.0",
            key=aes_key,
        )
        rb = sneakernet.get_rollback_version("cve_db")
        assert rb == "1.0.0"

    def test_manifest_classification_preserved(self, sneakernet, aes_key, sample_payload_file, tmp_path):
        out = sneakernet.export_package(
            payload_files=[str(sample_payload_file)],
            package_type="cve_db",
            version="1.0.0",
            key=aes_key,
            classification="SECRET",
        )
        extract_dir = str(tmp_path / "extracted")
        manifest, _ = sneakernet.import_package(out, aes_key, extract_dir=extract_dir)
        assert manifest.classification == "SECRET"


# ===========================================================================
# 5. LocalTrustGraphConfig
# ===========================================================================


class TestLocalTrustGraphConfig:
    def test_apply_writes_config(self, tg_config):
        config = tg_config.apply_local_only()
        assert tg_config.config_path.exists()
        assert config["mode"] == "local_only"

    def test_apply_disables_telemetry(self, tg_config):
        config = tg_config.apply_local_only()
        assert config["telemetry_enabled"] is False

    def test_apply_disables_outbound(self, tg_config):
        config = tg_config.apply_local_only()
        assert config["allow_outbound"] is False
        assert config["external_sync"] is False

    def test_verify_compliant_after_apply(self, tg_config):
        tg_config.apply_local_only()
        ok, violations = tg_config.verify_no_outbound()
        assert ok
        assert violations == []

    def test_verify_non_compliant_detects_violation(self, tg_config):
        # Write a bad config manually
        tg_config.config_path.parent.mkdir(parents=True, exist_ok=True)
        tg_config.config_path.write_text(json.dumps({"telemetry_enabled": True, "allow_outbound": True}))
        ok, violations = tg_config.verify_no_outbound()
        assert not ok
        assert len(violations) > 0

    def test_read_missing_config_returns_empty(self, tg_config):
        config = tg_config.read_config()
        assert config == {}

    def test_local_storage_backend(self, tg_config):
        config = tg_config.apply_local_only()
        assert config["storage_backend"] == "local_sqlite"

    def test_network_timeout_zero(self, tg_config):
        config = tg_config.apply_local_only()
        assert config["network_timeout"] == 0


# ===========================================================================
# 6. NetworkIsolationVerifier
# ===========================================================================


class TestNetworkIsolationVerifier:
    def test_returns_network_check_result(self):
        verifier = NetworkIsolationVerifier()
        # In a test environment we patch socket to simulate isolation
        with patch("core.airgap_deployment.socket.create_connection", side_effect=OSError("blocked")), \
             patch("core.airgap_deployment.socket.getaddrinfo", side_effect=OSError("blocked")), \
             patch("core.airgap_deployment.urllib.request.urlopen", side_effect=OSError("blocked")):
            result = verifier.verify()
        assert isinstance(result, NetworkCheckResult)
        assert result.is_isolated is True

    def test_detects_violations_when_connected(self):
        verifier = NetworkIsolationVerifier()
        mock_sock = MagicMock()
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)
        with patch("core.airgap_deployment.socket.create_connection", return_value=mock_sock), \
             patch("core.airgap_deployment.socket.getaddrinfo", side_effect=OSError), \
             patch("core.airgap_deployment.urllib.request.urlopen", side_effect=OSError):
            result = verifier.verify()
        assert not result.is_isolated
        assert len(result.violations) > 0
        assert not result.tcp_blocked

    def test_probe_duration_recorded(self):
        verifier = NetworkIsolationVerifier()
        with patch("core.airgap_deployment.socket.create_connection", side_effect=OSError), \
             patch("core.airgap_deployment.socket.getaddrinfo", side_effect=OSError), \
             patch("core.airgap_deployment.urllib.request.urlopen", side_effect=OSError):
            result = verifier.verify()
        assert result.probe_duration_ms >= 0.0

    def test_assert_isolated_passes_when_blocked(self):
        verifier = NetworkIsolationVerifier()
        with patch("core.airgap_deployment.socket.create_connection", side_effect=OSError), \
             patch("core.airgap_deployment.socket.getaddrinfo", side_effect=OSError), \
             patch("core.airgap_deployment.urllib.request.urlopen", side_effect=OSError):
            verifier.assert_isolated()  # should not raise

    def test_assert_isolated_raises_when_connected(self):
        verifier = NetworkIsolationVerifier()
        mock_sock = MagicMock()
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)
        with patch("core.airgap_deployment.socket.create_connection", return_value=mock_sock), \
             patch("core.airgap_deployment.socket.getaddrinfo", side_effect=OSError), \
             patch("core.airgap_deployment.urllib.request.urlopen", side_effect=OSError), \
             pytest.raises(RuntimeError, match="violated"):
            verifier.assert_isolated()

    def test_checked_at_is_set(self):
        verifier = NetworkIsolationVerifier()
        with patch("core.airgap_deployment.socket.create_connection", side_effect=OSError), \
             patch("core.airgap_deployment.socket.getaddrinfo", side_effect=OSError), \
             patch("core.airgap_deployment.urllib.request.urlopen", side_effect=OSError):
            result = verifier.verify()
        assert result.checked_at != ""


# ===========================================================================
# 7. TelemetryKillSwitch
# ===========================================================================


class TestTelemetryKillSwitch:
    def test_disable_all_creates_kill_file(self, telemetry):
        status = telemetry.disable_all()
        assert telemetry.kill_file.exists()
        assert status.kill_file_present

    def test_disable_all_sets_env_vars(self, telemetry):
        telemetry.disable_all()
        assert os.environ.get("DO_NOT_TRACK") == "1"
        assert os.environ.get("HF_HUB_DISABLE_TELEMETRY") == "1"
        assert os.environ.get("NEXT_TELEMETRY_DISABLED") == "1"

    def test_disable_all_returns_all_disabled(self, telemetry):
        status = telemetry.disable_all()
        assert status.all_disabled is True

    def test_disable_all_lists_disabled_sources(self, telemetry):
        status = telemetry.disable_all()
        assert len(status.disabled_sources) > 0

    def test_verify_after_disable(self, telemetry):
        telemetry.disable_all()
        status = telemetry.verify()
        assert status.kill_file_present is True

    def test_verify_before_disable(self, telemetry):
        status = telemetry.verify()
        assert status.kill_file_present is False

    def test_telemetry_status_model(self):
        s = TelemetryStatus(all_disabled=True, kill_file_present=True, env_vars_cleared=True)
        assert s.all_disabled
        assert s.disabled_sources == []


# ===========================================================================
# 8. DeploymentValidator
# ===========================================================================


class TestDeploymentValidator:
    def _make_validator(self, tmp_path):
        tg = LocalTrustGraphConfig(config_path=tmp_path / "tg" / "config.json")
        tel = TelemetryKillSwitch(kill_file=tmp_path / "telemetry.disabled")
        cve = OfflineCVEDatabase(db_path=tmp_path / "cve_db" / "nvd.sqlite3")
        return DeploymentValidator(
            airgap_mode=AirGapMode,
            telemetry_switch=tel,
            trustgraph_config=tg,
            cve_db=cve,
        )

    def test_validate_returns_report(self, tmp_path):
        validator = self._make_validator(tmp_path)
        report = validator.validate()
        assert isinstance(report, DeploymentValidationReport)

    def test_validate_has_checks(self, tmp_path):
        validator = self._make_validator(tmp_path)
        report = validator.validate()
        assert len(report.checks) > 0

    def test_airgap_disabled_fails_check(self, tmp_path):
        AirGapMode.disable()
        validator = self._make_validator(tmp_path)
        report = validator.validate()
        airgap_check = next(c for c in report.checks if c.name == "air_gap_mode_enabled")
        assert not airgap_check.passed

    def test_airgap_enabled_passes_check(self, tmp_path):
        AirGapMode.enable()
        validator = self._make_validator(tmp_path)
        report = validator.validate()
        airgap_check = next(c for c in report.checks if c.name == "air_gap_mode_enabled")
        assert airgap_check.passed

    def test_telemetry_disabled_passes_after_kill(self, tmp_path):
        tel = TelemetryKillSwitch(kill_file=tmp_path / "telemetry.disabled")
        tel.disable_all()
        tg = LocalTrustGraphConfig(config_path=tmp_path / "tg" / "config.json")
        cve = OfflineCVEDatabase(db_path=tmp_path / "cve_db" / "nvd.sqlite3")
        validator = DeploymentValidator(
            airgap_mode=AirGapMode,
            telemetry_switch=tel,
            trustgraph_config=tg,
            cve_db=cve,
        )
        report = validator.validate()
        tel_check = next(c for c in report.checks if c.name == "telemetry_disabled")
        assert tel_check.passed

    def test_errors_count_computed(self, tmp_path):
        validator = self._make_validator(tmp_path)
        report = validator.validate()
        errors = sum(1 for c in report.checks if not c.passed and c.severity == "ERROR")
        assert report.errors == errors

    def test_classification_check_valid(self, tmp_path):
        validator = self._make_validator(tmp_path)
        report = validator.validate(classification="CUI")
        level_check = next(c for c in report.checks if c.name == "classification_level_valid")
        assert level_check.passed

    def test_classification_check_invalid(self, tmp_path):
        validator = self._make_validator(tmp_path)
        report = validator.validate(classification="UNKNOWN_LEVEL")
        level_check = next(c for c in report.checks if c.name == "classification_level_valid")
        assert not level_check.passed

    def test_check_item_severity_validation(self):
        item = DeploymentCheckItem(name="test", passed=True, severity="WARNING")
        assert item.severity == "WARNING"

    def test_check_item_invalid_severity_raises(self):
        with pytest.raises(Exception):
            DeploymentCheckItem(name="test", passed=True, severity="FATAL")


# ===========================================================================
# 9. ClassificationEnforcer
# ===========================================================================


class TestClassificationEnforcer:
    def setup_method(self):
        ClassificationEnforcer._current_level = ClassificationLevel.UNCLASSIFIED.value

    def test_default_level_unclassified(self):
        assert ClassificationEnforcer.get_level() == "UNCLASSIFIED"

    def test_set_level_returns_policy(self):
        policy = ClassificationEnforcer.set_level("CUI")
        assert isinstance(policy, ClassificationPolicy)
        assert policy.level == ClassificationLevel.CUI

    def test_set_invalid_level_raises(self):
        with pytest.raises(ValueError):
            ClassificationEnforcer.set_level("ULTRA_SECRET")

    def test_get_banner_unclassified(self):
        ClassificationEnforcer.set_level("UNCLASSIFIED")
        assert ClassificationEnforcer.get_banner() == "UNCLASSIFIED"

    def test_get_banner_secret(self):
        ClassificationEnforcer.set_level("SECRET")
        assert "SECRET" in ClassificationEnforcer.get_banner()

    def test_get_banner_top_secret(self):
        ClassificationEnforcer.set_level("TOP SECRET/SCI")
        assert "TOP SECRET" in ClassificationEnforcer.get_banner()

    def test_role_allowed_at_unclassified(self):
        ClassificationEnforcer.set_level("UNCLASSIFIED")
        assert ClassificationEnforcer.check_role_allowed("viewer")
        assert ClassificationEnforcer.check_role_allowed("admin")

    def test_role_blocked_at_top_secret(self):
        ClassificationEnforcer.set_level("TOP SECRET/SCI")
        assert not ClassificationEnforcer.check_role_allowed("viewer")
        assert ClassificationEnforcer.check_role_allowed("admin")

    def test_encrypt_at_rest_cui(self):
        ClassificationEnforcer.set_level("CUI")
        import os
        key = os.urandom(32)
        plaintext = b"CUI data"
        encrypted = ClassificationEnforcer.enforce_encryption(plaintext, key)
        assert encrypted != plaintext

    def test_no_encrypt_at_rest_unclassified(self):
        ClassificationEnforcer.set_level("UNCLASSIFIED")
        import os
        key = os.urandom(32)
        plaintext = b"open data"
        result = ClassificationEnforcer.enforce_encryption(plaintext, key)
        assert result == plaintext  # passthrough

    def test_all_policies_returns_all_levels(self):
        policies = ClassificationEnforcer.all_policies()
        assert "UNCLASSIFIED" in policies
        assert "CUI" in policies
        assert "SECRET" in policies
        assert "TOP SECRET/SCI" in policies

    def test_thread_safety(self):
        errors = []
        def set_level(level):
            try:
                ClassificationEnforcer.set_level(level)
            except Exception as e:
                errors.append(e)
        threads = [
            threading.Thread(target=set_level, args=("CUI",)),
            threading.Thread(target=set_level, args=("SECRET",)),
            threading.Thread(target=set_level, args=("UNCLASSIFIED",)),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert errors == []


# ===========================================================================
# 10. AirGapDeploymentHardening facade
# ===========================================================================


class TestAirGapDeploymentHardening:
    def test_enable_sets_airgap_mode(self, tmp_path):
        h = AirGapDeploymentHardening()
        h.enable()
        assert AirGapMode.is_enabled()

    def test_disable_clears_airgap_mode(self, tmp_path):
        h = AirGapDeploymentHardening()
        h.enable()
        h.disable()
        assert not AirGapMode.is_enabled()

    def test_status_returns_dict(self):
        h = AirGapDeploymentHardening()
        status = h.status()
        assert "air_gap_enabled" in status
        assert "classification" in status
        assert "cve_db_total" in status

    def test_network_check_returns_result(self):
        h = AirGapDeploymentHardening()
        with patch("core.airgap_deployment.socket.create_connection", side_effect=OSError), \
             patch("core.airgap_deployment.socket.getaddrinfo", side_effect=OSError), \
             patch("core.airgap_deployment.urllib.request.urlopen", side_effect=OSError):
            result = h.network_check()
        assert isinstance(result, NetworkCheckResult)

    def test_validate_returns_report(self):
        h = AirGapDeploymentHardening()
        report = h.validate()
        assert isinstance(report, DeploymentValidationReport)
        assert len(report.checks) >= 8


# ===========================================================================
# 11. Utility helpers
# ===========================================================================


class TestUtilityHelpers:
    def test_utcnow_returns_string(self):
        ts = _utcnow()
        assert isinstance(ts, str)
        assert "T" in ts

    def test_sha256_bytes_stable(self):
        data = b"hello world"
        h1 = _sha256_bytes(data)
        h2 = _sha256_bytes(data)
        assert h1 == h2
        assert len(h1) == 64

    def test_sneakernet_magic_length(self):
        assert len(SNEAKERNET_MAGIC) == 8

    def test_classification_policies_complete(self):
        assert len(CLASSIFICATION_POLICIES) == 4
        for level in ClassificationLevel:
            assert level.value in CLASSIFICATION_POLICIES
