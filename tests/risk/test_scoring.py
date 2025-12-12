"""Rigorous tests for risk scoring functionality.

These tests verify EPSS, KEV, version lag, exposure, and reachability
scoring with realistic scenarios and proper assertions.
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import pytest

from risk.scoring import (
    DEFAULT_WEIGHTS,
    EXPOSURE_ALIASES,
    EXPOSURE_WEIGHTS,
    VERSION_LAG_CAP_DAYS,
    _coerce_float,
    _collect_exposure_flags,
    _collect_strings,
    _component_key,
    _estimate_lag_from_versions,
    _exposure_factor,
    _infer_version_lag_days,
    _lag_factor,
    _normalize_exposure,
    _now,
    _parse_datetime,
    _score_vulnerability,
    _slugify,
    compute_risk_profile,
    write_risk_report,
)


class TestExposureConstants:
    """Tests for exposure constants."""

    def test_exposure_aliases_contains_common_values(self):
        """Verify exposure aliases contain expected mappings."""
        assert EXPOSURE_ALIASES["internet"] == "internet"
        assert EXPOSURE_ALIASES["internet_exposed"] == "internet"
        assert EXPOSURE_ALIASES["public"] == "public"
        assert EXPOSURE_ALIASES["external"] == "public"
        assert EXPOSURE_ALIASES["internal"] == "internal"
        assert EXPOSURE_ALIASES["unknown"] == "unknown"
        assert EXPOSURE_ALIASES[""] == "unknown"

    def test_exposure_weights_ordering(self):
        """Verify exposure weights are ordered by risk."""
        assert EXPOSURE_WEIGHTS["internet"] > EXPOSURE_WEIGHTS["public"]
        assert EXPOSURE_WEIGHTS["public"] > EXPOSURE_WEIGHTS["partner"]
        assert EXPOSURE_WEIGHTS["partner"] > EXPOSURE_WEIGHTS["internal"]
        assert EXPOSURE_WEIGHTS["internal"] > EXPOSURE_WEIGHTS["controlled"]
        assert EXPOSURE_WEIGHTS["controlled"] > EXPOSURE_WEIGHTS["unknown"]

    def test_default_weights_sum_to_one(self):
        """Verify default weights sum to 1.0."""
        total = sum(DEFAULT_WEIGHTS.values())
        assert total == pytest.approx(1.0)


class TestNowFunction:
    """Tests for _now function."""

    def test_now_returns_utc_datetime(self):
        """Verify _now returns UTC datetime."""
        result = _now()
        assert isinstance(result, datetime)
        assert result.tzinfo == timezone.utc

    def test_now_with_test_seed(self):
        """Verify _now respects FIXOPS_TEST_SEED environment variable."""
        with patch.dict(os.environ, {"FIXOPS_TEST_SEED": "2024-01-15T10:30:00Z"}):
            result = _now()
            assert result.year == 2024
            assert result.month == 1
            assert result.day == 15
            assert result.hour == 10
            assert result.minute == 30

    def test_now_with_test_seed_no_timezone(self):
        """Verify _now handles seed without timezone."""
        with patch.dict(os.environ, {"FIXOPS_TEST_SEED": "2024-06-20T14:00:00"}):
            result = _now()
            assert result.tzinfo == timezone.utc


class TestComponentKey:
    """Tests for _component_key function."""

    def test_component_key_with_purl(self):
        """Verify component key uses purl when available."""
        component = {
            "purl": "pkg:npm/lodash@4.17.21",
            "name": "lodash",
            "version": "4.17.21",
        }
        assert _component_key(component) == "pkg:npm/lodash@4.17.21"

    def test_component_key_without_purl(self):
        """Verify component key falls back to name@version."""
        component = {"name": "requests", "version": "2.28.0"}
        assert _component_key(component) == "requests@2.28.0"

    def test_component_key_missing_name(self):
        """Verify component key handles missing name."""
        component = {"version": "1.0.0"}
        assert _component_key(component) == "unknown@1.0.0"

    def test_component_key_missing_version(self):
        """Verify component key handles missing version."""
        component = {"name": "mypackage"}
        assert _component_key(component) == "mypackage@unspecified"


class TestSlugify:
    """Tests for _slugify function."""

    def test_slugify_basic(self):
        """Verify basic slugification."""
        assert _slugify("my-package") == "my-package"

    def test_slugify_with_at_symbol(self):
        """Verify @ symbol is replaced."""
        assert _slugify("lodash@4.17.21") == "lodash-4.17.21"

    def test_slugify_with_special_chars(self):
        """Verify special characters are replaced."""
        assert _slugify("pkg:npm/lodash@4.17.21") == "pkg-npm-lodash-4.17.21"

    def test_slugify_removes_double_dashes(self):
        """Verify double dashes are collapsed."""
        assert _slugify("my--package") == "my-package"

    def test_slugify_lowercase(self):
        """Verify result is lowercase."""
        assert _slugify("MyPackage") == "mypackage"

    def test_slugify_empty_string(self):
        """Verify empty string returns 'component'."""
        assert _slugify("") == "component"


class TestCollectStrings:
    """Tests for _collect_strings function."""

    def test_collect_strings_from_string(self):
        """Verify string is yielded directly."""
        result = list(_collect_strings("test"))
        assert result == ["test"]

    def test_collect_strings_from_dict(self):
        """Verify strings are collected from dict values."""
        result = list(_collect_strings({"a": "value1", "b": "value2"}))
        assert "value1" in result
        assert "value2" in result

    def test_collect_strings_from_list(self):
        """Verify strings are collected from list."""
        result = list(_collect_strings(["a", "b", "c"]))
        assert result == ["a", "b", "c"]

    def test_collect_strings_nested(self):
        """Verify strings are collected from nested structures."""
        data = {"outer": {"inner": "nested_value"}, "list": ["item1", "item2"]}
        result = list(_collect_strings(data))
        assert "nested_value" in result
        assert "item1" in result
        assert "item2" in result

    def test_collect_strings_ignores_bytes(self):
        """Verify bytes are not collected."""
        result = list(_collect_strings(b"bytes"))
        assert result == []


class TestNormalizeExposure:
    """Tests for _normalize_exposure function."""

    def test_normalize_exposure_known_value(self):
        """Verify known exposure values are normalized."""
        assert _normalize_exposure("internet") == "internet"
        assert _normalize_exposure("INTERNET") == "internet"
        assert _normalize_exposure("Internet-Facing") == "internet"

    def test_normalize_exposure_alias(self):
        """Verify aliases are resolved."""
        assert _normalize_exposure("external") == "public"
        assert _normalize_exposure("dmz") == "public"
        assert _normalize_exposure("intranet") == "internal"

    def test_normalize_exposure_unknown(self):
        """Verify unknown values return as-is or unknown."""
        assert _normalize_exposure("custom_exposure") == "custom_exposure"
        assert _normalize_exposure("") == "unknown"


class TestCollectExposureFlags:
    """Tests for _collect_exposure_flags function."""

    def test_collect_exposure_flags_single_source(self):
        """Verify flags are collected from single source."""
        result = _collect_exposure_flags("internet")
        assert "internet" in result

    def test_collect_exposure_flags_multiple_sources(self):
        """Verify flags are collected from multiple sources."""
        result = _collect_exposure_flags("internet", "internal")
        assert "internet" in result
        assert "internal" in result

    def test_collect_exposure_flags_removes_unknown_when_others_present(self):
        """Verify unknown is removed when other flags present."""
        result = _collect_exposure_flags("internet", "unknown")
        assert "internet" in result
        assert "unknown" not in result

    def test_collect_exposure_flags_keeps_unknown_when_alone(self):
        """Verify unknown is kept when no other flags."""
        result = _collect_exposure_flags()
        assert "unknown" in result


class TestExposureFactor:
    """Tests for _exposure_factor function."""

    def test_exposure_factor_internet(self):
        """Verify internet exposure has highest factor."""
        assert _exposure_factor(["internet"]) == 1.0

    def test_exposure_factor_multiple_takes_max(self):
        """Verify max factor is used for multiple flags."""
        factor = _exposure_factor(["internal", "internet"])
        assert factor == 1.0  # internet is highest

    def test_exposure_factor_empty_returns_unknown(self):
        """Verify empty flags return unknown weight."""
        assert _exposure_factor([]) == EXPOSURE_WEIGHTS["unknown"]


class TestParseDatetime:
    """Tests for _parse_datetime function."""

    def test_parse_datetime_from_datetime(self):
        """Verify datetime is returned as-is."""
        dt = datetime(2024, 1, 15, tzinfo=timezone.utc)
        assert _parse_datetime(dt) == dt

    def test_parse_datetime_from_iso_string(self):
        """Verify ISO string is parsed."""
        result = _parse_datetime("2024-01-15T10:30:00Z")
        assert result.year == 2024
        assert result.month == 1
        assert result.day == 15

    def test_parse_datetime_invalid_string(self):
        """Verify invalid string returns None."""
        assert _parse_datetime("not-a-date") is None

    def test_parse_datetime_none(self):
        """Verify None returns None."""
        assert _parse_datetime(None) is None


class TestCoerceFloat:
    """Tests for _coerce_float function."""

    def test_coerce_float_from_int(self):
        """Verify int is coerced to float."""
        assert _coerce_float(42) == 42.0

    def test_coerce_float_from_float(self):
        """Verify float is returned as-is."""
        assert _coerce_float(3.14) == 3.14

    def test_coerce_float_from_string(self):
        """Verify numeric string is parsed."""
        assert _coerce_float("2.5") == 2.5

    def test_coerce_float_invalid_string(self):
        """Verify invalid string returns default."""
        assert _coerce_float("not-a-number", default=0.0) == 0.0

    def test_coerce_float_none(self):
        """Verify None returns default."""
        assert _coerce_float(None, default=1.0) == 1.0


class TestEstimateLagFromVersions:
    """Tests for _estimate_lag_from_versions function."""

    def test_estimate_lag_major_version(self):
        """Verify major version difference is calculated."""
        lag = _estimate_lag_from_versions("1.0.0", "2.0.0")
        assert lag == 365  # 1 major version = 365 days

    def test_estimate_lag_minor_version(self):
        """Verify minor version difference is calculated."""
        lag = _estimate_lag_from_versions("1.0.0", "1.2.0")
        assert lag == 180  # 2 minor versions = 2 * 90 days

    def test_estimate_lag_patch_version(self):
        """Verify patch version difference is calculated."""
        lag = _estimate_lag_from_versions("1.0.0", "1.0.5")
        assert lag == 150  # 5 patches = 5 * 30 days

    def test_estimate_lag_target_lower(self):
        """Verify no lag when target is lower."""
        lag = _estimate_lag_from_versions("2.0.0", "1.0.0")
        assert lag == 0.0

    def test_estimate_lag_invalid_version(self):
        """Verify invalid versions return 0."""
        lag = _estimate_lag_from_versions("invalid", "1.0.0")
        assert lag == 0.0


class TestInferVersionLagDays:
    """Tests for _infer_version_lag_days function."""

    def test_infer_lag_from_vulnerability(self):
        """Verify lag is read from vulnerability."""
        component = {}
        vulnerability = {"version_lag_days": 45}
        assert _infer_version_lag_days(component, vulnerability) == 45.0

    def test_infer_lag_from_component(self):
        """Verify lag is read from component."""
        component = {"lag_days": 30}
        vulnerability = {}
        assert _infer_version_lag_days(component, vulnerability) == 30.0

    def test_infer_lag_from_versions(self):
        """Verify lag is estimated from versions."""
        component = {"version": "1.0.0"}
        vulnerability = {"fix_version": "1.1.0"}
        lag = _infer_version_lag_days(component, vulnerability)
        assert lag == 90  # 1 minor version

    def test_infer_lag_no_data(self):
        """Verify 0 is returned when no data available."""
        assert _infer_version_lag_days({}, {}) == 0.0


class TestLagFactor:
    """Tests for _lag_factor function."""

    def test_lag_factor_zero(self):
        """Verify zero days returns 0."""
        assert _lag_factor(0) == 0.0

    def test_lag_factor_half_cap(self):
        """Verify half cap returns 0.5."""
        assert _lag_factor(VERSION_LAG_CAP_DAYS / 2) == 0.5

    def test_lag_factor_at_cap(self):
        """Verify at cap returns 1.0."""
        assert _lag_factor(VERSION_LAG_CAP_DAYS) == 1.0

    def test_lag_factor_above_cap(self):
        """Verify above cap is capped at 1.0."""
        assert _lag_factor(VERSION_LAG_CAP_DAYS * 2) == 1.0


class TestScoreVulnerability:
    """Tests for _score_vulnerability function."""

    def test_score_vulnerability_basic(self):
        """Verify basic vulnerability scoring."""
        component = {"name": "test", "version": "1.0.0"}
        vulnerability = {"cve": "CVE-2024-1234"}
        epss_scores = {"CVE-2024-1234": 0.5}
        kev_entries = {}

        result = _score_vulnerability(
            component, vulnerability, epss_scores, kev_entries, DEFAULT_WEIGHTS
        )

        assert result is not None
        assert result["cve"] == "CVE-2024-1234"
        assert result["epss"] == 0.5
        assert result["kev"] is False
        assert "fixops_risk" in result

    def test_score_vulnerability_with_kev(self):
        """Verify KEV presence increases score."""
        component = {"name": "test", "version": "1.0.0"}
        vulnerability = {"cve": "CVE-2024-1234"}
        epss_scores = {"CVE-2024-1234": 0.5}
        kev_entries = {"CVE-2024-1234": {}}

        result = _score_vulnerability(
            component, vulnerability, epss_scores, kev_entries, DEFAULT_WEIGHTS
        )

        assert result["kev"] is True
        assert result["fixops_risk"] > 0

    def test_score_vulnerability_with_reachability_not_reachable(self):
        """Verify not reachable with high confidence reduces score."""
        component = {"name": "test", "version": "1.0.0"}
        vulnerability = {"cve": "CVE-2024-1234"}
        epss_scores = {"CVE-2024-1234": 0.8}
        kev_entries = {"CVE-2024-1234": {}}

        # Without reachability
        result_no_reach = _score_vulnerability(
            component, vulnerability, epss_scores, kev_entries, DEFAULT_WEIGHTS
        )

        # With high confidence NOT reachable
        reachability = {"is_reachable": False, "confidence_score": 0.9}
        result_not_reachable = _score_vulnerability(
            component,
            vulnerability,
            epss_scores,
            kev_entries,
            DEFAULT_WEIGHTS,
            reachability_result=reachability,
        )

        assert result_not_reachable["reachability"]["factor_applied"] == 0.1
        assert result_not_reachable["fixops_risk"] < result_no_reach["fixops_risk"]

    def test_score_vulnerability_with_reachability_is_reachable(self):
        """Verify reachable with high confidence increases score."""
        component = {"name": "test", "version": "1.0.0"}
        vulnerability = {"cve": "CVE-2024-1234"}
        epss_scores = {"CVE-2024-1234": 0.3}
        kev_entries = {}

        # Without reachability
        result_no_reach = _score_vulnerability(
            component, vulnerability, epss_scores, kev_entries, DEFAULT_WEIGHTS
        )

        # With high confidence IS reachable
        reachability = {"is_reachable": True, "confidence_score": 0.9}
        result_reachable = _score_vulnerability(
            component,
            vulnerability,
            epss_scores,
            kev_entries,
            DEFAULT_WEIGHTS,
            reachability_result=reachability,
        )

        assert result_reachable["reachability"]["factor_applied"] == 1.5
        assert result_reachable["fixops_risk"] > result_no_reach["fixops_risk"]

    def test_score_vulnerability_no_cve(self):
        """Verify vulnerability without CVE returns None."""
        component = {"name": "test"}
        vulnerability = {"description": "No CVE"}

        result = _score_vulnerability(component, vulnerability, {}, {}, DEFAULT_WEIGHTS)

        assert result is None

    def test_score_vulnerability_exposure_flags(self):
        """Verify exposure flags affect score."""
        component = {"name": "test", "version": "1.0.0", "exposure": "internet"}
        vulnerability = {"cve": "CVE-2024-1234"}

        result = _score_vulnerability(component, vulnerability, {}, {}, DEFAULT_WEIGHTS)

        assert "internet" in result["exposure_flags"]


class TestComputeRiskProfile:
    """Tests for compute_risk_profile function."""

    def test_compute_risk_profile_basic(self):
        """Verify basic risk profile computation."""
        sbom = {
            "components": [
                {
                    "name": "lodash",
                    "version": "4.17.20",
                    "purl": "pkg:npm/lodash@4.17.20",
                    "vulnerabilities": [{"cve": "CVE-2021-23337", "severity": "high"}],
                }
            ]
        }
        epss_scores = {"CVE-2021-23337": 0.6}
        kev_entries = {}

        result = compute_risk_profile(sbom, epss_scores, kev_entries)

        assert "generated_at" in result
        assert "components" in result
        assert "cves" in result
        assert "summary" in result
        assert result["summary"]["component_count"] == 1
        assert result["summary"]["cve_count"] == 1

    def test_compute_risk_profile_multiple_components(self):
        """Verify multiple components are processed."""
        sbom = {
            "components": [
                {
                    "name": "pkg1",
                    "version": "1.0.0",
                    "vulnerabilities": [{"cve": "CVE-2024-0001"}],
                },
                {
                    "name": "pkg2",
                    "version": "2.0.0",
                    "vulnerabilities": [{"cve": "CVE-2024-0002"}],
                },
            ]
        }

        result = compute_risk_profile(sbom, {}, {})

        assert result["summary"]["component_count"] == 2
        assert result["summary"]["cve_count"] == 2

    def test_compute_risk_profile_with_reachability(self):
        """Verify reachability results are integrated."""
        sbom = {
            "components": [
                {
                    "name": "vulnerable-pkg",
                    "version": "1.0.0",
                    "vulnerabilities": [{"cve": "CVE-2024-9999"}],
                }
            ]
        }
        reachability_results = {
            "CVE-2024-9999": {"is_reachable": True, "confidence_score": 0.85}
        }

        result = compute_risk_profile(
            sbom, {}, {}, reachability_results=reachability_results
        )

        assert result["summary"]["component_count"] == 1
        # Check that reachability was applied
        component = result["components"][0]
        vuln = component["vulnerabilities"][0]
        assert vuln["reachability"] is not None
        assert vuln["reachability"]["is_reachable"] is True

    def test_compute_risk_profile_empty_sbom(self):
        """Verify empty SBOM returns empty profile."""
        result = compute_risk_profile({"components": []}, {}, {})

        assert result["summary"]["component_count"] == 0
        assert result["summary"]["cve_count"] == 0
        assert result["summary"]["highest_risk_component"] is None

    def test_compute_risk_profile_highest_risk(self):
        """Verify highest risk component is identified."""
        sbom = {
            "components": [
                {
                    "name": "low-risk",
                    "version": "1.0.0",
                    "vulnerabilities": [{"cve": "CVE-2024-0001"}],
                },
                {
                    "name": "high-risk",
                    "version": "1.0.0",
                    "vulnerabilities": [{"cve": "CVE-2024-0002"}],
                },
            ]
        }
        # High EPSS for second CVE
        epss_scores = {"CVE-2024-0001": 0.1, "CVE-2024-0002": 0.9}
        kev_entries = {"CVE-2024-0002": {}}  # Also in KEV

        result = compute_risk_profile(sbom, epss_scores, kev_entries)

        # Slug includes name and version
        assert "high-risk" in result["summary"]["highest_risk_component"]
        assert result["summary"]["max_risk_score"] > 0


class TestWriteRiskReport:
    """Tests for write_risk_report function."""

    def test_write_risk_report_creates_file(self):
        """Verify risk report is written to file."""
        sbom = {
            "components": [
                {
                    "name": "test-pkg",
                    "version": "1.0.0",
                    "vulnerabilities": [{"cve": "CVE-2024-1234"}],
                }
            ]
        }

        with TemporaryDirectory() as tmpdir:
            sbom_path = Path(tmpdir) / "sbom.json"
            report_path = Path(tmpdir) / "report.json"

            with open(sbom_path, "w") as f:
                json.dump(sbom, f)

            result = write_risk_report(
                sbom_path, report_path, {"CVE-2024-1234": 0.5}, {}
            )

            assert report_path.exists()
            assert result["summary"]["component_count"] == 1

            # Verify file contents
            with open(report_path) as f:
                written = json.load(f)
            assert written["summary"]["cve_count"] == 1

    def test_write_risk_report_creates_parent_dirs(self):
        """Verify parent directories are created."""
        sbom = {"components": []}

        with TemporaryDirectory() as tmpdir:
            sbom_path = Path(tmpdir) / "sbom.json"
            report_path = Path(tmpdir) / "nested" / "dir" / "report.json"

            with open(sbom_path, "w") as f:
                json.dump(sbom, f)

            write_risk_report(sbom_path, report_path, {}, {})

            assert report_path.exists()
