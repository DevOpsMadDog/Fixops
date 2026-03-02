"""
Unit tests for suite-evidence-risk/risk/scoring.py — Risk Scoring Engine [V3].

Covers:
  - Helper functions: _component_key, _slugify, _normalize_exposure,
    _collect_exposure_flags, _exposure_factor, _parse_datetime, _coerce_float,
    _estimate_lag_from_versions, _infer_version_lag_days, _lag_factor,
    _collect_strings
  - _score_vulnerability — CVE scoring with EPSS, KEV, lag, exposure, reachability
  - compute_risk_profile — full SBOM risk profiling
  - Exposure alias normalization
  - Reachability factor adjustments
"""

import json
import os
from datetime import datetime, timezone


# Ensure suite paths
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-evidence-risk"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))

from risk.scoring import (
    EXPOSURE_ALIASES,
    EXPOSURE_WEIGHTS,
    DEFAULT_WEIGHTS,
    VERSION_LAG_CAP_DAYS,
    _component_key,
    _slugify,
    _normalize_exposure,
    _collect_exposure_flags,
    _exposure_factor,
    _parse_datetime,
    _coerce_float,
    _estimate_lag_from_versions,
    _infer_version_lag_days,
    _lag_factor,
    _collect_strings,
    _score_vulnerability,
    compute_risk_profile,
    write_risk_report,
)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

class TestConstants:
    def test_exposure_aliases_has_internet(self):
        assert EXPOSURE_ALIASES["internet"] == "internet"

    def test_exposure_aliases_normalizes_variants(self):
        assert EXPOSURE_ALIASES["internet_exposed"] == "internet"
        assert EXPOSURE_ALIASES["internet-facing"] == "internet"
        assert EXPOSURE_ALIASES["dmz"] == "public"
        assert EXPOSURE_ALIASES["saas"] == "partner"
        assert EXPOSURE_ALIASES["intranet"] == "internal"
        assert EXPOSURE_ALIASES["restricted"] == "controlled"

    def test_exposure_weights_internet_highest(self):
        assert EXPOSURE_WEIGHTS["internet"] == 1.0
        assert EXPOSURE_WEIGHTS["unknown"] < EXPOSURE_WEIGHTS["internet"]

    def test_default_weights_sum_to_one(self):
        assert abs(sum(DEFAULT_WEIGHTS.values()) - 1.0) < 0.001

    def test_version_lag_cap_is_180_days(self):
        assert VERSION_LAG_CAP_DAYS == 180.0


# ---------------------------------------------------------------------------
# _component_key
# ---------------------------------------------------------------------------

class TestComponentKey:
    def test_with_purl(self):
        assert _component_key({"purl": "pkg:npm/express@4.18.2"}) == "pkg:npm/express@4.18.2"

    def test_with_name_version(self):
        assert _component_key({"name": "lodash", "version": "4.17.21"}) == "lodash@4.17.21"

    def test_missing_name_version(self):
        assert _component_key({}) == "unknown@unspecified"

    def test_purl_takes_precedence(self):
        c = {"purl": "pkg:pypi/flask@2.0", "name": "flask", "version": "2.0"}
        assert _component_key(c) == "pkg:pypi/flask@2.0"

    def test_empty_purl_falls_back(self):
        assert _component_key({"purl": "", "name": "foo", "version": "1.0"}) == "foo@1.0"


# ---------------------------------------------------------------------------
# _slugify
# ---------------------------------------------------------------------------

class TestSlugify:
    def test_basic(self):
        assert _slugify("lodash@4.17.21") == "lodash-4.17.21"

    def test_special_chars(self):
        assert _slugify("pkg:npm/express@4.18") == "pkg-npm-express-4.18"

    def test_double_dash(self):
        result = _slugify("a//b")
        assert "--" not in result

    def test_empty(self):
        assert _slugify("") == "component"


# ---------------------------------------------------------------------------
# _normalize_exposure
# ---------------------------------------------------------------------------

class TestNormalizeExposure:
    def test_known_aliases(self):
        assert _normalize_exposure("internet") == "internet"
        assert _normalize_exposure("Internet-Facing") == "internet"
        assert _normalize_exposure("  DMZ  ") == "public"
        assert _normalize_exposure("SAAS") == "partner"
        assert _normalize_exposure("ONPREM") == "internal"

    def test_unknown(self):
        assert _normalize_exposure("") == "unknown"
        assert _normalize_exposure("some_random_value") == "some_random_value"


# ---------------------------------------------------------------------------
# _collect_strings
# ---------------------------------------------------------------------------

class TestCollectStrings:
    def test_string(self):
        assert list(_collect_strings("hello")) == ["hello"]

    def test_dict(self):
        result = list(_collect_strings({"a": "x", "b": "y"}))
        assert set(result) == {"x", "y"}

    def test_list(self):
        assert list(_collect_strings(["a", "b"])) == ["a", "b"]

    def test_nested(self):
        data = {"tags": ["internet", {"inner": "public"}]}
        result = list(_collect_strings(data))
        assert "internet" in result
        assert "public" in result

    def test_non_string_leaf(self):
        assert list(_collect_strings(42)) == []
        assert list(_collect_strings(None)) == []


# ---------------------------------------------------------------------------
# _collect_exposure_flags
# ---------------------------------------------------------------------------

class TestCollectExposureFlags:
    def test_single_source(self):
        flags = _collect_exposure_flags("internet")
        assert "internet" in flags

    def test_removes_unknown_when_others_exist(self):
        flags = _collect_exposure_flags("internet", "unknown_thing")
        assert "unknown" not in flags or "internet" not in flags
        assert "internet" in flags

    def test_only_unknown(self):
        flags = _collect_exposure_flags(None)
        assert "unknown" in flags

    def test_multiple_sources(self):
        flags = _collect_exposure_flags("internet", ["dmz", "saas"])
        assert "internet" in flags
        assert "public" in flags  # dmz → public
        assert "partner" in flags  # saas → partner


# ---------------------------------------------------------------------------
# _exposure_factor
# ---------------------------------------------------------------------------

class TestExposureFactor:
    def test_internet(self):
        assert _exposure_factor(["internet"]) == 1.0

    def test_internal(self):
        assert _exposure_factor(["internal"]) == 0.5

    def test_empty(self):
        assert _exposure_factor([]) == EXPOSURE_WEIGHTS["unknown"]

    def test_max_of_multiple(self):
        result = _exposure_factor(["internal", "internet"])
        assert result == 1.0  # max


# ---------------------------------------------------------------------------
# _parse_datetime
# ---------------------------------------------------------------------------

class TestParseDatetime:
    def test_string_iso(self):
        dt = _parse_datetime("2025-01-15T12:00:00Z")
        assert isinstance(dt, datetime)
        assert dt.year == 2025

    def test_datetime_passthrough(self):
        now = datetime.now(timezone.utc)
        assert _parse_datetime(now) is now

    def test_invalid(self):
        assert _parse_datetime("not-a-date") is None
        assert _parse_datetime(42) is None
        assert _parse_datetime(None) is None


# ---------------------------------------------------------------------------
# _coerce_float
# ---------------------------------------------------------------------------

class TestCoerceFloat:
    def test_int(self):
        assert _coerce_float(5) == 5.0

    def test_float(self):
        assert _coerce_float(3.14) == 3.14

    def test_string(self):
        assert _coerce_float("2.5") == 2.5

    def test_invalid_string(self):
        assert _coerce_float("abc") == 0.0

    def test_default(self):
        assert _coerce_float("abc", default=99.0) == 99.0

    def test_none(self):
        assert _coerce_float(None) == 0.0


# ---------------------------------------------------------------------------
# _estimate_lag_from_versions
# ---------------------------------------------------------------------------

class TestEstimateLagFromVersions:
    def test_major_lag(self):
        lag = _estimate_lag_from_versions("1.0.0", "2.0.0")
        assert lag == 365.0  # 1 major

    def test_minor_lag(self):
        lag = _estimate_lag_from_versions("1.0.0", "1.1.0")
        assert lag == 90.0  # 1 minor

    def test_patch_lag(self):
        lag = _estimate_lag_from_versions("1.0.0", "1.0.1")
        assert lag == 30.0  # 1 patch

    def test_no_lag(self):
        assert _estimate_lag_from_versions("2.0.0", "1.0.0") == 0.0

    def test_same_version(self):
        assert _estimate_lag_from_versions("1.0.0", "1.0.0") == 0.0

    def test_invalid_version(self):
        assert _estimate_lag_from_versions("abc", "1.0.0") == 0.0


# ---------------------------------------------------------------------------
# _lag_factor
# ---------------------------------------------------------------------------

class TestLagFactor:
    def test_zero_days(self):
        assert _lag_factor(0) == 0.0

    def test_negative(self):
        assert _lag_factor(-5) == 0.0

    def test_half_cap(self):
        assert abs(_lag_factor(90) - 0.5) < 0.01

    def test_at_cap(self):
        assert _lag_factor(180) == 1.0

    def test_beyond_cap(self):
        assert _lag_factor(360) == 1.0


# ---------------------------------------------------------------------------
# _infer_version_lag_days
# ---------------------------------------------------------------------------

class TestInferVersionLagDays:
    def test_explicit_lag(self):
        vuln = {"version_lag_days": 42}
        assert _infer_version_lag_days({}, vuln) == 42.0

    def test_from_component_lag(self):
        comp = {"lag_days": 15}
        assert _infer_version_lag_days(comp, {}) == 15.0

    def test_from_versions(self):
        comp = {"version": "1.0.0"}
        vuln = {"fix_version": "1.1.0"}
        assert _infer_version_lag_days(comp, vuln) == 90.0

    def test_from_dates(self):
        comp = {"last_observed": "2025-01-01T00:00:00Z"}
        vuln = {"fixed_release_date": "2025-02-01T00:00:00Z"}
        lag = _infer_version_lag_days(comp, vuln)
        assert lag == 31.0

    def test_no_data(self):
        assert _infer_version_lag_days({}, {}) == 0.0


# ---------------------------------------------------------------------------
# _score_vulnerability
# ---------------------------------------------------------------------------

class TestScoreVulnerability:
    def test_basic_scoring(self):
        result = _score_vulnerability(
            component={"name": "test", "version": "1.0"},
            vulnerability={"cve": "CVE-2024-0001"},
            epss_scores={"CVE-2024-0001": 0.9},
            kev_entries={"CVE-2024-0001": True},
            weights=DEFAULT_WEIGHTS,
        )
        assert result is not None
        assert result["cve"] == "CVE-2024-0001"
        assert result["epss"] == 0.9
        assert result["kev"] is True
        assert result["fixops_risk"] > 0

    def test_no_cve_returns_none(self):
        result = _score_vulnerability(
            component={}, vulnerability={},
            epss_scores={}, kev_entries={}, weights=DEFAULT_WEIGHTS,
        )
        assert result is None

    def test_kev_boosts_score(self):
        base = _score_vulnerability(
            component={}, vulnerability={"cve": "CVE-2024-0001"},
            epss_scores={}, kev_entries={}, weights=DEFAULT_WEIGHTS,
        )
        kev = _score_vulnerability(
            component={}, vulnerability={"cve": "CVE-2024-0001"},
            epss_scores={}, kev_entries={"CVE-2024-0001": True}, weights=DEFAULT_WEIGHTS,
        )
        assert kev["fixops_risk"] > base["fixops_risk"]

    def test_reachability_not_reachable_reduces(self):
        base = _score_vulnerability(
            component={}, vulnerability={"cve": "CVE-2024-0001"},
            epss_scores={"CVE-2024-0001": 0.5}, kev_entries={},
            weights=DEFAULT_WEIGHTS,
        )
        not_reach = _score_vulnerability(
            component={}, vulnerability={"cve": "CVE-2024-0001"},
            epss_scores={"CVE-2024-0001": 0.5}, kev_entries={},
            weights=DEFAULT_WEIGHTS,
            reachability_result={"is_reachable": False, "confidence_score": 0.9},
        )
        assert not_reach["fixops_risk"] < base["fixops_risk"]

    def test_reachability_reachable_boosts(self):
        base = _score_vulnerability(
            component={}, vulnerability={"cve": "CVE-2024-0001"},
            epss_scores={"CVE-2024-0001": 0.5}, kev_entries={},
            weights=DEFAULT_WEIGHTS,
        )
        reach = _score_vulnerability(
            component={}, vulnerability={"cve": "CVE-2024-0001"},
            epss_scores={"CVE-2024-0001": 0.5}, kev_entries={},
            weights=DEFAULT_WEIGHTS,
            reachability_result={"is_reachable": True, "confidence_score": 0.9},
        )
        assert reach["fixops_risk"] > base["fixops_risk"]

    def test_risk_breakdown_present(self):
        result = _score_vulnerability(
            component={}, vulnerability={"cve": "CVE-2024-0001"},
            epss_scores={}, kev_entries={}, weights=DEFAULT_WEIGHTS,
        )
        assert "risk_breakdown" in result
        assert "weights" in result["risk_breakdown"]
        assert "contributions" in result["risk_breakdown"]

    def test_score_clamped_0_100(self):
        result = _score_vulnerability(
            component={"exposure": "internet"},
            vulnerability={"cve": "CVE-2024-0001"},
            epss_scores={"CVE-2024-0001": 1.0},
            kev_entries={"CVE-2024-0001": True},
            weights=DEFAULT_WEIGHTS,
            reachability_result={"is_reachable": True, "confidence_score": 1.0},
        )
        assert 0 <= result["fixops_risk"] <= 100

    def test_cve_id_uppercased(self):
        result = _score_vulnerability(
            component={}, vulnerability={"cve": "cve-2024-0001"},
            epss_scores={}, kev_entries={}, weights=DEFAULT_WEIGHTS,
        )
        assert result["cve"] == "CVE-2024-0001"


# ---------------------------------------------------------------------------
# compute_risk_profile
# ---------------------------------------------------------------------------

class TestComputeRiskProfile:
    def test_empty_sbom(self):
        result = compute_risk_profile({}, {}, {})
        assert result["summary"]["component_count"] == 0
        assert result["summary"]["cve_count"] == 0

    def test_single_component_single_vuln(self):
        sbom = {
            "components": [
                {
                    "name": "express",
                    "version": "4.17.1",
                    "vulnerabilities": [{"cve": "CVE-2024-0001"}],
                }
            ]
        }
        result = compute_risk_profile(sbom, {"CVE-2024-0001": 0.7}, {})
        assert result["summary"]["component_count"] == 1
        assert result["summary"]["cve_count"] == 1
        assert result["summary"]["max_risk_score"] > 0

    def test_multiple_components(self):
        sbom = {
            "components": [
                {
                    "name": "express",
                    "version": "4.17.1",
                    "vulnerabilities": [{"cve": "CVE-2024-0001"}],
                },
                {
                    "name": "lodash",
                    "version": "4.17.20",
                    "vulnerabilities": [{"cve": "CVE-2024-0002"}],
                },
            ]
        }
        result = compute_risk_profile(sbom, {}, {})
        assert result["summary"]["component_count"] == 2
        assert result["summary"]["cve_count"] == 2

    def test_no_vulnerabilities_skipped(self):
        sbom = {"components": [{"name": "safe-lib", "version": "1.0.0"}]}
        result = compute_risk_profile(sbom, {}, {})
        assert result["summary"]["component_count"] == 0

    def test_kev_and_epss_affect_ranking(self):
        sbom = {
            "components": [
                {
                    "name": "lib-a",
                    "version": "1.0.0",
                    "vulnerabilities": [{"cve": "CVE-2024-0001"}],
                },
                {
                    "name": "lib-b",
                    "version": "1.0.0",
                    "vulnerabilities": [{"cve": "CVE-2024-0002"}],
                },
            ]
        }
        result = compute_risk_profile(
            sbom,
            {"CVE-2024-0001": 0.95, "CVE-2024-0002": 0.01},
            {"CVE-2024-0001": True},
        )
        cves = result["cves"]
        assert cves["CVE-2024-0001"]["max_risk"] > cves["CVE-2024-0002"]["max_risk"]

    def test_with_reachability(self):
        sbom = {
            "components": [
                {
                    "name": "lib-x",
                    "version": "1.0.0",
                    "vulnerabilities": [{"cve": "CVE-2024-0001"}],
                },
            ]
        }
        reach = {"CVE-2024-0001": {"is_reachable": True, "confidence_score": 0.95}}
        result = compute_risk_profile(
            sbom, {"CVE-2024-0001": 0.5}, {}, reachability_results=reach,
        )
        assert result["summary"]["component_count"] == 1

    def test_generated_at_present(self):
        result = compute_risk_profile({}, {}, {})
        assert "generated_at" in result

    def test_weights_in_output(self):
        result = compute_risk_profile({}, {}, {})
        assert "weights" in result


# ---------------------------------------------------------------------------
# write_risk_report
# ---------------------------------------------------------------------------

class TestWriteRiskReport:
    def test_writes_json(self, tmp_path):
        sbom = {
            "components": [
                {
                    "name": "express",
                    "version": "4.17.1",
                    "vulnerabilities": [{"cve": "CVE-2024-0001"}],
                }
            ]
        }
        sbom_path = tmp_path / "sbom.json"
        sbom_path.write_text(json.dumps(sbom))
        dest = tmp_path / "report.json"

        result = write_risk_report(str(sbom_path), str(dest), {"CVE-2024-0001": 0.5}, {})
        assert dest.exists()
        loaded = json.loads(dest.read_text())
        assert loaded["summary"]["component_count"] == 1
        assert result["summary"]["component_count"] == 1

    def test_creates_parent_dirs(self, tmp_path):
        sbom = {"components": []}
        sbom_path = tmp_path / "sbom.json"
        sbom_path.write_text(json.dumps(sbom))
        dest = tmp_path / "sub" / "dir" / "report.json"

        write_risk_report(str(sbom_path), str(dest), {}, {})
        assert dest.exists()
