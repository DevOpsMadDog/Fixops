"""Performance assertions for risk normalization pipeline.

Validates that:
1. compute_risk_profile over N findings completes within budget (no per-finding
   weight dict copy+rescaling regression).
2. Enhanced-weights precomputation (_build_enhanced_weights) produces correct
   proportional rescaling.
3. Scores remain in the valid 0-100 range.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.perf

import time
from typing import Any, Dict

import pytest

from risk.scoring import (
    _build_enhanced_weights,
    compute_risk_profile,
    DEFAULT_WEIGHTS,
)


def _make_sbom(n_components: int, vulns_per_component: int) -> Dict[str, Any]:
    """Generate a synthetic normalized SBOM."""
    components = []
    for c in range(n_components):
        vulns = []
        for v in range(vulns_per_component):
            cve_num = c * vulns_per_component + v + 1
            vulns.append({
                "cve": f"CVE-2024-{cve_num:05d}",
                "fix_version": "2.0.0",
            })
        components.append({
            "name": f"pkg-{c}",
            "version": "1.0.0",
            "purl": f"pkg:pypi/pkg-{c}@1.0.0",
            "vulnerabilities": vulns,
            "exposure": "internet",
        })
    return {"components": components}


class TestBuildEnhancedWeights:
    def test_no_reachability_returns_plain_copy(self):
        result = _build_enhanced_weights(DEFAULT_WEIGHTS, has_reachability=False)
        assert result == dict(DEFAULT_WEIGHTS)
        assert "reachability" not in result

    def test_with_reachability_adds_slot(self):
        result = _build_enhanced_weights(DEFAULT_WEIGHTS, has_reachability=True)
        assert "reachability" in result
        assert abs(result["reachability"] - 0.15) < 1e-9

    def test_with_reachability_rescales_proportionally(self):
        result = _build_enhanced_weights(DEFAULT_WEIGHTS, has_reachability=True)
        original_keys = set(DEFAULT_WEIGHTS.keys())
        rescaled_sum = sum(result[k] for k in original_keys)
        assert abs(rescaled_sum - 0.85) < 1e-9, f"Rescaled sum={rescaled_sum}"

    def test_total_weight_sums_to_one(self):
        result = _build_enhanced_weights(DEFAULT_WEIGHTS, has_reachability=True)
        assert abs(sum(result.values()) - 1.0) < 1e-9

    def test_already_has_reachability_unchanged(self):
        w = dict(DEFAULT_WEIGHTS)
        w["reachability"] = 0.10
        result = _build_enhanced_weights(w, has_reachability=True)
        assert result == w


class TestComputeRiskProfilePerf:
    """Timing guard: 500 findings must complete under 2 seconds."""

    N_COMPONENTS = 50
    VULNS_PER = 10  # 500 total findings

    def test_throughput_500_findings(self):
        sbom = _make_sbom(self.N_COMPONENTS, self.VULNS_PER)
        epss = {f"CVE-2024-{i:05d}": 0.05 + (i % 20) * 0.01 for i in range(1, 501)}
        kev = {f"CVE-2024-{i:05d}": True for i in range(1, 11)}

        start = time.perf_counter()
        report = compute_risk_profile(sbom, epss, kev)
        elapsed = time.perf_counter() - start

        assert elapsed < 2.0, f"500 findings took {elapsed:.3f}s — exceeds 2s budget"
        assert report["summary"]["component_count"] == self.N_COMPONENTS
        assert report["summary"]["cve_count"] == self.N_COMPONENTS * self.VULNS_PER

    def test_throughput_with_reachability(self):
        sbom = _make_sbom(self.N_COMPONENTS, self.VULNS_PER)
        epss = {f"CVE-2024-{i:05d}": 0.03 for i in range(1, 501)}
        kev: Dict[str, Any] = {}
        reach = {
            f"CVE-2024-{i:05d}": {"is_reachable": True, "confidence_score": 0.9}
            for i in range(1, 101)
        }

        start = time.perf_counter()
        report = compute_risk_profile(sbom, epss, kev, reachability_results=reach)
        elapsed = time.perf_counter() - start

        assert elapsed < 2.0, f"500 findings+reachability took {elapsed:.3f}s — exceeds 2s budget"
        assert report["summary"]["component_count"] == self.N_COMPONENTS

    def test_scores_in_valid_range(self):
        sbom = _make_sbom(10, 5)
        epss = {f"CVE-2024-{i:05d}": 0.5 for i in range(1, 51)}
        kev = {f"CVE-2024-{i:05d}": True for i in range(1, 6)}
        report = compute_risk_profile(sbom, epss, kev)
        for comp in report["components"]:
            assert 0.0 <= comp["component_risk"] <= 100.0
            for vuln in comp["vulnerabilities"]:
                assert 0.0 <= vuln["fixops_risk"] <= 100.0
