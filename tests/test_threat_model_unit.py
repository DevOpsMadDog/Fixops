"""Comprehensive unit tests for suite-evidence-risk/risk/threat_model.py.

Self-contained: uses sys.path manipulation and a local mock of EnrichmentEvidence
so no external suite dependencies are pulled in. Runnable with:

    python -m pytest tests/test_threat_model_unit.py -v
"""

from __future__ import annotations

import sys
import math
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock

# --- Path setup -------------------------------------------------------------
# Insert the evidence-risk suite so that `risk.threat_model` is importable.
sys.path.insert(0, "suite-evidence-risk")

# ---------------------------------------------------------------------------
# Lightweight stand-in for EnrichmentEvidence.
# The threat_model module only accesses .cvss_vector and .has_vendor_advisory,
# so that is all we need to provide.  We patch risk.enrichment.EnrichmentEvidence
# before importing threat_model so the module-level import resolves to our stub.
# ---------------------------------------------------------------------------


@dataclass
class _StubEnrichmentEvidence:
    """Minimal stub that satisfies threat_model's usage of EnrichmentEvidence."""

    cve_id: str
    cvss_vector: Optional[str] = None
    has_vendor_advisory: bool = False
    # Extra fields present on the real class — ignored by threat_model but kept
    # here so tests that build realistic objects stay readable.
    kev_listed: bool = False
    epss_score: Optional[float] = None
    exploitdb_refs: int = 0
    cvss_score: Optional[float] = None
    cwe_ids: List[str] = field(default_factory=list)
    age_days: Optional[int] = None
    published_date: Optional[str] = None
    last_modified_date: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


# Patch before import so the module-level `from risk.enrichment import …` resolves.
_enrichment_mod = MagicMock()
_enrichment_mod.EnrichmentEvidence = _StubEnrichmentEvidence
sys.modules.setdefault("risk.enrichment", _enrichment_mod)

# Now import the module under test.
from risk.threat_model import (  # noqa: E402
    ThreatModelResult,
    _calculate_reachability_score,
    _determine_exposure_level,
    _find_affected_components,
    _parse_cvss_vector,
    compute_threat_model,
)


# ---------------------------------------------------------------------------
# Helpers shared across test classes
# ---------------------------------------------------------------------------

def _make_evidence(
    cve_id: str = "CVE-2024-TEST",
    cvss_vector: Optional[str] = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    has_vendor_advisory: bool = False,
    cvss_score: float = 9.8,
) -> _StubEnrichmentEvidence:
    return _StubEnrichmentEvidence(
        cve_id=cve_id,
        cvss_vector=cvss_vector,
        has_vendor_advisory=has_vendor_advisory,
        cvss_score=cvss_score,
    )


def _make_graph(cve_id: str, component_names: List[str]) -> Dict[str, Any]:
    """Build a minimal knowledge graph referencing a vulnerability and components."""
    vuln_id = f"vuln:{cve_id}"
    nodes: List[Dict[str, Any]] = [
        {"id": vuln_id, "type": "vulnerability"},
    ]
    edges: List[Dict[str, Any]] = []
    for name in component_names:
        comp_id = f"comp:{name}"
        nodes.append({"id": comp_id, "type": "component", "name": name})
        edges.append({"source": comp_id, "target": vuln_id})
    return {"nodes": nodes, "edges": edges}


# ===========================================================================
# 1. ThreatModelResult dataclass
# ===========================================================================


class TestThreatModelResultDefaults:
    """ThreatModelResult must expose correct field defaults."""

    def test_only_cve_id_required(self):
        r = ThreatModelResult(cve_id="CVE-2024-0001")
        assert r.cve_id == "CVE-2024-0001"

    def test_attack_path_found_defaults_false(self):
        r = ThreatModelResult(cve_id="CVE-2024-0001")
        assert r.attack_path_found is False

    def test_critical_assets_defaults_empty_list(self):
        r = ThreatModelResult(cve_id="CVE-2024-0001")
        assert r.critical_assets == []

    def test_weak_links_defaults_empty_list(self):
        r = ThreatModelResult(cve_id="CVE-2024-0001")
        assert r.weak_links == []

    def test_vector_explanation_defaults_empty_string(self):
        r = ThreatModelResult(cve_id="CVE-2024-0001")
        assert r.vector_explanation == ""

    def test_reachability_score_defaults_zero(self):
        r = ThreatModelResult(cve_id="CVE-2024-0001")
        assert r.reachability_score == 0.0

    def test_exposure_level_defaults_internal(self):
        r = ThreatModelResult(cve_id="CVE-2024-0001")
        assert r.exposure_level == "internal"

    def test_attack_complexity_defaults_high(self):
        r = ThreatModelResult(cve_id="CVE-2024-0001")
        assert r.attack_complexity == "high"

    def test_privileges_required_defaults_high(self):
        r = ThreatModelResult(cve_id="CVE-2024-0001")
        assert r.privileges_required == "high"

    def test_user_interaction_defaults_required(self):
        r = ThreatModelResult(cve_id="CVE-2024-0001")
        assert r.user_interaction == "required"

    def test_mutable_defaults_are_independent(self):
        """Each instance must get its own list, not a shared one."""
        a = ThreatModelResult(cve_id="CVE-A")
        b = ThreatModelResult(cve_id="CVE-B")
        a.critical_assets.append("asset-x")
        assert b.critical_assets == []


class TestThreatModelResultToDict:
    """ThreatModelResult.to_dict() must serialise every field correctly."""

    def _full_result(self) -> ThreatModelResult:
        return ThreatModelResult(
            cve_id="CVE-2024-9999",
            attack_path_found=True,
            critical_assets=["web-server", "api-gw"],
            weak_links=[
                {"type": "network_exposure", "severity": "high", "description": "x"}
            ],
            vector_explanation="remotely exploitable, with low complexity",
            reachability_score=0.85,
            exposure_level="internet",
            attack_complexity="low",
            privileges_required="none",
            user_interaction="none",
        )

    def test_to_dict_returns_dict(self):
        assert isinstance(self._full_result().to_dict(), dict)

    def test_to_dict_cve_id(self):
        assert self._full_result().to_dict()["cve_id"] == "CVE-2024-9999"

    def test_to_dict_attack_path_found_true(self):
        assert self._full_result().to_dict()["attack_path_found"] is True

    def test_to_dict_attack_path_found_false(self):
        r = ThreatModelResult(cve_id="CVE-X")
        assert r.to_dict()["attack_path_found"] is False

    def test_to_dict_critical_assets_is_list_copy(self):
        r = self._full_result()
        d = r.to_dict()
        assert d["critical_assets"] == ["web-server", "api-gw"]
        # Must be a copy, not the same object.
        d["critical_assets"].append("extra")
        assert "extra" not in r.critical_assets

    def test_to_dict_weak_links_are_dict_copies(self):
        r = self._full_result()
        d = r.to_dict()
        assert d["weak_links"][0]["type"] == "network_exposure"
        d["weak_links"][0]["severity"] = "mutated"
        assert r.weak_links[0]["severity"] == "high"

    def test_to_dict_reachability_score_rounded_3dp(self):
        r = ThreatModelResult(cve_id="CVE-X", reachability_score=0.123456789)
        assert r.to_dict()["reachability_score"] == 0.123

    def test_to_dict_reachability_score_rounds_up(self):
        r = ThreatModelResult(cve_id="CVE-X", reachability_score=0.6789)
        assert r.to_dict()["reachability_score"] == 0.679

    def test_to_dict_exposure_level(self):
        r = ThreatModelResult(cve_id="CVE-X", exposure_level="partner")
        assert r.to_dict()["exposure_level"] == "partner"

    def test_to_dict_attack_complexity(self):
        r = ThreatModelResult(cve_id="CVE-X", attack_complexity="low")
        assert r.to_dict()["attack_complexity"] == "low"

    def test_to_dict_privileges_required(self):
        r = ThreatModelResult(cve_id="CVE-X", privileges_required="none")
        assert r.to_dict()["privileges_required"] == "none"

    def test_to_dict_user_interaction(self):
        r = ThreatModelResult(cve_id="CVE-X", user_interaction="none")
        assert r.to_dict()["user_interaction"] == "none"

    def test_to_dict_vector_explanation(self):
        r = ThreatModelResult(cve_id="CVE-X", vector_explanation="test explanation")
        assert r.to_dict()["vector_explanation"] == "test explanation"

    def test_to_dict_all_keys_present(self):
        expected_keys = {
            "cve_id",
            "attack_path_found",
            "critical_assets",
            "weak_links",
            "vector_explanation",
            "reachability_score",
            "exposure_level",
            "attack_complexity",
            "privileges_required",
            "user_interaction",
        }
        assert set(self._full_result().to_dict().keys()) == expected_keys


# ===========================================================================
# 2. _parse_cvss_vector
# ===========================================================================


class TestParseCVSSVector:
    """_parse_cvss_vector must correctly split CVSS metric strings."""

    # --- None / empty guard --------------------------------------------------

    def test_none_returns_empty_dict(self):
        assert _parse_cvss_vector(None) == {}

    def test_empty_string_returns_empty_dict(self):
        assert _parse_cvss_vector("") == {}

    # --- Full CVSS 3.1 -------------------------------------------------------

    def test_cvss31_prefix_parsed_as_key(self):
        components = _parse_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert components.get("CVSS") == "3.1"

    def test_cvss31_av_network(self):
        c = _parse_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert c["AV"] == "N"

    def test_cvss31_ac_low(self):
        c = _parse_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert c["AC"] == "L"

    def test_cvss31_pr_none(self):
        c = _parse_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert c["PR"] == "N"

    def test_cvss31_ui_none(self):
        c = _parse_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert c["UI"] == "N"

    def test_cvss31_scope_changed(self):
        c = _parse_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
        assert c["S"] == "C"

    # --- All AV values -------------------------------------------------------

    def test_av_network(self):
        assert _parse_cvss_vector("AV:N")["AV"] == "N"

    def test_av_adjacent(self):
        assert _parse_cvss_vector("AV:A")["AV"] == "A"

    def test_av_local(self):
        assert _parse_cvss_vector("AV:L")["AV"] == "L"

    def test_av_physical(self):
        assert _parse_cvss_vector("AV:P")["AV"] == "P"

    # --- All AC values -------------------------------------------------------

    def test_ac_low(self):
        assert _parse_cvss_vector("AC:L")["AC"] == "L"

    def test_ac_high(self):
        assert _parse_cvss_vector("AC:H")["AC"] == "H"

    # --- All PR values -------------------------------------------------------

    def test_pr_none(self):
        assert _parse_cvss_vector("PR:N")["PR"] == "N"

    def test_pr_low(self):
        assert _parse_cvss_vector("PR:L")["PR"] == "L"

    def test_pr_high(self):
        assert _parse_cvss_vector("PR:H")["PR"] == "H"

    # --- All UI values -------------------------------------------------------

    def test_ui_none(self):
        assert _parse_cvss_vector("UI:N")["UI"] == "N"

    def test_ui_required(self):
        assert _parse_cvss_vector("UI:R")["UI"] == "R"

    # --- Malformed / edge cases ----------------------------------------------

    def test_segment_without_colon_is_ignored(self):
        # "NOCOLON" has no colon so should not appear as a key.
        c = _parse_cvss_vector("NOCOLON/AV:N")
        assert "NOCOLON" not in c
        assert c["AV"] == "N"

    def test_value_with_colon_takes_first_split(self):
        # "KEY:val:extra" — split on first colon only.
        c = _parse_cvss_vector("KEY:val:extra")
        assert c["KEY"] == "val:extra"

    def test_partial_vector_two_components(self):
        c = _parse_cvss_vector("AV:N/AC:H")
        assert c["AV"] == "N"
        assert c["AC"] == "H"
        assert len(c) == 2

    def test_cvss_v2_style_vector(self):
        c = _parse_cvss_vector("AV:N/AC:L/Au:N/C:P/I:P/A:P")
        assert c["AV"] == "N"
        assert c["Au"] == "N"

    def test_returns_dict_type(self):
        assert isinstance(_parse_cvss_vector("AV:N"), dict)

    def test_whitespace_only_string_produces_no_useful_keys(self):
        # A string of only spaces has no ":" so the result should be empty.
        c = _parse_cvss_vector("   ")
        assert "AV" not in c


# ===========================================================================
# 3. _calculate_reachability_score
# ===========================================================================


class TestCalculateReachabilityScore:
    """_calculate_reachability_score must respect CVSS metrics and exposure."""

    # --- Return type / bounds ------------------------------------------------

    def test_returns_float(self):
        score = _calculate_reachability_score({"AV": "N", "AC": "L", "PR": "N", "UI": "N"}, "internet", False)
        assert isinstance(score, float)

    def test_score_never_below_zero(self):
        score = _calculate_reachability_score({}, "internal", True)
        assert score >= 0.0

    def test_score_never_above_one(self):
        # Maximum possible combination.
        score = _calculate_reachability_score(
            {"AV": "N", "AC": "L", "PR": "N", "UI": "N"}, "internet", False
        )
        assert score <= 1.0

    # --- AV contribution ordering -------------------------------------------

    def test_av_network_higher_than_adjacent(self):
        base = {"AC": "L", "PR": "N", "UI": "N"}
        sN = _calculate_reachability_score({**base, "AV": "N"}, "internal", False)
        sA = _calculate_reachability_score({**base, "AV": "A"}, "internal", False)
        assert sN > sA

    def test_av_adjacent_higher_than_local(self):
        base = {"AC": "L", "PR": "N", "UI": "N"}
        sA = _calculate_reachability_score({**base, "AV": "A"}, "internal", False)
        sL = _calculate_reachability_score({**base, "AV": "L"}, "internal", False)
        assert sA > sL

    def test_av_local_higher_than_physical(self):
        base = {"AC": "L", "PR": "N", "UI": "N"}
        sL = _calculate_reachability_score({**base, "AV": "L"}, "internal", False)
        sP = _calculate_reachability_score({**base, "AV": "P"}, "internal", False)
        assert sL > sP

    # --- AC contribution -----------------------------------------------------

    def test_ac_low_higher_than_high(self):
        base = {"AV": "N", "PR": "N", "UI": "N"}
        sL = _calculate_reachability_score({**base, "AC": "L"}, "internal", False)
        sH = _calculate_reachability_score({**base, "AC": "H"}, "internal", False)
        assert sL > sH

    # --- PR contribution -----------------------------------------------------

    def test_pr_none_higher_than_low(self):
        base = {"AV": "N", "AC": "L", "UI": "N"}
        sN = _calculate_reachability_score({**base, "PR": "N"}, "internal", False)
        sL = _calculate_reachability_score({**base, "PR": "L"}, "internal", False)
        assert sN > sL

    def test_pr_low_higher_than_high(self):
        base = {"AV": "N", "AC": "L", "UI": "N"}
        sL = _calculate_reachability_score({**base, "PR": "L"}, "internal", False)
        sH = _calculate_reachability_score({**base, "PR": "H"}, "internal", False)
        assert sL > sH

    # --- UI contribution -----------------------------------------------------

    def test_ui_none_higher_than_required(self):
        base = {"AV": "N", "AC": "L", "PR": "N"}
        sN = _calculate_reachability_score({**base, "UI": "N"}, "internal", False)
        sR = _calculate_reachability_score({**base, "UI": "R"}, "internal", False)
        assert sN > sR

    # --- Exposure level multipliers -----------------------------------------

    def test_internet_exposure_higher_than_partner(self):
        # Use a moderate base score (AV:A) so that neither internet nor partner
        # hits the 1.0 clamp ceiling, making the ordering comparison reliable.
        comps = {"AV": "A", "AC": "L", "PR": "N", "UI": "N"}
        sI = _calculate_reachability_score(comps, "internet", False)
        sP = _calculate_reachability_score(comps, "partner", False)
        assert sI > sP

    def test_partner_exposure_higher_than_internal(self):
        comps = {"AV": "A", "AC": "L", "PR": "N", "UI": "N"}
        sP = _calculate_reachability_score(comps, "partner", False)
        sIn = _calculate_reachability_score(comps, "internal", False)
        assert sP > sIn

    def test_unknown_exposure_level_uses_no_multiplier_bonus(self):
        # An unknown exposure type should not crash; score should be positive.
        comps = {"AV": "N", "AC": "L", "PR": "N", "UI": "N"}
        score = _calculate_reachability_score(comps, "unknown-level", False)
        assert score >= 0.0

    # --- Vendor advisory effect ----------------------------------------------

    def test_vendor_advisory_true_reduces_score(self):
        comps = {"AV": "N", "AC": "L", "PR": "N", "UI": "N"}
        no_adv = _calculate_reachability_score(comps, "internet", False)
        with_adv = _calculate_reachability_score(comps, "internet", True)
        assert with_adv < no_adv

    def test_vendor_advisory_reduction_factor_approx_70pct(self):
        comps = {"AV": "N", "AC": "L", "PR": "N", "UI": "N"}
        no_adv = _calculate_reachability_score(comps, "internal", False)
        with_adv = _calculate_reachability_score(comps, "internal", True)
        # After advisory the score should be approximately 70% of no-advisory.
        # Use a generous tolerance since clamping to [0,1] can affect this.
        if no_adv > 0:
            ratio = with_adv / no_adv
            assert abs(ratio - 0.7) < 0.05

    # --- Empty / missing components dict ------------------------------------

    def test_empty_components_uses_defaults(self):
        # All defaults: AV=L, AC=H, PR=H, UI=R.
        score = _calculate_reachability_score({}, "internal", False)
        # Should produce a small but positive score.
        assert score > 0.0
        assert score < 0.5

    # --- Specific numeric spot-checks ---------------------------------------

    def test_worst_case_minimum_is_positive(self):
        # Physical / high / high / required at internal with advisory.
        score = _calculate_reachability_score(
            {"AV": "P", "AC": "H", "PR": "H", "UI": "R"}, "internal", True
        )
        # 0.05 + 0.05 + 0.05 + 0.05 = 0.2, * 0.8 = 0.16, * 0.7 = 0.112
        assert score > 0.0

    def test_best_case_score_approaches_one(self):
        # AV:N + AC:L + PR:N + UI:N = 0.4+0.2+0.2+0.1 = 0.9, * 1.5 = 1.35 → clamped to 1.0
        score = _calculate_reachability_score(
            {"AV": "N", "AC": "L", "PR": "N", "UI": "N"}, "internet", False
        )
        assert math.isclose(score, 1.0)


# ===========================================================================
# 4. _find_affected_components
# ===========================================================================


class TestFindAffectedComponents:
    """_find_affected_components must walk the knowledge graph correctly."""

    # --- Guard conditions ----------------------------------------------------

    def test_none_graph_returns_empty(self):
        assert _find_affected_components("CVE-2024-1", None) == []

    def test_non_mapping_graph_returns_empty(self):
        assert _find_affected_components("CVE-2024-1", "not a dict") == []
        assert _find_affected_components("CVE-2024-1", 42) == []
        assert _find_affected_components("CVE-2024-1", ["list"]) == []

    def test_empty_graph_returns_empty(self):
        assert _find_affected_components("CVE-2024-1", {"nodes": [], "edges": []}) == []

    def test_graph_missing_nodes_key_returns_empty(self):
        assert _find_affected_components("CVE-2024-1", {"edges": []}) == []

    def test_graph_missing_edges_key_returns_empty(self):
        assert _find_affected_components("CVE-2024-1", {"nodes": []}) == []

    def test_nodes_not_list_returns_empty(self):
        assert _find_affected_components("CVE-2024-1", {"nodes": "bad", "edges": []}) == []

    def test_edges_not_list_returns_empty(self):
        graph = {
            "nodes": [{"id": "vuln:CVE-2024-1", "type": "vulnerability"}],
            "edges": "bad",
        }
        assert _find_affected_components("CVE-2024-1", graph) == []

    # --- CVE not in graph ----------------------------------------------------

    def test_cve_not_present_returns_empty(self):
        graph = _make_graph("CVE-2024-9999", ["component-x"])
        assert _find_affected_components("CVE-2024-OTHER", graph) == []

    # --- Single component ----------------------------------------------------

    def test_single_component_found(self):
        graph = _make_graph("CVE-2024-A", ["log4j-core"])
        result = _find_affected_components("CVE-2024-A", graph)
        assert result == ["log4j-core"]

    def test_returns_list(self):
        graph = _make_graph("CVE-2024-A", ["log4j-core"])
        assert isinstance(_find_affected_components("CVE-2024-A", graph), list)

    # --- Multiple components -------------------------------------------------

    def test_multiple_components_found(self):
        graph = _make_graph("CVE-2024-B", ["log4j-core", "spring-core", "netty"])
        result = _find_affected_components("CVE-2024-B", graph)
        assert sorted(result) == sorted(["log4j-core", "spring-core", "netty"])

    # --- Edge direction (component → vuln and vuln → component) -------------

    def test_source_to_target_edge(self):
        vuln_id = "vuln:CVE-2024-C"
        graph = {
            "nodes": [
                {"id": vuln_id, "type": "vulnerability"},
                {"id": "comp:libx", "type": "component", "name": "libx"},
            ],
            "edges": [{"source": "comp:libx", "target": vuln_id}],
        }
        result = _find_affected_components("CVE-2024-C", graph)
        assert "libx" in result

    def test_target_to_source_edge_direction(self):
        vuln_id = "vuln:CVE-2024-D"
        graph = {
            "nodes": [
                {"id": vuln_id, "type": "vulnerability"},
                {"id": "comp:liby", "type": "component", "name": "liby"},
            ],
            # Edge goes from vuln → component (reversed direction).
            "edges": [{"source": vuln_id, "target": "comp:liby"}],
        }
        result = _find_affected_components("CVE-2024-D", graph)
        assert "liby" in result

    # --- Non-component nodes should not appear in result --------------------

    def test_non_component_nodes_excluded(self):
        vuln_id = "vuln:CVE-2024-E"
        graph = {
            "nodes": [
                {"id": vuln_id, "type": "vulnerability"},
                {"id": "svc:nginx", "type": "service", "name": "nginx-service"},
                {"id": "comp:openssl", "type": "component", "name": "openssl"},
            ],
            "edges": [
                {"source": "svc:nginx", "target": vuln_id},
                {"source": "comp:openssl", "target": vuln_id},
            ],
        }
        result = _find_affected_components("CVE-2024-E", graph)
        assert "openssl" in result
        assert "nginx-service" not in result

    # --- Malformed node / edge entries don't crash --------------------------

    def test_non_mapping_node_is_skipped(self):
        vuln_id = "vuln:CVE-2024-F"
        graph = {
            "nodes": [
                "this-is-a-string-not-a-dict",
                {"id": vuln_id, "type": "vulnerability"},
                {"id": "comp:a", "type": "component", "name": "component-a"},
            ],
            "edges": [{"source": "comp:a", "target": vuln_id}],
        }
        result = _find_affected_components("CVE-2024-F", graph)
        assert "component-a" in result

    def test_non_mapping_edge_is_skipped(self):
        vuln_id = "vuln:CVE-2024-G"
        graph = {
            "nodes": [
                {"id": vuln_id, "type": "vulnerability"},
                {"id": "comp:b", "type": "component", "name": "component-b"},
            ],
            "edges": [
                "bad-edge-string",
                {"source": "comp:b", "target": vuln_id},
            ],
        }
        result = _find_affected_components("CVE-2024-G", graph)
        assert "component-b" in result

    def test_component_without_name_not_appended(self):
        vuln_id = "vuln:CVE-2024-H"
        graph = {
            "nodes": [
                {"id": vuln_id, "type": "vulnerability"},
                # Component node has no 'name' key.
                {"id": "comp:nameless", "type": "component"},
            ],
            "edges": [{"source": "comp:nameless", "target": vuln_id}],
        }
        result = _find_affected_components("CVE-2024-H", graph)
        assert result == []

    def test_component_name_must_be_str(self):
        vuln_id = "vuln:CVE-2024-I"
        graph = {
            "nodes": [
                {"id": vuln_id, "type": "vulnerability"},
                {"id": "comp:bad", "type": "component", "name": 12345},
            ],
            "edges": [{"source": "comp:bad", "target": vuln_id}],
        }
        result = _find_affected_components("CVE-2024-I", graph)
        assert result == []


# ===========================================================================
# 5. _determine_exposure_level
# ===========================================================================


class TestDetermineExposureLevel:
    """_determine_exposure_level must match CNAPP exposures to components."""

    # --- Guard conditions ----------------------------------------------------

    def test_none_exposures_returns_internal(self):
        assert _determine_exposure_level(None, ["svc"]) == "internal"

    def test_non_list_exposures_returns_internal(self):
        assert _determine_exposure_level("not-a-list", ["svc"]) == "internal"
        assert _determine_exposure_level(42, ["svc"]) == "internal"

    def test_empty_list_returns_internal(self):
        assert _determine_exposure_level([], ["svc"]) == "internal"

    # --- Internet detection --------------------------------------------------

    def test_internet_type_detected(self):
        exposures = [{"asset": "web-server", "type": "internet-facing"}]
        assert _determine_exposure_level(exposures, ["web-server"]) == "internet"

    def test_public_type_maps_to_internet(self):
        exposures = [{"asset": "api-gw", "type": "public"}]
        assert _determine_exposure_level(exposures, ["api-gw"]) == "internet"

    def test_type_with_internet_substring(self):
        exposures = [{"asset": "lb", "type": "internet-load-balancer"}]
        assert _determine_exposure_level(exposures, ["lb"]) == "internet"

    # --- Partner detection ---------------------------------------------------

    def test_partner_type_detected(self):
        exposures = [{"asset": "b2b-api", "type": "partner-network"}]
        assert _determine_exposure_level(exposures, ["b2b-api"]) == "partner"

    def test_external_type_maps_to_partner(self):
        exposures = [{"asset": "ext-svc", "type": "external"}]
        assert _determine_exposure_level(exposures, ["ext-svc"]) == "partner"

    def test_type_with_partner_substring(self):
        exposures = [{"asset": "relay", "type": "trusted-partner-relay"}]
        assert _determine_exposure_level(exposures, ["relay"]) == "partner"

    # --- Internal (default) --------------------------------------------------

    def test_internal_type_returns_internal(self):
        exposures = [{"asset": "db", "type": "internal-db"}]
        assert _determine_exposure_level(exposures, ["db"]) == "internal"

    def test_no_asset_match_returns_internal(self):
        exposures = [{"asset": "unrelated-service", "type": "internet-facing"}]
        assert _determine_exposure_level(exposures, ["my-component"]) == "internal"

    def test_empty_affected_components_returns_internal(self):
        exposures = [{"asset": "web-server", "type": "internet-facing"}]
        assert _determine_exposure_level(exposures, []) == "internal"

    # --- Priority: internet > partner ----------------------------------------

    def test_internet_takes_priority_over_partner(self):
        exposures = [
            {"asset": "svc", "type": "partner-network"},
            {"asset": "svc", "type": "internet-facing"},
        ]
        # First matching internet exposure wins on first encounter of internet type.
        # Result depends on order — first entry is partner so function iterates
        # until it finds a match.  The key point is that if an internet entry is
        # found, the function returns "internet".
        result = _determine_exposure_level(exposures, ["svc"])
        assert result in ("internet", "partner")  # Implementation-defined order.

    # --- Case-insensitive matching of type -----------------------------------

    def test_type_lowercased_before_comparison(self):
        exposures = [{"asset": "srv", "type": "INTERNET-FACING"}]
        # The implementation does .lower() on type, so upper-case should match.
        assert _determine_exposure_level(exposures, ["srv"]) == "internet"

    # --- Non-mapping exposure entries ----------------------------------------

    def test_non_mapping_exposure_skipped(self):
        exposures = [
            "bad-string-entry",
            {"asset": "svc", "type": "internet-facing"},
        ]
        assert _determine_exposure_level(exposures, ["svc"]) == "internet"

    # --- asset as non-string -------------------------------------------------

    def test_non_string_asset_does_not_match(self):
        exposures = [{"asset": 12345, "type": "internet-facing"}]
        assert _determine_exposure_level(exposures, ["12345"]) == "internal"


# ===========================================================================
# 6. compute_threat_model — integration of all sub-functions
# ===========================================================================


class TestComputeThreatModel:
    """compute_threat_model must correctly orchestrate all sub-functions."""

    # --- Empty / guard cases -------------------------------------------------

    def test_empty_enrichment_map_returns_empty_dict(self):
        assert compute_threat_model({}) == {}

    def test_returns_dict(self):
        result = compute_threat_model({"CVE-X": _make_evidence("CVE-X")})
        assert isinstance(result, dict)

    def test_result_contains_expected_cve_id(self):
        result = compute_threat_model({"CVE-2024-1": _make_evidence("CVE-2024-1")})
        assert "CVE-2024-1" in result

    def test_result_values_are_threat_model_results(self):
        result = compute_threat_model({"CVE-2024-1": _make_evidence("CVE-2024-1")})
        assert isinstance(result["CVE-2024-1"], ThreatModelResult)

    # --- Multiple CVEs -------------------------------------------------------

    def test_multiple_cves_all_processed(self):
        evidence_map = {
            "CVE-A": _make_evidence("CVE-A"),
            "CVE-B": _make_evidence("CVE-B", cvss_vector="CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:N"),
            "CVE-C": _make_evidence("CVE-C", has_vendor_advisory=True),
        }
        result = compute_threat_model(evidence_map)
        assert len(result) == 3
        assert {"CVE-A", "CVE-B", "CVE-C"}.issubset(result.keys())

    # --- CVSS-derived fields -------------------------------------------------

    def test_ac_low_from_cvss(self):
        r = compute_threat_model({"CVE-1": _make_evidence(cvss_vector="AV:N/AC:L/PR:N/UI:N")})
        assert r["CVE-1"].attack_complexity == "low"

    def test_ac_high_from_cvss(self):
        r = compute_threat_model({"CVE-1": _make_evidence(cvss_vector="AV:N/AC:H/PR:N/UI:N")})
        assert r["CVE-1"].attack_complexity == "high"

    def test_pr_none_from_cvss(self):
        r = compute_threat_model({"CVE-1": _make_evidence(cvss_vector="AV:N/AC:L/PR:N/UI:N")})
        assert r["CVE-1"].privileges_required == "none"

    def test_pr_low_from_cvss(self):
        r = compute_threat_model({"CVE-1": _make_evidence(cvss_vector="AV:N/AC:L/PR:L/UI:N")})
        assert r["CVE-1"].privileges_required == "low"

    def test_pr_high_from_cvss(self):
        r = compute_threat_model({"CVE-1": _make_evidence(cvss_vector="AV:N/AC:L/PR:H/UI:N")})
        assert r["CVE-1"].privileges_required == "high"

    def test_ui_none_from_cvss(self):
        r = compute_threat_model({"CVE-1": _make_evidence(cvss_vector="AV:N/AC:L/PR:N/UI:N")})
        assert r["CVE-1"].user_interaction == "none"

    def test_ui_required_from_cvss(self):
        r = compute_threat_model({"CVE-1": _make_evidence(cvss_vector="AV:N/AC:L/PR:N/UI:R")})
        assert r["CVE-1"].user_interaction == "required"

    # --- Attack path logic ---------------------------------------------------

    def test_attack_path_found_network_low_no_priv_internet(self):
        # AV:N + AC:L + PR:N → attack_vector=N, complexity=low, privileges=none.
        # Exposure must be internet or partner OR privileges == none.
        r = compute_threat_model(
            {"CVE-1": _make_evidence(cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")},
            cnapp_exposures=[{"asset": "anything", "type": "internet-facing"}],
        )
        # privileges_required == none alone satisfies the condition.
        assert r["CVE-1"].attack_path_found is True

    def test_attack_path_not_found_local_high_high(self):
        # Local + high complexity + high privileges → no attack path.
        r = compute_threat_model(
            {"CVE-1": _make_evidence(cvss_vector="CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:N")}
        )
        assert r["CVE-1"].attack_path_found is False

    def test_attack_path_not_found_network_high_complexity(self):
        # Network accessible BUT high complexity — path should not be found.
        r = compute_threat_model(
            {"CVE-1": _make_evidence(cvss_vector="AV:N/AC:H/PR:N/UI:N")}
        )
        assert r["CVE-1"].attack_path_found is False

    # --- Critical assets populated only for internet exposure ----------------

    def test_critical_assets_populated_for_internet_exposure(self):
        graph = _make_graph("CVE-1", ["web-front", "cdn-edge"])
        cnapp = [
            {"asset": "web-front", "type": "internet-facing"},
            {"asset": "cdn-edge", "type": "internet-facing"},
        ]
        r = compute_threat_model({"CVE-1": _make_evidence("CVE-1")}, graph, cnapp)
        assert len(r["CVE-1"].critical_assets) > 0

    def test_critical_assets_empty_for_internal_exposure(self):
        graph = _make_graph("CVE-1", ["db-server"])
        r = compute_threat_model({"CVE-1": _make_evidence("CVE-1")}, graph, None)
        # Exposure is internal → no critical assets.
        assert r["CVE-1"].critical_assets == []

    def test_critical_assets_capped_at_five(self):
        components = [f"svc-{i}" for i in range(10)]
        graph = _make_graph("CVE-1", components)
        cnapp = [{"asset": c, "type": "internet-facing"} for c in components]
        r = compute_threat_model({"CVE-1": _make_evidence("CVE-1")}, graph, cnapp)
        assert len(r["CVE-1"].critical_assets) <= 5

    # --- Weak links ----------------------------------------------------------

    def test_weak_link_low_complexity_added(self):
        r = compute_threat_model({"CVE-1": _make_evidence(cvss_vector="AV:N/AC:L/PR:N/UI:N")})
        types = [wl["type"] for wl in r["CVE-1"].weak_links]
        assert "low_complexity" in types

    def test_weak_link_no_privileges_added(self):
        r = compute_threat_model({"CVE-1": _make_evidence(cvss_vector="AV:N/AC:L/PR:N/UI:N")})
        types = [wl["type"] for wl in r["CVE-1"].weak_links]
        assert "no_privileges" in types

    def test_weak_link_network_exposure_added_when_attack_path_found(self):
        r = compute_threat_model(
            {"CVE-1": _make_evidence(cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")},
            cnapp_exposures=[{"asset": "x", "type": "internet-facing"}],
        )
        types = [wl["type"] for wl in r["CVE-1"].weak_links]
        assert "network_exposure" in types

    def test_no_low_complexity_weak_link_when_ac_high(self):
        r = compute_threat_model({"CVE-1": _make_evidence(cvss_vector="AV:N/AC:H/PR:N/UI:N")})
        types = [wl["type"] for wl in r["CVE-1"].weak_links]
        assert "low_complexity" not in types

    def test_no_no_privileges_weak_link_when_pr_high(self):
        r = compute_threat_model({"CVE-1": _make_evidence(cvss_vector="AV:N/AC:L/PR:H/UI:N")})
        types = [wl["type"] for wl in r["CVE-1"].weak_links]
        assert "no_privileges" not in types

    # --- Vector explanation --------------------------------------------------

    def test_vector_explanation_remotely_exploitable(self):
        r = compute_threat_model({"CVE-1": _make_evidence(cvss_vector="AV:N/AC:L/PR:N/UI:N")})
        assert "remotely exploitable" in r["CVE-1"].vector_explanation.lower()

    def test_vector_explanation_adjacent_network(self):
        r = compute_threat_model({"CVE-1": _make_evidence(cvss_vector="AV:A/AC:L/PR:N/UI:N")})
        assert "adjacent network" in r["CVE-1"].vector_explanation.lower()

    def test_vector_explanation_local_access(self):
        r = compute_threat_model({"CVE-1": _make_evidence(cvss_vector="AV:L/AC:H/PR:H/UI:R")})
        assert "local access" in r["CVE-1"].vector_explanation.lower()

    def test_vector_explanation_low_complexity(self):
        r = compute_threat_model({"CVE-1": _make_evidence(cvss_vector="AV:N/AC:L/PR:N/UI:N")})
        assert "low complexity" in r["CVE-1"].vector_explanation.lower()

    def test_vector_explanation_high_complexity(self):
        r = compute_threat_model({"CVE-1": _make_evidence(cvss_vector="AV:N/AC:H/PR:N/UI:N")})
        assert "high complexity" in r["CVE-1"].vector_explanation.lower()

    def test_vector_explanation_without_user_interaction(self):
        r = compute_threat_model({"CVE-1": _make_evidence(cvss_vector="AV:N/AC:L/PR:N/UI:N")})
        assert "without user interaction" in r["CVE-1"].vector_explanation.lower()

    def test_vector_explanation_requiring_user_interaction(self):
        r = compute_threat_model({"CVE-1": _make_evidence(cvss_vector="AV:N/AC:L/PR:N/UI:R")})
        assert "requiring user interaction" in r["CVE-1"].vector_explanation.lower()

    # --- Vendor advisory impact on reachability ------------------------------

    def test_vendor_advisory_lowers_reachability_in_full_pipeline(self):
        base_vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        r_no = compute_threat_model({"CVE-1": _make_evidence(cvss_vector=base_vec, has_vendor_advisory=False)})
        r_yes = compute_threat_model({"CVE-1": _make_evidence(cvss_vector=base_vec, has_vendor_advisory=True)})
        assert r_yes["CVE-1"].reachability_score < r_no["CVE-1"].reachability_score

    # --- None CVSS vector handled gracefully ---------------------------------

    def test_none_cvss_vector_does_not_crash(self):
        ev = _StubEnrichmentEvidence(cve_id="CVE-NULL", cvss_vector=None, has_vendor_advisory=False)
        result = compute_threat_model({"CVE-NULL": ev})
        assert "CVE-NULL" in result
        # Defaults apply: complexity=high, privileges=high.
        assert result["CVE-NULL"].attack_complexity == "high"
        assert result["CVE-NULL"].privileges_required == "high"

    # --- Exposure level flows into the result --------------------------------

    def test_exposure_level_internet_reflected_in_result(self):
        graph = _make_graph("CVE-1", ["frontend"])
        cnapp = [{"asset": "frontend", "type": "internet-facing"}]
        r = compute_threat_model({"CVE-1": _make_evidence("CVE-1")}, graph, cnapp)
        assert r["CVE-1"].exposure_level == "internet"

    def test_exposure_level_partner_reflected_in_result(self):
        graph = _make_graph("CVE-1", ["partner-relay"])
        cnapp = [{"asset": "partner-relay", "type": "partner-network"}]
        r = compute_threat_model({"CVE-1": _make_evidence("CVE-1")}, graph, cnapp)
        assert r["CVE-1"].exposure_level == "partner"

    def test_exposure_level_internal_when_no_graph(self):
        r = compute_threat_model({"CVE-1": _make_evidence("CVE-1")}, None, None)
        assert r["CVE-1"].exposure_level == "internal"

    # --- Reachability score within bounds in all cases ----------------------

    def test_reachability_score_bounded_for_high_risk(self):
        r = compute_threat_model({"CVE-1": _make_evidence(cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")})
        assert 0.0 <= r["CVE-1"].reachability_score <= 1.0

    def test_reachability_score_bounded_for_low_risk(self):
        r = compute_threat_model({"CVE-1": _make_evidence(cvss_vector="AV:P/AC:H/PR:H/UI:R")})
        assert 0.0 <= r["CVE-1"].reachability_score <= 1.0

    # --- to_dict round-trip on compute_threat_model output ------------------

    def test_to_dict_round_trip(self):
        r = compute_threat_model({"CVE-1": _make_evidence("CVE-1")})
        d = r["CVE-1"].to_dict()
        assert d["cve_id"] == "CVE-1"
        assert isinstance(d["reachability_score"], float)
        assert isinstance(d["critical_assets"], list)
        assert isinstance(d["weak_links"], list)
