"""Threat modeling and attack path analysis for CVE exploitation."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional

from risk.enrichment import EnrichmentEvidence

logger = logging.getLogger(__name__)


@dataclass
class ThreatModelResult:
    """Threat model result for CVE exploitation."""

    cve_id: str
    attack_path_found: bool = False
    critical_assets: List[str] = field(default_factory=list)
    weak_links: List[Dict[str, Any]] = field(default_factory=list)
    vector_explanation: str = ""
    reachability_score: float = 0.0
    exposure_level: str = "internal"
    attack_complexity: str = "high"
    privileges_required: str = "high"
    user_interaction: str = "required"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "cve_id": self.cve_id,
            "attack_path_found": self.attack_path_found,
            "critical_assets": list(self.critical_assets),
            "weak_links": [dict(link) for link in self.weak_links],
            "vector_explanation": self.vector_explanation,
            "reachability_score": round(self.reachability_score, 3),
            "exposure_level": self.exposure_level,
            "attack_complexity": self.attack_complexity,
            "privileges_required": self.privileges_required,
            "user_interaction": self.user_interaction,
        }


def _parse_cvss_vector(cvss_vector: Optional[str]) -> Dict[str, str]:
    """Parse CVSS vector string into components.

    Parameters
    ----------
    cvss_vector:
        CVSS vector string (e.g., "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").

    Returns
    -------
    Dict[str, str]
        Mapping of CVSS metric codes to values.
    """
    if not cvss_vector:
        return {}

    components: Dict[str, str] = {}
    parts = cvss_vector.split("/")

    for part in parts:
        if ":" in part:
            key, value = part.split(":", 1)
            components[key] = value

    return components


def _calculate_reachability_score(
    cvss_components: Dict[str, str],
    exposure_level: str,
    has_vendor_advisory: bool,
) -> float:
    """Calculate reachability score based on CVSS and exposure.

    Parameters
    ----------
    cvss_components:
        Parsed CVSS vector components.
    exposure_level:
        Exposure level (internet, partner, internal).
    has_vendor_advisory:
        Whether vendor advisory/patch is available.

    Returns
    -------
    float
        Reachability score (0.0 to 1.0).
    """
    score = 0.0

    av = cvss_components.get("AV", "L")
    if av == "N":  # Network
        score += 0.4
    elif av == "A":  # Adjacent
        score += 0.2
    elif av == "L":  # Local
        score += 0.1
    elif av == "P":  # Physical
        score += 0.05

    ac = cvss_components.get("AC", "H")
    if ac == "L":  # Low complexity
        score += 0.2
    elif ac == "H":  # High complexity
        score += 0.05

    pr = cvss_components.get("PR", "H")
    if pr == "N":  # None required
        score += 0.2
    elif pr == "L":  # Low privileges
        score += 0.1
    elif pr == "H":  # High privileges
        score += 0.05

    ui = cvss_components.get("UI", "R")
    if ui == "N":  # None required
        score += 0.1
    elif ui == "R":  # Required
        score += 0.05

    if exposure_level == "internet":
        score *= 1.5
    elif exposure_level == "partner":
        score *= 1.2
    elif exposure_level == "internal":
        score *= 0.8

    if has_vendor_advisory:
        score *= 0.7

    return max(0.0, min(1.0, score))


def _find_affected_components(
    cve_id: str,
    graph: Optional[Mapping[str, Any]],
) -> List[str]:
    """Find components affected by CVE using knowledge graph.

    Parameters
    ----------
    cve_id:
        CVE identifier.
    graph:
        Knowledge graph with nodes and edges.

    Returns
    -------
    List[str]
        List of affected component names.
    """
    if not isinstance(graph, Mapping):
        return []

    affected_components: List[str] = []
    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])

    if not isinstance(nodes, list) or not isinstance(edges, list):
        return []

    vuln_node_id = None
    for node in nodes:
        if not isinstance(node, Mapping):
            continue
        if node.get("type") == "vulnerability" and cve_id in str(node.get("id", "")):
            vuln_node_id = node.get("id")
            break

    if not vuln_node_id:
        return affected_components

    for edge in edges:
        if not isinstance(edge, Mapping):
            continue
        if edge.get("target") == vuln_node_id or edge.get("source") == vuln_node_id:
            component_id = (
                edge.get("source")
                if edge.get("target") == vuln_node_id
                else edge.get("target")
            )
            for node in nodes:
                if not isinstance(node, Mapping):
                    continue
                if node.get("id") == component_id and node.get("type") == "component":
                    name = node.get("name")
                    if isinstance(name, str):
                        affected_components.append(name)

    return affected_components


def _determine_exposure_level(
    cnapp_exposures: Optional[List[Mapping[str, Any]]],
    affected_components: List[str],
) -> str:
    """Determine exposure level based on CNAPP data.

    Parameters
    ----------
    cnapp_exposures:
        List of CNAPP exposure findings.
    affected_components:
        List of affected component names.

    Returns
    -------
    str
        Exposure level (internet, partner, internal).
    """
    if not isinstance(cnapp_exposures, list):
        return "internal"

    for exposure in cnapp_exposures:
        if not isinstance(exposure, Mapping):
            continue

        asset = exposure.get("asset")
        exposure_type = exposure.get("type", "").lower()

        if isinstance(asset, str) and any(
            comp in asset for comp in affected_components
        ):
            if "internet" in exposure_type or "public" in exposure_type:
                return "internet"
            elif "partner" in exposure_type or "external" in exposure_type:
                return "partner"

    return "internal"


def compute_threat_model(
    enrichment_map: Dict[str, EnrichmentEvidence],
    graph: Optional[Mapping[str, Any]] = None,
    cnapp_exposures: Optional[List[Mapping[str, Any]]] = None,
) -> Dict[str, ThreatModelResult]:
    """Compute threat models for all CVEs.

    Parameters
    ----------
    enrichment_map:
        Mapping of CVE ID to enrichment evidence.
    graph:
        Optional knowledge graph with components and vulnerabilities.
    cnapp_exposures:
        Optional CNAPP exposure findings.

    Returns
    -------
    Dict[str, ThreatModelResult]
        Mapping of CVE ID to threat model result.
    """
    threat_map: Dict[str, ThreatModelResult] = {}

    for cve_id, evidence in enrichment_map.items():
        cvss_components = _parse_cvss_vector(evidence.cvss_vector)

        attack_vector = cvss_components.get("AV", "L")
        attack_complexity = "low" if cvss_components.get("AC") == "L" else "high"
        privileges_required = (
            "none"
            if cvss_components.get("PR") == "N"
            else "low"
            if cvss_components.get("PR") == "L"
            else "high"
        )
        user_interaction = "none" if cvss_components.get("UI") == "N" else "required"

        affected_components = _find_affected_components(cve_id, graph)

        exposure_level = _determine_exposure_level(cnapp_exposures, affected_components)

        reachability_score = _calculate_reachability_score(
            cvss_components,
            exposure_level,
            evidence.has_vendor_advisory,
        )

        attack_path_found = (
            attack_vector == "N"  # Network accessible
            and attack_complexity == "low"
            and (
                exposure_level in ("internet", "partner")
                or privileges_required == "none"
            )
        )

        critical_assets: List[str] = []
        if affected_components:
            if exposure_level == "internet":
                critical_assets = affected_components[:5]  # Limit to top 5

        weak_links: List[Dict[str, Any]] = []
        if attack_path_found:
            weak_links.append(
                {
                    "type": "network_exposure",
                    "description": f"Component exposed at {exposure_level} level",
                    "severity": "high" if exposure_level == "internet" else "medium",
                }
            )
        if attack_complexity == "low":
            weak_links.append(
                {
                    "type": "low_complexity",
                    "description": "Attack requires low complexity to execute",
                    "severity": "medium",
                }
            )
        if privileges_required == "none":
            weak_links.append(
                {
                    "type": "no_privileges",
                    "description": "No privileges required for exploitation",
                    "severity": "high",
                }
            )

        vector_parts = []
        if attack_vector == "N":
            vector_parts.append("remotely exploitable")
        elif attack_vector == "A":
            vector_parts.append("exploitable from adjacent network")
        else:
            vector_parts.append("requires local access")

        if attack_complexity == "low":
            vector_parts.append("with low complexity")
        else:
            vector_parts.append("with high complexity")

        if privileges_required == "none":
            vector_parts.append("and no privileges required")
        elif privileges_required == "low":
            vector_parts.append("and low privileges required")
        else:
            vector_parts.append("and high privileges required")

        if user_interaction == "none":
            vector_parts.append("without user interaction")
        else:
            vector_parts.append("requiring user interaction")

        vector_explanation = f"Vulnerability is {', '.join(vector_parts)}."

        threat_model = ThreatModelResult(
            cve_id=cve_id,
            attack_path_found=attack_path_found,
            critical_assets=critical_assets,
            weak_links=weak_links,
            vector_explanation=vector_explanation,
            reachability_score=reachability_score,
            exposure_level=exposure_level,
            attack_complexity=attack_complexity,
            privileges_required=privileges_required,
            user_interaction=user_interaction,
        )

        threat_map[cve_id] = threat_model

    logger.info(
        "Computed threat models for %d CVEs: %d with attack paths, avg reachability=%.3f",
        len(threat_map),
        sum(1 for t in threat_map.values() if t.attack_path_found),
        sum(t.reachability_score for t in threat_map.values()) / len(threat_map)
        if threat_map
        else 0,
    )

    return threat_map


__all__ = ["ThreatModelResult", "compute_threat_model"]
