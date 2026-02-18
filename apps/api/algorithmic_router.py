"""ALdeci Algorithmic Engines API Router.

Exposes advanced algorithmic capabilities:
- Monte Carlo Risk Quantification (FAIR-based)
- Causal Inference for Root Cause Analysis
- GNN Attack Path Prediction
"""

from __future__ import annotations

from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from core.attack_graph_gnn import (
    EdgeType,
    GraphNeuralPredictor,
    NodeType,
    SecurityGraph,
    analyze_attack_surface,
)
from core.causal_inference import CausalInferenceEngine, analyze_vulnerability_causes

# Import algorithmic engines
from core.monte_carlo import FAIRInputs, MonteCarloRiskEngine, quantify_cve_risk

router = APIRouter(prefix="/api/v1/algorithms", tags=["ALdeci Algorithms"])


# ============================================================================
# MONTE CARLO RISK QUANTIFICATION
# ============================================================================


class MonteCarloRequest(BaseModel):
    """Request for Monte Carlo risk quantification."""

    # Threat parameters
    threat_event_frequency_min: float = Field(
        0.1, description="Min annual threat events"
    )
    threat_event_frequency_mode: float = Field(
        1.0, description="Most likely annual threat events"
    )
    threat_event_frequency_max: float = Field(
        5.0, description="Max annual threat events"
    )

    # Vulnerability parameters
    vulnerability_probability_min: float = Field(
        0.1, description="Min probability of successful exploit"
    )
    vulnerability_probability_mode: float = Field(
        0.5, description="Most likely probability"
    )
    vulnerability_probability_max: float = Field(0.9, description="Max probability")

    # Loss parameters
    loss_magnitude_min: float = Field(10000, description="Minimum loss in dollars")
    loss_magnitude_mode: float = Field(100000, description="Most likely loss")
    loss_magnitude_max: float = Field(1000000, description="Maximum loss")

    # Simulation settings
    iterations: int = Field(
        10000, ge=1000, le=100000, description="Number of simulations"
    )
    confidence_level: float = Field(
        0.95, ge=0.80, le=0.99, description="Confidence level for intervals"
    )


class CVERiskRequest(BaseModel):
    """Request for CVE-based risk quantification."""

    cve_id: str = Field(..., description="CVE identifier")
    cvss_score: float = Field(..., ge=0.0, le=10.0, description="CVSS score")
    epss_score: float = Field(0.0, ge=0.0, le=1.0, description="EPSS score (0-1)")
    kev_listed: bool = Field(False, description="Whether in CISA KEV catalog")
    asset_value: float = Field(100000, ge=0, description="Asset value in dollars")
    is_reachable: bool = Field(True, description="Whether vulnerable code is reachable")


class PortfolioRiskRequest(BaseModel):
    """Request for portfolio-level risk quantification."""

    vulnerabilities: List[CVERiskRequest] = Field(
        ..., description="List of vulnerabilities"
    )
    correlation: float = Field(
        0.3, ge=0.0, le=1.0, description="Cross-vulnerability correlation"
    )


@router.post("/monte-carlo/quantify")
async def quantify_risk_monte_carlo(request: MonteCarloRequest) -> Dict[str, Any]:
    """Quantify risk using FAIR-based Monte Carlo simulation.

    Returns Value-at-Risk (VaR), Expected Annual Loss (ALE),
    loss exceedance probabilities, and confidence intervals.
    """
    try:
        inputs = FAIRInputs(
            threat_event_frequency=(
                request.threat_event_frequency_min,
                request.threat_event_frequency_mode,
                request.threat_event_frequency_max,
            ),
            vulnerability=(
                request.vulnerability_probability_min,
                request.vulnerability_probability_mode,
                request.vulnerability_probability_max,
            ),
            loss_magnitude=(
                request.loss_magnitude_min,
                request.loss_magnitude_mode,
                request.loss_magnitude_max,
            ),
        )

        engine = MonteCarloRiskEngine(iterations=request.iterations)
        result = engine.simulate(inputs)

        return {
            "status": "success",
            "algorithm": "FAIR Monte Carlo",
            "iterations": request.iterations,
            "result": result.to_dict(),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/monte-carlo/cve")
async def quantify_cve_risk_endpoint(request: CVERiskRequest) -> Dict[str, Any]:
    """Quantify risk for a specific CVE using Monte Carlo simulation."""
    try:
        result = quantify_cve_risk(
            cve_id=request.cve_id,
            cvss_score=request.cvss_score,
            epss_score=request.epss_score,
            kev_listed=request.kev_listed,
            asset_value=request.asset_value,
            is_reachable=request.is_reachable,
        )
        return {
            "status": "success",
            "algorithm": "CVE Monte Carlo",
            "cve_id": request.cve_id,
            "result": result,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/monte-carlo/portfolio")
async def quantify_portfolio_risk(request: PortfolioRiskRequest) -> Dict[str, Any]:
    """Quantify aggregated portfolio risk across multiple vulnerabilities."""
    try:
        individual_results = []
        total_expected_loss = 0.0
        total_var_95 = 0.0

        for vuln in request.vulnerabilities:
            result = quantify_cve_risk(
                cve_id=vuln.cve_id,
                cvss_score=vuln.cvss_score,
                epss_score=vuln.epss_score,
                kev_listed=vuln.kev_listed,
                asset_value=vuln.asset_value,
                is_reachable=vuln.is_reachable,
            )
            individual_results.append(result)
            total_expected_loss += result["expected_annual_loss"]
            total_var_95 += result["value_at_risk"]["var_95"]

        # Apply correlation adjustment
        correlated_var = total_var_95 * (
            1 + request.correlation * (len(request.vulnerabilities) - 1)
        )

        return {
            "status": "success",
            "algorithm": "Portfolio Monte Carlo",
            "vulnerability_count": len(request.vulnerabilities),
            "portfolio_summary": {
                "total_expected_annual_loss": round(total_expected_loss, 2),
                "uncorrelated_var_95": round(total_var_95, 2),
                "correlated_var_95": round(correlated_var, 2),
                "correlation_factor": request.correlation,
            },
            "individual_results": individual_results,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# CAUSAL INFERENCE FOR ROOT CAUSE ANALYSIS
# ============================================================================


class CausalAnalysisRequest(BaseModel):
    """Request for causal analysis of a vulnerability."""

    has_exploit: bool = Field(False, description="Whether an exploit is available")
    is_reachable: bool = Field(True, description="Whether vulnerable code is reachable")
    is_internet_facing: bool = Field(False, description="Whether exposed to internet")
    has_waf: bool = Field(False, description="Whether WAF is enabled")
    is_patched: bool = Field(False, description="Whether vulnerability is patched")
    has_auth: bool = Field(True, description="Whether authentication is required")


class CounterfactualRequest(BaseModel):
    """Request for counterfactual analysis."""

    has_exploit: bool = Field(False, description="Whether an exploit is available")
    is_reachable: bool = Field(True, description="Whether vulnerable code is reachable")
    is_internet_facing: bool = Field(False, description="Whether exposed to internet")
    has_waf: bool = Field(False, description="Whether WAF is enabled")
    is_patched: bool = Field(False, description="Whether vulnerability is patched")
    has_auth: bool = Field(True, description="Whether authentication is required")
    intervention: str = Field(
        ..., description="Proposed intervention: patch, enable_waf, add_auth, etc."
    )


@router.post("/causal/analyze")
async def analyze_vulnerability_root_cause(
    request: CausalAnalysisRequest,
) -> Dict[str, Any]:
    """Perform causal inference analysis on a vulnerability.

    Identifies root causes, contributing factors, and provides
    SHAP-like explanations for risk factors.
    """
    try:
        result = analyze_vulnerability_causes(
            has_exploit=request.has_exploit,
            is_reachable=request.is_reachable,
            is_internet_facing=request.is_internet_facing,
            has_waf=request.has_waf,
            is_patched=request.is_patched,
            has_auth=request.has_auth,
        )
        return {
            "status": "success",
            "algorithm": "Causal Inference (DAG-based)",
            "result": result,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/causal/counterfactual")
async def analyze_counterfactual(request: CounterfactualRequest) -> Dict[str, Any]:
    """Perform counterfactual analysis: 'What if we applied this intervention?'"""
    try:
        from core.causal_inference import SecurityFactor

        engine = CausalInferenceEngine()

        # Build current evidence
        evidence = {
            SecurityFactor.EXPLOIT_AVAILABLE: request.has_exploit,
            SecurityFactor.CODE_REACHABLE: request.is_reachable,
            SecurityFactor.INTERNET_EXPOSED: request.is_internet_facing,
            SecurityFactor.WAF_ENABLED: request.has_waf,
            SecurityFactor.PATCHED: request.is_patched,
            SecurityFactor.AUTH_REQUIRED: request.has_auth,
            SecurityFactor.VULNERABILITY_EXISTS: not request.is_patched,
        }

        # Map intervention string to SecurityFactor and value
        intervention_map = {
            "patch": (SecurityFactor.PATCHED, True),
            "enable_waf": (SecurityFactor.WAF_ENABLED, True),
            "add_auth": (SecurityFactor.AUTH_REQUIRED, True),
            "remove_internet_exposure": (SecurityFactor.INTERNET_EXPOSED, False),
            "block_reachability": (SecurityFactor.CODE_REACHABLE, False),
        }

        intervention_key = (
            request.intervention.lower().replace(" ", "_").replace("-", "_")
        )
        if intervention_key not in intervention_map:
            return {
                "status": "error",
                "message": f"Unknown intervention: {request.intervention}",
                "valid_interventions": list(intervention_map.keys()),
            }

        intervention_factor, intervention_value = intervention_map[intervention_key]

        # Perform counterfactual analysis
        result = engine.counterfactual_analysis(
            outcome=SecurityFactor.ATTACK_SUCCESSFUL,
            current_evidence=evidence,
            intervention=intervention_factor,
            intervention_value=intervention_value,
        )

        return {
            "status": "success",
            "algorithm": "Counterfactual Analysis",
            "intervention": request.intervention,
            "result": result.to_dict(),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/causal/treatment-effect")
async def estimate_treatment_effect(request: CounterfactualRequest) -> Dict[str, Any]:
    """Estimate the causal effect of an intervention (treatment)."""
    try:
        engine = CausalInferenceEngine()

        result = engine.estimate_treatment_effect(
            treatment="patch_vulnerability",
            outcome="breach_occurred",
        )

        return {
            "status": "success",
            "algorithm": "Causal Treatment Effect Estimation",
            "treatment": request.intervention,
            "result": result,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# GNN ATTACK PATH PREDICTION
# ============================================================================


class InfrastructureNode(BaseModel):
    """Infrastructure node for attack graph."""

    id: str
    type: str = Field(
        "compute",
        description="Node type: compute, storage, network, identity, service, etc.",
    )
    properties: Dict[str, Any] = Field(default_factory=dict)
    risk_score: float = Field(0.0, ge=0.0, le=1.0)


class Connection(BaseModel):
    """Connection between nodes."""

    source: str
    target: str
    type: str = Field("connects_to", description="Edge type")
    weight: float = Field(1.0, ge=0.0, le=1.0)


class VulnerabilityNode(BaseModel):
    """Vulnerability affecting infrastructure."""

    cve_id: str
    cvss_score: float = Field(5.0, ge=0.0, le=10.0)
    affects: List[str] = Field(
        default_factory=list, description="IDs of affected nodes"
    )


class AttackSurfaceRequest(BaseModel):
    """Request for attack surface analysis."""

    infrastructure: List[InfrastructureNode] = Field(
        ..., description="Infrastructure nodes"
    )
    connections: List[Connection] = Field(
        default_factory=list, description="Connections"
    )
    vulnerabilities: List[VulnerabilityNode] = Field(
        default_factory=list, description="Vulnerabilities"
    )
    max_paths: int = Field(
        10, ge=1, le=50, description="Maximum attack paths to return"
    )


class CriticalNodeRequest(BaseModel):
    """Request for critical node identification."""

    infrastructure: List[InfrastructureNode]
    connections: List[Connection]
    top_k: int = Field(10, ge=1, le=50)


@router.post("/gnn/attack-surface")
async def analyze_attack_surface_gnn(request: AttackSurfaceRequest) -> Dict[str, Any]:
    """Analyze attack surface using GNN-based path prediction.

    Returns:
    - Predicted attack paths with probabilities
    - Critical nodes in the infrastructure
    - Blast radius estimates
    - MITRE ATT&CK technique mappings
    """
    try:
        result = analyze_attack_surface(
            infrastructure=[n.dict() for n in request.infrastructure],
            connections=[c.dict() for c in request.connections],
            vulnerabilities=[v.dict() for v in request.vulnerabilities],
        )

        return {
            "status": "success",
            "algorithm": "Graph Neural Network Attack Path Prediction",
            "result": result,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/gnn/critical-nodes")
async def identify_critical_nodes(request: CriticalNodeRequest) -> Dict[str, Any]:
    """Identify critical infrastructure nodes using graph centrality and risk propagation."""
    try:
        # Build graph
        graph = SecurityGraph()

        for node in request.infrastructure:
            node_type = NodeType(node.type)
            graph.add_node(
                node.id,
                node_type,
                properties=node.properties,
                risk_score=node.risk_score,
            )

        for conn in request.connections:
            edge_type = EdgeType(conn.type)
            graph.add_edge(conn.source, conn.target, edge_type, weight=conn.weight)

        predictor = GraphNeuralPredictor()
        critical_nodes = predictor.identify_critical_nodes(graph, top_k=request.top_k)

        return {
            "status": "success",
            "algorithm": "GNN Critical Node Identification",
            "total_nodes": len(graph.nodes),
            "total_edges": len(graph.edges),
            "critical_nodes": critical_nodes,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/gnn/risk-propagation")
async def propagate_risk_through_graph(request: AttackSurfaceRequest) -> Dict[str, Any]:
    """Propagate risk from vulnerabilities through the infrastructure graph."""
    try:
        # Build graph
        graph = SecurityGraph()

        for node in request.infrastructure:
            node_type = NodeType(node.type)
            graph.add_node(
                node.id,
                node_type,
                properties=node.properties,
                risk_score=node.risk_score,
            )

        vuln_ids = []
        for vuln in request.vulnerabilities:
            vuln_id = f"vuln_{vuln.cve_id}"
            graph.add_node(
                vuln_id,
                NodeType.VULNERABILITY,
                properties={"cve_id": vuln.cve_id, "cvss_score": vuln.cvss_score},
                risk_score=vuln.cvss_score / 10.0,
            )
            vuln_ids.append(vuln_id)

            for affected in vuln.affects:
                if affected in graph.nodes:
                    graph.add_edge(
                        vuln_id,
                        affected,
                        EdgeType.AFFECTS,
                        weight=vuln.cvss_score / 10.0,
                    )

        for conn in request.connections:
            edge_type = EdgeType(conn.type)
            graph.add_edge(conn.source, conn.target, edge_type, weight=conn.weight)

        predictor = GraphNeuralPredictor()
        risk_scores = predictor.propagate_risk(graph, vuln_ids)

        # Sort by risk
        sorted_risks = sorted(
            [(node_id, score) for node_id, score in risk_scores.items()],
            key=lambda x: x[1],
            reverse=True,
        )

        return {
            "status": "success",
            "algorithm": "PageRank-style Risk Propagation",
            "vulnerability_sources": len(vuln_ids),
            "risk_scores": [
                {"node_id": node_id, "propagated_risk": round(score, 4)}
                for node_id, score in sorted_risks[:50]
            ],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# ALGORITHM STATUS & HEALTH
# ============================================================================


@router.get("/status")
async def get_algorithm_status() -> Dict[str, Any]:
    """Get status of all algorithmic engines."""
    return {
        "status": "healthy",
        "engines": {
            "monte_carlo": {
                "status": "available",
                "description": "FAIR-based Monte Carlo risk quantification",
                "capabilities": [
                    "Value-at-Risk (VaR) calculation",
                    "Expected Annual Loss (ALE)",
                    "Loss exceedance curves",
                    "Portfolio aggregation",
                    "PERT distribution sampling",
                ],
            },
            "causal_inference": {
                "status": "available",
                "description": "DAG-based causal analysis for root cause identification",
                "capabilities": [
                    "Root cause chain identification",
                    "Counterfactual analysis",
                    "Treatment effect estimation",
                    "SHAP-like risk factor explanations",
                ],
            },
            "gnn_attack_path": {
                "status": "available",
                "description": "Graph Neural Network attack path prediction",
                "capabilities": [
                    "Attack path prediction",
                    "Blast radius estimation",
                    "Critical node identification",
                    "Risk propagation through infrastructure",
                    "MITRE ATT&CK technique mapping",
                ],
            },
        },
        "version": "1.0.0",
        "framework": "ALdeci - Algorithmic Vulnerability Management",
    }


@router.get("/capabilities")
async def list_capabilities() -> Dict[str, Any]:
    """List all algorithmic capabilities with examples."""
    return {
        "algorithms": [
            {
                "name": "Monte Carlo Risk Quantification",
                "endpoint": "/api/v1/algorithms/monte-carlo/quantify",
                "method": "POST",
                "description": "FAIR-compliant financial risk quantification using 10K+ simulations",
                "use_cases": [
                    "Calculate breach probability with confidence intervals",
                    "Estimate Value-at-Risk for vulnerability portfolios",
                    "Compare remediation costs vs potential losses",
                ],
            },
            {
                "name": "Causal Root Cause Analysis",
                "endpoint": "/api/v1/algorithms/causal/analyze",
                "method": "POST",
                "description": "DAG-based causal inference to identify why vulnerabilities exist",
                "use_cases": [
                    "Identify systemic causes of recurring vulnerabilities",
                    "Estimate 'what if we patched?' scenarios",
                    "Prioritize interventions by causal impact",
                ],
            },
            {
                "name": "GNN Attack Path Prediction",
                "endpoint": "/api/v1/algorithms/gnn/attack-surface",
                "method": "POST",
                "description": "Graph neural network analysis of infrastructure attack surfaces",
                "use_cases": [
                    "Predict most likely attack paths from entry to target",
                    "Identify critical nodes to protect",
                    "Estimate blast radius of potential breaches",
                ],
            },
        ],
        "differentiators": [
            "Explainable AI: Every prediction includes justification",
            "Financial Quantification: All risks expressed in dollar terms",
            "Causal Reasoning: Moves beyond correlation to causation",
            "Graph-Aware: Understands infrastructure topology and dependencies",
        ],
    }
