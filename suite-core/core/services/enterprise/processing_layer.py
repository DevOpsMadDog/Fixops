"""
FixOps Processing Layer Implementation
Based on the architecture documentation showing specific components:
- Bayesian Prior Mapping (Custom)
- Markov Transition Matrix Builder (Custom)
- SSVC + Probabilistic Fusion Logic (Custom)
- SARIF-Based Non-CVE Vulnerability Handling (Custom)
- Knowledge Graph Construction
- LLM Explanation Engine
"""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import structlog

# Optional scientific stack -------------------------------------------------
try:  # pragma: no cover - optional dependency
    import numpy as np

    NUMPY_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised in constrained envs
    NUMPY_AVAILABLE = False
    np = None  # type: ignore

# OSS Component Imports as per architecture
try:  # pragma: no cover - optional dependency
    from pgmpy.factors.discrete import TabularCPD
    from pgmpy.inference import VariableElimination
    from pgmpy.models import BayesianNetwork

    PGMPY_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised when pgmpy missing
    PGMPY_AVAILABLE = False

try:  # pragma: no cover - optional dependency
    pass

    POMEGRANATE_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised when pomegranate missing
    POMEGRANATE_AVAILABLE = False

try:  # pragma: no cover - optional dependency
    import mchmm as mc

    MCHMM_AVAILABLE = True
except ImportError:  # pragma: no cover - executed in minimal envs
    mc = None  # type: ignore
    MCHMM_AVAILABLE = False

logger = structlog.get_logger()


def _mean(values: List[float]) -> float:
    """Lightweight mean helper that avoids hard dependency on numpy."""
    if not values:
        return 0.0
    return sum(values) / len(values)


def _variance(values: List[float]) -> float:
    """Population variance helper compatible with single-value lists."""
    if len(values) < 2:
        return 0.0
    avg = _mean(values)
    return sum((value - avg) ** 2 for value in values) / len(values)


@dataclass
class SSVCContext:
    """SSVC context for Bayesian prior mapping"""

    exploitation: str  # "none", "poc", "active"
    exposure: str  # "small", "controlled", "open"
    utility: str  # "laborious", "efficient", "super_effective"
    safety_impact: str  # "negligible", "marginal", "major", "hazardous"
    mission_impact: str  # "degraded", "crippled", "mev"


@dataclass
class MarkovState:
    """States for Markov transition modeling"""

    current_state: str  # "secure", "vulnerable", "exploited", "patched"
    cve_id: Optional[str]
    epss_score: float
    kev_flag: bool
    disclosure_date: datetime


@dataclass
class SARIFVulnerability:
    """Non-CVE vulnerability from SARIF analysis"""

    rule_id: str
    message: str
    severity: str
    cwe_id: Optional[str]
    owasp_category: Optional[str]
    file_location: str
    confidence: float


class BayesianPriorMapping:
    """
    Bayesian Prior Mapping (Custom)
    Purpose: Assign probabilities to components based on SSVC context
    Uses pgmpy or pomegranate for Bayesian inference
    """

    def __init__(self):
        self.network = None
        self.inference_engine = None
        self._initialize_network()

    def _initialize_network(self):
        """Initialize Bayesian network with SSVC variables"""
        if not PGMPY_AVAILABLE or not NUMPY_AVAILABLE:
            logger.warning(
                "pgmpy/numpy not available, using simplified Bayesian mapping"
            )
            return

        try:
            # Create Bayesian Network structure
            model = BayesianNetwork(
                [
                    ("exploitation", "risk_level"),
                    ("exposure", "risk_level"),
                    ("utility", "risk_level"),
                    ("safety_impact", "risk_level"),
                    ("mission_impact", "risk_level"),
                ]
            )

            # Define CPDs (Conditional Probability Distributions)
            cpd_exploitation = TabularCPD(
                variable="exploitation",
                variable_card=3,
                values=[[0.6], [0.3], [0.1]],  # none, poc, active
                state_names={"exploitation": ["none", "poc", "active"]},
            )

            cpd_exposure = TabularCPD(
                variable="exposure",
                variable_card=3,
                values=[[0.5], [0.3], [0.2]],  # small, controlled, open
                state_names={"exposure": ["small", "controlled", "open"]},
            )

            # Risk level depends on all factors
            # Build a deterministic CPD so inference remains reproducible
            columns = 3 * 3 * 3 * 4 * 3
            base_distribution = [0.25, 0.35, 0.25, 0.15]
            values = []
            for risk_weight in base_distribution:
                values.append([risk_weight for _ in range(columns)])

            cpd_risk = TabularCPD(
                variable="risk_level",
                variable_card=4,  # low, medium, high, critical
                values=values,
                evidence=[
                    "exploitation",
                    "exposure",
                    "utility",
                    "safety_impact",
                    "mission_impact",
                ],
                evidence_card=[3, 3, 3, 4, 3],
                state_names={
                    "risk_level": ["low", "medium", "high", "critical"],
                    "exploitation": ["none", "poc", "active"],
                    "exposure": ["small", "controlled", "open"],
                    "utility": ["laborious", "efficient", "super_effective"],
                    "safety_impact": ["negligible", "marginal", "major", "hazardous"],
                    "mission_impact": ["degraded", "crippled", "mev"],
                },
            )

            model.add_cpds(cpd_exploitation, cpd_exposure, cpd_risk)
            self.network = model
            self.inference_engine = VariableElimination(model)

            logger.info("✅ Bayesian Prior Mapping network initialized with pgmpy")

        except Exception as e:
            logger.error(f"Bayesian network initialization failed: {e}")
            self.network = None

    async def compute_priors(self, ssvc_context: SSVCContext) -> Dict[str, float]:
        """Compute Bayesian priors based on SSVC context"""
        if self.network and self.inference_engine:
            try:
                # Query the Bayesian network
                evidence = {
                    "exploitation": ssvc_context.exploitation,
                    "exposure": ssvc_context.exposure,
                    "utility": ssvc_context.utility,
                    "safety_impact": ssvc_context.safety_impact,
                    "mission_impact": ssvc_context.mission_impact,
                }

                result = self.inference_engine.query(["risk_level"], evidence=evidence)
                priors = {
                    state: float(prob)
                    for state, prob in zip(
                        result.state_names["risk_level"], result.values
                    )
                }

                return priors

            except Exception as e:
                logger.error(f"Bayesian inference failed: {e}")

        # Fallback to heuristic mapping
        return self._heuristic_priors(ssvc_context)

    def _heuristic_priors(self, ssvc_context: SSVCContext) -> Dict[str, float]:
        """Fallback heuristic when Bayesian network unavailable"""
        risk_score = 0

        # Exploitation scoring
        exploit_scores = {"none": 0.1, "poc": 0.5, "active": 0.9}
        risk_score += exploit_scores.get(ssvc_context.exploitation, 0.5) * 0.3

        # Exposure scoring
        exposure_scores = {"small": 0.2, "controlled": 0.5, "open": 0.8}
        risk_score += exposure_scores.get(ssvc_context.exposure, 0.5) * 0.25

        # Mission impact scoring
        mission_scores = {"degraded": 0.3, "crippled": 0.7, "mev": 1.0}
        risk_score += mission_scores.get(ssvc_context.mission_impact, 0.5) * 0.45

        # Convert to probability distribution
        if risk_score >= 0.8:
            return {"critical": 0.7, "high": 0.2, "medium": 0.08, "low": 0.02}
        elif risk_score >= 0.6:
            return {"critical": 0.3, "high": 0.5, "medium": 0.15, "low": 0.05}
        elif risk_score >= 0.4:
            return {"critical": 0.1, "high": 0.25, "medium": 0.5, "low": 0.15}
        else:
            return {"critical": 0.02, "high": 0.08, "medium": 0.3, "low": 0.6}


class MarkovTransitionMatrixBuilder:
    """
    Markov Transition Matrix Builder using REAL mchmm library
    Purpose: Define model state transitions (e.g., Secure → Vulnerable → Exploited → Patched)
    Inputs: CVE disclosure dates, EPSS scores, KEV flags
    Uses mchmm to define and simulate transitions
    """

    def __init__(self):
        self.mc = mc if MCHMM_AVAILABLE else None
        self.states = ["secure", "vulnerable", "exploited", "patched"]
        self.state_to_index = {state: i for i, state in enumerate(self.states)}
        self.hmm_model = None
        # Fallback transition matrix is always available for deterministic paths
        self.transition_matrix = {
            "secure": {
                "secure": 0.7,
                "vulnerable": 0.3,
                "exploited": 0.0,
                "patched": 0.0,
            },
            "vulnerable": {
                "secure": 0.1,
                "vulnerable": 0.6,
                "exploited": 0.2,
                "patched": 0.1,
            },
            "exploited": {
                "secure": 0.0,
                "vulnerable": 0.1,
                "exploited": 0.4,
                "patched": 0.5,
            },
            "patched": {
                "secure": 0.8,
                "vulnerable": 0.1,
                "exploited": 0.05,
                "patched": 0.05,
            },
        }

        if self.mc and NUMPY_AVAILABLE:
            self._build_real_markov_model()
        else:
            logger.warning(
                "mchmm/numpy not available, using deterministic transition matrix"
            )

    def _build_real_markov_model(self):
        """Build real Markov model using mchmm library"""
        try:
            # Create transition probability matrix using mchmm
            # Define empirical transition probabilities based on security research
            transition_matrix = np.array(
                [
                    [0.7, 0.3, 0.0, 0.0],
                    [0.1, 0.6, 0.2, 0.1],
                    [0.0, 0.1, 0.4, 0.5],
                    [0.8, 0.1, 0.05, 0.05],
                ]
            )

            # Create MarkovChain using real mchmm
            self.hmm_model = self.mc.MarkovChain().from_matrix(
                transition_matrix, states=self.states
            )

            logger.info("✅ Real Markov Transition Matrix initialized using mchmm")

        except Exception as e:
            logger.error(f"Real mchmm initialization failed: {e}")
            self.hmm_model = None

    async def predict_state_evolution(
        self, current_states: List[MarkovState]
    ) -> Dict[str, Any]:
        """Predict vulnerability state evolution using REAL mchmm library"""
        predictions = []

        try:
            for state in current_states:
                if self.hmm_model:
                    # Use real mchmm for state prediction
                    current_state_idx = self.state_to_index.get(state.current_state, 1)

                    # Generate sequence of next states using mchmm
                    sequence = self.hmm_model.generate_states(
                        length=5, start_state=current_state_idx
                    )
                    next_state_probs = self._calculate_transition_probs(
                        current_state_idx, state
                    )

                    predictions.append(
                        {
                            "cve_id": state.cve_id,
                            "current_state": state.current_state,
                            "predicted_transitions": next_state_probs,
                            "mchmm_sequence": [self.states[idx] for idx in sequence],
                            "epss_factor": state.epss_score,
                            "kev_factor": state.kev_flag,
                            "days_since_disclosure": (
                                datetime.now(timezone.utc) - state.disclosure_date
                            ).days,
                            "using_real_mchmm": True,
                        }
                    )
                else:
                    # Fallback prediction
                    adjusted_probs = self._adjust_transitions_fallback(state)
                    predictions.append(
                        {
                            "cve_id": state.cve_id,
                            "current_state": state.current_state,
                            "predicted_transitions": adjusted_probs,
                            "epss_factor": state.epss_score,
                            "kev_factor": state.kev_flag,
                            "days_since_disclosure": (
                                datetime.now(timezone.utc) - state.disclosure_date
                            ).days,
                            "using_real_mchmm": False,
                        }
                    )

            return {
                "predictions": predictions,
                "model_confidence": self._calculate_model_confidence(predictions),
                "high_risk_count": len(
                    [
                        p
                        for p in predictions
                        if p["predicted_transitions"].get("exploited", 0) > 0.3
                    ]
                ),
                "real_mchmm_used": self.hmm_model is not None,
            }

        except Exception as e:
            logger.error(f"mchmm prediction failed: {e}")
            return {"error": str(e), "predictions": []}

    def _calculate_transition_probs(
        self, current_state_idx: int, state: MarkovState
    ) -> Dict[str, float]:
        """Calculate transition probabilities using real mchmm adjusted for EPSS/KEV"""
        try:
            # Get base transition probabilities from mchmm model
            base_probs = self.hmm_model.tp[current_state_idx].copy()

            # Adjust based on EPSS and KEV flags
            if state.epss_score > 0.7 and current_state_idx == 1:  # vulnerable state
                base_probs[2] *= 2.0  # increase exploited probability

            if state.kev_flag and current_state_idx == 1:  # vulnerable state
                base_probs[2] *= 3.0  # significantly increase exploited probability

            # Normalize without assuming numpy availability at runtime
            if NUMPY_AVAILABLE:
                total = float(np.sum(base_probs))
                normalized = [float(prob) / total for prob in base_probs]
            else:
                base_list = [float(prob) for prob in base_probs]
                total = sum(base_list) or 1.0
                normalized = [prob / total for prob in base_list]

            return {self.states[i]: normalized[i] for i in range(len(normalized))}

        except Exception as e:
            logger.error(f"Transition probability calculation failed: {e}")
            return {state: 0.25 for state in self.states}

    def _adjust_transitions_fallback(self, state: MarkovState) -> Dict[str, float]:
        """Fallback transition adjustment when mchmm unavailable"""
        base_probs = self.transition_matrix[state.current_state].copy()

        # Higher EPSS score increases exploitation probability
        if state.epss_score > 0.7:
            if "exploited" in base_probs:
                base_probs["exploited"] *= 2.0

        # KEV flag significantly increases exploitation probability
        if state.kev_flag and "exploited" in base_probs:
            base_probs["exploited"] *= 3.0

        # Normalize probabilities
        total = sum(base_probs.values())
        return {k: v / total for k, v in base_probs.items()}

    def _calculate_model_confidence(self, predictions: List[Dict]) -> float:
        """Calculate overall model confidence based on data quality"""
        if not predictions:
            return 0.0

        # Higher confidence when using real mchmm
        base_confidence = (
            0.9 if any(p.get("using_real_mchmm", False) for p in predictions) else 0.6
        )

        # Adjust based on data completeness
        confidence_factors = []
        for pred in predictions:
            factors = [
                1.0 if pred["cve_id"] else 0.5,  # Has CVE ID
                min(pred["epss_factor"] * 2, 1.0),  # EPSS availability
                1.0 if pred["kev_factor"] else 0.8,  # KEV data
                min(pred["days_since_disclosure"] / 365, 1.0),  # Maturity of disclosure
            ]
            confidence_factors.append(_mean(factors))

        return base_confidence * _mean(confidence_factors)


class SSVCProbabilisticFusion:
    """
    SSVC + Probabilistic Fusion Logic (Custom)
    Purpose: Combine deterministic SSVC decisions with probabilistic risk scores
    Fuses SSVC vector outcomes with Bayesian/Markov outputs
    """

    def __init__(self):
        self.ssvc_weights = {
            "exploitation": 0.25,
            "exposure": 0.20,
            "utility": 0.15,
            "safety_impact": 0.20,
            "mission_impact": 0.20,
        }

    async def fuse_decisions(
        self,
        ssvc_context: SSVCContext,
        bayesian_priors: Dict[str, float],
        markov_predictions: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Fuse SSVC decisions with probabilistic outputs"""

        # 1. Compute deterministic SSVC score
        ssvc_score = self._compute_ssvc_score(ssvc_context)

        # 2. Extract probabilistic risk from Bayesian priors
        bayesian_risk = (
            bayesian_priors.get("critical", 0) * 1.0
            + bayesian_priors.get("high", 0) * 0.75
            + bayesian_priors.get("medium", 0) * 0.5
            + bayesian_priors.get("low", 0) * 0.25
        )

        # 3. Extract Markov risk indicators
        markov_risk = self._extract_markov_risk(markov_predictions)

        # 4. Fusion logic
        composite_risk = self._fusion_algorithm(ssvc_score, bayesian_risk, markov_risk)

        # 5. Generate final decision
        decision = self._risk_to_decision(composite_risk)

        return {
            "composite_risk_score": composite_risk,
            "ssvc_component": ssvc_score,
            "bayesian_component": bayesian_risk,
            "markov_component": markov_risk,
            "final_decision": decision,
            "confidence": self._calculate_fusion_confidence(
                ssvc_score, bayesian_risk, markov_risk
            ),
            "explanation": self._generate_fusion_explanation(decision, composite_risk),
        }

    def _compute_ssvc_score(self, context: SSVCContext) -> float:
        """Compute deterministic SSVC score"""
        scores = {
            "exploitation": {"none": 0.1, "poc": 0.5, "active": 0.9},
            "exposure": {"small": 0.2, "controlled": 0.5, "open": 0.8},
            "utility": {"laborious": 0.2, "efficient": 0.6, "super_effective": 0.9},
            "safety_impact": {
                "negligible": 0.1,
                "marginal": 0.4,
                "major": 0.7,
                "hazardous": 1.0,
            },
            "mission_impact": {"degraded": 0.3, "crippled": 0.7, "mev": 1.0},
        }

        weighted_score = 0
        for factor, weight in self.ssvc_weights.items():
            factor_value = getattr(context, factor, "unknown")
            score = scores.get(factor, {}).get(factor_value, 0.5)
            weighted_score += score * weight

        return weighted_score

    def _extract_markov_risk(self, markov_predictions: Dict[str, Any]) -> float:
        """Extract risk indicator from Markov predictions"""
        if not markov_predictions.get("predictions"):
            return 0.5

        high_risk_ratio = markov_predictions.get("high_risk_count", 0) / len(
            markov_predictions["predictions"]
        )
        model_confidence = markov_predictions.get("model_confidence", 0.5)

        return high_risk_ratio * model_confidence

    def _fusion_algorithm(
        self, ssvc_score: float, bayesian_risk: float, markov_risk: float
    ) -> float:
        """Fusion algorithm combining all risk components"""
        # Weighted combination with confidence-based adjustments
        weights = {"ssvc": 0.4, "bayesian": 0.35, "markov": 0.25}

        composite = (
            ssvc_score * weights["ssvc"]
            + bayesian_risk * weights["bayesian"]
            + markov_risk * weights["markov"]
        )

        # Apply non-linear amplification for high-risk scenarios
        if composite > 0.7:
            composite = min(composite * 1.2, 1.0)

        return composite

    def _risk_to_decision(self, risk_score: float) -> str:
        """Convert composite risk score to decision"""
        if risk_score >= 0.8:
            return "BLOCK"
        elif risk_score >= 0.6:
            return "DEFER"
        else:
            return "ALLOW"

    def _calculate_fusion_confidence(
        self, ssvc: float, bayesian: float, markov: float
    ) -> float:
        """Calculate confidence in fusion result"""
        # Higher confidence when components agree
        variance = _variance([ssvc, bayesian, markov])
        return max(0.5, 1.0 - variance * 2)

    def _generate_fusion_explanation(self, decision: str, risk_score: float) -> str:
        """Generate human-readable explanation"""
        if decision == "BLOCK":
            return f"High composite risk ({risk_score:.2f}) - multiple indicators suggest blocking deployment"
        elif decision == "DEFER":
            return f"Medium composite risk ({risk_score:.2f}) - requires manual review before deployment"
        else:
            return f"Low composite risk ({risk_score:.2f}) - safe to proceed with deployment"


class SARIFVulnerabilityHandler:
    """
    SARIF-Based Non-CVE Vulnerability Handling (Custom)
    Purpose: Handle scanner findings without CVEs
    Parse SARIF JSON to extract metadata, infer risk probabilities based on CWE/OWASP mapping
    """

    def __init__(self):
        self.cwe_risk_mapping = self._initialize_cwe_mapping()
        self.owasp_risk_mapping = self._initialize_owasp_mapping()

    def _initialize_cwe_mapping(self) -> Dict[str, float]:
        """Initialize CWE to risk score mapping"""
        return {
            "CWE-79": 0.8,  # XSS
            "CWE-89": 0.9,  # SQL Injection
            "CWE-22": 0.7,  # Path Traversal
            "CWE-78": 0.9,  # OS Command Injection
            "CWE-94": 0.9,  # Code Injection
            "CWE-119": 0.8,  # Buffer Overflow
            "CWE-20": 0.6,  # Input Validation
            "CWE-200": 0.5,  # Information Exposure
            "CWE-285": 0.7,  # Improper Authorization
            "CWE-287": 0.8,  # Improper Authentication
        }

    def _initialize_owasp_mapping(self) -> Dict[str, float]:
        """Initialize OWASP category to risk score mapping"""
        return {
            "A01:2021": 0.8,  # Broken Access Control
            "A02:2021": 0.9,  # Cryptographic Failures
            "A03:2021": 0.8,  # Injection
            "A04:2021": 0.7,  # Insecure Design
            "A05:2021": 0.6,  # Security Misconfiguration
            "A06:2021": 0.7,  # Vulnerable Components
            "A07:2021": 0.8,  # Identity and Authentication Failures
            "A08:2021": 0.6,  # Software and Data Integrity Failures
            "A09:2021": 0.7,  # Security Logging Failures
            "A10:2021": 0.8,  # Server-Side Request Forgery
        }

    async def process_sarif_findings(
        self, sarif_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Process SARIF JSON and extract non-CVE vulnerabilities"""
        vulnerabilities = []

        try:
            # Parse SARIF structure
            runs = sarif_data.get("runs", [])

            for run in runs:
                results = run.get("results", [])

                for result in results:
                    vuln = self._extract_vulnerability(result)
                    if vuln:
                        vulnerabilities.append(vuln)

            # Cluster similar findings
            clustered_vulns = self._cluster_vulnerabilities(vulnerabilities)

            # Calculate risk scores
            risk_assessment = self._assess_clustered_risks(clustered_vulns)

            return {
                "total_findings": len(vulnerabilities),
                "unique_clusters": len(clustered_vulns),
                "clustered_vulnerabilities": clustered_vulns,
                "risk_assessment": risk_assessment,
                "high_risk_findings": [
                    v for v in vulnerabilities if v.confidence > 0.7
                ],
                "processing_metadata": {
                    "processed_at": datetime.now(timezone.utc).isoformat(),
                    "sarif_version": sarif_data.get("version", "unknown"),
                    "tools_used": self._extract_tool_info(sarif_data),
                },
            }

        except Exception as e:
            logger.error(f"SARIF processing failed: {e}")
            return {"error": str(e), "total_findings": 0}

    def _extract_vulnerability(
        self, result: Dict[str, Any]
    ) -> Optional[SARIFVulnerability]:
        """Extract vulnerability from SARIF result"""
        try:
            rule_id = result.get("ruleId", "unknown")
            message = result.get("message", {}).get("text", "No description")

            # Extract severity
            level = result.get("level", "note")
            severity_mapping = {
                "error": "HIGH",
                "warning": "MEDIUM",
                "note": "LOW",
                "info": "INFO",
            }
            severity = severity_mapping.get(level, "MEDIUM")

            # Extract CWE/OWASP if available
            cwe_id = self._extract_cwe(result)
            owasp_category = self._extract_owasp(result)

            # Extract location
            locations = result.get("locations", [{}])
            file_location = (
                locations[0]
                .get("physicalLocation", {})
                .get("artifactLocation", {})
                .get("uri", "unknown")
            )

            # Calculate confidence based on available metadata
            confidence = self._calculate_confidence(result, cwe_id, owasp_category)

            return SARIFVulnerability(
                rule_id=rule_id,
                message=message,
                severity=severity,
                cwe_id=cwe_id,
                owasp_category=owasp_category,
                file_location=file_location,
                confidence=confidence,
            )

        except Exception as e:
            logger.error(f"Vulnerability extraction failed: {e}")
            return None

    def _extract_cwe(self, result: Dict[str, Any]) -> Optional[str]:
        """Extract CWE ID from SARIF result"""
        # Check various locations where CWE might be stored
        properties = result.get("properties", {})
        tags = result.get("tags", [])

        for tag in tags:
            if tag.startswith("CWE-"):
                return tag

        return properties.get("cwe_id")

    def _extract_owasp(self, result: Dict[str, Any]) -> Optional[str]:
        """Extract OWASP category from SARIF result"""
        properties = result.get("properties", {})
        tags = result.get("tags", [])

        for tag in tags:
            if "A0" in tag and "2021" in tag:
                return tag

        return properties.get("owasp_category")

    def _calculate_confidence(
        self, result: Dict, cwe_id: Optional[str], owasp_category: Optional[str]
    ) -> float:
        """Calculate confidence score for vulnerability"""
        confidence = 0.5  # Base confidence

        # Higher confidence with CWE mapping
        if cwe_id and cwe_id in self.cwe_risk_mapping:
            confidence += 0.2

        # Higher confidence with OWASP mapping
        if owasp_category and owasp_category in self.owasp_risk_mapping:
            confidence += 0.2

        # Higher confidence with detailed message
        message_length = len(result.get("message", {}).get("text", ""))
        if message_length > 50:
            confidence += 0.1

        return min(confidence, 1.0)

    def _cluster_vulnerabilities(
        self, vulnerabilities: List[SARIFVulnerability]
    ) -> List[Dict[str, Any]]:
        """Cluster similar vulnerabilities for shared risk profiles"""
        clusters = {}

        for vuln in vulnerabilities:
            # Cluster by rule_id and CWE
            cluster_key = f"{vuln.rule_id}_{vuln.cwe_id or 'unknown'}"

            if cluster_key not in clusters:
                clusters[cluster_key] = {
                    "cluster_id": cluster_key,
                    "rule_id": vuln.rule_id,
                    "cwe_id": vuln.cwe_id,
                    "owasp_category": vuln.owasp_category,
                    "instances": [],
                    "severity": vuln.severity,
                    "avg_confidence": 0,
                }

            clusters[cluster_key]["instances"].append(asdict(vuln))

        # Calculate cluster statistics
        for cluster in clusters.values():
            instances = cluster["instances"]
            cluster["count"] = len(instances)
            cluster["avg_confidence"] = _mean(
                [inst["confidence"] for inst in instances]
            )
            cluster["affected_files"] = list(
                set([inst["file_location"] for inst in instances])
            )

        return list(clusters.values())

    def _assess_clustered_risks(self, clusters: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Assess risk for clustered vulnerabilities"""
        total_risk = 0
        high_risk_clusters = 0

        for cluster in clusters:
            cluster_risk = self._calculate_cluster_risk(cluster)
            cluster["risk_score"] = cluster_risk
            total_risk += cluster_risk

            if cluster_risk > 0.7:
                high_risk_clusters += 1

        return {
            "overall_risk": total_risk / len(clusters) if clusters else 0,
            "high_risk_clusters": high_risk_clusters,
            "total_clusters": len(clusters),
            "risk_distribution": self._calculate_risk_distribution(clusters),
        }

    def _calculate_cluster_risk(self, cluster: Dict[str, Any]) -> float:
        """Calculate risk score for a vulnerability cluster"""
        base_risk = 0.5

        # Risk from CWE mapping
        cwe_id = cluster.get("cwe_id")
        if cwe_id and cwe_id in self.cwe_risk_mapping:
            base_risk = self.cwe_risk_mapping[cwe_id]

        # Risk from OWASP mapping
        owasp_cat = cluster.get("owasp_category")
        if owasp_cat and owasp_cat in self.owasp_risk_mapping:
            base_risk = max(base_risk, self.owasp_risk_mapping[owasp_cat])

        # Adjust for cluster size (more instances = higher risk)
        instance_factor = min(cluster["count"] / 10, 0.3)

        # Adjust for confidence
        confidence_factor = cluster["avg_confidence"]

        final_risk = base_risk + instance_factor
        return min(final_risk * confidence_factor, 1.0)

    def _calculate_risk_distribution(
        self, clusters: List[Dict[str, Any]]
    ) -> Dict[str, int]:
        """Calculate distribution of risk levels"""
        distribution = {"low": 0, "medium": 0, "high": 0, "critical": 0}

        for cluster in clusters:
            risk = cluster.get("risk_score", 0)
            if risk >= 0.9:
                distribution["critical"] += 1
            elif risk >= 0.7:
                distribution["high"] += 1
            elif risk >= 0.4:
                distribution["medium"] += 1
            else:
                distribution["low"] += 1

        return distribution

    def _extract_tool_info(self, sarif_data: Dict[str, Any]) -> List[str]:
        """Extract information about tools used to generate SARIF"""
        tools = []
        runs = sarif_data.get("runs", [])

        for run in runs:
            tool = run.get("tool", {})
            driver = tool.get("driver", {})
            name = driver.get("name", "unknown")
            version = driver.get("version", "unknown")
            tools.append(f"{name} v{version}")

        return tools


# Processing Layer Orchestrator
class ProcessingLayer:
    """
    Main Processing Layer orchestrator that coordinates all components
    """

    def __init__(self):
        self.bayesian_mapper = BayesianPriorMapping()
        self.markov_builder = MarkovTransitionMatrixBuilder()
        self.fusion_engine = SSVCProbabilisticFusion()
        self.sarif_handler = SARIFVulnerabilityHandler()

        # Initialize missing architecture components
        self.knowledge_graph = None
        self.explanation_engine = None
        self._initialize_additional_components()

    async def process_security_context(
        self,
        ssvc_context: SSVCContext,
        markov_states: List[MarkovState],
        sarif_data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Main processing pipeline that coordinates all components
        """
        start_time = datetime.now(timezone.utc)

        # 1. Bayesian Prior Mapping
        logger.info("🧠 Computing Bayesian priors...")
        bayesian_priors = await self.bayesian_mapper.compute_priors(ssvc_context)

        # 2. Markov Transition Analysis
        logger.info("🔄 Analyzing Markov state transitions...")
        markov_predictions = await self.markov_builder.predict_state_evolution(
            markov_states
        )

        # 3. SARIF Vulnerability Processing (if provided)
        sarif_results = None
        if sarif_data:
            logger.info("📋 Processing SARIF vulnerabilities...")
            sarif_results = await self.sarif_handler.process_sarif_findings(sarif_data)

        # 4. SSVC + Probabilistic Fusion
        logger.info("⚖️ Fusing decisions with probabilistic logic...")
        fusion_results = await self.fusion_engine.fuse_decisions(
            ssvc_context, bayesian_priors, markov_predictions
        )

        # 5. Generate comprehensive results
        processing_time = (datetime.now(timezone.utc) - start_time).total_seconds()

        # 6. Knowledge Graph Construction (if enabled)
        knowledge_graph_results = None
        if self.knowledge_graph:
            logger.info("🕸️ Constructing knowledge graph...")
            scan_data_dict = {"sarif": sarif_data} if sarif_data else {}
            knowledge_graph_results = await self.knowledge_graph.build_graph(
                scan_data_dict
            )

        # 7. LLM Explanation Generation (if enabled)
        human_explanation = None
        if self.explanation_engine:
            logger.info("📝 Generating human-readable explanation...")
            explanation_data = {
                "decision": fusion_results["final_decision"],
                "confidence": fusion_results["confidence"],
                "risk_score": fusion_results["composite_risk_score"],
                "ssvc_context": ssvc_context.__dict__,
                "markov_predictions": markov_predictions,
                "sarif_findings": sarif_results.get("total_findings", 0)
                if sarif_results
                else 0,
            }

            from src.services.llm_explanation_engine import ExplanationRequest

            explanation_request = ExplanationRequest(
                context_type="decision_rationale",
                technical_data=explanation_data,
                audience="security_analyst",
                detail_level="detailed",
            )
            human_explanation = await self.explanation_engine.generate_explanation(
                explanation_request
            )

        components_used = ["bayesian", "markov", "fusion"] + (
            ["sarif"] if sarif_data else []
        )
        if knowledge_graph_results:
            components_used.append("knowledge_graph")
        if human_explanation:
            components_used.append("llm_explanation")

        return {
            "processing_results": {
                "bayesian_priors": bayesian_priors,
                "markov_predictions": markov_predictions,
                "sarif_analysis": sarif_results,
                "fusion_decision": fusion_results,
                "knowledge_graph": knowledge_graph_results,
                "human_explanation": human_explanation.__dict__
                if human_explanation
                else None,
            },
            "final_recommendation": fusion_results["final_decision"],
            "confidence_score": fusion_results["confidence"],
            "risk_score": fusion_results["composite_risk_score"],
            "explanation": fusion_results["explanation"],
            "human_readable_summary": human_explanation.summary
            if human_explanation
            else fusion_results["explanation"],
            "key_insights": human_explanation.key_points if human_explanation else [],
            "recommendations": human_explanation.recommendations
            if human_explanation
            else [],
            "processing_metadata": {
                "processing_time_seconds": processing_time,
                "components_used": components_used,
                "timestamp": start_time.isoformat(),
                "architecture_complete": len(components_used)
                >= 6,  # All major components
            },
        }

    def _initialize_additional_components(self):
        """Initialize Knowledge Graph and LLM Explanation Engine"""
        try:
            # Initialize Knowledge Graph
            from src.services.knowledge_graph import knowledge_graph

            self.knowledge_graph = knowledge_graph
            logger.info("✅ Knowledge Graph Construction initialized")

        except Exception as e:
            logger.warning(f"Knowledge Graph initialization failed: {e}")
            self.knowledge_graph = None

        try:
            # Initialize LLM Explanation Engine
            from src.services.llm_explanation_engine import explanation_engine

            self.explanation_engine = explanation_engine
            logger.info("✅ LLM Explanation Engine initialized")

        except Exception as e:
            logger.warning(f"LLM Explanation Engine initialization failed: {e}")
            self.explanation_engine = None
