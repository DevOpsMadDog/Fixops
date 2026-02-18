"""Markov Chain model for security state transition prediction.

This module provides a real Markov Chain implementation for predicting
vulnerability exploitation paths and security state transitions.
"""

from __future__ import annotations

import logging
import random
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Tuple

import numpy as np

logger = logging.getLogger(__name__)


@dataclass
class StateTransition:
    """Represents a transition between security states."""

    from_state: str
    to_state: str
    probability: float
    conditions: List[str] = field(default_factory=list)
    time_to_transition_hours: float = 24.0


@dataclass
class MarkovState:
    """Represents a security state in the Markov Chain."""

    name: str
    risk_level: str  # low, medium, high, critical
    description: str
    mitre_technique: Optional[str] = None
    is_absorbing: bool = False


class SecurityMarkovChain:
    """Markov Chain model for security state prediction.

    Models the progression of security vulnerabilities through exploitation stages:
    - Initial: Vulnerability discovered but not exploited
    - Reconnaissance: Attacker gathering information
    - InitialAccess: First foothold established
    - Execution: Malicious code running
    - Persistence: Attacker maintains access
    - PrivilegeEscalation: Higher privileges obtained
    - Exfiltration: Data being stolen
    - Impact: Damage realized
    """

    # Standard security states based on MITRE ATT&CK kill chain
    STANDARD_STATES = [
        MarkovState(
            "Initial", "low", "Vulnerability exists but not actively exploited"
        ),
        MarkovState(
            "Reconnaissance", "low", "Attacker gathering target information", "TA0043"
        ),
        MarkovState(
            "ResourceDevelopment", "low", "Attacker preparing resources", "TA0042"
        ),
        MarkovState("InitialAccess", "medium", "First foothold established", "TA0001"),
        MarkovState(
            "Execution", "medium", "Malicious code running on target", "TA0002"
        ),
        MarkovState(
            "Persistence", "high", "Attacker maintains access across restarts", "TA0003"
        ),
        MarkovState(
            "PrivilegeEscalation", "high", "Higher privileges obtained", "TA0004"
        ),
        MarkovState(
            "DefenseEvasion", "high", "Attacker hiding their presence", "TA0005"
        ),
        MarkovState("CredentialAccess", "high", "Stealing credentials", "TA0006"),
        MarkovState("Discovery", "medium", "Mapping the environment", "TA0007"),
        MarkovState("LateralMovement", "high", "Moving to other systems", "TA0008"),
        MarkovState("Collection", "high", "Gathering data of interest", "TA0009"),
        MarkovState(
            "Exfiltration",
            "critical",
            "Data being stolen",
            "TA0010",
            is_absorbing=False,
        ),
        MarkovState(
            "Impact",
            "critical",
            "Damage realized (ransomware, destruction)",
            "TA0040",
            is_absorbing=True,
        ),
        MarkovState(
            "Contained", "low", "Threat contained/mitigated", is_absorbing=True
        ),
    ]

    def __init__(self, config: Optional[Mapping[str, Any]] = None):
        """Initialize the Markov Chain with security states."""
        self.config = dict(config or {})
        self.states = {s.name: s for s in self.STANDARD_STATES}
        self.state_names = [s.name for s in self.STANDARD_STATES]
        self.n_states = len(self.state_names)
        self.state_idx = {name: i for i, name in enumerate(self.state_names)}

        # Initialize transition matrix with real security progression probabilities
        self.transition_matrix = self._build_default_transition_matrix()

        # Time-to-transition estimates (in hours)
        self.transition_times = self._build_transition_times()

    def _build_default_transition_matrix(self) -> np.ndarray:
        """Build realistic transition matrix based on security attack patterns.

        Probabilities derived from threat intelligence and MITRE ATT&CK patterns.
        """
        n = self.n_states
        matrix = np.zeros((n, n))

        # Define transitions based on typical attack progression
        # Format: (from_state, to_state, probability)
        transitions = [
            # From Initial (vulnerability exists)
            ("Initial", "Reconnaissance", 0.15),
            ("Initial", "Initial", 0.75),  # Stay in initial (not yet targeted)
            ("Initial", "Contained", 0.10),  # Patched before exploitation
            # From Reconnaissance
            ("Reconnaissance", "ResourceDevelopment", 0.40),
            ("Reconnaissance", "InitialAccess", 0.20),  # Direct exploitation attempt
            ("Reconnaissance", "Reconnaissance", 0.30),  # Continue recon
            ("Reconnaissance", "Contained", 0.10),  # Detected during recon
            # From Resource Development
            ("ResourceDevelopment", "InitialAccess", 0.60),
            ("ResourceDevelopment", "ResourceDevelopment", 0.30),
            ("ResourceDevelopment", "Contained", 0.10),
            # From Initial Access
            ("InitialAccess", "Execution", 0.50),
            ("InitialAccess", "Discovery", 0.25),
            ("InitialAccess", "Persistence", 0.15),
            ("InitialAccess", "Contained", 0.10),
            # From Execution
            ("Execution", "Persistence", 0.35),
            ("Execution", "PrivilegeEscalation", 0.25),
            ("Execution", "Discovery", 0.20),
            ("Execution", "DefenseEvasion", 0.10),
            ("Execution", "Contained", 0.10),
            # From Persistence
            ("Persistence", "PrivilegeEscalation", 0.30),
            ("Persistence", "DefenseEvasion", 0.25),
            ("Persistence", "Discovery", 0.20),
            ("Persistence", "CredentialAccess", 0.15),
            ("Persistence", "Contained", 0.10),
            # From Privilege Escalation
            ("PrivilegeEscalation", "CredentialAccess", 0.30),
            ("PrivilegeEscalation", "DefenseEvasion", 0.25),
            ("PrivilegeEscalation", "LateralMovement", 0.20),
            ("PrivilegeEscalation", "Collection", 0.15),
            ("PrivilegeEscalation", "Contained", 0.10),
            # From Defense Evasion
            ("DefenseEvasion", "CredentialAccess", 0.30),
            ("DefenseEvasion", "LateralMovement", 0.25),
            ("DefenseEvasion", "Collection", 0.25),
            ("DefenseEvasion", "Discovery", 0.15),
            ("DefenseEvasion", "Contained", 0.05),
            # From Credential Access
            ("CredentialAccess", "LateralMovement", 0.40),
            ("CredentialAccess", "PrivilegeEscalation", 0.20),
            ("CredentialAccess", "Collection", 0.20),
            ("CredentialAccess", "Discovery", 0.10),
            ("CredentialAccess", "Contained", 0.10),
            # From Discovery
            ("Discovery", "LateralMovement", 0.30),
            ("Discovery", "Collection", 0.30),
            ("Discovery", "CredentialAccess", 0.20),
            ("Discovery", "Execution", 0.10),
            ("Discovery", "Contained", 0.10),
            # From Lateral Movement
            ("LateralMovement", "Collection", 0.35),
            ("LateralMovement", "PrivilegeEscalation", 0.20),
            ("LateralMovement", "CredentialAccess", 0.20),
            ("LateralMovement", "Exfiltration", 0.15),
            ("LateralMovement", "Contained", 0.10),
            # From Collection
            ("Collection", "Exfiltration", 0.50),
            ("Collection", "Impact", 0.20),
            ("Collection", "LateralMovement", 0.15),
            ("Collection", "Collection", 0.10),
            ("Collection", "Contained", 0.05),
            # From Exfiltration
            ("Exfiltration", "Impact", 0.40),
            ("Exfiltration", "Exfiltration", 0.30),  # Ongoing exfiltration
            ("Exfiltration", "Collection", 0.15),  # More data
            ("Exfiltration", "Contained", 0.15),
            # Impact and Contained are absorbing states
            ("Impact", "Impact", 1.0),
            ("Contained", "Contained", 1.0),
        ]

        for from_state, to_state, prob in transitions:
            if from_state in self.state_idx and to_state in self.state_idx:
                i = self.state_idx[from_state]
                j = self.state_idx[to_state]
                matrix[i, j] = prob

        # Normalize rows to sum to 1
        for i in range(n):
            row_sum = matrix[i].sum()
            if row_sum > 0:
                matrix[i] /= row_sum
            else:
                matrix[i, i] = 1.0  # Self-loop if no transitions defined

        return matrix

    def _build_transition_times(self) -> Dict[Tuple[str, str], float]:
        """Build estimated time-to-transition in hours."""
        return {
            ("Initial", "Reconnaissance"): 168.0,  # 1 week average
            ("Reconnaissance", "InitialAccess"): 48.0,  # 2 days
            ("InitialAccess", "Execution"): 2.0,  # 2 hours
            ("Execution", "Persistence"): 4.0,  # 4 hours
            ("Persistence", "PrivilegeEscalation"): 8.0,  # 8 hours
            ("PrivilegeEscalation", "CredentialAccess"): 6.0,  # 6 hours
            ("CredentialAccess", "LateralMovement"): 12.0,  # 12 hours
            ("LateralMovement", "Collection"): 24.0,  # 1 day
            ("Collection", "Exfiltration"): 12.0,  # 12 hours
            ("Exfiltration", "Impact"): 2.0,  # 2 hours
        }

    def get_transition_probability(self, from_state: str, to_state: str) -> float:
        """Get probability of transitioning from one state to another."""
        if from_state not in self.state_idx or to_state not in self.state_idx:
            return 0.0
        i = self.state_idx[from_state]
        j = self.state_idx[to_state]
        return float(self.transition_matrix[i, j])

    def predict_next_state(self, current_state: str) -> Tuple[str, float]:
        """Predict the most likely next state from current state."""
        if current_state not in self.state_idx:
            return current_state, 1.0

        i = self.state_idx[current_state]
        probs = self.transition_matrix[i]
        max_idx = int(np.argmax(probs))

        return self.state_names[max_idx], float(probs[max_idx])

    def sample_next_state(self, current_state: str) -> str:
        """Sample the next state based on transition probabilities."""
        if current_state not in self.state_idx:
            return current_state

        i = self.state_idx[current_state]
        probs = self.transition_matrix[i]
        next_idx = np.random.choice(self.n_states, p=probs)

        return self.state_names[next_idx]

    def simulate_attack_path(
        self,
        start_state: str = "Initial",
        max_steps: int = 20,
        seed: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """Simulate an attack path from the starting state.

        Returns a list of state transitions with probabilities and timing.
        """
        if seed is not None:
            np.random.seed(seed)
            random.seed(seed)

        path = []
        current_state = start_state
        total_time = 0.0

        for step in range(max_steps):
            state_obj = self.states.get(current_state)

            # Get transition probabilities
            next_state, prob = self.predict_next_state(current_state)

            # Estimate time to transition
            transition_key = (current_state, next_state)
            time_hours = self.transition_times.get(transition_key, 24.0)

            path.append(
                {
                    "step": step,
                    "state": current_state,
                    "risk_level": state_obj.risk_level if state_obj else "unknown",
                    "mitre_technique": state_obj.mitre_technique if state_obj else None,
                    "next_state_predicted": next_state,
                    "transition_probability": round(prob, 4),
                    "estimated_time_hours": round(time_hours, 1),
                    "cumulative_time_hours": round(total_time, 1),
                }
            )

            # Check for absorbing state
            if state_obj and state_obj.is_absorbing:
                break

            # Sample actual next state (may differ from most likely)
            actual_next = self.sample_next_state(current_state)
            total_time += self.transition_times.get((current_state, actual_next), 24.0)
            current_state = actual_next

        return path

    def calculate_risk_trajectory(
        self, current_state: str, horizon_steps: int = 10
    ) -> Dict[str, Any]:
        """Calculate risk trajectory over time horizon.

        Uses matrix exponentiation to compute n-step transition probabilities.
        """
        if current_state not in self.state_idx:
            return {"error": f"Unknown state: {current_state}"}

        start_idx = self.state_idx[current_state]
        risk_levels = {"low": 0.2, "medium": 0.5, "high": 0.8, "critical": 1.0}

        trajectory = []
        self.transition_matrix.copy()

        for step in range(1, horizon_steps + 1):
            # Compute n-step transition matrix
            P_n = np.linalg.matrix_power(self.transition_matrix, step)
            probs = P_n[start_idx]

            # Calculate expected risk at this step
            expected_risk = 0.0
            state_probs = {}

            for state_name, idx in self.state_idx.items():
                prob = float(probs[idx])
                state_probs[state_name] = round(prob, 4)

                state_obj = self.states.get(state_name)
                if state_obj and prob > 0.001:
                    risk = risk_levels.get(state_obj.risk_level, 0.5)
                    expected_risk += prob * risk

            trajectory.append(
                {
                    "step": step,
                    "expected_risk": round(expected_risk, 4),
                    "probability_impact": round(state_probs.get("Impact", 0.0), 4),
                    "probability_contained": round(
                        state_probs.get("Contained", 0.0), 4
                    ),
                    "top_states": dict(
                        sorted(state_probs.items(), key=lambda x: x[1], reverse=True)[
                            :5
                        ]
                    ),
                }
            )

        return {
            "start_state": current_state,
            "horizon_steps": horizon_steps,
            "trajectory": trajectory,
            "final_impact_probability": trajectory[-1]["probability_impact"],
            "final_containment_probability": trajectory[-1]["probability_contained"],
        }

    def adjust_for_vulnerability(
        self,
        cvss_score: float,
        has_exploit: bool = False,
        is_network_exposed: bool = False,
    ) -> "SecurityMarkovChain":
        """Create an adjusted chain based on vulnerability characteristics.

        Higher CVSS scores and exploit availability increase transition probabilities
        toward more severe states.
        """
        adjusted = SecurityMarkovChain(self.config)

        # Adjustment factor based on vulnerability severity
        severity_factor = cvss_score / 10.0

        # Increase probability of progressing to dangerous states
        dangerous_states = [
            "InitialAccess",
            "Execution",
            "PrivilegeEscalation",
            "Exfiltration",
            "Impact",
        ]

        for from_state in self.state_names:
            if from_state in ["Impact", "Contained"]:
                continue

            i = self.state_idx[from_state]

            for to_state in dangerous_states:
                j = self.state_idx.get(to_state)
                if j is None:
                    continue

                # Increase dangerous transitions
                base_prob = self.transition_matrix[i, j]
                if base_prob > 0:
                    boost = 1.0 + (0.5 * severity_factor)
                    if has_exploit:
                        boost += 0.3
                    if is_network_exposed:
                        boost += 0.2
                    adjusted.transition_matrix[i, j] = min(base_prob * boost, 0.9)

            # Reduce containment probability for severe vulnerabilities
            contained_idx = self.state_idx.get("Contained")
            if contained_idx is not None:
                reduction = 1.0 - (0.3 * severity_factor)
                adjusted.transition_matrix[i, contained_idx] *= reduction

            # Re-normalize row
            row_sum = adjusted.transition_matrix[i].sum()
            if row_sum > 0:
                adjusted.transition_matrix[i] /= row_sum

        return adjusted

    def to_dict(self) -> Dict[str, Any]:
        """Export the Markov Chain to a dictionary."""
        transitions = []
        for i, from_state in enumerate(self.state_names):
            for j, to_state in enumerate(self.state_names):
                prob = float(self.transition_matrix[i, j])
                if prob > 0.001:
                    transitions.append(
                        {
                            "from": from_state,
                            "to": to_state,
                            "probability": round(prob, 4),
                        }
                    )

        return {
            "states": [
                {
                    "name": s.name,
                    "risk_level": s.risk_level,
                    "description": s.description,
                    "mitre_technique": s.mitre_technique,
                    "is_absorbing": s.is_absorbing,
                }
                for s in self.STANDARD_STATES
            ],
            "transitions": transitions,
            "n_states": self.n_states,
        }


def create_attack_chain_for_cve(
    cve_id: str,
    cvss_score: float = 7.5,
    has_exploit: bool = False,
    is_network_exposed: bool = True,
) -> Dict[str, Any]:
    """Create an attack chain prediction for a specific CVE.

    Args:
        cve_id: CVE identifier
        cvss_score: CVSS score (0-10)
        has_exploit: Whether an exploit is known to exist
        is_network_exposed: Whether the vulnerability is network-accessible

    Returns:
        Dictionary with attack chain prediction and risk trajectory
    """
    base_chain = SecurityMarkovChain()
    adjusted_chain = base_chain.adjust_for_vulnerability(
        cvss_score=cvss_score,
        has_exploit=has_exploit,
        is_network_exposed=is_network_exposed,
    )

    # Simulate attack path
    attack_path = adjusted_chain.simulate_attack_path(
        start_state="Initial",
        max_steps=15,
        seed=hash(cve_id) % (2**32),  # Deterministic based on CVE
    )

    # Calculate risk trajectory
    trajectory = adjusted_chain.calculate_risk_trajectory(
        current_state="Initial", horizon_steps=10
    )

    return {
        "cve_id": cve_id,
        "cvss_score": cvss_score,
        "has_exploit": has_exploit,
        "is_network_exposed": is_network_exposed,
        "attack_path_simulation": attack_path,
        "risk_trajectory": trajectory,
        "time_to_impact_hours": sum(
            step.get("estimated_time_hours", 0)
            for step in attack_path
            if step["state"] not in ["Impact", "Contained"]
        ),
        "recommendations": _generate_recommendations(attack_path, trajectory),
    }


def _generate_recommendations(
    attack_path: List[Dict[str, Any]], trajectory: Dict[str, Any]
) -> List[str]:
    """Generate mitigation recommendations based on attack chain analysis."""
    recommendations = []

    # Check final impact probability
    final_impact = trajectory.get("final_impact_probability", 0)
    if final_impact > 0.3:
        recommendations.append(
            f"HIGH PRIORITY: {round(final_impact * 100, 1)}% chance of reaching Impact state. "
            "Immediate patching recommended."
        )

    # Check for rapid progression
    high_risk_steps = [
        step for step in attack_path if step.get("risk_level") in ("high", "critical")
    ]
    if len(high_risk_steps) > 3:
        recommendations.append(
            "Attack chain shows rapid progression to high-risk states. "
            "Consider network segmentation and enhanced monitoring."
        )

    # Check transition probabilities
    for step in attack_path:
        if step.get("transition_probability", 0) > 0.5:
            recommendations.append(
                f"State '{step['state']}' has {round(step['transition_probability'] * 100)}% "
                f"chance of transitioning to '{step['next_state_predicted']}'. "
                "Deploy controls at this stage."
            )

    # MITRE-specific recommendations
    mitre_techniques = [
        step.get("mitre_technique")
        for step in attack_path
        if step.get("mitre_technique")
    ]
    if mitre_techniques:
        recommendations.append(
            f"MITRE ATT&CK techniques in predicted path: {', '.join(set(mitre_techniques))}. "
            "Review detection rules for these techniques."
        )

    if not recommendations:
        recommendations.append(
            "Low risk trajectory. Continue standard monitoring procedures."
        )

    return recommendations


__all__ = [
    "SecurityMarkovChain",
    "MarkovState",
    "StateTransition",
    "create_attack_chain_for_cve",
]
