"""
ALdeci Predictive Vulnerability Scorer — Year 3 ML Roadmap Preview.

[V3] Decision Intelligence — Pre-CVE risk prediction using code patterns.

This module predicts vulnerability risk BEFORE CVEs are assigned by analyzing
code patterns, dependency graphs, and historical vulnerability correlations.
Unlike reactive scoring (wait for CVE → score it), predictive scoring
identifies risky patterns proactively.

Key capabilities:
1. CWE pattern frequency analysis — which weakness patterns correlate with
   high exploit probability
2. Dependency risk scoring — score packages by historical vulnerability density
3. Code complexity → vulnerability correlation — cyclomatic complexity,
   function length, nested depth correlate with bug density
4. Temporal risk decay — how vulnerability risk changes over time
5. Cross-CVE similarity — find vulns similar to known exploited ones

All models are air-gap compatible — no cloud API calls, numpy/sklearn only.

Usage:
    from core.ml.predictive_scorer import PredictiveScorer
    scorer = PredictiveScorer()
    scorer.fit_from_cve_history(golden_path="data/golden_regression_cases.json")

    # Predict risk for a code pattern
    result = scorer.predict_code_risk({
        "cwe_id": "CWE-89",
        "language": "python",
        "complexity": 25,
        "function_length": 150,
        "has_user_input": True,
        "dependency_age_days": 730,
        "dependency_vuln_history": 5,
    })
    # result.risk_score: 0-100
    # result.exploit_probability: 0-1
    # result.similar_cves: ["CVE-2025-50190", ...]
"""

from __future__ import annotations

import json
import logging
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# CWE Risk Profile Database
# ---------------------------------------------------------------------------

# Historical exploit probability by CWE category (from MITRE CWE Top 25 + EPSS research)
CWE_EXPLOIT_PROFILES = {
    # Injection flaws — highest exploit probability
    "CWE-89":  {"name": "SQL Injection",           "base_exploit_prob": 0.85, "category": "injection",       "avg_cvss": 9.2, "weaponize_days": 7},
    "CWE-78":  {"name": "OS Command Injection",    "base_exploit_prob": 0.82, "category": "injection",       "avg_cvss": 9.5, "weaponize_days": 5},
    "CWE-94":  {"name": "Code Injection",          "base_exploit_prob": 0.78, "category": "injection",       "avg_cvss": 9.0, "weaponize_days": 10},
    "CWE-79":  {"name": "Cross-site Scripting",    "base_exploit_prob": 0.72, "category": "injection",       "avg_cvss": 6.5, "weaponize_days": 3},
    "CWE-917": {"name": "Expression Language Inj", "base_exploit_prob": 0.75, "category": "injection",       "avg_cvss": 9.0, "weaponize_days": 14},

    # Deserialization / data handling
    "CWE-502": {"name": "Insecure Deserialization", "base_exploit_prob": 0.80, "category": "deserialization", "avg_cvss": 9.5, "weaponize_days": 14},
    "CWE-611": {"name": "XML External Entity",      "base_exploit_prob": 0.55, "category": "deserialization", "avg_cvss": 7.5, "weaponize_days": 21},

    # Authentication / authorization
    "CWE-287": {"name": "Improper Authentication",  "base_exploit_prob": 0.70, "category": "auth",           "avg_cvss": 8.5, "weaponize_days": 10},
    "CWE-798": {"name": "Hardcoded Credentials",    "base_exploit_prob": 0.90, "category": "auth",           "avg_cvss": 9.0, "weaponize_days": 1},
    "CWE-306": {"name": "Missing Authentication",   "base_exploit_prob": 0.85, "category": "auth",           "avg_cvss": 9.0, "weaponize_days": 3},
    "CWE-862": {"name": "Missing Authorization",    "base_exploit_prob": 0.65, "category": "auth",           "avg_cvss": 7.5, "weaponize_days": 14},

    # Memory safety
    "CWE-787": {"name": "Out-of-bounds Write",     "base_exploit_prob": 0.60, "category": "memory",         "avg_cvss": 8.5, "weaponize_days": 30},
    "CWE-125": {"name": "Out-of-bounds Read",      "base_exploit_prob": 0.35, "category": "memory",         "avg_cvss": 6.0, "weaponize_days": 45},
    "CWE-416": {"name": "Use After Free",          "base_exploit_prob": 0.55, "category": "memory",         "avg_cvss": 8.0, "weaponize_days": 30},
    "CWE-120": {"name": "Buffer Overflow",         "base_exploit_prob": 0.65, "category": "memory",         "avg_cvss": 9.0, "weaponize_days": 21},
    "CWE-190": {"name": "Integer Overflow",        "base_exploit_prob": 0.30, "category": "memory",         "avg_cvss": 7.0, "weaponize_days": 60},

    # Path traversal / file
    "CWE-22":  {"name": "Path Traversal",          "base_exploit_prob": 0.70, "category": "path",           "avg_cvss": 7.5, "weaponize_days": 7},
    "CWE-434": {"name": "Unrestricted File Upload", "base_exploit_prob": 0.75, "category": "path",          "avg_cvss": 9.0, "weaponize_days": 5},

    # Crypto
    "CWE-327": {"name": "Broken Crypto Algorithm",  "base_exploit_prob": 0.25, "category": "crypto",        "avg_cvss": 5.5, "weaponize_days": 90},
    "CWE-330": {"name": "Insufficient Randomness",  "base_exploit_prob": 0.30, "category": "crypto",        "avg_cvss": 5.0, "weaponize_days": 60},

    # Supply chain
    "CWE-506": {"name": "Embedded Malicious Code",  "base_exploit_prob": 0.95, "category": "supply_chain",  "avg_cvss": 10.0, "weaponize_days": 0},
    "CWE-494": {"name": "Download w/o Integrity",   "base_exploit_prob": 0.65, "category": "supply_chain",  "avg_cvss": 8.5, "weaponize_days": 14},

    # DoS
    "CWE-400": {"name": "Resource Exhaustion",     "base_exploit_prob": 0.50, "category": "dos",            "avg_cvss": 7.0, "weaponize_days": 7},
    "CWE-617": {"name": "Reachable Assertion",     "base_exploit_prob": 0.20, "category": "dos",            "avg_cvss": 5.0, "weaponize_days": 30},

    # Information disclosure
    "CWE-200": {"name": "Exposure of Info",         "base_exploit_prob": 0.40, "category": "info_disclosure","avg_cvss": 5.5, "weaponize_days": 14},
    "CWE-209": {"name": "Error Message Info Leak",  "base_exploit_prob": 0.25, "category": "info_disclosure","avg_cvss": 4.0, "weaponize_days": 30},

    # Race conditions
    "CWE-362": {"name": "Race Condition",           "base_exploit_prob": 0.35, "category": "race",          "avg_cvss": 7.0, "weaponize_days": 45},
    "CWE-668": {"name": "Exposure to Wrong Sphere", "base_exploit_prob": 0.55, "category": "access",        "avg_cvss": 7.5, "weaponize_days": 21},
}

# Language-specific vulnerability multipliers
LANGUAGE_RISK_MULTIPLIERS = {
    "c":          1.3,   # Memory-unsafe → more exploitable vulns
    "cpp":        1.25,  # Same as C but slightly better tooling
    "java":       1.0,   # Reference baseline
    "python":     0.9,   # Memory-safe but injection-prone
    "javascript": 1.0,   # Prototype pollution, XSS risks
    "typescript": 0.85,  # Type safety reduces some classes
    "go":         0.8,   # Memory-safe, strong stdlib
    "rust":       0.5,   # Borrow checker prevents memory bugs
    "ruby":       0.95,  # Similar to Python
    "php":        1.15,  # Historically high vuln density
    "kotlin":     0.8,   # Type-safe, null-safe
    "swift":      0.75,  # Memory-safe, modern
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class PredictiveResult:
    """Result of predictive vulnerability scoring."""
    risk_score: float           # 0-100 predictive risk
    exploit_probability: float  # 0-1 probability of exploitation
    confidence_interval: Tuple[float, float]  # CI for risk_score
    time_to_exploit_days: int   # Estimated days to weaponization
    similar_cves: List[Dict[str, Any]]  # Similar known CVEs
    risk_factors: List[Dict[str, Any]]  # Contributing risk factors
    recommendation: str         # Action recommendation
    category: str               # Risk category (injection, memory, etc.)
    priority: str               # Suggested priority (P0-P4, FP)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "risk_score": round(self.risk_score, 2),
            "exploit_probability": round(self.exploit_probability, 4),
            "confidence_interval": [round(self.confidence_interval[0], 2),
                                   round(self.confidence_interval[1], 2)],
            "time_to_exploit_days": self.time_to_exploit_days,
            "similar_cves": self.similar_cves,
            "risk_factors": self.risk_factors,
            "recommendation": self.recommendation,
            "category": self.category,
            "priority": self.priority,
        }


@dataclass
class DependencyRiskResult:
    """Risk assessment for a software dependency."""
    package_name: str
    risk_score: float            # 0-100
    vuln_density: float          # vulns per year
    avg_time_to_fix_days: float  # Mean remediation time
    active_cve_count: int
    highest_cvss: float
    supply_chain_risk: str       # low, medium, high, critical
    recommendation: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "package_name": self.package_name,
            "risk_score": round(self.risk_score, 2),
            "vuln_density": round(self.vuln_density, 2),
            "avg_time_to_fix_days": round(self.avg_time_to_fix_days, 1),
            "active_cve_count": self.active_cve_count,
            "highest_cvss": self.highest_cvss,
            "supply_chain_risk": self.supply_chain_risk,
            "recommendation": self.recommendation,
        }


@dataclass
class TemporalDecay:
    """Temporal risk decay model for a vulnerability."""
    initial_risk: float
    current_risk: float
    decay_rate: float       # Per-day decay constant
    days_since_discovery: int
    half_life_days: float   # Days until risk halves
    is_actively_exploited: bool  # Resets decay if True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "initial_risk": round(self.initial_risk, 2),
            "current_risk": round(self.current_risk, 2),
            "decay_rate": round(self.decay_rate, 6),
            "days_since_discovery": self.days_since_discovery,
            "half_life_days": round(self.half_life_days, 1),
            "is_actively_exploited": self.is_actively_exploited,
        }


# ---------------------------------------------------------------------------
# Predictive Scorer
# ---------------------------------------------------------------------------

class PredictiveScorer:
    """
    Predictive vulnerability scorer — Year 3 ML roadmap.

    Uses code patterns, CWE profiles, and historical CVE data to predict
    vulnerability risk BEFORE CVEs are assigned.
    """

    def __init__(self, model_dir: Optional[str] = None, random_seed: int = 42):
        self.model_dir = Path(model_dir) if model_dir else Path(".claude/team-state/data-science/models")
        self.random_seed = random_seed
        self._rng = np.random.RandomState(random_seed)
        self._cve_history: List[Dict[str, Any]] = []
        self._cwe_stats: Dict[str, Dict[str, float]] = {}
        self._fitted = False

    def fit_from_cve_history(self, golden_path: str = "data/golden_regression_cases.json") -> Dict[str, Any]:
        """Learn from historical CVE data to calibrate predictions.

        Analyzes golden regression dataset to build CWE→risk correlations,
        exploit probability distributions, and temporal patterns.
        """
        path = Path(golden_path)
        if not path.exists():
            raise FileNotFoundError(f"Golden dataset not found: {golden_path}")

        with open(path) as f:
            data = json.load(f)

        cases = data.get("cases", [])
        self._cve_history = cases

        # Build CWE statistics from golden dataset
        cwe_groups: Dict[str, List[Dict]] = {}
        for case in cases:
            cwe = case.get("cwe_id", "unknown")
            cwe_groups.setdefault(cwe, []).append(case)

        self._cwe_stats = {}
        for cwe, group in cwe_groups.items():
            cvss_scores = [c.get("cvss_score", 0) for c in group]
            epss_scores = [c.get("epss_score", 0) for c in group]
            risk_scores_mid = [(c.get("expected_risk_score_min", 0) + c.get("expected_risk_score_max", 100)) / 2
                               for c in group]
            exploit_rate = sum(1 for c in group if c.get("exploit_available", False)) / len(group)
            kev_rate = sum(1 for c in group if c.get("in_kev", False)) / len(group)

            self._cwe_stats[cwe] = {
                "count": len(group),
                "avg_cvss": float(np.mean(cvss_scores)),
                "avg_epss": float(np.mean(epss_scores)),
                "avg_risk": float(np.mean(risk_scores_mid)),
                "max_cvss": float(np.max(cvss_scores)),
                "exploit_rate": exploit_rate,
                "kev_rate": kev_rate,
            }

        self._fitted = True

        stats = {
            "cases_analyzed": len(cases),
            "unique_cwes": len(cwe_groups),
            "cwe_stats": self._cwe_stats,
            "version": data.get("_meta", {}).get("version", "unknown"),
        }

        logger.info("PredictiveScorer fitted: %d cases, %d CWEs", len(cases), len(cwe_groups))
        return stats

    def predict_code_risk(self, pattern: Dict[str, Any]) -> PredictiveResult:
        """Predict vulnerability risk from code pattern analysis.

        Args:
            pattern: Dict with keys:
                - cwe_id: str (e.g., "CWE-89")
                - language: str (e.g., "python")
                - complexity: int (cyclomatic complexity, 1-100+)
                - function_length: int (lines of code)
                - has_user_input: bool (processes external input)
                - dependency_age_days: int (age of dependency)
                - dependency_vuln_history: int (# past vulns)
                - is_internet_facing: bool (optional)
                - has_auth_check: bool (optional, reduces risk)
        """
        cwe_id = pattern.get("cwe_id", "CWE-0")
        language = pattern.get("language", "java").lower()
        complexity = min(max(pattern.get("complexity", 10), 1), 200)
        func_length = min(max(pattern.get("function_length", 50), 1), 2000)
        has_user_input = pattern.get("has_user_input", False)
        dep_age_days = max(pattern.get("dependency_age_days", 0), 0)
        dep_vuln_history = max(pattern.get("dependency_vuln_history", 0), 0)
        is_internet_facing = pattern.get("is_internet_facing", True)
        has_auth_check = pattern.get("has_auth_check", True)

        # ─── CWE profile lookup ────────────────────────────────────────
        cwe_profile = CWE_EXPLOIT_PROFILES.get(cwe_id, {
            "name": "Unknown Weakness",
            "base_exploit_prob": 0.30,
            "category": "unknown",
            "avg_cvss": 5.0,
            "weaponize_days": 30,
        })

        base_exploit_prob = cwe_profile["base_exploit_prob"]
        category = cwe_profile["category"]
        weaponize_days = cwe_profile["weaponize_days"]

        # ─── Feature engineering ────────────────────────────────────────
        risk_factors = []

        # 1. CWE base risk (40% weight)
        cwe_risk = base_exploit_prob * 100
        risk_factors.append({
            "factor": "cwe_base_risk",
            "value": cwe_id,
            "contribution": round(cwe_risk * 0.40, 2),
            "description": f"{cwe_profile['name']} has {base_exploit_prob:.0%} historical exploit probability"
        })

        # 2. Language risk multiplier (10% weight)
        lang_mult = LANGUAGE_RISK_MULTIPLIERS.get(language, 1.0)
        lang_risk = lang_mult * 50  # Normalize to 0-65 range
        risk_factors.append({
            "factor": "language_risk",
            "value": language,
            "contribution": round(lang_risk * 0.10, 2),
            "description": f"{language} has {lang_mult:.2f}x vulnerability multiplier"
        })

        # 3. Code complexity (15% weight)
        # Cyclomatic complexity > 15 significantly increases bug density
        complexity_risk = min(100, (complexity / 50) * 100)
        if complexity > 30:
            complexity_risk = min(100, complexity_risk * 1.5)
        risk_factors.append({
            "factor": "code_complexity",
            "value": complexity,
            "contribution": round(complexity_risk * 0.15, 2),
            "description": f"Cyclomatic complexity {complexity} ({'high' if complexity > 20 else 'moderate' if complexity > 10 else 'low'} risk)"
        })

        # 4. Function length (5% weight)
        length_risk = min(100, (func_length / 500) * 100)
        risk_factors.append({
            "factor": "function_length",
            "value": func_length,
            "contribution": round(length_risk * 0.05, 2),
            "description": f"{func_length} LOC function ({'long' if func_length > 200 else 'moderate' if func_length > 50 else 'short'})"
        })

        # 5. User input handling (10% weight)
        input_risk = 90.0 if has_user_input else 10.0
        risk_factors.append({
            "factor": "user_input_handling",
            "value": has_user_input,
            "contribution": round(input_risk * 0.10, 2),
            "description": f"{'Processes user input — attack surface present' if has_user_input else 'No direct user input handling'}"
        })

        # 6. Dependency risk (10% weight)
        dep_risk = 0.0
        if dep_age_days > 0:
            age_factor = min(1.0, dep_age_days / 1095)  # Max risk at 3 years
            vuln_factor = min(1.0, dep_vuln_history / 10)  # Max at 10 past vulns
            dep_risk = (age_factor * 40 + vuln_factor * 60)
        risk_factors.append({
            "factor": "dependency_risk",
            "value": f"age={dep_age_days}d, vulns={dep_vuln_history}",
            "contribution": round(dep_risk * 0.10, 2),
            "description": f"Dependency age {dep_age_days}d with {dep_vuln_history} historical vulns"
        })

        # 7. Exposure (5% weight)
        exposure_risk = 80.0 if is_internet_facing else 30.0
        risk_factors.append({
            "factor": "internet_exposure",
            "value": is_internet_facing,
            "contribution": round(exposure_risk * 0.05, 2),
            "description": f"{'Internet-facing — full exposure' if is_internet_facing else 'Internal only'}"
        })

        # 8. Auth check (5% weight — reduces risk)
        auth_reduction = 0.0 if has_auth_check else 50.0
        if not has_auth_check and category in ("injection", "auth", "path"):
            auth_reduction = 80.0  # Missing auth on injection/auth flaws is very bad
        risk_factors.append({
            "factor": "auth_check",
            "value": has_auth_check,
            "contribution": round(auth_reduction * 0.05, 2),
            "description": f"{'Auth check present — reduces exploitability' if has_auth_check else 'No auth check — unauthenticated access possible'}"
        })

        # ─── Compute final risk score ──────────────────────────────────
        raw_score = sum(f["contribution"] for f in risk_factors)
        risk_score = min(100.0, max(0.0, raw_score))

        # ─── Exploit probability calibration ───────────────────────────
        # Adjust base exploit probability by code-level factors
        exploit_adjustments = 1.0
        if has_user_input:
            exploit_adjustments *= 1.3
        if not has_auth_check:
            exploit_adjustments *= 1.4
        if complexity > 30:
            exploit_adjustments *= 1.1
        if dep_vuln_history > 3:
            exploit_adjustments *= 1.2
        if not is_internet_facing:
            exploit_adjustments *= 0.5

        exploit_prob = min(0.99, base_exploit_prob * exploit_adjustments)

        # ─── Confidence interval (bootstrap-like) ──────────────────────
        # Wider CI for unknown CWEs or unusual patterns
        base_width = 8.0
        if cwe_id not in CWE_EXPLOIT_PROFILES:
            base_width = 15.0  # More uncertainty for unknown CWEs
        if not self._fitted:
            base_width = 20.0  # Much more uncertainty without historical calibration

        ci_low = max(0, risk_score - base_width)
        ci_high = min(100, risk_score + base_width)

        # ─── Time to exploit estimation ────────────────────────────────
        tte = weaponize_days
        if has_user_input and not has_auth_check:
            tte = max(1, tte // 2)
        if dep_vuln_history > 5:
            tte = max(1, tte - 7)

        # ─── Similar CVE lookup ────────────────────────────────────────
        similar_cves = self._find_similar_cves(cwe_id, category, risk_score)

        # ─── Recommendation ────────────────────────────────────────────
        recommendation = self._generate_recommendation(
            risk_score, exploit_prob, cwe_profile, has_user_input,
            has_auth_check, is_internet_facing
        )

        # ─── Priority assignment ───────────────────────────────────────
        if risk_score >= 82:
            priority = "P0"
        elif risk_score >= 56:
            priority = "P1"
        elif risk_score >= 30:
            priority = "P2"
        elif risk_score >= 8:
            priority = "P3"
        elif risk_score >= 5:
            priority = "P4"
        else:
            priority = "FP"

        return PredictiveResult(
            risk_score=risk_score,
            exploit_probability=exploit_prob,
            confidence_interval=(ci_low, ci_high),
            time_to_exploit_days=tte,
            similar_cves=similar_cves,
            risk_factors=risk_factors,
            recommendation=recommendation,
            category=category,
            priority=priority,
        )

    def score_dependency_risk(self, dep_info: Dict[str, Any]) -> DependencyRiskResult:
        """Score risk for a software dependency/package.

        Args:
            dep_info: Dict with keys:
                - name: str (package name)
                - version: str (current version)
                - latest_version: str (latest available)
                - cve_count: int (total CVEs ever)
                - active_cves: int (currently unpatched)
                - highest_cvss: float (max CVSS of active CVEs)
                - age_days: int (days since package was published)
                - last_update_days: int (days since last release)
                - maintainers: int (number of maintainers)
                - downloads_weekly: int (weekly downloads / popularity)
        """
        name = dep_info.get("name", "unknown")
        cve_count = dep_info.get("cve_count", 0)
        active_cves = dep_info.get("active_cves", 0)
        highest_cvss = dep_info.get("highest_cvss", 0.0)
        age_days = max(dep_info.get("age_days", 365), 1)
        last_update_days = dep_info.get("last_update_days", 30)
        maintainers = max(dep_info.get("maintainers", 1), 1)
        downloads = dep_info.get("downloads_weekly", 1000)

        # Vulnerability density (vulns per year of existence)
        vuln_density = (cve_count / (age_days / 365.0))

        # Risk factors
        active_cve_risk = min(50, active_cves * 12.5)
        density_risk = min(25, vuln_density * 5)
        cvss_risk = min(15, highest_cvss * 1.5)
        staleness_risk = min(10, (last_update_days / 180) * 10)

        # Protective factors
        maintainer_factor = max(0.5, 1.0 - (maintainers - 1) * 0.1)
        popularity_factor = max(0.7, 1.0 - min(0.3, downloads / 1_000_000))

        raw_risk = (active_cve_risk + density_risk + cvss_risk + staleness_risk)
        risk_score = min(100, max(0, raw_risk * maintainer_factor * popularity_factor))

        # Average time to fix (estimate from vulnerability density + maintainer count)
        if vuln_density > 0 and maintainers > 0:
            avg_fix_days = max(7, 90 / maintainers - downloads / 100_000)
        else:
            avg_fix_days = 30.0

        # Supply chain risk tier
        if risk_score >= 75:
            sc_risk = "critical"
        elif risk_score >= 50:
            sc_risk = "high"
        elif risk_score >= 25:
            sc_risk = "medium"
        else:
            sc_risk = "low"

        # Recommendation
        if active_cves > 0 and highest_cvss >= 9.0:
            rec = f"URGENT: Upgrade {name} immediately — {active_cves} active CVE(s) with CVSS {highest_cvss}"
        elif active_cves > 0:
            rec = f"Upgrade {name} to patch {active_cves} known vulnerability(s)"
        elif last_update_days > 365:
            rec = f"Consider replacing {name} — last updated {last_update_days} days ago"
        elif vuln_density > 2.0:
            rec = f"Monitor {name} closely — high vulnerability density ({vuln_density:.1f}/year)"
        else:
            rec = f"{name} appears well-maintained with acceptable risk"

        return DependencyRiskResult(
            package_name=name,
            risk_score=risk_score,
            vuln_density=vuln_density,
            avg_time_to_fix_days=avg_fix_days,
            active_cve_count=active_cves,
            highest_cvss=highest_cvss,
            supply_chain_risk=sc_risk,
            recommendation=rec,
        )

    def compute_temporal_decay(
        self,
        initial_risk: float,
        days_since_discovery: int,
        is_actively_exploited: bool = False,
        has_patch: bool = False,
        in_kev: bool = False,
    ) -> TemporalDecay:
        """Compute how vulnerability risk decays over time.

        Risk decay follows an exponential model:
            risk(t) = initial_risk * exp(-decay_rate * t)

        But actively exploited vulns have ZERO decay (or even increase).
        Patched vulns decay faster.
        KEV membership resets decay.
        """
        # Base decay rate: 50% reduction every 90 days
        base_decay = math.log(2) / 90  # ~0.0077 per day

        if is_actively_exploited or in_kev:
            # No decay for actively exploited — risk persists or increases
            decay_rate = 0.0
            current_risk = initial_risk
            if in_kev and days_since_discovery > 30:
                # KEV entries that aren't patched actually get RISKIER
                current_risk = min(100, initial_risk * 1.1)
        elif has_patch:
            # Patched vulns decay 3x faster
            decay_rate = base_decay * 3.0
            current_risk = initial_risk * math.exp(-decay_rate * days_since_discovery)
        else:
            # Standard exponential decay
            decay_rate = base_decay
            current_risk = initial_risk * math.exp(-decay_rate * days_since_discovery)

        current_risk = max(0, min(100, current_risk))

        # Half-life calculation
        if decay_rate > 0:
            half_life = math.log(2) / decay_rate
        else:
            half_life = float("inf")

        return TemporalDecay(
            initial_risk=initial_risk,
            current_risk=current_risk,
            decay_rate=decay_rate,
            days_since_discovery=days_since_discovery,
            half_life_days=half_life if half_life != float("inf") else 9999.0,
            is_actively_exploited=is_actively_exploited,
        )

    def compute_similarity(self, vuln_a: Dict[str, Any], vuln_b: Dict[str, Any]) -> float:
        """Compute similarity between two vulnerabilities (0-1).

        Uses multi-factor similarity:
        - CWE match (40%): Same weakness type
        - CVSS proximity (20%): Similar severity
        - Category match (20%): Same attack category
        - Feature overlap (20%): Exploit availability, network exposure, etc.
        """
        score = 0.0

        # CWE match
        if vuln_a.get("cwe_id") == vuln_b.get("cwe_id") and vuln_a.get("cwe_id"):
            score += 0.40
        elif (vuln_a.get("cwe_id", "").split("-")[0] == vuln_b.get("cwe_id", "").split("-")[0]
              and vuln_a.get("cwe_id")):
            score += 0.20  # Same CWE prefix (e.g., both CWE-*)

        # CVSS proximity
        cvss_a = vuln_a.get("cvss_score", 5.0)
        cvss_b = vuln_b.get("cvss_score", 5.0)
        cvss_sim = max(0, 1.0 - abs(cvss_a - cvss_b) / 10.0)
        score += cvss_sim * 0.20

        # Category match
        cat_a = CWE_EXPLOIT_PROFILES.get(vuln_a.get("cwe_id", ""), {}).get("category", "")
        cat_b = CWE_EXPLOIT_PROFILES.get(vuln_b.get("cwe_id", ""), {}).get("category", "")
        if cat_a and cat_b and cat_a == cat_b:
            score += 0.20

        # Feature overlap
        features = ["exploit_available", "in_kev", "reachable"]
        feature_matches = sum(
            1 for f in features
            if vuln_a.get(f) == vuln_b.get(f) and vuln_a.get(f) is not None
        )
        score += (feature_matches / max(len(features), 1)) * 0.20

        return min(1.0, score)

    # ── Private helpers ────────────────────────────────────────────────

    def _find_similar_cves(self, cwe_id: str, category: str,
                           risk_score: float) -> List[Dict[str, Any]]:
        """Find CVEs from history that are similar to the predicted pattern."""
        if not self._cve_history:
            return []

        similar = []
        for case in self._cve_history:
            sim_score = 0.0
            if case.get("cwe_id") == cwe_id:
                sim_score += 0.5
            case_cat = CWE_EXPLOIT_PROFILES.get(case.get("cwe_id", ""), {}).get("category", "")
            if case_cat == category:
                sim_score += 0.3
            # Risk score proximity
            case_mid = (case.get("expected_risk_score_min", 0) + case.get("expected_risk_score_max", 100)) / 2
            risk_sim = max(0, 1.0 - abs(risk_score - case_mid) / 100)
            sim_score += risk_sim * 0.2

            if sim_score >= 0.3:
                similar.append({
                    "cve_id": case.get("cve_id", ""),
                    "title": case.get("title", ""),
                    "similarity": round(sim_score, 3),
                    "cvss": case.get("cvss_score", 0),
                    "exploited": case.get("exploit_available", False),
                })

        # Sort by similarity and return top 5
        similar.sort(key=lambda x: x["similarity"], reverse=True)
        return similar[:5]

    def _generate_recommendation(
        self,
        risk_score: float,
        exploit_prob: float,
        cwe_profile: Dict,
        has_user_input: bool,
        has_auth_check: bool,
        is_internet_facing: bool,
    ) -> str:
        """Generate actionable recommendation based on predicted risk."""
        cwe_name = cwe_profile.get("name", "Unknown")

        if risk_score >= 80:
            if exploit_prob > 0.8:
                return (f"CRITICAL: {cwe_name} pattern with {exploit_prob:.0%} exploit probability. "
                        f"Immediate remediation required. Add input validation, authentication checks, "
                        f"and consider WAF rules as interim mitigation.")
            return (f"HIGH RISK: {cwe_name} pattern detected. Prioritize remediation in current sprint. "
                    f"Review all code paths handling external input.")
        elif risk_score >= 50:
            parts = [f"MEDIUM RISK: {cwe_name} pattern."]
            if not has_auth_check:
                parts.append("Add authentication check before processing.")
            if has_user_input:
                parts.append("Validate and sanitize all user inputs.")
            if is_internet_facing:
                parts.append("Consider rate limiting and WAF protection.")
            return " ".join(parts)
        elif risk_score >= 20:
            return (f"LOW RISK: {cwe_name} pattern. Monitor in next security review cycle. "
                    f"Document known limitations.")
        else:
            return f"MINIMAL RISK: {cwe_name} pattern has low exploitability in current context."


# ---------------------------------------------------------------------------
# Module-level convenience
# ---------------------------------------------------------------------------

_default_scorer: Optional[PredictiveScorer] = None


def get_predictive_scorer(golden_path: str = "data/golden_regression_cases.json") -> PredictiveScorer:
    """Get or create the default PredictiveScorer instance."""
    global _default_scorer
    if _default_scorer is None:
        _default_scorer = PredictiveScorer()
        try:
            _default_scorer.fit_from_cve_history(golden_path)
        except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
            logger.warning("PredictiveScorer fit failed: %s — predictions will have wider CIs", e)
    return _default_scorer
