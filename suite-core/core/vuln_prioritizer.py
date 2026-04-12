"""
VulnPrioritizer — ML-based vulnerability prioritization for ALDECI.

Ranks findings by exploitability risk using multiple weighted signals:
  - CVSS score, EPSS score, asset criticality, exposure level
  - Exploit availability, age, CWE severity, patch status, attack path

Architecture:
  - VulnPrioritizer: stateless scoring engine (weights configurable)
  - RiskFactor: individual signal with weight and source
  - PrioritizedFinding: scored + ranked finding with explanation
"""

from __future__ import annotations

import json
import logging
import math
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Default weight configuration
# ---------------------------------------------------------------------------
_DEFAULT_WEIGHTS: Dict[str, float] = {
    "cvss_score": 0.25,
    "epss_score": 0.20,
    "asset_criticality": 0.15,
    "exposure_level": 0.15,
    "exploit_available": 0.10,
    "age_days": 0.05,
    "cwe_severity_weight": 0.00,  # informational — folded into combined score
    "has_patch": 0.05,
    "in_attack_path": 0.05,
}

# CWE severity lookup (higher = more dangerous)
_CWE_SEVERITY: Dict[str, float] = {
    "CWE-89": 0.9,   # SQL Injection
    "CWE-79": 0.85,  # XSS
    "CWE-78": 0.95,  # OS Command Injection
    "CWE-22": 0.8,   # Path Traversal
    "CWE-94": 0.9,   # Code Injection
    "CWE-287": 0.85, # Improper Authentication
    "CWE-798": 0.9,  # Hard-coded Credentials
    "CWE-502": 0.85, # Deserialization
    "CWE-918": 0.8,  # SSRF
    "CWE-611": 0.75, # XXE
    "CWE-200": 0.5,  # Info Exposure
    "CWE-400": 0.45, # Uncontrolled Resource Consumption
}

# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class RiskFactor(BaseModel):
    """A single weighted risk signal contributing to a finding's score."""

    name: str = Field(..., description="Factor name (e.g. cvss_score)")
    value: float = Field(..., ge=0.0, le=1.0, description="Normalised value 0-1")
    weight: float = Field(..., ge=0.0, description="Factor weight")
    source: str = Field(..., description="Signal source (e.g. NVD, EPSS, asset_db)")


class PrioritizedFinding(BaseModel):
    """A finding that has been scored and ranked by VulnPrioritizer."""

    finding_id: str
    risk_score: float = Field(..., ge=0.0, le=100.0, description="Composite risk score 0-100")
    rank: int = Field(..., ge=1, description="Rank among all prioritized findings (1 = highest risk)")
    factors: List[RiskFactor]
    explanation: str
    category: str = Field(..., description="critical_now | act_soon | monitor | defer")


# ---------------------------------------------------------------------------
# Feedback store (SQLite, lightweight)
# ---------------------------------------------------------------------------

_FEEDBACK_DB_PATH = Path(__file__).parent.parent / "data" / "vuln_prioritizer_feedback.db"


def _get_feedback_db(db_path: Optional[Path] = None) -> sqlite3.Connection:
    path = db_path or _FEEDBACK_DB_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS analyst_feedback (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_id  TEXT NOT NULL,
            analyst_priority TEXT NOT NULL,
            recorded_at TEXT NOT NULL
        )
        """
    )
    conn.commit()
    return conn


# ---------------------------------------------------------------------------
# VulnPrioritizer
# ---------------------------------------------------------------------------


class VulnPrioritizer:
    """Scores and ranks vulnerability findings by exploitability risk.

    All scoring is deterministic and weight-configurable. Analyst feedback
    is persisted for future model tuning.
    """

    def __init__(
        self,
        weights: Optional[Dict[str, float]] = None,
        db_path: Optional[Path] = None,
    ) -> None:
        self._weights: Dict[str, float] = dict(_DEFAULT_WEIGHTS)
        if weights:
            self._weights.update(weights)
        self._db_path: Optional[Path] = db_path

    # ------------------------------------------------------------------
    # Feature extraction
    # ------------------------------------------------------------------

    def extract_features(self, finding: Dict[str, Any]) -> Dict[str, float]:
        """Extract normalised numeric features from a raw finding dict.

        Returns a dict of feature_name → float in [0, 1] (except age_days
        which is returned as days before normalisation in calculate_risk_score).
        """
        features: Dict[str, float] = {}

        # CVSS (0-10 → 0-1)
        cvss_raw = finding.get("cvss_score") or finding.get("cvss") or 0.0
        try:
            features["cvss_score"] = float(cvss_raw) / 10.0
        except (TypeError, ValueError):
            features["cvss_score"] = 0.0
        features["cvss_score"] = max(0.0, min(1.0, features["cvss_score"]))

        # EPSS (already 0-1)
        epss_raw = finding.get("epss_score") or finding.get("epss") or 0.0
        try:
            features["epss_score"] = float(epss_raw)
        except (TypeError, ValueError):
            features["epss_score"] = 0.0
        features["epss_score"] = max(0.0, min(1.0, features["epss_score"]))

        # Asset criticality (0-1 or mapped from string)
        ac_raw = finding.get("asset_criticality") or finding.get("criticality") or 0.5
        if isinstance(ac_raw, str):
            ac_map = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.2, "none": 0.0}
            features["asset_criticality"] = ac_map.get(ac_raw.lower(), 0.5)
        else:
            try:
                features["asset_criticality"] = float(ac_raw)
            except (TypeError, ValueError):
                features["asset_criticality"] = 0.5
        features["asset_criticality"] = max(0.0, min(1.0, features["asset_criticality"]))

        # Exposure level: external=1.0, dmz=0.6, internal=0.3, none=0.0
        exposure_raw = finding.get("exposure_level") or finding.get("exposure") or "internal"
        if isinstance(exposure_raw, (int, float)):
            features["exposure_level"] = max(0.0, min(1.0, float(exposure_raw)))
        else:
            exp_map = {
                "external": 1.0,
                "internet-facing": 1.0,
                "public": 1.0,
                "dmz": 0.6,
                "semi-public": 0.6,
                "internal": 0.3,
                "private": 0.3,
                "none": 0.0,
                "isolated": 0.0,
            }
            features["exposure_level"] = exp_map.get(str(exposure_raw).lower(), 0.3)

        # Exploit available (boolean → 0/1)
        exploit_raw = finding.get("exploit_available") or finding.get("has_exploit") or False
        if isinstance(exploit_raw, bool):
            features["exploit_available"] = 1.0 if exploit_raw else 0.0
        elif isinstance(exploit_raw, (int, float)):
            features["exploit_available"] = 1.0 if exploit_raw else 0.0
        else:
            features["exploit_available"] = 1.0 if str(exploit_raw).lower() in ("true", "yes", "1") else 0.0

        # Age in days (raw, normalised in scoring with log decay)
        age_raw = finding.get("age_days") or finding.get("days_open") or 0
        try:
            features["age_days"] = float(age_raw)
        except (TypeError, ValueError):
            features["age_days"] = 0.0

        # CWE severity weight
        cwe_id = str(finding.get("cwe_id") or finding.get("cwe") or "")
        if not cwe_id.upper().startswith("CWE-"):
            cwe_id = f"CWE-{cwe_id}" if cwe_id else ""
        features["cwe_severity_weight"] = _CWE_SEVERITY.get(cwe_id.upper(), 0.5)

        # Has patch (boolean → 0=patched 1=unpatched, so higher = more risky for unpatched)
        has_patch_raw = finding.get("has_patch") or finding.get("patch_available") or False
        if isinstance(has_patch_raw, bool):
            # no patch available → higher risk
            features["has_patch"] = 0.0 if has_patch_raw else 1.0
        elif isinstance(has_patch_raw, (int, float)):
            features["has_patch"] = 0.0 if has_patch_raw else 1.0
        else:
            has_patch_str = str(has_patch_raw).lower()
            features["has_patch"] = 0.0 if has_patch_str in ("true", "yes", "1") else 1.0

        # In attack path (boolean → 0/1)
        atp_raw = finding.get("in_attack_path") or finding.get("attack_path") or False
        if isinstance(atp_raw, bool):
            features["in_attack_path"] = 1.0 if atp_raw else 0.0
        elif isinstance(atp_raw, (int, float)):
            features["in_attack_path"] = 1.0 if atp_raw else 0.0
        else:
            features["in_attack_path"] = 1.0 if str(atp_raw).lower() in ("true", "yes", "1") else 0.0

        return features

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------

    def calculate_risk_score(self, features: Dict[str, float]) -> float:
        """Compute weighted composite risk score (0-100).

        Age is log-normalised (older unresolved = higher risk, capped at 1.0).
        CVSS and EPSS dominate; exploit availability and attack path apply
        multiplicative boosts.
        """
        w = self._weights

        # Age: log-normalise to [0, 1] — 30 days → ~0.5, 365 days → ~1.0
        age_days = max(0.0, features.get("age_days", 0.0))
        age_norm = min(1.0, math.log1p(age_days) / math.log1p(365))

        base = (
            w.get("cvss_score", 0.25) * features.get("cvss_score", 0.0)
            + w.get("epss_score", 0.20) * features.get("epss_score", 0.0)
            + w.get("asset_criticality", 0.15) * features.get("asset_criticality", 0.0)
            + w.get("exposure_level", 0.15) * features.get("exposure_level", 0.0)
            + w.get("exploit_available", 0.10) * features.get("exploit_available", 0.0)
            + w.get("age_days", 0.05) * age_norm
            + w.get("has_patch", 0.05) * features.get("has_patch", 0.0)
            + w.get("in_attack_path", 0.05) * features.get("in_attack_path", 0.0)
        )

        # Normalise base by sum of active weights (so scores remain 0-1 even with custom weights)
        total_weight = sum(
            v for k, v in w.items()
            if k not in ("cwe_severity_weight",)
        )
        if total_weight > 0:
            normalised = base / total_weight
        else:
            normalised = base

        # CWE acts as a mild multiplicative modifier (±10%)
        cwe_factor = features.get("cwe_severity_weight", 0.5)
        cwe_modifier = 0.9 + 0.2 * cwe_factor  # range [0.9, 1.1]
        normalised = min(1.0, normalised * cwe_modifier)

        return round(normalised * 100.0, 2)

    # ------------------------------------------------------------------
    # Categorisation
    # ------------------------------------------------------------------

    def categorize(self, score: float) -> str:
        """Map a risk score to an action category.

        >80   → critical_now
        60-80 → act_soon
        30-60 → monitor
        <30   → defer
        """
        if score > 80:
            return "critical_now"
        if score >= 60:
            return "act_soon"
        if score >= 30:
            return "monitor"
        return "defer"

    # ------------------------------------------------------------------
    # Explanation
    # ------------------------------------------------------------------

    def explain_ranking(self, prioritized: PrioritizedFinding) -> str:
        """Return a human-readable explanation of why a finding ranked where it did."""
        top_factors = sorted(prioritized.factors, key=lambda f: f.value * f.weight, reverse=True)[:3]
        factor_parts = ", ".join(
            f"{f.name}={f.value:.2f} (w={f.weight:.2f})" for f in top_factors
        )
        return (
            f"Finding '{prioritized.finding_id}' ranked #{prioritized.rank} "
            f"with risk score {prioritized.risk_score:.1f}/100 (category: {prioritized.category}). "
            f"Top contributing factors: {factor_parts}."
        )

    # ------------------------------------------------------------------
    # Core prioritization
    # ------------------------------------------------------------------

    def prioritize_findings(self, findings: List[Dict[str, Any]]) -> List[PrioritizedFinding]:
        """Score and rank all findings. Returns list sorted by risk_score descending."""
        if not findings:
            return []

        scored: List[tuple[float, str, Dict[str, float], Dict[str, Any]]] = []
        for finding in findings:
            fid = str(finding.get("id") or finding.get("finding_id") or finding.get("_id") or id(finding))
            features = self.extract_features(finding)
            score = self.calculate_risk_score(features)
            scored.append((score, fid, features, finding))

        # Sort descending by score (ties broken by finding_id for stability)
        scored.sort(key=lambda x: (-x[0], x[1]))

        results: List[PrioritizedFinding] = []
        for rank, (score, fid, features, _finding) in enumerate(scored, start=1):
            factors = self._build_factors(features)
            category = self.categorize(score)
            pf = PrioritizedFinding(
                finding_id=fid,
                risk_score=score,
                rank=rank,
                factors=factors,
                explanation="",
                category=category,
            )
            pf.explanation = self.explain_ranking(pf)
            results.append(pf)

        return results

    def _build_factors(self, features: Dict[str, float]) -> List[RiskFactor]:
        """Convert feature dict to list of RiskFactor for a finding."""
        age_days = features.get("age_days", 0.0)
        age_norm = min(1.0, math.log1p(age_days) / math.log1p(365))

        factor_map = {
            "cvss_score": (features.get("cvss_score", 0.0), "NVD"),
            "epss_score": (features.get("epss_score", 0.0), "FIRST EPSS"),
            "asset_criticality": (features.get("asset_criticality", 0.0), "asset_db"),
            "exposure_level": (features.get("exposure_level", 0.0), "network_topology"),
            "exploit_available": (features.get("exploit_available", 0.0), "exploit_db"),
            "age_days": (age_norm, "ticket_system"),
            "cwe_severity_weight": (features.get("cwe_severity_weight", 0.5), "CWE"),
            "has_patch": (features.get("has_patch", 0.0), "patch_db"),
            "in_attack_path": (features.get("in_attack_path", 0.0), "attack_graph"),
        }

        return [
            RiskFactor(
                name=name,
                value=round(value, 4),
                weight=self._weights.get(name, 0.0),
                source=source,
            )
            for name, (value, source) in factor_map.items()
        ]

    # ------------------------------------------------------------------
    # Convenience methods
    # ------------------------------------------------------------------

    def get_top_n(self, findings: List[Dict[str, Any]], n: int) -> List[PrioritizedFinding]:
        """Return the top-N highest-risk findings."""
        prioritized = self.prioritize_findings(findings)
        return prioritized[:n]

    def compare_findings(
        self, finding_a: Dict[str, Any], finding_b: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Side-by-side factor comparison of two findings."""
        features_a = self.extract_features(finding_a)
        features_b = self.extract_features(finding_b)
        score_a = self.calculate_risk_score(features_a)
        score_b = self.calculate_risk_score(features_b)

        fid_a = str(finding_a.get("id") or finding_a.get("finding_id") or "A")
        fid_b = str(finding_b.get("id") or finding_b.get("finding_id") or "B")

        comparison: Dict[str, Any] = {
            "finding_a": {"id": fid_a, "risk_score": score_a, "category": self.categorize(score_a)},
            "finding_b": {"id": fid_b, "risk_score": score_b, "category": self.categorize(score_b)},
            "winner": fid_a if score_a >= score_b else fid_b,
            "score_delta": round(abs(score_a - score_b), 2),
            "factors": {},
        }

        all_factors = set(features_a.keys()) | set(features_b.keys())
        for factor in sorted(all_factors):
            val_a = features_a.get(factor, 0.0)
            val_b = features_b.get(factor, 0.0)
            comparison["factors"][factor] = {
                "finding_a": round(val_a, 4),
                "finding_b": round(val_b, 4),
                "delta": round(val_a - val_b, 4),
            }

        return comparison

    def get_factor_weights(self) -> Dict[str, float]:
        """Return the current weight configuration."""
        return dict(self._weights)

    def update_weights(self, weights: Dict[str, float]) -> None:
        """Adjust factor weights. Only known factors are updated."""
        for key, value in weights.items():
            if key in self._weights:
                self._weights[key] = float(value)
            else:
                logger.warning("VulnPrioritizer: unknown weight key '%s' — ignored", key)

    def train_from_feedback(self, finding_id: str, analyst_priority: str) -> None:
        """Record analyst feedback for future model tuning.

        Args:
            finding_id: ID of the finding being re-prioritized.
            analyst_priority: Analyst's judgement — one of: critical_now, act_soon, monitor, defer.
        """
        try:
            conn = _get_feedback_db(self._db_path)
            conn.execute(
                "INSERT INTO analyst_feedback (finding_id, analyst_priority, recorded_at) VALUES (?, ?, ?)",
                (finding_id, analyst_priority, datetime.now(timezone.utc).isoformat()),
            )
            conn.commit()
            conn.close()
            logger.info("Recorded analyst feedback: %s → %s", finding_id, analyst_priority)
        except (OSError, sqlite3.Error) as exc:
            logger.warning("Failed to record analyst feedback: %s", exc)

    def get_prioritization_stats(self, org_id: str = "") -> Dict[str, Any]:
        """Return distribution stats across prioritized categories.

        Since this engine is stateless (no persistent finding store), stats
        are pulled from analyst feedback records as a proxy.
        """
        try:
            conn = _get_feedback_db(self._db_path)
            rows = conn.execute(
                "SELECT analyst_priority, COUNT(*) as cnt FROM analyst_feedback GROUP BY analyst_priority"
            ).fetchall()
            conn.close()
        except (OSError, sqlite3.Error):
            rows = []

        distribution: Dict[str, int] = {
            "critical_now": 0,
            "act_soon": 0,
            "monitor": 0,
            "defer": 0,
        }
        total = 0
        for row in rows:
            cat, cnt = row
            if cat in distribution:
                distribution[cat] = cnt
                total += cnt

        return {
            "org_id": org_id,
            "total_feedback_records": total,
            "distribution": distribution,
            "weights": self.get_factor_weights(),
            "top_factors": sorted(
                self._weights.items(), key=lambda kv: kv[1], reverse=True
            )[:3],
        }
