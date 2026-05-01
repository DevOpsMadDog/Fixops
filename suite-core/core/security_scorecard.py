"""
⚠️  SIMULATED DATA — NOT FOR PRODUCTION OR DEMO USE  ⚠️

This engine generates randomized/hash-derived scores for development/testing.
DO NOT use the output in customer-facing screens or pitches.

Real implementation tracking:
- Org-wide security scoring: requires aggregation of real scanner findings via
  /api/v1/connectors/{sast,dast,secrets,container,cspm}/configure
- Category scores (_simulate_score lines 188-220) are seeded from org_id+category
  hash — not from real platform data.

Until real data pipelines are wired, these endpoints return a structured
warning header so callers can detect simulation mode.

Security Scorecard for ALDECI — SecurityScorecard-style self-hosted scoring.

Provides organization-wide security grades computed from all platform data:
findings, connectors, scanner results, compliance posture, threat intel.

Categories mirror SecurityScorecard's methodology:
  NETWORK, APPLICATION, PATCHING, DNS, ENDPOINT,
  IP_REPUTATION, SOCIAL_ENGINEERING, INFORMATION_LEAK

Vision Pillars: V1 (APP_ID-Centric), V3 (Decision Intelligence), V9 (Air-Gapped)
License: Proprietary (ALdeci).
"""

from __future__ import annotations

import json
import logging
import random
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)
logger.warning(
    "⚠️  %s loaded in SIMULATION mode — output is randomized/hash-derived; do not present in demos. "
    "Configure real connectors via /api/v1/connectors/",
    __name__,
)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class ScoreCategory(str, Enum):
    """Security scoring categories aligned with industry scorecard methodology."""

    NETWORK = "network"
    APPLICATION = "application"
    PATCHING = "patching"
    DNS = "dns"
    ENDPOINT = "endpoint"
    IP_REPUTATION = "ip_reputation"
    SOCIAL_ENGINEERING = "social_engineering"
    INFORMATION_LEAK = "information_leak"


# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------


class SecurityScore(BaseModel):
    """Full scorecard for an organization at a point in time."""

    id: str
    org_id: str
    overall_score: float = Field(ge=0, le=100, description="Aggregate score 0–100")
    grade: str = Field(description="Letter grade A–F")
    categories: Dict[str, float] = Field(
        default_factory=dict,
        description="Per-category scores keyed by ScoreCategory value",
    )
    factors: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Individual scoring factors with weight, score, and detail",
    )
    generated_at: str
    valid_until: str


class PublicScore(BaseModel):
    """Shareable external scorecard (limited information)."""

    org_id: str
    overall_score: float
    grade: str
    generated_at: str
    valid_until: str
    category_grades: Dict[str, str] = Field(
        default_factory=dict,
        description="Per-category letter grades (no raw scores exposed)",
    )


# ---------------------------------------------------------------------------
# Scoring weights
# ---------------------------------------------------------------------------

# Weights must sum to 1.0
CATEGORY_WEIGHTS: Dict[ScoreCategory, float] = {
    ScoreCategory.NETWORK: 0.20,
    ScoreCategory.APPLICATION: 0.20,
    ScoreCategory.PATCHING: 0.15,
    ScoreCategory.DNS: 0.10,
    ScoreCategory.ENDPOINT: 0.15,
    ScoreCategory.IP_REPUTATION: 0.10,
    ScoreCategory.SOCIAL_ENGINEERING: 0.05,
    ScoreCategory.INFORMATION_LEAK: 0.05,
}


# ---------------------------------------------------------------------------
# SecurityScorecard
# ---------------------------------------------------------------------------


class SecurityScorecard:
    """SQLite-backed security scorecard engine.

    Computes organization-wide security grades from all available platform
    data.  In a real deployment, each _score_* method would query live
    findings, connector data, scanner results, and threat intel feeds.
    The simulation approach used here produces deterministic, reproducible
    scores based on org_id — safe for testing without external dependencies.
    """

    def __init__(self, db_path: str = "data/security_scorecard.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_tables()

    # ------------------------------------------------------------------
    # DB helpers
    # ------------------------------------------------------------------

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_tables(self) -> None:
        with self._get_conn() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS scorecards (
                    id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL,
                    overall_score REAL NOT NULL,
                    grade TEXT NOT NULL,
                    categories TEXT NOT NULL DEFAULT '{}',
                    factors TEXT NOT NULL DEFAULT '[]',
                    generated_at TEXT NOT NULL,
                    valid_until TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_scorecards_org_id
                    ON scorecards(org_id);
                CREATE INDEX IF NOT EXISTS idx_scorecards_generated_at
                    ON scorecards(generated_at);
                """
            )

    def _row_to_score(self, row: sqlite3.Row) -> SecurityScore:
        return SecurityScore(
            id=row["id"],
            org_id=row["org_id"],
            overall_score=row["overall_score"],
            grade=row["grade"],
            categories=json.loads(row["categories"]),
            factors=json.loads(row["factors"]),
            generated_at=row["generated_at"],
            valid_until=row["valid_until"],
        )

    # ------------------------------------------------------------------
    # Grade helpers
    # ------------------------------------------------------------------

    def _score_to_grade(self, score: float) -> str:
        """Map numeric score to letter grade (A–F)."""
        if score >= 90:
            return "A"
        if score >= 80:
            return "B"
        if score >= 70:
            return "C"
        if score >= 60:
            return "D"
        return "F"

    # ------------------------------------------------------------------
    # Category scoring simulation
    # ------------------------------------------------------------------

    def _make_rng(self, org_id: str, category: str) -> random.Random:
        """Deterministic RNG seeded from org_id + category for reproducibility."""
        seed = hash(f"{org_id}:{category}") % (2**32)
        return random.Random(seed)

    def _simulate_score(self, org_id: str, category: str) -> tuple[float, List[Dict[str, Any]]]:
        """Simulate a category score with sub-factors.

        Returns (score 0-100, list of factor dicts).
        In production this would query real platform data.
        """
        rng = self._make_rng(org_id, category)

        def _s(base: float, var: float) -> float:
            return round(max(0.0, min(100.0, base + rng.uniform(-var, var))), 2)

        # Base score heuristic: mix of org_id hash and category
        base = 55.0 + (hash(org_id) % 30)

        if category == ScoreCategory.NETWORK:
            factors = [
                {"name": "open_ports", "score": _s(base, 15), "weight": 0.30, "detail": "Exposed network services"},
                {"name": "firewall_config", "score": _s(base + 5, 10), "weight": 0.35, "detail": "Firewall rule hygiene"},
                {"name": "network_segmentation", "score": _s(base - 5, 12), "weight": 0.20, "detail": "Network segmentation posture"},
                {"name": "tls_config", "score": _s(base + 10, 8), "weight": 0.15, "detail": "TLS/SSL configuration quality"},
            ]
        elif category == ScoreCategory.APPLICATION:
            factors = [
                {"name": "vuln_density", "score": _s(base - 5, 18), "weight": 0.35, "detail": "Vulnerability density per KLOC"},
                {"name": "sast_findings", "score": _s(base, 12), "weight": 0.25, "detail": "Static analysis finding rate"},
                {"name": "dependency_risk", "score": _s(base - 10, 15), "weight": 0.25, "detail": "Risky dependency exposure"},
                {"name": "api_security", "score": _s(base + 5, 10), "weight": 0.15, "detail": "API authentication and rate limiting"},
            ]
        elif category == ScoreCategory.PATCHING:
            factors = [
                {"name": "critical_patch_lag", "score": _s(base - 10, 20), "weight": 0.40, "detail": "Days to patch critical CVEs"},
                {"name": "high_patch_lag", "score": _s(base - 5, 15), "weight": 0.30, "detail": "Days to patch high CVEs"},
                {"name": "os_currency", "score": _s(base + 5, 12), "weight": 0.20, "detail": "OS version currency"},
                {"name": "eol_software", "score": _s(base, 10), "weight": 0.10, "detail": "End-of-life software ratio"},
            ]
        elif category == ScoreCategory.DNS:
            factors = [
                {"name": "dnssec", "score": _s(base + 10, 15), "weight": 0.30, "detail": "DNSSEC implementation"},
                {"name": "spf_record", "score": _s(base + 5, 10), "weight": 0.25, "detail": "SPF record validity"},
                {"name": "dmarc_policy", "score": _s(base, 12), "weight": 0.25, "detail": "DMARC policy enforcement"},
                {"name": "dkim_config", "score": _s(base - 5, 8), "weight": 0.20, "detail": "DKIM signing configuration"},
            ]
        elif category == ScoreCategory.ENDPOINT:
            factors = [
                {"name": "edr_coverage", "score": _s(base + 5, 15), "weight": 0.35, "detail": "EDR agent deployment coverage"},
                {"name": "patch_compliance", "score": _s(base, 12), "weight": 0.30, "detail": "Endpoint patch compliance rate"},
                {"name": "encryption_coverage", "score": _s(base + 10, 10), "weight": 0.20, "detail": "Disk encryption coverage"},
                {"name": "mfa_enforcement", "score": _s(base - 5, 18), "weight": 0.15, "detail": "MFA enforcement rate"},
            ]
        elif category == ScoreCategory.IP_REPUTATION:
            factors = [
                {"name": "blocklist_appearances", "score": _s(base + 5, 20), "weight": 0.40, "detail": "IP blocklist presence"},
                {"name": "botnet_activity", "score": _s(base + 10, 12), "weight": 0.30, "detail": "Known botnet C2 activity"},
                {"name": "spam_score", "score": _s(base + 5, 10), "weight": 0.20, "detail": "Email spam reputation"},
                {"name": "tor_exit_node", "score": _s(base + 15, 8), "weight": 0.10, "detail": "Tor exit node presence"},
            ]
        elif category == ScoreCategory.SOCIAL_ENGINEERING:
            factors = [
                {"name": "phishing_susceptibility", "score": _s(base - 5, 15), "weight": 0.40, "detail": "Phishing simulation failure rate"},
                {"name": "security_awareness", "score": _s(base, 12), "weight": 0.35, "detail": "Security awareness training completion"},
                {"name": "credential_exposure", "score": _s(base - 10, 18), "weight": 0.25, "detail": "Credential exposure in breaches"},
            ]
        else:  # INFORMATION_LEAK
            factors = [
                {"name": "data_exposure", "score": _s(base - 5, 15), "weight": 0.35, "detail": "Public data exposure incidents"},
                {"name": "secret_leaks", "score": _s(base - 10, 20), "weight": 0.35, "detail": "Code repository secret leaks"},
                {"name": "dark_web_mentions", "score": _s(base, 12), "weight": 0.30, "detail": "Dark web mention frequency"},
            ]

        # Weighted average
        total_weight = sum(f["weight"] for f in factors)
        weighted_sum = sum(f["score"] * f["weight"] for f in factors)
        score = round(weighted_sum / total_weight, 2) if total_weight > 0 else 50.0
        score = max(0.0, min(100.0, score))

        # Tag each factor with its category
        for f in factors:
            f["category"] = category

        return score, factors

    # ------------------------------------------------------------------
    # Core public API
    # ------------------------------------------------------------------

    def generate_scorecard(self, org_id: str, validity_days: int = 30) -> SecurityScore:
        """Compute a full security scorecard for the given org.

        Scores all 8 categories, computes the weighted overall score,
        assigns a grade, and persists the result.  Returns the new scorecard.
        """
        categories: Dict[str, float] = {}
        all_factors: List[Dict[str, Any]] = []

        for cat in ScoreCategory:
            cat_score, cat_factors = self._simulate_score(org_id, cat.value)
            categories[cat.value] = cat_score
            all_factors.extend(cat_factors)

        # Weighted overall score
        overall = sum(
            categories[cat.value] * weight
            for cat, weight in CATEGORY_WEIGHTS.items()
        )
        overall = round(max(0.0, min(100.0, overall)), 2)
        grade = self._score_to_grade(overall)

        now = datetime.now(timezone.utc)
        scorecard = SecurityScore(
            id=str(uuid.uuid4()),
            org_id=org_id,
            overall_score=overall,
            grade=grade,
            categories=categories,
            factors=all_factors,
            generated_at=now.isoformat(),
            valid_until=(now + timedelta(days=validity_days)).isoformat(),
        )

        with self._get_conn() as conn:
            conn.execute(
                """INSERT INTO scorecards
                   (id, org_id, overall_score, grade, categories, factors,
                    generated_at, valid_until)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    scorecard.id,
                    scorecard.org_id,
                    scorecard.overall_score,
                    scorecard.grade,
                    json.dumps(scorecard.categories),
                    json.dumps(scorecard.factors),
                    scorecard.generated_at,
                    scorecard.valid_until,
                ),
            )

        logger.info(
            "Scorecard generated for org %s: score=%.1f grade=%s",
            org_id, overall, grade,
        )
        return scorecard

    def get_scorecard(self, org_id: str) -> Optional[SecurityScore]:
        """Return the most recent scorecard for the given org, or None."""
        with self._get_conn() as conn:
            row = conn.execute(
                """SELECT * FROM scorecards WHERE org_id = ?
                   ORDER BY generated_at DESC LIMIT 1""",
                (org_id,),
            ).fetchone()
        return self._row_to_score(row) if row else None

    def get_score_history(self, org_id: str, days: int = 90) -> List[Dict[str, Any]]:
        """Return score history for the org over the past N days.

        Each entry contains: generated_at, overall_score, grade.
        """
        since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        with self._get_conn() as conn:
            rows = conn.execute(
                """SELECT id, org_id, overall_score, grade, generated_at
                   FROM scorecards
                   WHERE org_id = ? AND generated_at >= ?
                   ORDER BY generated_at ASC""",
                (org_id, since),
            ).fetchall()
        return [
            {
                "id": r["id"],
                "overall_score": r["overall_score"],
                "grade": r["grade"],
                "generated_at": r["generated_at"],
            }
            for r in rows
        ]

    def get_category_breakdown(self, org_id: str) -> Dict[str, Any]:
        """Return per-category scores from the latest scorecard.

        Includes score, grade, weight, and trend indicator (vs previous scorecard).
        Returns empty dict structure if no scorecard exists.
        """
        latest = self.get_scorecard(org_id)
        if not latest:
            return {"org_id": org_id, "categories": {}, "generated_at": None}

        # Fetch previous scorecard for trend
        with self._get_conn() as conn:
            rows = conn.execute(
                """SELECT categories FROM scorecards
                   WHERE org_id = ? ORDER BY generated_at DESC LIMIT 2""",
                (org_id,),
            ).fetchall()

        prev_categories: Dict[str, float] = {}
        if len(rows) >= 2:
            prev_categories = json.loads(rows[1]["categories"])

        breakdown: Dict[str, Any] = {}
        for cat in ScoreCategory:
            score = latest.categories.get(cat.value, 0.0)
            prev_score = prev_categories.get(cat.value)
            if prev_score is not None:
                delta = round(score - prev_score, 2)
                trend = "improving" if delta > 1 else "degrading" if delta < -1 else "stable"
            else:
                delta = None
                trend = "new"

            breakdown[cat.value] = {
                "score": score,
                "grade": self._score_to_grade(score),
                "weight": CATEGORY_WEIGHTS[cat],
                "trend": trend,
                "delta": delta,
            }

        return {
            "org_id": org_id,
            "overall_score": latest.overall_score,
            "overall_grade": latest.grade,
            "categories": breakdown,
            "generated_at": latest.generated_at,
        }

    def get_improvement_plan(self, org_id: str) -> Dict[str, Any]:
        """Return a prioritized improvement plan to raise the org's score.

        Actions are ranked by expected score impact (weight × gap to 100).
        """
        latest = self.get_scorecard(org_id)
        if not latest:
            return {"org_id": org_id, "actions": [], "generated_at": None}

        actions: List[Dict[str, Any]] = []
        for cat in ScoreCategory:
            score = latest.categories.get(cat.value, 0.0)
            gap = 100.0 - score
            weight = CATEGORY_WEIGHTS[cat]
            impact = round(gap * weight, 2)  # points gained if this cat reaches 100

            if gap < 5:
                priority = "low"
                recommendation = f"Maintain current {cat.value} posture — near optimal."
            elif gap < 20:
                priority = "medium"
                recommendation = _improvement_recommendation(cat, score)
            else:
                priority = "high"
                recommendation = _improvement_recommendation(cat, score)

            actions.append(
                {
                    "category": cat.value,
                    "current_score": score,
                    "current_grade": self._score_to_grade(score),
                    "gap": round(gap, 2),
                    "weight": weight,
                    "estimated_impact": impact,
                    "priority": priority,
                    "recommendation": recommendation,
                }
            )

        # Sort by estimated_impact descending
        actions.sort(key=lambda a: a["estimated_impact"], reverse=True)

        return {
            "org_id": org_id,
            "overall_score": latest.overall_score,
            "overall_grade": latest.grade,
            "actions": actions,
            "generated_at": latest.generated_at,
        }

    def compare_orgs(self, org_ids: List[str]) -> Dict[str, Any]:
        """Compare multiple orgs side-by-side using their latest scorecards.

        Returns a comparison matrix with per-org scores, grades, and
        category-level rankings.
        """
        orgs: List[Dict[str, Any]] = []
        for oid in org_ids:
            sc = self.get_scorecard(oid)
            if sc:
                orgs.append(
                    {
                        "org_id": oid,
                        "overall_score": sc.overall_score,
                        "grade": sc.grade,
                        "categories": sc.categories,
                        "generated_at": sc.generated_at,
                    }
                )
            else:
                orgs.append(
                    {
                        "org_id": oid,
                        "overall_score": None,
                        "grade": None,
                        "categories": {},
                        "generated_at": None,
                        "error": "No scorecard available",
                    }
                )

        # Rank orgs by overall_score (highest first); unscored orgs last
        scored = [o for o in orgs if o["overall_score"] is not None]
        unscored = [o for o in orgs if o["overall_score"] is None]
        scored.sort(key=lambda o: o["overall_score"], reverse=True)  # type: ignore[arg-type]
        for rank, o in enumerate(scored, start=1):
            o["rank"] = rank
        for o in unscored:
            o["rank"] = None

        # Per-category best/worst
        cat_rankings: Dict[str, Any] = {}
        if scored:
            for cat in ScoreCategory:
                cat_scores = [
                    (o["org_id"], o["categories"].get(cat.value))
                    for o in scored
                    if cat.value in o["categories"]
                ]
                if cat_scores:
                    cat_scores.sort(key=lambda x: x[1], reverse=True)  # type: ignore[arg-type]
                    cat_rankings[cat.value] = {
                        "best": cat_scores[0][0],
                        "worst": cat_scores[-1][0],
                    }

        return {
            "orgs": scored + unscored,
            "total": len(orgs),
            "category_rankings": cat_rankings,
        }

    def get_public_score(self, org_id: str) -> Optional[PublicScore]:
        """Return a shareable public scorecard with limited information.

        Exposes overall score, grade, and per-category grades only.
        Raw numeric category scores are withheld.
        """
        sc = self.get_scorecard(org_id)
        if not sc:
            return None

        category_grades = {
            cat_name: self._score_to_grade(cat_score)
            for cat_name, cat_score in sc.categories.items()
        }

        return PublicScore(
            org_id=org_id,
            overall_score=sc.overall_score,
            grade=sc.grade,
            generated_at=sc.generated_at,
            valid_until=sc.valid_until,
            category_grades=category_grades,
        )


# ---------------------------------------------------------------------------
# Improvement recommendation helpers
# ---------------------------------------------------------------------------


_RECOMMENDATIONS: Dict[ScoreCategory, str] = {
    ScoreCategory.NETWORK: (
        "Review firewall rules for over-permissive ingress, audit open ports, "
        "enforce TLS 1.2+ across all services, and segment networks by trust zone."
    ),
    ScoreCategory.APPLICATION: (
        "Integrate SAST/DAST into CI pipelines, enforce dependency scanning, "
        "remediate critical OWASP Top 10 findings, and adopt secure coding training."
    ),
    ScoreCategory.PATCHING: (
        "Establish SLAs for critical CVE patching (<72 h), automate patch deployment "
        "for OS and middleware, and decommission end-of-life software."
    ),
    ScoreCategory.DNS: (
        "Enable DNSSEC, publish strict SPF/DMARC/DKIM records, and monitor for "
        "DNS hijacking or unauthorized zone changes."
    ),
    ScoreCategory.ENDPOINT: (
        "Deploy EDR to 100% of endpoints, enforce disk encryption and MFA, "
        "and automate endpoint patch compliance reporting."
    ),
    ScoreCategory.IP_REPUTATION: (
        "Investigate IPs flagged on blocklists, remediate compromised hosts, "
        "and monitor outbound traffic for botnet C2 patterns."
    ),
    ScoreCategory.SOCIAL_ENGINEERING: (
        "Run quarterly phishing simulations, mandate security awareness training, "
        "and monitor breach databases for credential exposure."
    ),
    ScoreCategory.INFORMATION_LEAK: (
        "Scan code repositories for secrets, configure DLP policies, and subscribe "
        "to dark web monitoring to detect data exposure early."
    ),
}


def _improvement_recommendation(category: ScoreCategory, score: float) -> str:
    """Return a targeted recommendation string for a category."""
    return _RECOMMENDATIONS.get(category, f"Improve {category.value} posture.")
