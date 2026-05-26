"""
Security Scorecard for ALDECI — SecurityScorecard-style self-hosted scoring.

REAL IMPLEMENTATION: category scores are computed from the organisation's
actual security findings (SecurityFindingsEngine), severity-weighted. There
are no hash-derived or simulated values. A category is only scored when the
org has real findings evidence covering it; categories with no scanner
coverage are reported as "not_assessed" (never a fabricated 100 or 0), and the
overall score is the weight-renormalised average over assessed categories only.

Findings flow in from the connector/scanner framework (GitHub connector,
SAST/SCA/secrets/container scanners) via SecurityFindingsEngine.record_finding().
To raise a score: remediate open findings. To add coverage for an unassessed
category: onboard the relevant scanner via /api/v1/connectors/.

Categories mirror SecurityScorecard's methodology:
  NETWORK, APPLICATION, PATCHING, DNS, ENDPOINT,
  IP_REPUTATION, SOCIAL_ENGINEERING, INFORMATION_LEAK

Vision Pillars: V1 (APP_ID-Centric), V3 (Decision Intelligence), V9 (Air-Gapped)
License: Proprietary (ALdeci).
"""

from __future__ import annotations

import json
import logging
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)
logger.info(
    "%s loaded — scores computed from real SecurityFindingsEngine findings "
    "(severity-weighted, coverage-aware). No simulated data.",
    __name__,
)


class ScorecardDataError(ValueError):
    """Raised when a scorecard cannot be computed because the org has no
    security findings to score. Surfaced by the router as HTTP 422 with an
    onboarding hint — never as a fabricated grade."""


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


# Severity → penalty points deducted from a category's 100 baseline per OPEN
# finding. Tuned so a single critical drops a category roughly one grade band.
SEVERITY_PENALTY: Dict[str, float] = {
    "critical": 15.0,
    "high": 8.0,
    "medium": 3.0,
    "low": 1.0,
    "info": 0.25,
    "informational": 0.25,
}

# Ordered finding → category classification. Each tuple lists substrings matched
# against the finding's finding_type/source_tool/title/asset_type (lowercased).
# Order matters: the FIRST category whose keywords match wins, so the most
# specific categories are listed first (secrets before generic "code", etc.).
_CATEGORY_MATCHERS: List[Tuple[ScoreCategory, Tuple[str, ...]]] = [
    (ScoreCategory.INFORMATION_LEAK, (
        "secret", "credential", "leak", "exposed_key", "api_key", "apikey",
        "password", "pii", "gitleaks", "trufflehog", "detect-secrets", "ggshield",
    )),
    (ScoreCategory.ENDPOINT, (
        "container", "image", "docker", "cis", "benchmark", "iac",
        "kubernetes", "k8s", "misconfiguration", "misconfig", "trivy-image",
        "dockle", "kube-bench", "checkov", "kics", "tfsec", "kubescape", "host",
    )),
    (ScoreCategory.PATCHING, (
        "sca", "dependency", "dependencies", "package", "library", "outdated",
        "eol", "cve-", "grype", "dependabot", "osv", "npm-audit", "pip-audit",
        "safety", "vulnerable_dependency", "transitive",
    )),
    (ScoreCategory.IP_REPUTATION, (
        "ip_reputation", "malicious_ip", "blocklist", "botnet", "c2", "ioc",
        "abuseipdb", "greynoise", "threatfox",
    )),
    (ScoreCategory.DNS, (
        "dns", "spf", "dkim", "dmarc", "dnssec", "subdomain", "dnsrecon", "dnstwist",
    )),
    (ScoreCategory.NETWORK, (
        "network", "open_port", "port", "tls", "ssl", "certificate", "firewall",
        "exposed_service", "nmap", "masscan", "sslyze", "testssl",
    )),
    (ScoreCategory.SOCIAL_ENGINEERING, (
        "phishing", "social_engineering", "awareness", "breach",
        "haveibeenpwned", "hibp", "gophish",
    )),
    (ScoreCategory.APPLICATION, (
        "sast", "code", "xss", "sql", "injection", "csrf", "ssrf", "deserial",
        "xxe", "owasp", "dast", "web", "semgrep", "bandit", "codeql", "sonar",
        "zap", "burp", "application",
    )),
]
# Generic findings with no specific signal fall back to APPLICATION (the
# broadest software-security category) so they are still counted, never dropped.
_DEFAULT_CATEGORY = ScoreCategory.APPLICATION


# ---------------------------------------------------------------------------
# SecurityScorecard
# ---------------------------------------------------------------------------


class SecurityScorecard:
    """SQLite-backed security scorecard engine.

    Computes organization-wide security grades from the org's real security
    findings (SecurityFindingsEngine). Each category starts at 100 and loses
    severity-weighted points per open finding mapped to it. Only categories
    with real findings evidence are scored; the overall is the renormalised
    weighted average over those assessed categories.
    """

    def __init__(self, db_path: str = "data/security_scorecard.db", findings_engine: Any = None):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_tables()
        self._injected_findings_engine = findings_engine

    def _findings_engine(self) -> Any:
        """Return the SecurityFindingsEngine used to source real findings.

        Lazily imported (no hard import-time dependency) and injectable for
        tests via the ``findings_engine`` constructor arg.
        """
        if self._injected_findings_engine is None:
            from core.security_findings_engine import SecurityFindingsEngine
            self._injected_findings_engine = SecurityFindingsEngine()
        return self._injected_findings_engine

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
    # Finding classification (real data)
    # ------------------------------------------------------------------

    @staticmethod
    def _categorize_finding(finding: Dict[str, Any]) -> ScoreCategory:
        """Map a real finding to a scorecard category by its type/tool keywords.

        Matches finding_type/source_tool/title/asset_type (lowercased) against
        the ordered ``_CATEGORY_MATCHERS``; falls back to APPLICATION so no
        finding is silently dropped from scoring.
        """
        haystack = " ".join(
            str(finding.get(k, "")).lower()
            for k in ("finding_type", "source_tool", "title", "asset_type")
        )
        for category, keywords in _CATEGORY_MATCHERS:
            if any(kw in haystack for kw in keywords):
                return category
        return _DEFAULT_CATEGORY

    # ------------------------------------------------------------------
    # Core public API
    # ------------------------------------------------------------------

    def generate_scorecard(self, org_id: str, validity_days: int = 30) -> SecurityScore:
        """Compute a real scorecard from the org's actual security findings.

        Pulls findings from SecurityFindingsEngine, maps each to a category,
        and deducts severity-weighted penalty points from each assessed
        category's 100 baseline (only OPEN findings deduct; resolved/suppressed
        findings still prove coverage). The overall score is the
        weight-renormalised average over assessed categories only — categories
        with no findings evidence are reported as not_assessed, never faked.

        Raises ScorecardDataError when the org has no findings at all, so a
        scorecard is never fabricated from thin air.
        """
        findings = self._findings_engine().list_findings(org_id)
        if not findings:
            raise ScorecardDataError(
                f"No security findings for org '{org_id}'. Onboard a scanner "
                "(SAST, SCA, secrets, or container) via /api/v1/connectors/ and "
                "run a scan before generating a scorecard."
            )

        # Bucket findings by category. Presence of ANY finding (any status)
        # marks a category 'assessed' — proof a scanner covered it.
        buckets: Dict[str, List[Dict[str, Any]]] = {}
        for f in findings:
            buckets.setdefault(self._categorize_finding(f).value, []).append(f)

        categories: Dict[str, float] = {}
        all_factors: List[Dict[str, Any]] = []
        for cat_value, cat_findings in buckets.items():
            open_findings = [
                f for f in cat_findings if (f.get("status") or "open") == "open"
            ]
            penalty = 0.0
            sev_counts: Dict[str, int] = {}
            for f in open_findings:
                sev = str(f.get("severity", "medium")).lower()
                penalty += SEVERITY_PENALTY.get(sev, SEVERITY_PENALTY["medium"])
                sev_counts[sev] = sev_counts.get(sev, 0) + 1
            score = round(max(0.0, min(100.0, 100.0 - penalty)), 2)
            categories[cat_value] = score
            all_factors.append({
                "category": cat_value,
                "score": score,
                "open_findings": len(open_findings),
                "total_findings": len(cat_findings),
                "severity_breakdown": sev_counts,
                "penalty_points": round(penalty, 2),
                "detail": (
                    f"{len(open_findings)} open of {len(cat_findings)} finding(s) "
                    "from real scanner data"
                ),
            })

        # Overall = renormalised weighted average over ASSESSED categories only.
        assessed_weight = sum(CATEGORY_WEIGHTS[ScoreCategory(c)] for c in categories) or 1.0
        overall = sum(
            categories[c] * CATEGORY_WEIGHTS[ScoreCategory(c)] for c in categories
        ) / assessed_weight
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
                    scorecard.id, scorecard.org_id, scorecard.overall_score,
                    scorecard.grade, json.dumps(scorecard.categories),
                    json.dumps(scorecard.factors), scorecard.generated_at,
                    scorecard.valid_until,
                ),
            )
        logger.info(
            "Generated scorecard for org %s: %.1f (%s) across %d assessed categories",
            org_id, overall, grade, len(categories),
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
            # A category absent from the latest scorecard has no scanner
            # coverage — report it honestly as not_assessed, never 0/F.
            if cat.value not in latest.categories:
                breakdown[cat.value] = {
                    "score": None,
                    "grade": "N/A",
                    "weight": CATEGORY_WEIGHTS[cat],
                    "trend": "not_assessed",
                    "delta": None,
                    "assessed": False,
                }
                continue

            score = latest.categories[cat.value]
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
                "assessed": True,
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
            weight = CATEGORY_WEIGHTS[cat]

            # Not assessed → the highest-value action is gaining visibility.
            if cat.value not in latest.categories:
                actions.append({
                    "category": cat.value,
                    "type": "coverage",
                    "current_score": None,
                    "current_grade": "N/A",
                    "gap": None,
                    "weight": weight,
                    "estimated_impact": None,
                    "priority": "medium",
                    "recommendation": (
                        f"No {cat.value} coverage — onboard the relevant scanner via "
                        "/api/v1/connectors/. This category is excluded from your score "
                        "until real findings evidence exists."
                    ),
                })
                continue

            score = latest.categories[cat.value]
            gap = 100.0 - score
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
                    "type": "remediation",
                    "current_score": score,
                    "current_grade": self._score_to_grade(score),
                    "gap": round(gap, 2),
                    "weight": weight,
                    "estimated_impact": impact,
                    "priority": priority,
                    "recommendation": recommendation,
                }
            )

        # Sort by estimated_impact desc; coverage actions (None impact) sink last.
        actions.sort(
            key=lambda a: a["estimated_impact"] if a["estimated_impact"] is not None else -1.0,
            reverse=True,
        )

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
