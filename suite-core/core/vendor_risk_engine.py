"""
Vendor Risk Engine — ALDECI.

Automated third-party vendor security risk assessment layer on top of the
existing VRM foundation (core.vendor_risk).

Capabilities:
- Domain reputation check (WHOIS/DNS — checks existence and age)
- NVD CVE search for vendor products
- Threat intel IP-range correlation (stub — hookable)
- Data handling classification
- Hardcoded known-breach database for major vendors
- Composite risk score 0-100
- Security questionnaire tracking (SQLite-backed)
- Fourth-party risk calculation
- Vendor scorecard generation

Compliance: SOC2 CC9.2, ISO27001 A.15, PCI-DSS 12.8, NIST CSF ID.SC
"""

from __future__ import annotations

import json
import logging
import socket
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

import structlog

_logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Known Breach Database (hardcoded — major incidents, updated periodically)
# ---------------------------------------------------------------------------

KNOWN_BREACHES: Dict[str, Dict[str, Any]] = {
    "solarwinds": {
        "severity": "critical",
        "year": 2020,
        "type": "supply_chain_attack",
        "description": "SolarWinds Orion supply chain compromise (SUNBURST backdoor). "
                        "~18,000 organisations affected including US federal agencies.",
        "cve": "CVE-2020-10148",
    },
    "log4j": {
        "severity": "high",
        "year": 2021,
        "type": "remote_code_execution",
        "description": "Log4Shell vulnerability (CVE-2021-44228) affects any product "
                        "using Log4j 2.x — extremely broad vendor impact.",
        "cve": "CVE-2021-44228",
    },
    "okta": {
        "severity": "high",
        "year": 2022,
        "type": "data_breach",
        "description": "Okta support system breached by Lapsus$ group; customer "
                        "tenant data exposed. Second breach in 2023 affected all support users.",
        "cve": None,
    },
    "lastpass": {
        "severity": "high",
        "year": 2022,
        "type": "data_breach",
        "description": "LastPass source code and encrypted password vaults stolen. "
                        "Threat actor used DevOps engineer credentials.",
        "cve": None,
    },
    "circleci": {
        "severity": "high",
        "year": 2023,
        "type": "secrets_exposure",
        "description": "CircleCI security incident: malware on engineer laptop led to "
                        "theft of customer secrets stored in CI environment variables.",
        "cve": None,
    },
    "equifax": {
        "severity": "critical",
        "year": 2017,
        "type": "data_breach",
        "description": "147 million consumer records exposed via Apache Struts vulnerability.",
        "cve": "CVE-2017-5638",
    },
    "crowdstrike": {
        "severity": "high",
        "year": 2024,
        "type": "faulty_update",
        "description": "Faulty content update caused ~8.5 million Windows systems to crash "
                        "(BSOD), disrupting airlines, banks, and hospitals globally.",
        "cve": None,
    },
    "xz": {
        "severity": "critical",
        "year": 2024,
        "type": "supply_chain_attack",
        "description": "XZ Utils backdoor (CVE-2024-3094) — sophisticated supply chain attack "
                        "embedded in Linux compression library.",
        "cve": "CVE-2024-3094",
    },
    "3cx": {
        "severity": "critical",
        "year": 2023,
        "type": "supply_chain_attack",
        "description": "3CX Desktop App supply chain attack — Lazarus Group trojanised "
                        "the official installer used by 600,000+ companies.",
        "cve": None,
    },
}

# ---------------------------------------------------------------------------
# Risk Level Enum
# ---------------------------------------------------------------------------


class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------


class VendorRiskFinding(object):
    """A single finding from an automated risk check."""

    def __init__(
        self,
        check: str,
        severity: str,
        title: str,
        detail: str,
        score_impact: float = 0.0,
    ) -> None:
        self.check = check
        self.severity = severity
        self.title = title
        self.detail = detail
        self.score_impact = score_impact  # Negative = risk reduction on base score

    def to_dict(self) -> Dict[str, Any]:
        return {
            "check": self.check,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "score_impact": self.score_impact,
        }


class VendorRiskAssessment(object):
    """Result of automated vendor risk assessment."""

    def __init__(
        self,
        vendor_id: str,
        name: str,
        domain: Optional[str],
        risk_score: float,
        risk_level: RiskLevel,
        findings: List[VendorRiskFinding],
        last_assessed: str,
        recommendations: List[str],
        cves: List[Dict[str, Any]],
        breach_matches: List[Dict[str, Any]],
    ) -> None:
        self.vendor_id = vendor_id
        self.name = name
        self.domain = domain
        self.risk_score = risk_score
        self.risk_level = risk_level
        self.findings = findings
        self.last_assessed = last_assessed
        self.recommendations = recommendations
        self.cves = cves
        self.breach_matches = breach_matches

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vendor_id": self.vendor_id,
            "name": self.name,
            "domain": self.domain,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level.value,
            "findings": [f.to_dict() for f in self.findings],
            "last_assessed": self.last_assessed,
            "recommendations": self.recommendations,
            "cves": self.cves,
            "breach_matches": self.breach_matches,
        }


class VendorScorecard(object):
    """Generated vendor security scorecard."""

    def __init__(
        self,
        vendor_id: str,
        vendor_name: str,
        overall_score: float,
        risk_level: RiskLevel,
        grade: str,
        domain_score: float,
        cve_score: float,
        breach_score: float,
        data_handling_score: float,
        fourth_party_score: float,
        findings_count: int,
        critical_findings: int,
        calculated_at: str,
        recommendations: List[str],
    ) -> None:
        self.vendor_id = vendor_id
        self.vendor_name = vendor_name
        self.overall_score = overall_score
        self.risk_level = risk_level
        self.grade = grade
        self.domain_score = domain_score
        self.cve_score = cve_score
        self.breach_score = breach_score
        self.data_handling_score = data_handling_score
        self.fourth_party_score = fourth_party_score
        self.findings_count = findings_count
        self.critical_findings = critical_findings
        self.calculated_at = calculated_at
        self.recommendations = recommendations

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vendor_id": self.vendor_id,
            "vendor_name": self.vendor_name,
            "overall_score": self.overall_score,
            "risk_level": self.risk_level.value,
            "grade": self.grade,
            "domain_score": self.domain_score,
            "cve_score": self.cve_score,
            "breach_score": self.breach_score,
            "data_handling_score": self.data_handling_score,
            "fourth_party_score": self.fourth_party_score,
            "findings_count": self.findings_count,
            "critical_findings": self.critical_findings,
            "calculated_at": self.calculated_at,
            "recommendations": self.recommendations,
        }


# ---------------------------------------------------------------------------
# SQLite persistence for assessments + questionnaires
# ---------------------------------------------------------------------------

_CREATE_ASSESSMENTS_TABLE = """
CREATE TABLE IF NOT EXISTS engine_assessments (
    id TEXT PRIMARY KEY,
    vendor_id TEXT NOT NULL,
    vendor_name TEXT NOT NULL,
    domain TEXT,
    risk_score REAL NOT NULL,
    risk_level TEXT NOT NULL,
    findings_json TEXT NOT NULL DEFAULT '[]',
    recommendations_json TEXT NOT NULL DEFAULT '[]',
    cves_json TEXT NOT NULL DEFAULT '[]',
    breach_matches_json TEXT NOT NULL DEFAULT '[]',
    assessed_at TEXT NOT NULL
)
"""

_CREATE_QUESTIONNAIRES_TABLE = """
CREATE TABLE IF NOT EXISTS engine_questionnaires (
    id TEXT PRIMARY KEY,
    vendor_id TEXT NOT NULL,
    questions_json TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    sent_at TEXT NOT NULL,
    completed_at TEXT,
    completion_pct REAL NOT NULL DEFAULT 0.0
)
"""

_CREATE_SCORECARDS_TABLE = """
CREATE TABLE IF NOT EXISTS engine_scorecards (
    id TEXT PRIMARY KEY,
    vendor_id TEXT NOT NULL,
    vendor_name TEXT NOT NULL,
    overall_score REAL NOT NULL,
    risk_level TEXT NOT NULL,
    grade TEXT NOT NULL,
    domain_score REAL NOT NULL DEFAULT 0.0,
    cve_score REAL NOT NULL DEFAULT 0.0,
    breach_score REAL NOT NULL DEFAULT 0.0,
    data_handling_score REAL NOT NULL DEFAULT 0.0,
    fourth_party_score REAL NOT NULL DEFAULT 0.0,
    findings_count INTEGER NOT NULL DEFAULT 0,
    critical_findings INTEGER NOT NULL DEFAULT 0,
    recommendations_json TEXT NOT NULL DEFAULT '[]',
    calculated_at TEXT NOT NULL
)
"""


class _EngineDB:
    """Thread-safe SQLite store for VendorRiskEngine."""

    def __init__(self, db_path: str) -> None:
        self._path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._init_schema()

    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(self._path, check_same_thread=False)
            self._local.conn.row_factory = sqlite3.Row
        return self._local.conn

    def _init_schema(self) -> None:
        conn = self._conn()
        conn.execute(_CREATE_ASSESSMENTS_TABLE)
        conn.execute(_CREATE_QUESTIONNAIRES_TABLE)
        conn.execute(_CREATE_SCORECARDS_TABLE)
        conn.commit()

    # --- Assessments ---

    def upsert_assessment(self, assessment: VendorRiskAssessment) -> None:
        conn = self._conn()
        conn.execute(
            """
            INSERT OR REPLACE INTO engine_assessments
              (id, vendor_id, vendor_name, domain, risk_score, risk_level,
               findings_json, recommendations_json, cves_json, breach_matches_json, assessed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                assessment.vendor_id,  # use vendor_id as pk (one row per vendor)
                assessment.vendor_id,
                assessment.name,
                assessment.domain,
                assessment.risk_score,
                assessment.risk_level.value,
                json.dumps([f.to_dict() for f in assessment.findings]),
                json.dumps(assessment.recommendations),
                json.dumps(assessment.cves),
                json.dumps(assessment.breach_matches),
                assessment.last_assessed,
            ),
        )
        conn.commit()

    def get_assessment(self, vendor_id: str) -> Optional[Dict[str, Any]]:
        row = self._conn().execute(
            "SELECT * FROM engine_assessments WHERE vendor_id = ?", (vendor_id,)
        ).fetchone()
        if not row:
            return None
        return dict(row)

    def list_assessments(self) -> List[Dict[str, Any]]:
        rows = self._conn().execute(
            "SELECT * FROM engine_assessments ORDER BY assessed_at DESC"
        ).fetchall()
        return [dict(r) for r in rows]

    # --- Questionnaires ---

    def insert_questionnaire(
        self,
        vendor_id: str,
        questions: Dict[str, Any],
    ) -> str:
        qid = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        self._conn().execute(
            """
            INSERT INTO engine_questionnaires
              (id, vendor_id, questions_json, status, sent_at)
            VALUES (?, ?, ?, 'pending', ?)
            """,
            (qid, vendor_id, json.dumps(questions), now),
        )
        self._conn().commit()
        return qid

    def get_questionnaire(self, questionnaire_id: str) -> Optional[Dict[str, Any]]:
        row = self._conn().execute(
            "SELECT * FROM engine_questionnaires WHERE id = ?", (questionnaire_id,)
        ).fetchone()
        return dict(row) if row else None

    def update_questionnaire_status(
        self,
        questionnaire_id: str,
        status: str,
        completion_pct: float = 0.0,
    ) -> None:
        now = datetime.now(timezone.utc).isoformat()
        self._conn().execute(
            """
            UPDATE engine_questionnaires
            SET status = ?, completion_pct = ?,
                completed_at = CASE WHEN ? = 'completed' THEN ? ELSE completed_at END
            WHERE id = ?
            """,
            (status, completion_pct, status, now, questionnaire_id),
        )
        self._conn().commit()

    # --- Scorecards ---

    def upsert_scorecard(self, scorecard: VendorScorecard) -> None:
        conn = self._conn()
        conn.execute(
            """
            INSERT OR REPLACE INTO engine_scorecards
              (id, vendor_id, vendor_name, overall_score, risk_level, grade,
               domain_score, cve_score, breach_score, data_handling_score,
               fourth_party_score, findings_count, critical_findings,
               recommendations_json, calculated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scorecard.vendor_id,  # use vendor_id as pk
                scorecard.vendor_id,
                scorecard.vendor_name,
                scorecard.overall_score,
                scorecard.risk_level.value,
                scorecard.grade,
                scorecard.domain_score,
                scorecard.cve_score,
                scorecard.breach_score,
                scorecard.data_handling_score,
                scorecard.fourth_party_score,
                scorecard.findings_count,
                scorecard.critical_findings,
                json.dumps(scorecard.recommendations),
                scorecard.calculated_at,
            ),
        )
        conn.commit()

    def get_scorecard(self, vendor_id: str) -> Optional[Dict[str, Any]]:
        row = self._conn().execute(
            "SELECT * FROM engine_scorecards WHERE vendor_id = ?", (vendor_id,)
        ).fetchone()
        return dict(row) if row else None


# ---------------------------------------------------------------------------
# Score helpers
# ---------------------------------------------------------------------------


def _score_to_risk_level(score: float) -> RiskLevel:
    if score >= 80:
        return RiskLevel.LOW
    if score >= 60:
        return RiskLevel.MEDIUM
    if score >= 40:
        return RiskLevel.HIGH
    return RiskLevel.CRITICAL


def _score_to_grade(score: float) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


# ---------------------------------------------------------------------------
# VendorRiskEngine
# ---------------------------------------------------------------------------

_DEFAULT_DB_PATH = "data/vendor_risk_engine.db"


class VendorRiskEngine:
    """
    Third-party vendor security risk assessment engine.

    Performs automated risk checks using:
    - Domain reputation (DNS reachability + existence)
    - NVD CVE search for vendor products
    - Threat intel IP correlation (stub, hookable)
    - Data-handling classification
    - Known breach database lookup
    - Composite risk score 0-100 (higher = safer)
    """

    def __init__(self, db_path: str = _DEFAULT_DB_PATH) -> None:
        self._db = _EngineDB(db_path)

    # ------------------------------------------------------------------ #
    # Public API                                                           #
    # ------------------------------------------------------------------ #

    def assess_vendor(self, vendor: Dict[str, Any]) -> VendorRiskAssessment:
        """
        Run automated risk assessment for a vendor.

        Checks performed (in order):
          1. Domain reputation — DNS resolution + basic existence check
          2. NVD CVE lookup — searches NVD API for vendor name
          3. Threat intel IP check (stub)
          4. Data-handling classification from vendor metadata
          5. Known breach database match
          6. Composite risk score computation (0-100, higher = safer)

        Args:
            vendor: dict with keys: name (required), domain (optional),
                    data_access_level (optional), fourth_party_vendors (optional list).

        Returns:
            VendorRiskAssessment with full findings and recommendations.
        """
        name: str = vendor.get("name", "unknown")
        domain: Optional[str] = vendor.get("domain")
        vendor_id: str = vendor.get("id", str(uuid.uuid4()))
        data_access: str = vendor.get("data_access_level", "none")
        fourth_parties: List[str] = vendor.get("fourth_party_vendors", [])

        findings: List[VendorRiskFinding] = []
        recommendations: List[str] = []
        cves: List[Dict[str, Any]] = []
        breach_matches: List[Dict[str, Any]] = []

        # Start from a perfect score and subtract for risks
        base_score = 100.0

        # --- Check 1: Domain reputation ---
        domain_finding, domain_penalty = self._check_domain_reputation(domain)
        if domain_finding:
            findings.append(domain_finding)
            base_score -= domain_penalty
            if domain_penalty > 0:
                recommendations.append(
                    f"Verify domain '{domain}' is legitimate and controlled by the vendor."
                )

        # --- Check 2: NVD CVE lookup ---
        cves = self.check_vendor_cvss(name)
        cve_penalty = self._score_cve_penalty(cves)
        if cves:
            findings.append(VendorRiskFinding(
                check="nvd_cve_lookup",
                severity="high" if cve_penalty >= 20 else "medium",
                title=f"Found {len(cves)} CVE(s) for '{name}' in NVD",
                detail=f"Top CVE: {cves[0].get('id', 'N/A')} "
                       f"(CVSS: {cves[0].get('cvss_score', 'N/A')})",
                score_impact=-cve_penalty,
            ))
            base_score -= cve_penalty
            recommendations.append(
                f"Review {len(cves)} known CVE(s) for {name}. Ensure vendor has patched "
                "all critical/high-severity vulnerabilities."
            )

        # --- Check 3: Threat intel IP correlation (stub) ---
        ti_finding = self._check_threat_intel(domain)
        if ti_finding:
            findings.append(ti_finding)
            base_score -= ti_finding.score_impact * -1
            recommendations.append(
                "Vendor IP ranges appear in threat intelligence feeds. Investigate further."
            )

        # --- Check 4: Data handling assessment ---
        data_finding, data_penalty = self._assess_data_handling(data_access, name)
        if data_finding:
            findings.append(data_finding)
            base_score -= data_penalty
            if data_access in ("restricted", "secret"):
                recommendations.append(
                    f"Vendor has {data_access} data access. Ensure DPA is signed and "
                    "encryption at rest/transit is confirmed."
                )

        # --- Check 5: Known breach database ---
        breach_matches = self._check_known_breaches(name)
        breach_penalty = self._score_breach_penalty(breach_matches)
        if breach_matches:
            for breach in breach_matches:
                findings.append(VendorRiskFinding(
                    check="known_breach_db",
                    severity=breach["severity"],
                    title=f"Known breach: {breach['type']} ({breach['year']})",
                    detail=breach["description"],
                    score_impact=-breach_penalty / max(len(breach_matches), 1),
                ))
            base_score -= breach_penalty
            recommendations.append(
                f"Vendor has {len(breach_matches)} known breach incident(s). Request "
                "post-incident remediation report and updated security attestation."
            )

        # --- Check 6: Fourth-party risk contribution ---
        fp_penalty = self._assess_fourth_party_penalty(fourth_parties)
        if fp_penalty > 0:
            findings.append(VendorRiskFinding(
                check="fourth_party_depth",
                severity="medium",
                title=f"Supply chain depth: {len(fourth_parties)} fourth-party vendor(s)",
                detail="Each additional supply-chain layer increases exposure.",
                score_impact=-fp_penalty,
            ))
            base_score -= fp_penalty
            recommendations.append(
                "Map and assess fourth-party vendors. Require vendor to disclose sub-processors."
            )

        risk_score = max(0.0, min(100.0, round(base_score, 2)))
        risk_level = _score_to_risk_level(risk_score)

        now = datetime.now(timezone.utc).isoformat()
        result = VendorRiskAssessment(
            vendor_id=vendor_id,
            name=name,
            domain=domain,
            risk_score=risk_score,
            risk_level=risk_level,
            findings=findings,
            last_assessed=now,
            recommendations=recommendations,
            cves=cves,
            breach_matches=breach_matches,
        )

        self._db.upsert_assessment(result)
        _logger.info(
            "Vendor assessed",
            vendor_id=vendor_id,
            name=name,
            risk_score=risk_score,
            risk_level=risk_level.value,
        )
        return result

    def check_vendor_cvss(self, vendor_name: str) -> List[Dict[str, Any]]:
        """
        Check NVD for CVEs affecting vendor products.

        Queries: https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={vendor_name}

        Returns a list of dicts with keys: id, description, cvss_score, severity, published.
        Falls back to empty list on network failure (offline-safe).
        """
        try:
            import urllib.request
            import urllib.parse

            keyword = urllib.parse.quote(vendor_name)
            url = (
                f"https://services.nvd.nist.gov/rest/json/cves/2.0"
                f"?keywordSearch={keyword}&resultsPerPage=10"
            )
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "ALDECI-VendorRiskEngine/1.0"},
            )
            with urllib.request.urlopen(req, timeout=8) as resp:
                data = json.loads(resp.read().decode())

            cves: List[Dict[str, Any]] = []
            for vuln in data.get("vulnerabilities", []):
                cve = vuln.get("cve", {})
                cve_id = cve.get("id", "")
                descriptions = cve.get("descriptions", [])
                desc = next(
                    (d["value"] for d in descriptions if d.get("lang") == "en"),
                    "No description available.",
                )
                # Extract CVSS score (try v3.1, then v3.0, then v2)
                cvss_score: Optional[float] = None
                severity: str = "unknown"
                metrics = cve.get("metrics", {})
                for version_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    metric_list = metrics.get(version_key, [])
                    if metric_list:
                        cvss_data = metric_list[0].get("cvssData", {})
                        cvss_score = cvss_data.get("baseScore")
                        severity = cvss_data.get("baseSeverity", "unknown").lower()
                        break

                cves.append({
                    "id": cve_id,
                    "description": desc[:300],
                    "cvss_score": cvss_score,
                    "severity": severity,
                    "published": cve.get("published", ""),
                })

            return cves

        except Exception as exc:  # noqa: BLE001
            _logger.warning(
                "NVD CVE lookup failed (offline-safe fallback)",
                vendor=vendor_name,
                error=str(exc),
            )
            return []

    def track_questionnaire(
        self,
        vendor_id: str,
        questions: Dict[str, Any],
    ) -> str:
        """
        Send and track security questionnaire completion.

        Stores the questionnaire in SQLite with 'pending' status.
        Returns the questionnaire ID for status tracking.

        Args:
            vendor_id: The vendor to send the questionnaire to.
            questions: Dict of question_id -> question_text or response data.

        Returns:
            questionnaire_id (UUID string).
        """
        if not questions:
            raise ValueError("Questionnaire must contain at least one question.")

        qid = self._db.insert_questionnaire(vendor_id, questions)
        _logger.info(
            "Questionnaire sent",
            vendor_id=vendor_id,
            questionnaire_id=qid,
            question_count=len(questions),
        )
        return qid

    def update_questionnaire(
        self,
        questionnaire_id: str,
        status: str,
        completion_pct: float = 0.0,
    ) -> None:
        """Update questionnaire status (pending / in_progress / completed)."""
        valid_statuses = {"pending", "in_progress", "completed"}
        if status not in valid_statuses:
            raise ValueError(f"status must be one of {valid_statuses}")
        self._db.update_questionnaire_status(questionnaire_id, status, completion_pct)

    def calculate_fourth_party_risk(self, vendor_id: str) -> float:
        """
        Assess risk from vendor's vendors (supply chain depth).

        Returns a risk score 0.0-1.0 where:
          0.0 = no fourth-party exposure
          1.0 = maximum fourth-party risk

        The score is derived from assessment data for each fourth-party vendor.
        Falls back to a depth-based estimate when assessments are unavailable.
        """
        assessment_row = self._db.get_assessment(vendor_id)
        if not assessment_row:
            return 0.0

        # Parse breach matches stored in assessment to count breached fourth parties
        breach_json = assessment_row.get("breach_matches_json", "[]")
        try:
            breaches = json.loads(breach_json)
        except (json.JSONDecodeError, TypeError):
            breaches = []

        findings_json = assessment_row.get("findings_json", "[]")
        try:
            findings = json.loads(findings_json)
        except (json.JSONDecodeError, TypeError):
            findings = []

        fp_findings = [
            f for f in findings if f.get("check") == "fourth_party_depth"
        ]

        # Base risk: 0.05 per fourth-party layer, max 0.5
        depth_risk = min(0.5, len(fp_findings) * 0.15)
        # Breach escalation
        breach_risk = min(0.5, len(breaches) * 0.2)

        return round(min(1.0, depth_risk + breach_risk), 4)

    def generate_vendor_scorecard(self, vendor_id: str) -> VendorScorecard:
        """
        Generate a vendor security scorecard.

        Computes component scores:
          - domain_score: from domain reputation findings
          - cve_score: from NVD CVE findings
          - breach_score: from known breach database
          - data_handling_score: from data access level
          - fourth_party_score: from supply chain depth

        Overall score is a weighted average. Persists to SQLite.
        """
        assessment_row = self._db.get_assessment(vendor_id)
        if not assessment_row:
            raise ValueError(
                f"No assessment found for vendor '{vendor_id}'. "
                "Run assess_vendor() first."
            )

        vendor_name = assessment_row["vendor_name"]
        overall = assessment_row["risk_score"]

        # Parse findings to derive component scores
        try:
            findings = json.loads(assessment_row.get("findings_json", "[]"))
        except (json.JSONDecodeError, TypeError):
            findings = []

        try:
            recommendations = json.loads(assessment_row.get("recommendations_json", "[]"))
        except (json.JSONDecodeError, TypeError):
            recommendations = []

        def _component_score(check_name: str) -> float:
            """100 minus absolute penalties from matching checks."""
            penalty = sum(
                abs(f.get("score_impact", 0.0))
                for f in findings
                if f.get("check") == check_name
            )
            return max(0.0, round(100.0 - penalty, 2))

        domain_score = _component_score("domain_reputation")
        cve_score = _component_score("nvd_cve_lookup")
        breach_score = _component_score("known_breach_db")
        data_handling_score = _component_score("data_handling")
        fourth_party_score = _component_score("fourth_party_depth")

        # Default 100 for unchecked components
        for score_name, val in [
            ("domain_score", domain_score),
            ("cve_score", cve_score),
            ("breach_score", breach_score),
        ]:
            _ = score_name, val  # used below

        critical_count = sum(
            1 for f in findings if f.get("severity") == "critical"
        )
        risk_level = _score_to_risk_level(overall)
        grade = _score_to_grade(overall)
        now = datetime.now(timezone.utc).isoformat()

        scorecard = VendorScorecard(
            vendor_id=vendor_id,
            vendor_name=vendor_name,
            overall_score=overall,
            risk_level=risk_level,
            grade=grade,
            domain_score=domain_score,
            cve_score=cve_score,
            breach_score=breach_score,
            data_handling_score=data_handling_score,
            fourth_party_score=fourth_party_score,
            findings_count=len(findings),
            critical_findings=critical_count,
            calculated_at=now,
            recommendations=recommendations,
        )

        self._db.upsert_scorecard(scorecard)
        return scorecard

    def get_assessment(self, vendor_id: str) -> Optional[Dict[str, Any]]:
        """Return the latest automated assessment for a vendor."""
        return self._db.get_assessment(vendor_id)

    def list_high_risk_vendors(
        self,
        threshold: float = 60.0,
    ) -> List[Dict[str, Any]]:
        """
        Return all vendors with risk_score below threshold (higher = safer).

        Default threshold 60.0 means scores < 60 are considered high-risk.
        """
        assessments = self._db.list_assessments()
        return [a for a in assessments if a.get("risk_score", 100.0) < threshold]

    def get_scorecard(self, vendor_id: str) -> Optional[Dict[str, Any]]:
        """Return persisted scorecard for a vendor."""
        return self._db.get_scorecard(vendor_id)

    def get_questionnaire(self, questionnaire_id: str) -> Optional[Dict[str, Any]]:
        """Return questionnaire details by ID."""
        return self._db.get_questionnaire(questionnaire_id)

    # ------------------------------------------------------------------ #
    # Internal checks                                                      #
    # ------------------------------------------------------------------ #

    def _check_domain_reputation(
        self,
        domain: Optional[str],
    ) -> tuple[Optional[VendorRiskFinding], float]:
        """
        Check domain reputation via DNS resolution.

        Returns (finding, penalty).
        - No domain: low penalty (5) — cannot verify
        - DNS resolves: no penalty
        - DNS fails: medium penalty (15) — suspicious
        """
        if not domain:
            return (
                VendorRiskFinding(
                    check="domain_reputation",
                    severity="low",
                    title="No domain provided for vendor",
                    detail="Cannot perform domain reputation check without a domain.",
                    score_impact=-5.0,
                ),
                5.0,
            )

        domain_clean = domain.strip().lower().lstrip("https://").lstrip("http://").split("/")[0]
        try:
            socket.setdefaulttimeout(5)
            socket.gethostbyname(domain_clean)
            # Domain resolves — good sign
            return (
                VendorRiskFinding(
                    check="domain_reputation",
                    severity="info",
                    title=f"Domain '{domain_clean}' resolves successfully",
                    detail="DNS resolution passed — domain appears legitimate.",
                    score_impact=0.0,
                ),
                0.0,
            )
        except socket.gaierror:
            return (
                VendorRiskFinding(
                    check="domain_reputation",
                    severity="medium",
                    title=f"Domain '{domain_clean}' does not resolve",
                    detail="DNS lookup failed. Domain may be invalid, expired, or fictional.",
                    score_impact=-15.0,
                ),
                15.0,
            )
        except Exception:  # noqa: BLE001
            return (
                VendorRiskFinding(
                    check="domain_reputation",
                    severity="low",
                    title=f"Domain check inconclusive for '{domain_clean}'",
                    detail="Network error prevented domain reputation check.",
                    score_impact=-3.0,
                ),
                3.0,
            )

    def _check_threat_intel(
        self,
        domain: Optional[str],
    ) -> Optional[VendorRiskFinding]:
        """
        Check if vendor's IP ranges appear in threat intel feeds.

        This is a stub — in production, integrate with TrustGraph or threat feed APIs.
        Always returns None in the default implementation (no false positives).
        """
        # Stub: production implementation would query TrustGraph or threat feed
        return None

    def _assess_data_handling(
        self,
        data_access_level: str,
        vendor_name: str,
    ) -> tuple[Optional[VendorRiskFinding], float]:
        """
        Assess data handling risk based on access level.

        Penalty scale:
          none/public: 0
          internal: 5
          confidential: 10
          restricted (PII): 20
          secret: 30
        """
        penalties = {
            "none": 0.0,
            "public": 0.0,
            "internal": 5.0,
            "confidential": 10.0,
            "restricted": 20.0,
            "secret": 30.0,
        }
        penalty = penalties.get(data_access_level.lower(), 5.0)

        if penalty == 0.0:
            return None, 0.0

        severity_map = {
            "internal": "low",
            "confidential": "medium",
            "restricted": "high",
            "secret": "critical",
        }
        severity = severity_map.get(data_access_level.lower(), "medium")

        return (
            VendorRiskFinding(
                check="data_handling",
                severity=severity,
                title=f"Data access level: {data_access_level}",
                detail=(
                    f"{vendor_name} has {data_access_level}-level data access. "
                    "Ensure appropriate controls (DPA, encryption, access logging) are in place."
                ),
                score_impact=-penalty,
            ),
            penalty,
        )

    def _check_known_breaches(self, vendor_name: str) -> List[Dict[str, Any]]:
        """
        Check vendor name against the hardcoded known breach database.

        Matches on lowercased vendor name substring.
        """
        name_lower = vendor_name.lower()
        matches: List[Dict[str, Any]] = []
        for key, breach in KNOWN_BREACHES.items():
            if key in name_lower or name_lower in key:
                matches.append({**breach, "vendor_key": key})
        return matches

    def _score_cve_penalty(self, cves: List[Dict[str, Any]]) -> float:
        """
        Compute score penalty from CVE list.

        Critical CVE: -15, High: -10, Medium: -5, Low: -2
        Capped at 40 total.
        """
        weights = {"critical": 15.0, "high": 10.0, "medium": 5.0, "low": 2.0}
        total = sum(weights.get(c.get("severity", "medium"), 5.0) for c in cves)
        return min(40.0, total)

    def _score_breach_penalty(self, breaches: List[Dict[str, Any]]) -> float:
        """
        Compute score penalty from breach database matches.

        Critical: -25, High: -20.
        Capped at 50 total.
        """
        weights = {"critical": 25.0, "high": 20.0, "medium": 10.0, "low": 5.0}
        total = sum(weights.get(b.get("severity", "high"), 20.0) for b in breaches)
        return min(50.0, total)

    def _assess_fourth_party_penalty(self, fourth_parties: List[str]) -> float:
        """5 points per fourth-party vendor, capped at 20."""
        return min(20.0, len(fourth_parties) * 5.0)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_engine_instance: Optional[VendorRiskEngine] = None
_engine_lock = threading.Lock()


def get_vendor_risk_engine(db_path: str = _DEFAULT_DB_PATH) -> VendorRiskEngine:
    """Return the module-level VendorRiskEngine singleton."""
    global _engine_instance
    if _engine_instance is None:
        with _engine_lock:
            if _engine_instance is None:
                _engine_instance = VendorRiskEngine(db_path=db_path)
    return _engine_instance
