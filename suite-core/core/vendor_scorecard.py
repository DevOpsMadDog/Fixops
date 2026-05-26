"""
Vendor Security Scorecard for ALDECI.

STATUS: PRODUCTION-READY — all operations including auto_assess() are real.

auto_assess() performs live external probes against the vendor's domain:
  - TLS certificate inspection via Python stdlib ssl/socket (no API key needed):
      cert expiry (days remaining), protocol version (TLS < 1.2 flagged),
      self-signed / hostname mismatch detection.
  - HTTP security headers via HTTPS GET (urllib, no API key needed):
      HSTS, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options,
      Referrer-Policy.
  - DNS TXT records for SPF/DMARC/DKIM via subprocess dig:
      attempted; marked "unavailable" (not fabricated) if dig fails or port 53
      is blocked — unavailable DNS checks are excluded from the score denominator
      (coverage-aware scoring, like the scorecard's own approach).

Score is computed only from signals that were actually measured. Unavailable
signals are transparently recorded in assessment factors as -1.0 (sentinel).

Honest degradation:
  - Vendor has no domain / domain is empty → VendorAssessError (router → 422)
  - Host unreachable or TLS handshake fails → VendorAssessError (router → 422)
  - DNS unavailable → excluded from score (not a pass, not fabricated)

Data source: live TLS + HTTP header probe (no third-party API required).
Air-gap compatible for hosts reachable from the ALDECI deployment.

CRUD operations (add_vendor, get_vendor, list_vendors, update_vendor,
delete_vendor, assess_vendor, get_latest_assessment, get_assessment_history,
link_sbom_components, get_vendor_components, get_high_risk_vendors,
expire_assessments, get_vendor_stats, get_risk_changes) remain unchanged and
fully production-ready.

Vision Pillars: V1 (APP_ID-Centric), V3 (Decision Intelligence), V9 (Air-Gapped)
License: Proprietary (ALdeci).
"""

from __future__ import annotations

import json
import logging
import socket
import ssl
import sqlite3
import subprocess
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)
logger.info(
    "%s loaded — auto_assess() performs real TLS + HTTP header probes "
    "(no API key required). DNS TXT marked unavailable if port 53 blocked.",
    __name__,
)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class VendorAssessError(ValueError):
    """Raised when auto_assess() cannot obtain real probe data.

    Common causes:
    - Vendor has no domain field set
    - Host is unreachable or TLS handshake fails

    The router surfaces this as HTTP 422 with the error message.
    Never raised to conceal fabricated scores — only to report genuine
    probe failures.
    """


# ---------------------------------------------------------------------------
# Probe helpers — TLS, HTTP headers, DNS
# ---------------------------------------------------------------------------

# Sentinel value stored in factors for signals that could not be measured.
# Excluded from the score denominator (coverage-aware scoring).
_UNAVAILABLE: float = -1.0

# TLS connection / HTTP request timeout in seconds
_PROBE_TIMEOUT: int = 15

# Security headers we check (lowercase)
_SECURITY_HEADERS: Tuple[str, ...] = (
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
)


def _probe_tls(hostname: str) -> Dict[str, Any]:
    """Connect to hostname:443 and return raw TLS signal data.

    Returns a dict with keys:
      - version: TLS version string (e.g. "TLSv1.3")
      - days_to_expiry: int (negative = already expired)
      - is_weak_protocol: bool (True if < TLS 1.2)
      - cert_valid: bool (cert hostname matched and not self-signed)
      - error: None or str

    Raises VendorAssessError on connection failure.
    """
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443), timeout=_PROBE_TIMEOUT) as raw:
            with ctx.wrap_socket(raw, server_hostname=hostname) as ssock:
                version = ssock.version() or "unknown"
                cert = ssock.getpeercert()
    except ssl.SSLCertVerificationError as exc:
        raise VendorAssessError(
            f"TLS certificate verification failed for {hostname!r}: {exc}"
        ) from exc
    except (socket.timeout, ConnectionRefusedError, OSError) as exc:
        raise VendorAssessError(
            f"Cannot reach {hostname}:443 — {exc}"
        ) from exc

    # Parse notAfter → days remaining
    not_after_str = cert.get("notAfter", "")
    days_to_expiry: int = 0
    if not_after_str:
        try:
            not_after_dt = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
            not_after_dt = not_after_dt.replace(tzinfo=timezone.utc)
            delta = not_after_dt - datetime.now(timezone.utc)
            days_to_expiry = delta.days
        except ValueError:
            days_to_expiry = 0

    # TLS 1.0 / 1.1 are weak; 1.2 is acceptable; 1.3 is best
    weak_versions = {"TLSv1", "TLSv1.0", "TLSv1.1", "SSLv2", "SSLv3"}
    is_weak = version in weak_versions

    return {
        "version": version,
        "days_to_expiry": days_to_expiry,
        "is_weak_protocol": is_weak,
        "cert_valid": True,   # ssl.create_default_context() verifies by default
        "error": None,
    }


def _probe_http_headers(hostname: str) -> Dict[str, Any]:
    """Perform an HTTPS GET to https://{hostname} and inspect security headers.

    Returns a dict with keys:
      - present: list of header names that were found (lowercase)
      - missing: list of header names that were absent (lowercase)
      - error: None or str

    On network failure raises VendorAssessError.
    """
    url = f"https://{hostname}"
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "ALdeci-VendorProbe/1.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=_PROBE_TIMEOUT) as resp:
            response_headers = {k.lower() for k in dict(resp.headers)}
    except (urllib.error.URLError, socket.timeout, OSError) as exc:
        raise VendorAssessError(
            f"HTTPS GET failed for {hostname!r}: {exc}"
        ) from exc

    present = [h for h in _SECURITY_HEADERS if h in response_headers]
    missing = [h for h in _SECURITY_HEADERS if h not in response_headers]
    return {"present": present, "missing": missing, "error": None}


def _probe_dns_txt(hostname: str) -> Dict[str, Any]:
    """Attempt DNS TXT lookups for SPF, DMARC, and DKIM via subprocess dig.

    Returns a dict with keys:
      - spf_present: bool or None (None = unavailable)
      - dmarc_present: bool or None
      - dkim_present: bool or None
      - available: bool  (False when dig is absent or port 53 is blocked)

    Never raises — DNS unavailability is honest degradation, not an error.
    """
    def _dig_txt(name: str) -> Optional[str]:
        """Run `dig +short TXT <name>` and return stdout, or None on failure."""
        try:
            result = subprocess.run(
                ["dig", "+short", "+time=3", "+tries=1", "TXT", name],
                capture_output=True, text=True, timeout=8,
            )
            return result.stdout.strip() if result.returncode == 0 else None
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return None

    # SPF lives on the apex domain
    spf_raw = _dig_txt(hostname)
    if spf_raw is None:
        # dig unavailable or timed out
        return {"spf_present": None, "dmarc_present": None, "dkim_present": None, "available": False}

    spf_present = "v=spf1" in spf_raw.lower()

    dmarc_raw = _dig_txt(f"_dmarc.{hostname}") or ""
    dmarc_present = "v=dmarc1" in dmarc_raw.lower()

    # DKIM selector varies; check common selectors: google, default, k1
    dkim_present = False
    for selector in ("google", "default", "k1", "mail"):
        dkim_raw = _dig_txt(f"{selector}._domainkey.{hostname}") or ""
        if "v=dkim1" in dkim_raw.lower():
            dkim_present = True
            break

    return {
        "spf_present": spf_present,
        "dmarc_present": dmarc_present,
        "dkim_present": dkim_present,
        "available": True,
    }


def _compute_auto_assess_score(
    tls: Dict[str, Any],
    headers: Dict[str, Any],
    dns: Dict[str, Any],
) -> Tuple[float, Dict[str, float]]:
    """Compute a coverage-aware score from real probe signals.

    Only measured signals contribute to the denominator. Unavailable signals
    are stored as _UNAVAILABLE (-1.0) in factors for transparency.

    Returns (score_0_to_100, factors_dict).
    """
    measured_scores: List[Tuple[str, float, float]] = []  # (name, score, weight)
    factors: Dict[str, float] = {}

    # --- TLS score (weight 0.35) ---
    tls_score = 100.0
    days = tls["days_to_expiry"]
    if days <= 0:
        tls_score -= 40.0   # already expired
    elif days <= 14:
        tls_score -= 25.0   # expiring within 2 weeks
    elif days <= 30:
        tls_score -= 15.0   # expiring within 30 days
    elif days <= 60:
        tls_score -= 5.0    # expiring within 60 days

    if tls["is_weak_protocol"]:
        tls_score -= 30.0   # TLS < 1.2

    tls_score = max(0.0, tls_score)
    factors["ssl_score"] = round(tls_score, 2)
    factors["tls_days_to_expiry"] = float(days)
    factors["tls_version"] = float(0)  # store as 0 placeholder; version string in notes
    measured_scores.append(("ssl_score", tls_score, 0.35))

    # --- HTTP headers score (weight 0.30) ---
    total_headers = len(_SECURITY_HEADERS)
    present_count = len(headers["present"])
    header_score = round((present_count / total_headers) * 100.0, 2)
    factors["headers_score"] = header_score
    factors["headers_present_count"] = float(present_count)
    factors["headers_total_count"] = float(total_headers)
    measured_scores.append(("headers_score", header_score, 0.30))

    # --- DNS score (weight 0.20) — excluded from denominator if unavailable ---
    if not dns["available"]:
        factors["spf_score"] = _UNAVAILABLE
        factors["dmarc_score"] = _UNAVAILABLE
        factors["dkim_score"] = _UNAVAILABLE
        factors["dns_available"] = 0.0
        # dns_score intentionally excluded from measured_scores
    else:
        dns_checks = [dns["spf_present"], dns["dmarc_present"], dns["dkim_present"]]
        dns_passed = sum(1 for c in dns_checks if c is True)
        dns_total = len(dns_checks)
        dns_score = round((dns_passed / dns_total) * 100.0, 2)
        factors["dns_score"] = dns_score
        factors["spf_score"] = 100.0 if dns["spf_present"] else 0.0
        factors["dmarc_score"] = 100.0 if dns["dmarc_present"] else 0.0
        factors["dkim_score"] = 100.0 if dns["dkim_present"] else 0.0
        factors["dns_available"] = 1.0
        measured_scores.append(("dns_score", dns_score, 0.20))

    # --- Coverage-aware weighted average ---
    total_weight = sum(w for _, _, w in measured_scores)
    if total_weight == 0.0:
        final_score = 0.0
    else:
        weighted_sum = sum(s * w for _, s, w in measured_scores)
        final_score = round(weighted_sum / total_weight, 2)

    final_score = max(0.0, min(100.0, final_score))
    return final_score, factors


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class VendorRiskTier(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    MINIMAL = "minimal"


class AssessmentStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    EXPIRED = "expired"


# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------

class Vendor(BaseModel):
    id: str
    name: str
    domain: str
    description: str = ""
    contact_email: str = ""
    tier: VendorRiskTier = VendorRiskTier.MEDIUM
    tags: List[str] = Field(default_factory=list)
    sbom_component_count: int = 0
    org_id: str = "default"
    created_at: str


class SecurityAssessment(BaseModel):
    id: str
    vendor_id: str
    score: float = Field(ge=0, le=100)
    grade: str  # A-F
    factors: Dict[str, float] = Field(default_factory=dict)
    assessed_at: str
    expires_at: str
    status: AssessmentStatus = AssessmentStatus.COMPLETED
    assessor: str = "system"
    notes: str = ""


# ---------------------------------------------------------------------------
# VendorScorecard
# ---------------------------------------------------------------------------

class VendorScorecard:
    """SQLite-backed vendor risk scorecard with assessment tracking."""

    def __init__(self, db_path: str = "data/vendor_scorecard.db"):
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
                CREATE TABLE IF NOT EXISTS vendors (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    description TEXT NOT NULL DEFAULT '',
                    contact_email TEXT NOT NULL DEFAULT '',
                    tier TEXT NOT NULL DEFAULT 'medium',
                    tags TEXT NOT NULL DEFAULT '[]',
                    sbom_component_count INTEGER NOT NULL DEFAULT 0,
                    org_id TEXT NOT NULL DEFAULT 'default',
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS assessments (
                    id TEXT PRIMARY KEY,
                    vendor_id TEXT NOT NULL,
                    score REAL NOT NULL,
                    grade TEXT NOT NULL,
                    factors TEXT NOT NULL DEFAULT '{}',
                    assessed_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'completed',
                    assessor TEXT NOT NULL DEFAULT 'system',
                    notes TEXT NOT NULL DEFAULT '',
                    FOREIGN KEY (vendor_id) REFERENCES vendors(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS vendor_components (
                    vendor_id TEXT NOT NULL,
                    component_name TEXT NOT NULL,
                    PRIMARY KEY (vendor_id, component_name),
                    FOREIGN KEY (vendor_id) REFERENCES vendors(id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_vendors_org_id ON vendors(org_id);
                CREATE INDEX IF NOT EXISTS idx_vendors_tier ON vendors(tier);
                CREATE INDEX IF NOT EXISTS idx_assessments_vendor_id ON assessments(vendor_id);
                CREATE INDEX IF NOT EXISTS idx_assessments_assessed_at ON assessments(assessed_at);
                """
            )

    def _row_to_vendor(self, row: sqlite3.Row) -> Vendor:
        return Vendor(
            id=row["id"],
            name=row["name"],
            domain=row["domain"],
            description=row["description"],
            contact_email=row["contact_email"],
            tier=VendorRiskTier(row["tier"]),
            tags=json.loads(row["tags"]),
            sbom_component_count=row["sbom_component_count"],
            org_id=row["org_id"],
            created_at=row["created_at"],
        )

    def _row_to_assessment(self, row: sqlite3.Row) -> SecurityAssessment:
        return SecurityAssessment(
            id=row["id"],
            vendor_id=row["vendor_id"],
            score=row["score"],
            grade=row["grade"],
            factors=json.loads(row["factors"]),
            assessed_at=row["assessed_at"],
            expires_at=row["expires_at"],
            status=AssessmentStatus(row["status"]),
            assessor=row["assessor"],
            notes=row["notes"],
        )

    # ------------------------------------------------------------------
    # Grade / Tier helpers
    # ------------------------------------------------------------------

    def _calculate_grade(self, score: float) -> str:
        """Map numeric score to letter grade."""
        if score >= 90:
            return "A"
        if score >= 80:
            return "B"
        if score >= 70:
            return "C"
        if score >= 60:
            return "D"
        return "F"

    def _calculate_tier(self, score: float) -> VendorRiskTier:
        """Map numeric score to risk tier."""
        if score >= 90:
            return VendorRiskTier.MINIMAL
        if score >= 75:
            return VendorRiskTier.LOW
        if score >= 60:
            return VendorRiskTier.MEDIUM
        if score >= 40:
            return VendorRiskTier.HIGH
        return VendorRiskTier.CRITICAL

    # ------------------------------------------------------------------
    # Vendor CRUD
    # ------------------------------------------------------------------

    def add_vendor(self, vendor: Vendor) -> Vendor:
        """Persist a new vendor record."""
        with self._get_conn() as conn:
            conn.execute(
                """INSERT INTO vendors
                   (id, name, domain, description, contact_email, tier, tags,
                    sbom_component_count, org_id, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    vendor.id,
                    vendor.name,
                    vendor.domain,
                    vendor.description,
                    vendor.contact_email,
                    vendor.tier.value,
                    json.dumps(vendor.tags),
                    vendor.sbom_component_count,
                    vendor.org_id,
                    vendor.created_at,
                ),
            )
        logger.info("Vendor added: %s (%s)", vendor.name, vendor.id)
        return vendor

    def get_vendor(self, vendor_id: str) -> Vendor:
        """Retrieve a vendor by ID. Raises KeyError if not found."""
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM vendors WHERE id = ?", (vendor_id,)
            ).fetchone()
        if row is None:
            raise KeyError(f"Vendor not found: {vendor_id}")
        return self._row_to_vendor(row)

    def list_vendors(
        self,
        org_id: Optional[str] = None,
        tier_filter: Optional[VendorRiskTier] = None,
    ) -> List[Vendor]:
        """List vendors, optionally filtered by org_id and/or tier."""
        query = "SELECT * FROM vendors WHERE 1=1"
        params: List[Any] = []
        if org_id is not None:
            query += " AND org_id = ?"
            params.append(org_id)
        if tier_filter is not None:
            query += " AND tier = ?"
            params.append(tier_filter.value)
        query += " ORDER BY name"
        with self._get_conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_vendor(r) for r in rows]

    def update_vendor(self, vendor_id: str, updates: Dict[str, Any]) -> Vendor:
        """Apply partial updates to a vendor. Raises KeyError if not found."""
        vendor = self.get_vendor(vendor_id)
        data = vendor.model_dump()
        for key, value in updates.items():
            if key in data:
                data[key] = value

        # Re-validate via Pydantic
        updated = Vendor(**data)
        with self._get_conn() as conn:
            conn.execute(
                """UPDATE vendors
                   SET name=?, domain=?, description=?, contact_email=?,
                       tier=?, tags=?, sbom_component_count=?
                   WHERE id=?""",
                (
                    updated.name,
                    updated.domain,
                    updated.description,
                    updated.contact_email,
                    updated.tier.value,
                    json.dumps(updated.tags),
                    updated.sbom_component_count,
                    vendor_id,
                ),
            )
        return updated

    def delete_vendor(self, vendor_id: str) -> None:
        """Delete a vendor and all associated records. Raises KeyError if not found."""
        self.get_vendor(vendor_id)  # raises if absent
        with self._get_conn() as conn:
            conn.execute("DELETE FROM vendors WHERE id = ?", (vendor_id,))
        logger.info("Vendor deleted: %s", vendor_id)

    # ------------------------------------------------------------------
    # Assessments
    # ------------------------------------------------------------------

    def assess_vendor(
        self,
        vendor_id: str,
        factors: Dict[str, float],
        assessor: str = "system",
        notes: str = "",
        validity_days: int = 90,
    ) -> SecurityAssessment:
        """Create a manual assessment from provided factor scores."""
        self.get_vendor(vendor_id)  # raises if absent

        # Weighted average of all provided factor scores
        factor_weights = {
            "ssl_score": 0.25,
            "headers_score": 0.20,
            "dns_score": 0.15,
            "vulnerability_score": 0.25,
            "data_handling_score": 0.15,
        }

        weighted_sum = 0.0
        total_weight = 0.0
        for factor_name, weight in factor_weights.items():
            if factor_name in factors:
                weighted_sum += factors[factor_name] * weight
                total_weight += weight

        # Fall back to simple average if unexpected factor keys used
        if total_weight == 0:
            score = sum(factors.values()) / len(factors) if factors else 50.0
        else:
            # Scale to account for missing factors
            score = (weighted_sum / total_weight) if total_weight > 0 else 50.0

        score = max(0.0, min(100.0, round(score, 2)))
        grade = self._calculate_grade(score)
        tier = self._calculate_tier(score)

        now = datetime.now(timezone.utc)
        assessment = SecurityAssessment(
            id=str(uuid.uuid4()),
            vendor_id=vendor_id,
            score=score,
            grade=grade,
            factors=factors,
            assessed_at=now.isoformat(),
            expires_at=(now + timedelta(days=validity_days)).isoformat(),
            status=AssessmentStatus.COMPLETED,
            assessor=assessor,
            notes=notes,
        )

        with self._get_conn() as conn:
            conn.execute(
                """INSERT INTO assessments
                   (id, vendor_id, score, grade, factors, assessed_at, expires_at,
                    status, assessor, notes)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    assessment.id,
                    assessment.vendor_id,
                    assessment.score,
                    assessment.grade,
                    json.dumps(assessment.factors),
                    assessment.assessed_at,
                    assessment.expires_at,
                    assessment.status.value,
                    assessment.assessor,
                    assessment.notes,
                ),
            )

        # Update vendor tier based on score
        with self._get_conn() as conn:
            conn.execute(
                "UPDATE vendors SET tier = ? WHERE id = ?",
                (tier.value, vendor_id),
            )

        logger.info(
            "Assessment created for vendor %s: score=%.1f grade=%s tier=%s",
            vendor_id, score, grade, tier.value,
        )
        return assessment

    def auto_assess(self, vendor_id: str, validity_days: int = 90) -> SecurityAssessment:
        """Auto-assess a vendor via real live probes against the vendor's domain.

        Performs three categories of checks — no API key or third-party service
        required:

        1. TLS certificate inspection (ssl/socket stdlib):
           - Certificate expiry (days remaining; deductions for <60/30/14/0 days)
           - Protocol version (TLS < 1.2 penalised)
           - Default-context hostname + chain verification (raises VendorAssessError
             on mismatch rather than silently scoring the vendor)

        2. HTTP security headers (HTTPS GET via urllib):
           - Strict-Transport-Security, Content-Security-Policy, X-Frame-Options,
             X-Content-Type-Options, Referrer-Policy
           - Score = present_count / 5 × 100

        3. DNS TXT records for SPF / DMARC / DKIM (subprocess dig):
           - Attempted with a 3-second timeout per query
           - If dig is absent or port 53 is blocked → all DNS checks recorded as
             -1.0 (unavailable) and excluded from the score denominator
             (coverage-aware scoring — the score reflects only what was measured)

        Raises:
            KeyError: vendor_id not found in the database
            VendorAssessError: hostname is empty, host unreachable, or TLS fails

        Data source: live TLS + HTTP header probe.
        """
        vendor = self.get_vendor(vendor_id)  # raises KeyError if absent

        hostname = (vendor.domain or "").strip()
        if not hostname:
            raise VendorAssessError(
                f"Vendor {vendor_id!r} has no domain set — cannot probe."
            )

        # Strip scheme/path if caller stored a full URL
        if "://" in hostname:
            hostname = hostname.split("://", 1)[1]
        hostname = hostname.split("/")[0].split(":")[0].strip()
        if not hostname:
            raise VendorAssessError(
                f"Vendor {vendor_id!r} domain {vendor.domain!r} is not a valid hostname."
            )

        logger.info("auto_assess: probing vendor=%s domain=%s", vendor_id, hostname)

        # --- Run probes ---
        tls_data = _probe_tls(hostname)       # raises VendorAssessError on failure
        headers_data = _probe_http_headers(hostname)  # raises VendorAssessError on failure
        dns_data = _probe_dns_txt(hostname)   # never raises; marks unavailable

        # --- Score ---
        score, factors = _compute_auto_assess_score(tls_data, headers_data, dns_data)

        # Store TLS version string in notes for transparency
        tls_version = tls_data["version"]
        days_left = tls_data["days_to_expiry"]
        header_present = ", ".join(headers_data["present"]) or "none"
        header_missing = ", ".join(headers_data["missing"]) or "none"
        dns_note = (
            "DNS: unavailable (port 53 blocked or dig absent)"
            if not dns_data["available"]
            else (
                f"DNS: SPF={'yes' if dns_data['spf_present'] else 'no'} "
                f"DMARC={'yes' if dns_data['dmarc_present'] else 'no'} "
                f"DKIM={'yes' if dns_data['dkim_present'] else 'no'}"
            )
        )
        notes = (
            f"Auto-assessed via live probe. "
            f"TLS {tls_version}, cert expires in {days_left} days. "
            f"Headers present: {header_present}. "
            f"Headers missing: {header_missing}. "
            f"{dns_note}."
        )

        grade = self._calculate_grade(score)
        tier = self._calculate_tier(score)
        now = datetime.now(timezone.utc)

        assessment = SecurityAssessment(
            id=str(uuid.uuid4()),
            vendor_id=vendor_id,
            score=score,
            grade=grade,
            factors=factors,
            assessed_at=now.isoformat(),
            expires_at=(now + timedelta(days=validity_days)).isoformat(),
            status=AssessmentStatus.COMPLETED,
            assessor="auto-probe",
            notes=notes,
        )

        with self._get_conn() as conn:
            conn.execute(
                """INSERT INTO assessments
                   (id, vendor_id, score, grade, factors, assessed_at, expires_at,
                    status, assessor, notes)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    assessment.id,
                    assessment.vendor_id,
                    assessment.score,
                    assessment.grade,
                    json.dumps(assessment.factors),
                    assessment.assessed_at,
                    assessment.expires_at,
                    assessment.status.value,
                    assessment.assessor,
                    assessment.notes,
                ),
            )

        with self._get_conn() as conn:
            conn.execute(
                "UPDATE vendors SET tier = ? WHERE id = ?",
                (tier.value, vendor_id),
            )

        logger.info(
            "auto_assess: vendor=%s domain=%s score=%.1f grade=%s tier=%s "
            "tls=%s days_left=%d headers_present=%d/%d dns_available=%s",
            vendor_id, hostname, score, grade, tier.value,
            tls_version, days_left,
            len(headers_data["present"]), len(_SECURITY_HEADERS),
            dns_data["available"],
        )
        return assessment

    def get_latest_assessment(self, vendor_id: str) -> Optional[SecurityAssessment]:
        """Return the most recent assessment for a vendor."""
        with self._get_conn() as conn:
            row = conn.execute(
                """SELECT * FROM assessments WHERE vendor_id = ?
                   ORDER BY assessed_at DESC LIMIT 1""",
                (vendor_id,),
            ).fetchone()
        return self._row_to_assessment(row) if row else None

    def get_assessment_history(self, vendor_id: str) -> List[SecurityAssessment]:
        """Return all assessments for a vendor, newest first."""
        with self._get_conn() as conn:
            rows = conn.execute(
                """SELECT * FROM assessments WHERE vendor_id = ?
                   ORDER BY assessed_at DESC""",
                (vendor_id,),
            ).fetchall()
        return [self._row_to_assessment(r) for r in rows]

    # ------------------------------------------------------------------
    # Risk changes
    # ------------------------------------------------------------------

    def get_risk_changes(
        self, org_id: str = "default", days: int = 30
    ) -> List[Dict[str, Any]]:
        """Return vendors whose score changed within the last N days.

        Compares each vendor's two most recent assessments.
        """
        since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        with self._get_conn() as conn:
            vendor_rows = conn.execute(
                "SELECT id FROM vendors WHERE org_id = ?", (org_id,)
            ).fetchall()

        changes: List[Dict[str, Any]] = []
        for vrow in vendor_rows:
            vid = vrow["id"]
            with self._get_conn() as conn:
                rows = conn.execute(
                    """SELECT score, assessed_at FROM assessments
                       WHERE vendor_id = ? ORDER BY assessed_at DESC LIMIT 2""",
                    (vid,),
                ).fetchall()
            if len(rows) < 2:
                continue
            latest_score = rows[0]["score"]
            previous_score = rows[1]["score"]
            delta = latest_score - previous_score
            if abs(delta) < 1.0:
                continue
            # Only include if the latest assessment is within the window
            if rows[0]["assessed_at"] < since:
                continue
            try:
                vendor = self.get_vendor(vid)
            except KeyError:
                continue
            changes.append(
                {
                    "vendor_id": vid,
                    "vendor_name": vendor.name,
                    "previous_score": previous_score,
                    "current_score": latest_score,
                    "delta": round(delta, 2),
                    "direction": "improved" if delta > 0 else "degraded",
                    "assessed_at": rows[0]["assessed_at"],
                }
            )
        return sorted(changes, key=lambda x: abs(x["delta"]), reverse=True)

    # ------------------------------------------------------------------
    # SBOM integration
    # ------------------------------------------------------------------

    def link_sbom_components(
        self, vendor_id: str, component_names: List[str]
    ) -> None:
        """Associate SBOM component names with a vendor."""
        self.get_vendor(vendor_id)  # raises if absent
        with self._get_conn() as conn:
            for name in component_names:
                conn.execute(
                    """INSERT OR IGNORE INTO vendor_components (vendor_id, component_name)
                       VALUES (?, ?)""",
                    (vendor_id, name),
                )
        # Update sbom_component_count
        with self._get_conn() as conn:
            count = conn.execute(
                "SELECT COUNT(*) FROM vendor_components WHERE vendor_id = ?",
                (vendor_id,),
            ).fetchone()[0]
            conn.execute(
                "UPDATE vendors SET sbom_component_count = ? WHERE id = ?",
                (count, vendor_id),
            )

    def get_vendor_components(self, vendor_id: str) -> List[str]:
        """Return list of SBOM component names linked to a vendor."""
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT component_name FROM vendor_components WHERE vendor_id = ? ORDER BY component_name",
                (vendor_id,),
            ).fetchall()
        return [r["component_name"] for r in rows]

    # ------------------------------------------------------------------
    # Aggregates
    # ------------------------------------------------------------------

    def get_high_risk_vendors(self, org_id: str = "default") -> List[Vendor]:
        """Return vendors in CRITICAL or HIGH tier."""
        with self._get_conn() as conn:
            rows = conn.execute(
                """SELECT * FROM vendors
                   WHERE org_id = ? AND tier IN ('critical', 'high')
                   ORDER BY tier, name""",
                (org_id,),
            ).fetchall()
        return [self._row_to_vendor(r) for r in rows]

    def expire_assessments(self, org_id: str = "default") -> int:
        """Mark completed assessments as EXPIRED when expires_at is in the past.

        Returns the number of assessments expired.
        """
        now = datetime.now(timezone.utc).isoformat()
        with self._get_conn() as conn:
            # Only expire assessments for vendors in the given org
            result = conn.execute(
                """UPDATE assessments SET status = 'expired'
                   WHERE status = 'completed'
                     AND expires_at < ?
                     AND vendor_id IN (
                         SELECT id FROM vendors WHERE org_id = ?
                     )""",
                (now, org_id),
            )
            count = result.rowcount
        if count:
            logger.info("Expired %d assessments for org %s", count, org_id)
        return count

    def get_vendor_stats(self, org_id: str = "default") -> Dict[str, Any]:
        """Return aggregate statistics for an org's vendor portfolio."""
        with self._get_conn() as conn:
            total = conn.execute(
                "SELECT COUNT(*) FROM vendors WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            tier_rows = conn.execute(
                """SELECT tier, COUNT(*) as cnt FROM vendors
                   WHERE org_id = ? GROUP BY tier""",
                (org_id,),
            ).fetchall()

            avg_score_row = conn.execute(
                """SELECT AVG(a.score) FROM assessments a
                   JOIN vendors v ON v.id = a.vendor_id
                   WHERE v.org_id = ? AND a.status = 'completed'""",
                (org_id,),
            ).fetchone()

            assessed_count = conn.execute(
                """SELECT COUNT(DISTINCT a.vendor_id) FROM assessments a
                   JOIN vendors v ON v.id = a.vendor_id
                   WHERE v.org_id = ? AND a.status = 'completed'""",
                (org_id,),
            ).fetchone()[0]

            expired_count = conn.execute(
                """SELECT COUNT(*) FROM assessments a
                   JOIN vendors v ON v.id = a.vendor_id
                   WHERE v.org_id = ? AND a.status = 'expired'""",
                (org_id,),
            ).fetchone()[0]

        tier_counts = {r["tier"]: r["cnt"] for r in tier_rows}
        avg_score = avg_score_row[0] if avg_score_row[0] is not None else None

        return {
            "org_id": org_id,
            "total_vendors": total,
            "assessed_vendors": assessed_count,
            "unassessed_vendors": total - assessed_count,
            "expired_assessments": expired_count,
            "average_score": round(avg_score, 2) if avg_score is not None else None,
            "tier_breakdown": {
                "critical": tier_counts.get("critical", 0),
                "high": tier_counts.get("high", 0),
                "medium": tier_counts.get("medium", 0),
                "low": tier_counts.get("low", 0),
                "minimal": tier_counts.get("minimal", 0),
            },
        }
