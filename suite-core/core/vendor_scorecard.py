"""
⚠️  SIMULATED DATA — NOT FOR PRODUCTION OR DEMO USE  ⚠️

This engine generates hash-derived vendor security scores for development/testing.
DO NOT use the output in customer-facing screens or pitches.

Real implementation tracking:
- _auto_assess() (lines 392-420) derives scores from domain name hash — not
  from real SSL probes, DNS checks, or vulnerability scans.
- Real implementation requires: ssl, requests, dnspython probes against live
  vendor domains, or integration with SecurityScorecard/BitSight APIs.
  Configure via /api/v1/connectors/vendor-risk/configure

Until real integrations are wired, these endpoints return a structured
warning header so callers can detect simulation mode.

Vendor Security Scorecard for ALDECI.

Provides third-party vendor risk scoring, assessment tracking, and supply
chain integration via SBOM component linking.

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
    "⚠️  %s loaded in SIMULATION mode — output is hash-derived; do not present in demos. "
    "Configure real connectors via /api/v1/connectors/",
    __name__,
)


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
        """Auto-assess a vendor via domain analysis simulation.

        Simulates SSL, HTTP headers, DNS, vulnerability, and data handling
        checks against the vendor's domain. Safe for environments without
        real network access.
        """
        vendor = self.get_vendor(vendor_id)
        domain = vendor.domain

        # Deterministic seed from domain for reproducible results in tests
        rng = random.Random(hash(domain) % (2**32))

        def _score(base: float, variance: float) -> float:
            return round(max(0.0, min(100.0, base + rng.uniform(-variance, variance))), 2)

        # Simulate security checks — heuristics based on domain characteristics
        # (In production these would be real probes via ssl, requests, dnspython)
        is_well_known = any(
            kw in domain
            for kw in ("google", "microsoft", "github", "amazon", "cloudflare")
        )
        base = 85.0 if is_well_known else 65.0

        factors = {
            "ssl_score": _score(base + 5, 10),
            "headers_score": _score(base - 5, 15),
            "dns_score": _score(base, 8),
            "vulnerability_score": _score(base - 10, 20),
            "data_handling_score": _score(base, 12),
        }

        return self.assess_vendor(
            vendor_id=vendor_id,
            factors=factors,
            assessor="auto-scanner",
            notes=f"Auto-assessment of {domain}",
            validity_days=validity_days,
        )

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
