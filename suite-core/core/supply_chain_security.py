"""
Supply Chain Security Engine for ALDECI.

Covers:
- SBOM Management: parse/store CycloneDX and SPDX SBOMs, component inventory, license tracking
- Dependency Risk Scoring: CVEs, maintenance status, license risk, transitive depth, popularity
- Supply Chain Attack Detection: typosquatting, dependency confusion, malicious version bumps
- Provenance Verification: SLSA provenance, build attestation, signature verification
- Policy Engine: GPL blocking, SBOM requirements, max transitive depth, provenance levels
- Vendor Risk Assessment: security posture, SLA compliance, breach history, concentration risk

Compliance: NIST SP 800-218 (SSDF), EO 14028 (Software Supply Chain Security),
            SLSA Framework, CycloneDX v1.6, SPDX 2.3
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field, field_validator

# ---------------------------------------------------------------------------
# TrustGraph event-bus wiring (auto-added by hub-wiring wave)
# ---------------------------------------------------------------------------
try:  # pragma: no cover - optional dependency
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except Exception:  # noqa: BLE001
    _get_tg_bus = None  # type: ignore[assignment]


def _emit_event(event_type: str, payload):  # type: ignore[no-untyped-def]
    """Emit an event to the TrustGraph event bus. Never raises.

    Hub-level emit so this engine module participates in second-brain coverage.
    Downstream callers are AQUA via blast-radius (depth ≤ 2).
    """
    if _get_tg_bus is None:
        return
    try:
        bus = _get_tg_bus()
        if bus is None:
            return
        emit = getattr(bus, "emit", None) or getattr(bus, "publish", None)
        if emit is None:
            return
        result = emit(event_type, payload)
        try:
            import asyncio as _aio
            import inspect as _insp
            if _insp.iscoroutine(result):
                try:
                    loop = _aio.get_running_loop()
                    loop.create_task(result)
                except RuntimeError:
                    result.close()
        except Exception:  # pragma: no cover
            pass
    except Exception:  # pragma: no cover
        pass


# Module-load heartbeat — fires once per process so this file is observable
# in the TrustGraph second-brain, even if no public method is called yet.
try:  # pragma: no cover
    _emit_event("engine.loaded", {"module": __name__})
except Exception:  # noqa: BLE001
    pass


_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(Path(__file__).resolve().parents[2] / "data" / "supply_chain.db")

# Popular package namespaces — used for dependency confusion detection
_POPULAR_PACKAGES: List[str] = [
    "requests", "numpy", "pandas", "flask", "django", "fastapi", "pydantic",
    "boto3", "sqlalchemy", "pytest", "click", "httpx", "aiohttp", "celery",
    "redis", "pymongo", "psycopg2", "pillow", "cryptography", "paramiko",
    "lodash", "express", "react", "vue", "angular", "axios", "webpack",
    "typescript", "eslint", "prettier", "jest", "moment", "dayjs",
]

# License risk tiers
_HIGH_RISK_LICENSES = {"GPL-2.0", "GPL-3.0", "AGPL-3.0", "LGPL-2.1", "LGPL-3.0", "SSPL-1.0"}
_MEDIUM_RISK_LICENSES = {"MPL-2.0", "EPL-2.0", "CDDL-1.0", "EUPL-1.2"}
_LOW_RISK_LICENSES = {"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "0BSD", "Unlicense"}


# ============================================================================
# ENUMS
# ============================================================================


class SBOMFormat(str, Enum):
    CYCLONEDX = "cyclonedx"
    SPDX = "spdx"
    UNKNOWN = "unknown"


class LicenseRisk(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    UNKNOWN = "unknown"


class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AttackType(str, Enum):
    TYPOSQUATTING = "typosquatting"
    DEPENDENCY_CONFUSION = "dependency_confusion"
    VERSION_BUMP = "malicious_version_bump"
    NAMESPACE_HIJACK = "namespace_hijack"


class ProvenanceLevel(str, Enum):
    """SLSA provenance levels."""
    SLSA_0 = "slsa_0"
    SLSA_1 = "slsa_1"
    SLSA_2 = "slsa_2"
    SLSA_3 = "slsa_3"
    SLSA_4 = "slsa_4"


class PolicyAction(str, Enum):
    BLOCK = "block"
    WARN = "warn"
    AUDIT = "audit"


class VendorTier(str, Enum):
    CRITICAL = "critical"    # Single point of failure
    HIGH = "high"            # Major dependency, alternatives exist
    MEDIUM = "medium"        # Important but replaceable
    LOW = "low"              # Minor dependency


# ============================================================================
# PYDANTIC MODELS
# ============================================================================


class SBOMComponent(BaseModel):
    """A software component tracked in an SBOM."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = Field(..., description="Package name")
    version: str = Field(..., description="Package version")
    ecosystem: str = Field("unknown", description="e.g. pypi, npm, maven, cargo")
    purl: Optional[str] = Field(None, description="Package URL (purl spec)")
    license_id: str = Field("UNKNOWN", description="SPDX license identifier")
    license_risk: LicenseRisk = Field(LicenseRisk.UNKNOWN)
    description: Optional[str] = None
    homepage: Optional[str] = None
    repository: Optional[str] = None
    author: Optional[str] = None
    sbom_id: str = Field(..., description="Parent SBOM this component belongs to")
    transitive_depth: int = Field(0, description="0 = direct, 1+ = transitive")
    is_internal: bool = Field(False, description="Internal package (not public registry)")
    hashes: Dict[str, str] = Field(default_factory=dict, description="sha256, sha512, md5")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("license_risk", mode="before")
    @classmethod
    def _infer_license_risk(cls, v: Any) -> Any:
        return v  # Will be computed by engine after init


class DependencyRiskScore(BaseModel):
    """Risk score for a single dependency."""

    component_id: str
    component_name: str
    component_version: str
    overall_score: float = Field(0.0, ge=0.0, le=100.0, description="0=safe, 100=critical")
    risk_level: RiskLevel = Field(RiskLevel.INFO)
    cve_count: int = Field(0, description="Known CVE count")
    critical_cve_count: int = Field(0)
    days_since_last_commit: Optional[int] = Field(None)
    open_issues_count: Optional[int] = Field(None)
    license_risk: LicenseRisk = Field(LicenseRisk.UNKNOWN)
    transitive_depth: int = Field(0)
    weekly_downloads: Optional[int] = Field(None)
    is_maintained: bool = Field(True)
    score_breakdown: Dict[str, float] = Field(default_factory=dict)
    computed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class SBOMRecord(BaseModel):
    """A stored SBOM document."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    format: SBOMFormat = Field(SBOMFormat.UNKNOWN)
    spec_version: str = Field("unknown")
    name: str = Field("", description="Project/application name")
    version: str = Field("", description="Project version")
    org_id: str = Field("default")
    component_count: int = Field(0)
    sha256: str = Field("", description="SHA-256 of the raw SBOM payload")
    source_repo: Optional[str] = Field(None)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    uploaded_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AttackSignal(BaseModel):
    """A detected supply chain attack signal."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    attack_type: AttackType
    severity: RiskLevel = Field(RiskLevel.HIGH)
    component_name: str
    component_version: str
    description: str
    evidence: Dict[str, Any] = Field(default_factory=dict)
    similar_package: Optional[str] = Field(None, description="For typosquatting: the real package")
    confidence: float = Field(0.0, ge=0.0, le=1.0)
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    org_id: str = Field("default")


class ProvenanceRecord(BaseModel):
    """SLSA provenance / build attestation for a component."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    component_name: str
    component_version: str
    slsa_level: ProvenanceLevel = Field(ProvenanceLevel.SLSA_0)
    build_system: Optional[str] = Field(None, description="e.g. GitHub Actions, Jenkins")
    build_config_uri: Optional[str] = None
    builder_id: Optional[str] = None
    source_uri: Optional[str] = None
    source_digest: Optional[str] = None
    attestation_payload: Optional[str] = Field(None, description="Raw attestation JSON")
    signature_verified: bool = Field(False)
    signature_keyid: Optional[str] = None
    sigstore_bundle: Optional[str] = None
    verification_errors: List[str] = Field(default_factory=list)
    verified_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class SupplyChainPolicy(BaseModel):
    """Configurable supply chain security policy."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = Field(..., description="Human-readable policy name")
    description: str = Field("")
    enabled: bool = Field(True)
    action: PolicyAction = Field(PolicyAction.WARN)
    org_id: str = Field("default")

    # License rules
    blocked_licenses: List[str] = Field(
        default_factory=lambda: list(_HIGH_RISK_LICENSES),
        description="SPDX IDs of licenses to block",
    )

    # SBOM requirements
    require_sbom: bool = Field(False, description="Block deployments without SBOM")

    # Depth limit
    max_transitive_depth: Optional[int] = Field(
        None, description="Block if transitive dependency depth exceeds this"
    )

    # Provenance requirements
    required_provenance_level: ProvenanceLevel = Field(
        ProvenanceLevel.SLSA_0, description="Minimum SLSA level required"
    )

    # CVE thresholds
    max_critical_cves: int = Field(0, description="Block if component has more critical CVEs")
    max_overall_risk_score: float = Field(80.0, description="Block if score exceeds this")

    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class PolicyViolation(BaseModel):
    """A policy violation for a component."""

    policy_id: str
    policy_name: str
    component_name: str
    component_version: str
    action: PolicyAction
    reason: str
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class VendorRiskAssessment(BaseModel):
    """Security risk assessment for a software vendor."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    vendor_name: str
    vendor_url: Optional[str] = None
    tier: VendorTier = Field(VendorTier.MEDIUM)
    org_id: str = Field("default")

    # Security posture (0–100, higher = better)
    security_score: float = Field(50.0, ge=0.0, le=100.0)

    # SLA compliance
    sla_uptime_pct: Optional[float] = Field(None, description="Reported uptime %")
    sla_response_hours: Optional[int] = Field(None, description="Incident response SLA hours")
    sla_compliant: bool = Field(True)

    # Breach history
    known_breaches: int = Field(0, description="Number of publicly known breaches")
    last_breach_date: Optional[datetime] = Field(None)
    breach_details: List[str] = Field(default_factory=list)

    # Concentration risk
    component_count: int = Field(0, description="Number of components sourced from this vendor")
    concentration_risk: RiskLevel = Field(RiskLevel.LOW)

    # Additional metadata
    security_contact: Optional[str] = None
    bug_bounty: bool = Field(False)
    mfa_required: bool = Field(False)
    sbom_provided: bool = Field(False)
    notes: str = Field("")

    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class RiskDashboard(BaseModel):
    """Aggregated supply chain risk dashboard data."""

    org_id: str
    total_components: int
    total_sboms: int
    critical_components: int
    high_risk_components: int
    attack_signals: int
    critical_attack_signals: int
    policy_violations: int
    blocked_components: int
    avg_risk_score: float
    top_risks: List[DependencyRiskScore]
    recent_signals: List[AttackSignal]
    vendor_count: int
    high_risk_vendors: int
    computed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ============================================================================
# HELPERS
# ============================================================================


def _levenshtein(a: str, b: str) -> int:
    """Compute Levenshtein edit distance between two strings."""
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            curr.append(min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = curr
    return prev[-1]


def _classify_license_risk(license_id: str) -> LicenseRisk:
    """Classify a SPDX license identifier into a risk tier."""
    lid = license_id.upper().replace(" ", "-")
    for hl in _HIGH_RISK_LICENSES:
        if hl.upper() in lid:
            return LicenseRisk.HIGH
    for ml in _MEDIUM_RISK_LICENSES:
        if ml.upper() in lid:
            return LicenseRisk.MEDIUM
    for ll in _LOW_RISK_LICENSES:
        if ll.upper() in lid:
            return LicenseRisk.LOW
    if license_id in ("UNKNOWN", "", "NOASSERTION"):
        return LicenseRisk.UNKNOWN
    return LicenseRisk.MEDIUM


def _parse_version_tuple(version: str) -> Tuple[int, ...]:
    """Parse a semver string into a comparable tuple of ints."""
    parts = re.split(r"[.\-+]", version)
    result: List[int] = []
    for p in parts[:3]:
        try:
            result.append(int(p))
        except ValueError:
            break
    while len(result) < 3:
        result.append(0)
    return tuple(result)


def _sha256_of(payload: str) -> str:
    return hashlib.sha256(payload.encode()).hexdigest()


# ============================================================================
# SBOM PARSERS
# ============================================================================


def _parse_cyclonedx(raw: Dict[str, Any], sbom_id: str) -> Tuple[SBOMRecord, List[SBOMComponent]]:
    """Parse a CycloneDX JSON SBOM (v1.4 / v1.5 / v1.6)."""
    spec_version = str(raw.get("specVersion", "unknown"))
    metadata = raw.get("metadata", {})
    component_meta = metadata.get("component", {})
    name = component_meta.get("name", raw.get("serialNumber", "unknown"))
    version = component_meta.get("version", "")

    record = SBOMRecord(
        id=sbom_id,
        format=SBOMFormat.CYCLONEDX,
        spec_version=spec_version,
        name=name,
        version=version,
    )

    components: List[SBOMComponent] = []
    for comp in raw.get("components", []):
        cname = comp.get("name", "")
        cversion = comp.get("version", "")
        if not cname:
            continue
        license_id = "UNKNOWN"
        licenses = comp.get("licenses", [])
        if licenses:
            first = licenses[0]
            lic = first.get("license", first)
            license_id = lic.get("id", lic.get("name", "UNKNOWN"))
        hashes: Dict[str, str] = {}
        for h in comp.get("hashes", []):
            alg = h.get("alg", "").lower().replace("-", "")
            val = h.get("content", "")
            if alg and val:
                hashes[alg] = val
        components.append(
            SBOMComponent(
                name=cname,
                version=cversion,
                ecosystem=_infer_ecosystem_from_purl(comp.get("purl", "")),
                purl=comp.get("purl"),
                license_id=license_id,
                license_risk=_classify_license_risk(license_id),
                description=comp.get("description"),
                hashes=hashes,
                sbom_id=sbom_id,
            )
        )
    return record, components


def _parse_spdx(raw: Dict[str, Any], sbom_id: str) -> Tuple[SBOMRecord, List[SBOMComponent]]:
    """Parse an SPDX JSON SBOM (v2.2 / v2.3)."""
    spec_version = str(raw.get("spdxVersion", "unknown"))
    name = raw.get("name", "unknown")
    # document describes first package
    packages = raw.get("packages", [])
    project_version = ""
    if packages:
        project_version = packages[0].get("versionInfo", "")

    record = SBOMRecord(
        id=sbom_id,
        format=SBOMFormat.SPDX,
        spec_version=spec_version,
        name=name,
        version=project_version,
    )

    components: List[SBOMComponent] = []
    for pkg in packages:
        pname = pkg.get("name", "")
        pversion = pkg.get("versionInfo", "")
        if not pname:
            continue
        concluded = pkg.get("licenseConcluded", "NOASSERTION")
        declared = pkg.get("licenseDeclared", "NOASSERTION")
        license_id = concluded if concluded not in ("NOASSERTION", "NONE") else declared
        if license_id in ("NOASSERTION", "NONE"):
            license_id = "UNKNOWN"
        purl = pkg.get("externalRefs", [{}])[0].get("referenceLocator", "") if pkg.get("externalRefs") else None
        components.append(
            SBOMComponent(
                name=pname,
                version=pversion,
                ecosystem=_infer_ecosystem_from_purl(purl or ""),
                purl=purl,
                license_id=license_id,
                license_risk=_classify_license_risk(license_id),
                description=pkg.get("comment"),
                hashes={},
                sbom_id=sbom_id,
            )
        )
    return record, components


def _infer_ecosystem_from_purl(purl: str) -> str:
    """Extract ecosystem type from a Package URL string."""
    if not purl:
        return "unknown"
    m = re.match(r"^pkg:([a-z0-9]+)/", purl)
    return m.group(1) if m else "unknown"


def _detect_sbom_format(raw: Dict[str, Any]) -> SBOMFormat:
    """Auto-detect whether a JSON dict is CycloneDX or SPDX."""
    if "bomFormat" in raw and raw.get("bomFormat", "").lower() == "cyclonedx":
        return SBOMFormat.CYCLONEDX
    if "specVersion" in raw and raw.get("spdxVersion", ""):
        return SBOMFormat.SPDX
    if "spdxVersion" in raw:
        return SBOMFormat.SPDX
    if "components" in raw:
        return SBOMFormat.CYCLONEDX
    return SBOMFormat.UNKNOWN


# ============================================================================
# RISK SCORER
# ============================================================================


class DependencyRiskScorer:
    """Score each dependency's risk across multiple dimensions."""

    # Scoring weights (must sum to 1.0)
    _WEIGHTS = {
        "cve": 0.35,
        "maintenance": 0.20,
        "license": 0.15,
        "depth": 0.10,
        "popularity": 0.10,
        "provenance": 0.10,
    }

    def score(
        self,
        component: SBOMComponent,
        cve_count: int = 0,
        critical_cve_count: int = 0,
        days_since_last_commit: Optional[int] = None,
        open_issues_count: Optional[int] = None,
        weekly_downloads: Optional[int] = None,
        provenance_level: ProvenanceLevel = ProvenanceLevel.SLSA_0,
    ) -> DependencyRiskScore:
        breakdown: Dict[str, float] = {}

        # CVE score (0-100): each critical = 25 pts, each other = 10 pts, cap at 100
        cve_score = min(100.0, critical_cve_count * 25.0 + (cve_count - critical_cve_count) * 10.0)
        breakdown["cve"] = cve_score

        # Maintenance score: stale repos score higher risk
        if days_since_last_commit is None:
            maint_score = 50.0  # unknown
        elif days_since_last_commit > 730:
            maint_score = 90.0
        elif days_since_last_commit > 365:
            maint_score = 60.0
        elif days_since_last_commit > 180:
            maint_score = 30.0
        else:
            maint_score = 5.0
        is_maintained = days_since_last_commit is None or days_since_last_commit < 730
        breakdown["maintenance"] = maint_score

        # License score
        license_scores = {
            LicenseRisk.HIGH: 90.0,
            LicenseRisk.MEDIUM: 40.0,
            LicenseRisk.LOW: 5.0,
            LicenseRisk.UNKNOWN: 50.0,
        }
        lic_score = license_scores.get(component.license_risk, 50.0)
        breakdown["license"] = lic_score

        # Transitive depth score: deeper = higher risk of undetected issues
        depth_score = min(100.0, component.transitive_depth * 15.0)
        breakdown["depth"] = depth_score

        # Popularity score: very low downloads = suspicious / no community vetting
        if weekly_downloads is None:
            pop_score = 40.0
        elif weekly_downloads < 100:
            pop_score = 80.0
        elif weekly_downloads < 1_000:
            pop_score = 50.0
        elif weekly_downloads < 10_000:
            pop_score = 20.0
        else:
            pop_score = 5.0
        breakdown["popularity"] = pop_score

        # Provenance score: lower SLSA level = higher risk
        prov_scores = {
            ProvenanceLevel.SLSA_0: 80.0,
            ProvenanceLevel.SLSA_1: 50.0,
            ProvenanceLevel.SLSA_2: 25.0,
            ProvenanceLevel.SLSA_3: 10.0,
            ProvenanceLevel.SLSA_4: 0.0,
        }
        prov_score = prov_scores.get(provenance_level, 80.0)
        breakdown["provenance"] = prov_score

        overall = sum(breakdown[k] * self._WEIGHTS[k] for k in breakdown)
        overall = round(min(100.0, overall), 2)

        if overall >= 75:
            risk_level = RiskLevel.CRITICAL
        elif overall >= 55:
            risk_level = RiskLevel.HIGH
        elif overall >= 35:
            risk_level = RiskLevel.MEDIUM
        elif overall >= 15:
            risk_level = RiskLevel.LOW
        else:
            risk_level = RiskLevel.INFO

        return DependencyRiskScore(
            component_id=component.id,
            component_name=component.name,
            component_version=component.version,
            overall_score=overall,
            risk_level=risk_level,
            cve_count=cve_count,
            critical_cve_count=critical_cve_count,
            days_since_last_commit=days_since_last_commit,
            open_issues_count=open_issues_count,
            license_risk=component.license_risk,
            transitive_depth=component.transitive_depth,
            weekly_downloads=weekly_downloads,
            is_maintained=is_maintained,
            score_breakdown=breakdown,
        )


# ============================================================================
# ATTACK DETECTOR
# ============================================================================


class AttackDetector:
    """Detect supply chain attack patterns in component lists."""

    TYPOSQUAT_THRESHOLD = 2  # max edit distance to flag as typosquatting
    VERSION_BUMP_MAJOR_THRESHOLD = 2  # flag if major version jumps by this much

    def detect_typosquatting(self, component: SBOMComponent) -> Optional[AttackSignal]:
        """Check if component name is close to a popular package name."""
        name = component.name.lower().replace("-", "").replace("_", "")
        for popular in _POPULAR_PACKAGES:
            pop_norm = popular.lower().replace("-", "").replace("_", "")
            if name == pop_norm:
                return None  # exact match — not a typosquat
            dist = _levenshtein(name, pop_norm)
            if 0 < dist <= self.TYPOSQUAT_THRESHOLD:
                confidence = max(0.1, 1.0 - (dist / max(len(pop_norm), 1)) * 0.5)
                return AttackSignal(
                    attack_type=AttackType.TYPOSQUATTING,
                    severity=RiskLevel.HIGH,
                    component_name=component.name,
                    component_version=component.version,
                    description=(
                        f"'{component.name}' is {dist} edit(s) away from popular package "
                        f"'{popular}' — possible typosquatting attack"
                    ),
                    evidence={"edit_distance": dist, "popular_package": popular},
                    similar_package=popular,
                    confidence=round(confidence, 3),
                )
        return None

    def detect_dependency_confusion(
        self, component: SBOMComponent, internal_namespaces: List[str]
    ) -> Optional[AttackSignal]:
        """
        Detect dependency confusion: an internal package name that also exists
        (or could exist) on a public registry.
        """
        if not component.is_internal:
            return None
        # If the component name matches a popular public package name, flag it
        name_lower = component.name.lower()
        for popular in _POPULAR_PACKAGES:
            if name_lower == popular.lower():
                return AttackSignal(
                    attack_type=AttackType.DEPENDENCY_CONFUSION,
                    severity=RiskLevel.CRITICAL,
                    component_name=component.name,
                    component_version=component.version,
                    description=(
                        f"Internal package '{component.name}' shares its name with "
                        f"public package '{popular}' — dependency confusion risk"
                    ),
                    evidence={"public_match": popular, "is_internal": True},
                    similar_package=popular,
                    confidence=0.90,
                )
        # Check if internal namespace is exposed publicly (namespace not in allowed list)
        for ns in internal_namespaces:
            if component.name.startswith(ns):
                return None  # explicitly tracked internal — ok
        return None

    def detect_version_bump(
        self,
        component: SBOMComponent,
        previous_version: Optional[str],
    ) -> Optional[AttackSignal]:
        """Detect unexpected major version bumps that could indicate a hijack."""
        if previous_version is None:
            return None
        prev = _parse_version_tuple(previous_version)
        curr = _parse_version_tuple(component.version)
        if len(prev) < 1 or len(curr) < 1:
            return None
        major_jump = curr[0] - prev[0]
        if major_jump >= self.VERSION_BUMP_MAJOR_THRESHOLD:
            return AttackSignal(
                attack_type=AttackType.VERSION_BUMP,
                severity=RiskLevel.HIGH,
                component_name=component.name,
                component_version=component.version,
                description=(
                    f"'{component.name}' jumped {major_jump} major version(s): "
                    f"{previous_version} → {component.version} — possible supply chain hijack"
                ),
                evidence={
                    "previous_version": previous_version,
                    "current_version": component.version,
                    "major_jump": major_jump,
                },
                confidence=0.70,
            )
        return None

    def scan_components(
        self,
        components: List[SBOMComponent],
        internal_namespaces: Optional[List[str]] = None,
        version_history: Optional[Dict[str, str]] = None,
        org_id: str = "default",
    ) -> List[AttackSignal]:
        """Run all detectors across a list of components."""
        signals: List[AttackSignal] = []
        ns = internal_namespaces or []
        vh = version_history or {}
        for comp in components:
            sig = self.detect_typosquatting(comp)
            if sig:
                sig.org_id = org_id
                signals.append(sig)
            sig = self.detect_dependency_confusion(comp, ns)
            if sig:
                sig.org_id = org_id
                signals.append(sig)
            sig = self.detect_version_bump(comp, vh.get(comp.name))
            if sig:
                sig.org_id = org_id
                signals.append(sig)
        return signals


# ============================================================================
# PROVENANCE VERIFIER
# ============================================================================


class ProvenanceVerifier:
    """Stub verifier for SLSA provenance and build attestations."""

    def verify_attestation(
        self,
        component_name: str,
        component_version: str,
        attestation_json: Optional[str] = None,
        signature: Optional[str] = None,
        expected_keyid: Optional[str] = None,
    ) -> ProvenanceRecord:
        """
        Verify a build attestation for a component.

        In production this would:
        - Verify the signature using sigstore / cosign
        - Validate the SLSA predicate schema
        - Check the builder identity against a trusted builder list
        - Confirm source digest matches the released artifact

        For now this is a structured stub that parses the attestation envelope
        and checks basic well-formedness.
        """
        errors: List[str] = []
        slsa_level = ProvenanceLevel.SLSA_0
        builder_id = None
        build_system = None
        source_uri = None
        source_digest = None
        build_config_uri = None

        if attestation_json:
            try:
                att = json.loads(attestation_json)
                pred = att.get("predicate", att)
                builder_id = pred.get("builder", {}).get("id")
                build_system = pred.get("buildType")
                source_uri = pred.get("invocation", {}).get("configSource", {}).get("uri")
                source_digest = pred.get("invocation", {}).get("configSource", {}).get("digest", {}).get("sha1")
                build_config_uri = pred.get("buildConfig", {}).get("steps", [{}])[0].get("entryPoint") if pred.get("buildConfig") else None

                # Determine SLSA level from builder metadata
                if builder_id:
                    if "github" in builder_id.lower():
                        slsa_level = ProvenanceLevel.SLSA_3
                    elif "google" in builder_id.lower() or "gcp" in builder_id.lower():
                        slsa_level = ProvenanceLevel.SLSA_3
                    else:
                        slsa_level = ProvenanceLevel.SLSA_1
                else:
                    errors.append("Missing builder.id in attestation — cannot determine SLSA level")

            except (json.JSONDecodeError, TypeError, KeyError) as exc:
                errors.append(f"Failed to parse attestation JSON: {exc}")
        else:
            errors.append("No attestation provided — SLSA level 0 (no provenance)")

        # Signature verification stub
        sig_verified = False
        sig_keyid = None
        if signature and attestation_json:
            # In production: verify using sigstore rekor / cosign
            # Stub: check keyid matches expected
            if expected_keyid and expected_keyid in signature:
                sig_verified = True
                sig_keyid = expected_keyid
            else:
                errors.append("Signature verification skipped — production stub (integrate cosign)")

        return ProvenanceRecord(
            component_name=component_name,
            component_version=component_version,
            slsa_level=slsa_level,
            build_system=build_system,
            build_config_uri=build_config_uri,
            builder_id=builder_id,
            source_uri=source_uri,
            source_digest=source_digest,
            attestation_payload=attestation_json,
            signature_verified=sig_verified,
            signature_keyid=sig_keyid,
            verification_errors=errors,
        )


# ============================================================================
# POLICY ENGINE
# ============================================================================


class PolicyEngine:
    """Evaluate components against configured supply chain policies."""

    def evaluate(
        self,
        component: SBOMComponent,
        risk_score: DependencyRiskScore,
        policies: List[SupplyChainPolicy],
        provenance: Optional[ProvenanceRecord] = None,
    ) -> List[PolicyViolation]:
        """Return all policy violations for a component."""
        violations: List[PolicyViolation] = []
        for policy in policies:
            if not policy.enabled:
                continue
            self._check_license(component, policy, violations)
            self._check_cves(component, risk_score, policy, violations)
            self._check_risk_score(component, risk_score, policy, violations)
            self._check_depth(component, policy, violations)
            self._check_provenance(component, provenance, policy, violations)
        return violations

    def _check_license(
        self,
        component: SBOMComponent,
        policy: SupplyChainPolicy,
        violations: List[PolicyViolation],
    ) -> None:
        lid = component.license_id.upper()
        for blocked in policy.blocked_licenses:
            if blocked.upper() in lid:
                violations.append(
                    PolicyViolation(
                        policy_id=policy.id,
                        policy_name=policy.name,
                        component_name=component.name,
                        component_version=component.version,
                        action=policy.action,
                        reason=f"License '{component.license_id}' is blocked by policy (blocked: {blocked})",
                    )
                )
                return

    def _check_cves(
        self,
        component: SBOMComponent,
        score: DependencyRiskScore,
        policy: SupplyChainPolicy,
        violations: List[PolicyViolation],
    ) -> None:
        if score.critical_cve_count > policy.max_critical_cves:
            violations.append(
                PolicyViolation(
                    policy_id=policy.id,
                    policy_name=policy.name,
                    component_name=component.name,
                    component_version=component.version,
                    action=policy.action,
                    reason=(
                        f"Component has {score.critical_cve_count} critical CVE(s); "
                        f"policy allows max {policy.max_critical_cves}"
                    ),
                )
            )

    def _check_risk_score(
        self,
        component: SBOMComponent,
        score: DependencyRiskScore,
        policy: SupplyChainPolicy,
        violations: List[PolicyViolation],
    ) -> None:
        if score.overall_score > policy.max_overall_risk_score:
            violations.append(
                PolicyViolation(
                    policy_id=policy.id,
                    policy_name=policy.name,
                    component_name=component.name,
                    component_version=component.version,
                    action=policy.action,
                    reason=(
                        f"Risk score {score.overall_score:.1f} exceeds policy maximum "
                        f"{policy.max_overall_risk_score:.1f}"
                    ),
                )
            )

    def _check_depth(
        self,
        component: SBOMComponent,
        policy: SupplyChainPolicy,
        violations: List[PolicyViolation],
    ) -> None:
        if policy.max_transitive_depth is not None:
            if component.transitive_depth > policy.max_transitive_depth:
                violations.append(
                    PolicyViolation(
                        policy_id=policy.id,
                        policy_name=policy.name,
                        component_name=component.name,
                        component_version=component.version,
                        action=policy.action,
                        reason=(
                            f"Transitive depth {component.transitive_depth} exceeds "
                            f"policy maximum {policy.max_transitive_depth}"
                        ),
                    )
                )

    def _check_provenance(
        self,
        component: SBOMComponent,
        provenance: Optional[ProvenanceRecord],
        policy: SupplyChainPolicy,
        violations: List[PolicyViolation],
    ) -> None:
        required = policy.required_provenance_level
        if required == ProvenanceLevel.SLSA_0:
            return  # no requirement
        if provenance is None:
            violations.append(
                PolicyViolation(
                    policy_id=policy.id,
                    policy_name=policy.name,
                    component_name=component.name,
                    component_version=component.version,
                    action=policy.action,
                    reason=f"No provenance record — policy requires {required.value}",
                )
            )
            return
        level_order = [p.value for p in ProvenanceLevel]
        actual_idx = level_order.index(provenance.slsa_level.value) if provenance.slsa_level.value in level_order else 0
        required_idx = level_order.index(required.value)
        if actual_idx < required_idx:
            violations.append(
                PolicyViolation(
                    policy_id=policy.id,
                    policy_name=policy.name,
                    component_name=component.name,
                    component_version=component.version,
                    action=policy.action,
                    reason=(
                        f"Provenance level {provenance.slsa_level.value} is below "
                        f"required {required.value}"
                    ),
                )
            )


# ============================================================================
# MAIN ENGINE
# ============================================================================


class SupplyChainEngine:
    """
    Central engine orchestrating SBOM management, risk scoring, attack detection,
    provenance verification, policy enforcement, and vendor risk assessment.
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self._db_path = db_path
        self._lock = threading.RLock()
        self._scorer = DependencyRiskScorer()
        self._detector = AttackDetector()
        self._verifier = ProvenanceVerifier()
        self._policy_engine = PolicyEngine()
        self._init_db()
        _logger.info("SupplyChainEngine initialised (db=%s)", db_path)

    # ------------------------------------------------------------------
    # DB SETUP
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS sboms (
                    id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL,
                    format TEXT,
                    spec_version TEXT,
                    name TEXT,
                    version TEXT,
                    component_count INTEGER DEFAULT 0,
                    sha256 TEXT,
                    source_repo TEXT,
                    created_at TEXT,
                    uploaded_at TEXT
                );
                CREATE TABLE IF NOT EXISTS components (
                    id TEXT PRIMARY KEY,
                    sbom_id TEXT NOT NULL,
                    org_id TEXT NOT NULL,
                    name TEXT,
                    version TEXT,
                    ecosystem TEXT,
                    purl TEXT,
                    license_id TEXT,
                    license_risk TEXT,
                    description TEXT,
                    transitive_depth INTEGER DEFAULT 0,
                    is_internal INTEGER DEFAULT 0,
                    hashes TEXT,
                    created_at TEXT
                );
                CREATE TABLE IF NOT EXISTS risk_scores (
                    component_id TEXT PRIMARY KEY,
                    data TEXT NOT NULL,
                    computed_at TEXT
                );
                CREATE TABLE IF NOT EXISTS attack_signals (
                    id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL,
                    data TEXT NOT NULL,
                    detected_at TEXT
                );
                CREATE TABLE IF NOT EXISTS policies (
                    id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL,
                    data TEXT NOT NULL,
                    created_at TEXT,
                    updated_at TEXT
                );
                CREATE TABLE IF NOT EXISTS vendors (
                    id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL,
                    vendor_name TEXT NOT NULL,
                    data TEXT NOT NULL,
                    updated_at TEXT
                );
                CREATE TABLE IF NOT EXISTS provenance (
                    id TEXT PRIMARY KEY,
                    component_name TEXT NOT NULL,
                    component_version TEXT NOT NULL,
                    data TEXT NOT NULL,
                    verified_at TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_components_sbom ON components(sbom_id);
                CREATE INDEX IF NOT EXISTS idx_components_org ON components(org_id);
                CREATE INDEX IF NOT EXISTS idx_signals_org ON attack_signals(org_id);
                CREATE INDEX IF NOT EXISTS idx_policies_org ON policies(org_id);
                CREATE INDEX IF NOT EXISTS idx_vendors_org ON vendors(org_id);
            """)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # SBOM MANAGEMENT
    # ------------------------------------------------------------------

    def ingest_sbom(
        self,
        raw_payload: Dict[str, Any],
        org_id: str = "default",
        source_repo: Optional[str] = None,
    ) -> Tuple[SBOMRecord, List[SBOMComponent], List[AttackSignal]]:
        """
        Parse and store an SBOM. Returns the record, components, and any
        attack signals detected during ingestion.
        """
        sbom_id = str(uuid.uuid4())
        sha256 = _sha256_of(json.dumps(raw_payload, sort_keys=True))
        fmt = _detect_sbom_format(raw_payload)

        if fmt == SBOMFormat.CYCLONEDX:
            record, components = _parse_cyclonedx(raw_payload, sbom_id)
        elif fmt == SBOMFormat.SPDX:
            record, components = _parse_spdx(raw_payload, sbom_id)
        else:
            raise ValueError("Unrecognised SBOM format — expected CycloneDX or SPDX JSON")

        record.org_id = org_id
        record.sha256 = sha256
        record.source_repo = source_repo
        record.component_count = len(components)

        # Set org on all components
        for comp in components:
            comp.sbom_id = sbom_id

        # Compute risk scores
        for comp in components:
            score = self._scorer.score(comp)
            self._upsert_risk_score(score)

        # Detect attacks
        signals = self._detector.scan_components(components, org_id=org_id)

        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO sboms VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        record.id, org_id, record.format.value, record.spec_version,
                        record.name, record.version, record.component_count,
                        record.sha256, record.source_repo,
                        record.created_at.isoformat(), record.uploaded_at.isoformat(),
                    ),
                )
                for comp in components:
                    conn.execute(
                        "INSERT OR REPLACE INTO components VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (
                            comp.id, comp.sbom_id, org_id, comp.name, comp.version,
                            comp.ecosystem, comp.purl, comp.license_id,
                            comp.license_risk.value, comp.description,
                            comp.transitive_depth, int(comp.is_internal),
                            json.dumps(comp.hashes), comp.created_at.isoformat(),
                        ),
                    )
                for sig in signals:
                    conn.execute(
                        "INSERT INTO attack_signals VALUES (?,?,?,?)",
                        (sig.id, org_id, sig.model_dump_json(), sig.detected_at.isoformat()),
                    )
        _logger.info(
            "Ingested SBOM id=%s fmt=%s components=%d signals=%d org=%s",
            sbom_id, fmt.value, len(components), len(signals), org_id,
        )
        return record, components, signals

    def _upsert_risk_score(self, score: DependencyRiskScore) -> None:
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO risk_scores VALUES (?,?,?)",
                    (score.component_id, score.model_dump_json(), score.computed_at.isoformat()),
                )

    def list_components(
        self, org_id: str = "default", limit: int = 200
    ) -> List[Dict[str, Any]]:
        """List all tracked components with their risk scores."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM components WHERE org_id=? ORDER BY rowid DESC LIMIT ?",
                (org_id, limit),
            ).fetchall()
        result = []
        for row in rows:
            comp_dict = dict(row)
            comp_dict["hashes"] = json.loads(comp_dict.get("hashes") or "{}")
            # Attach risk score if available
            with self._connect() as conn2:
                sr = conn2.execute(
                    "SELECT data FROM risk_scores WHERE component_id=?",
                    (comp_dict["id"],),
                ).fetchone()
            if sr:
                try:
                    comp_dict["risk_score"] = json.loads(sr["data"])
                except Exception:
                    comp_dict["risk_score"] = None
            result.append(comp_dict)
        return result

    def get_sbom(self, sbom_id: str, org_id: str = "default") -> Optional[SBOMRecord]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM sboms WHERE id=? AND org_id=?", (sbom_id, org_id)
            ).fetchone()
        if not row:
            return None
        d = dict(row)
        return SBOMRecord(**{k: v for k, v in d.items() if k in SBOMRecord.model_fields})

    # ------------------------------------------------------------------
    # RISK DASHBOARD
    # ------------------------------------------------------------------

    def get_risk_dashboard(self, org_id: str = "default") -> RiskDashboard:
        with self._connect() as conn:
            total_components = conn.execute(
                "SELECT COUNT(*) FROM components WHERE org_id=?", (org_id,)
            ).fetchone()[0]
            total_sboms = conn.execute(
                "SELECT COUNT(*) FROM sboms WHERE org_id=?", (org_id,)
            ).fetchone()[0]
            score_rows = conn.execute(
                """SELECT rs.data FROM risk_scores rs
                   JOIN components c ON c.id = rs.component_id
                   WHERE c.org_id = ?""",
                (org_id,),
            ).fetchall()
            signal_rows = conn.execute(
                "SELECT data FROM attack_signals WHERE org_id=? ORDER BY detected_at DESC LIMIT 20",
                (org_id,),
            ).fetchall()
            vendor_count = conn.execute(
                "SELECT COUNT(*) FROM vendors WHERE org_id=?", (org_id,)
            ).fetchone()[0]
            high_risk_vendors = conn.execute(
                "SELECT COUNT(*) FROM vendors WHERE org_id=?", (org_id,)
            ).fetchone()[0]

        scores: List[DependencyRiskScore] = []
        for row in score_rows:
            try:
                scores.append(DependencyRiskScore.model_validate_json(row["data"]))
            except Exception:
                pass

        signals: List[AttackSignal] = []
        for row in signal_rows:
            try:
                signals.append(AttackSignal.model_validate_json(row["data"]))
            except Exception:
                pass

        critical = sum(1 for s in scores if s.risk_level == RiskLevel.CRITICAL)
        high = sum(1 for s in scores if s.risk_level == RiskLevel.HIGH)
        avg_score = round(sum(s.overall_score for s in scores) / max(len(scores), 1), 2)
        top_risks = sorted(scores, key=lambda s: s.overall_score, reverse=True)[:10]

        policy_violations = 0  # would come from evaluation results in production

        return RiskDashboard(
            org_id=org_id,
            total_components=total_components,
            total_sboms=total_sboms,
            critical_components=critical,
            high_risk_components=high,
            attack_signals=len(signals),
            critical_attack_signals=sum(1 for s in signals if s.severity == RiskLevel.CRITICAL),
            policy_violations=policy_violations,
            blocked_components=0,
            avg_risk_score=avg_score,
            top_risks=top_risks,
            recent_signals=signals[:5],
            vendor_count=vendor_count,
            high_risk_vendors=high_risk_vendors,
        )

    # ------------------------------------------------------------------
    # DEPENDENCY SCAN
    # ------------------------------------------------------------------

    def scan_repo(
        self,
        repo_url: str,
        org_id: str = "default",
        branch: str = "main",
    ) -> Dict[str, Any]:
        """
        Trigger a supply chain scan for a repository.

        In production this would clone the repo, run dependency analysis tools
        (pip-audit, npm audit, trivy, grype) and return findings. This stub
        returns a scan job record that would be processed asynchronously.
        """
        scan_id = str(uuid.uuid4())
        result = {
            "scan_id": scan_id,
            "status": "queued",
            "repo_url": repo_url,
            "branch": branch,
            "org_id": org_id,
            "queued_at": datetime.now(timezone.utc).isoformat(),
            "message": (
                "Scan queued. In production this integrates with pip-audit, "
                "npm audit, trivy, and grype."
            ),
        }
        _logger.info("Supply chain scan queued scan_id=%s repo=%s", scan_id, repo_url)
        return result

    # ------------------------------------------------------------------
    # POLICIES
    # ------------------------------------------------------------------

    def create_policy(self, policy: SupplyChainPolicy) -> SupplyChainPolicy:
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO policies VALUES (?,?,?,?,?)",
                    (
                        policy.id, policy.org_id, policy.model_dump_json(),
                        policy.created_at.isoformat(), policy.updated_at.isoformat(),
                    ),
                )
        _logger.info("Policy created id=%s name=%s org=%s", policy.id, policy.name, policy.org_id)
        return policy

    def list_policies(self, org_id: str = "default") -> List[SupplyChainPolicy]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT data FROM policies WHERE org_id=? ORDER BY rowid DESC",
                (org_id,),
            ).fetchall()
        result = []
        for row in rows:
            try:
                result.append(SupplyChainPolicy.model_validate_json(row["data"]))
            except Exception:
                pass
        return result

    def get_policy(self, policy_id: str, org_id: str = "default") -> Optional[SupplyChainPolicy]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT data FROM policies WHERE id=? AND org_id=?",
                (policy_id, org_id),
            ).fetchone()
        if not row:
            return None
        return SupplyChainPolicy.model_validate_json(row["data"])

    # ------------------------------------------------------------------
    # VENDORS
    # ------------------------------------------------------------------

    def upsert_vendor(self, vendor: VendorRiskAssessment) -> VendorRiskAssessment:
        vendor.updated_at = datetime.now(timezone.utc)
        # Compute concentration risk based on component count
        if vendor.component_count >= 50:
            vendor.concentration_risk = RiskLevel.CRITICAL
        elif vendor.component_count >= 20:
            vendor.concentration_risk = RiskLevel.HIGH
        elif vendor.component_count >= 5:
            vendor.concentration_risk = RiskLevel.MEDIUM
        else:
            vendor.concentration_risk = RiskLevel.LOW
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO vendors VALUES (?,?,?,?,?)",
                    (
                        vendor.id, vendor.org_id, vendor.vendor_name,
                        vendor.model_dump_json(), vendor.updated_at.isoformat(),
                    ),
                )
        return vendor

    def list_vendors(self, org_id: str = "default") -> List[VendorRiskAssessment]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT data FROM vendors WHERE org_id=? ORDER BY rowid DESC",
                (org_id,),
            ).fetchall()
        result = []
        for row in rows:
            try:
                result.append(VendorRiskAssessment.model_validate_json(row["data"]))
            except Exception:
                pass
        return result

    def get_vendor(self, vendor_id: str, org_id: str = "default") -> Optional[VendorRiskAssessment]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT data FROM vendors WHERE id=? AND org_id=?",
                (vendor_id, org_id),
            ).fetchone()
        if not row:
            return None
        return VendorRiskAssessment.model_validate_json(row["data"])

    # ------------------------------------------------------------------
    # PROVENANCE
    # ------------------------------------------------------------------

    def verify_provenance(
        self,
        component_name: str,
        component_version: str,
        attestation_json: Optional[str] = None,
        signature: Optional[str] = None,
        expected_keyid: Optional[str] = None,
    ) -> ProvenanceRecord:
        record = self._verifier.verify_attestation(
            component_name=component_name,
            component_version=component_version,
            attestation_json=attestation_json,
            signature=signature,
            expected_keyid=expected_keyid,
        )
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO provenance VALUES (?,?,?,?,?)",
                    (
                        record.id, record.component_name, record.component_version,
                        record.model_dump_json(), record.verified_at.isoformat(),
                    ),
                )
        return record

    def get_provenance(
        self, component_name: str, component_version: Optional[str] = None
    ) -> Optional[ProvenanceRecord]:
        with self._connect() as conn:
            if component_version:
                row = conn.execute(
                    "SELECT data FROM provenance WHERE component_name=? AND component_version=? ORDER BY rowid DESC LIMIT 1",
                    (component_name, component_version),
                ).fetchone()
            else:
                row = conn.execute(
                    "SELECT data FROM provenance WHERE component_name=? ORDER BY rowid DESC LIMIT 1",
                    (component_name,),
                ).fetchone()
        if not row:
            return None
        return ProvenanceRecord.model_validate_json(row["data"])

    # ------------------------------------------------------------------
    # BRAIN GRAPH SYNC
    # ------------------------------------------------------------------

    def sync_from_brain(
        self,
        org_id: str = "default",
        brain_db_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Pull all ``component`` nodes from the KnowledgeBrain and upsert them
        into the supply-chain components table.

        Existing risk scores and metadata are preserved — we only update fields
        that come from the brain (name, version, ecosystem, purl, description).
        New components get a default risk score computed on the fly.

        Returns a summary dict with ``synced``, ``skipped``, and ``errors`` counts.
        """
        try:
            from core.knowledge_brain import (
                get_brain,  # local import to avoid circular dep
            )
        except ImportError:
            _logger.warning("sync_from_brain: knowledge_brain not available")
            return {"synced": 0, "skipped": 0, "errors": 1, "detail": "knowledge_brain unavailable"}

        brain = get_brain(brain_db_path) if brain_db_path else get_brain()

        # Query all component-type nodes scoped to this org
        result = brain.query_nodes(node_type="component", org_id=org_id, limit=5000)
        # Also fetch nodes with no org_id (ingested without org context)
        result_no_org = brain.query_nodes(node_type="component", org_id=None, limit=5000)
        # Also fetch from the ASPM scan org ("aldeci") — ASPM harness stores
        # components there regardless of the caller's org_id.
        result_aspm = brain.query_nodes(node_type="component", org_id="aldeci", limit=5000)
        # Merge, dedup by node_id
        all_nodes: Dict[str, Any] = {}
        for node in result.nodes + result_no_org.nodes + result_aspm.nodes:
            all_nodes[node["node_id"]] = node

        synced = 0
        skipped = 0
        errors = 0

        # Create a synthetic SBOM record for brain-sourced components if not exists
        brain_sbom_id = f"brain-sync-{org_id}"
        with self._lock:
            with self._connect() as conn:
                existing_sbom = conn.execute(
                    "SELECT id FROM sboms WHERE id=?", (brain_sbom_id,)
                ).fetchone()
                if not existing_sbom:
                    now_iso = datetime.now(timezone.utc).isoformat()
                    conn.execute(
                        "INSERT OR IGNORE INTO sboms VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                        (
                            brain_sbom_id, org_id, "cyclonedx", "1.4",
                            "Brain Graph Sync", "auto",
                            0,  # component_count updated below
                            "", None, now_iso, now_iso,
                        ),
                    )

        for node in all_nodes.values():
            try:
                props = node.get("properties", {})
                node_id = node["node_id"]
                name = props.get("name") or props.get("package_name") or node_id
                version = props.get("version") or props.get("package_version") or "unknown"
                ecosystem = props.get("ecosystem") or props.get("language") or "unknown"
                purl = props.get("purl")
                description = props.get("description") or props.get("summary")
                license_id = props.get("license") or props.get("license_id") or "UNKNOWN"
                license_risk = _classify_license_risk(license_id)

                # Use node_id as stable component id (deterministic, no duplicates)
                comp_id = hashlib.sha256(
                    f"{org_id}:{node_id}".encode()
                ).hexdigest()[:36]

                with self._lock:
                    with self._connect() as conn:
                        existing = conn.execute(
                            "SELECT id FROM components WHERE id=?", (comp_id,)
                        ).fetchone()

                        if existing:
                            # Preserve existing risk scores — only update brain-sourced fields
                            conn.execute(
                                """UPDATE components SET name=?, version=?, ecosystem=?,
                                   purl=?, description=?, license_id=?, license_risk=?
                                   WHERE id=?""",
                                (
                                    name, version, ecosystem, purl, description,
                                    license_id, license_risk.value, comp_id,
                                ),
                            )
                            skipped += 1
                        else:
                            now_iso = datetime.now(timezone.utc).isoformat()
                            conn.execute(
                                "INSERT OR IGNORE INTO components VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                                (
                                    comp_id, brain_sbom_id, org_id,
                                    name, version, ecosystem, purl,
                                    license_id, license_risk.value,
                                    description, 0, 0, "{}", now_iso,
                                ),
                            )
                            # Compute and store initial risk score
                            comp = SBOMComponent(
                                id=comp_id,
                                name=name,
                                version=version,
                                ecosystem=ecosystem,
                                purl=purl,
                                license_id=license_id,
                                license_risk=license_risk,
                                description=description,
                                sbom_id=brain_sbom_id,
                            )
                            score = self._scorer.score(comp)
                            conn.execute(
                                "INSERT OR REPLACE INTO risk_scores VALUES (?,?,?)",
                                (score.component_id, score.model_dump_json(),
                                 score.computed_at.isoformat()),
                            )
                            synced += 1

            except Exception as exc:
                _logger.warning("sync_from_brain: failed node %s — %s", node.get("node_id"), exc)
                errors += 1

        # Update component_count on the synthetic SBOM
        with self._lock:
            with self._connect() as conn:
                total = conn.execute(
                    "SELECT COUNT(*) FROM components WHERE sbom_id=?", (brain_sbom_id,)
                ).fetchone()[0]
                conn.execute(
                    "UPDATE sboms SET component_count=? WHERE id=?",
                    (total, brain_sbom_id),
                )

        _logger.info(
            "sync_from_brain: org=%s synced=%d skipped=%d errors=%d",
            org_id, synced, skipped, errors,
        )
        return {"synced": synced, "skipped": skipped, "errors": errors,
                "total_brain_nodes": len(all_nodes)}

    # ------------------------------------------------------------------
    # ATTACK SIGNALS
    # ------------------------------------------------------------------

    def list_attack_signals(
        self, org_id: str = "default", limit: int = 100
    ) -> List[AttackSignal]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT data FROM attack_signals WHERE org_id=? ORDER BY detected_at DESC LIMIT ?",
                (org_id, limit),
            ).fetchall()
        result = []
        for row in rows:
            try:
                result.append(AttackSignal.model_validate_json(row["data"]))
            except Exception:
                pass
        return result
