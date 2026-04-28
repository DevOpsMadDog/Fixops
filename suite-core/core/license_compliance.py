"""
License Compliance Engine — ALDECI Open Source License Risk Management.

Provides:
- License database with 50+ OSS licenses categorized by risk tier
- Compatibility matrix for project vs. dependency license checking
- Policy engine with configurable rules (block, warn, require-approval)
- SBOM license audit producing per-component violation reports
- Obligation tracking generating NOTICE/ATTRIBUTION content
- Risk scoring per dependency and aggregated at project level
- Dual-license detection with permissive-option recommendation

Compliance: OSS supply-chain risk management, NTIA SBOM minimum elements.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

import structlog

_logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# TrustGraph second-brain wiring
# ---------------------------------------------------------------------------
try:  # pragma: no cover - optional dependency
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except Exception:  # noqa: BLE001
    _get_tg_bus = None  # type: ignore[assignment]


def _emit_event(event_type: str, payload: dict) -> None:
    """Emit to TrustGraph event bus. Never raises."""
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


try:  # pragma: no cover
    _emit_event("engine.loaded", {"module": __name__})
except Exception:  # noqa: BLE001
    pass


# ============================================================================
# ENUMS
# ============================================================================


class LicenseCategory(str, Enum):
    """Risk tier / category for a license."""

    PERMISSIVE = "permissive"
    WEAK_COPYLEFT = "weak_copyleft"
    STRONG_COPYLEFT = "strong_copyleft"
    NON_COMMERCIAL = "non_commercial"
    PROPRIETARY = "proprietary"
    UNKNOWN = "unknown"


class CompatibilityResult(str, Enum):
    """Outcome of a compatibility check between two licenses."""

    COMPATIBLE = "compatible"
    INCOMPATIBLE = "incompatible"
    CONDITIONAL = "conditional"
    UNKNOWN = "unknown"


class PolicyAction(str, Enum):
    """Action a policy rule triggers."""

    ALLOW = "allow"
    WARN = "warn"
    BLOCK = "block"
    REQUIRE_APPROVAL = "require_approval"


class ObligationType(str, Enum):
    """Types of license obligations that must be satisfied."""

    ATTRIBUTION = "attribution"
    SOURCE_DISCLOSURE = "source_disclosure"
    PATENT_GRANT = "patent_grant"
    NETWORK_DISCLOSURE = "network_disclosure"
    TRADEMARK_RESTRICTION = "trademark_restriction"
    COPYLEFT_SHARE = "copyleft_share"
    NOTICE_FILE = "notice_file"


class ViolationSeverity(str, Enum):
    """Severity of a compliance violation."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# ============================================================================
# PYDANTIC v2 MODELS
# ============================================================================

try:
    from pydantic import BaseModel, Field, model_validator
    _PYDANTIC_V2 = True
except ImportError:
    from pydantic import BaseModel, Field  # type: ignore
    _PYDANTIC_V2 = False


class LicenseInfo(BaseModel):
    """Metadata for a single open-source license."""

    spdx_id: str = Field(..., description="SPDX license identifier, e.g. 'MIT'")
    name: str = Field(..., description="Full human-readable license name")
    category: LicenseCategory
    osi_approved: bool = Field(default=False, description="OSI-approved license")
    fsf_libre: bool = Field(default=False, description="FSF-approved free license")
    obligations: List[ObligationType] = Field(default_factory=list)
    risk_score: float = Field(
        default=0.0, ge=0.0, le=10.0, description="Base risk score 0-10"
    )
    commercial_use_allowed: bool = Field(default=True)
    patent_grant: bool = Field(default=False)
    network_disclosure: bool = Field(default=False, description="AGPL-style disclosure")
    aliases: List[str] = Field(default_factory=list, description="Common alternate names")
    url: str = Field(default="", description="License text URL")


class CompatibilityEntry(BaseModel):
    """One cell in the compatibility matrix."""

    project_license: str
    dependency_license: str
    result: CompatibilityResult
    notes: str = ""


class PolicyRule(BaseModel):
    """A single configurable policy rule."""

    rule_id: str
    description: str
    action: PolicyAction
    categories: List[LicenseCategory] = Field(default_factory=list)
    license_ids: List[str] = Field(default_factory=list, description="Specific SPDX IDs")
    enabled: bool = True


class LicensePolicy(BaseModel):
    """A full policy configuration for a project."""

    policy_id: str
    name: str
    description: str = ""
    rules: List[PolicyRule] = Field(default_factory=list)
    max_copyleft_percentage: float = Field(
        default=100.0, ge=0.0, le=100.0,
        description="Max % of dependencies that may be copyleft"
    )
    require_osi_approved: bool = False
    project_license: Optional[str] = None


class SBOMComponent(BaseModel):
    """A single component entry from an SBOM."""

    name: str
    version: str = ""
    license_expression: Optional[str] = None
    declared_licenses: List[str] = Field(default_factory=list)
    package_url: Optional[str] = None
    supplier: Optional[str] = None
    is_direct_dependency: bool = True


class LicenseViolation(BaseModel):
    """A policy violation found during SBOM audit."""

    component_name: str
    component_version: str = ""
    license_id: str
    policy_rule_id: str
    action: PolicyAction
    severity: ViolationSeverity
    message: str
    remediation: str = ""


class ObligationItem(BaseModel):
    """A concrete license obligation for a specific component."""

    component_name: str
    component_version: str = ""
    license_id: str
    obligation_type: ObligationType
    description: str
    satisfied: bool = False


class DependencyRiskScore(BaseModel):
    """Per-dependency license risk breakdown."""

    component_name: str
    component_version: str = ""
    license_id: str
    license_category: LicenseCategory
    copyleft_risk: float = Field(ge=0.0, le=10.0)
    commercial_restriction_risk: float = Field(ge=0.0, le=10.0)
    patent_risk: float = Field(ge=0.0, le=10.0)
    attribution_burden: float = Field(ge=0.0, le=10.0)
    aggregate_risk: float = Field(ge=0.0, le=10.0)
    risk_label: str = ""


class DualLicenseInfo(BaseModel):
    """Dual licensing detection result for a component."""

    component_name: str
    component_version: str = ""
    available_licenses: List[str]
    recommended_license: str
    reason: str


class ComplianceReport(BaseModel):
    """Full SBOM compliance audit report."""

    report_id: str
    generated_at: str
    policy_id: str
    project_license: Optional[str]
    total_components: int
    compliant_components: int
    violation_count: int
    violations: List[LicenseViolation]
    obligations: List[ObligationItem]
    dependency_scores: List[DependencyRiskScore]
    dual_license_detections: List[DualLicenseInfo]
    project_risk_score: float = Field(ge=0.0, le=10.0)
    project_risk_label: str
    notice_file_content: str = ""
    summary: Dict[str, Any] = Field(default_factory=dict)


# ============================================================================
# LICENSE DATABASE (50+ licenses)
# ============================================================================

_LICENSE_DB: Dict[str, LicenseInfo] = {}


def _build_license_db() -> Dict[str, LicenseInfo]:
    """Build the canonical license database at module load time."""
    entries: List[Dict[str, Any]] = [
        # ---- PERMISSIVE ----
        {
            "spdx_id": "MIT",
            "name": "MIT License",
            "category": LicenseCategory.PERMISSIVE,
            "osi_approved": True, "fsf_libre": True,
            "obligations": [ObligationType.ATTRIBUTION, ObligationType.NOTICE_FILE],
            "risk_score": 0.5,
            "commercial_use_allowed": True, "patent_grant": False, "network_disclosure": False,
            "aliases": ["MIT License", "The MIT License"],
            "url": "https://spdx.org/licenses/MIT.html",
        },
        {
            "spdx_id": "BSD-2-Clause",
            "name": 'BSD 2-Clause "Simplified" License',
            "category": LicenseCategory.PERMISSIVE,
            "osi_approved": True, "fsf_libre": True,
            "obligations": [ObligationType.ATTRIBUTION, ObligationType.NOTICE_FILE],
            "risk_score": 0.5,
            "commercial_use_allowed": True, "patent_grant": False, "network_disclosure": False,
            "aliases": ["BSD 2-Clause", "Simplified BSD", "FreeBSD"],
            "url": "https://spdx.org/licenses/BSD-2-Clause.html",
        },
        {
            "spdx_id": "BSD-3-Clause",
            "name": 'BSD 3-Clause "New" or "Revised" License',
            "category": LicenseCategory.PERMISSIVE,
            "osi_approved": True, "fsf_libre": True,
            "obligations": [ObligationType.ATTRIBUTION, ObligationType.NOTICE_FILE],
            "risk_score": 0.6,
            "commercial_use_allowed": True, "patent_grant": False, "network_disclosure": False,
            "aliases": ["BSD 3-Clause", "New BSD", "Revised BSD"],
            "url": "https://spdx.org/licenses/BSD-3-Clause.html",
        },
        {
            "spdx_id": "Apache-2.0",
            "name": "Apache License 2.0",
            "category": LicenseCategory.PERMISSIVE,
            "osi_approved": True, "fsf_libre": True,
            "obligations": [
                ObligationType.ATTRIBUTION,
                ObligationType.NOTICE_FILE,
                ObligationType.PATENT_GRANT,
            ],
            "risk_score": 1.0,
            "commercial_use_allowed": True, "patent_grant": True, "network_disclosure": False,
            "aliases": ["Apache 2", "Apache License, Version 2.0"],
            "url": "https://spdx.org/licenses/Apache-2.0.html",
        },
        {
            "spdx_id": "ISC",
            "name": "ISC License",
            "category": LicenseCategory.PERMISSIVE,
            "osi_approved": True, "fsf_libre": True,
            "obligations": [ObligationType.ATTRIBUTION],
            "risk_score": 0.3,
            "commercial_use_allowed": True, "patent_grant": False, "network_disclosure": False,
            "aliases": ["ISC"],
            "url": "https://spdx.org/licenses/ISC.html",
        },
        {
            "spdx_id": "0BSD",
            "name": "BSD Zero Clause License",
            "category": LicenseCategory.PERMISSIVE,
            "osi_approved": True, "fsf_libre": False,
            "obligations": [],
            "risk_score": 0.1,
            "commercial_use_allowed": True, "patent_grant": False, "network_disclosure": False,
            "aliases": ["Zero-Clause BSD", "Free Public License 1.0.0"],
            "url": "https://spdx.org/licenses/0BSD.html",
        },
        {
            "spdx_id": "Unlicense",
            "name": "The Unlicense",
            "category": LicenseCategory.PERMISSIVE,
            "osi_approved": True, "fsf_libre": True,
            "obligations": [],
            "risk_score": 0.1,
            "commercial_use_allowed": True, "patent_grant": False, "network_disclosure": False,
            "aliases": ["Public Domain"],
            "url": "https://spdx.org/licenses/Unlicense.html",
        },
        {
            "spdx_id": "CC0-1.0",
            "name": "Creative Commons Zero v1.0 Universal",
            "category": LicenseCategory.PERMISSIVE,
            "osi_approved": False, "fsf_libre": True,
            "obligations": [],
            "risk_score": 0.2,
            "commercial_use_allowed": True, "patent_grant": False, "network_disclosure": False,
            "aliases": ["CC0", "CC0 1.0"],
            "url": "https://spdx.org/licenses/CC0-1.0.html",
        },
        {
            "spdx_id": "Zlib",
            "name": "zlib License",
            "category": LicenseCategory.PERMISSIVE,
            "osi_approved": True, "fsf_libre": True,
            "obligations": [ObligationType.ATTRIBUTION],
            "risk_score": 0.4,
            "commercial_use_allowed": True, "patent_grant": False, "network_disclosure": False,
            "aliases": ["zlib", "zlib/libpng"],
            "url": "https://spdx.org/licenses/Zlib.html",
        },
        {
            "spdx_id": "PSF-2.0",
            "name": "Python Software Foundation License 2.0",
            "category": LicenseCategory.PERMISSIVE,
            "osi_approved": True, "fsf_libre": True,
            "obligations": [ObligationType.ATTRIBUTION],
            "risk_score": 0.5,
            "commercial_use_allowed": True, "patent_grant": False, "network_disclosure": False,
            "aliases": ["Python License", "PSFL"],
            "url": "https://spdx.org/licenses/PSF-2.0.html",
        },
        {
            "spdx_id": "MIT-0",
            "name": "MIT No Attribution",
            "category": LicenseCategory.PERMISSIVE,
            "osi_approved": True, "fsf_libre": False,
            "obligations": [],
            "risk_score": 0.1,
            "commercial_use_allowed": True, "patent_grant": False, "network_disclosure": False,
            "aliases": ["MIT-0", "MIT No Attribution License"],
            "url": "https://spdx.org/licenses/MIT-0.html",
        },
        {
            "spdx_id": "BSD-4-Clause",
            "name": "BSD 4-Clause License",
            "category": LicenseCategory.PERMISSIVE,
            "osi_approved": False, "fsf_libre": False,
            "obligations": [ObligationType.ATTRIBUTION, ObligationType.NOTICE_FILE],
            "risk_score": 1.2,
            "commercial_use_allowed": True, "patent_grant": False, "network_disclosure": False,
            "aliases": ["Original BSD"],
            "url": "https://spdx.org/licenses/BSD-4-Clause.html",
        },
        {
            "spdx_id": "WTFPL",
            "name": "Do What The F*ck You Want To Public License",
            "category": LicenseCategory.PERMISSIVE,
            "osi_approved": False, "fsf_libre": True,
            "obligations": [],
            "risk_score": 0.5,
            "commercial_use_allowed": True, "patent_grant": False, "network_disclosure": False,
            "aliases": ["WTFPL"],
            "url": "https://spdx.org/licenses/WTFPL.html",
        },
        {
            "spdx_id": "Artistic-2.0",
            "name": "Artistic License 2.0",
            "category": LicenseCategory.PERMISSIVE,
            "osi_approved": True, "fsf_libre": True,
            "obligations": [ObligationType.ATTRIBUTION],
            "risk_score": 1.0,
            "commercial_use_allowed": True, "patent_grant": False, "network_disclosure": False,
            "aliases": ["Artistic 2.0"],
            "url": "https://spdx.org/licenses/Artistic-2.0.html",
        },
        # ---- WEAK COPYLEFT ----
        {
            "spdx_id": "LGPL-2.0-only",
            "name": "GNU Lesser General Public License v2.0 only",
            "category": LicenseCategory.WEAK_COPYLEFT,
            "osi_approved": True, "fsf_libre": True,
            "obligations": [
                ObligationType.ATTRIBUTION,
                ObligationType.SOURCE_DISCLOSURE,
                ObligationType.COPYLEFT_SHARE,
            ],
            "risk_score": 4.0,
            "commercial_use_allowed": True, "patent_grant": False, "network_disclosure": False,
            "aliases": ["LGPL-2.0", "LGPL v2"],
            "url": "https://spdx.org/licenses/LGPL-2.0-only.html",
        },
        {
            "spdx_id": "LGPL-2.1-only",
            "name": "GNU Lesser General Public License v2.1 only",
            "category": LicenseCategory.WEAK_COPYLEFT,
            "osi_approved": True, "fsf_libre": True,
            "obligations": [
                ObligationType.ATTRIBUTION,
                ObligationType.SOURCE_DISCLOSURE,
                ObligationType.COPYLEFT_SHARE,
            ],
            "risk_score": 4.0,
            "commercial_use_allowed": True, "patent_grant": False, "network_disclosure": False,
            "aliases": ["LGPL-2.1", "LGPL v2.1", "LGPLv2.1"],
            "url": "https://spdx.org/licenses/LGPL-2.1-only.html",
        },
        {
            "spdx_id": "LGPL-3.0-only",
            "name": "GNU Lesser General Public License v3.0 only",
            "category": LicenseCategory.WEAK_COPYLEFT,
            "osi_approved": True, "fsf_libre": True,
            "obligations": [
                ObligationType.ATTRIBUTION,
                ObligationType.SOURCE_DISCLOSURE,
                ObligationType.COPYLEFT_SHARE,
            ],
            "risk_score": 4.5,
            "commercial_use_allowed": True, "patent_grant": False, "network_disclosure": False,
            "aliases": ["LGPL-3.0", "LGPL v3", "LGPLv3"],
            "url": "https://spdx.org/licenses/LGPL-3.0-only.html",
        },
        {
            "spdx_id": "MPL-2.0",
            "name": "Mozilla Public License 2.0",
            "category": LicenseCategory.WEAK_COPYLEFT,
            "osi_approved": True, "fsf_libre": True,
            "obligations": [
                ObligationType.ATTRIBUTION,
                ObligationType.SOURCE_DISCLOSURE,
                ObligationType.PATENT_GRANT,
            ],
            "risk_score": 3.5,
            "commercial_use_allowed": True, "patent_grant": True, "network_disclosure": False,
            "aliases": ["MPL 2.0", "Mozilla Public License"],
            "url": "https://spdx.org/licenses/MPL-2.0.html",
        },
        {
            "spdx_id": "EPL-1.0",
            "name": "Eclipse Public License 1.0",
            "category": LicenseCategory.WEAK_COPYLEFT,
            "osi_approved": True, "fsf_libre": False,
            "obligations": [
                ObligationType.ATTRIBUTION,
                ObligationType.SOURCE_DISCLOSURE,
                ObligationType.PATENT_GRANT,
            ],
            "risk_score": 4.0,
            "commercial_use_allowed": True, "patent_grant": True, "network_disclosure": False,
            "aliases": ["EPL 1.0", "Eclipse License"],
            "url": "https://spdx.org/licenses/EPL-1.0.html",
        },
        {
            "spdx_id": "EPL-2.0",
            "name": "Eclipse Public License 2.0",
            "category": LicenseCategory.WEAK_COPYLEFT,
            "osi_approved": True, "fsf_libre": False,
            "obligations": [
                ObligationType.ATTRIBUTION,
                ObligationType.SOURCE_DISCLOSURE,
                ObligationType.PATENT_GRANT,
            ],
            "risk_score": 4.0,
            "commercial_use_allowed": True, "patent_grant": True, "network_disclosure": False,
            "aliases": ["EPL 2.0"],
            "url": "https://spdx.org/licenses/EPL-2.0.html",
        },
        {
            "spdx_id": "CDDL-1.0",
            "name": "Common Development and Distribution License 1.0",
            "category": LicenseCategory.WEAK_COPYLEFT,
            "osi_approved": True, "fsf_libre": False,
            "obligations": [
                ObligationType.ATTRIBUTION,
                ObligationType.SOURCE_DISCLOSURE,
            ],
            "risk_score": 3.8,
            "commercial_use_allowed": True, "patent_grant": False, "network_disclosure": False,
            "aliases": ["CDDL", "CDDL 1.0"],
            "url": "https://spdx.org/licenses/CDDL-1.0.html",
        },
        {
            "spdx_id": "EUPL-1.2",
            "name": "European Union Public License 1.2",
            "category": LicenseCategory.WEAK_COPYLEFT,
            "osi_approved": True, "fsf_libre": False,
            "obligations": [
                ObligationType.ATTRIBUTION,
                ObligationType.SOURCE_DISCLOSURE,
                ObligationType.COPYLEFT_SHARE,
            ],
            "risk_score": 4.2,
            "commercial_use_allowed": True, "patent_grant": False, "network_disclosure": False,
            "aliases": ["EUPL 1.2"],
            "url": "https://spdx.org/licenses/EUPL-1.2.html",
        },
        {
            "spdx_id": "CPOL-1.02",
            "name": "Code Project Open License 1.02",
            "category": LicenseCategory.WEAK_COPYLEFT,
            "osi_approved": False, "fsf_libre": False,
            "obligations": [ObligationType.ATTRIBUTION, ObligationType.SOURCE_DISCLOSURE],
            "risk_score": 5.0,
            "commercial_use_allowed": False, "patent_grant": False, "network_disclosure": False,
            "aliases": ["CPOL"],
            "url": "https://spdx.org/licenses/CPOL-1.02.html",
        },
        # ---- STRONG COPYLEFT ----
        {
            "spdx_id": "GPL-2.0-only",
            "name": "GNU General Public License v2.0 only",
            "category": LicenseCategory.STRONG_COPYLEFT,
            "osi_approved": True, "fsf_libre": True,
            "obligations": [
                ObligationType.ATTRIBUTION,
                ObligationType.SOURCE_DISCLOSURE,
                ObligationType.COPYLEFT_SHARE,
                ObligationType.NOTICE_FILE,
            ],
            "risk_score": 7.5,
            "commercial_use_allowed": True, "patent_grant": False, "network_disclosure": False,
            "aliases": ["GPL-2.0", "GPL v2", "GPLv2"],
            "url": "https://spdx.org/licenses/GPL-2.0-only.html",
        },
        {
            "spdx_id": "GPL-2.0-or-later",
            "name": "GNU General Public License v2.0 or later",
            "category": LicenseCategory.STRONG_COPYLEFT,
            "osi_approved": True, "fsf_libre": True,
            "obligations": [
                ObligationType.ATTRIBUTION,
                ObligationType.SOURCE_DISCLOSURE,
                ObligationType.COPYLEFT_SHARE,
                ObligationType.NOTICE_FILE,
            ],
            "risk_score": 7.0,
            "commercial_use_allowed": True, "patent_grant": False, "network_disclosure": False,
            "aliases": ["GPL-2.0+", "GPL v2+"],
            "url": "https://spdx.org/licenses/GPL-2.0-or-later.html",
        },
        {
            "spdx_id": "GPL-3.0-only",
            "name": "GNU General Public License v3.0 only",
            "category": LicenseCategory.STRONG_COPYLEFT,
            "osi_approved": True, "fsf_libre": True,
            "obligations": [
                ObligationType.ATTRIBUTION,
                ObligationType.SOURCE_DISCLOSURE,
                ObligationType.COPYLEFT_SHARE,
                ObligationType.PATENT_GRANT,
                ObligationType.NOTICE_FILE,
            ],
            "risk_score": 8.0,
            "commercial_use_allowed": True, "patent_grant": True, "network_disclosure": False,
            "aliases": ["GPL-3.0", "GPL v3", "GPLv3"],
            "url": "https://spdx.org/licenses/GPL-3.0-only.html",
        },
        {
            "spdx_id": "GPL-3.0-or-later",
            "name": "GNU General Public License v3.0 or later",
            "category": LicenseCategory.STRONG_COPYLEFT,
            "osi_approved": True, "fsf_libre": True,
            "obligations": [
                ObligationType.ATTRIBUTION,
                ObligationType.SOURCE_DISCLOSURE,
                ObligationType.COPYLEFT_SHARE,
                ObligationType.PATENT_GRANT,
                ObligationType.NOTICE_FILE,
            ],
            "risk_score": 7.5,
            "commercial_use_allowed": True, "patent_grant": True, "network_disclosure": False,
            "aliases": ["GPL-3.0+", "GPL v3+"],
            "url": "https://spdx.org/licenses/GPL-3.0-or-later.html",
        },
        {
            "spdx_id": "AGPL-3.0-only",
            "name": "GNU Affero General Public License v3.0 only",
            "category": LicenseCategory.STRONG_COPYLEFT,
            "osi_approved": True, "fsf_libre": True,
            "obligations": [
                ObligationType.ATTRIBUTION,
                ObligationType.SOURCE_DISCLOSURE,
                ObligationType.COPYLEFT_SHARE,
                ObligationType.PATENT_GRANT,
                ObligationType.NETWORK_DISCLOSURE,
                ObligationType.NOTICE_FILE,
            ],
            "risk_score": 9.5,
            "commercial_use_allowed": True, "patent_grant": True, "network_disclosure": True,
            "aliases": ["AGPL-3.0", "AGPL v3", "AGPLv3"],
            "url": "https://spdx.org/licenses/AGPL-3.0-only.html",
        },
        {
            "spdx_id": "AGPL-3.0-or-later",
            "name": "GNU Affero General Public License v3.0 or later",
            "category": LicenseCategory.STRONG_COPYLEFT,
            "osi_approved": True, "fsf_libre": True,
            "obligations": [
                ObligationType.ATTRIBUTION,
                ObligationType.SOURCE_DISCLOSURE,
                ObligationType.COPYLEFT_SHARE,
                ObligationType.PATENT_GRANT,
                ObligationType.NETWORK_DISCLOSURE,
                ObligationType.NOTICE_FILE,
            ],
            "risk_score": 9.0,
            "commercial_use_allowed": True, "patent_grant": True, "network_disclosure": True,
            "aliases": ["AGPL-3.0+"],
            "url": "https://spdx.org/licenses/AGPL-3.0-or-later.html",
        },
        {
            "spdx_id": "OSL-3.0",
            "name": "Open Software License 3.0",
            "category": LicenseCategory.STRONG_COPYLEFT,
            "osi_approved": True, "fsf_libre": True,
            "obligations": [
                ObligationType.ATTRIBUTION,
                ObligationType.SOURCE_DISCLOSURE,
                ObligationType.COPYLEFT_SHARE,
            ],
            "risk_score": 6.5,
            "commercial_use_allowed": True, "patent_grant": True, "network_disclosure": True,
            "aliases": ["OSL 3.0"],
            "url": "https://spdx.org/licenses/OSL-3.0.html",
        },
        {
            "spdx_id": "SSPL-1.0",
            "name": "Server Side Public License v1",
            "category": LicenseCategory.STRONG_COPYLEFT,
            "osi_approved": False, "fsf_libre": False,
            "obligations": [
                ObligationType.SOURCE_DISCLOSURE,
                ObligationType.COPYLEFT_SHARE,
                ObligationType.NETWORK_DISCLOSURE,
            ],
            "risk_score": 9.8,
            "commercial_use_allowed": False, "patent_grant": False, "network_disclosure": True,
            "aliases": ["SSPL", "MongoDB SSPL"],
            "url": "https://spdx.org/licenses/SSPL-1.0.html",
        },
        {
            "spdx_id": "BUSL-1.1",
            "name": "Business Source License 1.1",
            "category": LicenseCategory.STRONG_COPYLEFT,
            "osi_approved": False, "fsf_libre": False,
            "obligations": [ObligationType.SOURCE_DISCLOSURE],
            "risk_score": 8.5,
            "commercial_use_allowed": False, "patent_grant": False, "network_disclosure": False,
            "aliases": ["BSL", "Business Source License"],
            "url": "https://spdx.org/licenses/BUSL-1.1.html",
        },
        # ---- NON-COMMERCIAL ----
        {
            "spdx_id": "CC-BY-NC-4.0",
            "name": "Creative Commons Attribution NonCommercial 4.0 International",
            "category": LicenseCategory.NON_COMMERCIAL,
            "osi_approved": False, "fsf_libre": False,
            "obligations": [ObligationType.ATTRIBUTION],
            "risk_score": 7.0,
            "commercial_use_allowed": False, "patent_grant": False, "network_disclosure": False,
            "aliases": ["CC-BY-NC", "CC BY-NC 4.0"],
            "url": "https://spdx.org/licenses/CC-BY-NC-4.0.html",
        },
        {
            "spdx_id": "CC-BY-NC-SA-4.0",
            "name": "Creative Commons Attribution NonCommercial ShareAlike 4.0",
            "category": LicenseCategory.NON_COMMERCIAL,
            "osi_approved": False, "fsf_libre": False,
            "obligations": [ObligationType.ATTRIBUTION, ObligationType.COPYLEFT_SHARE],
            "risk_score": 7.5,
            "commercial_use_allowed": False, "patent_grant": False, "network_disclosure": False,
            "aliases": ["CC-BY-NC-SA"],
            "url": "https://spdx.org/licenses/CC-BY-NC-SA-4.0.html",
        },
        {
            "spdx_id": "CC-BY-NC-ND-4.0",
            "name": "Creative Commons Attribution NonCommercial NoDerivatives 4.0",
            "category": LicenseCategory.NON_COMMERCIAL,
            "osi_approved": False, "fsf_libre": False,
            "obligations": [ObligationType.ATTRIBUTION],
            "risk_score": 8.0,
            "commercial_use_allowed": False, "patent_grant": False, "network_disclosure": False,
            "aliases": ["CC-BY-NC-ND"],
            "url": "https://spdx.org/licenses/CC-BY-NC-ND-4.0.html",
        },
        {
            "spdx_id": "JRL",
            "name": "Java Research License",
            "category": LicenseCategory.NON_COMMERCIAL,
            "osi_approved": False, "fsf_libre": False,
            "obligations": [ObligationType.ATTRIBUTION],
            "risk_score": 8.0,
            "commercial_use_allowed": False, "patent_grant": False, "network_disclosure": False,
            "aliases": ["Java Research License"],
            "url": "",
        },
        # ---- PROPRIETARY / OTHER ----
        {
            "spdx_id": "Proprietary",
            "name": "Proprietary License",
            "category": LicenseCategory.PROPRIETARY,
            "osi_approved": False, "fsf_libre": False,
            "obligations": [],
            "risk_score": 9.0,
            "commercial_use_allowed": False, "patent_grant": False, "network_disclosure": False,
            "aliases": ["Commercial", "All Rights Reserved"],
            "url": "",
        },
        {
            "spdx_id": "LicenseRef-scancode-public-domain",
            "name": "Public Domain",
            "category": LicenseCategory.PERMISSIVE,
            "osi_approved": False, "fsf_libre": True,
            "obligations": [],
            "risk_score": 0.1,
            "commercial_use_allowed": True, "patent_grant": False, "network_disclosure": False,
            "aliases": ["Public Domain", "PD"],
            "url": "",
        },
        {
            "spdx_id": "Elastic-2.0",
            "name": "Elastic License 2.0",
            "category": LicenseCategory.PROPRIETARY,
            "osi_approved": False, "fsf_libre": False,
            "obligations": [ObligationType.ATTRIBUTION],
            "risk_score": 8.5,
            "commercial_use_allowed": False, "patent_grant": False, "network_disclosure": False,
            "aliases": ["ELv2", "Elastic License"],
            "url": "https://spdx.org/licenses/Elastic-2.0.html",
        },
        {
            "spdx_id": "Commons-Clause",
            "name": "Commons Clause License Condition",
            "category": LicenseCategory.PROPRIETARY,
            "osi_approved": False, "fsf_libre": False,
            "obligations": [],
            "risk_score": 8.0,
            "commercial_use_allowed": False, "patent_grant": False, "network_disclosure": False,
            "aliases": ["Commons Clause"],
            "url": "",
        },
        {
            "spdx_id": "CC-BY-4.0",
            "name": "Creative Commons Attribution 4.0 International",
            "category": LicenseCategory.PERMISSIVE,
            "osi_approved": False, "fsf_libre": False,
            "obligations": [ObligationType.ATTRIBUTION],
            "risk_score": 1.5,
            "commercial_use_allowed": True, "patent_grant": False, "network_disclosure": False,
            "aliases": ["CC-BY 4.0", "CC BY 4.0"],
            "url": "https://spdx.org/licenses/CC-BY-4.0.html",
        },
        {
            "spdx_id": "CC-BY-SA-4.0",
            "name": "Creative Commons Attribution ShareAlike 4.0 International",
            "category": LicenseCategory.WEAK_COPYLEFT,
            "osi_approved": False, "fsf_libre": True,
            "obligations": [ObligationType.ATTRIBUTION, ObligationType.COPYLEFT_SHARE],
            "risk_score": 4.5,
            "commercial_use_allowed": True, "patent_grant": False, "network_disclosure": False,
            "aliases": ["CC-BY-SA", "CC BY-SA 4.0"],
            "url": "https://spdx.org/licenses/CC-BY-SA-4.0.html",
        },
        {
            "spdx_id": "OFL-1.1",
            "name": "SIL Open Font License 1.1",
            "category": LicenseCategory.WEAK_COPYLEFT,
            "osi_approved": True, "fsf_libre": True,
            "obligations": [ObligationType.ATTRIBUTION],
            "risk_score": 2.0,
            "commercial_use_allowed": True, "patent_grant": False, "network_disclosure": False,
            "aliases": ["OFL", "SIL OFL"],
            "url": "https://spdx.org/licenses/OFL-1.1.html",
        },
        {
            "spdx_id": "CPAL-1.0",
            "name": "Common Public Attribution License 1.0",
            "category": LicenseCategory.STRONG_COPYLEFT,
            "osi_approved": True, "fsf_libre": False,
            "obligations": [
                ObligationType.ATTRIBUTION,
                ObligationType.SOURCE_DISCLOSURE,
                ObligationType.NETWORK_DISCLOSURE,
            ],
            "risk_score": 7.0,
            "commercial_use_allowed": True, "patent_grant": False, "network_disclosure": True,
            "aliases": ["CPAL"],
            "url": "https://spdx.org/licenses/CPAL-1.0.html",
        },
        {
            "spdx_id": "Sleepycat",
            "name": "Sleepycat License",
            "category": LicenseCategory.STRONG_COPYLEFT,
            "osi_approved": True, "fsf_libre": True,
            "obligations": [ObligationType.SOURCE_DISCLOSURE, ObligationType.COPYLEFT_SHARE],
            "risk_score": 6.0,
            "commercial_use_allowed": False, "patent_grant": False, "network_disclosure": False,
            "aliases": ["Berkeley DB"],
            "url": "https://spdx.org/licenses/Sleepycat.html",
        },
        {
            "spdx_id": "UNKNOWN",
            "name": "Unknown License",
            "category": LicenseCategory.UNKNOWN,
            "osi_approved": False, "fsf_libre": False,
            "obligations": [],
            "risk_score": 8.0,
            "commercial_use_allowed": False, "patent_grant": False, "network_disclosure": False,
            "aliases": [],
            "url": "",
        },
        {
            "spdx_id": "EUPL-1.1",
            "name": "European Union Public License 1.1",
            "category": LicenseCategory.WEAK_COPYLEFT,
            "osi_approved": True, "fsf_libre": False,
            "obligations": [ObligationType.ATTRIBUTION, ObligationType.SOURCE_DISCLOSURE, ObligationType.COPYLEFT_SHARE],
            "risk_score": 4.0,
            "commercial_use_allowed": True, "patent_grant": False, "network_disclosure": False,
            "aliases": ["EUPL 1.1"],
            "url": "https://spdx.org/licenses/EUPL-1.1.html",
        },
        {
            "spdx_id": "LGPL-2.0-or-later",
            "name": "GNU Lesser General Public License v2.0 or later",
            "category": LicenseCategory.WEAK_COPYLEFT,
            "osi_approved": True, "fsf_libre": True,
            "obligations": [ObligationType.ATTRIBUTION, ObligationType.SOURCE_DISCLOSURE, ObligationType.COPYLEFT_SHARE],
            "risk_score": 3.8,
            "commercial_use_allowed": True, "patent_grant": False, "network_disclosure": False,
            "aliases": ["LGPL-2.0+"],
            "url": "https://spdx.org/licenses/LGPL-2.0-or-later.html",
        },
        {
            "spdx_id": "LGPL-3.0-or-later",
            "name": "GNU Lesser General Public License v3.0 or later",
            "category": LicenseCategory.WEAK_COPYLEFT,
            "osi_approved": True, "fsf_libre": True,
            "obligations": [ObligationType.ATTRIBUTION, ObligationType.SOURCE_DISCLOSURE, ObligationType.COPYLEFT_SHARE],
            "risk_score": 4.3,
            "commercial_use_allowed": True, "patent_grant": False, "network_disclosure": False,
            "aliases": ["LGPL-3.0+", "LGPLv3+"],
            "url": "https://spdx.org/licenses/LGPL-3.0-or-later.html",
        },
        {
            "spdx_id": "EPL-1.1",
            "name": "Eclipse Public License 1.1",
            "category": LicenseCategory.WEAK_COPYLEFT,
            "osi_approved": False, "fsf_libre": False,
            "obligations": [ObligationType.ATTRIBUTION, ObligationType.SOURCE_DISCLOSURE, ObligationType.PATENT_GRANT],
            "risk_score": 4.2,
            "commercial_use_allowed": True, "patent_grant": True, "network_disclosure": False,
            "aliases": ["EPL 1.1"],
            "url": "https://spdx.org/licenses/EPL-1.1.html",
        },
        {
            "spdx_id": "NPOSL-3.0",
            "name": "Non-Profit Open Software License 3.0",
            "category": LicenseCategory.NON_COMMERCIAL,
            "osi_approved": True, "fsf_libre": False,
            "obligations": [ObligationType.ATTRIBUTION, ObligationType.SOURCE_DISCLOSURE, ObligationType.COPYLEFT_SHARE],
            "risk_score": 7.0,
            "commercial_use_allowed": False, "patent_grant": True, "network_disclosure": False,
            "aliases": ["Non-Profit OSL 3.0"],
            "url": "https://spdx.org/licenses/NPOSL-3.0.html",
        },
    ]

    db: Dict[str, LicenseInfo] = {}
    for e in entries:
        info = LicenseInfo(**e)
        db[info.spdx_id] = info
        # Index by aliases too (lower-cased for lookup)
        for alias in info.aliases:
            db[alias.lower()] = info
    return db


_LICENSE_DB = _build_license_db()


# ============================================================================
# COMPATIBILITY MATRIX
# ============================================================================

# (project_license, dependency_license) -> CompatibilityResult
_COMPAT_MATRIX: Dict[Tuple[str, str], Tuple[CompatibilityResult, str]] = {
    # MIT project
    ("MIT", "MIT"): (CompatibilityResult.COMPATIBLE, "Same license"),
    ("MIT", "Apache-2.0"): (CompatibilityResult.COMPATIBLE, "Both permissive"),
    ("MIT", "BSD-2-Clause"): (CompatibilityResult.COMPATIBLE, "Both permissive"),
    ("MIT", "BSD-3-Clause"): (CompatibilityResult.COMPATIBLE, "Both permissive"),
    ("MIT", "ISC"): (CompatibilityResult.COMPATIBLE, "Both permissive"),
    ("MIT", "LGPL-2.1-only"): (CompatibilityResult.CONDITIONAL, "LGPL allows linking; distribute LGPL source"),
    ("MIT", "LGPL-3.0-only"): (CompatibilityResult.CONDITIONAL, "LGPL allows linking; distribute LGPL source"),
    ("MIT", "MPL-2.0"): (CompatibilityResult.CONDITIONAL, "MPL files stay MPL; MIT files stay MIT"),
    ("MIT", "GPL-2.0-only"): (CompatibilityResult.INCOMPATIBLE, "GPL requires entire work to be GPL"),
    ("MIT", "GPL-3.0-only"): (CompatibilityResult.INCOMPATIBLE, "GPL requires entire work to be GPL"),
    ("MIT", "AGPL-3.0-only"): (CompatibilityResult.INCOMPATIBLE, "AGPL requires entire work + network disclosure"),
    ("MIT", "AGPL-3.0-or-later"): (CompatibilityResult.INCOMPATIBLE, "AGPL requires entire work + network disclosure"),
    # Apache-2.0 project
    ("Apache-2.0", "MIT"): (CompatibilityResult.COMPATIBLE, "MIT is more permissive"),
    ("Apache-2.0", "Apache-2.0"): (CompatibilityResult.COMPATIBLE, "Same license"),
    ("Apache-2.0", "BSD-2-Clause"): (CompatibilityResult.COMPATIBLE, "BSD is permissive"),
    ("Apache-2.0", "BSD-3-Clause"): (CompatibilityResult.COMPATIBLE, "BSD is permissive"),
    ("Apache-2.0", "ISC"): (CompatibilityResult.COMPATIBLE, "ISC is permissive"),
    ("Apache-2.0", "LGPL-2.1-only"): (CompatibilityResult.CONDITIONAL, "Linking allowed; must provide LGPL source"),
    ("Apache-2.0", "LGPL-3.0-only"): (CompatibilityResult.CONDITIONAL, "Linking allowed; must provide LGPL source"),
    ("Apache-2.0", "MPL-2.0"): (CompatibilityResult.CONDITIONAL, "File-level copyleft only"),
    ("Apache-2.0", "GPL-2.0-only"): (CompatibilityResult.INCOMPATIBLE, "GPLv2 and Apache-2.0 patent clauses conflict"),
    ("Apache-2.0", "GPL-3.0-only"): (CompatibilityResult.COMPATIBLE, "Apache-2.0 is GPL-3.0 compatible per FSF"),
    ("Apache-2.0", "AGPL-3.0-only"): (CompatibilityResult.INCOMPATIBLE, "AGPL network disclosure incompatible with Apache commercial use"),
    ("Apache-2.0", "AGPL-3.0-or-later"): (CompatibilityResult.INCOMPATIBLE, "AGPL network disclosure incompatible"),
    ("Apache-2.0", "CC-BY-NC-4.0"): (CompatibilityResult.INCOMPATIBLE, "Non-commercial restriction"),
    # GPL-3.0 project
    ("GPL-3.0-only", "MIT"): (CompatibilityResult.COMPATIBLE, "MIT is compatible with GPL"),
    ("GPL-3.0-only", "Apache-2.0"): (CompatibilityResult.COMPATIBLE, "Apache-2.0 compatible with GPL-3.0"),
    ("GPL-3.0-only", "LGPL-3.0-only"): (CompatibilityResult.COMPATIBLE, "LGPL upgrades to GPL"),
    ("GPL-3.0-only", "GPL-3.0-only"): (CompatibilityResult.COMPATIBLE, "Same license"),
    ("GPL-3.0-only", "GPL-2.0-only"): (CompatibilityResult.INCOMPATIBLE, "GPL-2.0 not compatible with GPL-3.0 only"),
    ("GPL-3.0-only", "AGPL-3.0-only"): (CompatibilityResult.INCOMPATIBLE, "AGPL network clause not permitted in pure GPL"),
    ("GPL-3.0-only", "Proprietary"): (CompatibilityResult.INCOMPATIBLE, "Proprietary deps incompatible with GPL"),
    # AGPL-3.0 project
    ("AGPL-3.0-only", "MIT"): (CompatibilityResult.COMPATIBLE, "MIT compatible with AGPL"),
    ("AGPL-3.0-only", "Apache-2.0"): (CompatibilityResult.COMPATIBLE, "Apache-2.0 compatible with AGPL-3.0"),
    ("AGPL-3.0-only", "GPL-3.0-only"): (CompatibilityResult.COMPATIBLE, "GPL-3.0 compatible with AGPL"),
    ("AGPL-3.0-only", "AGPL-3.0-only"): (CompatibilityResult.COMPATIBLE, "Same license"),
    ("AGPL-3.0-only", "Proprietary"): (CompatibilityResult.INCOMPATIBLE, "Proprietary incompatible with AGPL"),
    # MPL-2.0 project
    ("MPL-2.0", "MIT"): (CompatibilityResult.COMPATIBLE, "MIT is permissive"),
    ("MPL-2.0", "Apache-2.0"): (CompatibilityResult.COMPATIBLE, "Apache-2.0 compatible with MPL-2.0"),
    ("MPL-2.0", "MPL-2.0"): (CompatibilityResult.COMPATIBLE, "Same license"),
    ("MPL-2.0", "GPL-3.0-only"): (CompatibilityResult.CONDITIONAL, "MPL 2.0 has GPL-compatible secondary license"),
    ("MPL-2.0", "AGPL-3.0-only"): (CompatibilityResult.INCOMPATIBLE, "AGPL network clause too strong for MPL"),
    # Proprietary project
    ("Proprietary", "MIT"): (CompatibilityResult.COMPATIBLE, "MIT allows proprietary use"),
    ("Proprietary", "Apache-2.0"): (CompatibilityResult.COMPATIBLE, "Apache-2.0 allows proprietary use"),
    ("Proprietary", "BSD-2-Clause"): (CompatibilityResult.COMPATIBLE, "BSD allows proprietary use"),
    ("Proprietary", "BSD-3-Clause"): (CompatibilityResult.COMPATIBLE, "BSD allows proprietary use"),
    ("Proprietary", "ISC"): (CompatibilityResult.COMPATIBLE, "ISC allows proprietary use"),
    ("Proprietary", "LGPL-2.1-only"): (CompatibilityResult.CONDITIONAL, "Allowed if linked dynamically"),
    ("Proprietary", "LGPL-3.0-only"): (CompatibilityResult.CONDITIONAL, "Allowed if linked dynamically"),
    ("Proprietary", "MPL-2.0"): (CompatibilityResult.CONDITIONAL, "Proprietary files may stay proprietary"),
    ("Proprietary", "GPL-2.0-only"): (CompatibilityResult.INCOMPATIBLE, "GPL requires open-sourcing entire work"),
    ("Proprietary", "GPL-3.0-only"): (CompatibilityResult.INCOMPATIBLE, "GPL requires open-sourcing entire work"),
    ("Proprietary", "AGPL-3.0-only"): (CompatibilityResult.INCOMPATIBLE, "AGPL requires open-sourcing + network disclosure"),
    ("Proprietary", "CC-BY-NC-4.0"): (CompatibilityResult.INCOMPATIBLE, "Non-commercial restriction blocks commercial product"),
    ("Proprietary", "SSPL-1.0"): (CompatibilityResult.INCOMPATIBLE, "SSPL requires service stack disclosure"),
}


# ============================================================================
# LICENSE DATABASE API
# ============================================================================


def get_license(spdx_id: str) -> Optional[LicenseInfo]:
    """Look up a license by SPDX ID or common alias (case-insensitive alias lookup)."""
    if spdx_id in _LICENSE_DB:
        return _LICENSE_DB[spdx_id]
    return _LICENSE_DB.get(spdx_id.lower())


def list_licenses(category: Optional[LicenseCategory] = None) -> List[LicenseInfo]:
    """Return all canonical licenses, optionally filtered by category."""
    seen: Set[str] = set()
    result: List[LicenseInfo] = []
    for info in _LICENSE_DB.values():
        if info.spdx_id not in seen:
            if category is None or info.category == category:
                result.append(info)
            seen.add(info.spdx_id)
    return sorted(result, key=lambda x: x.spdx_id)


def normalize_license_id(raw: str) -> str:
    """Normalize a raw license string to best-matching SPDX ID."""
    raw_stripped = raw.strip()
    if raw_stripped in _LICENSE_DB:
        return _LICENSE_DB[raw_stripped].spdx_id
    lower = raw_stripped.lower()
    if lower in _LICENSE_DB:
        return _LICENSE_DB[lower].spdx_id
    # Common shorthand normalization
    _NORMALIZATIONS: Dict[str, str] = {
        "gpl2": "GPL-2.0-only",
        "gpl-2": "GPL-2.0-only",
        "gpl v2": "GPL-2.0-only",
        "gplv2": "GPL-2.0-only",
        "gpl3": "GPL-3.0-only",
        "gpl-3": "GPL-3.0-only",
        "gpl v3": "GPL-3.0-only",
        "gplv3": "GPL-3.0-only",
        "agpl": "AGPL-3.0-only",
        "agplv3": "AGPL-3.0-only",
        "lgpl2": "LGPL-2.1-only",
        "lgpl3": "LGPL-3.0-only",
        "apache": "Apache-2.0",
        "apache2": "Apache-2.0",
        "bsd": "BSD-3-Clause",
        "bsd2": "BSD-2-Clause",
        "bsd3": "BSD-3-Clause",
        "cc0": "CC0-1.0",
        "mpl": "MPL-2.0",
        "epl": "EPL-2.0",
        "commercial": "Proprietary",
        "all rights reserved": "Proprietary",
        "proprietary": "Proprietary",
        "unknown": "UNKNOWN",
    }
    return _NORMALIZATIONS.get(lower, "UNKNOWN")


# ============================================================================
# COMPATIBILITY MATRIX API
# ============================================================================


def check_compatibility(
    project_license: str, dependency_license: str
) -> Tuple[CompatibilityResult, str]:
    """
    Check whether a dependency license is compatible with the project license.

    Returns (CompatibilityResult, notes_string).
    """
    proj_norm = normalize_license_id(project_license)
    dep_norm = normalize_license_id(dependency_license)

    key = (proj_norm, dep_norm)
    if key in _COMPAT_MATRIX:
        return _COMPAT_MATRIX[key]

    # Category-level fallback rules
    proj_info = get_license(proj_norm)
    dep_info = get_license(dep_norm)

    if dep_info is None or dep_info.spdx_id == "UNKNOWN":
        return (CompatibilityResult.UNKNOWN, "Dependency license unknown — manual review required")

    if proj_info is None:
        return (CompatibilityResult.UNKNOWN, "Project license unknown — manual review required")

    # If dep is non-commercial and project is commercial, block
    if not dep_info.commercial_use_allowed:
        return (CompatibilityResult.INCOMPATIBLE, "Dependency prohibits commercial use")

    # If dep is strong copyleft and project is proprietary or permissive, incompatible
    if dep_info.category == LicenseCategory.STRONG_COPYLEFT and proj_info.category in (
        LicenseCategory.PERMISSIVE,
        LicenseCategory.PROPRIETARY,
    ):
        return (
            CompatibilityResult.INCOMPATIBLE,
            f"{dep_norm} is strong copyleft — requires entire project to be {dep_norm}",
        )

    # If dep is weak copyleft and project is permissive
    if dep_info.category == LicenseCategory.WEAK_COPYLEFT and proj_info.category == LicenseCategory.PERMISSIVE:
        return (
            CompatibilityResult.CONDITIONAL,
            f"{dep_norm} is weak copyleft — linking may be allowed; check terms carefully",
        )

    # Same category — generally compatible
    if dep_info.category == proj_info.category:
        return (CompatibilityResult.COMPATIBLE, "Same license category")

    # Permissive dep is broadly compatible
    if dep_info.category == LicenseCategory.PERMISSIVE:
        return (CompatibilityResult.COMPATIBLE, "Permissive dependency is broadly compatible")

    return (CompatibilityResult.UNKNOWN, "No specific rule — manual review recommended")


# ============================================================================
# POLICY ENGINE
# ============================================================================


_DEFAULT_COMMERCIAL_POLICY = LicensePolicy(
    policy_id="default-commercial",
    name="Default Commercial Policy",
    description="Blocks strong copyleft in commercial software, warns on weak copyleft",
    rules=[
        PolicyRule(
            rule_id="block-agpl",
            description="Block AGPL licenses in commercial projects",
            action=PolicyAction.BLOCK,
            categories=[LicenseCategory.STRONG_COPYLEFT],
            license_ids=["AGPL-3.0-only", "AGPL-3.0-or-later", "SSPL-1.0"],
        ),
        PolicyRule(
            rule_id="block-gpl",
            description="Block GPL licenses in commercial projects",
            action=PolicyAction.BLOCK,
            categories=[LicenseCategory.STRONG_COPYLEFT],
            license_ids=["GPL-2.0-only", "GPL-2.0-or-later", "GPL-3.0-only", "GPL-3.0-or-later"],
        ),
        PolicyRule(
            rule_id="block-non-commercial",
            description="Block non-commercial licenses",
            action=PolicyAction.BLOCK,
            categories=[LicenseCategory.NON_COMMERCIAL],
        ),
        PolicyRule(
            rule_id="warn-lgpl",
            description="Warn on LGPL usage",
            action=PolicyAction.WARN,
            categories=[LicenseCategory.WEAK_COPYLEFT],
            license_ids=["LGPL-2.0-only", "LGPL-2.1-only", "LGPL-3.0-only"],
        ),
        PolicyRule(
            rule_id="require-approval-unknown",
            description="Require manual approval for unknown licenses",
            action=PolicyAction.REQUIRE_APPROVAL,
            categories=[LicenseCategory.UNKNOWN],
        ),
        PolicyRule(
            rule_id="warn-proprietary",
            description="Warn on proprietary dependency licenses",
            action=PolicyAction.WARN,
            categories=[LicenseCategory.PROPRIETARY],
        ),
    ],
    max_copyleft_percentage=10.0,
    require_osi_approved=False,
)


def evaluate_license_policy(
    license_id: str, policy: LicensePolicy
) -> Tuple[PolicyAction, Optional[PolicyRule]]:
    """
    Evaluate a single license against a policy.

    Returns (action, matching_rule). Action is ALLOW if no rule matches.
    """
    norm_id = normalize_license_id(license_id)
    info = get_license(norm_id)
    category = info.category if info else LicenseCategory.UNKNOWN

    best_action = PolicyAction.ALLOW
    best_rule: Optional[PolicyRule] = None

    _action_rank = {
        PolicyAction.ALLOW: 0,
        PolicyAction.WARN: 1,
        PolicyAction.REQUIRE_APPROVAL: 2,
        PolicyAction.BLOCK: 3,
    }

    for rule in policy.rules:
        if not rule.enabled:
            continue
        matches = False
        if category in rule.categories:
            matches = True
        if norm_id in rule.license_ids or license_id in rule.license_ids:
            matches = True
        if matches and _action_rank[rule.action] > _action_rank[best_action]:
            best_action = rule.action
            best_rule = rule

    # OSI requirement check
    if policy.require_osi_approved and info and not info.osi_approved:
        if _action_rank[PolicyAction.WARN] > _action_rank[best_action]:
            best_action = PolicyAction.WARN

    return best_action, best_rule


# ============================================================================
# OBLIGATION TRACKER
# ============================================================================

_OBLIGATION_DESCRIPTIONS: Dict[ObligationType, str] = {
    ObligationType.ATTRIBUTION: "Include copyright notice and license text in documentation or UI",
    ObligationType.SOURCE_DISCLOSURE: "Provide access to complete corresponding source code",
    ObligationType.PATENT_GRANT: "Patent rights are granted to users; contributor cannot sue for patent infringement",
    ObligationType.NETWORK_DISCLOSURE: "If running as a network service, make source available to users",
    ObligationType.TRADEMARK_RESTRICTION: "Do not use contributor names or trademarks for endorsement",
    ObligationType.COPYLEFT_SHARE: "Derivative works must use the same license",
    ObligationType.NOTICE_FILE: "Retain all copyright, patent, trademark, and attribution notices",
}


def extract_obligations(components: List[SBOMComponent]) -> List[ObligationItem]:
    """Extract license obligations for all SBOM components."""
    items: List[ObligationItem] = []
    for comp in components:
        licenses = _resolve_component_licenses(comp)
        for lic_id in licenses:
            norm = normalize_license_id(lic_id)
            info = get_license(norm)
            if info is None:
                continue
            for obligation in info.obligations:
                items.append(
                    ObligationItem(
                        component_name=comp.name,
                        component_version=comp.version,
                        license_id=norm,
                        obligation_type=obligation,
                        description=_OBLIGATION_DESCRIPTIONS.get(obligation, ""),
                        satisfied=False,
                    )
                )
    return items


def generate_notice_file(obligations: List[ObligationItem], components: List[SBOMComponent]) -> str:
    """Generate NOTICE/ATTRIBUTION file content from obligations."""
    lines: List[str] = [
        "NOTICE",
        "=" * 70,
        "",
        "This product includes software developed by third parties.",
        "The following is a list of all third-party components and their license obligations.",
        "",
    ]

    # Group by component
    comp_map: Dict[str, List[ObligationItem]] = {}
    for ob in obligations:
        key = f"{ob.component_name}@{ob.component_version}"
        comp_map.setdefault(key, []).append(ob)

    for comp_key, obs in sorted(comp_map.items()):
        license_ids = list(dict.fromkeys(o.license_id for o in obs))
        lines.append(f"Component: {comp_key}")
        lines.append(f"License(s): {', '.join(license_ids)}")
        for ob in obs:
            if ob.obligation_type == ObligationType.ATTRIBUTION:
                lines.append(f"  - Attribution required: include copyright notice for {ob.component_name}")
            elif ob.obligation_type == ObligationType.SOURCE_DISCLOSURE:
                lines.append(f"  - Source disclosure: provide source code for {ob.component_name}")
            elif ob.obligation_type == ObligationType.NOTICE_FILE:
                lines.append(f"  - Retain all notices from {ob.component_name}")
        lines.append("")

    lines.append("=" * 70)
    lines.append("Generated by ALDECI License Compliance Engine")
    lines.append(f"Generated at: {datetime.now(timezone.utc).isoformat()}")
    return "\n".join(lines)


# ============================================================================
# RISK SCORING
# ============================================================================


def score_dependency_license(component: SBOMComponent) -> DependencyRiskScore:
    """Compute license risk score for a single SBOM component."""
    licenses = _resolve_component_licenses(component)
    primary_id = licenses[0] if licenses else "UNKNOWN"
    norm_id = normalize_license_id(primary_id)
    info = get_license(norm_id)

    if info is None:
        return DependencyRiskScore(
            component_name=component.name,
            component_version=component.version,
            license_id="UNKNOWN",
            license_category=LicenseCategory.UNKNOWN,
            copyleft_risk=8.0,
            commercial_restriction_risk=8.0,
            patent_risk=0.0,
            attribution_burden=0.0,
            aggregate_risk=8.0,
            risk_label="high",
        )

    copyleft_risk = {
        LicenseCategory.PERMISSIVE: 0.0,
        LicenseCategory.WEAK_COPYLEFT: 4.0,
        LicenseCategory.STRONG_COPYLEFT: 8.5,
        LicenseCategory.NON_COMMERCIAL: 3.0,
        LicenseCategory.PROPRIETARY: 2.0,
        LicenseCategory.UNKNOWN: 8.0,
    }[info.category]

    commercial_restriction_risk = 0.0 if info.commercial_use_allowed else 9.0
    if info.category == LicenseCategory.NON_COMMERCIAL:
        commercial_restriction_risk = 9.0

    # Network disclosure (AGPL-style) is a severe additional risk factor
    network_disclosure_risk = 9.0 if info.network_disclosure else 0.0

    patent_risk = 0.0
    if ObligationType.PATENT_GRANT not in info.obligations and info.category in (
        LicenseCategory.STRONG_COPYLEFT,
        LicenseCategory.WEAK_COPYLEFT,
    ):
        patent_risk = 3.0

    attribution_burden = 0.0
    if ObligationType.ATTRIBUTION in info.obligations:
        attribution_burden += 1.0
    if ObligationType.NOTICE_FILE in info.obligations:
        attribution_burden += 0.5
    if ObligationType.SOURCE_DISCLOSURE in info.obligations:
        attribution_burden += 3.0
    attribution_burden = min(10.0, attribution_burden)

    aggregate = min(
        10.0,
        (copyleft_risk * 0.40)
        + (commercial_restriction_risk * 0.25)
        + (network_disclosure_risk * 0.20)
        + (patent_risk * 0.08)
        + (attribution_burden * 0.07),
    )
    # Network-disclosure licenses (AGPL-style) are always at least critical risk
    if info.network_disclosure:
        aggregate = max(aggregate, 8.0)
    # Unknown licenses are always at least high risk
    if info.category == LicenseCategory.UNKNOWN:
        aggregate = max(aggregate, 6.0)

    risk_label = (
        "critical" if aggregate >= 8.0
        else "high" if aggregate >= 6.0
        else "medium" if aggregate >= 3.0
        else "low"
    )

    return DependencyRiskScore(
        component_name=component.name,
        component_version=component.version,
        license_id=norm_id,
        license_category=info.category,
        copyleft_risk=round(copyleft_risk, 2),
        commercial_restriction_risk=round(commercial_restriction_risk, 2),
        patent_risk=round(patent_risk, 2),
        attribution_burden=round(attribution_burden, 2),
        aggregate_risk=round(aggregate, 2),
        risk_label=risk_label,
    )


def compute_project_risk_score(scores: List[DependencyRiskScore]) -> Tuple[float, str]:
    """Aggregate per-component scores into a project-level license risk score."""
    if not scores:
        return 0.0, "none"
    total = sum(s.aggregate_risk for s in scores)
    avg = total / len(scores)
    max_score = max(s.aggregate_risk for s in scores)
    # Weighted: 60% max + 40% average
    project_score = round(min(10.0, max_score * 0.6 + avg * 0.4), 2)
    label = (
        "critical" if project_score >= 8.0
        else "high" if project_score >= 6.0
        else "medium" if project_score >= 3.0
        else "low"
    )
    return project_score, label


# ============================================================================
# DUAL LICENSE DETECTION
# ============================================================================


def detect_dual_licenses(components: List[SBOMComponent]) -> List[DualLicenseInfo]:
    """
    Detect components that declare multiple licenses (dual-licensing).
    Recommends the most permissive option.
    """
    results: List[DualLicenseInfo] = []
    for comp in components:
        all_licenses: List[str] = list(comp.declared_licenses)
        if comp.license_expression:
            # Parse OR expressions as dual-licensing
            expr = comp.license_expression
            if " OR " in expr.upper():
                parts = [p.strip() for p in expr.split(" OR ")]
                all_licenses = list(dict.fromkeys(all_licenses + parts))

        if len(all_licenses) < 2:
            continue

        # Pick recommended: lowest risk_score
        normed = [(normalize_license_id(l), l) for l in all_licenses]
        scored = [
            (nid, orig, (get_license(nid) or get_license("UNKNOWN")).risk_score)
            for nid, orig in normed
        ]
        scored.sort(key=lambda x: x[2])
        recommended = scored[0][0]
        reason = (
            f"{recommended} has the lowest risk score ({scored[0][2]:.1f}) "
            f"among available options: {', '.join(s[0] for s in scored)}"
        )
        results.append(
            DualLicenseInfo(
                component_name=comp.name,
                component_version=comp.version,
                available_licenses=[s[0] for s in scored],
                recommended_license=recommended,
                reason=reason,
            )
        )
    return results


# ============================================================================
# SBOM AUDIT (main entry point)
# ============================================================================


def _resolve_component_licenses(comp: SBOMComponent) -> List[str]:
    """Resolve a component's license(s) to a deduplicated list."""
    licenses: List[str] = []
    if comp.license_expression:
        # Simple: split on AND/OR, take distinct
        for part in comp.license_expression.replace(" AND ", " OR ").split(" OR "):
            part = part.strip().strip("()")
            if part:
                licenses.append(part)
    licenses.extend(comp.declared_licenses)
    # Deduplicate, preserving order
    seen: Set[str] = set()
    result: List[str] = []
    for l in licenses:
        if l not in seen:
            seen.add(l)
            result.append(l)
    return result or ["UNKNOWN"]


def _violation_severity(action: PolicyAction, license_category: LicenseCategory) -> ViolationSeverity:
    if action == PolicyAction.BLOCK:
        if license_category in (LicenseCategory.STRONG_COPYLEFT, LicenseCategory.NON_COMMERCIAL):
            return ViolationSeverity.CRITICAL
        return ViolationSeverity.HIGH
    if action == PolicyAction.REQUIRE_APPROVAL:
        return ViolationSeverity.MEDIUM
    if action == PolicyAction.WARN:
        return ViolationSeverity.LOW
    return ViolationSeverity.INFO


def audit_sbom(
    components: List[SBOMComponent],
    policy: Optional[LicensePolicy] = None,
    report_id: Optional[str] = None,
) -> ComplianceReport:
    """
    Run a full license compliance audit against an SBOM component list.

    Args:
        components: List of SBOM components to audit.
        policy: Policy to apply (defaults to default commercial policy).
        report_id: Optional report identifier.

    Returns:
        ComplianceReport with violations, obligations, risk scores, and notice content.
    """
    import uuid as _uuid

    if policy is None:
        policy = _DEFAULT_COMMERCIAL_POLICY
    if report_id is None:
        report_id = str(_uuid.uuid4())

    log = _logger.bind(report_id=report_id, component_count=len(components))
    log.info("license_audit_start")

    violations: List[LicenseViolation] = []
    dep_scores: List[DependencyRiskScore] = []
    compliant_count = 0

    # Dual license detection
    dual_detections = detect_dual_licenses(components)
    # Map component name -> recommended license for policy checks
    dual_map = {d.component_name: d.recommended_license for d in dual_detections}

    for comp in components:
        licenses = _resolve_component_licenses(comp)

        # If dual-licensed, use recommended license for policy evaluation
        effective_licenses = [dual_map.get(comp.name, l) for l in licenses]
        effective_licenses = list(dict.fromkeys(effective_licenses))

        comp_violated = False
        for lic_id in effective_licenses:
            norm_id = normalize_license_id(lic_id)
            info = get_license(norm_id)
            category = info.category if info else LicenseCategory.UNKNOWN

            action, rule = evaluate_license_policy(lic_id, policy)

            # Compatibility check with project license
            compat_action = PolicyAction.ALLOW
            compat_notes = ""
            if policy.project_license:
                compat_result, compat_notes = check_compatibility(policy.project_license, lic_id)
                if compat_result == CompatibilityResult.INCOMPATIBLE:
                    compat_action = PolicyAction.BLOCK
                elif compat_result == CompatibilityResult.UNKNOWN:
                    compat_action = PolicyAction.REQUIRE_APPROVAL

            final_action = action
            _rank = {PolicyAction.ALLOW: 0, PolicyAction.WARN: 1, PolicyAction.REQUIRE_APPROVAL: 2, PolicyAction.BLOCK: 3}
            if _rank[compat_action] > _rank[action]:
                final_action = compat_action

            if final_action != PolicyAction.ALLOW:
                comp_violated = True
                sev = _violation_severity(final_action, category)
                rule_id = rule.rule_id if rule else "compatibility-check"
                msg = (
                    compat_notes
                    if compat_action != PolicyAction.ALLOW and compat_notes
                    else (rule.description if rule else f"License {norm_id} flagged by policy")
                )
                remediation = _remediation_hint(norm_id, final_action, policy.project_license)
                violations.append(
                    LicenseViolation(
                        component_name=comp.name,
                        component_version=comp.version,
                        license_id=norm_id,
                        policy_rule_id=rule_id,
                        action=final_action,
                        severity=sev,
                        message=msg,
                        remediation=remediation,
                    )
                )

        if not comp_violated:
            compliant_count += 1

        # Risk score
        dep_scores.append(score_dependency_license(comp))

    # Max copyleft check
    total = len(components)
    if total > 0:
        copyleft_count = sum(
            1 for s in dep_scores
            if s.license_category in (LicenseCategory.STRONG_COPYLEFT, LicenseCategory.WEAK_COPYLEFT)
        )
        copyleft_pct = copyleft_count / total * 100
        if copyleft_pct > policy.max_copyleft_percentage:
            violations.append(
                LicenseViolation(
                    component_name="(project-wide)",
                    component_version="",
                    license_id="multiple",
                    policy_rule_id="max-copyleft-percentage",
                    action=PolicyAction.WARN,
                    severity=ViolationSeverity.MEDIUM,
                    message=(
                        f"Copyleft dependency percentage {copyleft_pct:.1f}% exceeds "
                        f"policy limit of {policy.max_copyleft_percentage:.1f}%"
                    ),
                    remediation="Replace some copyleft dependencies with permissively-licensed alternatives",
                )
            )

    obligations = extract_obligations(components)
    notice_content = generate_notice_file(obligations, components)
    project_risk, project_risk_label = compute_project_risk_score(dep_scores)

    summary = {
        "total_components": total,
        "compliant_components": compliant_count,
        "violation_count": len(violations),
        "block_count": sum(1 for v in violations if v.action == PolicyAction.BLOCK),
        "warn_count": sum(1 for v in violations if v.action == PolicyAction.WARN),
        "require_approval_count": sum(1 for v in violations if v.action == PolicyAction.REQUIRE_APPROVAL),
        "dual_license_count": len(dual_detections),
        "license_category_breakdown": _category_breakdown(dep_scores),
    }

    log.info("license_audit_complete", violation_count=len(violations), project_risk=project_risk)
    _emit_event("license.audit_complete", {
        "report_id": report_id,
        "component_count": len(components),
        "violation_count": len(violations),
        "project_risk_score": project_risk,
        "policy_id": policy.policy_id,
    })

    return ComplianceReport(
        report_id=report_id,
        generated_at=datetime.now(timezone.utc).isoformat(),
        policy_id=policy.policy_id,
        project_license=policy.project_license,
        total_components=total,
        compliant_components=compliant_count,
        violation_count=len(violations),
        violations=violations,
        obligations=obligations,
        dependency_scores=dep_scores,
        dual_license_detections=dual_detections,
        project_risk_score=project_risk,
        project_risk_label=project_risk_label,
        notice_file_content=notice_content,
        summary=summary,
    )


def _remediation_hint(license_id: str, action: PolicyAction, project_license: Optional[str]) -> str:
    hints: Dict[str, str] = {
        "GPL-2.0-only": "Replace with a permissively-licensed alternative or seek a commercial exception",
        "GPL-3.0-only": "Replace with a permissively-licensed alternative or seek a commercial exception",
        "AGPL-3.0-only": "Replace with a permissively-licensed alternative; AGPL is very restrictive for SaaS",
        "AGPL-3.0-or-later": "Replace with a permissively-licensed alternative; AGPL is very restrictive for SaaS",
        "SSPL-1.0": "Replace with an OSI-approved alternative; SSPL requires full service-stack disclosure",
        "CC-BY-NC-4.0": "This license prohibits commercial use — replace with a commercially-licensed version",
        "Proprietary": "Review commercial license terms; ensure a valid commercial license is obtained",
        "UNKNOWN": "Identify the correct license; contact the supplier or check the package repository",
    }
    if license_id in hints:
        return hints[license_id]
    if action == PolicyAction.BLOCK:
        return f"Replace {license_id} dependency or obtain a license exception"
    if action == PolicyAction.REQUIRE_APPROVAL:
        return f"Get legal team approval before using {license_id} in production"
    return f"Review {license_id} terms with your legal team"


def _category_breakdown(scores: List[DependencyRiskScore]) -> Dict[str, int]:
    breakdown: Dict[str, int] = {}
    for s in scores:
        key = s.license_category.value
        breakdown[key] = breakdown.get(key, 0) + 1
    return breakdown


# ============================================================================
# MODULE-LEVEL SINGLETON
# ============================================================================


class LicenseComplianceEngine:
    """
    Singleton facade providing access to all license compliance capabilities.
    Maintains a mutable policy registry.
    """

    def __init__(self) -> None:
        self._policies: Dict[str, LicensePolicy] = {
            _DEFAULT_COMMERCIAL_POLICY.policy_id: _DEFAULT_COMMERCIAL_POLICY
        }

    # --- Policy management ---

    def add_policy(self, policy: LicensePolicy) -> None:
        self._policies[policy.policy_id] = policy
        _logger.info("license_policy_added", policy_id=policy.policy_id)
        _emit_event("license.policy_added", {"policy_id": policy.policy_id, "name": policy.name})

    def get_policy(self, policy_id: str) -> Optional[LicensePolicy]:
        return self._policies.get(policy_id)

    def list_policies(self) -> List[LicensePolicy]:
        return list(self._policies.values())

    def delete_policy(self, policy_id: str) -> bool:
        if policy_id in self._policies:
            del self._policies[policy_id]
            _emit_event("license.policy_deleted", {"policy_id": policy_id})
            return True
        return False

    # --- Core operations (delegates to module-level functions) ---

    def lookup_license(self, spdx_id: str) -> Optional[LicenseInfo]:
        return get_license(spdx_id)

    def list_licenses(self, category: Optional[LicenseCategory] = None) -> List[LicenseInfo]:
        return list_licenses(category)

    def check_compatibility(
        self, project_license: str, dependency_license: str
    ) -> Tuple[CompatibilityResult, str]:
        return check_compatibility(project_license, dependency_license)

    def audit(
        self,
        components: List[SBOMComponent],
        policy_id: str = "default-commercial",
        report_id: Optional[str] = None,
    ) -> ComplianceReport:
        policy = self._policies.get(policy_id, _DEFAULT_COMMERCIAL_POLICY)
        return audit_sbom(components, policy, report_id)

    def score_component(self, component: SBOMComponent) -> DependencyRiskScore:
        return score_dependency_license(component)

    def detect_dual_licenses(self, components: List[SBOMComponent]) -> List[DualLicenseInfo]:
        return detect_dual_licenses(components)

    def generate_notice(self, components: List[SBOMComponent]) -> str:
        obligations = extract_obligations(components)
        return generate_notice_file(obligations, components)


# Module-level singleton
_engine: Optional[LicenseComplianceEngine] = None


def get_engine() -> LicenseComplianceEngine:
    """Return the module-level LicenseComplianceEngine singleton."""
    global _engine
    if _engine is None:
        _engine = LicenseComplianceEngine()
    return _engine
