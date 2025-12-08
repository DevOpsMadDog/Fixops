"""FixOps License Compliance Engine - Proprietary license analysis."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class LicenseType(Enum):
    """License types."""

    PERMISSIVE = "permissive"  # MIT, Apache, BSD
    WEAK_COPYLEFT = "weak_copyleft"  # LGPL, MPL
    STRONG_COPYLEFT = "strong_copyleft"  # GPL, AGPL
    PROPRIETARY = "proprietary"
    UNKNOWN = "unknown"


class LicenseRisk(Enum):
    """License risk levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class LicenseFinding:
    """License finding."""

    package_name: str
    license_type: LicenseType
    license_name: str
    risk_level: LicenseRisk
    compatibility_issues: List[str] = field(default_factory=list)
    recommendation: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class LicenseComplianceResult:
    """License compliance result."""

    findings: List[LicenseFinding]
    total_findings: int
    findings_by_risk: Dict[str, int]
    findings_by_type: Dict[str, int]
    incompatible_licenses: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class LicenseComplianceAnalyzer:
    """FixOps License Compliance Analyzer - Proprietary license analysis."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize license compliance analyzer."""
        self.config = config or {}
        self.license_database = self._build_license_database()
        self.compatibility_matrix = self._build_compatibility_matrix()
        self.policy = self.config.get("policy", {})

    def _build_license_database(self) -> Dict[str, Dict[str, Any]]:
        """Build proprietary license database."""
        return {
            "MIT": {
                "type": LicenseType.PERMISSIVE,
                "risk": LicenseRisk.LOW,
                "commercial_use": True,
                "modification": True,
                "distribution": True,
                "patent_use": True,
            },
            "Apache-2.0": {
                "type": LicenseType.PERMISSIVE,
                "risk": LicenseRisk.LOW,
                "commercial_use": True,
                "modification": True,
                "distribution": True,
                "patent_use": True,
            },
            "BSD-3-Clause": {
                "type": LicenseType.PERMISSIVE,
                "risk": LicenseRisk.LOW,
                "commercial_use": True,
                "modification": True,
                "distribution": True,
                "patent_use": True,
            },
            "GPL-2.0": {
                "type": LicenseType.STRONG_COPYLEFT,
                "risk": LicenseRisk.HIGH,
                "commercial_use": True,
                "modification": True,
                "distribution": True,
                "patent_use": True,
                "copyleft": True,
            },
            "GPL-3.0": {
                "type": LicenseType.STRONG_COPYLEFT,
                "risk": LicenseRisk.HIGH,
                "commercial_use": True,
                "modification": True,
                "distribution": True,
                "patent_use": True,
                "copyleft": True,
            },
            "AGPL-3.0": {
                "type": LicenseType.STRONG_COPYLEFT,
                "risk": LicenseRisk.CRITICAL,
                "commercial_use": True,
                "modification": True,
                "distribution": True,
                "patent_use": True,
                "copyleft": True,
                "network_use": True,
            },
            "LGPL-2.1": {
                "type": LicenseType.WEAK_COPYLEFT,
                "risk": LicenseRisk.MEDIUM,
                "commercial_use": True,
                "modification": True,
                "distribution": True,
                "patent_use": True,
                "copyleft": True,
            },
            "MPL-2.0": {
                "type": LicenseType.WEAK_COPYLEFT,
                "risk": LicenseRisk.MEDIUM,
                "commercial_use": True,
                "modification": True,
                "distribution": True,
                "patent_use": True,
            },
        }

    def _build_compatibility_matrix(self) -> Dict[str, List[str]]:
        """Build license compatibility matrix."""
        return {
            "MIT": ["MIT", "Apache-2.0", "BSD-3-Clause", "LGPL-2.1", "MPL-2.0"],
            "Apache-2.0": ["MIT", "Apache-2.0", "BSD-3-Clause", "LGPL-2.1", "MPL-2.0"],
            "BSD-3-Clause": [
                "MIT",
                "Apache-2.0",
                "BSD-3-Clause",
                "LGPL-2.1",
                "MPL-2.0",
            ],
            "GPL-2.0": ["GPL-2.0", "GPL-3.0"],
            "GPL-3.0": ["GPL-3.0"],
            "AGPL-3.0": ["AGPL-3.0"],
            "LGPL-2.1": ["MIT", "Apache-2.0", "BSD-3-Clause", "LGPL-2.1", "MPL-2.0"],
            "MPL-2.0": ["MIT", "Apache-2.0", "BSD-3-Clause", "LGPL-2.1", "MPL-2.0"],
        }

    def analyze(self, packages: List[Dict[str, Any]]) -> LicenseComplianceResult:
        """Analyze package licenses for compliance."""
        findings = []
        incompatible = []

        project_license = self.policy.get("project_license", "MIT")
        allowed_licenses = self.policy.get("allowed_licenses", [])
        blocked_licenses = self.policy.get("blocked_licenses", ["AGPL-3.0"])

        for package in packages:
            package_name = package.get("name", "unknown")
            license_name = package.get("license", "UNKNOWN")

            # Get license info
            license_info = self.license_database.get(license_name, {})
            license_type = license_info.get("type", LicenseType.UNKNOWN)
            risk_level = license_info.get("risk", LicenseRisk.MEDIUM)

            # Check if blocked
            if license_name in blocked_licenses:
                risk_level = LicenseRisk.CRITICAL
                incompatible.append(license_name)

            # Check compatibility
            compatibility_issues = []
            if project_license:
                compatible_licenses = self.compatibility_matrix.get(project_license, [])
                if license_name not in compatible_licenses:
                    compatibility_issues.append(
                        f"Incompatible with project license {project_license}"
                    )

            # Check policy
            if allowed_licenses and license_name not in allowed_licenses:
                compatibility_issues.append("Not in allowed licenses list")

            finding = LicenseFinding(
                package_name=package_name,
                license_type=license_type,
                license_name=license_name,
                risk_level=risk_level,
                compatibility_issues=compatibility_issues,
                recommendation=self._get_recommendation(license_name, risk_level),
            )

            findings.append(finding)

        return self._build_result(findings, incompatible)

    def _get_recommendation(self, license_name: str, risk_level: LicenseRisk) -> str:
        """Get recommendation for license."""
        if risk_level == LicenseRisk.CRITICAL:
            return f"Consider replacing {license_name} with a permissive license"
        elif risk_level == LicenseRisk.HIGH:
            return f"Review {license_name} license terms and ensure compliance"
        elif risk_level == LicenseRisk.MEDIUM:
            return f"Monitor {license_name} license compliance"
        else:
            return f"{license_name} is generally safe to use"

    def _build_result(
        self, findings: List[LicenseFinding], incompatible: List[str]
    ) -> LicenseComplianceResult:
        """Build license compliance result."""
        findings_by_risk: Dict[str, int] = {}
        findings_by_type: Dict[str, int] = {}

        for finding in findings:
            risk = finding.risk_level.value
            findings_by_risk[risk] = findings_by_risk.get(risk, 0) + 1

            license_type = finding.license_type.value
            findings_by_type[license_type] = findings_by_type.get(license_type, 0) + 1

        return LicenseComplianceResult(
            findings=findings,
            total_findings=len(findings),
            findings_by_risk=findings_by_risk,
            findings_by_type=findings_by_type,
            incompatible_licenses=list(set(incompatible)),
        )
