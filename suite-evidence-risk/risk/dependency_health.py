"""FixOps Dependency Health Monitoring

Proprietary dependency health tracking, age monitoring, and maintenance status.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class MaintenanceStatus(Enum):
    """Maintenance status of dependency."""

    ACTIVE = "active"  # Recent updates
    SLOW = "slow"  # Infrequent updates
    STALE = "stale"  # No updates in 1+ year
    ABANDONED = "abandoned"  # No updates in 2+ years
    UNKNOWN = "unknown"


class SecurityPosture(Enum):
    """Security posture of dependency."""

    SECURE = "secure"  # No known vulnerabilities
    VULNERABLE = "vulnerable"  # Has vulnerabilities
    CRITICAL = "critical"  # Has critical vulnerabilities
    UNKNOWN = "unknown"


@dataclass
class DependencyHealth:
    """Dependency health information."""

    name: str
    version: str
    package_manager: str
    age_days: int  # Days since last update
    maintenance_status: MaintenanceStatus
    security_posture: SecurityPosture
    vulnerability_count: int = 0
    critical_vulnerability_count: int = 0
    last_update_date: Optional[datetime] = None
    health_score: float = 0.0  # 0.0 to 100.0
    recommendations: List[str] = field(default_factory=list)


@dataclass
class DependencyHealthReport:
    """Dependency health report."""

    dependencies: List[DependencyHealth]
    total_dependencies: int
    healthy_count: int
    at_risk_count: int
    critical_count: int
    average_health_score: float
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class DependencyHealthMonitor:
    """FixOps Dependency Health Monitor - Proprietary health tracking."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize dependency health monitor."""
        self.config = config or {}
        self.update_history: Dict[str, List[datetime]] = defaultdict(list)
        self.vulnerability_data: Dict[str, List[Dict[str, Any]]] = {}

    def monitor_dependency(
        self,
        name: str,
        version: str,
        package_manager: str,
        last_update_date: Optional[datetime] = None,
        vulnerabilities: Optional[List[Dict[str, Any]]] = None,
    ) -> DependencyHealth:
        """Monitor dependency health."""
        # Calculate age
        if last_update_date:
            age_days = (datetime.now(timezone.utc) - last_update_date).days
        else:
            age_days = 999  # Unknown age

        # Determine maintenance status
        maintenance_status = self._determine_maintenance_status(age_days)

        # Determine security posture
        vulnerabilities = vulnerabilities or []
        critical_vulns = [v for v in vulnerabilities if v.get("severity") == "critical"]
        security_posture = self._determine_security_posture(
            len(vulnerabilities), len(critical_vulns)
        )

        # Calculate health score
        health_score = self._calculate_health_score(
            age_days, maintenance_status, security_posture, len(vulnerabilities)
        )

        # Generate recommendations
        recommendations = self._generate_recommendations(
            maintenance_status, security_posture, age_days, len(vulnerabilities)
        )

        return DependencyHealth(
            name=name,
            version=version,
            package_manager=package_manager,
            age_days=age_days,
            maintenance_status=maintenance_status,
            security_posture=security_posture,
            vulnerability_count=len(vulnerabilities),
            critical_vulnerability_count=len(critical_vulns),
            last_update_date=last_update_date,
            health_score=health_score,
            recommendations=recommendations,
        )

    def monitor_all_dependencies(
        self, dependencies: List[Dict[str, Any]]
    ) -> DependencyHealthReport:
        """Monitor all dependencies."""
        health_data = []

        for dep in dependencies:
            health = self.monitor_dependency(
                name=dep.get("name", "unknown"),
                version=dep.get("version", "unknown"),
                package_manager=dep.get("package_manager", "unknown"),
                last_update_date=dep.get("last_update_date"),
                vulnerabilities=dep.get("vulnerabilities", []),
            )
            health_data.append(health)

        # Calculate statistics
        healthy_count = sum(1 for h in health_data if h.health_score >= 70)
        at_risk_count = sum(1 for h in health_data if 50 <= h.health_score < 70)
        critical_count = sum(1 for h in health_data if h.health_score < 50)

        avg_score = (
            sum(h.health_score for h in health_data) / len(health_data)
            if health_data
            else 0.0
        )

        return DependencyHealthReport(
            dependencies=health_data,
            total_dependencies=len(health_data),
            healthy_count=healthy_count,
            at_risk_count=at_risk_count,
            critical_count=critical_count,
            average_health_score=round(avg_score, 2),
        )

    def _determine_maintenance_status(self, age_days: int) -> MaintenanceStatus:
        """Determine maintenance status based on age."""
        if age_days < 30:
            return MaintenanceStatus.ACTIVE
        elif age_days < 90:
            return MaintenanceStatus.SLOW
        elif age_days < 365:
            return MaintenanceStatus.STALE
        elif age_days >= 365:
            return MaintenanceStatus.ABANDONED
        else:
            return MaintenanceStatus.UNKNOWN

    def _determine_security_posture(
        self, vuln_count: int, critical_vuln_count: int
    ) -> SecurityPosture:
        """Determine security posture."""
        if critical_vuln_count > 0:
            return SecurityPosture.CRITICAL
        elif vuln_count > 0:
            return SecurityPosture.VULNERABLE
        else:
            return SecurityPosture.SECURE

    def _calculate_health_score(
        self,
        age_days: int,
        maintenance_status: MaintenanceStatus,
        security_posture: SecurityPosture,
        vuln_count: int,
    ) -> float:
        """Calculate dependency health score (0-100)."""
        score = 100.0

        # Age penalty
        if age_days < 30:
            score -= 0  # No penalty
        elif age_days < 90:
            score -= 5
        elif age_days < 365:
            score -= 15
        else:
            score -= 30

        # Maintenance status penalty
        status_penalties = {
            MaintenanceStatus.ACTIVE: 0,
            MaintenanceStatus.SLOW: 5,
            MaintenanceStatus.STALE: 15,
            MaintenanceStatus.ABANDONED: 30,
            MaintenanceStatus.UNKNOWN: 10,
        }
        score -= status_penalties.get(maintenance_status, 10)

        # Security posture penalty
        posture_penalties = {
            SecurityPosture.SECURE: 0,
            SecurityPosture.VULNERABLE: 20,
            SecurityPosture.CRITICAL: 40,
            SecurityPosture.UNKNOWN: 5,
        }
        score -= posture_penalties.get(security_posture, 5)

        # Vulnerability count penalty
        score -= min(20, vuln_count * 2)  # Max 20 point penalty

        return max(0.0, min(100.0, score))

    def _generate_recommendations(
        self,
        maintenance_status: MaintenanceStatus,
        security_posture: SecurityPosture,
        age_days: int,
        vuln_count: int,
    ) -> List[str]:
        """Generate health recommendations."""
        recommendations = []

        if maintenance_status == MaintenanceStatus.ABANDONED:
            recommendations.append(
                "Consider replacing with actively maintained alternative"
            )
        elif maintenance_status == MaintenanceStatus.STALE:
            recommendations.append("Monitor for updates or consider alternatives")

        if security_posture == SecurityPosture.CRITICAL:
            recommendations.append(
                "URGENT: Update or replace due to critical vulnerabilities"
            )
        elif security_posture == SecurityPosture.VULNERABLE:
            recommendations.append("Update to latest version to fix vulnerabilities")

        if age_days > 365:
            recommendations.append("Package has not been updated in over a year")

        if vuln_count > 5:
            recommendations.append(
                "Multiple vulnerabilities detected - consider alternative"
            )

        return recommendations
