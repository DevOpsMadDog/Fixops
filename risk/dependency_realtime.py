"""FixOps Real-Time Dependency Scanning

Proprietary real-time dependency monitoring and webhook-based updates.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class DependencyUpdate:
    """Dependency update event."""

    package_name: str
    package_manager: str
    old_version: str
    new_version: str
    vulnerability_count: int
    critical_vulnerability_count: int
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class VulnerabilityAlert:
    """Vulnerability alert."""

    cve_id: str
    package_name: str
    package_version: str
    severity: str
    description: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class RealTimeDependencyScanner:
    """FixOps Real-Time Dependency Scanner - Proprietary continuous monitoring."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize real-time scanner."""
        self.config = config or {}
        self.watched_dependencies: Dict[str, Dict[str, Any]] = {}
        self.update_callbacks: List[Callable[[DependencyUpdate], None]] = []
        self.alert_callbacks: List[Callable[[VulnerabilityAlert], None]] = []
        self.scanning = False
        self.scan_interval = self.config.get("scan_interval", 60)  # seconds

    async def start_monitoring(self):
        """Start real-time monitoring."""
        self.scanning = True
        logger.info("Starting real-time dependency monitoring")

        while self.scanning:
            try:
                await self._scan_cycle()
                await asyncio.sleep(self.scan_interval)
            except Exception as e:
                logger.error(f"Error in monitoring cycle: {e}")
                await asyncio.sleep(5)  # Short delay on error

    def stop_monitoring(self):
        """Stop real-time monitoring."""
        self.scanning = False
        logger.info("Stopped real-time dependency monitoring")

    def watch_dependency(
        self,
        package_name: str,
        package_manager: str,
        current_version: str,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """Watch a dependency for updates."""
        key = f"{package_manager}:{package_name}"
        self.watched_dependencies[key] = {
            "package_name": package_name,
            "package_manager": package_manager,
            "current_version": current_version,
            "metadata": metadata or {},
            "last_scan": None,
        }
        logger.info(f"Watching dependency: {key}")

    def unwatch_dependency(self, package_name: str, package_manager: str):
        """Stop watching a dependency."""
        key = f"{package_manager}:{package_name}"
        if key in self.watched_dependencies:
            del self.watched_dependencies[key]
            logger.info(f"Stopped watching: {key}")

    def register_update_callback(self, callback: Callable[[DependencyUpdate], None]):
        """Register callback for dependency updates."""
        self.update_callbacks.append(callback)

    def register_alert_callback(self, callback: Callable[[VulnerabilityAlert], None]):
        """Register callback for vulnerability alerts."""
        self.alert_callbacks.append(callback)

    async def _scan_cycle(self):
        """Perform one scan cycle."""
        for key, dep_info in self.watched_dependencies.items():
            try:
                # Check for updates
                update_info = await self._check_for_updates(dep_info)
                if update_info:
                    update = DependencyUpdate(
                        package_name=dep_info["package_name"],
                        package_manager=dep_info["package_manager"],
                        old_version=dep_info["current_version"],
                        new_version=update_info["new_version"],
                        vulnerability_count=update_info.get("vulnerability_count", 0),
                        critical_vulnerability_count=update_info.get(
                            "critical_vulnerability_count", 0
                        ),
                    )

                    # Notify callbacks
                    for callback in self.update_callbacks:
                        try:
                            callback(update)
                        except Exception as e:
                            logger.error(f"Error in update callback: {e}")

                    # Update stored version
                    dep_info["current_version"] = update_info["new_version"]

                # Check for new vulnerabilities
                alerts = await self._check_for_vulnerabilities(dep_info)
                for alert in alerts:
                    for callback in self.alert_callbacks:
                        try:
                            callback(alert)
                        except Exception as e:
                            logger.error(f"Error in alert callback: {e}")

                dep_info["last_scan"] = datetime.now(timezone.utc)

            except Exception as e:
                logger.error(f"Error scanning {key}: {e}")

    async def _check_for_updates(
        self, dep_info: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Check for dependency updates using real package registry APIs.

        Queries npm, PyPI, or Maven registries to check for newer versions.
        """
        package_name = dep_info.get("package_name", "")
        package_manager = dep_info.get("package_manager", "")
        current_version = dep_info.get("current_version", "")

        if not package_name or not package_manager:
            return None

        try:
            import httpx

            async with httpx.AsyncClient(timeout=30.0) as client:
                if package_manager == "npm":
                    # Query npm registry
                    response = await client.get(
                        f"https://registry.npmjs.org/{package_name}"
                    )
                    if response.status_code == 200:
                        data = response.json()
                        latest = data.get("dist-tags", {}).get("latest")
                        if latest and latest != current_version:
                            return {
                                "new_version": latest,
                                "vulnerability_count": 0,
                                "critical_vulnerability_count": 0,
                            }

                elif package_manager == "pypi":
                    # Query PyPI registry
                    response = await client.get(
                        f"https://pypi.org/pypi/{package_name}/json"
                    )
                    if response.status_code == 200:
                        data = response.json()
                        latest = data.get("info", {}).get("version")
                        if latest and latest != current_version:
                            return {
                                "new_version": latest,
                                "vulnerability_count": 0,
                                "critical_vulnerability_count": 0,
                            }

                elif package_manager == "maven":
                    # Query Maven Central
                    group_id = dep_info.get("metadata", {}).get(
                        "group_id", package_name
                    )
                    response = await client.get(
                        f"https://search.maven.org/solrsearch/select?q=a:{package_name}+AND+g:{group_id}&rows=1&wt=json"
                    )
                    if response.status_code == 200:
                        data = response.json()
                        docs = data.get("response", {}).get("docs", [])
                        if docs:
                            latest = docs[0].get("latestVersion")
                            if latest and latest != current_version:
                                return {
                                    "new_version": latest,
                                    "vulnerability_count": 0,
                                    "critical_vulnerability_count": 0,
                                }

        except Exception as e:
            logger.warning(f"Failed to check updates for {package_name}: {e}")

        return None

    async def _check_for_vulnerabilities(
        self, dep_info: Dict[str, Any]
    ) -> List[VulnerabilityAlert]:
        """Check for vulnerabilities using real vulnerability databases.

        Queries the OSV (Open Source Vulnerabilities) database for known CVEs.
        """
        package_name = dep_info.get("package_name", "")
        package_manager = dep_info.get("package_manager", "")
        current_version = dep_info.get("current_version", "")

        if not package_name or not current_version:
            return []

        alerts = []

        try:
            import httpx

            # Map package managers to OSV ecosystem names
            ecosystem_map = {
                "npm": "npm",
                "pypi": "PyPI",
                "maven": "Maven",
                "go": "Go",
                "cargo": "crates.io",
                "rubygems": "RubyGems",
                "nuget": "NuGet",
            }

            ecosystem = ecosystem_map.get(package_manager.lower())
            if not ecosystem:
                return []

            async with httpx.AsyncClient(timeout=30.0) as client:
                # Query OSV database
                response = await client.post(
                    "https://api.osv.dev/v1/query",
                    json={
                        "package": {
                            "name": package_name,
                            "ecosystem": ecosystem,
                        },
                        "version": current_version,
                    },
                )

                if response.status_code == 200:
                    data = response.json()
                    vulns = data.get("vulns", [])

                    for vuln in vulns:
                        # Extract CVE ID if available
                        cve_id = None
                        for alias in vuln.get("aliases", []):
                            if alias.startswith("CVE-"):
                                cve_id = alias
                                break
                        if not cve_id:
                            cve_id = vuln.get("id", "UNKNOWN")

                        # Determine severity
                        severity = "medium"
                        if vuln.get("database_specific", {}).get("severity"):
                            severity = vuln["database_specific"]["severity"].lower()
                        elif vuln.get("severity"):
                            for sev in vuln["severity"]:
                                if sev.get("type") == "CVSS_V3":
                                    score = sev.get("score", "")
                                    # Parse CVSS score
                                    if "CRITICAL" in score.upper() or (
                                        score
                                        and float(score.split("/")[0].split(":")[-1])
                                        >= 9.0
                                    ):
                                        severity = "critical"
                                    elif "HIGH" in score.upper():
                                        severity = "high"
                                    break

                        alert = VulnerabilityAlert(
                            cve_id=cve_id,
                            package_name=package_name,
                            package_version=current_version,
                            severity=severity,
                            description=vuln.get("summary", vuln.get("details", ""))[
                                :500
                            ],
                        )
                        alerts.append(alert)

        except Exception as e:
            logger.warning(f"Failed to check vulnerabilities for {package_name}: {e}")

        return alerts


class WebhookHandler:
    """Webhook handler for dependency updates."""

    def __init__(self, scanner: RealTimeDependencyScanner):
        """Initialize webhook handler."""
        self.scanner = scanner

    async def handle_webhook(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Handle incoming webhook."""
        event_type = payload.get("event_type")

        if event_type == "vulnerability_discovered":
            alert = VulnerabilityAlert(
                cve_id=payload.get("cve_id", ""),
                package_name=payload.get("package_name", ""),
                package_version=payload.get("package_version", ""),
                severity=payload.get("severity", "medium"),
                description=payload.get("description", ""),
            )

            # Notify scanner
            for callback in self.scanner.alert_callbacks:
                try:
                    callback(alert)
                except Exception as e:
                    logger.error(f"Error in webhook alert callback: {e}")

            return {"status": "processed", "alert_id": alert.cve_id}

        elif event_type == "package_updated":
            update = DependencyUpdate(
                package_name=payload.get("package_name", ""),
                package_manager=payload.get("package_manager", ""),
                old_version=payload.get("old_version", ""),
                new_version=payload.get("new_version", ""),
                vulnerability_count=payload.get("vulnerability_count", 0),
                critical_vulnerability_count=payload.get(
                    "critical_vulnerability_count", 0
                ),
            )

            # Notify scanner
            for callback in self.scanner.update_callbacks:
                try:
                    callback(update)
                except Exception as e:
                    logger.error(f"Error in webhook update callback: {e}")

            return {"status": "processed", "package": update.package_name}

        else:
            return {"status": "unknown_event", "event_type": event_type}
