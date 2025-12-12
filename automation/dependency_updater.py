"""FixOps Dependency Updater - Automated dependency updates."""

from __future__ import annotations

import logging
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class UpdateStrategy(Enum):
    """Update strategies."""

    PATCH = "patch"  # Only patch versions (1.0.0 -> 1.0.1)
    MINOR = "minor"  # Minor versions (1.0.0 -> 1.1.0)
    MAJOR = "major"  # Major versions (1.0.0 -> 2.0.0)
    SECURITY = "security"  # Only security updates


@dataclass
class DependencyUpdate:
    """Dependency update information."""

    package_name: str
    current_version: str
    new_version: str
    update_type: str  # patch, minor, major, security
    has_security_vulnerability: bool
    cve_ids: List[str] = field(default_factory=list)
    changelog_url: Optional[str] = None


@dataclass
class UpdateResult:
    """Dependency update result."""

    updates: List[DependencyUpdate]
    total_updates: int
    security_updates: int
    files_modified: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class DependencyUpdater:
    """FixOps Dependency Updater - Automated dependency updates."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize dependency updater."""
        self.config = config or {}
        self.update_strategy = UpdateStrategy(self.config.get("strategy", "security"))

    def find_updates(
        self, project_path: Path, strategy: Optional[UpdateStrategy] = None
    ) -> UpdateResult:
        """Find available dependency updates."""
        strategy = strategy or self.update_strategy

        updates = []

        # Detect package manager
        package_manager = self._detect_package_manager(project_path)

        if package_manager == "npm":
            updates = self._find_npm_updates(project_path, strategy)
        elif package_manager == "pip":
            updates = self._find_pip_updates(project_path, strategy)
        elif package_manager == "maven":
            updates = self._find_maven_updates(project_path, strategy)
        elif package_manager == "gradle":
            updates = self._find_gradle_updates(project_path, strategy)
        else:
            logger.warning(f"Unsupported package manager: {package_manager}")

        # Filter by strategy
        if strategy == UpdateStrategy.SECURITY:
            updates = [u for u in updates if u.has_security_vulnerability]
        elif strategy == UpdateStrategy.PATCH:
            updates = [
                u
                for u in updates
                if u.update_type == "patch" or u.has_security_vulnerability
            ]

        return UpdateResult(
            updates=updates,
            total_updates=len(updates),
            security_updates=sum(1 for u in updates if u.has_security_vulnerability),
        )

    def apply_updates(
        self, project_path: Path, updates: List[DependencyUpdate]
    ) -> UpdateResult:
        """Apply dependency updates."""
        files_modified = []

        package_manager = self._detect_package_manager(project_path)

        for update in updates:
            try:
                if package_manager == "npm":
                    self._update_npm_package(project_path, update)
                    files_modified.append("package.json")
                elif package_manager == "pip":
                    self._update_pip_package(project_path, update)
                    files_modified.append("requirements.txt")
                elif package_manager == "maven":
                    self._update_maven_package(project_path, update)
                    files_modified.append("pom.xml")
                elif package_manager == "gradle":
                    self._update_gradle_package(project_path, update)
                    files_modified.append("build.gradle")
            except Exception as e:
                logger.error(f"Failed to update {update.package_name}: {e}")

        return UpdateResult(
            updates=updates,
            total_updates=len(updates),
            security_updates=sum(1 for u in updates if u.has_security_vulnerability),
            files_modified=list(set(files_modified)),
        )

    def _detect_package_manager(self, project_path: Path) -> str:
        """Detect package manager."""
        if (project_path / "package.json").exists():
            return "npm"
        elif (project_path / "requirements.txt").exists() or (
            project_path / "pyproject.toml"
        ).exists():
            return "pip"
        elif (project_path / "pom.xml").exists():
            return "maven"
        elif (project_path / "build.gradle").exists():
            return "gradle"
        else:
            return "unknown"

    def _find_npm_updates(
        self, project_path: Path, strategy: UpdateStrategy
    ) -> List[DependencyUpdate]:
        """Find npm package updates."""
        updates = []

        try:
            # Run npm outdated
            result = subprocess.run(
                ["npm", "outdated", "--json"],
                cwd=project_path,
                capture_output=True,
                text=True,
                timeout=60,
            )

            if result.returncode == 0:
                import json

                outdated = json.loads(result.stdout)

                for package, info in outdated.items():
                    current = info.get("current", "")
                    latest = info.get("latest", "")

                    # Determine update type
                    update_type = self._determine_update_type(current, latest)

                    # Check for security vulnerabilities
                    has_vuln = self._check_security_vulnerability(package, current)

                    updates.append(
                        DependencyUpdate(
                            package_name=package,
                            current_version=current,
                            new_version=latest,
                            update_type=update_type,
                            has_security_vulnerability=has_vuln,
                        )
                    )
        except Exception as e:
            logger.warning(f"Failed to find npm updates: {e}")

        return updates

    def _find_pip_updates(
        self, project_path: Path, strategy: UpdateStrategy
    ) -> List[DependencyUpdate]:
        """Find pip package updates."""
        updates = []

        try:
            # Run pip list --outdated
            result = subprocess.run(
                ["pip", "list", "--outdated", "--format=json"],
                cwd=project_path,
                capture_output=True,
                text=True,
                timeout=60,
            )

            if result.returncode == 0:
                import json

                outdated = json.loads(result.stdout)

                for package_info in outdated:
                    package = package_info.get("name", "")
                    current = package_info.get("version", "")
                    latest = package_info.get("latest", "")

                    update_type = self._determine_update_type(current, latest)
                    has_vuln = self._check_security_vulnerability(package, current)

                    updates.append(
                        DependencyUpdate(
                            package_name=package,
                            current_version=current,
                            new_version=latest,
                            update_type=update_type,
                            has_security_vulnerability=has_vuln,
                        )
                    )
        except Exception as e:
            logger.warning(f"Failed to find pip updates: {e}")

        return updates

    def _find_maven_updates(
        self, project_path: Path, strategy: UpdateStrategy
    ) -> List[DependencyUpdate]:
        """Find Maven dependency updates."""
        # In production, would use Maven Versions plugin
        return []

    def _find_gradle_updates(
        self, project_path: Path, strategy: UpdateStrategy
    ) -> List[DependencyUpdate]:
        """Find Gradle dependency updates."""
        # In production, would use Gradle dependency update plugin
        return []

    def _update_npm_package(self, project_path: Path, update: DependencyUpdate) -> None:
        """Update npm package."""
        subprocess.run(
            ["npm", "install", f"{update.package_name}@{update.new_version}"],
            cwd=project_path,
            check=True,
            timeout=300,
        )

    def _update_pip_package(self, project_path: Path, update: DependencyUpdate) -> None:
        """Update pip package."""
        # Update requirements.txt
        requirements_file = project_path / "requirements.txt"
        if requirements_file.exists():
            content = requirements_file.read_text()
            # Replace version
            import re

            pattern = rf"^{re.escape(update.package_name)}=={re.escape(update.current_version)}$"
            replacement = f"{update.package_name}=={update.new_version}"
            content = re.sub(pattern, replacement, content, flags=re.MULTILINE)
            requirements_file.write_text(content)

    def _update_maven_package(
        self, project_path: Path, update: DependencyUpdate
    ) -> None:
        """Update Maven dependency."""
        # In production, would update pom.xml

    def _update_gradle_package(
        self, project_path: Path, update: DependencyUpdate
    ) -> None:
        """Update Gradle dependency."""
        # In production, would update build.gradle

    def _determine_update_type(self, current: str, new: str) -> str:
        """Determine update type (patch, minor, major)."""
        # Simple version comparison (would use proper semver in production)
        current_parts = current.split(".")
        new_parts = new.split(".")

        if len(current_parts) >= 1 and len(new_parts) >= 1:
            if current_parts[0] != new_parts[0]:
                return "major"
            elif len(current_parts) >= 2 and len(new_parts) >= 2:
                if current_parts[1] != new_parts[1]:
                    return "minor"
                else:
                    return "patch"

        return "patch"

    def _check_security_vulnerability(self, package: str, version: str) -> bool:
        """Check if package version has security vulnerabilities."""
        # In production, would query vulnerability database
        # For now, return False (would be implemented with real vulnerability data)
        return False
