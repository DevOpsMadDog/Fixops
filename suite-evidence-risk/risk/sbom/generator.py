"""FixOps SBOM Generator - Generate SBOMs from Source Code

Proprietary SBOM generation that discovers dependencies from code analysis.
"""

from __future__ import annotations

import ast
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class SBOMFormat(Enum):
    """SBOM output formats."""

    CYCLONEDX = "cyclonedx"
    SPDX = "spdx"


@dataclass
class Dependency:
    """Dependency representation."""

    name: str
    version: Optional[str] = None
    package_manager: str = "unknown"  # npm, pip, maven, gradle, etc.
    purl: Optional[str] = None
    license: Optional[str] = None
    source_file: Optional[str] = None
    confidence: float = 1.0  # 0.0 to 1.0


@dataclass
class SBOMComponent:
    """SBOM component representation."""

    type: str  # application, library, container, etc.
    name: str
    version: str
    purl: Optional[str] = None
    licenses: List[Dict[str, str]] = field(default_factory=list)
    properties: List[Dict[str, str]] = field(default_factory=list)


class DependencyDiscoverer:
    """Proprietary dependency discovery from source code."""

    def __init__(self):
        """Initialize dependency discoverer."""
        self.discovered_deps: Dict[str, Dependency] = {}

    def discover_from_python(self, file_path: Path) -> List[Dependency]:
        """Discover Python dependencies from code."""
        dependencies = []

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            tree = ast.parse(content, filename=str(file_path))

            # Find import statements
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        dep = self._parse_python_import(alias.name, file_path)
                        if dep:
                            dependencies.append(dep)

                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        dep = self._parse_python_import(node.module, file_path)
                        if dep:
                            dependencies.append(dep)

        except Exception as e:
            logger.warning(f"Failed to parse Python file {file_path}: {e}")

        return dependencies

    def discover_from_javascript(self, file_path: Path) -> List[Dependency]:
        """Discover JavaScript dependencies from code."""
        dependencies = []

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            # Find require/import statements
            require_pattern = r"require\s*\(['\"]([^'\"]+)['\"]\)"
            import_pattern = r"import\s+.*from\s+['\"]([^'\"]+)['\"]"

            for match in re.finditer(require_pattern, content):
                module_name = match.group(1)
                if not module_name.startswith("."):  # Skip relative imports
                    dep = Dependency(
                        name=module_name,
                        package_manager="npm",
                        source_file=str(file_path),
                    )
                    dependencies.append(dep)

            for match in re.finditer(import_pattern, content):
                module_name = match.group(1)
                if not module_name.startswith("."):
                    dep = Dependency(
                        name=module_name,
                        package_manager="npm",
                        source_file=str(file_path),
                    )
                    dependencies.append(dep)

        except Exception as e:
            logger.warning(f"Failed to parse JavaScript file {file_path}: {e}")

        return dependencies

    def discover_from_java(self, file_path: Path) -> List[Dependency]:
        """Discover Java dependencies from code."""
        dependencies = []

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            # Find import statements
            import_pattern = r"import\s+([a-z][a-z0-9]*\.[a-z0-9.]+)"

            for match in re.finditer(import_pattern, content):
                package_name = match.group(1)
                # Extract group ID and artifact ID
                parts = package_name.split(".")
                if len(parts) >= 2:
                    artifact_id = parts[-1]
                    group_id = ".".join(parts[:-1])

                    dep = Dependency(
                        name=f"{group_id}:{artifact_id}",
                        package_manager="maven",
                        source_file=str(file_path),
                    )
                    dependencies.append(dep)

        except Exception as e:
            logger.warning(f"Failed to parse Java file {file_path}: {e}")

        return dependencies

    def _parse_python_import(
        self, module_name: str, file_path: Path
    ) -> Optional[Dependency]:
        """Parse Python import to dependency."""
        # Skip standard library
        if module_name.split(".")[0] in [
            "sys",
            "os",
            "json",
            "datetime",
            "collections",
            "itertools",
            "functools",
            "operator",
            "math",
            "random",
            "string",
            "re",
        ]:
            return None

        # Skip relative imports
        if module_name.startswith("."):
            return None

        # Extract package name (first part)
        package_name = module_name.split(".")[0]

        return Dependency(
            name=package_name,
            package_manager="pip",
            source_file=str(file_path),
        )


class SBOMGenerator:
    """FixOps SBOM Generator - Proprietary SBOM generation."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize SBOM generator."""
        self.config = config or {}
        self.discoverer = DependencyDiscoverer()

    def generate_from_codebase(
        self, codebase_path: Path, output_format: SBOMFormat = SBOMFormat.CYCLONEDX
    ) -> Dict[str, Any]:
        """Generate SBOM from codebase."""
        dependencies = []

        # Discover dependencies from code
        python_files = list(codebase_path.rglob("*.py"))
        js_files = list(codebase_path.rglob("*.js")) + list(codebase_path.rglob("*.ts"))
        java_files = list(codebase_path.rglob("*.java"))

        ignore_dirs = {".git", "node_modules", "venv", "__pycache__", "target", "build"}

        for py_file in python_files:
            if not any(part in ignore_dirs for part in py_file.parts):
                deps = self.discoverer.discover_from_python(py_file)
                dependencies.extend(deps)

        for js_file in js_files:
            if not any(part in ignore_dirs for part in js_file.parts):
                deps = self.discoverer.discover_from_javascript(js_file)
                dependencies.extend(deps)

        for java_file in java_files:
            if not any(part in ignore_dirs for part in java_file.parts):
                deps = self.discoverer.discover_from_java(java_file)
                dependencies.extend(deps)

        # Deduplicate
        unique_deps = self._deduplicate_dependencies(dependencies)

        # Generate SBOM
        if output_format == SBOMFormat.CYCLONEDX:
            return self._generate_cyclonedx(unique_deps, codebase_path)
        else:
            return self._generate_spdx(unique_deps, codebase_path)

    def _deduplicate_dependencies(
        self, dependencies: List[Dependency]
    ) -> List[Dependency]:
        """Deduplicate dependencies."""
        seen = {}

        for dep in dependencies:
            key = f"{dep.package_manager}:{dep.name}"
            if key not in seen:
                seen[key] = dep
            else:
                # Merge versions if different
                existing = seen[key]
                if dep.version and not existing.version:
                    existing.version = dep.version

        return list(seen.values())

    def _generate_cyclonedx(
        self, dependencies: List[Dependency], codebase_path: Path
    ) -> Dict[str, Any]:
        """Generate CycloneDX SBOM."""
        components = []

        for dep in dependencies:
            # Generate PURL
            purl = self._generate_purl(dep)

            component = {
                "type": "library",
                "name": dep.name,
                "version": dep.version or "unknown",
                "purl": purl,
            }

            if dep.license:
                component["licenses"] = [{"license": {"id": dep.license}}]

            components.append(component)

        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "tools": [
                    {
                        "vendor": "FixOps",
                        "name": "SBOM Generator",
                        "version": "1.0.0",
                    }
                ],
                "component": {
                    "type": "application",
                    "name": codebase_path.name,
                    "version": "1.0.0",
                },
            },
            "components": components,
        }

    def _generate_spdx(
        self, dependencies: List[Dependency], codebase_path: Path
    ) -> Dict[str, Any]:
        """Generate SPDX SBOM."""
        packages = []

        for dep in dependencies:
            purl = self._generate_purl(dep)

            package = {
                "SPDXID": f"SPDXRef-Package-{dep.name}",
                "name": dep.name,
                "versionInfo": dep.version or "NOASSERTION",
                "downloadLocation": "NOASSERTION",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": purl,
                    }
                ],
            }

            if dep.license:
                package["licenseDeclared"] = dep.license

            packages.append(package)

        return {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": f"{codebase_path.name} SBOM",
            "documentNamespace": f"https://fixops.com/spdx/{codebase_path.name}",
            "creationInfo": {
                "created": datetime.now(timezone.utc).isoformat(),
                "creators": ["Tool: FixOps-SBOM-Generator-1.0.0"],
            },
            "packages": packages,
        }

    def _generate_purl(self, dep: Dependency) -> str:
        """Generate Package URL (purl) for dependency."""
        if dep.purl:
            return dep.purl

        # Generate PURL based on package manager
        if dep.package_manager == "pip":
            return f"pkg:pypi/{dep.name}@{dep.version or ''}"
        elif dep.package_manager == "npm":
            return f"pkg:npm/{dep.name}@{dep.version or ''}"
        elif dep.package_manager == "maven":
            # Parse group:artifact format
            if ":" in dep.name:
                group, artifact = dep.name.split(":", 1)
                return f"pkg:maven/{group}/{artifact}@{dep.version or ''}"
            else:
                return f"pkg:maven/{dep.name}@{dep.version or ''}"
        else:
            return f"pkg:generic/{dep.name}@{dep.version or ''}"


class SBOMQualityScorer:
    """Proprietary SBOM quality scoring."""

    def score_sbom(self, sbom: Dict[str, Any]) -> Dict[str, Any]:
        """Score SBOM quality."""
        score = 100.0
        issues = []

        components = sbom.get("components", []) or sbom.get("packages", [])

        if not components:
            return {
                "score": 0.0,
                "grade": "F",
                "issues": ["SBOM has no components"],
            }

        # Check for missing versions
        missing_versions = sum(
            1
            for c in components
            if not c.get("version") or c.get("version") == "unknown"
        )
        if missing_versions > 0:
            score -= (missing_versions / len(components)) * 30
            issues.append(f"{missing_versions} components missing versions")

        # Check for missing PURLs
        missing_purls = sum(1 for c in components if not c.get("purl"))
        if missing_purls > 0:
            score -= (missing_purls / len(components)) * 20
            issues.append(f"{missing_purls} components missing PURLs")

        # Check for missing licenses
        missing_licenses = sum(
            1
            for c in components
            if not c.get("licenses") and not c.get("licenseDeclared")
        )
        if missing_licenses > 0:
            score -= (missing_licenses / len(components)) * 15
            issues.append(f"{missing_licenses} components missing licenses")

        # Determine grade
        if score >= 90:
            grade = "A"
        elif score >= 80:
            grade = "B"
        elif score >= 70:
            grade = "C"
        elif score >= 60:
            grade = "D"
        else:
            grade = "F"

        return {
            "score": round(score, 2),
            "grade": grade,
            "issues": issues,
            "total_components": len(components),
            "complete_components": len(components)
            - missing_versions
            - missing_purls
            - missing_licenses,
        }
