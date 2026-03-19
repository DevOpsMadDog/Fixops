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
    """Proprietary dependency discovery from source code and lockfiles."""

    # Extended Python stdlib list for accurate filtering
    _PYTHON_STDLIB = frozenset([
        "sys", "os", "json", "datetime", "collections", "itertools",
        "functools", "operator", "math", "random", "string", "re",
        "pathlib", "typing", "abc", "io", "hashlib", "hmac", "secrets",
        "sqlite3", "csv", "xml", "html", "http", "urllib", "email",
        "logging", "unittest", "dataclasses", "enum", "copy", "shutil",
        "tempfile", "glob", "fnmatch", "time", "threading", "multiprocessing",
        "subprocess", "socket", "ssl", "signal", "struct", "array",
        "queue", "heapq", "bisect", "weakref", "contextlib", "textwrap",
        "difflib", "pprint", "inspect", "dis", "traceback", "warnings",
        "argparse", "configparser", "importlib", "pkgutil", "platform",
        "uuid", "base64", "binascii", "codecs", "decimal", "fractions",
        "statistics", "cmath", "numbers", "ast", "token", "tokenize",
        "pdb", "profile", "timeit", "trace", "gc", "resource",
        "asyncio", "concurrent", "zipfile", "tarfile", "gzip", "bz2",
        "lzma", "zlib", "pickle", "shelve", "marshal", "dbm",
        "posixpath", "ntpath", "genericpath", "stat", "fileinput",
        "linecache", "atexit", "builtins", "site", "sysconfig",
        "_thread", "ctypes", "mmap", "select", "selectors", "errno",
    ])

    def __init__(self):
        """Initialize dependency discoverer."""
        self.discovered_deps: Dict[str, Dependency] = {}

    # -----------------------------------------------------------------
    # Lockfile parsers — extract exact versions from package manager files
    # -----------------------------------------------------------------

    def discover_from_requirements_txt(self, file_path: Path) -> List[Dependency]:
        """Parse Python requirements.txt / constraints.txt for pinned deps."""
        dependencies = []
        try:
            content = file_path.read_text(encoding="utf-8")
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("-"):
                    continue
                # Handle: package==1.2.3, package>=1.0, package~=2.0
                match = re.match(
                    r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:([=~<>!]=?)\s*([^\s;,#]+))?",
                    line,
                )
                if match:
                    name = match.group(1).lower()
                    version = match.group(3) if match.group(2) in ("==", "~=") else None
                    dependencies.append(Dependency(
                        name=name,
                        version=version,
                        package_manager="pip",
                        source_file=str(file_path),
                        confidence=1.0 if version else 0.7,
                    ))
        except OSError:
            logger.warning("Failed to read %s", file_path)
        return dependencies

    def discover_from_pipfile_lock(self, file_path: Path) -> List[Dependency]:
        """Parse Pipfile.lock for exact pinned versions."""
        import json as _json
        dependencies = []
        try:
            data = _json.loads(file_path.read_text(encoding="utf-8"))
            for section in ("default", "develop"):
                packages = data.get(section, {})
                for name, info in packages.items():
                    if not isinstance(info, dict):
                        continue
                    version = info.get("version", "").lstrip("=")
                    dependencies.append(Dependency(
                        name=name.lower(),
                        version=version or None,
                        package_manager="pip",
                        source_file=str(file_path),
                        confidence=1.0,
                    ))
        except (OSError, ValueError):
            logger.warning("Failed to parse %s", file_path)
        return dependencies

    def discover_from_package_lock_json(self, file_path: Path) -> List[Dependency]:
        """Parse package-lock.json (npm) for exact pinned versions."""
        import json as _json
        dependencies = []
        try:
            data = _json.loads(file_path.read_text(encoding="utf-8"))
            # npm lockfile v2/v3 uses "packages", v1 uses "dependencies"
            packages = data.get("packages", {})
            if packages:
                for pkg_path, info in packages.items():
                    if not pkg_path or not isinstance(info, dict):
                        continue
                    # Extract package name from node_modules path
                    parts = pkg_path.split("node_modules/")
                    if len(parts) < 2:
                        continue
                    name = parts[-1]
                    version = info.get("version")
                    dependencies.append(Dependency(
                        name=name,
                        version=version,
                        package_manager="npm",
                        source_file=str(file_path),
                        confidence=1.0,
                        license=info.get("license"),
                    ))
            else:
                # Fallback to v1 format
                for name, info in data.get("dependencies", {}).items():
                    if not isinstance(info, dict):
                        continue
                    dependencies.append(Dependency(
                        name=name,
                        version=info.get("version"),
                        package_manager="npm",
                        source_file=str(file_path),
                        confidence=1.0,
                    ))
        except (OSError, ValueError):
            logger.warning("Failed to parse %s", file_path)
        return dependencies

    def discover_from_yarn_lock(self, file_path: Path) -> List[Dependency]:
        """Parse yarn.lock for pinned versions (simplified parser)."""
        dependencies = []
        try:
            content = file_path.read_text(encoding="utf-8")
            current_pkg = None
            for line in content.splitlines():
                # Package header: "package-name@^1.0.0":
                header = re.match(r'^"?(@?[^@\s"]+)@', line)
                if header:
                    current_pkg = header.group(1)
                elif current_pkg and line.strip().startswith("version "):
                    version = re.search(r'"([^"]+)"', line)
                    if version:
                        dependencies.append(Dependency(
                            name=current_pkg,
                            version=version.group(1),
                            package_manager="npm",
                            source_file=str(file_path),
                            confidence=1.0,
                        ))
                    current_pkg = None
        except OSError:
            logger.warning("Failed to parse %s", file_path)
        return dependencies

    def discover_from_pom_xml(self, file_path: Path) -> List[Dependency]:
        """Parse Maven pom.xml for dependencies."""
        dependencies = []
        try:
            content = file_path.read_text(encoding="utf-8")
            # Simple regex — avoids xml.etree for security (XXE)
            dep_blocks = re.findall(
                r"<dependency>\s*(.*?)\s*</dependency>",
                content,
                re.DOTALL,
            )
            for block in dep_blocks:
                gid = re.search(r"<groupId>\s*([^<]+)\s*</groupId>", block)
                aid = re.search(r"<artifactId>\s*([^<]+)\s*</artifactId>", block)
                ver = re.search(r"<version>\s*([^<$]+)\s*</version>", block)
                if gid and aid:
                    name = f"{gid.group(1).strip()}:{aid.group(1).strip()}"
                    version = ver.group(1).strip() if ver else None
                    dependencies.append(Dependency(
                        name=name,
                        version=version,
                        package_manager="maven",
                        source_file=str(file_path),
                        confidence=1.0 if version else 0.8,
                    ))
        except OSError:
            logger.warning("Failed to parse %s", file_path)
        return dependencies

    def discover_from_go_sum(self, file_path: Path) -> List[Dependency]:
        """Parse go.sum for Go module dependencies."""
        dependencies = []
        seen = set()
        try:
            content = file_path.read_text(encoding="utf-8")
            for line in content.splitlines():
                parts = line.strip().split()
                if len(parts) >= 2:
                    module = parts[0]
                    version = parts[1].split("/")[0].lstrip("v")
                    key = f"{module}@{version}"
                    if key not in seen:
                        seen.add(key)
                        dependencies.append(Dependency(
                            name=module,
                            version=version,
                            package_manager="go",
                            source_file=str(file_path),
                            confidence=1.0,
                        ))
        except OSError:
            logger.warning("Failed to parse %s", file_path)
        return dependencies

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

        except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
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

        except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
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

        except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
            logger.warning(f"Failed to parse Java file {file_path}: {e}")

        return dependencies

    def _parse_python_import(
        self, module_name: str, file_path: Path
    ) -> Optional[Dependency]:
        """Parse Python import to dependency."""
        # Skip standard library
        if module_name.split(".")[0] in self._PYTHON_STDLIB:
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
            confidence=0.6,  # Heuristic — lower confidence than lockfile
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
        """Generate SBOM from codebase using lockfiles + code analysis.

        Resolution order (highest confidence first):
        1. Lockfiles (exact versions — confidence 1.0)
        2. Manifest files (declared deps — confidence 0.8-1.0)
        3. Source code imports (heuristic — confidence 0.6)
        """
        dependencies = []

        ignore_dirs = {".git", "node_modules", "venv", "__pycache__", "target", "build", ".tox", "dist"}

        def _should_skip(p: Path) -> bool:
            return any(part in ignore_dirs for part in p.parts)

        # ----- Phase 1: Lockfiles (highest confidence) -----
        lockfile_map = {
            "requirements.txt": self.discoverer.discover_from_requirements_txt,
            "requirements-dev.txt": self.discoverer.discover_from_requirements_txt,
            "requirements-prod.txt": self.discoverer.discover_from_requirements_txt,
            "Pipfile.lock": self.discoverer.discover_from_pipfile_lock,
            "package-lock.json": self.discoverer.discover_from_package_lock_json,
            "yarn.lock": self.discoverer.discover_from_yarn_lock,
            "pom.xml": self.discoverer.discover_from_pom_xml,
            "go.sum": self.discoverer.discover_from_go_sum,
        }

        lockfile_count = 0
        for filename, parser in lockfile_map.items():
            for lockfile in codebase_path.rglob(filename):
                if not _should_skip(lockfile):
                    deps = parser(lockfile)
                    dependencies.extend(deps)
                    if deps:
                        lockfile_count += 1

        # ----- Phase 2: Source code imports (lower confidence) -----
        python_files = list(codebase_path.rglob("*.py"))
        js_files = list(codebase_path.rglob("*.js")) + list(codebase_path.rglob("*.ts"))
        java_files = list(codebase_path.rglob("*.java"))

        for py_file in python_files:
            if not _should_skip(py_file):
                deps = self.discoverer.discover_from_python(py_file)
                dependencies.extend(deps)

        for js_file in js_files:
            if not _should_skip(js_file):
                deps = self.discoverer.discover_from_javascript(js_file)
                dependencies.extend(deps)

        for java_file in java_files:
            if not _should_skip(java_file):
                deps = self.discoverer.discover_from_java(java_file)
                dependencies.extend(deps)

        # Deduplicate (lockfile versions take precedence over heuristic)
        unique_deps = self._deduplicate_dependencies(dependencies)

        # Generate SBOM
        if output_format == SBOMFormat.CYCLONEDX:
            sbom = self._generate_cyclonedx(unique_deps, codebase_path)
        else:
            sbom = self._generate_spdx(unique_deps, codebase_path)

        # Add discovery metadata
        sbom["_discovery_metadata"] = {
            "lockfiles_parsed": lockfile_count,
            "source_files_scanned": len(python_files) + len(js_files) + len(java_files),
            "total_components": len(unique_deps),
            "with_exact_version": sum(1 for d in unique_deps if d.version and d.confidence >= 0.9),
            "heuristic_only": sum(1 for d in unique_deps if d.confidence < 0.7),
        }

        return sbom

    def _deduplicate_dependencies(
        self, dependencies: List[Dependency]
    ) -> List[Dependency]:
        """Deduplicate dependencies, preferring highest-confidence entries."""
        seen: Dict[str, Dependency] = {}

        for dep in dependencies:
            key = f"{dep.package_manager}:{dep.name}"
            if key not in seen:
                seen[key] = dep
            else:
                existing = seen[key]
                # Higher confidence wins (lockfile > heuristic)
                if dep.confidence > existing.confidence:
                    seen[key] = dep
                elif dep.version and not existing.version:
                    existing.version = dep.version
                    existing.confidence = max(existing.confidence, dep.confidence)

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
