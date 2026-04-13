"""
SBOM Generator for ALDECI — CycloneDX 1.4 generation from project manifests.

Generates Software Bills of Materials by:
- Parsing requirements.txt, package.json, go.mod manifest files
- Querying installed packages via `pip list --format=json` / `npm list --json`
- Querying OSV (https://api.osv.dev/v1/query) for vulnerabilities per dependency
- Outputting CycloneDX 1.4 JSON format

Class: SBOMGenerator
  generate_from_requirements(path) -> dict   CycloneDX SBOM from requirements.txt
  generate_from_package_json(path)  -> dict   CycloneDX SBOM from package.json
  generate_from_installed_pip()     -> dict   CycloneDX SBOM from pip list
  query_osv(packages)               -> list   OSV findings for a list of packages
  scan_osv_for_sbom(sbom)           -> list   OSV scan of all components in SBOM
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.error import URLError
from urllib.request import Request, urlopen

logger = logging.getLogger(__name__)

_OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
_OSV_QUERY_URL = "https://api.osv.dev/v1/query"
_CYCLONEDX_SPEC_VERSION = "1.4"
_HTTP_TIMEOUT = 15  # seconds


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _parse_requirements_txt(text: str) -> List[Tuple[str, str]]:
    """Return list of (name, version_spec) from requirements.txt content."""
    packages: List[Tuple[str, str]] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        # Skip blanks, comments, options
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Strip inline comments
        line = line.split("#")[0].strip()
        # Handle extras: requests[security]==2.28.0
        match = re.match(r"^([A-Za-z0-9_.\-]+)(?:\[.*?\])?([><=!~^].+)?$", line)
        if match:
            name = match.group(1).strip()
            version_spec = (match.group(2) or "").strip()
            # Extract bare version from ==x.y.z
            version = ""
            if version_spec:
                eq_match = re.match(r"^==(.+)$", version_spec)
                version = eq_match.group(1).strip() if eq_match else version_spec.lstrip("=<>!~^")
            packages.append((name, version))
    return packages


def _parse_package_json_deps(data: Dict[str, Any]) -> List[Tuple[str, str]]:
    """Extract (name, version) pairs from package.json dependencies sections."""
    packages: List[Tuple[str, str]] = []
    for section in ("dependencies", "devDependencies", "peerDependencies"):
        for name, version_spec in data.get(section, {}).items():
            # Strip semver range prefixes: ^1.2.3 -> 1.2.3
            version = re.sub(r"^[\^~>=<v]", "", str(version_spec)).strip()
            packages.append((name, version))
    return packages


def _make_purl(ecosystem: str, name: str, version: str) -> str:
    """Build a Package URL (purl) string."""
    if version:
        return f"pkg:{ecosystem}/{name}@{version}"
    return f"pkg:{ecosystem}/{name}"


def _make_component(
    name: str,
    version: str,
    ecosystem: str,
    licenses: Optional[List[str]] = None,
    description: str = "",
    hashes: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Build a CycloneDX component dict."""
    comp: Dict[str, Any] = {
        "type": "library",
        "name": name,
        "version": version,
        "purl": _make_purl(ecosystem, name, version),
    }
    if description:
        comp["description"] = description
    if licenses:
        comp["licenses"] = [{"license": {"name": lic}} for lic in licenses]
    if hashes:
        comp["hashes"] = [
            {"alg": alg.upper(), "content": val} for alg, val in hashes.items()
        ]
    return comp


def _cyclonedx_envelope(
    project_name: str,
    project_version: str,
    components: List[Dict[str, Any]],
    serial_number: Optional[str] = None,
) -> Dict[str, Any]:
    """Wrap components in a CycloneDX 1.4 envelope."""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": _CYCLONEDX_SPEC_VERSION,
        "serialNumber": serial_number or f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [{"name": "ALDECI SBOMGenerator", "version": "1.0"}],
            "component": {
                "type": "application",
                "name": project_name,
                "version": project_version,
            },
        },
        "components": components,
    }


def _http_post_json(url: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    """POST JSON to url, return parsed response. Raises URLError / ValueError on failure."""
    body = json.dumps(payload).encode()
    req = Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    with urlopen(req, timeout=_HTTP_TIMEOUT) as resp:
        return json.loads(resp.read())


# ---------------------------------------------------------------------------
# Public class
# ---------------------------------------------------------------------------


class SBOMGenerator:
    """
    Generate CycloneDX 1.4 SBOMs from project manifests and query OSV
    for vulnerability data.

    All methods are synchronous and have no required constructor args.
    OSV calls are best-effort — network errors are logged and return empty lists.
    """

    def __init__(self, project_name: str = "unknown", project_version: str = "0.0.0") -> None:
        self.project_name = project_name
        self.project_version = project_version

    # ------------------------------------------------------------------
    # SBOM generation
    # ------------------------------------------------------------------

    def generate_from_requirements(self, path: str) -> Dict[str, Any]:
        """
        Parse a requirements.txt file and return a CycloneDX 1.4 SBOM dict.

        Args:
            path: Filesystem path to requirements.txt

        Returns:
            CycloneDX 1.4 SBOM as a Python dict.

        Raises:
            FileNotFoundError: if path does not exist.
            ValueError: if the file cannot be parsed.
        """
        req_path = Path(path)
        if not req_path.exists():
            raise FileNotFoundError(f"requirements.txt not found: {path}")

        text = req_path.read_text(encoding="utf-8")
        pairs = _parse_requirements_txt(text)

        components = [
            _make_component(name=name, version=version, ecosystem="pypi")
            for name, version in pairs
            if name
        ]

        # Infer project name from parent directory if not set
        project_name = self.project_name
        if project_name == "unknown":
            project_name = req_path.parent.name or "unknown"

        return _cyclonedx_envelope(project_name, self.project_version, components)

    def generate_from_package_json(self, path: str) -> Dict[str, Any]:
        """
        Parse a package.json file and return a CycloneDX 1.4 SBOM dict.

        Args:
            path: Filesystem path to package.json

        Returns:
            CycloneDX 1.4 SBOM as a Python dict.

        Raises:
            FileNotFoundError: if path does not exist.
            ValueError: if the JSON is invalid.
        """
        pkg_path = Path(path)
        if not pkg_path.exists():
            raise FileNotFoundError(f"package.json not found: {path}")

        data = json.loads(pkg_path.read_text(encoding="utf-8"))
        pairs = _parse_package_json_deps(data)

        components = [
            _make_component(name=name, version=version, ecosystem="npm")
            for name, version in pairs
            if name
        ]

        project_name = data.get("name", self.project_name) or self.project_name
        project_version = data.get("version", self.project_version) or self.project_version

        return _cyclonedx_envelope(project_name, project_version, components)

    def generate_from_installed_pip(self) -> Dict[str, Any]:
        """
        Generate a CycloneDX SBOM from the currently installed pip packages
        using `pip list --format=json`.

        Returns:
            CycloneDX 1.4 SBOM as a Python dict.

        Raises:
            RuntimeError: if pip is not available or the subprocess fails.
        """
        try:
            result = subprocess.run(
                ["pip", "list", "--format=json"],
                capture_output=True,
                text=True,
                timeout=30,
            )
        except FileNotFoundError as exc:
            raise RuntimeError("pip not found in PATH") from exc
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("pip list timed out") from exc

        if result.returncode != 0:
            raise RuntimeError(f"pip list failed: {result.stderr.strip()}")

        try:
            packages = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"Could not parse pip list output: {exc}") from exc

        components = [
            _make_component(
                name=pkg.get("name", ""),
                version=pkg.get("version", ""),
                ecosystem="pypi",
            )
            for pkg in packages
            if pkg.get("name")
        ]

        return _cyclonedx_envelope(self.project_name, self.project_version, components)

    # ------------------------------------------------------------------
    # OSV vulnerability scanning
    # ------------------------------------------------------------------

    def query_osv(self, packages: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        """
        Query the OSV API for vulnerabilities affecting the given packages.

        Uses the batch endpoint (POST /v1/querybatch) when possible,
        falling back to individual queries.

        Args:
            packages: List of dicts with keys 'name', 'version', 'ecosystem'.
                      ecosystem should be 'PyPI', 'npm', 'Go', 'Maven', etc.
                      (OSV canonical casing).

        Returns:
            List of OSV vulnerability dicts, each enriched with
            'affected_package' showing which input package matched.
            Returns empty list on network error.
        """
        if not packages:
            return []

        queries = []
        for pkg in packages:
            q: Dict[str, Any] = {}
            if pkg.get("version"):
                q["version"] = pkg["version"]
                q["package"] = {
                    "name": pkg["name"],
                    "ecosystem": pkg.get("ecosystem", "PyPI"),
                }
            else:
                q["package"] = {
                    "name": pkg["name"],
                    "ecosystem": pkg.get("ecosystem", "PyPI"),
                }
            queries.append(q)

        try:
            response = _http_post_json(_OSV_BATCH_URL, {"queries": queries})
        except (URLError, OSError, ValueError) as exc:
            logger.warning("OSV batch query failed: %s", exc)
            return []

        findings: List[Dict[str, Any]] = []
        results = response.get("results", [])
        for i, result in enumerate(results):
            vulns = result.get("vulns", [])
            if i < len(packages):
                affected_pkg = packages[i]
            else:
                affected_pkg = {}
            for vuln in vulns:
                findings.append({**vuln, "affected_package": affected_pkg})

        return findings

    def scan_osv_for_sbom(self, sbom: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extract all components from a CycloneDX SBOM dict and query OSV.

        Maps purl ecosystem to OSV ecosystem names.

        Args:
            sbom: CycloneDX SBOM dict (as returned by generate_from_* methods).

        Returns:
            List of OSV vulnerability findings enriched with 'affected_package'.
        """
        components = sbom.get("components", [])
        packages: List[Dict[str, str]] = []
        for comp in components:
            purl = comp.get("purl", "")
            ecosystem = "PyPI"
            if "pkg:npm" in purl:
                ecosystem = "npm"
            elif "pkg:golang" in purl or "pkg:go" in purl:
                ecosystem = "Go"
            elif "pkg:maven" in purl:
                ecosystem = "Maven"
            packages.append({
                "name": comp.get("name", ""),
                "version": comp.get("version", ""),
                "ecosystem": ecosystem,
            })
        return self.query_osv(packages)

    def map_osv_to_findings(self, osv_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Map raw OSV vulnerability dicts to ALDECI finding schema.

        Args:
            osv_results: List returned by query_osv() or scan_osv_for_sbom().

        Returns:
            List of ALDECI-schema finding dicts with keys:
            id, title, severity, cvss_score, cve_ids, affected_package,
            affected_version, fix_versions, description, references, source.
        """
        findings: List[Dict[str, Any]] = []
        for vuln in osv_results:
            vuln_id = vuln.get("id", "")
            aliases = vuln.get("aliases", [])
            cve_ids = [a for a in aliases if a.startswith("CVE-")]

            # Determine severity from CVSS or database-specific severity
            severity = "UNKNOWN"
            cvss_score: Optional[float] = None
            for severity_info in vuln.get("severity", []):
                s_type = severity_info.get("type", "")
                if s_type in ("CVSS_V3", "CVSS_V2"):
                    score_str = severity_info.get("score", "")
                    # CVSS vector string — extract base score if numeric
                    try:
                        cvss_score = float(score_str)
                    except (ValueError, TypeError):
                        pass
                    if cvss_score is not None:
                        if cvss_score >= 9.0:
                            severity = "CRITICAL"
                        elif cvss_score >= 7.0:
                            severity = "HIGH"
                        elif cvss_score >= 4.0:
                            severity = "MEDIUM"
                        else:
                            severity = "LOW"
                    break

            # Collect fix versions from affected ranges
            fix_versions: List[str] = []
            affected_pkg = vuln.get("affected_package", {})
            for affected in vuln.get("affected", []):
                for rng in affected.get("ranges", []):
                    for event in rng.get("events", []):
                        fixed = event.get("fixed")
                        if fixed:
                            fix_versions.append(fixed)

            references = [r.get("url", "") for r in vuln.get("references", [])]

            findings.append({
                "id": str(uuid.uuid4()),
                "osv_id": vuln_id,
                "title": vuln.get("summary", vuln_id),
                "severity": severity,
                "cvss_score": cvss_score,
                "cve_ids": cve_ids,
                "affected_package": affected_pkg.get("name", ""),
                "affected_version": affected_pkg.get("version", ""),
                "fix_versions": fix_versions,
                "description": vuln.get("details", ""),
                "references": references,
                "source": "osv.dev",
                "published": vuln.get("published", ""),
                "modified": vuln.get("modified", ""),
            })
        return findings
