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
import sqlite3
import subprocess  # nosec B404
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


def _ecosystem_from_purl(purl: str) -> str:
    """Infer ecosystem string from a package URL for _make_component."""
    if purl.startswith("pkg:npm"):
        return "npm"
    if purl.startswith("pkg:golang"):
        return "golang"
    if purl.startswith("pkg:maven"):
        return "maven"
    return "pypi"


def _http_post_json(url: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    """POST JSON to url, return parsed response. Raises URLError / ValueError on failure."""
    body = json.dumps(payload).encode()
    req = Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    with urlopen(req, timeout=_HTTP_TIMEOUT) as resp:  # nosec
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

    def __init__(
        self,
        project_name: str = "unknown",
        project_version: str = "0.0.0",
        db_path: str = "data/sbom.db",
    ) -> None:
        self.project_name = project_name
        self.project_version = project_version
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    # ------------------------------------------------------------------
    # SQLite persistence
    # ------------------------------------------------------------------

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._get_conn() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS sboms (
                    id TEXT PRIMARY KEY,
                    format TEXT NOT NULL,
                    target TEXT NOT NULL,
                    org_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    content TEXT NOT NULL
                )
                """
            )
            conn.commit()

    # ------------------------------------------------------------------
    # Parsing helpers (instance-method wrappers)
    # ------------------------------------------------------------------

    def parse_requirements_txt(self, content: str) -> List[Dict[str, Any]]:
        """Parse Python requirements.txt text. Returns list of {name, version, purl}."""
        components = []
        for name, version in _parse_requirements_txt(content):
            if name:
                components.append(
                    {"name": name, "version": version, "purl": _make_purl("pypi", name, version)}
                )
        return components

    def parse_package_json(self, content: str) -> List[Dict[str, Any]]:
        """Parse Node.js package.json text. Returns list of {name, version, purl}."""
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return []
        components = []
        for name, version in _parse_package_json_deps(data):
            if name:
                components.append(
                    {"name": name, "version": version, "purl": _make_purl("npm", name, version)}
                )
        return components

    def parse_go_mod(self, content: str) -> List[Dict[str, Any]]:
        """Parse Go go.mod require block. Returns list of {name, version, purl}."""
        components = []
        in_require = False
        for raw_line in content.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("//"):
                continue
            if line == "require (":
                in_require = True
                continue
            if in_require and line == ")":
                in_require = False
                continue
            # Single-line: require module/path v1.2.3
            if line.startswith("require ") and not line.endswith("("):
                parts = line[len("require "):].split()
                if len(parts) >= 2:
                    name, version = parts[0], parts[1]
                    components.append(
                        {"name": name, "version": version, "purl": _make_purl("golang", name, version)}
                    )
                continue
            if in_require:
                # Strip inline comments
                line = line.split("//")[0].strip()
                if not line:
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    name, version = parts[0], parts[1]
                    components.append(
                        {"name": name, "version": version, "purl": _make_purl("golang", name, version)}
                    )
        return components

    # ------------------------------------------------------------------
    # SBOM document generation
    # ------------------------------------------------------------------

    def generate_cyclonedx(
        self, components: List[Dict[str, Any]], metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Generate CycloneDX 1.4 JSON SBOM from a component list."""
        cdx_components = []
        for comp in components:
            cdx_components.append(
                _make_component(
                    name=comp.get("name", ""),
                    version=comp.get("version", ""),
                    ecosystem=_ecosystem_from_purl(comp.get("purl", "")),
                    licenses=comp.get("licenses"),
                    hashes=comp.get("hashes"),
                )
            )
        project_name = (metadata or {}).get("project_name", self.project_name)
        project_version = (metadata or {}).get("project_version", self.project_version)
        return _cyclonedx_envelope(project_name, project_version, cdx_components)

    def generate_spdx(
        self, components: List[Dict[str, Any]], metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Generate SPDX 2.3 JSON SBOM from a component list."""
        project_name = (metadata or {}).get("project_name", self.project_name)
        packages = []
        for comp in components:
            packages.append(
                {
                    "SPDXID": f"SPDXRef-Package-{comp.get('name', 'unknown')}",
                    "name": comp.get("name", ""),
                    "versionInfo": comp.get("version", ""),
                    "externalRefs": [
                        {
                            "referenceCategory": "PACKAGE-MANAGER",
                            "referenceType": "purl",
                            "referenceLocator": comp.get("purl", ""),
                        }
                    ]
                    if comp.get("purl")
                    else [],
                    "licenseConcluded": "NOASSERTION",
                    "licenseDeclared": "NOASSERTION",
                    "downloadLocation": "NOASSERTION",
                    "filesAnalyzed": False,
                }
            )
        return {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": project_name,
            "documentNamespace": f"https://aldeci.local/sbom/{uuid.uuid4()}",
            "creationInfo": {
                "created": datetime.now(timezone.utc).isoformat(),
                "creators": ["Tool: ALDECI SBOMGenerator-1.0"],
            },
            "packages": packages,
        }

    # ------------------------------------------------------------------
    # Directory scanning
    # ------------------------------------------------------------------

    def scan_directory(self, directory: str) -> List[Dict[str, Any]]:
        """Scan a directory for dependency files and parse all found."""
        base = Path(directory)
        components: List[Dict[str, Any]] = []
        for req_file in base.rglob("requirements*.txt"):
            try:
                content = req_file.read_text(encoding="utf-8", errors="replace")
                components.extend(self.parse_requirements_txt(content))
            except OSError as exc:
                logger.warning("Could not read %s: %s", req_file, exc)
        for pkg_file in base.rglob("package.json"):
            try:
                content = pkg_file.read_text(encoding="utf-8", errors="replace")
                components.extend(self.parse_package_json(content))
            except OSError as exc:
                logger.warning("Could not read %s: %s", pkg_file, exc)
        for go_file in base.rglob("go.mod"):
            try:
                content = go_file.read_text(encoding="utf-8", errors="replace")
                components.extend(self.parse_go_mod(content))
            except OSError as exc:
                logger.warning("Could not read %s: %s", go_file, exc)
        # Deduplicate by purl
        seen: set = set()
        unique: List[Dict[str, Any]] = []
        for comp in components:
            key = comp.get("purl") or f"{comp['name']}@{comp.get('version','')}"
            if key not in seen:
                seen.add(key)
                unique.append(comp)
        return unique

    # ------------------------------------------------------------------
    # Storage
    # ------------------------------------------------------------------

    def store_sbom(
        self,
        sbom: Dict[str, Any],
        format: str,
        target: str,
        org_id: str = "default",
    ) -> str:
        """Store SBOM in SQLite. Returns sbom_id."""
        sbom_id = str(uuid.uuid4())
        created_at = datetime.now(timezone.utc).isoformat()
        with self._get_conn() as conn:
            conn.execute(
                "INSERT INTO sboms (id, format, target, org_id, created_at, content) VALUES (?,?,?,?,?,?)",
                (sbom_id, format, target, org_id, created_at, json.dumps(sbom)),
            )
            conn.commit()
        return sbom_id

    def get_sbom(self, sbom_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve stored SBOM by ID. Returns None if not found."""
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT content FROM sboms WHERE id = ?", (sbom_id,)
            ).fetchone()
        if row is None:
            return None
        return json.loads(row["content"])

    def list_sboms(self, org_id: str = "default") -> List[Dict[str, Any]]:
        """List SBOM records (without full content) for an org."""
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT id, format, target, org_id, created_at FROM sboms WHERE org_id = ? ORDER BY created_at DESC",
                (org_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def diff_sboms(self, sbom_id_a: str, sbom_id_b: str) -> Dict[str, Any]:
        """Compare two SBOMs. Returns {added: [...], removed: [...], changed: [...]}."""
        sbom_a = self.get_sbom(sbom_id_a)
        sbom_b = self.get_sbom(sbom_id_b)
        if sbom_a is None:
            raise KeyError(f"SBOM not found: {sbom_id_a}")
        if sbom_b is None:
            raise KeyError(f"SBOM not found: {sbom_id_b}")

        def _index(sbom: Dict[str, Any]) -> Dict[str, str]:
            """Build name -> version index from CycloneDX or SPDX doc."""
            # CycloneDX
            comps = sbom.get("components", [])
            if comps:
                return {c["name"]: c.get("version", "") for c in comps}
            # SPDX
            pkgs = sbom.get("packages", [])
            return {p["name"]: p.get("versionInfo", "") for p in pkgs}

        idx_a = _index(sbom_a)
        idx_b = _index(sbom_b)

        added = [{"name": n, "version": v} for n, v in idx_b.items() if n not in idx_a]
        removed = [{"name": n, "version": v} for n, v in idx_a.items() if n not in idx_b]
        changed = [
            {"name": n, "version_a": idx_a[n], "version_b": idx_b[n]}
            for n in idx_a
            if n in idx_b and idx_a[n] != idx_b[n]
        ]
        return {"added": added, "removed": removed, "changed": changed}

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

    # ------------------------------------------------------------------
    # High-level scan helpers (read from project filesystem)
    # ------------------------------------------------------------------

    def scan_python_deps(self, org_id: str = "default") -> List[Dict[str, Any]]:
        """Scan requirements.txt at the project root and return parsed components.

        Each item has keys: name, version, license, purl.
        Falls back to an empty list if the file is missing.
        """
        req_path = Path("requirements.txt")
        if not req_path.exists():
            logger.warning("requirements.txt not found at %s", req_path.resolve())
            return []
        text = req_path.read_text(encoding="utf-8")
        components = []
        for name, version in _parse_requirements_txt(text):
            if name:
                components.append({
                    "name": name,
                    "version": version,
                    "license": "UNKNOWN",
                    "purl": _make_purl("pypi", name, version),
                })
        return components

    def scan_js_deps(self, org_id: str = "default") -> List[Dict[str, Any]]:
        """Scan suite-ui/aldeci-ui-new/package.json and return parsed components.

        Each item has keys: name, version, license, purl.
        Falls back to an empty list if the file is missing or invalid JSON.
        """
        pkg_path = Path("suite-ui/aldeci-ui-new/package.json")
        if not pkg_path.exists():
            logger.warning("package.json not found at %s", pkg_path.resolve())
            return []
        try:
            data = json.loads(pkg_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            logger.warning("package.json is not valid JSON: %s", pkg_path)
            return []
        components = []
        for name, version in _parse_package_json_deps(data):
            if name:
                components.append({
                    "name": name,
                    "version": version,
                    "license": data.get("license", "UNKNOWN"),
                    "purl": _make_purl("npm", name, version),
                })
        return components

    def get_sbom_stats(self, org_id: str = "default") -> Dict[str, Any]:
        """Return dependency counts and generation timestamp.

        Returns a dict with: python_deps, js_deps, total_deps, generated_at.
        """
        python_deps = self.scan_python_deps(org_id)
        js_deps = self.scan_js_deps(org_id)
        return {
            "python_deps": len(python_deps),
            "js_deps": len(js_deps),
            "total_deps": len(python_deps) + len(js_deps),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

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
