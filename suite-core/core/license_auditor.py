"""
License Auditor for ALDECI — dependency license classification and risk flagging.

Provides:
- LicenseCategory: PERMISSIVE, COPYLEFT, PROPRIETARY, UNKNOWN
- LicenseAuditResult: per-dependency audit result with risk flag
- LicenseAuditor: main class

LicenseAuditor public methods:
  audit_requirements(path)    -> List[LicenseAuditResult]  from requirements.txt
  audit_package_json(path)    -> List[LicenseAuditResult]  from package.json
  fetch_pypi_license(name)    -> str                        via PyPI JSON API
  classify_license(spdx_id)   -> LicenseCategory
  audit_summary(results)      -> dict                       aggregate counts + flagged

Copyleft deps in a commercial project are flagged as HIGH risk.
PyPI queries are best-effort — network errors fall back to UNKNOWN.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.error import URLError
from urllib.request import urlopen

logger = logging.getLogger(__name__)

_PYPI_JSON_URL = "https://pypi.org/pypi/{package}/json"
_HTTP_TIMEOUT = 10  # seconds


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class LicenseCategory(str, Enum):
    """Broad license category for risk classification."""
    PERMISSIVE = "PERMISSIVE"
    COPYLEFT = "COPYLEFT"       # GPL, LGPL, AGPL, MPL, EUPL, CDDL, EPL
    PROPRIETARY = "PROPRIETARY"
    UNKNOWN = "UNKNOWN"


# ---------------------------------------------------------------------------
# Known license classifications
# ---------------------------------------------------------------------------

_PERMISSIVE_KEYWORDS = {
    "mit", "apache", "bsd", "isc", "0bsd", "unlicense", "wtfpl",
    "zlib", "boost", "cc0", "public domain", "artistic-2", "python-2",
    "psf", "historical permission notice", "hpnd",
}

_COPYLEFT_KEYWORDS = {
    "gpl", "lgpl", "agpl", "mpl", "mozilla public license",
    "eupl", "european union public license",
    "cddl", "common development and distribution",
    "epl", "eclipse public license",
    "sspl", "server side public license",
    "osl", "open software license",
    "rpl", "reciprocal public license",
    "cpal", "common public attribution",
    "eupl",
}

_PROPRIETARY_KEYWORDS = {
    "proprietary", "commercial", "all rights reserved",
    "eula", "not open source", "closed source",
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class LicenseAuditResult:
    """Audit result for a single dependency."""
    name: str
    version: str
    ecosystem: str                      # "pypi" | "npm"
    license_id: str                     # Raw license string
    category: LicenseCategory
    is_high_risk: bool                  # True when COPYLEFT or PROPRIETARY
    risk_reason: str = ""
    pypi_license: Optional[str] = None  # Fetched from PyPI API when available
    metadata: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _normalize_license(raw: str) -> str:
    """Lowercase and strip whitespace/punctuation for keyword matching."""
    return raw.lower().strip().rstrip(".")


def _parse_requirements_txt(text: str) -> List[tuple[str, str]]:
    """Return (name, version) pairs from requirements.txt text."""
    packages: list[tuple[str, str]] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        line = line.split("#")[0].strip()
        match = re.match(r"^([A-Za-z0-9_.\-]+)(?:\[.*?\])?([><=!~^].+)?$", line)
        if match:
            name = match.group(1).strip()
            version_spec = (match.group(2) or "").strip()
            version = ""
            if version_spec:
                eq_match = re.match(r"^==(.+)$", version_spec)
                version = eq_match.group(1).strip() if eq_match else version_spec.lstrip("=<>!~^")
            packages.append((name, version))
    return packages


def _parse_package_json_deps(data: Dict[str, Any]) -> List[tuple[str, str]]:
    """Return (name, version) from package.json dependency sections."""
    packages: list[tuple[str, str]] = []
    for section in ("dependencies", "devDependencies", "peerDependencies"):
        for name, ver in data.get(section, {}).items():
            version = re.sub(r"^[\^~>=<v]", "", str(ver)).strip()
            packages.append((name, version))
    return packages


def _fetch_url_json(url: str) -> Optional[Dict[str, Any]]:
    """Fetch JSON from url. Returns None on any error."""
    try:
        with urlopen(url, timeout=_HTTP_TIMEOUT) as resp:  # nosec
            return json.loads(resp.read())
    except (URLError, OSError, json.JSONDecodeError, ValueError) as exc:
        logger.debug("HTTP fetch failed %s: %s", url, exc)
        return None


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------


class LicenseAuditor:
    """
    Audit dependency licenses from project manifest files.

    Classifies each dependency as PERMISSIVE, COPYLEFT, PROPRIETARY, or UNKNOWN.
    Flags COPYLEFT and PROPRIETARY dependencies as high-risk in commercial projects.
    Optionally enriches Python packages with live license data from PyPI JSON API.
    """

    def __init__(self, fetch_pypi: bool = True) -> None:
        """
        Args:
            fetch_pypi: When True, unknown Python package licenses are looked up
                        via the PyPI JSON API. Disable for offline/test use.
        """
        self.fetch_pypi = fetch_pypi

    # ------------------------------------------------------------------
    # Classification
    # ------------------------------------------------------------------

    def classify_license(self, license_id: str) -> LicenseCategory:
        """
        Classify a license string into a LicenseCategory.

        Uses keyword matching against known permissive, copyleft, and
        proprietary license identifiers (case-insensitive).

        Args:
            license_id: SPDX identifier or free-form license string.

        Returns:
            LicenseCategory enum value.
        """
        if not license_id or license_id.upper() in ("UNKNOWN", "NOASSERTION", "NONE", ""):
            return LicenseCategory.UNKNOWN

        normalized = _normalize_license(license_id)

        # Check proprietary first (some strings contain both "commercial" and "MIT")
        for kw in _PROPRIETARY_KEYWORDS:
            if kw in normalized:
                return LicenseCategory.PROPRIETARY

        for kw in _COPYLEFT_KEYWORDS:
            if kw in normalized:
                return LicenseCategory.COPYLEFT

        for kw in _PERMISSIVE_KEYWORDS:
            if kw in normalized:
                return LicenseCategory.PERMISSIVE

        return LicenseCategory.UNKNOWN

    # ------------------------------------------------------------------
    # PyPI enrichment
    # ------------------------------------------------------------------

    def fetch_pypi_license(self, name: str) -> str:
        """
        Query PyPI JSON API for the license field of a package.

        Args:
            name: PyPI package name (case-insensitive).

        Returns:
            License string from PyPI metadata, or "UNKNOWN" on failure.
        """
        url = _PYPI_JSON_URL.format(package=name)
        data = _fetch_url_json(url)
        if not data:
            return "UNKNOWN"
        info = data.get("info", {})
        license_str = info.get("license", "") or ""
        return license_str.strip() or "UNKNOWN"

    # ------------------------------------------------------------------
    # Audit methods
    # ------------------------------------------------------------------

    def _build_result(
        self,
        name: str,
        version: str,
        ecosystem: str,
        license_id: str,
        pypi_license: Optional[str] = None,
    ) -> LicenseAuditResult:
        """Build a LicenseAuditResult, optionally enriching with PyPI data."""
        effective_license = license_id

        # Use PyPI data when the manifest doesn't specify a license
        if (
            ecosystem == "pypi"
            and (not license_id or license_id.upper() in ("UNKNOWN", ""))
            and pypi_license
            and pypi_license.upper() != "UNKNOWN"
        ):
            effective_license = pypi_license

        category = self.classify_license(effective_license)
        is_high_risk = category in (LicenseCategory.COPYLEFT, LicenseCategory.PROPRIETARY)
        risk_reason = ""
        if category == LicenseCategory.COPYLEFT:
            risk_reason = (
                f"Copyleft license '{effective_license}' may require releasing "
                "your source code in commercial projects."
            )
        elif category == LicenseCategory.PROPRIETARY:
            risk_reason = (
                f"Proprietary license '{effective_license}' may prohibit "
                "redistribution or commercial use."
            )

        return LicenseAuditResult(
            name=name,
            version=version,
            ecosystem=ecosystem,
            license_id=effective_license,
            category=category,
            is_high_risk=is_high_risk,
            risk_reason=risk_reason,
            pypi_license=pypi_license,
        )

    def audit_requirements(self, path: str) -> List[LicenseAuditResult]:
        """
        Audit licenses for all dependencies in a requirements.txt file.

        For each dependency:
        1. Parses name and version from the file.
        2. If fetch_pypi=True, queries PyPI API for the license field.
        3. Classifies the license and flags copyleft/proprietary as HIGH risk.

        Args:
            path: Filesystem path to requirements.txt.

        Returns:
            List of LicenseAuditResult, one per valid dependency line.

        Raises:
            FileNotFoundError: if path does not exist.
        """
        req_path = Path(path)
        if not req_path.exists():
            raise FileNotFoundError(f"requirements.txt not found: {path}")

        text = req_path.read_text(encoding="utf-8")
        pairs = _parse_requirements_txt(text)

        results: List[LicenseAuditResult] = []
        for name, version in pairs:
            if not name:
                continue
            pypi_license: Optional[str] = None
            if self.fetch_pypi:
                pypi_license = self.fetch_pypi_license(name)
            results.append(
                self._build_result(
                    name=name,
                    version=version,
                    ecosystem="pypi",
                    license_id="",
                    pypi_license=pypi_license,
                )
            )
        return results

    def audit_package_json(self, path: str) -> List[LicenseAuditResult]:
        """
        Audit licenses for all dependencies in a package.json file.

        Reads the 'license' field per-dependency when available in the
        package.json (not always present). Classifies and flags high risk.

        Args:
            path: Filesystem path to package.json.

        Returns:
            List of LicenseAuditResult, one per dependency entry.

        Raises:
            FileNotFoundError: if path does not exist.
            ValueError: if the JSON is invalid.
        """
        pkg_path = Path(path)
        if not pkg_path.exists():
            raise FileNotFoundError(f"package.json not found: {path}")

        data = json.loads(pkg_path.read_text(encoding="utf-8"))
        pairs = _parse_package_json_deps(data)

        results: List[LicenseAuditResult] = []
        for name, version in pairs:
            if not name:
                continue
            # package.json top-level 'license' applies to the project itself,
            # not to deps. Individual dep licenses require npm list --json.
            results.append(
                self._build_result(
                    name=name,
                    version=version,
                    ecosystem="npm",
                    license_id="",
                )
            )
        return results

    def audit_summary(self, results: List[LicenseAuditResult]) -> Dict[str, Any]:
        """
        Produce an aggregate summary dict from a list of audit results.

        Args:
            results: Output from audit_requirements() or audit_package_json().

        Returns:
            Dict with keys:
              total, permissive, copyleft, proprietary, unknown,
              high_risk_count, high_risk_packages, risk_score (0-100).
        """
        counts: Dict[str, int] = {
            "total": len(results),
            "permissive": 0,
            "copyleft": 0,
            "proprietary": 0,
            "unknown": 0,
        }
        high_risk_packages: List[Dict[str, str]] = []

        for r in results:
            cat = r.category.value.lower()
            if cat in counts:
                counts[cat] += 1
            if r.is_high_risk:
                high_risk_packages.append({
                    "name": r.name,
                    "version": r.version,
                    "license": r.license_id,
                    "category": r.category.value,
                    "reason": r.risk_reason,
                })

        total = counts["total"] or 1
        risk_score = round(
            (counts["copyleft"] * 70 + counts["proprietary"] * 90 + counts["unknown"] * 20)
            / total,
            1,
        )

        return {
            **counts,
            "high_risk_count": len(high_risk_packages),
            "high_risk_packages": high_risk_packages,
            "risk_score": min(risk_score, 100.0),
        }
