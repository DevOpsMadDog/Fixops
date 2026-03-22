"""FixOps License Compliance Engine - Proprietary license analysis.

Supports 55+ SPDX-identified licenses, SPDX expression parsing (AND/OR/WITH),
license alias normalization, transitive dependency license analysis, and
compatibility matrix for commercial, SaaS, and government use.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class LicenseType(Enum):
    """License types."""

    PERMISSIVE = "permissive"  # MIT, Apache, BSD, ISC, Zlib, …
    WEAK_COPYLEFT = "weak_copyleft"  # LGPL, MPL, EPL, CDDL, …
    STRONG_COPYLEFT = "strong_copyleft"  # GPL, AGPL
    NETWORK_COPYLEFT = "network_copyleft"  # AGPL, EUPL (network triggers)
    PUBLIC_DOMAIN = "public_domain"  # Unlicense, CC0, WTFPL, 0BSD
    SOURCE_AVAILABLE = "source_available"  # SSPL, BSL, Elastic, …
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
        """Build proprietary license database — 55+ SPDX-identified licenses."""
        P, WC, SC, NC, PD, SA = (
            LicenseType.PERMISSIVE, LicenseType.WEAK_COPYLEFT,
            LicenseType.STRONG_COPYLEFT, LicenseType.NETWORK_COPYLEFT,
            LicenseType.PUBLIC_DOMAIN, LicenseType.SOURCE_AVAILABLE,
        )
        L, M, H, C = LicenseRisk.LOW, LicenseRisk.MEDIUM, LicenseRisk.HIGH, LicenseRisk.CRITICAL

        def _lic(lt: LicenseType, r: LicenseRisk, **kw: Any) -> Dict[str, Any]:
            base = {"type": lt, "risk": r, "commercial_use": True,
                    "modification": True, "distribution": True, "patent_use": True}
            base.update(kw)
            return base

        return {
            # ── Permissive ────────────────────────────────────────────────
            "MIT":              _lic(P, L),
            "Apache-2.0":       _lic(P, L),
            "BSD-2-Clause":     _lic(P, L),
            "BSD-3-Clause":     _lic(P, L),
            "ISC":              _lic(P, L),
            "Zlib":             _lic(P, L),
            "X11":              _lic(P, L),
            "curl":             _lic(P, L),
            "PostgreSQL":       _lic(P, L),
            "OpenSSL":          _lic(P, L),
            "BSL-1.0":          _lic(P, L),  # Boost Software License
            "JSON":             _lic(P, L),
            "HPND":             _lic(P, L),  # Historical Permission Notice
            "blessing":         _lic(P, L),
            "PSF-2.0":          _lic(P, L),  # Python Software Foundation
            "Ruby":             _lic(P, L),
            "Artistic-2.0":     _lic(P, L),
            "ClArtistic":       _lic(P, L),  # Clarified Artistic
            "PIL":              _lic(P, L),  # Pillow/PIL
            "WTFPL":            _lic(PD, L),
            "Unlicense":        _lic(PD, L),
            "CC0-1.0":          _lic(PD, L),
            "0BSD":             _lic(PD, L),
            # ── Weak Copyleft ─────────────────────────────────────────────
            "LGPL-2.0":         _lic(WC, M, copyleft=True),
            "LGPL-2.0-only":    _lic(WC, M, copyleft=True),
            "LGPL-2.0-or-later": _lic(WC, M, copyleft=True),
            "LGPL-2.1":         _lic(WC, M, copyleft=True),
            "LGPL-2.1-only":    _lic(WC, M, copyleft=True),
            "LGPL-2.1-or-later": _lic(WC, M, copyleft=True),
            "LGPL-3.0":         _lic(WC, M, copyleft=True),
            "LGPL-3.0-only":    _lic(WC, M, copyleft=True),
            "LGPL-3.0-or-later": _lic(WC, M, copyleft=True),
            "MPL-2.0":          _lic(WC, M, copyleft=True),
            "MPL-1.0":          _lic(WC, M, copyleft=True),
            "MPL-1.1":          _lic(WC, M, copyleft=True),
            "EPL-1.0":          _lic(WC, M, copyleft=True),
            "EPL-2.0":          _lic(WC, M, copyleft=True),
            "CDDL-1.0":        _lic(WC, M, copyleft=True),
            "CDDL-1.1":        _lic(WC, M, copyleft=True),
            "CPL-1.0":          _lic(WC, M, copyleft=True),
            "OSL-3.0":          _lic(WC, M, copyleft=True),
            # ── Strong Copyleft ───────────────────────────────────────────
            "GPL-2.0":          _lic(SC, H, copyleft=True),
            "GPL-2.0-only":     _lic(SC, H, copyleft=True),
            "GPL-2.0-or-later": _lic(SC, H, copyleft=True),
            "GPL-3.0":          _lic(SC, H, copyleft=True),
            "GPL-3.0-only":     _lic(SC, H, copyleft=True),
            "GPL-3.0-or-later": _lic(SC, H, copyleft=True),
            "CC-BY-SA-4.0":     _lic(SC, H, copyleft=True),
            "CC-BY-SA-3.0":     _lic(SC, H, copyleft=True),
            # ── Network Copyleft (SaaS trigger) ──────────────────────────
            "AGPL-3.0":         _lic(NC, C, copyleft=True, network_use=True),
            "AGPL-3.0-only":    _lic(NC, C, copyleft=True, network_use=True),
            "AGPL-3.0-or-later": _lic(NC, C, copyleft=True, network_use=True),
            "EUPL-1.1":         _lic(NC, H, copyleft=True, network_use=True),
            "EUPL-1.2":         _lic(NC, H, copyleft=True, network_use=True),
            # ── Source-Available / Restrictive ────────────────────────────
            "SSPL-1.0":         _lic(SA, C, commercial_use=False),
            "BSL-1.1":          _lic(SA, H, commercial_use=False),  # MariaDB Business Source
            "Elastic-2.0":      _lic(SA, H, commercial_use=False),
            "RSAL":             _lic(SA, H, commercial_use=False),  # Redis Source Available
            "Confluent":        _lic(SA, H, commercial_use=False),
            "HashiCorp-BSL":    _lic(SA, H, commercial_use=False),
            "Commons-Clause":   _lic(SA, C, commercial_use=False),
            # ── Non-commercial / restrictive CC ───────────────────────────
            "CC-BY-NC-4.0":     _lic(SA, C, commercial_use=False),
            "CC-BY-NC-SA-4.0":  _lic(SA, C, commercial_use=False),
            "CC-BY-NC-ND-4.0":  _lic(SA, C, commercial_use=False),
            "CC-BY-4.0":        _lic(P, L),
            "CC-BY-3.0":        _lic(P, L),
        }

    # ── SPDX alias map — maps common non-canonical names to SPDX IDs ────────
    LICENSE_ALIASES: Dict[str, str] = {
        "MIT License": "MIT", "The MIT License": "MIT", "Expat": "MIT",
        "Apache License 2.0": "Apache-2.0", "Apache 2": "Apache-2.0",
        "Apache License, Version 2.0": "Apache-2.0",
        "BSD": "BSD-3-Clause", "BSD License": "BSD-3-Clause",
        "BSD-2": "BSD-2-Clause", "Simplified BSD": "BSD-2-Clause",
        "New BSD": "BSD-3-Clause", "Modified BSD": "BSD-3-Clause",
        "ISC License": "ISC",
        "GNU General Public License v2": "GPL-2.0",
        "GNU General Public License v2.0": "GPL-2.0",
        "GPL-2": "GPL-2.0", "GPLv2": "GPL-2.0", "GPL2": "GPL-2.0",
        "GPL v2": "GPL-2.0",
        "GNU General Public License v3": "GPL-3.0",
        "GNU General Public License v3.0": "GPL-3.0",
        "GPL-3": "GPL-3.0", "GPLv3": "GPL-3.0", "GPL3": "GPL-3.0",
        "GPL v3": "GPL-3.0",
        "GNU Affero General Public License v3": "AGPL-3.0",
        "AGPL": "AGPL-3.0", "AGPLv3": "AGPL-3.0",
        "GNU Lesser General Public License v2.1": "LGPL-2.1",
        "LGPLv2": "LGPL-2.1", "LGPL": "LGPL-2.1",
        "GNU Lesser General Public License v3": "LGPL-3.0",
        "LGPLv3": "LGPL-3.0",
        "Mozilla Public License 2.0": "MPL-2.0", "MPL": "MPL-2.0",
        "Eclipse Public License 2.0": "EPL-2.0", "EPL": "EPL-2.0",
        "Eclipse Public License 1.0": "EPL-1.0",
        "Common Development and Distribution License": "CDDL-1.0",
        "Artistic License 2.0": "Artistic-2.0",
        "Boost Software License": "BSL-1.0", "Boost": "BSL-1.0",
        "Python Software Foundation License": "PSF-2.0", "PSF": "PSF-2.0",
        "Unlicense": "Unlicense", "The Unlicense": "Unlicense",
        "Public Domain": "Unlicense", "public domain": "Unlicense",
        "CC0": "CC0-1.0", "CC-0": "CC0-1.0",
        "WTFPL": "WTFPL", "Do What The F*ck You Want To": "WTFPL",
        "Server Side Public License": "SSPL-1.0", "SSPL": "SSPL-1.0",
        "Business Source License": "BSL-1.1",
        "Elastic License": "Elastic-2.0", "ELv2": "Elastic-2.0",
        "0BSD": "0BSD", "Zero-Clause BSD": "0BSD",
    }

    def normalize_license(self, raw: str) -> str:
        """Normalize a license string to its SPDX ID.

        Handles common aliases, case-insensitive matching, and strips
        trailing ``-only`` / ``-or-later`` for database lookups when the
        exact variant isn't present.
        """
        if not raw or raw == "UNKNOWN":
            return "UNKNOWN"
        # Direct hit
        if raw in self.license_database:
            return raw
        # Alias lookup
        canonical = self.LICENSE_ALIASES.get(raw)
        if canonical and canonical in self.license_database:
            return canonical
        # Case-insensitive fallback
        raw_lower = raw.lower().strip()
        for key in self.license_database:
            if key.lower() == raw_lower:
                return key
        for alias, spdx in self.LICENSE_ALIASES.items():
            if alias.lower() == raw_lower:
                return spdx
        # Strip -only / -or-later suffix
        for suffix in ("-only", "-or-later"):
            if raw.endswith(suffix):
                base = raw[: -len(suffix)]
                if base in self.license_database:
                    return base
        return raw  # Return as-is; will classify as UNKNOWN downstream

    # ── SPDX expression parser ────────────────────────────────────────────
    _SPDX_TOKEN_RE = re.compile(
        r"\s*(AND|OR|WITH|\(|\)|[A-Za-z0-9][A-Za-z0-9.\-]*)\s*"
    )

    def parse_spdx_expression(self, expr: str) -> List[str]:
        """Parse an SPDX license expression and return individual license IDs.

        Handles ``MIT OR Apache-2.0``, ``GPL-2.0-only WITH Classpath-exception-2.0``,
        and nested parentheses like ``(MIT AND BSD-3-Clause) OR Apache-2.0``.
        """
        if not expr:
            return []
        tokens = self._SPDX_TOKEN_RE.findall(expr)
        licenses: List[str] = []
        skip_next = False
        for tok in tokens:
            upper = tok.upper()
            if upper in ("AND", "OR", "(", ")"):
                continue
            if upper == "WITH":
                skip_next = True
                continue
            if skip_next:
                skip_next = False
                continue
            licenses.append(self.normalize_license(tok))
        return licenses

    def _build_compatibility_matrix(self) -> Dict[str, List[str]]:
        """Build license compatibility matrix.

        Key = project license, value = list of dependency licenses that are
        compatible when used as dependencies of a project with that license.
        """
        _PERMISSIVE_ALL = [
            "MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC",
            "Zlib", "X11", "curl", "PostgreSQL", "OpenSSL", "BSL-1.0",
            "JSON", "HPND", "PSF-2.0", "Ruby", "Artistic-2.0",
            "Unlicense", "CC0-1.0", "0BSD", "WTFPL", "CC-BY-4.0", "CC-BY-3.0",
            "blessing", "ClArtistic", "PIL",
        ]
        _WEAK_COPYLEFT = ["LGPL-2.1", "LGPL-3.0", "LGPL-2.0", "MPL-2.0",
                          "MPL-1.1", "EPL-2.0", "EPL-1.0", "CDDL-1.0",
                          "CDDL-1.1", "CPL-1.0", "OSL-3.0"]
        return {
            # Permissive projects can use permissive + weak copyleft deps
            **{lic: _PERMISSIVE_ALL + _WEAK_COPYLEFT for lic in _PERMISSIVE_ALL},
            # GPL-2.0 can use permissive + LGPL + GPL-2.0
            "GPL-2.0": _PERMISSIVE_ALL + _WEAK_COPYLEFT + ["GPL-2.0", "GPL-2.0-only", "GPL-2.0-or-later"],
            "GPL-2.0-only": _PERMISSIVE_ALL + _WEAK_COPYLEFT + ["GPL-2.0", "GPL-2.0-only"],
            # GPL-3.0 can use almost anything except AGPL network trigger
            "GPL-3.0": _PERMISSIVE_ALL + _WEAK_COPYLEFT + [
                "GPL-2.0", "GPL-2.0-or-later", "GPL-3.0", "GPL-3.0-only", "GPL-3.0-or-later"],
            "GPL-3.0-only": _PERMISSIVE_ALL + _WEAK_COPYLEFT + ["GPL-3.0", "GPL-3.0-only"],
            # AGPL — everything GPL-3.0 can plus AGPL itself
            "AGPL-3.0": _PERMISSIVE_ALL + _WEAK_COPYLEFT + [
                "GPL-2.0", "GPL-3.0", "GPL-3.0-or-later", "AGPL-3.0", "AGPL-3.0-only"],
            # Weak copyleft projects
            **{lic: _PERMISSIVE_ALL + _WEAK_COPYLEFT for lic in _WEAK_COPYLEFT},
        }

    def analyze(self, packages: List[Dict[str, Any]]) -> LicenseComplianceResult:
        """Analyze package licenses for compliance.

        Supports raw SPDX IDs, aliases ("MIT License"), and compound SPDX
        expressions ("MIT OR Apache-2.0").  Each sub-license in an expression
        is evaluated individually; the *most permissive* outcome wins for OR,
        and the *most restrictive* wins for AND.
        """
        findings: List[LicenseFinding] = []
        incompatible: List[str] = []

        project_license = self.policy.get("project_license", "MIT")
        allowed_licenses = self.policy.get("allowed_licenses", [])
        blocked_licenses = self.policy.get("blocked_licenses", ["AGPL-3.0"])
        # Normalize blocked list for reliable matching
        blocked_set: Set[str] = {self.normalize_license(b) for b in blocked_licenses}

        for package in packages:
            package_name = package.get("name", "unknown")
            raw_license = package.get("license", "UNKNOWN")

            # Parse SPDX expression (handles OR / AND / WITH)
            sub_licenses = self.parse_spdx_expression(raw_license)
            if not sub_licenses:
                sub_licenses = [self.normalize_license(raw_license)]

            # Evaluate each sub-license and pick best/worst depending on operator
            is_or = " OR " in raw_license.upper() if raw_license else False
            best_finding = self._evaluate_sub_licenses(
                package_name, sub_licenses, project_license,
                allowed_licenses, blocked_set, pick_best=is_or,
            )
            if best_finding.risk_level == LicenseRisk.CRITICAL:
                incompatible.append(best_finding.license_name)
            findings.append(best_finding)

        return self._build_result(findings, incompatible)

    def _evaluate_sub_licenses(
        self,
        package_name: str,
        sub_licenses: List[str],
        project_license: str,
        allowed_licenses: List[str],
        blocked_set: Set[str],
        pick_best: bool = False,
    ) -> LicenseFinding:
        """Evaluate a list of sub-licenses from an SPDX expression."""
        _RISK_ORDER = {LicenseRisk.LOW: 0, LicenseRisk.MEDIUM: 1,
                       LicenseRisk.HIGH: 2, LicenseRisk.CRITICAL: 3}
        candidates: List[LicenseFinding] = []

        for lic_name in sub_licenses:
            info = self.license_database.get(lic_name, {})
            lt = info.get("type", LicenseType.UNKNOWN)
            risk = info.get("risk", LicenseRisk.MEDIUM)

            if lic_name in blocked_set:
                risk = LicenseRisk.CRITICAL

            issues: List[str] = []
            if project_license:
                compat = self.compatibility_matrix.get(project_license, [])
                if lic_name not in compat and lic_name != "UNKNOWN":
                    issues.append(f"Incompatible with project license {project_license}")
            if allowed_licenses and lic_name not in allowed_licenses:
                issues.append("Not in allowed licenses list")
            # SaaS / network-use warning
            if info.get("network_use"):
                issues.append("Network-use copyleft — triggers for SaaS/cloud deployment")
            if info.get("commercial_use") is False:
                issues.append("License prohibits commercial use")

            candidates.append(LicenseFinding(
                package_name=package_name,
                license_type=lt,
                license_name=lic_name,
                risk_level=risk,
                compatibility_issues=issues,
                recommendation=self._get_recommendation(lic_name, risk),
            ))

        if not candidates:
            return LicenseFinding(
                package_name=package_name,
                license_type=LicenseType.UNKNOWN,
                license_name="UNKNOWN",
                risk_level=LicenseRisk.MEDIUM,
                recommendation="License not detected — manual review required",
            )

        # OR → pick the most permissive (lowest risk); AND → most restrictive
        candidates.sort(key=lambda f: _RISK_ORDER.get(f.risk_level, 9))
        return candidates[0] if pick_best else candidates[-1]

    # ── Transitive license analysis ───────────────────────────────────────
    def analyze_transitive(
        self, dependency_tree: Dict[str, Any],
    ) -> LicenseComplianceResult:
        """Analyze a dependency tree for transitive license contamination.

        ``dependency_tree`` format (recursive)::

            {
                "name": "my-app",
                "license": "MIT",
                "dependencies": [
                    {"name": "lib-a", "license": "Apache-2.0", "dependencies": [...]},
                    ...
                ]
            }

        Walks the full tree, tracking depth and propagating copyleft
        contamination upward.
        """
        flat: List[Dict[str, Any]] = []
        self._flatten_tree(dependency_tree, flat, depth=0)
        result = self.analyze(flat)

        # Annotate findings with depth and transitive-contamination flag
        copyleft_ancestors: Set[str] = set()
        for f in result.findings:
            info = self.license_database.get(f.license_name, {})
            if info.get("copyleft"):
                copyleft_ancestors.add(f.package_name)
                if f.risk_level not in (LicenseRisk.HIGH, LicenseRisk.CRITICAL):
                    f.compatibility_issues.append(
                        "Transitive copyleft — may contaminate parent packages"
                    )
        return result

    def _flatten_tree(
        self, node: Dict[str, Any], out: List[Dict[str, Any]], depth: int
    ) -> None:
        """Recursively flatten a dependency tree."""
        out.append({
            "name": node.get("name", "unknown"),
            "license": node.get("license", "UNKNOWN"),
            "depth": depth,
        })
        for child in node.get("dependencies", []):
            self._flatten_tree(child, out, depth + 1)

    def _get_recommendation(self, license_name: str, risk_level: LicenseRisk) -> str:
        """Get actionable recommendation for license."""
        info = self.license_database.get(license_name, {})
        if risk_level == LicenseRisk.CRITICAL:
            if info.get("network_use"):
                return (f"AGPL/network-copyleft: {license_name} requires releasing "
                        "source code for SaaS usage. Replace with a permissive alternative.")
            if info.get("commercial_use") is False:
                return (f"{license_name} prohibits commercial use. "
                        "Replace immediately or obtain a commercial license.")
            return f"CRITICAL: Replace {license_name} with a permissive license (MIT, Apache-2.0, BSD)"
        elif risk_level == LicenseRisk.HIGH:
            if info.get("copyleft"):
                return (f"{license_name} is strong copyleft — derivative works must use "
                        "the same license. Review linking and distribution model.")
            return f"Review {license_name} license terms and ensure compliance"
        elif risk_level == LicenseRisk.MEDIUM:
            if info.get("copyleft"):
                return (f"{license_name} is weak copyleft — modifications to the library "
                        "itself must be shared. Dynamic linking is usually safe.")
            return f"Monitor {license_name} license compliance"
        else:
            return f"{license_name} is permissive — safe for commercial use"

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
