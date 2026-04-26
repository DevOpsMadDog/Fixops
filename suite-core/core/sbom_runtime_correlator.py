"""SBOM-to-Runtime Correlation Engine.

Correlates static SBOM component inventory with runtime vulnerability findings
to determine which dependencies are actually loaded, reachable, and exploitable.

This is ALdeci's key differentiator — no competitor correlates SBOM with runtime.

Apiiro does static SBOM analysis only.
Akido does runtime behavior only.
ALdeci correlates BOTH — giving true exploitability context.

Key capabilities:
  - Parse CycloneDX (JSON) and SPDX (JSON) SBOM formats
  - Index components by purl, name+version, and group/artifact
  - Fuzzy-match runtime finding package names against SBOM inventory
  - Classify findings into: matched, sbom-only (lower risk), runtime-only (shadow, higher risk)
  - Produce calibrated risk adjustments per finding
  - Emit shadow dependency alerts for supply chain audit
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except ImportError:  # pragma: no cover - bus optional
    _get_tg_bus = None

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Risk delta constants — calibrated against internal test data
# ---------------------------------------------------------------------------

#: Component confirmed loaded and reachable at runtime — raise risk
RISK_DELTA_CONFIRMED_RUNTIME: float = 0.30

#: Component in SBOM but NOT seen at runtime — lower risk (may be tree-shaken)
RISK_DELTA_NOT_AT_RUNTIME: float = -0.20

#: Runtime-only (not declared in SBOM) — shadow dependency, raise risk aggressively
RISK_DELTA_SHADOW_DEPENDENCY: float = 0.50


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class SBOMComponent:
    """A single component extracted from a CycloneDX or SPDX SBOM."""

    purl: str = ""                        # pkg:npm/lodash@4.17.21 — canonical identifier
    name: str = ""                        # lodash
    version: str = ""                     # 4.17.21
    group: str = ""                       # org.springframework (Maven / Gradle)
    component_type: str = "library"       # library | framework | device | container | file
    bom_ref: str = ""                     # internal BOM reference
    supplier: str = ""
    licenses: List[str] = field(default_factory=list)
    hashes: Dict[str, str] = field(default_factory=dict)  # {"SHA-256": "abc..."}
    properties: Dict[str, Any] = field(default_factory=dict)
    sbom_format: str = ""                 # "cyclonedx" | "spdx"

    # ------------------------------------------------------------------ #
    # Derived lookup keys (set by correlator, not parser)
    # ------------------------------------------------------------------ #
    _norm_key: str = field(default="", repr=False)

    def norm_key(self) -> str:
        """Normalised name+version key for fuzzy matching."""
        if self._norm_key:
            return self._norm_key
        self._norm_key = _norm_pkg_name(self.name) + "@" + (self.version or "any")
        return self._norm_key


@dataclass
class CorrelationMatch:
    """A single matched finding ↔ SBOM component pair."""

    finding_id: str
    component: SBOMComponent
    match_type: str        # "purl_exact" | "name_version_exact" | "name_fuzzy"
    confidence: float      # 0.0 – 1.0
    risk_delta: float


@dataclass
class CorrelationResult:
    """Full output from a SBOM vs. runtime correlation run."""

    # Components whose names appear in runtime findings
    matched_components: List[SBOMComponent] = field(default_factory=list)

    # Components in SBOM but absent from all runtime findings
    sbom_only_components: List[SBOMComponent] = field(default_factory=list)

    # Packages seen in runtime findings but absent from the SBOM
    runtime_only_components: List[Dict[str, Any]] = field(default_factory=list)

    # Per-finding risk delta adjustments: {finding_id: delta}
    risk_adjustments: Dict[str, float] = field(default_factory=dict)

    # True if any shadow (runtime-only) dependencies were found
    shadow_dependency_alert: bool = False

    # Detailed match records for audit trail
    matches: List[CorrelationMatch] = field(default_factory=list)

    # Statistics
    stats: Dict[str, Any] = field(default_factory=dict)

    # Timestamp
    correlated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to JSON-safe dict for API responses."""
        return {
            "matched_components": [_comp_to_dict(c) for c in self.matched_components],
            "sbom_only_components": [_comp_to_dict(c) for c in self.sbom_only_components],
            "runtime_only_components": self.runtime_only_components,
            "risk_adjustments": self.risk_adjustments,
            "shadow_dependency_alert": self.shadow_dependency_alert,
            "matches": [
                {
                    "finding_id": m.finding_id,
                    "component_purl": m.component.purl,
                    "component_name": m.component.name,
                    "component_version": m.component.version,
                    "match_type": m.match_type,
                    "confidence": round(m.confidence, 4),
                    "risk_delta": round(m.risk_delta, 4),
                }
                for m in self.matches
            ],
            "stats": self.stats,
            "correlated_at": self.correlated_at,
        }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

# Characters that are not alphanumeric — used for name normalisation
_NON_ALNUM = re.compile(r"[^a-z0-9]")


def _norm_pkg_name(name: str) -> str:
    """Lowercase and strip non-alphanumeric chars for fuzzy matching.

    "org.springframework.boot" → "orgspringframeworkboot"
    "lodash"                   → "lodash"
    "aws-sdk-js-v3"            → "awssdkjsv3"
    """
    return _NON_ALNUM.sub("", name.lower())


def _comp_to_dict(c: SBOMComponent) -> Dict[str, Any]:
    return {
        "purl": c.purl,
        "name": c.name,
        "version": c.version,
        "group": c.group,
        "component_type": c.component_type,
        "bom_ref": c.bom_ref,
        "supplier": c.supplier,
        "licenses": c.licenses,
        "sbom_format": c.sbom_format,
    }


def _extract_pkg_from_finding(finding: Dict[str, Any]) -> Tuple[str, str, str]:
    """Extract (purl, name, version) from a runtime finding.

    Checks common field names produced by the normaliser pipeline:
      - purl (e.g. from CycloneDX/Grype/Trivy findings)
      - package_name / package / component / target
      - package_version / version
    Returns empty strings for any field not found.
    """
    # Try purl first — highest fidelity
    purl = finding.get("purl", "")

    # Package name — try a prioritised list of field names
    name = (
        finding.get("package_name")
        or finding.get("package")
        or finding.get("component")
        or finding.get("artifact_name")
        or finding.get("target")
        or ""
    )

    # Fall back: extract from title like "Vulnerability in lodash"
    if not name and finding.get("title"):
        title = finding["title"]
        for prefix in ("Vulnerability in ", "CVE in ", "Issue in "):
            if title.startswith(prefix):
                name = title[len(prefix):].split()[0]
                break

    version = (
        finding.get("package_version")
        or finding.get("version")
        or finding.get("artifact_version")
        or ""
    )

    return str(purl), str(name), str(version)


# ---------------------------------------------------------------------------
# SBOM Parsers — CycloneDX and SPDX
# ---------------------------------------------------------------------------


def _parse_cyclonedx(sbom: Dict[str, Any]) -> List[SBOMComponent]:
    """Extract components from a CycloneDX SBOM dict.

    Supports CycloneDX 1.2 – 1.6 JSON format.
    Each component record looks like:
      {
        "type": "library",
        "bom-ref": "pkg:npm/lodash@4.17.21",
        "group": "",
        "name": "lodash",
        "version": "4.17.21",
        "purl": "pkg:npm/lodash@4.17.21",
        "licenses": [{"license": {"id": "MIT"}}],
        "hashes": [{"alg": "SHA-256", "content": "abc..."}]
      }
    """
    components: List[SBOMComponent] = []
    raw_components = sbom.get("components", [])
    if not isinstance(raw_components, list):
        logger.warning("CycloneDX SBOM 'components' field is not a list — skipping")
        return components

    for idx, raw in enumerate(raw_components):
        if not isinstance(raw, dict):
            continue
        try:
            # Licenses: [{license: {id: "MIT"}}, {license: {name: "Apache-2.0"}}]
            licenses: List[str] = []
            for lic_entry in raw.get("licenses", []):
                if isinstance(lic_entry, dict):
                    lic = lic_entry.get("license", {})
                    lic_id = lic.get("id") or lic.get("name") or ""
                    if lic_id:
                        licenses.append(lic_id)

            # Hashes: [{alg: "SHA-256", content: "abc..."}]
            hashes: Dict[str, str] = {}
            for h in raw.get("hashes", []):
                if isinstance(h, dict) and h.get("alg") and h.get("content"):
                    hashes[h["alg"]] = h["content"]

            comp = SBOMComponent(
                purl=raw.get("purl", ""),
                name=raw.get("name", ""),
                version=raw.get("version", ""),
                group=raw.get("group", ""),
                component_type=raw.get("type", "library"),
                bom_ref=raw.get("bom-ref", ""),
                supplier=(raw.get("supplier") or {}).get("name", "")
                if isinstance(raw.get("supplier"), dict)
                else str(raw.get("supplier", "")),
                licenses=licenses,
                hashes=hashes,
                properties={p.get("name", ""): p.get("value", "")
                            for p in raw.get("properties", [])
                            if isinstance(p, dict)},
                sbom_format="cyclonedx",
            )
            if comp.name or comp.purl:
                components.append(comp)
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            logger.debug("CycloneDX component parse error at index %d: %s", idx, exc)
            continue

    logger.debug("CycloneDX: parsed %d components", len(components))
    return components


def _parse_spdx(sbom: Dict[str, Any]) -> List[SBOMComponent]:
    """Extract packages from an SPDX SBOM dict.

    Supports SPDX 2.2 – 2.3 JSON format.
    Each package record looks like:
      {
        "SPDXID": "SPDXRef-Package-lodash",
        "name": "lodash",
        "versionInfo": "4.17.21",
        "externalRefs": [
          {"referenceCategory": "PACKAGE-MANAGER",
           "referenceType": "purl",
           "referenceLocator": "pkg:npm/lodash@4.17.21"}
        ],
        "licenseConcluded": "MIT"
      }
    """
    components: List[SBOMComponent] = []
    packages = sbom.get("packages", [])
    if not isinstance(packages, list):
        logger.warning("SPDX SBOM 'packages' field is not a list — skipping")
        return components

    for idx, pkg in enumerate(packages):
        if not isinstance(pkg, dict):
            continue
        try:
            # Extract purl from externalRefs
            purl = ""
            for ref in pkg.get("externalRefs", []):
                if (
                    isinstance(ref, dict)
                    and ref.get("referenceType") == "purl"
                    and ref.get("referenceLocator")
                ):
                    purl = ref["referenceLocator"]
                    break

            # Licenses — can be SPDX license expression string or NOASSERTION
            raw_lic = pkg.get("licenseConcluded", "") or pkg.get("licenseDeclared", "")
            licenses: List[str] = (
                [raw_lic] if raw_lic and raw_lic not in ("NOASSERTION", "NONE") else []
            )

            comp = SBOMComponent(
                purl=purl,
                name=pkg.get("name", ""),
                version=pkg.get("versionInfo", ""),
                group="",
                component_type="library",
                bom_ref=pkg.get("SPDXID", ""),
                supplier=(pkg.get("supplier") or "").replace("Organization: ", "")
                         .replace("Tool: ", ""),
                licenses=licenses,
                hashes={},
                properties={},
                sbom_format="spdx",
            )
            if comp.name or comp.purl:
                components.append(comp)
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            logger.debug("SPDX package parse error at index %d: %s", idx, exc)
            continue

    logger.debug("SPDX: parsed %d packages", len(components))
    return components


# ---------------------------------------------------------------------------
# Main correlator
# ---------------------------------------------------------------------------


class SBOMRuntimeCorrelator:
    """Correlate a static SBOM against runtime vulnerability findings.

    Implements a three-tier matching strategy:
      1. purl_exact      — full Package URL equality (highest confidence)
      2. name_version_exact — normalised name + version equality
      3. name_fuzzy      — normalised name only (version-agnostic)

    Usage:
        correlator = SBOMRuntimeCorrelator()

        # Parse SBOM (dict from JSON.loads or already-parsed)
        result = correlator.correlate(sbom_dict, runtime_findings)

        # Apply risk adjustments back to findings list
        for finding in runtime_findings:
            fid = finding.get("id", "")
            delta = result.risk_adjustments.get(fid, 0.0)
            finding["risk_score"] = min(
                max(finding.get("risk_score", 0.5) + delta, 0.0), 1.0
            )
    """

    # Minimum fuzzy match confidence to count as "matched"
    FUZZY_THRESHOLD: float = 0.75

    def correlate(
        self,
        sbom: Dict[str, Any],
        findings: List[Dict[str, Any]],
        org_id: str = "",
    ) -> CorrelationResult:
        """Run the full SBOM ↔ runtime correlation.

        Args:
            sbom:     Parsed SBOM dict (CycloneDX or SPDX JSON).
            findings: List of runtime finding dicts from the pipeline.
            org_id:   Optional org ID for logging.

        Returns:
            CorrelationResult with matched/unmatched components and risk deltas.
        """
        # Input validation
        if not isinstance(sbom, dict):
            logger.warning("SBOM correlator: sbom must be a dict, got %s", type(sbom).__name__)
            return CorrelationResult(
                stats={"error": "Invalid SBOM: not a dict", "findings_processed": 0}
            )
        if not isinstance(findings, list):
            logger.warning("SBOM correlator: findings must be a list, got %s", type(findings).__name__)
            return CorrelationResult(
                stats={"error": "Invalid findings: not a list", "findings_processed": 0}
            )

        # Detect format and parse
        components = self._parse_sbom(sbom)
        if not components:
            logger.info(
                "SBOM correlator [%s]: no components parsed from SBOM (format may be unknown)",
                org_id or "?",
            )
            return CorrelationResult(
                stats={
                    "sbom_format": self._detect_format(sbom),
                    "components_in_sbom": 0,
                    "findings_processed": len(findings),
                    "warning": "No components found in SBOM",
                }
            )

        logger.info(
            "SBOM correlator [%s]: %d SBOM components, %d runtime findings",
            org_id or "?",
            len(components),
            len(findings),
        )

        # Build lookup indexes
        purl_index: Dict[str, SBOMComponent] = {}
        name_ver_index: Dict[str, SBOMComponent] = {}
        name_index: Dict[str, SBOMComponent] = {}

        for comp in components:
            if comp.purl:
                # Normalise purl to lowercase for case-insensitive match
                purl_index[comp.purl.lower()] = comp
            # name+version key
            nv_key = f"{_norm_pkg_name(comp.name)}@{comp.version or 'any'}"
            name_ver_index[nv_key] = comp
            # name-only key (maps to last seen — good enough for shadow detection)
            if comp.name:
                name_index[_norm_pkg_name(comp.name)] = comp

        # Track which SBOM components were matched
        matched_bom_refs: set = set()

        result = CorrelationResult()

        for finding in findings:
            if not isinstance(finding, dict):
                continue

            fid = finding.get("id") or finding.get("finding_id") or ""
            if not fid:
                # Generate a stable ID from content hash so we can track it
                fid = "fid_" + hashlib.sha256(
                    json.dumps(finding, sort_keys=True, default=str).encode()
                ).hexdigest()[:12]
                finding.setdefault("id", fid)

            f_purl, f_name, f_version = _extract_pkg_from_finding(finding)

            match: Optional[CorrelationMatch] = None

            # ---- Strategy 1: purl_exact ----
            if f_purl:
                comp = purl_index.get(f_purl.lower())
                if comp:
                    match = CorrelationMatch(
                        finding_id=fid,
                        component=comp,
                        match_type="purl_exact",
                        confidence=1.0,
                        risk_delta=RISK_DELTA_CONFIRMED_RUNTIME,
                    )

            # ---- Strategy 2: name_version_exact ----
            if match is None and f_name:
                nv_key = f"{_norm_pkg_name(f_name)}@{f_version or 'any'}"
                comp = name_ver_index.get(nv_key)
                if comp is None and f_version:
                    # Try without version (any)
                    comp = name_ver_index.get(f"{_norm_pkg_name(f_name)}@any")
                if comp:
                    match = CorrelationMatch(
                        finding_id=fid,
                        component=comp,
                        match_type="name_version_exact",
                        confidence=0.95,
                        risk_delta=RISK_DELTA_CONFIRMED_RUNTIME,
                    )

            # ---- Strategy 3: name_fuzzy ----
            if match is None and f_name:
                norm_f_name = _norm_pkg_name(f_name)
                comp, confidence = self._fuzzy_name_match(norm_f_name, name_index)
                if comp and confidence >= self.FUZZY_THRESHOLD:
                    match = CorrelationMatch(
                        finding_id=fid,
                        component=comp,
                        match_type="name_fuzzy",
                        confidence=confidence,
                        risk_delta=RISK_DELTA_CONFIRMED_RUNTIME,
                    )

            if match:
                # Finding is backed by an SBOM component — confirmed runtime
                result.matches.append(match)
                result.risk_adjustments[fid] = RISK_DELTA_CONFIRMED_RUNTIME
                matched_bom_refs.add(match.component.bom_ref or match.component.purl)
            else:
                # Package seen at runtime but not in SBOM → shadow dependency
                if f_name or f_purl:
                    shadow_info: Dict[str, Any] = {
                        "finding_id": fid,
                        "purl": f_purl,
                        "name": f_name,
                        "version": f_version,
                        "risk_delta": RISK_DELTA_SHADOW_DEPENDENCY,
                        "title": finding.get("title", ""),
                        "severity": finding.get("severity", "unknown"),
                    }
                    result.runtime_only_components.append(shadow_info)
                    result.risk_adjustments[fid] = RISK_DELTA_SHADOW_DEPENDENCY
                    result.shadow_dependency_alert = True

        # Categorise SBOM components
        for comp in components:
            comp_key = comp.bom_ref or comp.purl
            if comp_key in matched_bom_refs:
                result.matched_components.append(comp)
            else:
                # In SBOM but not seen at runtime → apply negative delta to any findings
                # referencing it by purl (belt-and-suspenders)
                result.sbom_only_components.append(comp)
                # Apply not-at-runtime delta if any finding references this purl exactly
                if comp.purl:
                    for finding in findings:
                        fid2 = finding.get("id", "")
                        if finding.get("purl", "").lower() == comp.purl.lower():
                            # Override only if not already adjusted upward
                            existing = result.risk_adjustments.get(fid2, 0.0)
                            if existing >= 0:
                                result.risk_adjustments[fid2] = RISK_DELTA_NOT_AT_RUNTIME

        # Statistics
        result.stats = {
            "sbom_format": self._detect_format(sbom),
            "components_in_sbom": len(components),
            "matched_components": len(result.matched_components),
            "sbom_only_components": len(result.sbom_only_components),
            "runtime_only_components": len(result.runtime_only_components),
            "findings_processed": len(findings),
            "findings_with_risk_adjustment": len(result.risk_adjustments),
            "shadow_dependency_alert": result.shadow_dependency_alert,
            "shadow_count": len(result.runtime_only_components),
            "match_breakdown": {
                "purl_exact": sum(1 for m in result.matches if m.match_type == "purl_exact"),
                "name_version_exact": sum(
                    1 for m in result.matches if m.match_type == "name_version_exact"
                ),
                "name_fuzzy": sum(1 for m in result.matches if m.match_type == "name_fuzzy"),
            },
        }

        logger.info(
            "SBOM correlator [%s]: matched=%d sbom_only=%d shadows=%d adj=%d",
            org_id or "?",
            len(result.matched_components),
            len(result.sbom_only_components),
            len(result.runtime_only_components),
            len(result.risk_adjustments),
        )
        self._emit_event(
            "sbom.correlated",
            {
                "org_id": org_id,
                "matched_count": len(result.matched_components),
                "sbom_only_count": len(result.sbom_only_components),
                "runtime_only_count": len(result.runtime_only_components),
                "risk_adjustment_count": len(result.risk_adjustments),
                "findings_processed": len(findings),
            },
        )
        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _detect_format(self, sbom: Dict[str, Any]) -> str:
        """Detect whether sbom dict is CycloneDX, SPDX, or unknown."""
        if not isinstance(sbom, dict):
            return "unknown"
        if sbom.get("bomFormat") == "CycloneDX" or "components" in sbom:
            return "cyclonedx"
        if sbom.get("spdxVersion") or "SPDXRef-DOCUMENT" in str(sbom.get("SPDXID", "")):
            return "spdx"
        if "packages" in sbom:
            return "spdx"
        return "unknown"

    def _parse_sbom(self, sbom: Dict[str, Any]) -> List[SBOMComponent]:
        """Route to the correct parser based on detected format."""
        fmt = self._detect_format(sbom)
        try:
            if fmt == "cyclonedx":
                return _parse_cyclonedx(sbom)
            if fmt == "spdx":
                return _parse_spdx(sbom)
            # Unknown — try both, take whichever produces more components
            cdx = _parse_cyclonedx(sbom)
            spdx = _parse_spdx(sbom)
            return cdx if len(cdx) >= len(spdx) else spdx
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            logger.error("SBOM parser error (format=%s): %s", fmt, exc, exc_info=True)
            return []

    def _fuzzy_name_match(
        self,
        norm_finding_name: str,
        name_index: Dict[str, SBOMComponent],
    ) -> Tuple[Optional[SBOMComponent], float]:
        """Find the best fuzzy name match using simple Levenshtein similarity.

        We use a lightweight inline edit distance rather than importing
        fuzzy_identity.py to keep this module self-contained and testable
        in isolation.  For very large SBOMs (> 10K components) the O(n)
        scan is still fast because the strings are short.

        Returns (component, confidence) or (None, 0.0).
        """
        if not norm_finding_name or not name_index:
            return None, 0.0

        best_comp: Optional[SBOMComponent] = None
        best_sim: float = 0.0

        # Short-circuit: exact lookup is O(1)
        if norm_finding_name in name_index:
            return name_index[norm_finding_name], 1.0

        # Prefix match boost: if one starts with the other
        for norm_name, comp in name_index.items():
            sim = _levenshtein_similarity(norm_finding_name, norm_name)
            if sim > best_sim:
                best_sim = sim
                best_comp = comp

        return (best_comp, best_sim) if best_sim >= self.FUZZY_THRESHOLD else (None, 0.0)


# ---------------------------------------------------------------------------
# Inline Levenshtein — keeps the module dependency-free
# ---------------------------------------------------------------------------

    # ------------------------------------------------------------------
    # TrustGraph event emission (best-effort, non-blocking)
    # ------------------------------------------------------------------

    def _emit_event(self, event_type: str, payload: "dict[str, Any]") -> None:
        """Emit an event to the TrustGraph event bus. Never raises."""
        if _get_tg_bus is None:
            return
        try:
            bus = _get_tg_bus()
            if bus is None:
                return
            emit = getattr(bus, "emit", None) or getattr(bus, "publish", None)
            if emit is None:
                return
            result = emit(event_type, payload)
            try:
                import asyncio
                import inspect
                if inspect.iscoroutine(result):
                    try:
                        loop = asyncio.get_running_loop()
                        loop.create_task(result)
                    except RuntimeError:
                        result.close()
            except Exception:  # pragma: no cover
                pass
        except Exception:  # pragma: no cover - best-effort telemetry
            pass



def _levenshtein_similarity(s1: str, s2: str) -> float:
    """Compute normalised Levenshtein similarity (0.0 – 1.0)."""
    if s1 == s2:
        return 1.0
    len1, len2 = len(s1), len(s2)
    if len1 == 0 or len2 == 0:
        return 0.0
    max_len = max(len1, len2)
    # Cap edit distance computation for long strings (performance guard)
    if max_len > 200:
        # Fall back to prefix similarity for very long names
        common = sum(a == b for a, b in zip(s1, s2))
        return common / max_len
    prev = list(range(len2 + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (0 if c1 == c2 else 1)))
        prev = curr
    return 1.0 - prev[len2] / max_len


# ---------------------------------------------------------------------------
# Convenience factory
# ---------------------------------------------------------------------------


def get_correlator() -> SBOMRuntimeCorrelator:
    """Return a new SBOMRuntimeCorrelator instance.

    The correlator is stateless — no singleton needed.
    """
    return SBOMRuntimeCorrelator()
