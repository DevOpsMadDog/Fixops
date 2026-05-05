"""
ALDECI Normalizer Bridge — Unified Scanner Format Gateway.

Wires ALDECI's 32 scanner normalizers from scanner_parsers.py to the ConnectorGateway.
Provides:
- NormalizerRegistry: Auto-discovery and invocation of all 32 normalizer classes
- NormalizerGatewayBridge: High-level async interface for scan ingestion
- Format auto-detection: 15+ scanner formats with SARIF, CycloneDX, SPDX support
- Fallback: DefectDojo parser API for unknown formats
- Production-grade: Full type hints, logging, error handling, async support

The bridge transforms raw scan outputs (JSON/XML) into unified findings ready for
the ALDECI pipeline (stage 2: NORMALIZE).

Architecture:
    Web Hook / Scan Pull
        ↓
    NormalizerGatewayBridge.process_scan_output()
        ↓ auto-detect or hint-based
    NormalizerRegistry.get_normalizer(format)
        ↓
    Individual Normalizer (e.g., ZAPNormalizer.normalize())
        ↓
    List[UnifiedFinding]
        ↓
    ConnectorGateway.ingest() → ALDECI Pipeline
"""

from __future__ import annotations

import functools
import logging
import xml.etree.ElementTree as ET  # nosec B405
from typing import Any, Dict, List, Optional

from core.scanner_parsers import (
    AcunetixScannerNormalizer,
    AWSInspectorNormalizer,
    BanditNormalizer,
    BurpNormalizer,
    CheckmarxNormalizer,
    CheckovNormalizer,
    ClaudeCodeSecurityNormalizer,
    CombobulatorNormalizer,
    CycloneDXUniversalNormalizer,
    DependabotScannerNormalizer,
    FortifyNormalizer,
    GitLabSASTNormalizer,
    GitleaksScannerNormalizer,
    GrypeScannerNormalizer,
    NessusNormalizer,
    NiktoNormalizer,
    NmapNormalizer,
    NucleiNormalizer,
    OpenVASNormalizer,
    ProwlerNormalizer,
    QualysScannerNormalizer,
    Rapid7ScannerNormalizer,
    SARIFUniversalNormalizer,
    SemgrepScannerNormalizer,
    SnykNormalizer,
    SonarQubeNormalizer,
    SPDXUniversalNormalizer,
    TenableScannerNormalizer,
    TrivyScannerNormalizer,
    VeracodeNormalizer,
    # Import all 32 normalizers
    ZAPNormalizer,
    _Base,
    _parse_json_safe,
    _parse_xml_safe,
)

# Optional: Import DefectDojo fallback parser
try:
    from connectors.defectdojo_parser import DefectDojoParserClient
    _DEFECTDOJO_AVAILABLE = True
except ImportError:
    _DEFECTDOJO_AVAILABLE = False

# Optional: Import ConnectorGateway for bridge integration
try:
    from connectors.connector_registry import ConnectorGateway, ConnectorRegistry
    _GATEWAY_AVAILABLE = True
except ImportError:
    _GATEWAY_AVAILABLE = False

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
# Format Detection Rules
# ═══════════════════════════════════════════════════════════════════════════

class FormatDetector:
    """Auto-detect scanner format from raw data structure.

    Examines JSON keys, XML root elements, and data signatures to determine
    the scanner format. Returns format name or None if unrecognized.

    Supported formats:
    - SARIF, CycloneDX, SPDX (standards)
    - Trivy, Grype, Nuclei, Nessus, ZAP, Burp, Semgrep, Checkov, Prowler
    - Generic JSON/XML arrays
    """

    # Map format names to their "short names" used by normalizers
    FORMAT_ALIASES = {
        "sarif": "sarif",
        "cyclone-dx": "cyclonedx",
        "cyclonedx": "cyclonedx",
        "spdx": "spdx",
        "trivy": "trivy",
        "grype": "grype",
        "nuclei": "nuclei",
        "nessus": "nessus",
        "zap": "zap",
        "burp": "burp",
        "openvas": "openvas",
        "semgrep": "semgrep",
        "checkov": "checkov",
        "prowler": "prowler",
        "bandit": "bandit",
        "snyk": "snyk",
        "quickscan": "quickscan",
        "gitleaks": "gitleaks",
    }

    @staticmethod
    def detect(raw_data: Any) -> Optional[str]:
        """Detect scanner format from data structure.

        Args:
            raw_data: Parsed JSON object or XML root element.

        Returns:
            Format name (e.g., "sarif", "trivy") or None if not recognized.
        """
        if isinstance(raw_data, dict):
            return FormatDetector._detect_json_format(raw_data)
        elif isinstance(raw_data, ET.Element):
            return FormatDetector._detect_xml_format(raw_data)
        return None

    @staticmethod
    def _detect_json_format(obj: Dict[str, Any]) -> Optional[str]:
        """Detect format from JSON object."""
        # SARIF v2.1: has "$schema" containing "sarif" or "runs" array with tool.driver
        if "$schema" in obj and "sarif" in obj.get("$schema", "").lower():
            return "sarif"
        if "runs" in obj and isinstance(obj.get("runs"), list):
            if obj["runs"] and isinstance(obj["runs"][0], dict):
                if "tool" in obj["runs"][0]:
                    return "sarif"

        # CycloneDX: has "bomFormat" == "CycloneDX" or top-level "components"
        if obj.get("bomFormat") == "CycloneDX":
            return "cyclonedx"
        if "specVersion" in obj and "version" in obj and "components" in obj:
            # CycloneDX structure
            return "cyclonedx"

        # SPDX: has "spdxVersion" key (e.g., "SPDX-2.2")
        if "spdxVersion" in obj:
            return "spdx"

        # Trivy: has "Results" array with "Vulnerabilities"
        if "Results" in obj and isinstance(obj["Results"], list):
            if obj["Results"] and "Vulnerabilities" in obj["Results"][0]:
                return "trivy"

        # Grype: has "matches" array with vulnerability objects
        if "matches" in obj and isinstance(obj["matches"], list):
            if obj["matches"] and "vulnerability" in obj["matches"][0]:
                return "grype"

        # Nuclei: array of objects each with "template-id"
        # (Nuclei JSONL is streamed, but if it's a single object or array)
        if isinstance(obj, list):
            if obj and "template-id" in obj[0]:
                return "nuclei"
        if "template-id" in obj:
            return "nuclei"

        # Semgrep: has "results" array with objects containing "check_id"
        if "results" in obj and isinstance(obj["results"], list):
            if obj["results"] and "check_id" in obj["results"][0]:
                return "semgrep"

        # Checkov: has "passed" and "failed" lists
        if "passed" in obj and "failed" in obj:
            if isinstance(obj.get("passed"), list) and isinstance(obj.get("failed"), list):
                return "checkov"

        # Prowler: has "StatusExtended" key or "findings" with prowler metadata
        if "StatusExtended" in obj or ("findings" in obj and len(obj) > 0 and "AccountId" in obj):
            return "prowler"

        # Snyk: has "vulnerabilities" array and "ok" or "status" key
        if "vulnerabilities" in obj and (
            "ok" in obj or "status" in obj or "org" in obj
        ):
            return "snyk"

        # Bandit: has "results" array and "metrics" with "generated_at"
        if "results" in obj and "metrics" in obj and "generated_at" in obj:
            if isinstance(obj["results"], list):
                return "bandit"

        # Generic JSON array of findings: array of objects with "severity" or "vulnerability"
        if isinstance(obj, list):
            if obj and ("severity" in obj[0] or "vulnerability" in obj[0]):
                return "generic_json_array"

        # Burp: if we see "issues" array, could be Burp JSON
        if "issues" in obj and isinstance(obj["issues"], list):
            return "burp"

        # ZAP: if we see "site" array or alerts structure
        if "site" in obj and isinstance(obj.get("site"), list):
            return "zap"
        if "alerts" in obj and isinstance(obj.get("alerts"), list):
            return "zap"

        return None

    @staticmethod
    def _detect_xml_format(root: ET.Element) -> Optional[str]:
        """Detect format from XML root element."""
        tag = root.tag.lower() if root.tag else ""

        # ZAP: <OWASPZAPReport> root
        if "owaszapreport" in tag or "zapreport" in tag:
            return "zap"

        # Burp: <issues> root
        if tag == "issues":
            return "burp"

        # Nessus: <NessusClientData_v2> root
        if "nessusclientdata" in tag:
            return "nessus"

        # OpenVAS: <report> with <results>
        if tag == "report" and root.find(".//result") is not None:
            return "openvas"

        # SARIF can be XML (rare but possible)
        if "sarif" in tag:
            return "sarif"

        return None


# ═══════════════════════════════════════════════════════════════════════════
# NormalizerRegistry: Auto-discovery and Routing
# ═══════════════════════════════════════════════════════════════════════════

class NormalizerRegistry:
    """Registry of all 32 ALDECI scanner normalizers.

    Auto-discovers normalizer classes from scanner_parsers module.
    Maps format names to normalizer instances.
    Provides routing and normalization methods.

    Usage:
        registry = NormalizerRegistry()
        findings = registry.normalize("zap", raw_zap_data)
        formats = registry.get_supported_formats()
    """

    def __init__(self) -> None:
        """Initialize registry and auto-discover all normalizers."""
        self._normalizers: Dict[str, _Base] = {}
        self._format_to_normalizer: Dict[str, str] = {}
        self._discover_normalizers()
        logger.info(
            "NormalizerRegistry initialized with %d normalizers",
            len(self._normalizers),
        )

    def _discover_normalizers(self) -> None:
        """Auto-discover all normalizer classes from scanner_parsers module.

        Instantiates each normalizer and maps format names.
        """
        # Hardcoded list of all 32 normalizer classes
        normalizer_classes = [
            ZAPNormalizer,
            BurpNormalizer,
            NessusNormalizer,
            OpenVASNormalizer,
            BanditNormalizer,
            CheckmarxNormalizer,
            SonarQubeNormalizer,
            FortifyNormalizer,
            VeracodeNormalizer,
            NiktoNormalizer,
            NucleiNormalizer,
            NmapNormalizer,
            SnykNormalizer,
            ProwlerNormalizer,
            CheckovNormalizer,
            TrivyScannerNormalizer,
            GrypeScannerNormalizer,
            SemgrepScannerNormalizer,
            DependabotScannerNormalizer,
            QualysScannerNormalizer,
            TenableScannerNormalizer,
            Rapid7ScannerNormalizer,
            AcunetixScannerNormalizer,
            AWSInspectorNormalizer,
            GitLabSASTNormalizer,
            SARIFUniversalNormalizer,
            CycloneDXUniversalNormalizer,
            SPDXUniversalNormalizer,
            GitleaksScannerNormalizer,
            ClaudeCodeSecurityNormalizer,
            CombobulatorNormalizer,
        ]

        for normalizer_class in normalizer_classes:
            try:
                # Instantiate with minimal config
                instance = normalizer_class()
                normalizer_name = normalizer_class.__name__
                self._normalizers[normalizer_name] = instance

                # Map common format names to this normalizer
                format_name = self._infer_format_name(normalizer_name)
                if format_name:
                    self._format_to_normalizer[format_name] = normalizer_name
                    logger.debug(
                        "Registered normalizer: %s → %s",
                        format_name,
                        normalizer_name,
                    )
            except Exception as exc:
                logger.warning(
                    "Failed to instantiate %s: %s",
                    normalizer_class.__name__,
                    exc,
                )

    @staticmethod
    def _infer_format_name(normalizer_class_name: str) -> Optional[str]:
        """Infer format name from normalizer class name.

        Examples:
            ZAPNormalizer → zap
            SARIFUniversalNormalizer → sarif
            CycloneDXUniversalNormalizer → cyclonedx
            TrivyScannerNormalizer → trivy
        """
        name = normalizer_class_name.lower()

        # Remove common suffixes
        if name.endswith("normalizer"):
            name = name[:-10]  # Remove "normalizer"
        if name.endswith("scanner"):
            name = name[:-7]  # Remove "scanner"

        # Special cases
        substitutions = {
            "zapnormalizer": "zap",
            "burpnormalizer": "burp",
            "nessus": "nessus",
            "openvas": "openvas",
            "bandit": "bandit",
            "checkmarx": "checkmarx",
            "sonarqube": "sonarqube",
            "fortify": "fortify",
            "veracode": "veracode",
            "nikto": "nikto",
            "nuclei": "nuclei",
            "nmap": "nmap",
            "snyk": "snyk",
            "prowler": "prowler",
            "checkov": "checkov",
            "trivy": "trivy",
            "grype": "grype",
            "semgrep": "semgrep",
            "dependabot": "dependabot",
            "qualys": "qualys",
            "tenable": "tenable",
            "rapid7": "rapid7",
            "acunetix": "acunetix",
            "awsinspector": "awsinspector",
            "gitlabsast": "gitlabsast",
            "sarif": "sarif",
            "cyclonedx": "cyclonedx",
            "spdx": "spdx",
            "gitleaks": "gitleaks",
            "claudecodesecurity": "claudecodesecurity",
            "combobulator": "combobulator",
        }

        return substitutions.get(name, None)

    def get_normalizer(self, format_name: str) -> Optional[_Base]:
        """Get normalizer instance by format name.

        Args:
            format_name: Format name (e.g., "zap", "sarif", "trivy").

        Returns:
            Normalizer instance or None if not found.
        """
        format_lower = format_name.lower()
        normalizer_name = self._format_to_normalizer.get(format_lower)
        if normalizer_name:
            return self._normalizers.get(normalizer_name)
        return None

    def get_supported_formats(self) -> List[str]:
        """Get list of all supported format names.

        Returns:
            Sorted list of format names.
        """
        return sorted(self._format_to_normalizer.keys())

    def normalize(
        self,
        format_name: str,
        raw_data: bytes,
    ) -> tuple[List[Dict[str, Any]], Optional[str]]:
        """Normalize raw scan data.

        Args:
            format_name: Scanner format (e.g., "zap", "sarif").
            raw_data: Raw bytes from scanner output.

        Returns:
            Tuple of (findings_list, error_message).
            If successful: (findings, None)
            If failed: ([], error_message_str)
        """
        normalizer = self.get_normalizer(format_name)
        if not normalizer:
            return [], f"No normalizer found for format: {format_name}"

        try:
            findings = normalizer.normalize(raw_data)
            if findings is None:
                findings = []
            logger.info(
                "Normalized %d findings from %s",
                len(findings),
                format_name,
            )
            return findings, None
        except Exception as exc:
            error_msg = f"Normalization failed for {format_name}: {type(exc).__name__}: {exc}"
            logger.error(error_msg)
            return [], error_msg

    def auto_detect_format(self, raw_data: bytes) -> Optional[str]:
        """Auto-detect scanner format from raw data.

        Tries both JSON and XML parsing, then applies format detection rules.

        Args:
            raw_data: Raw bytes to analyze.

        Returns:
            Detected format name or None if unrecognized.
        """
        # Try JSON first
        parsed_json = _parse_json_safe(raw_data)
        if parsed_json:
            detected = FormatDetector.detect(parsed_json)
            if detected:
                logger.debug("Auto-detected format from JSON: %s", detected)
                return detected

        # Try XML
        parsed_xml = _parse_xml_safe(raw_data)
        if parsed_xml:
            detected = FormatDetector.detect(parsed_xml)
            if detected:
                logger.debug("Auto-detected format from XML: %s", detected)
                return detected

        logger.warning("Failed to auto-detect format")
        return None


# ═══════════════════════════════════════════════════════════════════════════
# NormalizerGatewayBridge: High-Level Async Interface
# ═══════════════════════════════════════════════════════════════════════════

class NormalizerGatewayBridge:
    """High-level bridge between scan sources and the ConnectorGateway.

    Provides async methods for:
    - Normalizing scan outputs from various scanners
    - Auto-detecting formats
    - Falling back to DefectDojo if needed
    - Feeding results into ConnectorGateway for pipeline processing

    Usage:
        bridge = NormalizerGatewayBridge()
        result = await bridge.process_scan_output(raw_zap_xml, format_hint="zap")

    The result dict contains:
    {
        "normalized_count": int,          # Number of findings normalized
        "format_used": str,               # Format that was used
        "fallback_used": bool,            # True if DefectDojo was used
        "errors": List[str],              # Any error messages
        "findings": List[Dict],           # Normalized findings
        "gateway_outcome": Optional[Dict], # ConnectorGateway.ingest result
    }
    """

    def __init__(
        self,
        registry: Optional[NormalizerRegistry] = None,
        gateway: Optional[ConnectorGateway] = None,
        defectdojo_client: Optional[DefectDojoParserClient] = None,
    ) -> None:
        """Initialize bridge.

        Args:
            registry: NormalizerRegistry (auto-creates if not provided).
            gateway: ConnectorGateway (auto-creates if not provided).
            defectdojo_client: Optional DefectDojoParserClient for fallback.
        """
        self._registry = registry or NormalizerRegistry()
        self._gateway = gateway or (ConnectorGateway() if _GATEWAY_AVAILABLE else None)
        self._defectdojo = defectdojo_client
        logger.info("NormalizerGatewayBridge initialized")

    async def process_scan_output(
        self,
        raw_data: bytes,
        format_hint: Optional[str] = None,
        source: str = "unknown",
    ) -> Dict[str, Any]:
        """Process raw scan output end-to-end.

        Flow:
        1. If format_hint provided, use it; else auto-detect
        2. Try local normalizer
        3. If local fails and DefectDojo available, fall back to DefectDojo
        4. Feed results into ConnectorGateway if available

        Args:
            raw_data: Raw bytes from scanner output.
            format_hint: Optional format hint (e.g., "zap", "sarif").
            source: Source identifier for logging/gateway (default "unknown").

        Returns:
            Result dict with normalized_count, format_used, fallback_used, errors, findings.
        """
        result: Dict[str, Any] = {
            "normalized_count": 0,
            "format_used": None,
            "fallback_used": False,
            "errors": [],
            "findings": [],
            "gateway_outcome": None,
        }

        # Step 1: Determine format
        format_to_use = format_hint
        if not format_to_use:
            format_to_use = self._registry.auto_detect_format(raw_data)
            if not format_to_use:
                error = "Could not determine scanner format (no hint, auto-detect failed)"
                result["errors"].append(error)
                logger.warning(error)

                # Try DefectDojo fallback
                if self._defectdojo:
                    result = await self._try_defectdojo_fallback(
                        raw_data, source, result
                    )
                return result

        result["format_used"] = format_to_use

        # Step 2: Try local normalizer
        findings, error = self._registry.normalize(format_to_use, raw_data)
        if error:
            result["errors"].append(error)
            logger.warning("Local normalization failed: %s", error)

            # Try DefectDojo fallback
            if self._defectdojo:
                result = await self._try_defectdojo_fallback(
                    raw_data, source, result
                )
            return result

        result["normalized_count"] = len(findings)
        result["findings"] = findings
        logger.info(
            "Normalized %d findings from %s (format: %s)",
            len(findings),
            source,
            format_to_use,
        )

        # Step 3: Feed into gateway if available
        if self._gateway and findings:
            try:
                outcome = await self._gateway.ingest(
                    source=source,
                    findings=findings,
                    metadata={"format": format_to_use},
                )
                result["gateway_outcome"] = outcome.to_dict() if hasattr(outcome, "to_dict") else outcome
            except Exception as exc:
                error_msg = f"Gateway ingestion failed: {type(exc).__name__}: {exc}"
                result["errors"].append(error_msg)
                logger.error(error_msg)

        return result

    async def _try_defectdojo_fallback(
        self,
        raw_data: bytes,
        source: str,
        result: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Try to parse via DefectDojo API as fallback.

        Args:
            raw_data: Raw bytes to parse.
            source: Source identifier.
            result: Existing result dict to update.

        Returns:
            Updated result dict.
        """
        logger.info("Attempting DefectDojo fallback parser for %s", source)
        try:
            # DefectDojo parser is async, use it
            findings = await self._defectdojo.parse_scan(
                raw_data, source=source
            )
            if findings:
                result["normalized_count"] = len(findings)
                result["findings"] = findings
                result["fallback_used"] = True
                result["format_used"] = "defectdojo_fallback"
                logger.info(
                    "DefectDojo fallback parsed %d findings for %s",
                    len(findings),
                    source,
                )

                # Feed into gateway
                if self._gateway:
                    try:
                        outcome = await self._gateway.ingest(
                            source=source,
                            findings=findings,
                            metadata={"format": "defectdojo_fallback"},
                        )
                        result["gateway_outcome"] = outcome.to_dict() if hasattr(outcome, "to_dict") else outcome
                    except Exception as exc:
                        error_msg = f"Gateway ingestion of DefectDojo findings failed: {exc}"
                        result["errors"].append(error_msg)
                        logger.error(error_msg)
            else:
                error = "DefectDojo fallback returned empty results"
                result["errors"].append(error)
                logger.warning(error)
        except Exception as exc:
            error_msg = f"DefectDojo fallback failed: {type(exc).__name__}: {exc}"
            result["errors"].append(error_msg)
            logger.error(error_msg)

        return result

    def get_supported_formats(self) -> List[str]:
        """Get list of all supported formats.

        Returns:
            Sorted list of format names.
        """
        return self._registry.get_supported_formats()


# ═══════════════════════════════════════════════════════════════════════════
# Utility & Testing
# ═══════════════════════════════════════════════════════════════════════════

@functools.lru_cache(maxsize=1)
def get_registry() -> NormalizerRegistry:
    """Get or create singleton NormalizerRegistry.

    Cached: 31 normalizer classes are instantiated only once per process,
    not on every call. Subsequent calls return the same instance in O(1).

    Returns:
        NormalizerRegistry instance (shared singleton).
    """
    return NormalizerRegistry()


@functools.lru_cache(maxsize=1)
def _get_default_bridge() -> NormalizerGatewayBridge:
    """Return the process-level default NormalizerGatewayBridge (no-arg variant).

    Cached so the registry + gateway are built only once.
    """
    return NormalizerGatewayBridge(registry=get_registry())


def get_bridge(
    registry: Optional[NormalizerRegistry] = None,
    gateway: Optional[ConnectorGateway] = None,
) -> NormalizerGatewayBridge:
    """Get or create NormalizerGatewayBridge.

    When called with no arguments, returns the cached singleton bridge
    (registry instantiation cost paid only once).  Custom registry/gateway
    arguments bypass the cache and always create a fresh bridge.

    Args:
        registry: Optional custom registry.
        gateway: Optional custom gateway.

    Returns:
        NormalizerGatewayBridge instance.
    """
    if registry is None and gateway is None:
        return _get_default_bridge()
    return NormalizerGatewayBridge(registry=registry, gateway=gateway)


# ═══════════════════════════════════════════════════════════════════════════
# CLI & Testing
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    """Quick test: List all supported formats and test basic registry."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    print("=" * 80)
    print("ALDECI Normalizer Registry — Format Support")
    print("=" * 80)

    registry = NormalizerRegistry()
    formats = registry.get_supported_formats()

    print(f"\nSupported formats ({len(formats)}):")
    for fmt in formats:
        normalizer = registry.get_normalizer(fmt)
        normalizer_class = normalizer.__class__.__name__ if normalizer else "N/A"
        print(f"  - {fmt:<20} → {normalizer_class}")

    print("\n" + "=" * 80)
    print("Total normalizers registered:", len(registry._normalizers))
    print("=" * 80)
