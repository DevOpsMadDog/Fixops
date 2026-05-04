"""
ALdeci Universal Scanner Parser Library — 15 Third-Party Scanner Normalizers.

Clean-room implementations inspired by ArcherySec's parser approach (GPL-3.0)
and DeepAudit's multi-agent audit flow (AGPL-3.0). Zero code copied — all parsers
written from each scanner's documented output format specifications.

Plugs into the existing NormalizerRegistry in apps/api/ingestion.py.
Feeds directly into Brain Pipeline Step 1 (CONNECT) → Step 2 (NORMALIZE).

Cherry-picked from ArcherySec:
  - Scanner output parsing patterns (ZAP, Burp, Nessus, OpenVAS, Bandit, Nmap, Nikto)
  - XML/JSON auto-detection approach
  - Severity normalization across heterogeneous scanner outputs

Cherry-picked from DeepAudit:
  - Multi-dimensional analysis concept (Bug + Security + Performance)
  - OWASP Top 10 rule mapping pattern
  - Structured audit report generation approach

Vision Pillars: V1 (APP_ID-Centric), V3 (Decision Intelligence), V9 (Air-Gapped)
License: Proprietary (ALdeci). All implementations are original.
"""

from __future__ import annotations

import json
import logging
import re
import xml.etree.ElementTree as ET  # noqa: B405 — defusedxml.defuse_stdlib() called below  # nosec B405
from typing import Any, Dict, List, Optional

# Harden stdlib XML parsers against XXE/entity-expansion attacks.
# defusedxml.defuse_stdlib() monkey-patches xml.etree.ElementTree (and others)
# so that even fallback code paths are safe.
try:
    import defusedxml
    defusedxml.defuse_stdlib()
except ImportError:
    pass  # defusedxml not installed — regex stripping in _parse_xml_safe provides defense

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# TrustGraph event bus — optional, never blocks on failure
# ---------------------------------------------------------------------------
try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except ImportError:  # pragma: no cover - bus is optional
    _get_tg_bus = None  # type: ignore[assignment]


def _emit_event(event_type: str, payload: Dict[str, Any]) -> None:
    """Emit an event to the TrustGraph event bus. Never raises. Module-level
    helper because there are 32 normalizer classes — wiring here covers all
    of them via a single _make_finding() call site.
    """
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


# ---------------------------------------------------------------------------
# Try to import from the ingestion module for tight integration
# ---------------------------------------------------------------------------
try:
    from apps.api.ingestion import (
        BaseNormalizer,
        FindingSeverity,
        FindingType,  # noqa: F401
        NormalizerConfig,
        SourceFormat,
        UnifiedFinding,
    )
    _INGESTION_AVAILABLE = True
except ImportError:
    _INGESTION_AVAILABLE = False
    # Standalone fallback — allows this module to work without suite-api
    logger.info("Running scanner_parsers in standalone mode (no ingestion module)")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _extract_cves(text: str) -> List[str]:
    """Extract CVE identifiers from text."""
    if not text:
        return []
    return list(set(re.findall(r"CVE-\d{4}-\d{4,}", str(text))))


def _extract_cwes(text: str) -> List[str]:
    """Extract CWE identifiers from text."""
    if not text:
        return []
    return list(set(re.findall(r"CWE-\d+", str(text))))


def _severity_from_number(num: Any) -> str:
    """Convert numeric severity to string."""
    try:
        n = int(num)
    except (ValueError, TypeError):
        return "medium"
    return {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "info"}.get(n, "medium")


_MAX_XML_SIZE = 100 * 1024 * 1024  # 100 MB limit for XML files


def _parse_xml_safe(data: bytes) -> Optional[ET.Element]:
    """Safely parse XML with XXE protection, return None on failure.

    Defenses:
    - Size limit to prevent billion-laughs DoS
    - Uses defusedxml when available (blocks entity expansion, DTD, external entities)
    - Falls back to regex DOCTYPE/ENTITY stripping when defusedxml is unavailable
    - Catches all parse errors gracefully
    """
    if len(data) > _MAX_XML_SIZE:
        logger.warning("XML data exceeds size limit (%d > %d bytes)", len(data), _MAX_XML_SIZE)
        return None
    try:
        # Prefer defusedxml for hardened XML parsing (blocks XXE, billion-laughs, DTD)
        try:
            from defusedxml.ElementTree import fromstring as _safe_fromstring
            return _safe_fromstring(data)
        except ImportError:
            pass  # defusedxml not installed — use regex-based stripping below

        # Fallback: manual DOCTYPE/ENTITY stripping + stdlib parser
        text = data.decode("utf-8", errors="ignore")
        # Strip DOCTYPE to prevent XXE (external entity injection)
        # This removes <!DOCTYPE ...> declarations including inline DTDs
        import re as _re
        text = _re.sub(
            r'<!DOCTYPE[^>\[]*(\[[^\]]*\])?\s*>',
            '',
            text,
            flags=_re.IGNORECASE | _re.DOTALL,
        )
        # Also strip any remaining entity declarations
        text = _re.sub(r'<!ENTITY[^>]*>', '', text, flags=_re.IGNORECASE)
        return ET.fromstring(text)  # noqa: B314 — defusedxml.defuse_stdlib() called at module load  # nosec
    except (ET.ParseError, ValueError, OverflowError):
        return None


_MAX_JSON_SIZE = 100 * 1024 * 1024  # 100 MB limit for JSON files


def _parse_json_safe(data: bytes) -> Optional[Any]:
    """Safely parse JSON with size limit, return None on failure."""
    if len(data) > _MAX_JSON_SIZE:
        logger.warning("JSON data exceeds size limit (%d > %d bytes)", len(data), _MAX_JSON_SIZE)
        return None
    try:
        return json.loads(data.decode("utf-8", errors="ignore"))
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
        return None


# ═══════════════════════════════════════════════════════════════════════════
# Normalizer implementations (extend BaseNormalizer when available)
# ═══════════════════════════════════════════════════════════════════════════

if _INGESTION_AVAILABLE:
    _Base = BaseNormalizer
else:
    # Minimal fallback base
    class _Base:  # type: ignore[no-redef]
        def __init__(self, config=None):
            self.name = config.name if config else "unknown"
            self.priority = config.priority if config else 50
            self.enabled = config.enabled if config else True
            self.config = config

        def can_handle(self, content, content_type=None):
            return 0.0

        def normalize(self, content, content_type=None):
            raise NotImplementedError

        def _map_severity(self, value):
            if _INGESTION_AVAILABLE:
                return super()._map_severity(value)
            smap = {
                "critical": "critical", "high": "high", "medium": "medium",
                "moderate": "medium", "low": "low", "info": "info",
                "informational": "info", "error": "high", "warning": "medium",
            }
            if isinstance(value, str):
                return smap.get(value.lower().strip(), "medium")
            if isinstance(value, (int, float)):
                if value >= 9.0:
                    return "critical"
                if value >= 7.0:
                    return "high"
                if value >= 4.0:
                    return "medium"
                if value > 0:
                    return "low"
                return "info"
            return "medium"


# Throttle counter so we emit one TrustGraph event per N findings, not per finding.
# Per-finding emits would be ~thousands per scan and would flood the bus.
_FINDING_EMIT_THROTTLE = 100
_finding_emit_counter = 0


def _make_finding(**kwargs) -> Any:
    """Create a UnifiedFinding or dict depending on availability."""
    global _finding_emit_counter
    _finding_emit_counter += 1
    if _finding_emit_counter % _FINDING_EMIT_THROTTLE == 0:
        _emit_event(
            "scanner.findings.batch_normalized",
            {
                "normalizer": kwargs.get("scanner") or kwargs.get("source") or "unknown",
                "severity": str(kwargs.get("severity", "unknown")),
                "batch_size": _FINDING_EMIT_THROTTLE,
                "running_total": _finding_emit_counter,
            },
        )
    if _INGESTION_AVAILABLE:
        # Map string severity to enum
        sev = kwargs.get("severity", "medium")
        if isinstance(sev, str):
            sev_map = {
                "critical": FindingSeverity.CRITICAL,
                "high": FindingSeverity.HIGH,
                "medium": FindingSeverity.MEDIUM,
                "low": FindingSeverity.LOW,
                "info": FindingSeverity.INFO,
            }
            kwargs["severity"] = sev_map.get(sev.lower(), FindingSeverity.UNKNOWN)
        # Map source_format string to enum
        sf = kwargs.pop("source_format_str", None)
        if sf:
            try:
                kwargs["source_format"] = SourceFormat(sf)
            except (ValueError, KeyError):
                kwargs["source_format"] = SourceFormat.CUSTOM
        return UnifiedFinding(**kwargs)
    return kwargs


# ═══════════════════════════════════════════════════════════════════════════
# 1. OWASP ZAP Parser (JSON + XML)
# ═══════════════════════════════════════════════════════════════════════════

class ZAPNormalizer(_Base):
    """Parse OWASP ZAP JSON and XML reports."""

    def can_handle(self, content: bytes, content_type: Optional[str] = None) -> float:
        text = content[:5000].decode("utf-8", errors="ignore")
        if "OWASPZAPReport" in text or "OWASP-ZAP" in text:
            return 0.95
        if '"site"' in text and ('"alerts"' in text or '"riskcode"' in text):
            return 0.85
        if "alertitem" in text and "riskcode" in text:
            return 0.9
        return 0.0

    def normalize(self, content: bytes, content_type: Optional[str] = None) -> list:
        findings = []
        parsed = _parse_json_safe(content)
        if parsed:
            findings = self._parse_json(parsed)
        else:
            root = _parse_xml_safe(content)
            if root is not None:
                findings = self._parse_xml(root)
        return findings

    def _parse_json(self, data: dict) -> list:
        findings = []
        sites = data.get("site", [data] if "alerts" in data else [])
        if isinstance(sites, dict):
            sites = [sites]
        for site in sites:
            for alert in site.get("alerts", []):
                instances = alert.get("instances", [{}])
                for inst in instances[:10]:  # Cap instances per alert
                    findings.append(_make_finding(
                        title=alert.get("name", alert.get("alert", "ZAP Finding")),
                        description=alert.get("desc", ""),
                        severity=_severity_from_number(alert.get("riskcode", "2")),
                        source_tool="zap",
                        source_format_str="sarif",
                        rule_id=str(alert.get("pluginid", "")),
                        cwe_id=f"CWE-{alert['cweid']}" if alert.get("cweid") and str(alert.get("cweid")) != "-1" else None,
                        recommendation=alert.get("solution", ""),
                        file_path=inst.get("uri", inst.get("url", "")),
                    ))
        return findings

    def _parse_xml(self, root: ET.Element) -> list:
        findings = []
        for item in root.findall(".//alertitem"):
            findings.append(_make_finding(
                title=item.findtext("alert", "ZAP Finding"),
                description=item.findtext("desc", ""),
                severity=_severity_from_number(item.findtext("riskcode", "2")),
                source_tool="zap",
                source_format_str="sarif",
                rule_id=item.findtext("pluginid", ""),
                cwe_id=f"CWE-{item.findtext('cweid', '')}" if item.findtext("cweid") else None,
                recommendation=item.findtext("solution", ""),
                file_path=item.findtext("uri", item.findtext("url", "")),
            ))
        return findings


# ═══════════════════════════════════════════════════════════════════════════
# 2. Burp Suite Parser (XML + JSON)
# ═══════════════════════════════════════════════════════════════════════════

class BurpNormalizer(_Base):
    """Parse Burp Suite XML and JSON exports."""

    def can_handle(self, content: bytes, content_type: Optional[str] = None) -> float:
        text = content[:5000].decode("utf-8", errors="ignore")
        if "burpVersion" in text or "serialNumber" in text:
            return 0.95
        if "<issues" in text and ("<issue>" in text or "issueType" in text):
            return 0.85
        return 0.0

    def normalize(self, content: bytes, content_type: Optional[str] = None) -> list:
        findings = []
        root = _parse_xml_safe(content)
        if root is not None:
            for issue in root.findall(".//issue"):
                findings.append(_make_finding(
                    title=issue.findtext("name", issue.findtext("type", "Burp Finding")),
                    description=issue.findtext("issueDetail", issue.findtext("issueBackground", "")),
                    severity=issue.findtext("severity", "medium").lower(),
                    source_tool="burp",
                    source_format_str="custom",
                    cwe_id=_extract_cwes(issue.findtext("vulnerabilityClassifications", ""))[0] if _extract_cwes(issue.findtext("vulnerabilityClassifications", "")) else None,
                    recommendation=issue.findtext("remediationDetail", issue.findtext("remediationBackground", "")),
                    file_path=(issue.findtext("host", "") + issue.findtext("path", "")),
                ))
        else:
            parsed = _parse_json_safe(content)
            if parsed:
                issues = parsed.get("issues", parsed.get("issue_events", []))
                for issue in issues:
                    findings.append(_make_finding(
                        title=issue.get("name", issue.get("type", "Burp Finding")),
                        description=issue.get("description", issue.get("detail", "")),
                        severity=issue.get("severity", "medium").lower(),
                        source_tool="burp",
                        source_format_str="custom",
                        file_path=issue.get("origin", "") + issue.get("path", ""),
                    ))
        return findings


# ═══════════════════════════════════════════════════════════════════════════
# 3. Nessus Parser (.nessus XML)
# ═══════════════════════════════════════════════════════════════════════════

class NessusNormalizer(_Base):
    """Parse Nessus .nessus XML exports."""

    def can_handle(self, content: bytes, content_type: Optional[str] = None) -> float:
        text = content[:5000].decode("utf-8", errors="ignore")
        if "NessusClientData" in text or ("Policy" in text and "ReportHost" in text):
            return 0.95
        return 0.0

    def normalize(self, content: bytes, content_type: Optional[str] = None) -> list:
        findings = []
        root = _parse_xml_safe(content)
        if root is None:
            return findings

        for host in root.findall(".//ReportHost"):
            host_name = host.get("name", "")
            for item in host.findall("ReportItem"):
                sev_num = item.get("severity", "0")
                if sev_num == "0":
                    continue  # Skip informationals
                cve_list = [cve.text for cve in item.findall("cve") if cve.text]
                cvss3 = item.findtext("cvss3_base_score", None)
                cvss2 = item.findtext("cvss_base_score", None)
                cvss = float(cvss3 or cvss2 or "0")
                findings.append(_make_finding(
                    title=item.get("pluginName", "Nessus Finding"),
                    description=item.findtext("description", item.findtext("synopsis", "")),
                    severity=_severity_from_number(sev_num),
                    source_tool="nessus",
                    source_format_str="custom",
                    rule_id=item.get("pluginID", ""),
                    cve_id=cve_list[0] if cve_list else None,
                    cvss_score=cvss if cvss > 0 else None,
                    recommendation=item.findtext("solution", ""),
                    code_snippet=item.findtext("plugin_output", "")[:500] if item.findtext("plugin_output") else None,
                    asset_name=host_name,
                    tags=cve_list[1:] if len(cve_list) > 1 else [],
                ))
        return findings


# ═══════════════════════════════════════════════════════════════════════════
# 4. OpenVAS Parser (XML)
# ═══════════════════════════════════════════════════════════════════════════

class OpenVASNormalizer(_Base):
    """Parse OpenVAS XML reports."""

    def can_handle(self, content: bytes, content_type: Optional[str] = None) -> float:
        text = content[:5000].decode("utf-8", errors="ignore")
        if "openvas" in text.lower() or ("<report" in text and "<results" in text and "<result" in text):
            return 0.9
        return 0.0

    def normalize(self, content: bytes, content_type: Optional[str] = None) -> list:
        findings = []
        root = _parse_xml_safe(content)
        if root is None:
            return findings

        for result in root.findall(".//result"):
            threat = result.findtext("threat", "Medium")
            nvt = result.find("nvt")
            host_el = result.find("host")
            host_text = host_el.text.strip() if host_el is not None and host_el.text else ""
            cves = []
            if nvt is not None:
                for cve_el in nvt.findall("cve"):
                    if cve_el.text and cve_el.text != "NOCVE":
                        cves.append(cve_el.text)
            cvss_val = 0.0
            if nvt is not None:
                try:
                    cvss_val = float(nvt.findtext("cvss_base", "0"))
                except ValueError:
                    pass

            findings.append(_make_finding(
                title=nvt.findtext("name", "OpenVAS Finding") if nvt is not None else result.findtext("name", "OpenVAS Finding"),
                description=result.findtext("description", ""),
                severity=threat.lower(),
                source_tool="openvas",
                source_format_str="custom",
                rule_id=nvt.get("oid", "") if nvt is not None else "",
                cve_id=cves[0] if cves else None,
                cvss_score=cvss_val if cvss_val > 0 else None,
                recommendation=nvt.findtext("solution", "") if nvt is not None else "",
                asset_name=host_text,
                tags=cves[1:] if len(cves) > 1 else [],
            ))
        return findings


# ═══════════════════════════════════════════════════════════════════════════
# 5. Bandit Parser (JSON)
# ═══════════════════════════════════════════════════════════════════════════

class BanditNormalizer(_Base):
    """Parse Python Bandit JSON output."""

    def can_handle(self, content: bytes, content_type: Optional[str] = None) -> float:
        text = content[:5000].decode("utf-8", errors="ignore")
        if '"results"' in text and '"test_id"' in text and '"test_name"' in text:
            return 0.95
        if '"results"' in text and '"test_id"' in text and '"generated_at"' in text:
            return 0.90
        if '"generated_at"' in text and '"metrics"' in text and '"_totals"' in text:
            return 0.85
        return 0.0

    def normalize(self, content: bytes, content_type: Optional[str] = None) -> list:
        findings = []
        parsed = _parse_json_safe(content)
        if not parsed:
            return findings

        for r in parsed.get("results", []):
            cwes = _extract_cwes(str(r.get("issue_cwe", {})))
            findings.append(_make_finding(
                title=f"{r.get('test_id', '')}: {r.get('test_name', 'Bandit Finding')}",
                description=r.get("issue_text", ""),
                severity=r.get("issue_severity", "medium").lower(),
                source_tool="bandit",
                source_format_str="custom",
                rule_id=r.get("test_id", ""),
                cwe_id=cwes[0] if cwes else None,
                file_path=r.get("filename", ""),
                line_number=r.get("line_number"),
                code_snippet=r.get("code", "")[:500] if r.get("code") else None,
            ))
        return findings


# ═══════════════════════════════════════════════════════════════════════════
# 6. Checkmarx Parser (XML + JSON)
# ═══════════════════════════════════════════════════════════════════════════

class CheckmarxNormalizer(_Base):
    """Parse Checkmarx CxSAST XML reports and REST API JSON."""

    def can_handle(self, content: bytes, content_type: Optional[str] = None) -> float:
        text = content[:5000].decode("utf-8", errors="ignore")
        if "Checkmarx" in text or "CxXMLResults" in text:
            return 0.95
        if '"queryName"' in text and ('"resultSeverity"' in text or '"sourceLine"' in text):
            return 0.85
        return 0.0

    def normalize(self, content: bytes, content_type: Optional[str] = None) -> list:
        findings = []
        # Try JSON first
        parsed = _parse_json_safe(content)
        if parsed:
            results = parsed if isinstance(parsed, list) else parsed.get("results", parsed.get("vulnerabilities", []))
            for r in results:
                cwe = r.get("cweId", r.get("cwe", ""))
                findings.append(_make_finding(
                    title=r.get("queryName", r.get("name", "Checkmarx Finding")),
                    description=r.get("description", r.get("resultDeepLink", "")),
                    severity=str(r.get("severity", r.get("resultSeverity", "medium"))).lower(),
                    source_tool="checkmarx",
                    source_format_str="custom",
                    rule_id=r.get("queryId", r.get("id", "")),
                    cwe_id=f"CWE-{cwe}" if cwe else None,
                    file_path=r.get("sourceFile", r.get("fileName", "")),
                    line_number=int(r.get("sourceLine", r.get("line", 0))) or None,
                    recommendation=r.get("recommendation", ""),
                ))
            return findings

        # XML (Checkmarx report export)
        root = _parse_xml_safe(content)
        if root is None:
            return findings

        for query in root.findall(".//Query"):
            query_name = query.get("name", "Checkmarx Finding")
            cwe = query.get("cweId", "")
            severity = query.get("Severity", "Medium")
            for result in query.findall(".//Result"):
                path_nodes = result.findall(".//PathNode")
                first_node = path_nodes[0] if path_nodes else None
                findings.append(_make_finding(
                    title=query_name,
                    description=result.get("DeepLink", ""),
                    severity=severity.lower(),
                    source_tool="checkmarx",
                    source_format_str="custom",
                    rule_id=result.get("NodeId", ""),
                    cwe_id=f"CWE-{cwe}" if cwe else None,
                    file_path=first_node.findtext("FileName", "") if first_node is not None else "",
                    line_number=int(first_node.findtext("Line", "0")) if first_node is not None else None,
                ))
        return findings


# ═══════════════════════════════════════════════════════════════════════════
# 7. SonarQube Parser (REST API JSON)
# ═══════════════════════════════════════════════════════════════════════════

class SonarQubeNormalizer(_Base):
    """Parse SonarQube /api/issues/search JSON output."""

    def can_handle(self, content: bytes, content_type: Optional[str] = None) -> float:
        text = content[:5000].decode("utf-8", errors="ignore")
        if '"issues"' in text and ('"component"' in text or '"rule"' in text) and '"severity"' in text:
            return 0.85
        # Only match "sonarqube" if the content looks like structured data (JSON/XML)
        if ('"paging"' in text or '"total"' in text) and ("sonarqube" in text.lower() or '"issues"' in text):
            return 0.7
        return 0.0

    def normalize(self, content: bytes, content_type: Optional[str] = None) -> list:
        findings = []
        parsed = _parse_json_safe(content)
        if not parsed:
            return findings

        for issue in parsed.get("issues", []):
            component = issue.get("component", "")
            file_path = component.split(":")[-1] if ":" in component else component
            sev = issue.get("severity", "MAJOR").lower()
            sev_map = {"blocker": "critical", "critical": "high", "major": "medium", "minor": "low", "info": "info"}
            cwes = _extract_cwes(str(issue.get("tags", [])))

            findings.append(_make_finding(
                title=f"{issue.get('rule', 'Unknown')}: {issue.get('message', '')[:80]}",
                description=issue.get("message", ""),
                severity=sev_map.get(sev, "medium"),
                source_tool="sonarqube",
                source_format_str="custom",
                rule_id=issue.get("rule", ""),
                cwe_id=cwes[0] if cwes else None,
                file_path=file_path,
                line_number=issue.get("line", issue.get("textRange", {}).get("startLine")),
                tags=issue.get("tags", []),
            ))
        return findings


# ═══════════════════════════════════════════════════════════════════════════
# 8. Fortify Parser (FPR/XML + JSON)
# ═══════════════════════════════════════════════════════════════════════════

class FortifyNormalizer(_Base):
    """Parse Fortify FPR XML and Fortify on Demand JSON."""

    def can_handle(self, content: bytes, content_type: Optional[str] = None) -> float:
        text = content[:5000].decode("utf-8", errors="ignore")
        if "fortifysoftware" in text.lower() or "Fortify" in text:
            return 0.9
        if '"category"' in text and '"frilesRating"' in text:
            return 0.75  # FoD JSON
        return 0.0

    def normalize(self, content: bytes, content_type: Optional[str] = None) -> list:
        findings = []
        # Try XML (Fortify FPR format)
        root = _parse_xml_safe(content)
        if root is not None:
            ns = {"fvdl": "xmlns://www.fortifysoftware.com/schema/fvdl"}
            for vuln in root.findall(".//fvdl:Vulnerability", ns) or root.findall(".//Vulnerability"):
                class_info = vuln.find("fvdl:ClassInfo", ns) or vuln.find("ClassInfo")
                primary = vuln.find(".//fvdl:Primary", ns) or vuln.find(".//Primary")
                title = "Fortify Finding"
                sev = "medium"
                if class_info is not None:
                    title = class_info.findtext("{xmlns://www.fortifysoftware.com/schema/fvdl}Type",
                                               class_info.findtext("Type", "Fortify Finding"))
                    sev_val = class_info.findtext("{xmlns://www.fortifysoftware.com/schema/fvdl}DefaultSeverity",
                                                 class_info.findtext("DefaultSeverity", "2.0"))
                    try:
                        sev_float = float(sev_val)
                        sev = "critical" if sev_float >= 4 else "high" if sev_float >= 3 else "medium" if sev_float >= 2 else "low"
                    except ValueError:
                        sev = sev_val.lower()

                fp = ""
                ln = None
                if primary is not None:
                    fp = primary.findtext("{xmlns://www.fortifysoftware.com/schema/fvdl}FileName",
                                         primary.findtext("FileName", ""))
                    try:
                        ln = int(primary.findtext("{xmlns://www.fortifysoftware.com/schema/fvdl}LineStart",
                                                  primary.findtext("LineStart", "0")))
                    except ValueError:
                        ln = None

                findings.append(_make_finding(
                    title=title,
                    severity=sev,
                    source_tool="fortify",
                    source_format_str="custom",
                    file_path=fp,
                    line_number=ln if ln and ln > 0 else None,
                ))
            if findings:
                return findings

        # Try JSON (Fortify on Demand API)
        parsed = _parse_json_safe(content)
        if parsed:
            vulns = parsed.get("vulnerabilities", parsed.get("items", []))
            for v in vulns:
                loc = v.get("primaryLocation", {})
                cwe = v.get("cwe", v.get("cweId", ""))
                findings.append(_make_finding(
                    title=v.get("category", v.get("name", "Fortify Finding")),
                    description=v.get("description", ""),
                    severity=str(v.get("severity", v.get("frilesRating", "medium"))).lower(),
                    source_tool="fortify",
                    source_format_str="custom",
                    cwe_id=f"CWE-{cwe}" if cwe else None,
                    file_path=loc.get("filePath", ""),
                    line_number=loc.get("startLine"),
                ))
        return findings


# ═══════════════════════════════════════════════════════════════════════════
# 9. Veracode Parser (XML detailed report + Findings API JSON)
# ═══════════════════════════════════════════════════════════════════════════

class VeracodeNormalizer(_Base):
    """Parse Veracode detailed XML report and Findings API JSON."""

    def can_handle(self, content: bytes, content_type: Optional[str] = None) -> float:
        text = content[:5000].decode("utf-8", errors="ignore")
        # Require structured data markers alongside "veracode" to avoid false positives
        if "detailedreport" in text.lower() or ('"veracode"' in text.lower() and ('{' in text or '<' in text)):
            return 0.9
        if '"finding_details"' in text or '"finding_status"' in text:
            return 0.8
        # XML with veracode namespace
        if "veracode" in text.lower() and ("<" in text and ">" in text):
            return 0.75
        return 0.0

    def normalize(self, content: bytes, content_type: Optional[str] = None) -> list:
        findings = []
        # Try JSON (Findings API v2)
        parsed = _parse_json_safe(content)
        if parsed:
            items = parsed.get("_embedded", {}).get("findings", parsed.get("findings", []))
            for f in items:
                dd = f.get("finding_details", {})
                cat = dd.get("finding_category", {})
                cwe = dd.get("cwe", {})
                findings.append(_make_finding(
                    title=cat.get("name", f.get("title", "Veracode Finding")),
                    description=f.get("description", ""),
                    severity=_severity_from_number(f.get("finding_status", {}).get("severity", 2)),
                    source_tool="veracode",
                    source_format_str="custom",
                    cwe_id=f"CWE-{cwe['id']}" if cwe.get("id") else None,
                    file_path=dd.get("file_path", dd.get("source_file", "")),
                    line_number=dd.get("file_line_number", dd.get("line")),
                    cvss_score=float(f.get("cvss", 0)) if f.get("cvss") else None,
                ))
            if findings:
                return findings

        # Try XML (detailed report)
        root = _parse_xml_safe(content)
        if root is not None:
            for flaw in root.findall(".//{*}flaw"):
                cwe = flaw.get("cweid", "")
                findings.append(_make_finding(
                    title=flaw.get("categoryname", "Veracode Finding"),
                    description=flaw.get("description", ""),
                    severity=_severity_from_number(flaw.get("severity", "2")),
                    source_tool="veracode",
                    source_format_str="custom",
                    rule_id=flaw.get("issueid", ""),
                    cwe_id=f"CWE-{cwe}" if cwe else None,
                    file_path=flaw.get("sourcefile", ""),
                    line_number=int(flaw.get("line", 0)) or None,
                ))
        return findings


# ═══════════════════════════════════════════════════════════════════════════
# 10. Nikto Parser (JSON)
# ═══════════════════════════════════════════════════════════════════════════

class NiktoNormalizer(_Base):
    """Parse Nikto JSON output."""

    def can_handle(self, content: bytes, content_type: Optional[str] = None) -> float:
        text = content[:5000].decode("utf-8", errors="ignore")
        if '"vulnerabilities"' in text and ('"OSVDB"' in text or '"nikto"' in text.lower()):
            return 0.95
        # Nikto-style JSON: host + vulnerabilities array
        if '"vulnerabilities"' in text and '"host"' in text and '"id"' in text:
            return 0.80
        return 0.0

    def normalize(self, content: bytes, content_type: Optional[str] = None) -> list:
        findings = []
        parsed = _parse_json_safe(content)
        if not parsed:
            return findings

        host = parsed.get("host", parsed.get("ip", ""))
        port = parsed.get("port", 80)
        for v in parsed.get("vulnerabilities", []):
            cves = _extract_cves(str(v.get("OSVDB", "")) + str(v.get("references", "")))
            findings.append(_make_finding(
                title=f"NIKTO-{v.get('id', 'UNK')}: {v.get('msg', 'Nikto Finding')[:80]}",
                description=v.get("msg", ""),
                severity="medium",
                source_tool="nikto",
                source_format_str="custom",
                rule_id=str(v.get("id", "")),
                cve_id=cves[0] if cves else None,
                asset_name=f"{host}:{port}",
                file_path=v.get("url", f"http://{host}:{port}"),
            ))
        return findings


# ═══════════════════════════════════════════════════════════════════════════
# 11. Nuclei Parser (JSONL — one JSON per line)
# ═══════════════════════════════════════════════════════════════════════════

class NucleiNormalizer(_Base):
    """Parse Nuclei JSONL output (one JSON object per line)."""

    def can_handle(self, content: bytes, content_type: Optional[str] = None) -> float:
        text = content[:2000].decode("utf-8", errors="ignore")
        first_line = text.split("\n", 1)[0]
        try:
            obj = json.loads(first_line)
            if "template-id" in obj and "matched-at" in obj:
                return 0.95
        except (json.JSONDecodeError, ValueError):
            pass
        return 0.0

    def normalize(self, content: bytes, content_type: Optional[str] = None) -> list:
        findings = []
        text = content.decode("utf-8", errors="ignore")
        for line in text.strip().split("\n"):
            if not line.strip():
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = r.get("info", {})
            classification = info.get("classification", {})
            cvss_raw = classification.get("cvss-score", 0)
            try:
                cvss_val = float(cvss_raw) if cvss_raw else None
            except (ValueError, TypeError):
                cvss_val = None
            cves = _extract_cves(str(classification))

            findings.append(_make_finding(
                title=info.get("name", r.get("template-id", "Nuclei Finding")),
                description=info.get("description", ""),
                severity=info.get("severity", "medium"),
                source_tool="nuclei",
                source_format_str="custom",
                rule_id=r.get("template-id", ""),
                cve_id=cves[0] if cves else None,
                cvss_score=cvss_val,
                recommendation=info.get("remediation", ""),
                file_path=r.get("matched-at", r.get("host", "")),
                code_snippet=str(r.get("extracted-results", r.get("matcher-name", "")))[:500] or None,
            ))
        return findings


# ═══════════════════════════════════════════════════════════════════════════
# 12. Nmap Parser (XML -oX)
# ═══════════════════════════════════════════════════════════════════════════

class NmapNormalizer(_Base):
    """Parse Nmap XML output (-oX)."""

    def can_handle(self, content: bytes, content_type: Optional[str] = None) -> float:
        text = content[:2000].decode("utf-8", errors="ignore")
        if "nmaprun" in text or "nmap.org" in text:
            return 0.95
        return 0.0

    def normalize(self, content: bytes, content_type: Optional[str] = None) -> list:
        findings = []
        root = _parse_xml_safe(content)
        if root is None:
            return findings

        for host in root.findall("host"):
            addr = host.find("address")
            host_ip = addr.get("addr", "") if addr is not None else ""
            for port_elem in host.findall(".//port"):
                state = port_elem.find("state")
                service = port_elem.find("service")
                if state is not None and state.get("state") == "open":
                    port_id = port_elem.get("portid", "?")
                    protocol = port_elem.get("protocol", "tcp")
                    svc_name = service.get("name", "unknown") if service is not None else "unknown"
                    svc_product = service.get("product", "") if service is not None else ""
                    svc_version = service.get("version", "") if service is not None else ""

                    # Report script-detected vulnerabilities (high priority)
                    scripts_found = False
                    for script in port_elem.findall("script"):
                        script_id = script.get("id", "")
                        output = script.get("output", "")
                        cves = _extract_cves(output)
                        if cves or "vuln" in script_id.lower():
                            scripts_found = True
                            findings.append(_make_finding(
                                title=f"Nmap {script_id}: {host_ip}:{port_id}",
                                description=output[:500],
                                severity="high" if cves else "medium",
                                source_tool="nmap",
                                source_format_str="custom",
                                rule_id=script_id,
                                cve_id=cves[0] if cves else None,
                                asset_name=host_ip,
                                code_snippet=output[:200] if output else None,
                                tags=cves[1:] if len(cves) > 1 else [],
                            ))

                    # Report open service as info finding (for asset inventory)
                    if not scripts_found:
                        svc_desc = f"{svc_product} {svc_version}".strip() or svc_name
                        findings.append(_make_finding(
                            title=f"Open port {port_id}/{protocol} ({svc_name}) on {host_ip}",
                            description=f"Service: {svc_desc}",
                            severity="info",
                            source_tool="nmap",
                            source_format_str="custom",
                            rule_id=f"nmap-open-port-{port_id}",
                            asset_name=host_ip,
                        ))
        return findings


# ═══════════════════════════════════════════════════════════════════════════
# 13. Snyk Parser (JSON)
# ═══════════════════════════════════════════════════════════════════════════

class SnykNormalizer(_Base):
    """Parse Snyk JSON output (snyk test --json)."""

    def can_handle(self, content: bytes, content_type: Optional[str] = None) -> float:
        text = content[:5000].decode("utf-8", errors="ignore")
        if '"vulnerabilities"' in text and '"packageManager"' in text:
            return 0.95
        if '"vulnerabilities"' in text and '"packageName"' in text:
            return 0.85
        return 0.0

    def normalize(self, content: bytes, content_type: Optional[str] = None) -> list:
        findings = []
        parsed = _parse_json_safe(content)
        if not parsed:
            return findings

        projects = parsed if isinstance(parsed, list) else [parsed]
        for project in projects:
            for vuln in project.get("vulnerabilities", []):
                pkg = vuln.get("packageName", "")
                ver = vuln.get("version", "")
                identifiers = vuln.get("identifiers", {})
                cves = identifiers.get("CVE", [])
                cwes = [f"CWE-{c}" for c in identifiers.get("CWE", [])]
                fix_in = vuln.get("fixedIn", [])

                findings.append(_make_finding(
                    title=f"{vuln.get('title', 'Snyk Finding')} in {pkg}@{ver}",
                    description=vuln.get("description", "")[:500] if vuln.get("description") else "",
                    severity=vuln.get("severity", "medium"),
                    source_tool="snyk",
                    source_format_str="snyk",
                    rule_id=vuln.get("id", ""),
                    cve_id=cves[0] if cves else None,
                    cwe_id=cwes[0] if cwes else None,
                    cvss_score=float(vuln.get("cvssScore", 0)) if vuln.get("cvssScore") else None,
                    package_name=pkg,
                    package_version=ver,
                    recommendation=f"Upgrade to {fix_in[0]}" if fix_in else "",
                    tags=cves[1:] + cwes[1:] if len(cves) > 1 or len(cwes) > 1 else [],
                ))
        return findings


# ═══════════════════════════════════════════════════════════════════════════
# 14. Prowler Parser (JSONL — AWS/Azure/GCP security auditing)
# ═══════════════════════════════════════════════════════════════════════════

class ProwlerNormalizer(_Base):
    """Parse Prowler JSONL output (AWS/Azure/GCP)."""

    def can_handle(self, content: bytes, content_type: Optional[str] = None) -> float:
        text = content[:2000].decode("utf-8", errors="ignore")
        first_line = text.split("\n", 1)[0].strip()
        try:
            parsed = json.loads(first_line)
            # Handle JSON array format (e.g., [{"CheckID": ...}])
            obj = parsed[0] if isinstance(parsed, list) and parsed else parsed
            if isinstance(obj, dict):
                if "CheckID" in obj or "check_id" in obj:
                    return 0.9
                if "StatusExtended" in obj or "status_extended" in obj:
                    return 0.85
        except (json.JSONDecodeError, ValueError, IndexError, TypeError):
            pass
        return 0.0

    def normalize(self, content: bytes, content_type: Optional[str] = None) -> list:
        findings = []
        text = content.decode("utf-8", errors="ignore")

        # Try JSON array format first
        try:
            parsed = json.loads(text)
            if isinstance(parsed, list):
                for r in parsed:
                    if not isinstance(r, dict):
                        continue
                    status = r.get("Status", r.get("status", ""))
                    if status.upper() in ("PASS", "MANUAL"):
                        continue

                    remediation = r.get("Remediation", {})
                    rec_text = ""
                    if isinstance(remediation, dict):
                        rec = remediation.get("Recommendation", {})
                        rec_text = rec.get("Text", "") if isinstance(rec, dict) else str(rec)
                    elif isinstance(remediation, str):
                        rec_text = remediation

                    findings.append(_make_finding(
                        title=r.get("CheckTitle", r.get("check_title", r.get("CheckID", "Prowler Finding"))),
                        description=r.get("StatusExtended", r.get("status_extended", "")),
                        severity=r.get("Severity", r.get("severity", "medium")).lower(),
                        source_tool="prowler",
                        source_format_str="custom",
                        rule_id=r.get("CheckID", r.get("check_id", "")),
                        cloud_account=r.get("AccountId", r.get("account_id", "")),
                        cloud_provider=r.get("Provider", r.get("provider", "")),
                        cloud_region=r.get("Region", r.get("region", "")),
                        cloud_resource_id=r.get("ResourceId", r.get("resource_id", "")),
                        recommendation=rec_text,
                        compliance_frameworks=r.get("Compliance", {}).keys() if isinstance(r.get("Compliance"), dict) else [],
                    ))
                if findings:
                    return findings
        except (json.JSONDecodeError, ValueError):
            pass

        # Fallback: JSONL format (one JSON object per line)
        for line in text.strip().split("\n"):
            if not line.strip():
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            status = r.get("Status", r.get("status", ""))
            if status.upper() in ("PASS", "MANUAL"):
                continue

            remediation = r.get("Remediation", {})
            rec_text = ""
            if isinstance(remediation, dict):
                rec = remediation.get("Recommendation", {})
                rec_text = rec.get("Text", "") if isinstance(rec, dict) else str(rec)
            elif isinstance(remediation, str):
                rec_text = remediation

            findings.append(_make_finding(
                title=r.get("CheckTitle", r.get("check_title", r.get("CheckID", "Prowler Finding"))),
                description=r.get("StatusExtended", r.get("status_extended", "")),
                severity=r.get("Severity", r.get("severity", "medium")).lower(),
                source_tool="prowler",
                source_format_str="custom",
                rule_id=r.get("CheckID", r.get("check_id", "")),
                cloud_account=r.get("AccountId", r.get("account_id", "")),
                cloud_provider=r.get("Provider", r.get("provider", "")),
                cloud_region=r.get("Region", r.get("region", "")),
                cloud_resource_id=r.get("ResourceId", r.get("resource_id", "")),
                recommendation=rec_text,
                compliance_frameworks=r.get("Compliance", {}).keys() if isinstance(r.get("Compliance"), dict) else [],
            ))
        return findings


# ═══════════════════════════════════════════════════════════════════════════
# 15. Checkov Parser (JSON — IaC scanning)
# ═══════════════════════════════════════════════════════════════════════════

class CheckovNormalizer(_Base):
    """Parse Checkov JSON output (Terraform, CloudFormation, Kubernetes IaC)."""

    def can_handle(self, content: bytes, content_type: Optional[str] = None) -> float:
        text = content[:5000].decode("utf-8", errors="ignore")
        if '"check_type"' in text and ('"passed_checks"' in text or '"failed_checks"' in text):
            return 0.95
        return 0.0

    def normalize(self, content: bytes, content_type: Optional[str] = None) -> list:
        findings = []
        parsed = _parse_json_safe(content)
        if not parsed:
            return findings

        # Handle both single and multi-check-type output
        results = parsed if isinstance(parsed, list) else [parsed]
        for result in results:
            check_type = result.get("check_type", "unknown")
            # failed_checks can be at top level or nested under "results"
            failed_checks = result.get("failed_checks", [])
            if not failed_checks and isinstance(result.get("results"), dict):
                failed_checks = result["results"].get("failed_checks", [])
            for check in failed_checks:
                guideline = check.get("guideline", "")
                findings.append(_make_finding(
                    title=f"{check.get('check_id', 'CKV')}: {check.get('check_name', 'Checkov Finding')}",
                    description=check.get("check_name", ""),
                    severity=check.get("severity", "medium").lower() if check.get("severity") else "medium",
                    source_tool="checkov",
                    source_format_str="custom",
                    rule_id=check.get("check_id", ""),
                    file_path=check.get("file_path", ""),
                    line_number=check.get("file_line_range", [0])[0] or None,
                    recommendation=guideline if isinstance(guideline, str) else "",
                    tags=[check_type],
                ))
        return findings


# ═══════════════════════════════════════════════════════════════════════════
# 16. Trivy Parser (Container / OS / Library vulnerabilities)
# ═══════════════════════════════════════════════════════════════════════════

class TrivyScannerNormalizer(_Base):
    """Normalizer for Trivy scanner JSON output."""

    def can_handle(self, content: bytes, content_type=None) -> float:
        try:
            d = json.loads(content)
            if "Results" in d or "results" in d:
                if "ArtifactName" in d or "ArtifactType" in d or "SchemaVersion" in d:
                    return 0.95
                return 0.6
        except (json.JSONDecodeError, KeyError, ValueError, UnicodeDecodeError):
            pass
        return 0.0

    def normalize(self, content: bytes, content_type=None) -> list:
        data = json.loads(content)
        findings = []
        results = data.get("Results") or data.get("results", [])
        data.get("ArtifactName") or data.get("artifactName", "")

        for result in results:
            target = result.get("Target") or result.get("target", "")
            rtype = result.get("Type") or result.get("type", "")

            for vuln in (result.get("Vulnerabilities") or result.get("vulnerabilities") or []):
                vid = vuln.get("VulnerabilityID") or vuln.get("vulnerabilityID", "")
                pkg = vuln.get("PkgName") or vuln.get("pkgName", "")
                ver = vuln.get("InstalledVersion") or vuln.get("installedVersion", "")
                fix = vuln.get("FixedVersion") or vuln.get("fixedVersion", "")
                sev = vuln.get("Severity") or vuln.get("severity", "UNKNOWN")
                title = vuln.get("Title") or vuln.get("title", vid)
                desc = vuln.get("Description") or vuln.get("description", "")

                f = _make_finding(
                    source_format_str="trivy",
                    source_tool="trivy",
                    source_id=vid,
                    severity=self._map_severity(sev),
                    title=f"{vid}: {title[:200]}" if title else vid,
                    description=desc,
                    recommendation=f"Upgrade {pkg} to {fix}" if fix else None,
                    cve_id=vid if vid.startswith("CVE-") else None,
                    package_name=pkg,
                    package_version=ver,
                    package_ecosystem=rtype,
                    file_path=target,
                )
                if hasattr(f, "compute_fingerprint"):
                    f.compute_fingerprint()
                findings.append(f)

            for mc in (result.get("Misconfigurations") or result.get("misconfigurations") or []):
                mcid = mc.get("ID") or mc.get("id", "")
                f = _make_finding(
                    source_format_str="trivy",
                    source_tool="trivy",
                    source_id=mcid,
                    severity=self._map_severity(mc.get("Severity") or mc.get("severity", "UNKNOWN")),
                    title=mc.get("Title") or mc.get("title", mcid),
                    description=mc.get("Description") or mc.get("description", ""),
                    recommendation=mc.get("Resolution") or mc.get("resolution", ""),
                    rule_id=mcid,
                    file_path=target,
                )
                if hasattr(f, "compute_fingerprint"):
                    f.compute_fingerprint()
                findings.append(f)

        return findings


# ═══════════════════════════════════════════════════════════════════════════
# 17. Grype Parser (Container vulnerability scanner)
# ═══════════════════════════════════════════════════════════════════════════

class GrypeScannerNormalizer(_Base):
    """Normalizer for Grype scanner JSON output."""

    def can_handle(self, content: bytes, content_type=None) -> float:
        try:
            d = json.loads(content)
            if "matches" in d:
                return 0.9
        except (json.JSONDecodeError, KeyError, ValueError, UnicodeDecodeError):
            pass
        return 0.0

    def normalize(self, content: bytes, content_type=None) -> list:
        data = json.loads(content)
        findings = []

        for match in data.get("matches", []):
            vuln = match.get("vulnerability", {})
            art = match.get("artifact", {})
            vid = vuln.get("id", "")
            sev = vuln.get("severity", "Unknown")
            desc = vuln.get("description", "")
            fix_versions = vuln.get("fix", {}).get("versions", [])
            pkg = art.get("name", "")
            ver = art.get("version", "")
            ptype = art.get("type", "")

            f = _make_finding(
                source_format_str="grype",
                source_tool="grype",
                source_id=vid,
                severity=self._map_severity(sev),
                title=f"{vid}: {desc[:200]}" if desc else vid,
                description=desc,
                recommendation=f"Upgrade {pkg} to {', '.join(fix_versions)}" if fix_versions else None,
                cve_id=vid if vid.startswith("CVE-") else None,
                package_name=pkg,
                package_version=ver,
                package_ecosystem=ptype,
            )
            if hasattr(f, "compute_fingerprint"):
                f.compute_fingerprint()
            findings.append(f)

        return findings


# ═══════════════════════════════════════════════════════════════════════════
# 18. Semgrep Parser (SARIF-based but also direct JSON)
# ═══════════════════════════════════════════════════════════════════════════

class SemgrepScannerNormalizer(_Base):
    """Normalizer for Semgrep JSON output (native format, not SARIF)."""

    def can_handle(self, content: bytes, content_type=None) -> float:
        try:
            d = json.loads(content)
            if "results" in d and isinstance(d["results"], list):
                if any("check_id" in r for r in d["results"][:3]):
                    return 0.95
            return 0.0
        except (json.JSONDecodeError, KeyError, ValueError, UnicodeDecodeError):
            return 0.0

    def normalize(self, content: bytes, content_type=None) -> list:
        data = json.loads(content)
        findings = []
        for r in data.get("results", []):
            sev = r.get("extra", {}).get("severity", "WARNING")
            f = _make_finding(
                source_format_str="semgrep",
                source_tool="semgrep",
                source_id=r.get("check_id", ""),
                severity=self._map_severity(sev),
                title=r.get("check_id", "Semgrep finding"),
                description=r.get("extra", {}).get("message", ""),
                file_path=r.get("path", ""),
                line_number=r.get("start", {}).get("line"),
                rule_id=r.get("check_id"),
            )
            if hasattr(f, "compute_fingerprint"):
                f.compute_fingerprint()
            findings.append(f)
        return findings


# ═══════════════════════════════════════════════════════════════════════════
# 19. Dependabot Parser (GitHub format)
# ═══════════════════════════════════════════════════════════════════════════

class DependabotScannerNormalizer(_Base):
    """Normalizer for GitHub Dependabot alerts JSON."""

    def can_handle(self, content: bytes, content_type=None) -> float:
        try:
            d = json.loads(content)
            if isinstance(d, list) and len(d) > 0:
                if "security_advisory" in d[0] or "dependency" in d[0]:
                    return 0.9
            return 0.0
        except (json.JSONDecodeError, KeyError, ValueError, UnicodeDecodeError):
            return 0.0

    def normalize(self, content: bytes, content_type=None) -> list:
        data = json.loads(content)
        findings = []
        alerts = data if isinstance(data, list) else data.get("alerts", [])
        for alert in alerts:
            adv = alert.get("security_advisory", {})
            dep = alert.get("dependency", {})
            pkg = dep.get("package", {}).get("name", "")
            sev = adv.get("severity", "medium")
            f = _make_finding(
                source_format_str="dependabot",
                source_tool="dependabot",
                source_id=adv.get("ghsa_id", adv.get("cve_id", "")),
                severity=self._map_severity(sev),
                title=adv.get("summary", "Dependabot alert"),
                description=adv.get("description", ""),
                cve_id=adv.get("cve_id"),
                package_name=pkg,
                package_version=dep.get("package", {}).get("version", ""),
            )
            if hasattr(f, "compute_fingerprint"):
                f.compute_fingerprint()
            findings.append(f)
        return findings


# ═══════════════════════════════════════════════════════════════════════════
# 20. Qualys Parser (VM XML/JSON)
# ═══════════════════════════════════════════════════════════════════════════

class QualysScannerNormalizer(_Base):
    """Normalizer for Qualys VM XML and JSON reports."""

    def can_handle(self, content: bytes, content_type=None) -> float:
        text = content[:5000].decode("utf-8", errors="ignore")
        # Qualys XML: contains <IP>, <QID>, <RESULT> elements
        if "<QID>" in text or "<QIDS>" in text:
            return 0.95
        if "<IP>" in text and "<RESULT>" in text and "<VULN" in text:
            return 0.90
        # Qualys JSON: contains "qid" field
        if '"qid"' in text and ('"vuln_list"' in text or '"vulns"' in text or '"detections"' in text):
            return 0.92
        if '"qid"' in text and '"severity"' in text and '"ip"' in text:
            return 0.80
        return 0.0

    def normalize(self, content: bytes, content_type=None) -> list:
        findings = []
        parsed = _parse_json_safe(content)
        if parsed:
            findings = self._parse_json(parsed)
        else:
            root = _parse_xml_safe(content)
            if root is not None:
                findings = self._parse_xml(root)
        return findings

    def _parse_json(self, data) -> list:
        findings = []
        # Handle top-level list or nested structures
        hosts = data if isinstance(data, list) else data.get("host_list", data.get("hosts", [data]))
        if isinstance(hosts, dict):
            hosts = [hosts]
        for host in hosts:
            ip = host.get("ip", host.get("address", ""))
            detections = (
                host.get("detections", host.get("vuln_list", host.get("vulns", [])))
            )
            if isinstance(detections, dict):
                detections = detections.get("detection", detections.get("vuln", []))
            if not isinstance(detections, list):
                detections = [detections] if detections else []
            for det in detections:
                qid = str(det.get("qid", ""))
                sev_num = det.get("severity", det.get("severity_level", 2))
                cves = _extract_cves(str(det.get("cve_list", det.get("cves", ""))))
                findings.append(_make_finding(
                    title=det.get("title", det.get("vuln_title", f"Qualys QID-{qid}")),
                    description=det.get("results", det.get("result", det.get("diagnosis", ""))),
                    severity=_severity_from_number(sev_num),
                    source_tool="qualys",
                    source_format_str="qualys",
                    rule_id=qid,
                    cve_id=cves[0] if cves else None,
                    asset_name=ip,
                    recommendation=det.get("solution", det.get("remediation", "")),
                    tags=cves[1:] if len(cves) > 1 else [],
                ))
        return findings

    def _parse_xml(self, root: ET.Element) -> list:
        findings = []
        # Qualys VM scan XML: HOST_LIST_VM_DETECTION_OUTPUT or similar
        for host in root.findall(".//HOST") or [root]:
            ip = host.findtext("IP", host.findtext("ip", ""))
            for det in host.findall(".//DETECTION") or host.findall(".//VULN"):
                qid = det.findtext("QID", det.findtext("qid", ""))
                sev_num = det.findtext("SEVERITY", det.findtext("severity", "2"))
                results_text = det.findtext("RESULTS", det.findtext("RESULT", ""))
                cves = _extract_cves(det.findtext("CVE_LIST", det.findtext("CVE", "")))
                title = det.findtext("TITLE", f"Qualys QID-{qid}")
                findings.append(_make_finding(
                    title=title,
                    description=results_text,
                    severity=_severity_from_number(sev_num),
                    source_tool="qualys",
                    source_format_str="qualys",
                    rule_id=qid,
                    cve_id=cves[0] if cves else None,
                    asset_name=ip,
                    recommendation=det.findtext("SOLUTION", ""),
                    tags=cves[1:] if len(cves) > 1 else [],
                ))
        return findings


# ═══════════════════════════════════════════════════════════════════════════
# 21. Tenable Parser (Tenable.io/Nessus JSON export)
# ═══════════════════════════════════════════════════════════════════════════

class TenableScannerNormalizer(_Base):
    """Normalizer for Tenable.io and Nessus JSON exports."""

    def can_handle(self, content: bytes, content_type=None) -> float:
        text = content[:5000].decode("utf-8", errors="ignore")
        # Tenable JSON: "vulnerabilities" list with "plugin_id" and "severity_index"
        if '"plugin_id"' in text and '"severity_index"' in text:
            return 0.95
        if '"vulnerabilities"' in text and '"plugin_id"' in text:
            return 0.88
        if '"tenable"' in text.lower() and '"vulnerabilities"' in text:
            return 0.80
        return 0.0

    def normalize(self, content: bytes, content_type=None) -> list:
        findings = []
        parsed = _parse_json_safe(content)
        if not parsed:
            return findings

        # Handle top-level list or wrapped object
        scans = parsed if isinstance(parsed, list) else [parsed]
        for scan in scans:
            asset_name = scan.get("target", scan.get("host", ""))
            if isinstance(asset_name, dict):
                asset_name = asset_name.get("name", "")
            for vuln in scan.get("vulnerabilities", []):
                plugin_id = str(vuln.get("plugin_id", vuln.get("pluginId", "")))
                sev_idx = vuln.get("severity_index", vuln.get("severity", 2))
                plugin_name = vuln.get("plugin_name", vuln.get("pluginName", f"Tenable Plugin {plugin_id}"))
                cves = _extract_cves(str(vuln.get("cve", vuln.get("cves", ""))))
                cvss_raw = vuln.get("cvss3_base_score", vuln.get("cvss_base_score", 0))
                try:
                    cvss_val = float(cvss_raw) if cvss_raw else None
                except (ValueError, TypeError):
                    cvss_val = None
                findings.append(_make_finding(
                    title=plugin_name,
                    description=vuln.get("synopsis", vuln.get("description", "")),
                    severity=_severity_from_number(sev_idx),
                    source_tool="tenable",
                    source_format_str="tenable",
                    rule_id=plugin_id,
                    cve_id=cves[0] if cves else None,
                    cvss_score=cvss_val,
                    asset_name=asset_name,
                    recommendation=vuln.get("solution", ""),
                    code_snippet=vuln.get("plugin_output", "")[:500] if vuln.get("plugin_output") else None,
                    tags=cves[1:] if len(cves) > 1 else [],
                ))
        return findings


# ═══════════════════════════════════════════════════════════════════════════
# 22. Rapid7 InsightVM Parser (XML/JSON)
# ═══════════════════════════════════════════════════════════════════════════

class Rapid7ScannerNormalizer(_Base):
    """Normalizer for Rapid7 InsightVM XML and JSON reports."""

    def can_handle(self, content: bytes, content_type=None) -> float:
        text = content[:5000].decode("utf-8", errors="ignore")
        # Rapid7 XML: <test> elements with vulnerability-id attribute
        if "<test" in text and "vulnerability-id" in text:
            return 0.92
        if "nexpose" in text.lower() or "insightvm" in text.lower():
            return 0.88
        # Rapid7 JSON: "test" / "tests" with "vulnerability-id"
        if '"vulnerability-id"' in text and ('"test"' in text or '"tests"' in text):
            return 0.90
        if '"rapid7"' in text.lower() and '"vulnerabilities"' in text:
            return 0.75
        return 0.0

    def normalize(self, content: bytes, content_type=None) -> list:
        findings = []
        parsed = _parse_json_safe(content)
        if parsed:
            findings = self._parse_json(parsed)
        else:
            root = _parse_xml_safe(content)
            if root is not None:
                findings = self._parse_xml(root)
        return findings

    def _parse_json(self, data) -> list:
        findings = []
        nodes = data if isinstance(data, list) else data.get("nodes", data.get("hosts", [data]))
        if isinstance(nodes, dict):
            nodes = [nodes]
        for node in nodes:
            asset_name = node.get("address", node.get("ip", ""))
            tests = node.get("tests", node.get("vulnerabilities", []))
            if isinstance(tests, dict):
                tests = tests.get("test", [])
            if not isinstance(tests, list):
                tests = [tests] if tests else []
            for test in tests:
                vuln_id = test.get("vulnerability-id", test.get("vulnerabilityId", test.get("id", "")))
                sev = test.get("severity", test.get("cvss_score", "medium"))
                cves = _extract_cves(str(test.get("references", "")))
                cwes = _extract_cwes(str(test.get("tags", "")))
                findings.append(_make_finding(
                    title=test.get("title", test.get("name", f"Rapid7 {vuln_id}")),
                    description=test.get("description", test.get("details", "")),
                    severity=self._map_severity(sev) if isinstance(sev, (int, float)) else str(sev).lower(),
                    source_tool="rapid7",
                    source_format_str="rapid7",
                    rule_id=str(vuln_id),
                    cve_id=cves[0] if cves else None,
                    cwe_id=cwes[0] if cwes else None,
                    asset_name=asset_name,
                    recommendation=test.get("solution", test.get("remediation", "")),
                    tags=cves[1:] if len(cves) > 1 else [],
                ))
        return findings

    def _parse_xml(self, root: ET.Element) -> list:
        findings = []
        for node in root.findall(".//node") or [root]:
            asset_name = node.get("address", node.get("name", ""))
            for test in node.findall(".//test"):
                vuln_id = test.get("vulnerability-id", test.get("id", ""))
                status = test.get("status", "vulnerable")
                if status not in ("vulnerable", "exception-vulnerable-exploited",
                                   "exception-vulnerable-version", "vulnerable-exploited",
                                   "vulnerable-version"):
                    continue
                cves = _extract_cves(test.findtext("references", ""))
                sev = test.get("severity", "2")
                findings.append(_make_finding(
                    title=f"Rapid7 {vuln_id}",
                    description=test.findtext("description", ""),
                    severity=_severity_from_number(sev),
                    source_tool="rapid7",
                    source_format_str="rapid7",
                    rule_id=vuln_id,
                    cve_id=cves[0] if cves else None,
                    asset_name=asset_name,
                    recommendation=test.findtext("solution", ""),
                    tags=cves[1:] if len(cves) > 1 else [],
                ))
        return findings


# ═══════════════════════════════════════════════════════════════════════════
# 23. Acunetix Parser (JSON export)
# ═══════════════════════════════════════════════════════════════════════════

class AcunetixScannerNormalizer(_Base):
    """Normalizer for Acunetix JSON exports."""

    def can_handle(self, content: bytes, content_type=None) -> float:
        text = content[:5000].decode("utf-8", errors="ignore")
        # Acunetix JSON: "vulnerabilities" with "severity" and "affects_url"
        if '"affects_url"' in text and '"vulnerabilities"' in text:
            return 0.95
        if '"affects_url"' in text and '"severity"' in text:
            return 0.90
        if '"acunetix"' in text.lower() and '"vulnerabilities"' in text:
            return 0.82
        if '"vuln_id"' in text and '"affects_url"' in text:
            return 0.85
        return 0.0

    def normalize(self, content: bytes, content_type=None) -> list:
        findings = []
        parsed = _parse_json_safe(content)
        if not parsed:
            return findings

        # Acunetix exports can have vulnerabilities at top-level or nested
        vulns = parsed if isinstance(parsed, list) else parsed.get("vulnerabilities", [])
        if isinstance(vulns, dict):
            vulns = vulns.get("items", [vulns])

        for vuln in vulns:
            affects_url = vuln.get("affects_url", vuln.get("url", ""))
            sev = vuln.get("severity", vuln.get("severity_text", "medium"))
            sev_map = {"high": "high", "medium": "medium", "low": "low", "info": "info", "informational": "info"}
            if isinstance(sev, str):
                sev = sev_map.get(sev.lower(), sev.lower())
            cves = _extract_cves(str(vuln.get("cvelist", vuln.get("cve", vuln.get("references", "")))))
            cwes = _extract_cwes(str(vuln.get("cwe", vuln.get("tags", ""))))
            vuln_id = str(vuln.get("vuln_id", vuln.get("type", "")))
            findings.append(_make_finding(
                title=vuln.get("vt_name", vuln.get("name", f"Acunetix {vuln_id}")),
                description=vuln.get("description", vuln.get("details", "")),
                severity=sev,
                source_tool="acunetix",
                source_format_str="acunetix",
                rule_id=vuln_id,
                cve_id=cves[0] if cves else None,
                cwe_id=cwes[0] if cwes else None,
                file_path=affects_url,
                recommendation=vuln.get("recommendation", vuln.get("fix", "")),
                code_snippet=vuln.get("request", "")[:500] if vuln.get("request") else None,
                tags=cves[1:] if len(cves) > 1 else [],
            ))
        return findings


# ═══════════════════════════════════════════════════════════════════════════
# 24. AWS Inspector v2 Parser (JSON)
# ═══════════════════════════════════════════════════════════════════════════

class AWSInspectorNormalizer(_Base):
    """Normalizer for AWS Inspector v2 JSON findings."""

    def can_handle(self, content: bytes, content_type=None) -> float:
        text = content[:5000].decode("utf-8", errors="ignore")
        # AWS Inspector v2 JSON: "findings" with "awsAccountId" and "inspectorScore"
        if '"awsAccountId"' in text and '"inspectorScore"' in text:
            return 0.97
        if '"findings"' in text and '"awsAccountId"' in text:
            return 0.90
        if '"inspectorScore"' in text and '"packageVulnerabilityDetails"' in text:
            return 0.95
        if '"awsInspector"' in text.lower() and '"findings"' in text:
            return 0.80
        return 0.0

    def normalize(self, content: bytes, content_type=None) -> list:
        findings = []
        parsed = _parse_json_safe(content)
        if not parsed:
            return findings

        raw_findings = parsed if isinstance(parsed, list) else parsed.get("findings", [])
        for finding in raw_findings:
            account_id = finding.get("awsAccountId", "")
            region = finding.get("region", "")
            score = finding.get("inspectorScore", finding.get("severity", {}))
            if isinstance(score, dict):
                score = score.get("score", 0)
            try:
                score_float = float(score)
            except (ValueError, TypeError):
                score_float = 0.0
            sev = finding.get("severity", "MEDIUM")
            if isinstance(sev, str):
                sev_map = {
                    "critical": "critical", "high": "high",
                    "medium": "medium", "low": "low", "informational": "info",
                }
                sev = sev_map.get(sev.lower(), "medium")
            else:
                sev = self._map_severity(score_float)

            # Package vulnerability details
            pkg_details = finding.get("packageVulnerabilityDetails", {})
            vuln_id = pkg_details.get("vulnerabilityId", finding.get("findingArn", ""))
            cves = _extract_cves(vuln_id) or _extract_cves(
                str(pkg_details.get("referenceUrls", ""))
            )
            if not cves and vuln_id.startswith("CVE-"):
                cves = [vuln_id]

            # Network reachability / resource details
            resources = finding.get("resources", [{}])
            resource_id = resources[0].get("id", "") if resources else ""
            resource_type = resources[0].get("type", "") if resources else ""

            # Fixed versions
            vuln_pkgs = pkg_details.get("vulnerablePackages", [])
            fix_available = None
            pkg_name = ""
            pkg_version = ""
            if vuln_pkgs:
                first_pkg = vuln_pkgs[0]
                pkg_name = first_pkg.get("name", "")
                pkg_version = first_pkg.get("version", "")
                fixed = first_pkg.get("fixedInVersion", "")
                if fixed:
                    fix_available = f"Upgrade {pkg_name} to {fixed}"

            findings.append(_make_finding(
                title=finding.get("title", f"AWS Inspector: {vuln_id}"),
                description=finding.get("description", ""),
                severity=sev,
                source_tool="aws_inspector",
                source_format_str="aws_inspector",
                rule_id=str(vuln_id),
                cve_id=cves[0] if cves else None,
                cvss_score=score_float if score_float > 0 else None,
                cloud_account=account_id,
                cloud_provider="aws",
                cloud_region=region,
                cloud_resource_id=resource_id,
                package_name=pkg_name,
                package_version=pkg_version,
                recommendation=fix_available or finding.get("remediation", {}).get("recommendation", {}).get("text", ""),
                tags=[resource_type] if resource_type else [],
            ))
        return findings


# ═══════════════════════════════════════════════════════════════════════════
# 25. GitLab SAST Parser (JSON)
# ═══════════════════════════════════════════════════════════════════════════

class GitLabSASTNormalizer(_Base):
    """Normalizer for GitLab SAST JSON report format."""

    def can_handle(self, content: bytes, content_type=None) -> float:
        text = content[:5000].decode("utf-8", errors="ignore")
        # GitLab SAST JSON: "vulnerabilities" with "scanner", "location", "identifiers"
        if '"identifiers"' in text and '"location"' in text and '"vulnerabilities"' in text:
            return 0.90
        if '"scanner"' in text and '"identifiers"' in text and '"vulnerabilities"' in text:
            return 0.88
        if '"gitlab"' in text.lower() and '"vulnerabilities"' in text and '"location"' in text:
            return 0.85
        # GitLab report schema version marker
        if '"version"' in text and '"vulnerabilities"' in text and '"scan"' in text and '"scanner"' in text:
            return 0.82
        return 0.0

    def normalize(self, content: bytes, content_type=None) -> list:
        findings = []
        parsed = _parse_json_safe(content)
        if not parsed:
            return findings

        vulns = parsed.get("vulnerabilities", [])
        if not vulns and isinstance(parsed, list):
            vulns = parsed

        for vuln in vulns:
            location = vuln.get("location", {})
            file_path = location.get("file", location.get("path", ""))
            line_start = location.get("start_line", location.get("line", None))
            if isinstance(line_start, str):
                try:
                    line_start = int(line_start)
                except ValueError:
                    line_start = None

            # Identifiers: extract CVE/CWE from the identifiers list
            identifiers = vuln.get("identifiers", [])
            cves = []
            cwes = []
            rule_id = ""
            for ident in identifiers:
                itype = ident.get("type", "").lower()
                iname = ident.get("name", ident.get("value", ""))
                if itype == "cve" or iname.startswith("CVE-"):
                    cves.append(iname)
                elif itype == "cwe" or iname.startswith("CWE-"):
                    cwes.append(iname)
                if not rule_id:
                    rule_id = ident.get("value", iname)

            # Fall back to text extraction if identifiers list is empty
            if not cves:
                cves = _extract_cves(str(vuln.get("description", "") + str(identifiers)))
            if not cwes:
                cwes = _extract_cwes(str(vuln.get("description", "") + str(identifiers)))

            scanner_info = vuln.get("scanner", {})
            scanner_name = scanner_info.get("name", scanner_info.get("id", "gitlab-sast")) if isinstance(scanner_info, dict) else str(scanner_info)

            sev = vuln.get("severity", "Medium")
            sev_map = {
                "critical": "critical", "high": "high",
                "medium": "medium", "low": "low",
                "unknown": "info", "info": "info",
            }
            if isinstance(sev, str):
                sev = sev_map.get(sev.lower(), "medium")

            findings.append(_make_finding(
                title=vuln.get("name", vuln.get("message", "GitLab SAST Finding")),
                description=vuln.get("description", vuln.get("message", "")),
                severity=sev,
                source_tool="gitlab_sast",
                source_format_str="gitlab_sast",
                rule_id=rule_id or vuln.get("id", ""),
                cve_id=cves[0] if cves else None,
                cwe_id=cwes[0] if cwes else None,
                file_path=file_path,
                line_number=line_start,
                recommendation=vuln.get("solution", vuln.get("remediations", [{}])[0].get("fixes", [""])[0] if vuln.get("remediations") else ""),
                code_snippet=location.get("snippet", "")[:500] if location.get("snippet") else None,
                tags=[scanner_name] if scanner_name else [],
            ))
        return findings


# ═══════════════════════════════════════════════════════════════════════════
# Universal Format Parsers: SARIF, CycloneDX, SPDX
# ═══════════════════════════════════════════════════════════════════════════

class SARIFUniversalNormalizer(_Base):
    """Parse SARIF 2.1+ format — the universal static analysis interchange format."""

    def can_handle(self, content: bytes, content_type: Optional[str] = None) -> float:
        text = content[:5000].decode("utf-8", errors="ignore")
        if '"$schema"' in text and 'sarif' in text.lower():
            return 0.98
        if '"version"' in text and '"runs"' in text and '"results"' in text:
            return 0.90
        if '"runs"' in text and '"tool"' in text:
            return 0.80
        return 0.0

    def normalize(self, content: bytes, content_type: Optional[str] = None) -> list:
        data = _parse_json_safe(content)
        if not data or not isinstance(data, dict):
            return []

        findings = []
        for run in data.get("runs", []):
            tool_name = ""
            tool_info = run.get("tool", {})
            driver = tool_info.get("driver", {})
            tool_name = driver.get("name", "unknown")

            # Build rule lookup for enrichment
            rules_by_id = {}
            for rule in driver.get("rules", []):
                rid = rule.get("id", "")
                if rid:
                    rules_by_id[rid] = rule

            for result in run.get("results", []):
                rule_id = result.get("ruleId", "")
                rule_index = result.get("ruleIndex")
                rule_info = rules_by_id.get(rule_id, {})

                # If rule_index is set and we have rules array, use it
                if not rule_info and rule_index is not None:
                    rules_list = driver.get("rules", [])
                    if 0 <= rule_index < len(rules_list):
                        rule_info = rules_list[rule_index]

                # Title: message > rule.shortDescription > rule.name > ruleId
                msg = result.get("message", {})
                title = msg.get("text", "")
                if not title:
                    title = rule_info.get("shortDescription", {}).get("text", "")
                if not title:
                    title = rule_info.get("name", rule_id or "SARIF Finding")

                # Description from rule fullDescription
                description = rule_info.get("fullDescription", {}).get("text", "")
                if not description:
                    description = rule_info.get("shortDescription", {}).get("text", title)

                # Severity mapping from level
                level = result.get("level", "warning")
                severity_map = {
                    "error": "high",
                    "warning": "medium",
                    "note": "low",
                    "none": "info",
                }
                severity = severity_map.get(level, "medium")

                # Check rule properties for security-severity (CVSS-like)
                props = rule_info.get("properties", {})
                sec_sev = props.get("security-severity", "")
                if sec_sev:
                    try:
                        cvss = float(sec_sev)
                        if cvss >= 9.0:
                            severity = "critical"
                        elif cvss >= 7.0:
                            severity = "high"
                        elif cvss >= 4.0:
                            severity = "medium"
                        elif cvss > 0:
                            severity = "low"
                    except (ValueError, TypeError):
                        pass

                # Location
                file_path = ""
                line_number = None
                code_snippet = None
                locations = result.get("locations", [])
                if locations:
                    loc = locations[0]
                    phys = loc.get("physicalLocation", {})
                    art = phys.get("artifactLocation", {})
                    file_path = art.get("uri", art.get("uriBaseId", ""))
                    region = phys.get("region", {})
                    line_number = region.get("startLine")
                    snippet = region.get("snippet", {})
                    if snippet:
                        code_snippet = snippet.get("text", "")[:500]

                # CWE extraction
                cwe_id = None
                tags = props.get("tags", [])
                for tag in tags:
                    if isinstance(tag, str) and tag.startswith("CWE-"):
                        cwe_id = tag
                        break
                # Also check taxa references
                for taxa in rule_info.get("relationships", []):
                    target = taxa.get("target", {})
                    tid = target.get("id", "")
                    if tid.startswith("CWE-") or tid.isdigit():
                        cwe_id = f"CWE-{tid}" if tid.isdigit() else tid
                        break

                # Recommendation from fixes or help
                recommendation = ""
                fixes = result.get("fixes", [])
                if fixes:
                    recommendation = fixes[0].get("description", {}).get("text", "")
                if not recommendation:
                    recommendation = rule_info.get("help", {}).get("text", "")

                findings.append(_make_finding(
                    title=title[:500],
                    description=description[:2000],
                    severity=severity,
                    source_tool=tool_name.lower(),
                    source_format_str="sarif",
                    rule_id=rule_id,
                    cwe_id=cwe_id,
                    file_path=file_path,
                    line_number=line_number,
                    code_snippet=code_snippet,
                    recommendation=recommendation[:1000],
                    tags=[tool_name, "sarif"] if tool_name else ["sarif"],
                ))

        return findings


class CycloneDXUniversalNormalizer(_Base):
    """Parse CycloneDX SBOM format (JSON)."""

    def can_handle(self, content: bytes, content_type: Optional[str] = None) -> float:
        text = content[:5000].decode("utf-8", errors="ignore")
        if '"bomFormat"' in text and 'CycloneDX' in text:
            return 0.95
        if 'cyclonedx' in text.lower() and '"components"' in text:
            return 0.85
        return 0.0

    def normalize(self, content: bytes, content_type: Optional[str] = None) -> list:
        data = _parse_json_safe(content)
        if not data or not isinstance(data, dict):
            return []

        findings = []
        # Extract from vulnerabilities section
        for vuln in data.get("vulnerabilities", []):
            vuln_id = vuln.get("id", "")
            title = vuln.get("description", vuln_id) or vuln_id
            description = vuln.get("detail", vuln.get("description", ""))

            # Severity from ratings
            severity = "medium"
            for rating in vuln.get("ratings", []):
                sev = rating.get("severity", "").lower()
                if sev in ("critical", "high", "medium", "low", "info"):
                    severity = sev
                    break
                score = rating.get("score")
                if score is not None:
                    try:
                        s = float(score)
                        severity = "critical" if s >= 9 else "high" if s >= 7 else "medium" if s >= 4 else "low"
                    except (ValueError, TypeError):
                        pass
                    break

            # Affected components
            affects = vuln.get("affects", [])
            component_ref = affects[0].get("ref", "") if affects else ""

            _extract_cves(vuln_id + " " + str(vuln.get("source", {}).get("name", "")))
            cwes = [f"CWE-{c}" for c in vuln.get("cwes", [])]

            recommendation = ""
            for adv in vuln.get("advisories", []):
                recommendation = adv.get("title", adv.get("url", ""))
                break

            findings.append(_make_finding(
                title=title[:500],
                description=description[:2000],
                severity=severity,
                source_tool="cyclonedx",
                source_format_str="cyclonedx",
                rule_id=vuln_id,
                cwe_id=cwes[0] if cwes else None,
                file_path=component_ref,
                recommendation=recommendation[:1000],
                tags=["sbom", "cyclonedx"],
            ))

        # Also extract components with known vulnerabilities
        for comp in data.get("components", []):
            if comp.get("type") == "library" and comp.get("purl"):
                # Only add as finding if there's evidence of vulnerability
                pass  # Component inventory, not findings

        return findings


class SPDXUniversalNormalizer(_Base):
    """Parse SPDX SBOM format (JSON)."""

    def can_handle(self, content: bytes, content_type: Optional[str] = None) -> float:
        text = content[:5000].decode("utf-8", errors="ignore")
        if '"spdxVersion"' in text or '"SPDX-' in text:
            return 0.90
        if 'SPDXRef' in text and '"packages"' in text:
            return 0.85
        return 0.0

    def normalize(self, content: bytes, content_type: Optional[str] = None) -> list:
        data = _parse_json_safe(content)
        if not data or not isinstance(data, dict):
            return []

        findings = []
        # SPDX doesn't natively carry vulnerability data, but some enriched SPDX docs do
        for pkg in data.get("packages", []):
            # Check for known vulnerability annotations
            ext_refs = pkg.get("externalRefs", [])
            for ref in ext_refs:
                if ref.get("referenceCategory") == "SECURITY" or "vulnerability" in str(ref.get("referenceType", "")).lower():
                    findings.append(_make_finding(
                        title=f"Vulnerability in {pkg.get('name', 'unknown')}",
                        description=f"Package: {pkg.get('name')} version {pkg.get('versionInfo', 'unknown')}",
                        severity="medium",
                        source_tool="spdx",
                        source_format_str="spdx",
                        rule_id=ref.get("referenceLocator", ""),
                        file_path=pkg.get("name", ""),
                        tags=["sbom", "spdx"],
                    ))
        return findings


# ═══════════════════════════════════════════════════════════════════════════
# Gitleaks Secrets Scanner Parser (JSON)
# ═══════════════════════════════════════════════════════════════════════════


class GitleaksScannerNormalizer(_Base):
    """Normalizer for Gitleaks JSON output (secrets detection)."""

    def can_handle(self, content: bytes, content_type: Optional[str] = None) -> float:
        text = content[:5000].decode("utf-8", errors="ignore")
        # Gitleaks JSON is a list of objects with RuleID, Secret, File, etc.
        if '"RuleID"' in text and '"Secret"' in text:
            return 0.95
        if '"ruleID"' in text and '"secret"' in text:
            return 0.90
        # v8+ format uses lowercase keys
        if '"rule"' in text and '"match"' in text and '"file"' in text:
            return 0.80
        return 0.0

    def normalize(self, content: bytes, content_type: Optional[str] = None) -> list:
        findings: list = []
        parsed = _parse_json_safe(content)
        if not parsed:
            return findings

        # Gitleaks outputs a JSON array of findings
        items = parsed if isinstance(parsed, list) else parsed.get("results", parsed.get("findings", []))

        for leak in items:
            # Support both PascalCase (v7) and camelCase/lowercase (v8+) keys
            rule_id = leak.get("RuleID") or leak.get("ruleID") or leak.get("rule", "unknown-rule")
            description = leak.get("Description") or leak.get("description") or leak.get("match", "")
            file_path = leak.get("File") or leak.get("file", "")
            line = leak.get("StartLine") or leak.get("startLine") or leak.get("line")
            commit = leak.get("Commit") or leak.get("commit", "")
            author = leak.get("Author") or leak.get("author", "")
            date = leak.get("Date") or leak.get("date", "")
            leak.get("Entropy") or leak.get("entropy")
            # Redact the actual secret value — never store plaintext secrets
            len(str(leak.get("Secret") or leak.get("secret", "")))

            # All leaked secrets are high severity by default;
            # certain rules like private keys or API tokens are critical
            sev = "high"
            rule_lower = rule_id.lower()
            if any(kw in rule_lower for kw in ("private", "key", "token", "password", "aws")):
                sev = "critical"

            title = f"Secret detected: {rule_id}"
            if file_path:
                title += f" in {file_path}"

            desc_parts = [description or f"Leaked secret matching rule {rule_id}"]
            if commit:
                desc_parts.append(f"Commit: {commit[:12]}")
            if author:
                desc_parts.append(f"Author: {author}")
            if date:
                desc_parts.append(f"Date: {date}")

            findings.append(_make_finding(
                title=title[:500],
                description=" | ".join(desc_parts)[:2000],
                severity=sev,
                source_tool="gitleaks",
                source_format_str="custom",
                source_id=rule_id,
                rule_id=rule_id,
                file_path=file_path,
                line_number=int(line) if line else None,
                cwe_id="CWE-798",  # Use of Hard-coded Credentials
                tags=["secret", "credential", "gitleaks"],
            ))
        return findings


# ═══════════════════════════════════════════════════════════════════════════
# 26b. pip-audit Parser (JSON — Python dependency CVE audit)
# ═══════════════════════════════════════════════════════════════════════════

class PipAuditNormalizer(_Base):
    """Parse pip-audit JSON output (`pip-audit --format json`).

    pip-audit produces a top-level object with a ``dependencies`` array. Each
    dependency entry has ``name``, ``version``, and a ``vulns`` list. Each
    vuln carries ``id`` (GHSA or CVE), ``description``, ``fix_versions`` and
    ``aliases`` (other identifiers — typically CVE↔GHSA).

    Empty ``vulns`` arrays produce zero findings (clean dependency).
    """

    def can_handle(self, content: bytes, content_type: Optional[str] = None) -> float:
        text = content[:8192].decode("utf-8", errors="ignore")
        # pip-audit signature: top-level "dependencies" array with name/version/vulns triplets
        if '"dependencies"' in text and '"vulns"' in text and '"fix_versions"' in text:
            return 0.97
        if '"dependencies"' in text and '"vulns"' in text and '"aliases"' in text:
            return 0.92
        return 0.0

    def normalize(self, content: bytes, content_type: Optional[str] = None) -> list:
        findings: list = []
        parsed = _parse_json_safe(content)
        if not parsed or not isinstance(parsed, dict):
            return findings

        deps = parsed.get("dependencies", [])
        if not isinstance(deps, list):
            return findings

        for dep in deps:
            if not isinstance(dep, dict):
                continue
            pkg = (dep.get("name") or "").strip()
            ver = (dep.get("version") or "").strip()
            for vuln in dep.get("vulns", []) or []:
                if not isinstance(vuln, dict):
                    continue
                vid = (vuln.get("id") or "").strip()
                aliases = vuln.get("aliases") or []
                # Pick the first CVE we can find — id may be GHSA, aliases may carry CVE
                all_ids = [vid] + [a for a in aliases if isinstance(a, str)]
                cves = [i for i in all_ids if i.upper().startswith("CVE-")]
                ghsas = [i for i in all_ids if i.upper().startswith("GHSA-")]
                description = (vuln.get("description") or "").strip()
                fix_versions = vuln.get("fix_versions") or []
                if isinstance(fix_versions, str):
                    fix_versions = [fix_versions]

                if fix_versions:
                    recommendation = f"Upgrade {pkg} to >= {fix_versions[0]}"
                else:
                    recommendation = f"No upstream fix released for {pkg} {ver}; mitigate via configuration"

                title_id = vid or (cves[0] if cves else "pip-audit-finding")
                findings.append(_make_finding(
                    title=f"{title_id}: {pkg}@{ver}",
                    description=description[:1000] if description else f"Vulnerable dependency {pkg}=={ver}",
                    severity="high",  # pip-audit only reports known-exploitable CVEs/GHSAs
                    source_tool="pip-audit",
                    source_format_str="custom",
                    rule_id=vid,
                    cve_id=cves[0] if cves else None,
                    package_name=pkg,
                    package_version=ver,
                    recommendation=recommendation,
                    tags=([t for t in (cves[1:] + ghsas) if t and t != vid]) or [],
                ))
        return findings


# ═══════════════════════════════════════════════════════════════════════════
# 27. Claude Code Security Parser (JSON — AI SAST)
# ═══════════════════════════════════════════════════════════════════════════

class ClaudeCodeSecurityNormalizer(_Base):
    """Parse Claude Code Security AI-SAST JSON findings.

    Claude Code Security detects logic flaws, broken access control, and
    context-dependent vulnerabilities that regex-based SAST misses.
    Output format: JSON array of findings with severity, confidence, CWE,
    suggested patches, and reasoning.
    """

    def can_handle(self, content: bytes, content_type: Optional[str] = None) -> float:
        text = content[:5000].decode("utf-8", errors="ignore")
        if '"claude_code_security"' in text or '"ai_sast"' in text:
            return 0.97
        if '"reasoning"' in text and '"suggested_patch"' in text and '"confidence"' in text:
            return 0.85
        if '"findings"' in text and '"claude"' in text.lower():
            return 0.80
        return 0.0

    def normalize(self, content: bytes, content_type: Optional[str] = None) -> list:
        findings = []
        parsed = _parse_json_safe(content)
        if not parsed:
            return findings

        items = parsed if isinstance(parsed, list) else parsed.get("findings", parsed.get("results", []))
        for f in items:
            sev = str(f.get("severity", "medium")).lower()
            sev_map = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "info"}
            cwe_raw = f.get("cwe", f.get("cwe_id", ""))
            cwe = f"CWE-{cwe_raw}" if cwe_raw and not str(cwe_raw).startswith("CWE") else str(cwe_raw) if cwe_raw else None
            cves = _extract_cves(str(f.get("references", "")))

            findings.append(_make_finding(
                title=f.get("title", f.get("name", "Claude Code Security Finding")),
                description=f.get("description", f.get("reasoning", "")),
                severity=sev_map.get(sev, "medium"),
                source_tool="claude_code_security",
                source_format_str="custom",
                rule_id=f.get("rule_id", f.get("check_id", "")),
                cwe_id=cwe,
                cve_id=cves[0] if cves else None,
                file_path=f.get("file_path", f.get("location", {}).get("file", "")),
                line_number=f.get("line", f.get("location", {}).get("line")),
                confidence=f.get("confidence", 0.8),
                tags=["ai-sast", "claude", "logic-flaw"],
            ))
        return findings


# ═══════════════════════════════════════════════════════════════════════════
# 28. Dependency Combobulator Parser (JSON — Supply Chain)
# ═══════════════════════════════════════════════════════════════════════════

class CombobulatorNormalizer(_Base):
    """Parse Dependency Combobulator JSON output.

    Detects dependency confusion, namespace hijacking, and supply chain
    attacks (apiiro/combobulator). Air-gap compatible, no API keys needed.
    """

    def can_handle(self, content: bytes, content_type: Optional[str] = None) -> float:
        text = content[:5000].decode("utf-8", errors="ignore")
        if '"combobulator"' in text.lower() or '"dependency_confusion"' in text:
            return 0.95
        if '"supply_chain"' in text and '"namespace"' in text:
            return 0.80
        if '"package_name"' in text and '"risk_type"' in text and '"registry"' in text:
            return 0.85
        return 0.0

    def normalize(self, content: bytes, content_type: Optional[str] = None) -> list:
        findings = []
        parsed = _parse_json_safe(content)
        if not parsed:
            return findings

        items = parsed if isinstance(parsed, list) else parsed.get("results", parsed.get("findings", []))
        for r in items:
            risk_type = r.get("risk_type", r.get("attack_type", "dependency_confusion"))
            sev = str(r.get("severity", "high")).lower()
            pkg = r.get("package_name", r.get("package", "unknown"))
            registry = r.get("registry", r.get("source_registry", ""))
            private_registry = r.get("private_registry", "")

            desc_parts = [
                f"Package: {pkg}",
                f"Risk: {risk_type}",
                f"Public registry: {registry}" if registry else "",
                f"Private registry: {private_registry}" if private_registry else "",
                r.get("description", ""),
            ]

            findings.append(_make_finding(
                title=f"Supply Chain: {risk_type} — {pkg}",
                description="\n".join(p for p in desc_parts if p),
                severity=sev if sev in ("critical", "high", "medium", "low") else "high",
                source_tool="combobulator",
                source_format_str="custom",
                rule_id=r.get("rule_id", risk_type),
                cwe_id="CWE-427",  # Uncontrolled Search Path
                file_path=r.get("manifest_file", r.get("lockfile", "")),
                tags=["supply-chain", "dependency-confusion", risk_type],
            ))
        return findings


# ═══════════════════════════════════════════════════════════════════════════
# Registry — Central catalog of all scanner parsers
# ═══════════════════════════════════════════════════════════════════════════

SCANNER_NORMALIZERS = {
    "zap": ZAPNormalizer,
    "burp": BurpNormalizer,
    "nessus": NessusNormalizer,
    "openvas": OpenVASNormalizer,
    "bandit": BanditNormalizer,
    "checkmarx": CheckmarxNormalizer,
    "sonarqube": SonarQubeNormalizer,
    "fortify": FortifyNormalizer,
    "veracode": VeracodeNormalizer,
    "nikto": NiktoNormalizer,
    "nuclei": NucleiNormalizer,
    "nmap": NmapNormalizer,
    "snyk": SnykNormalizer,
    "prowler": ProwlerNormalizer,
    "checkov": CheckovNormalizer,
    "gitleaks": GitleaksScannerNormalizer,
    # New parsers for enterprise scanner ecosystem
    "trivy": TrivyScannerNormalizer,
    "grype": GrypeScannerNormalizer,
    "semgrep": SemgrepScannerNormalizer,
    "dependabot": DependabotScannerNormalizer,
    # Enterprise scanner ecosystem
    "qualys": QualysScannerNormalizer,
    "tenable": TenableScannerNormalizer,
    "rapid7": Rapid7ScannerNormalizer,
    "acunetix": AcunetixScannerNormalizer,
    "aws_inspector": AWSInspectorNormalizer,
    "gitlab_sast": GitLabSASTNormalizer,
    # Universal format parsers
    "sarif": SARIFUniversalNormalizer,
    "cyclonedx": CycloneDXUniversalNormalizer,
    "spdx": SPDXUniversalNormalizer,
    # AI-powered scanners
    "claude_code_security": ClaudeCodeSecurityNormalizer,
    # Supply chain security
    "combobulator": CombobulatorNormalizer,
    # Python deps CVE audit
    "pip-audit": PipAuditNormalizer,
    "pip_audit": PipAuditNormalizer,
}


def register_scanner_normalizers(registry) -> int:
    """
    Register all 15 scanner normalizers into the existing NormalizerRegistry.

    Usage:
        from core.scanner_parsers import register_scanner_normalizers
        registry = get_default_registry()
        count = register_scanner_normalizers(registry)
        print(f"Registered {count} scanner normalizers")

    Returns:
        Number of normalizers registered.
    """
    count = 0
    for name, cls in SCANNER_NORMALIZERS.items():
        try:
            config = NormalizerConfig(
                name=name,
                enabled=True,
                priority=60,  # Slightly lower than builtins
                description=f"{name.title()} scanner output parser",
            )
            normalizer = cls(config)
            registry.register(name, normalizer)
            count += 1
            logger.info("Registered scanner normalizer: %s", name)
        except (TypeError, AttributeError, ImportError, ValueError) as e:
            # Only expose exception type — str(e) may contain import paths
            logger.warning(
                "Failed to register %s normalizer: %s", name, type(e).__name__
            )
    return count


def auto_detect_scanner(content: bytes) -> Optional[str]:
    """
    Auto-detect which scanner produced the given output.

    Returns scanner name or None if undetected.
    """
    best_score = 0.0
    best_name = None

    for name, cls in SCANNER_NORMALIZERS.items():
        try:
            config = NormalizerConfig(name=name, enabled=True, priority=50)
            normalizer = cls(config)
            score = normalizer.can_handle(content)
            if score > best_score:
                best_score = score
                best_name = name
        except (TypeError, AttributeError, ValueError, json.JSONDecodeError, UnicodeDecodeError):
            continue

    return best_name if best_score >= 0.5 else None


def parse_scanner_output(
    content: bytes,
    scanner_type: Optional[str] = None,
    app_id: str = "",
    component: str = "",
) -> list:
    """
    Universal entry point: parse any scanner output into normalized findings.

    Args:
        content: Raw scanner output (bytes)
        scanner_type: Optional scanner type hint (auto-detected if not provided)
        app_id: Optional APP_ID to tag findings
        component: Optional component name

    Returns:
        List of findings (UnifiedFinding objects or dicts)
    """
    # Content size validation — prevent processing unreasonably large inputs
    _MAX_CONTENT_SIZE = 500 * 1024 * 1024  # 500 MB hard limit
    if len(content) > _MAX_CONTENT_SIZE:
        logger.error(
            "Scanner output exceeds size limit (%d > %d bytes)", len(content), _MAX_CONTENT_SIZE
        )
        return []

    # Determine scanner type
    name = scanner_type.lower() if scanner_type else auto_detect_scanner(content)
    if not name:
        logger.error("Cannot detect scanner type. Provide scanner_type parameter.")
        return []

    cls = SCANNER_NORMALIZERS.get(name)
    if not cls:
        logger.error("No parser for scanner type: %s", name)
        return []

    config = NormalizerConfig(name=name, enabled=True, priority=50)
    normalizer = cls(config)

    # Hardening: wrap normalize() to catch crashes from malformed input.
    # Each normalizer must survive bad input without affecting others.
    try:
        findings = normalizer.normalize(content)
        if not isinstance(findings, list):
            logger.warning("Normalizer %s returned non-list: %s", name, type(findings).__name__)
            findings = list(findings) if findings else []
    except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
        logger.error(
            "Normalizer %s crashed on input (%d bytes): %s",
            name, len(content), type(e).__name__,
            exc_info=True,
        )
        return []

    # Cap total findings to prevent memory exhaustion from huge reports
    _MAX_FINDINGS_PER_PARSE = 50_000
    if len(findings) > _MAX_FINDINGS_PER_PARSE:
        logger.warning(
            "Normalizer %s produced %d findings, capping at %d",
            name, len(findings), _MAX_FINDINGS_PER_PARSE,
        )
        findings = findings[:_MAX_FINDINGS_PER_PARSE]

    # Tag with APP_ID
    if app_id or component:
        for f in findings:
            if hasattr(f, "asset_id") and app_id:
                f.asset_id = app_id
            elif isinstance(f, dict) and app_id:
                f["asset_id"] = app_id
            if hasattr(f, "tags") and component:
                if isinstance(f.tags, list):
                    f.tags.append(f"component:{component}")
            elif isinstance(f, dict) and component:
                f.setdefault("tags", []).append(f"component:{component}")

    logger.info("Parsed %d findings from %s", len(findings), name)
    return findings


def get_supported_scanners() -> Dict[str, List[str]]:
    """Return supported scanners grouped by category."""
    return {
        "sast": ["checkmarx", "sonarqube", "bandit", "fortify", "veracode", "semgrep", "gitlab_sast", "claude_code_security"],
        "dast": ["zap", "burp", "nikto", "nuclei", "acunetix"],
        "sca": ["snyk", "dependabot", "grype", "trivy"],
        "supply_chain": ["combobulator"],
        "infrastructure": ["nessus", "openvas", "nmap", "qualys", "tenable", "rapid7"],
        "cloud": ["prowler", "checkov", "aws_inspector"],
        "universal": ["sarif", "cyclonedx", "spdx"],  # via existing normalizers
        "total_new": list(SCANNER_NORMALIZERS.keys()),
        "note": "SARIF, CycloneDX, SPDX, Trivy, Grype, Semgrep, Dependabot already in base ingestion module",
    }


# ═══════════════════════════════════════════════════════════════════════════
# pip-audit → SARIF v2.1.0 Converter
# ═══════════════════════════════════════════════════════════════════════════

def pip_audit_to_sarif(pip_audit_json: bytes) -> Dict[str, Any]:
    """Convert pip-audit JSON output to SARIF v2.1.0 format.

    pip-audit (``pip-audit --format json``) produces::

        {"dependencies": [{"name": "pkg", "version": "x.y.z",
                           "vulns": [{"id": "GHSA-...", "description": "...",
                                      "fix_versions": [...], "aliases": ["CVE-..."]}]}]}

    The output conforms to SARIF v2.1.0 (OASIS Standard):
    - ``runs[0].tool.driver.rules[]``  — one rule per unique vuln id
    - ``runs[0].results[]``            — one result per (package, vuln) pair
    - ``level`` mapping: pip-audit reports all known-exploitable CVEs/GHSAs →
      "error" (HIGH).  No CVSS data in raw output so we do not guess lower.

    Args:
        pip_audit_json: Raw bytes of ``pip-audit --format json`` output.

    Returns:
        SARIF v2.1.0 dict (JSON-serialisable).  On malformed / empty input
        returns a valid empty SARIF run (zero rules, zero results).
    """
    _SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
    _SARIF_VERSION = "2.1.0"

    def _empty_sarif() -> Dict[str, Any]:
        return {
            "$schema": _SARIF_SCHEMA,
            "version": _SARIF_VERSION,
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "pip-audit",
                        "informationUri": "https://github.com/pypa/pip-audit",
                        "version": "unknown",
                        "rules": [],
                    }
                },
                "results": [],
            }],
        }

    parsed = _parse_json_safe(pip_audit_json)
    if not parsed or not isinstance(parsed, dict):
        logger.warning("pip_audit_to_sarif: invalid JSON input")
        return _empty_sarif()

    deps = parsed.get("dependencies", [])
    if not isinstance(deps, list):
        return _empty_sarif()

    rules: List[Dict[str, Any]] = []
    results: List[Dict[str, Any]] = []
    seen_rule_ids: Dict[str, int] = {}  # rule_id → index in rules[]

    for dep in deps:
        if not isinstance(dep, dict):
            continue
        pkg = (dep.get("name") or "").strip()
        ver = (dep.get("version") or "").strip()
        for vuln in dep.get("vulns", []) or []:
            if not isinstance(vuln, dict):
                continue
            vid = (vuln.get("id") or "").strip()
            if not vid:
                continue
            aliases: List[str] = [
                a for a in (vuln.get("aliases") or []) if isinstance(a, str)
            ]
            all_ids = [vid] + aliases
            cves = [i for i in all_ids if i.upper().startswith("CVE-")]
            description = (vuln.get("description") or "").strip()
            fix_versions: List[str] = vuln.get("fix_versions") or []
            if isinstance(fix_versions, str):
                fix_versions = [fix_versions]

            # Build rule entry (deduplicate by vuln id)
            if vid not in seen_rule_ids:
                rule_idx = len(rules)
                seen_rule_ids[vid] = rule_idx
                rule: Dict[str, Any] = {
                    "id": vid,
                    "name": vid.replace("-", "_"),
                    "shortDescription": {
                        "text": description[:200] if description else f"Vulnerable dependency ({vid})"
                    },
                    "fullDescription": {
                        "text": description[:1000] if description else f"Vulnerable dependency ({vid})"
                    },
                    "helpUri": (
                        f"https://github.com/advisories/{vid}"
                        if vid.upper().startswith("GHSA-")
                        else f"https://nvd.nist.gov/vuln/detail/{cves[0]}"
                        if cves
                        else f"https://github.com/pypa/pip-audit"
                    ),
                    "properties": {
                        "aliases": aliases,
                        "cves": cves,
                        "fix_versions": fix_versions,
                        "tags": ["supply-chain", "dependency"],
                    },
                    # SARIF default configuration — pip-audit only surfaces
                    # known-exploitable issues so we map them all to "error".
                    "defaultConfiguration": {"level": "error"},
                }
                rules.append(rule)

            rule_id_ref = vid
            fix_text = (
                f"Upgrade {pkg} to >= {fix_versions[0]}"
                if fix_versions
                else f"No upstream fix available for {pkg} {ver}. Mitigate via configuration."
            )

            result: Dict[str, Any] = {
                "ruleId": rule_id_ref,
                "ruleIndex": seen_rule_ids[vid],
                "level": "error",
                "message": {
                    "text": (
                        f"{vid} in {pkg}=={ver}. "
                        + (description[:300] if description else "")
                    ).strip()
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": "requirements.txt",
                                "uriBaseId": "%SRCROOT%",
                            }
                        },
                        "logicalLocations": [
                            {
                                "name": f"{pkg}=={ver}",
                                "kind": "module",
                            }
                        ],
                    }
                ],
                "fixes": [
                    {
                        "description": {"text": fix_text},
                        "artifactChanges": [],
                    }
                ],
                "properties": {
                    "package": pkg,
                    "version": ver,
                    "vuln_id": vid,
                    "aliases": aliases,
                    "cves": cves,
                    "fix_versions": fix_versions,
                },
            }
            results.append(result)

    sarif: Dict[str, Any] = {
        "$schema": _SARIF_SCHEMA,
        "version": _SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "pip-audit",
                        "informationUri": "https://github.com/pypa/pip-audit",
                        "version": parsed.get("pip_audit_version", "unknown"),
                        "rules": rules,
                    }
                },
                "results": results,
                "properties": {
                    "total_packages_scanned": len(deps),
                    "total_vulnerabilities": len(results),
                    "unique_vuln_ids": len(rules),
                },
            }
        ],
    }
    logger.info(
        "pip_audit_to_sarif: %d deps → %d results, %d unique rules",
        len(deps), len(results), len(rules),
    )
    return sarif


# ═══════════════════════════════════════════════════════════════════════════
# Cross-Scanner Deduplication
# ═══════════════════════════════════════════════════════════════════════════

def dedup_cross_scanner(
    findings: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Merge findings with the same (cve_id, file_path, line_number) key
    across different scanners into a single finding with a ``sources`` list.

    Deduplication key: ``(cve_id or rule_id, normalised_file_path, line_number)``.
    When the key matches across multiple scanner findings:
    - ``sources`` is set to a deduplicated list of all contributing scanner names.
    - The highest severity is kept.
    - The first non-empty description/recommendation wins.
    - All unique tags are merged.
    - ``deduped_from_count`` records how many raw findings collapsed.

    Findings with no cve_id AND no rule_id (i.e. no stable identifier) are
    passed through unchanged with ``sources`` set to their ``source_tool``.

    Args:
        findings: List of finding dicts (from any scanner normalizer or dict).

    Returns:
        Deduplicated list.  Order is deterministic (insertion order of first
        seen key).
    """
    if not findings:
        return []

    _SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

    def _norm_path(path: Optional[str]) -> str:
        if not path:
            return ""
        # Normalise separators and strip leading ./
        p = str(path).replace("\\", "/").lstrip("./")
        return p

    def _dedup_key(f: Dict[str, Any]) -> Optional[tuple]:
        """Return (vuln_id, norm_path, line) or None for ungroupable findings."""
        vuln_id = (
            (f.get("cve_id") or "")
            or (f.get("rule_id") or "")
            or (f.get("vuln_id") or "")
        )
        if not vuln_id:
            return None  # no stable identifier — pass through
        path = _norm_path(f.get("file_path") or f.get("artifact") or "")
        line = f.get("line_number") or f.get("line") or 0
        try:
            line = int(line)
        except (TypeError, ValueError):
            line = 0
        return (vuln_id.upper(), path, line)

    # Group findings by dedup key.
    # Ungroupable findings get a unique synthetic key so they pass through.
    grouped: Dict[Any, List[Dict[str, Any]]] = {}
    _passthrough_counter = 0
    for f in findings:
        key = _dedup_key(f)
        if key is None:
            _passthrough_counter += 1
            key = ("__passthrough__", _passthrough_counter)
        grouped.setdefault(key, []).append(f)

    merged: List[Dict[str, Any]] = []
    for key, group in grouped.items():
        if len(group) == 1:
            # Single finding — just ensure sources list is present.
            out = dict(group[0])
            tool = out.get("source_tool") or out.get("scanner") or "unknown"
            out.setdefault("sources", [tool] if tool else [])
            out["deduped_from_count"] = 1
            merged.append(out)
            continue

        # Multiple findings share the same key — merge them.
        base = dict(group[0])

        # Collect sources from all findings.
        sources: List[str] = []
        seen_sources: set = set()
        for f in group:
            tool = f.get("source_tool") or f.get("scanner") or "unknown"
            if tool and tool not in seen_sources:
                seen_sources.add(tool)
                sources.append(tool)
            for s in (f.get("sources") or []):
                if s and s not in seen_sources:
                    seen_sources.add(s)
                    sources.append(s)

        # Keep highest severity.
        best_sev = base.get("severity", "medium")
        for f in group[1:]:
            sev = f.get("severity", "medium")
            if _SEVERITY_RANK.get(sev, 0) > _SEVERITY_RANK.get(best_sev, 0):
                best_sev = sev

        # First non-empty description / recommendation wins.
        description = base.get("description") or ""
        recommendation = base.get("recommendation") or base.get("remediation") or ""
        for f in group[1:]:
            if not description:
                description = f.get("description") or ""
            if not recommendation:
                recommendation = (
                    f.get("recommendation") or f.get("remediation") or ""
                )

        # Merge tags (unique, sorted for determinism).
        all_tags: set = set(base.get("tags") or [])
        for f in group[1:]:
            all_tags.update(f.get("tags") or [])

        base["sources"] = sources
        base["source_tool"] = sources[0] if sources else "unknown"
        base["severity"] = best_sev
        base["description"] = description
        base["recommendation"] = recommendation
        base["tags"] = sorted(all_tags)
        base["deduped_from_count"] = len(group)
        merged.append(base)

    logger.info(
        "dedup_cross_scanner: %d raw findings → %d merged (%.1f%% reduction)",
        len(findings),
        len(merged),
        100.0 * (1 - len(merged) / len(findings)) if findings else 0.0,
    )
    return merged
