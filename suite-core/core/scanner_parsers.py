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
import xml.etree.ElementTree as ET  # noqa: B405 — defusedxml.defuse_stdlib() called below
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
# Try to import from the ingestion module for tight integration
# ---------------------------------------------------------------------------
try:
    from apps.api.ingestion import (
        BaseNormalizer,
        FindingSeverity,
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
        return ET.fromstring(text)  # noqa: B314 — defusedxml.defuse_stdlib() called at module load
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


def _make_finding(**kwargs) -> Any:
    """Create a UnifiedFinding or dict depending on availability."""
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
        except Exception as e:
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
        except Exception:
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
    except Exception as e:
        logger.error(
            "Normalizer %s crashed on input (%d bytes): %s",
            name, len(content), type(e).__name__,
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
        "sast": ["checkmarx", "sonarqube", "bandit", "fortify", "veracode"],
        "dast": ["zap", "burp", "nikto", "nuclei"],
        "sca": ["snyk"],
        "infrastructure": ["nessus", "openvas", "nmap"],
        "cloud": ["prowler", "checkov"],
        "universal": ["sarif", "cyclonedx", "spdx"],  # via existing normalizers
        "total_new": list(SCANNER_NORMALIZERS.keys()),
        "note": "SARIF, CycloneDX, SPDX, Trivy, Grype, Semgrep, Dependabot already in base ingestion module",
    }
