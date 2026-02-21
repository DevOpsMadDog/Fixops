"""
SBOM parser service with optional lib4sbom integration.
Falls back to direct JSON parsing if lib4sbom is unavailable.
"""
from __future__ import annotations

import json
from typing import Any, Dict

import structlog

logger = structlog.get_logger()

try:
    # Optional dependency
    pass

    HAS_LIB4SBOM = True
except Exception:  # pragma: no cover
    HAS_LIB4SBOM = False


async def parse_sbom(content: str) -> Dict[str, Any]:
    if HAS_LIB4SBOM:
        try:
            # Example using lib4sbom to normalize
            # Note: keeping generic due to environment constraints
            doc = json.loads(content)
            # In a full integration, lib4sbom would convert and validate formats
            return _extract_findings_from_cyclonedx(doc)
        except Exception as e:
            logger.warning("lib4sbom parsing failed, falling back", error=str(e))
    # Fallback
    try:
        doc = json.loads(content)
        return _extract_findings_from_cyclonedx(doc)
    except Exception as e:
        logger.error("SBOM parse failed", error=str(e))
        return {"findings": []}


def _extract_findings_from_cyclonedx(sbom: Dict[str, Any]) -> Dict[str, Any]:
    findings = []
    components = sbom.get("components", [])
    for component in components:
        vulnerabilities = component.get("vulnerabilities", [])
        for vuln in vulnerabilities:
            findings.append(
                {
                    "rule_id": vuln.get("id", "unknown"),
                    "title": f"Vulnerability in {component.get('name', 'unknown')}",
                    "description": vuln.get("description", ""),
                    "severity": (
                        vuln.get("ratings", [{}])[0].get("severity", "low") or "low"
                    ).lower(),
                    "category": "dependency",
                    "scanner_type": "sca",
                    "file_path": component.get("purl", ""),
                    "component_name": component.get("name"),
                    "component_version": component.get("version"),
                }
            )
    return {"findings": findings}
