"""SARIF canonicalization and normalization utilities for deterministic processing."""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, Dict, List, Mapping, Sequence

logger = logging.getLogger(__name__)

SEVERITY_MAP = {
    "error": "HIGH",
    "warning": "MEDIUM",
    "note": "LOW",
    "none": "INFO",
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
    "informational": "INFO",
}


def _now() -> datetime:
    """Return a reproducible timestamp when FIXOPS_TEST_SEED is present."""
    seed = os.getenv("FIXOPS_TEST_SEED")
    if seed:
        normalized_seed = seed.replace("Z", "+00:00")
        seeded = datetime.fromisoformat(normalized_seed)
        if seeded.tzinfo is None:
            seeded = seeded.replace(tzinfo=timezone.utc)
        else:
            seeded = seeded.astimezone(timezone.utc)
        return seeded
    return datetime.now(timezone.utc)


def _normalize_severity(severity: str | None) -> str:
    """Normalize severity to standard levels."""
    if not severity:
        return "INFO"
    normalized = severity.strip().lower()
    return SEVERITY_MAP.get(normalized, "MEDIUM")


def _normalize_path(path: str) -> str:
    """Normalize file path to relative forward-slash format."""
    if not path:
        return ""
    normalized = path.replace("\\", "/")
    if normalized.startswith("/"):
        parts = normalized.split("/")
        if len(parts) > 2:
            normalized = "/".join(parts[2:])
    return normalized


def _extract_tool_info(sarif: Mapping[str, Any]) -> Dict[str, str]:
    """Extract tool name and version from SARIF."""
    runs = sarif.get("runs", [])
    if not runs or not isinstance(runs, Sequence):
        return {"name": "unknown", "version": "unknown"}

    run = runs[0]
    tool = run.get("tool", {})
    driver = tool.get("driver", {})

    name = driver.get("name", "unknown")
    version = driver.get("version") or driver.get("semanticVersion") or "unknown"

    return {"name": str(name).lower(), "version": str(version)}


def _extract_cwe(result: Mapping[str, Any]) -> List[str]:
    """Extract CWE identifiers from a SARIF result."""
    cwes = []
    taxa = result.get("taxa", [])
    if isinstance(taxa, Sequence):
        for taxon in taxa:
            if isinstance(taxon, Mapping):
                taxon_id = taxon.get("id", "")
                if isinstance(taxon_id, str) and taxon_id.startswith("CWE-"):
                    cwes.append(taxon_id.upper())

    properties = result.get("properties", {})
    if isinstance(properties, Mapping):
        cwe_prop = properties.get("cwe") or properties.get("CWE")
        if isinstance(cwe_prop, str):
            if cwe_prop.startswith("CWE-"):
                cwes.append(cwe_prop.upper())
        elif isinstance(cwe_prop, Sequence):
            for cwe in cwe_prop:
                if isinstance(cwe, str) and cwe.startswith("CWE-"):
                    cwes.append(cwe.upper())

    return sorted(set(cwes))


def _extract_cvss(result: Mapping[str, Any]) -> Dict[str, Any] | None:
    """Extract CVSS information from a SARIF result."""
    properties = result.get("properties", {})
    if not isinstance(properties, Mapping):
        return None

    cvss_score = properties.get("cvss") or properties.get("cvssScore")
    cvss_vector = properties.get("cvssVector") or properties.get("cvss_vector")

    if cvss_score is not None:
        try:
            score = float(cvss_score)
            result_cvss: Dict[str, Any] = {"score": round(score, 1)}
            if isinstance(cvss_vector, str):
                result_cvss["vector"] = cvss_vector
            return result_cvss
        except (TypeError, ValueError):
            pass

    return None


def normalize_sarif(sarif_path: Path | str) -> Dict[str, Any]:
    """Normalize a SARIF file to canonical format.

    Args:
        sarif_path: Path to SARIF file

    Returns:
        Normalized SARIF data with metadata and sorted findings
    """
    path = Path(sarif_path)
    with path.open("r", encoding="utf-8") as handle:
        sarif = json.load(handle)

    if not isinstance(sarif, Mapping):
        raise ValueError(f"Invalid SARIF structure in {path}")

    source_hash = sha256(path.read_bytes()).hexdigest()
    tool_info = _extract_tool_info(sarif)

    findings: List[Dict[str, Any]] = []
    runs = sarif.get("runs", [])
    if isinstance(runs, Sequence):
        for run in runs:
            if not isinstance(run, Mapping):
                continue
            results = run.get("results", [])
            if not isinstance(results, Sequence):
                continue

            for result in results:
                if not isinstance(result, Mapping):
                    continue

                rule_id = result.get("ruleId", "unknown")
                message = result.get("message", {})
                if isinstance(message, Mapping):
                    message_text = message.get("text", "")
                else:
                    message_text = str(message)

                level = result.get("level", "warning")
                severity = _normalize_severity(level)

                locations = result.get("locations", [])
                file_path = ""
                line_number = None
                if isinstance(locations, Sequence) and locations:
                    location = locations[0]
                    if isinstance(location, Mapping):
                        physical_location = location.get("physicalLocation", {})
                        if isinstance(physical_location, Mapping):
                            artifact_location = physical_location.get(
                                "artifactLocation", {}
                            )
                            if isinstance(artifact_location, Mapping):
                                uri = artifact_location.get("uri", "")
                                file_path = _normalize_path(uri)
                            region = physical_location.get("region", {})
                            if isinstance(region, Mapping):
                                line_number = region.get("startLine")

                finding = {
                    "rule_id": str(rule_id),
                    "severity": severity,
                    "category": "security",
                    "file_path": file_path,
                    "message": message_text,
                }

                if line_number is not None:
                    finding["line_number"] = int(line_number)

                cwes = _extract_cwe(result)
                if cwes:
                    finding["cwe"] = cwes

                cvss = _extract_cvss(result)
                if cvss:
                    finding["cvss"] = cvss

                findings.append(finding)

    findings.sort(key=lambda f: (f["rule_id"], f["file_path"], f.get("line_number", 0)))

    return {
        "metadata": {
            "generated_at": _now().isoformat(),
            "tool": tool_info,
            "source_hash": source_hash,
        },
        "findings": findings,
    }


def write_normalized_sarif(
    sarif_path: Path | str, destination: Path | str, strict_schema: bool = False
) -> Dict[str, Any]:
    """Normalize SARIF and write to destination.

    Args:
        sarif_path: Path to input SARIF file
        destination: Path to output normalized JSON
        strict_schema: If True, validate against schema

    Returns:
        Normalized SARIF data
    """
    normalized = normalize_sarif(sarif_path)

    if strict_schema:
        findings = normalized.get("findings", [])
        errors = []
        for idx, finding in enumerate(findings):
            if not finding.get("rule_id"):
                errors.append(f"Finding {idx}: missing rule_id")
            if not finding.get("severity"):
                errors.append(f"Finding {idx}: missing severity")

        if errors:
            logger.error("Strict schema validation failed with %d errors", len(errors))
            for error in errors:
                logger.error("  %s", error)
            raise ValueError(
                f"Strict schema validation failed: {len(errors)} findings with missing required fields"
            )

    destination_path = Path(destination)
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    with destination_path.open("w", encoding="utf-8") as handle:
        json.dump(normalized, handle, indent=2, sort_keys=True)
        handle.write("\n")

    return normalized


__all__ = [
    "normalize_sarif",
    "write_normalized_sarif",
]
