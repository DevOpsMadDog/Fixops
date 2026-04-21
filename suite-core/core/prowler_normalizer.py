"""Prowler Output Normalizer — ALDECI.

Parses Prowler JSON/CSV output and normalizes findings to ALDECI's unified
finding format. Supports Prowler v3+ and v4 output formats.

CIS Benchmark mapping:
  - AWS: CIS Amazon Web Services Foundations Benchmark v1.5.0
  - Azure: CIS Microsoft Azure Foundations Benchmark v2.0.0
  - GCP: CIS Google Cloud Platform Foundation Benchmark v1.3.0

Output format matches ALDECI's scanner-ingest pipeline
(apps/api/ingestion.py UnifiedFinding).
"""
from __future__ import annotations

import csv
import io
import json
import logging
from typing import Any, Dict, List, Optional

_logger = logging.getLogger(__name__)

# Prowler severity → ALDECI severity mapping
_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "informational",
    "info": "informational",
}

# Prowler status → ALDECI finding status
_STATUS_MAP = {
    "FAIL": "open",
    "PASS": "passed",
    "WARNING": "open",
    "INFO": "informational",
    "MANUAL": "open",
}

# CIS Benchmark references per provider
CIS_BENCHMARKS = {
    "aws": "CIS Amazon Web Services Foundations Benchmark v1.5.0",
    "azure": "CIS Microsoft Azure Foundations Benchmark v2.0.0",
    "gcp": "CIS Google Cloud Platform Foundation Benchmark v1.3.0",
}

# Common Prowler check → compliance framework mapping
_COMPLIANCE_MAP = {
    "iam_": ["CIS", "NIST-800-53", "PCI-DSS"],
    "s3_": ["CIS", "NIST-800-53", "SOC2"],
    "ec2_": ["CIS", "NIST-800-53"],
    "rds_": ["CIS", "NIST-800-53", "HIPAA"],
    "cloudtrail_": ["CIS", "NIST-800-53", "SOC2", "PCI-DSS"],
    "cloudwatch_": ["CIS", "NIST-800-53"],
    "vpc_": ["CIS", "NIST-800-53"],
    "kms_": ["CIS", "NIST-800-53", "PCI-DSS", "HIPAA"],
    "logging_": ["CIS", "NIST-800-53", "SOC2"],
    "network_": ["CIS", "NIST-800-53"],
    "storage_": ["CIS", "NIST-800-53", "SOC2"],
    "compute_": ["CIS", "NIST-800-53"],
    "database_": ["CIS", "NIST-800-53", "HIPAA"],
}


def _map_compliance_frameworks(check_id: str) -> List[str]:
    """Map a Prowler check_id to relevant compliance frameworks."""
    frameworks: List[str] = []
    for prefix, fws in _COMPLIANCE_MAP.items():
        if check_id.startswith(prefix):
            frameworks.extend(fws)
            break
    if not frameworks:
        frameworks = ["CIS"]
    return sorted(set(frameworks))


class ProwlerNormalizer:
    """Normalizes Prowler output (JSON or CSV) to ALDECI unified finding format."""

    def __init__(self, provider: str = "aws") -> None:
        self.provider = provider.lower()

    def normalize_json(self, raw_json: str) -> List[Dict[str, Any]]:
        """Parse Prowler JSON output and normalize to ALDECI findings.

        Args:
            raw_json: JSON string — either a list of findings or a single finding dict.

        Returns:
            List of normalized ALDECI finding dicts.
        """
        try:
            data = json.loads(raw_json)
        except (json.JSONDecodeError, TypeError) as exc:
            _logger.error("Failed to parse Prowler JSON: %s", exc)
            return []

        if isinstance(data, dict):
            data = [data]

        if not isinstance(data, list):
            _logger.error("Prowler JSON must be a list or dict, got %s", type(data).__name__)
            return []

        findings: List[Dict[str, Any]] = []
        for item in data:
            normalized = self._normalize_finding(item)
            if normalized:
                findings.append(normalized)

        _logger.info("Normalized %d Prowler findings from JSON", len(findings))
        return findings

    def normalize_csv(self, raw_csv: str) -> List[Dict[str, Any]]:
        """Parse Prowler CSV output and normalize to ALDECI findings.

        Args:
            raw_csv: CSV string with headers.

        Returns:
            List of normalized ALDECI finding dicts.
        """
        findings: List[Dict[str, Any]] = []
        try:
            reader = csv.DictReader(io.StringIO(raw_csv))
            for row in reader:
                normalized = self._normalize_csv_row(row)
                if normalized:
                    findings.append(normalized)
        except Exception as exc:
            _logger.error("Failed to parse Prowler CSV: %s", exc)
            return []

        _logger.info("Normalized %d Prowler findings from CSV", len(findings))
        return findings

    def _normalize_finding(self, item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Normalize a single Prowler JSON finding to ALDECI format."""
        # Skip PASS results — we only ingest failures
        prowler_status = str(item.get("Status", item.get("status", "FAIL"))).upper()
        if prowler_status == "PASS":
            return None

        # Prowler v4 uses different field names than v3
        check_id = item.get("CheckID", item.get("check_id", item.get("CheckId", "")))
        check_title = item.get("CheckTitle", item.get("check_title", item.get("CheckType", "")))
        severity = str(item.get("Severity", item.get("severity", "medium"))).lower()
        severity = _SEVERITY_MAP.get(severity, "medium")

        # Resource info
        resource_id = item.get("ResourceId", item.get("resource_id", ""))
        resource_arn = item.get("ResourceArn", item.get("resource_arn", ""))
        resource_type = item.get("ResourceType", item.get("resource_type", ""))

        # Location
        region = item.get("Region", item.get("region", ""))
        account_id = item.get("AccountId", item.get("account_id", ""))
        service = item.get("ServiceName", item.get("service_name",
                          item.get("Service", item.get("service", ""))))

        # Detail
        status_extended = item.get("StatusExtended", item.get("status_extended", ""))
        risk = item.get("Risk", item.get("risk", ""))
        remediation_text = ""
        remediation_url = ""

        # Prowler v4 has Remediation as a dict
        remediation_raw = item.get("Remediation", item.get("remediation", {}))
        if isinstance(remediation_raw, dict):
            remediation_text = remediation_raw.get("Recommendation", {}).get("Text", "")
            remediation_url = remediation_raw.get("Recommendation", {}).get("Url", "")
        elif isinstance(remediation_raw, str):
            remediation_text = remediation_raw

        # CIS section
        compliance = item.get("Compliance", item.get("compliance", {}))
        cis_section = ""
        if isinstance(compliance, dict):
            # Prowler v4 format
            for fw_data in compliance.get("AssociatedStandards", []):
                if "CIS" in str(fw_data.get("StandardName", "")):
                    cis_section = fw_data.get("Section", "")
                    break
        elif isinstance(compliance, list):
            for c in compliance:
                if isinstance(c, dict) and "CIS" in str(c.get("Framework", "")):
                    cis_section = c.get("Section", c.get("Id", ""))
                    break

        compliance_frameworks = _map_compliance_frameworks(check_id)

        provider = str(item.get("Provider", item.get("provider", self.provider))).lower()

        return {
            "provider": provider,
            "account_id": str(account_id),
            "region": str(region),
            "service": str(service),
            "check_id": str(check_id),
            "check_title": str(check_title),
            "severity": severity,
            "resource_type": str(resource_type),
            "resource_id": str(resource_id),
            "resource_arn": str(resource_arn),
            "status_extended": str(status_extended),
            "risk": str(risk),
            "remediation": str(remediation_text),
            "remediation_url": str(remediation_url),
            "cis_section": str(cis_section),
            "compliance_frameworks": json.dumps(compliance_frameworks),
            "raw_json": json.dumps(item, default=str),
        }

    def _normalize_csv_row(self, row: Dict[str, str]) -> Optional[Dict[str, Any]]:
        """Normalize a single Prowler CSV row to ALDECI format."""
        # Prowler CSV uses different column names depending on version
        prowler_status = row.get("STATUS", row.get("Status", row.get("status", "FAIL"))).upper()
        if prowler_status == "PASS":
            return None

        check_id = row.get("CHECK_ID", row.get("CheckID", row.get("check_id", "")))
        check_title = row.get("CHECK_TITLE", row.get("CheckTitle", row.get("check_title", "")))
        severity = row.get("SEVERITY", row.get("Severity", row.get("severity", "medium"))).lower()
        severity = _SEVERITY_MAP.get(severity, "medium")

        resource_id = row.get("RESOURCE_ID", row.get("ResourceId", row.get("resource_id", "")))
        resource_arn = row.get("RESOURCE_ARN", row.get("ResourceArn", row.get("resource_arn", "")))
        resource_type = row.get("RESOURCE_TYPE", row.get("ResourceType", row.get("resource_type", "")))

        region = row.get("REGION", row.get("Region", row.get("region", "")))
        account_id = row.get("ACCOUNT_ID", row.get("AccountId", row.get("account_id", "")))
        service = row.get("SERVICE_NAME", row.get("ServiceName", row.get("service", "")))

        status_extended = row.get("STATUS_EXTENDED", row.get("StatusExtended", row.get("status_extended", "")))
        risk = row.get("RISK", row.get("Risk", row.get("risk", "")))
        remediation = row.get("REMEDIATION", row.get("Remediation", row.get("remediation", "")))
        remediation_url = row.get("REMEDIATION_URL", row.get("RemediationUrl", row.get("remediation_url", "")))

        provider = row.get("PROVIDER", row.get("Provider", row.get("provider", self.provider))).lower()
        compliance_frameworks = _map_compliance_frameworks(check_id)

        return {
            "provider": provider,
            "account_id": str(account_id),
            "region": str(region),
            "service": str(service),
            "check_id": str(check_id),
            "check_title": str(check_title),
            "severity": severity,
            "resource_type": str(resource_type),
            "resource_id": str(resource_id),
            "resource_arn": str(resource_arn),
            "status_extended": str(status_extended),
            "risk": str(risk),
            "remediation": str(remediation),
            "remediation_url": str(remediation_url),
            "cis_section": "",
            "compliance_frameworks": json.dumps(compliance_frameworks),
            "raw_json": json.dumps(dict(row), default=str),
        }


def normalize_prowler_output(
    raw_data: str,
    provider: str = "aws",
    format: str = "json",
) -> List[Dict[str, Any]]:
    """Convenience function — normalize Prowler output to ALDECI findings.

    Args:
        raw_data: Raw Prowler output (JSON or CSV string).
        provider: Cloud provider (aws/azure/gcp).
        format: Output format — "json" or "csv".

    Returns:
        List of normalized ALDECI finding dicts.
    """
    normalizer = ProwlerNormalizer(provider=provider)
    if format.lower() == "csv":
        return normalizer.normalize_csv(raw_data)
    return normalizer.normalize_json(raw_data)
