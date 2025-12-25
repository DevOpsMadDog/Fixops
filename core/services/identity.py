"""Identity Resolution - Map findings to org/app/component IDs.

This module provides cross-tool deduplication through:
- CWE normalization for SAST findings (maps tool-specific rules to CWE IDs)
- Control ID normalization for CSPM findings (maps cloud policies to control frameworks)
- Correlation key computation that uses normalized identifiers
"""

import hashlib
import re
from pathlib import Path
from typing import Any, Dict, Optional

try:
    import yaml  # type: ignore[import-untyped]

    HAS_YAML = True
except ImportError:
    HAS_YAML = False


# CWE mapping for common SAST rule patterns across tools
# This enables cross-tool deduplication for SAST findings
CWE_RULE_MAPPINGS: Dict[str, str] = {
    # SQL Injection patterns
    "sql-injection": "CWE-89",
    "sqli": "CWE-89",
    "sql_injection": "CWE-89",
    "tainted-sql-string": "CWE-89",
    # XSS patterns
    "xss": "CWE-79",
    "cross-site-scripting": "CWE-79",
    "reflected-xss": "CWE-79",
    "stored-xss": "CWE-79",
    "dom-xss": "CWE-79",
    # Command Injection
    "command-injection": "CWE-78",
    "os-command-injection": "CWE-78",
    "shell-injection": "CWE-78",
    # Path Traversal
    "path-traversal": "CWE-22",
    "directory-traversal": "CWE-22",
    "lfi": "CWE-22",
    # SSRF
    "ssrf": "CWE-918",
    "server-side-request-forgery": "CWE-918",
    # Deserialization
    "insecure-deserialization": "CWE-502",
    "unsafe-deserialization": "CWE-502",
    # Hardcoded secrets
    "hardcoded-secret": "CWE-798",
    "hardcoded-password": "CWE-798",
    "hardcoded-credential": "CWE-798",
    # Weak crypto
    "weak-crypto": "CWE-327",
    "insecure-crypto": "CWE-327",
    "weak-hash": "CWE-328",
    # XXE
    "xxe": "CWE-611",
    "xml-external-entity": "CWE-611",
    # Open redirect
    "open-redirect": "CWE-601",
    "url-redirect": "CWE-601",
    # LDAP injection
    "ldap-injection": "CWE-90",
    # NoSQL injection
    "nosql-injection": "CWE-943",
    # CSRF
    "csrf": "CWE-352",
    "cross-site-request-forgery": "CWE-352",
}

# Control ID mapping for CSPM findings across cloud providers
# Maps tool-specific policy IDs to common control frameworks (CIS, NIST, etc.)
CONTROL_ID_MAPPINGS: Dict[str, str] = {
    # S3 bucket policies
    "s3-bucket-public-read": "CIS-AWS-2.1.5",
    "s3-bucket-public-write": "CIS-AWS-2.1.5",
    "aws_s3_bucket_public": "CIS-AWS-2.1.5",
    "CKV_AWS_19": "CIS-AWS-2.1.5",  # Checkov
    "AWS.S3.DS.High.1043": "CIS-AWS-2.1.5",  # Prowler
    # Encryption at rest
    "s3-bucket-encryption": "CIS-AWS-2.1.1",
    "aws_s3_bucket_encryption": "CIS-AWS-2.1.1",
    "CKV_AWS_18": "CIS-AWS-2.1.1",
    # IAM policies
    "iam-root-access-key": "CIS-AWS-1.4",
    "iam-user-mfa": "CIS-AWS-1.2",
    "CKV_AWS_41": "CIS-AWS-1.4",
    # Security groups
    "security-group-open-ingress": "CIS-AWS-5.2",
    "aws_security_group_open": "CIS-AWS-5.2",
    "CKV_AWS_23": "CIS-AWS-5.2",
    # CloudTrail
    "cloudtrail-enabled": "CIS-AWS-3.1",
    "CKV_AWS_67": "CIS-AWS-3.1",
    # RDS
    "rds-encryption": "CIS-AWS-2.3.1",
    "rds-public-access": "CIS-AWS-2.3.2",
    "CKV_AWS_16": "CIS-AWS-2.3.1",
    # EBS
    "ebs-encryption": "CIS-AWS-2.2.1",
    "CKV_AWS_3": "CIS-AWS-2.2.1",
    # KMS
    "kms-key-rotation": "CIS-AWS-2.8",
    "CKV_AWS_7": "CIS-AWS-2.8",
}


class IdentityResolver:
    """Resolve application and component IDs from findings."""

    def __init__(self, mappings_path: Optional[Path] = None):
        """Initialize with optional mappings file."""
        self.mappings: Dict[str, Any] = {}
        if mappings_path and mappings_path.exists() and HAS_YAML:
            with mappings_path.open("r") as f:
                self.mappings = yaml.safe_load(f) or {}

    def resolve_app_id(self, finding: Dict[str, Any]) -> str:
        """Resolve application ID from finding."""
        if self.mappings.get("apps"):
            for app_pattern in self.mappings["apps"]:
                if self._matches_pattern(finding, app_pattern):
                    return app_pattern["app_id"]

        file_path = finding.get("file_path", "")
        if file_path:
            if "/api/" in file_path or "api-" in file_path:
                return "api-service"
            elif "/frontend/" in file_path or "/ui/" in file_path:
                return "frontend-app"
            elif "/backend/" in file_path:
                return "backend-service"

        resource_id = finding.get("resource_id", "")
        if resource_id:
            if resource_id.startswith("arn:aws:"):
                parts = resource_id.split(":")
                if len(parts) >= 6:
                    resource_name = parts[5]
                    match = re.match(r"([a-z-]+)-(?:prod|staging|dev)", resource_name)
                    if match:
                        return match.group(1)

        return "unknown"

    def resolve_component_id(self, finding: Dict[str, Any]) -> str:
        """Resolve component ID from finding."""
        if self.mappings.get("components"):
            for comp_pattern in self.mappings["components"]:
                if self._matches_pattern(finding, comp_pattern):
                    return comp_pattern["component_id"]

        file_path = finding.get("file_path", "")
        if file_path:
            parts = file_path.split("/")
            if len(parts) >= 2:
                for part in parts:
                    if part.endswith("-service") or part.endswith("-api"):
                        return part
                    elif part in ["auth", "payment", "user", "order", "inventory"]:
                        return f"{part}-service"

        resource_id = finding.get("resource_id", "")
        if resource_id:
            if "/" in resource_id:
                namespace, name = resource_id.split("/", 1)
                return name.split("-")[0] if "-" in name else name

            if resource_id.startswith("arn:aws:"):
                parts = resource_id.split(":")
                if len(parts) >= 6:
                    resource_name = parts[5]
                    return resource_name.split("-")[0]

        package = finding.get("package", "")
        if package:
            return package.split("/")[0] if "/" in package else package.split(".")[0]

        return "unknown"

    def resolve_asset_id(self, finding: Dict[str, Any]) -> str:
        """Generate unique asset ID."""
        asset_key = finding.get("asset_key", "")
        if asset_key:
            return asset_key

        parts = []
        if finding.get("resource_id"):
            parts.append(finding["resource_id"])
        elif finding.get("file_path"):
            parts.append(finding["file_path"])
        elif finding.get("package"):
            parts.append(f"pkg:{finding['package']}")

        if finding.get("version"):
            parts.append(finding["version"])

        return ":".join(parts) if parts else "unknown"

    def normalize_rule_id(self, finding: Dict[str, Any]) -> str:
        """Normalize rule ID to CWE for cross-tool SAST deduplication.

        Maps tool-specific rule IDs to standard CWE identifiers to enable
        deduplication across different SAST tools (Semgrep, Checkov, etc.).

        Args:
            finding: Finding dictionary with rule_id and optionally cwe_id

        Returns:
            Normalized identifier (CWE ID if mappable, original rule_id otherwise)
        """
        # If finding already has a CWE ID, use it
        cwe_id = finding.get("cwe_id", "")
        if cwe_id and cwe_id.startswith("CWE-"):
            return cwe_id

        rule_id = finding.get("rule_id", "").lower()
        if not rule_id:
            return ""

        # Try exact match first
        if rule_id in CWE_RULE_MAPPINGS:
            return CWE_RULE_MAPPINGS[rule_id]

        # Try partial match (rule contains pattern)
        for pattern, cwe in CWE_RULE_MAPPINGS.items():
            if pattern in rule_id:
                return cwe

        # Return original rule_id if no mapping found
        return finding.get("rule_id", "")

    def normalize_control_id(self, finding: Dict[str, Any]) -> str:
        """Normalize control ID for cross-tool CSPM deduplication.

        Maps tool-specific policy IDs to standard control framework identifiers
        (CIS, NIST, etc.) to enable deduplication across different CSPM tools.

        Args:
            finding: Finding dictionary with rule_id or policy_id

        Returns:
            Normalized control ID (framework ID if mappable, original otherwise)
        """
        # Check for policy_id first, then rule_id
        policy_id = finding.get("policy_id", "") or finding.get("rule_id", "")
        if not policy_id:
            return ""

        # Try exact match
        if policy_id in CONTROL_ID_MAPPINGS:
            return CONTROL_ID_MAPPINGS[policy_id]

        # Try case-insensitive match
        policy_lower = policy_id.lower()
        for pattern, control in CONTROL_ID_MAPPINGS.items():
            if pattern.lower() == policy_lower:
                return control

        return policy_id

    def compute_correlation_key(self, finding: Dict[str, Any]) -> str:
        """Compute deterministic correlation key for cross-run matching.

        Uses normalized identifiers for cross-tool deduplication:
        - SAST findings: Uses CWE ID instead of tool-specific rule_id
        - CSPM findings: Uses control framework ID instead of tool-specific policy_id
        - SCA findings: Uses CVE ID + purl for universal matching
        """
        category = finding.get("category", "")

        # Determine the normalized rule/control identifier based on category
        if category in ("sast", "code", "secrets"):
            normalized_id = self.normalize_rule_id(finding)
        elif category in ("cspm", "iac", "cloud", "posture"):
            normalized_id = self.normalize_control_id(finding)
        else:
            # For SCA/other, use CVE ID or rule_id as-is
            normalized_id = finding.get("cve_id", "") or finding.get("rule_id", "")

        parts = [
            category,
            finding.get("cve_id", ""),
            normalized_id,
            finding.get("app_id", ""),
            finding.get("component_id", ""),
            self._normalize_location(finding),
        ]

        key_str = "|".join(p for p in parts if p)

        return hashlib.sha256(key_str.encode()).hexdigest()[:16]

    def compute_fingerprint(self, finding: Dict[str, Any]) -> str:
        """Compute content-based fingerprint for similarity matching."""
        parts = [
            finding.get("title", ""),
            finding.get("description", "")[:200],  # First 200 chars
            finding.get("cve_id", ""),
            finding.get("rule_id", ""),
        ]

        content = " ".join(p for p in parts if p)

        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def _matches_pattern(
        self, finding: Dict[str, Any], pattern: Dict[str, Any]
    ) -> bool:
        """Check if finding matches a pattern."""
        for key, value in pattern.get("match", {}).items():
            if key not in finding:
                return False
            if isinstance(value, str):
                if not re.search(value, str(finding[key])):
                    return False
            elif finding[key] != value:
                return False
        return True

    def _normalize_location(self, finding: Dict[str, Any]) -> str:
        """Normalize location for correlation."""
        if finding.get("file_path"):
            path = finding["file_path"]
            path = re.sub(r":\d+$", "", path)  # Remove trailing line numbers
            return path.replace("\\", "/")
        elif finding.get("resource_id"):
            return finding["resource_id"]
        elif finding.get("package"):
            return f"pkg:{finding['package']}"
        return ""
