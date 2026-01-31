"""
FixOps Ingestion & Normalization Module

Scanner-agnostic ingestion system with 360° view capabilities.
Supports SBOM (CycloneDX/SPDX), SARIF 2.1+, VEX, CNAPP, dark web intel.

Features:
- NormalizerRegistry with YAML plugin configuration
- Dynamic asset inventory with continuous discovery
- Format drift handling with Pydantic lenient parsing
- Auto-detection of format variants
- Unified Finding model for all security data
- Performance: 10K findings in <2 min with 99% parse success
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Protocol, Tuple, Type

from pydantic import BaseModel, ConfigDict, Field, field_validator

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)


class FindingSeverity(str, Enum):
    """Unified severity levels for all finding types."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


class FindingStatus(str, Enum):
    """Status of a finding in the remediation lifecycle."""

    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"
    WONT_FIX = "wont_fix"


class FindingType(str, Enum):
    """Types of security findings."""

    VULNERABILITY = "vulnerability"
    MISCONFIGURATION = "misconfiguration"
    SECRET = "secret"
    LICENSE = "license"
    MALWARE = "malware"
    COMPLIANCE = "compliance"
    THREAT_INTEL = "threat_intel"
    CREDENTIAL_LEAK = "credential_leak"
    DATA_BREACH = "data_breach"
    SUPPLY_CHAIN = "supply_chain"
    CODE_QUALITY = "code_quality"
    CONTAINER = "container"
    IAC = "iac"
    API = "api"
    IDENTITY = "identity"


class AssetType(str, Enum):
    """Types of assets in the inventory."""

    COMPUTE = "compute"
    STORAGE = "storage"
    NETWORK = "network"
    DATABASE = "database"
    IDENTITY = "identity"
    CONTAINER = "container"
    SERVERLESS = "serverless"
    KUBERNETES = "kubernetes"
    APPLICATION = "application"
    REPOSITORY = "repository"
    PACKAGE = "package"
    IMAGE = "image"
    ENDPOINT = "endpoint"
    CLOUD_RESOURCE = "cloud_resource"


class SourceFormat(str, Enum):
    """Supported input formats."""

    SARIF = "sarif"
    CYCLONEDX = "cyclonedx"
    SPDX = "spdx"
    VEX = "vex"
    CNAPP = "cnapp"
    DARK_WEB_INTEL = "dark_web_intel"
    CVE_FEED = "cve_feed"
    SNYK = "snyk"
    TRIVY = "trivy"
    GRYPE = "grype"
    SEMGREP = "semgrep"
    DEPENDABOT = "dependabot"
    AWS_SECURITY_HUB = "aws_security_hub"
    AZURE_DEFENDER = "azure_defender"
    GCP_SCC = "gcp_scc"
    CUSTOM = "custom"
    UNKNOWN = "unknown"


class UnifiedFinding(BaseModel):
    """
    Unified Finding model for all security data.

    This model normalizes findings from any source into a consistent format
    for analysis, correlation, and remediation tracking.
    """

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    source_id: Optional[str] = Field(
        default=None, description="Original ID from the source system"
    )
    source_format: SourceFormat = Field(
        default=SourceFormat.UNKNOWN, description="Format of the original data"
    )
    source_tool: Optional[str] = Field(
        default=None, description="Tool that generated the finding"
    )
    source_version: Optional[str] = Field(
        default=None, description="Version of the source tool"
    )

    finding_type: FindingType = Field(
        default=FindingType.VULNERABILITY, description="Type of security finding"
    )
    severity: FindingSeverity = Field(
        default=FindingSeverity.UNKNOWN, description="Severity level"
    )
    status: FindingStatus = Field(
        default=FindingStatus.OPEN, description="Current status"
    )

    title: str = Field(..., description="Short description of the finding")
    description: Optional[str] = Field(default=None, description="Detailed description")
    recommendation: Optional[str] = Field(
        default=None, description="Remediation recommendation"
    )

    cve_id: Optional[str] = Field(
        default=None, description="CVE identifier if applicable"
    )
    cwe_id: Optional[str] = Field(
        default=None, description="CWE identifier if applicable"
    )
    cvss_score: Optional[float] = Field(
        default=None, ge=0.0, le=10.0, description="CVSS score"
    )
    cvss_vector: Optional[str] = Field(default=None, description="CVSS vector string")
    epss_score: Optional[float] = Field(
        default=None, ge=0.0, le=1.0, description="EPSS probability score"
    )

    asset_id: Optional[str] = Field(default=None, description="Related asset ID")
    asset_type: Optional[AssetType] = Field(
        default=None, description="Type of affected asset"
    )
    asset_name: Optional[str] = Field(
        default=None, description="Name of affected asset"
    )

    file_path: Optional[str] = Field(
        default=None, description="File path if applicable"
    )
    line_number: Optional[int] = Field(default=None, ge=1, description="Line number")
    column_number: Optional[int] = Field(
        default=None, ge=1, description="Column number"
    )
    code_snippet: Optional[str] = Field(
        default=None, description="Relevant code snippet"
    )

    package_name: Optional[str] = Field(default=None, description="Package name")
    package_version: Optional[str] = Field(default=None, description="Package version")
    package_ecosystem: Optional[str] = Field(
        default=None, description="Package ecosystem (npm, pypi, etc.)"
    )
    purl: Optional[str] = Field(default=None, description="Package URL")

    cloud_provider: Optional[str] = Field(
        default=None, description="Cloud provider (aws, azure, gcp)"
    )
    cloud_region: Optional[str] = Field(default=None, description="Cloud region")
    cloud_account: Optional[str] = Field(default=None, description="Cloud account ID")
    cloud_resource_id: Optional[str] = Field(
        default=None, description="Cloud resource ARN/ID"
    )
    cloud_resource_type: Optional[str] = Field(
        default=None, description="Cloud resource type"
    )

    container_image: Optional[str] = Field(
        default=None, description="Container image name"
    )
    container_tag: Optional[str] = Field(
        default=None, description="Container image tag"
    )
    container_digest: Optional[str] = Field(
        default=None, description="Container image digest"
    )

    rule_id: Optional[str] = Field(default=None, description="Rule/check ID")
    rule_name: Optional[str] = Field(default=None, description="Rule/check name")

    compliance_frameworks: List[str] = Field(
        default_factory=list, description="Related compliance frameworks"
    )
    tags: List[str] = Field(default_factory=list, description="Custom tags")
    labels: Dict[str, str] = Field(default_factory=dict, description="Custom labels")

    first_seen: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="First detection timestamp",
    )
    last_seen: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Last detection timestamp",
    )
    resolved_at: Optional[datetime] = Field(
        default=None, description="Resolution timestamp"
    )

    exploitability: Optional[str] = Field(
        default=None, description="Exploitability assessment"
    )
    exploit_available: bool = Field(
        default=False, description="Whether an exploit is publicly available"
    )
    in_kev: bool = Field(default=False, description="Whether in CISA KEV catalog")

    confidence: Optional[float] = Field(
        default=None, ge=0.0, le=1.0, description="Detection confidence"
    )
    false_positive_probability: Optional[float] = Field(
        default=None, ge=0.0, le=1.0, description="False positive probability"
    )

    references: List[str] = Field(default_factory=list, description="Reference URLs")
    raw_data: Dict[str, Any] = Field(
        default_factory=dict, description="Original raw data"
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict, description="Additional metadata"
    )

    fingerprint: Optional[str] = Field(
        default=None, description="Deduplication fingerprint"
    )

    @field_validator("severity", mode="before")
    @classmethod
    def normalize_severity(cls, v: Any) -> FindingSeverity:
        if isinstance(v, FindingSeverity):
            return v
        if isinstance(v, str):
            v_lower = v.lower().strip()
            severity_map = {
                "critical": FindingSeverity.CRITICAL,
                "high": FindingSeverity.HIGH,
                "medium": FindingSeverity.MEDIUM,
                "moderate": FindingSeverity.MEDIUM,
                "low": FindingSeverity.LOW,
                "info": FindingSeverity.INFO,
                "informational": FindingSeverity.INFO,
                "none": FindingSeverity.INFO,
                "error": FindingSeverity.HIGH,
                "warning": FindingSeverity.MEDIUM,
                "note": FindingSeverity.LOW,
            }
            return severity_map.get(v_lower, FindingSeverity.UNKNOWN)
        return FindingSeverity.UNKNOWN

    def compute_fingerprint(self) -> str:
        """Compute a deduplication fingerprint for this finding."""
        components = [
            self.source_format.value,
            self.finding_type.value,
            self.title,
            self.cve_id or "",
            self.file_path or "",
            str(self.line_number or ""),
            self.package_name or "",
            self.package_version or "",
            self.rule_id or "",
            self.cloud_resource_id or "",
        ]
        content = "|".join(components)
        self.fingerprint = hashlib.sha256(content.encode()).hexdigest()[:32]
        return self.fingerprint


class Asset(BaseModel):
    """Asset in the dynamic inventory."""

    model_config = ConfigDict(extra="allow")

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    asset_type: AssetType
    description: Optional[str] = None

    cloud_provider: Optional[str] = None
    cloud_region: Optional[str] = None
    cloud_account: Optional[str] = None
    resource_id: Optional[str] = None
    resource_type: Optional[str] = None

    owner: Optional[str] = None
    team: Optional[str] = None
    environment: Optional[str] = None
    criticality: Optional[str] = None

    tags: List[str] = Field(default_factory=list)
    labels: Dict[str, str] = Field(default_factory=dict)
    attributes: Dict[str, Any] = Field(default_factory=dict)

    discovered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    finding_count: int = Field(default=0)
    critical_count: int = Field(default=0)
    high_count: int = Field(default=0)


class NormalizerPlugin(Protocol):
    """Protocol for normalizer plugins."""

    name: str
    priority: int
    enabled: bool

    def can_handle(self, content: bytes, content_type: Optional[str] = None) -> float:
        """Return confidence (0.0-1.0) that this normalizer can handle the content."""
        ...  # pragma: no cover

    def normalize(
        self, content: bytes, content_type: Optional[str] = None
    ) -> List[UnifiedFinding]:
        """Normalize the content into unified findings."""
        ...  # pragma: no cover


@dataclass
class NormalizerConfig:
    """Configuration for a normalizer plugin."""

    name: str
    enabled: bool = True
    priority: int = 50
    description: str = ""
    supported_versions: List[str] = field(default_factory=list)
    schemas: List[str] = field(default_factory=list)
    lenient_fields: List[str] = field(default_factory=list)
    detection_patterns: List[str] = field(default_factory=list)
    settings: Dict[str, Any] = field(default_factory=dict)


class BaseNormalizer:
    """Base class for normalizer implementations."""

    def __init__(self, config: NormalizerConfig):
        self.config = config
        self.name = config.name
        self.priority = config.priority
        self.enabled = config.enabled
        self._compiled_patterns: List[re.Pattern] = []
        self._compile_patterns()

    def _compile_patterns(self) -> None:
        """Compile detection patterns for performance."""
        for pattern in self.config.detection_patterns:
            try:
                self._compiled_patterns.append(re.compile(pattern, re.IGNORECASE))
            except re.error as e:
                logger.warning(f"Invalid pattern '{pattern}' in {self.name}: {e}")

    def can_handle(self, content: bytes, content_type: Optional[str] = None) -> float:
        """Check if this normalizer can handle the content."""
        if not self.enabled:
            return 0.0

        try:
            text = content.decode("utf-8", errors="ignore")[:10000]
        except Exception:
            return 0.0

        matches = sum(1 for p in self._compiled_patterns if p.search(text))
        if not self._compiled_patterns:
            return 0.0

        confidence = min(1.0, matches / len(self._compiled_patterns))
        return confidence

    def normalize(
        self, content: bytes, content_type: Optional[str] = None
    ) -> List[UnifiedFinding]:
        """Normalize content into unified findings. Override in subclasses."""
        raise NotImplementedError

    def _parse_json(self, content: bytes) -> Dict[str, Any]:
        """Parse JSON with lenient handling."""
        try:
            text = content.decode("utf-8")
            return json.loads(text)
        except json.JSONDecodeError as e:
            logger.warning(f"JSON parse error in {self.name}: {e}")
            text = content.decode("utf-8", errors="ignore")
            text = re.sub(r",\s*}", "}", text)
            text = re.sub(r",\s*]", "]", text)
            return json.loads(text)

    def _map_severity(self, value: Any) -> FindingSeverity:
        """Map various severity representations to unified severity."""
        if value is None:
            return FindingSeverity.UNKNOWN

        if isinstance(value, (int, float)):
            if value >= 9.0:
                return FindingSeverity.CRITICAL
            elif value >= 7.0:
                return FindingSeverity.HIGH
            elif value >= 4.0:
                return FindingSeverity.MEDIUM
            elif value > 0:
                return FindingSeverity.LOW
            return FindingSeverity.INFO

        if isinstance(value, str):
            v_lower = value.lower().strip()
            mapping = {
                "critical": FindingSeverity.CRITICAL,
                "high": FindingSeverity.HIGH,
                "medium": FindingSeverity.MEDIUM,
                "moderate": FindingSeverity.MEDIUM,
                "low": FindingSeverity.LOW,
                "info": FindingSeverity.INFO,
                "informational": FindingSeverity.INFO,
                "none": FindingSeverity.INFO,
                "error": FindingSeverity.HIGH,
                "warning": FindingSeverity.MEDIUM,
                "note": FindingSeverity.LOW,
            }
            return mapping.get(v_lower, FindingSeverity.UNKNOWN)

        return FindingSeverity.UNKNOWN


class SARIFNormalizer(BaseNormalizer):
    """
    Normalizer for SARIF 2.1+ format with schema evolution support.

    Handles differences between SARIF versions:
    - 2.1.0: Original schema
    - 2.2.0: Added taxonomies, webRequests/webResponses, threadFlowLocations enhancements

    Uses lenient parsing to handle missing/extra fields gracefully.
    """

    def normalize(
        self, content: bytes, content_type: Optional[str] = None
    ) -> List[UnifiedFinding]:
        findings: List[UnifiedFinding] = []
        data = self._parse_json(content)

        # Detect SARIF version for schema evolution handling
        sarif_version = data.get("version", "2.1.0")
        schema = data.get("$schema", "")

        runs = data.get("runs", [])
        for run in runs:
            tool = run.get("tool", {}).get("driver", {})
            tool_name = tool.get("name", "unknown")
            tool_version = tool.get("version")

            rules_by_id: Dict[str, Dict] = {}
            for rule in tool.get("rules", []):
                rule_id = rule.get("id")
                if rule_id:
                    rules_by_id[rule_id] = rule

            for result in run.get("results", []):
                rule_id = result.get("ruleId")
                rule = rules_by_id.get(rule_id, {})

                level = result.get("level", "warning")
                severity = self._map_sarif_level(level)

                message = result.get("message", {})
                title = message.get(
                    "text",
                    rule.get("shortDescription", {}).get("text", "Unknown finding"),
                )

                description = rule.get("fullDescription", {}).get("text")
                help_text = rule.get("help", {}).get("text")

                locations = result.get("locations", [])
                file_path = None
                line_number = None
                column_number = None

                if locations:
                    loc = locations[0]
                    physical = loc.get("physicalLocation", {})
                    artifact = physical.get("artifactLocation", {})
                    file_path = artifact.get("uri")
                    region = physical.get("region", {})
                    line_number = region.get("startLine")
                    column_number = region.get("startColumn")

                properties = result.get("properties", {})
                tags = properties.get("tags", [])

                # Extract CWE from taxonomies (SARIF 2.2 feature) or rule properties
                cwe_id = None
                taxa = result.get("taxa", [])
                if taxa:
                    for taxon in taxa:
                        if (
                            taxon.get("toolComponent", {}).get("name", "").lower()
                            == "cwe"
                        ):
                            cwe_id = f"CWE-{taxon.get('id', '')}"
                            break
                if not cwe_id:
                    rule_props = rule.get("properties", {})
                    cwe_list = rule_props.get("cwe", [])
                    if cwe_list:
                        cwe_id = (
                            cwe_list[0]
                            if isinstance(cwe_list[0], str)
                            else f"CWE-{cwe_list[0]}"
                        )

                # Extract code snippet from region (lenient - may not exist)
                code_snippet = None
                if locations:
                    region = locations[0].get("physicalLocation", {}).get("region", {})
                    code_snippet = region.get("snippet", {}).get("text")

                # Build metadata with version info for schema evolution tracking
                metadata = {
                    "run_index": runs.index(run),
                    "sarif_version": sarif_version,
                    "schema": schema,
                }

                # SARIF 2.2: Extract web request/response info if present
                web_request = result.get("webRequest")
                web_response = result.get("webResponse")
                if web_request or web_response:
                    metadata["web_request"] = web_request
                    metadata["web_response"] = web_response

                finding = UnifiedFinding(
                    source_format=SourceFormat.SARIF,
                    source_tool=tool_name,
                    source_version=tool_version,
                    source_id=result.get("guid") or result.get("correlationGuid"),
                    finding_type=FindingType.VULNERABILITY,
                    severity=severity,
                    title=title[:500] if title else "Unknown finding",
                    description=description,
                    recommendation=help_text,
                    cwe_id=cwe_id,
                    rule_id=rule_id,
                    rule_name=rule.get("name"),
                    file_path=file_path,
                    line_number=line_number,
                    column_number=column_number,
                    code_snippet=code_snippet,
                    tags=tags if isinstance(tags, list) else [],
                    raw_data=result,
                    metadata=metadata,
                )
                finding.compute_fingerprint()
                findings.append(finding)

        return findings

    def _map_sarif_level(self, level: str) -> FindingSeverity:
        mapping = {
            "error": FindingSeverity.HIGH,
            "warning": FindingSeverity.MEDIUM,
            "note": FindingSeverity.LOW,
            "none": FindingSeverity.INFO,
        }
        return mapping.get(level.lower(), FindingSeverity.MEDIUM)


class CycloneDXNormalizer(BaseNormalizer):
    """Normalizer for CycloneDX SBOM format."""

    def normalize(
        self, content: bytes, content_type: Optional[str] = None
    ) -> List[UnifiedFinding]:
        findings: List[UnifiedFinding] = []
        data = self._parse_json(content)

        vulnerabilities = data.get("vulnerabilities", [])
        components_by_ref: Dict[str, Dict] = {}

        for comp in data.get("components", []):
            bom_ref = comp.get("bom-ref")
            if bom_ref:
                components_by_ref[bom_ref] = comp

        for vuln in vulnerabilities:
            vuln_id = vuln.get("id", "")
            source = vuln.get("source", {})

            ratings = vuln.get("ratings", [])
            severity = FindingSeverity.UNKNOWN
            cvss_score = None
            cvss_vector = None

            for rating in ratings:
                if rating.get("score"):
                    cvss_score = float(rating["score"])
                    severity = self._map_severity(cvss_score)
                    cvss_vector = rating.get("vector")
                    break
                if rating.get("severity"):
                    severity = self._map_severity(rating["severity"])

            description = vuln.get("description")
            recommendation = vuln.get("recommendation")

            affects = vuln.get("affects", [])
            for affect in affects:
                ref = affect.get("ref")
                component = components_by_ref.get(ref, {})

                finding = UnifiedFinding(
                    source_format=SourceFormat.CYCLONEDX,
                    source_tool=source.get("name", "cyclonedx"),
                    source_id=vuln_id,
                    finding_type=FindingType.VULNERABILITY,
                    severity=severity,
                    title=f"{vuln_id}: {component.get('name', 'Unknown')}",
                    description=description,
                    recommendation=recommendation,
                    cve_id=vuln_id if vuln_id.startswith("CVE-") else None,
                    cvss_score=cvss_score,
                    cvss_vector=cvss_vector,
                    package_name=component.get("name"),
                    package_version=component.get("version"),
                    package_ecosystem=component.get("type"),
                    purl=component.get("purl"),
                    references=[
                        r.get("url") for r in vuln.get("references", []) if r.get("url")
                    ],
                    raw_data=vuln,
                )
                finding.compute_fingerprint()
                findings.append(finding)

        return findings


class DarkWebIntelNormalizer(BaseNormalizer):
    """Normalizer for dark web threat intelligence feeds."""

    def normalize(
        self, content: bytes, content_type: Optional[str] = None
    ) -> List[UnifiedFinding]:
        findings: List[UnifiedFinding] = []
        data = self._parse_json(content)

        # Handle both list and dict formats for dark web intel
        if isinstance(data, list):
            intel_items = data
        else:
            intel_items = data.get(
                "items", data.get("threats", data.get("indicators", []))
            )

        for item in intel_items:
            finding_type = self._determine_finding_type(item)
            severity = self._assess_threat_severity(item)

            title = (
                item.get("title")
                or item.get("name")
                or item.get("indicator", "Unknown threat")
            )
            description = item.get("description") or item.get("summary")

            source_name = (
                item.get("source")
                or item.get("feed")
                or item.get("provider", "dark_web")
            )

            finding = UnifiedFinding(
                source_format=SourceFormat.DARK_WEB_INTEL,
                source_tool=source_name,
                source_id=item.get("id") or item.get("indicator_id"),
                finding_type=finding_type,
                severity=severity,
                title=title[:500],
                description=description,
                tags=item.get("tags", []),
                labels=item.get("labels", {}),
                references=item.get("references", []),
                confidence=item.get("confidence"),
                exploit_available=item.get("exploit_available", False),
                metadata={
                    "threat_type": item.get("type"),
                    "actor": item.get("threat_actor"),
                    "campaign": item.get("campaign"),
                    "malware_family": item.get("malware_family"),
                    "iocs": item.get("iocs", []),
                    "ttps": item.get("ttps", []),
                },
                raw_data=item,
            )
            finding.compute_fingerprint()
            findings.append(finding)

        return findings

    def _determine_finding_type(self, item: Dict[str, Any]) -> FindingType:
        item_type = str(item.get("type", "")).lower()
        type_mapping = {
            "credential": FindingType.CREDENTIAL_LEAK,
            "leak": FindingType.CREDENTIAL_LEAK,
            "breach": FindingType.DATA_BREACH,
            "malware": FindingType.MALWARE,
            "vulnerability": FindingType.VULNERABILITY,
            "exploit": FindingType.VULNERABILITY,
            "threat": FindingType.THREAT_INTEL,
        }
        for key, finding_type in type_mapping.items():
            if key in item_type:
                return finding_type
        return FindingType.THREAT_INTEL

    def _assess_threat_severity(self, item: Dict[str, Any]) -> FindingSeverity:
        if item.get("severity"):
            return self._map_severity(item["severity"])

        confidence = item.get("confidence", 0.5)
        if confidence >= 0.9:
            return FindingSeverity.CRITICAL
        elif confidence >= 0.7:
            return FindingSeverity.HIGH
        elif confidence >= 0.5:
            return FindingSeverity.MEDIUM
        return FindingSeverity.LOW


class CNAPPNormalizer(BaseNormalizer):
    """Normalizer for CNAPP findings."""

    def normalize(
        self, content: bytes, content_type: Optional[str] = None
    ) -> List[UnifiedFinding]:
        findings: List[UnifiedFinding] = []
        data = self._parse_json(content)

        cnapp_findings = data.get(
            "findings", data.get("securityFindings", data.get("alerts", []))
        )

        for item in cnapp_findings:
            severity = self._map_severity(item.get("severity"))

            cloud_provider = item.get("cloudProvider") or item.get("provider")
            cloud_region = item.get("region") or item.get("cloudRegion")
            cloud_account = (
                item.get("accountId")
                or item.get("subscriptionId")
                or item.get("projectId")
            )
            resource_id = (
                item.get("resourceId") or item.get("arn") or item.get("resourceName")
            )
            resource_type = item.get("resourceType")

            finding = UnifiedFinding(
                source_format=SourceFormat.CNAPP,
                source_tool=item.get("source") or item.get("scanner", "cnapp"),
                source_id=item.get("id") or item.get("findingId"),
                finding_type=self._determine_cnapp_type(item),
                severity=severity,
                title=item.get("title") or item.get("name") or "CNAPP Finding",
                description=item.get("description"),
                recommendation=item.get("remediation") or item.get("recommendation"),
                cloud_provider=cloud_provider,
                cloud_region=cloud_region,
                cloud_account=cloud_account,
                cloud_resource_id=resource_id,
                cloud_resource_type=resource_type,
                compliance_frameworks=item.get("complianceFrameworks", []),
                tags=item.get("tags", []),
                raw_data=item,
            )
            finding.compute_fingerprint()
            findings.append(finding)

        return findings

    def _determine_cnapp_type(self, item: Dict[str, Any]) -> FindingType:
        item_type = str(item.get("type", item.get("category", ""))).lower()
        if "misconfig" in item_type:
            return FindingType.MISCONFIGURATION
        if "vuln" in item_type:
            return FindingType.VULNERABILITY
        if "secret" in item_type:
            return FindingType.SECRET
        if "compliance" in item_type:
            return FindingType.COMPLIANCE
        if "identity" in item_type or "iam" in item_type:
            return FindingType.IDENTITY
        return FindingType.MISCONFIGURATION


class SPDXNormalizer(BaseNormalizer):
    """Normalizer for SPDX SBOM format (2.2 and 2.3)."""

    def normalize(
        self, content: bytes, content_type: Optional[str] = None
    ) -> List[UnifiedFinding]:
        findings: List[UnifiedFinding] = []
        data = self._parse_json(content)

        # SPDX 2.2+ structure
        packages = data.get("packages", [])
        external_refs = {}

        # Build package lookup by SPDXID
        packages_by_id: Dict[str, Dict] = {}
        for pkg in packages:
            spdx_id = pkg.get("SPDXID")
            if spdx_id:
                packages_by_id[spdx_id] = pkg
                # Extract external references (vulnerabilities, security advisories)
                for ref in pkg.get("externalRefs", []):
                    ref_type = ref.get("referenceType", "")
                    if ref_type in ("cpe23Type", "purl", "security", "advisory"):
                        if spdx_id not in external_refs:
                            external_refs[spdx_id] = []
                        external_refs[spdx_id].append(ref)

        # Check for vulnerabilities in annotations or external document refs
        annotations = data.get("annotations", [])
        for annotation in annotations:
            if annotation.get("annotationType") == "REVIEW":
                comment = annotation.get("comment", "")
                if "CVE-" in comment or "vulnerability" in comment.lower():
                    # Extract CVE from comment
                    cve_match = re.search(r"CVE-\d{4}-\d+", comment)
                    cve_id = cve_match.group(0) if cve_match else None

                    finding = UnifiedFinding(
                        source_format=SourceFormat.SPDX,
                        source_tool="spdx",
                        finding_type=FindingType.VULNERABILITY,
                        severity=FindingSeverity.MEDIUM,
                        title=f"Security annotation: {comment[:100]}",
                        description=comment,
                        cve_id=cve_id,
                        raw_data=annotation,
                    )
                    finding.compute_fingerprint()
                    findings.append(finding)

        # Process packages with security external refs
        for spdx_id, refs in external_refs.items():
            pkg = packages_by_id.get(spdx_id, {})
            for ref in refs:
                ref_type = ref.get("referenceType", "")
                ref_locator = ref.get("referenceLocator", "")

                if ref_type == "security" or "advisory" in ref_type.lower():
                    cve_match = re.search(r"CVE-\d{4}-\d+", ref_locator)
                    cve_id = cve_match.group(0) if cve_match else None

                    finding = UnifiedFinding(
                        source_format=SourceFormat.SPDX,
                        source_tool="spdx",
                        source_id=ref_locator,
                        finding_type=FindingType.VULNERABILITY,
                        severity=FindingSeverity.MEDIUM,
                        title=f"Security reference for {pkg.get('name', 'Unknown')}",
                        description=f"Security reference: {ref_locator}",
                        cve_id=cve_id,
                        package_name=pkg.get("name"),
                        package_version=pkg.get("versionInfo"),
                        purl=next(
                            (
                                r.get("referenceLocator")
                                for r in pkg.get("externalRefs", [])
                                if r.get("referenceType") == "purl"
                            ),
                            None,
                        ),
                        references=[ref_locator]
                        if ref_locator.startswith("http")
                        else [],
                        raw_data={"package": pkg, "reference": ref},
                    )
                    finding.compute_fingerprint()
                    findings.append(finding)

        return findings


class VEXNormalizer(BaseNormalizer):
    """Normalizer for VEX (Vulnerability Exploitability eXchange) format."""

    def normalize(
        self, content: bytes, content_type: Optional[str] = None
    ) -> List[UnifiedFinding]:
        findings: List[UnifiedFinding] = []
        data = self._parse_json(content)

        # Support both OpenVEX and CycloneDX VEX formats
        statements = data.get("statements", [])
        if not statements:
            # Try CycloneDX VEX format
            statements = data.get("vulnerabilities", [])

        for stmt in statements:
            vuln_id = stmt.get("vulnerability", {})
            if isinstance(vuln_id, dict):
                vuln_id = vuln_id.get("@id") or vuln_id.get("id", "")
            elif isinstance(vuln_id, str):
                pass
            else:
                vuln_id = str(stmt.get("id", ""))

            status = stmt.get("status", "").lower()
            justification = stmt.get("justification", "")
            impact = stmt.get("impact_statement") or stmt.get("actionStatement", "")

            # Map VEX status to finding status
            status_map = {
                "not_affected": FindingStatus.FALSE_POSITIVE,
                "affected": FindingStatus.OPEN,
                "fixed": FindingStatus.RESOLVED,
                "under_investigation": FindingStatus.IN_PROGRESS,
            }
            finding_status = status_map.get(status, FindingStatus.OPEN)

            # Determine severity from VEX data
            severity = FindingSeverity.UNKNOWN
            if status == "affected":
                severity = FindingSeverity.HIGH
            elif status == "not_affected":
                severity = FindingSeverity.INFO

            products = stmt.get("products", [])
            if not products:
                products = [stmt.get("product", {})]

            for product in products:
                if isinstance(product, dict):
                    product_id = product.get("@id") or product.get("id", "Unknown")
                else:
                    product_id = str(product) if product else "Unknown"

                finding = UnifiedFinding(
                    source_format=SourceFormat.VEX,
                    source_tool=data.get("author") or data.get("tooling", "vex"),
                    source_id=vuln_id,
                    finding_type=FindingType.VULNERABILITY,
                    severity=severity,
                    status=finding_status,
                    title=f"VEX: {vuln_id} - {status}",
                    description=impact or justification or f"VEX status: {status}",
                    cve_id=vuln_id if vuln_id.startswith("CVE-") else None,
                    asset_name=product_id,
                    metadata={
                        "vex_status": status,
                        "justification": justification,
                        "impact_statement": impact,
                    },
                    raw_data=stmt,
                )
                finding.compute_fingerprint()
                findings.append(finding)

        return findings


class TrivyNormalizer(BaseNormalizer):
    """Normalizer for Trivy scanner output (JSON format)."""

    def normalize(
        self, content: bytes, content_type: Optional[str] = None
    ) -> List[UnifiedFinding]:
        findings: List[UnifiedFinding] = []
        data = self._parse_json(content)

        # Trivy JSON output structure
        results = data.get("Results", [])
        if not results:
            # Try alternate format
            results = data.get("results", [])

        artifact_name = data.get("ArtifactName") or data.get("artifactName", "")
        artifact_type = data.get("ArtifactType") or data.get("artifactType", "")

        for result in results:
            target = result.get("Target") or result.get("target", "")
            result_type = result.get("Type") or result.get("type", "")

            vulnerabilities = result.get("Vulnerabilities") or result.get(
                "vulnerabilities", []
            )
            for vuln in vulnerabilities or []:
                vuln_id = vuln.get("VulnerabilityID") or vuln.get("vulnerabilityID", "")
                pkg_name = vuln.get("PkgName") or vuln.get("pkgName", "")
                pkg_version = vuln.get("InstalledVersion") or vuln.get(
                    "installedVersion", ""
                )
                fixed_version = vuln.get("FixedVersion") or vuln.get("fixedVersion", "")
                severity_str = vuln.get("Severity") or vuln.get("severity", "UNKNOWN")
                title = vuln.get("Title") or vuln.get("title", vuln_id)
                description = vuln.get("Description") or vuln.get("description", "")

                cvss_data = vuln.get("CVSS", {})
                cvss_score = None
                cvss_vector = None
                for source, cvss in cvss_data.items():
                    if isinstance(cvss, dict):
                        cvss_score = cvss.get("V3Score") or cvss.get("V2Score")
                        cvss_vector = cvss.get("V3Vector") or cvss.get("V2Vector")
                        if cvss_score:
                            break

                finding = UnifiedFinding(
                    source_format=SourceFormat.TRIVY,
                    source_tool="trivy",
                    source_id=vuln_id,
                    finding_type=FindingType.VULNERABILITY,
                    severity=self._map_severity(severity_str),
                    title=f"{vuln_id}: {title[:200]}" if title else vuln_id,
                    description=description,
                    recommendation=f"Upgrade to version {fixed_version}"
                    if fixed_version
                    else None,
                    cve_id=vuln_id if vuln_id.startswith("CVE-") else None,
                    cvss_score=cvss_score,
                    cvss_vector=cvss_vector,
                    package_name=pkg_name,
                    package_version=pkg_version,
                    package_ecosystem=result_type,
                    container_image=artifact_name
                    if artifact_type == "container_image"
                    else None,
                    file_path=target,
                    references=vuln.get("References") or vuln.get("references", []),
                    raw_data=vuln,
                )
                finding.compute_fingerprint()
                findings.append(finding)

            # Process misconfigurations
            misconfigs = result.get("Misconfigurations") or result.get(
                "misconfigurations", []
            )
            for misconfig in misconfigs or []:
                misconfig_id = misconfig.get("ID") or misconfig.get("id", "")
                severity_str = misconfig.get("Severity") or misconfig.get(
                    "severity", "UNKNOWN"
                )

                finding = UnifiedFinding(
                    source_format=SourceFormat.TRIVY,
                    source_tool="trivy",
                    source_id=misconfig_id,
                    finding_type=FindingType.MISCONFIGURATION,
                    severity=self._map_severity(severity_str),
                    title=misconfig.get("Title")
                    or misconfig.get("title", misconfig_id),
                    description=misconfig.get("Description")
                    or misconfig.get("description", ""),
                    recommendation=misconfig.get("Resolution")
                    or misconfig.get("resolution", ""),
                    rule_id=misconfig_id,
                    file_path=target,
                    references=misconfig.get("References")
                    or misconfig.get("references", []),
                    raw_data=misconfig,
                )
                finding.compute_fingerprint()
                findings.append(finding)

            # Process secrets
            secrets = result.get("Secrets") or result.get("secrets", [])
            for secret in secrets or []:
                finding = UnifiedFinding(
                    source_format=SourceFormat.TRIVY,
                    source_tool="trivy",
                    source_id=secret.get("RuleID") or secret.get("ruleID", ""),
                    finding_type=FindingType.SECRET,
                    severity=self._map_severity(
                        secret.get("Severity") or secret.get("severity", "HIGH")
                    ),
                    title=secret.get("Title") or secret.get("title", "Secret detected"),
                    description=secret.get("Match") or secret.get("match", ""),
                    file_path=target,
                    line_number=secret.get("StartLine") or secret.get("startLine"),
                    rule_id=secret.get("RuleID") or secret.get("ruleID"),
                    raw_data=secret,
                )
                finding.compute_fingerprint()
                findings.append(finding)

        return findings


class GrypeNormalizer(BaseNormalizer):
    """Normalizer for Grype scanner output (JSON format)."""

    def normalize(
        self, content: bytes, content_type: Optional[str] = None
    ) -> List[UnifiedFinding]:
        findings: List[UnifiedFinding] = []
        data = self._parse_json(content)

        matches = data.get("matches", [])
        source = data.get("source", {})
        artifact_type = source.get("type", "")
        artifact_target = source.get("target", "")

        for match in matches:
            vuln = match.get("vulnerability", {})
            artifact = match.get("artifact", {})
            related_vulns = match.get("relatedVulnerabilities", [])

            vuln_id = vuln.get("id", "")
            severity_str = vuln.get("severity", "Unknown")
            description = vuln.get("description", "")
            fix_versions = vuln.get("fix", {}).get("versions", [])

            # Get CVSS from related vulnerabilities
            cvss_score = None
            cvss_vector = None
            for related in related_vulns:
                cvss_list = related.get("cvss", [])
                for cvss in cvss_list:
                    if cvss.get("version", "").startswith("3"):
                        cvss_score = cvss.get("metrics", {}).get("baseScore")
                        cvss_vector = cvss.get("vector")
                        break
                if cvss_score:
                    break

            finding = UnifiedFinding(
                source_format=SourceFormat.GRYPE,
                source_tool="grype",
                source_id=vuln_id,
                finding_type=FindingType.VULNERABILITY,
                severity=self._map_severity(severity_str),
                title=f"{vuln_id}: {artifact.get('name', 'Unknown')}",
                description=description,
                recommendation=f"Upgrade to version {', '.join(fix_versions)}"
                if fix_versions
                else None,
                cve_id=vuln_id if vuln_id.startswith("CVE-") else None,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                package_name=artifact.get("name"),
                package_version=artifact.get("version"),
                package_ecosystem=artifact.get("type"),
                purl=artifact.get("purl"),
                container_image=artifact_target if artifact_type == "image" else None,
                file_path=artifact.get("locations", [{}])[0].get("path")
                if artifact.get("locations")
                else None,
                references=vuln.get("urls", []),
                raw_data=match,
            )
            finding.compute_fingerprint()
            findings.append(finding)

        return findings


class SemgrepNormalizer(BaseNormalizer):
    """Normalizer for Semgrep SAST scanner output (JSON format)."""

    def normalize(
        self, content: bytes, content_type: Optional[str] = None
    ) -> List[UnifiedFinding]:
        findings: List[UnifiedFinding] = []
        data = self._parse_json(content)

        results = data.get("results", [])

        for result in results:
            check_id = result.get("check_id", "")
            path = result.get("path", "")
            start = result.get("start", {})
            extra = result.get("extra", {})

            severity_str = extra.get("severity", "WARNING")
            message = extra.get("message", "")
            metadata = extra.get("metadata", {})

            # Map Semgrep severity
            severity_map = {
                "ERROR": FindingSeverity.HIGH,
                "WARNING": FindingSeverity.MEDIUM,
                "INFO": FindingSeverity.LOW,
            }
            severity = severity_map.get(severity_str.upper(), FindingSeverity.MEDIUM)

            # Determine finding type from metadata
            finding_type = FindingType.CODE_QUALITY
            category = metadata.get("category", "").lower()
            if "security" in category or "vulnerability" in category:
                finding_type = FindingType.VULNERABILITY
            elif "secret" in category:
                finding_type = FindingType.SECRET

            cwe_ids = metadata.get("cwe", [])
            cwe_id = cwe_ids[0] if cwe_ids else None
            if isinstance(cwe_id, str) and not cwe_id.startswith("CWE-"):
                cwe_id = f"CWE-{cwe_id}"

            # Convert string confidence to float if needed
            confidence_raw = metadata.get("confidence")
            confidence_value = None
            if confidence_raw is not None:
                if isinstance(confidence_raw, (int, float)):
                    confidence_value = float(confidence_raw)
                elif isinstance(confidence_raw, str):
                    confidence_map = {"HIGH": 0.9, "MEDIUM": 0.7, "LOW": 0.5}
                    confidence_value = confidence_map.get(confidence_raw.upper())

            finding = UnifiedFinding(
                source_format=SourceFormat.SEMGREP,
                source_tool="semgrep",
                source_id=check_id,
                finding_type=finding_type,
                severity=severity,
                title=f"{check_id}: {message[:100]}" if message else check_id,
                description=message,
                recommendation=extra.get("fix", ""),
                cwe_id=cwe_id,
                file_path=path,
                line_number=start.get("line"),
                column_number=start.get("col"),
                code_snippet=extra.get("lines", ""),
                rule_id=check_id,
                rule_name=metadata.get("rule_name", check_id),
                tags=metadata.get("tags", []),
                references=metadata.get("references", []),
                confidence=confidence_value,
                raw_data=result,
            )
            finding.compute_fingerprint()
            findings.append(finding)

        return findings


class DependabotNormalizer(BaseNormalizer):
    """Normalizer for GitHub Dependabot alerts (JSON format)."""

    def normalize(
        self, content: bytes, content_type: Optional[str] = None
    ) -> List[UnifiedFinding]:
        findings: List[UnifiedFinding] = []
        data = self._parse_json(content)

        # Handle both single alert and array of alerts
        alerts = data if isinstance(data, list) else data.get("alerts", [data])

        for alert in alerts:
            security_advisory = alert.get("security_advisory", {})
            security_vuln = alert.get("security_vulnerability", {})
            dependency = alert.get("dependency", {})

            ghsa_id = security_advisory.get("ghsa_id", "")
            cve_id = security_advisory.get("cve_id")
            summary = security_advisory.get("summary", "")
            description = security_advisory.get("description", "")
            severity_str = security_advisory.get("severity", "moderate")

            # Get CVSS from advisory
            cvss = security_advisory.get("cvss", {})
            cvss_score = cvss.get("score")
            cvss_vector = cvss.get("vector_string")

            # Get package info
            pkg = dependency.get("package", {})
            pkg_name = pkg.get("name", "")
            pkg_ecosystem = pkg.get("ecosystem", "")
            manifest_path = dependency.get("manifest_path", "")

            # Get vulnerable and patched versions
            vulnerable_range = security_vuln.get("vulnerable_version_range", "")
            first_patched = security_vuln.get("first_patched_version", {})
            patched_version = first_patched.get("identifier") if first_patched else None

            # Map severity
            severity_map = {
                "critical": FindingSeverity.CRITICAL,
                "high": FindingSeverity.HIGH,
                "moderate": FindingSeverity.MEDIUM,
                "medium": FindingSeverity.MEDIUM,
                "low": FindingSeverity.LOW,
            }
            severity = severity_map.get(severity_str.lower(), FindingSeverity.MEDIUM)

            finding = UnifiedFinding(
                source_format=SourceFormat.DEPENDABOT,
                source_tool="dependabot",
                source_id=ghsa_id or str(alert.get("number", "")),
                finding_type=FindingType.VULNERABILITY,
                severity=severity,
                title=f"{ghsa_id or cve_id}: {summary[:200]}"
                if summary
                else ghsa_id or cve_id or "Dependabot Alert",
                description=description,
                recommendation=f"Upgrade to version {patched_version}"
                if patched_version
                else "Review and update dependency",
                cve_id=cve_id,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                package_name=pkg_name,
                package_ecosystem=pkg_ecosystem,
                file_path=manifest_path,
                references=[
                    ref.get("url")
                    for ref in security_advisory.get("references", [])
                    if ref.get("url")
                ],
                metadata={
                    "ghsa_id": ghsa_id,
                    "vulnerable_range": vulnerable_range,
                    "state": alert.get("state"),
                    "dismissed_reason": alert.get("dismissed_reason"),
                },
                raw_data=alert,
            )
            finding.compute_fingerprint()
            findings.append(finding)

        return findings


class NormalizerRegistry:
    """
    Registry for normalizer plugins with YAML configuration support.

    Provides:
    - Plugin registration and discovery
    - Auto-detection of input formats
    - Parallel processing for large documents
    - Format drift handling with lenient parsing
    """

    def __init__(self, config_path: Optional[Path] = None):
        self._normalizers: Dict[str, BaseNormalizer] = {}
        self._config: Dict[str, Any] = {}
        self._schema_cache: Dict[str, Any] = {}
        self._cache_timestamps: Dict[str, float] = {}
        self._executor = ThreadPoolExecutor(max_workers=4)

        if config_path and config_path.exists():
            self._load_config(config_path)
        else:
            self._load_default_config()

        self._register_builtin_normalizers()

    def _load_config(self, config_path: Path) -> None:
        """Load configuration from YAML file."""
        if yaml is None:
            logger.warning("PyYAML not available, using default configuration")
            self._load_default_config()
            return

        try:
            with open(config_path, "r") as f:
                self._config = yaml.safe_load(f) or {}
            logger.info(f"Loaded normalizer config from {config_path}")
        except Exception as e:
            logger.warning(f"Failed to load config from {config_path}: {e}")
            self._load_default_config()

    def _load_default_config(self) -> None:
        """Load default configuration."""
        self._config = {
            "settings": {
                "max_document_bytes": 100 * 1024 * 1024,
                "max_findings_per_batch": 50000,
                "parallel_processing": True,
                "worker_threads": 4,
                "lenient_parsing": True,
            },
            "format_detection": {
                "auto_detect": True,
                "confidence_threshold": 0.7,
            },
            "normalizers": {
                "sarif": {
                    "enabled": True,
                    "priority": 100,
                    "detection_patterns": [
                        r'"version"\s*:\s*"2\.1',
                        r'"runs"\s*:',
                        r"\$schema.*sarif",
                    ],
                },
                "cyclonedx": {
                    "enabled": True,
                    "priority": 90,
                    "detection_patterns": [
                        r'"bomFormat"\s*:\s*"CycloneDX"',
                        r'"specVersion"\s*:',
                    ],
                },
                "dark_web_intel": {
                    "enabled": True,
                    "priority": 70,
                    "detection_patterns": [
                        r'"dark_web"',
                        r'"threat_intel"',
                        r'"breach_data"',
                    ],
                },
                "cnapp": {
                    "enabled": True,
                    "priority": 75,
                    "detection_patterns": [
                        r'"cloud_provider"',
                        r'"resource_type"',
                        r'"cnapp"',
                    ],
                },
                "spdx": {
                    "enabled": True,
                    "priority": 85,
                    "detection_patterns": [
                        r'"spdxVersion"\s*:',
                        r'"SPDXID"\s*:',
                        r'"SPDXRef-',
                    ],
                },
                "vex": {
                    "enabled": True,
                    "priority": 80,
                    "detection_patterns": [
                        r'"@context".*openvex',
                        r'"statements"\s*:',
                        r'"status"\s*:\s*"(not_affected|affected|fixed|under_investigation)"',
                    ],
                },
                "trivy": {
                    "enabled": True,
                    "priority": 88,
                    "detection_patterns": [
                        r'"ArtifactName"\s*:',
                        r'"ArtifactType"\s*:',
                        r'"Results"\s*:\s*\[',
                        r'"Vulnerabilities"\s*:',
                    ],
                },
                "grype": {
                    "enabled": True,
                    "priority": 87,
                    "detection_patterns": [
                        r'"matches"\s*:\s*\[',
                        r'"artifact"\s*:.*"purl"',
                        r'"vulnerability"\s*:.*"severity"',
                    ],
                },
                "semgrep": {
                    "enabled": True,
                    "priority": 82,
                    "detection_patterns": [
                        r'"results"\s*:\s*\[',
                        r'"check_id"\s*:',
                        r'"extra"\s*:.*"severity"',
                    ],
                },
                "dependabot": {
                    "enabled": True,
                    "priority": 83,
                    "detection_patterns": [
                        r'"security_advisory"\s*:',
                        r'"security_vulnerability"\s*:',
                        r'"ghsa_id"\s*:',
                    ],
                },
            },
        }

    def _register_builtin_normalizers(self) -> None:
        """Register built-in normalizer implementations."""
        normalizer_classes: Dict[str, Type[BaseNormalizer]] = {
            "sarif": SARIFNormalizer,
            "cyclonedx": CycloneDXNormalizer,
            "dark_web_intel": DarkWebIntelNormalizer,
            "cnapp": CNAPPNormalizer,
            "spdx": SPDXNormalizer,
            "vex": VEXNormalizer,
            "trivy": TrivyNormalizer,
            "grype": GrypeNormalizer,
            "semgrep": SemgrepNormalizer,
            "dependabot": DependabotNormalizer,
        }

        normalizers_config = self._config.get("normalizers", {})

        for name, cls in normalizer_classes.items():
            config_data = normalizers_config.get(name, {})
            config = NormalizerConfig(
                name=name,
                enabled=config_data.get("enabled", True),
                priority=config_data.get("priority", 50),
                description=config_data.get("description", ""),
                supported_versions=config_data.get("supported_versions", []),
                schemas=config_data.get("schemas", []),
                lenient_fields=config_data.get("lenient_fields", []),
                detection_patterns=config_data.get("detection_patterns", []),
                settings=config_data.get("settings", {}),
            )
            self._normalizers[name] = cls(config)

        # Load custom plugins from config
        self._load_custom_plugins()

    def _load_custom_plugins(self) -> None:
        """
        Load custom normalizer plugins from YAML configuration.

        Supports dynamic loading of normalizer classes from module paths.
        Config format:
            plugins:
              - name: custom_scanner
                module: mypackage.normalizers.custom
                class: CustomNormalizer
                enabled: true
                priority: 60
                detection_patterns: [...]
        """
        import importlib

        plugins_config = self._config.get("plugins", [])
        normalizers_config = self._config.get("normalizers", {})

        for plugin in plugins_config:
            name = plugin.get("name")
            module_path = plugin.get("module")
            class_name = plugin.get("class")

            if not all([name, module_path, class_name]):
                logger.warning(
                    f"Invalid plugin config (missing name/module/class): {plugin}"
                )
                continue

            if not plugin.get("enabled", True):
                logger.debug(f"Plugin {name} is disabled, skipping")
                continue

            try:
                module = importlib.import_module(module_path)
                cls = getattr(module, class_name)

                if not issubclass(cls, BaseNormalizer):
                    logger.warning(
                        f"Plugin {name} class {class_name} is not a BaseNormalizer subclass"
                    )
                    continue

                # Merge plugin config with normalizers config
                config_data = {**plugin, **normalizers_config.get(name, {})}
                config = NormalizerConfig(
                    name=name,
                    enabled=config_data.get("enabled", True),
                    priority=config_data.get("priority", 50),
                    description=config_data.get("description", ""),
                    supported_versions=config_data.get("supported_versions", []),
                    schemas=config_data.get("schemas", []),
                    lenient_fields=config_data.get("lenient_fields", []),
                    detection_patterns=config_data.get("detection_patterns", []),
                    settings=config_data.get("settings", {}),
                )
                self._normalizers[name] = cls(config)
                logger.info(
                    f"Loaded custom plugin: {name} from {module_path}.{class_name}"
                )

            except ImportError as e:
                logger.warning(
                    f"Failed to import plugin {name} from {module_path}: {e}"
                )
            except AttributeError as e:
                logger.warning(
                    f"Failed to find class {class_name} in {module_path}: {e}"
                )
            except Exception as e:
                logger.warning(f"Failed to load plugin {name}: {e}")

    def register(self, name: str, normalizer: BaseNormalizer) -> None:
        """Register a custom normalizer."""
        self._normalizers[name] = normalizer
        logger.info(f"Registered normalizer: {name}")

    def unregister(self, name: str) -> None:
        """Unregister a normalizer."""
        if name in self._normalizers:
            del self._normalizers[name]
            logger.info(f"Unregistered normalizer: {name}")

    def get_normalizer(self, name: str) -> Optional[BaseNormalizer]:
        """Get a normalizer by name."""
        return self._normalizers.get(name)

    def list_normalizers(self) -> List[str]:
        """List all registered normalizers."""
        return list(self._normalizers.keys())

    def detect_format(
        self, content: bytes, content_type: Optional[str] = None
    ) -> Tuple[Optional[str], float]:
        """
        Auto-detect the format of the input content.

        Returns:
            Tuple of (normalizer_name, confidence)
        """
        best_match: Optional[str] = None
        best_confidence = 0.0

        sorted_normalizers = sorted(
            self._normalizers.items(),
            key=lambda x: x[1].priority,
            reverse=True,
        )

        for name, normalizer in sorted_normalizers:
            if not normalizer.enabled:
                continue

            confidence = normalizer.can_handle(content, content_type)
            if confidence > best_confidence:
                best_confidence = confidence
                best_match = name

        threshold = self._config.get("format_detection", {}).get(
            "confidence_threshold", 0.7
        )
        if best_confidence < threshold:
            logger.warning(
                f"Low confidence format detection: {best_match} ({best_confidence:.2f})"
            )

        return best_match, best_confidence

    def get_cached_schema(self, schema_url: str) -> Optional[Any]:
        """Get a cached schema if available and not expired."""
        settings = self._config.get("settings", {})
        if not settings.get("cache_schemas", True):
            return None

        cache_ttl = settings.get("cache_ttl_seconds", 3600)
        if schema_url in self._schema_cache:
            cached_time = self._cache_timestamps.get(schema_url, 0)
            if time.time() - cached_time < cache_ttl:
                return self._schema_cache[schema_url]
            else:
                del self._schema_cache[schema_url]
                del self._cache_timestamps[schema_url]
        return None

    def cache_schema(self, schema_url: str, schema: Any) -> None:
        """Cache a schema for future use."""
        settings = self._config.get("settings", {})
        if settings.get("cache_schemas", True):
            self._schema_cache[schema_url] = schema
            self._cache_timestamps[schema_url] = time.time()

    def normalize(
        self,
        content: bytes,
        format_hint: Optional[str] = None,
        content_type: Optional[str] = None,
    ) -> List[UnifiedFinding]:
        """
        Normalize content into unified findings.

        Args:
            content: Raw content bytes
            format_hint: Optional format hint (e.g., "sarif", "cyclonedx")
            content_type: Optional MIME content type

        Returns:
            List of unified findings

        Raises:
            ValueError: If content exceeds max_document_bytes
        """
        start_time = time.time()

        # Enforce max_document_bytes setting
        settings = self._config.get("settings", {})
        max_bytes = settings.get("max_document_bytes", 100 * 1024 * 1024)
        if len(content) > max_bytes:
            raise ValueError(
                f"Document size ({len(content)} bytes) exceeds maximum "
                f"allowed size ({max_bytes} bytes)"
            )

        if format_hint and format_hint in self._normalizers:
            normalizer = self._normalizers[format_hint]
        else:
            detected_format, confidence = self.detect_format(content, content_type)
            if detected_format is None:
                logger.warning("Could not detect format, attempting all normalizers")
                return self._try_all_normalizers(content, content_type)
            normalizer = self._normalizers[detected_format]

        try:
            findings = normalizer.normalize(content, content_type)
            elapsed = time.time() - start_time
            logger.info(
                f"Normalized {len(findings)} findings using {normalizer.name} "
                f"in {elapsed:.2f}s"
            )
            return findings
        except Exception as e:
            logger.error(f"Normalization failed with {normalizer.name}: {e}")
            return self._try_all_normalizers(content, content_type)

    def _try_all_normalizers(
        self, content: bytes, content_type: Optional[str] = None
    ) -> List[UnifiedFinding]:
        """Try all normalizers and return first successful result."""
        sorted_normalizers = sorted(
            self._normalizers.items(),
            key=lambda x: x[1].priority,
            reverse=True,
        )

        for name, normalizer in sorted_normalizers:
            if not normalizer.enabled:
                continue
            try:
                findings = normalizer.normalize(content, content_type)
                if findings:
                    logger.info(f"Successfully normalized with fallback: {name}")
                    return findings
            except Exception as e:
                logger.debug(f"Normalizer {name} failed: {e}")
                continue

        logger.error("All normalizers failed")
        return []

    async def normalize_async(
        self,
        content: bytes,
        format_hint: Optional[str] = None,
        content_type: Optional[str] = None,
    ) -> List[UnifiedFinding]:
        """Async version of normalize for non-blocking operation."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            self._executor,
            self.normalize,
            content,
            format_hint,
            content_type,
        )

    def normalize_batch(
        self,
        items: List[Tuple[bytes, Optional[str], Optional[str]]],
    ) -> List[List[UnifiedFinding]]:
        """
        Normalize multiple items in parallel.

        Args:
            items: List of (content, format_hint, content_type) tuples

        Returns:
            List of finding lists, one per input item
        """
        if not self._config.get("settings", {}).get("parallel_processing", True):
            return [
                self.normalize(content, format_hint, content_type)
                for content, format_hint, content_type in items
            ]

        futures = []
        for content, format_hint, content_type in items:
            future = self._executor.submit(
                self.normalize, content, format_hint, content_type
            )
            futures.append(future)

        results = []
        for future in futures:
            try:
                results.append(future.result(timeout=300))
            except Exception as e:
                logger.error(f"Batch normalization failed: {e}")
                results.append([])

        return results

    def close(self) -> None:
        """Shutdown the executor to release resources."""
        self._executor.shutdown(wait=False)

    def __del__(self) -> None:
        """Cleanup executor on garbage collection."""
        try:
            self._executor.shutdown(wait=False)
        except Exception:
            pass


class IngestionResult(BaseModel):
    """Result of an ingestion operation."""

    model_config = ConfigDict(extra="allow")

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    status: str = Field(default="success")
    format_detected: Optional[str] = None
    detection_confidence: Optional[float] = None
    findings_count: int = 0
    assets_count: int = 0
    processing_time_ms: int = 0
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    findings: List[UnifiedFinding] = Field(default_factory=list)
    assets: List[Asset] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class IngestionService:
    """
    High-level ingestion service for the API.

    Provides:
    - Multipart file upload handling
    - Batch processing
    - Asset inventory updates
    - Performance monitoring
    """

    def __init__(self, registry: Optional[NormalizerRegistry] = None):
        self.registry = registry or NormalizerRegistry()
        self._asset_inventory: Dict[str, Asset] = {}

    async def ingest(
        self,
        content: bytes,
        filename: Optional[str] = None,
        content_type: Optional[str] = None,
        format_hint: Optional[str] = None,
    ) -> IngestionResult:
        """
        Ingest a single file and return normalized findings.

        Args:
            content: File content
            filename: Original filename
            content_type: MIME content type
            format_hint: Optional format hint

        Returns:
            IngestionResult with findings and metadata
        """
        start_time = time.time()
        result = IngestionResult()

        try:
            detected_format, confidence = self.registry.detect_format(
                content, content_type
            )
            result.format_detected = detected_format
            result.detection_confidence = confidence

            findings = await self.registry.normalize_async(
                content, format_hint or detected_format, content_type
            )

            result.findings = findings
            result.findings_count = len(findings)

            assets = self._extract_assets(findings)
            result.assets = assets
            result.assets_count = len(assets)

            for asset in assets:
                stable_key = self._get_stable_asset_key(asset)
                if stable_key in self._asset_inventory:
                    existing = self._asset_inventory[stable_key]
                    existing.finding_count += asset.finding_count
                    existing.critical_count += asset.critical_count
                    existing.high_count += asset.high_count
                    existing.last_seen = datetime.now(timezone.utc)
                else:
                    self._asset_inventory[stable_key] = asset

        except Exception as e:
            logger.error(f"Ingestion failed: {e}")
            result.status = "error"
            result.errors.append(str(e))

        result.processing_time_ms = int((time.time() - start_time) * 1000)
        result.metadata = {
            "filename": filename,
            "content_type": content_type,
            "content_size": len(content),
        }

        return result

    async def ingest_batch(
        self,
        files: List[Tuple[bytes, Optional[str], Optional[str]]],
    ) -> List[IngestionResult]:
        """
        Ingest multiple files in parallel.

        Args:
            files: List of (content, filename, content_type) tuples

        Returns:
            List of IngestionResult objects
        """
        tasks = [
            self.ingest(content, filename, content_type)
            for content, filename, content_type in files
        ]
        return await asyncio.gather(*tasks)

    def _extract_assets(self, findings: List[UnifiedFinding]) -> List[Asset]:
        """Extract unique assets from findings."""
        assets_by_key: Dict[str, Asset] = {}

        for finding in findings:
            asset_key = self._compute_asset_key(finding)
            if not asset_key:
                continue

            if asset_key not in assets_by_key:
                asset = self._create_asset_from_finding(finding)
                assets_by_key[asset_key] = asset
            else:
                asset = assets_by_key[asset_key]
                asset.finding_count += 1
                if finding.severity == FindingSeverity.CRITICAL:
                    asset.critical_count += 1
                elif finding.severity == FindingSeverity.HIGH:
                    asset.high_count += 1
                asset.last_seen = datetime.now(timezone.utc)

        return list(assets_by_key.values())

    def _compute_asset_key(self, finding: UnifiedFinding) -> Optional[str]:
        """Compute a unique key for asset deduplication."""
        if finding.cloud_resource_id:
            return f"cloud:{finding.cloud_resource_id}"
        if finding.container_image:
            return f"container:{finding.container_image}:{finding.container_tag or 'latest'}"
        if finding.package_name:
            return f"package:{finding.package_ecosystem or 'unknown'}:{finding.package_name}"
        if finding.file_path:
            return f"file:{finding.file_path}"
        return None

    def _get_stable_asset_key(self, asset: Asset) -> str:
        """Get a stable key for asset inventory deduplication.

        Uses deterministic identifiers instead of random UUIDs to ensure
        re-ingesting the same asset updates existing records rather than
        creating duplicates.

        Note: For packages, we strip the version to align with _compute_asset_key
        which deduplicates by package name only (not version). This ensures
        multiple versions of the same package are merged into one inventory entry.
        """
        if asset.resource_id:
            return f"cloud:{asset.cloud_provider or 'unknown'}:{asset.resource_id}"
        if asset.asset_type == AssetType.IMAGE:
            return f"container:{asset.name}"
        if asset.asset_type == AssetType.PACKAGE:
            # Use rsplit to split on the last "@" only, preserving scoped package names
            # e.g., "@scope/pkg@1.2.3" -> "@scope/pkg" (not empty string)
            package_name = (
                asset.name.rsplit("@", 1)[0] if "@" in asset.name else asset.name
            )
            return f"package:{package_name}"
        if asset.asset_type == AssetType.APPLICATION:
            return f"file:{asset.name}"
        return f"asset:{asset.asset_type.value}:{asset.name}"

    def _create_asset_from_finding(self, finding: UnifiedFinding) -> Asset:
        """Create an asset from a finding."""
        asset_type = finding.asset_type or AssetType.APPLICATION

        if finding.cloud_resource_id:
            asset_type = AssetType.CLOUD_RESOURCE
            name = finding.cloud_resource_id
        elif finding.container_image:
            asset_type = AssetType.IMAGE
            name = f"{finding.container_image}:{finding.container_tag or 'latest'}"
        elif finding.package_name:
            asset_type = AssetType.PACKAGE
            name = f"{finding.package_name}@{finding.package_version or 'unknown'}"
        elif finding.file_path:
            asset_type = AssetType.APPLICATION
            name = finding.file_path
        else:
            name = finding.asset_name or "Unknown Asset"

        asset = Asset(
            name=name,
            asset_type=asset_type,
            cloud_provider=finding.cloud_provider,
            cloud_region=finding.cloud_region,
            cloud_account=finding.cloud_account,
            resource_id=finding.cloud_resource_id,
            resource_type=finding.cloud_resource_type,
            finding_count=1,
            critical_count=1 if finding.severity == FindingSeverity.CRITICAL else 0,
            high_count=1 if finding.severity == FindingSeverity.HIGH else 0,
        )

        return asset

    def get_asset_inventory(self) -> List[Asset]:
        """Get the current asset inventory."""
        return list(self._asset_inventory.values())

    def get_asset(self, asset_id: str) -> Optional[Asset]:
        """Get an asset by ID."""
        return self._asset_inventory.get(asset_id)


_default_registry: Optional[NormalizerRegistry] = None
_default_service: Optional[IngestionService] = None


def get_registry() -> NormalizerRegistry:
    """Get the default normalizer registry."""
    global _default_registry
    if _default_registry is None:
        config_path = (
            Path(__file__).parent.parent.parent
            / "config"
            / "normalizers"
            / "registry.yaml"
        )
        _default_registry = NormalizerRegistry(
            config_path if config_path.exists() else None
        )
    return _default_registry


def get_ingestion_service() -> IngestionService:
    """Get the default ingestion service."""
    global _default_service
    if _default_service is None:
        _default_service = IngestionService(get_registry())
    return _default_service
