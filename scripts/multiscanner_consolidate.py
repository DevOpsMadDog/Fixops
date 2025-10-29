#!/usr/bin/env python3
"""FixOps Multi-Scanner Consolidation - Real-Time Client CVE Processing.

Consolidates findings from multiple security scanners:
- Snyk (38,000 findings)
- Tenable (5,000 findings)
- Wiz (200 findings)
- Rapid7 (1,000 findings)
- SonarQube (code quality)

Performs:
1. Normalization: Convert each scanner's format to unified schema
2. Deduplication: Merge overlapping CVEs across scanners
3. Enrichment: Add KEV/EPSS intelligence
4. Scoring: Bidirectional risk scoring (Day-0 + Day-N)
5. Compliance Mapping: SOC2, ISO27001, NIST, Essential 8
6. Prioritization: Cost-aware, compliance-driven fix planning

Output:
- artifacts/prioritized_top100.json
- artifacts/compliance_gap.json
- artifacts/fix_plan.csv
- reports/multiscanner_summary.md
"""

import argparse
import csv
import gzip
import json
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, cast

sys.path.insert(0, str(Path(__file__).parent))

REPO_ROOT = Path(__file__).parent.parent
FEEDS_DIR = REPO_ROOT / "data" / "feeds"
ARTIFACTS_DIR = REPO_ROOT / "artifacts"
REPORTS_DIR = REPO_ROOT / "reports"

ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)


@dataclass
class NormalizedFinding:
    """Unified finding schema across all scanners."""

    id: str  # Unique ID for this finding
    category: str  # "vulnerability", "code_issue", "misconfig", "secret"
    scanners: List[str]  # Which scanners reported this (for dedup tracking)

    cve_id: Optional[str] = None
    package: Optional[str] = None
    version: Optional[str] = None

    rule_id: Optional[str] = None
    file_path: Optional[str] = None
    line_range: Optional[str] = None

    resource_id: Optional[str] = None
    resource_type: Optional[str] = None

    asset_key: str = ""  # repo:file, image:tag, hostname:service, cloud:resourceId
    asset_type: str = ""  # "container", "host", "cloud", "code"

    severity_raw: str = ""  # Original scanner severity
    cvss: Optional[float] = None
    epss_score: float = 0.0
    kev: bool = False

    internet_facing: bool = False
    pre_auth: bool = False
    data_classes: List[str] = field(default_factory=list)

    control_tags: List[str] = field(default_factory=list)  # SOC2, ISO, NIST, Essential8

    title: str = ""
    description: str = ""
    remediation: str = ""
    first_seen: str = ""
    scanner_metadata: Dict[str, Any] = field(default_factory=dict)

    day0_score: float = 0.0
    dayn_score: float = 0.0
    final_score: float = 0.0
    final_severity: str = ""
    rationale: str = ""


class SnykNormalizer:
    """Normalize Snyk JSON output."""

    @staticmethod
    def normalize(data: Dict[str, Any]) -> List[NormalizedFinding]:
        """Convert Snyk JSON to normalized findings."""
        findings = []

        vulns = data.get("vulnerabilities", data.get("issues", []))

        for vuln in vulns:
            cve_id = vuln.get("identifiers", {}).get("CVE", [None])[0]
            if not cve_id and "id" in vuln:
                vid = vuln.get("id", "")
                if vid.startswith("CVE-"):
                    cve_id = vid

            package = vuln.get("packageName", vuln.get("name", ""))
            version = vuln.get("version", "")

            asset_key = f"{package}@{version}" if package else "unknown"

            asset_type = "container"  # Snyk is primarily for dependencies

            severity = vuln.get("severity", "medium").lower()

            cvss = vuln.get("cvssScore")
            if cvss is None and "cvss" in vuln:
                cvss = vuln.get("cvss", {}).get("baseScore")

            title = vuln.get("title", cve_id or "Unknown vulnerability")
            description = vuln.get("description", "")

            remediation = ""
            if "fixedIn" in vuln:
                fixed_versions = vuln.get("fixedIn", [])
                if fixed_versions:
                    remediation = f"Upgrade to {', '.join(fixed_versions)}"

            control_tags = []
            if "cwe" in vuln:
                cwes = vuln.get("cwe", [])
                control_tags.extend([f"CWE-{cwe}" for cwe in cwes])

            finding = NormalizedFinding(
                id=f"snyk-{vuln.get('id', hash(str(vuln)))}",
                category="vulnerability",
                scanners=["snyk"],
                cve_id=cve_id,
                package=package,
                version=version,
                asset_key=asset_key,
                asset_type=asset_type,
                severity_raw=severity,
                cvss=cvss,
                title=title,
                description=description,
                remediation=remediation,
                control_tags=control_tags,
                first_seen=datetime.now().isoformat(),
                scanner_metadata={"snyk": vuln},
            )

            findings.append(finding)

        return findings


class TenableNormalizer:
    """Normalize Tenable CSV output."""

    @staticmethod
    def normalize(csv_path: Path) -> List[NormalizedFinding]:
        """Convert Tenable CSV to normalized findings."""
        findings = []

        with csv_path.open("r", encoding="utf-8") as f:
            reader = csv.DictReader(f)

            for row in reader:
                plugin_id = row.get("Plugin ID", row.get("plugin_id", ""))
                name = row.get("Name", row.get("name", ""))
                severity = row.get("Severity", row.get("severity", "medium")).lower()
                cve_str = row.get("CVE", row.get("cve", ""))
                host = row.get("Host", row.get("host", row.get("IP", "")))

                cves = [c.strip() for c in cve_str.split(",") if c.strip()]

                asset_key = host if host else "unknown-host"
                asset_type = "host"

                cvss = None
                if "CVSS" in row:
                    try:
                        cvss = float(row["CVSS"])
                    except (ValueError, TypeError):
                        pass

                if cves:
                    for cve_id in cves:
                        finding = NormalizedFinding(
                            id=f"tenable-{plugin_id}-{cve_id}-{host}",
                            category="vulnerability",
                            scanners=["tenable"],
                            cve_id=cve_id,
                            asset_key=asset_key,
                            asset_type=asset_type,
                            severity_raw=severity,
                            cvss=cvss,
                            title=name,
                            description=f"Tenable Plugin {plugin_id}: {name}",
                            first_seen=datetime.now().isoformat(),
                            scanner_metadata={"tenable": row},
                        )
                        findings.append(finding)
                else:
                    finding = NormalizedFinding(
                        id=f"tenable-{plugin_id}-{host}",
                        category="misconfig",
                        scanners=["tenable"],
                        rule_id=plugin_id,
                        resource_id=host,
                        asset_key=asset_key,
                        asset_type=asset_type,
                        severity_raw=severity,
                        cvss=cvss,
                        title=name,
                        description=f"Tenable Plugin {plugin_id}: {name}",
                        first_seen=datetime.now().isoformat(),
                        scanner_metadata={"tenable": row},
                    )
                    findings.append(finding)

        return findings


class WizNormalizer:
    """Normalize Wiz JSON output."""

    @staticmethod
    def normalize(data: Dict[str, Any]) -> List[NormalizedFinding]:
        """Convert Wiz JSON to normalized findings."""
        findings = []

        issues = data.get("issues", [])

        for issue in issues:
            issue_id = issue.get("id", "")
            # issue_type = issue.get("type", "misconfig")  # "vulnerability" or "misconfig" (unused)
            resource_id = issue.get(
                "resourceId", issue.get("resource", {}).get("id", "")
            )
            resource_type = issue.get("resourceType", "")

            severity = issue.get("severity", "medium").lower()

            cve_ids = issue.get("cveIds", [])

            asset_key = resource_id if resource_id else "unknown-resource"
            asset_type = "cloud"

            title = issue.get("title", issue.get("name", "Unknown issue"))
            description = issue.get("description", "")

            control_tags = []
            if "compliance" in issue:
                compliance = issue.get("compliance", {})
                for framework, controls in compliance.items():
                    control_tags.extend([f"{framework}:{c}" for c in controls])

            if cve_ids:
                for cve_id in cve_ids:
                    finding = NormalizedFinding(
                        id=f"wiz-{issue_id}-{cve_id}",
                        category="vulnerability",
                        scanners=["wiz"],
                        cve_id=cve_id,
                        resource_id=resource_id,
                        resource_type=resource_type,
                        asset_key=asset_key,
                        asset_type=asset_type,
                        severity_raw=severity,
                        title=title,
                        description=description,
                        control_tags=control_tags,
                        first_seen=datetime.now().isoformat(),
                        scanner_metadata={"wiz": issue},
                    )
                    findings.append(finding)
            else:
                finding = NormalizedFinding(
                    id=f"wiz-{issue_id}",
                    category="misconfig",
                    scanners=["wiz"],
                    rule_id=issue.get("ruleId", ""),
                    resource_id=resource_id,
                    resource_type=resource_type,
                    asset_key=asset_key,
                    asset_type=asset_type,
                    severity_raw=severity,
                    title=title,
                    description=description,
                    control_tags=control_tags,
                    first_seen=datetime.now().isoformat(),
                    scanner_metadata={"wiz": issue},
                )
                findings.append(finding)

        return findings


class Rapid7Normalizer:
    """Normalize Rapid7 CSV output."""

    @staticmethod
    def normalize(csv_path: Path) -> List[NormalizedFinding]:
        """Convert Rapid7 CSV to normalized findings."""
        findings = []

        with csv_path.open("r", encoding="utf-8") as f:
            reader = csv.DictReader(f)

            for row in reader:
                vuln_id = row.get("Vulnerability ID", row.get("id", ""))
                title = row.get("Title", row.get("title", ""))
                severity = row.get("Severity", row.get("severity", "medium")).lower()
                cve_str = row.get("CVE", row.get("cve", ""))
                host = row.get("Host", row.get("host", row.get("IP", "")))

                cves = [c.strip() for c in cve_str.split(",") if c.strip()]

                asset_key = host if host else "unknown-host"
                asset_type = "host"

                cvss = None
                if "CVSS" in row:
                    try:
                        cvss = float(row["CVSS"])
                    except (ValueError, TypeError):
                        pass

                if cves:
                    for cve_id in cves:
                        finding = NormalizedFinding(
                            id=f"rapid7-{vuln_id}-{cve_id}-{host}",
                            category="vulnerability",
                            scanners=["rapid7"],
                            cve_id=cve_id,
                            asset_key=asset_key,
                            asset_type=asset_type,
                            severity_raw=severity,
                            cvss=cvss,
                            title=title,
                            description=f"Rapid7: {title}",
                            first_seen=datetime.now().isoformat(),
                            scanner_metadata={"rapid7": row},
                        )
                        findings.append(finding)
                else:
                    finding = NormalizedFinding(
                        id=f"rapid7-{vuln_id}-{host}",
                        category="misconfig",
                        scanners=["rapid7"],
                        rule_id=vuln_id,
                        resource_id=host,
                        asset_key=asset_key,
                        asset_type=asset_type,
                        severity_raw=severity,
                        cvss=cvss,
                        title=title,
                        description=f"Rapid7: {title}",
                        first_seen=datetime.now().isoformat(),
                        scanner_metadata={"rapid7": row},
                    )
                    findings.append(finding)

        return findings


class SonarQubeNormalizer:
    """Normalize SonarQube JSON output."""

    @staticmethod
    def normalize(data: Dict[str, Any]) -> List[NormalizedFinding]:
        """Convert SonarQube JSON to normalized findings."""
        findings = []

        issues = data.get("issues", [])

        for issue in issues:
            issue_key = issue.get("key", "")
            rule_key = issue.get("rule", "")
            # issue_type = issue.get("type", "CODE_SMELL")  # BUG, VULNERABILITY, CODE_SMELL (unused)
            severity = issue.get("severity", "MEDIUM").lower()

            component = issue.get("component", "")
            file_path = component.split(":")[-1] if ":" in component else component
            line = issue.get("line", 0)
            line_range = f"{line}-{line}" if line else ""

            repo = issue.get("project", "unknown-repo")
            asset_key = f"{repo}:{file_path}"
            asset_type = "code"

            message = issue.get("message", "")
            title = f"{rule_key}: {message}"

            control_tags = []
            if "securityCategory" in issue:
                control_tags.append(f"OWASP:{issue['securityCategory']}")

            finding = NormalizedFinding(
                id=f"sonarqube-{issue_key}",
                category="code_issue",
                scanners=["sonarqube"],
                rule_id=rule_key,
                file_path=file_path,
                line_range=line_range,
                asset_key=asset_key,
                asset_type=asset_type,
                severity_raw=severity,
                title=title,
                description=message,
                control_tags=control_tags,
                first_seen=datetime.now().isoformat(),
                scanner_metadata={"sonarqube": issue},
            )

            findings.append(finding)

        return findings


class AWSSecurityHubNormalizer:
    """Normalize AWS Security Hub (ASFF) JSON output."""

    @staticmethod
    def normalize(data: Dict[str, Any]) -> List[NormalizedFinding]:
        """Convert AWS Security Hub ASFF to normalized findings."""
        findings = []

        asff_findings = data.get("Findings", [])

        for asff in asff_findings:
            finding_id = asff.get("Id", "")
            title = asff.get("Title", "")
            description = asff.get("Description", "")

            severity_label = asff.get("Severity", {}).get("Label", "MEDIUM").lower()
            severity_normalized = asff.get("Severity", {}).get("Normalized", 50)

            resources = asff.get("Resources", [])
            resource_id = (
                resources[0].get("Id", "unknown-resource")
                if resources
                else "unknown-resource"
            )
            resource_type = (
                resources[0].get("Type", "unknown") if resources else "unknown"
            )

            asset_key = resource_id
            asset_type = "cloud"

            compliance = asff.get("Compliance", {})
            related_requirements = compliance.get("RelatedRequirements", [])

            control_tags = []
            for req in related_requirements:
                if "PCI" in req:
                    control_tags.append(f"PCI:{req}")
                elif "NIST" in req:
                    control_tags.append(f"NIST:{req}")
                elif "ISO" in req:
                    control_tags.append(f"ISO27001:{req}")

            product_fields = asff.get("ProductFields", {})
            control_id = product_fields.get("ControlId", "")
            if control_id:
                if "CIS" in str(asff.get("GeneratorId", "")):
                    control_tags.append(f"CIS:{control_id}")

            remediation = asff.get("Remediation", {}).get("Recommendation", {})
            remediation_text = remediation.get("Text", "")
            remediation_url = remediation.get("Url", "")

            finding = NormalizedFinding(
                id=f"aws-securityhub-{finding_id.split('/')[-1]}",
                category="misconfig",
                scanners=["aws_securityhub"],
                resource_id=resource_id,
                resource_type=resource_type,
                asset_key=asset_key,
                asset_type=asset_type,
                severity_raw=severity_label,
                cvss=float(severity_normalized) / 10.0 if severity_normalized else None,
                title=title,
                description=description,
                remediation=f"{remediation_text} {remediation_url}".strip(),
                control_tags=control_tags,
                first_seen=asff.get("FirstObservedAt", datetime.now().isoformat()),
                scanner_metadata={"aws_securityhub": asff},
            )

            findings.append(finding)

        return findings


class PrismaCloudNormalizer:
    """Normalize Prisma Cloud CSV output."""

    @staticmethod
    def normalize(data: Dict[str, Any]) -> List[NormalizedFinding]:
        """Convert Prisma Cloud CSV to normalized findings."""
        findings = []

        if isinstance(data, list):
            rows = data
        else:
            rows = data.get("rows", [])

        for row in rows:
            alert_id = row.get("Alert ID", "")
            resource_id = row.get("Resource ID", "unknown-resource")
            resource_type = row.get("Resource Type", "")
            severity = row.get("Severity", "medium").lower()
            policy = row.get("Policy", "")
            policy_type = row.get("Policy Type", "Config")
            compliance_standard = row.get("Compliance Standard", "")
            compliance_requirement = row.get("Compliance Requirement", "")

            asset_key = resource_id
            asset_type = "cloud"
            if "Image" in resource_type or "Container" in resource_type:
                asset_type = "container"

            control_tags = []
            if compliance_standard and compliance_requirement:
                if "PCI" in compliance_standard:
                    control_tags.append(f"PCI:{compliance_requirement}")
                elif "SOC" in compliance_standard:
                    control_tags.append(f"SOC2:{compliance_requirement}")
                elif "ISO" in compliance_standard:
                    control_tags.append(f"ISO27001:{compliance_requirement}")
                elif "NIST" in compliance_standard:
                    control_tags.append(f"NIST:{compliance_requirement}")
                elif "CIS" in compliance_standard:
                    control_tags.append(f"CIS:{compliance_requirement}")

            category = "misconfig"
            if policy_type == "Vulnerability":
                category = "vulnerability"

            finding = NormalizedFinding(
                id=f"prisma-{alert_id}",
                category=category,
                scanners=["prisma"],
                resource_id=resource_id,
                resource_type=resource_type,
                asset_key=asset_key,
                asset_type=asset_type,
                severity_raw=severity,
                title=policy,
                description=f"Prisma Cloud: {policy}",
                control_tags=control_tags,
                first_seen=row.get("First Seen", datetime.now().isoformat()),
                scanner_metadata={"prisma": row},
            )

            findings.append(finding)

        return findings


class VeracodeNormalizer:
    """Normalize Veracode JSON output."""

    @staticmethod
    def normalize(data: Dict[str, Any]) -> List[NormalizedFinding]:
        """Convert Veracode JSON to normalized findings."""
        findings = []

        veracode_findings = data.get("findings", [])

        for vf in veracode_findings:
            issue_id = vf.get("issue_id", "")

            description_obj = vf.get("description", {})
            description_text = description_obj.get("text", "")
            severity = description_obj.get("severity", 3)

            finding_details = vf.get("finding_details", {})
            cwe = finding_details.get("cwe", {})
            cwe_id = cwe.get("id", 0)
            cwe_name = cwe.get("name", "")

            file_path = finding_details.get("file_path", "")
            line_number = finding_details.get("file_line_number", 0)

            repo = "unknown-repo"
            asset_key = f"{repo}:{file_path}"
            asset_type = "code"

            severity_map = {5: "critical", 4: "high", 3: "medium", 2: "low", 1: "info"}
            severity_str = severity_map.get(severity, "medium")

            control_tags = []
            if cwe_id:
                control_tags.append(f"CWE:{cwe_id}")
            if "SQL" in cwe_name or "Injection" in cwe_name:
                control_tags.append("OWASP:A03")
            if "XSS" in cwe_name or "Cross-Site" in cwe_name:
                control_tags.append("OWASP:A03")
            if "Crypto" in cwe_name or "Encryption" in cwe_name:
                control_tags.append("OWASP:A02")

            finding = NormalizedFinding(
                id=f"veracode-{issue_id}",
                category="code_issue",
                scanners=["veracode"],
                rule_id=f"CWE-{cwe_id}",
                file_path=file_path,
                line_range=f"{line_number}-{line_number}" if line_number else "",
                asset_key=asset_key,
                asset_type=asset_type,
                severity_raw=severity_str,
                title=cwe_name,
                description=description_text,
                control_tags=control_tags,
                first_seen=vf.get("finding_status", {}).get(
                    "first_found_date", datetime.now().isoformat()
                ),
                scanner_metadata={"veracode": vf},
            )

            findings.append(finding)

        return findings


class InvictiNormalizer:
    """Normalize Invicti (formerly Netsparker) JSON output."""

    @staticmethod
    def normalize(data: Dict[str, Any]) -> List[NormalizedFinding]:
        """Convert Invicti JSON to normalized findings."""
        findings = []

        invicti_vulns = data.get("List", [])

        for vuln in invicti_vulns:
            vuln_id = vuln.get("Id", "")
            vuln_type = vuln.get("Type", "")
            url = vuln.get("Url", "")
            severity = vuln.get("Severity", 2)
            cwe_id = vuln.get("CweId", 0)
            cvss_obj = vuln.get("Cvss", {})
            cvss_score = cvss_obj.get("Score", 0.0)

            title = vuln_type
            description = vuln.get("LongDescription", "")
            remediation = vuln.get("Remediation", "")

            asset_key = url
            asset_type = "api"

            severity_map = {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "info"}
            severity_str = severity_map.get(severity, "medium")

            control_tags = []
            if cwe_id:
                control_tags.append(f"CWE:{cwe_id}")
            if "Sql" in vuln_type or "SQL" in vuln_type:
                control_tags.append("OWASP:A03")
            if "Xss" in vuln_type or "XSS" in vuln_type or "CrossSite" in vuln_type:
                control_tags.append("OWASP:A03")
            if "Path" in vuln_type or "Traversal" in vuln_type:
                control_tags.append("OWASP:A01")

            finding = NormalizedFinding(
                id=f"invicti-{vuln_id}",
                category="vulnerability",
                scanners=["invicti"],
                rule_id=f"CWE-{cwe_id}" if cwe_id else vuln_type,
                asset_key=asset_key,
                asset_type=asset_type,
                severity_raw=severity_str,
                cvss=float(cvss_score) if cvss_score else None,
                title=title,
                description=description,
                remediation=remediation,
                control_tags=control_tags,
                first_seen=vuln.get("FirstSeenDate", datetime.now().isoformat()),
                scanner_metadata={"invicti": vuln},
            )

            findings.append(finding)

        return findings


def load_kev_data() -> Set[str]:
    """Load KEV CVE IDs from CISA feed."""
    kev_path = FEEDS_DIR / "kev.json"
    kev_cves = set()

    if kev_path.exists():
        try:
            with kev_path.open("r") as f:
                data = json.load(f)
                vulns = data.get("data", {}).get("vulnerabilities", [])
                if not vulns:
                    vulns = data.get("vulnerabilities", [])

                for vuln in vulns:
                    cve_id = vuln.get("cveID")
                    if cve_id:
                        kev_cves.add(cve_id)
        except Exception as e:
            print(f"Warning: Could not load KEV data: {e}")

    return kev_cves


def load_epss_data() -> Dict[str, float]:
    """Load EPSS scores from FIRST feed."""
    epss_path = FEEDS_DIR / "epss.csv.gz"
    epss_scores = {}

    if epss_path.exists():
        try:
            with gzip.open(epss_path, "rt") as f:
                for line in f:
                    if line.startswith("#"):
                        continue
                    if line.startswith("cve,"):
                        continue
                    parts = line.strip().split(",")
                    if len(parts) >= 2:
                        cve_id = parts[0]
                        try:
                            epss_scores[cve_id] = float(parts[1])
                        except ValueError:
                            pass
        except Exception as e:
            print(f"Warning: Could not load EPSS data: {e}")

    return epss_scores


def deduplicate_findings(findings: List[NormalizedFinding]) -> List[NormalizedFinding]:
    """Deduplicate findings across scanners using correlation keys."""
    dedup_map: Dict[str, NormalizedFinding] = {}

    for finding in findings:
        if finding.category == "vulnerability" and finding.cve_id:
            key = f"vuln:{finding.cve_id}:{finding.package}:{finding.version}:{finding.asset_key}"
        elif finding.category == "code_issue":
            repo = finding.asset_key.split(":")[0] if ":" in finding.asset_key else ""
            key = f"code:{finding.rule_id}:{finding.file_path}:{finding.line_range}:{repo}"
        elif finding.category == "misconfig":
            key = f"misconfig:{finding.rule_id}:{finding.resource_id}"
        else:
            key = finding.id

        if key in dedup_map:
            existing = dedup_map[key]
            existing.scanners.extend(finding.scanners)
            existing.scanners = list(set(existing.scanners))  # Deduplicate scanner list

            for scanner, metadata in finding.scanner_metadata.items():
                if scanner not in existing.scanner_metadata:
                    existing.scanner_metadata[scanner] = metadata

            severity_order = {
                "critical": 4,
                "high": 3,
                "medium": 2,
                "low": 1,
                "info": 0,
            }
            if severity_order.get(finding.severity_raw, 0) > severity_order.get(
                existing.severity_raw, 0
            ):
                existing.severity_raw = finding.severity_raw

            if finding.cvss and (not existing.cvss or finding.cvss > existing.cvss):
                existing.cvss = finding.cvss
        else:
            dedup_map[key] = finding

    return list(dedup_map.values())


def enrich_findings(
    findings: List[NormalizedFinding], kev_cves: Set[str], epss_scores: Dict[str, float]
) -> None:
    """Enrich findings with KEV and EPSS data."""
    for finding in findings:
        if finding.cve_id:
            if finding.cve_id in kev_cves:
                finding.kev = True

            if finding.cve_id in epss_scores:
                finding.epss_score = epss_scores[finding.cve_id]


def score_findings(findings: List[NormalizedFinding]) -> None:
    """Apply bidirectional risk scoring to findings."""

    for finding in findings:
        day0_factors = []

        if finding.pre_auth:
            day0_factors.append(("pre_auth", 0.3))

        if finding.internet_facing:
            day0_factors.append(("internet_facing", 0.25))

        if finding.data_classes:
            day0_factors.append(("data_adjacency", 0.2))

        severity_scores = {
            "critical": 0.9,
            "high": 0.7,
            "medium": 0.5,
            "low": 0.3,
            "info": 0.1,
        }
        base_score = severity_scores.get(finding.severity_raw, 0.5)
        day0_factors.append(("base_severity", base_score * 0.25))

        finding.day0_score = min(1.0, sum(score for _, score in day0_factors))

        dayn_factors = []

        if finding.kev:
            dayn_factors.append(("kev", 0.4))

        if finding.epss_score > 0.5:
            dayn_factors.append(("high_epss", finding.epss_score * 0.3))
        elif finding.epss_score > 0.1:
            dayn_factors.append(("medium_epss", finding.epss_score * 0.2))

        finding.dayn_score = min(1.0, sum(score for _, score in dayn_factors))

        finding.final_score = (finding.day0_score * 0.6) + (finding.dayn_score * 0.4)

        if finding.final_score >= 0.8:
            finding.final_severity = "critical"
        elif finding.final_score >= 0.6:
            finding.final_severity = "high"
        elif finding.final_score >= 0.4:
            finding.final_severity = "medium"
        else:
            finding.final_severity = "low"

        rationale_parts = []
        if finding.kev:
            rationale_parts.append("KEV-listed (actively exploited)")
        if finding.epss_score > 0.5:
            rationale_parts.append(f"High EPSS ({finding.epss_score:.2f})")
        if finding.pre_auth:
            rationale_parts.append("Pre-auth exploit")
        if finding.internet_facing:
            rationale_parts.append("Internet-facing")
        if finding.data_classes:
            rationale_parts.append(f"Data exposure: {', '.join(finding.data_classes)}")

        finding.rationale = (
            "; ".join(rationale_parts)
            if rationale_parts
            else "Standard risk assessment"
        )


def map_compliance_controls(findings: List[NormalizedFinding]) -> None:
    """Map findings to compliance framework controls."""
    for finding in findings:
        controls = set(finding.control_tags)  # Start with scanner-provided tags

        if finding.category == "vulnerability":
            if finding.kev:
                controls.update(["SOC2:CC7.1", "ISO27001:A.12.6", "NIST:SI-2"])
            if finding.severity_raw in ["critical", "high"]:
                controls.update(
                    ["SOC2:CC7.2", "ISO27001:A.12.6", "Essential8:Patching"]
                )

        if finding.category == "misconfig":
            if (
                "public" in finding.description.lower()
                or "0.0.0.0" in finding.description
            ):
                controls.update(["SOC2:CC6.6", "ISO27001:A.13.1", "NIST:AC-3"])
            if "encrypt" in finding.description.lower():
                controls.update(["SOC2:CC6.1", "ISO27001:A.10.1", "NIST:SC-13"])

        if finding.category == "code_issue":
            if "sql" in finding.title.lower() or "injection" in finding.title.lower():
                controls.update(["SOC2:CC7.2", "ISO27001:A.14.2", "NIST:SI-10"])
            if "auth" in finding.title.lower():
                controls.update(["SOC2:CC6.1", "ISO27001:A.9.2", "NIST:IA-2"])

        finding.control_tags = sorted(list(controls))


def generate_compliance_gap(findings: List[NormalizedFinding]) -> Dict[str, Any]:
    """Generate compliance gap analysis."""
    frameworks: Dict[str, Set[str]] = {
        "SOC2": set(),
        "ISO27001": set(),
        "NIST": set(),
        "Essential8": set(),
    }

    for finding in findings:
        for tag in finding.control_tags:
            if ":" in tag:
                framework, control = tag.split(":", 1)
                if framework in frameworks:
                    frameworks[framework].add(control)

    frameworks_details: Dict[str, Dict[str, Any]] = {}
    for framework, controls in frameworks.items():
        frameworks_details[framework] = {
            "failing_controls": sorted(list(controls)),
            "control_count": len(controls),
            "findings_blocking": sum(
                1
                for f in findings
                if any(tag.startswith(f"{framework}:") for tag in f.control_tags)
            ),
        }

    gap_report: Dict[str, Any] = {
        "generated": datetime.now().isoformat(),
        "total_findings": len(findings),
        "frameworks": frameworks_details,
    }

    return gap_report


def generate_fix_plan(findings: List[NormalizedFinding]) -> List[Dict[str, Any]]:
    """Generate prioritized fix plan with cost estimates."""
    fix_groups = defaultdict(list)

    for finding in findings:
        if finding.category == "vulnerability":
            if finding.package:
                fix_groups["dependency_upgrade"].append(finding)
            else:
                fix_groups["patch_system"].append(finding)
        elif finding.category == "misconfig":
            fix_groups["infrastructure_config"].append(finding)
        elif finding.category == "code_issue":
            fix_groups["code_remediation"].append(finding)
        else:
            fix_groups["other"].append(finding)

    fix_plan = []

    effort_map = {
        "dependency_upgrade": "Small",  # 1-2 hours per batch
        "patch_system": "Medium",  # 4-8 hours per batch
        "infrastructure_config": "Small",  # 1-4 hours per batch
        "code_remediation": "Large",  # 1-2 days per batch
        "other": "Medium",
    }

    for fix_type, group_findings in fix_groups.items():
        if not group_findings:
            continue

        group_findings.sort(key=lambda f: f.final_score, reverse=True)

        top_findings = group_findings[:30]

        affected_controls = set()
        for f in top_findings:
            affected_controls.update(f.control_tags)

        all_scanners = set()
        for f in top_findings:
            all_scanners.update(f.scanners)

        fix_plan.append(
            {
                "fix_type": fix_type,
                "finding_count": len(top_findings),
                "effort": effort_map.get(fix_type, "Medium"),
                "affected_controls": sorted(list(affected_controls)),
                "control_count": len(affected_controls),
                "scanners": sorted(list(all_scanners)),
                "avg_score": sum(f.final_score for f in top_findings)
                / len(top_findings),
                "sample_findings": [
                    {
                        "id": f.id,
                        "title": f.title,
                        "severity": f.final_severity,
                        "score": f.final_score,
                        "scanners": f.scanners,
                    }
                    for f in top_findings[:5]
                ],
            }
        )

    fix_plan.sort(
        key=lambda item: float(cast(float, item.get("avg_score", 0.0))), reverse=True
    )

    return fix_plan


def save_outputs(
    findings: List[NormalizedFinding],
    compliance_gap: Dict[str, Any],
    fix_plan: List[Dict[str, Any]],
) -> None:
    """Save all output artifacts."""
    findings.sort(key=lambda f: f.final_score, reverse=True)

    top100_path = ARTIFACTS_DIR / "prioritized_top100.json"
    with top100_path.open("w") as f:
        json.dump([asdict(f) for f in findings[:100]], f, indent=2)
    print(f"✓ Saved top 100 prioritized findings to {top100_path}")

    gap_path = ARTIFACTS_DIR / "compliance_gap.json"
    with gap_path.open("w") as f:
        json.dump(compliance_gap, f, indent=2)
    print(f"✓ Saved compliance gap analysis to {gap_path}")

    plan_path = ARTIFACTS_DIR / "fix_plan.csv"
    with plan_path.open("w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "fix_type",
                "finding_count",
                "effort",
                "control_count",
                "avg_score",
                "scanners",
            ],
        )
        writer.writeheader()
        for item in fix_plan:
            writer.writerow(
                {
                    "fix_type": item["fix_type"],
                    "finding_count": item["finding_count"],
                    "effort": item["effort"],
                    "control_count": item["control_count"],
                    "avg_score": f"{item['avg_score']:.3f}",
                    "scanners": ", ".join(item["scanners"]),
                }
            )
    print(f"✓ Saved fix plan to {plan_path}")

    generate_summary_report(findings, compliance_gap, fix_plan)


def generate_summary_report(
    findings: List[NormalizedFinding],
    compliance_gap: Dict[str, Any],
    fix_plan: List[Dict[str, Any]],
) -> None:
    """Generate markdown summary report."""
    report_path = REPORTS_DIR / "multiscanner_summary.md"

    scanner_counts: Dict[str, int] = defaultdict(int)
    for finding in findings:
        for scanner in finding.scanners:
            scanner_counts[scanner] += 1

    severity_counts: Dict[str, int] = defaultdict(int)
    for finding in findings:
        severity_counts[finding.final_severity] += 1

    category_counts: Dict[str, int] = defaultdict(int)
    for finding in findings:
        category_counts[finding.category] += 1

    with report_path.open("w") as report_file:
        report_file.write("# FixOps Multi-Scanner Consolidation Report\n\n")
        report_file.write(
            f"**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        )

        report_file.write("## Executive Summary\n\n")
        report_file.write(
            f"- **Total Findings (After Deduplication)**: {len(findings):,}\n"
        )
        report_file.write(f"- **Critical**: {severity_counts['critical']:,}\n")
        report_file.write(f"- **High**: {severity_counts['high']:,}\n")
        report_file.write(f"- **Medium**: {severity_counts['medium']:,}\n")
        report_file.write(f"- **Low**: {severity_counts['low']:,}\n\n")

        report_file.write("## Scanner Coverage\n\n")
        for scanner, count in sorted(scanner_counts.items()):
            report_file.write(f"- **{scanner.capitalize()}**: {count:,} findings\n")
        report_file.write("\n")

        report_file.write("## Finding Categories\n\n")
        for category, count in sorted(category_counts.items()):
            report_file.write(
                f"- **{category.replace('_', ' ').title()}**: {count:,}\n"
            )
        report_file.write("\n")

        report_file.write("## Compliance Gap Analysis\n\n")
        for framework, data in compliance_gap["frameworks"].items():
            report_file.write(f"### {framework}\n\n")
            report_file.write(f"- **Failing Controls**: {data['control_count']}\n")
            report_file.write(
                f"- **Findings Blocking Compliance**: {data['findings_blocking']}\n"
            )
            if data["failing_controls"]:
                report_file.write(
                    f"- **Top Controls**: {', '.join(data['failing_controls'][:5])}\n"
                )
            report_file.write("\n")

        report_file.write("## Prioritized Fix Plan\n\n")
        report_file.write(
            "Recommended fix batches ordered by risk reduction and compliance impact:\n\n"
        )
        for i, item in enumerate(fix_plan, 1):
            report_file.write(
                f"### {i}. {item['fix_type'].replace('_', ' ').title()}\n\n"
            )
            report_file.write(f"- **Findings**: {item['finding_count']}\n")
            report_file.write(f"- **Effort**: {item['effort']}\n")
            report_file.write(f"- **Controls Addressed**: {item['control_count']}\n")
            report_file.write(f"- **Average Risk Score**: {item['avg_score']:.3f}\n")
            report_file.write(f"- **Scanners**: {', '.join(item['scanners'])}\n\n")

            if item["sample_findings"]:
                report_file.write("**Sample Findings**:\n\n")
                for sf in item["sample_findings"]:
                    report_file.write(
                        f"- [{sf['severity'].upper()}] {sf['title']} (Score: {sf['score']:.3f}, Scanners: {', '.join(sf['scanners'])})\n"
                    )
                report_file.write("\n")

        report_file.write("## Top 10 Critical Findings\n\n")
        for i, finding in enumerate(findings[:10], 1):
            report_file.write(f"### {i}. {finding.title}\n\n")
            report_file.write(f"- **ID**: {finding.id}\n")
            report_file.write(f"- **Severity**: {finding.final_severity.upper()}\n")
            report_file.write(f"- **Score**: {finding.final_score:.3f}\n")
            report_file.write(f"- **Category**: {finding.category}\n")
            if finding.cve_id:
                report_file.write(f"- **CVE**: {finding.cve_id}\n")
            report_file.write(f"- **Scanners**: {', '.join(finding.scanners)}\n")
            report_file.write(f"- **Rationale**: {finding.rationale}\n")
            if finding.control_tags:
                report_file.write(
                    f"- **Controls**: {', '.join(finding.control_tags[:5])}\n"
                )
            report_file.write("\n")

    print(f"✓ Generated summary report at {report_path}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="FixOps Multi-Scanner Consolidation - Consolidate findings from multiple security scanners"
    )
    parser.add_argument("--snyk", type=Path, help="Path to Snyk JSON output")
    parser.add_argument("--tenable", type=Path, help="Path to Tenable CSV output")
    parser.add_argument("--wiz", type=Path, help="Path to Wiz JSON output")
    parser.add_argument("--rapid7", type=Path, help="Path to Rapid7 CSV output")
    parser.add_argument("--sonarqube", type=Path, help="Path to SonarQube JSON output")
    parser.add_argument(
        "--aws-securityhub",
        type=Path,
        help="Path to AWS Security Hub (ASFF) JSON output",
    )
    parser.add_argument("--prisma", type=Path, help="Path to Prisma Cloud CSV output")
    parser.add_argument("--veracode", type=Path, help="Path to Veracode JSON output")
    parser.add_argument("--invicti", type=Path, help="Path to Invicti JSON output")

    args = parser.parse_args()

    if not any(
        [
            args.snyk,
            args.tenable,
            args.wiz,
            args.rapid7,
            args.sonarqube,
            args.aws_securityhub,
            args.prisma,
            args.veracode,
            args.invicti,
        ]
    ):
        print("Error: At least one scanner input must be provided")
        parser.print_help()
        return 1

    print("=" * 80)
    print("FixOps Multi-Scanner Consolidation")
    print("=" * 80)
    print()

    all_findings: List[NormalizedFinding] = []

    if args.snyk and args.snyk.exists():
        print(f"Loading Snyk findings from {args.snyk}...")
        with args.snyk.open("r") as f:
            snyk_data = json.load(f)
        snyk_findings = SnykNormalizer.normalize(snyk_data)
        all_findings.extend(snyk_findings)
        print(f"  ✓ Loaded {len(snyk_findings):,} Snyk findings")

    if args.tenable and args.tenable.exists():
        print(f"Loading Tenable findings from {args.tenable}...")
        tenable_findings = TenableNormalizer.normalize(args.tenable)
        all_findings.extend(tenable_findings)
        print(f"  ✓ Loaded {len(tenable_findings):,} Tenable findings")

    if args.wiz and args.wiz.exists():
        print(f"Loading Wiz findings from {args.wiz}...")
        with args.wiz.open("r") as f:
            wiz_data = json.load(f)
        wiz_findings = WizNormalizer.normalize(wiz_data)
        all_findings.extend(wiz_findings)
        print(f"  ✓ Loaded {len(wiz_findings):,} Wiz findings")

    if args.rapid7 and args.rapid7.exists():
        print(f"Loading Rapid7 findings from {args.rapid7}...")
        rapid7_findings = Rapid7Normalizer.normalize(args.rapid7)
        all_findings.extend(rapid7_findings)
        print(f"  ✓ Loaded {len(rapid7_findings):,} Rapid7 findings")

    if args.sonarqube and args.sonarqube.exists():
        print(f"Loading SonarQube findings from {args.sonarqube}...")
        with args.sonarqube.open("r") as f:
            sonar_data = json.load(f)
        sonar_findings = SonarQubeNormalizer.normalize(sonar_data)
        all_findings.extend(sonar_findings)
        print(f"  ✓ Loaded {len(sonar_findings):,} SonarQube findings")

    if args.aws_securityhub and args.aws_securityhub.exists():
        print(f"Loading AWS Security Hub findings from {args.aws_securityhub}...")
        with args.aws_securityhub.open("r") as f:
            asff_data = json.load(f)
        asff_findings = AWSSecurityHubNormalizer.normalize(asff_data)
        all_findings.extend(asff_findings)
        print(f"  ✓ Loaded {len(asff_findings):,} AWS Security Hub findings")

    if args.prisma and args.prisma.exists():
        print(f"Loading Prisma Cloud findings from {args.prisma}...")
        with args.prisma.open("r") as f:
            reader = csv.DictReader(f)
            prisma_data = list(reader)
        prisma_findings = PrismaCloudNormalizer.normalize(prisma_data)
        all_findings.extend(prisma_findings)
        print(f"  ✓ Loaded {len(prisma_findings):,} Prisma Cloud findings")

    if args.veracode and args.veracode.exists():
        print(f"Loading Veracode findings from {args.veracode}...")
        with args.veracode.open("r") as f:
            veracode_data = json.load(f)
        veracode_findings = VeracodeNormalizer.normalize(veracode_data)
        all_findings.extend(veracode_findings)
        print(f"  ✓ Loaded {len(veracode_findings):,} Veracode findings")

    if args.invicti and args.invicti.exists():
        print(f"Loading Invicti findings from {args.invicti}...")
        with args.invicti.open("r") as f:
            invicti_data = json.load(f)
        invicti_findings = InvictiNormalizer.normalize(invicti_data)
        all_findings.extend(invicti_findings)
        print(f"  ✓ Loaded {len(invicti_findings):,} Invicti findings")

    print(f"\nTotal findings loaded: {len(all_findings):,}")

    print("\nDeduplicating findings across scanners...")
    deduplicated = deduplicate_findings(all_findings)
    print(f"  ✓ After deduplication: {len(deduplicated):,} unique findings")
    print(f"  ✓ Eliminated {len(all_findings) - len(deduplicated):,} duplicates")

    print("\nLoading threat intelligence feeds...")
    kev_cves = load_kev_data()
    epss_scores = load_epss_data()
    print(f"  ✓ Loaded {len(kev_cves):,} KEV CVEs")
    print(f"  ✓ Loaded {len(epss_scores):,} EPSS scores")

    print("\nEnriching findings with KEV/EPSS data...")
    enrich_findings(deduplicated, kev_cves, epss_scores)
    kev_count = sum(1 for f in deduplicated if f.kev)
    epss_count = sum(1 for f in deduplicated if f.epss_score > 0)
    print(f"  ✓ {kev_count:,} findings are KEV-listed")
    print(f"  ✓ {epss_count:,} findings have EPSS scores")

    print("\nApplying bidirectional risk scoring...")
    score_findings(deduplicated)
    print("  ✓ Scored all findings with Day-0 + Day-N factors")

    print("\nMapping findings to compliance frameworks...")
    map_compliance_controls(deduplicated)
    print("  ✓ Mapped findings to SOC2, ISO27001, NIST, Essential 8")

    print("\nGenerating compliance gap analysis...")
    compliance_gap = generate_compliance_gap(deduplicated)

    print("\nGenerating prioritized fix plan...")
    fix_plan = generate_fix_plan(deduplicated)
    print(f"  ✓ Created {len(fix_plan)} fix batches")

    print("\nSaving outputs...")
    save_outputs(deduplicated, compliance_gap, fix_plan)

    print("\n" + "=" * 80)
    print("✓ Multi-Scanner Consolidation Complete")
    print("=" * 80)
    print("\nOutputs:")
    print(f"  - {ARTIFACTS_DIR / 'prioritized_top100.json'}")
    print(f"  - {ARTIFACTS_DIR / 'compliance_gap.json'}")
    print(f"  - {ARTIFACTS_DIR / 'fix_plan.csv'}")
    print(f"  - {REPORTS_DIR / 'multiscanner_summary.md'}")
    print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
