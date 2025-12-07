"""FixOps Terraform Analysis Engine - Proprietary IaC security analysis."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class TerraformIssueType(Enum):
    """Terraform security issue types."""
    
    PUBLIC_ACCESS = "public_access"
    UNENCRYPTED_STORAGE = "unencrypted_storage"
    WEAK_ENCRYPTION = "weak_encryption"
    MISSING_IAM_POLICY = "missing_iam_policy"
    OVERLY_PERMISSIVE_IAM = "overly_permissive_iam"
    MISSING_LOGGING = "missing_logging"
    INSECURE_NETWORK = "insecure_network"
    HARDCODED_SECRETS = "hardcoded_secrets"
    MISSING_TAGS = "missing_tags"
    INSECURE_DEFAULT = "insecure_default"


@dataclass
class TerraformFinding:
    """Terraform security finding."""
    
    issue_type: TerraformIssueType
    severity: str  # critical, high, medium, low
    resource_type: str
    resource_name: str
    file_path: str
    line_number: int
    description: str = ""
    recommendation: str = ""
    code_snippet: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class TerraformResult:
    """Terraform analysis result."""
    
    findings: List[TerraformFinding]
    total_findings: int
    findings_by_type: Dict[str, int]
    findings_by_severity: Dict[str, int]
    files_analyzed: int
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class TerraformAnalyzer:
    """FixOps Terraform Analyzer - Proprietary IaC security analysis."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize Terraform analyzer."""
        self.config = config or {}
        self.security_patterns = self._build_security_patterns()
    
    def _build_security_patterns(self) -> Dict[str, List[Dict[str, Any]]]:
        """Build proprietary security patterns for Terraform."""
        return {
            "s3_public_access": [
                {
                    "pattern": r'aws_s3_bucket\s+\w+\s*\{[^}]*block_public_acls\s*=\s*false',
                    "severity": "critical",
                    "issue_type": TerraformIssueType.PUBLIC_ACCESS,
                },
                {
                    "pattern": r'aws_s3_bucket\s+\w+\s*\{[^}]*block_public_policy\s*=\s*false',
                    "severity": "critical",
                    "issue_type": TerraformIssueType.PUBLIC_ACCESS,
                },
            ],
            "unencrypted_storage": [
                {
                    "pattern": r'aws_s3_bucket\s+\w+\s*\{[^}]*server_side_encryption_configuration\s*\{[^}]*\}',
                    "negate": True,  # Missing encryption
                    "severity": "high",
                    "issue_type": TerraformIssueType.UNENCRYPTED_STORAGE,
                },
                {
                    "pattern": r'aws_ebs_volume\s+\w+\s*\{[^}]*encrypted\s*=\s*false',
                    "severity": "high",
                    "issue_type": TerraformIssueType.UNENCRYPTED_STORAGE,
                },
            ],
            "overly_permissive_iam": [
                {
                    "pattern": r'aws_iam_policy\s+\w+\s*\{[^}]*"Effect"\s*:\s*"Allow"[^}]*"Action"\s*:\s*"\*"',
                    "severity": "critical",
                    "issue_type": TerraformIssueType.OVERLY_PERMISSIVE_IAM,
                },
                {
                    "pattern": r'"Resource"\s*:\s*"\*"',
                    "severity": "high",
                    "issue_type": TerraformIssueType.OVERLY_PERMISSIVE_IAM,
                },
            ],
            "hardcoded_secrets": [
                {
                    "pattern": r'(?:password|secret|api_key|access_key)\s*=\s*["\']([^"\']+)["\']',
                    "severity": "critical",
                    "issue_type": TerraformIssueType.HARDCODED_SECRETS,
                },
            ],
            "insecure_network": [
                {
                    "pattern": r'aws_security_group\s+\w+\s*\{[^}]*cidr_blocks\s*=\s*\["0\.0\.0\.0/0"\]',
                    "severity": "high",
                    "issue_type": TerraformIssueType.INSECURE_NETWORK,
                },
            ],
        }
    
    def analyze(self, terraform_path: Path) -> TerraformResult:
        """Analyze Terraform files for security issues."""
        findings = []
        files_analyzed = 0
        
        # Find all .tf files
        tf_files = list(terraform_path.rglob("*.tf"))
        
        for tf_file in tf_files:
            try:
                with open(tf_file, "r", encoding="utf-8") as f:
                    content = f.read()
                
                file_findings = self._analyze_file(tf_file, content)
                findings.extend(file_findings)
                files_analyzed += 1
            
            except Exception as e:
                logger.warning(f"Failed to analyze {tf_file}: {e}")
        
        return self._build_result(findings, files_analyzed)
    
    def _analyze_file(self, file_path: Path, content: str) -> List[TerraformFinding]:
        """Analyze a single Terraform file."""
        findings = []
        lines = content.split("\n")
        
        # Check each security pattern
        for category, patterns in self.security_patterns.items():
            for pattern_config in patterns:
                pattern = pattern_config["pattern"]
                severity = pattern_config["severity"]
                issue_type = pattern_config["issue_type"]
                negate = pattern_config.get("negate", False)
                
                matches = re.finditer(pattern, content, re.MULTILINE | re.DOTALL)
                
                for match in matches:
                    # Check if this is a negative pattern (missing something)
                    if negate:
                        # For negative patterns, we want to flag if pattern is NOT found
                        # This is handled differently - we check for absence
                        continue
                    
                    # Find line number
                    line_number = content[: match.start()].count("\n") + 1
                    
                    # Extract resource name
                    resource_name = self._extract_resource_name(match.group(0))
                    
                    finding = TerraformFinding(
                        issue_type=issue_type,
                        severity=severity,
                        resource_type=self._extract_resource_type(match.group(0)),
                        resource_name=resource_name,
                        file_path=str(file_path),
                        line_number=line_number,
                        description=self._get_description(issue_type),
                        recommendation=self._get_recommendation(issue_type),
                        code_snippet=lines[line_number - 1] if line_number <= len(lines) else "",
                    )
                    
                    findings.append(finding)
        
        # Check for missing encryption (negative patterns)
        if "aws_s3_bucket" in content:
            if "server_side_encryption_configuration" not in content:
                # Find S3 bucket resources
                bucket_matches = re.finditer(
                    r'aws_s3_bucket\s+(\w+)', content
                )
                for match in bucket_matches:
                    line_number = content[: match.start()].count("\n") + 1
                    finding = TerraformFinding(
                        issue_type=TerraformIssueType.UNENCRYPTED_STORAGE,
                        severity="high",
                        resource_type="aws_s3_bucket",
                        resource_name=match.group(1),
                        file_path=str(file_path),
                        line_number=line_number,
                        description="S3 bucket missing server-side encryption",
                        recommendation="Add server_side_encryption_configuration block",
                    )
                    findings.append(finding)
        
        return findings
    
    def _extract_resource_name(self, code: str) -> str:
        """Extract resource name from Terraform code."""
        match = re.search(r'(?:resource|data)\s+"[^"]+"\s+"([^"]+)"', code)
        return match.group(1) if match else "unknown"
    
    def _extract_resource_type(self, code: str) -> str:
        """Extract resource type from Terraform code."""
        match = re.search(r'(?:resource|data)\s+"([^"]+)"', code)
        return match.group(1) if match else "unknown"
    
    def _get_description(self, issue_type: TerraformIssueType) -> str:
        """Get description for issue type."""
        descriptions = {
            TerraformIssueType.PUBLIC_ACCESS: "Resource has public access enabled",
            TerraformIssueType.UNENCRYPTED_STORAGE: "Storage resource is not encrypted",
            TerraformIssueType.OVERLY_PERMISSIVE_IAM: "IAM policy is overly permissive",
            TerraformIssueType.HARDCODED_SECRETS: "Hardcoded secrets detected",
            TerraformIssueType.INSECURE_NETWORK: "Network security group allows insecure access",
        }
        return descriptions.get(issue_type, "Security issue detected")
    
    def _get_recommendation(self, issue_type: TerraformIssueType) -> str:
        """Get recommendation for issue type."""
        recommendations = {
            TerraformIssueType.PUBLIC_ACCESS: "Set block_public_acls and block_public_policy to true",
            TerraformIssueType.UNENCRYPTED_STORAGE: "Enable encryption for storage resources",
            TerraformIssueType.OVERLY_PERMISSIVE_IAM: "Use principle of least privilege",
            TerraformIssueType.HARDCODED_SECRETS: "Use secrets management (AWS Secrets Manager, etc.)",
            TerraformIssueType.INSECURE_NETWORK: "Restrict CIDR blocks to specific IP ranges",
        }
        return recommendations.get(issue_type, "Review and fix security configuration")
    
    def _build_result(
        self, findings: List[TerraformFinding], files_analyzed: int
    ) -> TerraformResult:
        """Build Terraform analysis result."""
        findings_by_type: Dict[str, int] = {}
        findings_by_severity: Dict[str, int] = {}
        
        for finding in findings:
            issue_type = finding.issue_type.value
            findings_by_type[issue_type] = findings_by_type.get(issue_type, 0) + 1
            
            severity = finding.severity
            findings_by_severity[severity] = findings_by_severity.get(severity, 0) + 1
        
        return TerraformResult(
            findings=findings,
            total_findings=len(findings),
            findings_by_type=findings_by_type,
            findings_by_severity=findings_by_severity,
            files_analyzed=files_analyzed,
        )
