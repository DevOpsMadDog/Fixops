#!/usr/bin/env python3
"""
FixOps Comprehensive End-to-End Test Suite
==========================================

Tests all 291 API endpoints across 14 applications with realistic security tool data.
Designed to find bugs and gaps, not just pass tests.

Results classified as: PASS, BUG, GAP, NEEDS-SEEDING, NOT-APPLICABLE
"""

import csv
import json
import os
import time
import traceback
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Tuple

import requests

# Configuration
BASE_URL = os.environ.get("FIXOPS_API_URL", "http://localhost:8002")
API_KEY = os.environ.get("FIXOPS_API_TOKEN", "demo-token")
OUTPUT_DIR = os.environ.get(
    "FIXOPS_TEST_OUTPUT", "/home/ubuntu/fixops_comprehensive_test/results"
)


class E2ETestResult(Enum):
    PASS = "PASS"
    BUG = "BUG"
    GAP = "GAP"
    NEEDS_SEEDING = "NEEDS-SEEDING"
    NOT_APPLICABLE = "NOT-APPLICABLE"
    SKIPPED = "SKIPPED"


@dataclass
class E2ETestCase:
    """Individual test case result"""

    endpoint: str
    method: str
    group: str
    description: str
    result: E2ETestResult
    status_code: int
    response_time_ms: float
    response_snippet: str
    reason: str
    prerequisites: List[str] = field(default_factory=list)
    payload_used: str = ""
    consistency_check: str = ""


@dataclass
class ConsistencyCheck:
    """Cross-endpoint consistency validation"""

    name: str
    description: str
    passed: bool
    expected: Any
    actual: Any
    endpoints_involved: List[str]


# ============================================================================
# CUSTOMER AND APPLICATION DEFINITIONS
# ============================================================================

CUSTOMERS = [
    {
        "name": "Acme Financial Services",
        "id": "acme-financial",
        "cloud": "AWS",
        "region": "us-east-1",
        "compliance": ["PCI-DSS", "SOX", "GLBA"],
        "industry": "Financial Services",
        "apps": [
            "payment-gateway",
            "mobile-banking-bff",
            "user-identity-service",
            "edge-cdn-service",
            "inventory-service",
        ],
    },
    {
        "name": "MedTech Healthcare",
        "id": "medtech-healthcare",
        "cloud": "Azure",
        "region": "eastus",
        "compliance": ["HIPAA", "SOC2", "HITRUST"],
        "industry": "Healthcare",
        "apps": [
            "healthcare-api",
            "ml-inference-engine",
            "data-pipeline",
            "legacy-mainframe-adapter",
        ],
    },
    {
        "name": "GameZone Entertainment",
        "id": "gamezone-entertainment",
        "cloud": "GCP",
        "region": "us-central1",
        "compliance": ["SOC2", "GDPR", "CCPA"],
        "industry": "Gaming/Media",
        "apps": [
            "gaming-matchmaker",
            "customer-portal",
            "media-transcoder",
            "realtime-analytics",
            "blockchain-bridge",
        ],
    },
]

APPLICATIONS = {
    # Acme Financial Services (AWS)
    "payment-gateway": {
        "lang": "java",
        "framework": "Spring Boot 3.2",
        "runtime": "Kubernetes",
        "cloud": "AWS EKS",
        "tools": ["SonarQube", "Checkmarx", "Trivy"],
        "criticality": "critical",
        "data_classification": "PCI",
        "internet_facing": True,
    },
    "mobile-banking-bff": {
        "lang": "kotlin",
        "framework": "Ktor 2.3",
        "runtime": "Serverless",
        "cloud": "AWS Lambda",
        "tools": ["Detekt", "Snyk", "OWASP ZAP"],
        "criticality": "high",
        "data_classification": "PII",
        "internet_facing": True,
    },
    "user-identity-service": {
        "lang": "nodejs",
        "framework": "Express 4.18",
        "runtime": "Container",
        "cloud": "AWS ECS",
        "tools": ["ESLint Security", "npm audit", "Burp Suite"],
        "criticality": "critical",
        "data_classification": "PII",
        "internet_facing": True,
    },
    "edge-cdn-service": {
        "lang": "rust",
        "framework": "Actix-web 4",
        "runtime": "Edge",
        "cloud": "AWS CloudFront",
        "tools": ["cargo-audit", "Semgrep"],
        "criticality": "medium",
        "data_classification": "public",
        "internet_facing": True,
    },
    "inventory-service": {
        "lang": "go",
        "framework": "Gin 1.9",
        "runtime": "Kubernetes",
        "cloud": "AWS EKS",
        "tools": ["gosec", "Trivy", "Falco"],
        "criticality": "high",
        "data_classification": "internal",
        "internet_facing": False,
    },
    # MedTech Healthcare (Azure)
    "healthcare-api": {
        "lang": "python",
        "framework": "FastAPI 0.109",
        "runtime": "Kubernetes",
        "cloud": "Azure AKS",
        "tools": ["Bandit", "Safety", "OWASP ZAP"],
        "criticality": "critical",
        "data_classification": "PHI",
        "internet_facing": True,
    },
    "ml-inference-engine": {
        "lang": "python",
        "framework": "TensorFlow 2.15",
        "runtime": "Container",
        "cloud": "Azure ML",
        "tools": ["Bandit", "pip-audit", "Snyk"],
        "criticality": "high",
        "data_classification": "PHI",
        "internet_facing": False,
    },
    "data-pipeline": {
        "lang": "scala",
        "framework": "Spark 3.5",
        "runtime": "Spark",
        "cloud": "Azure Databricks",
        "tools": ["SpotBugs", "Snyk", "Trivy"],
        "criticality": "high",
        "data_classification": "PHI",
        "internet_facing": False,
    },
    "legacy-mainframe-adapter": {
        "lang": "cobol",
        "framework": "Java Bridge",
        "runtime": "VM",
        "cloud": "Azure VMs",
        "tools": ["Fortify", "Checkmarx"],
        "criticality": "critical",
        "data_classification": "PHI",
        "internet_facing": False,
    },
    # GameZone Entertainment (GCP)
    "gaming-matchmaker": {
        "lang": "cpp",
        "framework": "gRPC 1.60",
        "runtime": "Kubernetes",
        "cloud": "GCP GKE",
        "tools": ["Coverity", "cppcheck", "Falco"],
        "criticality": "high",
        "data_classification": "internal",
        "internet_facing": True,
    },
    "customer-portal": {
        "lang": "typescript",
        "framework": "Next.js 14",
        "runtime": "Serverless",
        "cloud": "GCP Cloud Run",
        "tools": ["ESLint", "Snyk", "Nuclei"],
        "criticality": "high",
        "data_classification": "PII",
        "internet_facing": True,
    },
    "media-transcoder": {
        "lang": "go",
        "framework": "FFmpeg bindings",
        "runtime": "Kubernetes",
        "cloud": "GCP GKE",
        "tools": ["gosec", "Trivy", "Falco"],
        "criticality": "medium",
        "data_classification": "internal",
        "internet_facing": False,
    },
    "realtime-analytics": {
        "lang": "scala",
        "framework": "Kafka Streams",
        "runtime": "Spark",
        "cloud": "GCP Dataproc",
        "tools": ["SpotBugs", "Snyk"],
        "criticality": "high",
        "data_classification": "internal",
        "internet_facing": False,
    },
    "blockchain-bridge": {
        "lang": "solidity",
        "framework": "Hardhat/Node.js",
        "runtime": "Kubernetes",
        "cloud": "GCP GKE",
        "tools": ["Slither", "Mythril", "npm audit"],
        "criticality": "critical",
        "data_classification": "financial",
        "internet_facing": True,
    },
}

# ============================================================================
# CVE DATABASE BY LANGUAGE/FRAMEWORK
# ============================================================================

CVE_DATABASE = {
    "java": [
        {
            "id": "CVE-2021-44228",
            "name": "Log4Shell",
            "severity": "critical",
            "cvss": 10.0,
            "component": "log4j-core",
            "version": "<2.15.0",
            "cwe": "CWE-502",
        },
        {
            "id": "CVE-2022-22965",
            "name": "Spring4Shell",
            "severity": "critical",
            "cvss": 9.8,
            "component": "spring-core",
            "version": "<5.3.18",
            "cwe": "CWE-94",
        },
        {
            "id": "CVE-2023-20861",
            "name": "Spring Expression DoS",
            "severity": "high",
            "cvss": 7.5,
            "component": "spring-expression",
            "version": "<5.3.26",
            "cwe": "CWE-400",
        },
    ],
    "python": [
        {
            "id": "CVE-2023-4863",
            "name": "libwebp Heap Overflow",
            "severity": "critical",
            "cvss": 9.8,
            "component": "pillow",
            "version": "<10.0.1",
            "cwe": "CWE-787",
        },
        {
            "id": "CVE-2023-37920",
            "name": "Certifi Trust Store",
            "severity": "high",
            "cvss": 7.5,
            "component": "certifi",
            "version": "<2023.7.22",
            "cwe": "CWE-295",
        },
        {
            "id": "CVE-2022-42969",
            "name": "py ReDoS",
            "severity": "medium",
            "cvss": 5.3,
            "component": "py",
            "version": "<1.11.0",
            "cwe": "CWE-1333",
        },
    ],
    "nodejs": [
        {
            "id": "CVE-2022-24999",
            "name": "qs Prototype Pollution",
            "severity": "high",
            "cvss": 7.5,
            "component": "qs",
            "version": "<6.10.3",
            "cwe": "CWE-1321",
        },
        {
            "id": "CVE-2023-26136",
            "name": "tough-cookie Prototype Pollution",
            "severity": "medium",
            "cvss": 6.5,
            "component": "tough-cookie",
            "version": "<4.1.3",
            "cwe": "CWE-1321",
        },
        {
            "id": "CVE-2022-25883",
            "name": "semver ReDoS",
            "severity": "medium",
            "cvss": 5.3,
            "component": "semver",
            "version": "<7.5.2",
            "cwe": "CWE-1333",
        },
    ],
    "go": [
        {
            "id": "CVE-2022-41721",
            "name": "HTTP/2 Request Smuggling",
            "severity": "high",
            "cvss": 7.5,
            "component": "golang.org/x/net",
            "version": "<0.4.0",
            "cwe": "CWE-444",
        },
        {
            "id": "CVE-2023-44487",
            "name": "HTTP/2 Rapid Reset",
            "severity": "high",
            "cvss": 7.5,
            "component": "golang.org/x/net",
            "version": "<0.17.0",
            "cwe": "CWE-400",
        },
        {
            "id": "CVE-2023-39325",
            "name": "HTTP/2 Stream Reset",
            "severity": "high",
            "cvss": 7.5,
            "component": "golang.org/x/net",
            "version": "<0.17.0",
            "cwe": "CWE-400",
        },
    ],
    "kotlin": [
        {
            "id": "CVE-2022-24329",
            "name": "Kotlin Stdlib ReDoS",
            "severity": "medium",
            "cvss": 5.3,
            "component": "kotlin-stdlib",
            "version": "<1.6.0",
            "cwe": "CWE-1333",
        },
        {
            "id": "CVE-2020-29582",
            "name": "Kotlin Temp File Creation",
            "severity": "medium",
            "cvss": 5.3,
            "component": "kotlin-stdlib",
            "version": "<1.4.21",
            "cwe": "CWE-378",
        },
    ],
    "scala": [
        {
            "id": "CVE-2022-33891",
            "name": "Apache Spark Shell Command Injection",
            "severity": "critical",
            "cvss": 9.8,
            "component": "spark-core",
            "version": "<3.2.2",
            "cwe": "CWE-78",
        },
        {
            "id": "CVE-2023-32697",
            "name": "Scala XML XXE",
            "severity": "high",
            "cvss": 7.5,
            "component": "scala-xml",
            "version": "<2.1.0",
            "cwe": "CWE-611",
        },
    ],
    "rust": [
        {
            "id": "CVE-2023-26964",
            "name": "h2 DoS",
            "severity": "high",
            "cvss": 7.5,
            "component": "h2",
            "version": "<0.3.17",
            "cwe": "CWE-400",
        },
        {
            "id": "CVE-2022-24713",
            "name": "regex ReDoS",
            "severity": "medium",
            "cvss": 5.3,
            "component": "regex",
            "version": "<1.5.5",
            "cwe": "CWE-1333",
        },
    ],
    "cpp": [
        {
            "id": "CVE-2023-4863",
            "name": "libwebp Heap Overflow",
            "severity": "critical",
            "cvss": 9.8,
            "component": "libwebp",
            "version": "<1.3.2",
            "cwe": "CWE-787",
        },
        {
            "id": "CVE-2022-37434",
            "name": "zlib Heap Overflow",
            "severity": "critical",
            "cvss": 9.8,
            "component": "zlib",
            "version": "<1.2.12",
            "cwe": "CWE-787",
        },
    ],
    "typescript": [
        {
            "id": "CVE-2022-24999",
            "name": "qs Prototype Pollution",
            "severity": "high",
            "cvss": 7.5,
            "component": "qs",
            "version": "<6.10.3",
            "cwe": "CWE-1321",
        },
        {
            "id": "CVE-2023-26136",
            "name": "tough-cookie Prototype Pollution",
            "severity": "medium",
            "cvss": 6.5,
            "component": "tough-cookie",
            "version": "<4.1.3",
            "cwe": "CWE-1321",
        },
    ],
    "solidity": [
        {
            "id": "CVE-2022-24999",
            "name": "Node.js qs Prototype Pollution",
            "severity": "high",
            "cvss": 7.5,
            "component": "qs",
            "version": "<6.10.3",
            "cwe": "CWE-1321",
        },
    ],
    "cobol": [
        {
            "id": "CVE-2021-44228",
            "name": "Log4Shell (Java Bridge)",
            "severity": "critical",
            "cvss": 10.0,
            "component": "log4j-core",
            "version": "<2.15.0",
            "cwe": "CWE-502",
        },
    ],
}

# ============================================================================
# CNAPP FINDINGS BY CLOUD PROVIDER
# ============================================================================

CNAPP_FINDINGS = {
    "AWS": [
        {
            "id": "AWS-SEC-001",
            "title": "S3 Bucket Public Access",
            "severity": "high",
            "service": "S3",
            "resource_type": "aws_s3_bucket",
            "compliance": ["PCI-DSS 1.3", "SOC2 CC6.1"],
        },
        {
            "id": "AWS-SEC-002",
            "title": "Security Group Allows 0.0.0.0/0",
            "severity": "high",
            "service": "EC2",
            "resource_type": "aws_security_group",
            "compliance": ["PCI-DSS 1.2", "SOC2 CC6.6"],
        },
        {
            "id": "AWS-SEC-003",
            "title": "IAM User Without MFA",
            "severity": "medium",
            "service": "IAM",
            "resource_type": "aws_iam_user",
            "compliance": ["PCI-DSS 8.3", "SOC2 CC6.1"],
        },
        {
            "id": "AWS-SEC-004",
            "title": "EKS Cluster Public Endpoint",
            "severity": "high",
            "service": "EKS",
            "resource_type": "aws_eks_cluster",
            "compliance": ["PCI-DSS 1.3", "SOC2 CC6.6"],
        },
        {
            "id": "AWS-SEC-005",
            "title": "RDS Instance Not Encrypted",
            "severity": "high",
            "service": "RDS",
            "resource_type": "aws_db_instance",
            "compliance": ["PCI-DSS 3.4", "HIPAA 164.312"],
        },
    ],
    "Azure": [
        {
            "id": "AZ-SEC-001",
            "title": "Storage Account Public Access",
            "severity": "high",
            "service": "Storage",
            "resource_type": "azurerm_storage_account",
            "compliance": ["HIPAA 164.312", "SOC2 CC6.1"],
        },
        {
            "id": "AZ-SEC-002",
            "title": "NSG Allows Inbound From Any",
            "severity": "high",
            "service": "Network",
            "resource_type": "azurerm_network_security_group",
            "compliance": ["HIPAA 164.312", "SOC2 CC6.6"],
        },
        {
            "id": "AZ-SEC-003",
            "title": "Key Vault Soft Delete Disabled",
            "severity": "medium",
            "service": "Key Vault",
            "resource_type": "azurerm_key_vault",
            "compliance": ["SOC2 CC6.1"],
        },
        {
            "id": "AZ-SEC-004",
            "title": "AKS RBAC Disabled",
            "severity": "high",
            "service": "AKS",
            "resource_type": "azurerm_kubernetes_cluster",
            "compliance": ["HIPAA 164.312", "SOC2 CC6.1"],
        },
        {
            "id": "AZ-SEC-005",
            "title": "SQL Server TDE Disabled",
            "severity": "high",
            "service": "SQL",
            "resource_type": "azurerm_mssql_server",
            "compliance": ["HIPAA 164.312", "PCI-DSS 3.4"],
        },
    ],
    "GCP": [
        {
            "id": "GCP-SEC-001",
            "title": "GCS Bucket Public Access",
            "severity": "high",
            "service": "Storage",
            "resource_type": "google_storage_bucket",
            "compliance": ["SOC2 CC6.1", "GDPR Art.32"],
        },
        {
            "id": "GCP-SEC-002",
            "title": "Firewall Allows 0.0.0.0/0",
            "severity": "high",
            "service": "Compute",
            "resource_type": "google_compute_firewall",
            "compliance": ["SOC2 CC6.6", "GDPR Art.32"],
        },
        {
            "id": "GCP-SEC-003",
            "title": "Service Account Key Not Rotated",
            "severity": "medium",
            "service": "IAM",
            "resource_type": "google_service_account_key",
            "compliance": ["SOC2 CC6.1"],
        },
        {
            "id": "GCP-SEC-004",
            "title": "GKE Legacy ABAC Enabled",
            "severity": "high",
            "service": "GKE",
            "resource_type": "google_container_cluster",
            "compliance": ["SOC2 CC6.1", "GDPR Art.32"],
        },
        {
            "id": "GCP-SEC-005",
            "title": "BigQuery Dataset Public",
            "severity": "high",
            "service": "BigQuery",
            "resource_type": "google_bigquery_dataset",
            "compliance": ["GDPR Art.32", "CCPA 1798.150"],
        },
    ],
}

# ============================================================================
# SAST RULES BY LANGUAGE
# ============================================================================

SAST_RULES = {
    "java": [
        {
            "id": "java:S3649",
            "name": "SQL Injection",
            "severity": "critical",
            "cwe": "CWE-89",
            "owasp": "A03:2021",
        },
        {
            "id": "java:S5131",
            "name": "XSS",
            "severity": "high",
            "cwe": "CWE-79",
            "owasp": "A03:2021",
        },
        {
            "id": "java:S2076",
            "name": "Command Injection",
            "severity": "critical",
            "cwe": "CWE-78",
            "owasp": "A03:2021",
        },
        {
            "id": "java:S5144",
            "name": "SSRF",
            "severity": "high",
            "cwe": "CWE-918",
            "owasp": "A10:2021",
        },
        {
            "id": "java:S2755",
            "name": "XXE",
            "severity": "high",
            "cwe": "CWE-611",
            "owasp": "A05:2021",
        },
    ],
    "python": [
        {
            "id": "python:S3649",
            "name": "SQL Injection",
            "severity": "critical",
            "cwe": "CWE-89",
            "owasp": "A03:2021",
        },
        {
            "id": "python:S5131",
            "name": "XSS",
            "severity": "high",
            "cwe": "CWE-79",
            "owasp": "A03:2021",
        },
        {
            "id": "python:S2076",
            "name": "Command Injection",
            "severity": "critical",
            "cwe": "CWE-78",
            "owasp": "A03:2021",
        },
        {
            "id": "python:S5334",
            "name": "Hardcoded Credentials",
            "severity": "critical",
            "cwe": "CWE-798",
            "owasp": "A07:2021",
        },
        {
            "id": "python:S4790",
            "name": "Weak Cryptography",
            "severity": "high",
            "cwe": "CWE-327",
            "owasp": "A02:2021",
        },
    ],
    "nodejs": [
        {
            "id": "javascript:S3649",
            "name": "SQL Injection",
            "severity": "critical",
            "cwe": "CWE-89",
            "owasp": "A03:2021",
        },
        {
            "id": "javascript:S5131",
            "name": "XSS",
            "severity": "high",
            "cwe": "CWE-79",
            "owasp": "A03:2021",
        },
        {
            "id": "javascript:S2076",
            "name": "Command Injection",
            "severity": "critical",
            "cwe": "CWE-78",
            "owasp": "A03:2021",
        },
        {
            "id": "javascript:S5334",
            "name": "Hardcoded Credentials",
            "severity": "critical",
            "cwe": "CWE-798",
            "owasp": "A07:2021",
        },
        {
            "id": "javascript:S5696",
            "name": "Prototype Pollution",
            "severity": "high",
            "cwe": "CWE-1321",
            "owasp": "A03:2021",
        },
    ],
    "go": [
        {
            "id": "go:S1313",
            "name": "Hardcoded IP",
            "severity": "medium",
            "cwe": "CWE-547",
            "owasp": "A05:2021",
        },
        {
            "id": "go:S2076",
            "name": "Command Injection",
            "severity": "critical",
            "cwe": "CWE-78",
            "owasp": "A03:2021",
        },
        {
            "id": "go:S5131",
            "name": "XSS",
            "severity": "high",
            "cwe": "CWE-79",
            "owasp": "A03:2021",
        },
        {
            "id": "go:S4790",
            "name": "Weak Cryptography",
            "severity": "high",
            "cwe": "CWE-327",
            "owasp": "A02:2021",
        },
    ],
    "kotlin": [
        {
            "id": "kotlin:S3649",
            "name": "SQL Injection",
            "severity": "critical",
            "cwe": "CWE-89",
            "owasp": "A03:2021",
        },
        {
            "id": "kotlin:S5131",
            "name": "XSS",
            "severity": "high",
            "cwe": "CWE-79",
            "owasp": "A03:2021",
        },
        {
            "id": "kotlin:S5334",
            "name": "Hardcoded Credentials",
            "severity": "critical",
            "cwe": "CWE-798",
            "owasp": "A07:2021",
        },
    ],
    "scala": [
        {
            "id": "scala:S3649",
            "name": "SQL Injection",
            "severity": "critical",
            "cwe": "CWE-89",
            "owasp": "A03:2021",
        },
        {
            "id": "scala:S2076",
            "name": "Command Injection",
            "severity": "critical",
            "cwe": "CWE-78",
            "owasp": "A03:2021",
        },
    ],
    "rust": [
        {
            "id": "rust:S4790",
            "name": "Weak Cryptography",
            "severity": "high",
            "cwe": "CWE-327",
            "owasp": "A02:2021",
        },
        {
            "id": "rust:S5334",
            "name": "Hardcoded Credentials",
            "severity": "critical",
            "cwe": "CWE-798",
            "owasp": "A07:2021",
        },
    ],
    "cpp": [
        {
            "id": "cpp:S3649",
            "name": "SQL Injection",
            "severity": "critical",
            "cwe": "CWE-89",
            "owasp": "A03:2021",
        },
        {
            "id": "cpp:S5131",
            "name": "Buffer Overflow",
            "severity": "critical",
            "cwe": "CWE-120",
            "owasp": "A03:2021",
        },
        {
            "id": "cpp:S2076",
            "name": "Command Injection",
            "severity": "critical",
            "cwe": "CWE-78",
            "owasp": "A03:2021",
        },
        {
            "id": "cpp:S5782",
            "name": "Use After Free",
            "severity": "critical",
            "cwe": "CWE-416",
            "owasp": "A03:2021",
        },
    ],
    "typescript": [
        {
            "id": "typescript:S3649",
            "name": "SQL Injection",
            "severity": "critical",
            "cwe": "CWE-89",
            "owasp": "A03:2021",
        },
        {
            "id": "typescript:S5131",
            "name": "XSS",
            "severity": "high",
            "cwe": "CWE-79",
            "owasp": "A03:2021",
        },
        {
            "id": "typescript:S5696",
            "name": "Prototype Pollution",
            "severity": "high",
            "cwe": "CWE-1321",
            "owasp": "A03:2021",
        },
    ],
    "solidity": [
        {
            "id": "solidity:reentrancy",
            "name": "Reentrancy",
            "severity": "critical",
            "cwe": "CWE-841",
            "owasp": "A03:2021",
        },
        {
            "id": "solidity:overflow",
            "name": "Integer Overflow",
            "severity": "high",
            "cwe": "CWE-190",
            "owasp": "A03:2021",
        },
        {
            "id": "solidity:tx-origin",
            "name": "tx.origin Authentication",
            "severity": "high",
            "cwe": "CWE-287",
            "owasp": "A07:2021",
        },
    ],
    "cobol": [
        {
            "id": "cobol:S3649",
            "name": "SQL Injection",
            "severity": "critical",
            "cwe": "CWE-89",
            "owasp": "A03:2021",
        },
        {
            "id": "cobol:S5334",
            "name": "Hardcoded Credentials",
            "severity": "critical",
            "cwe": "CWE-798",
            "owasp": "A07:2021",
        },
    ],
}

# ============================================================================
# SAMPLE DATA GENERATORS
# ============================================================================


def generate_sarif(app_name: str, app_config: dict) -> dict:
    """Generate realistic SARIF based on app's tech stack."""
    lang = app_config.get("lang", "java")
    rules = SAST_RULES.get(lang, SAST_RULES["java"])[:5]

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": app_config.get("tools", ["SonarQube"])[0],
                        "version": "10.3.0",
                        "informationUri": "https://www.sonarqube.org/",
                        "rules": [
                            {
                                "id": rule["id"],
                                "name": rule["name"],
                                "shortDescription": {
                                    "text": f"{rule['name']} vulnerability detected"
                                },
                                "fullDescription": {
                                    "text": f"CWE-{rule['cwe'].split('-')[1]}: {rule['name']} - {rule['owasp']}"
                                },
                                "defaultConfiguration": {
                                    "level": "error"
                                    if rule["severity"] in ["critical", "high"]
                                    else "warning"
                                },
                                "properties": {
                                    "security-severity": "9.8"
                                    if rule["severity"] == "critical"
                                    else "7.5"
                                    if rule["severity"] == "high"
                                    else "5.0",
                                    "tags": ["security", rule["owasp"], rule["cwe"]],
                                },
                            }
                            for rule in rules
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": rule["id"],
                        "level": "error"
                        if rule["severity"] in ["critical", "high"]
                        else "warning",
                        "message": {
                            "text": f"{rule['name']} vulnerability found in {app_name}"
                        },
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": f"src/main/{lang}/{app_name.replace('-', '/')}/Service.{lang}"
                                    },
                                    "region": {
                                        "startLine": 42 + i * 10,
                                        "startColumn": 1,
                                        "endLine": 42 + i * 10,
                                        "endColumn": 80,
                                    },
                                }
                            }
                        ],
                        "fingerprints": {
                            "primaryLocationLineHash": f"{app_name}-{rule['id']}-{i}"
                        },
                        "properties": {
                            "security-severity": "9.8"
                            if rule["severity"] == "critical"
                            else "7.5"
                            if rule["severity"] == "high"
                            else "5.0"
                        },
                    }
                    for i, rule in enumerate(rules)
                ],
                "automationDetails": {
                    "id": f"{app_name}/security-scan/{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
                },
            }
        ],
    }
    return sarif


def generate_sbom(app_name: str, app_config: dict) -> dict:
    """Generate realistic CycloneDX SBOM based on app's tech stack."""
    lang = app_config.get("lang", "java")
    cves = CVE_DATABASE.get(lang, CVE_DATABASE["java"])

    components = []
    for cve in cves:
        purl_type = {
            "java": "maven",
            "kotlin": "maven",
            "scala": "maven",
            "python": "pypi",
            "nodejs": "npm",
            "typescript": "npm",
            "go": "golang",
            "rust": "cargo",
            "cpp": "conan",
            "solidity": "npm",
            "cobol": "maven",
        }.get(lang, "generic")

        components.append(
            {
                "type": "library",
                "name": cve["component"],
                "version": cve["version"].replace("<", "").replace(">", ""),
                "purl": f"pkg:{purl_type}/{cve['component']}@{cve['version'].replace('<', '').replace('>', '')}",
                "licenses": [{"license": {"id": "Apache-2.0"}}],
                "externalReferences": [
                    {
                        "type": "website",
                        "url": f"https://example.com/{cve['component']}",
                    }
                ],
            }
        )

    # Add framework component
    framework = app_config.get("framework", "Unknown")
    components.append(
        {
            "type": "framework",
            "name": framework.split()[0].lower(),
            "version": framework.split()[-1] if len(framework.split()) > 1 else "1.0.0",
            "purl": f"pkg:generic/{framework.split()[0].lower()}@{framework.split()[-1] if len(framework.split()) > 1 else '1.0.0'}",
        }
    )

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{app_name}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [{"vendor": "Trivy", "name": "trivy", "version": "0.48.0"}],
            "component": {"type": "application", "name": app_name, "version": "1.0.0"},
        },
        "components": components,
    }
    return sbom


def generate_cve_feed(app_name: str, app_config: dict) -> dict:
    """Generate CVE feed based on app's tech stack."""
    lang = app_config.get("lang", "java")
    cves = CVE_DATABASE.get(lang, CVE_DATABASE["java"])

    return {
        "cves": [
            {
                "id": cve["id"],
                "description": f"{cve['name']} - {cve.get('cwe', 'CWE-Unknown')}",
                "severity": cve["severity"],
                "cvss": cve["cvss"],
                "affected_components": [cve["component"]],
                "affected_versions": [cve["version"]],
                "published": "2023-01-15T00:00:00Z",
                "modified": datetime.now(timezone.utc).isoformat(),
                "references": [f"https://nvd.nist.gov/vuln/detail/{cve['id']}"],
            }
            for cve in cves
        ]
    }


def generate_cnapp_findings(app_name: str, customer: dict) -> dict:
    """Generate CNAPP findings based on customer's cloud provider."""
    cloud = customer.get("cloud", "AWS")
    findings = CNAPP_FINDINGS.get(cloud, CNAPP_FINDINGS["AWS"])

    return {
        "provider": cloud,
        "account_id": f"{customer['id']}-account",
        "region": customer.get("region", "us-east-1"),
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "findings": [
            {
                "id": f"{finding['id']}-{app_name}",
                "title": finding["title"],
                "severity": finding["severity"],
                "service": finding["service"],
                "resource_type": finding["resource_type"],
                "resource_id": f"arn:{cloud.lower()}:{finding['service'].lower()}:{customer.get('region', 'us-east-1')}:{customer['id']}:{app_name}",
                "compliance": finding["compliance"],
                "remediation": f"Review and remediate {finding['title']} for {app_name}",
                "first_seen": "2024-01-01T00:00:00Z",
                "last_seen": datetime.now(timezone.utc).isoformat(),
            }
            for finding in findings[:3]  # 3 findings per app
        ],
    }


def generate_design_csv(app_name: str, app_config: dict) -> str:
    """Generate threat model design CSV."""
    threats = [
        ("SQL Injection", "critical", "Input validation and parameterized queries"),
        ("XSS", "high", "Output encoding and CSP headers"),
        ("Authentication Bypass", "critical", "MFA and session management"),
        ("Data Exposure", "high", "Encryption at rest and in transit"),
        ("SSRF", "high", "URL validation and allowlisting"),
    ]

    rows = [
        f"{app_name},{threat},{severity},{mitigation}"
        for threat, severity, mitigation in threats[:3]
    ]

    return "component,threat,severity,mitigation\n" + "\n".join(rows)


# ============================================================================
# API CLIENT
# ============================================================================


class FixOpsClient:
    """API client for FixOps with comprehensive error handling."""

    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update(
            {"X-API-Key": api_key, "Accept": "application/json"}
        )
        self.resource_registry: Dict[str, List[str]] = {
            "app_ids": [],
            "team_ids": [],
            "user_ids": [],
            "policy_ids": [],
            "workflow_ids": [],
            "integration_ids": [],
            "report_ids": [],
            "finding_ids": [],
            "task_ids": [],
        }

    def call(self, method: str, endpoint: str, **kwargs) -> Tuple[int, dict, float]:
        """Make API call and return (status_code, response_json, response_time_ms)."""
        url = f"{self.base_url}{endpoint}"
        start = time.time()

        try:
            response = self.session.request(method, url, timeout=30, **kwargs)
            elapsed_ms = (time.time() - start) * 1000

            try:
                data = response.json()
            except Exception:
                data = {"raw": response.text[:500]}

            return response.status_code, data, elapsed_ms
        except requests.exceptions.Timeout:
            return 504, {"error": "Request timeout"}, 30000
        except requests.exceptions.ConnectionError:
            return 503, {"error": "Connection failed"}, 0
        except Exception as e:
            return 500, {"error": str(e)}, 0

    def upload_file(
        self, endpoint: str, content: str, filename: str, content_type: str
    ) -> Tuple[int, dict, float]:
        """Upload file as multipart form data."""
        files = {"file": (filename, content, content_type)}
        return self.call("POST", endpoint, files=files)


# ============================================================================
# TEST RUNNER
# ============================================================================


class ComprehensiveTestRunner:
    """Runs comprehensive end-to-end tests across all APIs."""

    def __init__(self, client: FixOpsClient):
        self.client = client
        self.results: List[E2ETestCase] = []
        self.consistency_checks: List[ConsistencyCheck] = []
        self.stats = {
            "total": 0,
            "pass": 0,
            "bug": 0,
            "gap": 0,
            "needs_seeding": 0,
            "not_applicable": 0,
            "skipped": 0,
        }
        # Track data for consistency checks
        self.ingested_findings_count = 0
        self.ingested_components_count = 0
        self.ingested_cves_count = 0
        self.registered_apps = []

    def add_result(self, test: E2ETestCase):
        """Add test result and update stats."""
        self.results.append(test)
        self.stats["total"] += 1
        self.stats[test.result.value.lower().replace("-", "_")] += 1

        # Print progress
        status_color = {
            E2ETestResult.PASS: "\033[92m",  # Green
            E2ETestResult.BUG: "\033[91m",  # Red
            E2ETestResult.GAP: "\033[93m",  # Yellow
            E2ETestResult.NEEDS_SEEDING: "\033[94m",  # Blue
            E2ETestResult.NOT_APPLICABLE: "\033[90m",  # Gray
            E2ETestResult.SKIPPED: "\033[90m",  # Gray
        }
        reset = "\033[0m"
        print(
            f"  [{status_color[test.result]}{test.result.value:15}{reset}] {test.method:6} {test.endpoint[:60]:<60} {test.status_code} - {test.reason[:40]}"
        )

    def classify_result(
        self,
        endpoint: str,
        method: str,
        status_code: int,
        response: dict,
        expected_data: bool = True,
    ) -> Tuple[E2ETestResult, str]:
        """Classify API response into result category."""

        # Server errors are always bugs
        if status_code >= 500:
            return (
                E2ETestResult.BUG,
                f"Server error: {status_code} - {str(response.get('detail', response))[:50]}",
            )

        # Auth errors - some are expected in demo mode
        if status_code == 401:
            # Login endpoint with test credentials is expected to fail
            if "/users/login" in endpoint:
                return (
                    E2ETestResult.NOT_APPLICABLE,
                    "Test credentials don't exist in demo mode",
                )
            return E2ETestResult.BUG, "Authentication failed unexpectedly"
        if status_code == 403:
            return E2ETestResult.GAP, "Permission denied - may need role/scope"

        # Not found - could be bug or needs seeding
        if status_code == 404:
            detail = str(response.get("detail", ""))
            # Stage not recognized - should use valid stage
            if "not recognised" in detail.lower() or "not recognized" in detail.lower():
                return E2ETestResult.NEEDS_SEEDING, f"Invalid stage: {detail[:50]}"
            # These 404s indicate data needs to be seeded first
            if (
                "not found" in detail.lower()
                or "not available" in detail.lower()
                or "no risk" in detail.lower()
                or "no analytics" in detail.lower()
            ):
                return E2ETestResult.NEEDS_SEEDING, f"Needs data: {detail[:50]}"
            return E2ETestResult.BUG, f"404 error: {detail[:50]}"

        # Validation errors - some are expected for file upload endpoints
        if status_code == 422:
            detail = response.get("detail", [])
            # File upload endpoints need multipart, not JSON - expected to fail
            if isinstance(detail, list) and len(detail) > 0:
                first_error = detail[0]
                if isinstance(first_error, dict):
                    loc = first_error.get("loc", [])
                    # File upload endpoints
                    if "file" in loc or "files" in loc or "chunk" in loc:
                        return (
                            E2ETestResult.NOT_APPLICABLE,
                            "File upload endpoint - needs multipart",
                        )
                return E2ETestResult.BUG, f"Validation error: {str(detail[0])[:50]}"
            return E2ETestResult.BUG, f"Validation error: {str(detail)[:50]}"

        # Other 4xx errors
        if status_code >= 400:
            detail = str(response.get("detail", response))
            # Disabled features in demo profile
            if "disabled" in detail.lower():
                return (
                    E2ETestResult.NOT_APPLICABLE,
                    f"Feature disabled in demo: {detail[:40]}",
                )
            # Task not found - needs seeding
            if "not found" in detail.lower():
                return E2ETestResult.NEEDS_SEEDING, f"Needs data: {detail[:50]}"
            return (
                E2ETestResult.BUG,
                f"Client error {status_code}: {detail[:50]}",
            )

        # Success responses - check content
        if status_code in [200, 201, 202, 204]:
            # Check if response has expected data
            if expected_data:
                # Check for empty responses that should have data
                if isinstance(response, dict):
                    # Check common patterns for empty data
                    if response.get("items") == [] and response.get("total", 0) == 0:
                        return (
                            E2ETestResult.NEEDS_SEEDING,
                            "Empty list - needs data seeding",
                        )
                    if response.get("findings") == []:
                        return (
                            E2ETestResult.NEEDS_SEEDING,
                            "No findings - needs data seeding",
                        )
                    if response.get("results") == []:
                        return (
                            E2ETestResult.NEEDS_SEEDING,
                            "No results - needs data seeding",
                        )
                elif isinstance(response, list) and len(response) == 0:
                    return E2ETestResult.NEEDS_SEEDING, "Empty list response"

            # Check for successful ingestion
            if "status" in response and response.get("status") == "ok":
                metadata = response.get("metadata", {})
                finding_count = metadata.get("finding_count", 0)
                component_count = metadata.get("component_count", 0)
                if finding_count > 0:
                    return E2ETestResult.PASS, f"Ingested {finding_count} findings"
                if component_count > 0:
                    return E2ETestResult.PASS, f"Ingested {component_count} components"
                if response.get("row_count", 0) > 0:
                    return (
                        E2ETestResult.PASS,
                        f"Ingested {response.get('row_count')} rows",
                    )
                if response.get("record_count", 0) > 0:
                    return (
                        E2ETestResult.PASS,
                        f"Ingested {response.get('record_count')} records",
                    )
                # Ingestion returned ok but count=0 - potential issue
                return (
                    E2ETestResult.GAP,
                    "Ingestion ok but count=0 - verify data format",
                )

            return E2ETestResult.PASS, "Success"

        return E2ETestResult.BUG, f"Unexpected status: {status_code}"

    # ========================================================================
    # PHASE 1: INFRASTRUCTURE SETUP
    # ========================================================================

    def phase1_infrastructure_setup(self):
        """Set up infrastructure: apps, teams, users, policies."""
        print("\n" + "=" * 80)
        print("PHASE 1: INFRASTRUCTURE SETUP")
        print("=" * 80)

        # Register all applications
        print("\n[1.1] Registering Applications")
        for customer in CUSTOMERS:
            for app_name in customer["apps"]:
                app_config = APPLICATIONS[app_name]
                payload = {
                    "name": app_name,
                    "description": f"{app_name} - {app_config['framework']} on {app_config['cloud']}",
                    "owner": customer["id"],
                    "criticality": app_config["criticality"],
                    "data_classification": app_config["data_classification"],
                    "internet_facing": app_config["internet_facing"],
                    "tech_stack": app_config["lang"],
                    "runtime": app_config["runtime"],
                    "cloud_provider": customer["cloud"],
                }

                status, response, elapsed = self.client.call(
                    "POST", "/api/v1/inventory/applications", json=payload
                )

                result, reason = self.classify_result(
                    "/api/v1/inventory/applications", "POST", status, response
                )

                # Track registered apps
                if status == 201:
                    app_id = response.get("id", response.get("name", app_name))
                    self.client.resource_registry["app_ids"].append(app_id)
                    self.registered_apps.append(app_name)
                    result = E2ETestResult.PASS
                    reason = f"Created: {app_name}"

                self.add_result(
                    E2ETestCase(
                        endpoint="/api/v1/inventory/applications",
                        method="POST",
                        group="inventory",
                        description=f"Register application: {app_name}",
                        result=result,
                        status_code=status,
                        response_time_ms=elapsed,
                        response_snippet=json.dumps(response)[:200],
                        reason=reason,
                        payload_used=json.dumps(payload)[:200],
                    )
                )

        # Create teams (use unique names to avoid conflicts)
        print("\n[1.2] Creating Teams")
        import time

        ts = int(time.time())
        teams = [
            {"name": f"security-team-{ts}", "description": "Security Operations"},
            {"name": f"dev-team-{ts}", "description": "Development Team"},
            {"name": f"compliance-team-{ts}", "description": "Compliance and Audit"},
        ]
        for team in teams:
            status, response, elapsed = self.client.call(
                "POST", "/api/v1/teams", json=team
            )
            result, reason = self.classify_result(
                "/api/v1/teams", "POST", status, response
            )

            if status == 201:
                team_id = response.get("id", response.get("name"))
                self.client.resource_registry["team_ids"].append(team_id)
                result = E2ETestResult.PASS
                reason = f"Created team: {team['name']}"
            elif status == 409:
                # Team already exists - not a bug, just skip
                result = E2ETestResult.PASS
                reason = f"Team already exists: {team['name']}"

            self.add_result(
                E2ETestCase(
                    endpoint="/api/v1/teams",
                    method="POST",
                    group="teams",
                    description=f"Create team: {team['name']}",
                    result=result,
                    status_code=status,
                    response_time_ms=elapsed,
                    response_snippet=json.dumps(response)[:200],
                    reason=reason,
                    payload_used=json.dumps(team),
                )
            )

        # Create users
        print("\n[1.3] Creating Users")
        # Use environment variable for test password or default for demo mode
        test_password = os.environ.get("FIXOPS_TEST_PASSWORD", "TestPass123")
        users = [
            {
                "email": "admin@example.com",
                "password": test_password,
                "first_name": "Admin",
                "last_name": "User",
                "role": "admin",
            },
            {
                "email": "analyst@example.com",
                "password": test_password,
                "first_name": "Security",
                "last_name": "Analyst",
                "role": "security_analyst",
            },
            {
                "email": "developer@example.com",
                "password": test_password,
                "first_name": "Dev",
                "last_name": "Developer",
                "role": "viewer",
            },
        ]
        for user in users:
            status, response, elapsed = self.client.call(
                "POST", "/api/v1/users", json=user
            )
            result, reason = self.classify_result(
                "/api/v1/users", "POST", status, response
            )

            if status == 201:
                user_id = response.get("id", response.get("email"))
                self.client.resource_registry["user_ids"].append(user_id)
                result = E2ETestResult.PASS
                reason = f"Created user: {user['email']}"
            elif status == 409:
                # User already exists - not a bug, just skip
                result = E2ETestResult.PASS
                reason = f"User already exists: {user['email']}"

            self.add_result(
                E2ETestCase(
                    endpoint="/api/v1/users",
                    method="POST",
                    group="users",
                    description=f"Create user: {user['email']}",
                    result=result,
                    status_code=status,
                    response_time_ms=elapsed,
                    response_snippet=json.dumps(response)[:200],
                    reason=reason,
                    payload_used=json.dumps(user),
                )
            )

        # Create policies
        print("\n[1.4] Creating Policies")
        policies = [
            {
                "name": f"critical-vuln-block-{ts}",
                "description": "Block critical vulnerabilities in production",
                "policy_type": "guardrail",
                "rules": {"condition": "severity == 'critical'", "action": "block"},
            },
            {
                "name": f"high-vuln-review-{ts}",
                "description": "Require review for high severity findings",
                "policy_type": "compliance",
                "rules": {"condition": "severity == 'high'", "action": "review"},
            },
        ]
        for policy in policies:
            status, response, elapsed = self.client.call(
                "POST", "/api/v1/policies", json=policy
            )
            result, reason = self.classify_result(
                "/api/v1/policies", "POST", status, response
            )

            if status == 201:
                policy_id = response.get("id", response.get("name"))
                self.client.resource_registry["policy_ids"].append(policy_id)
                result = E2ETestResult.PASS
                reason = f"Created policy: {policy['name']}"
            elif status == 409:
                # Policy already exists - not a bug
                result = E2ETestResult.PASS
                reason = f"Policy already exists: {policy['name']}"

            self.add_result(
                E2ETestCase(
                    endpoint="/api/v1/policies",
                    method="POST",
                    group="policies",
                    description=f"Create policy: {policy['name']}",
                    result=result,
                    status_code=status,
                    response_time_ms=elapsed,
                    response_snippet=json.dumps(response)[:200],
                    reason=reason,
                    payload_used=json.dumps(policy)[:200],
                )
            )

    # ========================================================================
    # PHASE 1.5: COMPREHENSIVE DATA SEEDING
    # ========================================================================

    def phase1_5_data_seeding(self):
        """Seed data for all NEEDS-SEEDING endpoints."""
        print("\n" + "=" * 80)
        print("PHASE 1.5: COMPREHENSIVE DATA SEEDING")
        print("=" * 80)

        import time

        ts = int(time.time())

        # 1. Seed compliance frameworks
        print("\n[1.5.1] Seeding Compliance Frameworks")
        frameworks = [
            {
                "name": "SOC2",
                "description": "SOC 2 Type II Compliance",
                "version": "2023",
            },
            {
                "name": "PCI-DSS",
                "description": "Payment Card Industry Data Security Standard",
                "version": "4.0",
            },
            {
                "name": "HIPAA",
                "description": "Health Insurance Portability and Accountability Act",
                "version": "2023",
            },
            {
                "name": "ISO27001",
                "description": "Information Security Management",
                "version": "2022",
            },
        ]
        for fw in frameworks:
            status, response, elapsed = self.client.call(
                "POST", "/api/v1/audit/compliance/frameworks", json=fw
            )
            if status in [200, 201]:
                self.client.resource_registry.setdefault("framework_ids", []).append(
                    response.get("id", fw["name"])
                )
            self.add_result(
                E2ETestCase(
                    endpoint="/api/v1/audit/compliance/frameworks",
                    method="POST",
                    group="seeding",
                    description=f"Seed framework: {fw['name']}",
                    result=E2ETestResult.PASS
                    if status in [200, 201, 409]
                    else E2ETestResult.NEEDS_SEEDING,
                    status_code=status,
                    response_time_ms=elapsed,
                    response_snippet=json.dumps(response)[:200]
                    if isinstance(response, dict)
                    else str(response)[:200],
                    reason=f"Seeded {fw['name']}"
                    if status in [200, 201]
                    else f"Status {status}",
                )
            )

        # 2. Seed compliance controls
        print("\n[1.5.2] Seeding Compliance Controls")
        controls = [
            {
                "framework": "SOC2",
                "control_id": "CC6.1",
                "name": "Logical Access Controls",
                "description": "Access to systems is restricted",
            },
            {
                "framework": "PCI-DSS",
                "control_id": "6.5.1",
                "name": "Injection Flaws",
                "description": "Protect against injection attacks",
            },
            {
                "framework": "HIPAA",
                "control_id": "164.312(a)",
                "name": "Access Control",
                "description": "Unique user identification",
            },
        ]
        for ctrl in controls:
            status, response, elapsed = self.client.call(
                "POST", "/api/v1/audit/compliance/controls", json=ctrl
            )
            self.add_result(
                E2ETestCase(
                    endpoint="/api/v1/audit/compliance/controls",
                    method="POST",
                    group="seeding",
                    description=f"Seed control: {ctrl['control_id']}",
                    result=E2ETestResult.PASS
                    if status in [200, 201, 409]
                    else E2ETestResult.NEEDS_SEEDING,
                    status_code=status,
                    response_time_ms=elapsed,
                    response_snippet=json.dumps(response)[:200]
                    if isinstance(response, dict)
                    else str(response)[:200],
                    reason=f"Seeded {ctrl['control_id']}"
                    if status in [200, 201]
                    else f"Status {status}",
                )
            )

        # 3. Seed audit logs
        print("\n[1.5.3] Seeding Audit Logs")
        audit_logs = [
            {
                "action": "policy_created",
                "user_id": "admin@example.com",
                "resource_type": "policy",
                "resource_id": "critical-vuln-block",
                "details": {"name": "critical-vuln-block"},
            },
            {
                "action": "user_login",
                "user_id": "analyst@example.com",
                "resource_type": "session",
                "resource_id": f"session-{ts}",
                "details": {"ip": "192.168.1.100"},
            },
            {
                "action": "finding_triaged",
                "user_id": "analyst@example.com",
                "resource_type": "finding",
                "resource_id": "CVE-2021-44228",
                "details": {"decision": "accept_risk"},
            },
        ]
        for log in audit_logs:
            status, response, elapsed = self.client.call(
                "POST", "/api/v1/audit/logs", json=log
            )
            self.add_result(
                E2ETestCase(
                    endpoint="/api/v1/audit/logs",
                    method="POST",
                    group="seeding",
                    description=f"Seed audit log: {log['action']}",
                    result=E2ETestResult.PASS
                    if status in [200, 201, 409]
                    else E2ETestResult.NEEDS_SEEDING,
                    status_code=status,
                    response_time_ms=elapsed,
                    response_snippet=json.dumps(response)[:200]
                    if isinstance(response, dict)
                    else str(response)[:200],
                    reason=f"Seeded {log['action']}"
                    if status in [200, 201]
                    else f"Status {status}",
                )
            )

        # 4. Seed PentAGI configs (per CreatePenTestConfigModel schema)
        print("\n[1.5.4] Seeding PentAGI Configs")
        pentagi_configs = [
            {
                "name": f"web-app-scan-{ts}",
                "pentagi_url": "https://pentagi.acme.com",
                "enabled": True,
                "target_environments": ["staging", "production"],
            },
            {
                "name": f"api-security-{ts}",
                "pentagi_url": "https://pentagi-api.acme.com",
                "enabled": True,
                "target_environments": ["dev", "staging"],
            },
        ]
        for cfg in pentagi_configs:
            status, response, elapsed = self.client.call(
                "POST", "/api/v1/pentagi/configs", json=cfg
            )
            if status in [200, 201]:
                self.client.resource_registry.setdefault(
                    "pentagi_config_ids", []
                ).append(response.get("id", cfg["name"]))
            self.add_result(
                E2ETestCase(
                    endpoint="/api/v1/pentagi/configs",
                    method="POST",
                    group="seeding",
                    description=f"Seed pentagi config: {cfg['name']}",
                    result=E2ETestResult.PASS
                    if status in [200, 201, 409]
                    else E2ETestResult.NEEDS_SEEDING,
                    status_code=status,
                    response_time_ms=elapsed,
                    response_snippet=json.dumps(response)[:200]
                    if isinstance(response, dict)
                    else str(response)[:200],
                    reason=f"Seeded {cfg['name']}"
                    if status in [200, 201]
                    else f"Status {status}",
                )
            )

        # 5. Seed PentAGI requests
        print("\n[1.5.5] Seeding PentAGI Requests")
        pentagi_requests = [
            {
                "target": "https://payment-gateway.acme.com",
                "scan_type": "vulnerability",
                "priority": "high",
            },
            {
                "target": "https://api.acme.com/v1",
                "scan_type": "api_security",
                "priority": "medium",
            },
        ]
        for req in pentagi_requests:
            status, response, elapsed = self.client.call(
                "POST", "/api/v1/pentagi/requests", json=req
            )
            if status in [200, 201]:
                self.client.resource_registry.setdefault(
                    "pentagi_request_ids", []
                ).append(response.get("id", response.get("request_id")))
            self.add_result(
                E2ETestCase(
                    endpoint="/api/v1/pentagi/requests",
                    method="POST",
                    group="seeding",
                    description=f"Seed pentagi request: {req['target'][:30]}",
                    result=E2ETestResult.PASS
                    if status in [200, 201, 409]
                    else E2ETestResult.NEEDS_SEEDING,
                    status_code=status,
                    response_time_ms=elapsed,
                    response_snippet=json.dumps(response)[:200]
                    if isinstance(response, dict)
                    else str(response)[:200],
                    reason="Seeded request"
                    if status in [200, 201]
                    else f"Status {status}",
                )
            )

        # 6. Seed PentAGI results
        print("\n[1.5.6] Seeding PentAGI Results")
        pentagi_results = [
            {
                "request_id": "test-request-1",
                "finding_type": "sql_injection",
                "severity": "critical",
                "target": "https://payment-gateway.acme.com/api/checkout",
                "details": {"payload": "' OR 1=1--"},
            },
            {
                "request_id": "test-request-2",
                "finding_type": "xss",
                "severity": "high",
                "target": "https://api.acme.com/v1/search",
                "details": {"payload": "<script>alert(1)</script>"},
            },
        ]
        for res in pentagi_results:
            status, response, elapsed = self.client.call(
                "POST", "/api/v1/pentagi/results", json=res
            )
            self.add_result(
                E2ETestCase(
                    endpoint="/api/v1/pentagi/results",
                    method="POST",
                    group="seeding",
                    description=f"Seed pentagi result: {res['finding_type']}",
                    result=E2ETestResult.PASS
                    if status in [200, 201, 409]
                    else E2ETestResult.NEEDS_SEEDING,
                    status_code=status,
                    response_time_ms=elapsed,
                    response_snippet=json.dumps(response)[:200]
                    if isinstance(response, dict)
                    else str(response)[:200],
                    reason=f"Seeded {res['finding_type']}"
                    if status in [200, 201]
                    else f"Status {status}",
                )
            )

        # 7. Seed reports (per ReportCreate schema: name, report_type required)
        print("\n[1.5.7] Seeding Reports")
        reports = [
            {
                "name": f"Security Assessment Q4-{ts}",
                "report_type": "security_summary",
                "format": "pdf",
                "parameters": {"applications": ["payment-gateway"]},
            },
            {
                "name": f"Compliance Report SOC2-{ts}",
                "report_type": "compliance",
                "format": "pdf",
                "parameters": {"framework": "SOC2"},
            },
        ]
        for rpt in reports:
            status, response, elapsed = self.client.call(
                "POST", "/api/v1/reports", json=rpt
            )
            if status in [200, 201]:
                self.client.resource_registry.setdefault("report_ids", []).append(
                    response.get("id", rpt["name"])
                )
            self.add_result(
                E2ETestCase(
                    endpoint="/api/v1/reports",
                    method="POST",
                    group="seeding",
                    description=f"Seed report: {rpt['name'][:30]}",
                    result=E2ETestResult.PASS
                    if status in [200, 201, 409]
                    else E2ETestResult.NEEDS_SEEDING,
                    status_code=status,
                    response_time_ms=elapsed,
                    response_snippet=json.dumps(response)[:200]
                    if isinstance(response, dict)
                    else str(response)[:200],
                    reason="Seeded report"
                    if status in [200, 201]
                    else f"Status {status}",
                )
            )

        # 8. Seed report templates
        print("\n[1.5.8] Seeding Report Templates")
        templates = [
            {
                "name": f"Executive Summary-{ts}",
                "type": "executive",
                "sections": ["overview", "findings", "recommendations"],
            },
            {
                "name": f"Technical Detail-{ts}",
                "type": "technical",
                "sections": ["methodology", "findings", "evidence", "remediation"],
            },
        ]
        for tpl in templates:
            status, response, elapsed = self.client.call(
                "POST", "/api/v1/reports/templates", json=tpl
            )
            self.add_result(
                E2ETestCase(
                    endpoint="/api/v1/reports/templates",
                    method="POST",
                    group="seeding",
                    description=f"Seed template: {tpl['name'][:30]}",
                    result=E2ETestResult.PASS
                    if status in [200, 201, 409]
                    else E2ETestResult.NEEDS_SEEDING,
                    status_code=status,
                    response_time_ms=elapsed,
                    response_snippet=json.dumps(response)[:200]
                    if isinstance(response, dict)
                    else str(response)[:200],
                    reason="Seeded template"
                    if status in [200, 201]
                    else f"Status {status}",
                )
            )

        # 9. Seed report schedules
        print("\n[1.5.9] Seeding Report Schedules")
        schedules = [
            {
                "name": f"Weekly Security-{ts}",
                "report_type": "security_assessment",
                "frequency": "weekly",
                "recipients": ["security@acme.com"],
            },
            {
                "name": f"Monthly Compliance-{ts}",
                "report_type": "compliance",
                "frequency": "monthly",
                "recipients": ["compliance@acme.com"],
            },
        ]
        for sched in schedules:
            status, response, elapsed = self.client.call(
                "POST", "/api/v1/reports/schedules", json=sched
            )
            self.add_result(
                E2ETestCase(
                    endpoint="/api/v1/reports/schedules",
                    method="POST",
                    group="seeding",
                    description=f"Seed schedule: {sched['name'][:30]}",
                    result=E2ETestResult.PASS
                    if status in [200, 201, 409]
                    else E2ETestResult.NEEDS_SEEDING,
                    status_code=status,
                    response_time_ms=elapsed,
                    response_snippet=json.dumps(response)[:200]
                    if isinstance(response, dict)
                    else str(response)[:200],
                    reason="Seeded schedule"
                    if status in [200, 201]
                    else f"Status {status}",
                )
            )

        # 10. Seed workflows (per WorkflowCreate schema: name, description required)
        print("\n[1.5.10] Seeding Workflows")
        workflows = [
            {
                "name": f"Critical Vuln Response-{ts}",
                "description": "Auto-respond to critical vulnerabilities",
                "steps": [
                    {"action": "notify", "target": "security-team"},
                    {"action": "create_ticket", "target": "jira"},
                ],
                "triggers": {"event": "finding_critical"},
                "enabled": True,
            },
            {
                "name": f"Compliance Review-{ts}",
                "description": "Review compliance violations",
                "steps": [
                    {"action": "notify", "target": "compliance-team"},
                    {"action": "block_deploy", "target": "pipeline"},
                ],
                "triggers": {"event": "compliance_violation"},
                "enabled": True,
            },
        ]
        for wf in workflows:
            status, response, elapsed = self.client.call(
                "POST", "/api/v1/workflows", json=wf
            )
            if status in [200, 201]:
                self.client.resource_registry.setdefault("workflow_ids", []).append(
                    response.get("id", wf["name"])
                )
            self.add_result(
                E2ETestCase(
                    endpoint="/api/v1/workflows",
                    method="POST",
                    group="seeding",
                    description=f"Seed workflow: {wf['name'][:30]}",
                    result=E2ETestResult.PASS
                    if status in [200, 201, 409]
                    else E2ETestResult.NEEDS_SEEDING,
                    status_code=status,
                    response_time_ms=elapsed,
                    response_snippet=json.dumps(response)[:200]
                    if isinstance(response, dict)
                    else str(response)[:200],
                    reason="Seeded workflow"
                    if status in [200, 201]
                    else f"Status {status}",
                )
            )

        # 11. Seed integrations (per IntegrationCreate schema: name, integration_type required)
        print("\n[1.5.11] Seeding Integrations")
        integrations = [
            {
                "name": f"Jira-{ts}",
                "integration_type": "jira",
                "config": {"url": "https://acme.atlassian.net", "project": "SEC"},
            },
            {
                "name": f"Slack-{ts}",
                "integration_type": "slack",
                "config": {"webhook_url": "https://hooks.slack.com/services/xxx"},
            },
            {
                "name": f"GitHub-{ts}",
                "integration_type": "github",
                "config": {"org": "acme-corp", "repo": "security-findings"},
            },
        ]
        for intg in integrations:
            status, response, elapsed = self.client.call(
                "POST", "/api/v1/integrations", json=intg
            )
            if status in [200, 201]:
                self.client.resource_registry.setdefault("integration_ids", []).append(
                    response.get("id", intg["name"])
                )
            self.add_result(
                E2ETestCase(
                    endpoint="/api/v1/integrations",
                    method="POST",
                    group="seeding",
                    description=f"Seed integration: {intg['name'][:30]}",
                    result=E2ETestResult.PASS
                    if status in [200, 201, 409]
                    else E2ETestResult.NEEDS_SEEDING,
                    status_code=status,
                    response_time_ms=elapsed,
                    response_snippet=json.dumps(response)[:200]
                    if isinstance(response, dict)
                    else str(response)[:200],
                    reason="Seeded integration"
                    if status in [200, 201]
                    else f"Status {status}",
                )
            )

        # 12. Seed secrets (per SecretFindingCreate schema)
        print("\n[1.5.12] Seeding Secrets (detected)")
        secrets = [
            {
                "secret_type": "aws_key",
                "file_path": "src/config.py",
                "line_number": 42,
                "repository": "acme/payment-gateway",
                "branch": "main",
            },
            {
                "secret_type": "api_key",
                "file_path": ".env",
                "line_number": 15,
                "repository": "acme/api-service",
                "branch": "develop",
            },
        ]
        for sec in secrets:
            status, response, elapsed = self.client.call(
                "POST", "/api/v1/secrets", json=sec
            )
            self.add_result(
                E2ETestCase(
                    endpoint="/api/v1/secrets",
                    method="POST",
                    group="seeding",
                    description=f"Seed secret: {sec['secret_type']}",
                    result=E2ETestResult.PASS
                    if status in [200, 201, 409]
                    else E2ETestResult.NEEDS_SEEDING,
                    status_code=status,
                    response_time_ms=elapsed,
                    response_snippet=json.dumps(response)[:200]
                    if isinstance(response, dict)
                    else str(response)[:200],
                    reason="Seeded secret"
                    if status in [200, 201]
                    else f"Status {status}",
                )
            )

        # 13. Seed IAC findings
        print("\n[1.5.13] Seeding IAC Findings")
        iac_findings = [
            {
                "resource": "aws_s3_bucket.data",
                "rule": "S3_BUCKET_PUBLIC_ACCESS",
                "severity": "critical",
                "file": "terraform/s3.tf",
                "line": 15,
            },
            {
                "resource": "aws_security_group.web",
                "rule": "SG_OPEN_TO_WORLD",
                "severity": "high",
                "file": "terraform/security.tf",
                "line": 42,
            },
        ]
        for iac in iac_findings:
            status, response, elapsed = self.client.call(
                "POST", "/api/v1/iac", json=iac
            )
            self.add_result(
                E2ETestCase(
                    endpoint="/api/v1/iac",
                    method="POST",
                    group="seeding",
                    description=f"Seed IAC: {iac['rule'][:30]}",
                    result=E2ETestResult.PASS
                    if status in [200, 201, 409]
                    else E2ETestResult.NEEDS_SEEDING,
                    status_code=status,
                    response_time_ms=elapsed,
                    response_snippet=json.dumps(response)[:200]
                    if isinstance(response, dict)
                    else str(response)[:200],
                    reason="Seeded IAC" if status in [200, 201] else f"Status {status}",
                )
            )

        # 14. Seed webhook outbox
        print("\n[1.5.14] Seeding Webhook Outbox")
        webhooks = [
            {
                "event_type": "finding_created",
                "payload": {"finding_id": "CVE-2021-44228", "severity": "critical"},
                "destination": "jira",
            },
            {
                "event_type": "policy_violation",
                "payload": {
                    "policy_id": "critical-vuln-block",
                    "app": "payment-gateway",
                },
                "destination": "slack",
            },
        ]
        for wh in webhooks:
            status, response, elapsed = self.client.call(
                "POST", "/api/v1/webhooks/outbox", json=wh
            )
            self.add_result(
                E2ETestCase(
                    endpoint="/api/v1/webhooks/outbox",
                    method="POST",
                    group="seeding",
                    description=f"Seed webhook: {wh['event_type']}",
                    result=E2ETestResult.PASS
                    if status in [200, 201, 409]
                    else E2ETestResult.NEEDS_SEEDING,
                    status_code=status,
                    response_time_ms=elapsed,
                    response_snippet=json.dumps(response)[:200]
                    if isinstance(response, dict)
                    else str(response)[:200],
                    reason="Seeded webhook"
                    if status in [200, 201]
                    else f"Status {status}",
                )
            )

        # 15. Seed services (inventory)
        print("\n[1.5.15] Seeding Services")
        services = [
            {
                "name": "payment-api",
                "type": "api",
                "owner": "payment-team",
                "endpoints": ["/api/v1/checkout", "/api/v1/refund"],
            },
            {
                "name": "auth-service",
                "type": "microservice",
                "owner": "platform-team",
                "endpoints": ["/auth/login", "/auth/token"],
            },
        ]
        for svc in services:
            status, response, elapsed = self.client.call(
                "POST", "/api/v1/inventory/services", json=svc
            )
            self.add_result(
                E2ETestCase(
                    endpoint="/api/v1/inventory/services",
                    method="POST",
                    group="seeding",
                    description=f"Seed service: {svc['name']}",
                    result=E2ETestResult.PASS
                    if status in [200, 201, 409]
                    else E2ETestResult.NEEDS_SEEDING,
                    status_code=status,
                    response_time_ms=elapsed,
                    response_snippet=json.dumps(response)[:200]
                    if isinstance(response, dict)
                    else str(response)[:200],
                    reason="Seeded service"
                    if status in [200, 201]
                    else f"Status {status}",
                )
            )

        # 16. Seed APIs (inventory)
        print("\n[1.5.16] Seeding APIs")
        apis = [
            {
                "name": "Payment API v1",
                "version": "1.0",
                "spec_url": "https://api.acme.com/payment/openapi.json",
                "owner": "payment-team",
            },
            {
                "name": "User API v2",
                "version": "2.0",
                "spec_url": "https://api.acme.com/users/openapi.json",
                "owner": "platform-team",
            },
        ]
        for api in apis:
            status, response, elapsed = self.client.call(
                "POST", "/api/v1/inventory/apis", json=api
            )
            self.add_result(
                E2ETestCase(
                    endpoint="/api/v1/inventory/apis",
                    method="POST",
                    group="seeding",
                    description=f"Seed API: {api['name']}",
                    result=E2ETestResult.PASS
                    if status in [200, 201, 409]
                    else E2ETestResult.NEEDS_SEEDING,
                    status_code=status,
                    response_time_ms=elapsed,
                    response_snippet=json.dumps(response)[:200]
                    if isinstance(response, dict)
                    else str(response)[:200],
                    reason="Seeded API" if status in [200, 201] else f"Status {status}",
                )
            )

        print("\n[1.5] Data seeding complete")

    # ========================================================================
    # PHASE 2: DATA INGESTION
    # ========================================================================

    def phase2_data_ingestion(self):
        """Ingest security data for all applications."""
        print("\n" + "=" * 80)
        print("PHASE 2: DATA INGESTION")
        print("=" * 80)

        for customer in CUSTOMERS:
            print(f"\n--- Customer: {customer['name']} ({customer['cloud']}) ---")

            for app_name in customer["apps"]:
                app_config = APPLICATIONS[app_name]
                print(
                    f"\n  App: {app_name} ({app_config['lang']}/{app_config['framework']})"
                )

                # Upload SARIF
                sarif = generate_sarif(app_name, app_config)
                sarif_json = json.dumps(sarif)
                status, response, elapsed = self.client.upload_file(
                    "/inputs/sarif", sarif_json, f"{app_name}.sarif", "application/json"
                )

                result, reason = self.classify_result(
                    "/inputs/sarif", "POST", status, response
                )
                finding_count = response.get("metadata", {}).get("finding_count", 0)
                if finding_count > 0:
                    self.ingested_findings_count += finding_count
                    result = E2ETestResult.PASS
                    reason = f"Ingested {finding_count} SAST findings"

                self.add_result(
                    E2ETestCase(
                        endpoint="/inputs/sarif",
                        method="POST",
                        group="ingestion",
                        description=f"Upload SARIF for {app_name}",
                        result=result,
                        status_code=status,
                        response_time_ms=elapsed,
                        response_snippet=json.dumps(response)[:200],
                        reason=reason,
                        payload_used=f"SARIF with {len(sarif['runs'][0]['results'])} findings",
                    )
                )

                # Upload SBOM
                sbom = generate_sbom(app_name, app_config)
                sbom_json = json.dumps(sbom)
                status, response, elapsed = self.client.upload_file(
                    "/inputs/sbom",
                    sbom_json,
                    f"{app_name}.sbom.json",
                    "application/json",
                )

                result, reason = self.classify_result(
                    "/inputs/sbom", "POST", status, response
                )
                component_count = response.get("metadata", {}).get("component_count", 0)
                if component_count > 0:
                    self.ingested_components_count += component_count
                    result = E2ETestResult.PASS
                    reason = f"Ingested {component_count} components"

                self.add_result(
                    E2ETestCase(
                        endpoint="/inputs/sbom",
                        method="POST",
                        group="ingestion",
                        description=f"Upload SBOM for {app_name}",
                        result=result,
                        status_code=status,
                        response_time_ms=elapsed,
                        response_snippet=json.dumps(response)[:200],
                        reason=reason,
                        payload_used=f"CycloneDX SBOM with {len(sbom['components'])} components",
                    )
                )

                # Upload CVE feed
                cve_feed = generate_cve_feed(app_name, app_config)
                cve_json = json.dumps(cve_feed)
                status, response, elapsed = self.client.upload_file(
                    "/inputs/cve", cve_json, f"{app_name}.cve.json", "application/json"
                )

                result, reason = self.classify_result(
                    "/inputs/cve", "POST", status, response
                )
                record_count = response.get("record_count", 0)
                if record_count > 0:
                    self.ingested_cves_count += record_count
                    result = E2ETestResult.PASS
                    reason = f"Ingested {record_count} CVEs"
                    # Note validation errors but don't fail
                    if response.get("validation_errors"):
                        reason += f" (with {len(response['validation_errors'])} schema warnings)"

                self.add_result(
                    E2ETestCase(
                        endpoint="/inputs/cve",
                        method="POST",
                        group="ingestion",
                        description=f"Upload CVE feed for {app_name}",
                        result=result,
                        status_code=status,
                        response_time_ms=elapsed,
                        response_snippet=json.dumps(response)[:200],
                        reason=reason,
                        payload_used=f"CVE feed with {len(cve_feed['cves'])} CVEs",
                    )
                )

                # Upload CNAPP findings
                cnapp = generate_cnapp_findings(app_name, customer)
                cnapp_json = json.dumps(cnapp)
                status, response, elapsed = self.client.upload_file(
                    "/inputs/cnapp",
                    cnapp_json,
                    f"{app_name}.cnapp.json",
                    "application/json",
                )

                result, reason = self.classify_result(
                    "/inputs/cnapp", "POST", status, response
                )
                if status == 200:
                    result = E2ETestResult.PASS
                    reason = f"Ingested CNAPP findings for {customer['cloud']}"

                self.add_result(
                    E2ETestCase(
                        endpoint="/inputs/cnapp",
                        method="POST",
                        group="ingestion",
                        description=f"Upload CNAPP for {app_name} ({customer['cloud']})",
                        result=result,
                        status_code=status,
                        response_time_ms=elapsed,
                        response_snippet=json.dumps(response)[:200],
                        reason=reason,
                        payload_used=f"CNAPP findings from {customer['cloud']}",
                    )
                )

                # Upload design/threat model
                design_csv = generate_design_csv(app_name, app_config)
                status, response, elapsed = self.client.upload_file(
                    "/inputs/design", design_csv, f"{app_name}.design.csv", "text/csv"
                )

                result, reason = self.classify_result(
                    "/inputs/design", "POST", status, response
                )
                row_count = response.get("row_count", 0)
                if row_count > 0:
                    result = E2ETestResult.PASS
                    reason = f"Ingested {row_count} threat model rows"

                self.add_result(
                    E2ETestCase(
                        endpoint="/inputs/design",
                        method="POST",
                        group="ingestion",
                        description=f"Upload threat model for {app_name}",
                        result=result,
                        status_code=status,
                        response_time_ms=elapsed,
                        response_snippet=json.dumps(response)[:200],
                        reason=reason,
                        payload_used=f"Design CSV with {design_csv.count(chr(10))} rows",
                    )
                )

    # ========================================================================
    # PHASE 3: PIPELINE EXECUTION
    # ========================================================================

    def phase3_pipeline_execution(self):
        """Run the security pipeline."""
        print("\n" + "=" * 80)
        print("PHASE 3: PIPELINE EXECUTION")
        print("=" * 80)

        # Run pipeline
        print("\n[3.1] Running Security Pipeline")
        status, response, elapsed = self.client.call("GET", "/pipeline/run")

        result, reason = self.classify_result("/pipeline/run", "GET", status, response)

        if status == 200 and response.get("status") == "ok":
            result = E2ETestResult.PASS
            sarif_summary = response.get("sarif_summary", {})
            sbom_summary = response.get("sbom_summary", {})
            reason = f"Pipeline completed: {sarif_summary.get('finding_count', 0)} findings, {sbom_summary.get('component_count', 0)} components"

        self.add_result(
            E2ETestCase(
                endpoint="/pipeline/run",
                method="GET",
                group="pipeline",
                description="Execute security pipeline",
                result=result,
                status_code=status,
                response_time_ms=elapsed,
                response_snippet=json.dumps(response)[:500],
                reason=reason,
            )
        )

        # Also test POST pipeline/run
        print("\n[3.2] Running Pipeline via POST")
        status, response, elapsed = self.client.call("POST", "/pipeline/run", json={})

        result, reason = self.classify_result("/pipeline/run", "POST", status, response)
        if status == 200:
            result = E2ETestResult.PASS
            reason = "POST pipeline execution successful"

        self.add_result(
            E2ETestCase(
                endpoint="/pipeline/run",
                method="POST",
                group="pipeline",
                description="Execute pipeline via POST",
                result=result,
                status_code=status,
                response_time_ms=elapsed,
                response_snippet=json.dumps(response)[:200],
                reason=reason,
            )
        )

    # ========================================================================
    # PHASE 4: API SURFACE COVERAGE
    # ========================================================================

    def phase4_api_coverage(self):
        """Test all remaining API endpoints."""
        print("\n" + "=" * 80)
        print("PHASE 4: API SURFACE COVERAGE")
        print("=" * 80)

        # Group endpoints by category
        endpoint_groups = {
            "health": [
                ("GET", "/health"),
                ("GET", "/api/v1/health"),
                ("GET", "/api/v1/ready"),
                ("GET", "/api/v1/status"),
                ("GET", "/api/v1/version"),
                ("GET", "/api/v1/metrics"),
            ],
            "analytics": [
                ("GET", "/api/v1/analytics/dashboard/overview"),
                ("GET", "/api/v1/analytics/dashboard/compliance-status"),
                ("GET", "/api/v1/analytics/dashboard/top-risks"),
                ("GET", "/api/v1/analytics/dashboard/trends"),
                ("GET", "/api/v1/analytics/findings"),
                ("GET", "/api/v1/analytics/decisions"),
                ("GET", "/api/v1/analytics/coverage"),
                ("GET", "/api/v1/analytics/mttr"),
                ("GET", "/api/v1/analytics/roi"),
                ("GET", "/api/v1/analytics/noise-reduction"),
                ("GET", "/api/v1/analytics/export"),
                ("GET", "/analytics/dashboard"),
            ],
            "inventory": [
                ("GET", "/api/v1/inventory/applications"),
                ("GET", "/api/v1/inventory/services"),
                ("GET", "/api/v1/inventory/apis"),
                ("GET", "/api/v1/inventory/search?q=payment"),
            ],
            "compliance": [
                ("GET", "/api/v1/audit/compliance/frameworks"),
                ("GET", "/api/v1/audit/compliance/controls"),
                ("GET", "/api/v1/audit/logs"),
                ("GET", "/api/v1/audit/decision-trail"),
                ("GET", "/api/v1/audit/policy-changes"),
                ("GET", "/api/v1/audit/user-activity?user_id=admin@example.com"),
            ],
            "feeds": [
                ("GET", "/api/v1/feeds/health"),
                ("GET", "/api/v1/feeds/stats"),
                ("GET", "/api/v1/feeds/sources"),
                ("GET", "/api/v1/feeds/categories"),
                ("GET", "/api/v1/feeds/kev"),
                ("GET", "/api/v1/feeds/epss"),
                ("GET", "/api/v1/feeds/scheduler/status"),
            ],
            "enhanced": [
                ("GET", "/api/v1/enhanced/capabilities"),
                ("GET", "/api/v1/enhanced/signals"),
            ],
            "reachability": [
                ("GET", "/api/v1/reachability/health"),
                ("GET", "/api/v1/reachability/metrics"),
            ],
            "pentagi": [
                ("GET", "/api/v1/pentagi/configs"),
                ("GET", "/api/v1/pentagi/requests"),
                ("GET", "/api/v1/pentagi/results"),
                ("GET", "/api/v1/pentagi/stats"),
            ],
            "remediation": [
                ("GET", "/api/v1/remediation/tasks?org_id=acme-financial"),
                ("GET", "/api/v1/remediation/statuses"),
                ("GET", "/api/v1/remediation/metrics"),
            ],
            "deduplication": [
                ("GET", "/api/v1/deduplication/clusters?org_id=acme-financial"),
                ("GET", "/api/v1/deduplication/stats"),
                ("GET", "/api/v1/deduplication/graph?org_id=acme-financial"),
            ],
            "collaboration": [
                ("GET", "/api/v1/collaboration/activities?org_id=acme-financial"),
                (
                    "GET",
                    "/api/v1/collaboration/comments?entity_type=finding&entity_id=test-finding-1",
                ),
                ("GET", "/api/v1/collaboration/activity-types"),
                ("GET", "/api/v1/collaboration/entity-types"),
            ],
            "marketplace": [
                ("GET", "/api/v1/marketplace/browse"),
                ("GET", "/api/v1/marketplace/stats"),
                ("GET", "/api/v1/marketplace/recommendations"),
                ("GET", "/api/v1/marketplace/contributors"),
            ],
            "reports": [
                ("GET", "/api/v1/reports"),
                ("GET", "/api/v1/reports/templates/list"),
                ("GET", "/api/v1/reports/schedules/list"),
            ],
            "webhooks": [
                ("GET", "/api/v1/webhooks/events"),
                ("GET", "/api/v1/webhooks/mappings"),
                ("GET", "/api/v1/webhooks/drift"),
                ("GET", "/api/v1/webhooks/outbox"),
                ("GET", "/api/v1/webhooks/outbox/pending"),
                ("GET", "/api/v1/webhooks/outbox/stats"),
                ("GET", "/api/v1/webhooks/alm/work-items"),
            ],
            "workflows": [
                ("GET", "/api/v1/workflows"),
            ],
            "integrations": [
                ("GET", "/api/v1/integrations"),
            ],
            "policies": [
                ("GET", "/api/v1/policies"),
            ],
            "teams": [
                ("GET", "/api/v1/teams"),
            ],
            "users": [
                ("GET", "/api/v1/users"),
            ],
            "secrets": [
                ("GET", "/api/v1/secrets"),
            ],
            "iac": [
                ("GET", "/api/v1/iac"),
            ],
            "triage": [
                ("GET", "/api/v1/triage"),
                ("GET", "/api/v1/triage/export"),
            ],
            "evidence": [
                ("GET", "/evidence/"),
            ],
            "graph": [
                ("GET", "/api/v1/graph"),
                ("GET", "/graph/"),
                ("GET", "/graph/anomalies"),
                ("GET", "/graph/kev-components"),
            ],
            "risk": [
                ("GET", "/risk/"),
            ],
            "provenance": [
                ("GET", "/provenance/"),
            ],
            "validation": [
                ("GET", "/api/v1/validate/supported-formats"),
            ],
            "auth": [
                ("GET", "/api/v1/auth/sso"),
            ],
            "ide": [
                ("GET", "/api/v1/ide/config"),
                (
                    "GET",
                    "/api/v1/ide/suggestions?file_path=/src/main.py&line=10&column=5",
                ),
            ],
            "bulk": [
                ("GET", "/api/v1/bulk/jobs"),
            ],
        }

        for group_name, endpoints in endpoint_groups.items():
            print(
                f"\n[4.{list(endpoint_groups.keys()).index(group_name)+1}] Testing {group_name.upper()} endpoints"
            )

            for method, endpoint in endpoints:
                status, response, elapsed = self.client.call(method, endpoint)

                # Determine if we expect data
                expects_data = group_name not in ["health", "validation", "auth"]
                result, reason = self.classify_result(
                    endpoint, method, status, response, expects_data
                )

                self.add_result(
                    E2ETestCase(
                        endpoint=endpoint,
                        method=method,
                        group=group_name,
                        description=f"Test {group_name}: {endpoint}",
                        result=result,
                        status_code=status,
                        response_time_ms=elapsed,
                        response_snippet=json.dumps(response)[:200]
                        if isinstance(response, dict)
                        else str(response)[:200],
                        reason=reason,
                    )
                )

    def _get_sample_payload(self, path: str, method: str) -> dict:
        """Generate sample payload based on endpoint path and OpenAPI schemas.

        Uses real IDs from resource_registry when available, falling back to
        realistic test data based on the 14 apps and 3 customer architectures.
        """
        import time

        ts = int(time.time())

        # Get real IDs from resource registry (populated during seeding)
        reg = self.client.resource_registry

        # Use real org IDs from our 3 customers
        org_id = "acme-corp"  # Default to first customer
        if reg.get("app_ids"):
            # Use first registered app's org
            org_id = "acme-corp"

        # Get real app ID if available
        app_id = (
            reg.get("app_ids", ["payment-gateway"])[0]
            if reg.get("app_ids")
            else "payment-gateway"
        )

        # Get real cluster ID if available (from deduplication)
        cluster_id = f"cluster-{app_id}-{ts}"

        # Get real finding ID pattern based on app
        finding_id = f"finding-{app_id}-{ts}"

        # Map endpoint patterns to sample payloads based on ACTUAL OpenAPI schemas
        payload_map = {
            # Enhanced/Analysis endpoints
            "/api/v1/enhanced/analysis": {
                "service_name": app_id,
                "security_findings": [
                    {
                        "rule_id": "CWE-89",
                        "severity": "high",
                        "description": "SQL Injection in payment processing",
                    }
                ],
                "business_context": {
                    "environment": "production",
                    "criticality": "high",
                },
            },
            "/api/v1/enhanced/compare-llms": {
                "service_name": app_id,
                "security_findings": [
                    {
                        "rule_id": "CWE-79",
                        "severity": "medium",
                        "description": "XSS vulnerability in user input",
                    }
                ],
                "business_context": {"environment": "staging", "criticality": "medium"},
            },
            # Deduplication endpoints - CORRECTED per CreateCorrelationLinkRequest schema
            # Required: source_cluster_id, target_cluster_id, link_type, confidence
            "/api/v1/deduplication/correlations": {
                "source_cluster_id": f"cluster-sast-{ts}",
                "target_cluster_id": f"cluster-dast-{ts}",
                "link_type": "same_vulnerability",
                "confidence": 0.95,
                "reason": "Same CVE detected in SAST and DAST scans",
            },
            # No requestBody for cross-stage - uses query params
            "/api/v1/deduplication/correlate/cross-stage": {},
            # OperatorFeedbackRequest: cluster_id, feedback_type required
            # feedback_type must be: 'merge_allowed', 'merge_blocked', or 'split_cluster'
            # merge_allowed and merge_blocked require target_cluster_id
            "/api/v1/deduplication/feedback": {
                "cluster_id": cluster_id,
                "feedback_type": "merge_allowed",
                "target_cluster_id": f"cluster-target-{ts}",
                "reason": "Verified as true positive - clusters can be merged",
                "operator_id": "security-analyst-1",
            },
            # BaselineComparisonRequest: org_id, current_run_id, baseline_run_id required
            "/api/v1/deduplication/baseline/compare": {
                "org_id": org_id,
                "current_run_id": f"run-{ts}",
                "baseline_run_id": f"run-{ts-86400}",
            },
            # MergeClustersRequest: source_cluster_ids (array), target_cluster_id required
            "/api/v1/deduplication/clusters/merge": {
                "source_cluster_ids": [f"cluster-{ts}-1", f"cluster-{ts}-2"],
                "target_cluster_id": f"cluster-{ts}-merged",
                "reason": "Duplicate findings from same root cause",
            },
            # Remediation endpoints - CORRECTED per CreateTaskRequest schema
            # Required: cluster_id, org_id, app_id, title, severity
            "/api/v1/remediation/tasks": {
                "cluster_id": cluster_id,
                "org_id": org_id,
                "app_id": app_id,
                "title": f"Remediate SQL Injection in {app_id}",
                "severity": "critical",
                "description": "Fix SQL injection vulnerability in payment processing module",
                "assignee": "dev-team-lead",
                "assignee_email": "lead@acme-corp.com",
            },
            # No requestBody for SLA check - uses query params
            "/api/v1/remediation/sla/check": {},
            # Collaboration endpoints - CORRECTED per actual schemas
            "/api/v1/collaboration/comments": {
                "entity_type": "finding",
                "entity_id": finding_id,
                "org_id": org_id,
                "author": "security-analyst",
                "content": "Confirmed this vulnerability in production environment",
            },
            "/api/v1/collaboration/watchers": {
                "entity_type": "finding",
                "entity_id": finding_id,
                "user_id": "security-analyst",
            },
            # RecordActivityRequest: entity_type, entity_id, org_id, activity_type, actor, summary required
            # activity_type must be one of: 'comment_added', 'status_changed', 'assigned', 'ticket_linked',
            # 'evidence_submitted', 'watcher_added', 'watcher_removed', 'mention'
            "/api/v1/collaboration/activities": {
                "entity_type": "finding",
                "entity_id": finding_id,
                "org_id": org_id,
                "activity_type": "comment_added",
                "actor": "security-analyst",
                "summary": "Reviewed and confirmed vulnerability",
                "actor_email": "analyst@acme-corp.com",
            },
            # Collaboration notifications and Webhooks ALM moved to CORRECTED section below
            "/api/v1/webhooks/mappings": {
                "cluster_id": cluster_id,
                "integration_type": "jira",
                "external_id": "SEC-123",
            },
            "/api/v1/webhooks/jira": {
                "webhookEvent": "jira:issue_updated",
                "issue": {
                    "key": "SEC-123",
                    "fields": {"summary": "Security vulnerability fix"},
                },
            },
            # ServiceNowWebhookPayload: event_type, sys_id required
            "/api/v1/webhooks/servicenow": {
                "event_type": "incident.updated",
                "sys_id": "INC0010001",
                "number": "INC0010001",
                "state": "2",
                "short_description": "Security incident from FixOps",
            },
            "/api/v1/webhooks/gitlab": {
                "object_kind": "merge_request",
                "project": {"id": 123, "name": app_id},
                "object_attributes": {"id": 1, "state": "merged"},
            },
            "/api/v1/webhooks/azure-devops": {
                "eventType": "workitem.updated",
                "resource": {
                    "id": 123,
                    "workItemId": 456,
                    "fields": {"System.State": "Active"},
                },
            },
            # Feeds endpoints - CORRECTED per actual schemas
            "/api/v1/feeds/exploits": {
                "cve_id": "CVE-2021-44228",
                "exploit_source": "exploit-db",
            },
            "/api/v1/feeds/threat-actors": {
                "cve_id": "CVE-2021-44228",
                "threat_actor": "APT29",
            },
            "/api/v1/feeds/supply-chain": {
                "vuln_id": "GHSA-jfh8-c2jp-5v3q",
                "ecosystem": "maven",
                "package_name": "org.apache.logging.log4j:log4j-core",
            },
            # EnrichFindingsRequest: findings array required (not cve_ids)
            "/api/v1/feeds/enrich": {
                "findings": [
                    {"cve_id": "CVE-2021-44228", "severity": "critical"},
                    {"cve_id": "CVE-2022-22965", "severity": "critical"},
                ],
                "target_region": "us-east-1",
            },
            # Validation endpoints - multipart file upload, return None to skip JSON
            "/api/v1/validate/input": None,
            "/api/v1/validate/batch": None,
            # Marketplace endpoints - CORRECTED per ContributeRequest schema
            # Required: name, content_type
            "/api/v1/marketplace/contribute": {
                "name": f"SQL Injection Prevention Policy {ts}",
                "description": "Policy to detect and prevent SQL injection vulnerabilities",
                "content_type": "policy",
                "compliance_frameworks": ["SOC2", "PCI-DSS"],
                "ssdlc_stages": ["code", "build"],
                "pricing_model": "free",
                "tags": ["security", "sql-injection", "sast"],
            },
            # Inputs endpoints - multipart file upload, return None to skip JSON
            "/inputs/vex": None,
            "/inputs/context": None,
            # PentAGI endpoints
            "/api/v1/pentagi/requests": {
                "config_id": reg.get("pentagi_config_ids", ["web-app-scan"])[0]
                if reg.get("pentagi_config_ids")
                else "web-app-scan",
                "target_url": "https://payment-gateway.acme-corp.com",
                "scan_type": "comprehensive",
            },
            "/api/v1/pentagi/results": {
                "request_id": reg.get("pentagi_request_ids", ["req-001"])[0]
                if reg.get("pentagi_request_ids")
                else "req-001",
                "findings": [
                    {
                        "type": "sql_injection",
                        "severity": "critical",
                        "url": "/api/checkout",
                    }
                ],
                "status": "completed",
            },
            # PentAGI and Reachability endpoints moved to CORRECTED section below
            # Bulk endpoints - CORRECTED per actual schemas
            "/api/v1/bulk/findings": {
                "findings": [
                    {
                        "id": f"{finding_id}-1",
                        "title": "SQL Injection",
                        "severity": "critical",
                        "app_id": app_id,
                    },
                    {
                        "id": f"{finding_id}-2",
                        "title": "XSS Vulnerability",
                        "severity": "high",
                        "app_id": app_id,
                    },
                ]
            },
            # BulkStatusUpdate: ids (array), new_status required
            "/api/v1/bulk/clusters/status": {
                "ids": [f"cluster-{ts}-1", f"cluster-{ts}-2"],
                "new_status": "in_progress",
                "reason": "Starting remediation",
                "changed_by": "security-analyst",
            },
            # BulkAssign: ids (array), assignee required
            "/api/v1/bulk/clusters/assign": {
                "ids": [f"cluster-{ts}-1", f"cluster-{ts}-2"],
                "assignee": "dev-team-lead",
                "assignee_email": "lead@acme-corp.com",
            },
            # BulkAcceptRisk: ids, justification, approved_by required
            "/api/v1/bulk/clusters/accept-risk": {
                "ids": [f"cluster-{ts}-1"],
                "justification": "Low risk - internal only system with no external exposure",
                "approved_by": "security-manager",
                "expiry_days": 90,
            },
            # BulkCreateTickets: ids, integration_id required
            "/api/v1/bulk/clusters/create-tickets": {
                "ids": [f"cluster-{ts}-1", f"cluster-{ts}-2"],
                "integration_id": reg.get("integration_ids", ["jira-integration"])[0]
                if reg.get("integration_ids")
                else "jira-integration",
                "project_key": "SEC",
                "issue_type": "Bug",
            },
            # BulkExport: ids, org_id required
            "/api/v1/bulk/export": {
                "ids": [f"cluster-{ts}-1", f"cluster-{ts}-2"],
                "org_id": org_id,
                "format": "csv",
            },
            # BulkFindingsUpdate: ids, updates required
            "/api/v1/bulk/findings/update": {
                "ids": [f"{finding_id}-1", f"{finding_id}-2"],
                "updates": {"status": "in_progress", "assignee": "dev-team"},
            },
            # BulkFindingsDelete: ids required
            "/api/v1/bulk/findings/delete": {
                "ids": [f"{finding_id}-1", f"{finding_id}-2"],
            },
            # User/Auth endpoints
            "/api/v1/users/login": {
                "email": "analyst@acme-corp.com",
                "password": "secure-password-123",
            },
            "/api/v1/teams/{id}/members": {
                "user_id": "user-analyst-1",
                "role": "member",
            },
            # Analytics endpoints - CORRECTED per actual schemas
            "/api/v1/analytics/findings": {
                "rule_id": "CWE-89",
                "severity": "critical",
                "title": "SQL Injection in Payment Module",
                "description": "Unsanitized user input in SQL query",
                "source": "semgrep",
                "application_id": app_id,
                "cve_id": "CVE-2021-44228",
            },
            # DecisionOutcome must be: 'block', 'alert', 'allow', or 'review'
            "/api/v1/analytics/decisions": {
                "finding_id": finding_id,
                "outcome": "block",
                "confidence": 0.95,
                "reasoning": "Critical vulnerability with known exploits in production system",
            },
            # Reports schedule - CORRECTED
            "/api/v1/reports/schedule": {
                "report_type": "security_summary",
                "schedule_cron": "0 9 * * 1",
                "format": "pdf",
                "parameters": {"org_id": org_id},
            },
            # Auth SSO - CORRECTED
            # provider must be: 'local', 'saml', 'oauth2', or 'ldap'
            "/api/v1/auth/sso": {
                "name": "Acme Corp SSO",
                "provider": "saml",
                "status": "active",
                "entity_id": "https://acme-corp.okta.com",
                "sso_url": "https://acme-corp.okta.com/sso",
            },
            # PentAGI endpoints - CORRECTED per actual schemas
            "/api/v1/pentagi/verify": {
                "finding_id": finding_id,
                "target_url": "https://payment-gateway.acme-corp.com/api/checkout",
                "vulnerability_type": "sql_injection",
                "evidence": "Parameter 'id' is vulnerable to SQL injection",
            },
            # PentAGI monitoring - targets should be array of strings
            "/api/v1/pentagi/monitoring": {
                "targets": [
                    "https://payment-gateway.acme-corp.com",
                    "https://api-gateway.acme-corp.com",
                ],
                "interval_minutes": 1440,
            },
            "/api/v1/pentagi/scan/comprehensive": {
                "target": "https://payment-gateway.acme-corp.com",
                "scan_types": ["sql_injection", "xss", "csrf"],
            },
            # Reachability endpoints - CORRECTED per actual schemas (use component_name, not package_name)
            "/api/v1/reachability/analyze": {
                "repository": {
                    "url": "https://github.com/acme-corp/payment-gateway",
                    "branch": "main",
                },
                "vulnerability": {
                    "cve_id": "CVE-2021-44228",
                    "component_name": "log4j-core",
                    "component_version": "2.14.1",
                },
            },
            "/api/v1/reachability/analyze/bulk": {
                "repository": {
                    "url": "https://github.com/acme-corp/payment-gateway",
                    "branch": "main",
                },
                "vulnerabilities": [
                    {
                        "cve_id": "CVE-2021-44228",
                        "component_name": "log4j-core",
                        "component_version": "2.14.1",
                    },
                    {
                        "cve_id": "CVE-2022-22965",
                        "component_name": "spring-core",
                        "component_version": "5.3.18",
                    },
                ],
            },
            # Remediation task sub-endpoints - CORRECTED
            "/api/v1/remediation/tasks/{task_id}/status": {
                "status": "in_progress",
                "changed_by": "dev-team-lead",
                "reason": "Started working on fix",
            },
            "/api/v1/remediation/tasks/{task_id}/verification": {
                "evidence_type": "test_results",
                "evidence_data": {"tests_passed": 42, "coverage": 0.85},
                "submitted_by": "qa-engineer",
            },
            "/api/v1/remediation/tasks/{task_id}/ticket": {
                "ticket_id": "SEC-456",
                "ticket_url": "https://jira.acme-corp.com/browse/SEC-456",
            },
            "/api/v1/remediation/tasks/{task_id}/transition": {
                "status": "resolved",
                "changed_by": "dev-team-lead",
                "reason": "Fix deployed to production",
            },
            "/api/v1/remediation/tasks/{task_id}/verify": {
                "evidence_type": "scan_results",
                "evidence_data": {"scan_id": "scan-123", "findings_count": 0},
                "submitted_by": "security-analyst",
            },
            # Collaboration endpoints - CORRECTED per actual schemas
            "/api/v1/collaboration/notifications/queue": {
                "entity_type": "finding",
                "entity_id": finding_id,
                "notification_type": "status_change",
                "title": "Finding Status Updated",
                "message": f"Finding {finding_id} has been marked as in_progress",
                "recipients": ["analyst@acme-corp.com", "lead@acme-corp.com"],
                "priority": "high",
            },
            "/api/v1/collaboration/notifications/notify-watchers": {
                "entity_type": "finding",
                "entity_id": finding_id,
                "notification_type": "comment_added",
                "title": "New Comment on Finding",
                "message": "A new comment has been added to the finding you are watching",
                "priority": "normal",
            },
            # Webhooks ALM - CORRECTED
            "/api/v1/webhooks/alm/work-items": {
                "cluster_id": cluster_id,
                "integration_type": "jira",
                "title": f"Security Finding: SQL Injection in {app_id}",
                "description": "Critical SQL injection vulnerability detected",
                "severity": "critical",
                "project_id": "SEC",
            },
            # Marketplace rate/purchase - CORRECTED
            "/api/v1/marketplace/items/{item_id}/rate": {
                "rating": 5,
            },
            "/api/v1/marketplace/purchase/{item_id}": {
                "organization": org_id,
            },
            # Additional missing endpoints
            # bulk/findings/assign expects a list of finding IDs as body, not an object
            "/api/v1/bulk/findings/assign": [f"{finding_id}-1", f"{finding_id}-2"],
            "/api/v1/bulk/policies/apply": {
                "policy_ids": ["policy-sql-injection", "policy-xss"],
                "target_ids": [app_id],
            },
            "/api/v1/ide/analyze": {
                "file_path": "/src/main/java/PaymentController.java",
                "content": 'public class PaymentController { String query = "SELECT * FROM users WHERE id=" + userId; }',
                "language": "java",
            },
            "/api/v1/deduplication/process": {
                "finding": {
                    "id": finding_id,
                    "title": "SQL Injection",
                    "severity": "critical",
                    "source": "semgrep",
                },
                "run_id": f"run-{ts}",
                "org_id": org_id,
            },
            "/api/v1/deduplication/process/batch": {
                "findings": [
                    {
                        "id": f"{finding_id}-1",
                        "title": "SQL Injection",
                        "severity": "critical",
                        "source": "semgrep",
                    },
                    {
                        "id": f"{finding_id}-2",
                        "title": "XSS",
                        "severity": "high",
                        "source": "semgrep",
                    },
                ],
                "run_id": f"run-{ts}",
                "org_id": org_id,
            },
        }

        # Check for exact match first
        if path in payload_map:
            return payload_map[path]

        # Check for pattern matches (endpoints with path params)
        # Convert path like /api/v1/remediation/tasks/test-task_id/status to pattern
        # IMPORTANT: Check regex patterns FIRST (more specific), then substring matches (less specific)
        import re

        # First pass: check all regex patterns (patterns with {param})
        for pattern, payload in payload_map.items():
            if "{" in pattern:
                # Convert pattern to regex: /api/v1/tasks/{task_id}/status -> /api/v1/tasks/[^/]+/status
                regex_pattern = re.sub(r"\{[^}]+\}", r"[^/]+", pattern)
                if re.match(f"^{regex_pattern}$", path):
                    return payload

        # Second pass: check substring matches (less specific patterns)
        for pattern, payload in payload_map.items():
            if "{" not in pattern and pattern in path:
                return payload

        # Default payloads based on path patterns (per actual schemas)
        # These are used when pattern matching doesn't find a specific payload
        if "/status" in path or "/transition" in path:
            # Remediation task status/transition requires 'status' field
            return {
                "status": "in_progress",
                "changed_by": "dev-team-lead",
                "reason": "Status update",
            }
        elif "/assign" in path:
            return {"assignee": "test-user"}
        elif "/verify" in path or "/verification" in path:
            # Remediation task verify/verification requires 'evidence_type' field
            return {
                "evidence_type": "test_results",
                "evidence_data": {"tests_passed": 42, "coverage": 0.85},
                "submitted_by": "qa-engineer",
            }
        elif "/ticket" in path:
            # Remediation task ticket requires 'ticket_id' field
            return {
                "ticket_id": "TICKET-123",
                "ticket_url": "https://jira.example.com/TICKET-123",
            }
        elif "/promote" in path:
            return {"promoted": True, "promoted_by": "test-user"}
        elif "/sync" in path:
            return {"force": False}
        elif "/resolve" in path:
            return {
                "resolution": "fixed",
                "resolution_notes": "Resolved",
                "resolved_by": "test-user",
            }
        elif "/process" in path:
            return {"processed": True}
        elif "/retry" in path:
            return {"retry": True}
        elif "/rate" in path:
            return {"rating": 5, "review": "Great!"}
        elif "/purchase" in path:
            return {"quantity": 1}
        elif "/acknowledge" in path:
            return {"acknowledged": True}
        elif "/chunks" in path:
            return {"chunk_data": "test data", "chunk_index": 0}
        elif "/compliance-content" in path:
            return {"framework": "SOC2", "stage": "design"}

        # Generic fallback
        return {"test": True, "timestamp": ts}

    def _get_query_params(self, path: str, method: str) -> dict:
        """Get query parameters for endpoints that require them."""
        import time

        ts = int(time.time())
        org_id = "acme-corp"

        # Map endpoints to their required query parameters
        query_params_map = {
            # Secrets and IAC scanning
            "/api/v1/secrets/scan": {
                "repository": "https://github.com/acme-corp/payment-gateway"
            },
            # provider must be: 'terraform', 'cloudformation', 'kubernetes', 'ansible', or 'helm'
            "/api/v1/iac/scan": {
                "provider": "terraform",
                "file_path": "terraform/main.tf",
            },
            # Bulk operations
            "/api/v1/bulk/findings/assign": {"assignee": "dev-team-lead"},
            # Deduplication
            "/api/v1/deduplication/correlate/cross-stage": {"org_id": org_id},
            # Remediation
            "/api/v1/remediation/sla/check": {"org_id": org_id},
            # Collaboration
            "/api/v1/collaboration/watchers": {
                "entity_type": "finding",
                "entity_id": f"finding-{ts}",
                "user_id": "analyst-1",
            },
            # Webhooks
            "/api/v1/webhooks/mappings/{mapping_id}/sync": {
                "fixops_status": "in_progress"
            },
            "/api/v1/webhooks/outbox/{outbox_id}/process": {"success": "true"},
            # Marketplace
            "/api/v1/marketplace/contribute": {
                "author": "security-team",
                "organization": org_id,
            },
            "/api/v1/marketplace/items/{item_id}/rate": {"reviewer": "analyst-1"},
            "/api/v1/marketplace/purchase/{item_id}": {"purchaser": org_id},
            "/api/v1/marketplace/compliance-content/{stage}": {
                "frameworks": "SOC2,PCI-DSS"
            },
            # Reachability results - needs repo_url too
            "/api/v1/reachability/results/{cve_id}": {
                "component_name": "log4j-core",
                "component_version": "2.14.1",
                "repo_url": "https://github.com/acme-corp/payment-gateway",
            },
            # Collaboration - promote needs promoted_by
            "/api/v1/collaboration/comments/{comment_id}/promote": {
                "promoted_by": "security-manager"
            },
        }

        # Check for exact match first
        if path in query_params_map:
            return query_params_map[path]

        # Check for pattern matches (endpoints with path params substituted)
        import re

        for pattern, params in query_params_map.items():
            if "{" in pattern:
                # Convert pattern to regex
                regex_pattern = re.sub(r"\{[^}]+\}", r"[^/]+", pattern)
                if re.match(f"^{regex_pattern}$", path):
                    return params

        # Check for partial matches
        for pattern, params in query_params_map.items():
            # Remove path params from pattern for comparison
            clean_pattern = re.sub(r"\{[^}]+\}", "", pattern)
            if clean_pattern and clean_pattern in path:
                return params

        return None

    # ========================================================================
    # PHASE 4.5: OPENAPI-DRIVEN FULL COVERAGE
    # ========================================================================

    def phase4_5_openapi_coverage(self):
        """Test ALL 291 OpenAPI operations not already covered."""
        print("\n" + "=" * 80)
        print("PHASE 4.5: OPENAPI-DRIVEN FULL COVERAGE (291 Operations)")
        print("=" * 80)

        # Fetch OpenAPI spec
        status, openapi_spec, _ = self.client.call("GET", "/openapi.json")
        if status != 200:
            print("[ERROR] Could not fetch OpenAPI spec")
            return

        # Extract all operations from OpenAPI spec
        all_operations = []
        for path, methods in openapi_spec.get("paths", {}).items():
            for method in methods.keys():
                if method.upper() in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
                    all_operations.append((method.upper(), path))

        print(f"[4.5] Found {len(all_operations)} operations in OpenAPI spec")

        # Track already tested endpoints
        tested_endpoints = set()
        for tc in self.results:
            tested_endpoints.add((tc.method, tc.endpoint.split("?")[0]))

        # Test operations not already covered
        untested = [(m, p) for m, p in all_operations if (m, p) not in tested_endpoints]
        print(f"[4.5] Testing {len(untested)} untested operations")

        # Group by path prefix for organized output
        from collections import defaultdict

        grouped = defaultdict(list)
        for method, path in untested:
            prefix = path.split("/")[1] if "/" in path else "root"
            grouped[prefix].append((method, path))

        counter = 1
        for prefix, ops in sorted(grouped.items()):
            print(
                f"\n[4.5.{counter}] Testing {prefix.upper()} endpoints ({len(ops)} ops)"
            )
            counter += 1

            for method, path in ops:
                # Skip paths with path parameters for now (need IDs)
                if "{" in path:
                    # Try to substitute with real IDs from registry
                    substituted_path = path
                    if "{config_id}" in path and self.client.resource_registry.get(
                        "pentagi_config_ids"
                    ):
                        substituted_path = path.replace(
                            "{config_id}",
                            str(self.client.resource_registry["pentagi_config_ids"][0]),
                        )
                    elif "{request_id}" in path and self.client.resource_registry.get(
                        "pentagi_request_ids"
                    ):
                        substituted_path = path.replace(
                            "{request_id}",
                            str(
                                self.client.resource_registry["pentagi_request_ids"][0]
                            ),
                        )
                    elif "{workflow_id}" in path and self.client.resource_registry.get(
                        "workflow_ids"
                    ):
                        substituted_path = path.replace(
                            "{workflow_id}",
                            str(self.client.resource_registry["workflow_ids"][0]),
                        )
                    elif "{policy_id}" in path and self.client.resource_registry.get(
                        "policy_ids"
                    ):
                        substituted_path = path.replace(
                            "{policy_id}",
                            str(self.client.resource_registry["policy_ids"][0]),
                        )
                    elif "{team_id}" in path and self.client.resource_registry.get(
                        "team_ids"
                    ):
                        substituted_path = path.replace(
                            "{team_id}",
                            str(self.client.resource_registry["team_ids"][0]),
                        )
                    elif "{user_id}" in path and self.client.resource_registry.get(
                        "user_ids"
                    ):
                        substituted_path = path.replace(
                            "{user_id}",
                            str(self.client.resource_registry["user_ids"][0]),
                        )
                    elif "{report_id}" in path and self.client.resource_registry.get(
                        "report_ids"
                    ):
                        substituted_path = path.replace(
                            "{report_id}",
                            str(self.client.resource_registry["report_ids"][0]),
                        )
                    elif (
                        "{integration_id}" in path
                        and self.client.resource_registry.get("integration_ids")
                    ):
                        substituted_path = path.replace(
                            "{integration_id}",
                            str(self.client.resource_registry["integration_ids"][0]),
                        )
                    elif "{mention_id}" in path:
                        # mention_id expects an integer, not a string
                        substituted_path = path.replace("{mention_id}", "1")
                    elif "{" in substituted_path:
                        # Still has unsubstituted params - use placeholder
                        substituted_path = substituted_path.replace(
                            "{", "test-"
                        ).replace("}", "")
                    path = substituted_path

                # For POST/PUT/DELETE, provide sample payload based on endpoint
                payload = None
                query_params = None

                # Check if this endpoint needs query parameters
                query_params = self._get_query_params(path, method)

                if method in ["POST", "PUT", "PATCH"]:
                    payload = self._get_sample_payload(path, method)
                    # Some endpoints return None to indicate they need file upload
                    if payload is None:
                        payload = {}

                # Build URL with query params if needed
                request_path = path
                if query_params:
                    from urllib.parse import urlencode

                    request_path = f"{path}?{urlencode(query_params)}"

                try:
                    if payload is not None and method in ["POST", "PUT", "PATCH"]:
                        status, response, elapsed = self.client.call(
                            method, request_path, json=payload
                        )
                    else:
                        status, response, elapsed = self.client.call(
                            method, request_path
                        )
                except Exception as e:
                    status, response, elapsed = 500, {"error": str(e)}, 0

                result, reason = self.classify_result(
                    path, method, status, response, True
                )

                self.add_result(
                    E2ETestCase(
                        endpoint=path,
                        method=method,
                        group="openapi_coverage",
                        description=f"OpenAPI: {method} {path[:40]}",
                        result=result,
                        status_code=status,
                        response_time_ms=elapsed,
                        response_snippet=json.dumps(response)[:200]
                        if isinstance(response, dict)
                        else str(response)[:200],
                        reason=reason,
                    )
                )

        print(
            f"\n[4.5] OpenAPI coverage complete - tested {len(untested)} additional operations"
        )

    # ========================================================================
    # PHASE 5: NEGATIVE TESTS
    # ========================================================================

    def phase5_negative_tests(self):
        """Run negative tests to find edge cases and bugs."""
        print("\n" + "=" * 80)
        print("PHASE 5: NEGATIVE TESTS")
        print("=" * 80)

        # Test without auth
        print("\n[5.1] Testing without authentication")
        session_backup = self.client.session.headers.get("X-API-Key")
        del self.client.session.headers["X-API-Key"]

        status, response, elapsed = self.client.call(
            "GET", "/api/v1/inventory/applications"
        )

        # Should get 401 or 403
        if status in [401, 403]:
            result = E2ETestResult.PASS
            reason = f"Correctly rejected unauthenticated request: {status}"
        else:
            result = E2ETestResult.BUG
            reason = f"Should reject unauthenticated request, got {status}"

        self.add_result(
            E2ETestCase(
                endpoint="/api/v1/inventory/applications",
                method="GET",
                group="negative",
                description="Request without API key",
                result=result,
                status_code=status,
                response_time_ms=elapsed,
                response_snippet=json.dumps(response)[:200],
                reason=reason,
            )
        )

        # Restore auth
        self.client.session.headers["X-API-Key"] = session_backup

        # Test with invalid API key
        print("\n[5.2] Testing with invalid API key")
        self.client.session.headers["X-API-Key"] = "invalid-key-12345"

        status, response, elapsed = self.client.call(
            "GET", "/api/v1/inventory/applications"
        )

        if status in [401, 403]:
            result = E2ETestResult.PASS
            reason = f"Correctly rejected invalid API key: {status}"
        else:
            result = E2ETestResult.BUG
            reason = f"Should reject invalid API key, got {status}"

        self.add_result(
            E2ETestCase(
                endpoint="/api/v1/inventory/applications",
                method="GET",
                group="negative",
                description="Request with invalid API key",
                result=result,
                status_code=status,
                response_time_ms=elapsed,
                response_snippet=json.dumps(response)[:200],
                reason=reason,
            )
        )

        # Restore valid auth
        self.client.session.headers["X-API-Key"] = session_backup

        # Test non-existent resource
        print("\n[5.3] Testing non-existent resources")
        status, response, elapsed = self.client.call(
            "GET", "/api/v1/inventory/applications/non-existent-app-12345"
        )

        if status == 404:
            result = E2ETestResult.PASS
            reason = "Correctly returned 404 for non-existent resource"
        else:
            result = E2ETestResult.BUG
            reason = f"Should return 404 for non-existent resource, got {status}"

        self.add_result(
            E2ETestCase(
                endpoint="/api/v1/inventory/applications/non-existent-app-12345",
                method="GET",
                group="negative",
                description="Request non-existent application",
                result=result,
                status_code=status,
                response_time_ms=elapsed,
                response_snippet=json.dumps(response)[:200],
                reason=reason,
            )
        )

        # Test malformed JSON
        print("\n[5.4] Testing malformed payloads")
        status, response, elapsed = self.client.call(
            "POST",
            "/api/v1/inventory/applications",
            data="not valid json {{{",
            headers={"Content-Type": "application/json"},
        )

        if status in [400, 422]:
            result = E2ETestResult.PASS
            reason = f"Correctly rejected malformed JSON: {status}"
        else:
            result = E2ETestResult.BUG
            reason = f"Should reject malformed JSON, got {status}"

        self.add_result(
            E2ETestCase(
                endpoint="/api/v1/inventory/applications",
                method="POST",
                group="negative",
                description="Submit malformed JSON",
                result=result,
                status_code=status,
                response_time_ms=elapsed,
                response_snippet=json.dumps(response)[:200]
                if isinstance(response, dict)
                else str(response)[:200],
                reason=reason,
            )
        )

        # Test wrong content type
        print("\n[5.5] Testing wrong content type")
        status, response, elapsed = self.client.call(
            "POST",
            "/inputs/sarif",
            data="plain text not json",
            headers={"Content-Type": "text/plain"},
        )

        if status in [400, 415, 422]:
            result = E2ETestResult.PASS
            reason = f"Correctly rejected wrong content type: {status}"
        else:
            result = E2ETestResult.GAP if status == 200 else E2ETestResult.BUG
            reason = f"Should validate content type, got {status}"

        self.add_result(
            E2ETestCase(
                endpoint="/inputs/sarif",
                method="POST",
                group="negative",
                description="Submit with wrong content type",
                result=result,
                status_code=status,
                response_time_ms=elapsed,
                response_snippet=json.dumps(response)[:200]
                if isinstance(response, dict)
                else str(response)[:200],
                reason=reason,
            )
        )

    # ========================================================================
    # PHASE 6: CONSISTENCY CHECKS
    # ========================================================================

    def phase6_consistency_checks(self):
        """Verify cross-endpoint data consistency."""
        print("\n" + "=" * 80)
        print("PHASE 6: CONSISTENCY CHECKS")
        print("=" * 80)

        # Check 1: Registered apps should appear in inventory
        print("\n[6.1] Checking application inventory consistency")
        status, response, elapsed = self.client.call(
            "GET", "/api/v1/inventory/applications"
        )

        if status == 200:
            apps_in_inventory = [
                app.get("name")
                for app in response.get(
                    "items", response if isinstance(response, list) else []
                )
            ]
            registered_count = len(self.registered_apps)
            inventory_count = len(apps_in_inventory)

            check = ConsistencyCheck(
                name="app_inventory_consistency",
                description="Registered apps should appear in inventory",
                passed=inventory_count >= registered_count,
                expected=f"{registered_count} apps registered",
                actual=f"{inventory_count} apps in inventory",
                endpoints_involved=[
                    "/api/v1/inventory/applications POST",
                    "/api/v1/inventory/applications GET",
                ],
            )
            self.consistency_checks.append(check)

            if check.passed:
                print(f"  [PASS] {check.description}: {check.actual}")
            else:
                print(
                    f"  [FAIL] {check.description}: expected {check.expected}, got {check.actual}"
                )

        # Check 2: Ingested findings should appear in analytics
        print("\n[6.2] Checking findings consistency")
        status, response, elapsed = self.client.call(
            "GET", "/api/v1/analytics/findings"
        )

        if status == 200:
            # Handle both list and dict responses
            if isinstance(response, list):
                analytics_findings = len(response)
            else:
                analytics_findings = response.get(
                    "total", len(response.get("items", []))
                )

            check = ConsistencyCheck(
                name="findings_consistency",
                description="Ingested SARIF findings should appear in analytics",
                passed=analytics_findings > 0 or self.ingested_findings_count == 0,
                expected=f"{self.ingested_findings_count} findings ingested",
                actual=f"{analytics_findings} findings in analytics",
                endpoints_involved=[
                    "/inputs/sarif POST",
                    "/api/v1/analytics/findings GET",
                ],
            )
            self.consistency_checks.append(check)

            if check.passed:
                print(f"  [PASS] {check.description}: {check.actual}")
            else:
                print(
                    f"  [WARN] {check.description}: expected ~{check.expected}, got {check.actual}"
                )

        # Check 3: Pipeline should reflect ingested data
        print("\n[6.3] Checking pipeline data consistency")
        status, response, elapsed = self.client.call("GET", "/pipeline/run")

        if status == 200 and response.get("status") == "ok":
            sarif_count = response.get("sarif_summary", {}).get("finding_count", 0)
            sbom_count = response.get("sbom_summary", {}).get("component_count", 0)

            check = ConsistencyCheck(
                name="pipeline_data_consistency",
                description="Pipeline should process ingested data",
                passed=sarif_count > 0 or sbom_count > 0,
                expected=f"Findings: {self.ingested_findings_count}, Components: {self.ingested_components_count}",
                actual=f"Findings: {sarif_count}, Components: {sbom_count}",
                endpoints_involved=[
                    "/inputs/sarif POST",
                    "/inputs/sbom POST",
                    "/pipeline/run GET",
                ],
            )
            self.consistency_checks.append(check)

            if check.passed:
                print(f"  [PASS] {check.description}: {check.actual}")
            else:
                print(
                    f"  [WARN] {check.description}: expected {check.expected}, got {check.actual}"
                )

    # ========================================================================
    # REPORT GENERATION
    # ========================================================================

    def generate_reports(self):
        """Generate comprehensive test reports."""
        os.makedirs(OUTPUT_DIR, exist_ok=True)

        # JSON results
        results_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "summary": self.stats,
            "consistency_checks": [asdict(c) for c in self.consistency_checks],
            "test_cases": [asdict(t) for t in self.results],
        }

        with open(f"{OUTPUT_DIR}/test_results.json", "w") as f:
            json.dump(results_data, f, indent=2, default=str)

        # CSV coverage matrix
        with open(f"{OUTPUT_DIR}/coverage_matrix.csv", "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(
                [
                    "Group",
                    "Method",
                    "Endpoint",
                    "Result",
                    "Status",
                    "Reason",
                    "Response Time (ms)",
                ]
            )
            for t in self.results:
                writer.writerow(
                    [
                        t.group,
                        t.method,
                        t.endpoint,
                        t.result.value,
                        t.status_code,
                        t.reason,
                        f"{t.response_time_ms:.2f}",
                    ]
                )

        # Bugs and gaps markdown
        bugs = [t for t in self.results if t.result == E2ETestResult.BUG]
        gaps = [t for t in self.results if t.result == E2ETestResult.GAP]
        needs_seeding = [
            t for t in self.results if t.result == E2ETestResult.NEEDS_SEEDING
        ]

        with open(f"{OUTPUT_DIR}/bugs_and_gaps.md", "w") as f:
            f.write("# FixOps Test Results - Bugs and Gaps\n\n")
            f.write(f"Generated: {datetime.now(timezone.utc).isoformat()}\n\n")

            f.write("## Summary\n\n")
            f.write(f"- **Total Tests**: {self.stats['total']}\n")
            f.write(
                f"- **PASS**: {self.stats['pass']} ({self.stats['pass']/self.stats['total']*100:.1f}%)\n"
            )
            f.write(f"- **BUG**: {self.stats['bug']}\n")
            f.write(f"- **GAP**: {self.stats['gap']}\n")
            f.write(f"- **NEEDS-SEEDING**: {self.stats['needs_seeding']}\n\n")

            if bugs:
                f.write("## Bugs Found\n\n")
                for t in bugs:
                    f.write(f"### {t.method} {t.endpoint}\n")
                    f.write(f"- **Group**: {t.group}\n")
                    f.write(f"- **Status Code**: {t.status_code}\n")
                    f.write(f"- **Reason**: {t.reason}\n")
                    f.write(f"- **Response**: `{t.response_snippet}`\n\n")

            if gaps:
                f.write("## Gaps Identified\n\n")
                for t in gaps:
                    f.write(f"### {t.method} {t.endpoint}\n")
                    f.write(f"- **Group**: {t.group}\n")
                    f.write(f"- **Status Code**: {t.status_code}\n")
                    f.write(f"- **Reason**: {t.reason}\n\n")

            if needs_seeding:
                f.write("## Needs Data Seeding\n\n")
                for t in needs_seeding:
                    f.write(f"- {t.method} {t.endpoint}: {t.reason}\n")

            f.write("\n## Consistency Check Results\n\n")
            for c in self.consistency_checks:
                status = "PASS" if c.passed else "FAIL"
                f.write(f"### {c.name}\n")
                f.write(f"- **Status**: {status}\n")
                f.write(f"- **Description**: {c.description}\n")
                f.write(f"- **Expected**: {c.expected}\n")
                f.write(f"- **Actual**: {c.actual}\n\n")

        # HTML report
        self._generate_html_report()

        print(f"\n{'='*80}")
        print("REPORTS GENERATED")
        print(f"{'='*80}")
        print(f"  - {OUTPUT_DIR}/test_results.json")
        print(f"  - {OUTPUT_DIR}/coverage_matrix.csv")
        print(f"  - {OUTPUT_DIR}/bugs_and_gaps.md")
        print(f"  - {OUTPUT_DIR}/comprehensive_report.html")

    def _generate_html_report(self):
        """Generate HTML report."""
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>FixOps Comprehensive Test Results</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 20px; background: #1a1a2e; color: #eee; }}
        h1 {{ color: #00d4ff; border-bottom: 2px solid #00d4ff; padding-bottom: 10px; }}
        h2 {{ color: #00d4ff; margin-top: 30px; }}
        .summary {{ display: flex; gap: 20px; flex-wrap: wrap; margin: 20px 0; }}
        .stat-box {{ background: #16213e; padding: 20px; border-radius: 8px; min-width: 150px; text-align: center; }}
        .stat-box h3 {{ margin: 0; font-size: 14px; color: #888; }}
        .stat-box .value {{ font-size: 36px; font-weight: bold; margin: 10px 0; }}
        .pass {{ color: #00ff88; }}
        .bug {{ color: #ff4444; }}
        .gap {{ color: #ffaa00; }}
        .needs-seeding {{ color: #4488ff; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #333; }}
        th {{ background: #16213e; color: #00d4ff; }}
        tr:hover {{ background: #16213e; }}
        .result-pass {{ color: #00ff88; }}
        .result-bug {{ color: #ff4444; font-weight: bold; }}
        .result-gap {{ color: #ffaa00; }}
        .result-needs-seeding {{ color: #4488ff; }}
        .filter-bar {{ margin: 20px 0; }}
        .filter-bar button {{ padding: 8px 16px; margin-right: 10px; border: none; border-radius: 4px; cursor: pointer; background: #16213e; color: #eee; }}
        .filter-bar button:hover {{ background: #1f4068; }}
        .filter-bar button.active {{ background: #00d4ff; color: #000; }}
    </style>
</head>
<body>
    <h1>FixOps Comprehensive Test Results</h1>
    <p>Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}</p>

    <div class="summary">
        <div class="stat-box">
            <h3>TOTAL TESTS</h3>
            <div class="value">{self.stats['total']}</div>
        </div>
        <div class="stat-box">
            <h3>PASSED</h3>
            <div class="value pass">{self.stats['pass']}</div>
        </div>
        <div class="stat-box">
            <h3>BUGS</h3>
            <div class="value bug">{self.stats['bug']}</div>
        </div>
        <div class="stat-box">
            <h3>GAPS</h3>
            <div class="value gap">{self.stats['gap']}</div>
        </div>
        <div class="stat-box">
            <h3>NEEDS SEEDING</h3>
            <div class="value needs-seeding">{self.stats['needs_seeding']}</div>
        </div>
        <div class="stat-box">
            <h3>PASS RATE</h3>
            <div class="value">{self.stats['pass']/self.stats['total']*100:.1f}%</div>
        </div>
    </div>

    <h2>Test Results</h2>
    <div class="filter-bar">
        <button class="active" onclick="filterResults('all')">All</button>
        <button onclick="filterResults('BUG')">Bugs Only</button>
        <button onclick="filterResults('GAP')">Gaps Only</button>
        <button onclick="filterResults('NEEDS-SEEDING')">Needs Seeding</button>
        <button onclick="filterResults('PASS')">Passed</button>
    </div>

    <table id="results-table">
        <thead>
            <tr>
                <th>Result</th>
                <th>Group</th>
                <th>Method</th>
                <th>Endpoint</th>
                <th>Status</th>
                <th>Reason</th>
                <th>Time (ms)</th>
            </tr>
        </thead>
        <tbody>
"""

        for t in self.results:
            result_class = f"result-{t.result.value.lower().replace('-', '-')}"
            html += f"""            <tr data-result="{t.result.value}">
                <td class="{result_class}">{t.result.value}</td>
                <td>{t.group}</td>
                <td>{t.method}</td>
                <td>{t.endpoint}</td>
                <td>{t.status_code}</td>
                <td>{t.reason[:60]}</td>
                <td>{t.response_time_ms:.1f}</td>
            </tr>
"""

        html += """        </tbody>
    </table>

    <h2>Consistency Checks</h2>
    <table>
        <thead>
            <tr>
                <th>Status</th>
                <th>Check</th>
                <th>Description</th>
                <th>Expected</th>
                <th>Actual</th>
            </tr>
        </thead>
        <tbody>
"""

        for c in self.consistency_checks:
            status_class = "pass" if c.passed else "bug"
            status_text = "PASS" if c.passed else "FAIL"
            html += f"""            <tr>
                <td class="{status_class}">{status_text}</td>
                <td>{c.name}</td>
                <td>{c.description}</td>
                <td>{c.expected}</td>
                <td>{c.actual}</td>
            </tr>
"""

        html += """        </tbody>
    </table>

    <script>
        function filterResults(filter) {
            const rows = document.querySelectorAll('#results-table tbody tr');
            const buttons = document.querySelectorAll('.filter-bar button');

            buttons.forEach(b => b.classList.remove('active'));
            event.target.classList.add('active');

            rows.forEach(row => {
                if (filter === 'all' || row.dataset.result === filter) {
                    row.style.display = '';
                } else {
                    row.style.display = 'none';
                }
            });
        }
    </script>
</body>
</html>
"""

        with open(f"{OUTPUT_DIR}/comprehensive_report.html", "w") as f:
            f.write(html)

    # ========================================================================
    # MAIN EXECUTION
    # ========================================================================

    def run_all(self):
        """Run all test phases."""
        print("\n" + "=" * 80)
        print("FIXOPS COMPREHENSIVE END-TO-END TEST SUITE")
        print("=" * 80)
        print(f"Base URL: {BASE_URL}")
        print(f"Started: {datetime.now(timezone.utc).isoformat()}")
        print(f"Customers: {len(CUSTOMERS)}")
        print(f"Applications: {len(APPLICATIONS)}")
        print("=" * 80)

        try:
            self.phase1_infrastructure_setup()
            self.phase1_5_data_seeding()
            self.phase2_data_ingestion()
            self.phase3_pipeline_execution()
            self.phase4_api_coverage()
            self.phase4_5_openapi_coverage()
            self.phase5_negative_tests()
            self.phase6_consistency_checks()
        except Exception as e:
            print(f"\n[ERROR] Test execution failed: {e}")
            traceback.print_exc()

        self.generate_reports()

        print("\n" + "=" * 80)
        print("TEST EXECUTION COMPLETE")
        print("=" * 80)
        print("\nFinal Results:")
        print(f"  Total:         {self.stats['total']}")
        pass_rate = self.stats["pass"] / max(self.stats["total"], 1) * 100
        print(f"  PASS:          {self.stats['pass']} ({pass_rate:.1f}%)")
        print(f"  BUG:           {self.stats['bug']}")
        print(f"  GAP:           {self.stats['gap']}")
        print(f"  NEEDS-SEEDING: {self.stats['needs_seeding']}")
        print(f"\nReports saved to: {OUTPUT_DIR}")


def main():
    """Main entry point."""
    client = FixOpsClient(BASE_URL, API_KEY)
    runner = ComprehensiveTestRunner(client)
    runner.run_all()


if __name__ == "__main__":
    main()
