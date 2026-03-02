#!/usr/bin/env python3
"""
ALdeci CTEM+ Multi-Architecture Showcase
==========================================
Demonstrates ALdeci processing 5 DIFFERENT enterprise verticals in one session.

  E-Commerce (AWS) → Healthcare (Azure) → FinServ (Multi-Cloud) →
  IoT/OT (Hybrid) → GovCloud (FedRAMP)

Each vertical:
  1. Ingests architecture-specific SBOM, SARIF, CNAPP, CVE feeds
  2. Runs native scanners against architecture code patterns
  3. Processes through 12-step Brain Pipeline
  4. Generates AutoFix remediation patches
  5. Produces compliance evidence bundles (PCI-DSS / HIPAA / SOX / IEC-62443 / FedRAMP)

Proves: ALdeci is NOT a one-trick demo — it handles ANY enterprise architecture.

Usage:
    python scripts/ctem_multi_architecture_showcase.py
    python scripts/ctem_multi_architecture_showcase.py --fast      # skip narration
    python scripts/ctem_multi_architecture_showcase.py --verbose   # full responses
    python scripts/ctem_multi_architecture_showcase.py --vertical ecommerce  # single vertical

Pillars: V3 (Decision Intelligence) + V5 (MPTE) + V10 (Evidence) + V9 (Air-Gap)
Sprint: 2 — Enterprise Demo (2026-03-06)
Author: threat-architect (Session 5, 2026-03-02)
"""

import json
import os
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone
from typing import Any, Dict, Tuple

# ── Config ──────────────────────────────────────────────────────────────

BASE_URL = os.getenv("ALDECI_BASE_URL", "http://localhost:8000")
API_TOKEN = os.getenv(
    "FIXOPS_API_TOKEN",
    "aVFf3-1e7EmlXzx37Y8jaCx--yzpd4OJroyIdgXH-vFiylmaN0FDl2vIOAfBA_Oh",
)
HEADERS = {"X-API-Key": API_TOKEN, "Content-Type": "application/json"}
VERBOSE = "--verbose" in sys.argv or "-v" in sys.argv
FAST = "--fast" in sys.argv
SINGLE_VERTICAL = None
for i, arg in enumerate(sys.argv):
    if arg == "--vertical" and i + 1 < len(sys.argv):
        SINGLE_VERTICAL = sys.argv[i + 1].lower()

# ── Colors ──────────────────────────────────────────────────────────────

class C:
    BOLD = "\033[1m"
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    MAGENTA = "\033[95m"
    WHITE = "\033[97m"
    DIM = "\033[2m"
    RESET = "\033[0m"
    BG_BLUE = "\033[44m"
    BG_GREEN = "\033[42m"
    BG_RED = "\033[41m"
    BG_MAGENTA = "\033[45m"

# ── HTTP Client ─────────────────────────────────────────────────────────

def api_call(
    method: str, path: str, body: Any = None, timeout: int = 60
) -> Tuple[int, Any, float]:
    """Make an API call with exponential backoff retry on 429."""
    for attempt in range(4):
        url = f"{BASE_URL}{path}"
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(url, data=data, method=method)
        for k, v in HEADERS.items():
            req.add_header(k, v)
        start = time.monotonic()
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8")
                elapsed = (time.monotonic() - start) * 1000
                try:
                    return resp.status, json.loads(raw), elapsed
                except json.JSONDecodeError:
                    return resp.status, {"raw": raw[:500]}, elapsed
        except urllib.error.HTTPError as e:
            elapsed = (time.monotonic() - start) * 1000
            if e.code == 429 and attempt < 3:
                wait = (attempt + 1) * 3
                time.sleep(wait)
                continue
            try:
                raw = e.read().decode("utf-8")
                return e.code, json.loads(raw), elapsed
            except Exception:
                return e.code, {"error": str(e)}, elapsed
        except Exception as e:
            elapsed = (time.monotonic() - start) * 1000
            return 0, {"error": str(e)}, elapsed
    return 429, {"error": "Rate limited after retries"}, 0


def api_upload(path: str, file_content: str, filename: str, content_type: str = "application/json") -> Tuple[int, Any, float]:
    """Upload a file via multipart/form-data with retry on 429."""
    for attempt in range(4):
        boundary = f"----ALdeciUpload{int(time.time())}{attempt}"
        body_parts = []
        body_parts.append(f"--{boundary}\r\n".encode())
        body_parts.append(f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'.encode())
        body_parts.append(f"Content-Type: {content_type}\r\n\r\n".encode())
        body_parts.append(file_content.encode("utf-8") if isinstance(file_content, str) else file_content)
        body_parts.append(f"\r\n--{boundary}--\r\n".encode())
        data = b"".join(body_parts)

        url = f"{BASE_URL}{path}"
        req = urllib.request.Request(url, data=data, method="POST")
        req.add_header("X-API-Key", API_TOKEN)
        req.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")

        start = time.monotonic()
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                raw = resp.read().decode("utf-8")
                elapsed = (time.monotonic() - start) * 1000
                try:
                    return resp.status, json.loads(raw), elapsed
                except json.JSONDecodeError:
                    return resp.status, {"raw": raw[:500]}, elapsed
        except urllib.error.HTTPError as e:
            elapsed = (time.monotonic() - start) * 1000
            if e.code == 429 and attempt < 3:
                time.sleep((attempt + 1) * 3)
                continue
            try:
                raw = e.read().decode("utf-8")
                return e.code, json.loads(raw), elapsed
            except Exception:
                return e.code, {"error": str(e)}, elapsed
        except Exception as e:
            elapsed = (time.monotonic() - start) * 1000
            return 0, {"error": str(e)}, elapsed
    return 429, {"error": "Rate limited after retries"}, 0


# ── Counters & Tracking ─────────────────────────────────────────────────

PASS = 0
FAIL = 0
TOTAL = 0
STEP = 0
RESULTS: Dict[str, Any] = {}
DEMO_START = time.monotonic()


def step(name: str, vertical: str = "") -> int:
    global STEP, TOTAL
    STEP += 1
    TOTAL += 1
    prefix = f"[{vertical}] " if vertical else ""
    print(f"\n  {C.BOLD}{C.MAGENTA}┌─ Step {STEP}: {prefix}{name}{C.RESET}")
    return STEP


def ok(msg: str):
    global PASS
    PASS += 1
    print(f"  {C.GREEN}│  ✓ {msg}{C.RESET}")


def warn(msg: str):
    print(f"  {C.YELLOW}│  ⚠ {msg}{C.RESET}")


def fail(msg: str):
    global FAIL
    FAIL += 1
    print(f"  {C.RED}│  ✗ {msg}{C.RESET}")


def detail(msg: str):
    print(f"  {C.DIM}│  {msg}{C.RESET}")


def footer():
    print(f"  {C.MAGENTA}└─────────────────────────────────{C.RESET}")


def narrate(msg: str):
    if not FAST:
        print(f"  {C.DIM}  💬 {msg}{C.RESET}")
        time.sleep(0.5)


def banner(title: str, subtitle: str = "", icon: str = "🏢"):
    w = 66
    print(f"\n{C.BOLD}{C.BG_BLUE}{C.WHITE}{'':>{w}}{C.RESET}")
    print(f"{C.BOLD}{C.BG_BLUE}{C.WHITE}  {icon} {title:<{w-4}}{C.RESET}")
    if subtitle:
        print(f"{C.BOLD}{C.BG_BLUE}{C.WHITE}  {subtitle:<{w-2}}{C.RESET}")
    print(f"{C.BOLD}{C.BG_BLUE}{C.WHITE}{'':>{w}}{C.RESET}")


def vertical_banner(name: str, cloud: str, compliance: str, icon: str):
    w = 66
    print(f"\n{'━' * w}")
    print(f"{C.BOLD}{C.BG_MAGENTA}{C.WHITE}{'':>{w}}{C.RESET}")
    print(f"{C.BOLD}{C.BG_MAGENTA}{C.WHITE}  {icon}  {name:<{w-5}}{C.RESET}")
    print(f"{C.BOLD}{C.BG_MAGENTA}{C.WHITE}  Cloud: {cloud}  |  Compliance: {compliance:<{w-30}}{C.RESET}")
    print(f"{C.BOLD}{C.BG_MAGENTA}{C.WHITE}{'':>{w}}{C.RESET}")
    print(f"{'━' * w}")


# ═══════════════════════════════════════════════════════════════════════
# ARCHITECTURE DEFINITIONS — Real enterprise stacks
# ═══════════════════════════════════════════════════════════════════════

VERTICALS = {
    "ecommerce": {
        "name": "Acme E-Commerce Platform",
        "cloud": "AWS",
        "compliance": ["PCI-DSS-v4.0", "SOC2-Type-II", "GDPR"],
        "compliance_framework": "PCI-DSS",
        "icon": "🛒",
        "org_id": "acme-ecommerce",
        "sbom": {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "metadata": {
                "timestamp": "2026-03-02T00:00:00Z",
                "component": {"name": "ecommerce-platform", "version": "2.4.1", "type": "application"}
            },
            "components": [
                {"type": "library", "name": "org.springframework.boot:spring-boot-starter-web", "version": "3.2.3",
                 "purl": "pkg:maven/org.springframework.boot/spring-boot-starter-web@3.2.3"},
                {"type": "library", "name": "com.fasterxml.jackson.core:jackson-databind", "version": "2.16.1",
                 "purl": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.16.1"},
                {"type": "library", "name": "org.postgresql:postgresql", "version": "42.7.1",
                 "purl": "pkg:maven/org.postgresql/postgresql@42.7.1"},
                {"type": "library", "name": "io.jsonwebtoken:jjwt-impl", "version": "0.12.3",
                 "purl": "pkg:maven/io.jsonwebtoken/jjwt-impl@0.12.3"},
                {"type": "library", "name": "org.apache.logging.log4j:log4j-core", "version": "2.23.0",
                 "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.23.0"},
                {"type": "library", "name": "express", "version": "4.18.3",
                 "purl": "pkg:npm/express@4.18.3"},
                {"type": "library", "name": "jsonwebtoken", "version": "9.0.2",
                 "purl": "pkg:npm/jsonwebtoken@9.0.2"},
                {"type": "library", "name": "fastapi", "version": "0.109.2",
                 "purl": "pkg:pypi/fastapi@0.109.2"},
                {"type": "library", "name": "redis", "version": "5.0.1",
                 "purl": "pkg:pypi/redis@5.0.1"},
                {"type": "library", "name": "stripe", "version": "8.2.0",
                 "purl": "pkg:pypi/stripe@8.2.0"},
            ],
        },
        "cves": [
            {"cve_id": "CVE-2024-22259", "cvss": 8.1, "severity": "HIGH",
             "description": "Spring Framework URL parsing vulnerability allows open redirect via crafted URL",
             "affected_package": "spring-boot-starter-web", "impact_type": "remote_code_execution"},
            {"cve_id": "CVE-2024-22243", "cvss": 8.1, "severity": "HIGH",
             "description": "Spring Framework URL parsing vulnerability",
             "affected_package": "spring-boot-starter-web", "impact_type": "remote_code_execution"},
            {"cve_id": "CVE-2023-35116", "cvss": 7.5, "severity": "HIGH",
             "description": "Jackson-databind denial of service via crafted object",
             "affected_package": "jackson-databind", "impact_type": "denial_of_service"},
        ],
        "sarif_findings": [
            {"ruleId": "CWE-89", "level": "error", "message": "SQL injection in user search — parameterized query not used",
             "file": "src/main/java/com/ecommerce/UserController.java", "line": 42},
            {"ruleId": "CWE-79", "level": "warning", "message": "Reflected XSS in product review rendering",
             "file": "src/main/java/com/ecommerce/ReviewController.java", "line": 87},
            {"ruleId": "CWE-502", "level": "error", "message": "Deserialization of untrusted data in order import",
             "file": "src/main/java/com/ecommerce/OrderImportService.java", "line": 156},
            {"ruleId": "CWE-798", "level": "error", "message": "Hardcoded Stripe API key in payment service",
             "file": "src/main/java/com/ecommerce/PaymentService.java", "line": 23},
        ],
        "cnapp_findings": [
            {"id": "CNAPP-AWS-001", "resource_type": "AWS::S3::Bucket", "resource_id": "arn:aws:s3:::ecommerce-media-prod",
             "rule": "S3_BUCKET_PUBLIC_READ_PROHIBITED", "severity": "HIGH", "status": "FAILED",
             "description": "S3 bucket allows public read access — media assets exposed",
             "remediation": "Enable S3 Block Public Access", "compliance": ["CIS-AWS-1.4-2.1.1", "PCI-DSS-v4.0-1.3.1"]},
            {"id": "CNAPP-AWS-002", "resource_type": "AWS::IAM::Role", "resource_id": "arn:aws:iam::123456789012:role/ecommerce-api-role",
             "rule": "IAM_POLICY_NO_STATEMENTS_WITH_ADMIN_ACCESS", "severity": "CRITICAL", "status": "FAILED",
             "description": "IAM role has AdministratorAccess policy attached — blast radius unlimited",
             "remediation": "Apply least-privilege IAM policy", "compliance": ["CIS-AWS-1.4-1.16", "NIST-800-53-AC-6"]},
            {"id": "CNAPP-AWS-003", "resource_type": "AWS::RDS::DBInstance", "resource_id": "arn:aws:rds:us-east-1:123456789012:db/ecommerce-users",
             "rule": "RDS_STORAGE_ENCRYPTED", "severity": "HIGH", "status": "FAILED",
             "description": "RDS instance storing PII not encrypted at rest",
             "remediation": "Enable RDS encryption at rest with KMS CMK", "compliance": ["PCI-DSS-v4.0-3.5.1", "GDPR-Art32"]},
        ],
        "vuln_code": 'import sqlite3\n\ndef search_users(query):\n    """Search users - VULNERABLE: SQL injection"""\n    conn = sqlite3.connect("users.db")\n    cursor = conn.cursor()\n    # BAD: string formatting in SQL query\n    cursor.execute(f"SELECT * FROM users WHERE name LIKE \'%{query}%\'")\n    results = cursor.fetchall()\n    conn.close()\n    return results\n\ndef render_review(review_text):\n    """Render review - VULNERABLE: XSS"""\n    return f"<div class=\\"review\\">{review_text}</div>"\n\nSTRIPE_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"\n',
        "iac_code": 'resource "aws_s3_bucket" "media" {\n  bucket = "ecommerce-media-prod"\n  acl    = "public-read"\n}\n\nresource "aws_db_instance" "users" {\n  identifier     = "ecommerce-users"\n  engine         = "postgres"\n  instance_class = "db.r6g.xlarge"\n  storage_encrypted = false\n  publicly_accessible = true\n}\n\nresource "aws_security_group" "api" {\n  name = "ecommerce-api"\n  ingress {\n    from_port   = 0\n    to_port     = 65535\n    protocol    = "tcp"\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n',
    },

    "healthcare": {
        "name": "MedSecure Healthcare SaaS",
        "cloud": "Azure",
        "compliance": ["HIPAA-BAA", "SOC2-Type-II", "HITRUST-CSF", "HL7-FHIR-R4"],
        "compliance_framework": "HIPAA",
        "icon": "🏥",
        "org_id": "medsecure-health",
        "sbom": {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "metadata": {
                "timestamp": "2026-03-02T00:00:00Z",
                "component": {"name": "medsecure-platform", "version": "3.1.0", "type": "application"}
            },
            "components": [
                {"type": "library", "name": "Microsoft.AspNetCore.App", "version": "8.0.2",
                 "purl": "pkg:nuget/Microsoft.AspNetCore.App@8.0.2"},
                {"type": "library", "name": "Hl7.Fhir.R4", "version": "5.7.0",
                 "purl": "pkg:nuget/Hl7.Fhir.R4@5.7.0"},
                {"type": "library", "name": "Azure.Identity", "version": "1.10.4",
                 "purl": "pkg:nuget/Azure.Identity@1.10.4"},
                {"type": "library", "name": "Microsoft.Azure.Cosmos", "version": "3.38.1",
                 "purl": "pkg:nuget/Microsoft.Azure.Cosmos@3.38.1"},
                {"type": "library", "name": "Azure.Security.KeyVault.Secrets", "version": "4.6.0",
                 "purl": "pkg:nuget/Azure.Security.KeyVault.Secrets@4.6.0"},
                {"type": "library", "name": "@angular/core", "version": "17.1.2",
                 "purl": "pkg:npm/%40angular/core@17.1.2"},
                {"type": "library", "name": "rxjs", "version": "7.8.1",
                 "purl": "pkg:npm/rxjs@7.8.1"},
                {"type": "library", "name": "dicom-parser", "version": "1.8.21",
                 "purl": "pkg:npm/dicom-parser@1.8.21"},
            ],
        },
        "cves": [
            {"cve_id": "CVE-2024-21319", "cvss": 6.8, "severity": "MEDIUM",
             "description": ".NET denial of service via malformed X.509 certificate chain",
             "affected_package": "Microsoft.AspNetCore.App", "impact_type": "denial_of_service"},
            {"cve_id": "CVE-2024-0057", "cvss": 9.1, "severity": "CRITICAL",
             "description": ".NET X.509 certificate chain validation bypass",
             "affected_package": "Microsoft.AspNetCore.App", "impact_type": "remote_code_execution"},
            {"cve_id": "CVE-2023-44487", "cvss": 7.5, "severity": "HIGH",
             "description": "HTTP/2 Rapid Reset attack (affects .NET Kestrel)",
             "affected_package": "Microsoft.AspNetCore.App", "impact_type": "denial_of_service"},
        ],
        "sarif_findings": [
            {"ruleId": "CWE-311", "level": "error", "message": "PHI transmitted without encryption — HIPAA §164.312(e)(1) violation",
             "file": "src/Services/PatientDataService.cs", "line": 134},
            {"ruleId": "CWE-532", "level": "error", "message": "PHI logged to application logs — HIPAA §164.312(b) violation",
             "file": "src/Services/ClinicalWorkflowService.cs", "line": 89},
            {"ruleId": "CWE-862", "level": "error", "message": "Missing authorization check on patient records API",
             "file": "src/Controllers/PatientController.cs", "line": 67},
            {"ruleId": "CWE-327", "level": "warning", "message": "Weak cryptographic algorithm (SHA1) used for PHI hashing",
             "file": "src/Utils/CryptoHelper.cs", "line": 42},
        ],
        "cnapp_findings": [
            {"id": "CNAPP-AZ-001", "resource_type": "Microsoft.Storage/storageAccounts",
             "resource_id": "/subscriptions/sub-123/resourceGroups/medsecure-prod/providers/Microsoft.Storage/storageAccounts/phidocs",
             "rule": "STORAGE_ACCOUNT_HTTPS_ONLY", "severity": "CRITICAL", "status": "FAILED",
             "description": "Storage account containing PHI allows HTTP (non-encrypted) access",
             "remediation": "Enable HTTPS-only on storage account", "compliance": ["HIPAA-164.312(e)(1)", "HITRUST-09.m"]},
            {"id": "CNAPP-AZ-002", "resource_type": "Microsoft.DBforCosmosDB/databaseAccounts",
             "resource_id": "/subscriptions/sub-123/resourceGroups/medsecure-prod/providers/Microsoft.DocumentDB/databaseAccounts/patient-db",
             "rule": "COSMOS_DB_FIREWALL_RULES", "severity": "HIGH", "status": "FAILED",
             "description": "Cosmos DB with patient PHI accepts connections from all networks",
             "remediation": "Configure Cosmos DB firewall to allow only VNET access", "compliance": ["HIPAA-164.312(a)(1)", "CIS-Azure-4.5.1"]},
            {"id": "CNAPP-AZ-003", "resource_type": "Microsoft.KeyVault/vaults",
             "resource_id": "/subscriptions/sub-123/resourceGroups/medsecure-prod/providers/Microsoft.KeyVault/vaults/phi-keys",
             "rule": "KEY_VAULT_SOFT_DELETE_ENABLED", "severity": "MEDIUM", "status": "FAILED",
             "description": "Key Vault without soft delete — PHI encryption keys could be permanently lost",
             "remediation": "Enable soft delete and purge protection", "compliance": ["HIPAA-164.312(a)(2)(iv)", "SOC2-CC6.1"]},
        ],
        "vuln_code": 'using System.Data.SqlClient;\n\npublic class PatientService {\n    // VULNERABLE: PHI logged without redaction\n    public Patient GetPatient(string patientId) {\n        var patient = _db.FindById(patientId);\n        _logger.LogInformation($"Retrieved patient: {patient.SSN}, {patient.Name}, DOB: {patient.DateOfBirth}");\n        return patient;\n    }\n\n    // VULNERABLE: No authorization check\n    public List<Patient> SearchPatients(string query) {\n        return _db.Query($"SELECT * FROM patients WHERE name LIKE \'%{query}%\'").ToList();\n    }\n\n    // VULNERABLE: Weak hashing for PHI\n    public string HashPHI(string data) {\n        using var sha1 = System.Security.Cryptography.SHA1.Create();\n        return Convert.ToBase64String(sha1.ComputeHash(System.Text.Encoding.UTF8.GetBytes(data)));\n    }\n}\n',
        "iac_code": 'resource "azurerm_storage_account" "phi_docs" {\n  name                     = "phidocs"\n  resource_group_name      = "medsecure-prod"\n  location                 = "eastus2"\n  account_tier             = "Standard"\n  account_replication_type = "GRS"\n  enable_https_traffic_only = false\n}\n\nresource "azurerm_cosmosdb_account" "patient_db" {\n  name                = "patient-db"\n  resource_group_name = "medsecure-prod"\n  location            = "eastus2"\n  offer_type          = "Standard"\n  is_virtual_network_filter_enabled = false\n}\n',
    },

    "finserv": {
        "name": "SecureTrade Financial Platform",
        "cloud": "Multi-Cloud (GCP+AWS)",
        "compliance": ["PCI-DSS-v4.0", "SOX", "GLBA", "FINRA"],
        "compliance_framework": "SOC2",
        "icon": "🏦",
        "org_id": "securetrade-fin",
        "sbom": {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "metadata": {
                "timestamp": "2026-03-02T00:00:00Z",
                "component": {"name": "securetrade-platform", "version": "4.0.0", "type": "application"}
            },
            "components": [
                {"type": "library", "name": "org.springframework.boot:spring-boot-starter-web", "version": "3.2.3",
                 "purl": "pkg:maven/org.springframework.boot/spring-boot-starter-web@3.2.3"},
                {"type": "library", "name": "io.grpc:grpc-netty-shaded", "version": "1.62.2",
                 "purl": "pkg:maven/io.grpc/grpc-netty-shaded@1.62.2"},
                {"type": "library", "name": "com.google.cloud:google-cloud-spanner", "version": "6.58.0",
                 "purl": "pkg:maven/com.google.cloud/google-cloud-spanner@6.58.0"},
                {"type": "library", "name": "numpy", "version": "1.26.4",
                 "purl": "pkg:pypi/numpy@1.26.4"},
                {"type": "library", "name": "pandas", "version": "2.2.1",
                 "purl": "pkg:pypi/pandas@2.2.1"},
                {"type": "library", "name": "tensorflow", "version": "2.16.1",
                 "purl": "pkg:pypi/tensorflow@2.16.1"},
                {"type": "library", "name": "next", "version": "14.1.3",
                 "purl": "pkg:npm/next@14.1.3"},
                {"type": "library", "name": "quickfix", "version": "1.15.1",
                 "purl": "pkg:pypi/quickfix@1.15.1"},
            ],
        },
        "cves": [
            {"cve_id": "CVE-2024-22259", "cvss": 8.1, "severity": "HIGH",
             "description": "Spring Framework URL parsing allows request smuggling in trading API",
             "affected_package": "spring-boot-starter-web", "impact_type": "remote_code_execution"},
            {"cve_id": "CVE-2024-3651", "cvss": 7.5, "severity": "HIGH",
             "description": "idna library DoS via crafted internationalized domain name",
             "affected_package": "tensorflow", "impact_type": "denial_of_service"},
            {"cve_id": "CVE-2024-34064", "cvss": 5.4, "severity": "MEDIUM",
             "description": "Jinja2 XSS via xmlattr filter in reporting templates",
             "affected_package": "pandas", "impact_type": "cross_site_scripting"},
        ],
        "sarif_findings": [
            {"ruleId": "CWE-89", "level": "error", "message": "SQL injection in trade history query — financial data at risk",
             "file": "src/main/java/com/securetrade/TradeHistoryService.java", "line": 78},
            {"ruleId": "CWE-306", "level": "error", "message": "Missing authentication on internal settlement API",
             "file": "src/main/java/com/securetrade/SettlementController.java", "line": 34},
            {"ruleId": "CWE-778", "level": "error", "message": "Insufficient audit logging on financial transactions — SOX violation",
             "file": "src/main/java/com/securetrade/TransactionService.java", "line": 112},
            {"ruleId": "CWE-330", "level": "warning", "message": "Weak random number generator in transaction ID generation",
             "file": "src/main/java/com/securetrade/IdGenerator.java", "line": 19},
        ],
        "cnapp_findings": [
            {"id": "CNAPP-GCP-001", "resource_type": "compute.googleapis.com/Instance",
             "resource_id": "projects/securetrade-prod/zones/us-central1-a/instances/trading-engine-1",
             "rule": "GCE_INSTANCE_NO_PUBLIC_IP", "severity": "CRITICAL", "status": "FAILED",
             "description": "Trading engine VM has public IP — direct internet exposure of financial systems",
             "remediation": "Remove public IP, route through Cloud NAT", "compliance": ["PCI-DSS-v4.0-1.3.2", "SOX-302"]},
            {"id": "CNAPP-GCP-002", "resource_type": "spanner.googleapis.com/Database",
             "resource_id": "projects/securetrade-prod/instances/trading/databases/transactions",
             "rule": "SPANNER_CMEK_ENCRYPTION", "severity": "HIGH", "status": "FAILED",
             "description": "Spanner database with financial transactions not using CMEK encryption",
             "remediation": "Enable Customer-Managed Encryption Keys", "compliance": ["PCI-DSS-v4.0-3.5.1", "GLBA-501"]},
        ],
        "vuln_code": 'import sqlite3\nimport random\nimport string\n\ndef get_trade_history(account_id, date_range):\n    """VULNERABLE: SQL injection in financial query"""\n    conn = sqlite3.connect("trades.db")\n    cursor = conn.cursor()\n    cursor.execute(f"SELECT * FROM trades WHERE account_id = \'{account_id}\' AND date >= \'{date_range}\'")\n    return cursor.fetchall()\n\ndef generate_transaction_id():\n    """VULNERABLE: Weak PRNG for transaction IDs"""\n    return \'\'.join(random.choices(string.ascii_letters + string.digits, k=16))\n\ndef log_transaction(tx):\n    """VULNERABLE: No audit trail"""\n    pass  # SOX requires comprehensive audit logging\n',
        "iac_code": 'resource "google_compute_instance" "trading_engine" {\n  name         = "trading-engine-1"\n  machine_type = "n2-highcpu-32"\n  zone         = "us-central1-a"\n  \n  network_interface {\n    network = "default"\n    access_config {}\n  }\n\n  metadata = {\n    enable-oslogin = "false"\n  }\n}\n\nresource "google_compute_firewall" "allow_all" {\n  name    = "allow-all-trading"\n  network = "default"\n  allow {\n    protocol = "tcp"\n    ports    = ["0-65535"]\n  }\n  source_ranges = ["0.0.0.0/0"]\n}\n',
    },

    "iot_ot": {
        "name": "IndustrialSecure IoT/OT Platform",
        "cloud": "Hybrid (On-Prem + AWS)",
        "compliance": ["IEC-62443", "NIST-CSF-2.0", "CIS-Controls-v8", "NERC-CIP"],
        "compliance_framework": "NIST-CSF",
        "icon": "🏭",
        "org_id": "industrialsecure-iot",
        "sbom": {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "metadata": {
                "timestamp": "2026-03-02T00:00:00Z",
                "component": {"name": "industrialsecure-platform", "version": "2.0.0", "type": "application"}
            },
            "components": [
                {"type": "library", "name": "eclipse-mosquitto", "version": "2.0.18",
                 "purl": "pkg:generic/eclipse-mosquitto@2.0.18"},
                {"type": "library", "name": "org.apache.kafka:kafka-clients", "version": "3.7.0",
                 "purl": "pkg:maven/org.apache.kafka/kafka-clients@3.7.0"},
                {"type": "library", "name": "influxdb-client", "version": "1.41.0",
                 "purl": "pkg:pypi/influxdb-client@1.41.0"},
                {"type": "library", "name": "paho-mqtt", "version": "2.0.0",
                 "purl": "pkg:pypi/paho-mqtt@2.0.0"},
                {"type": "library", "name": "pymodbus", "version": "3.6.4",
                 "purl": "pkg:pypi/pymodbus@3.6.4"},
                {"type": "library", "name": "grafana", "version": "10.3.3",
                 "purl": "pkg:generic/grafana@10.3.3"},
                {"type": "library", "name": "node-opcua", "version": "2.118.0",
                 "purl": "pkg:npm/node-opcua@2.118.0"},
                {"type": "library", "name": "tokio", "version": "1.36.0",
                 "purl": "pkg:cargo/tokio@1.36.0"},
            ],
        },
        "cves": [
            {"cve_id": "CVE-2023-3592", "cvss": 7.5, "severity": "HIGH",
             "description": "Eclipse Mosquitto memory leak via malformed CONNECT packets",
             "affected_package": "eclipse-mosquitto", "impact_type": "denial_of_service"},
            {"cve_id": "CVE-2024-31141", "cvss": 6.5, "severity": "MEDIUM",
             "description": "Apache Kafka clients JNDI injection via SASL configuration",
             "affected_package": "kafka-clients", "impact_type": "remote_code_execution"},
            {"cve_id": "CVE-2023-46604", "cvss": 10.0, "severity": "CRITICAL",
             "description": "Apache ActiveMQ RCE via OpenWire protocol (affects Kafka ecosystem)",
             "affected_package": "kafka-clients", "impact_type": "remote_code_execution"},
        ],
        "sarif_findings": [
            {"ruleId": "CWE-319", "level": "error", "message": "MQTT telemetry transmitted without TLS — Modbus data exposed",
             "file": "src/collectors/modbus_collector.py", "line": 56},
            {"ruleId": "CWE-287", "level": "error", "message": "OPC-UA server accepts anonymous authentication",
             "file": "src/gateways/opcua_gateway.js", "line": 34},
            {"ruleId": "CWE-494", "level": "error", "message": "Firmware update downloaded without integrity verification",
             "file": "src/services/firmware_updater.py", "line": 89},
            {"ruleId": "CWE-770", "level": "warning", "message": "No rate limiting on MQTT message ingestion — DoS risk to SCADA",
             "file": "src/brokers/mqtt_handler.py", "line": 23},
        ],
        "cnapp_findings": [
            {"id": "CNAPP-IOT-001", "resource_type": "AWS::IoT::TopicRule",
             "resource_id": "arn:aws:iot:us-east-1:123456789012:rule/TelemetryIngest",
             "rule": "IOT_TOPIC_RULE_ACTION_ENCRYPTED", "severity": "HIGH", "status": "FAILED",
             "description": "IoT topic rule sends OT telemetry to unencrypted S3 bucket",
             "remediation": "Enable SSE-KMS on target S3 bucket", "compliance": ["IEC-62443-3-3-SR3.1", "NIST-CSF-PR.DS-1"]},
            {"id": "CNAPP-IOT-002", "resource_type": "AWS::EC2::SecurityGroup",
             "resource_id": "arn:aws:ec2:us-east-1:123456789012:security-group/sg-edge-gw",
             "rule": "EC2_SG_RESTRICTED_COMMON_PORTS", "severity": "CRITICAL", "status": "FAILED",
             "description": "Edge gateway security group allows Modbus (502) from 0.0.0.0/0",
             "remediation": "Restrict Modbus port to VPN CIDR only", "compliance": ["IEC-62443-3-3-SR5.1", "CIS-Controls-v8-12.2"]},
        ],
        "vuln_code": 'import paho.mqtt.client as mqtt\nimport subprocess\nimport urllib.request\n\n# VULNERABLE: No TLS on MQTT\nclient = mqtt.Client()\nclient.connect("mqtt-broker.internal", 1883)\n\ndef handle_firmware_update(device_id, url):\n    """VULNERABLE: No integrity check on firmware"""\n    firmware = urllib.request.urlopen(url).read()\n    # Directly flash without verification\n    subprocess.run(["flash-firmware", device_id], input=firmware)\n\ndef process_modbus_data(data):\n    """VULNERABLE: No input validation on SCADA data"""\n    # Direct command injection via Modbus register values\n    subprocess.run(f"echo {data} >> /var/log/scada.log", shell=True)\n',
        "iac_code": 'resource "aws_security_group" "edge_gateway" {\n  name = "edge-gateway-sg"\n  \n  ingress {\n    from_port   = 502\n    to_port     = 502\n    protocol    = "tcp"\n    cidr_blocks = ["0.0.0.0/0"]\n    description = "Modbus TCP"\n  }\n  \n  ingress {\n    from_port   = 1883\n    to_port     = 1883\n    protocol    = "tcp"\n    cidr_blocks = ["0.0.0.0/0"]\n    description = "MQTT unencrypted"\n  }\n  \n  ingress {\n    from_port   = 4840\n    to_port     = 4840\n    protocol    = "tcp"\n    cidr_blocks = ["0.0.0.0/0"]\n    description = "OPC-UA"\n  }\n}\n',
    },

    "govcloud": {
        "name": "FedSecure Government Platform",
        "cloud": "GovCloud (Air-Gapped)",
        "compliance": ["FedRAMP-High", "NIST-800-53-Rev5", "FIPS-140-3", "IL5-DoD", "CMMC-L3"],
        "compliance_framework": "SOC2",
        "icon": "🏛️",
        "org_id": "fedsecure-gov",
        "sbom": {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "metadata": {
                "timestamp": "2026-03-02T00:00:00Z",
                "component": {"name": "fedsecure-platform", "version": "2.0.0", "type": "application"}
            },
            "components": [
                {"type": "library", "name": "Microsoft.AspNetCore.App", "version": "8.0.2",
                 "purl": "pkg:nuget/Microsoft.AspNetCore.App@8.0.2"},
                {"type": "library", "name": "Npgsql", "version": "8.0.2",
                 "purl": "pkg:nuget/Npgsql@8.0.2"},
                {"type": "library", "name": "RabbitMQ.Client", "version": "6.8.1",
                 "purl": "pkg:nuget/RabbitMQ.Client@6.8.1"},
                {"type": "library", "name": "Keycloak", "version": "24.0.1",
                 "purl": "pkg:generic/keycloak@24.0.1"},
                {"type": "library", "name": "HashiCorp.Vault", "version": "0.22.0",
                 "purl": "pkg:nuget/VaultSharp@0.22.0"},
                {"type": "library", "name": "istio", "version": "1.20.3",
                 "purl": "pkg:generic/istio@1.20.3"},
                {"type": "library", "name": "falco", "version": "0.37.1",
                 "purl": "pkg:generic/falco@0.37.1"},
                {"type": "library", "name": "trivy", "version": "0.49.1",
                 "purl": "pkg:generic/trivy@0.49.1"},
            ],
        },
        "cves": [
            {"cve_id": "CVE-2024-0057", "cvss": 9.1, "severity": "CRITICAL",
             "description": ".NET X.509 certificate chain validation bypass — auth bypass in CAC/PIV",
             "affected_package": "Microsoft.AspNetCore.App", "impact_type": "remote_code_execution"},
            {"cve_id": "CVE-2024-22201", "cvss": 7.5, "severity": "HIGH",
             "description": "Jetty HTTP/2 HPACK integer overflow — DoS in service mesh",
             "affected_package": "keycloak", "impact_type": "denial_of_service"},
            {"cve_id": "CVE-2023-44487", "cvss": 7.5, "severity": "HIGH",
             "description": "HTTP/2 Rapid Reset — affects Istio service mesh ingress",
             "affected_package": "istio", "impact_type": "denial_of_service"},
        ],
        "sarif_findings": [
            {"ruleId": "CWE-257", "level": "error", "message": "Recoverable password storage — NIST 800-53 IA-5(1) violation",
             "file": "src/Services/UserAuthService.cs", "line": 45},
            {"ruleId": "CWE-778", "level": "error", "message": "Insufficient audit logging on CUI access — NIST AU-2 violation",
             "file": "src/Services/DocumentService.cs", "line": 112},
            {"ruleId": "CWE-327", "level": "error", "message": "Non-FIPS cryptographic algorithm in use — FIPS 140-3 violation",
             "file": "src/Utils/EncryptionHelper.cs", "line": 28},
            {"ruleId": "CWE-522", "level": "warning", "message": "Credentials transmitted over non-mTLS channel",
             "file": "src/Services/InternalApiClient.cs", "line": 67},
        ],
        "cnapp_findings": [
            {"id": "CNAPP-GOV-001", "resource_type": "Kubernetes::Pod",
             "resource_id": "fedsecure-prod/case-management-pod",
             "rule": "K8S_POD_PRIVILEGED_CONTAINER", "severity": "CRITICAL", "status": "FAILED",
             "description": "Pod running privileged container in FedRAMP High environment",
             "remediation": "Remove privileged flag, use securityContext with minimal capabilities",
             "compliance": ["FedRAMP-AC-6(9)", "NIST-800-53-CM-7(2)", "CMMC-AC.L2-3.1.7"]},
            {"id": "CNAPP-GOV-002", "resource_type": "Kubernetes::NetworkPolicy",
             "resource_id": "fedsecure-prod/default-allow-all",
             "rule": "K8S_DEFAULT_DENY_NETWORK_POLICY", "severity": "HIGH", "status": "FAILED",
             "description": "No default-deny network policy — lateral movement possible in enclave",
             "remediation": "Create default-deny NetworkPolicy for namespace",
             "compliance": ["FedRAMP-SC-7(5)", "NIST-800-53-SC-7", "CMMC-SC.L2-3.13.1"]},
        ],
        "vuln_code": 'using System.Security.Cryptography;\nusing System.Text;\n\npublic class EncryptionHelper {\n    // VULNERABLE: Non-FIPS algorithm (FIPS 140-3 violation)\n    public static string Encrypt(string plaintext, string key) {\n        using var aes = Aes.Create();\n        // Not using FIPS-validated provider\n        aes.Mode = CipherMode.ECB;  // ECB mode is insecure\n        aes.Key = Encoding.UTF8.GetBytes(key.PadRight(32));\n        var encryptor = aes.CreateEncryptor();\n        var data = Encoding.UTF8.GetBytes(plaintext);\n        return Convert.ToBase64String(encryptor.TransformFinalBlock(data, 0, data.Length));\n    }\n\n    // VULNERABLE: Password stored reversibly\n    public static void StorePassword(string userId, string password) {\n        var encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes(password));\n        _db.Execute($"UPDATE users SET password = \'{encoded}\' WHERE id = \'{userId}\'");\n    }\n}\n',
        "iac_code": 'apiVersion: v1\nkind: Pod\nmetadata:\n  name: case-management\n  namespace: fedsecure-prod\nspec:\n  containers:\n  - name: case-mgmt\n    image: harbor.internal/fedsecure/case-mgmt:latest\n    securityContext:\n      privileged: true\n      runAsUser: 0\n    ports:\n    - containerPort: 8080\n',
    },
}


# ═══════════════════════════════════════════════════════════════════════
# CTEM LIFECYCLE PHASES — Applied to each vertical
# ═══════════════════════════════════════════════════════════════════════

def build_sarif(v: Dict) -> Dict:
    """Build a valid SARIF 2.1.0 report from vertical findings."""
    rules = []
    results = []
    seen_rules = set()
    for f in v["sarif_findings"]:
        rid = f["ruleId"]
        if rid not in seen_rules:
            seen_rules.add(rid)
            rules.append({
                "id": rid,
                "shortDescription": {"text": f["message"][:80]},
                "defaultConfiguration": {"level": f["level"]},
            })
        results.append({
            "ruleId": rid,
            "level": f["level"],
            "message": {"text": f["message"]},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f["file"]},
                    "region": {"startLine": f["line"]},
                }
            }],
        })
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "ALdeci-ThreatArchitect",
                    "version": "2.0.0",
                    "rules": rules,
                }
            },
            "results": results,
        }],
    }


def build_cve_feed(v: Dict) -> Dict:
    """Build CVE feed from vertical CVE list."""
    return {
        "source": "NVD+ThreatArchitect",
        "architecture": v["name"],
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "cves": v["cves"],
    }


def build_cnapp(v: Dict) -> Dict:
    """Build CNAPP findings from vertical cloud config."""
    provider = "aws"
    if "Azure" in v["cloud"]:
        provider = "azure"
    elif "GCP" in v["cloud"]:
        provider = "gcp"
    elif "Multi" in v["cloud"]:
        provider = "multi-cloud"
    return {
        "provider": provider,
        "account_id": f"org-{v['org_id']}",
        "architecture": v["name"],
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "findings": v["cnapp_findings"],
    }


def build_context(v: Dict) -> str:
    """Build business context YAML for vertical."""
    comp = v.get("compliance", [])
    comp_yaml = "\n".join(f"    - {c}" for c in comp)
    return f"""org:
  name: "{v['name']}"
  industry: "{v['org_id'].split('-')[-1]}"
  size: enterprise
  compliance_requirements:
{comp_yaml}
crown_jewels:
  - name: "primary-database"
    type: database
    criticality: critical
    data_classification: regulated
    sla_target: 99.99
  - name: "api-gateway"
    type: api_gateway
    criticality: high
    data_classification: internal
    sla_target: 99.95
environments:
  - name: production
    type: production
    region: us-east-1
    classification: regulated
"""


def phase_discover(vname: str, v: Dict) -> Dict:
    """Phase 1: DISCOVER — Ingest architecture data into ALdeci."""
    results = {"ingested": {}, "scanner_findings": {}}

    # 1a. SAST scan of vulnerable code
    step(f"SAST Scan — {v['name']}", vname)
    code, body, ms = api_call("POST", "/api/v1/sast/scan/code", {
        "code": v["vuln_code"],
        "language": "python" if "import " in v["vuln_code"] else "csharp",
        "scan_type": "security",
    })
    if code in (200, 201):
        findings = body.get("findings", body.get("vulnerabilities", []))
        count = len(findings) if isinstance(findings, list) else 0
        ok(f"SAST: {code} — {count} findings in {ms:.0f}ms")
        results["scanner_findings"]["sast"] = count
    else:
        warn(f"SAST: {code} — {ms:.0f}ms")
    footer()

    # 1b. IaC/CSPM scan
    step(f"IaC Security Scan — {v['name']}", vname)
    iac = v.get("iac_code", "")
    if "resource \"aws_" in iac or "resource \"google_" in iac:
        code, body, ms = api_call("POST", "/api/v1/cspm/scan/terraform", {"content": iac})
    elif "apiVersion:" in iac:
        code, body, ms = api_call("POST", "/api/v1/cspm/scan/terraform", {"content": iac})
    else:
        code, body, ms = api_call("POST", "/api/v1/cspm/scan/terraform", {"content": iac})
    if code in (200, 201):
        findings = body.get("findings", [])
        count = len(findings) if isinstance(findings, list) else 0
        ok(f"IaC: {code} — {count} misconfigurations in {ms:.0f}ms")
        results["scanner_findings"]["iac"] = count
    else:
        warn(f"IaC: {code} — {ms:.0f}ms")
    footer()

    # 1c. Secrets scan
    step(f"Secrets Scan — {v['name']}", vname)
    code, body, ms = api_call("POST", "/api/v1/secrets/scan/content", {
        "content": v["vuln_code"] + "\nAWS_SECRET_ACCESS_KEY = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nDATABASE_PASSWORD = SuperSecret123!\n",
        "filename": f"{vname}-config.py",
    })
    if code in (200, 201):
        findings = body.get("findings", [])
        count = len(findings) if isinstance(findings, list) else 0
        ok(f"Secrets: {code} — {count} secrets found in {ms:.0f}ms")
        results["scanner_findings"]["secrets"] = count
    else:
        warn(f"Secrets: {code} — {ms:.0f}ms")
    footer()

    # 1d. Ingest SBOM
    step(f"SBOM Ingestion ({len(v['sbom']['components'])} components)", vname)
    sbom_json = json.dumps(v["sbom"])
    code, body, ms = api_upload("/inputs/sbom", sbom_json, f"sbom-{vname}.json")
    if code in (200, 201):
        ok(f"SBOM: {code} — {len(v['sbom']['components'])} components ingested in {ms:.0f}ms")
        results["ingested"]["sbom"] = len(v["sbom"]["components"])
    else:
        warn(f"SBOM: {code} — {ms:.0f}ms")
    footer()

    # 1e. Ingest SARIF
    step(f"SARIF Ingestion ({len(v['sarif_findings'])} findings)", vname)
    sarif = build_sarif(v)
    sarif_json = json.dumps(sarif)
    code, body, ms = api_upload("/inputs/sarif", sarif_json, f"sarif-{vname}.json")
    if code in (200, 201):
        ok(f"SARIF: {code} — {len(v['sarif_findings'])} code findings in {ms:.0f}ms")
        results["ingested"]["sarif"] = len(v["sarif_findings"])
    else:
        warn(f"SARIF: {code} — {ms:.0f}ms")
    footer()

    # 1f. Ingest CVE feed
    step(f"CVE Feed ({len(v['cves'])} CVEs)", vname)
    cve_feed = build_cve_feed(v)
    code, body, ms = api_upload("/inputs/cve", json.dumps(cve_feed), f"cve-{vname}.json")
    if code in (200, 201):
        ok(f"CVE: {code} — {len(v['cves'])} CVEs correlated in {ms:.0f}ms")
        results["ingested"]["cves"] = len(v["cves"])
    else:
        warn(f"CVE: {code} — {ms:.0f}ms")
    footer()

    # 1g. Ingest CNAPP
    step(f"CNAPP Findings ({len(v['cnapp_findings'])} cloud misconfigs)", vname)
    cnapp = build_cnapp(v)
    code, body, ms = api_upload("/inputs/cnapp", json.dumps(cnapp), f"cnapp-{vname}.json")
    if code in (200, 201):
        ok(f"CNAPP: {code} — {len(v['cnapp_findings'])} cloud findings in {ms:.0f}ms")
        results["ingested"]["cnapp"] = len(v["cnapp_findings"])
    else:
        warn(f"CNAPP: {code} — {ms:.0f}ms")
    footer()

    # 1h. Ingest business context
    step(f"Business Context — {v['name']}", vname)
    ctx_yaml = build_context(v)
    code, body, ms = api_upload("/inputs/context", ctx_yaml, f"context-{vname}.yaml", "application/yaml")
    if code in (200, 201):
        ok(f"Context: {code} — Business context ingested in {ms:.0f}ms")
        results["ingested"]["context"] = True
    else:
        warn(f"Context: {code} — {ms:.0f}ms")
    footer()

    return results


def phase_validate(vname: str, v: Dict) -> Dict:
    """Phase 2: VALIDATE — Brain Pipeline + MPTE verification."""
    results = {"brain": {}, "mpte": {}}

    # 2a. Brain Pipeline
    step("Brain Pipeline (12-step CTEM)", vname)
    narrate("Brain Pipeline: connect → normalize → deduplicate → graph → enrich → score → policy → consensus")

    findings_for_brain = []
    for f in v["sarif_findings"]:
        findings_for_brain.append({
            "id": f"finding-{vname}-{f['ruleId']}-{f['line']}",
            "title": f["message"][:80],
            "severity": "critical" if f["level"] == "error" else "medium",
            "source": "threat-architect-sast",
            "cwe": f["ruleId"],
            "file_path": f["file"],
            "line_number": f["line"],
            "description": f["message"],
        })
    for c in v["cves"]:
        findings_for_brain.append({
            "id": f"finding-{vname}-{c['cve_id']}",
            "title": f"{c['cve_id']}: {c['description'][:60]}",
            "severity": c["severity"].lower(),
            "source": "threat-architect-cve",
            "cve_id": c["cve_id"],
            "cvss_score": c["cvss"],
            "description": c["description"],
        })
    for cn in v["cnapp_findings"]:
        findings_for_brain.append({
            "id": f"finding-{vname}-{cn['id']}",
            "title": cn["description"][:80],
            "severity": cn["severity"].lower(),
            "source": "threat-architect-cnapp",
            "resource_id": cn["resource_id"],
            "description": cn["description"],
        })

    code, body, ms = api_call("POST", "/api/v1/brain/pipeline/run", {
        "org_id": v["org_id"],
        "findings": findings_for_brain,
    }, timeout=120)

    if code in (200, 201):
        steps_completed = body.get("steps", [])
        step_count = len(steps_completed)
        summary = body.get("summary", {})
        ingested = summary.get("findings_ingested", len(findings_for_brain))
        clusters = summary.get("clusters_created", 0)
        graph_nodes = summary.get("graph_nodes", 0)
        avg_risk = summary.get("avg_risk_score", 0)

        noise_pct = 0
        if ingested > 0 and clusters > 0:
            noise_pct = max(0, (1 - clusters / ingested) * 100)

        ok(f"Brain Pipeline: {step_count}/12 steps, {ingested} findings → {clusters} clusters")
        detail(f"Noise reduction: {noise_pct:.1f}% | Graph: {graph_nodes} nodes | Avg risk: {avg_risk:.1f}")
        results["brain"] = {
            "steps": step_count,
            "findings_in": ingested,
            "clusters": clusters,
            "noise_reduction": round(noise_pct, 1),
            "graph_nodes": graph_nodes,
            "avg_risk": round(avg_risk, 1),
        }
    else:
        fail(f"Brain Pipeline: {code} — {ms:.0f}ms")
    footer()

    # 2b. MPTE Verification
    step("MPTE Micro-Pentest Verification", vname)
    narrate("MPTE proves exploitability — not just 'this might be vulnerable'")

    top_cve = v["cves"][0] if v["cves"] else None
    if top_cve:
        code, body, ms = api_call("POST", "/api/v1/mpte/verify", {
            "finding_id": f"finding-{vname}-{top_cve['cve_id']}",
            "target_url": f"https://{v['org_id']}.example.com",
            "vulnerability_type": top_cve["impact_type"],
            "evidence": f"SBOM shows {top_cve['affected_package']} vulnerable to {top_cve['cve_id']}",
        })
        if code in (200, 201):
            status = body.get("status", "unknown")
            ok(f"MPTE Verify: {code} — {top_cve['cve_id']} — status: {status} ({ms:.0f}ms)")
            results["mpte"]["verify"] = {"cve": top_cve["cve_id"], "status": status}
        else:
            warn(f"MPTE Verify: {code} — {ms:.0f}ms")

    # 2c. MPTE Comprehensive scan
    code, body, ms = api_call("POST", "/api/v1/mpte/scan/comprehensive", {
        "target": f"{v['org_id']}.example.com",
        "scan_type": "full",
        "include_cve_verification": True,
    }, timeout=120)
    if code in (200, 201):
        ok(f"MPTE Comprehensive: {code} — scan initiated ({ms:.0f}ms)")
        results["mpte"]["comprehensive"] = True
    else:
        warn(f"MPTE Comprehensive: {code} — {ms:.0f}ms")
    footer()

    return results


def phase_remediate(vname: str, v: Dict) -> Dict:
    """Phase 3: REMEDIATE — AutoFix generates patches."""
    results = {"fixes": []}

    # 3a. Generate AutoFix for top finding
    step("AutoFix — Generate Remediation", vname)
    narrate("AutoFix generates real code patches, not just 'fix this' advice")

    top_finding = v["sarif_findings"][0]
    code, body, ms = api_call("POST", "/api/v1/autofix/generate", {
        "finding_id": f"finding-{vname}-{top_finding['ruleId']}-{top_finding['line']}",
        "finding_type": top_finding["ruleId"],
        "code_context": v["vuln_code"][:500],
        "language": "python" if "import " in v["vuln_code"] else "csharp",
        "severity": "critical",
    })
    if code in (200, 201):
        fix = body.get("fix", body)
        fix_id = fix.get("fix_id", "unknown")
        confidence = fix.get("confidence_score", fix.get("confidence", 0))
        ok(f"AutoFix: {code} — fix_id={fix_id}, confidence={confidence:.1%} ({ms:.0f}ms)")
        results["fixes"].append({"fix_id": fix_id, "confidence": confidence, "finding": top_finding["ruleId"]})

        # 3b. Validate the fix
        step("AutoFix — Validate Fix", vname)
        vcode, vbody, vms = api_call("POST", "/api/v1/autofix/validate", {"fix_id": fix_id})
        if vcode in (200, 201):
            valid = vbody.get("valid", vbody.get("is_valid", True))
            ok(f"Validate: {vcode} — valid={valid} ({vms:.0f}ms)")
            results["fixes"][-1]["validated"] = valid
        else:
            warn(f"Validate: {vcode} — {vms:.0f}ms")
        footer()
    else:
        warn(f"AutoFix: {code} — {ms:.0f}ms")
    footer()

    # 3c. Bulk fix for remaining findings
    step(f"AutoFix — Bulk Remediation ({len(v['sarif_findings'])} findings)", vname)
    bulk_findings = []
    for f in v["sarif_findings"]:
        bulk_findings.append({
            "finding_id": f"finding-{vname}-{f['ruleId']}-{f['line']}",
            "finding_type": f["ruleId"],
            "code_context": v["vuln_code"][:300],
            "language": "python" if "import " in v["vuln_code"] else "csharp",
            "severity": "critical" if f["level"] == "error" else "medium",
        })
    code, body, ms = api_call("POST", "/api/v1/autofix/generate/bulk", {"findings": bulk_findings})
    if code in (200, 201):
        fixes = body.get("fixes", [])
        count = len(fixes) if isinstance(fixes, list) else 0
        ok(f"Bulk AutoFix: {code} — {count} fixes generated ({ms:.0f}ms)")
        results["bulk_fixes"] = count
    else:
        warn(f"Bulk AutoFix: {code} — {ms:.0f}ms")
    footer()

    return results


def phase_comply(vname: str, v: Dict) -> Dict:
    """Phase 4: COMPLY — Generate signed evidence bundles."""
    results = {"evidence": {}}

    # 4a. Evidence bundle
    step(f"Evidence Bundle — {v['compliance_framework']}", vname)
    narrate("Cryptographically signed evidence — auditors can verify independently")

    code, body, ms = api_call("POST", "/api/v1/evidence/bundles/generate", {
        "org_id": v["org_id"],
        "framework": v["compliance_framework"],
        "include_findings": True,
        "include_remediation": True,
    })
    if code in (200, 201):
        bundle_id = body.get("id", body.get("bundle_id", "unknown"))
        bundle_hash = body.get("hash", "none")
        sections = body.get("sections", [])
        ok(f"Evidence Bundle: {code} — id={bundle_id[:20]}... ({ms:.0f}ms)")
        detail(f"Hash: {bundle_hash[:40]}... | Sections: {len(sections)}")
        results["evidence"]["bundle_id"] = bundle_id
        results["evidence"]["hash"] = bundle_hash
    else:
        warn(f"Evidence Bundle: {code} — {ms:.0f}ms")
    footer()

    # 4b. Signed evidence export
    step("Signed Evidence Export — RSA-SHA256", vname)
    code, body, ms = api_call("POST", "/api/v1/evidence/export", {
        "framework": v["compliance_framework"],
        "sign": True,
        "org_id": v["org_id"],
    })
    if code in (200, 201):
        sig = body.get("signature", "")
        algo = body.get("signature_algorithm", "RSA-SHA256")
        body.get("content_hash", "")
        posture = body.get("posture", {})
        score = posture.get("overall_score", 0)
        compliance_pct = posture.get("compliance_percentage", 0)

        sig_preview = sig[:30] if isinstance(sig, str) else str(sig)[:30]
        ok(f"Signed Export: {code} — {algo} ({ms:.0f}ms)")
        detail(f"Signature: {sig_preview}...")
        detail(f"Score: {score}/100 | Compliance: {compliance_pct}%")
        results["evidence"]["signed"] = True
        results["evidence"]["algorithm"] = algo
        results["evidence"]["score"] = score
        results["evidence"]["compliance_pct"] = compliance_pct
    else:
        warn(f"Signed Export: {code} — {ms:.0f}ms")
    footer()

    # 4c. Brain evidence generation
    step("Brain Pipeline Evidence", vname)
    code, body, ms = api_call("POST", "/api/v1/brain/evidence/generate", {
        "org_id": v["org_id"],
        "framework": v["compliance_framework"],
    })
    if code in (200, 201):
        overall = body.get("overall_score", 0)
        status = body.get("overall_status", "unknown")
        ok(f"Brain Evidence: {code} — score={overall}, status={status} ({ms:.0f}ms)")
        results["evidence"]["brain_score"] = overall
        results["evidence"]["brain_status"] = status
    else:
        warn(f"Brain Evidence: {code} — {ms:.0f}ms")
    footer()

    return results


def phase_measure(vname: str, v: Dict) -> Dict:
    """Phase 5: MEASURE — Risk metrics and knowledge graph status."""
    results = {}

    # 5a. Knowledge graph status
    step("Knowledge Graph — Cross-Architecture View", vname)
    code, body, ms = api_call("GET", "/api/v1/brain/stats")
    if code in (200, 201):
        nodes = body.get("total_nodes", 0)
        edges = body.get("total_edges", 0)
        ok(f"Knowledge Graph: {nodes} nodes, {edges} edges ({ms:.0f}ms)")
        results["graph"] = {"nodes": nodes, "edges": edges}
    else:
        warn(f"Knowledge Graph: {code} — {ms:.0f}ms")
    footer()

    # 5b. Analytics dashboard
    step("Analytics Dashboard", vname)
    code, body, ms = api_call("GET", "/api/v1/analytics/dashboard/overview")
    if code in (200, 201):
        ok(f"Dashboard: {code} ({ms:.0f}ms)")
        results["dashboard"] = True
    else:
        warn(f"Dashboard: {code} — {ms:.0f}ms")
    footer()

    return results


# ═══════════════════════════════════════════════════════════════════════
# MAIN EXECUTION
# ═══════════════════════════════════════════════════════════════════════

def main():
    global STEP

    # ── Pre-flight ──
    print(f"\n{C.BOLD}{C.CYAN}{'═' * 66}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}  ALdeci CTEM+ Multi-Architecture Showcase{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}  5 Enterprise Verticals × Complete CTEM Lifecycle{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}{'═' * 66}{C.RESET}")
    print(f"  {C.DIM}API: {BASE_URL} | Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}{C.RESET}")
    print(f"  {C.DIM}Verticals: {'ALL 5' if not SINGLE_VERTICAL else SINGLE_VERTICAL.upper()}{C.RESET}")

    # Health check
    step("Pre-flight Health Check")
    code, body, ms = api_call("GET", "/api/v1/health")
    if code == 200:
        ok(f"API healthy: {code} ({ms:.0f}ms)")
    else:
        fail(f"API unhealthy: {code}")
        print(f"\n{C.RED}  Cannot proceed without healthy API. Exiting.{C.RESET}")
        sys.exit(1)
    footer()

    # ── Select verticals ──
    if SINGLE_VERTICAL:
        if SINGLE_VERTICAL in VERTICALS:
            selected = {SINGLE_VERTICAL: VERTICALS[SINGLE_VERTICAL]}
        else:
            print(f"\n{C.RED}  Unknown vertical: {SINGLE_VERTICAL}")
            print(f"  Available: {', '.join(VERTICALS.keys())}{C.RESET}")
            sys.exit(1)
    else:
        selected = VERTICALS

    # ── Process each vertical ──
    all_results = {}

    for vname, vdata in selected.items():
        STEP = 0
        vert_start = time.monotonic()

        vertical_banner(
            vdata["name"],
            vdata["cloud"],
            ", ".join(vdata["compliance"][:3]),
            vdata["icon"],
        )

        vert_results = {
            "vertical": vdata["name"],
            "cloud": vdata["cloud"],
            "compliance": vdata["compliance"],
        }

        # Phase 1: DISCOVER
        banner("PHASE 1: DISCOVER", "Ingest architecture data into ALdeci", "🔍")
        vert_results["discover"] = phase_discover(vname, vdata)

        # Phase 2: VALIDATE
        banner("PHASE 2: VALIDATE", "Brain Pipeline + MPTE verification", "🧠")
        vert_results["validate"] = phase_validate(vname, vdata)

        # Phase 3: REMEDIATE
        banner("PHASE 3: REMEDIATE", "AutoFix generates code patches", "🔧")
        vert_results["remediate"] = phase_remediate(vname, vdata)

        # Phase 4: COMPLY
        banner("PHASE 4: COMPLY", "Signed evidence bundles for auditors", "📋")
        vert_results["comply"] = phase_comply(vname, vdata)

        # Phase 5: MEASURE
        banner("PHASE 5: MEASURE", "Risk metrics and cross-architecture view", "📊")
        vert_results["measure"] = phase_measure(vname, vdata)

        vert_elapsed = time.monotonic() - vert_start
        vert_results["elapsed_seconds"] = round(vert_elapsed, 1)
        all_results[vname] = vert_results

        print(f"\n  {C.BOLD}{C.GREEN}✅ {vdata['icon']} {vdata['name']} complete — {vert_elapsed:.1f}s{C.RESET}")

    # ═══════════════════════════════════════════════════════════════════
    # FINAL SUMMARY
    # ═══════════════════════════════════════════════════════════════════

    total_elapsed = time.monotonic() - DEMO_START

    print(f"\n{'═' * 66}")
    print(f"{C.BOLD}{C.BG_GREEN}{C.WHITE}{'':>66}{C.RESET}")
    print(f"{C.BOLD}{C.BG_GREEN}{C.WHITE}  MULTI-ARCHITECTURE SHOWCASE — FINAL RESULTS                      {C.RESET}")
    print(f"{C.BOLD}{C.BG_GREEN}{C.WHITE}{'':>66}{C.RESET}")
    print(f"{'═' * 66}")

    print(f"\n  {C.BOLD}Verticals Processed:{C.RESET}")
    for vname, vr in all_results.items():
        v = VERTICALS[vname]
        vr.get("discover", {})
        validate = vr.get("validate", {})
        comply = vr.get("comply", {})
        brain = validate.get("brain", {})
        evidence = comply.get("evidence", {})

        noise = brain.get("noise_reduction", 0)
        score = evidence.get("score", 0)
        elapsed = vr.get("elapsed_seconds", 0)

        print(f"    {v['icon']} {v['name']:<40} {C.GREEN}✓{C.RESET} {elapsed:.1f}s")
        print(f"       Cloud: {v['cloud']:<25} Compliance: {', '.join(v['compliance'][:2])}")
        print(f"       Brain: {brain.get('steps', 0)}/12 steps, {noise:.0f}% noise reduction")
        print(f"       Evidence: score={score}, signed={'✓' if evidence.get('signed') else '✗'}")

    print(f"\n  {C.BOLD}Aggregate Metrics:{C.RESET}")
    total_findings = sum(
        sum(vr.get("discover", {}).get("scanner_findings", {}).values())
        for vr in all_results.values()
    )
    total_ingested = sum(
        sum(v for v in vr.get("discover", {}).get("ingested", {}).values() if isinstance(v, int))
        for vr in all_results.values()
    )
    total_fixes = sum(
        len(vr.get("remediate", {}).get("fixes", []))
        for vr in all_results.values()
    )

    print(f"    Scanner findings:     {total_findings}")
    print(f"    Artifacts ingested:   {total_ingested}")
    print(f"    AutoFix patches:      {total_fixes}")
    print(f"    Evidence bundles:     {len(all_results)}")

    print(f"\n  {C.BOLD}Results:{C.RESET}")
    print(f"    Steps: {TOTAL} | Passed: {C.GREEN}{PASS}{C.RESET} | Failed: {C.RED}{FAIL}{C.RESET}")
    print(f"    Duration: {total_elapsed:.1f}s")
    pct = (PASS / TOTAL * 100) if TOTAL > 0 else 0

    if pct >= 90:
        print(f"\n  {C.BOLD}{C.GREEN}🏆 SHOWCASE PASSED — {PASS}/{TOTAL} ({pct:.0f}%){C.RESET}")
        status = "PASSED"
    elif pct >= 70:
        print(f"\n  {C.BOLD}{C.YELLOW}⚠️ SHOWCASE PARTIAL — {PASS}/{TOTAL} ({pct:.0f}%){C.RESET}")
        status = "PARTIAL"
    else:
        print(f"\n  {C.BOLD}{C.RED}❌ SHOWCASE FAILED — {PASS}/{TOTAL} ({pct:.0f}%){C.RESET}")
        status = "FAILED"

    print(f"\n{C.DIM}  ALdeci CTEM+ — Not a scanner. A decision engine.{C.RESET}")
    print(f"{C.DIM}  5 architectures × 5 phases = Enterprise-grade proof.{C.RESET}\n")

    # Save results
    results_dir = os.path.join(os.path.dirname(__file__), "..", "data", "demo-results")
    os.makedirs(results_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    results_file = os.path.join(results_dir, f"multi-arch-showcase-{timestamp}.json")

    final = {
        "showcase": "ALdeci CTEM+ Multi-Architecture",
        "date": datetime.now(timezone.utc).isoformat(),
        "status": status,
        "steps_total": TOTAL,
        "steps_passed": PASS,
        "steps_failed": FAIL,
        "pass_rate": round(pct, 1),
        "duration_seconds": round(total_elapsed, 1),
        "verticals": all_results,
    }

    with open(results_file, "w") as f:
        json.dump(final, f, indent=2, default=str)
    print(f"  {C.DIM}Results saved: {results_file}{C.RESET}")

    sys.exit(0 if status == "PASSED" else 1)


if __name__ == "__main__":
    main()
