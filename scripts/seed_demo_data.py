#!/usr/bin/env python3
"""Seed realistic demo data into the ALDECI platform.

Populates Findings, Assets, Compliance scores, Incidents, Vendors, SLA records,
and Posture score history so the dashboard looks live on first boot.

Usage:
    python scripts/seed_demo_data.py           # seed everything
    python scripts/seed_demo_data.py --check   # dry-run, print counts only
    python scripts/seed_demo_data.py --wipe    # clear + re-seed

Idempotent: running twice does not create duplicates (uses deterministic IDs).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# ── Path setup ────────────────────────────────────────────────────────────────
ROOT = Path(__file__).resolve().parent.parent
for suite in [
    "suite-core",
    "suite-api",
    "suite-attack",
    "suite-feeds",
    "suite-evidence-risk",
    "suite-integrations",
    "archive/legacy",
    "archive/enterprise_legacy",
]:
    sys.path.insert(0, str(ROOT / suite))
os.chdir(ROOT)

NOW = datetime.now(timezone.utc)


def _ts(days_ago: int = 0, hours_ago: int = 0) -> datetime:
    return NOW - timedelta(days=days_ago, hours=hours_ago)


def _iso(days_ago: int = 0, hours_ago: int = 0) -> str:
    return _ts(days_ago, hours_ago).isoformat()


def _uid(prefix: str, seed: str) -> str:
    """Deterministic UUID from prefix + seed so re-runs are idempotent."""
    ns = uuid.UUID("a1de0000-0000-0000-0000-000000000000")
    return f"{prefix}-{uuid.uuid5(ns, seed).hex[:12]}"


def _make_grade(score: float) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


# ── 1. FINDINGS ───────────────────────────────────────────────────────────────

FINDINGS_DATA: List[Dict[str, Any]] = [
    # ── CRITICAL (5) ──────────────────────────────────────────────────────────
    {
        "title": "XZ Utils Backdoor — Supply Chain Compromise",
        "severity": "critical",
        "source": "Trivy",
        "cve_id": "CVE-2024-3094",
        "cvss_score": 10.0,
        "epss_score": 0.97,
        "exploitable": True,
        "rule_id": "TRIVY-SC-001",
        "application_id": "app-build-pipeline",
        "service_id": "svc-base-images",
        "status": "in_progress",
        "description": "xz-utils 5.6.0/5.6.1 contains a backdoor injected into the build system via malicious test files. Affects liblzma used by sshd on systemd-linked distros.",
        "metadata": {"cwe": "CWE-506", "path": "Dockerfile:12", "package": "xz-utils=5.6.1", "fix_version": "5.4.6"},
        "created_at_days": 5,
    },
    {
        "title": "PHP CGI Argument Injection (RCE)",
        "severity": "critical",
        "source": "Nuclei",
        "cve_id": "CVE-2024-4577",
        "cvss_score": 9.8,
        "epss_score": 0.95,
        "exploitable": True,
        "rule_id": "NUCLEI-RCE-002",
        "application_id": "app-web-api",
        "service_id": "svc-php-runtime",
        "status": "open",
        "description": "PHP CGI on Windows fails to properly handle character encoding conversions, allowing unauthenticated RCE via crafted URL parameters.",
        "metadata": {"cwe": "CWE-88", "endpoint": "/cgi-bin/php-cgi", "package": "php=8.1.8", "fix_version": "8.1.29"},
        "created_at_days": 3,
    },
    {
        "title": "Fortinet FortiOS Out-of-Bound Write (RCE)",
        "severity": "critical",
        "source": "Nuclei",
        "cve_id": "CVE-2024-21762",
        "cvss_score": 9.6,
        "epss_score": 0.93,
        "exploitable": True,
        "rule_id": "NUCLEI-FW-003",
        "application_id": "app-network-infra",
        "service_id": "svc-fortios-vpn",
        "status": "open",
        "description": "FortiOS SSL-VPN out-of-bound write vulnerability allows unauthenticated remote code execution via specially crafted HTTP requests.",
        "metadata": {"cwe": "CWE-787", "component": "FortiOS=7.4.2", "fix_version": "7.4.3"},
        "created_at_days": 7,
    },
    {
        "title": "OpenSSH regreSSHion Race Condition",
        "severity": "critical",
        "source": "Trivy",
        "cve_id": "CVE-2024-6387",
        "cvss_score": 8.1,
        "epss_score": 0.88,
        "exploitable": True,
        "rule_id": "TRIVY-SSH-004",
        "application_id": "app-compute-infra",
        "service_id": "svc-bastion-host",
        "status": "in_progress",
        "description": "Signal handler race condition in OpenSSH server allows unauthenticated RCE as root on glibc-based Linux systems. Regression of CVE-2006-5051.",
        "metadata": {"cwe": "CWE-362", "package": "openssh-server=9.2p1", "fix_version": "9.8p1"},
        "created_at_days": 12,
    },
    {
        "title": "Apache Log4Shell — JNDI Injection (RCE)",
        "severity": "critical",
        "source": "Snyk",
        "cve_id": "CVE-2021-44228",
        "cvss_score": 10.0,
        "epss_score": 0.98,
        "exploitable": True,
        "rule_id": "SNYK-JAVA-005",
        "application_id": "app-legacy-reporting",
        "service_id": "svc-log4j-runtime",
        "status": "open",
        "description": "Apache Log4j2 JNDI injection via user-controlled data allows unauthenticated RCE. Legacy reporting service still running log4j 2.14.1.",
        "metadata": {"cwe": "CWE-20", "package": "log4j-core=2.14.1", "fix_version": "2.17.1", "path": "pom.xml:34"},
        "created_at_days": 45,
    },
    # ── HIGH (12) ─────────────────────────────────────────────────────────────
    {
        "title": "SQL Injection in User Search Endpoint",
        "severity": "high",
        "source": "Semgrep",
        "cve_id": None,
        "cvss_score": 8.5,
        "epss_score": 0.12,
        "exploitable": False,
        "rule_id": "SEMGREP-SQL-006",
        "application_id": "app-user-service",
        "service_id": "svc-user-api",
        "status": "open",
        "description": "Unsanitized user input in /api/v2/users/search is passed directly to a raw SQL query. An authenticated attacker can exfiltrate the entire users table.",
        "metadata": {"cwe": "CWE-89", "path": "src/api/users/search.py:87", "confidence": "high"},
        "created_at_days": 8,
    },
    {
        "title": "Hardcoded AWS Credentials in Source Code",
        "severity": "high",
        "source": "Semgrep",
        "cve_id": None,
        "cvss_score": 8.0,
        "epss_score": 0.05,
        "exploitable": True,
        "rule_id": "SEMGREP-SECRETS-007",
        "application_id": "app-data-pipeline",
        "service_id": "svc-etl-worker",
        "status": "in_progress",
        "description": "AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY found hardcoded in etl/connectors/s3_uploader.py. Key has S3 full-access policy.",
        "metadata": {"cwe": "CWE-798", "path": "etl/connectors/s3_uploader.py:23", "key_prefix": "AKIA"},
        "created_at_days": 2,
    },
    {
        "title": "JWT Algorithm Confusion (RS256 to HS256)",
        "severity": "high",
        "source": "ZAP",
        "cve_id": "CVE-2022-21449",
        "cvss_score": 7.5,
        "epss_score": 0.08,
        "exploitable": True,
        "rule_id": "ZAP-AUTH-008",
        "application_id": "app-auth-service",
        "service_id": "svc-jwt-validator",
        "status": "open",
        "description": "JWT validator accepts HS256 tokens signed with the public key as an HMAC secret, allowing privilege escalation without a valid private key.",
        "metadata": {"cwe": "CWE-327", "endpoint": "/api/v1/token/verify", "path": "auth/jwt.py:112"},
        "created_at_days": 15,
    },
    {
        "title": "Prototype Pollution in lodash < 4.17.21",
        "severity": "high",
        "source": "Snyk",
        "cve_id": "CVE-2020-8203",
        "cvss_score": 7.4,
        "epss_score": 0.06,
        "exploitable": False,
        "rule_id": "SNYK-JS-009",
        "application_id": "app-dashboard-ui",
        "service_id": "svc-frontend-build",
        "status": "resolved",
        "description": "lodash 4.17.15 in the dashboard build chain is vulnerable to prototype pollution via _.merge, _.mergeWith, _.defaultsDeep.",
        "metadata": {"cwe": "CWE-1321", "package": "lodash=4.17.15", "fix_version": "4.17.21"},
        "created_at_days": 20,
    },
    {
        "title": "SSRF via Unchecked URL Parameter in Webhook Handler",
        "severity": "high",
        "source": "Semgrep",
        "cve_id": None,
        "cvss_score": 7.2,
        "epss_score": 0.03,
        "exploitable": False,
        "rule_id": "SEMGREP-SSRF-010",
        "application_id": "app-integration-hub",
        "service_id": "svc-webhook-proxy",
        "status": "open",
        "description": "The webhook delivery endpoint accepts an arbitrary callback_url without allowlist validation, enabling SSRF to internal metadata endpoints.",
        "metadata": {"cwe": "CWE-918", "path": "integrations/webhook_proxy.py:45", "endpoint": "/webhooks/deliver"},
        "created_at_days": 9,
    },
    {
        "title": "Insecure Deserialization in Celery Task Queue",
        "severity": "high",
        "source": "Bandit",
        "cve_id": None,
        "cvss_score": 8.8,
        "epss_score": 0.07,
        "exploitable": False,
        "rule_id": "BANDIT-DESER-011",
        "application_id": "app-worker-fleet",
        "service_id": "svc-celery-worker",
        "status": "in_progress",
        "description": "Celery workers configured with pickle serializer accept arbitrary objects from Redis broker. An attacker with broker access can achieve RCE.",
        "metadata": {"cwe": "CWE-502", "path": "workers/celery_config.py:18", "config": "CELERY_TASK_SERIALIZER=pickle"},
        "created_at_days": 6,
    },
    {
        "title": "Missing Rate Limiting on Password Reset Endpoint",
        "severity": "high",
        "source": "ZAP",
        "cve_id": None,
        "cvss_score": 7.1,
        "epss_score": 0.02,
        "exploitable": False,
        "rule_id": "ZAP-RATELIMIT-012",
        "application_id": "app-auth-service",
        "service_id": "svc-password-reset",
        "status": "open",
        "description": "The /auth/password-reset endpoint has no rate limiting, allowing brute-force token guessing. 10,000 tokens exhausted in 3 minutes during test.",
        "metadata": {"cwe": "CWE-307", "endpoint": "/auth/password-reset"},
        "created_at_days": 4,
    },
    {
        "title": "Container Running as Root with Privileged Flag",
        "severity": "high",
        "source": "Trivy",
        "cve_id": None,
        "cvss_score": 7.6,
        "epss_score": 0.04,
        "exploitable": False,
        "rule_id": "TRIVY-DOCKER-013",
        "application_id": "app-compute-infra",
        "service_id": "svc-data-processor",
        "status": "open",
        "description": "data-processor container runs as UID 0 (root) with --privileged flag. Container escape would grant full host access.",
        "metadata": {"cwe": "CWE-250", "image": "data-processor:latest", "path": "docker-compose.yml:44"},
        "created_at_days": 11,
    },
    {
        "title": "PyYAML Arbitrary Code Execution via yaml.load()",
        "severity": "high",
        "source": "Bandit",
        "cve_id": "CVE-2020-1747",
        "cvss_score": 9.8,
        "epss_score": 0.09,
        "exploitable": False,
        "rule_id": "BANDIT-YAML-014",
        "application_id": "app-config-service",
        "service_id": "svc-config-parser",
        "status": "resolved",
        "description": "yaml.load() called without Loader argument allows arbitrary Python code execution when parsing untrusted YAML input from API clients.",
        "metadata": {"cwe": "CWE-20", "path": "config/parser.py:56", "fix": "Use yaml.safe_load()"},
        "created_at_days": 30,
    },
    {
        "title": "Exposed Kubernetes Dashboard Without Authentication",
        "severity": "high",
        "source": "Nuclei",
        "cve_id": None,
        "cvss_score": 8.3,
        "epss_score": 0.11,
        "exploitable": True,
        "rule_id": "NUCLEI-K8S-015",
        "application_id": "app-compute-infra",
        "service_id": "svc-k8s-dashboard",
        "status": "in_progress",
        "description": "Kubernetes dashboard accessible at https://k8s-dashboard.internal.acme.com without authentication. Full cluster admin access available.",
        "metadata": {"cwe": "CWE-306", "url": "https://k8s-dashboard.internal.acme.com", "exposure": "internal"},
        "created_at_days": 1,
    },
    {
        "title": "Unencrypted PII in S3 Bucket (Customer Data)",
        "severity": "high",
        "source": "Trivy",
        "cve_id": None,
        "cvss_score": 7.9,
        "epss_score": 0.04,
        "exploitable": False,
        "rule_id": "TRIVY-CLOUD-016",
        "application_id": "app-data-lake",
        "service_id": "svc-s3-storage",
        "status": "open",
        "description": "S3 bucket acme-customer-data-prod has server-side encryption disabled. Bucket contains PII including names, emails, and payment tokens.",
        "metadata": {"cwe": "CWE-312", "resource": "s3://acme-customer-data-prod", "region": "us-east-1"},
        "created_at_days": 14,
    },
    {
        "title": "Path Traversal in File Download Endpoint",
        "severity": "high",
        "source": "Semgrep",
        "cve_id": None,
        "cvss_score": 7.8,
        "epss_score": 0.06,
        "exploitable": False,
        "rule_id": "SEMGREP-TRAV-016b",
        "application_id": "app-document-service",
        "service_id": "svc-file-download",
        "status": "open",
        "description": "File download handler constructs paths by joining user-supplied filename with base dir without sanitization. Allows reading arbitrary files from the server.",
        "metadata": {"cwe": "CWE-22", "path": "services/download.py:44", "endpoint": "/documents/download"},
        "created_at_days": 7,
    },
    # ── MEDIUM (18) ───────────────────────────────────────────────────────────
    {
        "title": "Missing Content Security Policy Header",
        "severity": "medium",
        "source": "ZAP",
        "cve_id": None,
        "cvss_score": 5.3,
        "epss_score": 0.01,
        "exploitable": False,
        "rule_id": "ZAP-HEADERS-017",
        "application_id": "app-dashboard-ui",
        "service_id": "svc-frontend-nginx",
        "status": "open",
        "description": "Content-Security-Policy header absent across all pages. Enables XSS injection and data exfiltration via script injection.",
        "metadata": {"cwe": "CWE-693", "endpoint": "/*"},
        "created_at_days": 20,
    },
    {
        "title": "Verbose Error Messages Expose Stack Traces",
        "severity": "medium",
        "source": "ZAP",
        "cve_id": None,
        "cvss_score": 5.0,
        "epss_score": 0.01,
        "exploitable": False,
        "rule_id": "ZAP-ERRDISC-018",
        "application_id": "app-web-api",
        "service_id": "svc-api-gateway",
        "status": "in_progress",
        "description": "500 error responses include full Python stack traces and internal file paths, aiding attacker reconnaissance.",
        "metadata": {"cwe": "CWE-209", "endpoint": "/api/v2/*", "environment": "production"},
        "created_at_days": 18,
    },
    {
        "title": "HTTP Strict Transport Security Not Enforced",
        "severity": "medium",
        "source": "ZAP",
        "cve_id": None,
        "cvss_score": 4.8,
        "epss_score": 0.01,
        "exploitable": False,
        "rule_id": "ZAP-HSTS-019",
        "application_id": "app-web-api",
        "service_id": "svc-api-gateway",
        "status": "open",
        "description": "HSTS header missing on API subdomain. Downgrade attacks possible on initial non-HTTPS connections.",
        "metadata": {"cwe": "CWE-319", "domain": "api.acme.com"},
        "created_at_days": 25,
    },
    {
        "title": "Outdated TLS 1.0/1.1 Supported on Load Balancer",
        "severity": "medium",
        "source": "Nuclei",
        "cve_id": "CVE-2011-3389",
        "cvss_score": 5.9,
        "epss_score": 0.02,
        "exploitable": False,
        "rule_id": "NUCLEI-TLS-020",
        "application_id": "app-network-infra",
        "service_id": "svc-load-balancer",
        "status": "open",
        "description": "ALB security policy supports TLS 1.0 and 1.1. These protocols are deprecated and vulnerable to BEAST and POODLE attacks.",
        "metadata": {"cwe": "CWE-326", "resource": "alb-prod-main", "region": "us-east-1"},
        "created_at_days": 35,
    },
    {
        "title": "Directory Listing Enabled on Static Asset Server",
        "severity": "medium",
        "source": "ZAP",
        "cve_id": None,
        "cvss_score": 5.1,
        "epss_score": 0.01,
        "exploitable": False,
        "rule_id": "ZAP-DIRLIST-021",
        "application_id": "app-dashboard-ui",
        "service_id": "svc-static-assets",
        "status": "resolved",
        "description": "Nginx autoindex enabled on /static/uploads/, exposing internal file listing including user-uploaded documents.",
        "metadata": {"cwe": "CWE-548", "path": "/static/uploads/", "server": "nginx/1.22.0"},
        "created_at_days": 40,
    },
    {
        "title": "Insecure Cookie Flags (Missing Secure + SameSite)",
        "severity": "medium",
        "source": "ZAP",
        "cve_id": None,
        "cvss_score": 4.3,
        "epss_score": 0.01,
        "exploitable": False,
        "rule_id": "ZAP-COOKIE-022",
        "application_id": "app-auth-service",
        "service_id": "svc-session-manager",
        "status": "in_progress",
        "description": "Session cookie 'aldeci_sess' lacks Secure and SameSite=Strict flags. Vulnerable to CSRF and interception over HTTP.",
        "metadata": {"cwe": "CWE-614", "cookie": "aldeci_sess", "endpoint": "/auth/login"},
        "created_at_days": 22,
    },
    {
        "title": "Weak Password Policy — No Complexity Requirement",
        "severity": "medium",
        "source": "Semgrep",
        "cve_id": None,
        "cvss_score": 5.5,
        "epss_score": 0.01,
        "exploitable": False,
        "rule_id": "SEMGREP-AUTH-023",
        "application_id": "app-auth-service",
        "service_id": "svc-user-management",
        "status": "open",
        "description": "Password validation function accepts 6-character passwords with no uppercase, digit, or symbol requirements.",
        "metadata": {"cwe": "CWE-521", "path": "auth/validators.py:33"},
        "created_at_days": 28,
    },
    {
        "title": "Redis Cache Exposed Without Authentication",
        "severity": "medium",
        "source": "Nuclei",
        "cve_id": "CVE-2022-0543",
        "cvss_score": 6.7,
        "epss_score": 0.15,
        "exploitable": False,
        "rule_id": "NUCLEI-REDIS-024",
        "application_id": "app-cache-infra",
        "service_id": "svc-redis-cache",
        "status": "open",
        "description": "Redis instance accessible on port 6379 without requirepass configuration. Exposes cached session tokens and API responses.",
        "metadata": {"cwe": "CWE-306", "host": "redis-cache.internal", "port": 6379},
        "created_at_days": 16,
    },
    {
        "title": "Dependency Confusion Attack Surface — Internal Package Names",
        "severity": "medium",
        "source": "Snyk",
        "cve_id": None,
        "cvss_score": 6.3,
        "epss_score": 0.03,
        "exploitable": False,
        "rule_id": "SNYK-DEPCNF-025",
        "application_id": "app-build-pipeline",
        "service_id": "svc-npm-registry",
        "status": "open",
        "description": "3 internal npm packages (acme-core, acme-auth, acme-utils) not scoped with @acme prefix. Dependency confusion via public registry injection possible.",
        "metadata": {"cwe": "CWE-427", "packages": ["acme-core", "acme-auth", "acme-utils"]},
        "created_at_days": 19,
    },
    {
        "title": "XML External Entity (XXE) in Report Parser",
        "severity": "medium",
        "source": "Semgrep",
        "cve_id": None,
        "cvss_score": 6.5,
        "epss_score": 0.02,
        "exploitable": False,
        "rule_id": "SEMGREP-XXE-026",
        "application_id": "app-reporting",
        "service_id": "svc-report-parser",
        "status": "open",
        "description": "XML parser in /reports/import does not disable external entity processing. Allows SSRF and local file disclosure via crafted SARIF/XML uploads.",
        "metadata": {"cwe": "CWE-611", "path": "reports/parser.py:78", "endpoint": "/reports/import"},
        "created_at_days": 13,
    },
    {
        "title": "Reflected XSS in Error Page Query Parameter",
        "severity": "medium",
        "source": "ZAP",
        "cve_id": None,
        "cvss_score": 6.1,
        "epss_score": 0.02,
        "exploitable": False,
        "rule_id": "ZAP-XSS-027",
        "application_id": "app-dashboard-ui",
        "service_id": "svc-error-handler",
        "status": "resolved",
        "description": "The ?message= query parameter on /error is reflected in the page without HTML encoding, enabling reflected XSS.",
        "metadata": {"cwe": "CWE-79", "endpoint": "/error?message=", "proof": "<script>alert(1)</script>"},
        "created_at_days": 50,
    },
    {
        "title": "EC2 Instance Metadata Service v1 (IMDSv1) Enabled",
        "severity": "medium",
        "source": "Trivy",
        "cve_id": None,
        "cvss_score": 5.8,
        "epss_score": 0.02,
        "exploitable": False,
        "rule_id": "TRIVY-CLOUD-028",
        "application_id": "app-compute-infra",
        "service_id": "svc-ec2-workers",
        "status": "in_progress",
        "description": "EC2 instances use IMDSv1 without requiring session tokens. SSRF vulnerabilities can reach metadata service to steal IAM role credentials.",
        "metadata": {"cwe": "CWE-284", "resource_type": "aws_instance", "count": 8},
        "created_at_days": 24,
    },
    {
        "title": "Unrestricted File Upload — MIME Type Not Validated",
        "severity": "medium",
        "source": "Semgrep",
        "cve_id": None,
        "cvss_score": 5.4,
        "epss_score": 0.02,
        "exploitable": False,
        "rule_id": "SEMGREP-UPLOAD-029",
        "application_id": "app-document-service",
        "service_id": "svc-file-upload",
        "status": "open",
        "description": "File upload endpoint checks extension only, not MIME type. Attacker can upload .php disguised as .jpg, enabling webshell deployment.",
        "metadata": {"cwe": "CWE-434", "path": "services/file_upload.py:91", "endpoint": "/documents/upload"},
        "created_at_days": 10,
    },
    {
        "title": "GraphQL Introspection Enabled in Production",
        "severity": "medium",
        "source": "Nuclei",
        "cve_id": None,
        "cvss_score": 4.7,
        "epss_score": 0.01,
        "exploitable": False,
        "rule_id": "NUCLEI-GRAPHQL-030",
        "application_id": "app-web-api",
        "service_id": "svc-graphql-api",
        "status": "open",
        "description": "GraphQL introspection endpoint active in production, exposing full schema including internal mutation types and deprecated admin fields.",
        "metadata": {"cwe": "CWE-200", "endpoint": "/graphql?query={__schema{types{name}}}"},
        "created_at_days": 17,
    },
    {
        "title": "Overly Permissive CORS Policy (Allow *)",
        "severity": "medium",
        "source": "ZAP",
        "cve_id": None,
        "cvss_score": 5.2,
        "epss_score": 0.01,
        "exploitable": False,
        "rule_id": "ZAP-CORS-031",
        "application_id": "app-web-api",
        "service_id": "svc-api-gateway",
        "status": "in_progress",
        "description": "API returns Access-Control-Allow-Origin: * on all endpoints including authenticated routes, enabling cross-origin data theft.",
        "metadata": {"cwe": "CWE-942", "header": "Access-Control-Allow-Origin: *"},
        "created_at_days": 26,
    },
    {
        "title": "Sensitive Data Logged to CloudWatch (PII Exposure)",
        "severity": "medium",
        "source": "Semgrep",
        "cve_id": None,
        "cvss_score": 5.0,
        "epss_score": 0.01,
        "exploitable": False,
        "rule_id": "SEMGREP-LOG-032",
        "application_id": "app-user-service",
        "service_id": "svc-audit-logger",
        "status": "open",
        "description": "User email and IP address logged at DEBUG level in request middleware. CloudWatch logs accessible to 47 IAM users.",
        "metadata": {"cwe": "CWE-532", "path": "middleware/request_logger.py:34"},
        "created_at_days": 21,
    },
    {
        "title": "Terraform State File Contains Plaintext Secrets",
        "severity": "medium",
        "source": "Semgrep",
        "cve_id": None,
        "cvss_score": 6.0,
        "epss_score": 0.03,
        "exploitable": False,
        "rule_id": "SEMGREP-IAC-033",
        "application_id": "app-infra-iac",
        "service_id": "svc-terraform-state",
        "status": "open",
        "description": "Terraform state in S3 contains plaintext RDS passwords and Stripe API keys. State bucket lacks encryption and has overly broad GetObject policy.",
        "metadata": {"cwe": "CWE-312", "path": "terraform/prod/terraform.tfstate"},
        "created_at_days": 33,
    },
    {
        "title": "npm Audit: word-wrap ReDoS in Transitive Dependencies",
        "severity": "medium",
        "source": "Snyk",
        "cve_id": "CVE-2023-26115",
        "cvss_score": 5.7,
        "epss_score": 0.03,
        "exploitable": False,
        "rule_id": "SNYK-JS-034",
        "application_id": "app-dashboard-ui",
        "service_id": "svc-frontend-build",
        "status": "in_progress",
        "description": "word-wrap < 1.2.4 (CVE-2023-26115) ReDoS vulnerability in 4 transitive dependencies. Affects build pipeline and SSR rendering.",
        "metadata": {"cwe": "CWE-1333", "package": "word-wrap=1.2.3", "fix_version": "1.2.4"},
        "created_at_days": 29,
    },
    # ── LOW (15) ──────────────────────────────────────────────────────────────
    {
        "title": "Server Version Disclosed in HTTP Response Headers",
        "severity": "low",
        "source": "ZAP",
        "cve_id": None,
        "cvss_score": 3.1,
        "epss_score": 0.01,
        "exploitable": False,
        "rule_id": "ZAP-INFO-035",
        "application_id": "app-web-api",
        "service_id": "svc-api-gateway",
        "status": "open",
        "description": "Server: nginx/1.22.0 header exposes exact software version, assisting vulnerability enumeration.",
        "metadata": {"cwe": "CWE-200", "header": "Server: nginx/1.22.0"},
        "created_at_days": 60,
    },
    {
        "title": "X-Frame-Options Header Missing (Clickjacking)",
        "severity": "low",
        "source": "ZAP",
        "cve_id": None,
        "cvss_score": 3.4,
        "epss_score": 0.01,
        "exploitable": False,
        "rule_id": "ZAP-FRAME-036",
        "application_id": "app-dashboard-ui",
        "service_id": "svc-frontend-nginx",
        "status": "open",
        "description": "X-Frame-Options header not set. UI pages can be embedded in iframes on attacker-controlled sites for clickjacking.",
        "metadata": {"cwe": "CWE-1021", "scope": "all pages"},
        "created_at_days": 45,
    },
    {
        "title": "Autocomplete Not Disabled on Password Fields",
        "severity": "low",
        "source": "ZAP",
        "cve_id": None,
        "cvss_score": 2.6,
        "epss_score": 0.01,
        "exploitable": False,
        "rule_id": "ZAP-AUTOFILL-037",
        "application_id": "app-auth-service",
        "service_id": "svc-frontend-nginx",
        "status": "resolved",
        "description": "Login form password field missing autocomplete=off attribute. Stored credentials at risk on shared devices.",
        "metadata": {"cwe": "CWE-525", "path": "templates/login.html:18"},
        "created_at_days": 55,
    },
    {
        "title": "Default Error Pages Expose Technology Stack",
        "severity": "low",
        "source": "ZAP",
        "cve_id": None,
        "cvss_score": 3.2,
        "epss_score": 0.01,
        "exploitable": False,
        "rule_id": "ZAP-ERRPAGE-038",
        "application_id": "app-web-api",
        "service_id": "svc-api-gateway",
        "status": "open",
        "description": "Default FastAPI/Starlette error pages returned on 404/422, exposing framework identity.",
        "metadata": {"cwe": "CWE-209", "endpoints": ["/nonexistent", "/api/v1/bad"]},
        "created_at_days": 70,
    },
    {
        "title": "Unused IAM Permissions on Lambda Execution Role",
        "severity": "low",
        "source": "Trivy",
        "cve_id": None,
        "cvss_score": 3.5,
        "epss_score": 0.01,
        "exploitable": False,
        "rule_id": "TRIVY-IAM-039",
        "application_id": "app-serverless",
        "service_id": "svc-lambda-functions",
        "status": "open",
        "description": "Lambda execution role has s3:* and ec2:* permissions. Actual usage requires only s3:GetObject on a single bucket.",
        "metadata": {"cwe": "CWE-250", "role": "arn:aws:iam::123456789:role/LambdaExecRole"},
        "created_at_days": 42,
    },
    {
        "title": "HTTP Methods Not Restricted (TRACE Enabled)",
        "severity": "low",
        "source": "ZAP",
        "cve_id": None,
        "cvss_score": 2.8,
        "epss_score": 0.01,
        "exploitable": False,
        "rule_id": "ZAP-METHODS-040",
        "application_id": "app-web-api",
        "service_id": "svc-api-gateway",
        "status": "open",
        "description": "TRACE and OPTIONS methods enabled on all API routes. TRACE can be used in cross-site tracing (XST) attacks.",
        "metadata": {"cwe": "CWE-16", "methods": ["TRACE", "OPTIONS"]},
        "created_at_days": 52,
    },
    {
        "title": "Missing Subresource Integrity on CDN Scripts",
        "severity": "low",
        "source": "ZAP",
        "cve_id": None,
        "cvss_score": 3.0,
        "epss_score": 0.01,
        "exploitable": False,
        "rule_id": "ZAP-SRI-041",
        "application_id": "app-dashboard-ui",
        "service_id": "svc-frontend-nginx",
        "status": "open",
        "description": "3 external scripts loaded from cdn.jsdelivr.net without integrity= attribute. CDN compromise could inject malicious JavaScript.",
        "metadata": {"cwe": "CWE-829", "count": 3, "cdn": "cdn.jsdelivr.net"},
        "created_at_days": 38,
    },
    {
        "title": "Debug Endpoint Reachable in Staging (/debug/vars)",
        "severity": "low",
        "source": "Nuclei",
        "cve_id": None,
        "cvss_score": 3.7,
        "epss_score": 0.01,
        "exploitable": False,
        "rule_id": "NUCLEI-DEBUG-042",
        "application_id": "app-web-api",
        "service_id": "svc-api-gateway",
        "status": "resolved",
        "description": "Go runtime /debug/vars endpoint exposed on staging, leaking memory stats, goroutine counts, and build info.",
        "metadata": {"cwe": "CWE-200", "endpoint": "/debug/vars", "environment": "staging"},
        "created_at_days": 62,
    },
    {
        "title": "Old SSH Host Keys Not Rotated (>180 days)",
        "severity": "low",
        "source": "Bandit",
        "cve_id": None,
        "cvss_score": 2.9,
        "epss_score": 0.01,
        "exploitable": False,
        "rule_id": "BANDIT-SSH-043",
        "application_id": "app-compute-infra",
        "service_id": "svc-bastion-host",
        "status": "open",
        "description": "Bastion host SSH RSA key unchanged for 287 days. Key rotation policy requires 180-day maximum.",
        "metadata": {"cwe": "CWE-324", "key_age_days": 287, "host": "bastion-01.acme.com"},
        "created_at_days": 58,
    },
    {
        "title": "RDS Automated Backups Retention Below 7 Days",
        "severity": "low",
        "source": "Trivy",
        "cve_id": None,
        "cvss_score": 3.3,
        "epss_score": 0.01,
        "exploitable": False,
        "rule_id": "TRIVY-RDS-044",
        "application_id": "app-data-infra",
        "service_id": "svc-rds-postgres",
        "status": "open",
        "description": "RDS instance db-prod-analytics has backup retention period of 3 days. SOC2 requires minimum 7-day retention.",
        "metadata": {"cwe": "CWE-665", "resource": "db-prod-analytics", "retention_days": 3},
        "created_at_days": 48,
    },
    {
        "title": "CloudTrail Not Enabled in Secondary Region (eu-west-1)",
        "severity": "low",
        "source": "Trivy",
        "cve_id": None,
        "cvss_score": 3.6,
        "epss_score": 0.01,
        "exploitable": False,
        "rule_id": "TRIVY-CLOUD-045",
        "application_id": "app-infra-iac",
        "service_id": "svc-cloudtrail",
        "status": "open",
        "description": "CloudTrail disabled in eu-west-1 region. API calls in that region produce no audit trail.",
        "metadata": {"cwe": "CWE-778", "region": "eu-west-1"},
        "created_at_days": 66,
    },
    {
        "title": "Stale Service Account Credentials (>90 days)",
        "severity": "low",
        "source": "Bandit",
        "cve_id": None,
        "cvss_score": 3.1,
        "epss_score": 0.01,
        "exploitable": False,
        "rule_id": "BANDIT-IAM-046",
        "application_id": "app-auth-service",
        "service_id": "svc-iam-governance",
        "status": "in_progress",
        "description": "4 GCP service account keys not rotated in 90+ days. Policy requires 90-day maximum key age.",
        "metadata": {"cwe": "CWE-324", "count": 4, "oldest_days": 127},
        "created_at_days": 35,
    },
    {
        "title": "Missing VPC Flow Logs on Production Subnets",
        "severity": "low",
        "source": "Trivy",
        "cve_id": None,
        "cvss_score": 2.7,
        "epss_score": 0.01,
        "exploitable": False,
        "rule_id": "TRIVY-CLOUD-047",
        "application_id": "app-network-infra",
        "service_id": "svc-vpc-config",
        "status": "open",
        "description": "3 production VPC subnets have flow logs disabled. Network forensics not possible for incidents in those subnets.",
        "metadata": {"cwe": "CWE-778", "subnets": ["subnet-a1b2c3d4", "subnet-e5f6g7h8", "subnet-i9j0k1l2"]},
        "created_at_days": 74,
    },
    {
        "title": "Public GitHub Actions Workflow Can Read Secrets",
        "severity": "low",
        "source": "Semgrep",
        "cve_id": None,
        "cvss_score": 3.9,
        "epss_score": 0.02,
        "exploitable": False,
        "rule_id": "SEMGREP-CI-048",
        "application_id": "app-build-pipeline",
        "service_id": "svc-github-actions",
        "status": "open",
        "description": "CI workflow .github/workflows/release.yml runs on pull_request_target with write permissions, allowing fork PRs to exfiltrate secrets.",
        "metadata": {"cwe": "CWE-269", "path": ".github/workflows/release.yml", "trigger": "pull_request_target"},
        "created_at_days": 44,
    },
    {
        "title": "pip install --extra-index-url Without Hash Pinning",
        "severity": "low",
        "source": "Bandit",
        "cve_id": None,
        "cvss_score": 3.0,
        "epss_score": 0.01,
        "exploitable": False,
        "rule_id": "BANDIT-SUPPLY-049",
        "application_id": "app-build-pipeline",
        "service_id": "svc-python-build",
        "status": "open",
        "description": "Dockerfile uses pip install --extra-index-url pointing to internal PyPI without hash pinning or --no-deps. Dependency substitution risk.",
        "metadata": {"cwe": "CWE-427", "path": "services/ml-worker/Dockerfile:22"},
        "created_at_days": 31,
    },
]


def seed_findings(dry_run: bool = False) -> int:
    from core.analytics_db import AnalyticsDB
    from core.analytics_models import Finding, FindingSeverity, FindingStatus

    db = AnalyticsDB()

    if dry_run:
        print(f"  [check] Would seed {len(FINDINGS_DATA)} findings")
        return len(FINDINGS_DATA)

    count = 0
    for d in FINDINGS_DATA:
        fid = _uid("finding", d["rule_id"] + d["title"][:20])

        if db.get_finding(fid) is not None:
            continue

        ts = _ts(d["created_at_days"])
        resolved_at = None
        if d["status"] == "resolved":
            resolved_at = _ts(max(0, d["created_at_days"] - 5))

        finding = Finding(
            id=fid,
            application_id=d.get("application_id"),
            service_id=d.get("service_id"),
            rule_id=d["rule_id"],
            severity=FindingSeverity(d["severity"]),
            status=FindingStatus(d["status"]),
            title=d["title"],
            description=d["description"],
            source=d["source"],
            cve_id=d.get("cve_id"),
            cvss_score=d.get("cvss_score"),
            epss_score=d.get("epss_score"),
            exploitable=d.get("exploitable", False),
            metadata=d.get("metadata", {}),
            created_at=ts,
            updated_at=ts,
            resolved_at=resolved_at,
        )
        db.create_finding(finding)
        count += 1

    skipped = len(FINDINGS_DATA) - count
    print(f"  [ok] Seeded {count} findings ({skipped} already existed)")
    return count


# ── 2. ASSETS ─────────────────────────────────────────────────────────────────

ASSETS_DATA: List[Dict[str, Any]] = [
    # Domains (5)
    {
        "name": "app.acme.com", "asset_type": "domain", "hostname": "app.acme.com",
        "owner_email": "platform@acme.com", "team": "platform-team",
        "criticality": "critical", "environment": "production", "lifecycle": "active",
        "tags": ["external", "customer-facing", "tier-0"],
        "metadata": {"exposure": "external", "dns_provider": "Route53"},
        "finding_count": 8, "risk_score": 7.8,
    },
    {
        "name": "api.acme.com", "asset_type": "domain", "hostname": "api.acme.com",
        "owner_email": "api-team@acme.com", "team": "api-team",
        "criticality": "critical", "environment": "production", "lifecycle": "active",
        "tags": ["external", "api-gateway", "tier-0"],
        "metadata": {"exposure": "external", "waf": "CloudFront+WAF"},
        "finding_count": 12, "risk_score": 8.2,
    },
    {
        "name": "admin.acme.com", "asset_type": "domain", "hostname": "admin.acme.com",
        "owner_email": "security@acme.com", "team": "security-team",
        "criticality": "critical", "environment": "production", "lifecycle": "active",
        "tags": ["internal", "admin-panel", "tier-0", "dmz"],
        "metadata": {"exposure": "dmz", "ip_allowlist": True, "mfa_enforced": True},
        "finding_count": 3, "risk_score": 5.1,
    },
    {
        "name": "staging.acme.com", "asset_type": "domain", "hostname": "staging.acme.com",
        "owner_email": "devops@acme.com", "team": "devops-team",
        "criticality": "medium", "environment": "staging", "lifecycle": "active",
        "tags": ["staging", "internet-facing"],
        "metadata": {"exposure": "external", "same_codebase_as_prod": True},
        "finding_count": 5, "risk_score": 4.9,
    },
    {
        "name": "cdn.acme.com", "asset_type": "domain", "hostname": "cdn.acme.com",
        "owner_email": "platform@acme.com", "team": "platform-team",
        "criticality": "high", "environment": "production", "lifecycle": "active",
        "tags": ["external", "cdn", "cloudfront"],
        "metadata": {"exposure": "external", "provider": "CloudFront"},
        "finding_count": 2, "risk_score": 3.4,
    },
    # IPs (5)
    {
        "name": "prod-bastion-01", "asset_type": "ip",
        "hostname": "bastion-01.acme.com", "ip_address": "34.201.45.178",
        "owner_email": "infra@acme.com", "team": "infra-team",
        "criticality": "critical", "environment": "production", "lifecycle": "active",
        "tags": ["bastion", "ssh", "external", "tier-0"],
        "metadata": {"exposure": "external", "ssh_port": 22, "mfa": True},
        "finding_count": 4, "risk_score": 6.5,
    },
    {
        "name": "prod-api-lb-01", "asset_type": "ip",
        "hostname": "alb-prod-main.us-east-1.elb.amazonaws.com", "ip_address": "54.176.33.210",
        "owner_email": "platform@acme.com", "team": "platform-team",
        "criticality": "critical", "environment": "production", "lifecycle": "active",
        "tags": ["load-balancer", "external", "tier-0"],
        "metadata": {"exposure": "external", "type": "ALB"},
        "finding_count": 6, "risk_score": 7.1,
    },
    {
        "name": "prod-redis-01", "asset_type": "ip",
        "hostname": "redis-cache.internal.acme.com", "ip_address": "10.0.12.45",
        "owner_email": "backend@acme.com", "team": "backend-team",
        "criticality": "high", "environment": "production", "lifecycle": "active",
        "tags": ["cache", "internal", "redis"],
        "metadata": {"exposure": "internal", "port": 6379, "auth_required": False},
        "finding_count": 1, "risk_score": 5.8,
    },
    {
        "name": "prod-rds-analytics", "asset_type": "ip",
        "hostname": "db-prod-analytics.us-east-1.rds.amazonaws.com", "ip_address": "10.0.8.22",
        "owner_email": "data@acme.com", "team": "data-team",
        "criticality": "critical", "environment": "production", "lifecycle": "active",
        "tags": ["database", "rds", "postgres", "internal", "pii"],
        "metadata": {"exposure": "internal", "engine": "postgres-15.3", "multi_az": True},
        "finding_count": 2, "risk_score": 4.2,
    },
    {
        "name": "staging-all-in-one", "asset_type": "ip",
        "hostname": "staging.internal.acme.com", "ip_address": "10.1.0.50",
        "owner_email": "devops@acme.com", "team": "devops-team",
        "criticality": "medium", "environment": "staging", "lifecycle": "active",
        "tags": ["staging", "internal", "multi-service"],
        "metadata": {"exposure": "internal", "services": ["api", "worker", "redis"]},
        "finding_count": 3, "risk_score": 3.9,
    },
    # Cloud Resources (5)
    {
        "name": "acme-customer-data-prod", "asset_type": "cloud_resource",
        "owner_email": "data@acme.com", "team": "data-team",
        "criticality": "critical", "environment": "production", "lifecycle": "active",
        "tags": ["s3", "pii", "external", "gdpr"],
        "metadata": {"exposure": "external", "type": "s3_bucket", "encryption": False},
        "finding_count": 2, "risk_score": 8.1,
    },
    {
        "name": "acme-k8s-prod-cluster", "asset_type": "cloud_resource",
        "owner_email": "platform@acme.com", "team": "platform-team",
        "criticality": "critical", "environment": "production", "lifecycle": "active",
        "tags": ["kubernetes", "eks", "tier-0"],
        "metadata": {"exposure": "internal", "type": "eks_cluster", "version": "1.29", "node_count": 12},
        "finding_count": 5, "risk_score": 7.4,
    },
    {
        "name": "acme-secrets-prod", "asset_type": "cloud_resource",
        "owner_email": "security@acme.com", "team": "security-team",
        "criticality": "critical", "environment": "production", "lifecycle": "active",
        "tags": ["secrets-manager", "aws", "credentials"],
        "metadata": {"exposure": "internal", "type": "aws_secrets_manager", "secret_count": 47},
        "finding_count": 0, "risk_score": 2.1,
    },
    {
        "name": "acme-terraform-state", "asset_type": "cloud_resource",
        "owner_email": "infra@acme.com", "team": "infra-team",
        "criticality": "high", "environment": "production", "lifecycle": "active",
        "tags": ["terraform", "iac", "s3"],
        "metadata": {"exposure": "internal", "type": "s3_bucket", "encryption": False, "plaintext_secrets": True},
        "finding_count": 1, "risk_score": 6.0,
    },
    {
        "name": "acme-cloudwatch-logs", "asset_type": "cloud_resource",
        "owner_email": "platform@acme.com", "team": "platform-team",
        "criticality": "medium", "environment": "production", "lifecycle": "active",
        "tags": ["cloudwatch", "logging", "observability"],
        "metadata": {"exposure": "internal", "type": "cloudwatch_log_group", "contains_pii": True},
        "finding_count": 1, "risk_score": 4.0,
    },
    # Containers (3)
    {
        "name": "data-processor:latest", "asset_type": "container",
        "owner_email": "data@acme.com", "team": "data-team",
        "criticality": "high", "environment": "production", "lifecycle": "active",
        "tags": ["container", "privileged", "docker", "risk"],
        "metadata": {"exposure": "internal", "image": "data-processor:latest", "runs_as_root": True, "privileged": True},
        "finding_count": 2, "risk_score": 7.6,
    },
    {
        "name": "payment-svc:v2.3.1", "asset_type": "container",
        "owner_email": "payments@acme.com", "team": "payments-team",
        "criticality": "critical", "environment": "production", "lifecycle": "active",
        "tags": ["container", "pci-dss", "tier-0", "payments"],
        "metadata": {"exposure": "internal", "image": "payment-svc:v2.3.1", "runs_as_root": False},
        "finding_count": 0, "risk_score": 2.8,
    },
    {
        "name": "ml-inference:v1.0.4", "asset_type": "container",
        "owner_email": "ai-team@acme.com", "team": "ai-team",
        "criticality": "medium", "environment": "production", "lifecycle": "active",
        "tags": ["container", "gpu", "ml", "internal"],
        "metadata": {"exposure": "internal", "image": "ml-inference:v1.0.4", "gpu_access": True},
        "finding_count": 1, "risk_score": 3.5,
    },
    # APIs (2)
    {
        "name": "Payment Gateway API v3", "asset_type": "api",
        "hostname": "payments-api.acme.com",
        "owner_email": "payments@acme.com", "team": "payments-team",
        "criticality": "critical", "environment": "production", "lifecycle": "active",
        "tags": ["api", "pci-dss", "stripe", "external", "tier-0"],
        "metadata": {"exposure": "external", "auth": "mTLS+API-Key", "rate_limited": True, "pci_scope": True},
        "finding_count": 0, "risk_score": 2.5,
    },
    {
        "name": "Internal Admin API", "asset_type": "api",
        "hostname": "admin-api.internal.acme.com",
        "owner_email": "platform@acme.com", "team": "platform-team",
        "criticality": "critical", "environment": "production", "lifecycle": "active",
        "tags": ["api", "internal", "admin", "dmz"],
        "metadata": {"exposure": "dmz", "auth": "API-Key", "rate_limited": False, "graphql": True},
        "finding_count": 3, "risk_score": 6.3,
    },
]


def seed_assets(dry_run: bool = False) -> int:
    from core.asset_inventory import AssetInventory, ManagedAsset, AssetCriticality, AssetLifecycle, Environment

    inv = AssetInventory()

    if dry_run:
        print(f"  [check] Would seed {len(ASSETS_DATA)} assets")
        return len(ASSETS_DATA)

    count = 0
    for d in ASSETS_DATA:
        aid = _uid("masset", d["name"])
        existing = inv._db.get_asset(aid)
        if existing is not None:
            continue

        asset = ManagedAsset(
            id=aid,
            name=d["name"],
            asset_type=d["asset_type"],
            hostname=d.get("hostname"),
            ip_address=d.get("ip_address"),
            owner_email=d.get("owner_email"),
            team=d.get("team"),
            criticality=AssetCriticality(d["criticality"]),
            environment=Environment(d["environment"]),
            lifecycle=AssetLifecycle(d["lifecycle"]),
            tags=d.get("tags", []),
            metadata=d.get("metadata", {}),
            first_discovered=_iso(90),
            last_seen=_iso(0),
            finding_count=d.get("finding_count", 0),
            risk_score=d.get("risk_score", 0.0),
            org_id="default",
        )
        inv.register_asset(asset)
        count += 1

    skipped = len(ASSETS_DATA) - count
    print(f"  [ok] Seeded {count} assets ({skipped} already existed)")
    return count


# ── 3. COMPLIANCE SCORES ──────────────────────────────────────────────────────

COMPLIANCE_FRAMEWORKS: Dict[str, float] = {
    "SOC2": 87.0,
    "PCI-DSS": 92.0,
    "HIPAA": 78.0,
    "ISO27001": 85.0,
    "NIST-CSF": 81.0,
    "CIS": 88.0,
    "GDPR": 75.0,
}


def seed_compliance(dry_run: bool = False) -> int:
    """Write a posture score snapshot with compliance framework scores embedded in
    the compliance_coverage component details. This is the canonical location the
    metrics_aggregator and dashboard query."""
    from core.posture_scoring import PostureScore, PostureComponent, _PostureDB

    db = _PostureDB("data/posture_scoring.db")

    if dry_run:
        print(f"  [check] Would seed {len(COMPLIANCE_FRAMEWORKS)} framework scores as posture snapshot")
        return len(COMPLIANCE_FRAMEWORKS)

    avg_score = sum(COMPLIANCE_FRAMEWORKS.values()) / len(COMPLIANCE_FRAMEWORKS)

    components = [
        PostureComponent(
            name="vulnerability_density", score=72.0, weight=0.25,
            details={"total": 50, "critical": 5, "high": 12, "medium": 18, "low": 15},
        ),
        PostureComponent(
            name="mttr_performance", score=68.0, weight=0.15,
            details={"avg_days_critical": 4.2, "avg_days_high": 9.7, "avg_days_medium": 21.3},
        ),
        PostureComponent(
            name="compliance_coverage", score=round(avg_score, 2), weight=0.20,
            details={"frameworks": COMPLIANCE_FRAMEWORKS, "avg": round(avg_score, 2)},
        ),
        PostureComponent(
            name="attack_surface_exposure", score=65.0, weight=0.15,
            details={"external_assets": 8, "exposed_critical": 3, "dmz_assets": 2},
        ),
        PostureComponent(
            name="finding_age", score=74.0, weight=0.10,
            details={"overdue_count": 7, "avg_age_days": 18.4, "oldest_days": 74},
        ),
        PostureComponent(
            name="scanner_coverage", score=82.0, weight=0.15,
            details={"scanners": ["Snyk", "Trivy", "Semgrep", "Bandit", "ZAP", "Nuclei"], "count": 6},
        ),
    ]

    overall = sum(c.score * c.weight for c in components)
    overall = round(max(0.0, min(100.0, overall)), 2)

    snapshot = PostureScore(
        id=_uid("ps", "compliance-seed-current"),
        org_id="default",
        overall_score=overall,
        grade=_make_grade(overall),
        components=components,
        calculated_at=_iso(0),
        period="current",
    )
    db.save(snapshot)
    print(
        f"  [ok] Seeded compliance snapshot: overall={overall} grade={snapshot.grade} "
        f"frameworks={list(COMPLIANCE_FRAMEWORKS.keys())}"
    )
    return len(COMPLIANCE_FRAMEWORKS)


# ── 4. INCIDENTS ──────────────────────────────────────────────────────────────

INCIDENTS_DATA: List[Dict[str, Any]] = [
    # Active incidents
    {
        "title": "Customer PII Exfiltration via S3 Bucket Misconfiguration",
        "type": "data_breach",
        "severity": "sev1",
        "status": "containing",
        "reported_by": "aws-guardduty-alert",
        "lead_responder": "sarah.chen@acme.com",
        "affected_assets": ["acme-customer-data-prod", "prod-rds-analytics"],
        "days_ago": 1,
    },
    {
        "title": "Developer API Keys Leaked in Public GitHub Repository",
        "type": "credential_compromise",
        "severity": "sev2",
        "status": "triaging",
        "reported_by": "github-secret-scanning",
        "lead_responder": "marcus.okafor@acme.com",
        "affected_assets": ["app-build-pipeline"],
        "days_ago": 0,
    },
    {
        "title": "Targeted Spear-Phishing Campaign Against Engineering Team",
        "type": "phishing",
        "severity": "sev3",
        "status": "recovering",
        "reported_by": "it-helpdesk",
        "lead_responder": "priya.sharma@acme.com",
        "affected_assets": [],
        "days_ago": 5,
    },
    # Resolved incidents
    {
        "title": "DDoS Attack on API Gateway — 40Gbps Volumetric Flood",
        "type": "ddos",
        "severity": "sev2",
        "status": "closed",
        "reported_by": "pagerduty-alert",
        "lead_responder": "devops-oncall@acme.com",
        "affected_assets": ["api.acme.com", "prod-api-lb-01"],
        "days_ago": 14,
    },
    {
        "title": "Malware Detected on Marketing Laptop via CrowdStrike EDR",
        "type": "malware",
        "severity": "sev3",
        "status": "closed",
        "reported_by": "crowdstrike-edr",
        "lead_responder": "alex.rivera@acme.com",
        "affected_assets": [],
        "days_ago": 21,
    },
]


def seed_incidents(dry_run: bool = False) -> int:
    from core.incident_response import (
        IncidentResponseManager,
        IncidentType,
        IncidentSeverity,
        IncidentStatus,
    )

    mgr = IncidentResponseManager()

    if dry_run:
        print(f"  [check] Would seed {len(INCIDENTS_DATA)} incidents")
        return len(INCIDENTS_DATA)

    count = 0
    for d in INCIDENTS_DATA:
        iid = _uid("inc", d["title"][:30])

        with mgr._conn() as conn:
            existing = conn.execute("SELECT id FROM incidents WHERE id = ?", (iid,)).fetchone()
        if existing:
            continue

        incident = mgr.create_incident(
            title=d["title"],
            type=IncidentType(d["type"]),
            severity=IncidentSeverity(d["severity"]),
            reported_by=d["reported_by"],
            org_id="default",
        )
        # Patch to deterministic ID and correct status/timing
        incident.id = iid
        incident.lead_responder = d.get("lead_responder")
        incident.affected_assets = d.get("affected_assets", [])
        incident.detected_at = _ts(d["days_ago"])
        incident.status = IncidentStatus(d["status"])
        if d["status"] == "closed":
            incident.closed_at = _ts(max(0, d["days_ago"] - 2))

        mgr._save_incident(incident)
        count += 1

    skipped = len(INCIDENTS_DATA) - count
    print(f"  [ok] Seeded {count} incidents ({skipped} already existed)")
    return count


# ── 5. VENDORS ────────────────────────────────────────────────────────────────

VENDORS_DATA: List[Dict[str, Any]] = [
    {
        "name": "Stripe", "domain": "stripe.com",
        "description": "Payment processing and billing infrastructure. PCI-DSS Level 1 certified.",
        "contact_email": "security@stripe.com", "tier": "minimal",
        "tags": ["payments", "pci-dss", "critical-vendor"], "sbom_count": 0,
        "factors": {"ssl_score": 98.0, "headers_score": 95.0, "dns_score": 97.0, "vulnerability_score": 96.0, "data_handling_score": 98.0},
    },
    {
        "name": "Datadog", "domain": "datadoghq.com",
        "description": "Observability, APM, and SIEM platform. Handles log data including partial PII.",
        "contact_email": "security@datadoghq.com", "tier": "low",
        "tags": ["monitoring", "apm", "siem", "data-processor"], "sbom_count": 3,
        "factors": {"ssl_score": 94.0, "headers_score": 91.0, "dns_score": 93.0, "vulnerability_score": 89.0, "data_handling_score": 86.0},
    },
    {
        "name": "GitHub", "domain": "github.com",
        "description": "Source code hosting, CI/CD, and secret scanning. All source code stored here.",
        "contact_email": "security@github.com", "tier": "low",
        "tags": ["scm", "cicd", "source-code"], "sbom_count": 0,
        "factors": {"ssl_score": 96.0, "headers_score": 93.0, "dns_score": 95.0, "vulnerability_score": 92.0, "data_handling_score": 90.0},
    },
    {
        "name": "Supabase Cloud", "domain": "supabase.com",
        "description": "Managed PostgreSQL and auth for staging environments. Contains test PII datasets.",
        "contact_email": "security@supabase.io", "tier": "medium",
        "tags": ["database", "managed", "staging"], "sbom_count": 1,
        "factors": {"ssl_score": 87.0, "headers_score": 82.0, "dns_score": 85.0, "vulnerability_score": 79.0, "data_handling_score": 77.0},
    },
    {
        "name": "OpenAI", "domain": "openai.com",
        "description": "LLM API for AI features. User queries sent for inference — no PII per contract.",
        "contact_email": "security@openai.com", "tier": "medium",
        "tags": ["ai", "llm", "data-processor", "new"], "sbom_count": 0,
        "factors": {"ssl_score": 91.0, "headers_score": 85.0, "dns_score": 88.0, "vulnerability_score": 72.0, "data_handling_score": 68.0},
    },
]


def seed_vendors(dry_run: bool = False) -> int:
    from core.vendor_scorecard import VendorScorecard, Vendor, VendorRiskTier

    sc = VendorScorecard()

    if dry_run:
        print(f"  [check] Would seed {len(VENDORS_DATA)} vendors with assessments")
        return len(VENDORS_DATA)

    count = 0
    for d in VENDORS_DATA:
        vid = _uid("vendor", d["domain"])
        try:
            sc.get_vendor(vid)
            continue  # already exists
        except KeyError:
            pass

        vendor = Vendor(
            id=vid,
            name=d["name"],
            domain=d["domain"],
            description=d["description"],
            contact_email=d["contact_email"],
            tier=VendorRiskTier(d["tier"]),
            tags=d["tags"],
            sbom_component_count=d["sbom_count"],
            org_id="default",
            created_at=_iso(60),
        )
        sc.add_vendor(vendor)
        sc.assess_vendor(
            vendor_id=vid,
            factors=d["factors"],
            assessor="security-team",
            notes=f"Annual third-party assessment — {d['name']}",
            validity_days=365,
        )
        count += 1

    skipped = len(VENDORS_DATA) - count
    print(f"  [ok] Seeded {count} vendors ({skipped} already existed)")
    return count


# ── 6. SLA RECORDS ────────────────────────────────────────────────────────────

def seed_sla_records(dry_run: bool = False) -> int:
    """Create SLA tracking record for every seeded finding."""
    from core.sla_manager import SLAManager, SLAPolicy

    mgr = SLAManager(db_path="data/sla.db")

    # Ensure a default org policy exists
    if mgr.get_policy("default") is None:
        policy = SLAPolicy(
            org_id="default",
            name="Default Security SLA Policy",
            severity_deadlines={"critical": 24, "high": 72, "medium": 336, "low": 720},
            escalation_chain=["soc@acme.com", "ciso@acme.com"],
            grace_period_hours=0,
        )
        mgr.create_policy(policy)

    if dry_run:
        print(f"  [check] Would seed SLA records for {len(FINDINGS_DATA)} findings")
        return len(FINDINGS_DATA)

    count = 0
    for d in FINDINGS_DATA:
        fid = _uid("finding", d["rule_id"] + d["title"][:20])
        discovered_at = _ts(d["created_at_days"])
        mgr.track_finding(
            finding_id=fid,
            severity=d["severity"],
            discovered_at=discovered_at,
            org_id="default",
        )
        count += 1

    print(f"  [ok] Tracked {count} findings in SLA engine")
    return count


# ── 7. POSTURE SCORE HISTORY (30 days) ────────────────────────────────────────

def seed_posture_history(dry_run: bool = False) -> int:
    """Insert 30 daily posture scores to render a trend line on the CISO dashboard."""
    import random as _rng
    from core.posture_scoring import PostureScore, PostureComponent, _PostureDB

    _rng.seed(42)  # deterministic

    db = _PostureDB("data/posture_scoring.db")
    DAYS = 30

    if dry_run:
        print(f"  [check] Would seed {DAYS} days of posture score history")
        return DAYS

    existing = db.get_history("default", DAYS + 1)
    existing_dates = {s.calculated_at[:10] for s in existing}

    count = 0
    for day in range(DAYS, 0, -1):
        ts = _ts(day)
        date_str = ts.date().isoformat()
        if date_str in existing_dates:
            continue

        # Gradual improvement trend: ~62 at day-30, ~74 today, with noise
        progress = (DAYS - day) / DAYS  # 0.0 → 1.0
        base = 62.0 + progress * 12.0 + _rng.uniform(-2.0, 2.0)
        base = max(55.0, min(80.0, base))

        def _c(offset: float, noise: float = 3.0) -> float:
            return round(max(0.0, min(100.0, base + offset + _rng.uniform(-noise, noise))), 2)

        components = [
            PostureComponent(name="vulnerability_density", score=_c(-5), weight=0.25, details={}),
            PostureComponent(name="mttr_performance", score=_c(-2), weight=0.15, details={}),
            PostureComponent(name="compliance_coverage", score=_c(+8, 2.0), weight=0.20, details={}),
            PostureComponent(name="attack_surface_exposure", score=_c(-8), weight=0.15, details={}),
            PostureComponent(name="finding_age", score=_c(+2), weight=0.10, details={}),
            PostureComponent(name="scanner_coverage", score=_c(+5, 2.0), weight=0.15, details={}),
        ]

        overall = round(max(0.0, min(100.0, sum(c.score * c.weight for c in components))), 2)

        score = PostureScore(
            id=_uid("ps", f"history-{date_str}"),
            org_id="default",
            overall_score=overall,
            grade=_make_grade(overall),
            components=components,
            calculated_at=ts.isoformat(),
            period="daily",
        )
        db.save(score)
        count += 1

    skipped = DAYS - count
    print(f"  [ok] Seeded {count} posture history points ({skipped} already existed)")
    return count


# ── MAIN ──────────────────────────────────────────────────────────────────────

def _dry_run_report() -> None:
    print("\n=== ALDECI Demo Seed — DRY RUN (no data written) ===\n")
    seed_findings(dry_run=True)
    seed_assets(dry_run=True)
    seed_compliance(dry_run=True)
    seed_incidents(dry_run=True)
    seed_vendors(dry_run=True)
    seed_sla_records(dry_run=True)
    seed_posture_history(dry_run=True)
    print("\n[done] Dry run complete.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed ALDECI demo data")
    parser.add_argument("--check", action="store_true", help="Dry run — print what would be seeded, no writes")
    parser.add_argument("--wipe", action="store_true", help="Delete existing data DBs then re-seed")
    args = parser.parse_args()

    if args.check:
        _dry_run_report()
        return

    if args.wipe:
        wipe_targets = [
            "data/analytics.db",
            "data/posture_scoring.db",
            "data/sla.db",
            "data/incident_response.db",
            "data/vendor_scorecard.db",
            ".fixops_data/asset_inventory.db",
        ]
        for db_path in wipe_targets:
            p = Path(db_path)
            if p.exists():
                p.unlink()
                print(f"  [wipe] Removed {db_path}")

    print("\n=== ALDECI Demo Data Seed ===\n")

    print("1/7  Seeding findings (50 across 6 scanners)...")
    seed_findings()

    print("2/7  Seeding assets (20 across domains/IPs/cloud/containers/APIs)...")
    seed_assets()

    print("3/7  Seeding compliance framework scores (7 frameworks)...")
    seed_compliance()

    print("4/7  Seeding incidents (3 active, 2 resolved)...")
    seed_incidents()

    print("5/7  Seeding vendors with security assessments (5 vendors)...")
    seed_vendors()

    print("6/7  Seeding SLA records for all findings...")
    seed_sla_records()

    print("7/7  Seeding 30-day posture score history...")
    seed_posture_history()

    print("\n[done] Demo data seeded successfully.")
    print("       API:       uvicorn main:app --reload --port 8000  (from suite-api/)")
    print("       Dashboard: cd suite-ui/aldeci-ui-new && npm run dev")


if __name__ == "__main__":
    main()
