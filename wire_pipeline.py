#!/usr/bin/env python3
"""
ALdeci FixOps — End-to-End Pipeline Wiring Script
===================================================
Wires scan→ingest→brain→dashboard pipeline so dashboard shows real numbers.

Pipeline stages:
  1. SAST scan on multiple vulnerable code snippets
  2. Ingest each finding into Analytics DB (populates dashboard)
  3. Ingest each finding into Knowledge Brain (graph intelligence)
  4. Score each finding through the FAIL Engine (risk prioritisation)
  5. Create remediation tasks for high/critical findings
  6. Verify dashboard shows non-zero numbers

Usage:
  PYTHONPATH=/home/user/workspace/Fixops/suite-core:/home/user/workspace/Fixops/suite-attack \
      python3 wire_pipeline.py
"""
from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

# ── Ensure correct module paths ──────────────────────────────────────────────
import os
sys.path.insert(0, "/home/user/workspace/Fixops/suite-core")
sys.path.insert(0, "/home/user/workspace/Fixops/suite-attack")

# ── HTTP client ───────────────────────────────────────────────────────────────
import urllib.request
import urllib.error

API_BASE = "http://localhost:8000"
API_KEY = os.environ.get("FIXOPS_API_TOKEN")
if not API_KEY:
    sys.exit("FIXOPS_API_TOKEN environment variable required")
HEADERS = {
    "X-API-Key": API_KEY,
    "Content-Type": "application/json",
}


def api_post(path: str, body: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
    """POST to the API, return (status_code, response_body)."""
    url = f"{API_BASE}{path}"
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, headers=HEADERS, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body_bytes = e.read()
        try:
            return e.code, json.loads(body_bytes)
        except Exception:
            return e.code, {"error": body_bytes.decode(errors="replace")}


def api_get(path: str) -> Tuple[int, Dict[str, Any]]:
    """GET from the API, return (status_code, response_body)."""
    url = f"{API_BASE}{path}"
    req = urllib.request.Request(url, headers=HEADERS, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body_bytes = e.read()
        try:
            return e.code, json.loads(body_bytes)
        except Exception:
            return e.code, {"error": body_bytes.decode(errors="replace")}


# ── Vulnerable code samples ───────────────────────────────────────────────────
VULNERABLE_SNIPPETS = [
    # 1. SQL Injection (CWE-89)
    (
        "sqli_app.py",
        """
import sqlite3

def get_user(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchall()

def login(user, password):
    db = sqlite3.connect('app.db')
    cur = db.cursor()
    cur.execute("SELECT id FROM accounts WHERE user='" + user + "' AND pass='" + password + "'")
    return cur.fetchone()
""",
    ),
    # 2. XSS — reflected output without escaping (CWE-79)
    (
        "xss_app.py",
        """
from flask import Flask, request, make_response

app = Flask(__name__)

@app.route('/search')
def search():
    query = request.args.get('q', '')
    return make_response('<html><body>Results for: ' + query + '</body></html>')

@app.route('/greet')
def greet():
    name = request.args.get('name', 'Guest')
    html = f'<h1>Hello, {name}!</h1>'
    return html
""",
    ),
    # 3. Command Injection (CWE-78)
    (
        "cmd_injection.py",
        """
import subprocess
import os

def run_ping(host):
    result = subprocess.call("ping -c 1 " + host, shell=True)
    return result

def list_dir(path):
    output = os.popen("ls -la " + path).read()
    return output

def compress(filename):
    os.system("tar -czf output.tar.gz " + filename)
""",
    ),
    # 4. Path Traversal (CWE-22)
    (
        "path_traversal.py",
        """
import os

BASE_DIR = '/var/www/files'

def read_file(filename):
    path = os.path.join(BASE_DIR, filename)
    with open(path, 'r') as f:
        return f.read()

def download(request):
    fname = request.get('file')
    full_path = BASE_DIR + '/' + fname
    return open(full_path, 'rb').read()
""",
    ),
    # 5. Hardcoded Secrets (CWE-798)
    (
        "hardcoded_secrets.py",
        """
import boto3

AWS_ACCESS_KEY = 'AKIAIOSFODNN7EXAMPLE'
AWS_SECRET_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
DB_PASSWORD = 'supersecret123!'
API_SECRET = 'my-hardcoded-jwt-secret-key'
ADMIN_PASSWORD = 'admin123'

def connect_aws():
    client = boto3.client(
        's3',
        aws_access_key_id=AWS_ACCESS_KEY,
        aws_secret_access_key=AWS_SECRET_KEY
    )
    return client
""",
    ),
    # 6. Insecure Deserialization (CWE-502)
    (
        "deserialization.py",
        """
import pickle
import yaml
import marshal

def load_user_data(data_bytes):
    return pickle.loads(data_bytes)

def parse_config(yaml_str):
    return yaml.load(yaml_str)

def execute_code(code_bytes):
    code = marshal.loads(code_bytes)
    exec(code)
""",
    ),
    # 7. Weak Cryptography (CWE-326, CWE-327)
    (
        "weak_crypto.py",
        """
import hashlib
import random
import base64

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

def generate_token():
    return str(random.randint(100000, 999999))

def encrypt_data(data, key):
    from Crypto.Cipher import DES
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(data)

def weak_hash(value):
    return hashlib.sha1(value.encode()).hexdigest()
""",
    ),
    # 8. SSRF (CWE-918)
    (
        "ssrf_app.py",
        """
import requests
from flask import Flask, request

app = Flask(__name__)

@app.route('/proxy')
def proxy():
    url = request.args.get('url')
    resp = requests.get(url)
    return resp.text

@app.route('/fetch')
def fetch():
    target = request.form.get('endpoint')
    data = requests.post(target, json={'key': 'value'})
    return data.json()
""",
    ),
    # 9. Open Redirect (CWE-601)
    (
        "open_redirect.py",
        """
from flask import Flask, redirect, request

app = Flask(__name__)

@app.route('/login')
def login():
    next_url = request.args.get('next', '/')
    return redirect(next_url)

@app.route('/logout')
def logout():
    return_to = request.args.get('return_to')
    return redirect(return_to)
""",
    ),
    # 10. Insecure Random + Integer Overflow (CWE-338, CWE-190)
    (
        "insecure_random.py",
        """
import random
import math

def generate_session_id():
    return random.randint(0, 2**32)

def generate_csrf_token():
    return str(random.random())

def unsafe_cast(value):
    result = int(value) * 999999999 * 999999999
    return result

SECRET_KEY = random.random()
""",
    ),
    # 11. XXE Injection (CWE-611)
    (
        "xxe_app.py",
        """
import xml.etree.ElementTree as ET
from lxml import etree

def parse_xml(xml_string):
    tree = ET.fromstring(xml_string)
    return tree

def parse_with_lxml(xml_bytes):
    parser = etree.XMLParser(resolve_entities=True, load_dtd=True)
    root = etree.fromstring(xml_bytes, parser)
    return root
""",
    ),
    # 12. Missing Authentication (CWE-306)
    (
        "missing_auth.py",
        """
from flask import Flask, request, jsonify

app = Flask(__name__)
users_db = {}

@app.route('/admin/users', methods=['GET'])
def list_users():
    # No auth check!
    return jsonify(list(users_db.values()))

@app.route('/admin/delete/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    # No authentication or authorisation
    users_db.pop(user_id, None)
    return jsonify({'deleted': user_id})

@app.route('/internal/config')
def get_config():
    return jsonify({'db_host': 'prod-db', 'secret': 'abc123'})
""",
    ),
]


# ── Severity mapping ──────────────────────────────────────────────────────────

SEVERITY_CVSS = {
    "critical": 9.5,
    "high": 7.5,
    "medium": 5.0,
    "low": 2.5,
    "info": 1.0,
}

SEVERITY_EPSS = {
    "critical": 0.75,
    "high": 0.45,
    "medium": 0.20,
    "low": 0.05,
    "info": 0.01,
}


# ── Pipeline implementation ───────────────────────────────────────────────────

def stage_1_sast_scan() -> List[Dict[str, Any]]:
    """Run SAST scan on all vulnerable snippets and collect findings."""
    print("\n" + "="*60)
    print("STAGE 1: SAST Scan")
    print("="*60)

    from core.sast_engine import get_sast_engine

    engine = get_sast_engine()
    all_findings = []

    for filename, code in VULNERABLE_SNIPPETS:
        result = engine.scan_code(code, filename)
        print(f"  [{filename}] → {len(result.findings)} findings")
        for f in result.findings:
            sev_value = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            all_findings.append({
                "finding_id": f.finding_id,
                "title": f.title,
                "severity": sev_value,
                "cwe_id": f.cwe_id,
                "rule_id": f.rule_id,
                "file_path": filename,
                "line_number": f.line_number,
                "snippet": f.snippet[:200],
                "message": f.message,
                "fix_suggestion": f.fix_suggestion,
            })

    print(f"\n  Total SAST findings: {len(all_findings)}")
    return all_findings


def stage_2_ingest_analytics(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Ingest findings into the Analytics DB via POST /api/v1/analytics/findings.

    This is the key stage that populates the dashboard — the dashboard reads
    directly from the analytics DB findings table.
    """
    print("\n" + "="*60)
    print("STAGE 2: Ingest into Analytics DB (populates dashboard)")
    print("="*60)

    ingested = []
    ok_count = 0
    err_count = 0

    for f in findings:
        sev = f["severity"].lower()
        payload = {
            "org_id": "default",
            "application_id": "aldeci-test-app",
            "rule_id": f["rule_id"],
            "severity": sev,
            "status": "open",
            "title": f["title"],
            "description": f.get("message", f["title"]),
            "source": "aldeci-sast",
            "cvss_score": SEVERITY_CVSS.get(sev, 5.0),
            "epss_score": SEVERITY_EPSS.get(sev, 0.1),
            "exploitable": sev in ("critical", "high"),
            "metadata": {
                "cwe_id": f["cwe_id"],
                "file_path": f["file_path"],
                "line_number": f["line_number"],
                "snippet": f["snippet"],
                "fix_suggestion": f.get("fix_suggestion", ""),
                "original_finding_id": f["finding_id"],
            },
        }

        status, resp = api_post("/api/v1/analytics/findings", payload)
        if status in (200, 201):
            ok_count += 1
            ingested.append({**f, "analytics_id": resp.get("id"), "analytics_resp": resp})
        else:
            err_count += 1
            print(f"  ERROR [{f['title']}]: HTTP {status} — {resp}")

    print(f"  Ingested: {ok_count} OK, {err_count} errors")
    return ingested


def stage_3_ingest_brain(findings: List[Dict[str, Any]]) -> None:
    """Ingest findings into the Knowledge Brain directly via the Python module.

    The Brain router isn't mounted on port 8000, so we call the Python
    module directly (same process context is not applicable from a script,
    but we import the module standalone with the right PYTHONPATH).
    """
    print("\n" + "="*60)
    print("STAGE 3: Ingest into Knowledge Brain")
    print("="*60)

    try:
        from core.knowledge_brain import get_brain
        brain = get_brain()
        ok_count = 0

        for f in findings:
            try:
                brain.ingest_finding(
                    f["finding_id"],
                    org_id="default",
                    title=f["title"],
                    severity=f["severity"],
                    source="aldeci-sast",
                )
                ok_count += 1
            except Exception as e:
                print(f"  WARN brain ingest [{f['finding_id']}]: {e}")

        stats = brain.stats()
        print(f"  Brain nodes: {stats.get('total_nodes', 0)}, edges: {stats.get('total_edges', 0)}")
        print(f"  Ingested {ok_count}/{len(findings)} findings into Brain")

    except ImportError as e:
        print(f"  WARN: Knowledge Brain not available ({e}) — skipping")


def stage_4_fail_scoring(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Score each finding through the FAIL Engine via POST /api/v1/fail/score."""
    print("\n" + "="*60)
    print("STAGE 4: FAIL Engine Scoring")
    print("="*60)

    scored = []
    ok_count = 0

    # Use batch scoring for efficiency — chunk into batches of 50
    batch_size = 50
    batch_payloads = []
    for f in findings:
        sev = f["severity"].lower()
        batch_payloads.append({
            "finding_id": f["finding_id"],
            "title": f["title"],
            "cvss_score": SEVERITY_CVSS.get(sev, 5.0),
            "epss_score": SEVERITY_EPSS.get(sev, 0.1),
            "is_kev": False,
            "has_exploit": sev in ("critical", "high"),
            "exploit_maturity": "poc" if sev == "critical" else "unknown",
            "active_campaigns": 1 if sev == "critical" else 0,
            "asset_criticality": "high" if sev in ("critical", "high") else "medium",
            "data_classification": "confidential" if sev in ("critical", "high") else "internal",
            "is_reachable": True,
            "is_internet_facing": True,
            "has_compensating_controls": False,
            "affected_assets": 3,
            "affected_users": 100,
            "compliance_frameworks": ["owasp-top10", "pci-dss"],
            "metadata": {"cwe_id": f.get("cwe_id", ""), "source": "aldeci-sast"},
        })

    for i in range(0, len(batch_payloads), batch_size):
        batch = batch_payloads[i : i + batch_size]
        status, resp = api_post("/api/v1/fail/score/batch", {"findings": batch})
        if status == 200:
            ok_count += resp.get("total", 0)
            for result in resp.get("results", []):
                finding_id = result.get("finding_id")
                scored.append({
                    "finding_id": finding_id,
                    "fail_score": result.get("fail_score"),
                    "grade": result.get("grade"),
                    "recommended_action": result.get("recommended_action"),
                })
            if resp.get("errors"):
                print(f"  WARN: {len(resp['errors'])} batch errors in chunk {i//batch_size + 1}")
        else:
            print(f"  ERROR batch chunk {i//batch_size + 1}: HTTP {status} — {resp}")

    # Build fail score map by finding_id
    fail_map: Dict[str, Dict] = {s["finding_id"]: s for s in scored if s.get("finding_id")}

    # Distribute scores back to original findings list
    for f in findings:
        if f["finding_id"] in fail_map:
            f["fail_score"] = fail_map[f["finding_id"]]["fail_score"]
            f["fail_grade"] = fail_map[f["finding_id"]]["grade"]
        else:
            f["fail_score"] = None
            f["fail_grade"] = None

    print(f"  FAIL scored: {ok_count} findings")
    if scored:
        grades = {}
        for s in scored:
            g = s.get("grade", "?")
            grades[g] = grades.get(g, 0) + 1
        print(f"  Grade distribution: {grades}")
    return findings


def stage_5_remediation_tasks(findings: List[Dict[str, Any]]) -> List[str]:
    """Create remediation tasks for critical and high severity findings."""
    print("\n" + "="*60)
    print("STAGE 5: Create Remediation Tasks")
    print("="*60)

    task_ids = []
    ok_count = 0
    TARGET_SEVERITIES = {"critical", "high"}

    priority_findings = [f for f in findings if f["severity"].lower() in TARGET_SEVERITIES]
    # Deduplicate by title to avoid spam
    seen_titles = set()
    deduped = []
    for f in priority_findings:
        key = f"{f['title']}::{f['file_path']}"
        if key not in seen_titles:
            seen_titles.add(key)
            deduped.append(f)

    print(f"  Creating tasks for {len(deduped)} critical/high findings (deduped from {len(priority_findings)})")

    for f in deduped:
        cluster_id = f"cluster-sast-{f['rule_id'].lower().replace('-', '')}"
        payload = {
            "cluster_id": cluster_id,
            "org_id": "default",
            "app_id": "aldeci-test-app",
            "title": f"[SAST] {f['title']} in {f['file_path']}",
            "severity": f["severity"].lower(),
            "description": (
                f"Security finding detected by ALdeci SAST scanner.\n"
                f"Rule: {f['rule_id']} | CWE: {f.get('cwe_id', 'N/A')}\n"
                f"File: {f['file_path']} (line {f.get('line_number', '?')})\n"
                f"Message: {f.get('message', '')}\n"
                f"Fix: {f.get('fix_suggestion', '')}"
            ),
            "assignee": "security-team",
            "assignee_email": "security@aldeci.io",
            "metadata": {
                "finding_id": f["finding_id"],
                "cwe_id": f.get("cwe_id"),
                "file_path": f["file_path"],
                "line_number": f.get("line_number"),
                "fail_score": f.get("fail_score"),
                "fail_grade": f.get("fail_grade"),
                "source": "aldeci-sast",
            },
        }

        status, resp = api_post("/api/v1/remediation/tasks", payload)
        if status in (200, 201):
            task_id = resp.get("task_id") or resp.get("id", "")
            task_ids.append(task_id)
            ok_count += 1
        else:
            print(f"  ERROR task [{f['title']}]: HTTP {status} — {resp}")

    print(f"  Created: {ok_count} remediation tasks")
    return task_ids


def stage_6_verify_dashboard() -> Dict[str, Any]:
    """Verify the dashboard now shows non-zero numbers."""
    print("\n" + "="*60)
    print("STAGE 6: Verify Dashboard Overview")
    print("="*60)

    status, overview = api_get("/api/v1/analytics/dashboard/overview")
    if status != 200:
        print(f"  ERROR: HTTP {status} — {overview}")
        return {}

    print("  Dashboard overview:")
    for key, val in overview.items():
        print(f"    {key}: {val}")

    # Check non-zero
    numeric_keys = ["total_findings", "open_findings", "critical_findings", "recent_findings_30d"]
    nonzero = {k: overview.get(k, 0) for k in numeric_keys if overview.get(k, 0) > 0}
    zero = {k: overview.get(k, 0) for k in numeric_keys if overview.get(k, 0) == 0}

    if nonzero:
        print(f"\n  ✓ NON-ZERO metrics: {nonzero}")
    if zero:
        print(f"  ✗ Still zero: {zero}")

    return overview


def stage_7_analytics_stats() -> Dict[str, Any]:
    """Pull additional analytics to confirm data is populated."""
    print("\n" + "="*60)
    print("STAGE 7: Extended Analytics Verification")
    print("="*60)

    status, stats = api_get("/api/v1/analytics/stats")
    if status == 200:
        print(f"  Stats: total_findings={stats.get('total_findings')}, "
              f"total_decisions={stats.get('total_decisions')}")
        print(f"  Severity breakdown: {stats.get('severity_breakdown', {})}")

    status2, compliance = api_get("/api/v1/analytics/dashboard/compliance-status")
    if status2 == 200:
        print(f"  Compliance score: {compliance.get('compliance_score')}%")
        print(f"  Open findings: {compliance.get('open_findings')}")

    status3, coverage = api_get("/api/v1/analytics/coverage")
    if status3 == 200:
        print(f"  Coverage — scanned apps: {coverage.get('scanned_applications')}, "
              f"sources: {coverage.get('sources', {})}")

    status4, fail_stats = api_get("/api/v1/fail/stats")
    if status4 == 200:
        print(f"  FAIL stats — total scored: {fail_stats.get('total')}, "
              f"avg score: {fail_stats.get('average_score'):.2f}")

    return stats


# ── Main pipeline orchestration ───────────────────────────────────────────────

def run_pipeline() -> Dict[str, Any]:
    """Run the full end-to-end pipeline and return results summary."""
    start_time = time.time()
    print("\n" + "█"*60)
    print("  ALdeci FixOps — E2E Pipeline Wiring")
    print("  " + datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"))
    print("█"*60)

    # Stage 0: Check dashboard before
    print("\n[PRE] Dashboard state BEFORE pipeline:")
    _, before = api_get("/api/v1/analytics/dashboard/overview")
    print(f"  {before}")

    # Run all stages
    findings = stage_1_sast_scan()
    ingested = stage_2_ingest_analytics(findings)
    stage_3_ingest_brain(findings)
    scored_findings = stage_4_fail_scoring(findings)
    task_ids = stage_5_remediation_tasks(scored_findings)
    dashboard_after = stage_6_verify_dashboard()
    stage_7_analytics_stats()

    elapsed = time.time() - start_time

    # Build summary
    summary = {
        "pipeline_run_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "snippets_scanned": len(VULNERABLE_SNIPPETS),
        "total_sast_findings": len(findings),
        "analytics_ingested": len(ingested),
        "remediation_tasks_created": len(task_ids),
        "dashboard_before": before,
        "dashboard_after": dashboard_after,
        "severity_breakdown": {},
        "findings_sample": [],
    }

    # Severity breakdown
    for f in findings:
        sev = f["severity"]
        summary["severity_breakdown"][sev] = summary["severity_breakdown"].get(sev, 0) + 1

    # FAIL grade breakdown
    grade_counts: Dict[str, int] = {}
    for f in scored_findings:
        g = f.get("fail_grade") or "unscored"
        grade_counts[g] = grade_counts.get(g, 0) + 1
    summary["fail_grade_breakdown"] = grade_counts

    # Sample of findings for report
    for f in scored_findings[:10]:
        summary["findings_sample"].append({
            "finding_id": f["finding_id"],
            "title": f["title"],
            "severity": f["severity"],
            "cwe_id": f.get("cwe_id"),
            "file_path": f["file_path"],
            "fail_score": f.get("fail_score"),
            "fail_grade": f.get("fail_grade"),
        })

    print("\n" + "█"*60)
    print("  PIPELINE COMPLETE")
    print("█"*60)
    print(f"\n  Time elapsed: {elapsed:.1f}s")
    print(f"  Snippets scanned:         {summary['snippets_scanned']}")
    print(f"  SAST findings discovered: {summary['total_sast_findings']}")
    print(f"  Analytics DB ingested:    {summary['analytics_ingested']}")
    print(f"  Remediation tasks:        {summary['remediation_tasks_created']}")
    print(f"\n  Dashboard BEFORE: {before.get('total_findings')} findings")
    print(f"  Dashboard AFTER:  {dashboard_after.get('total_findings')} findings")

    success = dashboard_after.get("total_findings", 0) > 0
    print(f"\n  Pipeline {'SUCCEEDED' if success else 'FAILED'} — "
          f"dashboard {'shows real data' if success else 'still shows zeros'}")

    return summary


if __name__ == "__main__":
    summary = run_pipeline()

    # Write JSON results for reference
    out_path = "/home/user/workspace/results/pipeline_run_results.json"
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w") as fh:
        json.dump(summary, fh, indent=2, default=str)
    print(f"\n  Results written to: {out_path}")
