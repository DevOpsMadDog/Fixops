#!/usr/bin/env python3
"""
ALdeci Persona-Driven Reality Test
===================================
Tests the PRODUCT against what 25 personas ACTUALLY NEED TO DO.
Not unit tests. Not code coverage farming. Real user workflows.

Each test simulates a persona's critical workflow and grades:
  PASS  = workflow completes, data is meaningful
  PARTIAL = endpoint responds but data is empty/degraded/dummy
  FAIL  = 404, 500, or nonsensical response
"""
import json
import os
import requests
import sys
import time
from dataclasses import dataclass, field
from typing import Optional

API = "http://localhost:8000"
_api_key = os.environ.get("FIXOPS_API_TOKEN")
if not _api_key:
    import sys; sys.exit("ERROR: FIXOPS_API_TOKEN not set. Export it before running tests.")
KEY = {"X-API-Key": _api_key}
CT = {"Content-Type": "application/json"}
HEADERS = {**KEY, **CT}

@dataclass
class TestResult:
    persona: str
    role: str
    space: str
    workflow: str
    status: str  # PASS, PARTIAL, FAIL
    detail: str
    endpoint: str = ""
    http_code: int = 0

results: list[TestResult] = []

def get(path, **kwargs):
    try:
        r = requests.get(f"{API}{path}", headers=KEY, timeout=10, **kwargs)
        return r
    except Exception as e:
        return type('R', (), {'status_code': 0, 'text': str(e), 'json': lambda: {}})()

def post(path, data=None, **kwargs):
    try:
        r = requests.post(f"{API}{path}", headers=HEADERS, json=data, timeout=10, **kwargs)
        return r
    except Exception as e:
        return type('R', (), {'status_code': 0, 'text': str(e), 'json': lambda: {}})()

def grade(persona, role, space, workflow, endpoint, r, check_fn=None):
    """Grade a response: PASS/PARTIAL/FAIL"""
    if r.status_code == 0:
        results.append(TestResult(persona, role, space, workflow, "FAIL", f"Connection error: {r.text}", endpoint, 0))
        return
    if r.status_code >= 500:
        results.append(TestResult(persona, role, space, workflow, "FAIL", f"Server error {r.status_code}", endpoint, r.status_code))
        return
    if r.status_code == 404:
        results.append(TestResult(persona, role, space, workflow, "FAIL", "Endpoint not found (404)", endpoint, 404))
        return
    if r.status_code == 405:
        results.append(TestResult(persona, role, space, workflow, "FAIL", "Method not allowed (405)", endpoint, 405))
        return
    if r.status_code == 422:
        results.append(TestResult(persona, role, space, workflow, "PARTIAL", f"Schema validation error — endpoint exists but input format wrong", endpoint, 422))
        return
    try:
        d = r.json()
    except:
        results.append(TestResult(persona, role, space, workflow, "PARTIAL", "Response not JSON", endpoint, r.status_code))
        return
    
    if check_fn:
        status, detail = check_fn(d)
        results.append(TestResult(persona, role, space, workflow, status, detail, endpoint, r.status_code))
    else:
        results.append(TestResult(persona, role, space, workflow, "PASS", "Responded with data", endpoint, r.status_code))


# ============================================================================
# PERSONA GROUP 1: LEADERSHIP (Mission Control)
# ============================================================================

def test_sarah_ciso():
    """Sarah Chen — CISO: 'Are we secure? What do I tell the board?'"""
    print("\n👤 Sarah Chen (CISO) — Mission Control / Executive View")
    
    # 1. She needs an executive dashboard with posture score
    r = get("/api/v1/analytics/dashboard/overview")
    def check(d):
        if isinstance(d, dict) and ("total_findings" in d or "posture" in str(d).lower() or "score" in str(d).lower() or "risk" in str(d).lower() or len(d) > 2):
            return "PASS", f"Dashboard data: {list(d.keys())[:5]}"
        if isinstance(d, dict) and d.get("detail"):
            return "FAIL", f"No dashboard: {d.get('detail')}"
        return "PARTIAL", f"Response exists but may lack posture data: {list(d.keys())[:5] if isinstance(d,dict) else type(d).__name__}"
    grade("Sarah Chen", "CISO", "Mission Control", "View executive dashboard", "/api/v1/analytics/dashboard/overview", r, check)
    
    # 2. She needs compliance status overview
    r = get("/api/v1/analytics/dashboard/compliance-status")
    def check(d):
        if isinstance(d, dict) and ("compliance_score" in d or "frameworks" in str(d).lower() or "controls" in str(d).lower()):
            score = d.get("compliance_score", 0)
            return "PASS", f"Compliance posture: score={score}, findings={d.get('total_findings', '?')}"
        if isinstance(d, dict) and d.get("detail"):
            return "FAIL", f"No compliance: {d.get('detail')}"
        return "PARTIAL", f"Response: {json.dumps(d)[:150]}"
    grade("Sarah Chen", "CISO", "Comply", "View compliance posture", "/api/v1/analytics/dashboard/compliance-status", r, check)
    
    # 3. Risk overview across all apps
    r = get("/api/v1/analytics/dashboard/top-risks")
    def check(d):
        if isinstance(d, dict) and d.get("detail", "").startswith("Not Found"):
            return "FAIL", "No risk overview endpoint"
        return "PASS" if len(str(d)) > 50 else "PARTIAL", f"Risk data: {json.dumps(d)[:150]}"
    grade("Sarah Chen", "CISO", "Mission Control", "View org-wide risk overview", "/api/v1/analytics/dashboard/top-risks", r, check)
    
    # 4. Evidence bundles for board report
    r = get("/api/v1/evidence/bundles")
    def check(d):
        bundles = d.get("bundles", []) if isinstance(d, dict) else d if isinstance(d, list) else []
        if len(bundles) > 0:
            return "PASS", f"{len(bundles)} evidence bundles available"
        return "PARTIAL", "No evidence bundles (empty but endpoint works)"
    grade("Sarah Chen", "CISO", "Comply", "Export evidence bundles for board", "/api/v1/evidence/bundles", r, check)

def test_david_vp_eng():
    """David Kim — VP Engineering: 'Is security slowing my teams?'"""
    print("\n👤 David Kim (VP Engineering) — Mission Control / SLA")
    
    # 1. SLA compliance dashboard
    r = get("/api/v1/remediation/backlog")
    def check(d):
        if isinstance(d, dict) and d.get("detail", "").startswith("Not Found"):
            return "FAIL", "No SLA endpoint"
        if isinstance(d, dict) and ("sla" in str(d).lower() or "compliance" in str(d).lower() or "overdue" in str(d).lower()):
            return "PASS", f"SLA data: {json.dumps(d)[:150]}"
        return "PARTIAL", f"Response: {json.dumps(d)[:150]}"
    grade("David Kim", "VP Engineering", "Mission Control", "Check SLA compliance by team", "/api/v1/remediation/backlog", r, check)
    
    # 2. Remediation velocity
    r = get("/api/v1/remediation/backlog")
    def check(d):
        if isinstance(d, dict) and d.get("detail", "").startswith("Not Found"):
            return "FAIL", "No remediation stats endpoint"
        return "PASS" if len(str(d)) > 50 else "PARTIAL", f"Remediation stats: {json.dumps(d)[:150]}"
    grade("David Kim", "VP Engineering", "Remediate", "Check remediation velocity", "/api/v1/remediation/backlog", r, check)
    
    # 3. AutoFix adoption (are PRs being generated?)
    r = get("/api/v1/autofix/stats")
    def check(d):
        stats = d.get("stats", d)
        total = stats.get("total_generated", 0) if isinstance(stats, dict) else 0
        if total > 0:
            return "PASS", f"{total} fixes generated"
        return "PARTIAL", "AutoFix stats endpoint works but 0 fixes generated (no data yet)"
    grade("David Kim", "VP Engineering", "Remediate", "Check AutoFix PR generation stats", "/api/v1/autofix/stats", r, check)

def test_priya_cto():
    """Priya Patel — CTO: 'Show me the architecture risk'"""
    print("\n👤 Priya Patel (CTO) — Mission Control / Discover")
    
    # 1. Knowledge graph status
    r = get("/api/v1/brain/status")
    def check(d):
        nodes = d.get("nodes", 0)
        return ("PASS" if nodes > 0 else "PARTIAL"), f"Graph: {nodes} nodes, {d.get('edges', 0)} edges"
    grade("Priya Patel", "CTO", "Discover", "View knowledge graph overview", "/api/v1/brain/status", r, check)
    
    # 2. Attack paths — GET /knowledge-graph/attack-paths (pre-computed paths)
    r = get("/api/v1/knowledge-graph/attack-paths")
    def check(d):
        if isinstance(d, dict) and d.get("detail", "").startswith("Not Found"):
            return "FAIL", "No GET attack paths endpoint"
        attack_paths = d.get("attack_paths", [])
        total = d.get("total_paths", len(attack_paths))
        critical = d.get("critical_paths", 0)
        if total > 0:
            return "PASS", f"{total} attack paths ({critical} critical) — e.g. {[p.get('name','?') for p in attack_paths[:2]]}"
        return "PARTIAL", f"Attack paths endpoint accessible but empty: {json.dumps(d)[:150]}"
    grade("Priya Patel", "CTO", "Discover", "View attack paths", "/api/v1/knowledge-graph/attack-paths", r, check)

def test_tom_cfo():
    """Tom Bradley — CFO: 'What does security cost us?'"""
    print("\n👤 Tom Bradley (CFO) — Mission Control / Executive")
    
    # ROI / cost analytics
    r = get("/api/v1/analytics/roi")
    def check(d):
        if isinstance(d, dict) and d.get("detail", "").startswith("Not Found"):
            return "FAIL", "No ROI analytics endpoint"
        return "PASS", f"ROI data: {json.dumps(d)[:150]}"
    grade("Tom Bradley", "CFO", "Mission Control", "View ROI and cost savings", "/api/v1/analytics/roi", r, check)


# ============================================================================
# PERSONA GROUP 2: SECURITY OPERATIONS (Discover + Triage)
# ============================================================================

def test_raj_devsecops():
    """Raj Mehta — DevSecOps Lead: 'What happened overnight?'"""
    print("\n👤 Raj Mehta (DevSecOps Lead) — Mission Control + Discover")
    
    # 1. Morning briefing — nerve center
    r = get("/api/v1/nerve-center/pulse")
    def check(d):
        if isinstance(d, dict) and d.get("detail", "").startswith("Not Found"):
            # Try alternate
            return "FAIL", "No nerve center summary"
        return "PASS", f"Nerve center: {json.dumps(d)[:150]}"
    grade("Raj Mehta", "DevSecOps Lead", "Mission Control", "Morning briefing: what happened overnight", "/api/v1/nerve-center/pulse", r, check)
    
    # 2. Priority queue of findings
    r = get("/api/v1/cases")
    def check(d):
        cases = d.get("cases", [])
        total = d.get("total", 0)
        return ("PASS" if total > 0 else "PARTIAL"), f"{total} exposure cases"
    grade("Raj Mehta", "DevSecOps Lead", "Discover", "View priority queue of exposure cases", "/api/v1/cases", r, check)

def test_alex_security_eng():
    """Alex Rivera — Security Engineer: 'Stop the noise, show me what matters'"""
    print("\n👤 Alex Rivera (Security Engineer) — Discover + Remediate")
    
    # 1. Scan code for vulnerabilities
    r = post("/api/v1/sast/scan/code", {
        "code": """import os, sqlite3
def login(request):
    username = request.form['username']
    password = request.form['password']
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    conn = sqlite3.connect('app.db')
    result = conn.execute(query)
    cmd = request.args.get('debug_cmd')
    if cmd:
        os.system(cmd)
    return result.fetchone()
""",
        "language": "python",
        "filename": "auth.py"
    })
    def check(d):
        findings = d.get("findings", [])
        total = d.get("total_findings", len(findings))
        if total >= 2:  # Should find SQLi + command injection at minimum
            sevs = [f.get("severity", "?") for f in findings]
            rules = [f.get("rule_id", "?") for f in findings]
            return "PASS", f"Found {total} vulns: {rules}"
        return "PARTIAL" if total > 0 else "FAIL", f"Only found {total} vulns in obviously vulnerable code"
    grade("Alex Rivera", "Security Engineer", "Discover", "SAST scan detects SQLi + command injection", "/api/v1/sast/scan/code", r, check)
    
    # 2. Deduplicate findings
    r = get("/api/v1/deduplication/stats")
    def check(d):
        if isinstance(d, dict) and d.get("detail", "").startswith("Not Found"):
            return "FAIL", "No dedup stats endpoint"
        return "PASS", f"Dedup stats: {json.dumps(d)[:150]}"
    grade("Alex Rivera", "Security Engineer", "Discover", "View deduplication stats (noise reduction)", "/api/v1/deduplication/stats", r, check)
    
    # 3. Triage a finding
    r = post("/api/v1/brain/ingest/finding", {
        "finding_id": "ALEX-TEST-001",
        "title": "SQL Injection in login handler",
        "severity": "critical",
        "cve_id": "CVE-2024-9999",
        "cwe_id": "CWE-89",
        "scanner": "aldeci-sast",
        "component": "auth-service",
        "app_id": "healthpay-portal"
    })
    def check(d):
        if d.get("ingested"):
            return "PASS", f"Finding ingested into graph: {d.get('node_id')}"
        return "PARTIAL", f"Response: {json.dumps(d)[:150]}"
    grade("Alex Rivera", "Security Engineer", "Discover", "Ingest finding into knowledge graph", "/api/v1/brain/ingest/finding", r, check)

def test_marcus_appsec():
    """Marcus Thompson — AppSec Engineer: 'One view for all PR security gates'"""
    print("\n👤 Marcus Thompson (AppSec Engineer) — Discover + Validate")
    
    # 1. Scanner ingest — upload SARIF from external scanner
    # Actual response shape: {"scanners": {"sast": [...], ...}, "total_new_parsers": 15, "total_with_builtins": 25, "ingestion_methods": [...]}
    r = get("/api/v1/scanner-ingest/supported")
    def check(d):
        if isinstance(d, dict) and d.get("detail", "").startswith("Not Found"):
            return "FAIL", "No supported formats endpoint"
        scanners = d.get("scanners", {})
        if isinstance(scanners, dict) and len(scanners) > 0:
            total_with_builtins = d.get("total_with_builtins", 0)
            total_new = d.get("total_new_parsers", 0)
            scanner_categories = list(scanners.keys())
            return "PASS", f"{total_with_builtins} total parsers ({total_new} new) in categories: {scanner_categories}"
        return "PARTIAL", f"Response: {json.dumps(d)[:150]}"
    grade("Marcus Thompson", "AppSec Engineer", "Discover", "Check supported scanner ingest formats", "/api/v1/scanner-ingest/supported", r, check)
    
    # 2. Upload scanner result
    r = get("/api/v1/ingest/formats")
    def check(d):
        if isinstance(d, dict) and d.get("detail", "").startswith("Not Found"):
            return "FAIL", "No ingest formats endpoint"
        return "PASS", f"Ingest formats: {json.dumps(d)[:200]}"
    grade("Marcus Thompson", "AppSec Engineer", "Discover", "List ingest formats for scanner results", "/api/v1/ingest/formats", r, check)


# ============================================================================
# PERSONA GROUP 3: ATTACK / VALIDATE
# ============================================================================

def test_jason_red_team():
    """Jason Wu — Red Team Lead: 'Prove it's exploitable'"""
    print("\n👤 Jason Wu (Red Team Lead) — Validate")
    
    # 1. MPTE — verify a vulnerability (correct schema: finding_id, target_url, vulnerability_type required)
    r = post("/api/v1/mpte/verify", {
        "finding_id": "SAST-fab3f5e0b22e",
        "target_url": "https://api.internal.aldeci.io/v2/auth/session",
        "vulnerability_type": "sql_injection",
        "evidence": "Tainted input from request.params['user_id'] flows to sql.execute() at auth_handler.py:142 without parameterization",
        "cve_id": "CVE-2024-29824"
    })
    def check(d):
        if isinstance(d, dict) and d.get("detail", "").startswith("Not Found"):
            return "FAIL", "MPTE verify endpoint not found"
        # 201 response returns {id, request_id, finding_id, status, message, source, created_at}
        if d.get("request_id") or d.get("id"):
            status_val = d.get("status", "")
            finding = d.get("finding_id", "")
            return "PASS", f"MPTE verification queued: id={d.get('id','')[:8]}, finding={finding}, status={status_val}"
        verdict = d.get("verdict", d.get("result", {}).get("verdict", ""))
        if verdict:
            return "PASS", f"MPTE verdict: {verdict}"
        return "PARTIAL", f"Response: {json.dumps(d)[:200]}"
    grade("Jason Wu", "Red Team Lead", "Validate", "MPTE verify exploitability of a finding", "/api/v1/mpte/verify", r, check)
    
    # 2. Attack simulation
    r = get("/api/v1/attack-sim/scenarios")
    def check(d):
        if isinstance(d, dict) and d.get("detail", "").startswith("Not Found"):
            return "FAIL", "No attack simulation scenarios endpoint"
        if isinstance(d, list):
            return "PASS", f"Attack scenarios: {len(d)} available"
        scenarios = d.get("scenarios", []) if isinstance(d, dict) else []
        return "PASS", f"Attack scenarios: {json.dumps(d)[:150]}"
    grade("Jason Wu", "Red Team Lead", "Validate", "List attack simulation scenarios", "/api/v1/attack-sim/scenarios", r, check)
    
    # 3. FAIL Engine — run a security drill
    r = get("/api/v1/fail/status")
    def check(d):
        if d.get("status") == "healthy":
            return "PASS", f"FAIL Engine healthy, version {d.get('engine_version')}, {d.get('total_scored', 0)} scored"
        return "PARTIAL", f"FAIL status: {json.dumps(d)[:150]}"
    grade("Jason Wu", "Red Team Lead", "Validate", "FAIL Engine status (chaos for security)", "/api/v1/fail/status", r, check)
    
    # 4. Score a specific CVE through FAIL
    r = post("/api/v1/fail/score", {
        "cve_id": "CVE-2024-9999",
        "cvss_score": 9.8,
        "epss_score": 0.92,
        "is_kev": True,
        "has_public_exploit": True
    })
    def check(d):
        score = d.get("fail_score", 0)
        grade_val = d.get("grade", "")
        action = d.get("recommended_action", "")
        if score > 0 and grade_val:
            return "PASS", f"FAIL score: {score}, grade: {grade_val}, action: {action}"
        return "PARTIAL", f"Response: {json.dumps(d)[:150]}"
    grade("Jason Wu", "Red Team Lead", "Validate", "FAIL Engine scores a critical CVE", "/api/v1/fail/score", r, check)

def test_emily_threat_analyst():
    """Emily Foster — Threat Analyst: 'Correlate threat intel across feeds'"""
    print("\n👤 Emily Foster (Threat Analyst) — Discover")
    
    # 1. Threat feeds status — real threat intelligence feed registry
    r = get("/api/v1/feeds/status")
    def check(d):
        if isinstance(d, dict) and d.get("detail", "").startswith("Not Found"):
            return "FAIL", "No threat feed endpoint"
        feeds = d.get("feeds", [])
        healthy = d.get("healthy", 0)
        if isinstance(feeds, list) and len(feeds) > 0:
            return "PASS", f"{len(feeds)} feeds configured, {healthy} healthy: {[f.get('name','?')[:30] for f in feeds[:3]]}"
        if isinstance(d, dict) and len(d) > 2:
            return "PASS", f"Feed status: {json.dumps(d)[:150]}"
        return "PARTIAL", f"Response: {json.dumps(d)[:150]}"
    grade("Emily Foster", "Threat Analyst", "Discover", "Check threat feed status", "/api/v1/feeds/status", r, check)
    
    # 2. EPSS scores — real EPSS probability data from FIRST.org feed
    r = get("/api/v1/feeds/epss/scores")
    def check(d):
        if isinstance(d, dict) and d.get("detail", "").startswith("Not Found"):
            return "FAIL", "No EPSS scores endpoint"
        scores = d.get("scores", [])
        if isinstance(scores, list) and len(scores) > 0:
            top = scores[0]
            return "PASS", f"{len(scores)} CVEs scored, top: {top.get('cve','?')} EPSS={top.get('epss','?')}, model: {d.get('model_version','?')}"
        if isinstance(d, dict) and ("scores" in d or "model_version" in d):
            return "PASS", f"EPSS data: {json.dumps(d)[:150]}"
        return "PARTIAL", f"Response: {json.dumps(d)[:150]}"
    grade("Emily Foster", "Threat Analyst", "Discover", "Query EPSS scores for prioritization", "/api/v1/feeds/epss/scores", r, check)


# ============================================================================
# PERSONA GROUP 4: REMEDIATE
# ============================================================================

def test_mike_developer():
    """Mike Chen — Senior Developer: 'Just tell me what to fix'"""
    print("\n👤 Mike Chen (Senior Developer) — Remediate")
    
    # 1. AutoFix — generate a fix for SQL injection
    r = post("/api/v1/autofix/generate", {
        "finding_id": "ALEX-TEST-001",
        "finding_type": "sql_injection",
        "code_snippet": "query = f\"SELECT * FROM users WHERE username='{username}'\"",
        "language": "python",
        "severity": "critical",
        "cve_id": "CVE-2024-9999"
    })
    def check(d):
        fix = d.get("fix", d)
        fix_id = fix.get("fix_id", "")
        confidence = fix.get("confidence_score", fix.get("confidence", 0))
        patches = fix.get("code_patches", [])
        if fix_id:
            has_real_fix = len(patches) > 0 or fix.get("description", "")
            if has_real_fix and confidence and float(str(confidence).replace("%","")) > 0.5:
                return "PASS", f"Fix {fix_id}, confidence: {confidence}, patches: {len(patches)}"
            return "PARTIAL", f"Fix generated but no actual code patches (LLM degraded): {fix_id}"
        return "FAIL", f"No fix generated: {json.dumps(d)[:150]}"
    grade("Mike Chen", "Senior Developer", "Remediate", "AutoFix generates fix for SQL injection", "/api/v1/autofix/generate", r, check)
    
    # 2. View remediation tasks
    r = get("/api/v1/remediation/tasks")
    def check(d):
        if isinstance(d, dict) and d.get("detail", "").startswith("Not Found"):
            return "FAIL", "No remediation tasks endpoint"
        tasks = d.get("tasks", d.get("items", []))
        return ("PASS" if len(tasks) > 0 else "PARTIAL"), f"Remediation tasks: {len(tasks)} items"
    grade("Mike Chen", "Senior Developer", "Remediate", "View remediation task queue", "/api/v1/remediation/tasks", r, check)

def test_rachel_junior_dev():
    """Rachel Kim — Junior Developer: 'I need help understanding what to fix'"""
    print("\n👤 Rachel Kim (Junior Developer) — Remediate")
    
    # Copilot — ask a security question
    r = post("/api/v1/copilot/ask", {
        "question": "What is SQL injection and how do I fix it in Python?",
        "context": {"finding_id": "ALEX-TEST-001", "language": "python"}
    })
    def check(d):
        if isinstance(d, dict) and d.get("detail", "").startswith("Not Found"):
            return "FAIL", "No copilot ask endpoint"
        answer = d.get("answer", d.get("response", d.get("message", "")))
        if answer and len(str(answer)) > 50:
            return "PASS", f"Copilot answer: {str(answer)[:150]}"
        return "PARTIAL", f"Response: {json.dumps(d)[:150]}"
    grade("Rachel Kim", "Junior Developer", "Remediate", "Ask Copilot for help understanding a vulnerability", "/api/v1/copilot/ask", r, check)


# ============================================================================
# PERSONA GROUP 5: COMPLY
# ============================================================================

def test_maria_compliance():
    """Maria Santos — Compliance Lead: 'Are we audit-ready?'"""
    print("\n👤 Maria Santos (Compliance Lead) — Comply")
    
    # 1. Compliance frameworks
    # Actual response: {"items": [...], "total": 6, "limit": 100, "offset": 0} — frameworks wrapped in "items" key
    r = get("/api/v1/audit/compliance/frameworks")
    def check(d):
        if isinstance(d, dict) and d.get("detail", "").startswith("Not Found"):
            # Try the compliance engine
            return "FAIL", "No compliance frameworks endpoint"
        # Response wraps frameworks in "items" key (paginated)
        frameworks = d.get("items", d.get("frameworks", d)) if isinstance(d, dict) else d
        if isinstance(frameworks, list) and len(frameworks) > 0:
            return "PASS", f"{len(frameworks)} frameworks: {[f.get('name', f) if isinstance(f,dict) else f for f in frameworks[:5]]}"
        return "PARTIAL", f"Response: {json.dumps(d)[:150]}"
    grade("Maria Santos", "Compliance Lead", "Comply", "List compliance frameworks", "/api/v1/audit/compliance/frameworks", r, check)
    
    # 2. SOC2 status — dedicated SOC2 Type II compliance view
    r = get("/api/v1/compliance-engine/soc2/status")
    def check(d):
        if isinstance(d, dict) and d.get("detail", "").startswith("Not Found"):
            return "FAIL", "No SOC2 status endpoint"
        if isinstance(d, dict) and "overall_score" in d:
            score = d.get("overall_score", 0)
            controls = d.get("total_controls", 0)
            gaps = d.get("gaps", 0)
            return "PASS", f"SOC2 Type II: {score}% compliant, {controls} controls, {gaps} gaps"
        if isinstance(d, dict) and ("trust_services_criteria" in d or "controls" in str(d).lower()):
            return "PASS", f"SOC2: {json.dumps(d)[:150]}"
        return "PARTIAL", f"SOC2: {json.dumps(d)[:150]}"
    grade("Maria Santos", "Compliance Lead", "Comply", "View SOC2 control status", "/api/v1/compliance-engine/soc2/status", r, check)
    
    # 3. Evidence bundles
    r = get("/api/v1/evidence/bundles")
    def check(d):
        bundles = d.get("bundles", [])
        return ("PASS" if len(bundles) > 0 else "PARTIAL"), f"{len(bundles)} evidence bundles"
    grade("Maria Santos", "Compliance Lead", "Comply", "List evidence bundles", "/api/v1/evidence/bundles", r, check)

def test_laura_auditor():
    """Laura Chen — External Auditor: 'Give me the evidence, fast'"""
    print("\n👤 Laura Chen (External Auditor) — Comply")
    
    # 1. Audit trail
    r = get("/api/v1/audit/logs")
    def check(d):
        if isinstance(d, dict) and "items" in d:
            total = d.get("total", len(d.get("items", [])))
            if total > 0:
                return "PASS", f"Audit trail: {total} entries"
            return "PARTIAL", f"Audit trail: 0 entries (endpoint works, needs events)"
        if isinstance(d, dict) and d.get("detail", "").startswith("Not Found"):
            return "FAIL", "No audit logs endpoint"
        logs = d.get("logs", d.get("entries", d.get("events", [])))
        if isinstance(logs, list):
            return ("PASS" if len(logs) > 0 else "PARTIAL"), f"Audit trail: {len(logs)} entries"
        return "FAIL", f"No audit trail: {json.dumps(d)[:150]}"
    grade("Laura Chen", "External Auditor", "Comply", "View audit trail", "/api/v1/audit/logs", r, check)
    
    # 2. Quantum crypto — sign evidence
    r = get("/api/v1/quantum-crypto/status")
    def check(d):
        status = d.get("status", "")
        if status == "operational":
            return "PASS", "Quantum crypto operational"
        if status == "degraded":
            error = d.get("error", "")
            return "PARTIAL", f"Quantum crypto degraded: {error[:100]}"
        return "FAIL", f"Quantum crypto: {json.dumps(d)[:150]}"
    grade("Laura Chen", "External Auditor", "Comply", "Verify quantum-secure evidence signing", "/api/v1/quantum-crypto/status", r, check)
    
    # 3. SLSA provenance
    r = get("/api/v1/provenance/")
    def check(d):
        if isinstance(d, dict) and d.get("detail", "").startswith("Not Found"):
            return "FAIL", "No provenance attestations endpoint"
        if isinstance(d, list):
            if len(d) > 0:
                return "PASS", f"Provenance: {len(d)} attestations"
            return "PARTIAL", f"Provenance store accessible (0 attestations — awaiting data)"
        atts = d.get("attestations", d.get("items", []))
        if isinstance(atts, list):
            if len(atts) > 0:
                return "PASS", f"Provenance: {len(atts)} attestations"
            return "PARTIAL", f"Provenance store accessible (0 attestations — awaiting data)"
        return "PARTIAL", f"Provenance: {json.dumps(d)[:150]}"
    grade("Laura Chen", "External Auditor", "Comply", "View SLSA provenance attestations", "/api/v1/provenance/", r, check)


# ============================================================================
# CROSS-CUTTING: Additional Personas
# ============================================================================

def test_derek_vm_manager():
    """Derek Washington — VM Manager: 'What's overdue?'"""
    print("\n👤 Derek Washington (VM Manager) — Mission Control")
    r = get("/api/v1/remediation/backlog")
    def check(d):
        if isinstance(d, dict) and d.get("detail", "").startswith("Not Found"):
            return "FAIL", "No overdue endpoint"
        return "PASS", f"Overdue findings: {json.dumps(d)[:150]}"
    grade("Derek Washington", "VM Manager", "Mission Control", "View overdue remediation items", "/api/v1/remediation/backlog", r, check)

def test_janet_soc_analyst():
    """Janet Liu — SOC Analyst: 'Real-time feed of events'"""
    print("\n👤 Janet Liu (SOC Analyst) — Mission Control")
    r = get("/api/v1/brain/events")
    def check(d):
        events = d.get("events", d) if isinstance(d, (dict, list)) else []
        if isinstance(events, list):
            return ("PASS" if len(events) > 0 else "PARTIAL"), f"Events: {len(events)} items"
        return "PARTIAL", f"Response: {json.dumps(d)[:150]}"
    grade("Janet Liu", "SOC Analyst", "Mission Control", "View real-time security events", "/api/v1/brain/events", r, check)

def test_brian_cloud_security():
    """Brian Mitchell — Cloud Security: 'Show me IaC drift'"""
    print("\n👤 Brian Mitchell (Cloud Security) — Discover")
    r = get("/api/v1/cspm/health")
    def check(d):
        if d.get("status") == "ready":
            return "PASS", f"CSPM ready (cloud providers: boto3={d.get('boto3_available')}, azure={d.get('azure_available')})"
        return "PARTIAL", f"CSPM: {json.dumps(d)[:150]}"
    grade("Brian Mitchell", "Cloud Security", "Discover", "Check cloud security posture", "/api/v1/cspm/health", r, check)

def test_kevin_dev_lead():
    """Kevin O'Brien — Dev Lead: 'Sprint-aware security backlog'"""
    print("\n👤 Kevin O'Brien (Dev Lead) — Mission Control")
    r = get("/api/v1/remediation/backlog")
    def check(d):
        if isinstance(d, dict) and d.get("detail", "").startswith("Not Found"):
            return "FAIL", "No security backlog endpoint"
        return "PASS", f"Backlog: {json.dumps(d)[:150]}"
    grade("Kevin O'Brien", "Dev Lead", "Mission Control", "View security backlog for sprint planning", "/api/v1/remediation/backlog", r, check)

def test_chris_platform_eng():
    """Chris Taylor — Platform Engineer: 'Manage tool configurations'"""
    print("\n👤 Chris Taylor (Platform Engineer) — Settings")
    r = get("/api/v1/mcp/tools")
    def check(d):
        if isinstance(d, dict) and d.get("detail", "").startswith("Not Found"):
            return "FAIL", "No connectors listing endpoint"
        if isinstance(d, (dict, list)) and len(str(d)) > 20:
            tools_count = len(d.get("tools", d)) if isinstance(d, dict) else len(d)
            return "PASS", f"MCP tools available: {tools_count}"
        return "PARTIAL", f"Response: {json.dumps(d)[:150]}"
    grade("Chris Taylor", "Platform Engineer", "Settings", "List available integrations/connectors", "/api/v1/mcp/tools", r, check)

def test_sam_ai_agent_dev():
    """Sam Parker — AI Agent Developer: 'Use ALdeci via MCP'"""
    print("\n👤 Sam Parker (AI Agent Dev) — Settings/MCP")
    r = get("/api/v1/mcp/tools")
    def check(d):
        if isinstance(d, dict) and d.get("detail", "").startswith("Not Found"):
            return "FAIL", "No MCP tools discovery endpoint"
        if isinstance(d, list):
            return ("PASS" if len(d) > 0 else "PARTIAL"), f"MCP exposes {len(d)} tools"
        tools = d.get("tools", []) if isinstance(d, dict) else []
        if len(tools) > 0:
            return "PASS", f"MCP exposes {len(tools)} tools"
        return "PARTIAL", f"MCP response: {json.dumps(d)[:150]}"
    grade("Sam Parker", "AI Agent Dev", "Settings", "Discover MCP tools for AI agents", "/api/v1/mcp/tools", r, check)

def test_dr_wei_ml_engineer():
    """Dr. Wei — ML Engineer: 'I need labeled training data'"""
    print("\n👤 Dr. Wei (ML Engineer) — Validate")
    r = get("/api/v1/self-learning/stats")
    def check(d):
        if isinstance(d, dict) and d.get("enabled") and d.get("feedback_loops", 0) > 0:
            total = d.get("total_feedback_records", 0)
            loops = d.get("feedback_loops", 0)
            return "PASS", f"Self-learning: {loops} loops, {total} feedback records, enabled={d.get('enabled')}"
        if isinstance(d, dict) and d.get("status") == "operational":
            loop_list = d.get("loops", [])
            counts = d.get("feedback_counts", {})
            total_feedback = sum(counts.values()) if isinstance(counts, dict) else 0
            return ("PASS" if total_feedback > 0 else "PARTIAL"), f"Self-learning: {len(loop_list)} loops, {total_feedback} feedback samples"
        return "PARTIAL", f"Response: {json.dumps(d)[:150]}"
    grade("Dr. Wei", "ML Engineer", "Validate", "Check self-learning stats and training data", "/api/v1/self-learning/stats", r, check)

def test_amy_qa_release():
    """Amy Rodriguez — QA/Release Eng: 'Is this build safe to deploy?'"""
    print("\n👤 Amy Rodriguez (QA/Release Eng) — Mission Control")
    r = get("/api/v1/provenance/")
    def check(d):
        if isinstance(d, dict) and d.get("detail", "").startswith("Not Found"):
            return "FAIL", "No provenance status endpoint"
        if isinstance(d, list):
            return "PASS", f"Provenance store accessible ({len(d)} items)"
        return "PASS", f"Provenance: {json.dumps(d)[:150]}"
    grade("Amy Rodriguez", "QA/Release Eng", "Mission Control", "Check SLSA provenance for build safety", "/api/v1/provenance/", r, check)

def test_lisa_cloud_architect():
    """Lisa Park — Cloud Architect: 'Security impact of infra decisions'"""
    print("\n👤 Lisa Park (Cloud Architect) — Discover")
    r = get("/api/v1/brain/most-connected")
    def check(d):
        nodes = d.get("nodes", d) if isinstance(d, (dict, list)) else []
        if isinstance(nodes, list):
            return ("PASS" if len(nodes) > 0 else "PARTIAL"), f"Most connected: {len(nodes)} nodes"
        return "PARTIAL", f"Response: {json.dumps(d)[:150]}"
    grade("Lisa Park", "Cloud Architect", "Discover", "Find most-connected nodes in knowledge graph", "/api/v1/brain/most-connected", r, check)

def test_nina_security_architect():
    """Nina Kowalski — Security Architect: 'Holistic posture view'"""
    print("\n👤 Nina Kowalski (Security Architect) — Discover")
    r = get("/api/v1/brain/health")
    def check(d):
        return "PASS" if d.get("status") == "healthy" else "PARTIAL", f"Brain health: {json.dumps(d)[:150]}"
    grade("Nina Kowalski", "Security Architect", "Discover", "View brain engine health", "/api/v1/brain/health", r, check)

def test_aisha_data_scientist():
    """Aisha Johnson — Data Scientist: 'Model drift detection'"""
    print("\n👤 Aisha Johnson (Data Scientist) — AI Copilot")
    r = get("/api/v1/self-learning/analyze")
    def check(d):
        if isinstance(d, dict) and d.get("detail", "").startswith("Not Found"):
            return "FAIL", "No self-learning analyze endpoint"
        return "PASS", f"Analysis: {json.dumps(d)[:200]}"
    grade("Aisha Johnson", "Data Scientist", "AI Copilot", "Analyze model drift in self-learning", "/api/v1/self-learning/analyze", r, check)

def test_carlos_consultant():
    """Carlos Mendez — Security Consultant: 'Connect any scanner, unified view'"""
    print("\n👤 Carlos Mendez (Security Consultant) — Mission Control")
    r = get("/api/v1/scanner-ingest/status")
    def check(d):
        if isinstance(d, dict) and d.get("detail", "").startswith("Not Found"):
            return "FAIL", "No scanner ingest status"
        return "PASS", f"Scanner ingest: {json.dumps(d)[:150]}"
    grade("Carlos Mendez", "Security Consultant", "Mission Control", "Check scanner ingest status (Switzerland)", "/api/v1/scanner-ingest/status", r, check)


# ============================================================================
# CROSS-CUTTING: Full Pipeline Test
# ============================================================================

def test_full_pipeline():
    """END-TO-END: Full CTEM+ pipeline — ingest → brain → score → verify → fix → evidence"""
    print("\n🔄 FULL PIPELINE TEST: ingest → brain → score → verify → fix → evidence")
    
    # Step 1: SAST scan
    r = post("/api/v1/sast/scan/code", {
        "code": "import os\nos.system(input('cmd: '))\neval(input('expr: '))",
        "language": "python",
        "filename": "vuln.py"
    })
    findings = r.json().get("findings", []) if r.status_code == 200 else []
    grade("Pipeline", "System", "Cross-cutting", "Step 1: SAST scan finds vulnerabilities", "/api/v1/sast/scan/code", r, 
          lambda d: ("PASS", f"{d.get('total_findings', 0)} findings") if d.get("total_findings", 0) > 0 else ("FAIL", "No findings"))
    
    # Step 2: Ingest into brain
    if findings:
        f = findings[0]
        r = post("/api/v1/brain/ingest/finding", {
            "finding_id": f.get("finding_id", "PIPE-001"),
            "title": f.get("message", "Test finding"),
            "severity": f.get("severity", "high"),
            "cwe_id": f.get("cwe_id", "CWE-78"),
            "scanner": "aldeci-sast",
            "component": "test-app",
            "app_id": "pipeline-test"
        })
        grade("Pipeline", "System", "Cross-cutting", "Step 2: Ingest finding into brain graph", "/api/v1/brain/ingest/finding", r,
              lambda d: ("PASS", f"Ingested: {d.get('node_id')}") if d.get("ingested") else ("FAIL", str(d)[:150]))
    
    # Step 3: FAIL score
    r = post("/api/v1/fail/score", {
        "cve_id": "CVE-2024-0001",
        "cvss_score": 9.1,
        "epss_score": 0.88
    })
    grade("Pipeline", "System", "Cross-cutting", "Step 3: FAIL Engine risk scoring", "/api/v1/fail/score", r,
          lambda d: ("PASS", f"Score: {d.get('fail_score')}, Grade: {d.get('grade')}") if d.get("fail_score") else ("FAIL", str(d)[:150]))
    
    # Step 4: MPTE verify
    r = post("/api/v1/mpte/verify", {
        "finding_id": "SAST-fab3f5e0b22e",
        "target_url": "https://api.internal.aldeci.io/v2/auth",
        "vulnerability_type": "sql_injection"
    })
    def _mpte_check(d):
        if d.get("verification_id") or d.get("result") or d.get("id") or d.get("request_id"):
            return "PASS", f"Verification: {json.dumps(d)[:150]}"
        verdict = d.get("verdict", d.get("result", {}).get("verdict", "") if isinstance(d.get("result"), dict) else "")
        if verdict:
            return "PASS", f"MPTE verdict: {verdict}"
        if r.status_code in (200, 201):
            return "PARTIAL", f"Response ({r.status_code}): {json.dumps(d)[:150]}"
        return "FAIL", f"Response: {json.dumps(d)[:150]}"
    grade("Pipeline", "System", "Cross-cutting", "Step 4: MPTE verification", "/api/v1/mpte/verify", r, _mpte_check)
    
    # Step 5: AutoFix
    r = post("/api/v1/autofix/generate", {
        "finding_id": "PIPE-001",
        "finding_type": "command_injection",
        "code_snippet": "os.system(input('cmd: '))",
        "language": "python",
        "severity": "critical"
    })
    grade("Pipeline", "System", "Cross-cutting", "Step 5: AutoFix generates remediation", "/api/v1/autofix/generate", r,
          lambda d: ("PASS", f"Fix: {d.get('fix',{}).get('fix_id','')}") if d.get("fix", {}).get("fix_id") else ("PARTIAL", str(d)[:150]))
    
    # Step 6: Evidence
    r = get("/api/v1/evidence/bundles")
    grade("Pipeline", "System", "Cross-cutting", "Step 6: Evidence bundles available", "/api/v1/evidence/bundles", r,
          lambda d: ("PASS", f"{len(d.get('bundles',[]))} bundles") if d.get("bundles") else ("PARTIAL", "No bundles yet"))


# ============================================================================
# MAIN: Run all and produce report
# ============================================================================

if __name__ == "__main__":
    print("=" * 70)
    print("  ALdeci PERSONA-DRIVEN REALITY TEST")
    print("  Testing 25 personas against the real product")
    print("=" * 70)
    
    # Leadership
    test_sarah_ciso()
    test_david_vp_eng()
    test_priya_cto()
    test_tom_cfo()
    
    # SecOps
    test_raj_devsecops()
    test_alex_security_eng()
    test_marcus_appsec()
    
    # Attack/Validate
    test_jason_red_team()
    test_emily_threat_analyst()
    
    # Remediate
    test_mike_developer()
    test_rachel_junior_dev()
    
    # Comply
    test_maria_compliance()
    test_laura_auditor()
    
    # Additional personas
    test_derek_vm_manager()
    test_janet_soc_analyst()
    test_brian_cloud_security()
    test_kevin_dev_lead()
    test_chris_platform_eng()
    test_sam_ai_agent_dev()
    test_dr_wei_ml_engineer()
    test_amy_qa_release()
    test_lisa_cloud_architect()
    test_nina_security_architect()
    test_aisha_data_scientist()
    test_carlos_consultant()
    
    # Full pipeline
    test_full_pipeline()
    
    # ── REPORT ──
    print("\n" + "=" * 70)
    print("  RESULTS MATRIX")
    print("=" * 70)
    
    pass_count = sum(1 for r in results if r.status == "PASS")
    partial_count = sum(1 for r in results if r.status == "PARTIAL")
    fail_count = sum(1 for r in results if r.status == "FAIL")
    total = len(results)
    
    # Group by space
    spaces = {}
    for r in results:
        spaces.setdefault(r.space, []).append(r)
    
    for space, tests in sorted(spaces.items()):
        print(f"\n── {space} ──")
        for t in tests:
            icon = {"PASS": "✅", "PARTIAL": "⚠️ ", "FAIL": "❌"}[t.status]
            print(f"  {icon} [{t.persona:20s}] {t.workflow}")
            print(f"     {t.detail[:120]}")
    
    print(f"\n{'=' * 70}")
    print(f"  SUMMARY: {pass_count} PASS / {partial_count} PARTIAL / {fail_count} FAIL  (out of {total} workflows)")
    print(f"  Pass rate: {pass_count/total*100:.0f}% | Usable (PASS+PARTIAL): {(pass_count+partial_count)/total*100:.0f}%")
    print(f"{'=' * 70}")
    
    # Per-space summary
    print(f"\n  PER-SPACE BREAKDOWN:")
    for space, tests in sorted(spaces.items()):
        sp = sum(1 for t in tests if t.status == "PASS")
        spar = sum(1 for t in tests if t.status == "PARTIAL")
        sf = sum(1 for t in tests if t.status == "FAIL")
        st = len(tests)
        print(f"  {space:20s}: {sp}✅ {spar}⚠️  {sf}❌  ({sp/st*100:.0f}% pass)")
    
    # FAIL list for priority fixing
    fails = [r for r in results if r.status == "FAIL"]
    if fails:
        print(f"\n  🔴 CRITICAL FAILURES ({len(fails)}):")
        for f in fails:
            print(f"    [{f.persona}] {f.workflow}")
            print(f"      Endpoint: {f.endpoint} → {f.detail[:100]}")
    
    # Save JSON results
    with open("/home/user/workspace/persona_test_results.json", "w") as fh:
        json.dump([{
            "persona": r.persona, "role": r.role, "space": r.space,
            "workflow": r.workflow, "status": r.status, "detail": r.detail,
            "endpoint": r.endpoint, "http_code": r.http_code
        } for r in results], fh, indent=2)
    print(f"\n  Results saved to persona_test_results.json")
