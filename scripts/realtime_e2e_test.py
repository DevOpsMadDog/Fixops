#!/usr/bin/env python3
"""
ALdeci Real-Time E2E Persona Validation Test
Tests against OWASP Juice Shop source code (cloned to /tmp/juiceshop-test)
Exercises: SAST, Secrets, Brain Pipeline, Triage, MPTE, AutoFix, Evidence
"""
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

BASE = os.getenv("ALDECI_BASE_URL", "http://localhost:8000")
API_KEY = os.getenv("FIXOPS_API_TOKEN", os.getenv("API_KEY", "fixops_ent_38wJA8mb7CsbJ3PaLvKNz7lFnLWvFWXti_5NcdISXSogi_4grP24NAe_XymVfps_"))
H = {"X-API-Key": API_KEY, "Content-Type": "application/json"}
JUICE_SHOP = Path("/tmp/juiceshop-test")
OUT = Path("/tmp/aldeci_e2e_results")
OUT.mkdir(parents=True, exist_ok=True)

results = {
    "run_id": f"e2e-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}",
    "target": "OWASP Juice Shop",
    "start_time": datetime.now(timezone.utc).isoformat(),
    "personas": {},
    "kpis": {},
    "verdict": "UNKNOWN",
}

def api(method, path, **kwargs):
    url = f"{BASE}{path}"
    r = getattr(requests, method)(url, headers=H, timeout=30, **kwargs)
    return r.status_code, r.json() if r.headers.get("content-type","").startswith("application/json") else r.text

def section(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")

# ── Step 0: Health Check ──
section("STEP 0: Platform Health Check")
code, data = api("get", "/api/v1/health")
print(f"  Health: {code} — {data.get('status', '?') if isinstance(data, dict) else '?'}")
if code != 200:
    print("  FATAL: Server not healthy. Aborting.")
    sys.exit(1)

code, sast_health = api("get", "/api/v1/sast/health")
print(f"  SAST Engine: {code} — rules={sast_health.get('rules_count', '?')}, langs={sast_health.get('languages', '?')}")

code, secrets_health = api("get", "/api/v1/secrets/health")
print(f"  Secrets Engine: {code} — {secrets_health}")

code, mpte_health = api("get", "/api/v1/mpte/health")
print(f"  MPTE Engine: {code} — {mpte_health}")

code, autofix_health = api("get", "/api/v1/autofix/health")
print(f"  AutoFix Engine: {code} — {autofix_health}")

code, brain_health = api("get", "/api/v1/brain/health")
print(f"  Brain Pipeline: {code} — {brain_health}")

code, triage_health = api("get", "/api/v1/triage/health")
print(f"  Triage Engine: {code} — {triage_health}")

results["personas"]["platform_health"] = {
    "sast": sast_health if isinstance(sast_health, dict) else str(sast_health),
    "mpte": mpte_health if isinstance(mpte_health, dict) else str(mpte_health),
    "autofix": autofix_health if isinstance(autofix_health, dict) else str(autofix_health),
}

# ── Step 1: SAST Scan (Persona: AppSec Engineer) ──
section("STEP 1: PERSONA — AppSec Engineer — SAST Scan")
vuln_files = [
    "routes/login.ts",
    "routes/basket.ts",
    "routes/changePassword.ts",
    "routes/dataExport.ts",
    "routes/fileUpload.ts",
    "routes/b2bOrder.ts",
    "routes/userProfile.ts",
    "lib/insecurity.ts",
]

sast_findings = []
sast_file_results = {}
for rel in vuln_files:
    fpath = JUICE_SHOP / rel
    if not fpath.exists():
        print(f"  SKIP {rel} (not found)")
        continue
    code_content = fpath.read_text(errors="replace")
    code, data = api("post", "/api/v1/sast/scan/code", json={
        "code": code_content,
        "language": "typescript",
        "filename": rel,
    })
    findings = []
    if isinstance(data, dict):
        findings = data.get("findings", data.get("vulnerabilities", []))
    sast_file_results[rel] = {"status": code, "count": len(findings)}
    print(f"  {rel}: HTTP {code} | {len(findings)} findings")
    for f in findings[:5]:
        sev = f.get("severity", "?")
        rule = f.get("rule_id", f.get("type", "?"))
        line = f.get("line", f.get("line_number", "?"))
        msg = f.get("message", f.get("description", ""))[:80]
        print(f"    [{sev}] {rule} @ line {line}: {msg}")
    sast_findings.extend(findings)

print(f"\n  SAST TOTAL: {len(sast_findings)} findings across {len(vuln_files)} files")
results["personas"]["appsec_sast"] = {
    "files_scanned": len(vuln_files),
    "total_findings": len(sast_findings),
    "per_file": sast_file_results,
}

# ── Step 2: Secrets Scan (Persona: Security Architect) ──
section("STEP 2: PERSONA — Security Architect — Secrets Scan")
secrets_targets = [
    "lib/insecurity.ts",
    "config/default.yml",
    "ctf.key",
]
secrets_findings = []
for rel in secrets_targets:
    fpath = JUICE_SHOP / rel
    if not fpath.exists():
        print(f"  SKIP {rel}")
        continue
    content = fpath.read_text(errors="replace")
    code, data = api("post", "/api/v1/secrets/scan/content", json={
        "content": content,
        "filename": rel,
    })
    findings = []
    if isinstance(data, dict):
        findings = data.get("findings", data.get("secrets", data.get("results", [])))
    print(f"  {rel}: HTTP {code} | {len(findings)} secrets found")
    for s in findings[:5]:
        stype = s.get("type", s.get("rule_id", "?"))
        line = s.get("line", s.get("line_number", "?"))
        print(f"    [{stype}] line {line}")
    secrets_findings.extend(findings)

print(f"\n  SECRETS TOTAL: {len(secrets_findings)} secrets across {len(secrets_targets)} files")
results["personas"]["security_architect_secrets"] = {
    "files_scanned": len(secrets_targets),
    "total_secrets": len(secrets_findings),
}

# ── Step 3: Brain Pipeline Ingest (Persona: Platform Engineer) ──
section("STEP 3: PERSONA — Platform Engineer — Brain Pipeline Ingest")
# Ingest SAST findings into brain
ingested = 0
for f in sast_findings[:10]:
    code, data = api("post", "/api/v1/brain/ingest/finding", json={
        "finding_id": f.get("id", f"sast-{ingested}"),
        "source": "sast",
        "severity": f.get("severity", "MEDIUM"),
        "title": f.get("message", f.get("description", "SAST finding"))[:200],
        "file": f.get("file", f.get("filename", "unknown")),
        "line": f.get("line", f.get("line_number", 0)),
        "rule_id": f.get("rule_id", "unknown"),
        "app_id": "juice-shop",
    })
    if code in (200, 201):
        ingested += 1
    else:
        print(f"  Ingest {ingested}: HTTP {code} — {str(data)[:100]}")

print(f"  Ingested {ingested}/{min(len(sast_findings),10)} findings into brain")
results["personas"]["platform_engineer_ingest"] = {"ingested": ingested}

# ── Step 4: Triage Queue (Persona: SOC T1 Analyst) ──
section("STEP 4: PERSONA — SOC T1 Analyst — Triage Queue")
code, triage_data = api("get", "/api/v1/triage/queue")
triage_items = []
if isinstance(triage_data, dict):
    triage_items = triage_data.get("items", triage_data.get("findings", triage_data.get("queue", [])))
    if isinstance(triage_data, list):
        triage_items = triage_data
print(f"  Triage Queue: HTTP {code} | {len(triage_items)} items")
for t in (triage_items or [])[:5]:
    print(f"    {t.get('id','?')}: [{t.get('severity','?')}] {str(t.get('title', t.get('message','')))[:60]}")

code, triage_stats = api("get", "/api/v1/triage/stats")
print(f"  Triage Stats: HTTP {code} — {json.dumps(triage_stats)[:200] if isinstance(triage_stats, dict) else str(triage_stats)[:200]}")

results["personas"]["soc_t1_triage"] = {
    "queue_size": len(triage_items) if triage_items else 0,
    "stats": triage_stats if isinstance(triage_stats, dict) else str(triage_stats),
}

# ── Step 5: Analytics / Findings (Persona: Vulnerability Manager) ──
section("STEP 5: PERSONA — Vulnerability Manager — Findings Analytics")
code, findings_data = api("get", "/api/v1/analytics/findings")
print(f"  Findings Analytics: HTTP {code}")
if isinstance(findings_data, dict):
    total = findings_data.get("total", findings_data.get("count", len(findings_data.get("findings", []))))
    print(f"  Total findings in platform: {total}")
    for f in findings_data.get("findings", [])[:5]:
        print(f"    [{f.get('severity','?')}] {str(f.get('title', f.get('message','')))[:60]}")
results["personas"]["vuln_manager_analytics"] = {
    "status": code,
    "response_sample": str(findings_data)[:500] if findings_data else "empty",
}

# ── Step 6: MPTE Verification (Persona: AppSec — Exploit Validation) ──
section("STEP 6: PERSONA — AppSec Engineer — MPTE Exploitability Check")
# Get a finding ID to verify
finding_id = None
if sast_findings:
    finding_id = sast_findings[0].get("id", "sast-0")

# Check MPTE status
code, mpte_status = api("get", "/api/v1/mpte/status")
print(f"  MPTE Status: HTTP {code} — {json.dumps(mpte_status)[:200] if isinstance(mpte_status, dict) else str(mpte_status)[:200]}")

# Try exploitability check
if finding_id:
    code, exploit_data = api("get", f"/api/v1/mpte/findings/{finding_id}/exploitability")
    print(f"  Exploitability for {finding_id}: HTTP {code}")
    if isinstance(exploit_data, dict):
        print(f"    Result: {json.dumps(exploit_data)[:300]}")

# Try comprehensive scan
code, mpte_scan = api("post", "/api/v1/mpte/scan/comprehensive", json={
    "target": "juice-shop",
    "finding_ids": [f.get("id", f"sast-{i}") for i, f in enumerate(sast_findings[:5])],
    "mode": "passive",
})
print(f"  MPTE Comprehensive Scan: HTTP {code}")
if isinstance(mpte_scan, dict):
    print(f"    {json.dumps(mpte_scan)[:300]}")

results["personas"]["appsec_mpte"] = {
    "status_code": code,
    "response_sample": str(mpte_scan)[:500] if mpte_scan else "empty",
}

# ── Step 7: AutoFix (Persona: Tech Lead / Engineering) ──
section("STEP 7: PERSONA — Tech Lead — AutoFix Generation")
code, autofix_status = api("get", "/api/v1/autofix/status")
print(f"  AutoFix Status: HTTP {code} — {json.dumps(autofix_status)[:200] if isinstance(autofix_status, dict) else str(autofix_status)[:200]}")

code, fix_types = api("get", "/api/v1/autofix/fix-types")
print(f"  Fix Types: HTTP {code} — {json.dumps(fix_types)[:300] if isinstance(fix_types, dict) else str(fix_types)[:300]}")

# Try to generate a fix
if sast_findings:
    f = sast_findings[0]
    code, fix_result = api("post", "/api/v1/autofix/generate", json={
        "finding_id": f.get("id", "sast-0"),
        "finding": {
            "title": f.get("message", f.get("description", "SQL Injection"))[:200],
            "severity": f.get("severity", "HIGH"),
            "file": f.get("file", f.get("filename", "routes/login.ts")),
            "line": f.get("line", f.get("line_number", 35)),
            "code_snippet": f.get("snippet", f.get("code", ""))[:500],
            "rule_id": f.get("rule_id", "sql-injection"),
        },
        "mode": "recommend",
    })
    print(f"  AutoFix Generate: HTTP {code}")
    if isinstance(fix_result, dict):
        conf = fix_result.get("confidence", fix_result.get("confidence_level", "?"))
        fix_type = fix_result.get("fix_type", fix_result.get("type", "?"))
        print(f"    Confidence: {conf}, Type: {fix_type}")
        print(f"    {json.dumps(fix_result)[:400]}")

code, autofix_summary = api("get", "/api/v1/autofix/summary")
print(f"  AutoFix Summary: HTTP {code} — {json.dumps(autofix_summary)[:200] if isinstance(autofix_summary, dict) else str(autofix_summary)[:200]}")

results["personas"]["tech_lead_autofix"] = {
    "fix_types": fix_types if isinstance(fix_types, dict) else str(fix_types),
    "status": autofix_status if isinstance(autofix_status, dict) else str(autofix_status),
}

# ── Step 8: Evidence Bundle (Persona: GRC / Compliance Manager) ──
section("STEP 8: PERSONA — GRC Analyst — Evidence Generation")
code, evidence_result = api("post", "/api/v1/brain/evidence/generate", json={
    "app_id": "juice-shop",
    "include": ["findings", "mpte", "autofix", "policy", "timeline"],
})
print(f"  Evidence Generate: HTTP {code}")
if isinstance(evidence_result, dict):
    pack_id = evidence_result.get("pack_id", evidence_result.get("id", "?"))
    print(f"    Pack ID: {pack_id}")
    print(f"    {json.dumps(evidence_result)[:400]}")

code, evidence_packs = api("get", "/api/v1/brain/evidence/packs")
print(f"  Evidence Packs: HTTP {code}")
if isinstance(evidence_packs, dict):
    packs = evidence_packs.get("packs", evidence_packs.get("items", []))
    print(f"    Total packs: {len(packs) if isinstance(packs, list) else '?'}")

# Compliance frameworks
code, frameworks = api("get", "/api/v1/compliance-engine/frameworks")
print(f"  Compliance Frameworks: HTTP {code}")
if isinstance(frameworks, dict):
    fws = frameworks.get("frameworks", frameworks.get("items", []))
    for fw in (fws if isinstance(fws, list) else [])[:5]:
        print(f"    {fw.get('id', fw.get('name', '?'))}")

results["personas"]["grc_evidence"] = {
    "evidence_status": code,
    "evidence_sample": str(evidence_result)[:500] if evidence_result else "empty",
}

# ── Step 9: Risk Overview (Persona: CISO) ──
section("STEP 9: PERSONA — CISO — Risk Overview")
code, risk_overview = api("get", "/api/v1/risk/overview")
print(f"  Risk Overview: HTTP {code}")
if isinstance(risk_overview, dict):
    print(f"    {json.dumps(risk_overview)[:400]}")

code, risk_score = api("get", "/api/v1/risk/score")
print(f"  Risk Score: HTTP {code}")
if isinstance(risk_score, dict):
    print(f"    {json.dumps(risk_score)[:300]}")

code, dashboard_risks = api("get", "/api/v1/analytics/dashboard/top-risks")
print(f"  Top Risks Dashboard: HTTP {code}")
if isinstance(dashboard_risks, dict):
    print(f"    {json.dumps(dashboard_risks)[:300]}")

results["personas"]["ciso_risk"] = {
    "overview_status": code,
    "risk_sample": str(risk_overview)[:500] if risk_overview else "empty",
}

# ── Step 10: Brain Pipeline Run (Persona: Platform Engineer) ──
section("STEP 10: PERSONA — Platform Engineer — Full Brain Pipeline Run")
code, pipeline_result = api("post", "/api/v1/brain/pipeline/run", json={
    "app_id": "juice-shop",
    "mode": "full",
})
print(f"  Pipeline Run: HTTP {code}")
if isinstance(pipeline_result, dict):
    run_id = pipeline_result.get("run_id", pipeline_result.get("id", "?"))
    steps = pipeline_result.get("steps_completed", pipeline_result.get("steps", "?"))
    print(f"    Run ID: {run_id}, Steps: {steps}")
    print(f"    {json.dumps(pipeline_result)[:400]}")

results["personas"]["platform_brain_pipeline"] = {
    "status_code": code,
    "response_sample": str(pipeline_result)[:500] if pipeline_result else "empty",
}

# ══════════════════════════════════════════════════════════════
# KPI SCORING
# ══════════════════════════════════════════════════════════════
section("KPI SCORING — HONEST ASSESSMENT")

total_sast = len(sast_findings)
total_secrets = len(secrets_findings)
total_all = total_sast + total_secrets

# Count severities
sevs = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
for f in sast_findings + secrets_findings:
    s = f.get("severity", "LOW").upper()
    if s in sevs:
        sevs[s] += 1

print(f"  Total Findings: {total_all}")
print(f"    SAST: {total_sast}")
print(f"    Secrets: {total_secrets}")
print(f"    Critical: {sevs['CRITICAL']}, High: {sevs['HIGH']}, Medium: {sevs['MEDIUM']}, Low: {sevs['LOW']}")

# Check what's real vs hardcoded
has_line_numbers = sum(1 for f in sast_findings if f.get("line", f.get("line_number", 0)) > 0)
has_rule_ids = sum(1 for f in sast_findings if f.get("rule_id", "") != "")
has_code_context = sum(1 for f in sast_findings if f.get("snippet", f.get("code", f.get("code_context", ""))) != "")

print(f"\n  AUTHENTICITY CHECKS:")
print(f"    Findings with real line numbers: {has_line_numbers}/{total_sast}")
print(f"    Findings with rule IDs: {has_rule_ids}/{total_sast}")
print(f"    Findings with code context: {has_code_context}/{total_sast}")

# Verdict
real_signal = has_line_numbers > 0 and has_rule_ids > 0
if total_sast == 0:
    verdict = "FAIL — No SAST findings detected from known-vulnerable code"
elif not real_signal:
    verdict = "FAIL — Findings lack line numbers or rule IDs (possible hardcoding)"
elif total_sast < 3:
    verdict = "PARTIAL — Too few findings for files with known vulns"
else:
    verdict = "PASS — Real findings with contextual metadata detected"

print(f"\n  VERDICT: {verdict}")

results["kpis"] = {
    "total_findings": total_all,
    "sast_findings": total_sast,
    "secrets_findings": total_secrets,
    "severities": sevs,
    "authenticity": {
        "has_line_numbers": has_line_numbers,
        "has_rule_ids": has_rule_ids,
        "has_code_context": has_code_context,
    },
    "verdict": verdict,
}
results["end_time"] = datetime.now(timezone.utc).isoformat()

# Save full results
out_file = OUT / f"{results['run_id']}.json"
with open(out_file, "w") as f:
    json.dump(results, f, indent=2, default=str)
print(f"\n  Full results saved: {out_file}")

print(f"\n{'='*60}")
print(f"  E2E TEST COMPLETE — {verdict}")
print(f"{'='*60}")
