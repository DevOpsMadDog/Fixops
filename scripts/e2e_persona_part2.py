#!/usr/bin/env python3
"""E2E Persona Steps 6-10: AutoFix, Evidence, Risk, Brain Pipeline, Compliance"""
import json
import requests
import time

API_KEY = "fixops_ent_38wJA8mb7CsbJ3PaLvKNz7lFnLWvFWXti_5NcdISXSogi_4grP24NAe_XymVfps_"
BASE = "http://localhost:8000"
H = {"X-API-Key": API_KEY, "Content-Type": "application/json"}

def section(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")

# Read actual SQL injection line from Juice Shop
with open("/tmp/juiceshop-test/routes/login.ts") as f:
    login_code = f.read()
sqli_lines = [l.strip() for l in login_code.split("\n") if "sequelize.query" in l]
snippet = sqli_lines[0] if sqli_lines else "sequelize.query with string concat"

# --- AutoFix ---
section("PERSONA: Tech Lead - AutoFix Generate for SQL Injection")
time.sleep(2)
r = requests.post(f"{BASE}/api/v1/autofix/generate", headers=H, json={
    "finding_id": "sast-juice-login-sqli",
    "finding": {
        "title": "SQL Injection via string concatenation in login query",
        "severity": "CRITICAL",
        "file": "routes/login.ts",
        "line": 34,
        "code_snippet": snippet[:500],
        "rule_id": "SAST-043",
        "language": "typescript",
    },
    "mode": "recommend",
}, timeout=30)
print(f"AutoFix Generate: HTTP {r.status_code}")
print(json.dumps(r.json(), indent=2)[:1500])

# --- MPTE Comprehensive ---
section("PERSONA: AppSec - MPTE Comprehensive Scan")
time.sleep(3)
r = requests.post(f"{BASE}/api/v1/mpte/scan/comprehensive", headers=H, json={
    "target": "http://localhost:3000",
    "scan_type": "passive",
}, timeout=30)
print(f"MPTE Scan: HTTP {r.status_code}")
print(json.dumps(r.json(), indent=2)[:1500])

# --- Evidence ---
section("PERSONA: GRC Analyst - Evidence Generation")
time.sleep(3)
r = requests.post(f"{BASE}/api/v1/brain/evidence/generate", headers=H, json={
    "app_id": "juice-shop",
    "include": ["findings", "mpte", "autofix", "policy", "timeline"],
}, timeout=30)
print(f"Evidence Generate: HTTP {r.status_code}")
print(json.dumps(r.json(), indent=2)[:1500])

# --- Evidence Packs ---
section("PERSONA: GRC - Evidence Packs List")
time.sleep(3)
r = requests.get(f"{BASE}/api/v1/brain/evidence/packs", headers=H, timeout=30)
print(f"Evidence Packs: HTTP {r.status_code}")
data = r.json()
packs = data.get("packs", data.get("items", []))
print(f"Total packs: {len(packs)}")
for p in packs[:5]:
    pid = p.get("id", p.get("pack_id", "?"))
    status = p.get("status", "?")
    created = p.get("created_at", "?")
    print(f"  {pid}: {status} ({created})")

# --- Risk ---
section("PERSONA: CISO - Risk Overview")
time.sleep(3)
r = requests.get(f"{BASE}/api/v1/risk/overview", headers=H, timeout=30)
print(f"Risk Overview: HTTP {r.status_code}")
print(json.dumps(r.json(), indent=2)[:800])

# --- Top Risks ---
section("PERSONA: CISO - Top Risks Dashboard")
time.sleep(3)
r = requests.get(f"{BASE}/api/v1/analytics/dashboard/top-risks", headers=H, timeout=30)
print(f"Top Risks: HTTP {r.status_code}")
print(json.dumps(r.json(), indent=2)[:800])

# --- Brain Pipeline ---
section("PERSONA: Platform Engineer - Brain Pipeline Run")
time.sleep(3)
r = requests.post(f"{BASE}/api/v1/brain/pipeline/run", headers=H, json={
    "app_id": "juice-shop",
    "mode": "full",
}, timeout=60)
print(f"Pipeline Run: HTTP {r.status_code}")
print(json.dumps(r.json(), indent=2)[:1500])

# --- Brain Stats ---
section("PERSONA: Platform Engineer - Brain Stats")
time.sleep(3)
r = requests.get(f"{BASE}/api/v1/brain/stats", headers=H, timeout=30)
print(f"Brain Stats: HTTP {r.status_code}")
print(json.dumps(r.json(), indent=2)[:800])

# --- Compliance Frameworks ---
section("PERSONA: Compliance Manager - Frameworks")
time.sleep(3)
r = requests.get(f"{BASE}/api/v1/compliance-engine/frameworks", headers=H, timeout=30)
print(f"Frameworks: HTTP {r.status_code}")
print(json.dumps(r.json(), indent=2)[:800])

print("\n" + "=" * 60)
print("  ALL PERSONA STEPS COMPLETE")
print("=" * 60)
