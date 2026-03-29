#!/usr/bin/env python3
"""Test P1: Real-World Compliance — verify dynamic control derivation."""
import json, urllib.request

API = "http://localhost:8000/api/v1"
import os
TOKEN = os.environ.get("FIXOPS_API_TOKEN", "fixops_ent_38wJA8mb7CsbJ3PaLvKNz7lFnLWvFWXti_5NcdISXSogi_4grP24NAe_XymVfps_")
HDR = {"Content-Type": "application/json", "X-API-Key": TOKEN}

def post(path, body):
    req = urllib.request.Request(f"{API}{path}", data=json.dumps(body).encode(), headers=HDR, method="POST")
    return json.loads(urllib.request.urlopen(req, timeout=30).read())

def get(path):
    req = urllib.request.Request(f"{API}{path}", headers=HDR)
    return json.loads(urllib.request.urlopen(req, timeout=30).read())

# --- Step 1: Ingest findings via SARIF ---
trivy = {"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Trivy","version":"0.50.0","rules":[
    {"id":"CVE-2023-46233","shortDescription":{"text":"crypto weakness"},"properties":{"precision":"very-high","security-severity":"9.1"}},
    {"id":"CVE-2015-9235","shortDescription":{"text":"JWT none algorithm"},"properties":{"precision":"very-high","security-severity":"9.8"}},
    {"id":"CVE-2024-4068","shortDescription":{"text":"braces ReDoS"},"properties":{"precision":"high","security-severity":"7.5"}},
]}},"results":[
    {"ruleId":"CVE-2023-46233","level":"error","message":{"text":"Insecure encryption algorithm in crossenv"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"package-lock.json"},"region":{"startLine":100}}}]},
    {"ruleId":"CVE-2015-9235","level":"error","message":{"text":"JWT algorithm bypass via none algorithm"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"package-lock.json"},"region":{"startLine":200}}}]},
    {"ruleId":"CVE-2024-4068","level":"warning","message":{"text":"ReDoS in braces package"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"package-lock.json"},"region":{"startLine":300}}}]},
]}]}

semgrep = {"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Semgrep","version":"1.60.0","rules":[
    {"id":"dom-xss","shortDescription":{"text":"DOM XSS via innerHTML"},"properties":{"precision":"high","security-severity":"8.0"}},
    {"id":"eval-detected","shortDescription":{"text":"eval() detected"},"properties":{"precision":"high","security-severity":"8.5"}},
]}},"results":[
    {"ruleId":"dom-xss","level":"error","message":{"text":"DOM XSS: innerHTML with user input"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/Dashboard.tsx"},"region":{"startLine":42}}}]},
    {"ruleId":"eval-detected","level":"error","message":{"text":"Dangerous eval() with user input"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"api/utils.py"},"region":{"startLine":15}}}]},
]}]}

r1 = post("/scanner-ingest/webhook/trivy?pipeline=true", trivy)
print(f"Trivy ingest: {r1.get('findings_count', r1.get('total_findings', 0))} findings")

r2 = post("/scanner-ingest/webhook/semgrep?pipeline=true", semgrep)
print(f"Semgrep ingest: {r2.get('findings_count', r2.get('total_findings', 0))} findings")

# --- Step 2: SOC2 compliance bundle ---
soc2 = post("/evidence/export", {"framework": "SOC2", "period_days": 90, "sign": True})
print(f"\n=== SOC2 Evidence Bundle ===")
print(f"Bundle ID: {soc2.get('bundle_id')}")
engine = soc2.get("metadata", {}).get("compliance_engine", "?")
print(f"Engine: {engine}")
print(f"Signed: {soc2.get('signed')}")
print(f"Controls: {len(soc2.get('controls', []))}")
posture = soc2.get("posture", {})
print(f"Compliance %: {posture.get('compliance_percentage')}")
print(f"Data source: {posture.get('data_source', 'N/A')}")
print(f"Findings analysed: {posture.get('total_findings_analysed', 'N/A')}")
print(f"Gaps: {len(soc2.get('gaps', []))}")

for c in soc2.get("controls", []):
    fc = c.get("finding_count", 0)
    sd = c.get("severity_distribution", {})
    ev = len(c.get("evidence_items", []))
    print(f"  {c['control_id']}: {c['status']} | findings={fc} sev={sd} evidence={ev}")

# --- Step 3: PCI-DSS ---
pci = post("/evidence/export", {"framework": "PCI-DSS", "period_days": 90, "sign": True})
print(f"\n=== PCI-DSS Evidence Bundle ===")
print(f"Engine: {pci.get('metadata', {}).get('compliance_engine', '?')}")
print(f"Controls: {len(pci.get('controls', []))}")
print(f"Compliance %: {pci.get('posture', {}).get('compliance_percentage')}")
for c in pci.get("controls", []):
    print(f"  {c['control_id']}: {c['status']} | findings={c.get('finding_count',0)}")

# --- Assertions ---
ok = True
if engine != "dynamic_findings_mapper":
    print(f"\nFAIL: Expected dynamic_findings_mapper, got {engine}")
    ok = False
if not soc2.get("controls"):
    print("\nFAIL: No controls in SOC2 bundle")
    ok = False
else:
    has_findings = any(c.get("finding_count", 0) > 0 for c in soc2["controls"])
    if not has_findings:
        print("\nFAIL: No controls have finding_count > 0")
        ok = False
    has_dynamic_status = any(c["status"] != "satisfied" for c in soc2["controls"])
    static_only = all(c["status"] == "satisfied" for c in soc2["controls"])
    if static_only and len(soc2["controls"]) > 3:
        print("\nWARN: All controls satisfied — scoring may not be dynamic")

if ok:
    print("\n=== P1 SUCCESS: Real compliance data wired ===")
else:
    print("\n=== P1 FAILED ===")

