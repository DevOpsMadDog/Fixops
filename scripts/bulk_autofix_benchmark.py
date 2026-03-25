#!/usr/bin/env python3
"""Bulk AutoFix benchmark against real CVEs from Juice Shop scans."""
import json
import urllib.request

API = "http://localhost:8000/api/v1/autofix/generate/bulk"
KEY = "fixops_ent_38wJA8mb7CsbJ3PaLvKNz7lFnLWvFWXti_5NcdISXSogi_4grP24NAe_XymVfps_"

findings = [
    {"id": "trivy-CVE-2023-46233", "title": "CVE-2023-46233: crypto-js PBKDF2 weakness",
     "severity": "critical", "cve_ids": ["CVE-2023-46233"], "cwe_id": "CWE-327",
     "source": "trivy", "description": "crypto-js PBKDF2 1000 iterations is weak"},
    {"id": "trivy-CVE-2015-9235", "title": "CVE-2015-9235: jsonwebtoken bypass",
     "severity": "critical", "cve_ids": ["CVE-2015-9235"], "cwe_id": "CWE-287",
     "source": "trivy", "description": "jsonwebtoken allows bypass via none algorithm"},
    {"id": "semgrep-eval-001", "title": "eval-detected: Detected eval usage",
     "severity": "error", "cve_ids": [], "cwe_id": "CWE-94",
     "source": "semgrep", "file_path": "/src/lib/utils.ts",
     "description": "Use of eval can lead to code injection"},
    {"id": "semgrep-xss-001", "title": "insecure-document-method: innerHTML XSS",
     "severity": "warning", "cve_ids": [], "cwe_id": "CWE-79",
     "source": "semgrep", "file_path": "/src/views/search.html",
     "description": "Setting innerHTML with user input leads to XSS"},
    {"id": "trivy-CVE-2024-4068", "title": "CVE-2024-4068: braces ReDoS",
     "severity": "high", "cve_ids": ["CVE-2024-4068"],
     "source": "trivy", "description": "braces package fails to limit chars causing memory exhaustion"},
]

data = json.dumps({"findings": findings}).encode()
req = urllib.request.Request(
    API, data=data,
    headers={"X-API-Key": KEY, "Content-Type": "application/json"}
)

print("=== BULK AUTOFIX BENCHMARK: 5 Real CVEs/SAST Findings ===\n")
try:
    resp = urllib.request.urlopen(req, timeout=120)
    d = json.loads(resp.read())
except Exception as e:
    print(f"ERROR: {e}")
    raise

print(f"Status: {d.get('status')}")
print(f"Total fixes generated: {d.get('count')}")

for i, f in enumerate(d.get("fixes", [])):
    print(f"\n--- Fix {i+1} ---")
    print(f"  Finding: {f.get('finding_title', '')[:80]}")
    print(f"  Type: {f.get('fix_type')} | Confidence: {f.get('confidence')} ({f.get('confidence_score', 0)*100:.0f}%)")
    print(f"  CVEs: {f.get('cve_ids')} | MITRE: {f.get('mitre_techniques')}")
    print(f"  Compliance: {f.get('compliance_frameworks')}")
    print(f"  Patches: {len(f.get('code_patches', []))} | Dep fixes: {len(f.get('dependency_fixes', []))}")
    print(f"  Effort: {f.get('effort_minutes')} min | Status: {f.get('status')}")
    meta = f.get("metadata", {})
    if meta.get("template_based"):
        print(f"  Mode: DETERMINISTIC (template CWE: {meta.get('template_cwe')})")
    ml = meta.get("ml_confidence", {})
    if ml:
        print(f"  ML Score: {ml.get('confidence_score', 0):.1f}% | Rec: {ml.get('recommendation', '')[:70]}")

errors = d.get("errors", [])
if errors:
    print(f"\n--- Errors ({len(errors)}) ---")
    for e in errors:
        print(f"  {e}")

print("\n=== BENCHMARK COMPLETE ===")

