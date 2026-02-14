#!/usr/bin/env python3
"""Audit the pentest report data for accuracy issues."""
import json

with open(".fixops_data/pentest_report_data.json") as f:
    data = json.load(f)

print("=== EXECUTIVE SUMMARY ===")
summary = data.get("executive_summary", {})
print(json.dumps(summary, indent=2, default=str)[:3000])

print("\n=== RISK ASSESSMENT ===")
risk = data.get("risk_assessment", {})
print(json.dumps(risk, indent=2, default=str)[:1500])

print("\n=== COMPLIANCE ===")
compliance = data.get("compliance", {})
print(json.dumps(compliance, indent=2, default=str)[:1500])

print("\n=== FALSE POSITIVE ANALYSIS ===")
fp = data.get("false_positive_analysis", {})
print(json.dumps(fp, indent=2, default=str)[:1500])

print("\n=== VERIFIED EXPLOITS ===")
cve_results = data.get("cve_results", [])
verified = [r for r in cve_results if r.get("finding_type") == "verified_exploit"]
for v in verified:
    cid = v.get("cve_id", "?")
    conf = v.get("confidence")
    cscore = v.get("confidence_score")
    sev = v.get("severity")
    cvss = v.get("cvss_score")
    print(f"  {cid}: confidence={conf}, confidence_score={cscore}, severity={sev}, cvss={cvss}")

print("\n=== VERDICT COUNTS ===")
meta = data.get("scan_metadata", {})
vc = meta.get("verdict_counts", {})
print(json.dumps(vc, indent=2))

print("\n=== AI ANALYSIS ===")
ai = meta.get("ai_analysis", {})
print(json.dumps(ai, indent=2, default=str)[:1500])

print("\n=== SEVERITY DISTRIBUTION ===")
sev_dist = data.get("severity_distribution", {})
print(json.dumps(sev_dist, indent=2))

print("\n=== FINDINGS SAMPLE (first 3) ===")
findings = data.get("findings", [])
for f in findings[:3]:
    print(json.dumps(f, indent=2, default=str)[:500])
    print("---")

