#!/usr/bin/env python3
"""Inspect pentest data - details."""
import json

with open(".fixops_data/pentest_report_data.json") as f:
    d = json.load(f)

m = d["scan_metadata"]

# Show all findings with their types and evidence keys
print("=== ALL FINDINGS ===")
for i, f in enumerate(d.get("findings", [])):
    ev_keys = list(f.get("evidence", {}).keys())
    print(f"  [{i}] {f.get('vulnerability_type','?')} | {f.get('severity','?')} | {f.get('target','?')}")
    print(f"       title: {f.get('title','?')}")
    print(f"       evidence keys: {ev_keys}")

# Show detailed evidence for a high-severity finding
print("\n=== DETAILED HIGH FINDING ===")
for f in d.get("findings", []):
    if f.get("severity") == "high":
        print(json.dumps(f, indent=2, default=str)[:1200])
        break

# Show all verified exploits fully
print("\n=== ALL VERIFIED EXPLOITS ===")
for r in d.get("cve_results", []):
    if r.get("finding_type") == "verified_exploit":
        print(json.dumps(r, indent=2, default=str)[:1000])
        print("---")

# Show attack chains
print("\n=== ATTACK CHAINS ===")
for c in m.get("attack_chains", []):
    print(json.dumps(c, indent=2, default=str)[:500])
    print("---")

# Show AI risk assessments
print("\n=== AI RISK ASSESSMENTS (first 3) ===")
ai = m.get("ai_analysis", {})
for a in ai.get("ai_risk_assessments", [])[:3]:
    print(json.dumps(a, indent=2, default=str)[:400])
    print("---")

# Show executive summary fully
print("\n=== EXECUTIVE SUMMARY ===")
es = m.get("executive_summary", {})
print(json.dumps(es, indent=2, default=str)[:1000])

# CVE IDs and target URLs
print("\n=== CVE IDS ===")
print(d.get("cve_ids", []))
print("\n=== TARGET URLS ===")
print(d.get("target_urls", []))

