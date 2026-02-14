#!/usr/bin/env python3
"""Inspect pentest report data structure for report enhancement."""
import json

with open(".fixops_data/pentest_report_data.json") as f:
    d = json.load(f)

m = d["scan_metadata"]

print("=== TOP-LEVEL KEYS ===")
for k in sorted(d.keys()):
    v = d[k]
    if isinstance(v, list):
        print(f"  {k}: list[{len(v)}]")
    elif isinstance(v, dict):
        print(f"  {k}: dict keys={list(v.keys())[:15]}")
    else:
        print(f"  {k}: {type(v).__name__} = {str(v)[:80]}")

print("\n=== SCAN_METADATA KEYS ===")
for k in sorted(m.keys()):
    v = m[k]
    if isinstance(v, list):
        print(f"  {k}: list[{len(v)}]")
    elif isinstance(v, dict):
        print(f"  {k}: dict keys={list(v.keys())[:15]}")
    else:
        print(f"  {k}: {type(v).__name__} = {str(v)[:80]}")

print("\n=== SAMPLE VERIFIED EXPLOIT ===")
for r in d.get("cve_results", []):
    if r.get("finding_type") == "verified_exploit":
        print(json.dumps(r, indent=2, default=str)[:800])
        break

print("\n=== SAMPLE UNVERIFIED CVE ===")
for r in d.get("cve_results", []):
    if r.get("verdict") == "UNVERIFIED":
        print(json.dumps(r, indent=2, default=str)[:600])
        break

print("\n=== SAMPLE NOT_APPLICABLE CVE ===")
for r in d.get("cve_results", []):
    if r.get("verdict") == "NOT_APPLICABLE":
        print(json.dumps(r, indent=2, default=str)[:600])
        break

print("\n=== SAMPLE FINDING ===")
for f in d.get("findings", [])[:1]:
    print(json.dumps(f, indent=2, default=str)[:600])

print("\n=== POC COMMANDS ===")
for p in m.get("poc_commands", []):
    print(json.dumps(p, indent=2)[:400])
    print("---")

print("\n=== SCAN CONFIG ===")
for k in ["targets_scanned", "cves_tested", "scan_duration_seconds", "engine",
           "ai_powered", "total_findings", "total_cve_tests"]:
    print(f"  {k}: {m.get(k)}")

print("\n=== AI ANALYSIS KEYS ===")
ai = m.get("ai_analysis", {})
for k in sorted(ai.keys()):
    v = ai[k]
    if isinstance(v, list):
        print(f"  {k}: list[{len(v)}]")
    elif isinstance(v, dict):
        print(f"  {k}: dict keys={list(v.keys())[:10]}")
    else:
        print(f"  {k}: {str(v)[:80]}")

print("\n=== FINDING TYPES ===")
types = set()
for f in d.get("findings", []):
    types.add(f.get("vulnerability_type", "?"))
for t in sorted(types):
    print(f"  {t}")

print("\n=== FINDING SEVERITIES ===")
sevs = {}
for f in d.get("findings", []):
    s = f.get("severity", "unknown")
    sevs[s] = sevs.get(s, 0) + 1
for s, c in sorted(sevs.items()):
    print(f"  {s}: {c}")

