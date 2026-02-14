#!/usr/bin/env python3
"""Run bounty scans and write results to tools/_status_result.txt"""
import requests, json, time, os, sys

BASE = "http://localhost:8000"
HEADERS = {"X-API-Key": "test-token-123", "Content-Type": "application/json"}
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_bounty_output.txt")

TARGETS = [
    ("HackerOne", "https://www.hackerone.com"),
    ("Bugcrowd", "https://www.bugcrowd.com"),
    ("Intigriti", "https://www.intigriti.com"),
    ("YesWeHack", "https://www.yeswehack.com"),
    ("OpenBugBounty", "https://www.openbugbounty.org"),
]

lines = []
def log(msg):
    lines.append(msg)
    print(msg)
    # Flush results after every target
    with open(OUT, "w") as f:
        f.write("\n".join(lines) + "\n")

def scan(name, url):
    log(f"\n{'='*60}")
    log(f"  SCANNING: {name} ({url})")
    log(f"{'='*60}")
    payload = {"cve_ids": [], "target_urls": [url], "context": {"scan_type": "advanced"}}
    t0 = time.time()
    try:
        r = requests.post(f"{BASE}/api/v1/micro-pentest/run", json=payload, headers=HEADERS, timeout=180)
        dt = time.time() - t0
        if r.status_code in (200, 201):
            d = r.json()
            findings = d.get("findings", [])
            cves = d.get("cve_results", [])
            risk = d.get("scan_metadata", {}).get("risk_score", {})
            verified = [c for c in cves if c.get("verdict") == "VULNERABLE_VERIFIED"]
            hicrit = [f for f in findings if f.get("severity") in ("critical", "high")]
            log(f"  Time: {dt:.1f}s | Status: {d.get('status')}")
            log(f"  Risk: {risk.get('score','?')}/10 ({risk.get('level','?')})")
            log(f"  Findings: {len(findings)} | Crit+High: {len(hicrit)} | Verified Exploits: {len(verified)}")
            for v in verified:
                log(f"    ** VULN: {v.get('cve_id')} - {v.get('title','?')} (conf: {v.get('confidence_score','?')}%)")
            for f in hicrit:
                log(f"    - [{f.get('severity','?').upper()}] {f.get('title','?')}")
            # Save full JSON
            jpath = os.path.join(os.path.dirname(OUT), f"_bounty_{name.lower().replace(' ','_')}.json")
            with open(jpath, "w") as jf:
                json.dump(d, jf, indent=2, default=str)
            return {"name": name, "risk": risk.get("score"), "findings": len(findings), "hicrit": len(hicrit), "exploits": len(verified), "time": round(dt, 1)}
        else:
            log(f"  ERROR: HTTP {r.status_code} - {r.text[:200]}")
            return {"name": name, "error": f"HTTP {r.status_code}"}
    except Exception as e:
        log(f"  ERROR: {e}")
        return {"name": name, "error": str(e)}

def main():
    try:
        h = requests.get(f"{BASE}/api/v1/health", timeout=5)
        log(f"Backend: HTTP {h.status_code}")
    except:
        log("Backend DOWN"); sys.exit(1)
    
    log(f"\nScanning {len(TARGETS)} major bug bounty platforms...")
    results = []
    for name, url in TARGETS:
        results.append(scan(name, url))
    
    log(f"\n{'='*80}")
    log(f"  SUMMARY")
    log(f"{'='*80}")
    log(f"{'Target':<20} {'Risk':>6} {'Finds':>6} {'Hi/Cr':>6} {'Expl':>5} {'Time':>7}")
    log(f"{'-'*20} {'-'*6} {'-'*6} {'-'*6} {'-'*5} {'-'*7}")
    for r in results:
        if "error" in r:
            log(f"{r['name']:<20} {'ERR':>6}")
        else:
            log(f"{r['name']:<20} {r['risk']:>6} {r['findings']:>6} {r['hicrit']:>6} {r['exploits']:>5} {r['time']:>6.1f}s")
    log("DONE")

if __name__ == "__main__":
    main()

