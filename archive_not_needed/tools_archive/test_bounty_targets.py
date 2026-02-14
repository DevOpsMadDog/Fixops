#!/usr/bin/env python3
"""Test major bug bounty targets with ALdeci micropentest engine."""
import requests
import json
import time
import sys
import os

BASE = "http://localhost:8000"
HEADERS = {"X-API-Key": "test-token-123", "Content-Type": "application/json"}
RESULTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_bounty_results")
os.makedirs(RESULTS_DIR, exist_ok=True)

# Major bug bounty platforms and their public-facing domains
TARGETS = [
    {"name": "HackerOne", "url": "https://www.hackerone.com"},
    {"name": "Bugcrowd", "url": "https://www.bugcrowd.com"},
    {"name": "Intigriti", "url": "https://www.intigriti.com"},
    {"name": "YesWeHack", "url": "https://www.yeswehack.com"},
    {"name": "OpenBugBounty", "url": "https://www.openbugbounty.org"},
]

def run_pentest(target_name, target_url):
    """Run micropentest against a single target."""
    print(f"\n{'='*60}")
    print(f"  SCANNING: {target_name} ({target_url})")
    print(f"{'='*60}")
    
    payload = {
        "cve_ids": [],
        "target_urls": [target_url],
        "context": {"scan_type": "advanced", "environment": "production"},
    }
    
    t0 = time.time()
    try:
        resp = requests.post(
            f"{BASE}/api/v1/micro-pentest/run",
            json=payload,
            headers=HEADERS,
            timeout=120,
        )
        elapsed = time.time() - t0
        
        if resp.status_code in (200, 201):
            data = resp.json()
            # Save full result
            safe_name = target_name.lower().replace(" ", "_")
            with open(os.path.join(RESULTS_DIR, f"{safe_name}.json"), "w") as f:
                json.dump(data, f, indent=2, default=str)
            
            # Extract summary
            findings = data.get("findings", [])
            cve_results = data.get("cve_results", [])
            risk = data.get("scan_metadata", {}).get("risk_score", {})
            
            vuln_verified = [c for c in cve_results if c.get("verdict") == "VULNERABLE_VERIFIED"]
            high_crit = [f for f in findings if f.get("severity") in ("critical", "high")]
            
            print(f"  Time: {elapsed:.1f}s")
            print(f"  Status: {data.get('status')}")
            print(f"  Risk Score: {risk.get('score', 'N/A')}/10 ({risk.get('level', 'N/A')})")
            print(f"  Total Findings: {len(findings)}")
            print(f"  Critical+High: {len(high_crit)}")
            print(f"  Verified Exploits: {len(vuln_verified)}")
            
            if vuln_verified:
                for v in vuln_verified:
                    print(f"    ** VULN: {v.get('cve_id')} - {v.get('title','?')}")
                    print(f"       Confidence: {v.get('confidence_score','?')}%")
                    print(f"       CVSS: {v.get('cvss_score','?')}")
            
            if high_crit:
                print(f"  High/Critical findings:")
                for f in high_crit:
                    print(f"    - [{f.get('severity','?').upper()}] {f.get('title','?')}")
            
            return {
                "target": target_name,
                "url": target_url,
                "time": round(elapsed, 1),
                "status": data.get("status"),
                "risk_score": risk.get("score"),
                "risk_level": risk.get("level"),
                "total_findings": len(findings),
                "critical_high": len(high_crit),
                "verified_exploits": len(vuln_verified),
                "vuln_details": [{"id": v.get("cve_id"), "title": v.get("title"), "conf": v.get("confidence_score")} for v in vuln_verified],
            }
        else:
            print(f"  ERROR: HTTP {resp.status_code} - {resp.text[:200]}")
            return {"target": target_name, "url": target_url, "error": f"HTTP {resp.status_code}"}
    except Exception as e:
        elapsed = time.time() - t0
        print(f"  ERROR after {elapsed:.1f}s: {e}")
        return {"target": target_name, "url": target_url, "error": str(e)}

def main():
    # First check health
    try:
        h = requests.get(f"{BASE}/api/v1/health", timeout=5)
        print(f"Backend health: HTTP {h.status_code}")
    except Exception as e:
        print(f"Backend NOT reachable: {e}")
        sys.exit(1)
    
    print(f"\nTesting {len(TARGETS)} major bug bounty platforms...")
    print(f"Results will be saved to: {RESULTS_DIR}/")
    
    all_results = []
    for t in TARGETS:
        result = run_pentest(t["name"], t["url"])
        all_results.append(result)
    
    # Save summary
    with open(os.path.join(RESULTS_DIR, "_summary.json"), "w") as f:
        json.dump(all_results, f, indent=2, default=str)
    
    # Print summary table
    print(f"\n{'='*80}")
    print(f"  SUMMARY - Bug Bounty Platform Security Scan Results")
    print(f"{'='*80}")
    print(f"{'Target':<20} {'Risk':>6} {'Findings':>9} {'Crit+High':>10} {'Exploits':>9} {'Time':>7}")
    print(f"{'-'*20} {'-'*6} {'-'*9} {'-'*10} {'-'*9} {'-'*7}")
    for r in all_results:
        if "error" in r:
            print(f"{r['target']:<20} {'ERR':>6} {'-':>9} {'-':>10} {'-':>9} {'-':>7}")
        else:
            print(f"{r['target']:<20} {r.get('risk_score','?'):>6} {r['total_findings']:>9} {r['critical_high']:>10} {r['verified_exploits']:>9} {r['time']:>6.1f}s")
    
    print(f"\nDetailed results saved to {RESULTS_DIR}/")

if __name__ == "__main__":
    main()

