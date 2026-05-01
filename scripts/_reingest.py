#!/usr/bin/env python3
"""
Collect all self-scan findings and re-ingest into ALDECI brain
with retry-on-429 backoff.  Standalone — no imports from self_security_scan.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
import urllib.error
import urllib.request

BASE_URL = "http://localhost:8000"
API_KEY  = os.environ.get("FIXOPS_API_KEY", "")  # set via env; do NOT hardcode
ORG_ID   = "aldeci-self"
ROOT     = Path("/Users/devops.ai/fixops/Fixops")

HEADERS  = {
    "X-API-Key": API_KEY,
    "Content-Type": "application/json",
    "X-Org-ID": ORG_ID,
}

# ---------------------------------------------------------------------------
# Re-use the scan logic by running it in dry-run mode and capturing a JSON
# dump of every finding we then re-POST with backoff.
# ---------------------------------------------------------------------------

def _http(method: str, path: str, body: Optional[dict] = None) -> dict:
    url  = BASE_URL + path
    data = json.dumps(body).encode() if body is not None else None
    req  = urllib.request.Request(url, data=data, headers=HEADERS, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            raw = r.read().decode()
            try:    return {"ok": True,  "status": r.status, "data": json.loads(raw)}
            except: return {"ok": True,  "status": r.status, "data": raw}
    except urllib.error.HTTPError as e:
        body_txt = ""
        try:    body_txt = e.read().decode()[:300]
        except: pass
        return {"ok": False, "status": e.code, "error": body_txt}
    except Exception as exc:
        return {"ok": False, "status": 0, "error": str(exc)}


# ---------------------------------------------------------------------------
# Collect findings — run the scan script with a JSON-dump patch
# ---------------------------------------------------------------------------

COLLECTOR = ROOT / "scripts" / "_findings_collector.py"

COLLECTOR_SRC = '''#!/usr/bin/env python3
"""Thin wrapper: runs all checks, dumps findings as JSON to stdout."""
import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

# Suppress interactive output from the checks
import builtins
_orig = builtins.print
builtins.print = lambda *a, **k: None

import self_security_scan as S
findings = []
findings.extend(S.check_bandit())
findings.extend(S.check_ruff())
findings.extend(S.check_hardcoded_secrets())
findings.extend(S.check_sql_injection())
findings.extend(S.check_missing_auth())
findings.extend(S.check_cors())
findings.extend(S.check_debug_mode())

builtins.print = _orig

out = []
for f in findings:
    out.append({
        "finding_id": f.finding_id[:512],
        "title":      f.title[:499],
        "severity":   f.severity.lower(),
        "source":     f"self-scan/{f.check}",
        "cwe":        f.cwe,
    })

print(json.dumps(out))
'''


def collect_findings() -> List[Dict[str, Any]]:
    COLLECTOR.write_text(COLLECTOR_SRC)
    result = subprocess.run(
        [sys.executable, str(COLLECTOR)],
        capture_output=True,
        text=True,
        timeout=300,
        cwd=str(ROOT / "scripts"),
        env={**os.environ, "SELF_SCAN_DRY_RUN": "1",
             "ALDECI_API_KEY": API_KEY, "ALDECI_ORG_ID": ORG_ID},
    )
    if result.returncode != 0 and not result.stdout.strip():
        print(f"Collector stderr:\n{result.stderr[:500]}", file=sys.stderr)
        sys.exit(1)
    return json.loads(result.stdout.strip())


# ---------------------------------------------------------------------------
# Ingest with retry
# ---------------------------------------------------------------------------

def ingest(findings: List[Dict[str, Any]]) -> None:
    total  = len(findings)
    ok = fail = 0
    INTER  = 0.25   # 250 ms between posts
    RETRY_WAITS = [1, 2, 4, 8, 16]

    print(f"Ingesting {total} findings into {BASE_URL} (org={ORG_ID}) ...")

    for i, f in enumerate(findings):
        payload = {
            "finding_id": f["finding_id"],
            "org_id":     ORG_ID,
            "title":      f["title"],
            "severity":   f["severity"],
            "source":     f["source"],
        }
        if f.get("cwe", "").startswith("CVE-"):
            payload["cve_id"] = f["cwe"]

        posted = False
        for attempt, wait in enumerate(RETRY_WAITS):
            res = _http("POST", "/api/v1/brain/ingest/finding", payload)
            if res["ok"]:
                ok += 1
                posted = True
                break
            elif res["status"] == 429:
                time.sleep(wait)
            else:
                print(f"  FAIL [{res['status']}] {res.get('error','')[:80]}")
                fail += 1
                posted = True   # won't retry non-429 errors
                break

        if not posted:
            fail += 1

        time.sleep(INTER)

        if (i + 1) % 200 == 0 or (i + 1) == total:
            pct = (i + 1) / total * 100
            print(f"  [{pct:5.1f}%] {i+1}/{total}  ok={ok}  fail={fail}")

    print(f"\nDone — ingested={ok}  failed={fail}  total={total}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("Step 1: collecting findings (dry-run scan) ...")
    findings = collect_findings()
    print(f"  Collected {len(findings)} findings\n")

    print("Step 2: ingesting with backoff ...")
    ingest(findings)

    print("\nStep 3: brain stats")
    stats = _http("GET", "/api/v1/brain/stats")
    print(json.dumps(stats.get("data", {}), indent=2))

    # Cleanup helper files
    COLLECTOR.unlink(missing_ok=True)
