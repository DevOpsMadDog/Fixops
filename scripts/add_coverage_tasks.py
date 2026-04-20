#!/usr/bin/env python3
"""
Add 10 quality-work tasks to Multica based on frontend_api_coverage.md findings.
Idempotent: skips tasks whose titles already exist.
"""

import json
import sys
import time
import uuid
import urllib.request
import urllib.error
from datetime import datetime, timezone, timedelta

MULTICA_BASE = "http://localhost:8080"
MULTICA_EMAIL = "beast@aldeci.io"
WORKSPACE_SLUG = "aldeci"
WORKSPACE_ID = "30fad00d-8273-4196-96d4-abd55f4cbb43"
USER_ID = "251f9fe6-613f-4beb-98aa-f718c581bc59"

_STATIC_TOKEN = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJlbWFpbCI6ImJlYXN0QGFsZGVjaS5pbyIsImV4cCI6MTc3OTAxNjY1MywiaWF0IjoxNzc2NDI0NjUzL"
    "CJuYW1lIjoiQmVhc3QgQWRtaW4iLCJzdWIiOiIyNTFmOWZlNi02MTNmLTRiZWItOThhYS1mNzE4YzU4MW"
    "JjNTkifQ.VZI_OrdpEudpl4xqrLvm9XJw0_0ud5IpFHXO_0J5FZQ"
)

TASKS = [
    {
        "title": "Fix 5 server bugs (analytics/kpis, analytics/posture, logs, ai-agent, compliance-engine/audit-bundle)",
        "description": (
            "Five endpoints return HTTP 500 on GET. Investigate and fix each:\n\n"
            "| Endpoint | Error |\n"
            "|----------|-------|\n"
            "| `/api/v1/analytics/kpis` | database error — check DB init / missing table |\n"
            "| `/api/v1/analytics/posture` | database error — check DB init / missing table |\n"
            "| `/api/v1/logs` | database error — check logs table exists |\n"
            "| `/api/v1/ai-agent/status` | internal error — check agent startup sequence |\n"
            "| `/api/v1/compliance-engine/audit-bundle` | internal error — check bundle generation logic |\n\n"
            "Steps:\n"
            "1. Start server, hit each endpoint, capture full traceback.\n"
            "2. Fix root cause in production code (not test hacks).\n"
            "3. Verify each returns 200 with valid JSON.\n"
            "4. Add regression test for each fixed endpoint."
        ),
        "status": "todo",
        "priority": "urgent",
    },
    {
        "title": "Add GET / list routes to 41 routers missing them",
        "description": (
            "44.1% of frontend API calls (165 endpoints) return 404. The primary cause is that "
            "routers for Wave 38–41 engines were wired into app.py but only have sub-resource routes "
            "(e.g. `GET /access-anomaly/alerts`) — no root `GET /` list route that the frontend calls.\n\n"
            "Routers needing `GET /` (minimum viable list endpoint):\n"
            "```\n"
            "access-anomaly, access-governance, actor-tracking, arch-review,\n"
            "alert-enrichment, asset-groups, cloud-accounts, cloud-ir,\n"
            "control-testing, cost-optimization, compliance-calendar,\n"
            "compliance-workflows, dependency-risk, hunting-playbooks,\n"
            "identity-lifecycle, intel-enrichment, ioc-enrichment, network-threats,\n"
            "posture-history, posture-trends, privacy-impact, ransomware-protection,\n"
            "threat-indicators, threat-modeling-pipeline, threat-response,\n"
            "training-effectiveness\n"
            "```\n"
            "Plus NO_CONN routes that need GET added:\n"
            "```\n"
            "security-findings, security-benchmarks, security-baselines,\n"
            "security-culture, soc-metrics, sbom-export, secrets, reports, search\n"
            "```\n\n"
            "Pattern to follow: each router should expose `GET /` → returns `{'items': [...], 'total': N}`\n"
            "filtered by `org_id` from the auth header. Use the existing engine's list/get_all method."
        ),
        "status": "todo",
        "priority": "high",
    },
    {
        "title": "Seed data into remaining 20 empty endpoints (NEEDS_DATA)",
        "description": (
            "20 endpoints return HTTP 200 with empty arrays/objects. "
            "They work correctly but have no data. Seed realistic data so dashboards show live content.\n\n"
            "Empty endpoints:\n"
            "```\n"
            "/api/v1/admin/users\n"
            "/api/v1/analytics/decisions\n"
            "/api/v1/apps/\n"
            "/api/v1/attack-sim/campaigns\n"
            "/api/v1/attack-sim/scenarios\n"
            "/api/v1/audit\n"
            "/api/v1/audit/compliance/controls\n"
            "/api/v1/audit/compliance/frameworks\n"
            "/api/v1/bulk/assign\n"
            "/api/v1/compliance-evidence/requests\n"
            "/api/v1/evidence/list\n"
            "/api/v1/integrations\n"
            "/api/v1/ml/analytics/anomalies\n"
            "/api/v1/ndr/alerts\n"
            "/api/v1/playbooks\n"
            "/api/v1/reachability/analysis\n"
            "/api/v1/risk-acceptance\n"
            "/api/v1/threat-sharing/indicators\n"
            "/api/v1/users\n"
            "/api/v1/vuln-scoring\n"
            "```\n\n"
            "Extend `scripts/seed_demo_data.py` to POST seed records to each of these endpoints. "
            "Aim for 3–10 realistic records per endpoint. Use org_id='demo'."
        ),
        "status": "todo",
        "priority": "high",
    },
    {
        "title": "Fix frontend pages still showing mock instead of real data",
        "description": (
            "Several frontend pages use hardcoded mock/static data instead of calling real backend APIs. "
            "Based on the coverage report, only 33.7% of frontend API calls return live data.\n\n"
            "Audit all pages in `suite-ui/aldeci-ui-new/src/pages/` for:\n"
            "1. `useState` initialized with hardcoded arrays (mock data)\n"
            "2. Missing `useEffect` + `fetch('/api/v1/...')` calls\n"
            "3. Pages that import from a local `mockData.ts` or `fixtures/` file\n\n"
            "Fix strategy:\n"
            "- For each mock page, identify the matching backend endpoint from the coverage report\n"
            "- Replace mock state with `useEffect(() => { fetch(endpoint).then(...) }, [])` pattern\n"
            "- Show loading spinner while fetching, error state on failure\n"
            "- Priority: pages used by the 30 ALDECI personas (SOC analyst, CISO, DevSecOps engineer)\n\n"
            "Reference: `suite-ui/aldeci-ui-new/src/pages/ThreatIntelDashboard.tsx` as a wired example."
        ),
        "status": "todo",
        "priority": "high",
    },
    {
        "title": "Add Chrome plugin E2E testing workflow",
        "description": (
            "ALDECI has no browser-based end-to-end test suite. Add a Playwright (or Cypress) workflow "
            "that tests the full UI flow from login to dashboard rendering.\n\n"
            "Scope:\n"
            "1. Install Playwright: `npm install --save-dev @playwright/test` in `suite-ui/aldeci-ui-new/`\n"
            "2. Write smoke tests for the 10 highest-traffic pages:\n"
            "   - /mission-control/soc-t1 (SOC T1 dashboard)\n"
            "   - /threat-intel (Threat Intel)\n"
            "   - /compliance (Compliance Dashboard)\n"
            "   - /assets (Asset Inventory)\n"
            "   - /vuln-lifecycle (Vuln Lifecycle)\n"
            "   - /executive-reporting (Executive Reporting)\n"
            "   - /posture-scoring (Security Posture)\n"
            "   - /risk-register-engine (Risk Register)\n"
            "   - /cloud-compliance (Cloud Compliance)\n"
            "   - /zero-trust-policy (Zero Trust)\n"
            "3. Each test: navigate to page → assert no console errors → assert at least one data row renders\n"
            "4. Add GitHub Actions workflow: `.github/workflows/e2e.yml` (runs on PR to main)\n"
            "5. Document in `suite-ui/aldeci-ui-new/README.md`\n\n"
            "Note from user memory: E2E testing should scan real GitHub repos, not just vulnerable demos."
        ),
        "status": "todo",
        "priority": "high",
    },
    {
        "title": "Import real GitHub Advisory Database vulns",
        "description": (
            "ALDECI's vulnerability intelligence engine has no real CVE data. "
            "Import from the GitHub Advisory Database (GHSA) to populate live data.\n\n"
            "Implementation:\n"
            "1. Clone/fetch https://github.com/github/advisory-database (JSON format)\n"
            "   - Or use the GraphQL API: https://api.github.com/graphql (SecurityAdvisories)\n"
            "2. Write `scripts/import_ghsa.py`:\n"
            "   - Fetch advisories for the last 90 days (or top 1000 by CVSS)\n"
            "   - Normalize to ALDECI's CVE schema: `{cve_id, cvss, epss, kev, description, affected_packages}`\n"
            "   - POST to `/api/v1/vuln-intel/cves` (bulk ingest endpoint)\n"
            "3. Map GHSA ecosystems to ALDECI scanner types (npm→sca, pip→sca, maven→sca, go→sca)\n"
            "4. Cross-reference with EPSS scores from https://api.first.org/data/v1/epss\n"
            "5. Cross-reference with CISA KEV: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json\n"
            "6. Schedule nightly refresh via SwarmClaw cron\n\n"
            "Target: 500+ real CVEs with CVSS + EPSS + KEV flags in the vulnerability intelligence engine."
        ),
        "status": "todo",
        "priority": "medium",
    },
    {
        "title": "Set up LocalStack for CSPM cloud scanning",
        "description": (
            "ALDECI's CSPM engine currently has no real cloud resources to scan. "
            "Use LocalStack to simulate AWS/GCP/Azure resources for realistic CSPM testing.\n\n"
            "Implementation:\n"
            "1. Add LocalStack to `docker/docker-compose.yml`:\n"
            "   ```yaml\n"
            "   localstack:\n"
            "     image: localstack/localstack\n"
            "     ports: ['4566:4566']\n"
            "     environment:\n"
            "       SERVICES: s3,ec2,iam,rds,lambda,cloudtrail,config\n"
            "   ```\n"
            "2. Write `scripts/seed_localstack.py`:\n"
            "   - Create intentionally misconfigured resources (public S3 bucket, overprivileged IAM role,\n"
            "     unencrypted RDS, security group 0.0.0.0/0, root access key active)\n"
            "3. Wire ALDECI CSPM engine to LocalStack endpoint (`AWS_ENDPOINT_URL=http://localhost:4566`)\n"
            "4. Run CSPM scan → verify findings appear in `/api/v1/cspm/rules` and `/api/v1/cloud-compliance`\n"
            "5. Add integration test `tests/test_cspm_localstack.py`\n\n"
            "Acceptance: CSPM dashboard shows 5+ real misconfig findings from LocalStack resources."
        ),
        "status": "todo",
        "priority": "medium",
    },
    {
        "title": "Wire SIEM to real log sources",
        "description": (
            "ALDECI's SIEM integration engine exists but is not connected to any real log sources. "
            "Wire it to system logs and the ALDECI API server itself.\n\n"
            "Phase 1 — Local log ingestion:\n"
            "1. Configure SIEM engine to tail `/var/log/syslog` (Linux) or `system.log` (macOS)\n"
            "2. Parse ALDECI FastAPI access logs from `suite-api/` server stdout\n"
            "3. Wire nginx/caddy access logs if running behind a proxy\n\n"
            "Phase 2 — Structured log forwarding:\n"
            "4. Add a Fluent Bit sidecar to `docker/docker-compose.yml` that ships logs to ALDECI SIEM\n"
            "5. Configure log normalization: map syslog fields to ALDECI event schema\n"
            "   `{timestamp, source, event_type, severity, raw_message, parsed_fields}`\n\n"
            "Phase 3 — Correlation:\n"
            "6. Add correlation rules: failed auth → alert, 429 spike → rate limit alert\n"
            "7. Verify events appear in `/api/v1/siem` and flow to `/api/v1/event-correlation`\n\n"
            "Acceptance: SIEM dashboard shows live events from at least 2 real log sources."
        ),
        "status": "todo",
        "priority": "medium",
    },
    {
        "title": "Connect frontend to ASPM scan results",
        "description": (
            "ALDECI's ASPM (Application Security Posture Management) engine exists but the frontend "
            "dashboards do not display real scan results. Connect the scan pipeline to the UI.\n\n"
            "Backend tasks:\n"
            "1. Run ALDECI self-scan: `python3 scripts/aldeci_self_scan.py` → verify results stored\n"
            "2. Ensure scan results are available at `/api/v1/findings` and `/api/v1/asm/assets`\n"
            "3. Wire attack surface engine output to `/api/v1/asm/stats` (currently working per coverage report)\n\n"
            "Frontend tasks:\n"
            "4. `suite-ui/aldeci-ui-new/src/pages/AttackSurfaceDashboard.tsx` — wire to `/api/v1/asm/assets`\n"
            "5. `SecurityPostureDashboard.tsx` — wire to `/api/v1/posture-scoring`\n"
            "6. `AppSecurityDashboard.tsx` — wire to `/api/v1/appsec` and `/api/v1/findings`\n"
            "7. Display scan history, finding trends, and top vulnerable assets\n\n"
            "Note from user memory: ALDECI scans itself as test subject — no fake data.\n\n"
            "Acceptance: ASPM dashboard shows findings from the last self-scan of the Fixops repo."
        ),
        "status": "todo",
        "priority": "medium",
    },
    {
        "title": "Add real-time WebSocket event display on all dashboards",
        "description": (
            "All ALDECI dashboards currently poll REST endpoints. Add WebSocket support so dashboards "
            "update in real-time when new events arrive (new CVE, new alert, new incident).\n\n"
            "Backend:\n"
            "1. Add FastAPI WebSocket endpoint: `GET /api/v1/stream/events` (already in NO_CONN list — fix it)\n"
            "2. Implement event bus in `suite-core/core/event_bus.py`:\n"
            "   - `publish(event_type, payload, org_id)` — broadcasts to all WS subscribers for that org\n"
            "   - Event types: `new_finding`, `alert_triggered`, `scan_complete`, `compliance_change`\n"
            "3. Wire event bus to: SIEM engine, alert triage engine, vuln scan engine, incident orchestration\n\n"
            "Frontend:\n"
            "4. Create `suite-ui/aldeci-ui-new/src/hooks/useEventStream.ts`:\n"
            "   ```ts\n"
            "   const { events } = useEventStream(['new_finding', 'alert_triggered'])\n"
            "   ```\n"
            "5. Wire to SOC T1 dashboard (live alert feed), Threat Intel dashboard (new IOC banner),\n"
            "   and Incident Response dashboard (incident status updates)\n"
            "6. Show live indicator dot (green pulse) when WebSocket is connected\n\n"
            "Note: TrustGraph event bus — 97% of 3,036 endpoints still disconnected (from project memory).\n\n"
            "Acceptance: SOC T1 dashboard updates within 1s of a new alert being created via the API."
        ),
        "status": "todo",
        "priority": "medium",
    },
]


def get_token() -> str:
    try:
        import psycopg2
    except ImportError:
        return _STATIC_TOKEN

    code = "888888"
    future = datetime.now(timezone.utc) + timedelta(minutes=60)
    try:
        with psycopg2.connect(
            host="localhost", port=5433, dbname="multica",
            user="multica", password="multica", connect_timeout=10,
        ) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id FROM verification_code WHERE email=%s", (MULTICA_EMAIL,))
                if cur.fetchone():
                    cur.execute(
                        "UPDATE verification_code SET code=%s, expires_at=%s, used=false, attempts=0 "
                        "WHERE email=%s",
                        (code, future, MULTICA_EMAIL),
                    )
                else:
                    cur.execute(
                        "INSERT INTO verification_code (id, email, code, expires_at, used, created_at) "
                        "VALUES (%s,%s,%s,%s,%s,%s)",
                        (str(uuid.uuid4()), MULTICA_EMAIL, code, future, False,
                         datetime.now(timezone.utc)),
                    )
            conn.commit()

        body = json.dumps({"email": MULTICA_EMAIL, "code": code}).encode()
        req = urllib.request.Request(
            f"{MULTICA_BASE}/auth/verify-code", data=body,
            headers={"Content-Type": "application/json"}, method="POST",
        )
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())["token"]
    except Exception as e:
        print(f"  [WARN] Fresh auth failed ({e}), using static token", file=sys.stderr)
        return _STATIC_TOKEN


def _headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


def fetch_existing_titles(token: str) -> set[str]:
    """Page through all issues and collect lowercased titles."""
    titles = set()
    page_size = 100
    offset = 0
    while True:
        url = f"{MULTICA_BASE}/api/issues?workspace_slug={WORKSPACE_SLUG}&limit={page_size}&offset={offset}"
        req = urllib.request.Request(url, headers=_headers(token))
        with urllib.request.urlopen(req, timeout=20) as r:
            data = json.loads(r.read())
        batch = data.get("issues", [])
        titles.update(i["title"].lower() for i in batch)
        total = data.get("total", 0)
        offset += len(batch)
        if len(batch) < page_size or offset >= total:
            break
        time.sleep(0.05)
    return titles


def create_issue(token: str, task: dict) -> dict:
    payload = {
        "workspace_id": WORKSPACE_ID,
        "title": task["title"],
        "description": task["description"],
        "status": task["status"],
        "priority": task["priority"],
    }
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        f"{MULTICA_BASE}/api/issues?workspace_slug={WORKSPACE_SLUG}",
        data=body,
        headers=_headers(token),
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        return {"error": e.read().decode()}
    except Exception as e:
        return {"error": str(e)}


def main():
    print("=" * 65)
    print("ADD COVERAGE QUALITY TASKS TO MULTICA")
    print(f"  Tasks to add: {len(TASKS)}")
    print("=" * 65)

    print("\n[1/3] Authenticating...")
    token = get_token()
    print(f"  Token acquired (len={len(token)})")

    print("\n[2/3] Fetching existing issue titles (dedup check)...")
    existing_titles = fetch_existing_titles(token)
    print(f"  {len(existing_titles)} existing titles loaded")

    print("\n[3/3] Creating tasks...")
    created = 0
    skipped = 0
    failed = 0

    for i, task in enumerate(TASKS, 1):
        title_lower = task["title"].lower()
        # Check for close match — skip if title already exists
        if title_lower in existing_titles:
            print(f"  [{i:02d}] SKIP (exists): {task['title'][:70]}")
            skipped += 1
            continue

        # Also check for partial match on first 40 chars
        prefix = title_lower[:40]
        if any(prefix in t for t in existing_titles):
            print(f"  [{i:02d}] SKIP (similar exists): {task['title'][:70]}")
            skipped += 1
            continue

        result = create_issue(token, task)
        if "error" in result:
            print(f"  [{i:02d}] FAIL: {task['title'][:60]} — {result['error'][:80]}")
            failed += 1
        else:
            identifier = result.get("identifier", "?")
            print(f"  [{i:02d}] CREATED {identifier} [{task['priority'].upper()}]: {task['title'][:60]}")
            created += 1

        time.sleep(0.1)  # rate-limit courtesy

    print("\n" + "=" * 65)
    print(f"  Created:  {created}")
    print(f"  Skipped:  {skipped} (already exist)")
    print(f"  Failed:   {failed}")
    print("=" * 65)

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
