#!/usr/bin/env python3
"""Seed MPTE pen_test_results table with realistic data."""
import json
import sys
import uuid
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
for p in ["suite-api", "suite-core", "suite-attack", "suite-feeds",
          "suite-evidence-risk", "suite-integrations"]:
    sys.path.insert(0, str(ROOT / p))

from core.mpte_db import MPTEDB
from core.mpte_models import (
    ExploitabilityLevel, PenTestConfig, PenTestPriority,
    PenTestRequest, PenTestResult, PenTestStatus,
)

db = MPTEDB()

# Clear old data
conn = db._get_connection()
conn.execute("DELETE FROM pen_test_requests")
conn.execute("DELETE FROM pen_test_results")
conn.execute("DELETE FROM pen_test_configs")
conn.commit()
conn.close()

# Real CVEs for pen test scenarios
scenarios = [
    ("CVE-2024-21626", "http://app.internal:8080/containers", "container_escape",
     "confirmed_exploitable", True, 0.95, 23.4, "critical"),
    ("CVE-2024-3094", "http://build.internal/xz-utils", "supply_chain",
     "confirmed_exploitable", True, 0.98, 45.2, "critical"),
    ("CVE-2024-4577", "http://web.internal/php-cgi", "rce",
     "confirmed_exploitable", True, 0.91, 18.7, "high"),
    ("CVE-2024-1709", "http://connect.internal:8443", "auth_bypass",
     "likely_exploitable", False, 0.72, 31.5, "high"),
    ("CVE-2024-27198", "http://teamcity.internal", "auth_bypass",
     "likely_exploitable", True, 0.85, 27.3, "high"),
    ("CVE-2024-0012", "http://firewall.internal/mgmt", "auth_bypass",
     "unexploitable", False, 0.35, 15.2, "medium"),
    ("CVE-2024-23897", "http://jenkins.internal:8080", "file_read",
     "confirmed_exploitable", True, 0.88, 22.1, "high"),
    ("CVE-2024-20353", "http://vpn.internal/admin", "dos",
     "blocked", False, 0.55, 40.8, "medium"),
]

statuses = ["completed"] * 7 + ["running"]

for i, (cve, url, vuln_type, exploit_lvl, success, conf, exec_t, prio) in enumerate(scenarios):
    req_id = str(uuid.uuid4())
    now = datetime.utcnow() - timedelta(hours=len(scenarios) - i)

    req = PenTestRequest(
        id=req_id,
        finding_id=f"finding-{cve}",
        target_url=url,
        vulnerability_type=vuln_type,
        test_case=f"tc-{cve.lower()}",
        priority=PenTestPriority(prio),
        status=PenTestStatus(statuses[i]),
        created_at=now,
        started_at=now + timedelta(seconds=5),
        completed_at=(now + timedelta(seconds=exec_t)) if statuses[i] == "completed" else None,
    )
    db.create_request(req)

    if statuses[i] == "completed":
        steps = [
            f"1. Reconnaissance on {url}",
            f"2. Vulnerability scanning for {vuln_type}",
            f"3. Exploit attempt for {cve}",
            f"4. {'Exploited successfully' if success else 'Exploit failed/blocked'}",
        ]
        result = PenTestResult(
            id=str(uuid.uuid4()),
            request_id=req_id,
            finding_id=f"finding-{cve}",
            exploitability=ExploitabilityLevel(exploit_lvl),
            exploit_successful=success,
            evidence=f"Pen test for {cve}: {'Confirmed exploitable' if success else 'Not exploitable'}. Target: {url}.",
            steps_taken=steps,
            artifacts=[f"screenshots/{cve.lower()}_attempt.png", f"logs/{cve.lower()}_traffic.pcap"],
            confidence_score=conf,
            execution_time_seconds=exec_t,
        )
        db.create_result(result)
        print(f"  ✅ {cve}: request + result ({exploit_lvl})")
    else:
        print(f"  🔄 {cve}: request only (running)")

# Production config
config = PenTestConfig(
    id=str(uuid.uuid4()),
    name="aldeci-production",
    mpte_url="http://localhost:9000",
    api_key="mpte-prod-key",
    enabled=True,
    max_concurrent_tests=5,
    timeout_seconds=300,
    auto_trigger=True,
    target_environments=["staging", "production"],
    created_at=datetime.utcnow(),
    updated_at=datetime.utcnow(),
)
db.create_config(config)
print("  ✅ Production config created")

# Verify
print(f"\nVerification:")
print(f"  Requests: {len(db.list_requests(limit=100))}")
print(f"  Results:  {len(db.list_results(limit=100))}")
print(f"  Configs:  {len(db.list_configs(limit=100))}")

