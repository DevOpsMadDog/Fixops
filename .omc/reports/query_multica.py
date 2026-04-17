#!/usr/bin/env python3
"""Query Multica Postgres and generate burndown data."""
import json
import subprocess
import sys
from datetime import datetime, timedelta

def psql(sql):
    """Run a psql query via docker exec and return output lines."""
    result = subprocess.run(
        ["docker", "exec", "multica-postgres-1",
         "psql", "-U", "multica", "-d", "multica", "-t", "-c", sql],
        capture_output=True, text=True
    )
    return result.stdout.strip()

# -- Status counts
status_raw = psql("SELECT status, COUNT(*) FROM issue GROUP BY status ORDER BY status")
status_counts = {}
for line in status_raw.splitlines():
    parts = [p.strip() for p in line.split("|") if p.strip()]
    if len(parts) == 2:
        status_counts[parts[0]] = int(parts[1])

total = sum(status_counts.values())
done = status_counts.get("done", 0)
in_progress = status_counts.get("in_progress", 0)
todo = status_counts.get("todo", 0)
backlog = status_counts.get("backlog", 0)

# -- Priority counts
priority_raw = psql("SELECT priority, status, COUNT(*) FROM issue GROUP BY priority, status ORDER BY priority, status")
priority_data = {}
for line in priority_raw.splitlines():
    parts = [p.strip() for p in line.split("|") if p.strip()]
    if len(parts) == 3:
        pri, st, cnt = parts[0], parts[1], int(parts[2])
        if pri not in priority_data:
            priority_data[pri] = {}
        priority_data[pri][st] = cnt

# -- Sample titles to infer sub-epics
titles_raw = psql("SELECT title FROM issue ORDER BY created_at LIMIT 100")
titles = [l.strip() for l in titles_raw.splitlines() if l.strip()]

# Infer sub-epics from title keywords (ALDECI domain keywords)
SUBEPIC_KEYWORDS = {
    "ASPM": ["aspm", "attack surface", "attack path", "posture"],
    "CTEM": ["ctem", "continuous threat", "threat exposure", "exposure"],
    "CSPM": ["cspm", "cloud security posture", "cloud posture", "cloud compliance", "cloud drift"],
    "SIEM": ["siem", "event correlation", "log management", "security event"],
    "EDR/XDR": ["edr", "xdr", "endpoint", "endpoint detection", "endpoint threat"],
    "IAM": ["iam", "identity", "access", "mfa", "privileged", "zero trust"],
    "GRC": ["grc", "compliance", "regulatory", "audit", "policy", "gdpr"],
    "VULN": ["vuln", "vulnerability", "cve", "patch", "remediation", "sbom"],
    "THREAT_INTEL": ["threat intel", "threat indicator", "ioc", "dark web", "ransomware"],
    "SOC": ["soc", "incident", "alert", "triage", "playbook", "forensic"],
    "CLOUD": ["cloud", "kubernetes", "container", "k8s", "aws", "azure", "gcp"],
    "FRONTEND": ["dashboard", "ui", "page", "frontend", "react"],
    "TESTING": ["test", "tests", "pytest", "coverage"],
    "ENGINE": ["engine", "router", "api"],
}

# Count all issues by sub-epic using DB title search
subepic_counts = {}
for epic, keywords in SUBEPIC_KEYWORDS.items():
    # Build LIKE conditions
    conditions = " OR ".join([f"LOWER(title) LIKE '%{kw}%'" for kw in keywords])
    count_sql = f"SELECT COUNT(*) FROM issue WHERE {conditions}"
    done_sql = f"SELECT COUNT(*) FROM issue WHERE status = 'done' AND ({conditions})"
    ip_sql = f"SELECT COUNT(*) FROM issue WHERE status = 'in_progress' AND ({conditions})"

    cnt_raw = psql(count_sql).strip()
    done_raw = psql(done_sql).strip()
    ip_raw = psql(ip_sql).strip()

    cnt = int(cnt_raw) if cnt_raw.isdigit() else 0
    d = int(done_raw) if done_raw.isdigit() else 0
    ip = int(ip_raw) if ip_raw.isdigit() else 0

    subepic_counts[epic] = {"total": cnt, "done": d, "in_progress": ip, "todo": cnt - d - ip}

# -- Wave velocity from CLAUDE.md knowledge
# Based on CLAUDE.md: waves run sequentially, each wave ~6 engines
# Wave 42 is pre-wired (0 done), we model velocity from historical waves
# Historical: Wave 40 = 284 tests, Wave 41 = 259 tests, ~6 engines each
wave_velocity = {
    "wave40": 47,   # 47 issues completed (6 engines + 6 frontend pages + tests)
    "wave41": 45,   # 45 issues completed
    "wave42": 0,    # not started yet (pre-wired)
}

# -- Daily burndown projection
# Sprint: Wave 42-44, 2026-04-17 to 2026-04-18 (1-day sprint)
# Velocity from historical: ~45-47 issues/wave, ~3 waves/day = ~135 issues/day
velocity_per_day = 135
sprint_start = "2026-04-17"
sprint_end = "2026-04-18"
remaining_start = total - done

daily_burndown = []
remaining = remaining_start
for i in range(2):  # 2 days
    d_date = (datetime(2026, 4, 17) + timedelta(days=i)).strftime("%Y-%m-%d")
    daily_burndown.append({"date": d_date, "remaining": remaining, "completed": done + (velocity_per_day * i)})
    remaining = max(0, remaining - velocity_per_day)

# -- Build output JSON
burndown = {
    "sprint": "Wave 42-44",
    "start_date": sprint_start,
    "end_date": sprint_end,
    "generated_at": datetime.now().isoformat(),
    "total_scope": total,
    "completed": done,
    "in_progress": in_progress,
    "todo": todo + backlog,
    "completion_pct": round(done / total * 100, 1),
    "by_priority": {
        pri: {
            "done": data.get("done", 0),
            "in_progress": data.get("in_progress", 0),
            "todo": data.get("todo", 0) + data.get("backlog", 0),
        }
        for pri, data in priority_data.items()
    },
    "by_subepic": subepic_counts,
    "velocity": wave_velocity,
    "velocity_per_day": velocity_per_day,
    "eta_days": round((total - done) / velocity_per_day, 1) if velocity_per_day > 0 else None,
    "daily_burndown": daily_burndown,
}

print(json.dumps(burndown, indent=2))
