"""Seed test data for bulk endpoint testing."""
import os
import sys

_root = os.path.join(os.path.dirname(__file__), "..")
for _d in ("suite-core", "suite-api", "suite-attack", "suite-feeds", "."):
    _p = os.path.normpath(os.path.join(_root, _d))
    if _p not in sys.path:
        sys.path.insert(0, _p)

from core.analytics_db import AnalyticsDB
from core.analytics_models import Finding, FindingSeverity, FindingStatus
from core.policy_db import PolicyDB
from core.policy_models import Policy, PolicyStatus

db = AnalyticsDB()
pdb = PolicyDB()

severities = [
    FindingSeverity.CRITICAL,
    FindingSeverity.HIGH,
    FindingSeverity.MEDIUM,
    FindingSeverity.LOW,
    FindingSeverity.INFO,
]

for i in range(1, 6):
    f = Finding(
        id=f"test-finding-{i:03d}",
        application_id="payment-service",
        service_id="payment-api",
        rule_id=f"SEC-{i:03d}",
        severity=severities[i - 1],
        status=FindingStatus.OPEN,
        title=f"Test Finding {i} - SQL Injection in endpoint /api/v{i}",
        description=f"SQL injection vulnerability found in parameter query_{i}",
        source="sast",
        cve_id=f"CVE-2024-{1000 + i}",
        cvss_score=round(10.0 - i * 1.5, 1),
        epss_score=round(0.95 - i * 0.15, 4),
        exploitable=i <= 3,
    )
    try:
        db.create_finding(f)
        print(f"Created: {f.id} ({f.severity.value})")
    except Exception as e:
        print(f"Skipped {f.id}: {e}")

# Policy: delete existing then recreate to ensure clean state
policy_id = "policy-block-critical"
try:
    pdb.delete_policy(policy_id)
    print(f"Deleted old policy: {policy_id}")
except Exception:
    pass
# Also remove any policies with same name (UNIQUE constraint on name column)
import sqlite3 as _sqlite3

_conn = _sqlite3.connect(str(pdb.db_path))
_conn.execute("DELETE FROM policies WHERE name = ?", ("Block Critical CVEs",))
_conn.commit()
_conn.close()
print("Cleaned up duplicate policy names")

p = Policy(
    id=policy_id,
    name="Block Critical CVEs",
    description="Block deployments with critical CVEs",
    policy_type="guardrail",
    status=PolicyStatus.ACTIVE,
    rules={"max_severity": "high", "block_exploitable": True, "sla_days": 7},
    created_by="admin",
)
pdb.create_policy(p)
print(f"Created policy: {p.id}")

# Verify it's accessible
check = pdb.get_policy(policy_id)
print(
    f"Verify policy lookup: {check is not None} (name={check.name if check else 'N/A'})"
)

print("DONE")
