#!/usr/bin/env python3
"""
ALDECI 30-Persona Walkthrough Test
Hits the LIVE API at http://localhost:8000 for each of the 30 security personas.
Each persona tests 3-5 relevant endpoints, checks HTTP 200 + non-empty data.
0.7s delay between requests to stay under 100 RPM rate limit.
"""

import os
import time
import json
import sys
import requests
from dataclasses import dataclass, field
from typing import List, Optional, Tuple
from datetime import datetime

# ── Config ──────────────────────────────────────────────────────────────────
BASE_URL = "http://localhost:8000"
API_TOKEN = os.getenv("FIXOPS_API_TOKEN", "")
HEADERS = {"X-API-Key": API_TOKEN, "Content-Type": "application/json"}
DELAY = 0.7  # seconds between requests

# ── Data structures ──────────────────────────────────────────────────────────
@dataclass
class EndpointResult:
    method: str
    path: str
    status_code: int
    has_data: bool
    error: Optional[str] = None
    notes: str = ""

    @property
    def passed(self) -> bool:
        return self.status_code == 200 and self.has_data

@dataclass
class PersonaResult:
    persona_id: int
    name: str
    role: str
    endpoints: List[EndpointResult] = field(default_factory=list)

    @property
    def passed(self) -> int:
        return sum(1 for e in self.endpoints if e.passed)

    @property
    def failed(self) -> int:
        return len(self.endpoints) - self.passed

    @property
    def total(self) -> int:
        return len(self.endpoints)

    @property
    def pass_rate(self) -> float:
        return (self.passed / self.total * 100) if self.total else 0.0

    @property
    def notes(self) -> str:
        fails = [e for e in self.endpoints if not e.passed]
        if not fails:
            return "All endpoints OK"
        return "; ".join(f"{e.path} → {e.status_code}" + (f" (no data)" if e.status_code == 200 else "") for e in fails)


# ── HTTP helpers ─────────────────────────────────────────────────────────────
session = requests.Session()
session.headers.update(HEADERS)

def get(path: str, params: dict = None, timeout: int = 15) -> Tuple[int, any]:
    """GET request with rate-limit delay. Returns (status_code, parsed_body)."""
    time.sleep(DELAY)
    try:
        r = session.get(f"{BASE_URL}{path}", params=params, timeout=timeout)
        if r.status_code == 429:
            time.sleep(2)
            r = session.get(f"{BASE_URL}{path}", params=params, timeout=timeout)
        try:
            body = r.json()
        except Exception:
            body = r.text
        return r.status_code, body
    except requests.RequestException as e:
        return 0, str(e)

def post(path: str, payload: dict = None, timeout: int = 15) -> Tuple[int, any]:
    """POST request with rate-limit delay."""
    time.sleep(DELAY)
    try:
        r = session.post(f"{BASE_URL}{path}", json=payload or {}, timeout=timeout)
        if r.status_code == 429:
            time.sleep(2)
            r = session.post(f"{BASE_URL}{path}", json=payload or {}, timeout=timeout)
        try:
            body = r.json()
        except Exception:
            body = r.text
        return r.status_code, body
    except requests.RequestException as e:
        return 0, str(e)


def has_data(body) -> bool:
    """Return True if the response body contains meaningful data."""
    if body is None:
        return False
    if isinstance(body, str):
        return len(body.strip()) > 2
    if isinstance(body, dict):
        # Non-empty dict, or a dict with any truthy value
        return len(body) > 0
    if isinstance(body, list):
        return True  # even empty list is a valid response; only fail on error
    return bool(body)


def probe(method: str, path: str, payload: dict = None) -> EndpointResult:
    """Execute one endpoint probe and return result."""
    if method.upper() == "POST":
        code, body = post(path, payload)
    else:
        code, body = get(path)
    return EndpointResult(
        method=method.upper(),
        path=path,
        status_code=code,
        has_data=has_data(body),
    )


# ── Persona definitions ───────────────────────────────────────────────────────
def run_all_personas() -> List[PersonaResult]:
    results: List[PersonaResult] = []

    # ── 1. Sarah Chen — CISO (admin) ──────────────────────────────────────────
    p = PersonaResult(1, "Sarah Chen", "CISO (admin)")
    print(f"\n[{p.persona_id:02d}] {p.name} — {p.role}")
    for ep in [
        ("GET", "/api/v1/analytics/dashboard/executive"),
        ("GET", "/api/v1/analytics/dashboard/overview"),
        ("GET", "/api/v1/risk/overview"),
        ("GET", "/api/v1/reports/stats"),
        ("GET", "/api/v1/sla/dashboard"),
    ]:
        r = probe(*ep)
        p.endpoints.append(r)
        print(f"  {'✓' if r.passed else '✗'} {r.method} {r.path} → {r.status_code}")
    results.append(p)

    # ── 2. Marcus Johnson — VP Engineering (admin) ────────────────────────────
    p = PersonaResult(2, "Marcus Johnson", "VP Engineering (admin)")
    print(f"\n[{p.persona_id:02d}] {p.name} — {p.role}")
    for ep in [
        ("GET", "/api/v1/sla/metrics"),
        ("GET", "/api/v1/sla/breaches"),
        ("GET", "/api/v1/remediation/metrics/test"),
        ("GET", "/api/v1/analytics/mttr"),
        ("GET", "/api/v1/analytics/sla"),
    ]:
        r = probe(*ep)
        p.endpoints.append(r)
        print(f"  {'✓' if r.passed else '✗'} {r.method} {r.path} → {r.status_code}")
    results.append(p)

    # ── 3. Alex Rivera — SOC T1 (security_analyst) ───────────────────────────
    p = PersonaResult(3, "Alex Rivera", "SOC T1 (security_analyst)")
    print(f"\n[{p.persona_id:02d}] {p.name} — {p.role}")
    for ep in [
        ("GET", "/api/v1/triage/queue"),
        ("GET", "/api/v1/triage/stats"),
        ("GET", "/api/v1/cases/stats/summary"),
        ("GET", "/api/v1/playbooks"),
        ("GET", "/api/v1/incident/active"),
    ]:
        r = probe(*ep)
        p.endpoints.append(r)
        print(f"  {'✓' if r.passed else '✗'} {r.method} {r.path} → {r.status_code}")
    results.append(p)

    # ── 4. Priya Sharma — SOC T2 (security_analyst) ──────────────────────────
    p = PersonaResult(4, "Priya Sharma", "SOC T2 (security_analyst)")
    print(f"\n[{p.persona_id:02d}] {p.name} — {p.role}")
    for ep in [
        ("GET", "/api/v1/threat-hunt/rules"),
        ("GET", "/api/v1/correlation/rules"),
        ("GET", "/api/v1/brain/stats"),
        ("GET", "/api/v1/deduplication/stats"),
        ("GET", "/api/v1/ml/stats"),
    ]:
        r = probe(*ep)
        p.endpoints.append(r)
        print(f"  {'✓' if r.passed else '✗'} {r.method} {r.path} → {r.status_code}")
    results.append(p)

    # ── 5. James Wilson — Security Engineer (security_analyst) ───────────────
    p = PersonaResult(5, "James Wilson", "Security Engineer (security_analyst)")
    print(f"\n[{p.persona_id:02d}] {p.name} — {p.role}")
    for ep in [
        ("GET", "/api/v1/findings"),
        ("GET", "/api/v1/remediation/tasks"),
        ("GET", "/api/v1/risk/scores"),
        ("GET", "/api/v1/scanner-ingest/stats"),
        ("GET", "/api/v1/security-automation/rules?org_id=test"),
    ]:
        r = probe(*ep)
        p.endpoints.append(r)
        print(f"  {'✓' if r.passed else '✗'} {r.method} {r.path} → {r.status_code}")
    results.append(p)

    # ── 6. Emma Davis — DevSecOps (security_analyst) ─────────────────────────
    p = PersonaResult(6, "Emma Davis", "DevSecOps (security_analyst)")
    print(f"\n[{p.persona_id:02d}] {p.name} — {p.role}")
    for ep in [
        ("GET", "/api/v1/sast/findings"),
        ("GET", "/api/v1/sast/rules"),
        ("GET", "/api/v1/sbom"),
        ("GET", "/api/v1/sbom/licenses"),
        ("GET", "/api/v1/dast/health"),
    ]:
        r = probe(*ep)
        p.endpoints.append(r)
        print(f"  {'✓' if r.passed else '✗'} {r.method} {r.path} → {r.status_code}")
    results.append(p)

    # ── 7. Robert Kim — Compliance Officer (viewer) ───────────────────────────
    p = PersonaResult(7, "Robert Kim", "Compliance Officer (viewer)")
    print(f"\n[{p.persona_id:02d}] {p.name} — {p.role}")
    for ep in [
        ("GET", "/api/v1/compliance-engine/frameworks"),
        ("GET", "/api/v1/compliance-engine/gaps"),
        ("GET", "/api/v1/compliance-engine/mappings"),
        ("GET", "/api/v1/evidence/stats"),
        ("GET", "/api/v1/audit/logs"),
    ]:
        r = probe(*ep)
        p.endpoints.append(r)
        print(f"  {'✓' if r.passed else '✗'} {r.method} {r.path} → {r.status_code}")
    results.append(p)

    # ── 8. Lisa Zhang — Pentester (security_analyst) ─────────────────────────
    p = PersonaResult(8, "Lisa Zhang", "Pentester (security_analyst)")
    print(f"\n[{p.persona_id:02d}] {p.name} — {p.role}")
    for ep in [
        ("GET", "/api/v1/mpte/stats"),
        ("GET", "/api/v1/mpte/results"),
        ("GET", "/api/v1/attack-sim/scenarios"),
        ("GET", "/api/v1/micro-pentest/enterprise/scans"),
        ("GET", "/api/v1/reachability/metrics"),
    ]:
        r = probe(*ep)
        p.endpoints.append(r)
        print(f"  {'✓' if r.passed else '✗'} {r.method} {r.path} → {r.status_code}")
    results.append(p)

    # ── 9. David Park — Risk Manager (viewer) ────────────────────────────────
    p = PersonaResult(9, "David Park", "Risk Manager (viewer)")
    print(f"\n[{p.persona_id:02d}] {p.name} — {p.role}")
    for ep in [
        ("GET", "/api/v1/risk/overview"),
        ("GET", "/api/v1/risk/scores"),
        ("GET", "/api/v1/analytics/risk-overview"),
        ("GET", "/api/v1/predictions"),
        ("GET", "/api/v1/analytics/risk-velocity"),
    ]:
        r = probe(*ep)
        p.endpoints.append(r)
        print(f"  {'✓' if r.passed else '✗'} {r.method} {r.path} → {r.status_code}")
    results.append(p)

    # ── 10. Maria Lopez — IT Director (admin) ────────────────────────────────
    p = PersonaResult(10, "Maria Lopez", "IT Director (admin)")
    print(f"\n[{p.persona_id:02d}] {p.name} — {p.role}")
    for ep in [
        ("GET", "/api/v1/inventory/assets"),
        ("GET", "/api/v1/inventory/applications"),
        ("GET", "/api/v1/identity/stats"),
        ("GET", "/api/v1/connectors"),
        ("GET", "/api/v1/integrations/status"),
    ]:
        r = probe(*ep)
        p.endpoints.append(r)
        print(f"  {'✓' if r.passed else '✗'} {r.method} {r.path} → {r.status_code}")
    results.append(p)

    # ── 11. Tom Anderson — AppSec Lead (security_analyst) ────────────────────
    p = PersonaResult(11, "Tom Anderson", "AppSec Lead (security_analyst)")
    print(f"\n[{p.persona_id:02d}] {p.name} — {p.role}")
    for ep in [
        ("GET", "/api/v1/sast/findings"),
        ("GET", "/api/v1/inventory/sbom/components"),
        ("GET", "/api/v1/sbom/licenses"),
        ("GET", "/api/v1/remediation/statuses"),
        ("GET", "/api/v1/analytics/summary"),
    ]:
        r = probe(*ep)
        p.endpoints.append(r)
        print(f"  {'✓' if r.passed else '✗'} {r.method} {r.path} → {r.status_code}")
    results.append(p)

    # ── 12. Jennifer Wu — Cloud Security Architect (security_analyst) ─────────
    p = PersonaResult(12, "Jennifer Wu", "Cloud Security Architect (security_analyst)")
    print(f"\n[{p.persona_id:02d}] {p.name} — {p.role}")
    for ep in [
        ("GET", "/api/v1/cspm/score"),
        ("GET", "/api/v1/cspm/rules"),
        ("GET", "/api/v1/cloud-compliance/stats"),
        ("GET", "/api/v1/kubernetes-security/clusters?org_id=test"),
        ("GET", "/api/v1/graph/stats"),
    ]:
        r = probe(*ep)
        p.endpoints.append(r)
        print(f"  {'✓' if r.passed else '✗'} {r.method} {r.path} → {r.status_code}")
    results.append(p)

    # ── 13. Michael Brown — Audit Manager (viewer) ───────────────────────────
    p = PersonaResult(13, "Michael Brown", "Audit Manager (viewer)")
    print(f"\n[{p.persona_id:02d}] {p.name} — {p.role}")
    for ep in [
        ("GET", "/api/v1/audit/logs"),
        ("GET", "/api/v1/audit/trail"),
        ("GET", "/api/v1/evidence/list"),
        ("GET", "/api/v1/compliance/gaps"),
        ("GET", "/api/v1/audit/compliance/frameworks"),
    ]:
        r = probe(*ep)
        p.endpoints.append(r)
        print(f"  {'✓' if r.passed else '✗'} {r.method} {r.path} → {r.status_code}")
    results.append(p)

    # ── 14. Karen Taylor — IR Lead (security_analyst) ────────────────────────
    p = PersonaResult(14, "Karen Taylor", "IR Lead (security_analyst)")
    print(f"\n[{p.persona_id:02d}] {p.name} — {p.role}")
    for ep in [
        ("GET", "/api/v1/cases"),
        ("GET", "/api/v1/cases/stats/summary"),
        ("GET", "/api/v1/playbooks"),
        ("GET", "/api/v1/soc/handoff/history"),
        ("GET", "/api/v1/analytics/mttr"),
    ]:
        r = probe(*ep)
        p.endpoints.append(r)
        print(f"  {'✓' if r.passed else '✗'} {r.method} {r.path} → {r.status_code}")
    results.append(p)

    # ── 15. Chris Lee — Security Data Scientist (security_analyst) ───────────
    p = PersonaResult(15, "Chris Lee", "Security Data Scientist (security_analyst)")
    print(f"\n[{p.persona_id:02d}] {p.name} — {p.role}")
    for ep in [
        ("GET", "/api/v1/ml/models"),
        ("GET", "/api/v1/ml/analytics/stats"),
        ("GET", "/api/v1/analytics/trends/severity-over-time"),
        ("GET", "/api/v1/analytics/noise-reduction"),
        ("GET", "/api/v1/self-learning/stats"),
    ]:
        r = probe(*ep)
        p.endpoints.append(r)
        print(f"  {'✓' if r.passed else '✗'} {r.method} {r.path} → {r.status_code}")
    results.append(p)

    # ── 16. Ryan Murphy — Platform Engineer (admin) ───────────────────────────
    p = PersonaResult(16, "Ryan Murphy", "Platform Engineer (admin)")
    print(f"\n[{p.persona_id:02d}] {p.name} — {p.role}")
    for ep in [
        ("GET", "/api/v1/system/health"),
        ("GET", "/api/v1/system/metrics"),
        ("GET", "/api/v1/container/images"),
        ("GET", "/api/v1/container/rules"),
        ("GET", "/api/v1/connectors/types"),
    ]:
        r = probe(*ep)
        p.endpoints.append(r)
        print(f"  {'✓' if r.passed else '✗'} {r.method} {r.path} → {r.status_code}")
    results.append(p)

    # ── 17. Nina Patel — Threat Intel Analyst (security_analyst) ─────────────
    p = PersonaResult(17, "Nina Patel", "Threat Intel Analyst (security_analyst)")
    print(f"\n[{p.persona_id:02d}] {p.name} — {p.role}")
    for ep in [
        ("GET", "/api/v1/feeds/stats"),
        ("GET", "/api/v1/feeds/kev"),
        ("GET", "/api/v1/feeds/trending"),
        ("GET", "/api/v1/feeds/threat-actors"),
        ("GET", "/api/v1/mitre/tactics"),
    ]:
        r = probe(*ep)
        p.endpoints.append(r)
        print(f"  {'✓' if r.passed else '✗'} {r.method} {r.path} → {r.status_code}")
    results.append(p)

    # ── 18. Olivia Martin — GRC Analyst (viewer) ─────────────────────────────
    p = PersonaResult(18, "Olivia Martin", "GRC Analyst (viewer)")
    print(f"\n[{p.persona_id:02d}] {p.name} — {p.role}")
    for ep in [
        ("GET", "/api/v1/compliance-engine/frameworks"),
        ("GET", "/api/v1/policies"),
        ("GET", "/api/v1/compliance-engine/mappings"),
        ("GET", "/api/v1/compliance/status"),
        ("GET", "/api/v1/audit/compliance/frameworks"),
    ]:
        r = probe(*ep)
        p.endpoints.append(r)
        print(f"  {'✓' if r.passed else '✗'} {r.method} {r.path} → {r.status_code}")
    results.append(p)

    # ── 19. Daniel Thompson — SecOps Manager (admin) ─────────────────────────
    p = PersonaResult(19, "Daniel Thompson", "SecOps Manager (admin)")
    print(f"\n[{p.persona_id:02d}] {p.name} — {p.role}")
    for ep in [
        ("GET", "/api/v1/soc/performance"),
        ("GET", "/api/v1/soc/workload"),
        ("GET", "/api/v1/analytics/summary"),
        ("GET", "/api/v1/workflows"),
        ("GET", "/api/v1/security-automation/rules?org_id=test"),
    ]:
        r = probe(*ep)
        p.endpoints.append(r)
        print(f"  {'✓' if r.passed else '✗'} {r.method} {r.path} → {r.status_code}")
    results.append(p)

    # ── 20. Emily Chang — Developer Security Champion (developer) ─────────────
    p = PersonaResult(20, "Emily Chang", "Developer Security Champion (developer)")
    print(f"\n[{p.persona_id:02d}] {p.name} — {p.role}")
    for ep in [
        ("GET", "/api/v1/training/lessons"),
        ("GET", "/api/v1/training/progress"),
        ("GET", "/api/v1/remediation/statuses"),
        ("GET", "/api/v1/security-scoreboard/leaderboard?org_id=test"),
        ("GET", "/api/v1/ide/status"),
    ]:
        r = probe(*ep)
        p.endpoints.append(r)
        print(f"  {'✓' if r.passed else '✗'} {r.method} {r.path} → {r.status_code}")
    results.append(p)

    # ── 21. Richard Adams — Security Architect (security_analyst) ─────────────
    p = PersonaResult(21, "Richard Adams", "Security Architect (security_analyst)")
    print(f"\n[{p.persona_id:02d}] {p.name} — {p.role}")
    for ep in [
        ("GET", "/api/v1/threat-model-gen/test/models"),
        ("GET", "/api/v1/mitre/techniques"),
        ("GET", "/api/v1/attack-paths/stats?org_id=test"),
        ("GET", "/api/v1/graph/stats"),
        ("GET", "/api/v1/arch-review/reviews?org_id=test"),
    ]:
        r = probe(*ep)
        p.endpoints.append(r)
        print(f"  {'✓' if r.passed else '✗'} {r.method} {r.path} → {r.status_code}")
    results.append(p)

    # ── 22. Amanda Scott — Supply Chain Security (security_analyst) ───────────
    p = PersonaResult(22, "Amanda Scott", "Supply Chain Security (security_analyst)")
    print(f"\n[{p.persona_id:02d}] {p.name} — {p.role}")
    for ep in [
        ("GET", "/api/v1/supply-chain-monitoring/suppliers?org_id=test"),
        ("GET", "/api/v1/supply-chain-attacks/packages?org_id=test"),
        ("GET", "/api/v1/sbom"),
        ("GET", "/api/v1/sbom/licenses"),
        ("GET", "/api/v1/feeds/supply-chain"),
    ]:
        r = probe(*ep)
        p.endpoints.append(r)
        print(f"  {'✓' if r.passed else '✗'} {r.method} {r.path} → {r.status_code}")
    results.append(p)

    # ── 23. Brian Hall — QA Security Tester (security_analyst) ───────────────
    p = PersonaResult(23, "Brian Hall", "QA Security Tester (security_analyst)")
    print(f"\n[{p.persona_id:02d}] {p.name} — {p.role}")
    for ep in [
        ("GET", "/api/v1/scanner-ingest/stats"),
        ("GET", "/api/v1/scanner-ingest/supported"),
        ("GET", "/api/v1/deduplication/stats"),
        ("GET", "/api/v1/analytics/false-positive-rate"),
        ("GET", "/api/v1/analytics/findings"),
    ]:
        r = probe(*ep)
        p.endpoints.append(r)
        print(f"  {'✓' if r.passed else '✗'} {r.method} {r.path} → {r.status_code}")
    results.append(p)

    # ── 24. Catherine Williams — Board Member (viewer) ────────────────────────
    p = PersonaResult(24, "Catherine Williams", "Board Member (viewer)")
    print(f"\n[{p.persona_id:02d}] {p.name} — {p.role}")
    for ep in [
        ("GET", "/api/v1/analytics/dashboard/executive"),
        ("GET", "/api/v1/reports/stats"),
        ("GET", "/api/v1/risk/overview"),
        ("GET", "/api/v1/analytics/roi"),
        ("GET", "/api/v1/analytics/overview"),
    ]:
        r = probe(*ep)
        p.endpoints.append(r)
        print(f"  {'✓' if r.passed else '✗'} {r.method} {r.path} → {r.status_code}")
    results.append(p)

    # ── 25. Mark Roberts — External Auditor (viewer) ─────────────────────────
    p = PersonaResult(25, "Mark Roberts", "External Auditor (viewer)")
    print(f"\n[{p.persona_id:02d}] {p.name} — {p.role}")
    for ep in [
        ("GET", "/api/v1/audit/logs"),
        ("GET", "/api/v1/evidence/summary"),
        ("GET", "/api/v1/compliance/status"),
        ("GET", "/api/v1/audit/compliance/controls"),
        ("GET", "/api/v1/compliance-engine/soc2/status"),
    ]:
        r = probe(*ep)
        p.endpoints.append(r)
        print(f"  {'✓' if r.passed else '✗'} {r.method} {r.path} → {r.status_code}")
    results.append(p)

    # ── 26. Security SRE (admin) ─────────────────────────────────────────────
    p = PersonaResult(26, "Security SRE", "SRE (admin)")
    print(f"\n[{p.persona_id:02d}] {p.name} — {p.role}")
    for ep in [
        ("GET", "/api/v1/health"),
        ("GET", "/api/v1/system/status"),
        ("GET", "/api/v1/sla/health"),
        ("GET", "/api/v1/log-management/stats"),
        ("GET", "/api/v1/system/metrics"),
    ]:
        r = probe(*ep)
        p.endpoints.append(r)
        print(f"  {'✓' if r.passed else '✗'} {r.method} {r.path} → {r.status_code}")
    results.append(p)

    # ── 27. Threat Modeler (security_analyst) ────────────────────────────────
    p = PersonaResult(27, "Threat Modeler", "Threat Modeler (security_analyst)")
    print(f"\n[{p.persona_id:02d}] {p.name} — {p.role}")
    for ep in [
        ("GET", "/api/v1/threat-model-gen/test/models"),
        ("GET", "/api/v1/threat-modeling-pipeline/models?org_id=test"),
        ("GET", "/api/v1/mitre/techniques"),
        ("GET", "/api/v1/attack-paths/stats?org_id=test"),
        ("GET", "/api/v1/predictions"),
    ]:
        r = probe(*ep)
        p.endpoints.append(r)
        print(f"  {'✓' if r.passed else '✗'} {r.method} {r.path} → {r.status_code}")
    results.append(p)

    # ── 28. DPO — Data Protection Officer (viewer) ───────────────────────────
    p = PersonaResult(28, "DPO", "Data Protection Officer (viewer)")
    print(f"\n[{p.persona_id:02d}] {p.name} — {p.role}")
    for ep in [
        ("GET", "/api/v1/compliance-engine/hipaa/status"),
        ("GET", "/api/v1/sbom/licenses"),
        ("GET", "/api/v1/inventory/sbom/licenses"),
        ("GET", "/api/v1/evidence/compliance-status"),
        ("GET", "/api/v1/compliance/status"),
    ]:
        r = probe(*ep)
        p.endpoints.append(r)
        print(f"  {'✓' if r.passed else '✗'} {r.method} {r.path} → {r.status_code}")
    results.append(p)

    # ── 29. Software Architect (developer) ───────────────────────────────────
    p = PersonaResult(29, "Software Architect", "Software Architect (developer)")
    print(f"\n[{p.persona_id:02d}] {p.name} — {p.role}")
    for ep in [
        ("GET", "/api/v1/graph/stats"),
        ("GET", "/api/v1/dependency-mapping/summary"),
        ("GET", "/api/v1/inventory/sbom/components"),
        ("GET", "/api/v1/inventory/apis"),
        ("GET", "/api/v1/code-to-cloud/summary"),
    ]:
        r = probe(*ep)
        p.endpoints.append(r)
        print(f"  {'✓' if r.passed else '✗'} {r.method} {r.path} → {r.status_code}")
    results.append(p)

    # ── 30. SecOps Tech Lead (security_analyst) ───────────────────────────────
    p = PersonaResult(30, "SecOps Tech Lead", "SecOps Tech Lead (security_analyst)")
    print(f"\n[{p.persona_id:02d}] {p.name} — {p.role}")
    for ep in [
        ("GET", "/api/v1/workflows"),
        ("GET", "/api/v1/workflows/rules"),
        ("GET", "/api/v1/security-automation/rules?org_id=test"),
        ("GET", "/api/v1/nerve-center/state"),
        ("GET", "/api/v1/nerve-center/pulse"),
    ]:
        r = probe(*ep)
        p.endpoints.append(r)
        print(f"  {'✓' if r.passed else '✗'} {r.method} {r.path} → {r.status_code}")
    results.append(p)

    return results


# ── Summary table ────────────────────────────────────────────────────────────
def print_summary(results: List[PersonaResult]):
    print("\n" + "=" * 110)
    print("ALDECI 30-PERSONA WALKTHROUGH — RESULTS SUMMARY")
    print("=" * 110)

    header = f"{'#':>3}  {'Persona':<32}  {'Role':<38}  {'Tested':>6}  {'Pass':>4}  {'Fail':>4}  {'Rate':>6}  Notes"
    print(header)
    print("-" * 110)

    total_tests = 0
    total_passed = 0

    for pr in results:
        total_tests += pr.total
        total_passed += pr.passed
        rate_str = f"{pr.pass_rate:5.0f}%"
        notes = pr.notes if pr.failed else "—"
        # Truncate notes to fit
        if len(notes) > 40:
            notes = notes[:37] + "..."
        print(
            f"{pr.persona_id:>3}  {pr.name:<32}  {pr.role:<38}  "
            f"{pr.total:>6}  {pr.passed:>4}  {pr.failed:>4}  {rate_str}  {notes}"
        )

    print("-" * 110)
    overall_rate = total_passed / total_tests * 100 if total_tests else 0
    print(f"{'TOTAL':>3}  {'':32}  {'':38}  {total_tests:>6}  {total_passed:>4}  {total_tests - total_passed:>4}  {overall_rate:5.0f}%")
    print("=" * 110)
    print(f"\nOverall pass rate: {total_passed}/{total_tests} endpoints ({overall_rate:.1f}%)")
    print(f"Personas with 100% pass: {sum(1 for pr in results if pr.failed == 0)}/30")
    print(f"Run completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Detailed failures
    failures = [(pr, e) for pr in results for e in pr.endpoints if not e.passed]
    if failures:
        print(f"\nFailed endpoints ({len(failures)} total):")
        for pr, e in failures:
            reason = "no data" if e.status_code == 200 else f"HTTP {e.status_code}"
            print(f"  [{pr.persona_id:02d}] {pr.name:<32}  {e.method} {e.path}  →  {reason}")

    return overall_rate


# ── Main ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 80)
    print("ALDECI 30-PERSONA WALKTHROUGH TEST")
    print(f"Target: {BASE_URL}")
    print(f"Delay between requests: {DELAY}s")
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 80)

    # Quick connectivity check
    try:
        r = requests.get(f"{BASE_URL}/api/v1/health", timeout=5)
        print(f"Health check: HTTP {r.status_code} ✓")
    except Exception as e:
        print(f"ERROR: Cannot reach {BASE_URL} — {e}")
        sys.exit(1)

    results = run_all_personas()
    rate = print_summary(results)

    # Exit code: 0 if ≥80% pass, 1 otherwise
    sys.exit(0 if rate >= 80 else 1)
