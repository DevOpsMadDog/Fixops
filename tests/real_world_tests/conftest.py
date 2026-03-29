"""
Real-World Trial conftest.py — zero hardcoding.

All configuration comes from environment variables so these tests
can be pointed at ANY deployment (localhost, Docker, staging, client site).

Required env vars:
    ALDECI_BASE_URL   — API base URL  (default: http://localhost:8000)
    ALDECI_API_KEY    — API key       (default: from FIXOPS_API_TOKEN)
    ALDECI_ORG_ID     — Org tenant ID (default: "default")

Optional env vars:
    ALDECI_UI_URL     — Frontend URL  (default: http://localhost:5173)
    ALDECI_TIMEOUT    — Request timeout in seconds (default: 30)
    ALDECI_SKIP_SLOW  — Skip slow MPTE/LLM tests (default: "0")
"""
import os
import pytest
import requests
from dataclasses import dataclass, field
from typing import Optional


# ── Dynamic Config ──────────────────────────────────────────────
def _env(name: str, fallback: str = "") -> str:
    return os.environ.get(name, fallback)


BASE_URL = _env("ALDECI_BASE_URL", _env("FIXOPS_BASE_URL", "http://localhost:8000"))
API_KEY = _env("ALDECI_API_KEY", _env("FIXOPS_API_TOKEN", ""))
ORG_ID = _env("ALDECI_ORG_ID", "default")
UI_URL = _env("ALDECI_UI_URL", "http://localhost:5173")
TIMEOUT = int(_env("ALDECI_TIMEOUT", "30"))
SKIP_SLOW = _env("ALDECI_SKIP_SLOW", "0") == "1"


# ── Persona Model ──────────────────────────────────────────────
@dataclass
class Persona:
    name: str
    title: str
    role: str  # admin | security_analyst | developer | viewer | service
    phase: str  # Which runbook phase they own
    description: str = ""


PERSONAS = {
    "ciso": Persona("Sarah Chen", "CISO", "admin", "phase7", "Executive risk owner"),
    "vp_eng": Persona("Marcus Johnson", "VP Engineering", "admin", "phase5", "Remediation SLA owner"),
    "soc_t1": Persona("Alex Rivera", "SOC Analyst T1", "security_analyst", "phase2", "Tier-1 triage"),
    "soc_t2": Persona("Priya Sharma", "SOC Analyst T2", "security_analyst", "phase2", "Tier-2 investigation"),
    "sec_eng": Persona("James Wilson", "Security Engineer", "security_analyst", "phase4", "Scanner/autofix"),
    "devsecops": Persona("Emma Davis", "DevSecOps Engineer", "security_analyst", "phase2", "Pipeline/SBOM"),
    "compliance": Persona("Robert Kim", "Compliance Officer", "viewer", "phase6", "Frameworks/audit"),
    "pentester": Persona("Lisa Zhang", "Penetration Tester", "security_analyst", "phase4", "MPTE/attack"),
    "risk_mgr": Persona("David Park", "Risk Manager", "viewer", "phase3", "Risk scoring"),
    "it_director": Persona("Maria Lopez", "IT Director", "admin", "phase1", "System health"),
    "appsec_lead": Persona("Tom Anderson", "AppSec Lead", "security_analyst", "phase3", "Triage funnel"),
    "cloud_arch": Persona("Jennifer Wu", "Cloud Security Architect", "security_analyst", "phase1", "Graph/assets"),
    "audit_mgr": Persona("Michael Brown", "Audit Manager", "viewer", "phase6", "Audit trail"),
    "ir_lead": Persona("Karen Taylor", "IR Lead", "security_analyst", "phase4", "Nerve center"),
    "data_sci": Persona("Chris Lee", "Security Data Scientist", "security_analyst", "phase3", "ML/anomaly"),
    "platform_eng": Persona("Ryan Murphy", "Platform Engineer", "admin", "phase1", "Health/metrics"),
    "threat_intel": Persona("Nina Patel", "Threat Intel Analyst", "security_analyst", "phase2", "NVD/MITRE/EPSS"),
    "grc": Persona("Olivia Martin", "GRC Analyst", "viewer", "phase6", "SOC2/PCI-DSS"),
    "secops_mgr": Persona("Daniel Thompson", "SecOps Manager", "admin", "phase5", "Workflows/policies"),
    "developer": Persona("Emily Chang", "Developer", "developer", "phase5", "Autofix consumer"),
    "sec_architect": Persona("Richard Adams", "Security Architect", "security_analyst", "phase1", "KG/brain"),
    "supply_chain": Persona("Amanda Scott", "Supply Chain Security", "security_analyst", "phase2", "SBOM/provenance"),
    "qa_tester": Persona("Brian Hall", "QA Security Tester", "security_analyst", "phase5", "Feedback loop"),
    "board": Persona("Catherine Williams", "Board Member", "viewer", "phase7", "Executive dashboard"),
    "auditor": Persona("Mark Roberts", "External Auditor", "viewer", "phase6", "Evidence verify"),
}


# ── API Client Fixture ─────────────────────────────────────────
class AldeciClient:
    """Thin HTTP client pointing at the deployment under test."""

    def __init__(self, base_url: str, api_key: str, org_id: str, timeout: int):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.org_id = org_id
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "X-API-Key": self.api_key,
            "Content-Type": "application/json",
            "X-Org-Id": self.org_id,
        })

    def get(self, path: str, **kw):
        return self.session.get(f"{self.base_url}{path}", timeout=self.timeout, **kw)

    def post(self, path: str, json=None, **kw):
        return self.session.post(f"{self.base_url}{path}", json=json, timeout=self.timeout, **kw)

    def put(self, path: str, json=None, **kw):
        return self.session.put(f"{self.base_url}{path}", json=json, timeout=self.timeout, **kw)

    def delete(self, path: str, **kw):
        return self.session.delete(f"{self.base_url}{path}", timeout=self.timeout, **kw)


# ── Fixtures ───────────────────────────────────────────────────
@pytest.fixture(scope="session")
def api():
    """Session-scoped API client against the live deployment."""
    return AldeciClient(BASE_URL, API_KEY, ORG_ID, TIMEOUT)


@pytest.fixture(scope="session")
def base_url():
    return BASE_URL


@pytest.fixture(scope="session")
def org_id():
    return ORG_ID


@pytest.fixture(params=list(PERSONAS.values()), ids=lambda p: p.name.replace(" ", "_"))
def persona(request):
    """Parametrized fixture yielding each persona."""
    return request.param


def pytest_collection_modifyitems(config, items):
    """Auto-apply timeout marker and skip slow tests if requested."""
    for item in items:
        item.add_marker(pytest.mark.timeout(TIMEOUT * 4))
        if SKIP_SLOW and "slow" in item.keywords:
            item.add_marker(pytest.mark.skip(reason="ALDECI_SKIP_SLOW=1"))


# ── Health Gate ────────────────────────────────────────────────
def pytest_configure(config):
    """Fail fast if the target deployment is unreachable."""
    if not API_KEY:
        pytest.exit("ALDECI_API_KEY / FIXOPS_API_TOKEN not set — cannot run real-world tests", returncode=1)
    try:
        r = requests.get(f"{BASE_URL}/health", timeout=10)
        if r.status_code >= 500:
            pytest.exit(f"Deployment unhealthy at {BASE_URL}: HTTP {r.status_code}", returncode=1)
    except requests.ConnectionError:
        pytest.exit(f"Cannot reach deployment at {BASE_URL} — is the server running?", returncode=1)

