"""
GAP-025 tests: multi-CSP (OCI, Alibaba, IBM) adapters on
cspm_engine / cnapp_engine / cloud_account_monitoring_engine
and the new /api/v1/multi-csp router.

30 tests total.
"""
from __future__ import annotations

import os
import sys
import tempfile
import pathlib

import pytest

# Add suite paths (sitecustomize normally does this, but be safe in isolation)
_ROOT = pathlib.Path(__file__).resolve().parents[1]
for sub in ("suite-core", "suite-api/apps"):
    p = str(_ROOT / sub)
    if p not in sys.path:
        sys.path.insert(0, p)

from core.cspm_engine import (  # noqa: E402
    PROVIDERS as CSPM_PROVIDERS,
    OCIProviderAdapter,
    AlibabaProviderAdapter,
    IBMProviderAdapter,
    get_provider_adapter,
    list_supported_providers,
    CloudProvider,
)
from core.cnapp_engine import (  # noqa: E402
    PROVIDERS as CNAPP_PROVIDERS,
    OCIWorkloadAdapter,
    AlibabaWorkloadAdapter,
    IBMWorkloadAdapter,
    get_workload_adapter,
    list_supported_cnapp_providers,
    CNAPPEngine,
)
from core.cloud_account_monitoring_engine import (  # noqa: E402
    CloudAccountMonitoringEngine,
    _VALID_PROVIDERS,
)


# =========================================================================
# CSPM adapters — OCI
# =========================================================================

def test_oci_cspm_adapter_list_resources_returns_at_least_one():
    adapter = OCIProviderAdapter()
    resources = adapter.list_resources("oci-acct-1")
    assert len(resources) >= 1
    assert all(r["provider"] == "oci" for r in resources)


def test_oci_cspm_adapter_scan_returns_findings():
    adapter = OCIProviderAdapter()
    resources = adapter.list_resources("oci-acct-1")
    findings = adapter.scan_resource(resources[0])
    assert len(findings) >= 1
    assert all(f["provider"] == "oci" for f in findings)


def test_oci_cspm_resources_have_required_fields():
    adapter = OCIProviderAdapter()
    for r in adapter.list_resources("acct-x"):
        for key in ("resource_id", "account_id", "provider", "resource_type", "name", "region"):
            assert key in r


# =========================================================================
# CSPM adapters — Alibaba
# =========================================================================

def test_alibaba_cspm_adapter_list_resources_returns_at_least_one():
    adapter = AlibabaProviderAdapter()
    resources = adapter.list_resources("ali-acct-1")
    assert len(resources) >= 1
    assert all(r["provider"] == "alibaba" for r in resources)


def test_alibaba_cspm_adapter_scan_returns_findings():
    adapter = AlibabaProviderAdapter()
    resources = adapter.list_resources("ali-acct-1")
    findings = adapter.scan_resource(resources[0])
    assert len(findings) >= 1
    assert all(f["provider"] == "alibaba" for f in findings)


def test_alibaba_cspm_findings_have_severity():
    adapter = AlibabaProviderAdapter()
    findings = adapter.scan_resource({"resource_id": "r1", "provider": "alibaba", "resource_type": "oss"})
    assert all(f["severity"] in ("critical", "high", "medium", "low", "info") for f in findings)


# =========================================================================
# CSPM adapters — IBM
# =========================================================================

def test_ibm_cspm_adapter_list_resources_returns_at_least_one():
    adapter = IBMProviderAdapter()
    resources = adapter.list_resources("ibm-acct-1")
    assert len(resources) >= 1
    assert all(r["provider"] == "ibm" for r in resources)


def test_ibm_cspm_adapter_scan_returns_findings():
    adapter = IBMProviderAdapter()
    resources = adapter.list_resources("ibm-acct-1")
    findings = adapter.scan_resource(resources[0])
    assert len(findings) >= 1
    assert all(f["provider"] == "ibm" for f in findings)


def test_ibm_cspm_findings_have_compliance_frameworks():
    adapter = IBMProviderAdapter()
    findings = adapter.scan_resource({"resource_id": "r1", "provider": "ibm", "resource_type": "cos"})
    assert all(isinstance(f["compliance_frameworks"], list) for f in findings)
    assert all(len(f["compliance_frameworks"]) > 0 for f in findings)


# =========================================================================
# CSPM provider registry + enum
# =========================================================================

def test_cspm_provider_registry_has_six_entries():
    assert set(CSPM_PROVIDERS.keys()) == {"aws", "azure", "gcp", "oci", "alibaba", "ibm"}
    assert len(CSPM_PROVIDERS) == 6


def test_cspm_cloud_provider_enum_accepts_new_names():
    assert CloudProvider("oci") == CloudProvider.OCI
    assert CloudProvider("alibaba") == CloudProvider.ALIBABA
    assert CloudProvider("ibm") == CloudProvider.IBM


def test_cspm_list_supported_providers_returns_six():
    providers = list_supported_providers()
    assert providers == ["aws", "azure", "gcp", "oci", "alibaba", "ibm"]


def test_cspm_get_provider_adapter_lookup():
    assert get_provider_adapter("oci") is not None
    assert get_provider_adapter("alibaba") is not None
    assert get_provider_adapter("ibm") is not None
    assert get_provider_adapter("aws") is None  # native, no adapter


def test_cspm_get_provider_adapter_case_insensitive():
    assert get_provider_adapter("OCI") is not None
    assert get_provider_adapter("Alibaba") is not None
    assert get_provider_adapter("IBM") is not None


# =========================================================================
# CNAPP workload adapters
# =========================================================================

def test_cnapp_oci_adapter_lists_workloads():
    wl = OCIWorkloadAdapter().list_resources("acct-1")
    assert len(wl) >= 1
    assert all(w["cloud_provider"] == "oci" for w in wl)


def test_cnapp_alibaba_adapter_scans_workload():
    adapter = AlibabaWorkloadAdapter()
    wl = adapter.list_resources("acct-1")[0]
    findings = adapter.scan_resource(wl)
    assert len(findings) >= 1
    assert all(f["cloud_provider"] == "alibaba" for f in findings)


def test_cnapp_ibm_adapter_workload_types_valid():
    wl = IBMWorkloadAdapter().list_resources("acct-1")
    for w in wl:
        assert w["workload_type"] in {"vm", "container", "serverless", "kubernetes_pod", "cloud_function"}


def test_cnapp_provider_registry_has_six_entries():
    assert set(CNAPP_PROVIDERS.keys()) == {"aws", "azure", "gcp", "oci", "alibaba", "ibm"}


def test_cnapp_list_supported_returns_six():
    assert list_supported_cnapp_providers() == ["aws", "azure", "gcp", "oci", "alibaba", "ibm"]


def test_cnapp_get_workload_adapter_lookup():
    assert get_workload_adapter("oci") is not None
    assert get_workload_adapter("alibaba") is not None
    assert get_workload_adapter("ibm") is not None


def test_cnapp_engine_accepts_new_provider_values():
    with tempfile.TemporaryDirectory() as tmp:
        eng = CNAPPEngine(db_path=os.path.join(tmp, "cnapp.db"))
        rec = eng.register_workload("org-1", {"name": "w1", "cloud_provider": "oci"})
        assert rec["cloud_provider"] == "oci"
        rec = eng.register_workload("org-1", {"name": "w2", "cloud_provider": "alibaba"})
        assert rec["cloud_provider"] == "alibaba"
        rec = eng.register_workload("org-1", {"name": "w3", "cloud_provider": "ibm"})
        assert rec["cloud_provider"] == "ibm"


# =========================================================================
# cloud_account_monitoring_engine — provider enum
# =========================================================================

def test_cloud_account_monitoring_accepts_oci():
    assert "oci" in _VALID_PROVIDERS


def test_cloud_account_monitoring_accepts_alibaba():
    assert "alibaba" in _VALID_PROVIDERS


def test_cloud_account_monitoring_accepts_ibm():
    assert "ibm" in _VALID_PROVIDERS


def test_cloud_account_monitoring_register_oci():
    with tempfile.TemporaryDirectory() as tmp:
        eng = CloudAccountMonitoringEngine(db_path=os.path.join(tmp, "cam.db"))
        rec = eng.register_account("org-1", "oci-123", "OCI Prod", "oci", "us-ashburn-1")
        assert rec["provider"] == "oci"


def test_cloud_account_monitoring_register_alibaba_and_ibm():
    with tempfile.TemporaryDirectory() as tmp:
        eng = CloudAccountMonitoringEngine(db_path=os.path.join(tmp, "cam.db"))
        r1 = eng.register_account("org-1", "ali-1", "Ali", "alibaba")
        r2 = eng.register_account("org-1", "ibm-1", "IBM", "ibm")
        assert r1["provider"] == "alibaba"
        assert r2["provider"] == "ibm"


# =========================================================================
# /api/v1/multi-csp router — endpoint tests
# =========================================================================

@pytest.fixture
def client():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from apps.api.multi_csp_router import router as multi_csp_router

    app = FastAPI()
    app.include_router(multi_csp_router)
    return TestClient(app)


def test_multi_csp_get_providers(client):
    r = client.get("/api/v1/multi-csp/providers")
    assert r.status_code == 200
    data = r.json()
    assert data["providers"] == ["aws", "azure", "gcp", "oci", "alibaba", "ibm"]
    assert data["count"] == 6


def test_multi_csp_scan_oci(client):
    r = client.post("/api/v1/multi-csp/scan", json={"provider": "oci", "account_id": "acct-1"})
    assert r.status_code == 200
    data = r.json()
    assert data["provider"] == "oci"
    assert data["resource_count"] > 0
    assert data["finding_count"] > 0


def test_multi_csp_scan_alibaba(client):
    r = client.post("/api/v1/multi-csp/scan", json={"provider": "alibaba", "account_id": "acct-1"})
    assert r.status_code == 200
    assert r.json()["provider"] == "alibaba"


def test_multi_csp_scan_ibm(client):
    r = client.post("/api/v1/multi-csp/scan", json={"provider": "ibm", "account_id": "acct-1"})
    assert r.status_code == 200
    assert r.json()["provider"] == "ibm"


def test_multi_csp_scan_rejects_unknown_provider(client):
    r = client.post("/api/v1/multi-csp/scan", json={"provider": "bogus", "account_id": "acct-1"})
    assert r.status_code == 400


def test_multi_csp_scan_rejects_empty_account(client):
    r = client.post("/api/v1/multi-csp/scan", json={"provider": "oci", "account_id": ""})
    # empty string fails pydantic min_length=1 → 422
    assert r.status_code in (400, 422)


def test_multi_csp_coverage_endpoint(client):
    r = client.get("/api/v1/multi-csp/coverage?org_id=org-1")
    assert r.status_code == 200
    data = r.json()
    assert data["provider_count"] == 6
    for p in ("aws", "azure", "gcp", "oci", "alibaba", "ibm"):
        assert p in data["coverage"]


def test_multi_csp_coverage_reports_adapter_availability(client):
    r = client.get("/api/v1/multi-csp/coverage?org_id=org-1")
    data = r.json()
    # oci/alibaba/ibm have CSPM + CNAPP adapters that list seeded assets
    for p in ("oci", "alibaba", "ibm"):
        assert data["coverage"][p]["cspm_supported"] is True
        assert data["coverage"][p]["cnapp_supported"] is True
        assert data["coverage"][p]["cspm_seeded_assets"] >= 1
        assert data["coverage"][p]["cnapp_seeded_workloads"] >= 1


def test_multi_csp_stats_endpoint(client):
    r = client.get("/api/v1/multi-csp/stats?org_id=org-1")
    assert r.status_code == 200
    data = r.json()
    assert data["total_providers"] == 6
    assert set(data["native_providers"]) == {"aws", "azure", "gcp"}
    assert set(data["adapter_providers"]) == {"oci", "alibaba", "ibm"}


def test_multi_csp_org_id_isolation(client):
    r1 = client.get("/api/v1/multi-csp/stats?org_id=org-A")
    r2 = client.get("/api/v1/multi-csp/stats?org_id=org-B")
    assert r1.status_code == 200 and r2.status_code == 200
    assert r1.json()["org_id"] == "org-A"
    assert r2.json()["org_id"] == "org-B"
