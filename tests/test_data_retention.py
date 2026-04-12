"""
Tests for suite-core/core/data_retention.py — Data Retention and Purge Engine.

Coverage:
- Policy CRUD + defaults
- Identify purgeable records
- Purge with/without export
- GDPR erasure request + processing
- Retention dashboard
- Purge history
- Router endpoints (via TestClient)
"""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

# Ensure suite-core and suite-api are importable
_repo = Path(__file__).parent.parent
for _sub in ("suite-core", "suite-api"):
    _p = str(_repo / _sub)
    if _p not in sys.path:
        sys.path.insert(0, _p)

# Set required env vars before importing app modules
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

from core.data_retention import (
    DataCategory,
    DataRetentionManager,
    ErasureRequest,
    ErasureStatus,
    PurgeRecord,
    RetentionPolicy,
)


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def mgr():
    """Fresh in-memory DataRetentionManager for each test."""
    return DataRetentionManager(db_path=":memory:")


@pytest.fixture
def mgr_with_policies(mgr):
    """Manager pre-loaded with policies for all categories."""
    for cat in DataCategory:
        mgr.set_policy(
            RetentionPolicy(
                category=cat,
                retention_days=90,
                org_id="test-org",
            )
        )
    return mgr


# ============================================================================
# DataCategory enum
# ============================================================================


def test_data_category_values():
    expected = {
        "findings", "audit_logs", "metrics", "scan_results", "events",
        "reports", "sboms", "evidence", "incidents", "user_data",
    }
    actual = {cat.value for cat in DataCategory}
    assert actual == expected


def test_data_category_count():
    assert len(DataCategory) == 10


# ============================================================================
# Default policies
# ============================================================================


def test_get_default_policies_returns_all_categories(mgr):
    defaults = mgr.get_default_policies()
    assert len(defaults) == len(DataCategory)


def test_default_policy_audit_logs_7_years(mgr):
    defaults = {p.category: p for p in mgr.get_default_policies()}
    assert defaults["audit_logs"].retention_days == 2555


def test_default_policy_metrics_90_days(mgr):
    defaults = {p.category: p for p in mgr.get_default_policies()}
    assert defaults["metrics"].retention_days == 90


def test_default_policy_evidence_7_years(mgr):
    defaults = {p.category: p for p in mgr.get_default_policies()}
    assert defaults["evidence"].retention_days == 2555


def test_default_policy_findings_365_days(mgr):
    defaults = {p.category: p for p in mgr.get_default_policies()}
    assert defaults["findings"].retention_days == 365


def test_default_policies_have_compliance_framework(mgr):
    defaults = {p.category: p for p in mgr.get_default_policies()}
    assert defaults["user_data"].compliance_framework == "GDPR"
    assert defaults["audit_logs"].compliance_framework == "SOC2"


# ============================================================================
# Policy CRUD
# ============================================================================


def test_set_and_get_policy(mgr):
    policy = RetentionPolicy(
        category=DataCategory.FINDINGS,
        retention_days=180,
        org_id="org-a",
    )
    created = mgr.set_policy(policy)
    assert created.id == policy.id

    fetched = mgr.get_policy(DataCategory.FINDINGS, "org-a")
    assert fetched is not None
    assert fetched.retention_days == 180
    assert fetched.category == "findings"


def test_set_policy_upsert(mgr):
    """Setting a policy for the same category + org updates it."""
    mgr.set_policy(RetentionPolicy(category=DataCategory.METRICS, retention_days=30, org_id="org-b"))
    mgr.set_policy(RetentionPolicy(category=DataCategory.METRICS, retention_days=60, org_id="org-b"))

    fetched = mgr.get_policy(DataCategory.METRICS, "org-b")
    assert fetched is not None
    assert fetched.retention_days == 60


def test_list_policies_empty(mgr):
    assert mgr.list_policies("no-org") == []


def test_list_policies_returns_only_org_policies(mgr):
    mgr.set_policy(RetentionPolicy(category=DataCategory.EVENTS, retention_days=45, org_id="org-1"))
    mgr.set_policy(RetentionPolicy(category=DataCategory.REPORTS, retention_days=365, org_id="org-2"))

    org1_policies = mgr.list_policies("org-1")
    assert len(org1_policies) == 1
    assert org1_policies[0].category == "events"


def test_delete_policy(mgr):
    policy = RetentionPolicy(category=DataCategory.SBOMS, retention_days=200, org_id="org-d")
    created = mgr.set_policy(policy)

    mgr.delete_policy(created.id)
    assert mgr.get_policy(DataCategory.SBOMS, "org-d") is None


def test_get_policy_returns_none_when_missing(mgr):
    result = mgr.get_policy(DataCategory.INCIDENTS, "org-x")
    assert result is None


def test_policy_compliance_framework(mgr):
    policy = RetentionPolicy(
        category=DataCategory.USER_DATA,
        retention_days=365,
        compliance_framework="GDPR",
        org_id="org-c",
    )
    mgr.set_policy(policy)
    fetched = mgr.get_policy(DataCategory.USER_DATA, "org-c")
    assert fetched.compliance_framework == "GDPR"


def test_policy_disabled_flag(mgr):
    policy = RetentionPolicy(
        category=DataCategory.SCAN_RESULTS,
        retention_days=180,
        enabled=False,
        org_id="org-e",
    )
    mgr.set_policy(policy)
    fetched = mgr.get_policy(DataCategory.SCAN_RESULTS, "org-e")
    assert fetched.enabled is False


# ============================================================================
# Identify purgeable
# ============================================================================


def test_identify_purgeable_all_categories(mgr_with_policies):
    result = mgr_with_policies.identify_purgeable("test-org")
    assert len(result) == len(DataCategory)


def test_identify_purgeable_single_category(mgr_with_policies):
    result = mgr_with_policies.identify_purgeable("test-org", DataCategory.FINDINGS)
    assert "findings" in result
    assert "cutoff_date" in result["findings"]
    assert result["findings"]["retention_days"] == 90


def test_identify_purgeable_no_policy(mgr):
    result = mgr.identify_purgeable("org-empty")
    for cat_str, info in result.items():
        assert info["status"] == "no_policy"


def test_identify_purgeable_has_cutoff_date(mgr_with_policies):
    result = mgr_with_policies.identify_purgeable("test-org", DataCategory.AUDIT_LOGS)
    info = result["audit_logs"]
    assert "cutoff_date" in info
    cutoff = datetime.fromisoformat(info["cutoff_date"])
    assert cutoff < datetime.now(timezone.utc)


# ============================================================================
# Purge operations
# ============================================================================


def test_purge_expired_returns_purge_record(mgr_with_policies):
    record = mgr_with_policies.purge_expired("test-org", DataCategory.FINDINGS)
    assert isinstance(record, PurgeRecord)
    assert record.category == "findings"
    assert record.policy_id != "none"


def test_purge_expired_stores_in_history(mgr_with_policies):
    mgr_with_policies.purge_expired("test-org", DataCategory.METRICS)
    history = mgr_with_policies.get_purge_history("test-org")
    cats = [r.category for r in history]
    assert "metrics" in cats


def test_purge_expired_with_export(mgr_with_policies, tmp_path):
    """Purge with export_first=True should create an export file."""
    record = mgr_with_policies.purge_expired(
        "test-org", DataCategory.EVIDENCE, export_first=True
    )
    assert record.exported_before_purge is True
    assert record.export_path is not None
    assert Path(record.export_path).exists()

    # Verify export is valid JSON
    with open(record.export_path) as f:
        data = json.load(f)
    assert data["category"] == "evidence"
    assert data["org_id"] == "test-org"


def test_purge_expired_without_export(mgr_with_policies):
    record = mgr_with_policies.purge_expired(
        "test-org", DataCategory.EVENTS, export_first=False
    )
    assert record.exported_before_purge is False
    assert record.export_path is None


def test_purge_all_expired_returns_list(mgr_with_policies):
    records = mgr_with_policies.purge_all_expired("test-org")
    assert isinstance(records, list)
    assert len(records) == len(DataCategory)


def test_purge_all_skips_disabled_policies(mgr):
    mgr.set_policy(RetentionPolicy(category=DataCategory.FINDINGS, retention_days=30, enabled=True, org_id="org-f"))
    mgr.set_policy(RetentionPolicy(category=DataCategory.METRICS, retention_days=30, enabled=False, org_id="org-f"))

    records = mgr.purge_all_expired("org-f")
    cats = [r.category for r in records]
    assert "findings" in cats
    assert "metrics" not in cats


# ============================================================================
# Export before purge
# ============================================================================


def test_export_before_purge_creates_json_file(mgr_with_policies, tmp_path):
    export_path = mgr_with_policies.export_before_purge("test-org", DataCategory.REPORTS, export_dir=str(tmp_path))
    assert Path(export_path).exists()
    with open(export_path) as f:
        data = json.load(f)
    assert data["category"] == "reports"
    assert "exported_at" in data
    assert "cutoff_date" in data


# ============================================================================
# GDPR erasure
# ============================================================================


def test_request_erasure_creates_pending_request(mgr):
    req = mgr.request_erasure("alice@example.com", "org-gdpr")
    assert isinstance(req, ErasureRequest)
    assert req.subject_email == "alice@example.com"
    assert req.status == ErasureStatus.PENDING or req.status == "pending"
    assert req.org_id == "org-gdpr"


def test_get_erasure_requests(mgr):
    mgr.request_erasure("bob@example.com", "org-gdpr")
    mgr.request_erasure("carol@example.com", "org-gdpr")
    requests = mgr.get_erasure_requests("org-gdpr")
    assert len(requests) == 2
    emails = {r.subject_email for r in requests}
    assert emails == {"bob@example.com", "carol@example.com"}


def test_get_erasure_requests_empty_for_other_org(mgr):
    mgr.request_erasure("dave@example.com", "org-a")
    assert mgr.get_erasure_requests("org-b") == []


def test_process_erasure_completes(mgr):
    req = mgr.request_erasure("eve@example.com", "org-gdpr")
    completed = mgr.process_erasure(req.id)
    status = completed.status
    # Accept both enum value and string
    assert status in (ErasureStatus.COMPLETED, "completed")
    assert len(completed.categories_erased) > 0


def test_process_erasure_not_found_raises(mgr):
    with pytest.raises(ValueError, match="not found"):
        mgr.process_erasure("nonexistent-id")


def test_process_erasure_already_completed_is_idempotent(mgr):
    req = mgr.request_erasure("frank@example.com", "org-gdpr")
    mgr.process_erasure(req.id)
    # Second call should not raise
    result = mgr.process_erasure(req.id)
    status = result.status
    assert status in (ErasureStatus.COMPLETED, "completed")


# ============================================================================
# Retention dashboard
# ============================================================================


def test_retention_dashboard_structure(mgr_with_policies):
    dashboard = mgr_with_policies.get_retention_dashboard("test-org")
    assert "org_id" in dashboard
    assert "categories" in dashboard
    assert "total_purgeable_records" in dashboard
    assert "policies_configured" in dashboard
    assert "generated_at" in dashboard
    assert dashboard["policies_configured"] == len(DataCategory)


def test_retention_dashboard_all_categories_present(mgr_with_policies):
    dashboard = mgr_with_policies.get_retention_dashboard("test-org")
    for cat in DataCategory:
        assert cat.value in dashboard["categories"]


def test_retention_dashboard_policy_set_flag(mgr_with_policies):
    dashboard = mgr_with_policies.get_retention_dashboard("test-org")
    for cat_info in dashboard["categories"].values():
        assert cat_info["policy_set"] is True


def test_retention_dashboard_no_policies(mgr):
    dashboard = mgr.get_retention_dashboard("empty-org")
    assert dashboard["policies_configured"] == 0
    for cat_info in dashboard["categories"].values():
        assert cat_info["policy_set"] is False


def test_retention_dashboard_shows_last_purge(mgr_with_policies):
    mgr_with_policies.purge_expired("test-org", DataCategory.FINDINGS)
    dashboard = mgr_with_policies.get_retention_dashboard("test-org")
    assert dashboard["categories"]["findings"]["last_purge"] is not None


# ============================================================================
# Purge history
# ============================================================================


def test_purge_history_empty_initially(mgr):
    assert mgr.get_purge_history("org-new") == []


def test_purge_history_accumulates(mgr_with_policies):
    mgr_with_policies.purge_expired("test-org", DataCategory.FINDINGS)
    mgr_with_policies.purge_expired("test-org", DataCategory.METRICS)
    history = mgr_with_policies.get_purge_history("test-org")
    assert len(history) >= 2
    cats = {r.category for r in history}
    assert "findings" in cats
    assert "metrics" in cats


def test_purge_history_ordered_newest_first(mgr_with_policies):
    mgr_with_policies.purge_expired("test-org", DataCategory.EVENTS)
    mgr_with_policies.purge_expired("test-org", DataCategory.REPORTS)
    history = mgr_with_policies.get_purge_history("test-org")
    if len(history) >= 2:
        ts0 = history[0].purged_at if isinstance(history[0].purged_at, datetime) else datetime.fromisoformat(str(history[0].purged_at))
        ts1 = history[1].purged_at if isinstance(history[1].purged_at, datetime) else datetime.fromisoformat(str(history[1].purged_at))
        assert ts0 >= ts1


# ============================================================================
# Router integration (FastAPI TestClient)
# ============================================================================


@pytest.fixture(scope="module")
def client():
    """FastAPI TestClient for the retention router."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    # Patch the manager in the router to use in-memory
    import apps.api.retention_router as rr
    rr._manager = DataRetentionManager(db_path=":memory:")

    app = FastAPI()
    app.include_router(rr.router)
    return TestClient(app)


def test_router_get_defaults(client):
    resp = client.get("/api/v1/retention/defaults")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) == len(DataCategory)


def test_router_set_and_list_policy(client):
    resp = client.post("/api/v1/retention/policies", json={
        "category": "findings",
        "retention_days": 120,
        "description": "Test policy",
        "enabled": True,
    })
    assert resp.status_code == 201
    policy = resp.json()
    assert policy["retention_days"] == 120

    resp2 = client.get("/api/v1/retention/policies")
    assert resp2.status_code == 200
    cats = [p["category"] for p in resp2.json()]
    assert "findings" in cats


def test_router_purgeable(client):
    # Ensure a policy exists
    client.post("/api/v1/retention/policies", json={"category": "metrics", "retention_days": 30})
    resp = client.get("/api/v1/retention/purgeable")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, dict)


def test_router_purge_category(client):
    client.post("/api/v1/retention/policies", json={"category": "events", "retention_days": 30})
    resp = client.post("/api/v1/retention/purge/events", json={"export_first": False})
    assert resp.status_code == 200
    record = resp.json()
    assert record["category"] == "events"


def test_router_purge_category_no_policy_404(client):
    # Use a fresh client with empty manager
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    import apps.api.retention_router as rr

    old_mgr = rr._manager
    rr._manager = DataRetentionManager(db_path=":memory:")
    app = FastAPI()
    app.include_router(rr.router)
    tc = TestClient(app)

    resp = tc.post("/api/v1/retention/purge/sboms", json={})
    assert resp.status_code == 404
    rr._manager = old_mgr


def test_router_purge_all(client):
    resp = client.post("/api/v1/retention/purge-all")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_router_erasure_request(client):
    resp = client.post("/api/v1/retention/erasure", json={"subject_email": "test@example.com"})
    assert resp.status_code == 201
    data = resp.json()
    assert data["subject_email"] == "test@example.com"
    status = data["status"]
    assert status == "pending"


def test_router_list_erasure_requests(client):
    client.post("/api/v1/retention/erasure", json={"subject_email": "another@example.com"})
    resp = client.get("/api/v1/retention/erasure")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_router_dashboard(client):
    resp = client.get("/api/v1/retention/dashboard")
    assert resp.status_code == 200
    data = resp.json()
    assert "categories" in data
    assert "policies_configured" in data


def test_router_purge_history(client):
    resp = client.get("/api/v1/retention/history")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)
