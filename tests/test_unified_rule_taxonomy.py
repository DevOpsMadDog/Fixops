"""Tests for GAP-062 — Unified Rule Taxonomy Registry (Sprint 3 scope).

Coverage (25 tests):
  Engine-level:
    - register UPSERT idempotent, updates fields on re-register
    - invalid domain/severity/rule_type/missing fields raise ValueError
    - list filters: domain, source_engine, enabled
    - disable/enable round-trip
    - taxonomy schema shape
    - org_id isolation
  Shim-level (policy_enforcement_engine.sync_from_unified_registry):
    - sync writes to policies table with field mapping
    - sync is idempotent on resync
    - sync skips disabled rules
    - sync filters by source_engine
  Router-level:
    - 6 endpoint smoke tests (auth + happy path)
"""

from __future__ import annotations

import os
import sys
import uuid

# Set env vars BEFORE any imports so auth_deps reads them at module import
os.environ["FIXOPS_API_TOKEN"] = "test-unified-rules-token-xyz"
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-jwt-secret-32-chars-padding!!")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

sys.path.insert(0, "suite-core")
sys.path.insert(0, "suite-api")

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

API_TOKEN = os.environ["FIXOPS_API_TOKEN"]
BASE = "/api/v1/rules/unified"
AUTH = {"X-API-Key": API_TOKEN}
NO_AUTH: dict = {}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def pe(tmp_path):
    """Fresh PolicyEngine per test."""
    from core.policy_engine import PolicyEngine
    return PolicyEngine(db_path=str(tmp_path / "test_urr.db"))


@pytest.fixture()
def enf(tmp_path):
    from core.policy_enforcement_engine import PolicyEnforcementEngine
    return PolicyEnforcementEngine(db_path=str(tmp_path / "test_urr_enf.db"))


@pytest.fixture()
def client(tmp_path_factory, monkeypatch):
    """TestClient with router mounted against fresh isolated engines."""
    from core.policy_engine import PolicyEngine
    from core.policy_enforcement_engine import PolicyEnforcementEngine
    import core.policy_engine as _pe_mod
    import core.policy_enforcement_engine as _enf_mod

    tmp = tmp_path_factory.mktemp("urr_router")
    fresh_pe = PolicyEngine(db_path=str(tmp / "urr_pe.db"))
    # Override module singleton for the router
    monkeypatch.setattr(_pe_mod, "_engine_instance", fresh_pe)
    # Override the enforcement registry so get_engine(org) returns a fresh engine
    _enf_mod._instances.clear()

    def _fresh_enf(org_id: str):
        if org_id not in _enf_mod._instances:
            _enf_mod._instances[org_id] = PolicyEnforcementEngine(
                db_path=str(tmp / f"urr_enf_{org_id}.db")
            )
        return _enf_mod._instances[org_id]

    monkeypatch.setattr(_enf_mod, "get_engine", _fresh_enf)

    from apps.api.unified_rules_router import router
    app = FastAPI()
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=True)


ORG = "org-urr-test"
ORG2 = "org-urr-other"


# ---------------------------------------------------------------------------
# 1. Engine: register UPSERT idempotent
# ---------------------------------------------------------------------------

def test_register_creates_new_rule(pe):
    r = pe.register_unified_rule(
        ORG, "sast.sql.injection", "sast", "injection", "critical",
        "detection", "sast_engine",
    )
    assert r["rule_key"] == "sast.sql.injection"
    assert r["domain"] == "sast"
    assert r["severity"] == "critical"
    assert r["rule_type"] == "detection"
    assert r["source_engine"] == "sast_engine"
    assert r["enabled"] is True
    assert r["id"]


def test_register_upsert_same_id_on_duplicate(pe):
    r1 = pe.register_unified_rule(
        ORG, "key.a", "sast", "cat", "high", "detection", "sast_engine"
    )
    r2 = pe.register_unified_rule(
        ORG, "key.a", "sast", "cat", "critical", "detection", "sast_engine"
    )
    assert r1["id"] == r2["id"]
    assert r2["severity"] == "critical"  # updated


def test_register_upsert_updates_fields(pe):
    pe.register_unified_rule(
        ORG, "key.b", "sast", "orig_cat", "low", "detection", "sast_engine"
    )
    r2 = pe.register_unified_rule(
        ORG, "key.b", "dast", "new_cat", "high", "validation", "dast_engine"
    )
    assert r2["domain"] == "dast"
    assert r2["category"] == "new_cat"
    assert r2["severity"] == "high"
    assert r2["rule_type"] == "validation"
    assert r2["source_engine"] == "dast_engine"


def test_register_severity_case_insensitive(pe):
    r = pe.register_unified_rule(
        ORG, "key.c", "sast", "cat", "HIGH", "detection", "sast_engine"
    )
    assert r["severity"] == "high"


# ---------------------------------------------------------------------------
# 2. Engine: validation failures
# ---------------------------------------------------------------------------

def test_register_invalid_domain_raises(pe):
    with pytest.raises(ValueError, match="Invalid domain"):
        pe.register_unified_rule(
            ORG, "k", "NOT_A_DOMAIN", "c", "high", "detection", "e"
        )


def test_register_invalid_severity_raises(pe):
    with pytest.raises(ValueError, match="Invalid severity"):
        pe.register_unified_rule(
            ORG, "k", "sast", "c", "URGENT", "detection", "e"
        )


def test_register_invalid_rule_type_raises(pe):
    with pytest.raises(ValueError, match="Invalid rule_type"):
        pe.register_unified_rule(
            ORG, "k", "sast", "c", "high", "unknown_type", "e"
        )


def test_register_missing_rule_key_raises(pe):
    with pytest.raises(ValueError, match="rule_key is required"):
        pe.register_unified_rule(ORG, "", "sast", "c", "high", "detection", "e")


def test_register_missing_source_engine_raises(pe):
    with pytest.raises(ValueError, match="source_engine is required"):
        pe.register_unified_rule(ORG, "k", "sast", "c", "high", "detection", "")


def test_register_missing_category_raises(pe):
    with pytest.raises(ValueError, match="category is required"):
        pe.register_unified_rule(ORG, "k", "sast", "", "high", "detection", "e")


# ---------------------------------------------------------------------------
# 3. Engine: list filters
# ---------------------------------------------------------------------------

def test_list_filter_by_domain(pe):
    pe.register_unified_rule(ORG, "k.sast.1", "sast", "c", "high", "detection", "sast_engine")
    pe.register_unified_rule(ORG, "k.dast.1", "dast", "c", "high", "detection", "dast_engine")
    pe.register_unified_rule(ORG, "k.secrets.1", "secrets", "c", "high", "detection", "secrets")
    sast_only = pe.list_unified_rules(ORG, domain="sast")
    assert len(sast_only) == 1
    assert sast_only[0]["rule_key"] == "k.sast.1"


def test_list_filter_by_source_engine(pe):
    pe.register_unified_rule(ORG, "k.1", "sast", "c", "high", "detection", "sast_engine")
    pe.register_unified_rule(ORG, "k.2", "sast", "c", "high", "detection", "other_engine")
    sast = pe.list_unified_rules(ORG, source_engine="sast_engine")
    assert len(sast) == 1
    assert sast[0]["rule_key"] == "k.1"


def test_list_filter_by_enabled_true(pe):
    pe.register_unified_rule(ORG, "k.1", "sast", "c", "high", "detection", "e")
    pe.register_unified_rule(ORG, "k.2", "sast", "c", "high", "detection", "e")
    pe.disable_rule(ORG, "k.2")
    enabled = pe.list_unified_rules(ORG, enabled=True)
    assert len(enabled) == 1
    assert enabled[0]["rule_key"] == "k.1"


def test_list_filter_by_enabled_false(pe):
    pe.register_unified_rule(ORG, "k.1", "sast", "c", "high", "detection", "e")
    pe.register_unified_rule(ORG, "k.2", "sast", "c", "high", "detection", "e")
    pe.disable_rule(ORG, "k.2")
    disabled = pe.list_unified_rules(ORG, enabled=False)
    assert len(disabled) == 1
    assert disabled[0]["rule_key"] == "k.2"


# ---------------------------------------------------------------------------
# 4. Engine: disable/enable round-trip
# ---------------------------------------------------------------------------

def test_disable_sets_enabled_false(pe):
    pe.register_unified_rule(ORG, "k.1", "sast", "c", "high", "detection", "e")
    r = pe.disable_rule(ORG, "k.1")
    assert r is not None
    assert r["enabled"] is False


def test_enable_sets_enabled_true(pe):
    pe.register_unified_rule(ORG, "k.1", "sast", "c", "high", "detection", "e")
    pe.disable_rule(ORG, "k.1")
    r = pe.enable_rule(ORG, "k.1")
    assert r is not None
    assert r["enabled"] is True


def test_disable_unknown_rule_returns_none(pe):
    assert pe.disable_rule(ORG, "does.not.exist") is None


# ---------------------------------------------------------------------------
# 5. Engine: taxonomy shape
# ---------------------------------------------------------------------------

def test_get_rule_taxonomy_shape(pe):
    tax = pe.get_rule_taxonomy()
    assert tax["gap_reference"] == "GAP-062"
    assert tax["schema_version"] == "1.0"
    fields = tax["fields"]
    for required in ("rule_key", "domain", "category", "severity",
                     "rule_type", "enabled", "source_engine"):
        assert required in fields
    assert "critical" in fields["severity"]["values"]
    assert "sast" in fields["domain"]["values"]
    assert "detection" in fields["rule_type"]["values"]


# ---------------------------------------------------------------------------
# 6. Engine: org_id isolation
# ---------------------------------------------------------------------------

def test_org_isolation(pe):
    pe.register_unified_rule(ORG, "shared.key", "sast", "c", "high", "detection", "e")
    pe.register_unified_rule(ORG2, "shared.key", "dast", "c", "low", "detection", "e2")
    org1_rules = pe.list_unified_rules(ORG)
    org2_rules = pe.list_unified_rules(ORG2)
    assert len(org1_rules) == 1
    assert len(org2_rules) == 1
    assert org1_rules[0]["domain"] == "sast"
    assert org2_rules[0]["domain"] == "dast"


# ---------------------------------------------------------------------------
# 7. Shim: sync writes to policies
# ---------------------------------------------------------------------------

def test_sync_writes_policies(pe, enf, monkeypatch):
    import core.policy_engine as _pe_mod
    monkeypatch.setattr(_pe_mod, "_engine_instance", pe)
    pe.register_unified_rule(ORG, "sast.sql", "sast", "injection", "critical",
                             "detection", "sast_engine")
    result = enf.sync_from_unified_registry(ORG, "sast_engine")
    assert result["synced"] == 1
    assert result["skipped"] == 0
    policies = enf.list_policies(ORG)
    assert len(policies) == 1
    p = policies[0]
    assert p["policy_domain"] == "application"
    assert p["policy_type"] == "mandatory"  # critical → mandatory
    assert p["enforcement_mechanism"] == "automated"  # detection → automated


def test_sync_is_idempotent(pe, enf, monkeypatch):
    import core.policy_engine as _pe_mod
    monkeypatch.setattr(_pe_mod, "_engine_instance", pe)
    pe.register_unified_rule(ORG, "k.1", "sast", "c", "high", "detection", "sast_engine")
    r1 = enf.sync_from_unified_registry(ORG, "sast_engine")
    r2 = enf.sync_from_unified_registry(ORG, "sast_engine")
    assert r1["synced"] == 1
    assert r2["synced"] == 0
    assert r2["skipped"] == 1


def test_sync_skips_disabled_rules(pe, enf, monkeypatch):
    import core.policy_engine as _pe_mod
    monkeypatch.setattr(_pe_mod, "_engine_instance", pe)
    pe.register_unified_rule(ORG, "k.on", "sast", "c", "high", "detection", "sast_engine")
    pe.register_unified_rule(ORG, "k.off", "sast", "c", "high", "detection", "sast_engine")
    pe.disable_rule(ORG, "k.off")
    r = enf.sync_from_unified_registry(ORG, "sast_engine")
    assert r["synced"] == 1
    assert r["total_rules"] == 1


def test_sync_filters_by_source_engine(pe, enf, monkeypatch):
    import core.policy_engine as _pe_mod
    monkeypatch.setattr(_pe_mod, "_engine_instance", pe)
    pe.register_unified_rule(ORG, "k.sast", "sast", "c", "high", "detection", "sast_engine")
    pe.register_unified_rule(ORG, "k.sec", "secrets", "c", "high", "detection", "secrets_scanner")
    r1 = enf.sync_from_unified_registry(ORG, "sast_engine")
    r2 = enf.sync_from_unified_registry(ORG, "secrets_scanner")
    assert r1["synced"] == 1
    assert r2["synced"] == 1
    all_pols = enf.list_policies(ORG)
    assert len(all_pols) == 2


# ---------------------------------------------------------------------------
# 8. Router: 6 endpoint smoke tests
# ---------------------------------------------------------------------------

def test_router_post_register(client):
    resp = client.post(
        BASE,
        params={"org_id": "rt-org"},
        json={
            "rule_key": "sast.xss",
            "domain": "sast",
            "category": "xss",
            "severity": "high",
            "rule_type": "detection",
            "source_engine": "sast_engine",
        },
        headers=AUTH,
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["rule_key"] == "sast.xss"
    assert body["enabled"] is True


def test_router_get_list(client):
    client.post(
        BASE,
        params={"org_id": "rt-list"},
        json={
            "rule_key": "k.1",
            "domain": "sast",
            "category": "c",
            "severity": "high",
            "rule_type": "detection",
            "source_engine": "sast_engine",
        },
        headers=AUTH,
    )
    resp = client.get(BASE, params={"org_id": "rt-list"}, headers=AUTH)
    assert resp.status_code == 200
    assert len(resp.json()) >= 1


def test_router_enable_disable_roundtrip(client):
    client.post(
        BASE,
        params={"org_id": "rt-ed"},
        json={
            "rule_key": "k.ed",
            "domain": "sast",
            "category": "c",
            "severity": "high",
            "rule_type": "detection",
            "source_engine": "e",
        },
        headers=AUTH,
    )
    dr = client.post(f"{BASE}/k.ed/disable", params={"org_id": "rt-ed"}, headers=AUTH)
    assert dr.status_code == 200
    assert dr.json()["enabled"] is False
    er = client.post(f"{BASE}/k.ed/enable", params={"org_id": "rt-ed"}, headers=AUTH)
    assert er.status_code == 200
    assert er.json()["enabled"] is True


def test_router_get_taxonomy(client):
    resp = client.get(f"{BASE}/taxonomy", headers=AUTH)
    assert resp.status_code == 200
    body = resp.json()
    assert body["gap_reference"] == "GAP-062"
    assert "fields" in body


def test_router_sync(client):
    org = "rt-sync"
    client.post(
        BASE,
        params={"org_id": org},
        json={
            "rule_key": "k.sync",
            "domain": "sast",
            "category": "c",
            "severity": "critical",
            "rule_type": "detection",
            "source_engine": "sast_engine",
        },
        headers=AUTH,
    )
    resp = client.post(
        f"{BASE}/sync",
        params={"org_id": org},
        json={"source_engine": "sast_engine"},
        headers=AUTH,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["synced"] == 1
    assert body["source_engine"] == "sast_engine"


def test_router_auth_required(client):
    resp = client.get(f"{BASE}/taxonomy", headers=NO_AUTH)
    assert resp.status_code in (401, 403)
