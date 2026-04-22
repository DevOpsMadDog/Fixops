"""Tests for GAP-059 shadow-AI inventory (ai_governance + cmdb + router)."""

from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

import pytest

from core.ai_governance_engine import AIGovernanceEngine
from core.cmdb_engine import CMDBEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def data_dir(tmp_path):
    """Temp directory emulating `.fixops_data`; AI engine + sibling DBs
    all live here so cross-DB discovery resolves correctly."""
    return tmp_path


@pytest.fixture
def ai_engine(data_dir):
    return AIGovernanceEngine(db_path=str(data_dir / "ai_governance.db"))


@pytest.fixture
def cmdb_engine(data_dir):
    return CMDBEngine(db_path=str(data_dir / "cmdb.db"))


def _seed_cloud_inventory(data_dir: Path, rows):
    db = data_dir / "cloud_resource_inventory.db"
    conn = sqlite3.connect(str(db))
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute(
            """CREATE TABLE IF NOT EXISTS cri_resources (
                id TEXT PRIMARY KEY, org_id TEXT NOT NULL,
                resource_id TEXT, resource_name TEXT,
                provider TEXT, resource_type TEXT,
                tags_json TEXT DEFAULT '{}')"""
        )
        for r in rows:
            conn.execute(
                "INSERT INTO cri_resources "
                "(id,org_id,resource_id,resource_name,provider,"
                "resource_type,tags_json) VALUES (?,?,?,?,?,?,?)",
                (r["id"], r["org_id"], r["resource_id"], r["resource_name"],
                 r.get("provider", "aws"), r.get("resource_type", "compute"),
                 json.dumps(r.get("tags", {}))),
            )
        conn.commit()
    finally:
        conn.close()


def _seed_identity_risk(data_dir: Path, rows):
    db = data_dir / "identity_risk.db"
    conn = sqlite3.connect(str(db))
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute(
            """CREATE TABLE IF NOT EXISTS ir_identities (
                id TEXT PRIMARY KEY, org_id TEXT NOT NULL,
                username TEXT, email TEXT, identity_type TEXT,
                department TEXT DEFAULT '', risk_level TEXT DEFAULT 'low',
                status TEXT DEFAULT 'active')"""
        )
        for r in rows:
            conn.execute(
                "INSERT INTO ir_identities "
                "(id,org_id,username,email,identity_type,risk_level) "
                "VALUES (?,?,?,?,?,?)",
                (r["id"], r["org_id"], r.get("username", ""),
                 r.get("email", ""), r.get("identity_type", "human"),
                 r.get("risk_level", "low")),
            )
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# 1. register_ai_service
# ---------------------------------------------------------------------------

def test_register_service_minimal(ai_engine):
    svc = ai_engine.register_ai_service("org1", "openai", provider="OpenAI")
    assert svc["service_name"] == "openai"
    assert svc["provider"] == "OpenAI"
    assert svc["data_classification"] == "internal"
    assert "id" in svc


def test_register_service_unique_idempotent(ai_engine):
    """Re-registering same service_name returns the stored row, not a dup."""
    first = ai_engine.register_ai_service("org1", "anthropic", provider="A")
    second = ai_engine.register_ai_service("org1", "anthropic", provider="B")
    # UNIQUE constraint → INSERT OR IGNORE → stored provider stays "A"
    assert second["id"] == first["id"]
    assert second["provider"] == "A"
    assert len(ai_engine.list_ai_services("org1")) == 1


def test_register_service_rejects_blank_name(ai_engine):
    with pytest.raises(ValueError, match="service_name"):
        ai_engine.register_ai_service("org1", "   ")


def test_register_service_rejects_bad_classification(ai_engine):
    with pytest.raises(ValueError, match="data_classification"):
        ai_engine.register_ai_service(
            "org1", "svc", data_classification="top-secret-alien"
        )


def test_register_service_requires_org(ai_engine):
    with pytest.raises(ValueError, match="org_id"):
        ai_engine.register_ai_service("", "svc")


# ---------------------------------------------------------------------------
# 2. discover_shadow_ai — explicit caller sources
# ---------------------------------------------------------------------------

def test_discover_domain_signal(ai_engine):
    result = ai_engine.discover_shadow_ai(
        "org1",
        sources=[{"asset_ref": "a1", "name": "scratch",
                  "domain": "api.openai.com"}],
    )
    assert result["total_signals"] == 1
    assert result["unregistered_count"] == 1
    assert result["registered_count"] == 0
    assert result["coverage_pct"] == 0.0


def test_discover_package_signal(ai_engine):
    result = ai_engine.discover_shadow_ai(
        "org1",
        sources=[{"asset_ref": "a2", "package": "langchain"}],
    )
    assert result["unregistered_count"] == 1
    assert result["discovered"][0]["signal"] == "langchain"


def test_discover_envvar_signal(ai_engine):
    result = ai_engine.discover_shadow_ai(
        "org1",
        sources=[{"asset_ref": "a3", "envvars": ["OPENAI_API_KEY", "PATH"]}],
    )
    assert result["unregistered_count"] == 1
    assert result["discovered"][0]["signal"] == "OPENAI_API_KEY"


def test_discover_no_signal_no_match(ai_engine):
    result = ai_engine.discover_shadow_ai(
        "org1",
        sources=[{"asset_ref": "nope", "domain": "example.com"}],
    )
    assert result["total_signals"] == 0
    assert result["coverage_pct"] == 100.0  # vacuous coverage


def test_discover_registered_vs_unregistered(ai_engine):
    """After registering 'openai', an openai domain signal should count as registered."""
    ai_engine.register_ai_service("org1", "openai")
    result = ai_engine.discover_shadow_ai(
        "org1",
        sources=[
            {"asset_ref": "a1", "domain": "api.openai.com"},
            {"asset_ref": "a2", "domain": "api.anthropic.com"},
        ],
    )
    assert result["total_signals"] == 2
    assert result["registered_count"] == 1
    assert result["unregistered_count"] == 1
    assert result["coverage_pct"] == 50.0


def test_discover_coverage_full(ai_engine):
    ai_engine.register_ai_service("org1", "openai")
    ai_engine.register_ai_service("org1", "anthropic")
    result = ai_engine.discover_shadow_ai(
        "org1",
        sources=[
            {"asset_ref": "a1", "domain": "openai.com"},
            {"asset_ref": "a2", "domain": "anthropic.com"},
        ],
    )
    assert result["coverage_pct"] == 100.0
    assert result["unregistered_count"] == 0


def test_discover_requires_org(ai_engine):
    with pytest.raises(ValueError):
        ai_engine.discover_shadow_ai("")


def test_discover_ignores_malformed_source(ai_engine):
    result = ai_engine.discover_shadow_ai(
        "org1", sources=["not-a-dict", 42, None]
    )
    assert result["total_signals"] == 0


# ---------------------------------------------------------------------------
# 3. discover_shadow_ai — cmdb / cloud / identity integration
# ---------------------------------------------------------------------------

def test_discover_surfaces_cmdb_saas_app(ai_engine, cmdb_engine):
    cmdb_engine.add_ci("org1", {
        "name": "Internal Chatbot",
        "ci_type": "application",
        "version": "uses openai.com backend",
    })
    result = ai_engine.discover_shadow_ai("org1")
    sources = {d["source"] for d in result["discovered"]}
    assert "cmdb" in sources
    assert result["unregistered_count"] >= 1


def test_discover_surfaces_cloud_inventory(ai_engine, data_dir):
    _seed_cloud_inventory(data_dir, [
        {"id": "r1", "org_id": "org1", "resource_id": "i-abc",
         "resource_name": "huggingface.co-cache-bucket",
         "provider": "aws"},
    ])
    result = ai_engine.discover_shadow_ai("org1")
    sources = {d["source"] for d in result["discovered"]}
    assert "cloud_inventory" in sources


def test_discover_surfaces_identity_email(ai_engine, data_dir):
    _seed_identity_risk(data_dir, [
        {"id": "id1", "org_id": "org1",
         "username": "alice", "email": "alice@openai.com"},
    ])
    result = ai_engine.discover_shadow_ai("org1")
    sources = {d["source"] for d in result["discovered"]}
    assert "identity_risk" in sources


def test_discover_handles_missing_sibling_dbs(ai_engine):
    """No cmdb / cloud / identity DB present → discover must not crash."""
    result = ai_engine.discover_shadow_ai("org1")
    assert result["total_signals"] == 0
    assert result["coverage_pct"] == 100.0


# ---------------------------------------------------------------------------
# 4. org_id isolation
# ---------------------------------------------------------------------------

def test_org_isolation_registry(ai_engine):
    ai_engine.register_ai_service("org1", "openai")
    ai_engine.register_ai_service("org2", "anthropic")
    assert [s["service_name"] for s in ai_engine.list_ai_services("org1")] == ["openai"]
    assert [s["service_name"] for s in ai_engine.list_ai_services("org2")] == ["anthropic"]


def test_org_isolation_discover(ai_engine):
    r1 = ai_engine.discover_shadow_ai(
        "org1",
        sources=[{"asset_ref": "a1", "domain": "openai.com"}],
    )
    r2 = ai_engine.discover_shadow_ai(
        "org2",
        sources=[{"asset_ref": "a2", "domain": "anthropic.com"}],
    )
    ai_engine.register_ai_service("org1", "openai")
    # Re-run org1; its registry should resolve but org2 should be unaffected.
    r1b = ai_engine.discover_shadow_ai(
        "org1",
        sources=[{"asset_ref": "a1", "domain": "openai.com"}],
    )
    assert r1["unregistered_count"] == 1
    assert r1b["unregistered_count"] == 0
    assert r2["unregistered_count"] == 1


# ---------------------------------------------------------------------------
# 5. attack_paths
# ---------------------------------------------------------------------------

def test_attack_paths_unregistered_returns_partial(ai_engine):
    """No identities, no data stores → partial path + unregistered=True."""
    result = ai_engine.ai_attack_paths("org1", "openai")
    assert result["service_name"] == "openai"
    assert result["registered"] is False
    assert result["path_count"] >= 1
    techs = result["paths"][0]["techniques"]
    assert "prompt_injection" in techs
    assert "data_exfiltration_via_tool_use" in techs


def test_attack_paths_full_graph(ai_engine, cmdb_engine, data_dir):
    _seed_identity_risk(data_dir, [
        {"id": "id1", "org_id": "org1",
         "username": "alice", "identity_type": "human",
         "risk_level": "high"},
    ])
    cmdb_engine.add_ci("org1", {
        "name": "customers-prod", "ci_type": "database",
        "criticality": "critical",
    })
    ai_engine.register_ai_service("org1", "openai", provider="OpenAI")
    result = ai_engine.ai_attack_paths("org1", "openai")
    assert result["registered"] is True
    assert result["identity_count"] == 1
    assert result["data_store_count"] == 1
    path0 = result["paths"][0]["path"]
    assert path0[0]["type"] == "identity"
    assert path0[1]["type"] == "ai_service"
    assert path0[1]["registered"] is True
    assert path0[2]["type"] == "data_store"


def test_attack_paths_requires_service_name(ai_engine):
    with pytest.raises(ValueError, match="service_name"):
        ai_engine.ai_attack_paths("org1", "")


# ---------------------------------------------------------------------------
# 6. CMDB flag_as_shadow_ai
# ---------------------------------------------------------------------------

def test_cmdb_flag_as_shadow_ai_records_tag(cmdb_engine):
    flag = cmdb_engine.flag_as_shadow_ai(
        "org1", "asset-abc", reason="shadow_ai:openai.com"
    )
    assert flag["asset_ref"] == "asset-abc"
    assert flag["reason"] == "shadow_ai:openai.com"
    assert "id" in flag
    assert "flagged_at" in flag


def test_cmdb_flag_list_scoped_to_org(cmdb_engine):
    cmdb_engine.flag_as_shadow_ai("org1", "a1", reason="r1")
    cmdb_engine.flag_as_shadow_ai("org2", "a2", reason="r2")
    assert len(cmdb_engine.list_shadow_ai_flags("org1")) == 1
    assert len(cmdb_engine.list_shadow_ai_flags("org2")) == 1
    assert cmdb_engine.list_shadow_ai_flags("org1")[0]["asset_ref"] == "a1"


def test_cmdb_flag_filter_by_asset_ref(cmdb_engine):
    cmdb_engine.flag_as_shadow_ai("org1", "a1", reason="r1")
    cmdb_engine.flag_as_shadow_ai("org1", "a2", reason="r2")
    assert len(cmdb_engine.list_shadow_ai_flags("org1", asset_ref="a1")) == 1


def test_cmdb_flag_rejects_blank_asset_ref(cmdb_engine):
    with pytest.raises(ValueError, match="asset_ref"):
        cmdb_engine.flag_as_shadow_ai("org1", "")


# ---------------------------------------------------------------------------
# 7. Endpoint smoke — direct-call mode, no HTTP stack
# ---------------------------------------------------------------------------

def test_router_endpoint_smoke(monkeypatch, ai_engine, cmdb_engine):
    """Hit router functions directly; inject our fixture engines so
    the module-level singletons don't cross-pollinate with other tests."""
    from apps.api import shadow_ai_router as mod  # type: ignore[import]

    monkeypatch.setattr(mod, "_get_ai_engine", lambda: ai_engine)
    monkeypatch.setattr(mod, "_get_cmdb_engine", lambda: cmdb_engine)

    # register
    reg = mod.register(mod.RegisterRequest(service_name="openai"), org_id="org1")
    assert reg["service_name"] == "openai"

    # registry
    assert len(mod.registry(org_id="org1")) == 1

    # discover
    disc = mod.discover(
        mod.DiscoverRequest(
            sources=[{"asset_ref": "a1", "domain": "anthropic.com"}],
            flag_unregistered=True,
        ),
        org_id="org1",
    )
    assert disc["unregistered_count"] == 1
    # flag_unregistered=True → cmdb should record a flag
    flags = cmdb_engine.list_shadow_ai_flags("org1")
    assert len(flags) == 1

    # attack-paths
    paths = mod.attack_paths(
        mod.AttackPathsRequest(service_name="openai"), org_id="org1"
    )
    assert paths["registered"] is True

    # stats
    st = mod.stats(org_id="org1")
    assert st["registered_services"] == 1
    assert "coverage_pct" in st
