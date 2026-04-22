"""Tests for subsidiary attribution (GAP-030) + exposure-layer tagging (GAP-045).

Covers:
  - attack_surface_engine: attribute_asset_to_subsidiary + list_subsidiary_assets
  - attack_surface_engine: tag_exposure_layer + list_assets_by_exposure
  - passive_dns_engine: find_subsidiary_domains heuristic
  - dark_web_monitoring_engine: monitor_subsidiary_mentions + list/disable
  - subsidiary_attribution_router: endpoint smoke (auth + status codes)
"""
from __future__ import annotations

import os
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from core.attack_surface_engine import AttackSurfaceEngine
from core.passive_dns_engine import PassiveDNSEngine
from core.dark_web_monitoring_engine import DarkWebMonitoringEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def as_engine(tmp_path):
    return AttackSurfaceEngine(db_dir=str(tmp_path / "as"))


@pytest.fixture
def pdns_engine(tmp_path):
    return PassiveDNSEngine(db_path=str(tmp_path / "pdns.db"))


@pytest.fixture
def dwm_engine(tmp_path):
    return DarkWebMonitoringEngine(db_path=str(tmp_path / "dwm.db"))


@pytest.fixture
def api_key(monkeypatch):
    """Patch auth_deps at module level — env vars are read at import, too late in fixtures."""
    key = "test-key-xyz"
    from apps.api import auth_deps
    monkeypatch.setattr(auth_deps, "_EXPECTED_TOKENS", (key,))
    monkeypatch.setattr(auth_deps, "_HAS_TOKEN_AUTH", True)
    monkeypatch.setattr(auth_deps, "_DEV_MODE", False)
    return key


@pytest.fixture
def client(api_key):
    from apps.api.subsidiary_attribution_router import router
    # Reset the lazy singletons so test fixtures don't leak across cases
    import apps.api.subsidiary_attribution_router as mod
    mod._as_engine = None
    mod._pdns_engine = None
    mod._dwm_engine = None
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


# ---------------------------------------------------------------------------
# Subsidiary Attribution (GAP-030) — engine
# ---------------------------------------------------------------------------

def test_attribute_asset_inserts_row(as_engine):
    rec = as_engine.attribute_asset_to_subsidiary(
        org_id="org1",
        asset_ref="acme-eu.com",
        subsidiary_name="ACME EU",
        attribution_source="whois",
        confidence=0.8,
    )
    assert rec["asset_ref"] == "acme-eu.com"
    assert rec["subsidiary_name"] == "ACME EU"
    assert rec["confidence"] == 0.8


def test_attribute_asset_unique_on_org_plus_asset_ref_upserts(as_engine):
    r1 = as_engine.attribute_asset_to_subsidiary(
        "org1", "acme-eu.com", "ACME EU", "whois", 0.5
    )
    r2 = as_engine.attribute_asset_to_subsidiary(
        "org1", "acme-eu.com", "ACME Germany", "manual", 0.95
    )
    # UPSERT keeps the id stable, updates the attribution
    assert r1["id"] == r2["id"]
    assert r2["subsidiary_name"] == "ACME Germany"
    assert r2["confidence"] == 0.95
    # Only one row for this asset_ref
    rows = as_engine.list_subsidiary_assets("org1")
    refs = [r["asset_ref"] for r in rows]
    assert refs.count("acme-eu.com") == 1


def test_attribute_asset_confidence_out_of_range_raises(as_engine):
    with pytest.raises(ValueError):
        as_engine.attribute_asset_to_subsidiary(
            "org1", "x.com", "X", "manual", 1.5
        )
    with pytest.raises(ValueError):
        as_engine.attribute_asset_to_subsidiary(
            "org1", "x.com", "X", "manual", -0.1
        )


def test_attribute_asset_missing_fields_raises(as_engine):
    with pytest.raises(ValueError):
        as_engine.attribute_asset_to_subsidiary("org1", "", "X", "manual", 0.5)
    with pytest.raises(ValueError):
        as_engine.attribute_asset_to_subsidiary("org1", "x.com", "", "manual", 0.5)
    with pytest.raises(ValueError):
        as_engine.attribute_asset_to_subsidiary("org1", "x.com", "X", "", 0.5)


def test_list_subsidiary_assets_filter(as_engine):
    as_engine.attribute_asset_to_subsidiary("org1", "a.com", "SubA", "whois", 0.7)
    as_engine.attribute_asset_to_subsidiary("org1", "b.com", "SubB", "whois", 0.7)
    as_engine.attribute_asset_to_subsidiary("org1", "c.com", "SubA", "whois", 0.7)
    suba = as_engine.list_subsidiary_assets("org1", subsidiary_name="SubA")
    refs = sorted(r["asset_ref"] for r in suba)
    assert refs == ["a.com", "c.com"]


def test_list_subsidiary_assets_org_id_isolation(as_engine):
    as_engine.attribute_asset_to_subsidiary("org1", "a.com", "SubA", "whois", 0.7)
    as_engine.attribute_asset_to_subsidiary("org2", "b.com", "SubA", "whois", 0.7)
    org1 = as_engine.list_subsidiary_assets("org1")
    org2 = as_engine.list_subsidiary_assets("org2")
    assert [r["asset_ref"] for r in org1] == ["a.com"]
    assert [r["asset_ref"] for r in org2] == ["b.com"]


# ---------------------------------------------------------------------------
# Exposure-Layer Tagging (GAP-045) — engine
# ---------------------------------------------------------------------------

VALID_LAYERS = ["external-internet", "dmz", "internal", "restricted", "isolated"]


@pytest.mark.parametrize("layer", VALID_LAYERS)
def test_tag_exposure_layer_accepts_all_five_enum_values(as_engine, layer):
    rec = as_engine.tag_exposure_layer("org1", f"{layer}-asset", layer)
    assert rec["exposure_layer"] == layer
    assert rec["asset_ref"] == f"{layer}-asset"


def test_tag_exposure_layer_invalid_rejected(as_engine):
    with pytest.raises(ValueError, match="exposure_layer"):
        as_engine.tag_exposure_layer("org1", "x.com", "public")
    with pytest.raises(ValueError, match="exposure_layer"):
        as_engine.tag_exposure_layer("org1", "x.com", "")


def test_tag_exposure_layer_unique_upserts(as_engine):
    r1 = as_engine.tag_exposure_layer("org1", "x.com", "dmz")
    r2 = as_engine.tag_exposure_layer("org1", "x.com", "internal")
    assert r1["id"] == r2["id"]
    assert r2["exposure_layer"] == "internal"
    # Not returned when querying old layer
    assert as_engine.list_assets_by_exposure("org1", "dmz") == []
    assert len(as_engine.list_assets_by_exposure("org1", "internal")) == 1


def test_list_assets_by_exposure_invalid_raises(as_engine):
    with pytest.raises(ValueError):
        as_engine.list_assets_by_exposure("org1", "not-a-layer")


def test_list_assets_by_exposure_org_id_isolation(as_engine):
    as_engine.tag_exposure_layer("orgA", "a.com", "dmz")
    as_engine.tag_exposure_layer("orgB", "b.com", "dmz")
    a_rows = as_engine.list_assets_by_exposure("orgA", "dmz")
    b_rows = as_engine.list_assets_by_exposure("orgB", "dmz")
    assert [r["asset_ref"] for r in a_rows] == ["a.com"]
    assert [r["asset_ref"] for r in b_rows] == ["b.com"]


# ---------------------------------------------------------------------------
# Subsidiary Domain Discovery (GAP-030) — passive DNS heuristic
# ---------------------------------------------------------------------------

def test_find_subsidiary_domains_requires_parent(pdns_engine):
    with pytest.raises(ValueError):
        pdns_engine.find_subsidiary_domains("org1", "")


def test_find_subsidiary_domains_token_match(pdns_engine):
    # Seed a few resolutions
    pdns_engine.record_resolution("org1", {
        "domain": "mail.acmecorp.com", "resolved_ip": "1.1.1.1", "record_type": "A",
    })
    pdns_engine.record_resolution("org1", {
        "domain": "acmecorp.co.uk", "resolved_ip": "2.2.2.2", "record_type": "A",
    })
    pdns_engine.record_resolution("org1", {
        "domain": "unrelated.com", "resolved_ip": "3.3.3.3", "record_type": "A",
    })
    candidates = pdns_engine.find_subsidiary_domains("org1", "acmecorp.com")
    hits = {c["domain"] for c in candidates}
    assert "mail.acmecorp.com" in hits
    assert "acmecorp.co.uk" in hits
    assert "unrelated.com" not in hits


def test_find_subsidiary_domains_seed_pattern_boost(pdns_engine):
    pdns_engine.record_resolution("org1", {
        "domain": "partner-brand-one.com", "resolved_ip": "4.4.4.4",
    })
    cands = pdns_engine.find_subsidiary_domains(
        "org1", "acmecorp.com", seed_patterns=["brand-one"]
    )
    assert any(c["domain"] == "partner-brand-one.com" for c in cands)
    # Confidence bumped by seed pattern
    match = next(c for c in cands if c["domain"] == "partner-brand-one.com")
    assert match["confidence"] >= 0.85


def test_find_subsidiary_domains_apex_token_highest_confidence(pdns_engine):
    pdns_engine.record_resolution("org1", {
        "domain": "acmecorp.de", "resolved_ip": "5.5.5.5",
    })
    cands = pdns_engine.find_subsidiary_domains("org1", "acmecorp.com")
    apex_match = next((c for c in cands if c["domain"] == "acmecorp.de"), None)
    assert apex_match is not None
    # Apex-token match yields the 0.9 tier
    assert apex_match["confidence"] >= 0.9


def test_find_subsidiary_domains_excludes_parent_itself(pdns_engine):
    pdns_engine.record_resolution("org1", {
        "domain": "acmecorp.com", "resolved_ip": "9.9.9.9",
    })
    cands = pdns_engine.find_subsidiary_domains("org1", "acmecorp.com")
    assert all(c["domain"] != "acmecorp.com" for c in cands)


def test_find_subsidiary_domains_empty_when_no_pdns(pdns_engine):
    cands = pdns_engine.find_subsidiary_domains("org1", "acmecorp.com")
    assert cands == []


# ---------------------------------------------------------------------------
# Dark-Web Subsidiary Monitors (GAP-030)
# ---------------------------------------------------------------------------

def test_monitor_subsidiary_creates_row(dwm_engine):
    rec = dwm_engine.monitor_subsidiary_mentions(
        "org1", "ACME EU", ["acme-eu.com", "ACME Europe"]
    )
    assert rec["subsidiary_name"] == "ACME EU"
    assert rec["enabled"] is True
    assert "acme-eu.com" in rec["keywords"]
    assert "ACME Europe" in rec["keywords"]


def test_monitor_subsidiary_unique_upserts_and_reenables(dwm_engine):
    r1 = dwm_engine.monitor_subsidiary_mentions("org1", "SubA", ["kw1"])
    dwm_engine.disable_subsidiary_monitor("org1", "SubA")
    r2 = dwm_engine.monitor_subsidiary_mentions("org1", "SubA", ["kw2", "kw3"])
    assert r1["id"] == r2["id"]
    assert r2["enabled"] is True
    assert r2["keywords"] == ["kw2", "kw3"]
    # Still only one row for this subsidiary
    monitors = dwm_engine.list_subsidiary_monitors("org1")
    names = [m["subsidiary_name"] for m in monitors]
    assert names.count("SubA") == 1


def test_monitor_subsidiary_requires_name(dwm_engine):
    with pytest.raises(ValueError):
        dwm_engine.monitor_subsidiary_mentions("org1", "", ["kw"])
    with pytest.raises(ValueError):
        dwm_engine.monitor_subsidiary_mentions("org1", "   ", None)


def test_monitor_subsidiary_keywords_dedupe_and_strip(dwm_engine):
    rec = dwm_engine.monitor_subsidiary_mentions(
        "org1", "SubA", ["  kw1 ", "kw1", "", "kw2"]
    )
    assert rec["keywords"] == ["kw1", "kw2"]


def test_monitor_subsidiary_keywords_type_guard(dwm_engine):
    with pytest.raises(ValueError):
        dwm_engine.monitor_subsidiary_mentions("org1", "SubA", ["ok", 42])  # type: ignore[list-item]


def test_list_subsidiary_monitors_filter_enabled(dwm_engine):
    dwm_engine.monitor_subsidiary_mentions("org1", "SubA", ["k"])
    dwm_engine.monitor_subsidiary_mentions("org1", "SubB", ["k"])
    dwm_engine.disable_subsidiary_monitor("org1", "SubB")

    enabled = dwm_engine.list_subsidiary_monitors("org1", enabled=True)
    disabled = dwm_engine.list_subsidiary_monitors("org1", enabled=False)
    all_ = dwm_engine.list_subsidiary_monitors("org1")

    assert [m["subsidiary_name"] for m in enabled] == ["SubA"]
    assert [m["subsidiary_name"] for m in disabled] == ["SubB"]
    assert {m["subsidiary_name"] for m in all_} == {"SubA", "SubB"}


def test_disable_subsidiary_monitor_flips_enabled(dwm_engine):
    dwm_engine.monitor_subsidiary_mentions("org1", "SubA", ["k"])
    ok = dwm_engine.disable_subsidiary_monitor("org1", "SubA")
    assert ok is True
    rows = dwm_engine.list_subsidiary_monitors("org1")
    assert rows[0]["enabled"] is False


def test_disable_subsidiary_monitor_missing_returns_false(dwm_engine):
    assert dwm_engine.disable_subsidiary_monitor("org1", "NotThere") is False


def test_disable_subsidiary_monitor_requires_name(dwm_engine):
    with pytest.raises(ValueError):
        dwm_engine.disable_subsidiary_monitor("org1", "")


def test_subsidiary_monitors_org_id_isolation(dwm_engine):
    dwm_engine.monitor_subsidiary_mentions("orgA", "Shared", ["k"])
    dwm_engine.monitor_subsidiary_mentions("orgB", "Shared", ["k"])
    a_list = dwm_engine.list_subsidiary_monitors("orgA")
    b_list = dwm_engine.list_subsidiary_monitors("orgB")
    assert len(a_list) == 1
    assert len(b_list) == 1
    # Disabling in orgA does not affect orgB
    dwm_engine.disable_subsidiary_monitor("orgA", "Shared")
    assert dwm_engine.list_subsidiary_monitors("orgA")[0]["enabled"] is False
    assert dwm_engine.list_subsidiary_monitors("orgB")[0]["enabled"] is True


# ---------------------------------------------------------------------------
# Router — endpoint smoke tests (auth + status codes)
# ---------------------------------------------------------------------------

def _hdr(api_key):
    return {"X-API-Key": api_key, "Authorization": f"Bearer {api_key}"}


def test_router_attribute_endpoint_201(client, api_key):
    r = client.post(
        "/api/v1/subsidiary/attribute",
        headers=_hdr(api_key),
        json={
            "org_id": "rtr-org",
            "asset_ref": "a.com",
            "subsidiary_name": "SubA",
            "attribution_source": "manual",
            "confidence": 0.7,
        },
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["asset_ref"] == "a.com"


def test_router_list_subsidiary_assets(client, api_key):
    client.post(
        "/api/v1/subsidiary/attribute",
        headers=_hdr(api_key),
        json={
            "org_id": "rtr-list",
            "asset_ref": "b.com",
            "subsidiary_name": "SubB",
            "attribution_source": "manual",
            "confidence": 0.6,
        },
    )
    r = client.get(
        "/api/v1/subsidiary/assets",
        headers=_hdr(api_key),
        params={"org_id": "rtr-list"},
    )
    assert r.status_code == 200
    rows = r.json()
    assert any(x["asset_ref"] == "b.com" for x in rows)


def test_router_exposure_layer_201(client, api_key):
    r = client.post(
        "/api/v1/subsidiary/exposure-layer",
        headers=_hdr(api_key),
        json={"org_id": "rtr-exp", "asset_ref": "x.com", "exposure_layer": "dmz"},
    )
    assert r.status_code == 201, r.text
    assert r.json()["exposure_layer"] == "dmz"


def test_router_exposure_layer_invalid_returns_422(client, api_key):
    r = client.post(
        "/api/v1/subsidiary/exposure-layer",
        headers=_hdr(api_key),
        json={"org_id": "rtr-exp", "asset_ref": "x.com", "exposure_layer": "public"},
    )
    assert r.status_code == 422


def test_router_list_by_exposure(client, api_key):
    client.post(
        "/api/v1/subsidiary/exposure-layer",
        headers=_hdr(api_key),
        json={"org_id": "rtr-ls", "asset_ref": "y.com", "exposure_layer": "internal"},
    )
    r = client.get(
        "/api/v1/subsidiary/exposure",
        headers=_hdr(api_key),
        params={"org_id": "rtr-ls", "exposure_layer": "internal"},
    )
    assert r.status_code == 200
    assert any(x["asset_ref"] == "y.com" for x in r.json())


def test_router_dark_web_monitor_201(client, api_key):
    r = client.post(
        "/api/v1/subsidiary/dark-web-monitor",
        headers=_hdr(api_key),
        json={
            "org_id": "rtr-dwm",
            "subsidiary_name": "DarkSub",
            "keywords": ["k1", "k2"],
        },
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["subsidiary_name"] == "DarkSub"
    assert body["enabled"] is True


def test_router_find_domains(client, api_key, tmp_path, monkeypatch):
    # Pre-seed the pdns singleton used by the router
    import apps.api.subsidiary_attribution_router as mod
    mod._pdns_engine = PassiveDNSEngine(db_path=str(tmp_path / "rtr_pdns.db"))
    mod._pdns_engine.record_resolution("rtr-fd", {
        "domain": "eu.acmecorp.com", "resolved_ip": "10.0.0.1",
    })
    r = client.post(
        "/api/v1/subsidiary/find-domains",
        headers=_hdr(api_key),
        json={"org_id": "rtr-fd", "parent_domain": "acmecorp.com"},
    )
    assert r.status_code == 200, r.text
    domains = {c["domain"] for c in r.json()}
    assert "eu.acmecorp.com" in domains


def test_router_auth_required(client):
    # No headers at all
    r = client.get(
        "/api/v1/subsidiary/assets",
        params={"org_id": "rtr-auth"},
    )
    assert r.status_code in (401, 403)
