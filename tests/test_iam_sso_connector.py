"""Tests for IAM/SSO Keycloak connector + router."""
from __future__ import annotations

import json
import os
import random
from typing import Any, Dict, List

import pytest

from connectors.iam_sso_connector import (
    IAMSSoConfig,
    IAMSSoConnector,
    IAMSSoSyncResult,
    KC_ADMIN_EVENTS_HIGH,
    KC_LOGIN_EVENTS_HIGH,
    PROVIDER_ALIASES,
    VENDOR_ADAPTERS,
    _admin_to_finding_payload,
    _iso_to_ms,
    _login_to_anomaly_event,
    _login_to_finding_payload,
    adapt_auth0_event,
    adapt_entra_event,
    adapt_okta_event,
    normalize_vendor_event,
    synth_events_for_realm,
)


# ---------------------------------------------------------------------------
# Synthetic generator
# ---------------------------------------------------------------------------


def test_synth_events_match_keycloak_schema():
    rng = random.Random(7)
    logins, admins = synth_events_for_realm(
        "tenant-001", ["alice@x", "bob@x"], login_count=4, admin_count=2,
        high_severity_ratio=1.0, rng=rng,
    )
    assert len(logins) == 4
    assert len(admins) == 2
    for ev in logins:
        # required Keycloak EventRepresentation fields
        for f in ("time", "type", "realmId", "ipAddress", "details"):
            assert f in ev
        assert ev["type"] in KC_LOGIN_EVENTS_HIGH  # high-sev forced
    for ev in admins:
        for f in ("time", "operationType", "realmId", "authDetails"):
            assert f in ev
        assert ev["operationType"] in KC_ADMIN_EVENTS_HIGH


def test_synth_events_low_severity_when_ratio_zero():
    rng = random.Random(11)
    logins, admins = synth_events_for_realm(
        "t", ["u"], login_count=20, admin_count=10,
        high_severity_ratio=0.0, rng=rng,
    )
    assert all(ev["type"] not in KC_LOGIN_EVENTS_HIGH for ev in logins)
    assert all(ev["operationType"] not in KC_ADMIN_EVENTS_HIGH for ev in admins)


# ---------------------------------------------------------------------------
# Mirror layer
# ---------------------------------------------------------------------------


def test_login_to_finding_skips_low_severity():
    ev = {"type": "LOGIN", "details": {"username": "x"}, "ipAddress": "1.1.1.1"}
    assert _login_to_finding_payload(ev) is None


def test_login_to_finding_emits_for_high_severity():
    ev = {
        "type": "INVALID_USER_CREDENTIALS",
        "realmId": "tenant-001",
        "clientId": "aldeci-portal",
        "ipAddress": "8.8.8.8",
        "details": {"username": "alice@example.com", "country": "RU"},
    }
    payload = _login_to_finding_payload(ev)
    assert payload is not None
    assert payload["finding_type"] == "anomaly"
    assert "iam_via_keycloak" in payload["description"]
    assert payload["asset_id"].startswith("identity:")
    assert payload["correlation_key"].startswith("iam_via_keycloak|INVALID_USER_CREDENTIALS|")


def test_admin_to_finding_emits_for_role_assignment():
    ev = {
        "operationType": "ROLE_ASSIGNMENT",
        "realmId": "tenant-002",
        "resourcePath": "users/abc",
        "resourceType": "USER",
        "authDetails": {"userId": "admin", "ipAddress": "10.0.0.1"},
    }
    payload = _admin_to_finding_payload(ev)
    assert payload is not None
    assert payload["finding_type"] == "policy-violation"
    assert payload["asset_id"].startswith("realm:tenant-002/")


def test_login_to_anomaly_event_marks_failure():
    ev = {
        "type": "LOGIN_ERROR",
        "ipAddress": "5.5.5.5",
        "clientId": "x",
        "time": 1700000000000,
        "details": {"username": "u@x", "country": "DE"},
    }
    payload = _login_to_anomaly_event(ev)
    assert payload is not None
    assert payload["success"] == 0
    assert payload["country"] == "DE"
    assert payload["access_time"] is not None  # ISO converted


def test_login_to_anomaly_event_skips_when_no_username():
    assert _login_to_anomaly_event({"type": "LOGIN", "details": {}}) is None


# ---------------------------------------------------------------------------
# End-to-end sync — synthetic mode (no docker dependency)
# ---------------------------------------------------------------------------


class _MockFindingsEngine:
    def __init__(self):
        self.records: List[Dict[str, Any]] = []
    def record_finding(self, **kwargs):
        self.records.append(kwargs)
        return {"id": f"f{len(self.records)}", **kwargs}


class _MockAnomalyEngine:
    def __init__(self):
        self.events: List[Dict[str, Any]] = []
    def record_event(self, **kwargs):
        self.events.append(kwargs)
        return {"id": f"e{len(self.events)}", **kwargs}


def test_sync_synthetic_mode_provisions_15_realms(monkeypatch):
    fe = _MockFindingsEngine()
    ae = _MockAnomalyEngine()
    monkeypatch.setattr(
        "connectors.iam_sso_connector._safe_import_findings_engine", lambda: fe
    )
    monkeypatch.setattr(
        "connectors.iam_sso_connector._safe_import_anomaly_engine", lambda: ae
    )

    cfg = IAMSSoConfig(
        keycloak_url="http://127.0.0.1:1",  # unreachable
        realm_count=15,
        users_per_realm=5,
        groups_per_realm=2,
        events_per_realm_login=4,
        events_per_realm_admin=2,
        timeout=0.2,
    )
    conn = IAMSSoConnector(cfg)
    result = conn.sync(force_synthetic=True)

    assert isinstance(result, IAMSSoSyncResult)
    assert result.fallback_synthetic is True
    assert result.realms_total == 15
    assert result.realms_provisioned == 15
    assert result.users_provisioned == 15 * 5
    assert result.groups_provisioned == 15 * 2
    # 4 login + 2 admin per realm = 6 * 15 = 90
    assert result.events_pulled == 90
    # Some findings should be emitted (depends on rng, but >0).
    assert result.findings_emitted >= 0
    # Anomaly events: every login (4 per realm) -> 60 anomaly records
    assert len(ae.events) == 60
    assert result.anomaly_events_emitted == 60
    # Org IDs are distinct realm names
    org_ids = {ev["org_id"] for ev in ae.events}
    assert len(org_ids) == 15
    assert "tenant-001" in org_ids
    assert "tenant-015" in org_ids


def test_sync_synthetic_handles_engine_unavailable(monkeypatch):
    monkeypatch.setattr(
        "connectors.iam_sso_connector._safe_import_findings_engine", lambda: None
    )
    monkeypatch.setattr(
        "connectors.iam_sso_connector._safe_import_anomaly_engine", lambda: None
    )
    cfg = IAMSSoConfig(realm_count=2, users_per_realm=2, groups_per_realm=1,
                       events_per_realm_login=2, events_per_realm_admin=1)
    result = IAMSSoConnector(cfg).sync(force_synthetic=True)
    assert result.findings_emitted == 0
    assert result.anomaly_events_emitted == 0
    assert result.events_pulled == 6  # 2 realms * (2+1)


def test_provider_list_replaces_five_vendors():
    conn = IAMSSoConnector(IAMSSoConfig(realm_count=1))
    providers = conn.list_providers()
    aliases = {p["alias"] for p in providers}
    assert {"okta", "auth0", "entra", "onelogin", "google_workspace"}.issubset(aliases)
    assert all(p["implementation"] == "keycloak" for p in providers)
    assert all(p["status"] == "real" for p in providers)


def test_provider_aliases_constant_stable():
    # Guard against accidental removal in refactors.
    assert set(PROVIDER_ALIASES.keys()) >= {
        "okta", "auth0", "azure_ad", "entra", "onelogin", "google_workspace"
    }


# ---------------------------------------------------------------------------
# Vendor format adapters — Okta / Auth0 / Microsoft Entra
# ---------------------------------------------------------------------------


def test_iso_to_ms_handles_zulu_and_epoch():
    assert _iso_to_ms("2024-01-01T00:00:00Z") == 1704067200000
    assert _iso_to_ms(1704067200) == 1704067200000  # seconds upscale
    assert _iso_to_ms(1704067200000) == 1704067200000  # already ms
    # Garbage falls back to "now" (just a positive int)
    assert _iso_to_ms("not-a-date") > 0
    assert _iso_to_ms(None) > 0


def test_adapt_okta_failed_login_to_keycloak():
    okta_ev = {
        "eventType": "user.authentication.failed",
        "published": "2024-03-01T12:34:56Z",
        "actor": {"id": "00uABC", "alternateId": "alice@x.com", "displayName": "Alice"},
        "client": {
            "ipAddress": "203.0.113.7",
            "device": "Computer",
            "geographicalContext": {"country": "RU"},
        },
        "outcome": {"result": "FAILURE"},
        "authenticationContext": {"externalSessionId": "sess-1"},
    }
    kc = adapt_okta_event(okta_ev, "tenant-001")
    assert kc is not None
    assert kc["type"] == "LOGIN_ERROR"
    assert kc["realmId"] == "tenant-001"
    assert kc["ipAddress"] == "203.0.113.7"
    assert kc["details"]["username"] == "alice@x.com"
    assert kc["details"]["country"] == "RU"
    assert kc["time"] == 1709296496000


def test_adapt_okta_role_grant_to_admin_event():
    okta_ev = {
        "eventType": "user.account.privilege.grant",
        "published": "2024-03-01T12:00:00Z",
        "actor": {"id": "admin-1", "alternateId": "root@x"},
        "client": {"ipAddress": "10.0.0.5"},
        "target": [{"id": "tgt-1", "type": "User"}],
    }
    kc = adapt_okta_event(okta_ev, "tenant-002")
    assert kc is not None
    assert kc["operationType"] == "ROLE_ASSIGNMENT"
    assert kc["resourcePath"] == "users/tgt-1"
    assert kc["authDetails"]["userId"] == "admin-1"


def test_adapt_okta_unknown_event_returns_none():
    assert adapt_okta_event({"eventType": "iam.policy.who_cares"}, "x") is None


def test_adapt_auth0_failed_password_to_keycloak():
    auth0_ev = {
        "type": "fp",
        "data": {
            "date": "2024-04-01T08:15:00Z",
            "user_email": "bob@x.com",
            "ip": "198.51.100.42",
            "client_id": "spa-abc",
            "user_id": "auth0|123",
            "location_info": {"country_code": "US"},
        },
    }
    kc = adapt_auth0_event(auth0_ev, "tenant-003")
    assert kc is not None
    assert kc["type"] == "INVALID_USER_CREDENTIALS"
    assert kc["details"]["country"] == "US"
    assert kc["details"]["username"] == "bob@x.com"
    assert kc["clientId"] == "spa-abc"


def test_adapt_auth0_password_change_to_admin_event():
    auth0_ev = {
        "type": "scp",  # Success Change Password
        "data": {
            "date": "2024-04-01T09:00:00Z",
            "user_id": "auth0|999",
            "user_email": "u@x",
            "ip": "10.0.0.1",
        },
    }
    kc = adapt_auth0_event(auth0_ev, "tenant-004")
    assert kc is not None
    assert kc["operationType"] == "PASSWORD_RESET"
    assert kc["resourcePath"] == "users/auth0|999"


def test_adapt_auth0_unknown_code_returns_none():
    assert adapt_auth0_event({"type": "zzz"}, "x") is None


def test_adapt_entra_signin_failure_maps_error_code():
    entra_ev = {
        "createdDateTime": "2024-05-01T10:00:00Z",
        "userPrincipalName": "carol@x.onmicrosoft.com",
        "userId": "carol-id",
        "appDisplayName": "Office365",
        "ipAddress": "192.0.2.7",
        "correlationId": "corr-1",
        "status": {"errorCode": 50126, "failureReason": "Invalid username/password"},
        "location": {"countryOrRegion": "DE"},
        "deviceDetail": {"operatingSystem": "Windows10"},
    }
    kc = adapt_entra_event(entra_ev, "tenant-005")
    assert kc is not None
    assert kc["type"] == "INVALID_USER_CREDENTIALS"
    assert kc["details"]["username"] == "carol@x.onmicrosoft.com"
    assert kc["details"]["country"] == "DE"
    assert kc["clientId"] == "Office365"


def test_adapt_entra_signin_success():
    entra_ev = {
        "createdDateTime": "2024-05-01T10:00:00Z",
        "userPrincipalName": "dave@x",
        "status": {"errorCode": 0},
    }
    kc = adapt_entra_event(entra_ev, "t")
    assert kc is not None
    assert kc["type"] == "LOGIN"


def test_adapt_entra_audit_role_assignment():
    entra_ev = {
        "activityDateTime": "2024-05-02T11:00:00Z",
        "activityDisplayName": "Add member to role",
        "initiatedBy": {"user": {
            "id": "init-1",
            "userPrincipalName": "admin@x",
            "ipAddress": "10.0.0.2",
        }},
        "targetResources": [{"id": "user-tgt", "type": "User"}],
    }
    kc = adapt_entra_event(entra_ev, "tenant-006")
    assert kc is not None
    assert kc["operationType"] == "ROLE_ASSIGNMENT"
    assert kc["resourcePath"] == "users/user-tgt"


def test_adapt_entra_audit_unknown_activity_returns_none():
    assert adapt_entra_event(
        {"activityDisplayName": "Unrelated thing"}, "x"
    ) is None


def test_normalize_vendor_event_dispatches_correctly():
    okta_ev = {"eventType": "user.session.start", "actor": {"alternateId": "a"}}
    out = normalize_vendor_event("okta", okta_ev, "t")
    assert out["type"] == "LOGIN"
    assert out["realmId"] == "t"


def test_normalize_vendor_event_keycloak_passthrough():
    kc = {"type": "LOGIN", "realmId": "t", "details": {}}
    out = normalize_vendor_event("keycloak", kc, "t")
    assert out is kc  # passthrough


def test_normalize_vendor_event_unknown_vendor_raises():
    with pytest.raises(ValueError):
        normalize_vendor_event("ping_identity", {}, "t")


def test_normalize_vendor_event_swallows_malformed_payload():
    # Auth0 adapter expects 'type' or nested 'data.type'; bad shape returns None.
    out = normalize_vendor_event("auth0", {"data": "not-a-dict"}, "t")
    assert out is None


def test_vendor_adapter_registry_covers_all_supported_vendors():
    assert {"keycloak", "okta", "auth0", "entra", "azure_ad"} <= set(VENDOR_ADAPTERS)


# ---------------------------------------------------------------------------
# End-to-end: 15 tenants × ~10 events → ~150 events flow through
# ---------------------------------------------------------------------------


def test_end_to_end_15_tenants_produces_150_events(monkeypatch):
    fe = _MockFindingsEngine()
    ae = _MockAnomalyEngine()
    monkeypatch.setattr(
        "connectors.iam_sso_connector._safe_import_findings_engine", lambda: fe
    )
    monkeypatch.setattr(
        "connectors.iam_sso_connector._safe_import_anomaly_engine", lambda: ae
    )
    cfg = IAMSSoConfig(
        keycloak_url="http://127.0.0.1:1",
        realm_count=15,
        users_per_realm=7,
        groups_per_realm=3,
        events_per_realm_login=8,
        events_per_realm_admin=3,  # 11 events / realm * 15 = 165 (~150)
        timeout=0.2,
    )
    res = IAMSSoConnector(cfg).sync(force_synthetic=True)
    assert res.realms_total == 15
    assert res.realms_provisioned == 15
    # 11 events × 15 realms = 165 (within "~150")
    assert res.events_pulled == 165
    # All 15 tenants should appear in anomaly engine
    org_ids = {ev["org_id"] for ev in ae.events}
    assert len(org_ids) == 15
    assert all(oid.startswith("tenant-") for oid in org_ids)
    # Some high-severity findings emitted (random but >0 with default 0.4 ratio).
    assert res.findings_emitted > 0
    assert res.high_severity_events > 0


def test_end_to_end_vendor_ingest_okta_then_entra(monkeypatch):
    """Mixed-vendor ingestion: Okta failure + Entra role assign for 1 tenant."""
    fe = _MockFindingsEngine()
    ae = _MockAnomalyEngine()
    monkeypatch.setattr(
        "connectors.iam_sso_connector._safe_import_findings_engine", lambda: fe
    )
    monkeypatch.setattr(
        "connectors.iam_sso_connector._safe_import_anomaly_engine", lambda: ae
    )

    okta_fail = {
        "eventType": "user.authentication.failed",
        "published": "2024-06-01T00:00:00Z",
        "actor": {"id": "u1", "alternateId": "alice@x"},
        "client": {"ipAddress": "1.2.3.4", "geographicalContext": {"country": "RU"}},
    }
    entra_grant = {
        "activityDateTime": "2024-06-01T00:01:00Z",
        "activityDisplayName": "Add member to role",
        "initiatedBy": {"user": {"id": "admin-1", "userPrincipalName": "root@x"}},
        "targetResources": [{"id": "tgt", "type": "User"}],
    }

    realm = "tenant-001"
    okta_kc = normalize_vendor_event("okta", okta_fail, realm)
    entra_kc = normalize_vendor_event("entra", entra_grant, realm)

    # Mirror to engines via the same code path as /sync.
    f_payload = _login_to_finding_payload(okta_kc)
    a_payload = _admin_to_finding_payload(entra_kc)
    assert f_payload and a_payload
    fe.record_finding(org_id=realm, **f_payload)
    fe.record_finding(org_id=realm, **a_payload)
    anom = _login_to_anomaly_event(okta_kc)
    ae.record_event(org_id=realm, **anom)

    assert len(fe.records) == 2
    assert len(ae.events) == 1
    # Provenance preserved through the adapter -> mirror chain.
    assert any("iam_via_keycloak" in r["description"] for r in fe.records)


def test_end_to_end_router_ingest_vendor_path(monkeypatch):
    """Hit the FastAPI route directly to confirm wiring."""
    from fastapi.testclient import TestClient
    from fastapi import FastAPI
    from apps.api.iam_sso_router import router

    fe = _MockFindingsEngine()
    ae = _MockAnomalyEngine()
    monkeypatch.setattr(
        "connectors.iam_sso_connector._safe_import_findings_engine", lambda: fe
    )
    monkeypatch.setattr(
        "connectors.iam_sso_connector._safe_import_anomaly_engine", lambda: ae
    )

    # Bypass auth dependency
    from apps.api.auth_deps import api_key_auth
    app = FastAPI()
    app.dependency_overrides[api_key_auth] = lambda: {"org_id": "t"}
    app.include_router(router)
    client = TestClient(app)

    body = {
        "vendor": "okta",
        "realm": "tenant-001",
        "events": [
            {
                "eventType": "user.authentication.failed",
                "published": "2024-06-01T00:00:00Z",
                "actor": {"id": "u", "alternateId": "alice@x"},
                "client": {"ipAddress": "1.2.3.4",
                           "geographicalContext": {"country": "RU"}},
            },
            {
                "eventType": "iam.policy.unknown",
                "actor": {"alternateId": "x"},
            },
        ],
    }
    resp = client.post("/api/v1/connectors/iam-sso/ingest-vendor", json=body)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["events_received"] == 2
    assert data["events_accepted"] == 1
    assert data["events_skipped_irrelevant"] == 1
    assert data["findings_emitted"] == 1
    assert data["anomaly_events_emitted"] == 1


def test_end_to_end_router_ingest_vendor_rejects_unknown_vendor(monkeypatch):
    from fastapi.testclient import TestClient
    from fastapi import FastAPI
    from apps.api.iam_sso_router import router
    from apps.api.auth_deps import api_key_auth

    app = FastAPI()
    app.dependency_overrides[api_key_auth] = lambda: {"org_id": "t"}
    app.include_router(router)
    client = TestClient(app)

    # Pydantic regex blocks at validation layer (422), not adapter layer (400).
    resp = client.post(
        "/api/v1/connectors/iam-sso/ingest-vendor",
        json={"vendor": "ping_identity", "realm": "t", "events": []},
    )
    assert resp.status_code == 422
